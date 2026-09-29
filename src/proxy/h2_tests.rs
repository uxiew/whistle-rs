//! HTTP/2 to the origin, end to end through [`forward_with_addr`]: when it is
//! offered, what the origin receives, how many connections a client's requests
//! take, and what happens when the origin says HTTP/1.1 instead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::BodyExt;
use hyper::{Request, Response, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use super::super::body::{self, DynBody};
use super::super::pool::ConnPool;
use super::super::timing::Timings;
use super::*;

/// What the fixture origin saw of one request.
#[derive(Clone, Debug)]
struct Seen {
    version: Version,
    uri: String,
    headers: hyper::HeaderMap,
}

struct Origin {
    port: u16,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// A TLS origin for `localhost` that offers `alpn` and answers every request
/// with `ok`, speaking whichever protocol the handshake settled on.
async fn origin(alpn: &[&[u8]]) -> Origin {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![test_tls::LEAF.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(test_tls::LEAF.key_pair.serialize_der().into()),
        )
        .expect("server config");
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (count, log) = (connections.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        log.lock().unwrap().push(Seen {
                            version: req.version(),
                            uri: req.uri().to_string(),
                            headers: req.headers().clone(),
                        });
                        async { Ok::<_, std::convert::Infallible>(Response::new(body::full("ok"))) }
                    });
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let io = TokioIo::new(tls);
                let _ = match h2 {
                    true => {
                        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service)
                            .await
                    }
                    false => {
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                    }
                };
            });
        }
    });
    Origin {
        port,
        connections,
        seen,
    }
}

fn tls_target(port: u16) -> Target {
    Target {
        tls_ciphers: None,
        cipher_dropped: None,
        no_proxy_ua: false,
        proxy_connection_close: false,
        connect_host: "127.0.0.1".into(),
        connect_port: port,
        tls: true,
        origin_tls_stripped: false,
        sni: "localhost".into(),
        request_port: port,
        proxy: None,
        tls_versions: TlsVersions::Default,
        host_fallback_direct: false,
        auto2http: false,
        h2: None,
    }
}

/// A GET as a client connection would hand it on: `version` is the protocol
/// the client spoke to this proxy.
fn get(version: Version, port: u16, pool: Option<&ConnPool>) -> Request<DynBody> {
    let mut req = Request::builder()
        .method("GET")
        .uri("/path?q=1")
        .version(version)
        .header("host", format!("localhost:{port}"))
        .header("connection", "keep-alive")
        .header("te", "gzip")
        .header("x-kept", "yes")
        .body(body::empty())
        .unwrap();
    if let Some(pool) = pool {
        req.extensions_mut().insert(pool.clone());
    }
    req
}

/// `n` h2 GETs at once, on one client connection's pool.
async fn fetch_all(target: &Target, port: u16, pool: &ConnPool, n: usize) -> Vec<Timings> {
    let tasks: Vec<_> = (0..n)
        .map(|_| {
            let (target, req) = (target.clone(), get(Version::HTTP_2, port, Some(pool)));
            tokio::spawn(async move { fetch(&target, req).await })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.expect("request task"));
    }
    out
}

async fn fetch(target: &Target, req: Request<DynBody>) -> Timings {
    let timings = Timings::new();
    let (resp, _) = forward_with_addr(target, req, &timings)
        .await
        .expect("forwarded");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
    timings
}

#[tokio::test]
async fn an_h2_client_reaches_an_h2_origin_over_h2() {
    let o = origin(&[b"h2", b"http/1.1"]).await;
    let pool = ConnPool::new();
    fetch(
        &tls_target(o.port),
        get(Version::HTTP_2, o.port, Some(&pool)),
    )
    .await;
    let seen = o.seen.lock().unwrap()[0].clone();
    assert_eq!(seen.version, Version::HTTP_2);
    // `:authority` from the Host header, and no Host header beside it —
    // whistle's `formatH2Headers`.
    assert_eq!(seen.uri, format!("https://localhost:{}/path?q=1", o.port));
    assert!(seen.headers.get("host").is_none());
    assert!(seen.headers.get("connection").is_none());
    assert!(
        seen.headers.get("te").is_none(),
        "only `te: trailers` crosses"
    );
    assert_eq!(seen.headers["x-kept"], "yes");
}

/// A page's worth of requests on one h2 client connection is one connection
/// to the origin — including the burst at the start, which waits for the
/// first connection rather than each opening its own.
#[tokio::test]
async fn concurrent_h2_requests_share_one_origin_connection() {
    let o = origin(&[b"h2", b"http/1.1"]).await;
    let pool = ConnPool::new();
    let target = tls_target(o.port);
    let timings = fetch_all(&target, o.port, &pool, 20).await;
    assert_eq!(o.connections.load(Ordering::SeqCst), 1);
    let numbers: std::collections::HashSet<_> = timings.iter().map(|t| t.connection_id()).collect();
    assert_eq!(numbers.len(), 1, "one connection, numbered once");
    let reused = timings
        .iter()
        .filter(|t| serde_json::to_value(t).unwrap().get("reused").is_some())
        .count();
    assert_eq!(reused, 19, "every request but the one that connected");
}

#[tokio::test]
async fn an_http1_client_stays_on_http1() {
    let o = origin(&[b"h2", b"http/1.1"]).await;
    fetch(&tls_target(o.port), get(Version::HTTP_11, o.port, None)).await;
    assert_eq!(o.seen.lock().unwrap()[0].version, Version::HTTP_11);
}

/// `enable://h2` and `disable://h2`, as the rules leave them on the target.
#[tokio::test]
async fn the_rules_turn_it_either_way() {
    let o = origin(&[b"h2", b"http/1.1"]).await;
    let on = Target {
        h2: Some(true),
        ..tls_target(o.port)
    };
    fetch(&on, get(Version::HTTP_11, o.port, None)).await;
    let off = Target {
        h2: Some(false),
        ..tls_target(o.port)
    };
    fetch(&off, get(Version::HTTP_2, o.port, None)).await;
    let versions: Vec<_> = o.seen.lock().unwrap().iter().map(|s| s.version).collect();
    assert_eq!(versions, [Version::HTTP_2, Version::HTTP_11]);
}

/// An origin that answers the offer with HTTP/1.1 gets HTTP/1.1 on the
/// connection it already accepted — no second handshake — and the client's
/// next requests do not queue behind one another waiting for an h2
/// connection that is never coming.
#[tokio::test]
async fn an_origin_that_picks_http1_gets_http1() {
    let o = origin(&[b"http/1.1"]).await;
    let pool = ConnPool::new();
    let target = tls_target(o.port);
    fetch(&target, get(Version::HTTP_2, o.port, Some(&pool))).await;
    assert_eq!(o.connections.load(Ordering::SeqCst), 1);
    assert_eq!(o.seen.lock().unwrap()[0].version, Version::HTTP_11);
    fetch_all(&target, o.port, &pool, 4).await;
    assert!(
        o.seen
            .lock()
            .unwrap()
            .iter()
            .all(|s| s.version == Version::HTTP_11)
    );
}

/// The shared connection going away is not the client's problem: the next
/// request opens another.
#[tokio::test]
async fn a_closed_session_is_replaced() {
    let o = origin(&[b"h2", b"http/1.1"]).await;
    let pool = ConnPool::new();
    let target = tls_target(o.port);
    fetch(&target, get(Version::HTTP_2, o.port, Some(&pool))).await;
    pool.close_sessions();
    // Give the connection task a moment to see its last handle go.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    fetch(&target, get(Version::HTTP_2, o.port, Some(&pool))).await;
    assert_eq!(o.connections.load(Ordering::SeqCst), 2);
}

/// Everything an h2 origin cannot be sent, and nothing else.
#[test]
fn the_head_is_rewritten_for_h2() {
    let mut req = get(Version::HTTP_11, 8443, None);
    for (name, value) in [
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "h2c"),
        ("http2-settings", "AAMAAABkAAQAAP__"),
    ] {
        req.headers_mut().insert(name, value.parse().unwrap());
    }
    let out = for_h2(req, &tls_target(8443));
    assert_eq!(out.version(), Version::HTTP_2);
    assert_eq!(out.uri(), "https://localhost:8443/path?q=1");
    let names: Vec<_> = out.headers().keys().map(|k| k.as_str()).collect();
    assert_eq!(names, ["x-kept"]);

    let mut trailers = get(Version::HTTP_11, 8443, None);
    trailers
        .headers_mut()
        .insert("te", "trailers".parse().unwrap());
    assert_eq!(
        for_h2(trailers, &tls_target(8443)).headers()["te"],
        "trailers"
    );
}
