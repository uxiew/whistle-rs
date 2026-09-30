//! The origin connection pool, end to end through [`forward_with_addr`]: what
//! is reused, what is not, and what happens when a reused connection turns out
//! to have been closed. See [`super::super::pool`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::super::body::{self, DynBody};
use super::super::pool::ConnPool;
use super::super::timing::Timings;
use super::*;

/// How the fixture origin treats each connection.
#[derive(Clone, Copy)]
enum Origin {
    /// Answers every request, keeping the connection.
    KeepAlive,
    /// Answers with `Connection: close` and closes.
    Closes,
    /// Answers the first request, then closes when the second arrives without
    /// answering it — an idle timer firing just as a request goes out.
    HangsUpOnTheSecond,
    /// Answers with a body big enough that a client can walk away mid-way.
    Big,
}

/// Start an origin; returns its port and the count of connections it accepted.
async fn origin(kind: Origin) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve(sock, kind));
        }
    });
    (port, accepted)
}

async fn serve(mut sock: TcpStream, kind: Origin) {
    let mut served = 0;
    while read_request(&mut sock).await {
        served += 1;
        let response: Vec<u8> = match kind {
            Origin::HangsUpOnTheSecond if served == 2 => return,
            Origin::Closes => {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
            }
            Origin::Big => {
                let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 4194304\r\n\r\n".to_vec();
                r.resize(r.len() + 4 * 1024 * 1024, b'x');
                r
            }
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        };
        if sock.write_all(&response).await.is_err() {
            return;
        }
        if matches!(kind, Origin::Closes) {
            return;
        }
    }
}

/// Read one request, head and `Content-Length` body. False at end of stream.
async fn read_request(sock: &mut TcpStream) -> bool {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match sock.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return false,
        }
    }
    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let len: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body).await.is_ok()
}

fn direct(port: u16) -> Target {
    Target {
        tls_ciphers: None,
        tls_extras: None,
        cipher_dropped: None,
        no_proxy_ua: false,
        proxy_connection_close: false,
        connect_host: "127.0.0.1".into(),
        connect_port: port,
        tls: false,
        origin_tls_stripped: false,
        sni: "127.0.0.1".into(),
        request_port: port,
        proxy: None,
        tls_versions: TlsVersions::Default,
        host_fallback_direct: false,
        auto2http: false,
        h2: None,
    }
}

fn request(method: &str, pool: Option<&ConnPool>, body: DynBody) -> Request<DynBody> {
    let mut req = Request::builder()
        .method(method)
        .uri("/")
        .header("host", "127.0.0.1")
        .body(body)
        .unwrap();
    if let Some(pool) = pool {
        req.extensions_mut().insert(pool.clone());
    }
    req
}

/// Send `req` and read its whole response; the response's timings come back
/// so a test can ask whether a connection was made for it.
async fn fetch(target: &Target, req: Request<DynBody>) -> anyhow::Result<Timings> {
    let timings = Timings::new();
    let (resp, _) = forward_with_addr(target, req, &timings).await?;
    resp.into_body().collect().await?;
    Ok(timings)
}

/// Wait for the pool to hold `n` idle connections. Parking happens on a task of
/// its own once hyper says the connection is free, which in a test can be a
/// poll or two after the body was read.
async fn settle(pool: &ConnPool, n: usize) {
    for _ in 0..200 {
        if pool.idle() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("pool holds {}, expected {n}", pool.idle());
}

#[tokio::test]
async fn a_client_connection_reuses_its_origin_connection() {
    let (port, accepted) = origin(Origin::KeepAlive).await;
    let pool = ConnPool::new();
    let first = fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    for _ in 0..2 {
        settle(&pool, 1).await;
        let again = fetch(&direct(port), request("GET", Some(&pool), body::empty()))
            .await
            .unwrap();
        // HAR's spelling of a reused connection: no connect phase at all —
        // and the session says why, and which connection it was.
        assert_eq!(again.har()["connect"], -1.0);
        let seen = serde_json::to_value(&again).unwrap();
        assert_eq!(seen["reused"], true);
        assert_eq!(again.connection_id(), first.connection_id());
    }
    assert_ne!(first.har()["connect"], -1.0);
    assert!(
        serde_json::to_value(&first)
            .unwrap()
            .get("reused")
            .is_none()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// Two clients never share an origin connection, however alike their
/// requests — see the pool's module docs for why.
#[tokio::test]
async fn another_client_connection_gets_its_own() {
    let (port, accepted) = origin(Origin::KeepAlive).await;
    let (a, b) = (ConnPool::new(), ConnPool::new());
    let first = fetch(&direct(port), request("GET", Some(&a), body::empty()))
        .await
        .unwrap();
    settle(&a, 1).await;
    let second = fetch(&direct(port), request("GET", Some(&b), body::empty()))
        .await
        .unwrap();
    assert_ne!(first.connection_id(), second.connection_id());
    assert!(
        serde_json::to_value(&second)
            .unwrap()
            .get("reused")
            .is_none()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// Composer, plugins' own fetches and anything else without a client
/// connection behind it connect afresh every time, as before.
#[tokio::test]
async fn a_request_with_no_pool_connects_every_time() {
    let (port, accepted) = origin(Origin::KeepAlive).await;
    for _ in 0..2 {
        fetch(&direct(port), request("GET", None, body::empty()))
            .await
            .unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// The same address asked for under another name is a different origin: its
/// `Host`, its SNI and whatever it keys its sessions on differ.
#[tokio::test]
async fn another_requested_host_gets_its_own() {
    let (port, accepted) = origin(Origin::KeepAlive).await;
    let pool = ConnPool::new();
    fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    settle(&pool, 1).await;
    let renamed = Target {
        sni: "localhost".into(),
        ..direct(port)
    };
    fetch(&renamed, request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_response_the_client_walked_away_from_is_not_reused() {
    let (port, accepted) = origin(Origin::Big).await;
    let pool = ConnPool::new();
    let (resp, _) = forward_with_addr(
        &direct(port),
        request("GET", Some(&pool), body::empty()),
        &Timings::new(),
    )
    .await
    .unwrap();
    drop(resp); // the head, and not a byte of the 4 MiB body
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(pool.idle(), 0);
    fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// Either end saying `Connection: close` ends the connection's life — the
/// origin's answer here, and the request's in `disable://keepAlive`. The
/// fixture keeps the connection open whatever the request says, so what is
/// pinned is that this side does not count on the origin to act on it.
#[tokio::test]
async fn connection_close_from_either_side_is_honoured() {
    let (port, accepted) = origin(Origin::Closes).await;
    let pool = ConnPool::new();
    for _ in 0..2 {
        fetch(&direct(port), request("GET", Some(&pool), body::empty()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle(), 0);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    let (port, accepted) = origin(Origin::KeepAlive).await;
    for _ in 0..2 {
        let mut req = request("GET", Some(&pool), body::empty());
        req.headers_mut()
            .insert(hyper::header::CONNECTION, "close".parse().unwrap());
        fetch(&direct(port), req).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle(), 0);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    // HTTP/1.0 closes unless it says `keep-alive`.
    let (port, accepted) = origin(Origin::KeepAlive).await;
    for keep_alive in [false, true] {
        let mut req = request("GET", Some(&pool), body::empty());
        *req.version_mut() = hyper::Version::HTTP_10;
        if keep_alive {
            req.headers_mut()
                .insert(hyper::header::CONNECTION, "keep-alive".parse().unwrap());
        }
        fetch(&direct(port), req).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle(), usize::from(keep_alive));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// The race every keep-alive client has with a server's idle timer. A GET goes
/// out again on a fresh connection and the client never knows.
#[tokio::test]
async fn a_get_sent_down_a_connection_that_was_closing_is_sent_again() {
    let (port, accepted) = origin(Origin::HangsUpOnTheSecond).await;
    let pool = ConnPool::new();
    fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    settle(&pool, 1).await;
    let retried = fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .expect("sent again on a fresh connection");
    assert_ne!(retried.har()["connect"], -1.0, "the retry connected afresh");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

/// A body is streamed from the client as it goes out, so there is nothing left
/// to send twice: the failure is the client's to see.
#[tokio::test]
async fn a_request_with_a_body_is_not_sent_twice() {
    let (port, accepted) = origin(Origin::HangsUpOnTheSecond).await;
    let pool = ConnPool::new();
    fetch(&direct(port), request("GET", Some(&pool), body::empty()))
        .await
        .unwrap();
    settle(&pool, 1).await;
    let post = request(
        "POST",
        Some(&pool),
        body::full(bytes::Bytes::from_static(b"once")),
    );
    assert!(fetch(&direct(port), post).await.is_err());
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn upgrades_and_tunnels_stay_out_of_the_pool() {
    let pool = ConnPool::new();
    let mut upgrade = request("GET", Some(&pool), body::empty());
    upgrade
        .headers_mut()
        .insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());
    upgrade
        .headers_mut()
        .insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
    assert!(pool_for(&upgrade).is_none());
    assert!(pool_for(&request("CONNECT", Some(&pool), body::empty())).is_none());
    assert!(pool_for(&request("GET", Some(&pool), body::empty())).is_some());
}

/// A key with no h2 offer, which is what every variant below starts from.
fn key_of(target: &Target, hop: &Hop) -> super::super::pool::Key {
    pool_key(target, hop, false)
}

/// Every part of a connection's identity is in its key: change any one and
/// the request needs a connection of its own.
#[test]
fn every_part_of_the_route_is_in_the_key() {
    let proxy = ProxyConfig {
        kind: ProxyKind::Http,
        host: "proxy.test".into(),
        port: 8080,
        auth: Some(ProxyAuth("alice:secret".into())),
        host_override: None,
        tunnel: false,
        fallback_direct: false,
    };
    let tls = Target {
        tls: true,
        proxy: Some(proxy.clone()),
        ..direct(443)
    };
    let hop = Hop {
        user_agent: Some("ua/1".into()),
        client_proxy_auth: Some("Basic Y2xpZW50".into()),
        ..Hop::default()
    };
    let base = key_of(&tls, &hop);
    let with_proxy = |f: &dyn Fn(&mut ProxyConfig)| {
        let mut p = proxy.clone();
        f(&mut p);
        Target {
            proxy: Some(p),
            ..tls.clone()
        }
    };
    let policy =
        super::super::ciphers::evaluate("TLS_AES_128_GCM_SHA256").expect("a suite this build has");
    let variants: Vec<(&str, super::super::pool::Key)> = vec![
        (
            "connect address",
            key_of(
                &Target {
                    connect_host: "10.0.0.1".into(),
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "requested host",
            key_of(
                &Target {
                    sni: "other.test".into(),
                    connect_host: "other.test".into(),
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "plain vs TLS",
            key_of(
                &Target {
                    tls: false,
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "TLS versions",
            key_of(
                &Target {
                    tls_versions: TlsVersions::Only12,
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "cipher suites",
            key_of(
                &Target {
                    tls_ciphers: Some(Arc::new(policy)),
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "client certificate",
            key_of(
                &Target {
                    tls_extras: Some(super::super::tls_options::TlsExtras::named("alice")),
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "stripped TLS",
            key_of(
                &Target {
                    origin_tls_stripped: true,
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "no proxy",
            key_of(
                &Target {
                    proxy: None,
                    ..tls.clone()
                },
                &hop,
            ),
        ),
        (
            "proxy kind",
            key_of(&with_proxy(&|p| p.kind = ProxyKind::Socks), &hop),
        ),
        (
            "proxy address",
            key_of(&with_proxy(&|p| p.port = 8081), &hop),
        ),
        (
            "proxy credentials",
            key_of(
                &with_proxy(&|p| p.auth = Some(ProxyAuth("bob:secret".into()))),
                &hop,
            ),
        ),
        (
            "proxy ?host=",
            key_of(
                &with_proxy(&|p| {
                    p.host_override = Some(HostOverride {
                        host: "10.0.0.2".into(),
                        port: None,
                    })
                }),
                &hop,
            ),
        ),
        (
            "proxyTunnel",
            key_of(&with_proxy(&|p| p.tunnel = true), &hop),
        ),
        (
            "User-Agent on CONNECT",
            key_of(
                &tls,
                &Hop {
                    user_agent: Some("ua/2".into()),
                    ..Hop::default()
                },
            ),
        ),
        (
            "disable://proxyConnection",
            key_of(
                &Target {
                    proxy_connection_close: true,
                    ..tls.clone()
                },
                &Hop {
                    proxy_connection_close: true,
                    ..Hop {
                        user_agent: Some("ua/1".into()),
                        client_proxy_auth: Some("Basic Y2xpZW50".into()),
                        ..Hop::default()
                    }
                },
            ),
        ),
    ];
    for (what, key) in &variants {
        assert_ne!(key, &base, "{what} must be part of the key");
    }
    // A connection made with an h2 offer may be h2; one made without never is.
    assert_ne!(
        pool_key(&tls, &hop, true),
        base,
        "the h2 offer must be part of the key"
    );

    // With no credentials of its own, the proxy is shown the client's, and
    // two clients' credentials are two identities.
    let anonymous = with_proxy(&|p| p.auth = None);
    let as_client = |auth: &str| {
        key_of(
            &anonymous,
            &Hop {
                client_proxy_auth: Some(auth.into()),
                ..Hop::default()
            },
        )
    };
    assert_ne!(as_client("Basic YQ=="), as_client("Basic Yg=="));
    // And a User-Agent only matters where it is sent: not on a direct hop.
    let direct_tls = Target {
        proxy: None,
        ..tls.clone()
    };
    assert_eq!(
        key_of(&direct_tls, &hop),
        key_of(&direct_tls, &Hop::default())
    );
}
