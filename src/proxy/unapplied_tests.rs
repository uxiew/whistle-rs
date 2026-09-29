//! A matched operator that did not take effect says so on its session — each
//! reason reproduced through the proxy against a local origin, beside the case
//! just inside the line where the operator does apply.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::tunnel_abort_tests::proxy_with_config;
use super::unapplied::Kind;
use super::{AppState, Session};

/// An origin that answers every request with `head` and then `body`.
async fn origin(head: &'static str, body: Vec<u8>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = l.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let head = head.replace("{len}", &body.len().to_string());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    addr
}

/// A request through the proxy, `Connection: close`, read to the end: the
/// response head and body.
async fn ask(proxy: SocketAddr, url: &str, extra: &str, body: &[u8]) -> (String, Vec<u8>) {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap();
    let method = if body.is_empty() { "GET" } else { "POST" };
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let head = format!(
        "{method} {url} HTTP/1.1\r\nHost: {host}\r\n{extra}content-length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await.unwrap();
    client.write_all(body).await.unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.ok();
    let at = got
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4;
    (
        String::from_utf8_lossy(&got[..at]).into_owned(),
        got[at..].to_vec(),
    )
}

/// The one session recorded, once it is complete.
async fn session(state: &Arc<AppState>) -> Session {
    for _ in 0..200 {
        if let Some(s) = state.sessions.lock().unwrap().front()
            && !s.error.is_open()
        {
            return s.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no session completed");
}

const TEXT: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n";

/// Over `--body-rewrite-limit` the response goes through as it arrived and the
/// session says which operator that left undone. At the limit — the comparison
/// is "over" — and under it, the operator applies and nothing is said.
#[tokio::test]
async fn a_response_over_the_rewrite_limit_names_the_operators_it_skipped() {
    for (len, rewritten) in [(65, false), (64, true), (10, true)] {
        let site = origin(TEXT, vec![b'a'; len]).await;
        let rules = format!("http://{site} resReplace://a=b resHeaders://x-seen=1");
        let (state, proxy) = proxy_with_config(&rules, |c| c.body_rewrite_cap = 64).await;
        let (head, body) = ask(proxy, &format!("http://{site}/x"), "", b"").await;
        assert!(head.contains("x-seen: 1"), "{head}");
        assert_eq!(body.len(), len, "the body arrives whole either way");
        assert_eq!(body.iter().all(|&b| b == b'b'), rewritten, "{len} bytes");
        let s = session(&state).await;
        if rewritten {
            assert!(s.unapplied.is_empty(), "{len}: {:?}", s.unapplied);
            continue;
        }
        let [u] = s.unapplied.as_slice() else {
            panic!("one reason: {:?}", s.unapplied)
        };
        assert_eq!(u.kind, Kind::BodyOverLimit);
        // Named by the token `rules` lists it under; the header operator,
        // which did apply, is not named.
        assert_eq!(u.ops, ["resReplace://a=b"]);
        assert!(s.rules.iter().any(|r| r.raw == u.ops[0]));
        assert!(u.reason.contains("64 bytes"), "{}", u.reason);
    }
}

/// A response no operator was waiting on says nothing, however big.
#[tokio::test]
async fn a_big_response_no_rule_touches_says_nothing() {
    let site = origin(TEXT, vec![b'a'; 200]).await;
    let (state, proxy) = proxy_with_config(&format!("http://{site} resHeaders://x=1"), |c| {
        c.body_rewrite_cap = 64
    })
    .await;
    ask(proxy, &format!("http://{site}/x"), "", b"").await;
    assert!(session(&state).await.unapplied.is_empty());
}

/// An origin that keeps each request body it receives and answers `ok`.
async fn keeper() -> (SocketAddr, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let kept: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let sink = kept.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = l.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = vec![0u8; 64 * 1024];
                let body = loop {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse().unwrap());
                    if got.len() >= at + 4 + len {
                        break got[at + 4..at + 4 + len].to_vec();
                    }
                };
                sink.lock().unwrap().push(body);
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, kept)
}

/// The request side has its own limit — 2 MiB unless a flag raises it — and
/// the same promise: over it, the body reaches the origin as the client sent
/// it, and the session names the operators that did not run on it.
#[tokio::test]
async fn a_request_over_its_limit_names_the_operators_it_skipped() {
    const LIMIT: usize = 2 * 1024 * 1024;
    for (len, rewritten) in [(LIMIT + 1, false), (LIMIT, true)] {
        let (site, kept) = keeper().await;
        let rules = format!("http://{site} reqReplace://a=b");
        let (state, proxy) = proxy_with_config(&rules, |_| {}).await;
        let sent = vec![b'a'; len];
        let (head, _) = ask(
            proxy,
            &format!("http://{site}/up"),
            "content-type: text/plain\r\n",
            &sent,
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let got = kept.lock().unwrap().pop().expect("the origin got a body");
        assert_eq!(got.len(), len, "the body arrives whole either way");
        assert_eq!(got.iter().all(|&b| b == b'b'), rewritten, "{len} bytes");
        let s = session(&state).await;
        match rewritten {
            true => assert!(s.unapplied.is_empty(), "{:?}", s.unapplied),
            false => {
                assert_eq!(s.unapplied.len(), 1, "{:?}", s.unapplied);
                assert_eq!(s.unapplied[0].kind, Kind::RequestBodyOverLimit);
                assert_eq!(s.unapplied[0].ops, ["reqReplace://a=b"]);
            }
        }
    }
}

/// An event stream is passed through as it arrives, never held until it ends:
/// the first event reaches the client while the origin is still holding the
/// stream open. What needs the whole body does not run and is named; what can
/// travel with the stream runs and is not.
#[tokio::test]
async fn an_event_stream_streams_and_names_what_needs_the_whole_body() {
    let release = Arc::new(tokio::sync::Notify::new());
    let site = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let release = release.clone();
        tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: one\n\n",
            )
            .await
            .unwrap();
            release.notified().await;
            let _ = sock.write_all(b"data: two\n\n").await;
        });
        addr
    };
    let rules =
        format!("http://{site} resReplace://one=ONE resMerge://{{\"a\":1}} htmlAppend://<b>x</b>");
    let (state, proxy) = proxy_with_config(&rules, |_| {}).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://{site}/events HTTP/1.1\r\nHost: {site}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    // The first event, rewritten by the one operator that travels, before
    // the origin has sent the second.
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("data: ONE") {
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("the first event arrives while the stream is open")
            .unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    release.notify_one();
    client.read_to_end(&mut got).await.ok();
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains("data: two\n\n"), "{text}");
    assert!(
        text.ends_with("0\r\n\r\n"),
        "the stream ended cleanly: {text}"
    );
    assert!(!text.contains("<b>x</b>"), "{text}");

    let s = session(&state).await;
    assert_eq!(s.unapplied.len(), 1, "{:?}", s.unapplied);
    assert_eq!(s.unapplied[0].kind, Kind::EventStream);
    assert_eq!(
        s.unapplied[0].ops,
        ["resMerge://{\"a\":1}", "htmlAppend://<b>x</b>"]
    );
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    super::coding::encode(super::coding::Coding::Gzip, bytes).expect("gzip")
}

/// A body this proxy cannot take out of its coding goes through exactly as it
/// arrived — not with the operators run over compressed bytes, which wrote
/// `resAppend` text after the end of a gzip stream — and the session says why.
/// A gzip that would inflate past the rewrite limit is one of them: the limit
/// bounds memory, and a small gzip can inflate to gigabytes.
#[tokio::test]
async fn a_body_that_cannot_be_undone_goes_through_as_it_arrived() {
    const GZ: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-encoding: gzip\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n";
    const ZSTD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-encoding: zstd\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n";
    let zeros = gzip(&[b'a'; 1000]);
    assert!(zeros.len() < 64, "small on the wire: {}", zeros.len());
    let cases: [(&str, &'static str, Vec<u8>, Option<Kind>); 4] = [
        (
            "corrupt",
            GZ,
            b"this is not gzip".to_vec(),
            Some(Kind::Undecodable),
        ),
        (
            "zstd",
            ZSTD,
            b"(zstd bytes)".to_vec(),
            Some(Kind::UnsupportedCoding),
        ),
        (
            "inflates past the limit",
            GZ,
            zeros,
            Some(Kind::DecodedOverLimit),
        ),
        ("the control", GZ, gzip(b"aaaa"), None),
    ];
    for (name, head, wire, kind) in cases {
        let site = origin(head, wire.clone()).await;
        let rules = format!("http://{site} resAppend://END");
        let (state, proxy) = proxy_with_config(&rules, |c| c.body_rewrite_cap = 64).await;
        let (_, body) = ask(proxy, &format!("http://{site}/x"), "", b"").await;
        let s = session(&state).await;
        match kind {
            Some(kind) => {
                assert_eq!(body, wire, "{name}: the bytes as they arrived");
                assert_eq!(s.unapplied.len(), 1, "{name}: {:?}", s.unapplied);
                assert_eq!(s.unapplied[0].kind, kind, "{name}");
                assert_eq!(s.unapplied[0].ops, ["resAppend://END"], "{name}");
            }
            None => {
                let plain = super::coding::decode(super::coding::Coding::Gzip, &body);
                assert_eq!(plain.as_deref(), Some(&b"aaaaEND"[..]), "{name}");
                assert!(s.unapplied.is_empty(), "{name}: {:?}", s.unapplied);
            }
        }
    }
}

/// The request side, the same way: a body whose coding will not undo reaches
/// the origin as the client sent it.
#[tokio::test]
async fn a_request_body_that_cannot_be_undone_reaches_the_origin_as_sent() {
    let (site, kept) = keeper().await;
    let (state, proxy) = proxy_with_config(&format!("http://{site} reqAppend://END"), |_| {}).await;
    let sent = b"this is not gzip";
    ask(
        proxy,
        &format!("http://{site}/up"),
        "content-type: text/plain\r\ncontent-encoding: gzip\r\n",
        sent,
    )
    .await;
    assert_eq!(kept.lock().unwrap().pop().as_deref(), Some(&sent[..]));
    let s = session(&state).await;
    assert_eq!(s.unapplied.len(), 1, "{:?}", s.unapplied);
    assert_eq!(s.unapplied[0].kind, Kind::Undecodable);
    assert!(
        s.unapplied[0].reason.contains("request body"),
        "{}",
        s.unapplied[0].reason
    );
}

/// A `cipher://` pin that cannot be used is dropped and the connection made
/// without it — on the record, where it used to be a WARN. The note rides on
/// whatever the session becomes; here the origin refuses TLS, so it is a
/// failed one, and says both things.
#[tokio::test]
async fn a_cipher_pin_that_cannot_be_used_is_named() {
    let site = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = l.accept().await {
                drop(sock);
            }
        });
        addr
    };
    let rules = format!("tls.test https://{site} cipher://NOTACIPHER disable://auto2http");
    let (state, proxy) = proxy_with_config(&rules, |_| {}).await;
    let (head, _) = ask(proxy, "http://tls.test/x", "", b"").await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    let s = session(&state).await;
    assert_eq!(
        s.error.get().map(|f| f.phase),
        Some(super::outcome::Phase::Tls)
    );
    assert_eq!(s.unapplied.len(), 1, "{:?}", s.unapplied);
    assert_eq!(s.unapplied[0].kind, Kind::CipherUnusable);
    assert_eq!(s.unapplied[0].ops, ["cipher://NOTACIPHER"]);

    // Over plain HTTP there is no handshake, so nothing to report missing.
    let plain = origin(TEXT, b"ok".to_vec()).await;
    let (state, proxy) =
        proxy_with_config(&format!("http://{plain} cipher://NOTACIPHER"), |_| {}).await;
    ask(proxy, &format!("http://{plain}/x"), "", b"").await;
    assert!(session(&state).await.unapplied.is_empty());
}
