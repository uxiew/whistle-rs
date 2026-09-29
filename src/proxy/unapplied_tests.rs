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
