//! Every way a request can fail, reproduced against local fixtures, and what
//! each one leaves behind: a session saying where it stopped, and — when the
//! client got an answer at all — a 502 that says it came from here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::outcome::Phase;
use super::tunnel_abort_tests::proxy_with;
use super::{AppState, ERROR_HEADER, SESSION_HEADER, Session};

/// A request through the proxy, `Connection: close` so reading to the end ends.
async fn ask(proxy: SocketAddr, url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    let mut client = TcpStream::connect(proxy).await.expect("proxy");
    client
        .write_all(
            format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.ok();
    String::from_utf8_lossy(&got).into_owned()
}

/// A header's value in a raw response, if it is there.
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The sessions recorded so far, oldest first — waiting up to two seconds for
/// there to be at least `n`, because a cancelled request is recorded when hyper
/// gets round to dropping it.
async fn sessions(state: &Arc<AppState>, n: usize) -> Vec<Session> {
    for _ in 0..200 {
        let got: Vec<Session> = state.sessions.lock().unwrap().iter().cloned().collect();
        if got.len() >= n {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    state.sessions.lock().unwrap().iter().cloned().collect()
}

/// The one session a single failed request must leave, checked for the parts
/// every failure shares: the phase, the status the client got, and — when it
/// got a 502 from here — the headers that say so and name the session.
async fn one_failure(state: &Arc<AppState>, response: &str, phase: Phase) -> Session {
    let got = sessions(state, 1).await;
    // Give a second, wrongly recorded session the chance to show up.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let got_now = state.sessions.lock().unwrap().len();
    assert_eq!(got.len(), 1, "exactly one session per request");
    assert_eq!(got_now, 1, "exactly one session per request");
    let s = got.into_iter().next().unwrap();
    let failure = s.error.get().unwrap_or_else(|| {
        panic!(
            "no failure recorded; target {:?}, status {}",
            s.target, s.status
        )
    });
    assert_eq!(failure.phase, phase, "{}", failure.message);
    if !response.is_empty() {
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert_eq!(s.status, 502);
        assert_eq!(header(response, ERROR_HEADER), Some(phase.as_str()));
        assert_eq!(
            header(response, SESSION_HEADER),
            Some(s.id.to_string().as_str()),
            "the 502 names the session it was recorded as"
        );
        // The client reads the same reason the console shows.
        assert!(response.contains(&failure.message), "{response}");
    }
    s
}

/// An address nothing listens on.
async fn refused() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// A server that accepts, reads what it is sent, and runs `then` on the socket.
async fn server<F, Fut>(then: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let then = Arc::new(then);
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            tokio::spawn(then(sock));
        }
    });
    addr
}

/// Reads the request, then hangs up without a word.
async fn hangs_up() -> SocketAddr {
    server(|mut sock| async move {
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
    })
    .await
}

/// Hangs up before reading anything — a TLS handshake or a SOCKS greeting sent
/// here gets nothing back.
async fn closes_at_once() -> SocketAddr {
    server(|sock| async move { drop(sock) }).await
}

/// A name no resolver will look up: a DNS label is at most 63 bytes, and this
/// one is 64. Refused before any query leaves the machine, so the test does not
/// depend on the network — a fake-IP resolver answers `.invalid` too.
fn unresolvable() -> String {
    format!("{}.example", "a".repeat(64))
}

#[tokio::test]
async fn a_name_that_does_not_resolve_fails_at_dns() {
    let (state, proxy) = proxy_with("").await;
    let url = format!("http://{}/x", unresolvable());
    let response = ask(proxy, &url).await;
    let s = one_failure(&state, &response, Phase::Dns).await;
    assert_eq!(s.url, url);
    assert_eq!(s.method, "GET");
    // The phases stop where it failed: no lookup finished, so none is shown.
    let timings = serde_json::to_value(s.timings.expect("measured")).unwrap();
    assert_eq!(timings, serde_json::json!({}), "{timings}");
}

#[tokio::test]
async fn a_refused_connection_fails_at_connect() {
    let dead = refused().await;
    let (state, proxy) = proxy_with("").await;
    let response = ask(proxy, &format!("http://{dead}/x")).await;
    let s = one_failure(&state, &response, Phase::Connect).await;
    assert_eq!(s.target, dead.to_string());
    // The lookup of an address literal finished; the connect did not.
    let timings = serde_json::to_value(s.timings.expect("measured")).unwrap();
    assert!(timings.get("dns").is_some(), "{timings}");
    assert!(timings.get("connect").is_none(), "{timings}");
}

#[tokio::test]
async fn a_server_that_will_not_shake_hands_fails_at_tls() {
    let origin = closes_at_once().await;
    // `disable://auto2http`: a local address otherwise gets a cleartext retry,
    // and then the failure reported is the retry's.
    let (state, proxy) =
        proxy_with(&format!("tls.test https://{origin} disable://auto2http")).await;
    let response = ask(proxy, "http://tls.test/x").await;
    let s = one_failure(&state, &response, Phase::Tls).await;
    let timings = serde_json::to_value(s.timings.expect("measured")).unwrap();
    assert!(timings.get("connect").is_some(), "{timings}");
    assert!(timings.get("ssl").is_none(), "{timings}");
}

/// A retry that fails too reports its own failure — it is what the client got
/// — and says what the first attempt died of, which is usually the real story.
#[tokio::test]
async fn a_failed_retry_keeps_the_first_attempts_reason() {
    let origin = closes_at_once().await;
    let (state, proxy) = proxy_with(&format!("tls.test https://{origin}")).await;
    let response = ask(proxy, "http://tls.test/x").await;
    let s = one_failure(&state, &response, Phase::Response).await;
    let message = s.error.get().unwrap().message;
    assert!(message.contains("upstream TLS handshake"), "{message}");
    assert!(message.contains("cleartext"), "{message}");
}

#[tokio::test]
async fn a_server_that_hangs_up_without_answering_fails_at_response() {
    let origin = hangs_up().await;
    let (state, proxy) = proxy_with("").await;
    let response = ask(proxy, &format!("http://{origin}/x")).await;
    let s = one_failure(&state, &response, Phase::Response).await;
    // What was sent is there to look at: the request did go out.
    assert!(
        s.req_headers.iter().any(|(k, _)| k == "host"),
        "{:?}",
        s.req_headers
    );
}

#[tokio::test]
async fn an_upstream_proxy_that_refuses_fails_at_proxy() {
    let socks = closes_at_once().await;
    let (state, proxy) = proxy_with(&format!("proxy.test socks://{socks}")).await;
    let response = ask(proxy, "http://proxy.test/x").await;
    let s = one_failure(&state, &response, Phase::Proxy).await;
    assert!(s.target.ends_with("(via proxy)"), "{}", s.target);
}

#[tokio::test]
async fn an_unreachable_upstream_proxy_fails_at_connect() {
    let dead = refused().await;
    let (state, proxy) = proxy_with(&format!("proxy.test proxy://{dead}")).await;
    let response = ask(proxy, "http://proxy.test/x").await;
    let s = one_failure(&state, &response, Phase::Connect).await;
    let failure = s.error.get().unwrap();
    assert!(failure.message.contains("proxy"), "{}", failure.message);
}

#[tokio::test]
async fn a_rule_that_cannot_be_carried_out_fails_at_rules() {
    let (state, proxy) = proxy_with("rules.test ws://127.0.0.1:9").await;
    let response = ask(proxy, "http://rules.test/x").await;
    let s = one_failure(&state, &response, Phase::Rules).await;
    // It failed before anything was dialled, so nothing was measured.
    assert!(s.timings.is_none());
    assert_eq!(s.rules.len(), 1, "the rule that failed is on the session");
}

/// An abort is recorded as the rule's doing — not as a client that hung up,
/// which is the other request that ends with no status at all.
#[tokio::test]
async fn an_abort_is_recorded_as_the_rules_doing() {
    let (state, proxy) = proxy_with("abort.test enable://abort").await;
    let response = ask(proxy, "http://abort.test/x").await;
    assert_eq!(response, "", "an abort answers nothing");
    let s = one_failure(&state, "", Phase::Abort).await;
    assert_eq!(s.status, 0);
}

/// The client gives up while the origin is still thinking. hyper drops the
/// request's future, and the session is recorded as the client's doing.
#[tokio::test]
async fn a_client_that_hangs_up_while_waiting_is_recorded() {
    let (seen, mut saw) = tokio::sync::mpsc::unbounded_channel::<()>();
    let origin = server(move |mut sock| {
        let seen = seen.clone();
        async move {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            seen.send(()).ok();
            // Never answer; hold the socket until the test is over.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })
    .await;
    let (state, proxy) = proxy_with("").await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/slow HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    saw.recv().await.expect("the request reached the origin");
    drop(client);
    let s = one_failure(&state, "", Phase::Client).await;
    assert_eq!(s.status, 0, "the client got nothing");
    assert_eq!(s.url, format!("http://{origin}/slow"));
}

/// A WebSocket handshake takes its own path to the origin, and fails the same
/// way on it.
#[tokio::test]
async fn an_upgrade_that_cannot_connect_fails_at_connect() {
    let dead = refused().await;
    let (state, proxy) = proxy_with("").await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{dead}/ws HTTP/1.1\r\nHost: {dead}\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut got = vec![0u8; 4096];
    let n = client.read(&mut got).await.unwrap();
    let response = String::from_utf8_lossy(&got[..n]).into_owned();
    let s = one_failure(&state, &response, Phase::Connect).await;
    assert_eq!(s.url, format!("ws://{dead}/ws"));
}

/// The control: an origin that answers 502 itself. That is a response, and
/// nothing about it is a failure here — which is the whole point of the header.
#[tokio::test]
async fn an_origins_own_502_is_not_a_failure() {
    let origin = server(|mut sock| async move {
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 2\r\nconnection: close\r\n\r\nno",
            )
            .await;
    })
    .await;
    let (state, proxy) = proxy_with("").await;
    let response = ask(proxy, &format!("http://{origin}/x")).await;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert_eq!(header(&response, ERROR_HEADER), None, "{response}");
    assert_eq!(header(&response, SESSION_HEADER), None, "{response}");
    let got = sessions(&state, 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].status, 502);
    assert!(got[0].error.is_ok(), "{:?}", got[0].error);
}
