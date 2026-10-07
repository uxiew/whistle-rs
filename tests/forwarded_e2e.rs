//! What a front proxy claims about a request, end to end.
//!
//! `tests/differential/forwarded-bench.js` measures this against real whistle
//! and is the authority on what the behaviour *is*. This file crosses a real
//! socket with nothing installed, and covers the wiring the unit tests in
//! `src/proxy/forwarded.rs` cannot reach: the `Host` the origin ends up seeing,
//! and the default port moving with a scheme the claim changed.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that answers with the `Host` it was given and the request line.
async fn echo_origin(name: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read_exact(&mut byte).await.is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let seen: Vec<String> = text
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| format!("{}={}", k.trim().to_ascii_lowercase(), v.trim()))
                    .collect();
                let body = format!("who={name}\n{}", seen.join("\n"));
                let answer = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(answer.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    addr
}

/// One request through the proxy; returns what the origin reported, or the
/// proxy's own status line when it never got there.
async fn through(
    proxy: std::net::SocketAddr,
    url: &str,
    host: &str,
    headers: &[(&str, &str)],
) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read answer");
    let text = String::from_utf8_lossy(&out).into_owned();
    match text.find("\r\n\r\n") {
        Some(at) if text.starts_with("HTTP/1.1 200") => text[at + 4..].to_string(),
        _ => text.lines().next().unwrap_or("(nothing)").to_string(),
    }
}

async fn proxy(rules: String, mode: &str) -> whix::embed::Proxy {
    let mut b = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(std::env::temp_dir().join(format!(
            "whix-forwarded-e2e-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        )))
        .rules(rules);
    if !mode.is_empty() {
        b = b.mode(mode);
    }
    b.start().await.expect("proxy starts")
}

const FWD_HOST: &str = "x-forwarded-host";
const FWD_PROTO: &str = "x-forwarded-proto";
const REAL_HOST: &str = "x-whistle-real-host";
const PROPS: &str = "x-whistle-forwarded-props";

/// Believing nothing is the default — and the two ungated headers are taken
/// anyway, so a claim this proxy did not act on is not handed to the origin
/// either.
#[tokio::test]
async fn nothing_is_believed_and_the_ungated_pair_is_still_taken() {
    let a = echo_origin("A").await;
    let b = echo_origin("B").await;
    let p = proxy(String::new(), "").await;
    let seen = through(
        p.addr(),
        &format!("http://{a}/echo"),
        &a.to_string(),
        &[
            (REAL_HOST, &b.to_string()),
            (PROPS, "host,proto,ip"),
            (FWD_HOST, &b.to_string()),
        ],
    )
    .await;
    assert!(seen.contains("who=A"), "the claim was not acted on: {seen}");
    assert!(
        !seen.contains(REAL_HOST),
        "and not forwarded either: {seen}"
    );
    assert!(!seen.contains(PROPS), "{seen}");
    // The gated one travels on: upstream's delete is inside the branch that did
    // not run, and dropping it would be this port inventing a policy.
    assert!(seen.contains(FWD_HOST), "{seen}");
}

/// `-M x-forwarded-host`: both spellings are believed, both are consumed, and
/// the `Host` the origin sees is the claimed one.
#[tokio::test]
async fn the_host_claim_redirects_and_rewrites_the_host_header() {
    let a = echo_origin("A").await;
    let b = echo_origin("B").await;
    let p = proxy(String::new(), "x-forwarded-host").await;

    for header in [FWD_HOST, REAL_HOST] {
        let seen = through(
            p.addr(),
            &format!("http://{a}/echo"),
            &a.to_string(),
            &[(header, &b.to_string())],
        )
        .await;
        assert!(seen.contains("who=B"), "{header}: {seen}");
        assert!(seen.contains(&format!("host={b}")), "{header}: {seen}");
        assert!(!seen.contains(header), "{header} must be consumed: {seen}");
    }

    // Both, disagreeing: the whistle spelling wins and the loser is still taken.
    let seen = through(
        p.addr(),
        &format!("http://{a}/echo"),
        &a.to_string(),
        &[(REAL_HOST, &b.to_string()), (FWD_HOST, &a.to_string())],
    )
    .await;
    assert!(seen.contains("who=B"), "{seen}");
    assert!(
        !seen.contains(FWD_HOST),
        "the losing claim must not travel on: {seen}"
    );
}

/// A request cannot open its own gate. Upstream lets `x-whistle-forwarded-props`
/// do exactly that — measured, with no mode set — and this is the divergence
/// `forwarded-bench.js` declares.
#[tokio::test]
async fn a_request_cannot_open_its_own_gate() {
    let a = echo_origin("A").await;
    let b = echo_origin("B").await;
    let p = proxy(String::new(), "").await;
    let seen = through(
        p.addr(),
        &format!("http://{a}/echo"),
        &a.to_string(),
        &[(PROPS, "host"), (FWD_HOST, &b.to_string())],
    )
    .await;
    assert!(seen.contains("who=A"), "the gate stayed shut: {seen}");
}

/// `-M x-forwarded-proto` changes **which pattern matches**, not the connection
/// this proxy makes — measured on upstream, where a request labelled `https`
/// still left over plain HTTP and still reached a plain origin.
#[tokio::test]
async fn the_proto_claim_decides_which_pattern_matches() {
    let a = echo_origin("A").await;
    let rules = format!(
        "https://{a}/echo reqHeaders://x-scheme=https\nhttp://{a}/echo reqHeaders://x-scheme=http"
    );
    let p = proxy(rules, "x-forwarded-proto").await;

    let plain = through(p.addr(), &format!("http://{a}/echo"), &a.to_string(), &[]).await;
    assert!(plain.contains("x-scheme=http"), "{plain}");

    let claimed = through(
        p.addr(),
        &format!("http://{a}/echo"),
        &a.to_string(),
        &[(FWD_PROTO, "https")],
    )
    .await;
    assert!(claimed.contains("x-scheme=https"), "{claimed}");
    assert!(!claimed.contains(FWD_PROTO), "consumed: {claimed}");
    assert!(
        claimed.contains("who=A"),
        "still the same connection: {claimed}"
    );
}

/// A default port moves with a scheme the claim changed: 80 and 443 are the
/// same request to two different servers, so a rule written for one must not
/// fire for the other. An explicit port stands.
#[tokio::test]
async fn a_default_port_moves_with_the_claimed_scheme() {
    let a = echo_origin("A").await;
    let rules = format!(
        "https://claimed.test/echo {a}\n\
         https://claimed.test:80/echo statusCode://418\n\
         http://claimed.test/echo statusCode://417"
    );
    let p = proxy(rules, "x-forwarded-proto").await;

    // No claim: port 80, the `http://` line answers.
    let plain = through(p.addr(), "http://claimed.test/echo", "claimed.test", &[]).await;
    assert!(plain.contains("417"), "{plain}");

    // Claimed https with no explicit port: 443, so the `:80` line must not fire
    // and the request goes where the plain `https://` line sends it.
    let claimed = through(
        p.addr(),
        "http://claimed.test/echo",
        "claimed.test",
        &[(FWD_PROTO, "https")],
    )
    .await;
    assert!(claimed.contains("who=A"), "{claimed}");
}

/// **The claim changes which pattern matches, and not the connection.**
///
/// The bug this pins: promoting the scheme promoted the *transport* too, so a
/// claimed `https` sent a ClientHello to a plain origin. It passed every
/// differential probe, because a failed handshake retries in plain and the
/// answer comes out the same — it only showed against an origin that read the
/// handshake instead of rejecting it, and then hung. Measured on upstream
/// afterwards: whistle sends no ClientHello at all here.
///
/// So this origin does not answer HTTP. It reports the **first byte**, and
/// `0x16` is a TLS record.
#[tokio::test]
async fn a_claimed_scheme_never_reaches_for_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u8>();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if sock.read_exact(&mut first).await.is_ok() {
                    let _ = tx.send(first[0]);
                }
                // Answered without reading the rest, so a handshake cannot hang
                // the test the way it hung the first version of this file.
                let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            });
        }
    });

    let rules = format!("https://{addr}/echo statusCode://418");
    let p = proxy(rules, "x-forwarded-proto").await;
    let answer = through(
        p.addr(),
        &format!("http://{addr}/echo"),
        &addr.to_string(),
        &[(FWD_PROTO, "https")],
    )
    .await;
    // The `https://` rule matched — so the claim was believed.
    assert!(
        answer.contains("418"),
        "the claim was not believed: {answer}"
    );

    // And nothing was ever spoken at the origin, because the rule answered
    // outright. Now one that does reach it.
    let p = proxy(String::new(), "x-forwarded-proto").await;
    let _ = through(
        p.addr(),
        &format!("http://{addr}/echo"),
        &addr.to_string(),
        &[(FWD_PROTO, "https")],
    )
    .await;
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the origin was never reached")
        .expect("channel closed");
    assert_eq!(
        first,
        b'G',
        "the origin was spoken to in {}, not HTTP",
        match first {
            0x16 => "TLS".to_string(),
            b => format!("{b:#04x}"),
        }
    );
}

/// A claim that is not a destination is obeyed and fails, rather than being
/// ignored and quietly sending the request to the original one. Upstream
/// answers 502 for this; so does the port.
#[tokio::test]
async fn an_unusable_claim_fails_visibly() {
    let a = echo_origin("A").await;
    let p = proxy(String::new(), "x-forwarded-host").await;
    let seen = through(
        p.addr(),
        &format!("http://{a}/echo"),
        &a.to_string(),
        &[(FWD_HOST, ":::not-a-host")],
    )
    .await;
    assert!(
        !seen.contains("who=A"),
        "it must not go to the old destination: {seen}"
    );
    assert!(seen.contains("502"), "{seen}");
}

/// The client's `Proxy-Authorization` is its credential for *this* proxy and
/// stops here: an origin reached directly never sees it (whistle 2.10.8
/// forwards it, measured — a proxy password configured in a browser reached
/// every site). A `Proxy-Authorization` a rule sets on purpose still goes out.
#[tokio::test]
async fn the_clients_proxy_credential_does_not_reach_the_origin() {
    let a = echo_origin("A").await;
    let p = proxy(
        format!(
            "{a}/by-rule auth://{{\"proxy\":true,\"username\":\"admin\",\"password\":\"secret\"}}"
        ),
        "",
    )
    .await;
    let direct = through(
        p.addr(),
        &format!("http://{a}/direct"),
        &a.to_string(),
        &[("proxy-authorization", "Basic dXNlcjpwYXNz")],
    )
    .await;
    assert!(direct.starts_with("who=A"), "{direct}");
    assert!(!direct.contains("proxy-authorization"), "{direct}");

    let by_rule = through(
        p.addr(),
        &format!("http://{a}/by-rule"),
        &a.to_string(),
        &[],
    )
    .await;
    assert!(
        by_rule.contains("proxy-authorization=Basic YWRtaW46c2VjcmV0"),
        "{by_rule}"
    );
}
