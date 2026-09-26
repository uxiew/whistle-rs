//! Rules a request brings in its own headers, end to end.
//!
//! `tests/differential/header-rules-bench.js` measures this against real
//! whistle and is the authority on what the behaviour *is*. It needs node and
//! an installed whistle, so it is not what `cargo test` runs. This file pins
//! the same facts through a real socket with nothing installed:
//!
//!   * the default refuses to read them, and strips them anyway;
//!   * `enableRequestHeaderRules` reads them and the stored rules still win;
//!   * `multiEnv` reads them and they win;
//!   * `x-whistle-rule-name` is the one that reaches the origin — except under
//!     `multiEnv`, where it is consumed and resolved.
//!
//! The origin echoes the headers it was given, so "what reached the origin" is
//! readable directly rather than inferred.

use std::collections::BTreeMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that answers with the request headers it saw, as JSON.
async fn echo_origin() -> std::net::SocketAddr {
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
                let body = seen.join("\n");
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

/// One request through the proxy, answered as the headers the origin saw.
async fn through(
    proxy: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    headers: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let req = format!(
        "GET http://{origin}/echo HTTP/1.1\r\nHost: {origin}\r\n{extra}Connection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read answer");
    let text = String::from_utf8_lossy(&out).into_owned();
    let body = match text.find("\r\n\r\n") {
        Some(at) => &text[at + 4..],
        None => panic!("no answer from the proxy: {text}"),
    };
    body.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A proxy with one stored rule and one named group, under a mode.
async fn proxy(origin: std::net::SocketAddr, mode: &str) -> whistle_rs::embed::Proxy {
    let mut builder = whistle_rs::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(std::env::temp_dir().join(format!(
            "whistle-rs-header-rules-e2e-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        )))
        .value("envA", format!("{origin} reqHeaders://x-mark-key=1"))
        .rules(format!("{origin} reqHeaders://x-who=stored"));
    if !mode.is_empty() {
        builder = builder.mode(mode);
    }
    builder.start().await.expect("proxy starts")
}

const RULES: &str = "x-whistle-rule-value";
const HOST: &str = "x-whistle-rule-host";
const KEY: &str = "x-whistle-rule-key";
const NAME: &str = "x-whistle-rule-name";
const KV: &str = "x-whistle-key-value";

/// Off is the default, and off does not mean "forwarded": the four are stripped
/// whatever the mode, which is what keeps a client's rules text away from the
/// origin — and away from any whistle further up the chain.
#[tokio::test]
async fn by_default_the_headers_are_taken_and_ignored() {
    let origin = echo_origin().await;
    let p = proxy(origin, "").await;
    let seen = through(
        p.addr(),
        origin,
        &[
            (
                RULES,
                &urlencode(&format!("{origin} reqHeaders://x-mark-hdr=1")),
            ),
            (
                HOST,
                &urlencode(&format!("{origin} reqHeaders://x-mark-host=1")),
            ),
            (KEY, "envA"),
            (KV, r#"{"pv":"x"}"#),
        ],
    )
    .await;
    assert_eq!(seen.get("x-who").map(String::as_str), Some("stored"));
    assert!(
        !seen.contains_key("x-mark-hdr"),
        "nothing was read: {seen:?}"
    );
    assert!(!seen.contains_key("x-mark-host"));
    assert!(!seen.contains_key("x-mark-key"));
    for name in [RULES, HOST, KEY, KV] {
        assert!(
            !seen.contains_key(name),
            "{name} reached the origin: {seen:?}"
        );
    }
}

/// `-M enableRequestHeaderRules`: read, and the stored rules still win. The
/// second half is the whole difference from `multiEnv`, and it is decided by
/// which way round upstream merges (`initRules`, `rules/index.js:647-652`).
#[tokio::test]
async fn the_console_keeps_the_last_word_under_enable_request_header_rules() {
    let origin = echo_origin().await;
    let p = proxy(origin, "enableRequestHeaderRules").await;

    let seen = through(
        p.addr(),
        origin,
        &[(
            RULES,
            &urlencode(&format!("{origin} reqHeaders://x-mark-hdr=1")),
        )],
    )
    .await;
    assert_eq!(seen.get("x-mark-hdr").map(String::as_str), Some("1"));
    assert_eq!(seen.get("x-who").map(String::as_str), Some("stored"));

    // Both set `x-who`. The stored rule is the one that answers.
    let seen = through(
        p.addr(),
        origin,
        &[(
            RULES,
            &urlencode(&format!("{origin} reqHeaders://x-who=header")),
        )],
    )
    .await;
    assert_eq!(seen.get("x-who").map(String::as_str), Some("stored"));
}

/// `-M multiEnv`: read, and the request wins.
#[tokio::test]
async fn the_request_wins_under_multi_env() {
    let origin = echo_origin().await;
    let p = proxy(origin, "multiEnv").await;
    let seen = through(
        p.addr(),
        origin,
        &[(
            RULES,
            &urlencode(&format!("{origin} reqHeaders://x-who=header")),
        )],
    )
    .await;
    assert_eq!(seen.get("x-who").map(String::as_str), Some("header"));
}

/// The other three readable headers: a line appended, a values entry prepended,
/// and a `{name}` answered by JSON the same request carried.
#[tokio::test]
async fn the_other_headers_compose_into_the_same_text() {
    let origin = echo_origin().await;
    let p = proxy(origin, "multiEnv").await;

    let seen = through(
        p.addr(),
        origin,
        &[(
            HOST,
            &urlencode(&format!("{origin} reqHeaders://x-mark-host=1")),
        )],
    )
    .await;
    assert_eq!(seen.get("x-mark-host").map(String::as_str), Some("1"));

    let seen = through(p.addr(), origin, &[(KEY, "envA")]).await;
    assert_eq!(seen.get("x-mark-key").map(String::as_str), Some("1"));

    // A name the store does not know contributes nothing, and is not an error.
    let seen = through(p.addr(), origin, &[(KEY, "no-such-value")]).await;
    assert_eq!(seen.get("x-who").map(String::as_str), Some("stored"));

    let seen = through(
        p.addr(),
        origin,
        &[
            (
                RULES,
                &urlencode(&format!("{origin} reqHeaders://x-mark-kv=${{pv}}")),
            ),
            (KV, r#"{"pv":"FROMKV"}"#),
        ],
    )
    .await;
    assert_eq!(seen.get("x-mark-kv").map(String::as_str), Some("FROMKV"));
}

/// The asymmetry that cost a bench run to find: `x-whistle-rule-name` reaches
/// the origin under every mode but `multiEnv`, because `getValue` — which is
/// what deletes — is the function upstream never calls for it otherwise.
#[tokio::test]
async fn the_name_header_is_the_one_that_travels_on() {
    let origin = echo_origin().await;
    for mode in ["", "enableRequestHeaderRules"] {
        let p = proxy(origin, mode).await;
        let seen = through(p.addr(), origin, &[(NAME, "Named")]).await;
        assert_eq!(
            seen.get(NAME).map(String::as_str),
            Some("Named"),
            "mode {mode:?} must forward it: {seen:?}"
        );
    }
    let p = proxy(origin, "multiEnv").await;
    let seen = through(p.addr(), origin, &[(NAME, "Named")]).await;
    assert!(!seen.contains_key(NAME), "multiEnv consumes it: {seen:?}");
}

/// `-M strict|multiEnv` takes the *reading* away and leaves the delete, which
/// is the shape of upstream's `getValue`: the `delete` is above the branch.
#[tokio::test]
async fn strict_takes_the_reading_and_not_the_delete() {
    let origin = echo_origin().await;
    let p = proxy(origin, "strict|multiEnv").await;
    let seen = through(
        p.addr(),
        origin,
        &[
            (
                RULES,
                &urlencode(&format!("{origin} reqHeaders://x-mark-hdr=1")),
            ),
            (NAME, "Named"),
        ],
    )
    .await;
    assert!(
        !seen.contains_key("x-mark-hdr"),
        "nothing is read: {seen:?}"
    );
    assert!(!seen.contains_key(RULES));
    assert!(
        !seen.contains_key(NAME),
        "multiEnv still consumes the name header: {seen:?}"
    );
}

/// Percent-encoded and raw both work — a client may send either, and upstream
/// honours either because `decodeURIComponent` leaves a text with no escapes
/// alone.
#[tokio::test]
async fn either_spelling_of_the_rules_text_is_honoured() {
    let origin = echo_origin().await;
    let p = proxy(origin, "multiEnv").await;
    for value in [
        urlencode(&format!("{origin} reqHeaders://x-mark-hdr=1")),
        format!("{origin} reqHeaders://x-mark-hdr=1"),
    ] {
        let seen = through(p.addr(), origin, &[(RULES, &value)]).await;
        assert_eq!(
            seen.get("x-mark-hdr").map(String::as_str),
            Some("1"),
            "{value}"
        );
    }
}

/// `encodeURIComponent`, for the characters these tests actually send.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
