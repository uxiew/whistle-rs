//! The console, end to end: a real socket in, a real socket out, and the
//! console's own HTTP API asked what it saw.
//!
//! The unit tests reach the functions behind these features. What they cannot
//! reach is the path from *a request arriving* to *the console answering about
//! it* — the session id reserved before the body is built, the frames filed
//! under it, the API that reads them back. That path is where the last round of
//! console work lives (a body shown as frames, the Test Rules pane), and it had
//! no test that crossed a socket.
//!
//! `cases-frames.js` covers what the framing does to the **wire**, and
//! `frames-bench.js` covers the frames themselves — the two consoles have
//! different data models but the question "how many frames, carrying what" is
//! the same question, and both answer it over HTTP. (An earlier note here said
//! that comparison was impossible. It is not, and believing it was is how a real
//! divergence went unmeasured: a named separator framed here without the
//! `enable://captureStream` upstream requires.)
//!
//! What is left for this file is what has no counterpart at all: the session id
//! reserved before the body is built, the Test Rules API, and the refusals.
//!
//! Everything binds port 0 and cleans up after itself, so this runs under
//! `cargo test` like anything else.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that answers every request with the same fixed response.
///
/// Hand-rolled rather than hyper: the point is to control the bytes exactly,
/// including a `content-type` the framing keys off and a body whose separators
/// are the thing under test.
async fn origin(response: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Read the head, then answer. The bench's requests carry no
                // body, so the blank line is the end of what has to be read.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read_exact(&mut byte).await.is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = sock.write_all(response).await;
                let _ = sock.flush().await;
            });
        }
    });
    addr
}

/// One proxied request, written and read as bytes so the request line is
/// exactly what this test says it is.
async fn through_proxy(proxy: std::net::SocketAddr, url: &str, extra_headers: &str) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let req = format!(
        "GET {url} HTTP/1.1\r\nHost: origin.test\r\n{extra_headers}Connection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read answer");
    String::from_utf8_lossy(&out).into_owned()
}

/// A request to the console's own API on the proxy port.
async fn console(
    proxy: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect console");
    let head = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: console.test\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => {
            format!("{method} {path} HTTP/1.1\r\nHost: console.test\r\nConnection: close\r\n\r\n")
        }
    };
    sock.write_all(head.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    let text = String::from_utf8_lossy(&out).into_owned();
    // The body, which is all any caller here wants.
    match text.find("\r\n\r\n") {
        Some(at) => text[at + 4..].to_string(),
        None => text,
    }
}

/// Poll until the console has recorded something, or give up.
///
/// The capture is written after the response goes out, so a test that read the
/// answer is not thereby guaranteed to see the session. Polling rather than
/// sleeping keeps it fast when it is fast and honest when it is not.
async fn until<F, T>(mut f: F) -> T
where
    F: AsyncFnMut() -> Option<T>,
{
    for _ in 0..200 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the console never showed it");
}

fn proxy_with(rules: &str) -> impl std::future::Future<Output = whistle_rs::embed::Proxy> {
    let rules = rules.to_string();
    async move {
        whistle_rs::embed::Proxy::builder()
            .port(0)
            .persist_sessions(false)
            .storage_dir(std::env::temp_dir().join(format!(
                "whistle-rs-console-e2e-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )))
            .rules(rules)
            .start()
            .await
            .expect("proxy starts")
    }
}

/// Every frame the console has for a session, as `(direction, preview)`.
fn frames_of(state: &Arc<whistle_rs::proxy::AppState>) -> Vec<(String, String)> {
    state
        .ws_frames
        .lock()
        .unwrap()
        .iter()
        .map(|f| (f.dir.to_string(), f.preview.clone()))
        .collect()
}

const SSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 42\r\n\
Connection: close\r\n\r\ndata: one\n\ndata: two\n\ndata: three\n\n";

/// An event stream reaches the client whole **and** reaches the console as one
/// frame per event. Both halves matter: the framing runs inside the streaming
/// path, so a splitter that swallowed a boundary would corrupt the body, and
/// one that never ran would leave the panel empty.
#[tokio::test]
async fn an_event_stream_arrives_whole_and_is_shown_as_frames() {
    let addr = origin(SSE).await;
    let proxy = proxy_with(&format!("origin.test host://{addr}\n")).await;

    let answer = through_proxy(proxy.addr(), "http://origin.test/stream", "").await;
    assert!(
        answer.contains("data: one\n\ndata: two\n\ndata: three\n\n"),
        "{answer}"
    );

    let state = proxy.state().clone();
    let frames = until(async || {
        let f = frames_of(&state);
        (f.len() >= 3).then_some(f)
    })
    .await;
    let previews: Vec<&str> = frames.iter().map(|(_, p)| p.as_str()).collect();
    assert_eq!(previews, ["data: one", "data: two", "data: three"]);
    assert!(frames.iter().all(|(dir, _)| dir == "receive"), "{frames:?}");

    proxy.shutdown().await;
}

/// `disable://captureStream` leaves the same stream unframed, and the body is
/// still untouched. Without this the test above would pass just as well against
/// a build that framed everything unconditionally.
#[tokio::test]
async fn capture_stream_can_be_turned_off() {
    let addr = origin(SSE).await;
    let proxy = proxy_with(&format!(
        "origin.test host://{addr}\norigin.test disable://captureStream\n"
    ))
    .await;

    let answer = through_proxy(proxy.addr(), "http://origin.test/stream", "").await;
    assert!(answer.contains("data: one\n\ndata: two\n\n"), "{answer}");

    // The session lands even when the frames do not, so waiting for it is a
    // real wait rather than a fixed sleep.
    let state = proxy.state().clone();
    until(async || (!state.sessions.lock().unwrap().is_empty()).then_some(())).await;
    assert!(frames_of(&state).is_empty(), "{:?}", frames_of(&state));

    proxy.shutdown().await;
}

/// A header names the separator, and then it works **for any content type** —
/// which is how the FAQ turns a chunked JSON stream into frames. The header must
/// also not reach the client: `cases-frames.js` measures that on the wire, and
/// this measures it from the other side, where the frames exist at all.
///
/// **`enable://captureStream` is part of the recipe, not decoration.** Measured
/// through whistle's own frames API: a separator header with no flag produces no
/// frames there, on either side of the exchange, and it produces none here. The
/// FAQ's example carries the flag for that reason — and a header that arrives
/// from the origin, or from a whistle further up the chain, should not by itself
/// turn on body capture in this proxy.
#[tokio::test]
async fn a_named_separator_cuts_any_body_into_frames() {
    const BODY: &str = "{\"a\":1}|{\"b\":2}|{\"c\":3}";
    const NAMED: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
x-whistle-custom-frame-separator: |\r\ncontent-length: 23\r\nConnection: close\r\n\r\n\
{\"a\":1}|{\"b\":2}|{\"c\":3}";

    let named = origin(NAMED).await;
    let proxy = proxy_with(&format!(
        "origin.test host://{named}\norigin.test enable://captureStream\n"
    ))
    .await;
    let answer = through_proxy(proxy.addr(), "http://origin.test/x", "").await;
    assert!(
        answer.contains(BODY),
        "the body is forwarded whole: {answer}"
    );
    assert!(
        !answer
            .to_lowercase()
            .contains("x-whistle-custom-frame-separator"),
        "the separator header is the proxy's alone: {answer}"
    );
    let state = proxy.state().clone();
    let frames = until(async || {
        let f = frames_of(&state);
        (f.len() >= 3).then_some(f)
    })
    .await;
    assert_eq!(
        frames.iter().map(|(_, p)| p.as_str()).collect::<Vec<_>>(),
        ["{\"a\":1}", "{\"b\":2}", "{\"c\":3}"]
    );
    proxy.shutdown().await;

    // The control, and the gate: the **same** response, the same separator, and
    // no `enable://captureStream`. Upstream frames nothing here and neither does
    // this — otherwise a header sent by somebody else would be deciding what
    // this proxy holds on to.
    let named = origin(NAMED).await;
    let proxy = proxy_with(&format!("origin.test host://{named}\n")).await;
    let answer = through_proxy(proxy.addr(), "http://origin.test/x", "").await;
    assert!(answer.contains(BODY), "{answer}");
    let state = proxy.state().clone();
    until(async || (!state.sessions.lock().unwrap().is_empty()).then_some(())).await;
    assert!(frames_of(&state).is_empty(), "{:?}", frames_of(&state));

    proxy.shutdown().await;
}

/// The Test Rules pane's API: a rules text and a request, and what matched.
/// It runs no traffic at all, which is the point — it is how a rule is checked
/// before it is saved.
#[tokio::test]
async fn test_rules_answers_which_operators_matched() {
    let proxy = proxy_with("").await;
    let query = serde_json::json!({
        "rules": "www.example.com/api resHeaders://x-tag=1 reqHeaders://x-a=2\n\
                  www.other.com file:///tmp/nope",
        "url": "http://www.example.com/api?id=1",
        "method": "GET",
    });
    let body = console(
        proxy.addr(),
        "POST",
        "/api/explain",
        Some(&query.to_string()),
    )
    .await;
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        panic!("explain did not answer JSON: {e}; body was {body}");
    });
    let text = answer.to_string();
    assert!(text.contains("resHeaders"), "{text}");
    assert!(text.contains("reqHeaders"), "{text}");
    // The line that does not match must not be reported as if it did.
    assert!(!text.contains("/tmp/nope"), "{text}");

    proxy.shutdown().await;
}

/// A malformed Test Rules request is answered, not dropped: the pane reads
/// every reply as JSON, so a 400 that is not JSON is a pane that shows nothing.
#[tokio::test]
async fn test_rules_refuses_in_json() {
    let proxy = proxy_with("").await;
    let body = console(proxy.addr(), "POST", "/api/explain", Some("{not json")).await;
    let answer: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON: {e}; body was {body}"));
    assert_eq!(answer["ok"], serde_json::Value::Bool(false));
    assert!(answer["error"].is_string(), "{answer}");

    proxy.shutdown().await;
}

/// Sending a frame into a session that is not there is refused in the console's
/// own words rather than by a panic or a hang.
#[tokio::test]
async fn sending_a_frame_into_nothing_is_refused() {
    let proxy = proxy_with("").await;
    for (payload, expect) in [
        (
            r#"{"id":999999,"dir":"send","data":"hi"}"#,
            "no live WebSocket",
        ),
        (r#"{"dir":"send","data":"hi"}"#, "id is required"),
        (r#"{"id":1,"dir":"sideways","data":"hi"}"#, "dir must be"),
    ] {
        let body = console(proxy.addr(), "POST", "/api/ws/send", Some(payload)).await;
        assert!(body.contains(expect), "for {payload}: {body}");
    }

    proxy.shutdown().await;
}
