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

/// A request to the console's own API on the proxy port, addressed the way a
/// client that dialled it would address it — by the address it dialled. The
/// console refuses a `Host` that is not one of its names, which is what stops
/// DNS rebinding; a made-up name here used to be accepted.
async fn console(
    proxy: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect console");
    let head = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: {proxy}\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => {
            format!("{method} {path} HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n\r\n")
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

fn proxy_with(rules: &str) -> impl std::future::Future<Output = whix::embed::Proxy> {
    let rules = rules.to_string();
    async move {
        whix::embed::Proxy::builder()
            .port(0)
            .persist_sessions(false)
            .storage_dir(std::env::temp_dir().join(format!(
                "whix-console-e2e-{}-{:?}",
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
fn frames_of(state: &Arc<whix::proxy::AppState>) -> Vec<(String, String)> {
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

/// One raw request with exactly the head given, answered as (status line, body).
async fn raw(proxy: std::net::SocketAddr, head: &str, body: &str) -> (String, String) {
    let mut sock = TcpStream::connect(proxy).await.expect("connect console");
    let request = format!(
        "{head}content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(request.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.lines().next().unwrap_or("").to_string();
    let body = text
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_string());
    (status, body)
}

/// The cross-site write, end to end: what a `<form enctype="text/plain">` or a
/// `fetch(…, {mode: "no-cors"})` on another site sends. It is refused, and the
/// rules are what they were — the refusal is not just a status code.
#[tokio::test]
async fn a_page_on_another_site_cannot_rewrite_the_rules() {
    let proxy = proxy_with("keep.test statusCode://204\n").await;
    let addr = proxy.addr();
    let (status, body) = raw(
        addr,
        &format!(
            "POST /api/rules HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://evil.example\r\n\
             content-type: text/plain\r\n"
        ),
        "* resWrite:///tmp/owned",
    )
    .await;
    assert!(status.contains(" 403 "), "{status}");
    assert!(body.contains("cross-site"), "{body}");
    let rules = console(addr, "GET", "/api/rules", None).await;
    assert!(rules.contains("keep.test statusCode://204"), "{rules}");
    assert!(!rules.contains("resWrite"), "{rules}");

    // The same write from the console's own page goes through.
    let (status, _) = raw(
        addr,
        &format!(
            "POST /api/rules HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
             content-type: text/plain\r\n"
        ),
        "changed.test statusCode://204",
    )
    .await;
    assert!(status.contains(" 200 "), "{status}");
    let rules = console(addr, "GET", "/api/rules", None).await;
    assert!(rules.contains("changed.test"), "{rules}");

    proxy.shutdown().await;
}

/// DNS rebinding, end to end: a page whose own name now resolves to the proxy
/// is same-origin with it, but its requests still say which name they used.
///
/// The name is not the console's, so the request is an ordinary one to be
/// forwarded — and forwarded, it would reach this proxy again. It is sent to
/// the console's own address with a 302 instead, which is a different origin
/// to the page: it cannot read what is there. The rebinding is simulated with
/// a rule, so the test does not depend on a resolver.
#[tokio::test]
async fn a_rebound_hostname_cannot_read_the_console() {
    let proxy = proxy_with("evil.example 127.0.0.1\n").await;
    let addr = proxy.addr();
    let port = addr.port();
    let (status, body) = raw(
        addr,
        &format!("GET /sessions.json HTTP/1.1\r\nHost: evil.example:{port}\r\n"),
        "",
    )
    .await;
    assert!(status.contains(" 302 "), "{status}");
    assert!(!body.contains('['), "a capture was served: {body}");
    let (status, _) = raw(
        addr,
        &format!("GET /sessions.json HTTP/1.1\r\nHost: localhost:{port}\r\n"),
        "",
    )
    .await;
    assert!(status.contains(" 200 "), "{status}");

    proxy.shutdown().await;
}

/// A request that reaches the proxy port without a proxy configured — its
/// `Host` names somebody else — is forwarded, as upstream forwards it
/// (`biz/index.js:98-106`). It used to be the console's, and after the
/// rebinding check a 403; upstream's own suite sends WebSockets this way.
#[tokio::test]
async fn a_request_for_another_name_is_forwarded_not_answered() {
    let origin = origin(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nfrom origin").await;
    let proxy = proxy_with(&format!("named.test {origin}\n")).await;
    let (status, body) = raw(proxy.addr(), "GET /x HTTP/1.1\r\nHost: named.test\r\n", "").await;
    assert!(status.contains(" 200 "), "{status}");
    assert_eq!(body, "from origin");

    proxy.shutdown().await;
}

/// The backstop: a request this proxy forwarded to itself comes back carrying
/// its own marker, and is refused rather than forwarded round again — for the
/// name that resolves here by an address the proxy did not know as its own.
#[tokio::test]
async fn a_request_that_comes_back_is_refused() {
    let proxy = proxy_with("").await;
    let (status, _) = raw(
        proxy.addr(),
        &format!(
            "GET /x HTTP/1.1\r\nHost: came-back.test\r\n{}: {}\r\n",
            whix::proxy::upstream::LOOP_HEADER,
            whix::proxy::upstream::loop_nonce()
        ),
        "",
    )
    .await;
    assert!(status.contains(" 508 "), "{status}");

    proxy.shutdown().await;
}

/// A body over the console's limit is refused whole, and changes nothing. Every
/// console route used to read its body with no limit, so one request could
/// make the proxy hold as much memory as it cared to send.
#[tokio::test]
async fn an_oversized_body_is_refused_and_changes_nothing() {
    let proxy = proxy_with("keep.test statusCode://204\n").await;
    let addr = proxy.addr();
    let huge = "x".repeat(whix::config::CONSOLE_BODY_LIMIT + 1);
    let (status, body) = raw(
        addr,
        &format!("POST /api/rules HTTP/1.1\r\nHost: {addr}\r\ncontent-type: text/plain\r\n"),
        &huge,
    )
    .await;
    assert!(status.contains(" 413 "), "{status}");
    assert!(body.contains("limit"), "{body}");
    let rules = console(addr, "GET", "/api/rules", None).await;
    assert!(rules.contains("keep.test statusCode://204"), "{rules}");

    // The JSON routes share the reader.
    let (status, _) = raw(
        addr,
        &format!("POST /api/values HTTP/1.1\r\nHost: {addr}\r\ncontent-type: application/json\r\n"),
        &huge,
    )
    .await;
    assert!(status.contains(" 413 "), "{status}");

    proxy.shutdown().await;
}

/// A plugin page is served behind the console's login and never sees it: the
/// console checked the credentials, and a plugin that received them could read
/// the admin password off its first request.
#[tokio::test]
async fn a_plugin_page_does_not_receive_the_console_login() {
    use whix::plugins::{PluginManifest, PluginReq, PluginResult, RustPlugin, ui};

    struct Echo;
    impl RustPlugin for Echo {
        fn name(&self) -> &str {
            "echo-ui"
        }
        fn on_request(&self, _req: &PluginReq) -> PluginResult {
            PluginResult::default()
        }
        fn manifest(&self) -> PluginManifest {
            let mut m = PluginManifest::v1_fallback(self.name());
            m.ui = true;
            m
        }
        fn ui(&self, req: &ui::UiReq) -> ui::UiResp {
            let names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
            ui::UiResp::html(names.join(","))
        }
    }

    let proxy = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(
            std::env::temp_dir().join(format!("whix-plugin-ui-login-{}", std::process::id())),
        )
        .plugin(Echo)
        .start()
        .await
        .expect("proxy starts");
    let addr = proxy.addr();
    let (status, body) = raw(
        addr,
        &format!(
            "GET /plugin/echo-ui/ HTTP/1.1\r\nHost: {addr}\r\n\
             Authorization: Basic YWRtaW46czNjcmV0\r\n\
             Proxy-Authorization: Basic YWRtaW46czNjcmV0\r\nx-probe: 1\r\n"
        ),
        "",
    )
    .await;
    assert!(status.contains(" 200 "), "{status}");
    assert!(
        body.contains("x-probe"),
        "the plugin saw the request: {body}"
    );
    assert!(!body.contains("authorization"), "{body}");

    proxy.shutdown().await;
}

/// The search box's `h:` and `b:`, which a list row cannot answer, answered by
/// the proxy over what it holds — and a condition it cannot answer refused in
/// the JSON everything else here refuses in.
#[tokio::test]
async fn headers_and_bodies_are_searched_by_the_proxy() {
    let site = origin(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nset-cookie: sid=abc\r\n\
content-length: 17\r\nConnection: close\r\n\r\n{\"success\":false}",
    )
    .await;
    let proxy = proxy_with("").await;
    let addr = proxy.addr();
    through_proxy(addr, &format!("http://{site}/api"), "").await;
    let id = until(async || {
        let held = proxy.state().sessions.lock().unwrap();
        held.iter()
            .find(|s| s.url.ends_with("/api") && s.res_body.is_some())
            .map(|s| s.id)
    })
    .await;

    // `b:"success":false` and `h:/sid=\w+/`, as `URLSearchParams` sends them.
    let found = console(
        addr,
        "GET",
        "/api/sessions/search?c=b%3A%22success%22%3Afalse&c=h%3A%2Fsid%3D%5Cw%2B%2F&c=b%3Anowhere",
        None,
    )
    .await;
    let found: serde_json::Value = serde_json::from_str(&found).expect("JSON");
    assert_eq!(found["scanned"], 1, "{found}");
    let ids = |i: usize| found["results"][i]["ids"].clone();
    assert_eq!(found["results"][0]["condition"], r#"b:"success":false"#);
    assert_eq!(ids(0), serde_json::json!([id]), "{found}");
    assert_eq!(ids(1), serde_json::json!([id]), "{found}");
    assert_eq!(ids(2), serde_json::json!([]), "{found}");
    assert_eq!(found["results"][2]["partly_kept"], serde_json::json!([]));

    let (status, body) = raw(
        addr,
        &format!("GET /api/sessions/search?c=m%3APOST HTTP/1.1\r\nHost: {addr}\r\n"),
        "",
    )
    .await;
    assert!(status.contains(" 400 "), "{status}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(body["ok"], false);
    assert!(
        body["error"].as_str().unwrap().contains("h: and b:"),
        "{body}"
    );
    proxy.shutdown().await;
}

/// Every refusal from the console's API has one shape: a 4xx, JSON, and
/// `{ok: false, error}` saying why. Some were plain text (`invalid JSON`),
/// some JSON without a content type, and one was JSON built with `format!`
/// that broke on the quotes in its own message.
#[tokio::test]
async fn every_api_refusal_is_json_saying_why() {
    let proxy = proxy_with("").await;
    let addr = proxy.addr();
    let cases: [(&str, &str, Option<&str>, u16); 10] = [
        ("POST", "/api/replay", Some("not json"), 400),
        ("POST", "/api/replay", Some("{}"), 400),
        ("POST", "/api/replay", Some(r#"{"id":999999}"#), 404),
        ("POST", "/api/values", Some("[1]"), 400),
        ("POST", "/api/value", Some("not json"), 400),
        (
            "POST",
            "/api/ws/send",
            Some(r#"{"id":1,"dir":"up","data":"x"}"#),
            400,
        ),
        (
            "POST",
            "/api/composer",
            Some(r#"{"method":"GET","url":"/only/a/path"}"#),
            400,
        ),
        ("GET", "/api/sessions/search", None, 400),
        ("GET", "/body.bin?id=999999&side=res", None, 404),
        ("GET", "/api/no-such-thing", None, 404),
    ];
    for (method, path, body, want) in cases {
        let head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let body = body.unwrap_or("");
        sock.write_all(
            format!(
                "{head}content-length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("write");
        let mut out = Vec::new();
        sock.read_to_end(&mut out).await.expect("read");
        let text = String::from_utf8_lossy(&out).into_owned();
        let (head, answer) = text.split_once("\r\n\r\n").expect("a response");
        let case = format!("{method} {path}");
        assert!(
            head.starts_with(&format!("HTTP/1.1 {want} ")),
            "{case}: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{case}: {head}"
        );
        let answer: serde_json::Value = serde_json::from_str(answer)
            .unwrap_or_else(|e| panic!("{case}: not JSON ({e}): {answer}"));
        assert_eq!(answer["ok"], false, "{case}: {answer}");
        assert!(
            answer["error"].as_str().is_some_and(|e| !e.is_empty()),
            "{case}: {answer}"
        );
    }
    proxy.shutdown().await;
}

/// `/sessions.json` as a cursor: `after` for what arrived since, `ids` for the
/// rows being watched, and `open` on a row whose response is still arriving —
/// here, an origin that sends half its body and waits.
#[tokio::test]
async fn the_session_list_can_be_polled_as_a_cursor() {
    let release = Arc::new(tokio::sync::Notify::new());
    let site = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let release = release.clone();
        tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhalf-")
                .await
                .unwrap();
            release.notified().await;
            sock.write_all(b"done!").await.unwrap();
        });
        addr
    };
    let proxy = proxy_with("").await;
    let addr = proxy.addr();
    let url = format!("http://{site}/slow");
    let client = tokio::spawn(async move { through_proxy(addr, &url, "").await });

    let rows = |q: &'static str| async move {
        let list = console(addr, "GET", &format!("/sessions.json{q}"), None).await;
        serde_json::from_str::<serde_json::Value>(&list).expect("json")
    };
    let row = until(async || {
        let list = rows("").await;
        list.as_array()?.first().cloned()
    })
    .await;
    let id = row["id"].as_u64().unwrap();
    assert_eq!(row["open"], true, "the body is still arriving: {row}");
    let detail = console(addr, "GET", &format!("/session.json?id={id}"), None).await;
    let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["open"], true, "{detail}");

    // `after` the newest id: nothing new. `ids` of the open one: that row.
    let after = console(addr, "GET", &format!("/sessions.json?after={id}"), None).await;
    assert_eq!(after, "[]");
    let before = console(
        addr,
        "GET",
        &format!("/sessions.json?after={}", id - 1),
        None,
    )
    .await;
    assert!(before.contains(&format!("\"id\":{id}")), "{before}");
    let watched = console(
        addr,
        "GET",
        &format!("/sessions.json?ids={id},999999"),
        None,
    )
    .await;
    let watched: serde_json::Value = serde_json::from_str(&watched).unwrap();
    assert_eq!(watched.as_array().unwrap().len(), 1, "{watched}");

    release.notify_one();
    let answer = client.await.unwrap();
    assert!(answer.ends_with("half-done!"), "{answer}");
    let done = until(async || {
        let list = console(addr, "GET", &format!("/sessions.json?ids={id}"), None).await;
        let list: serde_json::Value = serde_json::from_str(&list).ok()?;
        let row = list.as_array()?.first()?.clone();
        row.get("open").is_none().then_some(row)
    })
    .await;
    assert_eq!(done["down"], 10, "{done}");

    let (status, _) = raw(
        addr,
        &format!("GET /sessions.json?after=latest HTTP/1.1\r\nHost: {addr}\r\n"),
        "",
    )
    .await;
    assert!(status.contains(" 400 "), "{status}");
    proxy.shutdown().await;
}

/// The rewrite limit decides whether a rule's body operators run at all, and
/// an embedder can set it and read it back like the preview limit.
#[tokio::test]
async fn the_rewrite_limit_can_be_set_and_read_back() {
    let proxy = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(std::env::temp_dir().join(format!("whix-rewrite-cap-{}", std::process::id())))
        .body_rewrite_cap(64)
        .start()
        .await
        .expect("proxy starts");
    let status = console(proxy.addr(), "GET", "/api/status", None).await;
    let status: serde_json::Value = serde_json::from_str(&status).expect("json");
    assert_eq!(status["body_rewrite_cap"], 64, "{status}");
    proxy.shutdown().await;
}
