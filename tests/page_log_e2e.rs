//! `log://`, end to end: the page a rule matched comes back carrying the
//! collector, what the collector posts is kept and never reaches the origin,
//! and the console's API reads it back.
//!
//! What the collector does *inside a page* — wrapping `console`, catching an
//! uncaught error — is run in `src/proxy/pagelog.rs`'s own tests, against the
//! same script. This file is the path around it: a socket in, a socket out.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

/// An origin that serves [`PAGE`] under a CSP that forbids inline script, and
/// counts what it is asked for.
async fn origin() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read_exact(&mut byte).await.is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let answer = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\n\
                     content-security-policy: script-src 'self'\r\ncontent-length: {}\r\n\
                     Connection: close\r\n\r\n{PAGE}",
                    PAGE.len()
                );
                let _ = sock.write_all(answer.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    (addr, hits)
}

/// One request through the proxy, as bytes; the whole answer back.
async fn through_proxy(proxy: std::net::SocketAddr, method: &str, url: &str, body: &str) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let req = format!(
        "{method} {url} HTTP/1.1\r\nHost: origin.test\r\ncontent-type: text/plain\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read answer");
    String::from_utf8_lossy(&out).into_owned()
}

/// The console's API, asked at the address the proxy listens on.
async fn console(
    proxy: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> serde_json::Value {
    let mut sock = TcpStream::connect(proxy).await.expect("connect console");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {proxy}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    let text = String::from_utf8_lossy(&out).into_owned();
    let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{path} answered {text:?}: {e}"))
}

async fn proxy_with(rules: String) -> whistle_rs::embed::Proxy {
    whistle_rs::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(std::env::temp_dir().join(format!(
            "whistle-rs-page-log-e2e-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        )))
        .rules(rules)
        .start()
        .await
        .expect("proxy starts")
}

#[tokio::test]
async fn a_page_under_a_log_rule_reports_to_the_console() {
    let (addr, hits) = origin().await;
    let proxy = proxy_with(format!(
        "origin.test host://{addr}\norigin.test log://audit\n"
    ))
    .await;
    let at = proxy.addr();

    // The page comes back with the collector in it, first thing in <head>,
    // and without the policy that would have stopped it running.
    let page = through_proxy(at, "GET", "http://origin.test/", "").await;
    let (head, body) = page.split_once("\r\n\r\n").expect("a response");
    assert!(
        body.starts_with("<!doctype html><html><head><script>;(function"),
        "{body}"
    );
    assert!(body.contains("var ID = 'audit';"), "{body}");
    assert!(
        body.ends_with("<title>t</title></head><body>hi</body></html>"),
        "{body}"
    );
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("content-security-policy"),
        "an inline script under `script-src 'self'` never runs: {head}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // What the collector posts, to the path on the page's own origin.
    let report = serde_json::json!({
        "page": "http://origin.test/",
        "list": [
            { "t": 1_700_000_000_000u64, "level": "warn", "id": "audit", "args": ["cart", "{\"items\":2}"] },
            { "t": 1_700_000_000_001u64, "level": "error", "id": "audit", "args": ["Error: boom\n    at f (a.js:1:2)"] },
            { "t": 1_700_000_000_002u64, "level": "nonsense", "id": "other", "args": ["x"] },
        ],
    })
    .to_string();
    let answer = through_proxy(at, "POST", "http://origin.test/.whistle-rs/log", &report).await;
    assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the report is this proxy's to answer; the origin never hears of it"
    );

    // …and the console has it.
    let got = console(at, "GET", "/api/logs", "").await;
    assert_eq!(got["ok"], true);
    assert_eq!(got["ids"], serde_json::json!(["audit", "other"]));
    assert_eq!(got["last"], 3);
    let logs = got["logs"].as_array().expect("logs");
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0]["level"], "warn");
    assert_eq!(
        logs[0]["args"],
        serde_json::json!(["cart", "{\"items\":2}"])
    );
    assert_eq!(logs[0]["page"], "http://origin.test/");
    assert_eq!(logs[0]["client_ip"], "127.0.0.1");
    assert_eq!(logs[1]["level"], "error");
    // A level nobody has is filed as a plain log rather than dropped.
    assert_eq!(logs[2]["level"], "log");

    // As a cursor, and by group.
    let newer = console(at, "GET", "/api/logs?after=2", "").await;
    assert_eq!(newer["logs"].as_array().map(Vec::len), Some(1));
    let one = console(at, "GET", "/api/logs?id=audit", "").await;
    assert_eq!(one["logs"].as_array().map(Vec::len), Some(2));
    assert_eq!(one["ids"], serde_json::json!(["audit", "other"]));

    // The report left no session: one row, the page's.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let urls: Vec<String> = proxy
        .state()
        .sessions
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.url.clone())
        .collect();
    assert_eq!(urls, ["http://origin.test/"]);

    // Cleared by group, then altogether; the numbering carries on.
    let cleared = console(at, "POST", "/api/logs/clear", "{\"id\":\"other\"}").await;
    assert_eq!(cleared["cleared"], 1);
    let cleared = console(at, "POST", "/api/logs/clear", "{}").await;
    assert_eq!(cleared["cleared"], 2);
    let empty = console(at, "GET", "/api/logs", "").await;
    assert_eq!(empty["logs"], serde_json::json!([]));
    assert_eq!(empty["last"], 3);

    proxy.shutdown().await;
}

/// `log://{name}`: the group is called `name`, and the value `name` holds goes
/// in as a second script, straight after the collector.
///
/// By the time the response is built the rule's value has already been swapped
/// for what the store holds, so the name has to be carried beside it. Read off
/// the value alone, this rule had no id and no script of its own.
#[tokio::test]
async fn a_named_value_is_the_group_and_a_second_script() {
    let (addr, _hits) = origin().await;
    let proxy = proxy_with(format!(
        "``` strip\nwindow.onBeforeWhistleLogSend = function () {{ return false; }};\n```\n\
         origin.test host://{addr}\norigin.test log://{{strip}}\n"
    ))
    .await;
    let page = through_proxy(proxy.addr(), "GET", "http://origin.test/", "").await;
    let body = page.split_once("\r\n\r\n").expect("a response").1;
    assert!(body.contains("var ID = 'strip';"), "{body}");
    let collector = body
        .find("window.__whistleRsLog = true")
        .expect("collector");
    let user = body
        .find("<script>window.onBeforeWhistleLogSend = function () { return false; };\n</script>")
        .unwrap_or_else(|| panic!("the value's script is not in the page: {body}"));
    assert!(collector < user, "the collector runs first");
    proxy.shutdown().await;
}

/// Without the rule the page is the origin's, byte for byte, policy and all —
/// and a report is still answered here rather than forwarded, because the path
/// is this proxy's whoever asks.
#[tokio::test]
async fn without_the_rule_nothing_is_injected() {
    let (addr, hits) = origin().await;
    let proxy = proxy_with(format!("origin.test host://{addr}\n")).await;
    let page = through_proxy(proxy.addr(), "GET", "http://origin.test/", "").await;
    let (head, body) = page.split_once("\r\n\r\n").expect("a response");
    assert_eq!(body, PAGE);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-security-policy"),
        "{head}"
    );

    // Not a report: refused, and still not forwarded.
    let answer = through_proxy(
        proxy.addr(),
        "POST",
        "http://origin.test/.whistle-rs/log",
        "not json",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    proxy.shutdown().await;
}
