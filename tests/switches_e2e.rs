//! The console's switches, through its API, as a request sees them: every rule
//! off and on again, a plugin off by name and all of them at once, and the
//! answers when a switch is not there to move.
//!
//! The HTTPS switch is tested where a tunnel decides, in `src/proxy/tunnel.rs`
//! (`the_https_switch_is_read_at_each_connect`); here only its API. Also here,
//! because it is how a plugin is most often named: `name://`, upstream's short
//! spelling of a plugin's rule.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that answers every request `origin`.
async fn origin() -> std::net::SocketAddr {
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
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nConnection: close\r\n\r\norigin",
                    )
                    .await;
            });
        }
    });
    addr
}

/// `GET url` through the proxy; the head and the body.
async fn get(proxy: std::net::SocketAddr, url: &str) -> (String, String) {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let host = url.split('/').nth(2).unwrap_or("");
    let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (head.to_ascii_lowercase(), body.to_string())
}

/// The console's API; the status and the JSON.
async fn api(
    proxy: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, serde_json::Value) {
    let mut sock = TcpStream::connect(proxy).await.expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {proxy}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let json = text.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    (
        status,
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{path}: {text:?}: {e}")),
    )
}

async fn proxy(rules: String, mode: Option<&str>) -> whix::embed::Proxy {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut builder = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(
            std::env::temp_dir().join(format!("whix-switches-e2e-{}-{n}", std::process::id())),
        )
        .rules(rules);
    if let Some(mode) = mode {
        builder = builder.mode(mode);
    }
    builder.start().await.expect("proxy starts")
}

#[tokio::test]
async fn every_rule_off_and_on_again() {
    let at = origin().await;
    let p = proxy(format!("{at} resHeaders://x-rule=1\n"), None).await;
    let url = format!("http://{at}/");

    assert!(get(p.addr(), &url).await.0.contains("x-rule: 1"));
    let (status, s) = api(p.addr(), "POST", "/api/switches", r#"{"rules":false}"#).await;
    assert_eq!(status, 200, "{s}");
    assert_eq!(s["rules"], false);
    let (head, body) = get(p.addr(), &url).await;
    assert!(!head.contains("x-rule"), "{head}");
    assert_eq!(body, "origin", "the request still goes through, untouched");

    // Kept for the next start by the binary, the one that reads it back; an
    // embedded proxy like this one keeps it in memory. See `data_dir_e2e.rs`.

    api(p.addr(), "POST", "/api/switches", r#"{"rules":true}"#).await;
    assert!(get(p.addr(), &url).await.0.contains("x-rule: 1"));
    // The groups' own switches were never touched.
    let (_, groups) = api(p.addr(), "GET", "/api/rule-groups", "").await;
    assert!(groups.to_string().contains("\"enabled\":true"), "{groups}");
    p.shutdown().await;
}

#[tokio::test]
async fn a_plugin_off_is_a_plugin_that_is_not_there() {
    let at = origin().await;
    // `echo` is built in: it answers the request itself.
    let p = proxy(format!("{at} plugin://echo\n"), None).await;
    let url = format!("http://{at}/");
    assert!(get(p.addr(), &url).await.1.contains("echo (rust)"));

    let (status, s) = api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"echo","on":false}"#,
    )
    .await;
    assert_eq!(status, 200, "{s}");
    assert_eq!(s["plugins_off"], serde_json::json!(["echo"]));
    assert_eq!(get(p.addr(), &url).await.1, "origin");

    api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"echo","on":true}"#,
    )
    .await;
    assert!(get(p.addr(), &url).await.1.contains("echo (rust)"));

    // All at once, without forgetting which were off one by one.
    api(p.addr(), "POST", "/api/switches", r#"{"plugins":false}"#).await;
    assert_eq!(get(p.addr(), &url).await.1, "origin");
    api(p.addr(), "POST", "/api/switches", r#"{"plugins":true}"#).await;
    assert!(get(p.addr(), &url).await.1.contains("echo (rust)"));

    // A name nothing is registered under is refused, not remembered.
    let (status, s) = api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"ehco","on":false}"#,
    )
    .await;
    assert_eq!(status, 404, "{s}");
    p.shutdown().await;
}

#[tokio::test]
async fn a_switch_a_mode_took_away_answers_409_and_changes_nothing() {
    let at = origin().await;
    let p = proxy(
        format!("{at} plugin://echo\n"),
        Some("notAllowedDisableRules|notAllowedDisablePlugins|notAllowedEnableHTTPS"),
    )
    .await;
    let (_, s) = api(p.addr(), "GET", "/api/switches", "").await;
    assert_eq!(s["rules_locked"], true);
    assert_eq!(s["plugins_locked"], true);
    assert_eq!(s["intercept_https_locked"], true);
    assert_eq!(s["intercept_https"], false);

    // Refused whole: the plugin half would have been allowed alone.
    for body in [
        r#"{"rules":false}"#,
        r#"{"plugins":false}"#,
        r#"{"intercept_https":true}"#,
        r#"{"plugins":true,"rules":false}"#,
    ] {
        let (status, s) = api(p.addr(), "POST", "/api/switches", body).await;
        assert_eq!(status, 409, "{body}: {s}");
    }
    let (status, _) = api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"echo","on":false}"#,
    )
    .await;
    assert_eq!(status, 409);
    assert!(
        get(p.addr(), &format!("http://{at}/"))
            .await
            .1
            .contains("echo (rust)")
    );

    // Malformed is 400, not 409.
    let (status, _) = api(p.addr(), "POST", "/api/switches", r#"{"rules":"no"}"#).await;
    assert_eq!(status, 400);
    p.shutdown().await;
}

/// `echo://hi` is the built-in `echo` plugin's rule, as `whistle.echo://hi`
/// is: it used to be read as a destination with the scheme `echo:` and failed
/// every request. A name no plugin has still is one — and still fails. Switched
/// off, the plugin is not there and the request reaches its origin.
#[tokio::test]
async fn a_plugin_name_is_a_protocol_of_its_own() {
    let at = origin().await;
    let p = proxy(
        format!("{at}/echo echo://hi\n{at}/nosuch nosuch://hi\n"),
        None,
    )
    .await;
    let (_, body) = get(p.addr(), &format!("http://{at}/echo")).await;
    assert!(body.contains("echo (rust)"), "{body}");

    let (head, body) = get(p.addr(), &format!("http://{at}/nosuch")).await;
    assert!(head.starts_with("http/1.1 502"), "{head}");
    assert!(body.contains("unsupported protocol nosuch:"), "{body}");

    api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"echo","on":false}"#,
    )
    .await;
    assert_eq!(
        get(p.addr(), &format!("http://{at}/echo")).await.1,
        "origin"
    );
    p.shutdown().await;
}

/// A plugin that hands back rules **and** the values they name — upstream's
/// `{rules, values}` — the way a mock plugin carries its bodies.
struct Mocks;

impl whix::plugins::RustPlugin for Mocks {
    fn name(&self) -> &str {
        "mocks"
    }

    fn on_request(&self, _req: &whix::plugins::PluginReq) -> whix::plugins::PluginResult {
        let mut values = std::collections::HashMap::new();
        values.insert("who".to_string(), "the plugin".to_string());
        values.insert("body".to_string(), "mocked by the plugin".to_string());
        whix::plugins::PluginResult {
            // The two `includeFilter://s:` lines are decided once the response
            // is in — PLUGINS.md offers that in place of `resRulesServer`.
            rules: Some(
                "* resHeaders://x-who=${who} resBody://{body}\n\
                 * resHeaders://x-on-200=1 includeFilter://s:200\n\
                 * resHeaders://x-on-404=1 includeFilter://s:404"
                    .into(),
            ),
            values,
            ..Default::default()
        }
    }
}

/// The plugin's values answer its own rules ahead of the store's entry of the
/// same name — and only its own: the console's rule on the same request still
/// reads the store.
#[tokio::test]
async fn a_plugins_rules_read_the_values_it_sent_with_them() {
    let at = origin().await;
    let p = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(
            std::env::temp_dir().join(format!("whix-switches-e2e-values-{}", std::process::id())),
        )
        .rules(format!(
            "{at} plugin://mocks reqHeaders://x-store=${{who}}\n"
        ))
        .value("who", "the store")
        .plugin(Mocks)
        .start()
        .await
        .expect("proxy starts");
    let (head, body) = get(p.addr(), &format!("http://{at}/")).await;
    assert!(head.contains("x-who: the plugin"), "{head}");
    assert_eq!(body, "mocked by the plugin");
    assert!(head.contains("x-on-200: 1"), "{head}");
    assert!(!head.contains("x-on-404"), "{head}");
    // What reached the origin carried the store's value: the plugin's are
    // private to the plugin's rules.
    let sent = p
        .state()
        .sessions
        .lock()
        .unwrap()
        .back()
        .expect("a session")
        .req_headers
        .clone();
    assert!(
        sent.iter().any(|(k, v)| k == "x-store" && v == "the store"),
        "{sent:?}"
    );
    p.shutdown().await;
}

/// A plugin that is nothing but the rules it brings — upstream's `rules.txt`.
struct Brings(std::net::SocketAddr);

impl whix::plugins::RustPlugin for Brings {
    fn name(&self) -> &str {
        "brings"
    }

    fn manifest(&self) -> whix::plugins::PluginManifest {
        let at = self.0;
        whix::plugins::PluginManifest {
            rules: Some(
                format!(
                    "* resHeaders://x-brought=1\n\
                     {at}/slot file://(from-the-plugin)\n\
                     {at}/only file://(only-the-plugin)\n\
                     {at}/imp file://(important-in-the-plugin) lineProps://important\n"
                )
                .into(),
            ),
            ..whix::plugins::PluginManifest::none("brings")
        }
    }

    fn on_request(&self, _req: &whix::plugins::PluginReq) -> whix::plugins::PluginResult {
        Default::default()
    }
}

/// The rules a plugin brings apply with no line naming it, rank below the
/// console's own (the slot `/slot` is the console's) unless they are
/// `important`, and go when the plugin is switched off.
#[tokio::test]
async fn a_plugins_own_rules_apply_below_the_consoles() {
    let at = origin().await;
    let p = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(
            std::env::temp_dir().join(format!("whix-switches-e2e-brings-{}", std::process::id())),
        )
        .rules(format!(
            "{at}/slot file://(from-the-console)\n{at}/imp file://(plain-in-the-console)\n"
        ))
        .plugin(Brings(at))
        .start()
        .await
        .expect("proxy starts");
    let (head, body) = get(p.addr(), &format!("http://{at}/")).await;
    assert!(head.contains("x-brought: 1"), "{head}");
    assert_eq!(body, "origin");
    assert_eq!(
        get(p.addr(), &format!("http://{at}/slot")).await.1,
        "from-the-console"
    );
    assert_eq!(
        get(p.addr(), &format!("http://{at}/only")).await.1,
        "only-the-plugin"
    );
    // As in one rules file: `important` outranks a plain line wherever it is.
    assert_eq!(
        get(p.addr(), &format!("http://{at}/imp")).await.1,
        "important-in-the-plugin"
    );

    api(
        p.addr(),
        "POST",
        "/api/plugin/switch",
        r#"{"name":"brings","on":false}"#,
    )
    .await;
    let (head, body) = get(p.addr(), &format!("http://{at}/only")).await;
    assert!(!head.contains("x-brought"), "{head}");
    assert_eq!(body, "origin");
    p.shutdown().await;
}
