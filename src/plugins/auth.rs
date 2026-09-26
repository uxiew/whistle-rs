//! The `auth` hook — a plugin that decides whether a request may proceed.
//!
//! ## Where it runs, and why not in the proxy
//!
//! Auth is a *gate in front of a plugin's request hook*, not a new stage of the
//! request path. The proxy already walks the matched plugins in rule order and
//! already knows what to do with the two things a gate produces — a response
//! that short-circuits the upstream, and headers to set on the request it lets
//! through. So the gate lives inside the plugin runtime's request dispatch
//! ([`super::Plugins::on_request`]): declaring `auth` costs a `bool` test on the
//! cached manifest, and a request that matches no plugin never reaches this
//! module at all.
//!
//! That placement also gets the ordering right for free. Upstream stops the
//! moment one plugin forbids — the remaining plugins' rule hooks are not run
//! (`lib/plugins/index.js:929-960`). Here, a denial is returned as
//! [`super::PluginResult::response`], and the proxy's plugin loop returns on the
//! first response it is handed. Same rule, no new code.
//!
//! ## Fail closed
//!
//! Everywhere else in this plugin system a broken plugin degrades to "no
//! change": a pipe that will not open forwards the body, a frame hook that dies
//! is unhooked, a request hook that times out is a no-op. Those are cosmetic
//! properties, and the request is better off proceeding.
//!
//! Auth is not cosmetic. A gate that admits everything when it breaks is not a
//! gate, so **every failure blocks**: unreachable plugin, timeout, non-2xx,
//! reply we cannot parse. Upstream lands in the same place from the other
//! direction — its `authReq` treats a transport error exactly like a refusal
//! (`if (err || body)` → forbidden) and gives it a `502` rather than the `403`
//! of a deliberate refusal (`lib/plugins/index.js:836-846`, `:951`). The status
//! code is how the two are told apart, and this module keeps that distinction.
//!
//! The one deliberate exception: a **successful reply with an empty body** —
//! `204`, or `200` with nothing in it — is an *allow*. That is this protocol's
//! "nothing to say" everywhere else, and upstream agrees (an auth server that
//! writes no body has not forbidden anything). A reply with a body we cannot
//! understand is the opposite case: the plugin tried to say something and we
//! failed to hear it, which is the one situation where guessing "allow" is
//! unsafe.
//!
//! ## The shapes of a denial
//!
//! Upstream turns a refusal into synthetic rules, of which there are three
//! (`lib/plugins/index.js:936-959`):
//!
//! | upstream | rules it parses | here |
//! |----------|-----------------|------|
//! | `req.setUrl` / `setFile` | `* ignore://… method://get <url>` | [`DenyPage::Fetch`] |
//! | `req.setRedirect` | `* ignore://!redirect redirect://<url>` | [`DenyPage::Redirect`] |
//! | `req.setHtml` / nothing | `* status://<code> resBody://{msg} resType://html` | [`DenyPage::Html`] |
//!
//! whistle-rs renders them directly instead of routing them back through the
//! rule engine. The synthetic rules exist upstream because a refusal has to
//! re-enter a pipeline that only speaks rules; every one of them is pinned with
//! `ignore://` so that nothing else can touch the result. Rendering the response
//! here reaches the same place with less machinery — and, unlike injected rules,
//! it stops the plugin chain, which is the part that matters.

use std::time::Duration;

use super::{PluginReq, PluginResp};

/// How long to wait for a verdict before giving up — and, since this is a
/// security gate, blocking.
///
/// Generous, because a false denial is worse than a slow one and the plugin is
/// a local process: the budget only ever binds when a plugin has genuinely
/// stopped answering.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for fetching a [`DenyPage::Fetch`] block page.
///
/// Much tighter than [`AUTH_TIMEOUT`]: the verdict is already known by then and
/// a page that will not load only costs the client a nicer-looking `403`.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Ceiling on a block page held in memory. Upstream caps the same thing
/// (`MAX_BODY_SIZE`, `lib/plugins/load-plugin.js:1815-1818`).
const MAX_PAGE_BYTES: usize = 1024 * 1024;

/// Body of a refusal that carries no page of its own — upstream's default
/// (`lib/plugins/load-plugin.js:1819`).
const DEFAULT_BODY: &str = "Forbidden";

/// Marks a blocked response, so a refusal is recognisable in the Network panel
/// without reading the body.
pub const AUTH_HEADER: &str = "x-whistle-rs-auth";

/// What an auth plugin decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVerdict {
    /// Let the request through, after setting these request headers.
    Allow(Vec<(String, String)>),
    /// Stop the request and answer with this.
    Deny(Denial),
}

/// A refusal, before it is rendered into a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Denial {
    /// Status the plugin asked for. Honoured only in `300..=599` — a blocked
    /// request must never come back `2xx`.
    pub status: Option<u16>,
    /// Ask the client for credentials: `401` plus `www-authenticate`
    /// (`407`/`proxy-authenticate` if the plugin chose that status).
    pub login: bool,
    /// What the client sees.
    pub page: DenyPage,
    /// Why, for the log. Set when the *plugin* failed rather than refused.
    pub reason: Option<String>,
}

/// What a blocked client is served.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DenyPage {
    /// A plain refusal — [`DEFAULT_BODY`].
    #[default]
    Default,
    /// Literal bytes, from `setHtml`.
    Html(Vec<u8>),
    /// A `location:` redirect, from `setRedirect`.
    Redirect(String),
    /// Fetch this URL (or read this file) and serve it, from `setUrl`/`setFile`.
    Fetch(String),
}

impl Denial {
    /// The plugin refused deliberately.
    pub fn forbidden() -> Self {
        Denial::default()
    }

    /// The plugin *failed*: unreachable, slow, or incomprehensible. Distinct
    /// from a refusal, and given upstream's `502` so the two never look alike.
    pub fn failed(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Denial {
            status: Some(502),
            login: false,
            page: DenyPage::Html(format!("Plugin auth failed: {reason}").into_bytes()),
            reason: Some(reason),
        }
    }
}

/// Whether an auth plugin may set this request header on a request it admits.
///
/// Upstream restricts the same set twice — once when the plugin calls
/// `req.setHeader` (`lib/plugins/load-plugin.js:1757-1768`) and again when the
/// core copies the reply's headers onto the request
/// (`lib/plugins/index.js:878-895`). The second check is the load-bearing one
/// and it is the one reproduced here: the plugin is not the security boundary,
/// so its own filtering cannot be trusted to have happened. An auth hook exists
/// to *identify* a request, not to rewrite it.
pub fn allowed_request_header(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.starts_with("x-whistle-") || n == "proxy-authorization"
}

/// The `POST /auth` payload. Deliberately body-free: a gate that buffered
/// request bodies would tax every authenticated upload, and upstream's auth hook
/// does not receive one either.
pub fn payload(req: &PluginReq) -> serde_json::Value {
    serde_json::json!({
        "id": req.id,
        "method": req.method,
        "url": req.url,
        "headers": req.headers.iter().map(|(k, v)| serde_json::json!([k, v])).collect::<Vec<_>>(),
        "clientIp": req.client_ip,
        "param": req.param,
    })
}

/// Interpret a `200`/`204` reply body.
///
/// An empty body is an allow (see the module docs); anything that is not a JSON
/// object is a failure, and failures block.
pub fn parse_reply(bytes: &[u8]) -> AuthVerdict {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return AuthVerdict::Allow(Vec::new());
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return AuthVerdict::Deny(Denial::failed("auth reply was not JSON"));
    };
    if !v.is_object() {
        return AuthVerdict::Deny(Denial::failed("auth reply was not an object"));
    }
    // Absent `allow` means "no opinion", which is an allow: a plugin that means
    // to block says so.
    if v.get("allow").and_then(|a| a.as_bool()).unwrap_or(true) {
        return AuthVerdict::Allow(admitted_headers(v.get("setHeaders")));
    }

    // Precedence follows upstream, where each setter clears the others and the
    // reader checks location, then url, then html
    // (`lib/plugins/load-plugin.js:1806-1820`).
    let text = |key: &str| {
        v.get(key)
            .and_then(|s| s.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let page = if let Some(url) = text("redirect").filter(|u| sane_header_value(u)) {
        DenyPage::Redirect(url)
    } else if let Some(url) = text("url").or_else(|| text("file")) {
        DenyPage::Fetch(url)
    } else if let Some(html) = v.get("html").or_else(|| v.get("body")) {
        match html {
            serde_json::Value::String(s) => DenyPage::Html(s.clone().into_bytes()),
            serde_json::Value::Null => DenyPage::Default,
            other => DenyPage::Html(other.to_string().into_bytes()),
        }
    } else {
        DenyPage::Default
    };

    AuthVerdict::Deny(Denial {
        status: v
            .get("statusCode")
            .or_else(|| v.get("status"))
            .and_then(|s| s.as_u64())
            .and_then(|s| u16::try_from(s).ok()),
        login: v.get("login").and_then(|l| l.as_bool()).unwrap_or(false),
        page,
        reason: None,
    })
}

/// The `x-whistle-*` / `proxy-authorization` subset of a reply's `setHeaders`.
fn admitted_headers(v: Option<&serde_json::Value>) -> Vec<(String, String)> {
    super::parse_headers_value(v)
        .into_iter()
        .filter(|(k, v)| allowed_request_header(k) && sane_header_value(v))
        .collect()
}

/// Render a refusal.
///
/// `plugin` names the gate that produced it, both in the log and in the
/// [`AUTH_HEADER`] on the response.
pub async fn deny_response(plugin: &str, denial: &Denial) -> PluginResp {
    let mut headers: Vec<(String, String)> = vec![(AUTH_HEADER.to_string(), plugin.to_string())];
    let mut body = Vec::new();
    let mut content_type = "text/html; charset=utf-8";
    let mut redirected = false;

    match &denial.page {
        DenyPage::Default => {}
        DenyPage::Html(html) => body = truncate(html.clone()),
        DenyPage::Redirect(url) => {
            headers.push(("location".to_string(), url.clone()));
            redirected = true;
        }
        DenyPage::Fetch(url) => match fetch_page(url).await {
            Ok((bytes, ct)) => {
                body = bytes;
                content_type = ct;
            }
            // The verdict stands; only the prettier page is lost.
            Err(e) => {
                tracing::warn!("auth {plugin}: block page {url} unavailable: {e:#}");
                body = DEFAULT_BODY.as_bytes().to_vec();
            }
        },
    }
    if body.is_empty() && !redirected {
        body = DEFAULT_BODY.as_bytes().to_vec();
    }

    let status = denial
        .status
        .filter(|s| (300..=599).contains(s))
        .unwrap_or(if redirected {
            302
        } else if denial.login {
            401
        } else {
            403
        });
    if !redirected {
        headers.push(("content-type".to_string(), content_type.to_string()));
    }
    // whistle sends the matching challenge header with either login status
    // (`lib/util/index.js:398-403`); without it a browser never shows the box.
    if denial.login || status == 401 || status == 407 {
        let (name, value) = if status == 407 {
            ("proxy-authenticate", "Basic realm=\"whistle-rs\"")
        } else {
            ("www-authenticate", "Basic realm=\"whistle-rs\"")
        };
        headers.push((name.to_string(), value.to_string()));
    }

    PluginResp {
        status,
        headers,
        body,
    }
}

/// Load a `setUrl`/`setFile` block page.
///
/// Upstream serves the same thing by rewriting the request to a `GET` of that
/// URL (`method://get`, `lib/plugins/index.js:940-944`), so this is a plain GET
/// too. A bare path — or a `file://` URL — is read from disk, matching upstream's
/// `'file://' + authHtmlUrl` fallback for a value that is not a URL
/// (`lib/plugins/index.js:868`).
async fn fetch_page(url: &str) -> anyhow::Result<(Vec<u8>, &'static str)> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let (status, bytes) =
            tokio::time::timeout(FETCH_TIMEOUT, crate::proxy::upstream::simple_get(url))
                .await
                .map_err(|_| anyhow::anyhow!("timed out after {FETCH_TIMEOUT:?}"))??;
        if status != 200 {
            anyhow::bail!("status {status}");
        }
        return Ok((truncate(bytes.to_vec()), content_type_for(url)));
    }
    let path = url.strip_prefix("file://").unwrap_or(url);
    let data = tokio::fs::read(path).await?;
    Ok((truncate(data), content_type_for(path)))
}

/// Content type of a block page, from its extension. Deliberately tiny: a block
/// page is a page, and upstream forces `resType://html` for every shape but this
/// one.
fn content_type_for(path: &str) -> &'static str {
    let ext = path
        .rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.split(['?', '#']).next().unwrap_or(e).to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "json" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        _ => "text/html; charset=utf-8",
    }
}

/// Clamp a block page to [`MAX_PAGE_BYTES`].
fn truncate(mut data: Vec<u8>) -> Vec<u8> {
    data.truncate(MAX_PAGE_BYTES);
    data
}

/// Whether a string can be sent as a header value at all.
///
/// Load-bearing rather than tidy: the proxy builds a plugin response with
/// `Response::builder`, and one rejected header value there discards the whole
/// response — including its status. A refusal that degraded into a `200` because
/// of a newline in a redirect URL would be a fail-*open*, so anything that
/// cannot be a header value never becomes one.
fn sane_header_value(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn deny(json: &str) -> Denial {
        match parse_reply(json.as_bytes()) {
            AuthVerdict::Deny(d) => d,
            AuthVerdict::Allow(_) => panic!("expected a denial from {json}"),
        }
    }

    #[test]
    fn allow_shapes() {
        assert_eq!(parse_reply(b"{}"), AuthVerdict::Allow(Vec::new()));
        assert_eq!(
            parse_reply(br#"{"allow":true}"#),
            AuthVerdict::Allow(Vec::new())
        );
        // An empty successful reply is "nothing to say", which is an allow.
        assert_eq!(parse_reply(b""), AuthVerdict::Allow(Vec::new()));
        assert_eq!(parse_reply(b"  \n"), AuthVerdict::Allow(Vec::new()));
    }

    /// The fail-closed half: a reply we cannot understand blocks, and says so
    /// with 502 rather than the 403 of a deliberate refusal.
    #[test]
    fn unparseable_reply_blocks() {
        for raw in ["not json", "[1,2]", "\"yes\"", "null"] {
            let d = deny(raw);
            assert_eq!(d.status, Some(502), "{raw} should fail closed");
            assert!(d.reason.is_some());
        }
    }

    #[test]
    fn admitted_headers_are_restricted() {
        let v = parse_reply(
            br#"{"allow":true,"setHeaders":{"x-whistle-user":"bob","proxy-authorization":"Basic x",
                 "cookie":"nope","x-other":"nope","x-whistle-bad":"a\nb"}}"#,
        );
        let AuthVerdict::Allow(headers) = v else {
            panic!("expected allow");
        };
        assert_eq!(
            headers,
            // Source order, not alphabetical: upstream walks `Object.keys`.
            vec![
                ("x-whistle-user".to_string(), "bob".to_string()),
                ("proxy-authorization".to_string(), "Basic x".to_string()),
            ]
        );
    }

    #[test]
    fn deny_shapes_and_precedence() {
        assert_eq!(deny(r#"{"allow":false}"#).page, DenyPage::Default);
        assert_eq!(
            deny(r#"{"allow":false,"html":"<b>no</b>"}"#).page,
            DenyPage::Html(b"<b>no</b>".to_vec())
        );
        assert_eq!(
            deny(r#"{"allow":false,"url":"http://a/b.html"}"#).page,
            DenyPage::Fetch("http://a/b.html".into())
        );
        // location wins over url wins over html, as upstream reads them.
        assert_eq!(
            deny(r#"{"allow":false,"redirect":"http://a/","url":"http://b/","html":"x"}"#).page,
            DenyPage::Redirect("http://a/".into())
        );
        assert_eq!(
            deny(r#"{"allow":false,"url":"http://b/","html":"x"}"#).page,
            DenyPage::Fetch("http://b/".into())
        );
        // A redirect that cannot be a header value is not a redirect.
        assert_eq!(
            deny("{\"allow\":false,\"redirect\":\"http://a/\\nx\",\"html\":\"x\"}").page,
            DenyPage::Html(b"x".to_vec())
        );
    }

    #[test]
    fn rendered_statuses() {
        rt().block_on(async {
            let plain = deny_response("g", &Denial::forbidden()).await;
            assert_eq!(plain.status, 403);
            assert_eq!(plain.body, DEFAULT_BODY.as_bytes());
            assert!(
                plain
                    .headers
                    .iter()
                    .any(|(k, v)| k == AUTH_HEADER && v == "g")
            );

            let login = deny_response("g", &deny(r#"{"allow":false,"login":true}"#)).await;
            assert_eq!(login.status, 401);
            assert!(
                login
                    .headers
                    .iter()
                    .any(|(k, v)| k == "www-authenticate" && v.starts_with("Basic"))
            );

            let tunnel = deny_response("g", &deny(r#"{"allow":false,"statusCode":407}"#)).await;
            assert_eq!(tunnel.status, 407);
            assert!(
                tunnel
                    .headers
                    .iter()
                    .any(|(k, _)| k == "proxy-authenticate")
            );

            let redirect =
                deny_response("g", &deny(r#"{"allow":false,"redirect":"http://a/login"}"#)).await;
            assert_eq!(redirect.status, 302);
            assert!(
                redirect
                    .headers
                    .iter()
                    .any(|(k, v)| k == "location" && v == "http://a/login")
            );
            assert!(redirect.body.is_empty());

            let failed = deny_response("g", &Denial::failed("boom")).await;
            assert_eq!(failed.status, 502);
            assert!(String::from_utf8_lossy(&failed.body).contains("boom"));
        });
    }

    /// A plugin cannot turn a block into a success, whatever status it asks for.
    #[test]
    fn a_block_is_never_2xx() {
        rt().block_on(async {
            for status in ["200", "204", "0", "99", "1000"] {
                let d = deny(&format!(r#"{{"allow":false,"statusCode":{status}}}"#));
                let resp = deny_response("g", &d).await;
                assert_eq!(resp.status, 403, "statusCode {status} must not be honoured");
            }
            // In-range codes are honoured.
            let d = deny(r#"{"allow":false,"statusCode":451}"#);
            assert_eq!(deny_response("g", &d).await.status, 451);
        });
    }

    /// `setFile` reads from disk; a page that will not load still blocks.
    #[test]
    fn fetch_page_from_disk_and_failure() {
        rt().block_on(async {
            let dir = std::env::temp_dir().join(format!("whistle-rs-auth-{}", std::process::id()));
            tokio::fs::create_dir_all(&dir).await.expect("mkdir");
            let path = dir.join("blocked.html");
            tokio::fs::write(&path, b"<h1>nope</h1>")
                .await
                .expect("write");

            let d = Denial {
                page: DenyPage::Fetch(path.to_string_lossy().into_owned()),
                ..Denial::forbidden()
            };
            let resp = deny_response("g", &d).await;
            assert_eq!(resp.status, 403);
            assert_eq!(resp.body, b"<h1>nope</h1>");

            let missing = Denial {
                page: DenyPage::Fetch(dir.join("absent.html").to_string_lossy().into_owned()),
                ..Denial::forbidden()
            };
            let resp = deny_response("g", &missing).await;
            assert_eq!(resp.status, 403);
            assert_eq!(resp.body, DEFAULT_BODY.as_bytes());

            tokio::fs::remove_dir_all(&dir).await.ok();
        });
    }

    #[test]
    fn header_allow_list() {
        assert!(allowed_request_header("X-Whistle-User"));
        assert!(allowed_request_header("x-whistle-rs-anything"));
        assert!(allowed_request_header("Proxy-Authorization"));
        assert!(!allowed_request_header("authorization"));
        assert!(!allowed_request_header("cookie"));
        assert!(!allowed_request_header("x-whistle"));
    }

    #[test]
    fn block_pages_are_bounded() {
        let huge = vec![b'a'; MAX_PAGE_BYTES + 4096];
        assert_eq!(truncate(huge).len(), MAX_PAGE_BYTES);
        assert_eq!(
            content_type_for("/a/b.json"),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            content_type_for("http://a/b.html?x=1"),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for("/no-extension"),
            "text/html; charset=utf-8"
        );
    }
}
