//! The `ui` hook — a plugin serving its own pages inside the web UI.
//!
//! ## One more HTTP hop, deliberately
//!
//! A UI request is already an HTTP request with an HTTP answer, so this hook
//! reuses HTTP whole: the browser's method, path, query, headers and body go to
//! the plugin under `/ui…`, and its status, headers and body stream back. There
//! is no JSON envelope, because there is nothing to envelope — the same argument
//! that made [`super::pipe`] chunked HTTP rather than a reinvented framing, one
//! step further along. A plugin author writes an ordinary Node request handler
//! and gets to use their own paths, content types, caching headers and
//! streaming, none of which a JSON protocol would carry.
//!
//! The proxy strips `/plugin/<name>` from the path before forwarding and adds
//! the `/ui` prefix, which is what keeps a plugin's pages from colliding with
//! its hooks: everything under `/ui` belongs to the browser, everything beside
//! it (`/manifest`, `/request`, `/auth`, …) belongs to the proxy. Upstream keeps
//! them apart differently — one port, dispatched on an internal hook-name header
//! (`lib/plugins/load-plugin.js:2006-2024`) — but it has a separate `uiServer`
//! object to dispatch *to*. Here there is one server and one router, so the
//! boundary has to be visible in the path.
//!
//! ## What a UI request is *not* given
//!
//! Not the proxied request. Upstream is pointed about this: the HTTP hook gets
//! `initReq(req, res, true)` — the full decorated request with rules, session
//! info and the original request/response — while the UI hook gets only
//! `setContext(req)`, which attaches storage and (when the caller supplied
//! session headers) the client address (`lib/plugins/load-plugin.js:160-200`,
//! `:2019-2024`). A UI request is a browser asking a plugin for a page; it is
//! not part of anyone's proxied traffic, and handing it a request context would
//! invent an association that does not exist.
//!
//! whix follows that: the plugin receives the browser's own request and
//! nothing else. A plugin that wants to show captured traffic accumulates it in
//! the hooks that *do* see traffic (`onRequest`, `resStats`) and serves it from
//! its own state — which is exactly how upstream plugins do it too.
//!
//! ## Failure
//!
//! Cosmetic, so it degrades: an unreachable or silent plugin becomes a `502`
//! page in the browser and a `debug` line in the log. Nothing about proxied
//! traffic changes.

use std::time::Duration;

use bytes::Bytes;
use hyper::{Request, Response, StatusCode, Uri};

use crate::proxy::body::{self, DynBody};

/// Path prefix under which the web UI routes to a plugin.
pub const UI_ROUTE_PREFIX: &str = "/plugin/";

/// Prefix added to the forwarded path, reserving a subtree of the plugin's URL
/// space for its pages.
pub const UI_PATH_PREFIX: &str = "/ui";

/// How long to wait for a plugin's UI response head. Only bounds a local
/// connection, and a browser tab is the only thing waiting on it.
const UI_TIMEOUT: Duration = Duration::from_secs(10);

/// Headers that describe *this* hop and must not be copied to the next one.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    // Re-framed by whichever side sends the body onward.
    "content-length",
    "host",
];

/// A UI request handed to a native Rust plugin.
///
/// The browser's request, with the `/plugin/<name>` prefix already stripped —
/// and nothing else. See the module docs for why there is no proxied-request
/// context here.
#[derive(Debug, Default, Clone)]
pub struct UiReq {
    pub method: String,
    /// Path within the plugin's UI, always starting with `/`.
    pub path: String,
    /// Raw query string, without the `?`.
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl UiReq {
    /// Look up a query parameter (first occurrence), percent-decoding `+`.
    pub fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| v.replace('+', " "))
        })
    }
}

/// A native plugin's UI answer.
#[derive(Debug, Clone)]
pub struct UiResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl UiResp {
    /// An HTML page.
    pub fn html(body: impl Into<Vec<u8>>) -> Self {
        UiResp {
            status: 200,
            headers: vec![(
                "content-type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body: body.into(),
        }
    }

    /// A JSON document.
    pub fn json(value: &serde_json::Value) -> Self {
        UiResp {
            status: 200,
            headers: vec![(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )],
            body: serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    /// Nothing at this path.
    pub fn not_found() -> Self {
        UiResp {
            status: 404,
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: b"not found".to_vec(),
        }
    }

    /// Render into a real response.
    pub fn into_response(self) -> Response<DynBody> {
        let mut builder =
            Response::builder().status(StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK));
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        builder
            .body(body::full(Bytes::from(self.body)))
            .unwrap_or_else(|_| {
                error_page(StatusCode::INTERNAL_SERVER_ERROR, "bad plugin UI response")
            })
    }
}

/// Forward a UI request to a remote plugin and stream the answer back.
pub async fn forward(
    name: &str,
    base_url: &str,
    req: Request<DynBody>,
) -> anyhow::Result<Response<DynBody>> {
    let (parts, incoming) = req.into_parts();
    let (mut sender, authority) = super::pipe::dial(base_url).await?;

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri: Uri = format!("{UI_PATH_PREFIX}{path_and_query}").parse()?;

    let mut out = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .header(hyper::header::HOST, authority);
    for (k, v) in parts.headers.iter() {
        if !HOP_BY_HOP
            .iter()
            .any(|h| k.as_str().eq_ignore_ascii_case(h))
        {
            out = out.header(k, v);
        }
    }
    let path_and_query = path_and_query.to_string();
    let out = out.body(incoming)?;

    let resp = tokio::time::timeout(UI_TIMEOUT, sender.send_request(out))
        .await
        .map_err(|_| anyhow::anyhow!("no response within {UI_TIMEOUT:?}"))??;

    let (rparts, rbody) = resp.into_parts();
    tracing::debug!(
        "ui {name}: {} {path_and_query} -> {}",
        parts.method,
        rparts.status
    );
    let mut builder = Response::builder().status(rparts.status);
    for (k, v) in rparts.headers.iter() {
        // `content-length` survives here: the body is forwarded verbatim, so the
        // length the plugin declared is still the truth.
        if !k.as_str().eq_ignore_ascii_case("transfer-encoding")
            && !k.as_str().eq_ignore_ascii_case("connection")
        {
            builder = builder.header(k, v);
        }
    }
    Ok(builder.body(body::from_incoming(rbody))?)
}

/// Escape text for interpolation into an HTML page.
///
/// A native plugin's UI is built by string formatting, and the interesting
/// things to show — URLs, header values — come from traffic. Anything that
/// crosses that boundary goes through here.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A plain error page, used when a plugin's UI cannot be reached.
pub fn error_page(status: StatusCode, message: &str) -> Response<DynBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| Response::new(body::empty()))
}

/// Split `/plugin/<name>/rest?query` into the plugin name and the remainder.
///
/// Returns `None` when the path is not a plugin UI path at all. The remainder
/// keeps its leading `/`; an empty remainder (`/plugin/<name>`) comes back as
/// `None` for the rest, which the router turns into a redirect — a UI whose base
/// URL has no trailing slash breaks every relative link on the page, which is
/// why upstream redirects too (`biz/webui/lib/index.js:489-491`).
pub fn split_route(path: &str) -> Option<(&str, Option<&str>)> {
    let rest = path.strip_prefix(UI_ROUTE_PREFIX)?;
    match rest.find('/') {
        Some(i) => Some((&rest[..i], Some(&rest[i..]))),
        None => Some((rest, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_splitting() {
        assert_eq!(split_route("/plugin/gate"), Some(("gate", None)));
        assert_eq!(split_route("/plugin/gate/"), Some(("gate", Some("/"))));
        assert_eq!(
            split_route("/plugin/gate/a/b.css"),
            Some(("gate", Some("/a/b.css")))
        );
        assert_eq!(split_route("/plugin/"), Some(("", None)));
        assert_eq!(split_route("/plugins/x"), None);
        assert_eq!(split_route("/sessions.json"), None);
    }

    #[test]
    fn query_parameters() {
        let req = UiReq {
            query: "a=1&b=two+words&c".into(),
            ..Default::default()
        };
        assert_eq!(req.param("a").as_deref(), Some("1"));
        assert_eq!(req.param("b").as_deref(), Some("two words"));
        assert_eq!(req.param("c"), None);
        assert_eq!(req.param("d"), None);
    }

    #[test]
    fn responses_render() {
        let resp = UiResp::html("<h1>hi</h1>").into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            UiResp::not_found().into_response().status(),
            StatusCode::NOT_FOUND
        );
    }

    /// An unreachable plugin is an error, never a hang and never a panic.
    #[test]
    fn unreachable_plugin_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let req = Request::builder()
                .uri("/")
                .body(body::empty())
                .expect("request");
            let out = forward("gone", "http://127.0.0.1:1", req).await;
            assert!(out.is_err());
        });
    }
}
