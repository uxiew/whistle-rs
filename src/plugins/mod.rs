//! whistle-rs plugin system.
//!
//! A plugin is per-request middleware. It can **inject rules**, **answer the
//! request directly** (a mock), **rewrite request headers**, and **rewrite the
//! response** (status, headers, body). Two runtimes implement the same contract:
//!
//! * **Rust plugins** — native, in-process, implementing [`RustPlugin`]. Zero IPC.
//! * **Remote plugins** — any process exposing an HTTP endpoint that speaks the
//!   JSON protocol below. In practice that means JavaScript/TypeScript via the
//!   SDK in `sdk/`, but the protocol is deliberately language-agnostic.
//!   whistle-rs can spawn the process for you (`--node-plugin name=path.js`) or
//!   point at an already-running one (`--plugin name=host:port`).
//!
//! Both are triggered by a `plugin://<name>[/<param>]` (or `pipe://…`) rule.
//!
//! ## Wire protocol
//!
//! ### `GET /manifest` — capability declaration
//!
//! Fetched once, lazily, on a plugin's first use and then cached. It is what
//! keeps the fast path fast: whistle-rs only buffers a request or response body
//! when a plugin has explicitly asked for it, so plugins that don't care never
//! cost the proxy its streaming behaviour.
//!
//! ```json
//! { "name": "my-plugin", "version": "1.0.0",
//!   "hooks": ["request", "response"],
//!   "requestBody": false, "responseBody": true }
//! ```
//!
//! A plugin that does not serve `/manifest` is treated as **protocol v1**:
//! request hook only, no bodies, dispatched to `POST /`. Existing plugins
//! therefore keep working untouched.
//!
//! ### `POST /request` — before the upstream request
//!
//! ```json
//! { "id": 42, "method": "GET", "url": "http://…", "headers": [["k","v"], …],
//!   "clientIp": "1.2.3.4", "param": "extra/after/name", "bodyBase64": "…" }
//! ```
//! `bodyBase64` is present only when the manifest set `requestBody`. Reply:
//! ```json
//! { "rules": "example.com resHeaders://x=1",
//!   "setHeaders": { "x-foo": "bar" }, "removeHeaders": ["cookie"],
//!   "response": { "statusCode": 200, "headers": {…}, "body": "…" } }
//! ```
//! Every field is optional. `rules` is merged into the resolved rule set;
//! `setHeaders`/`removeHeaders` rewrite the outgoing request; a `response`
//! short-circuits the upstream request entirely.
//!
//! ### `POST /response` — after the upstream response
//!
//! ```json
//! { "id": 42, "method": "GET", "url": "http://…", "statusCode": 200,
//!   "headers": [["k","v"], …], "param": "…", "bodyBase64": "…" }
//! ```
//! `bodyBase64` is present only when the manifest set `responseBody`. Reply:
//! ```json
//! { "statusCode": 201, "setHeaders": {…}, "removeHeaders": […], "body": "…" }
//! ```
//! Every field is optional; omitting all of them leaves the response untouched.
//!
//! Binary bodies use `bodyBase64` in both directions; `body` is UTF-8 text.

use std::collections::HashMap;

use serde_json::json;
use tokio::sync::OnceCell;

use crate::proxy::upstream;

/// What a plugin can do, so the proxy only pays for what is actually used.
///
/// The body flags are the load-bearing part: buffering a body defeats streaming,
/// so whistle-rs does it only when a matched plugin declares it needs one.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    pub name: String,
    pub version: Option<String>,
    /// Serve the `POST /request` hook.
    pub on_request: bool,
    /// Serve the `POST /response` hook.
    pub on_response: bool,
    /// Wants the request body buffered and handed over.
    pub request_body: bool,
    /// Wants the response body buffered and handed over.
    pub response_body: bool,
}

impl PluginManifest {
    /// What we assume when a plugin does not serve `/manifest`: the original
    /// protocol — a request hook, no bodies.
    pub fn v1_fallback(name: &str) -> Self {
        PluginManifest {
            name: name.to_string(),
            version: None,
            on_request: true,
            on_response: false,
            request_body: false,
            response_body: false,
        }
    }

    /// Parse a manifest document; every missing field defaults to "not supported".
    fn parse(name: &str, bytes: &[u8]) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let hooks: Vec<String> = v
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_ascii_lowercase))
                    .collect()
            })
            .unwrap_or_default();
        let flag = |k: &str| v.get(k).and_then(|b| b.as_bool()).unwrap_or(false);
        Some(PluginManifest {
            name: v
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(name)
                .to_string(),
            version: v
                .get("version")
                .and_then(|s| s.as_str())
                .map(str::to_string),
            on_request: hooks.iter().any(|h| h == "request"),
            on_response: hooks.iter().any(|h| h == "response"),
            request_body: flag("requestBody"),
            response_body: flag("responseBody"),
        })
    }
}

/// The request context handed to a plugin's request hook.
#[derive(Default)]
pub struct PluginReq {
    /// Session id, so a plugin can correlate the request and response hooks.
    pub id: u64,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub client_ip: Option<String>,
    /// The `plugin://name/PARAM` suffix after the plugin name (a routing hint).
    pub param: String,
    /// Request body — `Some` only when the plugin's manifest asked for it.
    pub body: Option<Vec<u8>>,
}

/// The response context handed to a plugin's response hook.
#[derive(Default)]
pub struct PluginRes {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub param: String,
    /// Response body — `Some` only when the plugin's manifest asked for it.
    pub body: Option<Vec<u8>>,
}

/// A plugin-produced response (a mock that short-circuits the upstream request).
#[derive(Default)]
pub struct PluginResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What a plugin's request hook returns.
#[derive(Default)]
pub struct PluginResult {
    /// whistle rules to merge into the resolved set for this request.
    pub rules: Option<String>,
    /// A response that short-circuits the upstream request.
    pub response: Option<PluginResp>,
    /// Headers to set on the outgoing request (replacing any existing value).
    pub set_headers: Vec<(String, String)>,
    /// Headers to strip from the outgoing request.
    pub remove_headers: Vec<String>,
}

/// What a plugin's response hook returns. All fields optional — an empty result
/// leaves the response exactly as it was.
#[derive(Default)]
pub struct PluginResResult {
    pub status: Option<u16>,
    pub set_headers: Vec<(String, String)>,
    pub remove_headers: Vec<String>,
    pub body: Option<Vec<u8>>,
}

impl PluginResResult {
    /// Nothing to apply — lets callers skip the rewrite entirely.
    pub fn is_noop(&self) -> bool {
        self.status.is_none()
            && self.body.is_none()
            && self.set_headers.is_empty()
            && self.remove_headers.is_empty()
    }
}

/// The interface a native Rust plugin implements (synchronous).
///
/// Only [`name`](RustPlugin::name) and [`on_request`](RustPlugin::on_request)
/// are required; the rest have defaults, so adding hooks to the protocol never
/// breaks existing implementations.
pub trait RustPlugin: Send + Sync {
    /// The plugin's name (matched by `plugin://<name>`).
    fn name(&self) -> &str;

    /// Produce rules, header rewrites and/or a response for the request.
    fn on_request(&self, req: &PluginReq) -> PluginResult;

    /// Observe or rewrite the upstream response. Default: no change.
    fn on_response(&self, _res: &PluginRes) -> PluginResResult {
        PluginResResult::default()
    }

    /// Declared capabilities. Default: request hook only, no bodies.
    fn manifest(&self) -> PluginManifest {
        PluginManifest::v1_fallback(self.name())
    }
}

/// A remote plugin reached over HTTP (the JS/TS SDK, or any process).
pub struct RemotePlugin {
    name: String,
    base_url: String,
    /// Fetched lazily on first use — a plugin spawned alongside us may not be
    /// listening yet at registration time.
    manifest: OnceCell<PluginManifest>,
}

impl RemotePlugin {
    pub fn new(name: impl Into<String>, host_port: &str) -> Self {
        let base = if host_port.contains("://") {
            host_port.trim_end_matches('/').to_string()
        } else {
            format!("http://{}", host_port.trim_end_matches('/'))
        };
        RemotePlugin {
            name: name.into(),
            base_url: base,
            manifest: OnceCell::new(),
        }
    }

    /// The plugin's manifest, fetched once and cached. A plugin that does not
    /// serve `/manifest` (or is unreachable) is treated as protocol v1.
    async fn manifest(&self) -> &PluginManifest {
        self.manifest
            .get_or_init(|| async {
                match upstream::simple_get(&format!("{}/manifest", self.base_url)).await {
                    Ok((200, bytes)) => match PluginManifest::parse(&self.name, &bytes) {
                        Some(m) => {
                            tracing::info!(
                                "plugin {} manifest: request={} response={} reqBody={} resBody={}",
                                self.name,
                                m.on_request,
                                m.on_response,
                                m.request_body,
                                m.response_body
                            );
                            m
                        }
                        None => {
                            tracing::warn!(
                                "plugin {} served an unparseable manifest; assuming v1",
                                self.name
                            );
                            PluginManifest::v1_fallback(&self.name)
                        }
                    },
                    _ => {
                        tracing::debug!("plugin {} has no manifest; assuming v1", self.name);
                        PluginManifest::v1_fallback(&self.name)
                    }
                }
            })
            .await
    }

    async fn on_request(&self, req: &PluginReq) -> PluginResult {
        let manifest = self.manifest().await;
        if !manifest.on_request {
            return PluginResult::default();
        }
        // v1 plugins have no `/request` route; they answer on `/`.
        let is_v1 = !manifest.on_response && !manifest.request_body && manifest.version.is_none();
        let path = if is_v1 { "" } else { "/request" };

        let mut payload = json!({
            "id": req.id,
            "method": req.method,
            "url": req.url,
            "headers": headers_json(&req.headers),
            "clientIp": req.client_ip,
            "param": req.param,
        });
        if let Some(body) = &req.body {
            payload["bodyBase64"] = json!(b64(body));
        }

        match self.post(path, &payload.to_string()).await {
            Some(bytes) => parse_request_result(&bytes),
            None => PluginResult::default(),
        }
    }

    async fn on_response(&self, res: &PluginRes) -> PluginResResult {
        if !self.manifest().await.on_response {
            return PluginResResult::default();
        }
        let mut payload = json!({
            "id": res.id,
            "method": res.method,
            "url": res.url,
            "statusCode": res.status,
            "headers": headers_json(&res.headers),
            "param": res.param,
        });
        if let Some(body) = &res.body {
            payload["bodyBase64"] = json!(b64(body));
        }

        match self.post("/response", &payload.to_string()).await {
            Some(bytes) => parse_response_result(&bytes),
            None => PluginResResult::default(),
        }
    }

    /// POST to the plugin, retrying briefly: a freshly spawned plugin process
    /// may still be binding its port when the first request arrives.
    async fn post(&self, path: &str, body: &str) -> Option<bytes::Bytes> {
        let url = format!("{}{path}", self.base_url);
        let mut last_err = None;
        for attempt in 0..3 {
            match upstream::simple_post_json(&url, body).await {
                Ok((200, bytes)) => return Some(bytes),
                // 204/304 are the idiomatic "nothing to do" replies.
                Ok((204, _)) | Ok((304, _)) => return None,
                Ok((status, _)) => {
                    tracing::debug!("plugin {} {path} returned status {status}", self.name);
                    return None;
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < 3 {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
        }
        if let Some(e) = last_err {
            tracing::debug!("plugin {} {path} failed: {e:#}", self.name);
        }
        None
    }
}

fn headers_json(headers: &[(String, String)]) -> Vec<serde_json::Value> {
    headers.iter().map(|(k, v)| json!([k, v])).collect()
}

fn b64(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
}

fn from_b64(s: &str) -> Option<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok()
}

/// Parse the reply to `POST /request` (lenient — a malformed field is skipped,
/// never fatal).
fn parse_request_result(bytes: &[u8]) -> PluginResult {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return PluginResult::default();
    };
    let rules = v
        .get("rules")
        .and_then(|r| r.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());
    let response = v.get("response").filter(|r| !r.is_null()).map(|r| {
        let status = r
            .get("statusCode")
            .or_else(|| r.get("status"))
            .and_then(|s| s.as_u64())
            .unwrap_or(200) as u16;
        PluginResp {
            status,
            headers: parse_headers_value(r.get("headers")),
            body: body_bytes(r),
        }
    });
    PluginResult {
        rules,
        response,
        set_headers: parse_headers_value(v.get("setHeaders")),
        remove_headers: parse_string_list(v.get("removeHeaders")),
    }
}

/// Parse the reply to `POST /response`.
fn parse_response_result(bytes: &[u8]) -> PluginResResult {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return PluginResResult::default();
    };
    let status = v
        .get("statusCode")
        .or_else(|| v.get("status"))
        .and_then(|s| s.as_u64())
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| (100..=599).contains(s));
    // Distinguish "no body field" from "empty body": only rewrite when present.
    let body = if v.get("bodyBase64").is_some() || v.get("body").is_some() {
        Some(body_bytes(&v))
    } else {
        None
    };
    PluginResResult {
        status,
        set_headers: parse_headers_value(v.get("setHeaders")),
        remove_headers: parse_string_list(v.get("removeHeaders")),
        body,
    }
}

/// Read a body from `bodyBase64` (binary) or `body` (UTF-8 text, or any JSON
/// value stringified).
fn body_bytes(v: &serde_json::Value) -> Vec<u8> {
    if let Some(b64) = v.get("bodyBase64").and_then(|b| b.as_str()) {
        return from_b64(b64).unwrap_or_default();
    }
    v.get("body")
        .map(|b| match b {
            serde_json::Value::String(s) => s.clone().into_bytes(),
            serde_json::Value::Null => Vec::new(),
            other => other.to_string().into_bytes(),
        })
        .unwrap_or_default()
}

/// Accept headers as either an object `{k:v}` or an array of `[k,v]` pairs.
fn parse_headers_value(v: Option<&serde_json::Value>) -> Vec<(String, String)> {
    match v {
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .map(|(k, v)| (k.clone(), value_to_string(v)))
            .collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|pair| {
                let p = pair.as_array()?;
                Some((value_to_string(p.first()?), value_to_string(p.get(1)?)))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Accept a list of names as an array, or a single string.
fn parse_string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().map(value_to_string).collect()
        }
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A registered plugin, of either runtime.
enum PluginKind {
    Rust(Box<dyn RustPlugin>),
    Remote(RemotePlugin),
}

/// The plugin registry held in shared server state.
pub struct Plugins {
    map: HashMap<String, PluginKind>,
}

impl Default for Plugins {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugins {
    /// A registry preloaded with the built-in Rust example plugins.
    pub fn new() -> Self {
        let mut p = Plugins {
            map: HashMap::new(),
        };
        for plugin in builtin::all() {
            p.register_rust(plugin);
        }
        p
    }

    pub fn register_rust(&mut self, plugin: Box<dyn RustPlugin>) {
        self.map
            .insert(plugin.name().to_string(), PluginKind::Rust(plugin));
    }

    pub fn register_remote(&mut self, name: &str, host_port: &str) {
        self.map.insert(
            name.to_string(),
            PluginKind::Remote(RemotePlugin::new(name, host_port)),
        );
    }

    pub fn contains(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Sorted plugin names (for logging / the UI).
    pub fn names(&self) -> Vec<String> {
        let mut n: Vec<String> = self.map.keys().cloned().collect();
        n.sort();
        n
    }

    /// The capability manifest for `name`, if registered.
    pub async fn manifest(&self, name: &str) -> Option<PluginManifest> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => Some(p.manifest()),
            PluginKind::Remote(r) => Some(r.manifest().await.clone()),
        }
    }

    /// Does any of `names` want the request body? Drives the proxy's decision to
    /// buffer, so that plugins which don't care keep the streaming fast path.
    pub async fn any_wants_request_body(&self, names: &[String]) -> bool {
        for name in names {
            if matches!(self.manifest(name).await, Some(m) if m.request_body) {
                return true;
            }
        }
        false
    }

    /// Does any of `names` want the response body?
    pub async fn any_wants_response_body(&self, names: &[String]) -> bool {
        for name in names {
            if matches!(self.manifest(name).await, Some(m) if m.response_body) {
                return true;
            }
        }
        false
    }

    /// Does any of `names` serve the response hook?
    pub async fn any_has_response_hook(&self, names: &[String]) -> bool {
        for name in names {
            if matches!(self.manifest(name).await, Some(m) if m.on_response) {
                return true;
            }
        }
        false
    }

    /// Run plugin `name`'s request hook. Returns `None` if no such plugin.
    pub async fn on_request(&self, name: &str, req: &PluginReq) -> Option<PluginResult> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => Some(p.on_request(req)),
            PluginKind::Remote(r) => Some(r.on_request(req).await),
        }
    }

    /// Run plugin `name`'s response hook. Returns `None` if no such plugin.
    pub async fn on_response(&self, name: &str, res: &PluginRes) -> Option<PluginResResult> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => Some(p.on_response(res)),
            PluginKind::Remote(r) => Some(r.on_response(res).await),
        }
    }
}

pub mod builtin;

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> PluginReq {
        PluginReq {
            id: 1,
            method: "GET".into(),
            url: "http://example.com/x".into(),
            headers: vec![("host".into(), "example.com".into())],
            client_ip: Some("1.2.3.4".into()),
            param: "hi".into(),
            body: None,
        }
    }

    #[test]
    fn builtins_registered() {
        let p = Plugins::new();
        assert!(p.contains("echo"));
        assert!(p.contains("tag"));
        assert!(!p.contains("nope"));
    }

    #[test]
    fn rust_echo_returns_response() {
        let p = Plugins::new();
        // Dispatch is async but the built-ins are sync; drive on a tiny runtime.
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let out = rt.block_on(p.on_request("echo", &req())).unwrap();
        let resp = out.response.expect("echo should return a response");
        assert_eq!(resp.status, 200);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("echo (rust)"));
        assert!(body.contains("http://example.com/x"));
    }

    #[test]
    fn rust_tag_injects_rules() {
        let p = Plugins::new();
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let out = rt.block_on(p.on_request("tag", &req())).unwrap();
        let rules = out.rules.expect("tag should return rules");
        assert!(rules.contains("resHeaders://x-rust-plugin-res=hi"));
        assert!(out.response.is_none());
    }

    #[test]
    fn request_result_parsing() {
        let json = br#"{"rules":"a.com resHeaders://x=1","response":{"statusCode":201,"headers":{"content-type":"text/plain"},"body":"hi"}}"#;
        let r = parse_request_result(json);
        assert_eq!(r.rules.as_deref(), Some("a.com resHeaders://x=1"));
        let resp = r.response.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"hi");
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v == "text/plain"));
    }

    #[test]
    fn request_result_binary_body() {
        // base64("\x00\x01\x02\xff") = "AAEC/w=="
        let json = br#"{"response":{"statusCode":200,"bodyBase64":"AAEC/w=="}}"#;
        let r = parse_request_result(json);
        let resp = r.response.unwrap();
        assert_eq!(resp.body, vec![0u8, 1, 2, 255]);
    }

    #[test]
    fn request_result_empty_is_noop() {
        let r = parse_request_result(b"{}");
        assert!(r.rules.is_none());
        assert!(r.response.is_none());
        assert!(r.set_headers.is_empty());
        assert!(r.remove_headers.is_empty());
    }

    #[test]
    fn request_result_header_rewrites() {
        let json = br#"{"setHeaders":{"x-a":"1"},"removeHeaders":["cookie","x-b"]}"#;
        let r = parse_request_result(json);
        assert_eq!(r.set_headers, vec![("x-a".to_string(), "1".to_string())]);
        assert_eq!(r.remove_headers, vec!["cookie", "x-b"]);
    }

    /// A single string is accepted where a list is expected — plugin authors
    /// reach for `removeHeaders: 'cookie'` and it should just work.
    #[test]
    fn remove_headers_accepts_a_bare_string() {
        let r = parse_request_result(br#"{"removeHeaders":"cookie"}"#);
        assert_eq!(r.remove_headers, vec!["cookie"]);
    }

    #[test]
    fn response_result_parsing() {
        let json = br#"{"statusCode":404,"setHeaders":{"x-a":"1"},"body":"gone"}"#;
        let r = parse_response_result(json);
        assert_eq!(r.status, Some(404));
        assert_eq!(r.body.as_deref(), Some(&b"gone"[..]));
        assert!(!r.is_noop());
    }

    /// An empty reply must leave the response alone — distinct from a reply
    /// that deliberately sets an empty body.
    #[test]
    fn response_result_empty_is_noop() {
        let r = parse_response_result(b"{}");
        assert!(r.is_noop());
        assert!(r.body.is_none());

        let cleared = parse_response_result(br#"{"body":""}"#);
        assert!(!cleared.is_noop());
        assert_eq!(cleared.body.as_deref(), Some(&b""[..]));
    }

    /// Nonsense status codes are ignored rather than propagated.
    #[test]
    fn response_result_rejects_bad_status() {
        assert_eq!(parse_response_result(br#"{"statusCode":9000}"#).status, None);
        assert_eq!(parse_response_result(br#"{"statusCode":0}"#).status, None);
        assert_eq!(parse_response_result(br#"{"statusCode":302}"#).status, Some(302));
    }

    #[test]
    fn manifest_parsing() {
        let m = PluginManifest::parse(
            "fallback",
            br#"{"name":"my-plugin","version":"1.2.3","hooks":["request","response"],"responseBody":true}"#,
        )
        .unwrap();
        assert_eq!(m.name, "my-plugin");
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
        assert!(m.on_request && m.on_response);
        assert!(!m.request_body && m.response_body);
    }

    /// Unknown hook names are ignored, and a manifest without `hooks` declares
    /// nothing — the plugin simply never gets called.
    #[test]
    fn manifest_unknown_hooks_ignored() {
        let m = PluginManifest::parse("p", br#"{"hooks":["request","teleport"]}"#).unwrap();
        assert!(m.on_request && !m.on_response);

        let bare = PluginManifest::parse("p", b"{}").unwrap();
        assert!(!bare.on_request && !bare.on_response);
        assert_eq!(bare.name, "p");
    }

    #[test]
    fn manifest_v1_fallback() {
        let m = PluginManifest::v1_fallback("legacy");
        assert!(m.on_request);
        assert!(!m.on_response && !m.request_body && !m.response_body);
        assert!(PluginManifest::parse("p", b"not json").is_none());
    }
}
