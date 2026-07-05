//! Unified plugin system.
//!
//! A plugin is a per-request middleware that can **inject whistle rules** (the
//! `rulesServer` hook in upstream whistle) and/or **handle a request directly**
//! (the `server` hook — a mock response). Two runtimes implement the same
//! contract:
//!
//! * **Rust plugins** — native, in-process, implementing [`RustPlugin`]. Zero IPC.
//! * **Remote plugins** — a Node (or any) process exposing an HTTP endpoint that
//!   speaks the JSON protocol below. whistle-rs can spawn the Node process for
//!   you (`--node-plugin name=path.js`) or point at an already-running one
//!   (`--plugin name=host:port`).
//!
//! Both are triggered by a `plugin://<name>` (or `pipe://<name>`) rule.
//!
//! ## Remote JSON protocol
//!
//! whistle-rs → plugin: `POST /` with
//! ```json
//! { "method": "GET", "url": "http://…", "headers": [["k","v"], …],
//!   "clientIp": "1.2.3.4", "param": "extra/after/name" }
//! ```
//! plugin → whistle-rs:
//! ```json
//! { "rules": "example.com resHeaders://x=1",
//!   "response": { "statusCode": 200, "headers": {"content-type":"…"}, "body": "…" } }
//! ```
//! Both `rules` and `response` are optional. `rules` is merged into the resolved
//! rule set; a `response` short-circuits the upstream request.

use std::collections::HashMap;

use serde_json::json;

use crate::proxy::upstream;

/// The request context passed to a plugin.
pub struct PluginReq {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub client_ip: Option<String>,
    /// The `plugin://name/PARAM` suffix after the plugin name (a routing hint).
    pub param: String,
}

/// A plugin-produced response (mock / `server` hook).
#[derive(Default)]
pub struct PluginResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What a plugin returns for a request.
#[derive(Default)]
pub struct PluginResult {
    /// whistle rules to merge into the resolved set for this request.
    pub rules: Option<String>,
    /// A response that short-circuits the upstream request.
    pub response: Option<PluginResp>,
}

/// The interface a native Rust plugin implements (synchronous).
pub trait RustPlugin: Send + Sync {
    /// The plugin's name (matched by `plugin://<name>`).
    fn name(&self) -> &str;
    /// Produce rules and/or a response for the request.
    fn dispatch(&self, req: &PluginReq) -> PluginResult;
}

/// A remote plugin reached over HTTP (Node or any process).
pub struct RemotePlugin {
    name: String,
    base_url: String,
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
        }
    }

    async fn dispatch(&self, req: &PluginReq) -> PluginResult {
        let headers: Vec<serde_json::Value> = req
            .headers
            .iter()
            .map(|(k, v)| json!([k, v]))
            .collect();
        let body = json!({
            "method": req.method,
            "url": req.url,
            "headers": headers,
            "clientIp": req.client_ip,
            "param": req.param,
        })
        .to_string();

        match upstream::simple_post_json(&self.base_url, &body).await {
            Ok((status, bytes)) if status == 200 => parse_remote_result(&bytes),
            Ok((status, _)) => {
                tracing::debug!("plugin {} returned status {status}", self.name);
                PluginResult::default()
            }
            Err(e) => {
                tracing::debug!("plugin {} dispatch failed: {e:#}", self.name);
                PluginResult::default()
            }
        }
    }
}

/// Parse the remote plugin's JSON reply into a [`PluginResult`] (lenient).
fn parse_remote_result(bytes: &[u8]) -> PluginResult {
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
        let headers = parse_headers_value(r.get("headers"));
        let body = r
            .get("body")
            .map(|b| match b {
                serde_json::Value::String(s) => s.clone().into_bytes(),
                other => other.to_string().into_bytes(),
            })
            .unwrap_or_default();
        PluginResp {
            status,
            headers,
            body,
        }
    });
    PluginResult { rules, response }
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

    /// Dispatch to plugin `name`. Returns `None` if no such plugin.
    pub async fn dispatch(&self, name: &str, req: &PluginReq) -> Option<PluginResult> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => Some(p.dispatch(req)),
            PluginKind::Remote(r) => Some(r.dispatch(req).await),
        }
    }
}

pub mod builtin;

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> PluginReq {
        PluginReq {
            method: "GET".into(),
            url: "http://example.com/x".into(),
            headers: vec![("host".into(), "example.com".into())],
            client_ip: Some("1.2.3.4".into()),
            param: "hi".into(),
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
        let out = rt.block_on(p.dispatch("echo", &req())).unwrap();
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
        let out = rt.block_on(p.dispatch("tag", &req())).unwrap();
        let rules = out.rules.expect("tag should return rules");
        assert!(rules.contains("resHeaders://x-rust-plugin-res=hi"));
        assert!(out.response.is_none());
    }

    #[test]
    fn remote_result_parsing() {
        let json = br#"{"rules":"a.com resHeaders://x=1","response":{"statusCode":201,"headers":{"content-type":"text/plain"},"body":"hi"}}"#;
        let r = parse_remote_result(json);
        assert_eq!(r.rules.as_deref(), Some("a.com resHeaders://x=1"));
        let resp = r.response.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"hi");
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v == "text/plain"));
    }

    #[test]
    fn remote_result_empty_is_noop() {
        let r = parse_remote_result(b"{}");
        assert!(r.rules.is_none());
        assert!(r.response.is_none());
    }
}
