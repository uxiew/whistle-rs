//! Built-in Rust example plugins, demonstrating the two hooks. They serve as
//! working references for writing native plugins.

use serde_json::json;

use super::{PluginReq, PluginResp, PluginResult, RustPlugin};

/// Every built-in plugin, registered by default.
pub fn all() -> Vec<Box<dyn RustPlugin>> {
    vec![Box::new(EchoPlugin), Box::new(TagPlugin)]
}

/// `plugin://echo` — a mock server that returns the request as JSON.
/// Demonstrates the `response` (server) hook.
struct EchoPlugin;

impl RustPlugin for EchoPlugin {
    fn name(&self) -> &str {
        "echo"
    }

    fn dispatch(&self, req: &PluginReq) -> PluginResult {
        let body = json!({
            "plugin": "echo (rust)",
            "method": req.method,
            "url": req.url,
            "param": req.param,
            "clientIp": req.client_ip,
            "headers": req.headers,
        });
        PluginResult {
            rules: None,
            response: Some(PluginResp {
                status: 200,
                headers: vec![(
                    "content-type".to_string(),
                    "application/json; charset=utf-8".to_string(),
                )],
                body: serde_json::to_vec_pretty(&body).unwrap_or_default(),
            }),
        }
    }
}

/// `plugin://tag` — injects rules that tag the request and response headers.
/// Demonstrates the `rules` (rulesServer) hook. `plugin://tag/<value>` uses
/// `<value>` as the tag (default `1`).
struct TagPlugin;

impl RustPlugin for TagPlugin {
    fn name(&self) -> &str {
        "tag"
    }

    fn dispatch(&self, req: &PluginReq) -> PluginResult {
        let tag = if req.param.is_empty() {
            "1"
        } else {
            req.param.as_str()
        };
        let rules = format!(
            "* reqHeaders://x-rust-plugin-req={tag}\n* resHeaders://x-rust-plugin-res={tag}\n"
        );
        PluginResult {
            rules: Some(rules),
            response: None,
        }
    }
}
