//! Built-in Rust example plugins, demonstrating each hook. They double as
//! working references for writing native plugins.

use serde_json::json;

use super::{
    PluginManifest, PluginReq, PluginRes, PluginResResult, PluginResp, PluginResult, RustPlugin,
};

/// Every built-in plugin, registered by default.
pub fn all() -> Vec<Box<dyn RustPlugin>> {
    vec![
        Box::new(EchoPlugin),
        Box::new(TagPlugin),
        Box::new(StampPlugin),
    ]
}

/// `plugin://echo` — a mock server that returns the request as JSON.
/// Demonstrates answering a request directly.
struct EchoPlugin;

impl RustPlugin for EchoPlugin {
    fn name(&self) -> &str {
        "echo"
    }

    fn on_request(&self, req: &PluginReq) -> PluginResult {
        let body = json!({
            "plugin": "echo (rust)",
            "method": req.method,
            "url": req.url,
            "param": req.param,
            "clientIp": req.client_ip,
            "headers": req.headers,
        });
        PluginResult {
            response: Some(PluginResp {
                status: 200,
                headers: vec![(
                    "content-type".to_string(),
                    "application/json; charset=utf-8".to_string(),
                )],
                body: serde_json::to_vec_pretty(&body).unwrap_or_default(),
            }),
            ..Default::default()
        }
    }
}

/// `plugin://tag` — injects rules that tag the request and response headers.
/// Demonstrates the rule-injection hook. `plugin://tag/<value>` uses `<value>`
/// as the tag (default `1`).
struct TagPlugin;

impl RustPlugin for TagPlugin {
    fn name(&self) -> &str {
        "tag"
    }

    fn on_request(&self, req: &PluginReq) -> PluginResult {
        let tag = if req.param.is_empty() {
            "1"
        } else {
            req.param.as_str()
        };
        PluginResult {
            rules: Some(format!(
                "* reqHeaders://x-rust-plugin-req={tag}\n* resHeaders://x-rust-plugin-res={tag}\n"
            )),
            ..Default::default()
        }
    }
}

/// `plugin://stamp` — stamps a header onto the response as it goes back.
/// Demonstrates the **response** hook, and a manifest that declares it.
///
/// It deliberately does *not* ask for the response body, so the proxy keeps
/// streaming the response through untouched.
struct StampPlugin;

impl RustPlugin for StampPlugin {
    fn name(&self) -> &str {
        "stamp"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            name: self.name().to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            on_request: false,
            on_response: true,
            request_body: false,
            response_body: false,
        }
    }

    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult::default()
    }

    fn on_response(&self, res: &PluginRes) -> PluginResResult {
        let stamp = if res.param.is_empty() {
            "whistle-rs"
        } else {
            res.param.as_str()
        };
        PluginResResult {
            set_headers: vec![("x-stamped-by".to_string(), stamp.to_string())],
            ..Default::default()
        }
    }
}
