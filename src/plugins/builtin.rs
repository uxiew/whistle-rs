//! Built-in Rust example plugins, demonstrating each hook. They double as
//! working references for writing native plugins.

use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::json;

use super::pipe::{Dir, PipeMeta};
use super::wsframe::{FrameMeta, HookFrame, Verdict};
use super::{
    PluginManifest, PluginReq, PluginRes, PluginResResult, PluginResp, PluginResult, RustPlugin,
};
use crate::proxy::body::DynBody;

/// Every built-in plugin, registered by default.
pub fn all() -> Vec<Box<dyn RustPlugin>> {
    vec![
        Box::new(EchoPlugin),
        Box::new(TagPlugin),
        Box::new(StampPlugin),
        Box::new(UpperPlugin),
        Box::new(WsUpperPlugin),
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
            ws_frame: false,
            pipe_request: false,
            pipe_response: false,
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

/// `pipe://upper` — uppercases a body **as it streams**, frame by frame.
///
/// The reference for the streaming hook: note that it never sees, or needs, the
/// whole body. Each frame is transformed and forwarded on the spot, so an SSE
/// stream piped through it still arrives event by event.
struct UpperPlugin;

impl RustPlugin for UpperPlugin {
    fn name(&self) -> &str {
        "upper"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            name: self.name().to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            on_request: false,
            on_response: false,
            request_body: false,
            response_body: false,
            ws_frame: false,
            pipe_request: true,
            pipe_response: true,
        }
    }

    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult::default()
    }

    fn pipe(&self, _dir: Dir, _meta: &PipeMeta, body: DynBody) -> DynBody {
        body.map_frame(|frame| frame.map_data(|data| Bytes::from(data.to_ascii_uppercase())))
            .boxed()
    }
}

/// `pipe://ws-upper` — uppercases the **text frames** of a WebSocket, in both
/// directions.
///
/// The reference for the frame hook, and for its one discipline: it touches
/// whole text messages only — never a binary frame, never a fragment of
/// anything — and leaves everything else exactly as it arrived. Nothing here
/// decodes a payload to a `String` either: `to_ascii_uppercase` works on bytes,
/// so a text frame carrying multi-byte UTF-8 survives byte for byte.
struct WsUpperPlugin;

/// WebSocket opcode for a text message.
const OPCODE_TEXT: u8 = 0x1;

impl RustPlugin for WsUpperPlugin {
    fn name(&self) -> &str {
        "ws-upper"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            name: self.name().to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            on_request: false,
            on_response: false,
            request_body: false,
            response_body: false,
            ws_frame: true,
            pipe_request: false,
            pipe_response: false,
        }
    }

    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult::default()
    }

    fn on_ws_frame(&self, _meta: &FrameMeta, frame: &HookFrame) -> Verdict {
        if frame.opcode != OPCODE_TEXT || !frame.fin {
            return Verdict::Keep;
        }
        Verdict::Replace(Bytes::from(frame.payload.to_ascii_uppercase()))
    }
}
