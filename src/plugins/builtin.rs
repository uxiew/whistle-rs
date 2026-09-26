//! Built-in Rust example plugins, demonstrating each hook. They double as
//! working references for writing native plugins.

use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::json;

use super::auth::{AuthVerdict, Denial, DenyPage};
use super::pipe::{Dir, PipeMeta};
use super::sni::{SniReq, SniVerdict};
use super::ui::{UiReq, UiResp, escape_html};
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
        Box::<GatePlugin>::default(),
        Box::new(NoMitmPlugin),
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
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            on_response: true,
            response_hook: true,
            ..PluginManifest::none(self.name())
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
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            pipe_request: true,
            pipe_response: true,
            ..PluginManifest::none(self.name())
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
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            ws_frame: true,
            ..PluginManifest::none(self.name())
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

/// `plugin://gate[/<token>]` — the reference for the three hooks that are not
/// about rewriting traffic: the **auth gate**, the **stats** pings, and a
/// **UI page** of its own.
///
/// It admits a request that presents `x-gate-token`, matching `<token>` when the
/// rule supplied one, and blocks everything else. Counting what it saw needs
/// state, which is the other thing it demonstrates: a plugin is a long-lived
/// object, and the hooks are called from the request tasks, so shared state
/// wants a lock. The lock is only ever held for the length of an increment —
/// never across an await, and never while a page is rendered.
///
/// Try it:
///
/// ```text
/// example.com  plugin://gate/s3cret
/// ```
///
/// then open `http://127.0.0.1:<proxy port>/plugin/gate/` for the tally.
#[derive(Default)]
struct GatePlugin {
    counts: Mutex<GateCounts>,
}

/// What [`GatePlugin`] has seen. Small on purpose: a stats hook that accumulated
/// per-request records would be a memory leak wearing a hook's clothes.
#[derive(Default, Clone)]
struct GateCounts {
    admitted: u64,
    blocked: u64,
    responses: u64,
    last_status: u16,
    /// Most recent request the request-phase stats hook was told about.
    last_request: String,
}

/// Request header carrying [`GatePlugin`]'s token.
const GATE_TOKEN_HEADER: &str = "x-gate-token";

impl GatePlugin {
    /// The token presented by this request, if any.
    fn presented(req: &PluginReq) -> Option<&str> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(GATE_TOKEN_HEADER))
            .map(|(_, v)| v.as_str())
    }
}

impl RustPlugin for GatePlugin {
    fn name(&self) -> &str {
        "gate"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            on_request: true,
            on_response: true,
            auth: true,
            req_stats: true,
            res_stats: true,
            ui: true,
            ..PluginManifest::none(self.name())
        }
    }

    fn auth(&self, req: &PluginReq) -> AuthVerdict {
        let presented = Self::presented(req);
        let ok = match (presented, req.param.as_str()) {
            (Some(token), expected) if !expected.is_empty() => token == expected,
            (Some(_), _) => true,
            (None, _) => false,
        };
        if !ok {
            self.counts.lock().unwrap().blocked += 1;
            return AuthVerdict::Deny(Denial {
                login: presented.is_none(),
                page: DenyPage::Html(
                    format!(
                        "<h1>Blocked by plugin://gate</h1><p>{} <code>{GATE_TOKEN_HEADER}</code>.</p>",
                        if presented.is_none() { "This request carried no" } else { "Wrong" }
                    )
                    .into_bytes(),
                ),
                ..Denial::forbidden()
            });
        }
        self.counts.lock().unwrap().admitted += 1;
        // Identify the caller downstream. Only `x-whistle-*` and
        // `proxy-authorization` survive the filter — an auth hook is not a
        // general-purpose header rewriter.
        AuthVerdict::Allow(vec![(
            "x-whistle-gate-user".to_string(),
            presented.unwrap_or_default().to_string(),
        )])
    }

    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult::default()
    }

    fn on_req_stats(&self, req: &PluginReq) {
        let mut counts = self.counts.lock().unwrap();
        counts.last_request = format!("{} {}", req.method, req.url);
    }

    fn on_res_stats(&self, res: &PluginRes) {
        let mut counts = self.counts.lock().unwrap();
        counts.responses += 1;
        counts.last_status = res.status;
    }

    fn ui(&self, req: &UiReq) -> UiResp {
        // Cloned out from under the lock: rendering a page is not something to
        // do while holding one.
        let counts = self.counts.lock().unwrap().clone();
        let value = json!({
            "plugin": "gate",
            "admitted": counts.admitted,
            "blocked": counts.blocked,
            "responses": counts.responses,
            "lastStatus": counts.last_status,
            "lastRequest": counts.last_request,
        });
        match req.path.as_str() {
            "/" | "" => UiResp::html(format!(
                "<!doctype html><meta charset=utf-8><title>plugin://gate</title>\
                 <style>body{{font:14px/1.6 system-ui;margin:2rem;max-width:40rem}}\
                 td{{padding:.2rem 1rem .2rem 0}}code{{background:#eee;padding:0 .3rem}}</style>\
                 <h1>plugin://gate</h1>\
                 <p>Admits requests presenting <code>{GATE_TOKEN_HEADER}</code>, blocks the rest.</p>\
                 <table><tr><td>admitted<td>{}<tr><td>blocked<td>{}\
                 <tr><td>responses seen<td>{}<tr><td>last status<td>{}\
                 <tr><td>last request<td>{}</table>\
                 <p><a href=\"stats.json\">stats.json</a></p>",
                counts.admitted,
                counts.blocked,
                counts.responses,
                counts.last_status,
                escape_html(&counts.last_request)
            )),
            "/stats.json" => UiResp::json(&value),
            _ => UiResp::not_found(),
        }
    }
}

/// `sniCallback://no-mitm` — decline to intercept, whatever the host.
///
/// The one certificate answer that needs no certificate, and the one nothing
/// else in this proxy can express: the connection stays encrypted between the
/// client and the origin, and whistle-rs relays the bytes without looking. Use
/// it for the hosts that pin their certificates, or that no one is debugging.
///
/// ```text
/// pinned.example.com  sniCallback://no-mitm
/// ```
///
/// The rule is matched against `https://<the name in the ClientHello>`, so it
/// takes ordinary host patterns — and, because the decision is made before any
/// request exists, that name is all there is to match on.
struct NoMitmPlugin;

impl RustPlugin for NoMitmPlugin {
    fn name(&self) -> &str {
        "no-mitm"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            sni: true,
            ..PluginManifest::none(self.name())
        }
    }

    fn sni(&self, _req: &SniReq) -> SniVerdict {
        SniVerdict::Bypass
    }

    /// Declared for the trait, never reached: this plugin's manifest offers no
    /// request hook, so `plugin://no-mitm` matches nothing to run.
    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult::default()
    }
}
