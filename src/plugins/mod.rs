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
//!   "hooks": ["request", "response", "pipeRequest", "pipeResponse"],
//!   "requestBody": false, "responseBody": true }
//! ```
//!
//! A plugin that does not serve `/manifest` — it answers the route with `404` —
//! is treated as **protocol v1**: request hook only, no bodies, dispatched to
//! `POST /`. Existing plugins therefore keep working untouched.
//!
//! Anything else that is not a manifest — no answer, a `5xx`, a body that is
//! not a JSON object — is **not** v1. It is a plugin whose capabilities are
//! unknown, and the requests matched against it are blocked until it says what
//! it is: see [`RemotePlugin::manifest`].
//!
//! The hooks fall into families, and which family runs is chosen by the *rule*,
//! not the plugin:
//!
//! | Rule | Hooks | Body |
//! |------|-------|------|
//! | `plugin://name[/param]` | `request`, `response` | buffered whole, opt-in |
//! | `pipe://name[(value)]`  | `pipeRequest`, `pipeResponse` | streamed, never buffered |
//! | either, on a WebSocket   | `wsFrame` | one frame at a time |
//!
//! `pipe://` on a plugin that declares no pipe hook falls back to the buffered
//! hooks, which is what it has always meant. `wsFrame` is reached by *both*
//! schemes, because a WebSocket offers no buffered-versus-streaming choice for
//! the scheme to express — see [`wsframe`].
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
//!
//! ### `POST /pipe/request`, `POST /pipe/response` — streaming hooks
//!
//! The request body *is* the body being proxied and the reply body *is* what
//! replaces it, both chunked; metadata rides in one header. Nothing is buffered
//! at either end. See [`pipe`] for the exchange and why it is HTTP rather than
//! whistle's CONNECT + `transproto` framing.
//!
//! ### `POST /ws/frames` — the WebSocket frame hook
//!
//! One long-lived connection per direction of a tunnelled WebSocket, carrying
//! one length-prefixed record per data frame and one verdict record back. See
//! [`wsframe`] for the record format and why frames need one.
//!
//! ### `POST /auth` — the gate
//!
//! Runs before everything else in the request phase and decides whether the
//! request proceeds at all. It is the one hook that **fails closed**: a plugin
//! that declares `auth` and then cannot be reached blocks the requests it was
//! matched against, rather than waving them through. See [`auth`].
//!
//! ### `POST /stats` — fire and forget
//!
//! Told what went past, once before the request is forwarded (`reqStats`) and
//! once after the response head arrives (`resStats`). Nothing waits for it and
//! the reply is discarded, which is what makes it safe on the request path. See
//! [`stats`].
//!
//! ### `GET|POST /ui/…` — the plugin's own pages
//!
//! The web UI routes `/plugin/<name>/…` to the plugin, prefix stripped, as an
//! ordinary HTTP hop. A UI request deliberately carries no proxied-request
//! context — see [`ui`].

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::OnceCell;

use crate::proxy::body::DynBody;
use crate::proxy::upstream;
use crate::rules::Resolved;

/// What a plugin can do, so the proxy only pays for what is actually used.
///
/// The body flags are the load-bearing part: buffering a body defeats streaming,
/// so whistle-rs does it only when a matched plugin declares it needs one.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    pub name: String,
    pub version: Option<String>,
    /// The proxy runs this plugin's **request phase**. True when any hook of
    /// that phase is declared — [`auth`](Self::auth), [`req_stats`](Self::req_stats)
    /// or [`request_hook`](Self::request_hook) — because they are dispatched
    /// from one place, in that order.
    pub on_request: bool,
    /// Serves the buffered `POST /request` hook specifically.
    pub request_hook: bool,
    /// The proxy runs this plugin's **response phase**: the buffered
    /// [`response_hook`](Self::response_hook), the [`res_stats`](Self::res_stats)
    /// ping, or both. This is the flag the proxy gates dispatch on; a
    /// stats-only plugin would otherwise never be called.
    pub on_response: bool,
    /// Serves the buffered `POST /response` hook specifically.
    pub response_hook: bool,
    /// Wants the request body buffered and handed over.
    pub request_body: bool,
    /// Wants the response body buffered and handed over.
    pub response_body: bool,
    /// Serves the streaming `POST /pipe/request` hook.
    pub pipe_request: bool,
    /// Serves the streaming `POST /pipe/response` hook.
    pub pipe_response: bool,
    /// Serves the WebSocket frame hook, `POST /ws/frames`.
    pub ws_frame: bool,
    /// Serves `POST /auth` — the gate that decides whether a request proceeds.
    /// The only hook whose failure blocks rather than degrades; see [`auth`].
    pub auth: bool,
    /// Serves `POST /sni` — the certificate chooser, consulted during the TLS
    /// handshake of an intercepted connection. See [`sni`].
    pub sni: bool,
    /// Serves the fire-and-forget request-phase `POST /stats`.
    pub req_stats: bool,
    /// Serves the fire-and-forget response-phase `POST /stats`.
    pub res_stats: bool,
    /// Serves `GET|POST /ui/…` — the plugin's own pages, routed from the web UI
    /// at `/plugin/<name>/`.
    pub ui: bool,
}

impl PluginManifest {
    /// Whether a `pipe://` rule has a *body* streaming hook to reach on this
    /// plugin. When it does not, `pipe://` keeps its historical meaning — an
    /// alias for `plugin://`.
    ///
    /// Deliberately excludes [`ws_frame`](Self::ws_frame): the frame hook has
    /// nothing to say about how an HTTP body is handled, and a plugin that
    /// declares only `wsFrame` must not change what `pipe://` means for one.
    pub fn has_pipe_hook(&self) -> bool {
        self.pipe_request || self.pipe_response
    }

    /// Whether this plugin serves the streaming hook for `dir`.
    pub fn serves_pipe(&self, dir: pipe::Dir) -> bool {
        match dir {
            pipe::Dir::Request => self.pipe_request,
            pipe::Dir::Response => self.pipe_response,
        }
    }

    /// A manifest declaring nothing, to build on. Adding a hook to the protocol
    /// therefore never has to touch every existing declaration.
    pub fn none(name: &str) -> Self {
        PluginManifest {
            name: name.to_string(),
            version: None,
            on_request: false,
            request_hook: false,
            on_response: false,
            response_hook: false,
            request_body: false,
            response_body: false,
            pipe_request: false,
            pipe_response: false,
            ws_frame: false,
            auth: false,
            sni: false,
            req_stats: false,
            res_stats: false,
            ui: false,
        }
    }

    /// What we assume when a plugin does not serve `/manifest`: the original
    /// protocol — a request hook, no bodies.
    pub fn v1_fallback(name: &str) -> Self {
        PluginManifest {
            on_request: true,
            request_hook: true,
            ..PluginManifest::none(name)
        }
    }

    /// Parse a manifest document; every missing field defaults to "not supported".
    fn parse(name: &str, bytes: &[u8]) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        // `"ok"` and `[]` are JSON too, and every lookup below would answer
        // "not declared" for them — a manifest declaring nothing, where the
        // truth is that the plugin said something unintelligible.
        if !v.is_object() {
            return None;
        }
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
        let has = |h: &str| hooks.iter().any(|k| k == h);
        let (request_hook, response_hook) = (has("request"), has("response"));
        let (auth, req_stats, res_stats) = (has("auth"), has("reqstats"), has("resstats"));
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
            on_request: request_hook || auth || req_stats,
            request_hook,
            on_response: response_hook || res_stats,
            response_hook,
            request_body: flag("requestBody"),
            response_body: flag("responseBody"),
            pipe_request: has("piperequest"),
            pipe_response: has("piperesponse"),
            ws_frame: has("wsframe"),
            auth,
            sni: has("sni"),
            req_stats,
            res_stats,
            ui: has("ui"),
        })
    }
}

/// One matched `plugin://` or `pipe://` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMatch {
    /// The plugin name — everything before a `/param` suffix or `(value)`.
    pub name: String,
    /// The `/…` suffix after the name, a routing hint inside one plugin.
    pub param: String,
    /// The `(…)` value of `pipe://name(value)` — whistle's `pipeValue`.
    pub pipe_value: Option<String>,
    /// Matched through `pipe://` (streaming) rather than `plugin://` (buffered).
    pub via_pipe: bool,
}

/// Collect the `plugin://` and `pipe://` rules that matched this request.
///
/// Lives here rather than beside the other rule readers because the two schemes
/// have different value grammars, and only the plugin runtime cares which:
/// `plugin://name/param` routes inside a plugin, while `pipe://name(value)`
/// carries an opaque argument (whistle's `PIPE_PLUGIN_RE`, which also tolerates
/// the `whistle.`/`plugin.` package prefixes real whistle plugins are named
/// with). A name is taken once per scheme, in rule order.
pub fn matched(resolved: &Resolved) -> Vec<PluginMatch> {
    let mut out: Vec<PluginMatch> = Vec::new();
    for (proto, via_pipe) in [("plugin", false), ("pipe", true)] {
        for op in resolved.all(proto) {
            let Some(m) = parse_match(&op.value, via_pipe) else {
                continue;
            };
            if !out
                .iter()
                .any(|o| o.name == m.name && o.via_pipe == m.via_pipe)
            {
                out.push(m);
            }
        }
    }
    out
}

/// Parse one rule value into a [`PluginMatch`]. Returns `None` for an empty name.
///
/// The extra grammar — `(value)` and the package prefixes — is `pipe://`-only,
/// so `plugin://` keeps parsing exactly as it always has.
fn parse_match(value: &str, via_pipe: bool) -> Option<PluginMatch> {
    let value = value.trim();
    if let Some((head, arg)) = via_pipe.then(|| split_pipe_arg(value)).flatten() {
        let name = clean_name(head);
        return (!name.is_empty()).then(|| PluginMatch {
            name,
            param: String::new(),
            pipe_value: Some(arg.to_string()),
            via_pipe,
        });
    }
    let head = value.split(['/', '?']).next().unwrap_or("").trim();
    let name = if via_pipe {
        clean_name(head)
    } else {
        head.to_string()
    };
    if name.is_empty() {
        return None;
    }
    Some(PluginMatch {
        param: value[head.len()..].trim_start_matches('/').to_string(),
        name,
        pipe_value: None,
        via_pipe,
    })
}

/// Parse an `sniCallback://[whistle.|plugin.]<name>(<value>)` rule value into
/// the plugin name and its argument.
///
/// Shares [`split_pipe_arg`] and [`clean_name`] with `pipe://` because it is
/// literally the same grammar — upstream writes it out twice, as `PIPE_PLUGIN_RE`
/// and as `SNI_CALLBACK_RE` (`_original/lib/https/load-cert.js:7-8`), with the
/// same package prefixes and the same greedy `([\s\S]*)` argument. An absent
/// `(…)` gives an empty value, which is what a plugin sees as `ctx.value`.
pub fn parse_sni_rule(value: &str) -> Option<(String, String)> {
    let value = value.trim();
    let (head, arg) = match split_pipe_arg(value) {
        Some((head, arg)) => (head, arg.to_string()),
        None => (value, String::new()),
    };
    let name = clean_name(head);
    (!name.is_empty()).then_some((name, arg))
}

/// Split `name(value)`, the `pipe://` argument grammar. The argument runs to the
/// *final* `)`, so it may itself contain slashes, parens and whitespace.
fn split_pipe_arg(value: &str) -> Option<(&str, &str)> {
    let open = value.find('(')?;
    let close = value.rfind(')')?;
    (close > open).then(|| (&value[..open], &value[open + 1..close]))
}

/// Strip the `whistle.` / `plugin.` package prefixes whistle plugin names carry,
/// as `PIPE_PLUGIN_RE` does.
fn clean_name(raw: &str) -> String {
    let raw = raw.trim();
    for prefix in ["whistle.", "plugin."] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    raw.to_string()
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
    /// This [`response`](Self::response) is a **refusal** from the [`auth`] gate,
    /// not an answer the plugin chose to give.
    ///
    /// The difference is who may still touch it. An answer is an ordinary
    /// response and every response hook runs over it; a refusal is pinned as
    /// produced, because a gate another plugin can rewrite is not a gate.
    /// Upstream pins it the same way and for the same reason — it hands the
    /// denial back as `* ignore://!statusCode|!resBody|!resType|!resCharset …`,
    /// which ignores every other rule on the request
    /// (`_original/lib/plugins/index.js:936-959`).
    pub blocked: bool,
    /// Why the gate blocked this request when the plugin *failed* — could not
    /// be reached, did not answer in time, answered nonsense — rather than
    /// refused. The request's session carries it as a failure, where a refusal
    /// is the plugin's answer and is not one.
    pub failure: Option<String>,
    /// Why the request hook itself failed — unreachable, an error status, no
    /// answer within [`HOOK_TIMEOUT`] — when it did. The request goes on as if
    /// the hook had said nothing, and the session says it did not run.
    pub hook_failed: Option<String>,
}

/// What a plugin's response hook returns. All fields optional — an empty result
/// leaves the response exactly as it was.
#[derive(Default)]
pub struct PluginResResult {
    pub status: Option<u16>,
    pub set_headers: Vec<(String, String)>,
    pub remove_headers: Vec<String>,
    pub body: Option<Vec<u8>>,
    /// Why the response hook failed, when it did — see
    /// [`PluginResult::hook_failed`].
    pub hook_failed: Option<String>,
}

/// How long a request or response hook may take before the request goes on
/// without it.
///
/// There was no bound: a plugin that accepted the call and never answered held
/// the request forever, while the documentation said a timeout was treated as
/// "no-op". Longer than the gates' 5 s ([`auth::AUTH_TIMEOUT`]), because these
/// hooks may be handed a whole body to work on.
pub const HOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a plugin has to answer `GET /manifest`. The gate's own budget: an
/// unanswered manifest blocks the request just as an unanswered verdict does.
const MANIFEST_TIMEOUT: std::time::Duration = auth::AUTH_TIMEOUT;

/// How long a manifest fetch that learned nothing is remembered before the
/// plugin is asked again.
///
/// One request asks several times — does any plugin want the body, then the
/// request phase itself — and a plugin that accepts connections and never
/// answers would otherwise cost each of them [`MANIFEST_TIMEOUT`]. Short,
/// because the other side of it is how long a recovered plugin stays blocked.
const MANIFEST_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// The plugin name a `plugin://` or `pipe://` rule value names, if any.
pub fn match_name(value: &str, via_pipe: bool) -> Option<String> {
    parse_match(value, via_pipe).map(|m| m.name)
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

    /// Decide whether the request may proceed. Default: it may.
    ///
    /// Runs *before* [`on_request`](RustPlugin::on_request), and a denial stops
    /// the request there and then — no later plugin's hooks run. Only consulted
    /// when the manifest declares [`PluginManifest::auth`].
    fn auth(&self, _req: &PluginReq) -> auth::AuthVerdict {
        auth::AuthVerdict::Allow(Vec::new())
    }

    /// Choose the certificate for an intercepted TLS connection, or decline the
    /// interception. Default: no opinion.
    ///
    /// Runs inside the handshake, before any request exists, so an
    /// implementation must be quick — the client is waiting on it. Only
    /// consulted when the manifest declares [`PluginManifest::sni`] and an
    /// `sniCallback://` rule named this plugin. See [`sni`].
    fn sni(&self, _req: &sni::SniReq) -> sni::SniVerdict {
        sni::SniVerdict::Generated
    }

    /// Told that a request went past, before it is forwarded. Default: ignore.
    ///
    /// Nothing is returned, and nothing waits: a stats hook observes, it does
    /// not decide. Runs in the request task, so it must be quick.
    fn on_req_stats(&self, _req: &PluginReq) {}

    /// Told how a request turned out. Default: ignore.
    fn on_res_stats(&self, _res: &PluginRes) {}

    /// Serve one of this plugin's own UI pages. Default: nothing here.
    ///
    /// Receives the browser's request with the `/plugin/<name>` prefix stripped
    /// — and no proxied-request context, deliberately; see [`ui`].
    fn ui(&self, _req: &ui::UiReq) -> ui::UiResp {
        ui::UiResp::not_found()
    }

    /// Observe or rewrite the upstream response. Default: no change.
    fn on_response(&self, _res: &PluginRes) -> PluginResResult {
        PluginResResult::default()
    }

    /// The streaming (`pipe://`) hook: wrap `body` so bytes are transformed as
    /// they flow. Default: identity — the body is returned untouched.
    ///
    /// Implementations must not collect the body; doing so silently reintroduces
    /// the buffering the pipe hooks exist to avoid.
    fn pipe(&self, _dir: pipe::Dir, _meta: &pipe::PipeMeta, body: DynBody) -> DynBody {
        body
    }

    /// The WebSocket frame hook: inspect or rewrite one frame of a tunnelled
    /// session. Default: forward it unchanged.
    ///
    /// Called once per data frame per direction, in the tunnel's own task, so
    /// an implementation must be quick and must not block — every frame in that
    /// direction waits behind it.
    fn on_ws_frame(
        &self,
        _meta: &wsframe::FrameMeta,
        _frame: &wsframe::HookFrame,
    ) -> wsframe::Verdict {
        wsframe::Verdict::Keep
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
    /// listening yet at registration time. Set only by a fetch that learned
    /// something; see [`RemotePlugin::manifest`].
    manifest: OnceCell<PluginManifest>,
    /// The last fetch that learned nothing, and when. Answers the callers that
    /// ask again within [`MANIFEST_RETRY`] without dialling the plugin again.
    manifest_failed: std::sync::Mutex<Option<(std::time::Instant, String)>>,
    /// [`MANIFEST_RETRY`], except in a test of recovery.
    manifest_retry: std::time::Duration,
    /// [`HOOK_TIMEOUT`], except in a test that cannot wait thirty seconds.
    hook_timeout: std::time::Duration,
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
            manifest_failed: std::sync::Mutex::new(None),
            manifest_retry: MANIFEST_RETRY,
            hook_timeout: HOOK_TIMEOUT,
        }
    }

    /// The plugin's manifest: fetched on first use, cached once it is known,
    /// and `Err` saying why while it is not.
    ///
    /// Three answers, and only two of them are knowledge:
    ///
    /// * `200` with a JSON object — the manifest. Cached for good.
    /// * `404` — the plugin has no such route, which is what protocol v1 looks
    ///   like. Cached for good as [`PluginManifest::v1_fallback`].
    /// * anything else — refused connection, no answer in [`MANIFEST_TIMEOUT`],
    ///   a `5xx`, a body that is not a JSON object — is **not cached as
    ///   anything**. The plugin is asked again, at most once per
    ///   [`MANIFEST_RETRY`].
    ///
    /// The third used to be cached as v1, forever. A plugin that declares
    /// `auth` and answered its first `/manifest` with a `503` — still starting,
    /// briefly overloaded — was from then on a plugin with no gate: every
    /// request it was matched against went to the origin, and `/auth` was never
    /// called again, however healthy the plugin became. The gate's own
    /// fail-closed rule ([`auth`]) was sound and unreachable.
    async fn manifest(&self) -> Result<&PluginManifest, String> {
        if let Some(known) = self.manifest.get() {
            return Ok(known);
        }
        if let Some((at, why)) = self.manifest_failed.lock().unwrap().as_ref()
            && at.elapsed() < self.manifest_retry
        {
            return Err(why.clone());
        }
        match self.manifest.get_or_try_init(|| self.discover()).await {
            Ok(known) => {
                *self.manifest_failed.lock().unwrap() = None;
                Ok(known)
            }
            Err(why) => {
                tracing::warn!("plugin {}: manifest unavailable: {why}", self.name);
                *self.manifest_failed.lock().unwrap() =
                    Some((std::time::Instant::now(), why.clone()));
                Err(why)
            }
        }
    }

    /// Ask the plugin what it is. `Err` is "could not find out".
    async fn discover(&self) -> Result<PluginManifest, String> {
        let url = format!("{}/manifest", self.base_url);
        let fetched = tokio::time::timeout(MANIFEST_TIMEOUT, async {
            // The same brief retry every other call to a plugin gets: one that
            // was spawned a moment ago may still be binding its port.
            let mut last = None;
            for attempt in 0..3 {
                match upstream::simple_get(&url).await {
                    Ok(pair) => return Ok(pair),
                    Err(e) => last = Some(e),
                }
                if attempt + 1 < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            Err(last.expect("three attempts, three errors"))
        })
        .await;
        match fetched {
            Ok(Ok((200, bytes))) => {
                let m = PluginManifest::parse(&self.name, &bytes)
                    .ok_or_else(|| "the manifest is not a JSON object".to_string())?;
                tracing::info!(
                    "plugin {} manifest: request={} response={} reqBody={} resBody={}",
                    self.name,
                    m.on_request,
                    m.on_response,
                    m.request_body,
                    m.response_body,
                );
                if m.has_pipe_hook() {
                    tracing::info!(
                        "plugin {} streaming hooks: pipeRequest={} pipeResponse={}",
                        self.name,
                        m.pipe_request,
                        m.pipe_response
                    );
                }
                if m.ws_frame {
                    tracing::info!("plugin {} hooks WebSocket frames", self.name);
                }
                Ok(m)
            }
            // "No such route" is an answer about the plugin, and the one a v1
            // plugin gives. Nothing else is: a plugin that is starting, broken
            // or overloaded answers `5xx` or not at all.
            Ok(Ok((404, _))) => {
                tracing::info!("plugin {} serves no /manifest; assuming v1", self.name);
                Ok(PluginManifest::v1_fallback(&self.name))
            }
            Ok(Ok((status, _))) => Err(format!("/manifest answered {status}")),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Err(_) => Err(format!("no manifest within {MANIFEST_TIMEOUT:?}")),
        }
    }

    /// Run the request phase: the gate, then the ping, then the hook.
    ///
    /// The order is upstream's (`lib/plugins/index.js:929-960`) and it is the
    /// only one that makes sense: a blocked request has no rules to inject and
    /// nothing downstream to tell about.
    ///
    /// A plugin whose manifest could not be learned **blocks**: whether it has
    /// a gate is exactly what is not known, and guessing "no" is how a request
    /// gets past one. It is the [`auth`] rule — every failure blocks — applied
    /// one step earlier, to the question the gate depends on.
    async fn on_request(&self, req: &PluginReq) -> PluginResult {
        let manifest = match self.manifest().await {
            Ok(manifest) => manifest,
            Err(why) => {
                let denial = auth::Denial::unavailable(format!("manifest unavailable: {why}"));
                return PluginResult {
                    response: Some(auth::deny_response(&self.name, &denial).await),
                    blocked: true,
                    failure: denial.reason.clone(),
                    ..Default::default()
                };
            }
        };
        let mut admitted: Vec<(String, String)> = Vec::new();
        if manifest.auth {
            match self.auth(req).await {
                auth::AuthVerdict::Allow(headers) => admitted = headers,
                auth::AuthVerdict::Deny(denial) => {
                    if let Some(reason) = &denial.reason {
                        tracing::warn!("auth {}: {reason}; request blocked", self.name);
                    } else {
                        tracing::info!("auth {}: blocked {} {}", self.name, req.method, req.url);
                    }
                    return PluginResult {
                        response: Some(auth::deny_response(&self.name, &denial).await),
                        blocked: true,
                        failure: denial.reason.clone(),
                        ..Default::default()
                    };
                }
            }
        }
        if manifest.req_stats {
            stats::post(&self.name, &self.base_url, stats::request_payload(req));
        }
        if !manifest.request_hook {
            return PluginResult {
                set_headers: admitted,
                ..Default::default()
            };
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

        let mut result = match self.post(path, &payload.to_string()).await {
            Ok(Some(bytes)) => parse_request_result(&bytes),
            Ok(None) => PluginResult::default(),
            Err(why) => PluginResult {
                hook_failed: Some(why),
                ..Default::default()
            },
        };
        // The gate's headers go on first, so a plugin's own request hook can
        // still override what its auth hook set — the narrower hook wins.
        admitted.append(&mut result.set_headers);
        result.set_headers = admitted;
        result
    }

    /// Ask the gate. Every failure is a denial; see [`auth`] for why.
    async fn auth(&self, req: &PluginReq) -> auth::AuthVerdict {
        let body = auth::payload(req).to_string();
        let call = self.post_status("/auth", &body);
        match tokio::time::timeout(auth::AUTH_TIMEOUT, call).await {
            Ok(Ok((200, bytes))) => auth::parse_reply(&bytes),
            // 204/304 are this protocol's "nothing to say", which for a gate
            // means it has no objection.
            Ok(Ok((204, _))) | Ok(Ok((304, _))) => auth::AuthVerdict::Allow(Vec::new()),
            Ok(Ok((status, _))) => {
                auth::AuthVerdict::Deny(auth::Denial::failed(format!("auth returned {status}")))
            }
            Ok(Err(e)) => auth::AuthVerdict::Deny(auth::Denial::failed(format!("{e:#}"))),
            Err(_) => auth::AuthVerdict::Deny(auth::Denial::failed(format!(
                "no verdict within {:?}",
                auth::AUTH_TIMEOUT
            ))),
        }
    }

    /// Ask for a certificate. `Err` is "could not ask", which is not the same as
    /// "had nothing to say" — see [`sni`] for what each one costs.
    async fn sni_cert(&self, req: &sni::SniReq) -> Result<sni::SniVerdict, String> {
        let body = sni::payload(req).to_string();
        let call = self.post_status("/sni", &body);
        match tokio::time::timeout(sni::SNI_TIMEOUT, call).await {
            Ok(Ok((200, bytes))) => Ok(sni::parse_reply(&bytes)),
            // This protocol's "nothing to say", which here is a real answer:
            // the plugin is not supplying a certificate for this name.
            Ok(Ok((204, _))) | Ok(Ok((304, _))) => Ok(sni::SniVerdict::Generated),
            Ok(Ok((status, _))) => Err(format!("returned {status}")),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Err(_) => Err(format!("no answer within {:?}", sni::SNI_TIMEOUT)),
        }
    }

    async fn on_response(&self, res: &PluginRes) -> PluginResResult {
        // The request phase blocked if the manifest was unknown, so a response
        // only gets here without one when no request phase ran — and then there
        // is nothing this plugin is known to want from it.
        let Ok(manifest) = self.manifest().await else {
            return PluginResResult::default();
        };
        if manifest.res_stats {
            stats::post(&self.name, &self.base_url, stats::response_payload(res));
        }
        if !manifest.response_hook {
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
            Ok(Some(bytes)) => parse_response_result(&bytes),
            Ok(None) => PluginResResult::default(),
            Err(why) => PluginResResult {
                hook_failed: Some(why),
                ..Default::default()
            },
        }
    }

    /// POST to a hook: `Ok(Some(body))` for a `200` to act on, `Ok(None)` for
    /// the idiomatic `204`/`304` "nothing to do", and `Err` saying why for
    /// anything else — unreachable, another status, no answer within
    /// [`HOOK_TIMEOUT`].
    ///
    /// The request goes on without the hook either way; the difference is that
    /// a failure is recorded on its session, where "nothing to do" is not.
    async fn post(&self, path: &str, body: &str) -> Result<Option<bytes::Bytes>, String> {
        let why = match tokio::time::timeout(self.hook_timeout, self.post_status(path, body)).await
        {
            Ok(Ok((200, bytes))) => return Ok(Some(bytes)),
            Ok(Ok((204 | 304, _))) => return Ok(None),
            Ok(Ok((status, _))) => format!("answered {status}"),
            Ok(Err(e)) => format!("{e:#}"),
            Err(_) => format!("no answer within {:?}", self.hook_timeout),
        };
        tracing::debug!("plugin {} {path} failed: {why}", self.name);
        Err(why)
    }

    /// POST to the plugin, retrying briefly: a freshly spawned plugin process
    /// may still be binding its port when the first request arrives.
    ///
    /// Keeps the status and the error, which the gate needs — for [`auth`] a
    /// plugin that answered `403` and a plugin that could not be reached are
    /// both denials, but only one of them is the plugin's own decision.
    async fn post_status(&self, path: &str, body: &str) -> anyhow::Result<(u16, bytes::Bytes)> {
        let url = format!("{}{path}", self.base_url);
        let mut last_err = None;
        for attempt in 0..3 {
            match upstream::simple_post_json(&url, body).await {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < 3 {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("plugin {} unreachable", self.name)))
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
        // A response the request hook chose to send is an answer, never a
        // refusal: refusals come from the `auth` gate, which is a different
        // route with a verdict of its own.
        blocked: false,
        failure: None,
        hook_failed: None,
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
        hook_failed: None,
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
        Some(serde_json::Value::Array(arr)) => arr.iter().map(value_to_string).collect(),
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
///
/// Native plugins are held behind an `Arc` so a long-lived hook (a WebSocket
/// frame hook outlives the call that opened it) can keep one alive without
/// borrowing the registry.
enum PluginKind {
    Rust(Arc<dyn RustPlugin>),
    Remote(Box<RemotePlugin>),
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
            .insert(plugin.name().to_string(), PluginKind::Rust(plugin.into()));
    }

    pub fn register_remote(&mut self, name: &str, host_port: &str) {
        self.map.insert(
            name.to_string(),
            PluginKind::Remote(Box::new(RemotePlugin::new(name, host_port))),
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

    /// The capability manifest for `name`: `None` when nothing by that name is
    /// registered, or when a remote plugin has not been able to say what it is.
    ///
    /// Every caller reads `None` as "do not run this hook", which is the right
    /// answer for the optional ones — a body nobody asked for is not buffered,
    /// a pipe nobody declared is not opened. The request phase does not go
    /// through here: [`Plugins::on_request`] blocks on an unknown manifest.
    pub async fn manifest(&self, name: &str) -> Option<PluginManifest> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => Some(p.manifest()),
            PluginKind::Remote(r) => r.manifest().await.ok().cloned(),
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

    /// Run plugin `name`'s request phase. Returns `None` if no such plugin.
    ///
    /// The gate runs first and a denial comes back as
    /// [`PluginResult::response`], which the proxy already knows how to serve
    /// and which already ends the plugin chain — the same stop upstream gets by
    /// abandoning the remaining plugins' rules (`lib/plugins/index.js:929-936`).
    pub async fn on_request(&self, name: &str, req: &PluginReq) -> Option<PluginResult> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => {
                let manifest = p.manifest();
                let mut admitted: Vec<(String, String)> = Vec::new();
                if manifest.auth {
                    match p.auth(req) {
                        auth::AuthVerdict::Allow(headers) => {
                            admitted = headers;
                            // The same restriction the wire protocol applies, so
                            // both runtimes honour one contract.
                            admitted.retain(|(k, _)| auth::allowed_request_header(k));
                        }
                        auth::AuthVerdict::Deny(denial) => {
                            tracing::info!("auth {name}: blocked {} {}", req.method, req.url);
                            return Some(PluginResult {
                                response: Some(auth::deny_response(name, &denial).await),
                                blocked: true,
                                failure: denial.reason.clone(),
                                ..Default::default()
                            });
                        }
                    }
                }
                if manifest.req_stats {
                    p.on_req_stats(req);
                }
                let mut result = p.on_request(req);
                admitted.append(&mut result.set_headers);
                result.set_headers = admitted;
                Some(result)
            }
            PluginKind::Remote(r) => Some(r.on_request(req).await),
        }
    }

    /// Run plugin `name`'s response phase. Returns `None` if no such plugin.
    pub async fn on_response(&self, name: &str, res: &PluginRes) -> Option<PluginResResult> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => {
                let manifest = p.manifest();
                if manifest.res_stats {
                    p.on_res_stats(res);
                }
                if !manifest.response_hook {
                    return Some(PluginResResult::default());
                }
                Some(p.on_response(res))
            }
            PluginKind::Remote(r) => Some(r.on_response(res).await),
        }
    }

    /// Ask plugin `name` which certificate to present for an intercepted TLS
    /// connection.
    ///
    /// `Err` means the plugin could not be asked — unregistered, silent, slow,
    /// or answering something that is not a reply. The caller distinguishes it
    /// from [`sni::SniVerdict::Generated`] ("asked, nothing to say") because the
    /// two do different things to the cached certificate; see
    /// [`crate::proxy::sni::decide`].
    ///
    /// A plugin that does not declare the hook is *not* an error: a rule can
    /// name a plugin that has no `sni` hook, and that means the same thing as
    /// having no opinion.
    pub async fn sni_cert(&self, name: &str, req: &sni::SniReq) -> Result<sni::SniVerdict, String> {
        let Some(plugin) = self.map.get(name) else {
            return Err(format!("no plugin named {name}"));
        };
        match plugin {
            PluginKind::Rust(p) => Ok(if p.manifest().sni {
                p.sni(req)
            } else {
                sni::SniVerdict::Generated
            }),
            PluginKind::Remote(r) => {
                // Could not ask, which the caller treats differently from
                // "asked, nothing to say".
                if !r.manifest().await?.sni {
                    return Ok(sni::SniVerdict::Generated);
                }
                r.sni_cert(req).await
            }
        }
    }

    /// Serve one of plugin `name`'s own pages.
    ///
    /// `None` means "not a plugin UI": no such plugin, or one that declares no
    /// `ui` hook. The web UI turns that into its own 404 rather than inventing
    /// a page.
    pub async fn serve_ui(
        &self,
        name: &str,
        req: hyper::Request<DynBody>,
    ) -> Option<hyper::Response<DynBody>> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => {
                if !p.manifest().ui {
                    return None;
                }
                let (parts, mut body) = req.into_parts();
                // Bounded like every console body, read frame by frame (see
                // `webui::read_body` for why not `Limited`). Over the limit is
                // a 413; it used to be read whole, however large.
                let mut bytes = Vec::new();
                while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
                    // A read error ends the body; a trailers frame is skipped.
                    let Ok(frame) = frame else { break };
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if bytes.len() + data.len() > crate::config::CONSOLE_BODY_LIMIT {
                        return Some(ui::error_page(
                            hyper::StatusCode::PAYLOAD_TOO_LARGE,
                            &format!("plugin {name}: request body over the console's limit"),
                        ));
                    }
                    bytes.extend_from_slice(&data);
                }
                let ureq = ui::UiReq {
                    method: parts.method.as_str().to_string(),
                    path: parts.uri.path().to_string(),
                    query: parts.uri.query().unwrap_or("").to_string(),
                    headers: parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                        })
                        .collect(),
                    body: bytes,
                };
                Some(p.ui(&ureq).into_response())
            }
            PluginKind::Remote(r) => {
                if !r.manifest().await.ok()?.ui {
                    return None;
                }
                Some(match ui::forward(name, &r.base_url, req).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::debug!("ui {name}: {e:#}");
                        ui::error_page(
                            hyper::StatusCode::BAD_GATEWAY,
                            &format!("plugin {name} UI unavailable: {e}"),
                        )
                    }
                })
            }
        }
    }

    /// Names of the registered plugins that serve their own UI, sorted.
    pub async fn ui_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for name in self.names() {
            if matches!(self.manifest(&name).await, Some(m) if m.ui) {
                out.push(name);
            }
        }
        out
    }

    /// Route `body` through plugin `name`'s streaming hook for `dir`.
    ///
    /// Always returns a usable body: an unknown plugin, an undeclared hook or a
    /// failed handshake all yield `body` unchanged. Nothing here reads the body,
    /// so a request whose plugins declare no pipe hook is not slowed at all.
    pub async fn pipe(
        &self,
        name: &str,
        dir: pipe::Dir,
        meta: &pipe::PipeMeta,
        body: DynBody,
    ) -> DynBody {
        let Some(plugin) = self.map.get(name) else {
            return body;
        };
        match plugin {
            PluginKind::Rust(p) => {
                if p.manifest().serves_pipe(dir) {
                    p.pipe(dir, meta, body)
                } else {
                    body
                }
            }
            PluginKind::Remote(r) => {
                if matches!(r.manifest().await, Ok(m) if m.serves_pipe(dir)) {
                    pipe::transform(name, &r.base_url, dir, meta, body).await
                } else {
                    body
                }
            }
        }
    }

    /// Open plugin `name`'s frame hook for one direction of a WebSocket session.
    ///
    /// `None` — the common answer — means the session runs exactly as it would
    /// with no plugin at all: an unknown plugin, one that declares no frame
    /// hook, or a remote one that could not be reached. A plugin that cannot be
    /// dialled is never allowed to cost the WebSocket anything.
    pub async fn ws_frame_hook(
        &self,
        name: &str,
        meta: &wsframe::FrameMeta,
    ) -> Option<wsframe::FrameHook> {
        match self.map.get(name)? {
            PluginKind::Rust(p) => p.manifest().ws_frame.then(|| wsframe::FrameHook::Native {
                name: name.to_string(),
                plugin: p.clone(),
                meta: meta.clone(),
            }),
            PluginKind::Remote(r) => {
                if !r.manifest().await.ok()?.ws_frame {
                    return None;
                }
                match wsframe::connect(name, &r.base_url, meta).await {
                    Ok(hook) => Some(wsframe::FrameHook::Remote(hook)),
                    Err(e) => {
                        tracing::warn!(
                            "wsFrame {name} ({}): {e:#}; frames forwarded unchanged",
                            meta.dir.label()
                        );
                        None
                    }
                }
            }
        }
    }
}

pub mod auth;
pub mod builtin;
pub mod pipe;
pub mod sni;
pub mod stats;
pub mod ui;
pub mod wsframe;

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
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
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
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
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
        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "text/plain")
        );
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
        assert_eq!(
            parse_response_result(br#"{"statusCode":9000}"#).status,
            None
        );
        assert_eq!(parse_response_result(br#"{"statusCode":0}"#).status, None);
        assert_eq!(
            parse_response_result(br#"{"statusCode":302}"#).status,
            Some(302)
        );
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
        assert!(!m.has_pipe_hook());
        assert!(PluginManifest::parse("p", b"not json").is_none());
    }

    #[test]
    fn manifest_declares_streaming_hooks() {
        let m = PluginManifest::parse("p", br#"{"hooks":["pipeResponse"]}"#).unwrap();
        assert!(m.has_pipe_hook());
        assert!(m.serves_pipe(pipe::Dir::Response));
        assert!(!m.serves_pipe(pipe::Dir::Request));
        // Streaming hooks are independent of the buffered ones and of the body
        // flags — a pipe plugin never asks the proxy to buffer.
        assert!(!m.on_response && !m.response_body);
    }

    /// `pipe://name(value)` — whistle's `pipeValue`, with the package prefixes
    /// real whistle plugin names carry.
    #[test]
    fn pipe_rule_value_syntax() {
        let m = parse_match("upper(shout loudly)", true).unwrap();
        assert_eq!(m.name, "upper");
        assert_eq!(m.pipe_value.as_deref(), Some("shout loudly"));
        assert!(m.via_pipe);

        // The argument is opaque: slashes and nested parens survive intact.
        let nested = parse_match("p(a/b(c))", true).unwrap();
        assert_eq!(nested.name, "p");
        assert_eq!(nested.pipe_value.as_deref(), Some("a/b(c)"));

        for raw in ["whistle.upper", "plugin.upper"] {
            assert_eq!(parse_match(raw, true).unwrap().name, "upper");
        }
        assert!(parse_match("(x)", true).is_none());
    }

    /// `plugin://` parses exactly as it always has: no `(…)` grammar, no prefix
    /// stripping, `/param` preserved.
    #[test]
    fn plugin_rule_value_syntax_unchanged() {
        let m = parse_match("my-plugin/deep/param", false).unwrap();
        assert_eq!(m.name, "my-plugin");
        assert_eq!(m.param, "deep/param");
        assert!(m.pipe_value.is_none() && !m.via_pipe);

        assert_eq!(parse_match("whistle.x", false).unwrap().name, "whistle.x");
        assert_eq!(parse_match("p(v)", false).unwrap().name, "p(v)");
        assert!(parse_match("  ", false).is_none());
    }

    #[test]
    fn matched_keeps_schemes_apart() {
        let mut mgr = crate::rules::RuleManager::new();
        mgr.set_text("example.com plugin://a\nexample.com pipe://a(v)\nexample.com pipe://a(w)\n");
        let info = crate::proxy::apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let ms = matched(&mgr.resolve(&info));
        // The same plugin may appear once per scheme; a repeated scheme does not.
        assert_eq!(ms.len(), 2);
        assert!(ms.iter().any(|m| !m.via_pipe && m.pipe_value.is_none()));
        assert!(
            ms.iter()
                .any(|m| m.via_pipe && m.pipe_value.as_deref() == Some("v"))
        );
    }

    /// The load-bearing property: a plugin that declares no streaming hook must
    /// hand the body straight back, untouched and unread.
    #[test]
    fn no_streaming_hook_means_no_pipe() {
        let p = Plugins::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let meta = pipe::PipeMeta::default();
            // `stamp` has a response hook but no streaming one.
            let out = p
                .pipe(
                    "stamp",
                    pipe::Dir::Response,
                    &meta,
                    crate::proxy::body::full("as-is"),
                )
                .await;
            assert_eq!(collect(out).await, b"as-is");
            // An unregistered name is equally harmless.
            let out = p
                .pipe(
                    "nope",
                    pipe::Dir::Response,
                    &meta,
                    crate::proxy::body::full("as-is"),
                )
                .await;
            assert_eq!(collect(out).await, b"as-is");
        });
    }

    /// The built-in Rust pipe plugin transforms frame by frame, and only in the
    /// directions it declares.
    #[test]
    fn rust_pipe_plugin_transforms_each_frame() {
        let p = Plugins::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let meta = pipe::PipeMeta::default();
            let (tx, source) = crate::proxy::body::channel(4);
            let out = p.pipe("upper", pipe::Dir::Response, &meta, source).await;
            tokio::spawn(async move {
                for part in ["ab", "cd"] {
                    tx.send(Ok(bytes::Bytes::from_static(part.as_bytes())))
                        .await
                        .ok();
                }
            });
            // Two frames in, two frames out — a transform, not a collect.
            let mut frames = Vec::new();
            let mut out = out;
            while let Some(Ok(f)) = http_body_util::BodyExt::frame(&mut out).await {
                if let Ok(d) = f.into_data() {
                    frames.push(String::from_utf8_lossy(&d).into_owned());
                }
            }
            assert_eq!(frames, vec!["AB", "CD"]);
        });
    }

    /// Drain a body into bytes (test helper).
    async fn collect(body: DynBody) -> Vec<u8> {
        use http_body_util::BodyExt;
        body.collect()
            .await
            .map(|c| c.to_bytes().to_vec())
            .unwrap_or_default()
    }

    // -- the auth gate, the stats pings and the UI hook ----------------------

    /// A minimal plugin server: answers the given routes and records every path
    /// it was asked for, so a test can assert what was *not* called.
    struct FakePlugin {
        url: String,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
        routes: Arc<std::sync::Mutex<Routes>>,
    }

    /// What a fake plugin answers: `(path, status, body)`.
    type Routes = Vec<(&'static str, u16, String)>;

    impl FakePlugin {
        fn paths(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }

        /// Change what `path` answers from now on — a plugin that was starting
        /// and has now started.
        fn set(&self, path: &'static str, status: u16, body: &str) {
            let mut routes = self.routes.lock().unwrap();
            routes.retain(|(p, _, _)| *p != path);
            routes.push((path, status, body.to_string()));
        }
    }

    /// Start a fake plugin. `routes` maps a path to `(status, body)`; anything
    /// else gets a 404.
    async fn fake_plugin(routes: Routes) -> FakePlugin {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let routes = Arc::new(std::sync::Mutex::new(routes));
        let served = routes.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let routes = served.clone();
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    while sock.read_exact(&mut byte).await.is_ok() {
                        buf.push(byte[0]);
                        if buf.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    // The body is read too, though nothing looks at it: a
                    // socket closed with unread bytes is reset, and Windows
                    // then drops the answer the client had not read yet —
                    // every POST here failed there as "connection reset".
                    let length = head
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    sock.read_exact(&mut body).await.ok();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    recorder.lock().unwrap().push(path.clone());
                    let (status, body) = routes
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|(p, _, _)| *p == path)
                        .map(|(_, s, b)| (*s, b.clone()))
                        .unwrap_or((404, String::new()));
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.flush().await.ok();
                });
            }
        });
        FakePlugin { url, seen, routes }
    }

    /// `hooks: ["auth","request"]`, whose gate refuses everything.
    const GATED: &str = r#"{"name":"p","version":"1","hooks":["auth","request"]}"#;

    /// A remote plugin that asks again at once after a failed manifest fetch,
    /// so a test of recovery does not have to wait out [`MANIFEST_RETRY`].
    fn impatient(url: &str) -> RemotePlugin {
        let mut plugin = RemotePlugin::new("p", url);
        plugin.manifest_retry = std::time::Duration::ZERO;
        plugin
    }

    /// The defect this guards against: the first `/manifest` answered `503`,
    /// that was cached as "protocol v1, no gate", and from then on every
    /// request matched against the plugin reached the origin — `/auth` was
    /// never called, however long the plugin had been healthy.
    #[test]
    fn a_manifest_that_fails_first_blocks_and_is_asked_again() {
        rt().block_on(async {
            for (status, body) in [(503, ""), (200, "<html>starting</html>"), (200, "[]")] {
                let fake = fake_plugin(vec![
                    ("/manifest", status, body.to_string()),
                    ("/auth", 200, r#"{"allow":false}"#.into()),
                    ("/request", 200, r#"{"rules":"* resHeaders://x=1"}"#.into()),
                    // A v1 plugin answers here; nothing may be sent to it.
                    ("/", 200, r#"{"rules":"* resHeaders://v1=1"}"#.into()),
                ])
                .await;
                let plugin = impatient(&fake.url);

                let out = plugin.on_request(&req()).await;
                let resp = out.response.expect("an unknown plugin must block");
                assert_eq!(resp.status, 502, "manifest {status} {body:?}");
                assert!(out.blocked && out.rules.is_none());
                let why = out.failure.expect("and the session says why");
                assert!(why.contains("manifest unavailable"), "{why}");
                assert_eq!(
                    fake.paths(),
                    vec!["/manifest"],
                    "no hook may run before the plugin has said what it is"
                );

                // The plugin comes up. It declares a gate, and the gate refuses.
                fake.set("/manifest", 200, GATED);
                let out = plugin.on_request(&req()).await;
                let resp = out.response.expect("the gate refuses");
                assert_eq!(resp.status, 403, "the plugin's own refusal, not a failure");
                assert!(out.blocked && out.failure.is_none());
                assert!(
                    fake.paths().iter().any(|p| p == "/auth"),
                    "the gate was asked"
                );
                assert!(
                    !fake.paths().iter().any(|p| p == "/request" || p == "/"),
                    "and nothing ran behind it: {:?}",
                    fake.paths()
                );
            }
        });
    }

    /// A plugin that is not there at all is the same case: nothing is known
    /// about it, so nothing gets past it.
    #[test]
    fn an_unreachable_plugin_blocks_until_it_appears() {
        rt().block_on(async {
            // Bind a port, note it, and let it go: nothing is listening there.
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap().to_string();
            drop(l);
            let plugin = impatient(&addr);
            let out = plugin.on_request(&req()).await;
            assert_eq!(out.response.expect("blocked").status, 502);
            assert!(out.blocked && out.failure.is_some());
        });
    }

    /// `404` is the one non-manifest answer that *is* knowledge: the plugin has
    /// no such route, which is what the first protocol looks like. It keeps
    /// working, and it is asked only once.
    #[test]
    fn a_plugin_with_no_manifest_route_is_the_first_protocol() {
        rt().block_on(async {
            let fake = fake_plugin(vec![(
                "/",
                200,
                r#"{"rules":"* resHeaders://v1=1"}"#.into(),
            )])
            .await;
            let plugin = impatient(&fake.url);
            for _ in 0..2 {
                let out = plugin.on_request(&req()).await;
                assert!(out.response.is_none() && !out.blocked);
                assert_eq!(out.rules.as_deref(), Some("* resHeaders://v1=1"));
            }
            assert_eq!(fake.paths(), vec!["/manifest", "/", "/"]);
        });
    }

    /// A failed fetch is remembered for [`MANIFEST_RETRY`], so the several
    /// questions one request asks cost one dial between them — and a plugin
    /// that accepts and never answers cannot charge each of them the timeout.
    #[test]
    fn a_failed_manifest_fetch_is_not_repeated_at_once() {
        rt().block_on(async {
            let fake = fake_plugin(vec![("/manifest", 503, String::new())]).await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);
            assert!(p.manifest("p").await.is_none());
            assert!(!p.any_wants_request_body(&["p".to_string()]).await);
            let out = p.on_request("p", &req()).await.expect("registered");
            assert!(out.blocked);
            assert_eq!(fake.paths(), vec!["/manifest"]);
        });
    }

    fn manifest_route(hooks: &str) -> (&'static str, u16, String) {
        (
            "/manifest",
            200,
            format!(r#"{{"name":"p","version":"1","hooks":[{hooks}]}}"#),
        )
    }

    /// A refusal and an answer are both a `response`, and the proxy has to tell
    /// them apart: every response hook runs over an answer, none over a refusal.
    /// Pinning the classification here means the exit only has a flag to read.
    #[test]
    fn a_refusal_is_marked_and_an_answer_is_not() {
        rt().block_on(async {
            let p = Plugins::new();
            // `gate` refuses a request that carries no token.
            let denied = p.on_request("gate", &req()).await.expect("registered");
            assert!(denied.response.is_some(), "the gate refused");
            assert!(denied.blocked, "a refusal must be marked as one");

            // `echo` answers every request, by choice.
            let answered = p.on_request("echo", &req()).await.expect("registered");
            assert!(answered.response.is_some(), "echo answers");
            assert!(
                !answered.blocked,
                "an answer is an ordinary response, not a refusal"
            );
        });
    }

    /// The fail-closed property, stated as a test: a plugin that declares `auth`
    /// and then cannot answer must block, not admit.
    #[test]
    fn a_failing_auth_plugin_blocks() {
        rt().block_on(async {
            // Declares auth, but every /auth call 500s.
            let fake = fake_plugin(vec![
                manifest_route(r#""auth","request""#),
                ("/auth", 500, String::new()),
                ("/request", 200, r#"{"rules":"* resHeaders://x=1"}"#.into()),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let out = p.on_request("p", &req()).await.expect("registered");
            let resp = out.response.expect("a failing gate must produce a block");
            assert_eq!(resp.status, 502, "a broken gate is not a refusal");
            assert!(out.rules.is_none(), "a blocked request gets no rules");
            // The request hook must not have run behind a failed gate.
            assert!(!fake.paths().iter().any(|p| p == "/request"));
        });
    }

    /// A request hook that accepts the call and never answers is given up on,
    /// and the request goes on: there was no bound at all, and such a plugin
    /// held every request it matched for as long as it stayed silent.
    #[test]
    fn a_hook_that_never_answers_is_given_up_on() {
        rt().block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = l.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if buf[..n].starts_with(b"GET /manifest") {
                            let m = r#"{"name":"p","version":"1","hooks":["request"]}"#;
                            let reply = format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{m}",
                                m.len()
                            );
                            let _ = sock.write_all(reply.as_bytes()).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    });
                }
            });
            let mut plugin = RemotePlugin::new("p", &addr.to_string());
            plugin.hook_timeout = std::time::Duration::from_millis(200);
            let started = std::time::Instant::now();
            let out = plugin.on_request(&req()).await;
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            let why = out.hook_failed.expect("the silence is reported");
            assert!(why.contains("no answer within"), "{why}");
            assert!(out.response.is_none() && out.rules.is_none(), "and nothing applied");
        });
    }

    /// Same property when the plugin is not there at all.
    #[test]
    fn an_unreachable_auth_plugin_blocks() {
        rt().block_on(async {
            let fake = fake_plugin(vec![manifest_route(r#""auth""#)]).await;
            let url = fake.url.clone();
            let mut p = Plugins::new();
            p.register_remote("p", &url);
            // Warm the manifest cache, then take the plugin away.
            assert!(p.manifest("p").await.expect("manifest").auth);
            drop(fake);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            // The port may or may not still accept; either way the verdict
            // never arrives, and either way the request must be blocked.
            let out = p.on_request("p", &req()).await.expect("registered");
            let resp = out.response.expect("an absent gate must block");
            assert_eq!(resp.status, 502);
        });
    }

    /// An admitted request keeps going, and the gate's headers are filtered to
    /// the identifying subset.
    #[test]
    fn an_allowed_request_proceeds_with_filtered_headers() {
        rt().block_on(async {
            let fake = fake_plugin(vec![
                manifest_route(r#""auth","request""#),
                (
                    "/auth",
                    200,
                    r#"{"allow":true,"setHeaders":{"x-whistle-user":"bob","cookie":"stolen"}}"#
                        .into(),
                ),
                (
                    "/request",
                    200,
                    r#"{"setHeaders":{"x-from-hook":"1"}}"#.into(),
                ),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let out = p.on_request("p", &req()).await.expect("registered");
            assert!(out.response.is_none(), "an allowed request is not answered");
            assert_eq!(
                out.set_headers,
                vec![
                    ("x-whistle-user".to_string(), "bob".to_string()),
                    ("x-from-hook".to_string(), "1".to_string()),
                ]
            );
            assert!(fake.paths().iter().any(|p| p == "/request"));
        });
    }

    /// A plugin that declares no `auth` hook is never asked for a verdict — the
    /// gate costs a matched plugin nothing unless it wants one.
    #[test]
    fn a_plugin_without_the_hook_is_never_gated() {
        rt().block_on(async {
            let fake = fake_plugin(vec![
                manifest_route(r#""request""#),
                ("/request", 200, "{}".into()),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let out = p.on_request("p", &req()).await.expect("registered");
            assert!(out.response.is_none());
            assert_eq!(fake.paths(), vec!["/manifest", "/request"]);
        });
    }

    /// A deliberate refusal is a 403 with the plugin's own page, and it stops
    /// the plugin before its request hook.
    #[test]
    fn a_refusal_serves_the_plugins_page() {
        rt().block_on(async {
            let fake = fake_plugin(vec![
                manifest_route(r#""auth","request""#),
                ("/auth", 200, r#"{"allow":false,"html":"<b>no</b>"}"#.into()),
                ("/request", 200, "{}".into()),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let resp = p
                .on_request("p", &req())
                .await
                .expect("registered")
                .response
                .expect("refused");
            assert_eq!(resp.status, 403);
            assert_eq!(resp.body, b"<b>no</b>");
            assert!(
                resp.headers
                    .iter()
                    .any(|(k, v)| k == auth::AUTH_HEADER && v == "p")
            );
            assert!(!fake.paths().iter().any(|p| p == "/request"));
        });
    }

    /// Stats are dispatched from the phases the proxy already runs, and never
    /// waited for. A stats-only plugin still gets its response-phase ping, which
    /// only works because the manifest reports the phase as needed.
    #[test]
    fn stats_only_plugin_is_still_dispatched() {
        rt().block_on(async {
            let fake = fake_plugin(vec![
                manifest_route(r#""reqStats","resStats""#),
                ("/stats", 200, String::new()),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let m = p.manifest("p").await.expect("manifest");
            assert!(
                m.on_request && m.on_response,
                "both phases must be dispatched"
            );
            assert!(
                !m.request_hook && !m.response_hook,
                "but neither hook is served"
            );

            p.on_request("p", &req()).await.expect("registered");
            let res = PluginRes {
                id: 1,
                status: 204,
                ..Default::default()
            };
            p.on_response("p", &res).await.expect("registered");

            // Fire-and-forget: the pings are in flight, so wait for them here
            // rather than in the request path, which is the entire point.
            for _ in 0..50 {
                if fake.paths().iter().filter(|p| *p == "/stats").count() == 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(fake.paths().iter().filter(|p| *p == "/stats").count(), 2);
            // Nothing else was called: a stats plugin serves no buffered hook.
            assert!(
                !fake
                    .paths()
                    .iter()
                    .any(|p| p == "/request" || p == "/response")
            );
        });
    }

    /// The UI hop: prefix stripped here, `/ui` added on the way out.
    #[test]
    fn ui_requests_reach_the_plugin_under_the_ui_prefix() {
        rt().block_on(async {
            let fake = fake_plugin(vec![
                manifest_route(r#""ui""#),
                ("/ui/page.html?x=1", 200, "<h1>plugin</h1>".into()),
            ])
            .await;
            let mut p = Plugins::new();
            p.register_remote("p", &fake.url);

            let req = hyper::Request::builder()
                .uri("/page.html?x=1")
                .body(crate::proxy::body::empty())
                .expect("request");
            let resp = p.serve_ui("p", req).await.expect("a ui plugin answers");
            assert_eq!(resp.status(), 200);
            assert_eq!(collect(resp.into_body()).await, b"<h1>plugin</h1>");
            assert!(fake.paths().iter().any(|p| p == "/ui/page.html?x=1"));
        });
    }

    /// A plugin that declares no UI is not a UI: the web UI must be able to tell
    /// the difference and serve its own 404.
    #[test]
    fn plugins_without_a_ui_hook_are_not_routed() {
        rt().block_on(async {
            let mut p = Plugins::new();
            p.register_remote("p", "http://127.0.0.1:1");
            let request = || {
                hyper::Request::builder()
                    .uri("/")
                    .body(crate::proxy::body::empty())
                    .expect("request")
            };
            // Unknown plugin, and a registered one with no manifest at all.
            assert!(p.serve_ui("nope", request()).await.is_none());
            assert!(p.serve_ui("p", request()).await.is_none());
            // A built-in without the hook is equally not routed.
            assert!(p.serve_ui("echo", request()).await.is_none());
        });
    }

    /// The built-in gate, end to end in-process: block, admit, count, render.
    #[test]
    fn rust_gate_blocks_admits_and_serves_its_page() {
        rt().block_on(async {
            let p = Plugins::new();
            let mut anonymous = req();
            anonymous.param = "s3cret".into();
            anonymous.headers = vec![("host".into(), "example.com".into())];

            let blocked = p
                .on_request("gate", &anonymous)
                .await
                .expect("registered")
                .response
                .expect("no token means blocked");
            // No credentials at all asks for them; a wrong token does not.
            assert_eq!(blocked.status, 401);

            let mut wrong = anonymous.clone_for_test();
            wrong.headers.push(("x-gate-token".into(), "guess".into()));
            let blocked = p
                .on_request("gate", &wrong)
                .await
                .expect("registered")
                .response
                .expect("a wrong token is blocked");
            assert_eq!(blocked.status, 403);

            let mut right = anonymous.clone_for_test();
            right.headers.push(("x-gate-token".into(), "s3cret".into()));
            let out = p.on_request("gate", &right).await.expect("registered");
            assert!(out.response.is_none(), "the right token gets through");
            assert_eq!(
                out.set_headers,
                vec![("x-whistle-gate-user".to_string(), "s3cret".to_string())]
            );

            // The response phase pings the same plugin, in process.
            let res = PluginRes {
                id: 1,
                status: 200,
                ..Default::default()
            };
            p.on_response("gate", &res).await.expect("registered");

            let request = hyper::Request::builder()
                .uri("/stats.json")
                .body(crate::proxy::body::empty())
                .expect("request");
            let resp = p.serve_ui("gate", request).await.expect("gate serves a ui");
            assert_eq!(resp.status(), 200);
            let body = collect(resp.into_body()).await;
            let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(v["admitted"], 1);
            assert_eq!(v["blocked"], 2);
            assert_eq!(v["responses"], 1);
            assert_eq!(v["lastStatus"], 200);
        });
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    impl PluginReq {
        /// Copy a request for a second dispatch (test helper).
        fn clone_for_test(&self) -> PluginReq {
            PluginReq {
                id: self.id,
                method: self.method.clone(),
                url: self.url.clone(),
                headers: self.headers.clone(),
                client_ip: self.client_ip.clone(),
                param: self.param.clone(),
                body: self.body.clone(),
            }
        }
    }
}
