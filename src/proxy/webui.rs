//! The console, served when a client hits the proxy port directly (or the
//! console port): the embedded single-page app, and the HTTP API it and any
//! script use — traffic, rules, values, replay — plus the root CA and a PAC
//! file. [`handle`] is the route table; the work is one kind per file:
//!
//! | file | what it does |
//! | --- | --- |
//! | `access` | who may use the console: Host/Origin checks, `--allow-origin`, the login and guest account |
//! | `console_hosts` | the hostnames the console answers through the proxy (`rootca.pro` …) |
//! | `sessions`, `har` | captured traffic: list, search, detail, bodies, frames, status; HAR export |
//! | `logs` | what `log://` pages wrote to their consoles |
//! | `rules`, `values`, `bundle` | rules and rule groups, the Values store, both as one file |
//! | `composer` | replay, the Composer, Test Rules |
//! | `plugin_pages` | a plugin's own pages under `/plugin/<name>/` |

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::body::{self, DynBody};
use super::{AppState, Capture, ReplayBody, Session, WsFrame};

// One file per kind of work the console does. Each takes what it needs from
// here with `use super::*` and is imported whole, so the rest of the proxy
// still names everything `webui::…`. What was private here is `pub(super)`
// there, and what was `pub(super)` is `pub(in super::super)`: the same reach
// each had before.
mod access;
mod bundle;
mod composer;
mod console_hosts;
mod har;
mod logs;
mod plugin_pages;
mod rules;
mod sessions;
mod switches;
mod values;

pub(super) use access::*;
use bundle::*;
use composer::*;
pub(super) use console_hosts::*;
use har::*;
use logs::*;
use plugin_pages::*;
use rules::*;
use sessions::*;
use switches::*;
use values::*;

/// Route a direct (non-proxied) request to the UI / API.
pub async fn handle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let path = req.uri().path().to_string();
    // Read before the request is consumed; applied to whatever answers.
    let cors = allowed_origin(state, &req, &path);
    // `-M headless`: no console. The root certificate and the PAC file answer
    // anyway — a client that cannot fetch them cannot be configured to use the
    // proxy at all, and upstream keeps its own two open under `headless` for the
    // same reason (measured: `/cgi-bin/rootca` and `/cgi-bin/status` answer, the
    // rest is 404).
    if !state.config.console
        && !open_without_login(&path)
        && !ALIVE_WHEN_HEADLESS.contains(&path.as_str())
    {
        return not_found();
    }
    // A browser acting for another site, or reached through a hostname that is
    // not ours. Before the login: a request that is refused for where it came
    // from learns nothing about the credentials either.
    if let Some(refused) = cross_site_refused(state, &req, &path) {
        return refused;
    }
    // The login, when one is configured. Before the route table, and before the
    // plugin subtree: a plugin's own pages are part of the console.
    if let Some(denied) = login_required(state, &req, &path) {
        return denied;
    }
    // `/plugin/<name>/…` belongs to a plugin, not to us. Checked before the
    // route table because the tail is arbitrary — it is the plugin's own URL
    // space, and nothing here may reserve a path inside it.
    if crate::plugins::ui::split_route(&path).is_some() {
        return plugin_ui(state, req).await;
    }
    let mut answer = match (req.method().as_str(), path.as_str()) {
        (_, "/rootCA.crt") | (_, "/rootca.crt") => root_ca(state),
        (_, "/proxy.pac") | (_, "/pac") => pac(state, &req),
        (_, "/sessions.json") => sessions_json(state, req.uri().query()),
        ("GET", "/api/sessions/search") => sessions_search(state, &req).await,
        (_, "/sessions.har") => sessions_har(state, &req),
        (_, "/session.json") => session_detail_json(state, &req),
        (_, "/body.bin") => session_body_bytes(state, &req),
        (_, "/frames.json") => frames_json(state, &req),
        ("GET", "/api/rules") => rules_get(state),
        ("POST", "/api/rules") => rules_post(state, req).await,
        ("GET", "/api/values") => values_get(state),
        ("POST", "/api/values") => values_post(state, req).await,
        ("POST", "/api/value") => value_set(state, req).await,
        ("POST", "/api/value/rename") => value_rename(state, req).await,
        ("DELETE", "/api/value") => value_delete(state, req).await,
        ("POST", "/api/replay") => replay_session(state, req).await,
        ("POST", "/api/composer") => compose_request(state, req).await,
        ("POST", "/api/explain") => explain_rules(state, req).await,
        ("GET", "/api/export") => bundle_export(state),
        ("POST", "/api/import") => bundle_import(state, req).await,
        ("GET", "/api/rule-groups") => rule_groups_get(state),
        ("POST", "/api/rule-groups") => rule_groups_add(state, req).await,
        ("POST", "/api/rule-group/toggle") => rule_group_toggle(state, req).await,
        ("POST", "/api/rule-group/update") => rule_group_update(state, req).await,
        ("GET", "/api/rule-group") => rule_group_get(state, &req),
        ("DELETE", "/api/rule-group") => rule_group_delete(state, req).await,
        ("GET", "/api/qr") => qr_svg(&req),
        ("GET", "/api/ws/status") => ws_status(state, &req),
        ("POST", "/api/ws/release") => ws_release(state, req).await,
        ("POST", "/api/ws/send") => ws_send(state, req).await,
        // Takes a body now: the console can forget just the rows it selected.
        ("POST", "/api/sessions/clear") => sessions_clear(state, req).await,
        // Clear only tidies memory; this deletes what persistence wrote too.
        ("POST", "/api/sessions/purge") => sessions_purge(state).await,
        ("GET", "/api/logs") => logs_get(state, &req),
        ("POST", "/api/logs/clear") => logs_clear(state, req).await,
        ("GET", "/api/switches") => switches_get(state),
        ("POST", "/api/switches") => switches_set(state, req).await,
        ("POST", "/api/plugin/switch") => plugin_switch(state, req).await,
        ("GET", "/api/status") => status_json(state, status_body_restricted(state, &req)).await,
        ("GET", "/plugin") => redirect_to("/plugin/"),
        ("GET", "/") | ("GET", "/index.html") => html_ok(index_html(state)),
        _ => not_found(),
    };
    if let Some(origin) = cors {
        let headers = answer.headers_mut();
        if let Ok(value) = hyper::header::HeaderValue::from_str(&origin) {
            headers.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                hyper::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                hyper::header::HeaderValue::from_static("true"),
            );
        }
    }
    answer
}

/// The web UI's own 404 — in the API's refusal shape, since most of what asks
/// for a path that is not here is a script asking the API.
fn not_found() -> Response<DynBody> {
    api_error(StatusCode::NOT_FOUND, "not found")
}

fn root_ca(state: &Arc<AppState>) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/x-x509-ca-cert")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whix-rootCA.crt\"",
        )
        .body(body::full(Bytes::from(
            state.ca.root_cert_pem().to_string(),
        )))
        .unwrap()
}

fn pac(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                state
                    .config
                    .host
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                state.config.port
            )
        });
    let pac = format!("function FindProxyForURL(url, host) {{\n  return \"PROXY {host}\";\n}}\n");
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-ns-proxy-autoconfig",
        )
        .body(body::full(Bytes::from(pac)))
        .unwrap()
}

/// A console request's body, at most [`crate::config::CONSOLE_BODY_LIMIT`];
/// the error is the response to send, `413` when it is too big. Boxed for the
/// same reason as [`read_json_body`]'s.
async fn read_body(req: Request<Incoming>) -> Result<Bytes, Box<Response<DynBody>>> {
    let limit = crate::config::CONSOLE_BODY_LIMIT;
    // Read frame by frame rather than through `http_body_util::Limited`: its
    // boxed `dyn Error` made every future holding this one fail rustc's
    // `Send` check ("implementation of `Send` is not general enough").
    let mut body = req.into_body();
    let mut buf = bytes::BytesMut::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Err(Box::new(api_error(
                StatusCode::BAD_REQUEST,
                "could not read the request body",
            )));
        };
        if let Some(data) = frame.data_ref() {
            if buf.len() + data.len() > limit {
                return Err(Box::new(api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!(
                        "request body over the console's {} MiB limit",
                        limit / (1024 * 1024)
                    ),
                )));
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(buf.freeze())
}

/// Helper: read request body as JSON.
///
/// The error is the ready-made 400 to send back, boxed: a bare
/// `Response<DynBody>` is 128+ bytes, and it would ride along in every `Ok`
/// too. Only a malformed request pays for the allocation.
async fn read_json_body(
    req: Request<Incoming>,
) -> Result<serde_json::Value, Box<Response<DynBody>>> {
    let body = read_body(req).await?;
    serde_json::from_slice(&body).map_err(|e| Box::new(refused(&format!("invalid JSON: {e}"))))
}

fn json_ok() -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from_static(b"{\"ok\":true}")))
        .unwrap()
}

fn json_error(msg: &str) -> Response<DynBody> {
    api_error(StatusCode::BAD_REQUEST, msg)
}

/// Every refusal the console's API makes, in one shape: `status`, JSON, and
/// `{ok: false, error}`. The console reads every answer as JSON, and an agent
/// should not have to sniff which of three shapes a failure came in — some
/// were plain text, one was JSON built with `format!` that broke on the quotes
/// in its own message.
fn api_error(status: StatusCode, msg: &str) -> Response<DynBody> {
    let body = serde_json::json!({ "ok": false, "error": msg });
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body.to_string())))
        .unwrap()
}

/// The hooks a manifest declares, named the way the docs name them.
fn hook_names(m: &crate::plugins::PluginManifest) -> Vec<&'static str> {
    [
        (m.request_hook, "request"),
        (m.response_hook, "response"),
        (m.pipe_request, "pipe/request"),
        (m.pipe_response, "pipe/response"),
        (m.ws_frame, "ws/frames"),
        (m.auth, "auth"),
        (m.sni, "sniCallback"),
        (m.req_stats || m.res_stats, "stats"),
    ]
    .into_iter()
    .filter_map(|(on, name)| on.then_some(name))
    .collect()
}

/// A QR code for a URL, as an SVG — `GET /api/qr?text=…&scale=…`.
///
/// What `gui/mobile.md` is a whole page about: reading an address off a screen
/// and into a phone is where a setup goes wrong, and a camera does not mistype.
/// The console draws one per LAN address beside the certificate link.
///
/// The text is never markup here — it becomes modules — so there is nothing to
/// escape and nothing a payload can do to the page it is drawn on. A payload
/// larger than the encoder takes is a 400 rather than a broken image, and the
/// console falls back to showing the link.
fn qr_svg(req: &Request<Incoming>) -> Response<DynBody> {
    let text = query_param(req, "text").unwrap_or_default();
    if text.is_empty() {
        return json_error("nothing to encode");
    }
    // Clamped rather than trusted: a scale is a multiplier on a square, and an
    // unbounded one is a denial of service written in someone else's query
    // string.
    let scale = query_param(req, "scale")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 20);
    match crate::qr::encode(&text) {
        Some(code) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "image/svg+xml")
            // A QR code for a fixed string never changes, and the console draws
            // several on every visit to the status pane.
            .header(hyper::header::CACHE_CONTROL, "public, max-age=3600")
            .body(body::full(Bytes::from(code.to_svg(scale))))
            .unwrap(),
        None => json_error("too long to encode"),
    }
}

fn html_ok(html: String) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body::full(Bytes::from(html)))
        .unwrap()
}

/// The console: the Vue application from `ui-src/`, built to one file.
///
/// The bundle is **not** in the repository — it is a generated 445 KB artifact
/// that changes wholesale on every UI build. `build.rs` copies
/// `ui-src/dist/index.html` into `OUT_DIR` when it has been built and writes a
/// placeholder page there when it has not, so `cargo build` still produces a
/// working binary on a machine with no node; `ui-src/README.md` says how to
/// build the real one. The choice is made before compilation because
/// `include_str!` cannot express "this file, or that one".
///
/// It is one file for a harder reason than convenience: the console is served by
/// the proxy being debugged, and has to load with the network it is inspecting
/// switched off. A second request for a chunk or a stylesheet could not be
/// relied on to arrive.
///
/// The three runtime facts the page needs are substituted here rather than
/// fetched, so the first paint needs no round trip.
fn index_html(state: &Arc<AppState>) -> String {
    let host = state
        .config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    include_str!(concat!(env!("OUT_DIR"), "/console.html"))
        .replace("__VERSION__", crate::config::VERSION)
        .replace("__HOST__", &host)
        .replace("__PORT__", &state.config.port.to_string())
}

#[cfg(test)]
mod tests {
    use crate::rules::protocols;

    /// The search box's filter language, run in the engine the proxy already
    /// carries — the same arrangement as the classifier below, and for the same
    /// reason: one copy of the logic, and a test that cannot drift from what the
    /// console actually does.
    ///
    /// The grammar is `gui/network.md`'s. What is pinned here is every prefix
    /// this console can answer, that a bare word still means the URL, that a
    /// `/regexp/` is one, that conditions are AND-ed, and — the part that made
    /// this worth writing — that a prefix it *cannot* answer is reported instead
    /// of quietly matching nothing.
    #[test]
    fn the_search_box_speaks_whistles_filter_language() {
        use boa_engine::{Context, Source};

        let mut ctx = Context::default();
        ctx.eval(Source::from_bytes(include_str!(
            "../../ui-src/src/filter/session-filter.js"
        )))
        .expect("session-filter.js evaluates");

        // One row, standing in for a busy capture.
        let row = r#"{
            id: 7, method: 'POST', url: 'https://api.example.com/v1/users?id=2',
            status: 404, client_ip: '10.1.2.3', target: '93.184.216.34:443',
            type: 'application/json; charset=utf-8',
            rules: [{ protocol: 'style', value: 'italic', raw: 'style://italic' }]
        }"#;
        let ask = |ctx: &mut Context, query: &str, marked: &str| -> bool {
            let script = format!(
                "(() => {{ const p = whistleParseFilter({query:?});\n\
                   return whistleMatchSession({row}, p.conditions, {{ marked: {marked} }}); }})()"
            );
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("the filter runs")
                .as_boolean()
                .expect("a boolean")
        };
        let unsupported = |ctx: &mut Context, query: &str| -> String {
            let script =
                format!("whistleParseFilter({query:?}).unsupported.map((u) => u.prefix).join(',')");
            let value = ctx
                .eval(Source::from_bytes(script.as_bytes()))
                .expect("parses");
            value.as_string().expect("a string").to_std_string_escaped()
        };

        for (query, want) in [
            // A bare word is the URL, as it always was.
            ("users", true),
            ("nothing-like-it", false),
            ("/v1/", true),
            // …and the prefixes, which used to be searched for as literal text.
            ("m:POST", true),
            ("m:GET", false),
            ("s:404", true),
            ("s:200", false),
            ("H:api.example.com", true),
            ("H:example.org", false),
            ("t:json", true),
            ("t:html", false),
            ("i:10.1.2.3", true),
            ("i:93.184", true),
            ("i:172.16", false),
            ("style:italic", true),
            ("style:bold", false),
            // `e:` is "did this go wrong", which the status answers.
            ("e:users", true),
            // A regexp, with and without flags.
            ("m:/^p/i", true),
            ("m:/^p/", false),
            // Several conditions are AND-ed.
            ("m:POST s:404", true),
            ("m:POST s:200", false),
            ("m:POST users t:json", true),
            // A colon that is not a prefix leaves the word alone.
            ("api.example.com/v1", true),
            // An unfinished regexp matches nothing rather than throwing.
            ("m:/^(", false),
        ] {
            assert_eq!(ask(&mut ctx, query, "[]"), want, "{query}");
        }

        // `mark:` reads the console's own list, not the row.
        assert!(!ask(&mut ctx, "mark:users", "[]"));
        assert!(ask(&mut ctx, "mark:users", "[7]"));
        assert!(!ask(&mut ctx, "mark:elsewhere", "[7]"));
        // `mark:` and `e:` with no value mean the *set*, not "match anything":
        // an empty needle is inside every string, so without this `e:` on its
        // own would select the whole capture — the opposite of what it says.
        assert!(!ask(&mut ctx, "mark:", "[]"));
        assert!(ask(&mut ctx, "mark:", "[7]"));
        assert!(ask(&mut ctx, "e:", "[]"), "the row is a 404");
        assert!(!ask(&mut ctx, "s:200 e:", "[]"), "and 200s are not errors");
        // …unless the proxy recorded that it did not complete: a 200 whose
        // body broke off went wrong, and `e:` finds it by the phase too.
        let broken = |ctx: &mut Context, query: &str| -> bool {
            let script = format!(
                "whistleMatchSession({{ id: 8, url: 'https://a.example/x', status: 200, \
                   error: {{ phase: 'response', message: 'the response body broke off' }} }}, \
                   whistleParseFilter({query:?}).conditions, {{ marked: [] }})"
            );
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("the filter runs")
                .as_boolean()
                .expect("a boolean")
        };
        assert!(broken(&mut ctx, "e:"));
        assert!(broken(&mut ctx, "e:response"));
        assert!(broken(&mut ctx, "e:broke"));
        assert!(!broken(&mut ctx, "e:dns"));

        // **A path is not a regexp.** A leading `/` looks like the start of one,
        // and a path is the most natural thing to type into these boxes: an
        // earlier split read `/heartbeat m:POST` as one unterminated regexp, so
        // it matched nothing at all and the filter silently did nothing. A slash
        // only opens a regexp when something later closes it.
        let count = |ctx: &mut Context, query: &str| -> f64 {
            let script = format!("whistleParseFilter({query:?}).conditions.length");
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("parses")
                .as_number()
                .expect("a number")
        };
        assert_eq!(count(&mut ctx, "/heartbeat m:POST"), 2.0);
        assert_eq!(count(&mut ctx, "/api/users"), 1.0);
        assert_eq!(count(&mut ctx, "/never-closes m:GET"), 2.0);
        // …and a regexp that really does contain a space stays one condition.
        assert_eq!(count(&mut ctx, "H:/a b/ m:GET"), 2.0);
        assert_eq!(count(&mut ctx, "H:/a b/"), 1.0);

        // Conditions join differently in the two places they are used: the
        // search box AND-s one line, the capture filters OR the contents of one
        // box (`gui/network.md`). Same parser, same conditions, different join.
        let any = |ctx: &mut Context, query: &str| -> bool {
            let script = format!(
                "(() => {{ const p = whistleParseFilter({query:?});
                   return whistleMatchAny({row}, p.conditions, {{ marked: [] }}); }})()"
            );
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("runs")
                .as_boolean()
                .expect("a boolean")
        };
        assert!(any(&mut ctx, "m:POST s:999"), "either may match");
        assert!(
            !ask(&mut ctx, "m:POST s:999", "[]"),
            "but both must, joined the other way"
        );
        assert!(
            !any(&mut ctx, "m:GET s:999"),
            "and neither matching is still no"
        );

        // `fc:` is the Composer's, and with a value its URL too.
        let composed = |ctx: &mut Context, composer: bool, query: &str| -> bool {
            let script = format!(
                "whistleMatchSession({{ id: 9, url: 'https://a.example/login', status: 200, \
                   composer: {composer} }}, whistleParseFilter({query:?}).conditions, {{ marked: [] }})"
            );
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("the filter runs")
                .as_boolean()
                .expect("a boolean")
        };
        assert!(composed(&mut ctx, true, "fc:"));
        assert!(!composed(&mut ctx, false, "fc:"), "fc: alone is the set");
        assert!(composed(&mut ctx, true, "fc:login"));
        assert!(!composed(&mut ctx, true, "fc:logout"));
        assert!(!composed(&mut ctx, false, "fc:login"));

        // `h:` and `b:` are answered by the proxy when the caller asks it to —
        // the search box does — and matched by id against its answer.
        let remote = |ctx: &mut Context, query: &str, answer: &str| -> bool {
            let script = format!(
                "(() => {{ const p = whistleParseFilter({query:?}, {{ remote: true }});
                   return whistleMatchSession({row}, p.conditions, {{ marked: [], remote: {answer} }}); }})()"
            );
            ctx.eval(Source::from_bytes(script.as_bytes()))
                .expect("runs")
                .as_boolean()
                .expect("a boolean")
        };
        assert!(remote(&mut ctx, "b:ok", "{ 'b:ok': [7] }"));
        assert!(!remote(&mut ctx, "b:ok", "{ 'b:ok': [8] }"));
        assert!(remote(&mut ctx, "h:x m:POST", "{ 'h:x': new Set([7]) }"));
        assert!(
            !remote(&mut ctx, "h:x m:GET", "{ 'h:x': [7] }"),
            "still AND-ed"
        );
        assert!(
            !remote(&mut ctx, "b:ok", "{}"),
            "no answer yet is not a match"
        );
        let remote_gaps = |ctx: &mut Context, query: &str| -> String {
            let script = format!(
                "whistleParseFilter({query:?}, {{ remote: true }}).unsupported.map((u) => u.prefix).join(',')"
            );
            let value = ctx
                .eval(Source::from_bytes(script.as_bytes()))
                .expect("parses");
            value.as_string().expect("a string").to_std_string_escaped()
        };
        assert_eq!(remote_gaps(&mut ctx, "h:cookie b:x fc:y"), "");

        // What cannot be answered is named, not dropped: `app:` anywhere, and
        // `h:`/`b:` where nobody will ask the proxy — the capture filters.
        assert_eq!(remote_gaps(&mut ctx, "app:wechat"), "app");
        assert_eq!(
            unsupported(&mut ctx, "h:cookie b:x app:wechat fc:y"),
            "h,b,app"
        );
        assert_eq!(unsupported(&mut ctx, "m:POST"), "");
        // An unsupported condition does not also silently filter everything out:
        // it is removed from the conditions and reported beside the box instead.
        assert!(ask(&mut ctx, "b:whatever m:POST", "[]"));
    }

    /// The rules editor highlights whichever token the proxy will treat as the
    /// **pattern**, and that is the whole reason the mode exists: whistle's line
    /// grammar is positional, `example.com http://localhost:5173` and
    /// `http://a.com/x host://1.2.3.4` look alike and split differently, and
    /// writing one the wrong way round is the most common way to get a rule that
    /// silently does nothing.
    ///
    /// So the two implementations have to agree — and they are in different
    /// languages, in different files, and neither would notice the other
    /// drifting. This runs the editor's classifier (in the JS engine the port
    /// already carries for `resScript` and PAC) over the same lines the parser
    /// gets, and holds the answers against each other.
    #[test]
    fn the_editor_and_the_parser_agree_on_what_a_pattern_is() {
        use boa_engine::{Context, Source};

        let mut ctx = Context::default();
        // The classifier is deliberately dependency-free, script-shaped
        // JavaScript so it can be evaluated here as well as bundled into the
        // console — see the note at the top of the file it comes from.
        ctx.eval(Source::from_bytes(include_str!(
            "../../ui-src/src/editor/whistle-classify.js"
        )))
        .expect("whistle-classify.js evaluates");

        for line in [
            // The forwarding rule, and the shape it is confused with.
            "example.com http://localhost:5173",
            "http://a.com/api host://1.1.1.1",
            "example.com localhost:5173",
            "example.com 1.2.3.4",
            "example.com 1.2.3.4:8080",
            // The swapped form, which is the only one that takes several patterns.
            "host://9.9.9.9 a.com b.com c.com",
            "proxy://1.1.1.1:8080 a.com b.com",
            "127.0.0.1 example.com",
            // Pattern kinds that announce themselves.
            "$example.com host://1.1.1.1",
            "!example.com host://1.1.1.1",
            ":8080 host://1.1.1.1",
            "/re/i host://1.1.1.1",
            "//a.com/x host://1.1.1.1",
            "^*.example.com/v0/** file:///mock/$1",
            "*.example.com/api reqHeaders://X-Tenant=$1",
            // Filters and line properties are neither.
            "a.com host://1.1.1.1 includeFilter://m:GET lineProps://important",
            "includeFilter://m:GET a.com host://1.1.1.1",
            // A line that configures nothing.
            "host://x proxy://y",
        ] {
            let js = format!(
                "JSON.stringify(whistleClassify({}).map(function(t){{return t.role}}))",
                serde_json::to_string(line).expect("a JSON string")
            );
            let editor: Vec<String> = serde_json::from_str(
                &ctx.eval(Source::from_bytes(js.as_bytes()))
                    .expect("classify runs")
                    .to_string(&mut ctx)
                    .expect("a string")
                    .to_std_string_escaped(),
            )
            .expect("an array of roles");

            assert_eq!(editor, parser_roles(line), "{line}");
        }
    }

    /// What the *parser* calls each token on `line`, in the editor's vocabulary.
    ///
    /// Read out of [`crate::rules::split_line`] — the function `parse_line`
    /// itself uses — rather than restated here, so this cannot agree with a
    /// parser that has since changed.
    fn parser_roles(line: &str) -> Vec<String> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let split = crate::rules::split_line(&tokens);
        tokens
            .iter()
            .map(|t| {
                let role = if t.starts_with("lineProps://") {
                    "props"
                } else if crate::rules::is_filter_spelling(t) {
                    "filter"
                } else {
                    match &split {
                        // No pattern: the line configures nothing.
                        None => "dead",
                        Some((patterns, _)) if patterns.contains(t) => "pattern",
                        Some(_) => "operator",
                    }
                };
                role.to_string()
            })
            .collect()
    }

    /// Every protocol the editor colours as an operator has to be one the parser
    /// recognises, or the highlighting would promise an effect that never comes.
    #[test]
    fn the_editors_filter_spellings_are_the_parsers() {
        for name in ["includeFilter", "excludeFilter", "filter", "ignore"] {
            assert!(
                crate::rules::is_filter_spelling(&format!("{name}://m:GET")),
                "{name}"
            );
        }
        assert!(!crate::rules::is_filter_spelling("host://1.2.3.4"));
        assert!(protocols::is_protocol(protocols::URL_REPLACE));
    }
}

#[cfg(test)]
mod api_doc_tests {
    use std::collections::BTreeSet;

    /// Every route the console answers, as `(method, path)`, read from the
    /// route table in this file — `"*"` where it answers any method.
    fn routes() -> BTreeSet<(String, String)> {
        let source = include_str!("webui.rs");
        let start = source
            .find("let mut answer = match (req.method().as_str(), path.as_str()) {")
            .expect("the route table");
        let table = &source[start..];
        let table = &table[..table.find("_ => not_found(),").expect("its end")];
        let arm = regex::Regex::new(r#"\((_|"([A-Z]+)"), "(/[^"]*)"\)"#).unwrap();
        arm.captures_iter(table)
            .map(|c| {
                let method = c.get(2).map_or("*", |m| m.as_str());
                (method.to_string(), c[3].to_string())
            })
            .collect()
    }

    /// Every `METHOD /path` docs/API.md names in code, and every other path
    /// it names in code — an alias written as a bare `/path` beside one.
    fn documented() -> (BTreeSet<(String, String)>, BTreeSet<String>) {
        let doc = include_str!("../../docs/API.md");
        let with_method = regex::Regex::new(r"`(GET|POST|DELETE|PUT) (/[^`?\s]*)").unwrap();
        let bare = regex::Regex::new(r"`(/[^`?\s]*)").unwrap();
        let routes = with_method
            .captures_iter(doc)
            .map(|c| (c[1].to_string(), c[2].to_string()))
            .collect();
        let paths = bare.captures_iter(doc).map(|c| c[1].to_string()).collect();
        (routes, paths)
    }

    /// The paths the document's `curl` examples call, with the method each
    /// uses: `-X POST` or `-d` make it a POST, as curl does.
    fn examples() -> Vec<(String, String)> {
        let doc = include_str!("../../docs/API.md");
        let url = regex::Regex::new(r"http://127\.0\.0\.1:8899(/[^'\s?]*)").unwrap();
        let method = regex::Regex::new(r"-X (GET|POST|DELETE)").unwrap();
        doc.lines()
            .filter(|line| line.contains("curl "))
            .flat_map(|line| {
                let m = match method.captures(line) {
                    Some(c) => c[1].to_string(),
                    None if line.contains(" -d ") => "POST".to_string(),
                    None => "GET".to_string(),
                };
                url.captures_iter(line)
                    .map(|c| (m.clone(), c[1].to_string()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The examples are what gets copied, so they are held to the table too.
    #[test]
    fn every_api_example_calls_a_route_that_exists() {
        let routes = routes();
        let examples = examples();
        assert!(examples.len() >= 4, "the examples were read: {examples:?}");
        let broken: Vec<_> = examples
            .iter()
            .filter(|(m, p)| {
                !routes.contains(&(m.clone(), p.clone()))
                    && !routes.contains(&("*".to_string(), p.clone()))
            })
            .collect();
        assert!(broken.is_empty(), "examples calling no route: {broken:?}");
    }

    /// docs/API.md is the contract an agent programs against, and it said
    /// nothing a test could hold it to: a route added here and not written
    /// down, or written down and gone, was noticed by whoever tripped on it.
    /// Now each side of the table is checked against the other.
    #[test]
    fn the_api_document_names_every_route_and_only_routes() {
        let routes = routes();
        let (named, paths) = documented();
        assert!(routes.len() > 30, "the route table was read: {routes:?}");

        let missing: Vec<_> = routes
            .iter()
            .filter(|(method, path)| {
                let path_named = named.iter().any(|(_, p)| p == path) || paths.contains(path);
                match method.as_str() {
                    // Any method: the document names it by the one to use.
                    "*" => !path_named,
                    m => !named.contains(&(m.to_string(), path.clone())),
                }
            })
            .collect();
        assert!(
            missing.is_empty(),
            "routes API.md does not name: {missing:?}"
        );

        // `/plugin/<name>/…` is a plugin's own space, not a route here.
        let invented: Vec<_> = named
            .iter()
            .filter(|(method, path)| {
                !path.starts_with("/plugin/")
                    && !routes.contains(&(method.clone(), path.clone()))
                    && !routes.contains(&("*".to_string(), path.clone()))
            })
            .collect();
        assert!(
            invented.is_empty(),
            "API.md names routes that are not here: {invented:?}"
        );
    }
}
