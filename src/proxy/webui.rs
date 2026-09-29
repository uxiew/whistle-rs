//! The built-in web UI, served when a client hits the proxy port directly.
//!
//! A self-contained single-page app (no external assets) mirroring the purpose
//! of whistle's `biz/webui`: inspect live traffic and view/edit rules. Also
//! serves the root CA, a PAC file, and a JSON traffic feed.

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
mod console_hosts;
mod plugin_pages;
mod sessions;

pub(super) use access::*;
pub(super) use console_hosts::*;
use plugin_pages::*;
use sessions::*;

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
            "attachment; filename=\"whistle-rs-rootCA.crt\"",
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

/// A captured body as a HAR field carries it.
#[derive(Default)]
struct HarBody {
    /// The whole body's (wire) size, which the kept part may fall short of.
    size: usize,
    text: String,
    /// `text` is the kept bytes, base64-encoded.
    base64: bool,
    /// Why `text` is not the whole body, when it is not — for HAR's own
    /// `comment` field, which is the one a viewer shows.
    short: Option<String>,
}

/// A body that is not text goes out **base64-encoded**, which is what HAR 1.2
/// defines `content.encoding` for. Until this did that, a binary body was
/// exported as the console's own `[binary, N bytes]` marker, written into the
/// `text` field where every tool that reads a HAR would take it for the body —
/// a sentence delivered as if it were an image. Text that is not UTF-8 goes
/// the same way: as `text` it would be U+FFFD.
///
/// The same key is used on `postData`, which HAR 1.2 does not define it for. It
/// is the least surprising extension available: a reader that ignores it still
/// receives the body, recoverable, rather than a sentence that never was one.
fn har_body(cap: Option<&Capture>) -> HarBody {
    let Some(cap) = cap else {
        return HarBody::default();
    };
    let (size, truncated, text) = cap.snapshot();
    let bytes = cap.preview_bytes().bytes;
    let short = truncated.then(|| match cap.is_undecodable() {
        true => format!(
            "whistle-rs: its content-encoding would not decode; this is the {} bytes that came out before it broke",
            bytes.len()
        ),
        false => format!(
            "whistle-rs kept {} of {size} bytes; the rest was not captured",
            bytes.len()
        ),
    });
    if !cap.is_binary() && text.as_bytes() == bytes.as_ref() {
        return HarBody {
            size,
            text,
            base64: false,
            short,
        };
    }
    HarBody {
        size,
        text: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
        base64: true,
        short,
    }
}

/// The two keys that say a HAR body is not the whole body: `comment` for a
/// person, `_truncated` for a program. Absent from a body that is whole.
fn har_mark_short(field: &mut serde_json::Value, body: &HarBody) {
    if let (Some(why), Some(obj)) = (&body.short, field.as_object_mut()) {
        obj.insert("comment".into(), serde_json::json!(why));
        obj.insert("_truncated".into(), serde_json::json!(true));
    }
}

/// One HAR 1.2 entry for one session. Separate from [`sessions_har`] so the
/// shape can be asserted on without a proxy behind it.
fn har_entry(s: &Session) -> serde_json::Value {
    let har_headers = |pairs: &[(String, String)]| -> Vec<serde_json::Value> {
        pairs
            .iter()
            .map(|(n, v)| serde_json::json!({ "name": n, "value": v }))
            .collect()
    };
    let mime_of = |pairs: &[(String, String)]| -> String {
        pairs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "application/octet-stream".to_string())
    };
    let encoding = |base64: bool| match base64 {
        true => serde_json::json!("base64"),
        false => serde_json::Value::Null,
    };

    let req = har_body(s.req_body.as_ref());
    let res = har_body(s.res_body.as_ref());
    let (req_len, res_len) = (req.size, res.size);
    let mut post_data = if req_len > 0 {
        serde_json::json!({
            "mimeType": mime_of(&s.req_headers),
            "text": req.text,
            "encoding": encoding(req.base64),
        })
    } else {
        serde_json::Value::Null
    };
    har_mark_short(&mut post_data, &req);
    let mut content = serde_json::json!({
        "size": res_len,
        "mimeType": mime_of(&s.res_headers),
        "text": res.text,
        "encoding": encoding(res.base64),
    });
    har_mark_short(&mut content, &res);
    let mut entry = serde_json::json!({
        "startedDateTime": super::iso8601_utc(s.time_ms),
        "time": s.duration_ms,
        "request": {
            "method": s.method,
            "url": s.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": har_headers(&s.req_headers),
            "queryString": [],
            "postData": post_data,
            "headersSize": -1,
            "bodySize": req_len,
        },
        "response": {
            "status": s.status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": har_headers(&s.res_headers),
            "content": content,
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": res_len,
        },
        "cache": {},
        // The phases as measured. A session that never left the proxy has none,
        // and HAR's `-1` says so — where the `{send: 0, wait: <all of it>,
        // receive: 0}` this used to write said something that never happened.
        "timings": match &s.timings {
            Some(t) => t.har(),
            None => serde_json::json!({
                "blocked": -1, "dns": -1, "connect": -1, "ssl": -1,
                "send": -1, "wait": s.duration_ms, "receive": -1,
            }),
        },
        "serverIPAddress": "",
        "_target": s.target,
        "_clientIp": s.client_ip,
        // Chrome's own export writes a failed request's reason here as one
        // string (`net::ERR_CONNECTION_REFUSED`), and HAR viewers that show it
        // expect a string; the phase leads so it reads the same way.
        "_error": s.error.get().map(|f| format!("{}: {}", f.phase, f.message)),
    });
    // HAR's own field for which requests shared a connection: a string, and
    // left out rather than null where there is none (§4.1, `entries`).
    if let Some(n) = s.timings.as_ref().and_then(|t| t.connection_id()) {
        entry["connection"] = n.to_string().into();
    }
    entry
}

/// Export captured traffic as a HAR 1.2 file (importable into DevTools etc.).
///
/// `?ids=1,2,3` exports only those sessions, in the order the capture holds
/// them — what the request table's multi-selection asks for. Without it the
/// answer is everything, as before.
fn sessions_har(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let wanted = id_list(req, "ids");
    let sessions: Vec<Session> = {
        let q = state.sessions.lock().unwrap();
        q.iter()
            .filter(|s| wanted.as_ref().is_none_or(|ids| ids.contains(&s.id)))
            .cloned()
            .collect()
    };
    let entries: Vec<serde_json::Value> = sessions.iter().map(har_entry).collect();

    let har = serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "whistle-rs", "version": crate::config::VERSION },
            "entries": entries,
        }
    });
    let body = serde_json::to_string(&har).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whistle-rs.har\"",
        )
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

fn rules_get(state: &Arc<AppState>) -> Response<DynBody> {
    let text = state.rules.read().unwrap().text().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(text)))
        .unwrap()
}

async fn rules_post(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let text = String::from_utf8_lossy(&body).into_owned();
    let count = {
        let mut mgr = state.rules.write().unwrap();
        mgr.set_text(&text);
        // Persist, like every *named* group endpoint already does. Without this
        // the default group — the one the console opens on — was in memory only:
        // edit, restart, gone, having been told "Saved".
        crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        mgr.len()
    };
    fetch_new_includes(state);
    tracing::info!("rules updated via UI: {count} rules");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!(
            "{{\"ok\":true,\"rules\":{count}}}"
        ))))
        .unwrap()
}

/// A rules text that just changed may name an `@` source nothing has fetched.
///
/// Spawned rather than awaited, and this is the whole contract of the feature:
/// someone typing in the console gets their answer back at the speed of the
/// parse, and the include lands when the fetch lands — at which point the
/// groups that carry an `@` line are re-parsed under the write lock. Blocking
/// the save on an intranet that is down would make a rules editor unusable for
/// exactly the reason includes exist.
///
/// Costs nothing when there is nothing to fetch: [`load_pending`] reads the set
/// of never-loaded sources, which is empty in every rule set that names none.
///
/// [`load_pending`]: crate::rules::include::load_pending
fn fetch_new_includes(state: &Arc<AppState>) {
    if !state.rules.read().unwrap().resolves_includes() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        crate::rules::include::load_pending(&state.rules).await;
    });
}

// ── Rule group management API ──

/// Where the values store is persisted — the storage root, beside `rules/`.
fn values_dir(state: &Arc<AppState>) -> std::path::PathBuf {
    state.config.data_dir().to_path_buf()
}

fn rules_dir(state: &Arc<AppState>) -> std::path::PathBuf {
    state.config.data_dir().join("rules")
}

/// The marker that identifies an exported bundle, so a file that merely happens
/// to be JSON is never applied as one.
const BUNDLE_MARKER: &str = "whistle_rs";

/// Everything the console can edit, as one object: every rule group with the
/// text and the enabled state it has, and the whole values store.
///
/// A group is plain text and the console can save one straight out of its
/// editor, so this exists for what a per-group file cannot carry: a *setup*.
/// Exporting groups one at a time loses which of them were switched off, and
/// loses the values store entirely — which is how a set of rules arrives on
/// another machine resolving `{mock.json}` to nothing at all.
fn bundle_of(
    mgr: &crate::rules::RuleManager,
    values: &std::collections::HashMap<String, String>,
) -> serde_json::Value {
    let groups: Vec<serde_json::Value> = mgr
        .groups()
        .iter()
        .map(|g| serde_json::json!({ "name": g.name, "enabled": g.enabled, "text": g.text }))
        .collect();
    serde_json::json!({
        BUNDLE_MARKER: crate::config::VERSION,
        "rules": groups,
        "values": values,
    })
}

/// Apply an exported bundle, returning how many groups and values it carried.
///
/// A group that is already there is updated **in place**. Group order is
/// precedence, so removing and re-adding one would move it to the back and
/// quietly change which rule wins — an import that says it restored a setup
/// must not reorder the rules that were already in it. A group that is not
/// there is appended, in the order the bundle lists it.
///
/// The default group is set rather than added, for the reason
/// [`crate::rules::storage::load_groups`] does the same: it always exists, and
/// `add_group` would refuse it and drop what the bundle carried for it.
fn apply_bundle(
    mgr: &mut crate::rules::RuleManager,
    values: &mut std::collections::HashMap<String, String>,
    bundle: &serde_json::Value,
) -> (usize, usize) {
    let mut groups = 0;
    for g in bundle
        .get("rules")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
    {
        let Some(name) = g.get("name").and_then(|v| v.as_str()).map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let text = g.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let enabled = g.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let was = mgr
            .groups()
            .iter()
            .find(|x| x.name == name)
            .map(|x| x.enabled);
        match (name, was) {
            ("default", _) => mgr.set_text(text),
            (_, Some(_)) => {
                mgr.update_group(name, text);
            }
            (_, None) => {
                mgr.add_group(name, text, enabled);
            }
        }
        // `update_group` and `set_text` leave the switch alone, so it is moved
        // separately — and only when it differs, since a toggle is all there is.
        if was.is_some_and(|w| w != enabled) {
            mgr.toggle_group(name);
        }
        groups += 1;
    }
    let mut count = 0;
    if let Some(map) = bundle.get("values").and_then(|v| v.as_object()) {
        for (name, value) in map {
            let Some(value) = value.as_str() else {
                continue;
            };
            values.insert(name.clone(), value.to_string());
            count += 1;
        }
    }
    (groups, count)
}

fn bundle_export(state: &Arc<AppState>) -> Response<DynBody> {
    let bundle = {
        let mgr = state.rules.read().unwrap();
        let values = state.values.read().unwrap();
        bundle_of(&mgr, &values)
    };
    let body = serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whistle-rs-rules-and-values.json\"",
        )
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

async fn bundle_import(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let bundle = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if bundle.get(BUNDLE_MARKER).is_none() {
        return json_error("not an exported bundle");
    }
    let (groups, values) = {
        let mut mgr = state.rules.write().unwrap();
        let mut store = state.values.write().unwrap();
        let counts = apply_bundle(&mut mgr, &mut store, &bundle);
        crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        crate::rules::storage::save_values(&values_dir(state), &store);
        counts
    };
    fetch_new_includes(state);
    tracing::info!("imported {groups} rule groups and {values} values via UI");
    let body = format!("{{\"ok\":true,\"groups\":{groups},\"values\":{values}}}");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

fn rule_groups_get(state: &Arc<AppState>) -> Response<DynBody> {
    let mgr = state.rules.read().unwrap();
    let groups: Vec<serde_json::Value> = mgr
        .groups()
        .iter()
        .map(|g| {
            serde_json::json!({
                "name": g.name,
                "enabled": g.enabled,
                "rules": g.len(),
            })
        })
        .collect();
    let body = serde_json::to_string(&groups).unwrap_or_else(|_| "[]".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

fn rule_group_get(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let name = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("name="))
                .map(|v| v.replace("%20", " ").replace("+", " "))
        })
        .unwrap_or_default();
    let mgr = state.rules.read().unwrap();
    if let Some(g) = mgr.groups().iter().find(|g| g.name == name) {
        let body = serde_json::json!({
            "name": g.name,
            "text": g.text,
            "enabled": g.enabled,
            "rules": g.len(),
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body::full(Bytes::from(body.to_string())))
            .unwrap()
    } else {
        json_error("group not found")
    }
}

async fn rule_groups_add(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return json_error("name is required");
    }
    let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.add_group(name, text, enabled);
        if ok {
            crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        }
        ok
    };
    if ok {
        fetch_new_includes(state);
        json_ok()
    } else {
        json_error("group already exists")
    }
}

async fn rule_group_toggle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let result = {
        let mut mgr = state.rules.write().unwrap();
        // `-M multiEnv` resolves the default group alone, so switching a named
        // one on would record a state the proxy then ignores. Upstream refuses
        // the same call for the same reason — `selectRulesFile` returns without
        // doing anything under `config.multiEnv`
        // (`_original/lib/rules/util.js:148-151`).
        if mgr.is_default_group_only() && name != "default" {
            return json_error(
                "-M multiEnv is on: only the default group resolves, and each \
                 request brings its own rules",
            );
        }
        let r = mgr.toggle_group(name);
        if r.is_some() {
            crate::rules::storage::save_meta(&rules_dir(state), &mgr);
        }
        r
    };
    match result {
        Some(enabled) => {
            // A group switched back on re-registers its sources, which may
            // never have been fetched — or were swept while it was off.
            fetch_new_includes(state);
            let body = format!("{{\"ok\":true,\"enabled\":{enabled}}}");
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from(body)))
                .unwrap()
        }
        None => json_error("group not found"),
    }
}

async fn rule_group_update(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.update_group(name, text);
        if ok {
            crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        }
        ok
    };
    if ok {
        fetch_new_includes(state);
        json_ok()
    } else {
        json_error("group not found")
    }
}

async fn rule_group_delete(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // Said here rather than left to "group not found", which would be a lie:
    // the default group is there, and is the one group that may not go. See
    // [`crate::rules::RuleManager::remove_group`] for why.
    if name == "default" {
        return json_error("the default group cannot be removed; switch it off instead");
    }
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.remove_group(name);
        if ok {
            crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        }
        ok
    };
    if ok {
        json_ok()
    } else {
        json_error("group not found")
    }
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

fn values_get(state: &Arc<AppState>) -> Response<DynBody> {
    let values = state.values.read().unwrap().clone();
    let body = serde_json::to_string(&values).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

async fn values_post(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    match serde_json::from_slice::<std::collections::HashMap<String, String>>(&body) {
        Ok(map) => {
            crate::rules::storage::save_values(&values_dir(state), &map);
            *state.values.write().unwrap() = map;
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from_static(b"{\"ok\":true}")))
                .unwrap()
        }
        Err(_) => refused("expected a JSON object of names to text values"),
    }
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

/// Read-modify-write the values store, persisting whatever the edit left.
///
/// The disk write happens under the same lock as the edit. Editing one key at a
/// time means the console makes several of these calls in quick succession, and
/// a save that ran outside the lock could write a copy of the store taken before
/// its neighbour's change — a key that comes back after a restart having quietly
/// lost an edit is the same failure this store was fixed for once already.
fn edit_values(
    state: &Arc<AppState>,
    edit: impl FnOnce(&mut std::collections::HashMap<String, String>) -> bool,
) -> bool {
    let mut values = state.values.write().unwrap();
    if !edit(&mut values) {
        return false;
    }
    crate::rules::storage::save_values(&values_dir(state), &values);
    true
}

/// Move a value from one name to another.
///
/// Refuses to rename onto a name that is taken: `{name}` references resolve by
/// name, so overwriting one here would silently repoint every rule that used it
/// at somebody else's content.
fn rename_value(
    values: &mut std::collections::HashMap<String, String>,
    from: &str,
    to: &str,
) -> Result<(), &'static str> {
    let Some(content) = values.get(from).cloned() else {
        return Err("value not found");
    };
    if from == to {
        return Ok(());
    }
    if values.contains_key(to) {
        return Err("a value by that name already exists");
    }
    values.remove(from);
    values.insert(to.to_string(), content);
    Ok(())
}

/// The `name` a value endpoint was given, trimmed. A blank one is not a name:
/// `{}` resolves to nothing, so a value stored under it could never be read.
fn value_name(payload: &serde_json::Value, key: &str) -> Option<String> {
    let name = payload
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Create or replace one named value (`{"name":…,"value":…}`).
///
/// Editing the store as a whole JSON object — the only way there was — means
/// every edit rewrites every key, so a typo anywhere loses the lot and two
/// tabs open on the pane overwrite each other silently.
async fn value_set(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(name) = value_name(&payload, "name") else {
        return json_error("name is required");
    };
    let value = payload
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    edit_values(state, |values| {
        values.insert(name, value);
        true
    });
    json_ok()
}

/// Rename one value (`{"name":…,"to":…}`).
async fn value_rename(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (Some(from), Some(to)) = (value_name(&payload, "name"), value_name(&payload, "to")) else {
        return json_error("name is required");
    };
    let mut failure = None;
    edit_values(state, |values| match rename_value(values, &from, &to) {
        Ok(()) => true,
        Err(why) => {
            failure = Some(why);
            false
        }
    });
    match failure {
        Some(why) => json_error(why),
        None => json_ok(),
    }
}

/// Delete one value (`{"name":…}`).
async fn value_delete(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(name) = value_name(&payload, "name") else {
        return json_error("name is required");
    };
    match edit_values(state, |values| values.remove(&name).is_some()) {
        true => json_ok(),
        false => json_error("value not found"),
    }
}

/// Replay a captured session by re-sending it through the proxy's own port.
/// Accepts `{ "id": N }` or `{ "ids": [N, M, ...] }` (batch, max 100).
///
/// The batch form has no caller: the console's request table is single-select,
/// so `store.ts` only ever posts `{ "id": N }`. It is kept because it costs
/// nothing and because multi-select is the obvious next thing the table grows —
/// but it is untested by use, and the answer's `sessions` array is per-id
/// precisely so a batch could report which of its members lost their bodies.
async fn replay_session(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return refused(&format!("invalid JSON: {e}")),
    };
    let ids: Vec<u64> = if let Some(id) = payload.get("id").and_then(|v| v.as_u64()) {
        vec![id]
    } else if let Some(arr) = payload.get("ids").and_then(|v| v.as_array()) {
        arr.iter().filter_map(|v| v.as_u64()).take(100).collect()
    } else {
        return refused("expected {\"id\": N} or {\"ids\": [N, …]}");
    };

    // Collect the sessions to replay while holding the lock briefly.
    let sessions: Vec<Session> = {
        let q = state.sessions.lock().unwrap();
        ids.iter()
            .filter_map(|id| q.iter().find(|s| s.id == *id).cloned())
            .collect()
    };
    if sessions.is_empty() {
        return api_error(
            StatusCode::NOT_FOUND,
            "no session with that id is held; it may have left the list or been cleared",
        );
    }

    let port = state.config.port;
    let replayed = sessions.len();
    // What each replay will actually carry, decided *here* rather than inside
    // the spawned task, so the answer can report it. A replay is fire-and-forget
    // — this is the only moment the caller is still listening.
    let report: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            let body = replay_body_of(s);
            serde_json::json!({
                "id": s.id,
                "body": body.kind(),
                // What is being sent, and what was seen. They differ whenever
                // the preview was capped, and the console says so — a replay
                // that silently drops 190 KB of a 200 KB upload is worse than
                // one that refuses to run.
                "sent": body.bytes().map(|b| b.len()).unwrap_or(0),
                "captured": s.req_body.as_ref().map(|c| c.total()).unwrap_or(0),
            })
        })
        .collect();
    // Fire-and-forget: spawn tasks that send requests through the proxy.
    for sess in sessions {
        tokio::spawn(async move {
            if let Err(e) = do_replay(port, &sess).await {
                tracing::warn!("replay id={} failed: {e}", sess.id);
            }
        });
    }
    let answer = serde_json::json!({ "replayed": replayed, "sessions": report });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(answer.to_string())))
        .unwrap()
}

/// What a replay of `sess` can re-send of its request body.
///
/// A session with no captured request body replays without one — which is
/// correct for the GET it usually is, and is *not* the same thing as the old
/// behaviour of sending nothing for every request alike.
fn replay_body_of(sess: &Session) -> ReplayBody {
    sess.req_body
        .as_ref()
        .map(|c| c.replay_body())
        .unwrap_or(ReplayBody::Empty)
}

/// Rebuild a captured session's request, body and all, ready to be sent back
/// through the proxy's own port.
///
/// Three headers are deliberately **not** copied from the capture, because all
/// three describe a body that no longer exists:
///
/// * `content-length` — the captured value belongs to the body as it arrived.
///   `do_replay` used to copy it and then send `Empty::new()`, so replaying a
///   POST announced 402 bytes and sent none; the origin either hung waiting for
///   them or read the next request off the socket as this one's body.
/// * `transfer-encoding` — the replay is sent as one length-delimited body, so
///   a copied `chunked` would frame it twice.
/// * `content-encoding` — the capture is *decoded* ([`Capture::replay_body`]),
///   so keeping the header would tell the origin to gunzip plain text.
///
/// Separate from [`do_replay`] so that what is sent can be asserted on without a
/// socket — see the tests.
fn replay_request(sess: &Session, body: &ReplayBody) -> hyper::Request<body::DynBody> {
    let method: hyper::Method = sess.method.parse().unwrap_or(hyper::Method::GET);
    let uri: hyper::Uri = sess.url.parse().unwrap_or_else(|_| "/".parse().unwrap());
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (name, value) in &sess.req_headers {
        if is_dropped_header(name) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    // Mark the hop as the Composer's, so a `from:composer` rule can tell a
    // replay from the traffic it was captured from. Consumed on arrival, like
    // whistle's own `FROM_COM_HEADER` — see `proxy::COMPOSER_REQ_HEADER`.
    builder = builder.header(super::COMPOSER_REQ_HEADER, "1");
    // The length of what is being sent, which is the only length that is true.
    let bytes = body.bytes().cloned().unwrap_or_default();
    builder = builder.header(hyper::header::CONTENT_LENGTH, bytes.len());
    builder
        .body(body::full(bytes))
        .expect("a request rebuilt from a captured one")
}

/// Headers a request sent back through our own port sets for itself rather than
/// taking from the capture or the Composer's box — see [`replay_request`] and
/// [`composed_request`]. All three describe a body that only exists here.
const DROPPED_HEADERS: [&str; 3] = ["content-length", "transfer-encoding", "content-encoding"];

/// True when `name` is one of [`DROPPED_HEADERS`].
fn is_dropped_header(name: &str) -> bool {
    DROPPED_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Send a captured session's request through the proxy's own port so it flows
/// through the full rule-matching + forwarding pipeline again.
async fn do_replay(
    proxy_port: u16,
    sess: &Session,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    send_through_self(proxy_port, replay_request(sess, &replay_body_of(sess))).await
}

/// Put a request on the proxy's own port, in absolute-form, and forget it.
///
/// This is the whole trick behind both Replay and the Composer: the request is
/// not sent to the origin from here — it is sent to *us*, so it arrives as any
/// other proxied request does and gets the full treatment, rules and capture
/// included. Upstream does the same, pointing its composer's client at
/// `config.host`/`config.port` rather than at the target
/// (`_original/lib/service/composer.js:241-242`).
///
/// The response is dropped: what it was is already being recorded on the way
/// past, and the console reads it out of the session list.
async fn send_through_self(
    proxy_port: u16,
    req: hyper::Request<DynBody>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let _resp = sender.send_request(req).await?;
    Ok(())
}

/// One request composed by hand in the console.
///
/// `headers` is the raw `Name: value` text of the console's box rather than an
/// object, because that is what a person types and what they paste; upstream's
/// composer takes the same string and parses it the same way
/// (`parseHeaders`, `_original/lib/util/common.js:1699-1729`).
///
/// Every field defaults, so a composition that omits one is a composition with
/// that field empty rather than a `400`: the console posts what its boxes hold,
/// and an empty box is a normal state for three of the four.
#[derive(serde::Deserialize)]
struct Composed {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    headers: String,
    #[serde(default)]
    body: String,
}

/// Send a request composed in the console's Composer through our own port.
///
/// Takes `{ "method", "url", "headers", "body" }` and answers
/// `{ "ok": true, "url": …, "sent": … }` — the URL as it was actually resolved,
/// so the console can show that a scheme was filled in, and the body length that
/// went out. Like Replay it is fire-and-forget: the transaction lands in the
/// session list a moment later, which is where the console reads its result.
async fn compose_request(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let composed: Composed = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return refused("invalid JSON"),
    };
    let request = match composed_request(&composed) {
        Ok(r) => r,
        Err(e) => return refused(&e),
    };
    let url = request.uri().to_string();
    let sent = composed.body.len();

    let port = state.config.port;
    tokio::spawn(async move {
        if let Err(e) = send_through_self(port, request).await {
            tracing::warn!("composed request failed: {e}");
        }
    });
    let answer = serde_json::json!({ "ok": true, "url": url, "sent": sent });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(answer.to_string())))
        .unwrap()
}

/// **Test Rules**: which rules a request *would* hit, without making one.
///
/// whistle's console has the same panel (`gui/test-rules.md`), and this port
/// has had the same answer on the command line since `explain` — this is that
/// function, over HTTP, so the console can ask it too.
///
/// The body is an [`crate::explain::Query`]: the rules text, a URL, and
/// whatever else the question needs (method, headers, body, a response head).
/// The values store is filled in from the proxy's own when the caller sends
/// none, so a `{name}` in the rules under test means what it means at runtime.
async fn explain_rules(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let mut query: crate::explain::Query = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return refused(&format!("invalid JSON: {e}")),
    };
    // Asked without values of its own, the tester answers from the proxy's —
    // and with the proxy's overrides, or it would disagree with the traffic.
    if query.values.is_empty() {
        query.values = state.values.read().unwrap().clone();
        query.overrides = state.config.value_overrides.clone();
    }
    match crate::explain::explain(&query) {
        Ok(answer) => {
            let json = serde_json::to_string(&answer).unwrap_or_else(|_| "{}".into());
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from(json)))
                .unwrap()
        }
        Err(e) => refused(&e),
    }
}

/// A `400` the console can read: everything it posts, it reads back as JSON.
fn refused(error: &str) -> Response<DynBody> {
    api_error(StatusCode::BAD_REQUEST, error)
}

/// Build what a composition puts on the wire, or say why it cannot.
///
/// Separate from [`compose_request`] so that what is sent can be asserted on
/// without a socket — as with [`replay_request`], see the tests.
fn composed_request(c: &Composed) -> Result<hyper::Request<DynBody>, String> {
    // A bare `example.com/x` means `http://example.com/x`, as everywhere else in
    // whistle (`setProtocol`, `_original/lib/util/common.js:508-510`).
    let typed = c.url.trim();
    if typed.is_empty() {
        return Err("a URL is required".into());
    }
    let url = match typed.contains("://") {
        true => typed.to_string(),
        false => format!("http://{typed}"),
    };
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| format!("not a URL: {}", c.url.trim()))?;
    // Absolute-form is what makes this a *proxy* request when it arrives back on
    // our port rather than a hit on the console — see `proxy::top_level`. A URI
    // with no authority never gets this far in practice (the parser refuses an
    // empty one), but the Host header below has to come from somewhere.
    let authority = uri
        .authority()
        .ok_or_else(|| format!("the URL needs a host: {url}"))?
        .as_str()
        .to_string();

    // An empty method is a GET, as upstream's `getMethod`
    // (`_original/lib/util/common.js:1664-1669`).
    let spelled = c.method.trim().to_ascii_uppercase();
    let method: hyper::Method = match spelled.is_empty() {
        true => hyper::Method::GET,
        false => spelled
            .parse()
            .map_err(|_| format!("not an HTTP method: {}", c.method.trim()))?,
    };

    let mut headers = hyper::HeaderMap::new();
    for line in c.headers.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Upstream ignores a line with no colon and a name it cannot use
        // (`parseHeaders`, and the `if (list)` walk that follows it). Here they
        // are refused instead: a capture is ground truth and dropping an odd
        // header from it is the lesser evil, but a composition is something a
        // person just typed into a box, and quietly not sending it is the worst
        // answer a debugging tool can give.
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("not a header: {line}"))?;
        let (name, value) = (name.trim(), value.trim());
        if is_dropped_header(name) {
            continue;
        }
        let n = hyper::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("not a header name: {name}"))?;
        let v = hyper::header::HeaderValue::from_str(value)
            .map_err(|_| format!("not a header value: {value}"))?;
        // Appended, not inserted: `Set-Cookie:` twice is two headers, and a box
        // you type header lines into is the one place that has to hold both.
        headers.append(n, v);
    }
    // The host is the URL's, whatever was typed — upstream overwrites it the
    // same way (`_original/lib/service/composer.js:391`). A request whose Host
    // disagrees with its own absolute URI is not a request anyone means to send;
    // moving the socket elsewhere is what `host://` rules are for.
    headers.insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_str(&authority)
            .map_err(|_| format!("not a host: {authority}"))?,
    );
    let bytes = Bytes::from(c.body.clone());
    headers.insert(hyper::header::CONTENT_LENGTH, bytes.len().into());
    headers.insert(
        hyper::header::HeaderName::from_static(super::COMPOSER_REQ_HEADER),
        hyper::header::HeaderValue::from_static("1"),
    );

    let mut request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .body(body::full(bytes))
        .map_err(|e| e.to_string())?;
    *request.headers_mut() = headers;
    Ok(request)
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
mod bundle_tests {
    use super::*;
    use crate::rules::RuleManager;
    use std::collections::HashMap;

    /// A manager with a default group and two named ones, the second off.
    fn setup() -> (RuleManager, HashMap<String, String>) {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com http://localhost:5173\n");
        mgr.add_group("staging", "api.example.com host://10.0.0.9\n", true);
        mgr.add_group("archive", "# kept, not applied\n", false);
        let values = HashMap::from([("mock.json".to_string(), "{\"ok\":true}".to_string())]);
        (mgr, values)
    }

    /// What a group list reduces to for comparison: name, switch and text, in
    /// order — order being precedence, it is part of what has to survive.
    fn shape(mgr: &RuleManager) -> Vec<(String, bool, String)> {
        mgr.groups()
            .iter()
            .map(|g| (g.name.clone(), g.enabled, g.text.clone()))
            .collect()
    }

    /// The whole point of the format: what comes out goes back in unchanged.
    #[test]
    fn a_bundle_restores_the_setup_it_was_taken_from() {
        let (mgr, values) = setup();
        let bundle = bundle_of(&mgr, &values);

        let mut restored = RuleManager::new();
        let mut restored_values = HashMap::new();
        let (groups, count) = apply_bundle(&mut restored, &mut restored_values, &bundle);
        assert_eq!((groups, count), (3, 1));
        assert_eq!(shape(&restored), shape(&mgr));
        assert_eq!(restored_values, values);
    }

    /// Applying a bundle over the setup it came from must be a no-op — not a
    /// second copy of every group, and not a reordering of them.
    #[test]
    fn re_importing_a_bundle_changes_nothing() {
        let (mut mgr, mut values) = setup();
        let bundle = bundle_of(&mgr, &values);
        let before = shape(&mgr);
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(shape(&mgr), before);
    }

    /// Group order is precedence. A group that is already there is updated
    /// where it stands, so an import cannot silently change which rule wins.
    #[test]
    fn an_imported_group_keeps_the_position_it_had() {
        let (mut mgr, mut values) = setup();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [{ "name": "staging", "enabled": true, "text": "changed\n" }],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(
            mgr.groups()
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>(),
            ["default", "staging", "archive"]
        );
        assert_eq!(mgr.groups()[1].text, "changed\n");
    }

    /// Whether a group is switched on is the thing a plain-text export cannot
    /// carry, so the bundle has to.
    #[test]
    fn an_import_moves_a_groups_switch_to_what_the_bundle_says() {
        let (mut mgr, mut values) = setup();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [
                { "name": "staging", "enabled": false, "text": "api.example.com host://10.0.0.9\n" },
                { "name": "archive", "enabled": true, "text": "# kept, not applied\n" },
            ],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert!(!mgr.groups()[1].enabled);
        assert!(mgr.groups()[2].enabled);
    }

    /// The default group always exists, so `add_group` refuses it — the same
    /// trap `storage::load_groups` documents. Its text has to be *set*.
    #[test]
    fn a_bundle_can_restore_the_default_group() {
        let mut mgr = RuleManager::new();
        mgr.set_text("# whatever was here\n");
        let mut values = HashMap::new();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [{ "name": "default", "enabled": true, "text": "a.com host://1.1.1.1\n" }],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(mgr.text(), "a.com host://1.1.1.1\n");
        assert_eq!(mgr.groups().len(), 1);
    }

    /// An import adds to the values store rather than replacing it: the bundle
    /// says what it carries, not what the machine it lands on may keep.
    #[test]
    fn imported_values_are_laid_over_the_ones_already_there() {
        let mut mgr = RuleManager::new();
        let mut values = HashMap::from([
            ("keep.txt".to_string(), "mine".to_string()),
            ("mock.json".to_string(), "old".to_string()),
        ]);
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "values": { "mock.json": "new" },
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(values.get("keep.txt").map(String::as_str), Some("mine"));
        assert_eq!(values.get("mock.json").map(String::as_str), Some("new"));
    }
}

#[cfg(test)]
mod value_tests {
    use super::*;
    use std::collections::HashMap;

    fn store(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_renamed_value_keeps_its_content_under_the_new_name() {
        let mut values = store(&[("mock.json", "{\"ok\":true}")]);
        assert_eq!(
            rename_value(&mut values, "mock.json", "fixture.json"),
            Ok(())
        );
        assert_eq!(
            values.get("fixture.json").map(String::as_str),
            Some("{\"ok\":true}")
        );
        assert!(!values.contains_key("mock.json"));
    }

    /// A `{name}` reference resolves by name, so a rename onto a name that is
    /// taken would repoint every rule that used it at somebody else's content —
    /// and nothing in the rules text would have changed to say so.
    #[test]
    fn a_rename_will_not_overwrite_a_value_that_exists() {
        let mut values = store(&[("a", "first"), ("b", "second")]);
        assert!(rename_value(&mut values, "a", "b").is_err());
        assert_eq!(values.get("b").map(String::as_str), Some("second"));
        assert_eq!(values.get("a").map(String::as_str), Some("first"));
    }

    /// Renaming to the same name is what a rename dialogue answers with when
    /// nothing was typed, and it must not read as a collision with itself.
    #[test]
    fn renaming_a_value_to_its_own_name_does_nothing() {
        let mut values = store(&[("a", "first")]);
        assert_eq!(rename_value(&mut values, "a", "a"), Ok(()));
        assert_eq!(values.get("a").map(String::as_str), Some("first"));
    }

    #[test]
    fn renaming_a_value_that_is_not_there_is_an_error() {
        assert!(rename_value(&mut store(&[]), "gone", "new").is_err());
    }
}

#[cfg(test)]
mod body_tests {
    use super::*;
    use crate::proxy::Capture;

    fn session(url: &str, id: u64) -> Session {
        Session {
            id,
            url: url.into(),
            ..Default::default()
        }
    }

    /// A PNG saved from the console should arrive under the name it had on the
    /// site it came from.
    #[test]
    fn a_downloaded_body_is_named_after_its_url() {
        let s = session("https://cdn.example.com/img/logo.png?v=2", 7);
        assert_eq!(body_filename(&s, "res", false), "logo.png");
    }

    /// A URL with nothing to take a name from still has to produce one, and the
    /// session it came from is the only thing left to name it after.
    #[test]
    fn a_body_from_a_url_with_no_filename_is_named_after_its_session() {
        assert_eq!(
            body_filename(&session("https://example.com/", 12), "req", false),
            "session-12-req.bin"
        );
        assert_eq!(
            body_filename(&session("https://example.com", 13), "res", false),
            "session-13-res.bin"
        );
    }

    /// The preview is capped, so what is downloaded is a prefix. Nothing inside
    /// a truncated PNG can say so — saved under the name of the whole file it
    /// would read as a corrupt server rather than a capped capture.
    #[test]
    fn a_truncated_download_says_so_in_its_name() {
        let s = session("https://cdn.example.com/app.a91f.js", 3);
        assert_eq!(body_filename(&s, "res", true), "partial-app.a91f.js");
    }

    /// A name is taken from the URL, not trusted from it: the value ends up in
    /// a `Content-Disposition` header, where a quote or a newline would end the
    /// filename early and start something else.
    #[test]
    fn a_downloaded_body_cannot_be_named_by_the_site_it_came_from() {
        let s = session("https://evil.example.com/a\"b\r\nX-Evil:%201.bin", 1);
        assert_eq!(body_filename(&s, "res", false), "abX-Evil201.bin");
    }

    /// The bug this closes: a HAR entry carried `[binary, N bytes]` in the field
    /// a HAR reader takes for the body, so an exported capture handed every
    /// image on to the next tool as that sentence.
    #[test]
    fn a_binary_body_is_exported_as_base64() {
        let raw = [0x89, b'P', b'N', b'G', 0x0d];
        let s = Session {
            res_headers: vec![("content-type".into(), "image/png".into())],
            res_body: Some(Capture::from_bytes(
                &raw,
                Some("image/png".into()),
                None,
                64,
            )),
            ..session("https://example.com/logo.png", 1)
        };
        let entry = har_entry(&s);
        let content = &entry["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        assert_eq!(content["size"], 5);
        assert_eq!(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                content["text"].as_str().unwrap()
            )
            .unwrap(),
            raw
        );
    }

    /// A text body is exported as itself, with no `encoding` for a reader to
    /// have to understand.
    #[test]
    fn a_text_body_is_exported_as_text() {
        let s = Session {
            req_headers: vec![("content-type".into(), "application/json".into())],
            req_body: Some(Capture::from_bytes(
                br#"{"name":"third"}"#,
                Some("application/json".into()),
                None,
                64,
            )),
            ..session("https://example.com/api/items", 1)
        };
        let post = &har_entry(&s)["request"]["postData"];
        assert_eq!(post["text"], r#"{"name":"third"}"#);
        assert!(post["encoding"].is_null());
    }

    /// A body the capture holds only part of is exported as that part — and
    /// says so. It used to go out with the whole body's `size` beside a prefix
    /// in `text` and nothing else, which every HAR reader takes for the body.
    #[test]
    fn a_body_that_was_not_all_kept_says_so_in_the_export() {
        let cut = Session {
            res_headers: vec![("content-type".into(), "text/plain".into())],
            res_body: Some(Capture::from_bytes(
                &[b'a'; 100],
                Some("text/plain".into()),
                None,
                10,
            )),
            ..session("https://example.com/big.txt", 1)
        };
        let content = &har_entry(&cut)["response"]["content"];
        assert_eq!(content["size"], 100);
        assert_eq!(content["text"], "a".repeat(10));
        assert_eq!(content["_truncated"], true);
        let comment = content["comment"].as_str().expect("a comment");
        assert!(comment.contains("10 of 100 bytes"), "{comment}");

        let broken = Session {
            req_headers: vec![("content-type".into(), "text/plain".into())],
            req_body: Some(Capture::from_bytes(
                b"this is not gzip",
                Some("text/plain".into()),
                Some("gzip"),
                64,
            )),
            ..session("https://example.com/upload", 2)
        };
        let post = &har_entry(&broken)["request"]["postData"];
        assert_eq!(post["_truncated"], true);
        let comment = post["comment"].as_str().expect("a comment");
        assert!(comment.contains("would not decode"), "{comment}");

        let whole = &har_entry(&session("https://example.com/", 3))["response"]["content"];
        assert!(whole.get("_truncated").is_none(), "{whole}");
        assert!(whole.get("comment").is_none(), "{whole}");
    }

    /// Text that is not UTF-8 — a GBK page — goes out as its bytes, base64, as
    /// a binary body does. As `text` it would be U+FFFD, which no reader can
    /// turn back into the page.
    #[test]
    fn text_that_is_not_utf8_is_exported_as_its_bytes() {
        let gbk = [0xc4, 0xe3, 0xba, 0xc3];
        let s = Session {
            res_headers: vec![("content-type".into(), "text/html; charset=gbk".into())],
            res_body: Some(Capture::from_bytes(
                &gbk,
                Some("text/html; charset=gbk".into()),
                None,
                64,
            )),
            ..session("https://example.com/gbk.html", 1)
        };
        let content = &har_entry(&s)["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        assert_eq!(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                content["text"].as_str().unwrap()
            )
            .unwrap(),
            gbk
        );
    }

    /// A session with no bodies still exports, with the fields a HAR requires
    /// and nothing invented behind them.
    #[test]
    fn a_session_without_bodies_exports_empty_ones() {
        let entry = har_entry(&session("https://example.com/", 1));
        assert!(entry["request"]["postData"].is_null());
        assert_eq!(entry["response"]["content"]["size"], 0);
        assert_eq!(entry["response"]["content"]["text"], "");
        assert!(entry["_error"].is_null(), "nothing went wrong");
    }

    /// A failed request exports its reason where Chrome's own export puts one:
    /// `_error`, a single string, phase first.
    #[test]
    fn a_failed_session_exports_its_reason() {
        let mut s = session("http://example.com/", 1);
        s.error = crate::proxy::outcome::Outcome::failed(crate::proxy::outcome::Failure::new(
            crate::proxy::outcome::Phase::Connect,
            "connecting to example.com:80: Connection refused",
        ));
        assert_eq!(
            har_entry(&s)["_error"],
            "connect: connecting to example.com:80: Connection refused"
        );
    }

    /// Requests that shared an origin connection say so in HAR's own field,
    /// and a request that reached none leaves the field out rather than null.
    #[test]
    fn the_origin_connection_is_exported_as_har_connection() {
        let mut s = session("https://example.com/", 1);
        assert!(har_entry(&s).get("connection").is_none());
        let t = crate::proxy::timing::Timings::new();
        t.connection(42, true);
        s.timings = Some(t);
        assert_eq!(har_entry(&s)["connection"], "42");
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use crate::proxy::Capture;
    use http_body_util::BodyExt;

    /// A captured POST, with `headers` as forwarded and `body` as captured.
    fn captured(headers: &[(&str, &str)], body: Option<Capture>) -> Session {
        Session {
            id: 1,
            method: "POST".into(),
            url: "http://example.com/api/items".into(),
            req_headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            req_body: body,
            ..Default::default()
        }
    }

    /// What the replay would put on the wire.
    async fn sent(sess: &Session) -> (Vec<(String, String)>, Bytes) {
        let req = replay_request(sess, &replay_body_of(sess));
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        let bytes = req
            .into_body()
            .collect()
            .await
            .expect("a full body")
            .to_bytes();
        (headers, bytes)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The bug this replaces: every captured header was copied and
    /// `Empty::new()` was sent, so a replayed POST announced a body it did not
    /// have. The origin then either waited for bytes that never came or read
    /// the next request off the socket as this one's payload.
    #[tokio::test]
    async fn a_replayed_post_carries_its_body() {
        let sess = captured(
            &[
                ("host", "example.com"),
                ("content-type", "application/json"),
                ("content-length", "402"),
            ],
            Some(Capture::from_bytes(
                br#"{"name":"third"}"#,
                Some("application/json".into()),
                None,
                4096,
            )),
        );
        let (headers, body) = sent(&sess).await;
        assert_eq!(body, Bytes::from_static(br#"{"name":"third"}"#));
        // The stale 402 is gone; the length describes what is being sent.
        assert_eq!(header(&headers, "content-length"), Some("16"));
        // Everything else the capture recorded still goes out.
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
        assert_eq!(header(&headers, "host"), Some("example.com"));
    }

    /// A GET replays with no body and a truthful zero length, rather than
    /// whatever the capture's headers happened to say.
    #[tokio::test]
    async fn a_request_without_a_body_replays_without_one() {
        let sess = captured(&[("host", "example.com")], None);
        let (headers, body) = sent(&sess).await;
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-length"), Some("0"));
    }

    /// The capture is decoded, so the encoding header has to go with it — else
    /// the origin is told to gunzip plain text and answers 400.
    #[tokio::test]
    async fn a_decoded_body_is_not_sent_under_the_encoding_it_arrived_in() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), 4096);
        cap.append(&{
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"plain again").unwrap();
            e.finish().unwrap()
        });
        cap.finish();
        let sess = captured(
            &[("content-encoding", "gzip"), ("content-length", "31")],
            Some(cap),
        );
        let (headers, body) = sent(&sess).await;
        assert_eq!(body, Bytes::from_static(b"plain again"));
        assert_eq!(header(&headers, "content-encoding"), None);
        assert_eq!(header(&headers, "content-length"), Some("11"));
    }

    /// A `transfer-encoding: chunked` copied from the capture would frame a
    /// length-delimited body a second time.
    #[tokio::test]
    async fn a_replay_does_not_inherit_chunked_framing() {
        let sess = captured(
            &[("transfer-encoding", "chunked")],
            Some(Capture::from_bytes(
                b"abc",
                Some("text/plain".into()),
                None,
                4096,
            )),
        );
        let (headers, _) = sent(&sess).await;
        assert_eq!(header(&headers, "transfer-encoding"), None);
        assert_eq!(header(&headers, "content-length"), Some("3"));
    }

    /// The replay is marked as the Composer's, so `from:composer` can tell it
    /// apart from the traffic it was captured from.
    #[tokio::test]
    async fn a_replay_announces_itself() {
        let (headers, _) = sent(&captured(&[], None)).await;
        assert_eq!(
            header(&headers, super::super::COMPOSER_REQ_HEADER),
            Some("1")
        );
    }

    /// What the console is told, so it can warn rather than let a short replay
    /// pass for the real thing.
    #[test]
    fn a_truncated_body_is_reported_as_partial() {
        let cap = Capture::new(Some("text/plain".into()), None, 8);
        cap.append(&[b'x'; 200]);
        let sess = captured(&[], Some(cap));
        let body = replay_body_of(&sess);
        assert_eq!(body.kind(), "partial");
        assert_eq!(body.bytes().map(|b| b.len()), Some(8));
        assert_eq!(sess.req_body.as_ref().unwrap().total(), 200);
    }
}

#[cfg(test)]
mod composer_tests {
    use super::*;
    use http_body_util::BodyExt;

    /// A composition as the console posts it.
    fn composed(method: &str, url: &str, headers: &str, body: &str) -> Composed {
        Composed {
            method: method.into(),
            url: url.into(),
            headers: headers.into(),
            body: body.into(),
        }
    }

    /// What the composition would put on the proxy's own port.
    async fn sent(c: &Composed) -> (hyper::Method, String, Vec<(String, String)>, Bytes) {
        let req = composed_request(c).expect("a composition that builds");
        let method = req.method().clone();
        let uri = req.uri().to_string();
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        let bytes = req
            .into_body()
            .collect()
            .await
            .expect("a full body")
            .to_bytes();
        (method, uri, headers, bytes)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The whole point: what was typed is what goes out.
    #[tokio::test]
    async fn a_composition_is_sent_as_it_was_typed() {
        let c = composed(
            "post",
            "https://example.com/api/items?page=1",
            "Content-Type: application/json\nX-Tenant: acme",
            r#"{"name":"third"}"#,
        );
        let (method, uri, headers, body) = sent(&c).await;
        assert_eq!(method, hyper::Method::POST);
        assert_eq!(uri, "https://example.com/api/items?page=1");
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
        assert_eq!(header(&headers, "x-tenant"), Some("acme"));
        assert_eq!(body, Bytes::from_static(br#"{"name":"third"}"#));
    }

    /// Composed traffic is the Composer's, so `from:composer` catches a hand-made
    /// request as readily as it catches a replayed one.
    #[tokio::test]
    async fn a_composition_announces_itself() {
        let (_, _, headers, _) = sent(&composed("GET", "example.com", "", "")).await;
        assert_eq!(
            header(&headers, super::super::COMPOSER_REQ_HEADER),
            Some("1")
        );
    }

    /// A request the Composer or Replay sent is marked on its session and its
    /// row — all `fc:` asks — including when it fails, which is when someone
    /// goes looking for it. One a client sent is not marked.
    #[tokio::test]
    async fn a_composed_request_is_marked_on_its_session_and_row() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dead = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (state, proxy) = crate::proxy::tunnel_abort_tests::proxy_with("").await;
        for (path, marker) in [("/composed", "x-whistle-composer: 1\r\n"), ("/sent", "")] {
            let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
            let head = format!(
                "GET http://{dead}{path} HTTP/1.1\r\nHost: {dead}\r\n{marker}Connection: close\r\n\r\n"
            );
            client.write_all(head.as_bytes()).await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.ok();
        }
        let sessions: Vec<Session> = state.sessions.lock().unwrap().iter().cloned().collect();
        let marked: Vec<(bool, bool)> = sessions
            .iter()
            .map(|s| (s.url.ends_with("/composed"), s.composer))
            .collect();
        assert_eq!(marked, [(true, true), (false, false)], "{marked:?}");
        assert!(sessions.iter().all(|s| !s.error.is_ok()), "both failed");

        let rows = sessions_json(&state, None)
            .into_body()
            .collect()
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&rows.to_bytes()).unwrap();
        let flag = |suffix: &str| {
            rows.iter()
                .find(|r| r["url"].as_str().unwrap().ends_with(suffix))
                .map(|r| r.get("composer").cloned())
                .expect("a row")
        };
        assert_eq!(flag("/composed"), Some(serde_json::json!(true)));
        assert_eq!(flag("/sent"), None, "absent, not false, on a client's row");
    }

    /// Typing a bare host is how anyone reaches for a quick request, and whistle
    /// has always read it as `http://`.
    #[tokio::test]
    async fn a_url_with_no_scheme_is_composed_as_http() {
        let (_, uri, headers, _) = sent(&composed("GET", " example.com/ping ", "", "")).await;
        assert_eq!(uri, "http://example.com/ping");
        assert_eq!(header(&headers, "host"), Some("example.com"));
    }

    /// An empty method is a GET rather than a refusal — the box starts empty.
    #[tokio::test]
    async fn a_composition_without_a_method_is_a_get() {
        let (method, _, _, _) = sent(&composed("  ", "http://example.com/", "", "")).await;
        assert_eq!(method, hyper::Method::GET);
    }

    /// The length describes what is being sent, so a `Content-Length` seeded from
    /// a capture — or typed and then forgotten — cannot make the request lie.
    #[tokio::test]
    async fn a_composed_body_carries_its_own_length() {
        let c = composed(
            "POST",
            "http://example.com/",
            "Content-Length: 402\nTransfer-Encoding: chunked\nContent-Encoding: gzip",
            "abc",
        );
        let (_, _, headers, body) = sent(&c).await;
        assert_eq!(body, Bytes::from_static(b"abc"));
        assert_eq!(header(&headers, "content-length"), Some("3"));
        assert_eq!(header(&headers, "transfer-encoding"), None);
        assert_eq!(header(&headers, "content-encoding"), None);
    }

    /// The URL decides the host. A typed `Host:` that disagrees with the URL
    /// describes a request nobody means to send.
    #[tokio::test]
    async fn the_host_header_follows_the_url() {
        let c = composed("GET", "http://example.com/x", "Host: elsewhere.test", "");
        let (_, _, headers, _) = sent(&c).await;
        assert_eq!(header(&headers, "host"), Some("example.com"));
    }

    /// One name, twice, is two headers — a cookie jar has no other shape.
    #[tokio::test]
    async fn a_name_typed_twice_is_sent_twice() {
        let c = composed("GET", "http://example.com/", "Cookie: a=1\nCookie: b=2", "");
        let req = composed_request(&c).expect("a composition that builds");
        let values: Vec<&str> = req
            .headers()
            .get_all(hyper::header::COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, ["a=1", "b=2"]);
    }

    /// Blank lines are how a headers box looks while it is being edited.
    #[tokio::test]
    async fn blank_lines_between_headers_are_not_headers() {
        let c = composed("GET", "http://example.com/", "\n\nAccept: */*\n\n", "");
        let (_, _, headers, _) = sent(&c).await;
        assert_eq!(header(&headers, "accept"), Some("*/*"));
    }

    /// Refused rather than dropped: a line that will not be sent has to say so,
    /// or the console shows a request that is not the one that went out.
    #[test]
    fn a_line_that_is_not_a_header_is_refused() {
        let c = composed(
            "GET",
            "http://example.com/",
            "Accept: */*\nX-Tenant acme",
            "",
        );
        assert_eq!(
            composed_request(&c).err().as_deref(),
            Some("not a header: X-Tenant acme")
        );
    }

    /// A path is not a URL. Sent as one it would arrive back on our own port in
    /// origin-form and be read as a hit on the console, not as traffic — so it
    /// is refused here, naming what was typed rather than the `http://` this
    /// would have prefixed to it.
    #[test]
    fn a_url_that_is_only_a_path_is_refused() {
        assert_eq!(
            composed_request(&composed("GET", "/api/items", "", ""))
                .err()
                .as_deref(),
            Some("not a URL: /api/items")
        );
        assert_eq!(
            composed_request(&composed("GET", "   ", "", ""))
                .err()
                .as_deref(),
            Some("a URL is required")
        );
    }

    /// The message names what was typed, because the box is the only place the
    /// mistake can be corrected.
    #[test]
    fn a_method_that_is_not_a_method_is_refused() {
        assert_eq!(
            composed_request(&composed("G ET", "http://example.com/", "", ""))
                .err()
                .as_deref(),
            Some("not an HTTP method: G ET")
        );
    }
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
