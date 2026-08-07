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
use super::{AppState, ReplayBody, Session, WsFrame};

/// Route a direct (non-proxied) request to the UI / API.
pub async fn handle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let path = req.uri().path().to_string();
    // `/plugin/<name>/…` belongs to a plugin, not to us. Checked before the
    // route table because the tail is arbitrary — it is the plugin's own URL
    // space, and nothing here may reserve a path inside it.
    if crate::plugins::ui::split_route(&path).is_some() {
        return plugin_ui(state, req).await;
    }
    match (req.method().as_str(), path.as_str()) {
        (_, "/rootCA.crt") | (_, "/rootca.crt") => root_ca(state),
        (_, "/proxy.pac") | (_, "/pac") => pac(state, &req),
        (_, "/sessions.json") => sessions_json(state),
        (_, "/sessions.har") => sessions_har(state),
        (_, "/session.json") => session_detail_json(state, &req),
        (_, "/frames.json") => frames_json(state, &req),
        ("GET", "/api/rules") => rules_get(state),
        ("POST", "/api/rules") => rules_post(state, req).await,
        ("GET", "/api/values") => values_get(state),
        ("POST", "/api/values") => values_post(state, req).await,
        ("POST", "/api/replay") => replay_session(state, req).await,
        ("POST", "/api/composer") => compose_request(state, req).await,
        ("GET", "/api/rule-groups") => rule_groups_get(state),
        ("POST", "/api/rule-groups") => rule_groups_add(state, req).await,
        ("POST", "/api/rule-group/toggle") => rule_group_toggle(state, req).await,
        ("POST", "/api/rule-group/update") => rule_group_update(state, req).await,
        ("GET", "/api/rule-group") => rule_group_get(state, &req),
        ("DELETE", "/api/rule-group") => rule_group_delete(state, req).await,
        ("POST", "/api/sessions/clear") => sessions_clear(state),
        ("GET", "/api/status") => status_json(state).await,
        ("GET", "/plugin") => redirect_to("/plugin/"),
        ("GET", "/") | ("GET", "/index.html") => html_ok(index_html(state)),
        _ => not_found(),
    }
}

/// Serve `/plugin/<name>/…` from the named plugin's own UI hook.
///
/// The prefix is stripped here and re-added by the plugin runtime as `/ui`, so a
/// plugin's pages live in their own subtree and can use any path they like
/// without colliding with a hook endpoint. See [`crate::plugins::ui`].
async fn plugin_ui(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let (parts, incoming) = req.into_parts();
    let raw = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let Some((name, rest)) = crate::plugins::ui::split_route(parts.uri.path()) else {
        return not_found();
    };
    if name.is_empty() {
        return plugin_index(state).await;
    }
    // A UI served without a trailing slash breaks every relative link on the
    // page, so redirect rather than serve it — as upstream does
    // (`biz/webui/lib/index.js:489-491`).
    if rest.is_none() {
        return redirect_to(&format!("{}{name}/", crate::plugins::ui::UI_ROUTE_PREFIX));
    }
    let name = name.to_string();
    // Rebuild the path from the raw target so percent-encoding survives.
    let tail = &raw[crate::plugins::ui::UI_ROUTE_PREFIX.len() + name.len()..];
    let Ok(uri) = tail.parse::<hyper::Uri>() else {
        return not_found();
    };

    let mut forwarded = Request::builder().method(parts.method).uri(uri);
    for (k, v) in parts.headers.iter() {
        forwarded = forwarded.header(k, v);
    }
    let Ok(forwarded) = forwarded.body(body::from_incoming(incoming)) else {
        return not_found();
    };
    match state.plugins.serve_ui(&name, forwarded).await {
        Some(resp) => resp,
        None => not_found(),
    }
}

/// Index of the plugins that serve a UI, so they are reachable without knowing
/// the URL by heart.
async fn plugin_index(state: &Arc<AppState>) -> Response<DynBody> {
    let names = state.plugins.ui_names().await;
    let items: String = names
        .iter()
        .map(|n| {
            let n = crate::plugins::ui::escape_html(n);
            format!("<li><a href=\"{n}/\">{n}</a></li>")
        })
        .collect();
    let list = if items.is_empty() {
        "<p>No registered plugin serves a UI.</p>".to_string()
    } else {
        format!("<ul>{items}</ul>")
    };
    html_ok(format!(
        "<!doctype html><meta charset=utf-8><title>whistle-rs plugins</title>\
         <style>body{{font:14px/1.6 system-ui;margin:2rem}}</style>\
         <h1>Plugin pages</h1>{list}"
    ))
}

/// A `302` to `location`.
fn redirect_to(location: &str) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, location)
        .body(body::empty())
        .unwrap_or_else(|_| not_found())
}

/// The web UI's own 404.
fn not_found() -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body::full(Bytes::from_static(b"not found")))
        .unwrap()
}

fn root_ca(state: &Arc<AppState>) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/x-x509-ca-cert")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whistle-rs-rootCA.crt\"",
        )
        .body(body::full(Bytes::from(state.ca.root_cert_pem().to_string())))
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

/// Lightweight session list for the polled Network view (no headers/bodies —
/// those are fetched on demand via [`session_detail_json`]).
fn sessions_json(state: &Arc<AppState>) -> Response<DynBody> {
    let list: Vec<serde_json::Value> = {
        let q = state.sessions.lock().unwrap();
        q.iter()
            .rev()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "time_ms": s.time_ms,
                    "method": s.method,
                    "url": s.url,
                    "status": s.status,
                    "client_ip": s.client_ip,
                    "target": s.target,
                    "duration_ms": s.duration_ms,
                    "log": s.log,
                    // The operators that applied. Carried on the *summary*, not
                    // only on the detail, because it is the one question a row
                    // should be able to answer without being clicked — and
                    // because it costs nothing to carry: the overwhelming
                    // majority of requests match no rule at all, and an empty
                    // list serializes to `[]`. A row that did match carries a
                    // handful of short strings.
                    "rules": s.rules,
                    // The traffic columns. Body bytes only: the head is a
                    // couple of hundred bytes that this port never counts on
                    // the wire, and reporting a guess for it would be worse
                    // than reporting the part it actually measured.
                    "up": s.req_body.as_ref().map(|c| c.total()).unwrap_or(0),
                    "down": s.res_body.as_ref().map(|c| c.total()).unwrap_or(0),
                    "has_req_body": s.req_body.as_ref().map(|c| c.total() > 0).unwrap_or(false),
                    "has_res_body": s.res_body.as_ref().map(|c| c.total() > 0).unwrap_or(false),
                })
            })
            .collect()
    };
    let body = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

/// Export captured traffic as a HAR 1.2 file (importable into DevTools etc.).
fn sessions_har(state: &Arc<AppState>) -> Response<DynBody> {
    let sessions: Vec<Session> = {
        let q = state.sessions.lock().unwrap();
        q.iter().cloned().collect()
    };
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

    let entries: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            let (req_len, _, req_text) = s
                .req_body
                .as_ref()
                .map(|c| c.snapshot())
                .unwrap_or((0, false, String::new()));
            let (res_len, _, res_text) = s
                .res_body
                .as_ref()
                .map(|c| c.snapshot())
                .unwrap_or((0, false, String::new()));
            let post_data = if req_len > 0 {
                serde_json::json!({ "mimeType": mime_of(&s.req_headers), "text": req_text })
            } else {
                serde_json::Value::Null
            };
            serde_json::json!({
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
                    "content": {
                        "size": res_len,
                        "mimeType": mime_of(&s.res_headers),
                        "text": res_text,
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": res_len,
                },
                "cache": {},
                "timings": { "send": 0, "wait": s.duration_ms, "receive": 0 },
                "serverIPAddress": "",
                "_target": s.target,
                "_clientIp": s.client_ip,
            })
        })
        .collect();

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

/// Full detail (headers + captured body previews) for one session (`?id=N`).
fn session_detail_json(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let want: Option<u64> = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("id=")))
        .and_then(|v| v.parse().ok());
    let found: Option<Session> = want.and_then(|id| {
        let q = state.sessions.lock().unwrap();
        q.iter().find(|s| s.id == id).cloned()
    });
    let body = match found {
        Some(s) => serde_json::to_string(&s).unwrap_or_else(|_| "null".into()),
        None => "null".into(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

/// Captured WebSocket frames as JSON. `?id=<session>` filters to one
/// connection; otherwise every buffered frame (newest first) is returned.
fn frames_json(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let want: Option<u64> = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("id="))
                .map(|v| v.to_string())
        })
        .and_then(|v| v.parse().ok());
    let frames: Vec<WsFrame> = {
        let q = state.ws_frames.lock().unwrap();
        q.iter()
            .rev()
            .filter(|f| want.map(|id| f.session == id).unwrap_or(true))
            .cloned()
            .collect()
    };
    let body = serde_json::to_string(&frames).unwrap_or_else(|_| "[]".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
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
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap();
        }
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
    tracing::info!("rules updated via UI: {count} rules");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!("{{\"ok\":true,\"rules\":{count}}}"))))
        .unwrap()
}

// ── Rule group management API ──

/// Where the values store is persisted — the storage root, beside `rules/`.
fn values_dir(state: &Arc<AppState>) -> std::path::PathBuf {
    state.config.data_dir().to_path_buf()
}

fn rules_dir(state: &Arc<AppState>) -> std::path::PathBuf {
    state.config.data_dir().join("rules")
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
        Err(r) => return r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return json_error("name is required");
    }
    let text = payload
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.add_group(name, text, enabled);
        if ok {
            crate::rules::storage::save_groups(&rules_dir(state), &mgr);
        }
        ok
    };
    if ok {
        json_ok()
    } else {
        json_error("group already exists")
    }
}

async fn rule_group_toggle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let result = {
        let mut mgr = state.rules.write().unwrap();
        let r = mgr.toggle_group(name);
        if r.is_some() {
            crate::rules::storage::save_meta(&rules_dir(state), &mgr);
        }
        r
    };
    match result {
        Some(enabled) => {
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
        Err(r) => return r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text = payload
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.update_group(name, text);
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

async fn rule_group_delete(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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

/// Helper: read request body as JSON.
async fn read_json_body(
    req: Request<Incoming>,
) -> Result<serde_json::Value, Response<DynBody>> {
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap()
        })?
        .to_bytes();
    serde_json::from_slice(&body).map_err(|_| {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"invalid JSON")))
            .unwrap()
    })
}

fn json_ok() -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from_static(b"{\"ok\":true}")))
        .unwrap()
}

fn json_error(msg: &str) -> Response<DynBody> {
    let body = format!("{{\"ok\":false,\"error\":\"{msg}\"}}");
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
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

/// What this proxy is, right now.
///
/// Everything here is otherwise only visible in the startup log, which is gone
/// by the time you have a question — "which port is SOCKS on", "is that plugin
/// actually registered", "where does the root certificate live", "is upstream
/// verification off". The console can answer them without a restart.
async fn status_json(state: &Arc<AppState>) -> Response<DynBody> {
    let cfg = &state.config;
    let plugins: Vec<serde_json::Value> = {
        let mut out = Vec::new();
        for name in state.plugins.names() {
            let manifest = state.plugins.manifest(&name).await;
            out.push(serde_json::json!({
                "name": name,
                // A remote plugin that has never answered has no manifest yet,
                // which is itself worth seeing.
                "hooks": manifest.map(|m| hook_names(&m)),
                "remote": cfg.plugins.get(&name),
            }));
        }
        out
    };
    let body = serde_json::json!({
        "version": crate::config::VERSION,
        "port": cfg.port,
        "host": cfg.host.map(|h| h.to_string()),
        "socks_port": cfg.socks_port,
        "intercept_https": cfg.intercept_https,
        "insecure_upstream": super::upstream::insecure_upstream(),
        "storage_dir": cfg.storage_dir.to_string_lossy(),
        "root_ca": cfg.root_ca_cert_path().to_string_lossy(),
        "body_preview_cap": cfg.body_preview_cap,
        "persist_sessions": cfg.persist_sessions,
        "persist_days": cfg.persist_days,
        "timeout_ms": cfg.timeout_ms,
        "rules": state.rules.read().unwrap().len(),
        "sessions": state.sessions.lock().unwrap().len(),
        "frames": state.ws_frames.lock().unwrap().len(),
        "plugins": plugins,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body.to_string())))
        .unwrap()
}

fn sessions_clear(state: &Arc<AppState>) -> Response<DynBody> {
    state.clear_sessions();
    tracing::info!("sessions cleared via UI");
    json_ok()
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
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap();
        }
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
        Err(_) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"expected a JSON object")))
            .unwrap(),
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
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap();
        }
    };
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"invalid JSON")))
                .unwrap();
        }
    };
    let ids: Vec<u64> = if let Some(id) = payload.get("id").and_then(|v| v.as_u64()) {
        vec![id]
    } else if let Some(arr) = payload.get("ids").and_then(|v| v.as_array()) {
        arr.iter()
            .filter_map(|v| v.as_u64())
            .take(100)
            .collect()
    } else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(
                b"{\"error\":\"expected id or ids\"}",
            )))
            .unwrap();
    };

    // Collect the sessions to replay while holding the lock briefly.
    let sessions: Vec<Session> = {
        let q = state.sessions.lock().unwrap();
        ids.iter()
            .filter_map(|id| q.iter().find(|s| s.id == *id).cloned())
            .collect()
    };
    if sessions.is_empty() {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body::full(Bytes::from_static(
                b"{\"replayed\":0,\"error\":\"no matching sessions\"}",
            )))
            .unwrap();
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
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return refused("could not read body"),
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

/// A `400` the console can read: everything it posts, it reads back as JSON.
fn refused(error: &str) -> Response<DynBody> {
    let answer = serde_json::json!({ "ok": false, "error": error });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(answer.to_string())))
        .unwrap()
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
/// `ui-src/dist/index.html` is a committed build artifact, and deliberately so.
/// The console is a Vue 3 / Vite / TypeScript app — which needs node to build —
/// but the *proxy* must not: `cargo build` on a machine with no node has to
/// produce a working binary. So the artifact is checked in and `include_str!`'d,
/// and `ui-src/README.md` says how to regenerate it.
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
    include_str!("../../ui-src/dist/index.html")
        .replace("__VERSION__", crate::config::VERSION)
        .replace("__HOST__", &host)
        .replace("__PORT__", &state.config.port.to_string())
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
        let bytes = req.into_body().collect().await.expect("a full body").to_bytes();
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
            Some(Capture::from_bytes(b"abc", Some("text/plain".into()), None, 4096)),
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
        assert_eq!(header(&headers, super::super::COMPOSER_REQ_HEADER), Some("1"));
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
        assert_eq!(header(&headers, super::super::COMPOSER_REQ_HEADER), Some("1"));
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
        let c = composed("GET", "http://example.com/", "Accept: */*\nX-Tenant acme", "");
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
