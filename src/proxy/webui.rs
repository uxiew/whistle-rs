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
use super::{AppState, Session, WsFrame};

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
    // Fire-and-forget: spawn tasks that send requests through the proxy.
    for sess in sessions {
        tokio::spawn(async move {
            if let Err(e) = do_replay(port, &sess).await {
                tracing::warn!("replay id={} failed: {e}", sess.id);
            }
        });
    }
    let body_text = format!("{{\"replayed\":{replayed}}}");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body_text)))
        .unwrap()
}

/// Send a captured session's request through the proxy's own port so it flows
/// through the full rule-matching + forwarding pipeline again.
async fn do_replay(
    proxy_port: u16,
    sess: &Session,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let method: hyper::Method = sess.method.parse().unwrap_or(hyper::Method::GET);
    let uri: hyper::Uri = sess.url.parse().unwrap_or_else(|_| "/".parse().unwrap());
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (name, value) in &sess.req_headers {
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
    let req = builder
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let _resp = sender.send_request(req).await?;
    Ok(())
}


fn html_ok(html: String) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body::full(Bytes::from(html)))
        .unwrap()
}

/// The console, assembled from `ui/` at compile time.
///
/// The three assets are separate files so the CSS and JavaScript can be edited
/// as CSS and JavaScript — with a formatter, with syntax highlighting, and
/// without escaping every brace past a `format!`. They are stitched together
/// here rather than served separately because the console must load with the
/// network it is inspecting switched off, which rules out a second request.
fn index_html(state: &Arc<AppState>) -> String {
    let host = state
        .config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    include_str!("ui/index.html")
        .replace("/*__CM_CSS__*/", include_str!("ui/vendor/codemirror.css"))
        .replace("/*__CSS__*/", include_str!("ui/app.css"))
        .replace(
            "/*__CM_JS__*/",
            &[
                include_str!("ui/vendor/codemirror.js"),
                include_str!("ui/vendor/mode-javascript.js"),
                include_str!("ui/vendor/addon-placeholder.js"),
            ]
            .join("\n;\n"),
        )
        .replace("/*__MODE_JS__*/", include_str!("ui/mode-whistle.js"))
        .replace("/*__JS__*/", include_str!("ui/app.js"))
        .replace("__VERSION__", crate::config::VERSION)
        .replace("__HOST__", &host)
        .replace("__PORT__", &state.config.port.to_string())
}
