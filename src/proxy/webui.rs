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

/// The single-page UI (all CSS/JS inline; no external requests).
fn index_html(state: &Arc<AppState>) -> String {
    let version = crate::config::VERSION;
    let host = state
        .config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = state.config.port;
    format!(
        r##"<!doctype html><html data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>whistle-rs</title>
<style>
:root{{--bg:#fff;--fg:#222;--muted:#888;--line:#eee;--accent:#2d7ff9;--code:#f4f4f4}}
@media(prefers-color-scheme:dark){{:root{{--bg:#1e1e1e;--fg:#e0e0e0;--muted:#999;--line:#333;--accent:#4c9ffe;--code:#2a2a2a}}}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
header{{display:flex;align-items:center;gap:16px;padding:10px 16px;border-bottom:1px solid var(--line)}}
header h1{{font-size:16px;margin:0}}
header .sp{{flex:1}}
header a{{color:var(--accent);text-decoration:none;font-size:13px}}
nav{{display:flex;gap:4px;padding:8px 16px;border-bottom:1px solid var(--line)}}
nav button{{background:none;border:1px solid var(--line);color:var(--fg);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:13px}}
nav button.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
main{{padding:12px 16px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);white-space:nowrap}}
td.url{{white-space:normal;word-break:break-all}}
.s2{{color:#2e9d4f}}.s3{{color:#3b8fd6}}.s4,.s5{{color:#e05a5a}}
textarea{{width:100%;height:60vh;font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--code);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:10px}}
.bar{{display:flex;gap:10px;align-items:center;margin-bottom:8px}}
.bar input#filter{{flex:1;max-width:360px;background:var(--code);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;font-size:13px}}
.bar button{{background:var(--accent);color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer}}
.hint{{color:var(--muted);font-size:12px}}
.hidden{{display:none}}
tr.row{{cursor:pointer}}
tr.row:hover td{{background:var(--code)}}
.wsbadge{{font-size:10px;background:var(--accent);color:#fff;border-radius:3px;padding:0 4px;margin-left:4px}}
.wsbadge.b{{background:var(--muted)}}
.detail{{padding:4px 2px}}
.grp{{margin:8px 0}}
.grpt{{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.03em}}
.hz{{display:flex;gap:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:1px 0;word-break:break-all}}
.hk{{color:var(--accent);flex:0 0 30%;max-width:260px}}
.hv{{flex:1;white-space:pre-wrap}}
pre.body{{font-family:ui-monospace,Menlo,monospace;font-size:12px;max-height:32vh;overflow:auto;background:var(--code);border-radius:6px;padding:8px;margin:0;white-space:pre-wrap;word-break:break-all}}
.frames{{font-family:ui-monospace,Menlo,monospace;font-size:12px;max-height:40vh;overflow:auto;background:var(--code);border-radius:6px;padding:6px}}
.frm{{display:flex;gap:8px;padding:2px 4px;border-bottom:1px solid var(--line);white-space:nowrap}}
.frm .arw{{width:56px}}
.frm.send .arw{{color:#3b8fd6}}
.frm.receive .arw{{color:#2e9d4f}}
.frm .op{{width:80px;color:var(--muted)}}
.frm .len{{width:64px;color:var(--muted);text-align:right}}
.frm .pv{{flex:1;white-space:pre;overflow:hidden;text-overflow:ellipsis}}
.rbtn{{background:none;border:1px solid var(--line);color:var(--muted);padding:1px 6px;border-radius:4px;cursor:pointer;font-size:12px;line-height:1}}
.rbtn:hover{{color:var(--accent);border-color:var(--accent)}}
.grp{{display:flex;align-items:center;gap:8px;padding:4px 8px;border-bottom:1px solid var(--line)}}
.grp label{{flex:1;cursor:pointer}}
.grp-off label{{opacity:.5;text-decoration:line-through}}
</style></head><body>
<header>
  <h1>whistle-rs</h1><span class="hint">v{version} · proxy {host}:{port}</span>
  <span class="sp"></span>
  <a href="/rootCA.crt">rootCA.crt</a>
  <a href="/proxy.pac">proxy.pac</a>
  <a href="/sessions.har" download>HAR</a>
</header>
<nav>
  <button id="tab-net" class="active" onclick="show('net')">Network</button>
  <button id="tab-rules" onclick="show('rules')">Rules</button>
  <button id="tab-values" onclick="show('values')">Values</button>
</nav>
<main>
  <section id="net">
    <div class="bar">
      <button onclick="loadNet()">Refresh</button>
      <button onclick="clearSessions()">Clear</button>
      <input id="filter" placeholder="filter: url / method / status" oninput="loadNet()">
      <label class="hint"><input type="checkbox" id="auto" checked> auto-refresh</label>
      <span class="hint" id="netcount"></span>
    </div>
    <table><thead><tr><th>#</th><th>Method</th><th>Status</th><th>URL</th><th>Target</th><th>ms</th><th></th></tr></thead>
    <tbody id="rows"></tbody></table>
  </section>
  <section id="rules" class="hidden">
    <div class="bar">
      <button onclick="saveRules()">Save</button>
      <span class="hint" id="rulestatus"></span>
    </div>
    <textarea id="editor" spellcheck="false" placeholder="pattern operator1 operator2 ..."></textarea>
    <p class="hint">Default group — one rule per line. See the docs for the full syntax.</p>
    <div class="bar" style="margin-top:8px">
      <b>Rule Groups</b>
      <button onclick="addGroup()">+ Add Group</button>
      <span class="hint" id="grpstatus"></span>
    </div>
    <div id="grplist"></div>
  </section>
  <section id="values" class="hidden">
    <div class="bar">
      <button onclick="saveValues()">Save</button>
      <span class="hint" id="valstatus"></span>
    </div>
    <textarea id="valeditor" spellcheck="false" placeholder='{{"name":"content"}}'></textarea>
    <p class="hint">A JSON object of named values. Reference them with <code>{{name}}</code> in rules.</p>
  </section>
</main>
<script>
var esc=function(s){{return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}};
function show(t){{
  ['net','rules','values'].forEach(function(x){{
    document.getElementById(x).classList.toggle('hidden',x!==t);
    document.getElementById('tab-'+x).classList.toggle('active',x===t);
  }});
  if(t==='rules') loadRules();
  if(t==='values') loadValues();
}}
var open={{}}, wsRows={{}};
function loadNet(){{
  fetch('/sessions.json').then(function(r){{return r.json()}}).then(function(all){{
    var q=(document.getElementById('filter').value||'').toLowerCase().trim();
    var list=q?all.filter(function(s){{
      return (s.url||'').toLowerCase().indexOf(q)>=0
        || (s.method||'').toLowerCase().indexOf(q)>=0
        || String(s.status).indexOf(q)>=0
        || (s.target||'').toLowerCase().indexOf(q)>=0;
    }}):all;
    document.getElementById('netcount').textContent=q?(list.length+' / '+all.length+' shown'):(all.length+' captured');
    document.getElementById('rows').innerHTML=list.map(function(s){{
      var cls='s'+Math.floor(s.status/100);
      var ws=s.status===101;
      wsRows[s.id]=ws;
      var tag=ws?'<span class="wsbadge">WS</span>':(s.has_res_body?'<span class="wsbadge b">body</span>':'');
      var row='<tr class="row" onclick="toggle('+s.id+')"><td>'+s.id+
        '</td><td>'+esc(s.method)+'</td><td class="'+cls+'">'+s.status+
        tag+'</td><td class="url">'+esc(s.url)+
        '</td><td>'+esc(s.target)+'</td><td>'+s.duration_ms+'</td><td><button class="rbtn" onclick="replayReq('+s.id+',event)" title="Replay">↻</button></td></tr>';
      row+='<tr class="det hidden" id="det'+s.id+'"><td colspan="7">'+
        '<div class="detail" id="dt'+s.id+'">click the row to load…</div></td></tr>';
      return row;
    }}).join('');
    Object.keys(open).forEach(render);
  }});
}}
function toggle(id){{
  if(open[id]) delete open[id]; else open[id]=true;
  render(id);
}}
function render(id){{
  var det=document.getElementById('det'+id);
  if(!det) return;
  var isOpen=!!open[id];
  det.classList.toggle('hidden',!isOpen);
  if(isOpen){{ if(wsRows[id]) loadFrames(id); else loadDetail(id); }}
}}
function headerTable(title,pairs){{
  if(!pairs||!pairs.length) return '';
  var rows=pairs.map(function(p){{return '<div class="hz"><span class="hk">'+esc(p[0])+'</span>'+
    '<span class="hv">'+esc(p[1])+'</span></div>';}}).join('');
  return '<div class="grp"><div class="grpt">'+title+'</div>'+rows+'</div>';
}}
function bodyBlock(title,b){{
  if(!b||!b.len) return '';
  var note=b.truncated?' <span class="hint">('+b.len+' bytes, truncated)</span>':' <span class="hint">('+b.len+' bytes)</span>';
  return '<div class="grp"><div class="grpt">'+title+note+'</div><pre class="body">'+esc(b.text)+'</pre></div>';
}}
function loadDetail(id){{
  fetch('/session.json?id='+id).then(function(r){{return r.json()}}).then(function(s){{
    var box=document.getElementById('dt'+id);
    if(!box) return;
    if(!s){{box.textContent='(no detail)';return;}}
    box.innerHTML=headerTable('Request headers',s.req_headers)+bodyBlock('Request body',s.req_body)+
      headerTable('Response headers',s.res_headers)+bodyBlock('Response body',s.res_body)||'(no captured detail)';
  }});
}}
function loadFrames(id){{
  fetch('/frames.json?id='+id).then(function(r){{return r.json()}}).then(function(list){{
    var box=document.getElementById('dt'+id);
    if(!box) return;
    if(!list.length){{box.textContent='no frames captured yet';return;}}
    box.innerHTML='<div class="frames">'+list.slice().reverse().map(function(f){{
      var arrow=f.dir==='send'?'▲ send':'▼ recv';
      return '<div class="frm '+f.dir+'"><span class="arw">'+arrow+'</span><span class="op">'+
        esc(f.opcode)+'</span><span class="len">'+f.len+'B</span><span class="pv">'+esc(f.preview)+'</span></div>';
    }}).join('')+'</div>';
  }});
}}
function loadRules(){{
  fetch('/api/rules').then(function(r){{return r.text()}}).then(function(t){{
    document.getElementById('editor').value=t;
  }});
  loadGroups();
}}
function saveRules(){{
  var txt=document.getElementById('editor').value;
  fetch('/api/rules',{{method:'POST',body:txt}}).then(function(r){{return r.json()}}).then(function(j){{
    document.getElementById('rulestatus').textContent='Saved · '+j.rules+' rules active';
  }}).catch(function(){{document.getElementById('rulestatus').textContent='Save failed'}});
}}
function loadGroups(){{
  fetch('/api/rule-groups').then(function(r){{return r.json()}}).then(function(groups){{
    var el=document.getElementById('grplist');
    if(!groups.length){{el.innerHTML='<p class="hint">No custom groups.</p>';return;}}
    el.innerHTML=groups.filter(function(g){{return g.name!=='default'}}).map(function(g){{
      var cls=g.enabled?'grp':'grp grp-off';
      return '<div class="'+cls+'" data-name="'+esc(g.name)+'">'+
        '<label><input type="checkbox" '+(g.enabled?'checked':'')+' onchange="toggleGroup(\''+esc(g.name)+'\')">'+ esc(g.name)+'</label>'+
        '<span class="hint">'+g.rules+' rules</span>'+
        '<button class="rbtn" onclick="editGroup(\''+esc(g.name)+'\')">edit</button>'+
        '<button class="rbtn" onclick="deleteGroup(\''+esc(g.name)+'\')">×</button>'+
        '</div>';
    }}).join('');
  }});
}}
function addGroup(){{
  var name=prompt('Group name:');
  if(!name||!name.trim()) return;
  fetch('/api/rule-groups',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name:name.trim(),text:'',enabled:true}})}}).then(function(r){{return r.json()}}).then(function(j){{
    if(j.ok) loadGroups(); else alert(j.error||'Failed');
  }});
}}
function toggleGroup(name){{
  fetch('/api/rule-group/toggle',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name:name}})}}).then(function(r){{return r.json()}}).then(function(j){{
    document.getElementById('grpstatus').textContent=name+(j.enabled?' enabled':' disabled');
    loadGroups();
  }});
}}
function editGroup(name){{
  var el=document.querySelector('[data-name="'+name+'"]');
  if(!el) return;
  if(el.querySelector('textarea')) return; // already editing
  fetch('/api/rule-group?name='+encodeURIComponent(name)).then(function(r){{return r.json()}}).then(function(g){{
    if(!g.name) return;
    var ta=document.createElement('textarea');
    ta.style.cssText='width:100%;height:120px;margin-top:4px;font-family:monospace;font-size:12px';
    ta.placeholder='rules for '+name;
    ta.value=g.text||'';
    var btn=document.createElement('button');
    btn.textContent='Save Group';
    btn.onclick=function(){{
      fetch('/api/rule-group/update',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name:name,text:ta.value}})}}).then(function(r){{return r.json()}}).then(function(j){{
        if(j.ok){{document.getElementById('grpstatus').textContent=name+' saved';loadGroups();}}
        else alert(j.error||'Failed');
      }});
    }};
    el.appendChild(ta);
    el.appendChild(btn);
  }});
}}
function deleteGroup(name){{
  if(!confirm('Delete group "'+name+'"?')) return;
  fetch('/api/rule-group',{{method:'DELETE',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name:name}})}}).then(function(r){{return r.json()}}).then(function(j){{
    if(j.ok) loadGroups(); else alert(j.error||'Failed');
  }});
}}
function loadValues(){{
  fetch('/api/values').then(function(r){{return r.json()}}).then(function(v){{
    document.getElementById('valeditor').value=JSON.stringify(v,null,2);
  }});
}}
function saveValues(){{
  var txt=document.getElementById('valeditor').value;
  try{{JSON.parse(txt);}}catch(e){{document.getElementById('valstatus').textContent='Invalid JSON';return;}}
  fetch('/api/values',{{method:'POST',body:txt}}).then(function(r){{return r.json()}}).then(function(){{
    document.getElementById('valstatus').textContent='Saved';
  }}).catch(function(){{document.getElementById('valstatus').textContent='Save failed'}});
}}
function replayReq(id,e){{
  e.stopPropagation();
  fetch('/api/replay',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{id:id}})}}).then(function(r){{return r.json()}}).then(function(j){{
    if(j.replayed) setTimeout(loadNet,500);
  }}).catch(function(){{}});
}}
function clearSessions(){{
  if(!confirm('Clear all captured sessions?')) return;
  fetch('/api/sessions/clear',{{method:'POST'}}).then(function(r){{return r.json()}}).then(function(){{
    loadNet();
    document.getElementById('netcount').textContent='cleared';
  }});
}}
loadNet();
setInterval(function(){{if(document.getElementById('auto').checked && !document.getElementById('net').classList.contains('hidden')) loadNet();}},2000);
</script>
</body></html>"##,
        version = version,
        host = host,
        port = port,
    )
}
