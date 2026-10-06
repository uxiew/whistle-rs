//! The captured traffic over HTTP: the session list and its cursor (`after`,
//! `ids`, `open`), the search the proxy runs over all of it (`h:`, `b:`), one
//! session's detail and bodies, WebSocket frames and their held directions,
//! the status pane, and clearing the list or deleting the history.

use super::*;

/// Lightweight session list for the polled Network view (no headers/bodies —
/// those are fetched on demand via [`session_detail_json`]). Newest first.
///
/// Two optional parameters make it a cursor for a program that polls it:
/// `after=N` keeps the rows with an id above N (ids only grow), and
/// `ids=1,2,3` keeps those rows. A row marked `open` is still receiving its
/// response, so polling `after` the newest id and `ids` of the open ones sees
/// every session arrive and every session finish. The console reads it whole.
pub(super) fn sessions_json(state: &Arc<AppState>, query: Option<&str>) -> Response<DynBody> {
    let param = |name: &str| {
        query?
            .split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
    };
    let after: u64 = match param("after").map(str::parse) {
        None => 0,
        Some(Ok(n)) => n,
        Some(Err(_)) => return refused("after must be a session id"),
    };
    let only: Option<std::collections::HashSet<u64>> = param("ids").map(|v| {
        v.split(',')
            .filter_map(|id| id.trim().parse().ok())
            .collect()
    });
    // Which sessions have frames to show. Read once and looked up per row: a
    // body cut into frames (an event stream, or a separator a rule named) is
    // not a WebSocket, so the status cannot answer this on its own — and the
    // console hides the Frames tab for a session with nothing in it.
    let framed: std::collections::HashSet<u64> = {
        let frames = state.ws_frames.lock().unwrap();
        frames.iter().map(|f| f.session).collect()
    };
    let list: Vec<serde_json::Value> = {
        let q = state.sessions.lock().unwrap();
        q.iter()
            .rev()
            .filter(|s| s.id > after && only.as_ref().is_none_or(|ids| ids.contains(&s.id)))
            .map(|s| {
                let mut row = serde_json::json!({
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
                    "has_frames": s.status == 101 || framed.contains(&s.id),
                    // The response's content type, for the console's `t:` filter
                    // — `t:json` is one of the two or three questions anyone
                    // asks of a busy capture, and the summary is the only place
                    // that can answer it without fetching every row's detail.
                    // One short string; the header itself, not a guess at a
                    // category, so a filter written `t:event-stream` works too.
                    "type": s.res_headers.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.as_str()),
                });
                // Why the request did not complete, on the row itself: "which of
                // these failed, and where" is a question about the whole list.
                // Only on the rows that have one, so the poll does not carry a
                // `null` for every request that went fine.
                if let Some(failure) = s.error.get() {
                    row["error"] = serde_json::json!(failure);
                }
                // Sent from the Composer or Replay: what `fc:` asks about. Only
                // on those rows, for the same reason.
                if s.composer {
                    row["composer"] = serde_json::json!(true);
                }
                // Still receiving its response: its sizes, its body and its
                // `error` can change. Only while it is.
                if s.error.is_open() {
                    row["open"] = serde_json::json!(true);
                }
                // Operators in `rules` that did not take effect. On the row
                // because "which of these did my rule not touch" is a question
                // about the list, and it sits beside `rules` there.
                if !s.unapplied.is_empty() {
                    row["unapplied"] = serde_json::json!(s.unapplied);
                }
                row
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

/// The search box's `h:` and `b:` over every session held — see
/// [`super::super::search`]. `?c=h:cookie&c=b:/ok/i`: one `c` per condition.
///
/// The work runs off the runtime: it reads every kept header and body in the
/// ring, and the console asks again on each poll while such a condition is in
/// the box.
pub(super) async fn sessions_search(
    state: &Arc<AppState>,
    req: &Request<Incoming>,
) -> Response<DynBody> {
    let asked = query_values(req, "c");
    if asked.is_empty() {
        return refused("nothing to search for: pass ?c=h:… or ?c=b:…, one c per condition");
    }
    let conditions = match asked
        .iter()
        .map(|c| super::super::search::Condition::parse(c))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(c) => c,
        Err(why) => return refused(&why),
    };
    let sessions: Vec<Session> = state.sessions.lock().unwrap().iter().cloned().collect();
    let scanned = sessions.len();
    let answers =
        tokio::task::spawn_blocking(move || super::super::search::search(&sessions, &conditions))
            .await
            .unwrap_or_default();
    let body = serde_json::json!({ "scanned": scanned, "results": answers });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body.to_string())))
        .unwrap()
}

/// Every value of a repeated query parameter, decoded as a form encodes it,
/// which is how `URLSearchParams` sends a search.
pub(super) fn query_values(req: &Request<Incoming>, name: &str) -> Vec<String> {
    let Some(query) = req.uri().query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
        .map(percent_decode)
        .collect()
}

/// Full detail (headers + captured body previews) for one session (`?id=N`).
pub(super) fn session_detail_json(
    state: &Arc<AppState>,
    req: &Request<Incoming>,
) -> Response<DynBody> {
    let want: Option<u64> = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("id=")))
        .and_then(|v| v.parse().ok());
    let found: Option<Session> = want.and_then(|id| {
        let q = state.sessions.lock().unwrap();
        q.iter().find(|s| s.id == id).cloned()
    });
    // An id the proxy does not hold (never had, hidden, or evicted) is `null`
    // with a 200, not a 404: the console asks for the selected row on every
    // poll, and a row that has just left the list is not an error.
    let body = match found {
        Some(s) => {
            let mut detail = serde_json::to_value(&s).unwrap_or_default();
            if s.error.is_open() {
                detail["open"] = serde_json::json!(true);
            }
            detail.to_string()
        }
        None => "null".into(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

/// One query parameter, undecoded. Every caller here reads digits, a side name
/// or a comma-separated id list, none of which percent-encoding reaches.
pub(super) fn query_param(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
            .map(|v| v.to_string())
    })
}

/// A `?name=1,2,3` session-id list. `None` when the parameter is absent, which
/// every caller reads as "all of them" — an *empty* list is a selection of
/// nothing and stays distinct from it.
pub(super) fn id_list(req: &Request<Incoming>, name: &str) -> Option<Vec<u64>> {
    query_param(req, name).map(|v| {
        v.split(',')
            .filter_map(|id| id.trim().parse().ok())
            .collect()
    })
}

/// The captured bytes of one body (`?id=N&side=req|res`).
///
/// The hex view, the image preview and the download all need the body as bytes,
/// and until this route existed the console never saw them: a non-textual body
/// was replaced by a `[binary, N bytes]` marker as it was serialized, so there
/// was nothing behind the marker to render.
///
/// `/session.json` deliberately does not grow a base64 copy instead. It is
/// fetched on every selection, and encoding two 16 KiB previews into it would be
/// paid on every click, by everyone, to serve the small minority of bodies
/// anyone opens as bytes. A HAR has no such choice — it is one file that has to
/// carry everything — which is why [`har_body`] does base64 and this does not.
///
/// The response is **always** an attachment, whatever type was recorded. These
/// bytes are whatever the inspected site sent, and they are served from the
/// console's own origin: a captured `text/html` body rendered as a page here
/// would be someone else's script with reach into `/api/rules`. An attachment
/// is never rendered as a page, and `nosniff` stops the browser deciding the
/// type for itself. Neither `fetch` nor `<img>` honours the disposition, and
/// those are the only two ways the console reads this route.
pub(super) fn session_body_bytes(
    state: &Arc<AppState>,
    req: &Request<Incoming>,
) -> Response<DynBody> {
    let want: Option<u64> = query_param(req, "id").and_then(|v| v.parse().ok());
    let side = query_param(req, "side").unwrap_or_else(|| "res".to_string());
    let found: Option<Session> = want.and_then(|id| {
        let q = state.sessions.lock().unwrap();
        q.iter().find(|s| s.id == id).cloned()
    });
    let Some(sess) = found else {
        return not_found();
    };
    let capture = match side.as_str() {
        "req" => sess.req_body.as_ref(),
        "res" => sess.res_body.as_ref(),
        _ => return not_found(),
    };
    let Some(preview) = capture.map(|c| c.preview_bytes()) else {
        return not_found();
    };
    let content_type = preview
        .content_type
        .as_deref()
        .and_then(|ct| hyper::header::HeaderValue::from_str(ct).ok())
        .unwrap_or_else(|| hyper::header::HeaderValue::from_static("application/octet-stream"));
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"{}\"",
                body_filename(&sess, &side, preview.truncated)
            ),
        )
        .body(body::full(preview.bytes))
        .unwrap()
}

/// What to call a downloaded body: the last segment of the URL when it has one,
/// and the session it came from when it does not.
///
/// A capped preview is named `partial-…`. The bytes are a prefix of the body and
/// nothing inside the file can say so — a truncated PNG saved under the name of
/// the whole one is a wrong answer that looks like a corrupt server.
pub(super) fn body_filename(sess: &Session, side: &str, truncated: bool) -> String {
    let without_query = sess.url.split(['?', '#']).next().unwrap_or("");
    // The path, never the authority: `https://example.com/` has no filename in
    // it, and the last `/`-segment of the whole URL would be the host.
    let path = match without_query.split_once("://") {
        Some((_, rest)) => rest.split_once('/').map(|(_, p)| p).unwrap_or(""),
        None => without_query,
    };
    // Only the characters a filename needs. The rest is dropped rather than
    // escaped: this ends up inside a quoted `Content-Disposition` filename, and
    // the URL is the inspected site's to choose — a quote or a CRLF in it would
    // close the filename early and start a header of its own.
    let name: String = path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let name = match name.trim_matches('.').is_empty() {
        true => format!("session-{}-{side}.bin", sess.id),
        false => name,
    };
    match truncated {
        true => format!("partial-{name}"),
        false => name,
    }
}

/// Captured WebSocket frames as JSON. `?id=<session>` filters to one
/// connection; otherwise every buffered frame (newest first) is returned.
pub(super) fn frames_json(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let want = query_id(req);
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

// ── the WebSocket pause control ──

/// A JSON body that is built rather than spelled out.
pub(super) fn json_value(body: &serde_json::Value) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body.to_string())))
        .unwrap()
}

/// Whether either direction of one live WebSocket session is being held, and how
/// much of it (`?id=<session>`).
///
/// Only a session `enable://pauseSend|pauseReceive` held is registered, so
/// `live: false` covers "never paused" and "already closed" alike — which is all
/// the console can act on anyway. It answers for an unknown id rather than
/// failing, because this is what the Frames tab polls.
///
/// whistle's own endpoint is the setter `/cgi-bin/socket/change-status`, which
/// can also *start* a pause on a live session from its UI (`changeStatus`,
/// `_original/lib/socket-mgr.js:907-918`). This port only lifts one: the hold
/// machinery is wired up for the directions a rule named, so there is nothing
/// for a mid-session pause to hold with.
pub(super) fn ws_status(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let want = query_id(req);
    let found = want.and_then(|id| state.ws_pause.lock().unwrap().get(&id).cloned());
    let dir = |d: Option<&crate::proxy::ws::DirPause>| match d {
        Some(d) => serde_json::json!({ "paused": d.paused(), "held": d.held() }),
        None => serde_json::json!({ "paused": false, "held": 0 }),
    };
    // `live` used to mean "somebody is holding this one", because a pause was
    // the only reason to register a session. It now means what it says: the
    // connection is open, which is also what decides whether a frame can be
    // sent into it.
    let open = want.is_some_and(|id| state.ws_write.lock().unwrap().contains_key(&id));
    let body = serde_json::json!({
        "live": open || found.is_some(),
        "send": dir(found.as_ref().map(|p| &p.send)),
        "receive": dir(found.as_ref().map(|p| &p.receive)),
    });
    json_value(&body)
}

/// Let one held direction of one session go: `{ "id": N, "dir": "send" }`.
///
/// Per session and per direction, and all of it at once, because that is the
/// only granularity upstream has — its console picks a status for a direction,
/// and everything held goes out when it picks `0` again. There is no
/// release-one-frame anywhere in whistle.
pub(super) async fn ws_release(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(id) = payload.get("id").and_then(|v| v.as_u64()) else {
        return json_error("id is required");
    };
    let name = payload.get("dir").and_then(|v| v.as_str()).unwrap_or("");
    let found = state.ws_pause.lock().unwrap().get(&id).cloned();
    let Some(pause) = found else {
        // The session ended while its frames were held. They stay flagged in the
        // capture, which is the truth: they never reached the peer.
        return json_error("no live paused WebSocket session with that id");
    };
    let Some(gate) = pause.dir(name) else {
        return json_error("dir must be \"send\" or \"receive\"");
    };
    let released = gate.release();
    tracing::info!("released {released} held {name} frame(s) of session {id}");
    json_value(&serde_json::json!({ "ok": true, "released": released }))
}

/// Send a frame into a **live** WebSocket session, from the console.
///
/// whistle's Frames panel has the same control (`gui/network.md`): a message to
/// either end of a connection that is still open, which is the one thing a
/// capture cannot answer on its own — what the other side *does* with a message
/// it has not been sent yet.
///
/// `dir` is the capture's own spelling, so it reads the same as the frame list:
/// `send` puts the frame on its way to the **server**, as if the client had
/// sent it, and `receive` on its way to the client. The frame is masked the way
/// a real one from that side would be, so neither end can tell it apart.
pub(super) async fn ws_send(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(id) = payload.get("id").and_then(|v| v.as_u64()) else {
        return json_error("id is required");
    };
    let dir = payload.get("dir").and_then(|v| v.as_str()).unwrap_or("");
    if dir != "send" && dir != "receive" {
        return json_error("dir must be \"send\" or \"receive\"");
    }
    let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("");
    let found = state.ws_write.lock().unwrap().get(&id).cloned();
    let Some(writers) = found else {
        return json_error("no live WebSocket session with that id");
    };
    if !writers.send(dir, data.as_bytes()).await {
        return json_error("the connection would not take it");
    }
    // Recorded like any other frame, because it is one — the direction says
    // where it went, and the console shows it in the same list.
    state.record_frame(crate::proxy::WsFrame::console_frame(
        id,
        dir,
        data.as_bytes(),
    ));
    tracing::info!(
        "console sent {} bytes into session {id} ({dir})",
        data.len()
    );
    json_value(&serde_json::json!({ "ok": true, "sent": data.len() }))
}

/// The `?id=<n>` a per-session endpoint takes.
pub(super) fn query_id(req: &Request<Incoming>) -> Option<u64> {
    req.uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("id=")))
        .and_then(|v| v.parse().ok())
}

/// What this proxy is, right now.
///
/// Everything here is otherwise only visible in the startup log, which is gone
/// by the time you have a question — "which port is SOCKS on", "is that plugin
/// actually registered", "where does the root certificate live", "is upstream
/// verification off". The console can answer them without a restart.
pub(super) async fn status_json(state: &Arc<AppState>, restricted: bool) -> Response<DynBody> {
    let cfg = &state.config;
    // A cross-origin caller reached this only through the blanket `CORS_PATHS`
    // exemption — see [`status_body_restricted`]. Answer that it is alive and
    // what version, and nothing that fingerprints the host: not the storage path
    // (which names the account), not the LAN addresses, not the plugin list.
    if restricted {
        let body = serde_json::json!({
            "version": crate::config::VERSION,
            "port": cfg.port,
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body::full(Bytes::from(body.to_string())))
            .unwrap();
    }
    let plugins: Vec<serde_json::Value> = {
        let mut out = Vec::new();
        for name in state.plugins.names() {
            let manifest = state.plugins.declared(&name).await;
            out.push(serde_json::json!({
                "on": state.plugins.is_on(&name),
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
        // The address actually bound, and whether that lets anything but this
        // machine in: the console offers phone QR codes only when it does.
        "host": cfg.bind_ip().to_string(),
        "listening_on_lan": cfg.listens_beyond_loopback(),
        // The addresses a device on the same network can reach this at — the
        // thing `mobile.md` is an entire page about typing into a phone, and
        // which `0.0.0.0` does not answer. See `proxy::lan_addresses`.
        "lan_addresses": super::super::lan_addresses()
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>(),
        "socks_port": cfg.socks_port,
        // What a connection actually meets, so the console does not claim to be
        // decrypting when `-M multiEnv` has taken the switch away — see
        // `Config::intercepts_https`.
        "intercept_https": state.intercepts_https(),
        // Why, when the two disagree: the switch is on and a mode overrode it.
        "capture_locked_off": cfg.capture_locked_off,
        // Whether a request may carry its own rules, and whose win when it does.
        "header_rules": match cfg.header_rules {
            crate::config::HeaderRules::Off => "off",
            crate::config::HeaderRules::Console => "enableRequestHeaderRules",
            crate::config::HeaderRules::Request => "multiEnv",
        },
        "insecure_upstream": super::super::upstream::insecure_upstream(),
        "storage_dir": cfg.storage_dir.to_string_lossy(),
        "root_ca": cfg.root_ca_cert_path().to_string_lossy(),
        "body_preview_cap": cfg.body_preview_cap,
        // The one that decides whether a rule's body operators run at all —
        // see `unapplied`. It was nowhere a person could read it back.
        "body_rewrite_cap": cfg.body_rewrite_cap,
        "persist_sessions": cfg.persist_sessions,
        "persist_days": cfg.persist_days,
        "persist_max_bytes": cfg.persist_max_bytes,
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

/// Forget captured sessions: all of them, or only the `{"ids":[…]}` the request
/// table's selection names.
///
/// A body that names no ids clears everything, which is both what the console
/// sent before multi-select existed (`{}`) and the only reading of "clear" that
/// an empty request can have.
pub(super) async fn sessions_clear(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let ids: Option<Vec<u64>> = read_json_body(req).await.ok().and_then(|v| {
        let list = v.get("ids")?.as_array()?;
        Some(list.iter().filter_map(|id| id.as_u64()).collect())
    });
    let Some(ids) = ids else {
        state.clear_sessions();
        tracing::info!("sessions cleared via UI");
        return json_ok();
    };
    // The frames go with the sessions they belong to, exactly as they do in
    // `clear_sessions` — a frame whose connection has been forgotten is
    // unreachable in the console and would only sit in the ring.
    {
        let mut q = state.sessions.lock().unwrap();
        q.retain(|s| !ids.contains(&s.id));
    }
    state
        .ws_frames
        .lock()
        .unwrap()
        .retain(|f| !ids.contains(&f.session));
    tracing::info!("{} sessions cleared via UI", ids.len());
    json_ok()
}

/// Delete the session history: memory and every persisted file.
pub(super) async fn sessions_purge(state: &Arc<AppState>) -> Response<DynBody> {
    let files = state.purge_sessions().await;
    tracing::info!("session history deleted via the console ({files} file(s))");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!(
            "{{\"ok\":true,\"files_deleted\":{files}}}"
        ))))
        .unwrap()
}
