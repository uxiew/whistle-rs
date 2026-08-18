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

/// Route a direct (non-proxied) request to the UI / API.
pub async fn handle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let path = req.uri().path().to_string();
    // `-M headless`: no console. The root certificate and the PAC file answer
    // anyway — a client that cannot fetch them cannot be configured to use the
    // proxy at all, and upstream keeps its own two open under `headless` for the
    // same reason (measured: `/cgi-bin/rootca` and `/cgi-bin/status` answer, the
    // rest is 404).
    if !state.config.console && !open_without_login(&path) && !ALIVE_WHEN_HEADLESS.contains(&path.as_str())
    {
        return not_found();
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
    match (req.method().as_str(), path.as_str()) {
        (_, "/rootCA.crt") | (_, "/rootca.crt") => root_ca(state),
        (_, "/proxy.pac") | (_, "/pac") => pac(state, &req),
        (_, "/sessions.json") => sessions_json(state),
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
        ("GET", "/api/ws/status") => ws_status(state, &req),
        ("POST", "/api/ws/release") => ws_release(state, req).await,
        ("POST", "/api/ws/send") => ws_send(state, req).await,
        // Takes a body now: the console can forget just the rows it selected.
        ("POST", "/api/sessions/clear") => sessions_clear(state, req).await,
        ("GET", "/api/status") => status_json(state).await,
        ("GET", "/plugin") => redirect_to("/plugin/"),
        ("GET", "/") | ("GET", "/index.html") => html_ok(index_html(state)),
        _ => not_found(),
    }
}

/// The hostnames that **are** the console rather than somewhere to forward to.
///
/// whistle's `LOCAL_UI_HOST_LIST` (`_original/lib/config.js:38-42`). A browser
/// pointed at the proxy and sent to `http://local.whistlejs.com/` gets the
/// console, which is what `w2 status` tells people to do — and what this port
/// used to answer with a `502`, because the name resolves to `127.0.0.1` and
/// there is nothing on port 80 there.
///
/// **`rootca.pro` is not the console**: it serves the root certificate, at
/// every path. That is the phone workflow — set the proxy, open `rootca.pro`,
/// install what it hands you — and it is why the name exists.
pub(super) const BUILTIN_UI_HOSTS: [&str; 2] = ["local.whistlejs.com", "local.wproxy.org"];

/// The one that hands out the certificate instead.
pub(super) const ROOT_CA_HOST: &str = "rootca.pro";

/// Whether a **proxied** request for this host is the console's to answer.
///
/// Measured against whistle 2.10.8 rather than read: this beats the rules. With
/// `local.whistlejs.com http://127.0.0.1:19902` installed and matching, upstream
/// still serves the console — so the question is asked before a rule is
/// resolved, and it is asked here for the same reason.
pub(super) fn console_host(state: &Arc<AppState>, host: &str) -> bool {
    // `-M pureProxy` puts these names back to being ordinary ones to forward,
    // which is upstream's own `if (config.pureProxy) return false` inside
    // `isWebUIHost` (`_original/lib/config.js:1068-1073`).
    //
    // `-M headless` deliberately does **not** stop the routing: upstream still
    // sends the name to the console and lets the console answer `404`, so the
    // name says "there is a console here and it is off" rather than "no such
    // host". Measured — under `headless` upstream's console hostname is a 404
    // and `rootca.pro` still hands out the certificate.
    if !state.config.console_hostnames {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    BUILTIN_UI_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h))
        || host.eq_ignore_ascii_case(ROOT_CA_HOST)
        || state
            .config
            .local_ui_hosts
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
}

/// Answer a proxied request that named one of those hostnames.
///
/// `rootca.pro` answers with the certificate whatever the path is — measured:
/// `/`, `/anything` and `/cgi-bin/rules/list` all return it. Everything else
/// goes to the ordinary console router, so the API, the login and `/-/` behave
/// exactly as they do on the proxy's own port.
pub(super) async fn handle_proxied(
    state: &Arc<AppState>,
    mut req: Request<Incoming>,
    host: &str,
) -> Response<DynBody> {
    if host.eq_ignore_ascii_case(ROOT_CA_HOST) {
        return root_ca(state);
    }
    // Origin-form, so the router sees the path it would have seen anyway.
    let rest = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if let Ok(uri) = rest.parse::<hyper::Uri>() {
        *req.uri_mut() = uri;
    }
    handle(state, req).await
}

/// Paths that answer before the login does.
///
/// A device that cannot reach the root certificate cannot trust the proxy, and
/// a client that cannot read the PAC file cannot use it — so both stay open,
/// which is upstream's arrangement too (`/cgi-bin/rootca` is in its
/// `DONT_CHECK_PATHS`, `_original/biz/webui/lib/index.js:39-40`).
/// What still answers when `-M headless` has turned the console off.
///
/// The status endpoint, because a console that is off is not a proxy that is
/// gone and something has to be able to say the difference. Upstream keeps
/// `/cgi-bin/status` answering under `headless` for the same reason — measured,
/// along with `/cgi-bin/rootca`, while everything else is a 404.
///
/// Deliberately **not** the same list as [`open_without_login`]: "the console is
/// switched off" and "you have not logged in" are different questions, and the
/// certificate is on both lists for its own reason.
const ALIVE_WHEN_HEADLESS: [&str; 1] = ["/api/status"];

fn open_without_login(path: &str) -> bool {
    matches!(path, "/rootCA.crt" | "/rootca.crt" | "/proxy.pac" | "/pac")
}

/// `None` when the request may proceed; the 401 to send when it may not.
///
/// whistle's model, minus its cookie. `-n`/`-w` name the account that may do
/// anything; `-N`/`-W` name one that may only **read**, which upstream spells
/// as "the guest login passes, and then the method has to be `GET`"
/// (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`). Credentials come from
/// `Authorization`, from `Proxy-Authorization` — a browser pointed at a proxy
/// port may send either — or from an `authorization` query parameter, all three
/// of which upstream reads (`verifyLogin`, `:171-173`).
///
/// **Narrowed on purpose:** upstream also sets a login cookie keyed on the
/// client's IP so the prompt appears once. Here every request carries its own
/// credentials, which a browser does by itself after the first prompt, and
/// nothing has to be stored.
fn login_required<B>(
    state: &Arc<AppState>,
    req: &Request<B>,
    path: &str,
) -> Option<Response<DynBody>> {
    let config = &state.config;
    let account = (config.ui_username.as_deref(), config.ui_password.as_deref());
    if account == (None, None) {
        return None;
    }
    if open_without_login(path) {
        return None;
    }
    let offered = offered_credentials(req);
    let matches = |name: Option<&str>, pass: Option<&str>| {
        offered
            .iter()
            .any(|(u, p)| u.as_str() == name.unwrap_or("") && p.as_str() == pass.unwrap_or(""))
    };
    if matches(account.0, account.1) {
        return None;
    }
    let guest = (
        config.guest_username.as_deref(),
        config.guest_password.as_deref(),
    );
    if guest != (None, None) && matches(guest.0, guest.1) && req.method() == hyper::Method::GET {
        return None;
    }
    let mut resp = Response::builder()
        .status(hyper::StatusCode::UNAUTHORIZED)
        .body(crate::proxy::body::full(bytes::Bytes::from_static(
            b"Access denied",
        )))
        .expect("static response");
    resp.headers_mut().insert(
        hyper::header::WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Basic realm=User Login"),
    );
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Some(resp)
}

/// Every username and password this request offers.
///
/// **Two candidates, not one.** Upstream reads a header *and* a query parameter
/// and lets either satisfy the login — `equalAuth(headerAuth, auth) ||
/// equalAuth(queryAuth, auth)` (`verifyLogin`,
/// `_original/biz/webui/lib/index.js:171-177`). This used to take the first
/// source that carried anything, which meant a browser holding a stale
/// `Authorization` from an earlier password masked the `?authorization=…` the
/// user had just pasted into the address bar, and no reload could get past it.
///
/// The header slot is itself one candidate: `Authorization` when it is there and
/// `Proxy-Authorization` only when it is not, which is upstream's `||` and not a
/// third try.
fn offered_credentials<B>(req: &Request<B>) -> Vec<(String, String)> {
    let from_header = |name: hyper::header::HeaderName| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let from_query = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "authorization")
            .map(|(_, v)| percent_decode(v))
    });
    let header = from_header(hyper::header::AUTHORIZATION)
        .or_else(|| from_header(hyper::header::PROXY_AUTHORIZATION));
    [header, from_query]
        .into_iter()
        .flatten()
        .filter_map(|raw| parse_basic(&raw))
        .collect()
}

/// One `Basic` credential, read the way upstream's `parseAuth` reads it.
fn parse_basic(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    // `Basic ` comes off when it is there, and **the whole value is decoded when
    // it is not** — `parseAuth` is `AUTH_RE.test(auth) ? auth.substring(6) : auth`
    // (`_original/lib/util/common.js:911-928`). The scheme-less spelling is not
    // idiomatic in a header, but the same function reads the `?authorization=`
    // parameter, where writing `Basic%20…` into a URL is the awkward one.
    // `auth-bench.js` measures all three places.
    let encoded = raw
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map_or(raw, |(_, rest)| rest);
    // Padding optional: `Buffer.from(s, 'base64')` accepts a value whose `=` was
    // trimmed, and a client that trims it is offering the right credentials.
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let decoded = base64::Engine::decode(&engine, encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // The **first** colon splits, so a password may contain one; with no colon
    // the whole value is the name and the password is empty, which is upstream's
    // `indexOf(':') === -1` branch and the only way an empty `-w` is satisfied.
    let (user, pass) = text.split_once(':').unwrap_or((text.as_str(), ""));
    Some((user.to_string(), pass.to_string()))
}

/// `%xx` decoding for the query-parameter spelling.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
                    "has_frames": s.status == 101 || framed.contains(&s.id),
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

/// A captured body as a HAR field carries it: `(size, text, base64)`.
///
/// A body that is not text goes out **base64-encoded**, which is what HAR 1.2
/// defines `content.encoding` for. Until this did that, a binary body was
/// exported as the console's own `[binary, N bytes]` marker, written into the
/// `text` field where every tool that reads a HAR would take it for the body —
/// a sentence delivered as if it were an image.
///
/// The same key is used on `postData`, which HAR 1.2 does not define it for. It
/// is the least surprising extension available: a reader that ignores it still
/// receives the body, recoverable, rather than a sentence that never was one.
fn har_body(cap: Option<&Capture>) -> (usize, String, bool) {
    let Some(cap) = cap else {
        return (0, String::new(), false);
    };
    let (len, _, text) = cap.snapshot();
    if !cap.is_binary() {
        return (len, text, false);
    }
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        cap.preview_bytes().bytes,
    );
    (len, encoded, true)
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

    let (req_len, req_text, req_b64) = har_body(s.req_body.as_ref());
    let (res_len, res_text, res_b64) = har_body(s.res_body.as_ref());
    let post_data = if req_len > 0 {
        serde_json::json!({
            "mimeType": mime_of(&s.req_headers),
            "text": req_text,
            "encoding": encoding(req_b64),
        })
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
                "encoding": encoding(res_b64),
            },
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
    })
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

/// One query parameter, undecoded. Every caller here reads digits, a side name
/// or a comma-separated id list, none of which percent-encoding reaches.
fn query_param(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
            .map(|v| v.to_string())
    })
}

/// A `?name=1,2,3` session-id list. `None` when the parameter is absent, which
/// every caller reads as "all of them" — an *empty* list is a selection of
/// nothing and stays distinct from it.
fn id_list(req: &Request<Incoming>, name: &str) -> Option<Vec<u64>> {
    query_param(req, name)
        .map(|v| v.split(',').filter_map(|id| id.trim().parse().ok()).collect())
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
fn session_body_bytes(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
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
fn body_filename(sess: &Session, side: &str, truncated: bool) -> String {
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
fn frames_json(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
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
fn json_value(body: &serde_json::Value) -> Response<DynBody> {
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
fn ws_status(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
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
async fn ws_release(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return r,
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
async fn ws_send(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return r,
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
    state.record_frame(crate::proxy::WsFrame::console_frame(id, dir, data.as_bytes()));
    tracing::info!("console sent {} bytes into session {id} ({dir})", data.len());
    json_value(&serde_json::json!({ "ok": true, "sent": data.len() }))
}

/// The `?id=<n>` a per-session endpoint takes.
fn query_id(req: &Request<Incoming>) -> Option<u64> {
    req.uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("id=")))
        .and_then(|v| v.parse().ok())
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
    fetch_new_includes(state);
    tracing::info!("rules updated via UI: {count} rules");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!("{{\"ok\":true,\"rules\":{count}}}"))))
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
    for g in bundle.get("rules").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        let Some(name) = g.get("name").and_then(|v| v.as_str()).map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let text = g.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let enabled = g.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let was = mgr.groups().iter().find(|x| x.name == name).map(|x| x.enabled);
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
            let Some(value) = value.as_str() else { continue };
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
        Err(r) => return r,
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
        fetch_new_includes(state);
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
        fetch_new_includes(state);
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

/// Forget captured sessions: all of them, or only the `{"ids":[…]}` the request
/// table's selection names.
///
/// A body that names no ids clears everything, which is both what the console
/// sent before multi-select existed (`{}`) and the only reading of "clear" that
/// an empty request can have.
async fn sessions_clear(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
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
    let name = payload.get(key).and_then(|v| v.as_str()).unwrap_or("").trim();
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
        Err(r) => return r,
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
        Err(r) => return r,
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
        Err(r) => return r,
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
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return refused("could not read body"),
    };
    let mut query: crate::explain::Query = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return refused(&format!("invalid JSON: {e}")),
    };
    if query.values.is_empty() {
        query.values = state.values.read().unwrap().clone();
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
            mgr.groups().iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
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
        assert_eq!(rename_value(&mut values, "mock.json", "fixture.json"), Ok(()));
        assert_eq!(values.get("fixture.json").map(String::as_str), Some("{\"ok\":true}"));
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
            res_body: Some(Capture::from_bytes(&raw, Some("image/png".into()), None, 64)),
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

    /// A session with no bodies still exports, with the fields a HAR requires
    /// and nothing invented behind them.
    #[test]
    fn a_session_without_bodies_exports_empty_ones() {
        let entry = har_entry(&session("https://example.com/", 1));
        assert!(entry["request"]["postData"].is_null());
        assert_eq!(entry["response"]["content"]["size"], 0);
        assert_eq!(entry["response"]["content"]["text"], "");
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
mod login_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn state(users: (Option<&str>, Option<&str>, Option<&str>, Option<&str>)) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = crate::config::Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-login-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ui_username: users.0.map(str::to_string),
            ui_password: users.1.map(str::to_string),
            guest_username: users.2.map(str::to_string),
            guest_password: users.3.map(str::to_string),
            ..crate::config::Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, crate::rules::RuleManager::new(), ca))
    }

    fn basic(user: &str, pass: &str) -> String {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    /// Build a request with an optional `Authorization` header.
    fn req(method: &str, path: &str, auth: Option<&str>) -> Request<()> {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(hyper::header::AUTHORIZATION, a);
        }
        b.body(()).expect("request")
    }

    /// Allowed if `login_required` says nothing.
    fn allowed(state: &Arc<AppState>, method: &str, path: &str, auth: Option<&str>) -> bool {
        let r = req(method, path, auth);
        let p = r.uri().path().to_string();
        login_required(state, &r, &p).is_none()
    }

    /// With no account configured the console is open — upstream's own first
    /// test, `if (!username && !password) return true`
    /// (`_original/biz/webui/lib/index.js:161-163`).
    #[test]
    fn no_account_means_no_login() {
        let s = state((None, None, None, None));
        assert!(allowed(&s, "GET", "/", None));
        assert!(allowed(&s, "POST", "/api/rules", None));
    }

    /// The full account may do anything; a wrong password may do nothing.
    #[test]
    fn the_account_opens_everything_and_a_wrong_one_opens_nothing() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(&s, "GET", "/", None));
        assert!(!allowed(&s, "GET", "/", Some(&basic("admin", "wrong"))));
        assert!(!allowed(&s, "GET", "/", Some(&basic("root", "s3cret"))));
        assert!(allowed(&s, "GET", "/", Some(&basic("admin", "s3cret"))));
        assert!(allowed(&s, "POST", "/api/rules", Some(&basic("admin", "s3cret"))));
        // A password may contain a colon: only the first one splits.
        let s2 = state((Some("admin"), Some("a:b"), None, None));
        assert!(allowed(&s2, "GET", "/", Some(&basic("admin", "a:b"))));
    }

    /// The guest may read and may not write — upstream gates it on the method
    /// being `GET` (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`).
    #[test]
    fn the_guest_account_may_only_read() {
        let s = state((Some("admin"), Some("s3cret"), Some("guest"), Some("look")));
        let guest = basic("guest", "look");
        assert!(allowed(&s, "GET", "/sessions.json", Some(&guest)));
        assert!(!allowed(&s, "POST", "/api/rules", Some(&guest)));
        assert!(!allowed(&s, "DELETE", "/api/value", Some(&guest)));
        // And a guest that is not configured is nobody.
        let s2 = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(&s2, "GET", "/sessions.json", Some(&guest)));
    }

    /// The three hostnames that open the console through the proxy, and the
    /// one that hands out the certificate instead.
    ///
    /// Measured against whistle 2.10.8: `local.whistlejs.com` and
    /// `local.wproxy.org` serve the console at every path, API included, and
    /// `rootca.pro` serves the root certificate at every path — `/`,
    /// `/anything` and `/cgi-bin/rules/list` all return it.
    #[test]
    fn the_console_hostnames_are_the_console() {
        let s = state((None, None, None, None));
        for host in ["local.whistlejs.com", "local.wproxy.org", "rootca.pro"] {
            assert!(console_host(&s, host), "{host}");
            // Case is not part of a hostname.
            assert!(console_host(&s, &host.to_ascii_uppercase()), "{host} upper");
        }
        assert!(!console_host(&s, "www.example.com"));
        assert!(!console_host(&s, "local.whistlejs.com.evil.test"));
        assert!(!console_host(&s, "notlocal.whistlejs.com"));
    }

    /// `-l/--localUIHost` **adds to** the built-in list rather than replacing
    /// it, which is what upstream does with it.
    #[test]
    fn extra_console_hostnames_are_added_not_substituted() {
        let mut config = crate::config::Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-uihost-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )),
            persist_sessions: false,
            local_ui_hosts: vec!["my.console.test".into(), "other.test".into()],
            ..crate::config::Config::default()
        };
        config.intercept_https = false;
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        let s = Arc::new(AppState::new(config, crate::rules::RuleManager::new(), ca));
        assert!(console_host(&s, "my.console.test"));
        assert!(console_host(&s, "other.test"));
        assert!(console_host(&s, "local.whistlejs.com"), "the built-ins survive");
        assert!(!console_host(&s, "somewhere.else.test"));
    }

    /// The certificate and the PAC file answer before the login does: a device
    /// that cannot fetch them cannot be configured to use the proxy at all.
    #[test]
    fn the_certificate_and_the_pac_stay_open() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        assert!(allowed(&s, "GET", "/rootCA.crt", None));
        assert!(allowed(&s, "GET", "/proxy.pac", None));
        assert!(!allowed(&s, "GET", "/sessions.json", None));
    }

    /// The three places credentials may travel — `Proxy-Authorization` because
    /// a browser pointed at a proxy port may send that one instead, and the
    /// query parameter because upstream reads it (`verifyLogin`, `:171-173`).
    #[test]
    fn credentials_travel_three_ways() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        let creds = basic("admin", "s3cret");
        let proxy_auth = Request::builder()
            .method("GET")
            .uri("/")
            .header(hyper::header::PROXY_AUTHORIZATION, &creds)
            .body(())
            .expect("request");
        assert!(login_required(&s, &proxy_auth, "/").is_none());
        let query = Request::builder()
            .method("GET")
            .uri(format!("/sessions.json?authorization={}", creds.replace(' ', "%20")))
            .body(())
            .expect("request");
        assert!(login_required(&s, &query, "/sessions.json").is_none());
        // A lower-case scheme is still Basic.
        assert!(allowed(&s, "GET", "/", Some(&creds.replace("Basic", "basic"))));
    }

    /// A header and a query parameter are **two candidates**, and either one
    /// satisfies the login on its own: upstream's `equalAuth(headerAuth, auth)
    /// || equalAuth(queryAuth, auth)` (`verifyLogin`, `:171-177`).
    ///
    /// Taking the first source that carried anything — which this did — meant a
    /// browser still holding an `Authorization` from an old password masked the
    /// `?authorization=…` in the address bar, and no reload could get past it.
    /// `auth-bench.js` is where the difference was measured.
    #[test]
    fn a_wrong_header_does_not_mask_a_right_query_parameter() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        let right = basic("admin", "s3cret").replace(' ', "%20");
        let with = |header: &str| {
            let r = Request::builder()
                .method("GET")
                .uri(format!("/sessions.json?authorization={right}"))
                .header(hyper::header::AUTHORIZATION, header)
                .body(())
                .expect("request");
            login_required(&s, &r, "/sessions.json").is_none()
        };
        assert!(with(&basic("admin", "wrong")));
        assert!(with(&basic("root", "s3cret")));
        assert!(with("Bearer nonsense"));
        // And the other way round: a right header beside a wrong parameter.
        let r = Request::builder()
            .method("GET")
            .uri(format!("/sessions.json?authorization={}", basic("admin", "wrong").replace(' ', "%20")))
            .header(hyper::header::AUTHORIZATION, basic("admin", "s3cret"))
            .body(())
            .expect("request");
        assert!(login_required(&s, &r, "/sessions.json").is_none());
    }

    /// `parseAuth` strips `Basic ` only when it is there and base64-decodes the
    /// whole value when it is not (`_original/lib/util/common.js:911-928`), and
    /// `Buffer.from(s, 'base64')` does not insist on the padding. The
    /// scheme-less spelling is the natural one in a URL, which is the other
    /// place the same function reads.
    #[test]
    fn a_credential_needs_neither_its_scheme_nor_its_padding() {
        use base64::Engine;
        let s = state((Some("admin"), Some("look"), None, None));
        let raw = base64::engine::general_purpose::STANDARD.encode("admin:look");
        assert!(raw.ends_with('='), "the fixture has to carry padding to prove anything");
        assert!(allowed(&s, "GET", "/", Some(&raw)));
        assert!(allowed(&s, "GET", "/", Some(raw.trim_end_matches('='))));
        assert!(allowed(&s, "GET", "/", Some(&format!("Basic {}", raw.trim_end_matches('=')))));
        // Still no: the wrong credentials are wrong however they are spelled.
        let wrong = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        assert!(!allowed(&s, "GET", "/", Some(&wrong)));
        // A scheme that is not Basic is not stripped, so what is decoded is the
        // whole value — which is not a credential, and does not become one.
        assert!(!allowed(&s, "GET", "/", Some(&format!("Bearer {raw}"))));
    }

    /// No colon at all: the whole value is the name and the password is empty,
    /// upstream's `indexOf(':') === -1` branch. It is the only way an account
    /// configured with an empty password can be satisfied.
    #[test]
    fn a_value_with_no_colon_is_a_name_and_an_empty_password() {
        use base64::Engine;
        let name_only = base64::engine::general_purpose::STANDARD.encode("admin");
        let s = state((Some("admin"), None, None, None));
        assert!(allowed(&s, "GET", "/", Some(&format!("Basic {name_only}"))));
        // And it does not open an account that has a password.
        let s2 = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(&s2, "GET", "/", Some(&format!("Basic {name_only}"))));
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
