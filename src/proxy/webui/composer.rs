//! Requests the console sends: replaying a captured session, the Composer, and
//! Test Rules — which rules a request would hit, without sending it. A replay
//! or a composed request goes back through this proxy, so the rules apply to it
//! as to any other.

use super::*;

/// Replay a captured session by re-sending it through the proxy's own port.
/// Accepts `{ "id": N }` or `{ "ids": [N, M, ...] }` (batch, max 100).
///
/// The batch form has no caller: the console's request table is single-select,
/// so `store.ts` only ever posts `{ "id": N }`. It is kept because it costs
/// nothing and because multi-select is the obvious next thing the table grows —
/// but it is untested by use, and the answer's `sessions` array is per-id
/// precisely so a batch could report which of its members lost their bodies.
pub(super) async fn replay_session(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
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
pub(super) fn replay_body_of(sess: &Session) -> ReplayBody {
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
pub(super) fn replay_request(sess: &Session, body: &ReplayBody) -> hyper::Request<body::DynBody> {
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
    builder = builder.header(super::super::COMPOSER_REQ_HEADER, "1");
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
pub(super) const DROPPED_HEADERS: [&str; 3] =
    ["content-length", "transfer-encoding", "content-encoding"];

/// True when `name` is one of [`DROPPED_HEADERS`].
pub(super) fn is_dropped_header(name: &str) -> bool {
    DROPPED_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Send a captured session's request through the proxy's own port so it flows
/// through the full rule-matching + forwarding pipeline again.
pub(super) async fn do_replay(
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
pub(super) async fn send_through_self(
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
pub(super) struct Composed {
    #[serde(default)]
    pub(super) method: String,
    #[serde(default)]
    pub(super) url: String,
    #[serde(default)]
    pub(super) headers: String,
    #[serde(default)]
    pub(super) body: String,
}

/// Send a request composed in the console's Composer through our own port.
///
/// Takes `{ "method", "url", "headers", "body" }` and answers
/// `{ "ok": true, "url": …, "sent": … }` — the URL as it was actually resolved,
/// so the console can show that a scheme was filled in, and the body length that
/// went out. Like Replay it is fire-and-forget: the transaction lands in the
/// session list a moment later, which is where the console reads its result.
pub(super) async fn compose_request(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
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
pub(super) async fn explain_rules(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
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
pub(super) fn refused(error: &str) -> Response<DynBody> {
    api_error(StatusCode::BAD_REQUEST, error)
}

/// Build what a composition puts on the wire, or say why it cannot.
///
/// Separate from [`compose_request`] so that what is sent can be asserted on
/// without a socket — as with [`replay_request`], see the tests.
pub(super) fn composed_request(c: &Composed) -> Result<hyper::Request<DynBody>, String> {
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
        hyper::header::HeaderName::from_static(super::super::COMPOSER_REQ_HEADER),
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

#[cfg(test)]
pub(super) mod replay_tests {
    use super::super::*;
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
            header(&headers, super::super::super::COMPOSER_REQ_HEADER),
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
pub(super) mod composer_tests {
    use super::super::*;
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
            header(&headers, super::super::super::COMPOSER_REQ_HEADER),
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
