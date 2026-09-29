//! What the console shows of a request: the [`Session`], its WebSocket frames,
//! which operators matched, and reading the client's request into a capture —
//! plus the timestamps sessions carry.

use super::*;

/// One operator a rule applied to a request, as recorded on its [`Session`].
///
/// This is the answer to "which rules matched?" — the question the console
/// exists to answer and the one it could not, because [`Resolved`] was consulted
/// for each decision and then dropped. What survived was the `log://` labels,
/// which the General tab showed under a heading people read as the matched
/// rules; a request whose `host://` rule never fired looked exactly like one
/// whose did.
///
/// Only the three fields that identify an operator are kept, not the whole
/// [`RuleOp`]: a session lives in a 500-deep ring, so what it holds is copied
/// 500 times over.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MatchedOp {
    /// Canonical protocol name (`host`, `resHeaders`, `redirect`, …) — the
    /// alias in the file has already been resolved to it.
    pub protocol: String,
    /// The value the operator resolved to. It is not always what was written:
    /// a `${name}` reference has been substituted by the time a request is
    /// recorded, which is exactly the difference worth seeing next to `raw`.
    pub value: String,
    /// The token as written on the line, shorthand and all.
    pub raw: String,
}

/// One captured request/response transaction.
#[derive(Clone, Default, serde::Serialize)]
pub struct Session {
    pub id: u64,
    /// Unix time in milliseconds when the request was received.
    pub time_ms: u128,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub client_ip: Option<String>,
    /// Where the request was sent (or "short-circuit").
    pub target: String,
    pub duration_ms: u128,
    /// `log://` channel labels attached to this request (whistle's log tags).
    ///
    /// Not "the rules that matched" — that is [`Session::rules`]. The two were
    /// conflated by the console for as long as only this one existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    /// Every operator that applied to this request, in resolution order — see
    /// [`matched_ops`]. Empty when no rule matched, which is the common case and
    /// costs nothing: an empty `Vec` allocates nothing and serializes to nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MatchedOp>,
    /// Request headers: the outgoing ones when the request was forwarded, and
    /// the client's own when it was answered here.
    ///
    /// The two are the same list seen from the two sides of a hop that a mocked
    /// request never makes — see [`capture_client_request`]. Which one a session
    /// holds follows from its `target`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub req_headers: Vec<(String, String)>,
    /// Response headers (as returned to the client).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub res_headers: Vec<(String, String)>,
    /// Request body preview (filled as the body streams), if captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_body: Option<Capture>,
    /// Response body preview (filled as the body streams), if captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_body: Option<Capture>,
    /// Where the time went, when the request left the proxy at all. A request a
    /// rule answered has no phases, and reports none rather than a row of zeros
    /// — see [`timing::Timings`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<timing::Timings>,
    /// Why the request did not complete, when it did not — see [`outcome`].
    /// Absent for every request that got its whole answer, including one whose
    /// origin answered `502`: that is the origin's answer, not a failure here.
    #[serde(skip_serializing_if = "outcome::Outcome::is_ok")]
    pub error: outcome::Outcome,
    /// Sent by the console's Composer or Replay rather than by a client — what
    /// the search box's `fc:` asks about, as upstream's `fc` flag does
    /// (`_original/lib/inspectors/data.js:159`). Read off the marker those two
    /// put on the request, and on the draft from then on, so a composition
    /// that fails is marked as one too.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub composer: bool,
    /// Operators in [`Session::rules`] that did not take effect, and why — see
    /// [`unapplied`]. Filled by the [`Ledger`] from what `serve` noted on the
    /// way, so a literal building a session leaves it empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unapplied: Vec<unapplied::Unapplied>,
}

/// Read a single header as an owned string, if present and valid UTF-8.
pub(super) fn header_str(
    headers: &hyper::HeaderMap,
    name: hyper::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Collect header name/value pairs for display.
pub(super) fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

/// True if a request carries a body worth capturing.
pub(super) fn has_request_body(headers: &hyper::HeaderMap) -> bool {
    headers.contains_key(hyper::header::CONTENT_LENGTH)
        || headers.contains_key(hyper::header::TRANSFER_ENCODING)
}

/// Capture what the client sent, on a path that answers without forwarding it.
///
/// A short-circuit (`file://`, `redirect://`, `statusCode://`, a template) and a
/// plugin-answered request never build an outgoing request, so the recording
/// sites there had nothing to put in `req_headers`/`req_body` and left both
/// empty. The console's Request Header and Request Body tabs were therefore
/// blank for **every mocked request** — and looking at what the client sent to
/// an endpoint you have just mocked is an ordinary thing to want to do. It is an
/// inspection gap in the primary tool, not merely a limit on replay.
///
/// The headers are the client's own rather than a forwarded request's, because
/// on these paths there is no forwarded request to report. Showing the
/// rule-rewritten headers instead would name a hop that never happened.
///
/// The body is read to its end and discarded, keeping only the bounded preview.
/// Nothing downstream is waiting for these bytes, but the preview is what the
/// console shows and the total is what the traffic column counts — and reading
/// it is what a keep-alive connection needs anyway before the next request on it
/// can be framed. Memory is the preview cap, not the upload: a 1 GB POST to a
/// mocked endpoint costs 16 KiB here, because [`Capture`] stops copying once the
/// preview is full.
pub(super) async fn capture_client_request(
    req: &mut Request<DynBody>,
    preview_cap: usize,
) -> (Vec<(String, String)>, Option<Capture>) {
    let headers = header_pairs(req.headers());
    if !has_request_body(req.headers()) {
        return (headers, None);
    }
    let capture = Capture::new(
        header_str(req.headers(), hyper::header::CONTENT_TYPE),
        header_str(req.headers(), hyper::header::CONTENT_ENCODING).as_deref(),
        preview_cap,
    );
    // Taken out rather than moved out of the request: the plugin path answers
    // from inside a loop over the matched plugins, where a move out of `req`
    // would be a move in a previous iteration.
    let body = std::mem::replace(req.body_mut(), body::empty());
    drain_into_capture(body, &capture).await;
    (headers, Some(capture))
}

/// Read `body` to its end, keeping only what `capture` has room for.
///
/// A client that hangs up mid-body ends the loop rather than failing the
/// request: the answer is already decided on these paths, and what arrived is
/// what there is to show.
pub(super) async fn drain_into_capture(mut body: DynBody, capture: &Capture) {
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    capture.append(data);
                }
            }
            Err(err) => {
                tracing::debug!("client body ended early: {err:#}");
                break;
            }
        }
    }
    capture.finish();
}

/// Convert a plugin-produced response into a real HTTP response, body and all.
///
/// The body stays a `Bytes` rather than becoming a stream because every response
/// operator and every plugin response hook still has to run over it — see
/// [`finish_local_response`].
pub(super) fn plugin_response(resp: crate::plugins::PluginResp) -> Response<Bytes> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    let body = Bytes::from(resp.body);
    builder.body(body.clone()).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .unwrap()
    })
}

/// One captured WebSocket frame, as surfaced in the Network view.
#[derive(Clone, serde::Serialize)]
pub struct WsFrame {
    /// Id of the [`Session`] this frame belongs to.
    pub session: u64,
    /// Unix time in milliseconds when the frame was seen.
    pub time_ms: u128,
    /// `"send"` (client→server) or `"receive"` (server→client).
    pub dir: &'static str,
    /// Frame type: `text`, `binary`, `close`, `ping`, `pong`, `continuation`.
    pub opcode: &'static str,
    /// Payload length in bytes.
    pub len: usize,
    /// A short preview: UTF-8 text (truncated) for text frames, else hex.
    pub preview: String,
    /// True when `enable://ignoreSend|ignoreReceive` discarded this frame: it
    /// was seen and recorded, but never delivered to the peer. Upstream marks
    /// the same thing (`ignore`, `_original/lib/socket-mgr.js:401,:531`) so the
    /// view shows a dropped frame rather than a gap.
    pub ignored: bool,
    /// True while `enable://pauseSend|pauseReceive` is holding this frame: it
    /// was seen and recorded, and is waiting for someone to release it from the
    /// console. Cleared when it goes out; a frame still marked when the
    /// connection ended never reached the peer at all.
    pub held: bool,
}

impl WsFrame {
    /// Build a frame record, deriving the opcode name and a bounded preview.
    /// A frame cut out of an ordinary **body** — an SSE event, or a piece of a
    /// stream a `x-whistle-custom-frame-separator` named.
    ///
    /// It is filed as a `text` frame, which is what it is: whistle shows these
    /// in the same Frames panel as a WebSocket's, and the direction is the only
    /// thing that tells them apart there (`emitFrame`,
    /// `_original/lib/inspectors/data.js:67-75`).
    /// A frame the **console** sent into a live connection.
    ///
    /// Recorded like any other, because it is one: it went out on the wire and
    /// the peer cannot tell it from traffic. The direction says which way.
    pub(crate) fn console_frame(session: u64, dir: &str, payload: &[u8]) -> Self {
        let dir = match dir {
            "send" => "send",
            _ => "receive",
        };
        WsFrame::new(session, dir, 0x1, payload)
    }

    pub(super) fn body_frame(session: u64, dir: &'static str, payload: &[u8]) -> Self {
        WsFrame::new(session, dir, 0x1, payload)
    }

    pub(super) fn new(session: u64, dir: &'static str, opcode: u8, payload: &[u8]) -> Self {
        let name = match opcode {
            0x0 => "continuation",
            0x1 => "text",
            0x2 => "binary",
            0x8 => "close",
            0x9 => "ping",
            0xa => "pong",
            _ => "unknown",
        };
        // Text/continuation → UTF-8 preview; everything else → hex.
        let preview = if opcode == 0x1 || opcode == 0x0 {
            match std::str::from_utf8(payload) {
                Ok(s) => truncate_preview(s),
                Err(_) => hex_preview(payload),
            }
        } else {
            hex_preview(payload)
        };
        WsFrame {
            session,
            time_ms: now_ms(),
            dir,
            opcode: name,
            len: payload.len(),
            preview,
            ignored: false,
            held: false,
        }
    }
}

/// Truncate a text preview to a sane length for the UI feed.
pub(super) fn truncate_preview(s: &str) -> String {
    const MAX: usize = 512;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let cut: String = s.chars().take(MAX).collect();
        format!("{cut}… (+{} bytes)", s.len() - cut.len())
    }
}

/// Hex-encode the first 64 bytes of a binary/control payload.
pub(super) fn hex_preview(payload: &[u8]) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(MAX * 2);
    for b in payload.iter().take(MAX) {
        out.push_str(&format!("{b:02x}"));
    }
    if payload.len() > MAX {
        out.push_str(&format!("… (+{} bytes)", payload.len() - MAX));
    }
    out
}

/// Collect `log://` channel labels for a resolved request.
pub(super) fn log_labels(resolved: &Resolved) -> Vec<String> {
    resolved
        .all("log")
        .iter()
        .map(|o| o.value.clone())
        .collect()
}

/// Collect every operator that applied to a request, in the order the rules file
/// would read them: important lines first, then source order — which is exactly
/// what [`crate::rules::order_key`] encodes and what decided each contest.
///
/// Called once per recorded session, at the point the session is built, so the
/// list is taken *after* the response phase has folded its operators in
/// ([`Resolved::merge_response_phase`]). Reading it earlier would report a
/// `resHeaders://` withheld by an `includeFilter://s:404` as never having
/// matched, on the requests where it did.
///
/// **A request no rule matched pays nothing.** The set is empty, the walk runs
/// zero times, and `Vec::new` does not allocate — so the common case is a couple
/// of `HashMap::is_empty`-shaped walks and a null pointer, not a heap allocation
/// holding nothing.
///
/// Ties are broken by protocol name so the list is stable between two identical
/// requests: the operators come out of a `HashMap`, whose iteration order is not.
/// Within one protocol the sort is stable, so several `reqHeaders://` written on
/// one line keep the order they were written in — which is the order in which
/// they are applied.
///
/// Only operators that **applied** are here, which is why the shared slot
/// contributes at most one: a `statusCode://` that lost to a `file://` did
/// nothing, and reporting it as a match would say the opposite.
pub(super) fn matched_ops(resolved: &Resolved) -> Vec<MatchedOp> {
    let mut ops: Vec<(u64, &crate::rules::RuleOp)> =
        resolved.ops().map(|op| (op.order, op)).collect();
    ops.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.protocol.cmp(&y.protocol)));
    ops.into_iter()
        .map(|(_, op)| MatchedOp {
            protocol: op.protocol.clone(),
            value: op.value.clone(),
            raw: op.raw.clone(),
        })
        .collect()
}

#[cfg(test)]
pub(super) mod client_capture_tests {
    use super::super::*;

    /// A request with a body, as the client sent it.
    fn posted(body: &'static [u8], content_type: &str) -> Request<DynBody> {
        Request::builder()
            .method("POST")
            .uri("http://example.com/api/items")
            .header("content-type", content_type)
            .header("content-length", body.len())
            .header("x-tenant", "acme")
            .body(body::full(Bytes::from_static(body)))
            .expect("a request")
    }

    /// The gap this closes: a mocked request recorded neither its headers nor
    /// its body, so the console's Request Header and Request Body tabs were
    /// blank for every request a rule answered locally.
    #[tokio::test]
    async fn a_request_answered_locally_still_records_what_the_client_sent() {
        let mut req = posted(br#"{"name":"third"}"#, "application/json");
        let (headers, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;

        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "x-tenant")
                .map(|(_, v)| v.as_str()),
            Some("acme"),
        );
        let (len, truncated, text) = body.expect("a captured body").snapshot();
        assert_eq!(
            (len, truncated, text.as_str()),
            (16, false, r#"{"name":"third"}"#)
        );
    }

    /// Memory is the preview cap, not the upload. A large POST to a mocked
    /// endpoint must not be held whole just to be shown.
    #[tokio::test]
    async fn a_large_upload_costs_the_preview_not_the_body() {
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header("content-type", "text/plain")
            .header("content-length", 200_000)
            .body(body::full(Bytes::from(vec![b'x'; 200_000])))
            .expect("a request");
        let (_, body) = capture_client_request(&mut req, 4096).await;

        let capture = body.expect("a captured body");
        let (len, truncated, text) = capture.snapshot();
        // The total is honest — it is what the traffic column counts — while
        // only the preview was kept.
        assert_eq!(len, 200_000);
        assert!(truncated);
        assert_eq!(text.len(), 4096);
    }

    /// A `GET` has no body to capture, and must not be given an empty one: an
    /// empty capture reads as "there was a body and it was empty".
    #[tokio::test]
    async fn a_request_without_a_body_captures_only_its_headers() {
        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("accept", "*/*")
            .body(body::empty())
            .expect("a request");
        let (headers, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        assert!(body.is_none());
        assert_eq!(headers.len(), 1);
    }

    /// The body is taken out of the request, not left to be sent twice. The
    /// plugin path answers from inside a loop and goes on to use `req`.
    #[tokio::test]
    async fn capturing_leaves_the_request_without_its_body() {
        let mut req = posted(b"payload", "text/plain");
        let _ = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        let left = collect_body(std::mem::replace(req.body_mut(), body::empty()))
            .await
            .expect("an empty body");
        assert!(left.is_empty());
    }

    /// A compressed upload is previewed decoded, the same as on the forwarded
    /// path — the tab shows what was sent, not the deflate stream.
    #[tokio::test]
    async fn a_compressed_upload_is_previewed_decoded() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"upload me").expect("gzip");
        let gz = e.finish().expect("gzip");
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .header("content-type", "text/plain")
            .header("content-encoding", "gzip")
            .header("content-length", gz.len())
            .body(body::full(Bytes::from(gz)))
            .expect("a request");
        let (_, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        assert_eq!(body.expect("a captured body").snapshot().2, "upload me");
    }
}

#[cfg(test)]
pub(super) mod matched_ops_tests {
    use super::super::*;

    /// Resolve `text` against `GET http://example.com/api` and record what
    /// matched, the way a session does.
    fn matched(text: &str) -> Vec<MatchedOp> {
        let mut m = RuleManager::new();
        m.set_text(text);
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/api",
            &hyper::HeaderMap::new(),
            None,
        );
        matched_ops(&m.resolve(&info))
    }

    /// The list a session carries has to be readable as the rules file: the
    /// important line first, then source order. Anything else and the console
    /// would show a *set* of operators, leaving "which one won" — the question
    /// two lines setting `host://` are asked about — unanswerable.
    #[test]
    fn the_operators_come_out_in_the_order_that_decided_them() {
        let ops = matched(concat!(
            "example.com reqHeaders://x-a=1\n",
            "example.com resHeaders://x-b=2\n",
            "example.com reqHeaders://x-c=3 lineProps://important\n",
        ));
        let seen: Vec<(&str, &str)> = ops
            .iter()
            .map(|o| (o.protocol.as_str(), o.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                // `$` marks the line important, so it resolves first.
                ("reqHeaders", "x-c=3"),
                ("reqHeaders", "x-a=1"),
                ("resHeaders", "x-b=2"),
            ]
        );
    }

    /// Two `reqHeaders://` on one line share an order key, and the order they
    /// are *applied* in is the order they were written in. A sort that lost it
    /// would show the losing header on top for a line that sets the same name
    /// twice.
    #[test]
    fn operators_sharing_a_line_keep_the_order_they_were_written_in() {
        let ops = matched("example.com reqHeaders://x-a=1 reqHeaders://x-a=2\n");
        let seen: Vec<&str> = ops.iter().map(|o| o.value.as_str()).collect();
        assert_eq!(seen, ["x-a=1", "x-a=2"]);
    }

    /// The token as written is kept beside what it resolved to, because they
    /// are not the same thing: a shorthand names a protocol it does not spell,
    /// and `example.com 1.2.3.4` is the form most likely to be doubted.
    #[test]
    fn a_shorthand_is_reported_under_the_protocol_it_means() {
        let ops = matched("example.com 1.2.3.4\n");
        assert_eq!(
            ops,
            [MatchedOp {
                protocol: "host".into(),
                value: "1.2.3.4".into(),
                raw: "1.2.3.4".into(),
            }]
        );
    }

    /// The hot path: a request no rule matched records an empty list, and an
    /// empty `Vec` neither allocates nor serializes. This is the majority of
    /// traffic through a proxy whose rules file names one host.
    #[test]
    fn a_request_no_rule_matched_carries_nothing() {
        let ops = matched("other.example.net host://1.2.3.4\n");
        assert!(ops.is_empty());
        assert_eq!(ops.capacity(), 0, "an empty list must not have allocated");
        let session = Session {
            rules: ops,
            ..Default::default()
        };
        let json = serde_json::to_value(&session).expect("a session serializes");
        assert!(json.get("rules").is_none(), "{json}");
    }

    /// Which rules matched is the thing the detail view is for, so it has to
    /// survive the trip through `/session.json`.
    #[test]
    fn the_operators_reach_the_console() {
        let session = Session {
            rules: matched("example.com http://localhost:5173 log://api\n"),
            ..Default::default()
        };
        let json = serde_json::to_value(&session).expect("a session serializes");
        let rules = json["rules"].as_array().expect("an array");
        assert!(
            rules
                .iter()
                .any(|r| r["protocol"] == "log" && r["value"] == "api"),
            "{json}"
        );
        // …and the pair of fields earns its keep on the forwarding shorthand:
        // `raw` is the token as typed, `value` is where the request was
        // actually sent — path and all. Reporting only one of them would leave
        // "why did /api go there" a question the console cannot answer.
        let replace = rules
            .iter()
            .find(|r| r["raw"] == "http://localhost:5173")
            .expect("the forwarding operator");
        assert_eq!(replace["value"], "http://localhost:5173/api");
    }
}

/// Milliseconds since the Unix epoch (best-effort).
pub(super) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Format Unix-epoch milliseconds as an ISO-8601 UTC timestamp (for HAR export).
/// Uses Howard Hinnant's civil-from-days algorithm; no external date crate.
pub(crate) fn iso8601_utc(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 → civil (year, month, day)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}
