//! HAR 1.2 export of the captured sessions: bodies as text or base64, the
//! marks on a body that was cut short, the timings, and which origin
//! connection each request shared.

use super::*;

/// A captured body as a HAR field carries it.
#[derive(Default)]
pub(super) struct HarBody {
    /// The whole body's (wire) size, which the kept part may fall short of.
    pub(super) size: usize,
    pub(super) text: String,
    /// `text` is the kept bytes, base64-encoded.
    pub(super) base64: bool,
    /// Why `text` is not the whole body, when it is not — for HAR's own
    /// `comment` field, which is the one a viewer shows.
    pub(super) short: Option<String>,
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
pub(super) fn har_body(cap: Option<&Capture>) -> HarBody {
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
pub(super) fn har_mark_short(field: &mut serde_json::Value, body: &HarBody) {
    if let (Some(why), Some(obj)) = (&body.short, field.as_object_mut()) {
        obj.insert("comment".into(), serde_json::json!(why));
        obj.insert("_truncated".into(), serde_json::json!(true));
    }
}

/// One HAR 1.2 entry for one session. Separate from [`sessions_har`] so the
/// shape can be asserted on without a proxy behind it.
pub(super) fn har_entry(s: &Session) -> serde_json::Value {
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
        "startedDateTime": super::super::iso8601_utc(s.time_ms),
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
pub(super) fn sessions_har(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
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

#[cfg(test)]
pub(super) mod body_tests {
    use super::super::*;
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
