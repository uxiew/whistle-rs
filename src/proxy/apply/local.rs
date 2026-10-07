//! Answers made here instead of by the origin: `redirect`/`location`,
//! `locationHref`, a mocked `statusCode`, and the local-file family — `file`,
//! `xfile`, `rawfile`, `tpl` and the rest — with their byte ranges, their raw
//! HTTP form, and the CORS headers a cross-origin page gets without asking.

use super::*;

/// Short-circuit responses produced without contacting upstream:
/// `redirect`/`location`, mocked `statusCode`, and the local-file family.
///
/// Only the operator that won the shared slot may answer, and
/// [`Resolved::slot`](crate::rules::Resolved::slot) holds exactly that one —
/// see [`crate::rules::protocols::SLOT_PROTOCOLS`].
pub fn short_circuit(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
) -> Option<Response<DynBody>> {
    let mut resp = short_circuit_inner(info, resolved, env, remote)?;
    mark_self_generated(resp.headers_mut());
    Some(resp)
}

/// The header whistle puts on every response it makes itself — `x-server`, set
/// from `config.appName` by `wrapResponse` (`_original/lib/util/index.js:1080-1090`).
///
/// It answers the question a mocked response otherwise leaves open: did this
/// come from the origin or from the proxy? Worth having for the same reason
/// upstream has it, and worth spelling honestly: this is not whistle, so it does
/// not say `Whistle`. A tool keying off the exact upstream value will not see
/// it, which is the correct outcome — it is not talking to whistle.
pub(crate) fn mark_self_generated(headers: &mut HeaderMap) {
    set_header(headers, "x-server", "whix");
}

pub(super) fn short_circuit_inner(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
) -> Option<Response<DynBody>> {
    let op = resolved.slot()?;
    let proto = op.protocol.as_str();
    match proto {
        "redirect" => {
            let mut resp = Response::builder()
                .status(StatusCode::FOUND)
                .body(body::empty())
                .unwrap();
            if let Ok(v) = HeaderValue::from_str(&op.value) {
                resp.headers_mut().insert(hyper::header::LOCATION, v);
            }
            Some(resp)
        }
        "statusCode" => {
            // An empty value is `200` upstream too — `var code = rule || 200`
            // (`getStatusCodeFromRule`, `_original/lib/util/index.js:3580`) —
            // and a value that is not a status at all has no upstream answer to
            // copy: `res.writeHead('abc')` throws inside Node and the client
            // gets a **connection reset**. Measured against whistle 2.10.8 for
            // `abc`, `20x`, `099`, `0`, `2000` and a file path; this port keeps
            // the empty-value answer for all of them rather than dropping a
            // socket over a typo.
            let status = op
                .value
                .trim()
                .parse::<u16>()
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::OK);
            let mut resp = Response::builder()
                .status(status)
                .body(body::empty())
                .unwrap();
            // A mocked `401`/`407` carries its challenge here as well, not only
            // on the `replaceStatus://` path: upstream answers a `statusCode://`
            // rule through `getStatusCodeFromRule`, which calls `handleStatusCode`
            // for exactly this reason (`_original/lib/util/index.js:3566-3588`).
            // Measured against the differential bench, `statusCode://401` came
            // back from whistle with `WWW-Authenticate: Basic realm=User Login`
            // and from here with nothing — so a mocked 401 never prompted, which
            // is most of the point of mocking one.
            if user_login_allowed(resolved, proto) {
                handle_status_code(resp.headers_mut(), status);
            }
            Some(resp)
        }
        "locationHref" => serve_loc_href(&op.value, info),
        // The destination rewrite won: nothing is answered here, the request
        // goes out to where it now points.
        p if p == crate::rules::protocols::URL_REPLACE => None,
        // A file rule, unless `weakRule` hands the request to a proxy instead.
        _ if weak_rule_yields(resolved, proto) => None,
        _ => {
            let cors = auto_cors_wanted(resolved, proto, info);
            // A preflight is answered here and the file is never opened —
            // upstream does the same (`file-proxy.js:249-252`). It has to: the
            // browser sends `OPTIONS` before the real request, and a mock that
            // answers it with the file's own bytes (or a 404, for a rule keyed
            // to the real method) fails the preflight and the real request
            // never follows.
            if cors && info.method.eq_ignore_ascii_case("OPTIONS") {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(body::empty())
                    .unwrap();
                write_auto_cors(resp.headers_mut(), info);
                return Some(resp);
            }
            let mut resp = serve_file_family(proto, op, info, env, remote)?;
            if cors {
                write_auto_cors(resp.headers_mut(), info);
            }
            Some(resp)
        }
    }
}

/// `locationHref://` — **answer** the request with a page that redirects itself
/// (`handleLocHref`, `_original/lib/handlers/file-proxy.js:193-231`).
///
/// It is a mock, not an injection: `isFileProxy` admits it (`protocols.js:282`)
/// so it shares the slot with `file://` and a destination rewrite, and the
/// origin is never contacted. This port had it as an HTML injection — a
/// `<script>` pushed into the origin's own `<head>` — which meant a request the
/// origin answers with JSON, or with nothing, or with an error got no redirect
/// at all, and one it answers with HTML paid for a round trip whose body was
/// then thrown away by the client. `docs/RULES.md` described the injection.
///
/// Three prefixes choose the shape, case-insensitively; with none, a request the
/// browser made *for a script* gets bare JavaScript, so a redirect written for a
/// page does not arrive nested inside another `<script>`.
///
/// Returns `None` when the target is the request's own URL, which is upstream's
/// `handleLocHref` returning false: the request goes out normally rather than
/// answering itself forever. (Upstream compares against the percent-decoded URL
/// as well; that arm is not replicated, so a value written decoded against an
/// encoded request URL still answers here.)
pub(super) fn serve_loc_href(value: &str, info: &ReqInfo) -> Option<Response<DynBody>> {
    let lower = value.to_ascii_lowercase();
    let (as_js, replace, target) = if lower.starts_with("js:") {
        (true, false, &value[3..])
    } else if lower.starts_with("html:") {
        (false, false, &value[5..])
    } else if lower.starts_with("replace:") {
        (false, true, &value[8..])
    } else {
        let wants_js = req_header(Some(info), "sec-fetch-dest") == Some("script");
        (wants_js, false, value)
    };

    let mut body = String::new();
    if !target.is_empty() {
        // `urlToStr`: backslashes go, quotes are escaped so they cannot close
        // the string literal, and every whitespace character becomes a space.
        let escaped: String = target
            .chars()
            .filter(|c| *c != '\\')
            .map(|c| match c.is_whitespace() {
                true => ' ',
                false => c,
            })
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                c => vec![c],
            })
            .collect();
        let no_hash = escaped.split('#').next().unwrap_or(&escaped);
        if abs_url(no_hash, &info.full_url) == info.full_url {
            return None;
        }
        let call = match replace {
            true => format!("window.location.replace(\"{escaped}\");"),
            false => format!("window.location.href = \"{escaped}\";"),
        };
        body = match as_js {
            true => call,
            false => format!("<script>{call}</script>"),
        };
    }
    let ctype = match as_js {
        true => "application/javascript; charset=utf-8",
        false => "text/html; charset=utf-8",
    };
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, ctype)
            .body(body::full(Bytes::from(body)))
            .unwrap(),
    )
}

/// Resolve a possibly-relative URL against the request's own
/// (`getAbsUrl` + `formatUrl`, `_original/lib/util/common.js:526-557`).
///
/// Only [`serve_loc_href`]'s loop check needs it, and only its exact shape will
/// do: whistle normalises both sides through `formatUrl`, which appends the `/`
/// a bare host is missing, so `http://a.test` and `http://a.test/` compare
/// equal.
pub(super) fn abs_url(url: &str, full_url: &str) -> String {
    if is_http_url(url) {
        return format_url(url);
    }
    if let Some(rest) = url.strip_prefix('/') {
        // `fullUrl.indexOf('/', 8)` skips past `https://` to the first slash of
        // the path. JavaScript's `substring(0, -1)` is the empty string, which
        // is what a full URL with no path at all yields.
        let base = full_url
            .get(8..)
            .and_then(|r| r.find('/'))
            .map_or("", |i| &full_url[..i + 8]);
        return format_url(&format!("{base}/{rest}"));
    }
    // `QUERY_RE = /\/[^/]*(?:\?.*)?$/` — the last path segment and the query go,
    // and the relative value takes their place.
    let stem = strip_last_segment(full_url);
    format_url(&format!("{stem}/{url}"))
}

/// `formatUrl` — split the query off, and give a URL with no path a `/`.
pub(super) fn format_url(pattern: &str) -> String {
    let (path, query) = match pattern.find('?') {
        Some(at) => (&pattern[..at], &pattern[at..]),
        None => (pattern, ""),
    };
    let from = path.find("://").map_or(0, |at| at + 3);
    match path[from..].contains('/') {
        true => format!("{path}{query}"),
        false => format!("{path}/{query}"),
    }
}

/// Drop the trailing `/<segment>` and any query — upstream's `QUERY_RE`.
pub(super) fn strip_last_segment(url: &str) -> &str {
    let head = url.split('?').next().unwrap_or(url);
    match head.rfind('/') {
        Some(at) => &head[..at],
        None => head,
    }
}

/// `weakRule` — the local-file rule steps aside for a matching `proxy`/`host`
/// rule instead of answering the request, inverting the usual precedence
/// (`filterWeakRule`, `_original/lib/util/index.js:3731-3743`).
///
/// Upstream drops the local rule when a `host://` rule matched, or when a proxy
/// rule matched that is *not* `proxyHostOnly` — that spelling needs a host rule
/// to mean anything, so on its own it does not outrank the file.
/// `enable://weakRule` says the same request-wide.
pub(super) fn weak_rule_yields(resolved: &Resolved, file_proto: &str) -> bool {
    if !resolved.props(file_proto).has("weakRule") && !is_enabled(resolved, "weakRule") {
        return false;
    }
    if resolved.value("host").is_some() {
        return true;
    }
    matched_proxy_proto(resolved)
        .map(|proto| !resolved.props(proto).has("proxyHostOnly"))
        .unwrap_or(false)
}

/// Does a local-file response carry CORS headers it was never asked for?
///
/// whistle adds them whenever the request came from a page on another origin —
/// `isAutoCors` is `!req.disable.autoCors && req.headers.origin`, with a line
/// property to turn it off (`_original/lib/handlers/file-proxy.js:178-191`).
///
/// This port had the writer and not the trigger, and `docs/LINE_PROPS.md` said
/// so while drawing the wrong conclusion — that implementing the automatic CORS
/// in order to have something for `disableAutoCors` to disable would be putting
/// the cart before the horse. The automatic CORS *is* the horse: mocking an API
/// with `file://` from a page on another origin is one of the things whistle is
/// for, and without it the browser rejects the response before any code sees it.
pub(super) fn auto_cors_wanted(resolved: &Resolved, proto: &str, info: &ReqInfo) -> bool {
    let props = resolved.props(proto);
    // Upstream reads both spellings; the second is its own typo, kept because
    // rules in the wild are written against it.
    if props.has("disableAutoCors") || props.has("disabledAutoCors") {
        return false;
    }
    if disabled_flags(resolved).contains("autoCors") {
        return false;
    }
    req_header(Some(info), "origin").is_some_and(|o| !o.is_empty())
}

/// The CORS headers a local-file response carries — `{enable: true}`, which
/// echoes the request's own `Origin` with credentials, and on a preflight fills
/// in the asked-for method and headers.
pub(super) fn write_auto_cors(headers: &mut HeaderMap, info: &ReqInfo) {
    let mut spec: HashMap<String, String> = HashMap::new();
    spec.insert("enable".to_string(), "true".to_string());
    write_res_cors(headers, &spec, Some(info));
}

/// Serve a matched file-family rule. Returns `None` only for a `x`/`xs` (cross)
/// variant whose file is missing — that falls through to the real server.
pub(super) fn serve_file_family(
    proto: &str,
    op: &RuleOp,
    info: &ReqInfo,
    env: super::super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
) -> Option<Response<DynBody>> {
    let value = op.value.as_str();
    let raw = proto.contains("rawfile");
    // `tpl`, `dust` and `jsonp` are one protocol in whistle
    // (`_original/lib/handlers/file-proxy.js:14`); none of them has any
    // protocol-specific behaviour of its own.
    let templated = proto.ends_with("tpl") || proto.ends_with("jsonp") || proto.ends_with("dust");
    let cross = proto.starts_with('x');

    // A value that *is* content rather than a location is served as the body.
    // Two ways to get one: the `(text)` inline form, and a whole-value `{name}`
    // the values store answered — both are `readRuleValue`'s `if (rule.value)`
    // arm upstream (`_original/lib/util/index.js:1178-1180`). `<path>` is the
    // third bracket form and means the opposite: a path pinned in place, which
    // the matcher has already honoured by not extending it.
    //
    // A body that came from the values store guesses its type from the *name*
    // it was stored under — `rule.key` at `file-proxy.js:270-272` — because that
    // is the only place `mock.json`'s extension is written down. An inline
    // `(text)` has no such name and falls back to the request URL.
    let Some((value, sources)) = file_location(op) else {
        // The value is content. Two ways to get one, and they differ only in
        // the name the content type is guessed from.
        let bytes = match op.value_is_content {
            true => value.as_bytes().to_vec(),
            false => crate::rules::url::fixed_value(value)?.1.into_bytes(),
        };
        let named = op.value_key.as_deref().unwrap_or(&info.full_url);
        return Some(if raw {
            serve_raw_value(&bytes)
        } else if templated {
            serve_template(&bytes, named, info, env)
        } else {
            serve_file_range(&bytes, named, info)
        });
    };

    let candidates = FileCandidates::of(proto, &value, sources);
    match candidates.read(remote) {
        // The *matched* path drives the content type, not the rule value: with
        // `file:///tmp/mock/` it is `/tmp/mock/index.html` that was served.
        //
        // Only this arm names the proxy in a `Server` header: upstream builds it
        // alongside the content type in the `readFiles` callback
        // (`file-proxy.js:315-318`), so a body that never touched the filesystem
        // — inline, values store, or the 404 — does not carry one.
        Some((path, data)) => Some(if raw {
            serve_raw_http(&data, &path, info)
        } else if templated {
            with_server(serve_template(&data, &path, info, env))
        } else {
            with_server(serve_file_range(&data, &path, info))
        }),
        // A cross (`x`/`xs`) rule falls through to the real server instead —
        // including when the path was refused (`file-proxy.js:298-303`).
        None if cross => None,
        // A URL source that answered something other than `404` is the file
        // server being broken rather than the file being absent, and upstream
        // says so with a `502` instead of hiding it behind a not-found
        // (`file-proxy.js:301-307`). Measured: a source answering `500` gets a
        // `502` from whistle and used to get a `404` from here — the one status
        // that tells a reader to go and look at their mock server.
        None if let Some(r) = remote
            && r.data.is_none()
            && r.status != 0
            && r.status != 404 =>
        {
            Some(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(body::full(Bytes::from(format!(
                        "Error: response {}",
                        r.status
                    ))))
                    .unwrap(),
            )
        }
        None => Some(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(body::full(Bytes::from(format!(
                    "whix: file not found <strong>{}</strong>",
                    encode_html(&candidates.blame)
                ))))
                .unwrap(),
        ),
    }
}

/// Where a file rule points, or `None` when its value **is** the content and
/// there is nothing to open.
///
/// Two value shapes are content: an inline `(text)`, and a `{name}` the values
/// store answered — both are `readRuleValue`'s `if (rule.value)` arm upstream
/// (`_original/lib/util/index.js:1178-1180`). `<path>` is the third bracket form
/// and means the opposite: a location pinned in place, which the matcher has
/// already honoured by not extending it.
///
/// Shared by the serving path and by [`prefetch_remote_file`], which have to
/// agree about what the rule points at — one fetches the URL the other will ask
/// for.
pub(super) fn file_location(op: &RuleOp) -> Option<(std::borrow::Cow<'_, str>, Sources)> {
    if op.value_is_content {
        return None;
    }
    match crate::rules::url::fixed_value(&op.value) {
        Some((crate::rules::url::Fixed::Inline, _)) => None,
        Some((crate::rules::url::Fixed::Verbatim, path)) => {
            Some((std::borrow::Cow::Owned(path), Sources::PathsOnly))
        }
        None => Some((
            std::borrow::Cow::Borrowed(op.value.as_str()),
            Sources::PathsAndUrls,
        )),
    }
}

/// Serve raw file bytes with a guessed content type (`file://`).
pub(super) fn serve_file_bytes(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .body(body::full(Bytes::copy_from_slice(data)))
        .unwrap()
}

/// Name the proxy that served a local file, as upstream names itself in the
/// header block it builds beside the content type (`server: config.appName`,
/// `_original/lib/handlers/file-proxy.js:315-318`).
///
/// Spelled honestly, for the reason [`mark_self_generated`] gives: this is not
/// whistle. It is a *response* header the mock carries, not proxy bookkeeping,
/// which is why it is set here and not on everything the proxy answers.
pub(super) fn with_server(mut resp: Response<DynBody>) -> Response<DynBody> {
    set_header(resp.headers_mut(), "server", "whix");
    resp
}

/// Serve `file://` bytes, honouring a `Range` request header.
///
/// Only this shape of response is rangeable: `getRawResByPath` asks for a range
/// unless the protocol is `rawfile` (`file-proxy.js:100-102`), and the template
/// branch never reaches it at all. So `rawfile://` and `tpl://` answer 200 with
/// the whole body however the client asks.
pub(super) fn serve_file_range(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    let Some((start, end)) = parse_range(info, data.len()) else {
        return serve_file_bytes(data, path, info);
    };
    Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .header(
            hyper::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", data.len()),
        )
        .header(hyper::header::ACCEPT_RANGES, "bytes")
        .body(body::full(Bytes::copy_from_slice(&data[start..=end])))
        .unwrap()
}

/// whistle's `parseRange` (`_original/lib/util/index.js:3346-3382`), returning
/// the inclusive byte range to serve, or `None` for "send the whole thing".
///
/// It is reproduced with its arithmetic intact rather than corrected, because
/// two of its answers are load-bearing for anyone who already has mocks:
///
/// * a **suffix** range (`bytes=-500`) computes its start as `size - end` and
///   then compares it against `end` itself, so `start > end` and the range is
///   dropped — whistle answers 200 with the whole body, never the last 500
///   bytes;
/// * **several** ranges collapse into one spanning the lowest start and the
///   highest end, so `bytes=0-1,5-6` serves bytes 0 through 6 as a single 206
///   rather than a multipart response.
///
/// A zero-length body is never ranged (`size &&` guards the whole function).
pub(super) fn parse_range(info: &ReqInfo, size: usize) -> Option<(usize, usize)> {
    if size == 0 {
        return None;
    }
    let header = req_header(Some(info), "range")?;
    let spec = header.trim_start();
    // `BYTES_RANGE_RE = /^\s*bytes=/i` — the `=` has to follow the unit
    // immediately, so `bytes =0-5` is not a range at all.
    let spec = spec
        .get(..6)
        .filter(|unit| unit.eq_ignore_ascii_case("bytes="))
        .map(|_| spec[6..].trim())?;
    if spec.is_empty() {
        return None;
    }
    // `parseInt(s, 10)`: skip leading whitespace, take a sign and then the
    // leading digits, and answer `NaN` if there are none. Splitting on every
    // `-` first is what makes `bytes=-3-5` an absent start and an end of `3`.
    let leading_int = |s: &str| {
        let s = s.trim_start();
        let digits = s.strip_prefix('+').unwrap_or(s);
        let len = digits.bytes().take_while(u8::is_ascii_digit).count();
        digits[..len].parse::<i64>().ok()
    };

    let size = size as i64;
    let (mut start, mut end) = (size, -1i64);
    for item in spec.split(',') {
        let mut parts = item.split('-');
        let (first, second) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let (s, e) = match (leading_int(first), leading_int(second)) {
            (None, None) => continue,
            (None, Some(e)) => (size - e, e),
            (Some(s), None) => (s, size - 1),
            (Some(s), Some(e)) => (s, e),
        };
        start = start.min(s);
        end = end.max(e);
    }
    if start < 0 || end < 0 || start > end || end >= size {
        return None;
    }
    Some((start as usize, end as usize))
}

/// Serve a `rawfile://` whose value *is* the response text, not a path to it
/// (`getRawResByValue`, `_original/lib/handlers/file-proxy.js:84-98`).
///
/// It differs from the path form twice. With no blank line anywhere, `parseRes`
/// is handed nothing and returns bare `{200, {}}`, so the body goes out with
/// **no content type at all** — where a path with no blank line falls back to
/// the file handler's own header block. And `content-encoding` is deleted
/// (`fromValue`, `file-proxy.js:71-73`): a value is written as literal text in
/// a rules file, so it cannot be the compressed bytes the header claims, and
/// leaving it in makes the client fail to decode a body it can read.
pub(super) fn serve_raw_value(data: &[u8]) -> Response<DynBody> {
    match find_headers_sep(data) {
        Some((head_end, body_start)) => {
            let mut resp = raw_response(
                &data[..head_end],
                Bytes::copy_from_slice(&data[body_start..]),
            );
            resp.headers_mut().remove(hyper::header::CONTENT_ENCODING);
            resp
        }
        None => Response::builder()
            .status(StatusCode::OK)
            .body(body::full(Bytes::copy_from_slice(data)))
            .unwrap(),
    }
}

/// How far into a `rawfile://` whistle looks for the header/body separator
/// before giving up and serving the file as an ordinary body
/// (`MAX_HEADERS_SIZE`, `_original/lib/handlers/file-proxy.js:13,151-158`).
pub(super) const MAX_RAW_HEADERS: usize = 256 * 1024;

/// Serve a `rawfile://`: the file is a complete HTTP response (status line +
/// headers + blank line + body). Parse it into a real response.
///
/// A file with no blank line in its first [`MAX_RAW_HEADERS`] bytes is not a
/// raw response at all, and whistle serves it verbatim rather than mistaking
/// its first line for a status line.
pub(super) fn serve_raw_http(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    let budget = &data[..data.len().min(MAX_RAW_HEADERS)];
    let Some((head_end, body_start)) = find_headers_sep(budget) else {
        // Not a raw response, so it is served as an ordinary file — header block
        // and all, which is what `reader.headers || headers` falls back to at
        // `file-proxy.js:348`.
        return with_server(serve_file_bytes(data, path, info));
    };
    raw_response(
        &data[..head_end],
        Bytes::copy_from_slice(&data[body_start..]),
    )
}

/// Build a response from a raw HTTP head and a body
/// (`parseRes`, `_original/lib/handlers/file-proxy.js:61-78`).
///
/// Only the head is decoded as text; the body stays bytes so a binary payload
/// survives. A head whose first line carries no numeric status is served as 200
/// — upstream assigns `statusLine[1]` unchecked and then throws while writing
/// the response, which reaches the client as a reset connection.
pub(super) fn raw_response(head: &[u8], body: Bytes) -> Response<DynBody> {
    let head = String::from_utf8_lossy(head);
    // `CRLF_RE = /\r\n|\r|\n/g` (`file-proxy.js:10`) — a lone CR ends a header
    // line too, so `.http` fixtures written on any platform parse.
    let mut lines = head.split(['\n', '\r']).filter(|l| !l.is_empty());
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            builder = builder.header(k.trim(), v.trim());
        }
    }
    builder.body(body::full(body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(body::empty())
            .unwrap()
    })
}

/// Locate the blank line separating a raw response's head from its body,
/// returning `(head_end, body_start)`.
///
/// whistle accepts every CR/LF spelling of a blank line
/// (`HEADERS_SEP_RE = /(\r?\n(?:\r\n|\r|\n)|\r\r\n?)/`, `file-proxy.js:12`),
/// because a hand-written `.http` fixture rarely has consistent line endings.
pub(super) fn find_headers_sep(data: &[u8]) -> Option<(usize, usize)> {
    for start in 0..data.len() {
        // `\r?\n` followed by any of `\r\n`, `\r`, `\n`.
        let after_first = start + usize::from(data[start] == b'\r');
        if data.get(after_first) == Some(&b'\n') {
            let second = after_first + 1;
            let end = match (data.get(second), data.get(second + 1)) {
                (Some(b'\r'), Some(b'\n')) => Some(second + 2),
                (Some(b'\r') | Some(b'\n'), _) => Some(second + 1),
                _ => None,
            };
            if let Some(end) = end {
                return Some((start, end));
            }
        }
        // `\r\r\n?` — the alternative whistle tries when the first one fails.
        if data[start] == b'\r' && data.get(start + 1) == Some(&b'\r') {
            let end = start
                + if data.get(start + 2) == Some(&b'\n') {
                    3
                } else {
                    2
                };
            return Some((start, end));
        }
    }
    None
}

/// Serve a `tpl://`/`jsonp://`/`dust://`: render the file through the two
/// substitution passes in [`super::super::template`]. The status is always 200 and
/// `content-length` follows from the rendered body, never the file's size.
pub(super) fn serve_template(
    data: &[u8],
    path: &str,
    info: &ReqInfo,
    env: super::super::template::ProxyEnv<'_>,
) -> Response<DynBody> {
    let rendered = super::super::template::render(&String::from_utf8_lossy(data), info, env);
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .body(body::full(Bytes::from(rendered)))
        .unwrap()
}
