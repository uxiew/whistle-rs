//! The response head: `apply_response` and everything it applies that is not a
//! body, a cookie, CORS or caching — status codes and `userLogin`, `disable://`
//! on response properties, `showHost`, `responseFor`, `attachment`, `csp`, and
//! the `x-whistle-rule` report of which rules matched.

use super::*;

/// The rules that matched, as `enable://responseWithMatchedRules` reports them.
///
/// `getRulesText` walks `req.rules` and writes `rawPattern + ' ' + rawMatcher`
/// per entry, joined with `\n` and `encodeURIComponent`d whole
/// (`_original/lib/util/index.js:1867-1877`). The header is
/// `x-whistle-matched-rules`.
///
/// **The order is the protocol table's**, which is what `Object.keys(req.rules)`
/// yields: whistle assigns its keys as it walks `protocols.js`, so the report
/// follows that array and not the order the operators were written. Measured
/// three ways before it was believed — `resHeaders://x-r=1 enable://…` reports
/// the `enable` first (index 24 against 57), and `file://(mocked) enable://…`
/// reports the `file` first, because a local file is filed under `rule` at
/// index 3. Operators sharing a protocol keep resolution order between them.
///
/// The request-side twin `requestWithMatchedRules` is deliberately absent:
/// upstream calls `addMatchedRules(req)` from the response inspector
/// (`res.js:770`), after the request head has gone, so the origin never sees
/// that header. Measured; both proxies send nothing.
pub(super) fn matched_rules_text(resolved: &Resolved) -> Option<String> {
    let mut ops: Vec<&RuleOp> = resolved
        .single
        .values()
        .chain(resolved.multi.values().flatten())
        .chain(resolved.slot())
        .collect();
    // The slot's members are all filed under `rule` upstream, whatever their own
    // spelling — that is what puts `file://` ahead of `enable://`.
    let key = |op: &RuleOp| -> (usize, u64) {
        let name = match crate::rules::protocols::is_slot_protocol(&op.protocol) {
            true => crate::rules::protocols::URL_REPLACE,
            false => op.protocol.as_str(),
        };
        let at = crate::rules::protocols::PROTOCOLS
            .iter()
            .position(|p| *p == name)
            .unwrap_or(usize::MAX);
        (at, op.order)
    };
    ops.sort_by_key(|op| key(op));
    let mut lines: Vec<String> = Vec::new();
    for op in ops {
        let line = format!("{} {}", op.raw_pattern, op.raw);
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    (!lines.is_empty()).then(|| crate::rules::replace::encode_uri_component(&lines.join("\n")))
}

/// Apply response-side operators (status replacement, headers) in place.
///
/// The `resCors` negotiation and the `attachment` filename fallback both need
/// the request that produced this response; without it they degrade to what can
/// be decided from the rule alone. Callers that have the request should use
/// [`apply_response_for`].
pub fn apply_response(parts: &mut response::Parts, resolved: &Resolved) {
    apply_response_for(parts, resolved, None)
}

/// As [`apply_response`], with the request the response answers.
///
/// Operators are applied in whistle's order, which is not the order they are
/// written on the line (`_original/lib/inspectors/res.js:820-950`): cookies and
/// CORS go straight onto the upstream headers, then `resHeaders` — with `cache`
/// and `attachment` folded into it — overwrites them, then `resType`, the
/// charset pass, `headerReplace`, the `Location` re-encode, and — last of all,
/// after the injection's CSP and cache strips — the `delete://` keys.
pub fn apply_response_for(
    parts: &mut response::Parts,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
    if is_enabled(resolved, "responseWithMatchedRules")
        && let Some(text) = matched_rules_text(resolved)
        && let Ok(value) = hyper::header::HeaderValue::from_str(&text)
    {
        parts.headers.insert("x-whistle-matched-rules", value);
    }
    // `statusCode` only speaks when it won the shared slot. Upstream reads it
    // off `rules.rule` (`getStatusCodeFromRule`,
    // `_original/lib/util/index.js:3566-3589`), which is the same single winner
    // a `file://` or a destination would have taken — so a `statusCode` written
    // below one of those, or after one on the same line, never reaches the
    // response at all. Here it was applied unconditionally, and so overwrote the
    // status of a file the rules had already chosen to serve. No gate is needed
    // for that any more: a losing `statusCode` is not in the resolved set to be
    // read. `replaceStatus` has a list of its own upstream and never was.
    if let Some((proto, code)) = ["replaceStatus", "statusCode"]
        .into_iter()
        .find_map(|p| resolved.value(p).map(|v| (p, v)))
        // A value that is not a status leaves the response alone. Upstream
        // hands it to `res.writeHead` and the client gets a connection reset
        // (measured, same list as `statusCode://` above); an operator that
        // cannot be honoured is not a reason to drop a response that arrived.
        && let Some(status) = code
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(|c| StatusCode::from_u16(c).ok())
        // `replaceStatus != _res.statusCode` (`res.js:827`). Without the guard a
        // `replaceStatus://401` on a response that was *already* a 401 wrote a
        // `WWW-Authenticate: Basic` the origin had not asked for — and a browser
        // answers that with a login box.
        && status != parts.status
    {
        parts.status = status;
        if user_login_allowed(resolved, proto) {
            handle_status_code(&mut parts.headers, status);
        }
    }
    // `disable://301` — hand back a `302` instead, so the browser does not cache
    // the redirect permanently (`_original/lib/inspectors/res.js:833-835`). This
    // is the flag you reach for once a site has already taught the browser a
    // `301` you now need to override, and it was not implemented.
    if parts.status == StatusCode::MOVED_PERMANENTLY && disabled_flags(resolved).contains("301") {
        parts.status = StatusCode::FOUND;
    }
    // Resolved before the cookies, because `delete://resCookies.x` is *served*
    // as a cookie rather than applied as a removal — see [`expiring_cookies`].
    let del = Deletions::of(resolved, false);
    apply_res_cookies(&mut parts.headers, resolved, &del, info);
    apply_res_cors(&mut parts.headers, resolved, info);

    apply_header_ops(&mut parts.headers, resolved, "resHeaders");
    apply_cache(&mut parts.headers, resolved);
    apply_attachment(&mut parts.headers, resolved, info);

    if let Some(ct) = resolved.value("resType") {
        set_content_type(&mut parts.headers, ct, no_type_alias);
    }
    set_charset(
        &mut parts.headers,
        resolved.value("resCharset"),
        del.drop_type,
        del.drop_charset,
    );
    apply_header_replace(&mut parts.headers, resolved, HeaderScope::Response);
    // Node's URL layer only speaks ASCII, so a `Location` carrying anything else
    // reaches the browser as mojibake; whistle percent-encodes it right here,
    // after `headerReplace` has had its say (`res.js:946-949`). A rule that
    // redirects to a path with a non-Latin-1 character in it needs this.
    //
    // Read as UTF-8 rather than through `to_str`, which refuses the very bytes
    // this exists to encode; a value that is not UTF-8 at all is left alone,
    // since there is no encoding to read it under. That last part is where this
    // is *wider* than upstream: Node hands its header values over as latin-1
    // strings, one character per byte, so an **origin's** raw-UTF-8 `Location`
    // matches nothing in `G_NON_LATIN1_RE` and passes through unencoded there.
    // Encoding it is the conformant answer and the one a browser follows.
    if let Some(location) = parts
        .headers
        .get(hyper::header::LOCATION)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .map(encode_non_latin1)
    {
        assign_header(&mut parts.headers, "location", &location);
    }

    // Injected content is useless behind a CSP that forbids it, or cached for
    // the next load; whistle strips both (`res.js:1093-1101`).
    if injects_into_body(
        &parts.headers,
        resolved,
        parts.status.as_u16(),
        info.map_or("GET", |i| i.method.as_str()),
    ) {
        if !is_enabled(resolved, "keepCSP") && !is_enabled(resolved, "keepAllCSP") {
            disable_csp(&mut parts.headers);
        }
        if !custom_cache(resolved) && !is_enabled(resolved, "keepCache") {
            disable_res_store(&mut parts.headers);
        }
    }

    // After the strip above, not before it, which is upstream's order
    // (`res.js:1160-1165` against `:1097-1104`) and the whole point of the
    // operator: `resAppend://x delete://resHeaders.cache-control` has to be able
    // to take away the `Cache-Control: no-store` the injection just wrote, and
    // deleting first left it standing.
    apply_deletes(&mut parts.headers, &del, false);

    disable_res_props(&mut parts.headers, resolved);
    apply_show_host(&mut parts.headers, resolved, info);
    annotate_response_for(&mut parts.headers, resolved, info);
}

/// `disable://` flags with response-header effects (`disableResProps`,
/// `_original/lib/util/index.js:3011-3027`), applied last so nothing can undo
/// them.
pub(super) fn disable_res_props(headers: &mut HeaderMap, resolved: &Resolved) {
    let dis = disabled_flags(resolved);
    if ["cookie", "cookies", "resCookie", "resCookies"]
        .iter()
        .any(|f| dis.contains(*f))
    {
        headers.remove(hyper::header::SET_COOKIE);
    }
    if dis.contains("cache") {
        // `no-cache`, not the `no-store` that the injection pass writes.
        set_header(headers, "cache-control", "no-cache");
        set_header(headers, "expires", &http_date(-60_000_000));
        set_header(headers, "pragma", "no-cache");
    }
    if dis.contains("csp") {
        disable_csp(headers);
    }
}

/// `enable://showHost` — report the address the request was actually sent to,
/// as `x-host-ip` (`_original/lib/inspectors/res.js:1197-1199`).
///
/// The value is the connected peer, which through an upstream proxy is the
/// proxy's address — the same `req.hostIp` [`serverIp:`] filters on, so the
/// header and the condition can never disagree. whistle falls back to
/// `127.0.0.1` when it has no address at all, and so does this.
pub(super) fn apply_show_host(
    headers: &mut HeaderMap,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
    if !enabled_flags(resolved).contains("showHost") {
        return;
    }
    let ip = info
        .and_then(|i| i.res.as_ref())
        .and_then(|r| r.server_ip.as_deref())
        .unwrap_or("127.0.0.1");
    set_header(headers, "x-host-ip", ip);
}

/// `responseFor://` — annotate the response with who answered it, as
/// `x-whistle-response-for` (`setResponseFor`,
/// `_original/lib/util/index.js:3214-3261`, called from `res.js:1200-1206`).
///
/// Two forms. A plain value is emitted verbatim. `name=a,b,req.c` names
/// *headers* to read: bare names from the response, `req.`-prefixed ones from
/// the request, with the address actually reached appended — so a response can
/// carry a chain of who served it without anyone having to guess.
///
/// **This used to be a different operator entirely.** The port fetched the value
/// as a URL, on every matching request, and wrote the result onto the *outgoing
/// request* — an unrequested outbound call to whatever a rules file named, and
/// headers the client never saw. Nothing upstream makes a network call here.
pub(super) fn annotate_response_for(
    headers: &mut HeaderMap,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
    let Some(spec) = resolved.value("responseFor") else {
        return;
    };
    let server_ip = info
        .and_then(|i| i.res.as_ref())
        .and_then(|r| r.server_ip.as_deref())
        .unwrap_or("127.0.0.1");

    let Some(names) = spec.strip_prefix("name=") else {
        set_header(headers, "x-whistle-response-for", spec);
        return;
    };

    // Response-header lookups keep their position; request-header ones are
    // collected and appended after, which is upstream's `result.concat(reqResult)`.
    let (mut from_res, mut from_req) = (Vec::new(), Vec::new());
    for name in names.to_ascii_lowercase().split(',') {
        let name = name.trim();
        match name.strip_prefix("req.") {
            Some(req_name) => {
                if let Some(v) = info.and_then(|i| header_of(&i.headers, req_name)) {
                    from_req.push(v);
                }
            }
            None => {
                if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
                    from_res.push(v.to_string());
                }
            }
        }
    }
    if !from_res.iter().any(|v| v == server_ip) {
        from_res.push(server_ip.to_string());
    }
    from_res.extend(from_req);
    set_header(headers, "x-whistle-response-for", &from_res.join(", "));
}

/// One request header by name, from the captured pairs.
pub(super) fn header_of(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

/// Does the rule that produced a `401`/`407` want the authentication challenge
/// that goes with it?
///
/// `isDisableUserLogin` (`_original/lib/util/index.js:3557-3562`): the line's own
/// `enableUserLogin` or a request-wide `enable://userLogin` forces it on and wins
/// outright; `disableUserLogin` on the line or `disable://userLogin` turns it off.
///
/// `docs/LINE_PROPS.md` had the two properties as "not applicable, this port has
/// no login box". They are not about whistle's own login box at all — they are
/// about the `WWW-Authenticate: Basic realm=User Login` header a mocked `401`
/// carries, which is the thing that *makes* a browser show one. This port writes
/// that header, so there was always something here to turn off.
pub(super) fn user_login_allowed(resolved: &Resolved, proto: &str) -> bool {
    let props = resolved.props(proto);
    if props.has("enableUserLogin") || enabled_flags(resolved).contains("userLogin") {
        return true;
    }
    !props.has("disableUserLogin") && !disabled_flags(resolved).contains("userLogin")
}

/// `statusCode://401`/`407` and `replaceStatus://401`/`407` also advertise the
/// authentication a browser needs in order to ask for credentials
/// (`handleStatusCode`, `_original/lib/util/index.js:401-408`).
pub(super) fn handle_status_code(headers: &mut HeaderMap, status: StatusCode) {
    match status.as_u16() {
        401 => set_header(headers, "www-authenticate", "Basic realm=User Login"),
        407 => set_header(headers, "proxy-authenticate", "Basic realm=User Login"),
        _ => {}
    }
}

/// `attachment://[filename]` — force a download.
///
/// whistle always writes a filename: with no value it falls back to the last
/// path segment of the request URL, or `index.html`
/// (`getFilename`, `_original/lib/util/index.js:957-970`).
pub(super) fn apply_attachment(
    headers: &mut HeaderMap,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
    let Some(value) = resolved.value("attachment") else {
        return;
    };
    let name = match value.is_empty() {
        false => value.to_string(),
        true => info.map(|i| url_filename(&i.full_url)).unwrap_or_default(),
    };
    let disposition = match name.is_empty() {
        // Without the request there is no fallback name to compute; a bare
        // `attachment` still forces the download.
        true => "attachment".to_string(),
        false => format!("attachment; filename=\"{}\"", encode_non_latin1(&name)),
    };
    set_header(headers, "content-disposition", &disposition);
}

/// The filename whistle derives from a URL: the last path segment, ignoring
/// query and fragment, or `index.html` when there is none.
pub(super) fn url_filename(url: &str) -> String {
    let pure = url.split(['?', '#']).next().unwrap_or(url).trim();
    // `getPath` drops the scheme, so the host counts as a segment: a URL with no
    // `/` after it has no filename at all.
    let after_scheme = pure.split_once("://").map(|(_, rest)| rest).unwrap_or(pure);
    match after_scheme.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_string(),
        _ => "index.html".to_string(),
    }
}

/// Percent-encode whitespace and everything outside Latin-1, which is all a
/// header value may not carry (`encodeNonLatin1Char`,
/// `_original/lib/util/common.js:1516,1534-1539`).
pub(super) fn encode_non_latin1(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_whitespace() && (c as u32) <= 0xFF {
            out.push(c);
            continue;
        }
        let mut buf = [0u8; 4];
        for b in c.encode_utf8(&mut buf).as_bytes() {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Would any operator write into this response's body?
///
/// Upstream asks the same question *before* the `safeHtml`/`strictHtml` gate
/// runs — it looks only at whether a rule produced content
/// (`_original/lib/inspectors/res.js:1093`) — so a refused injection still
/// costs the response its CSP and its cacheability.
///
/// "Produced content" is the operative half, and it is a truthiness test on the
/// assembled value, not on the operator having matched: a `resPrepend://()`
/// leaves `data.top` undefined and the strip never runs. This port asked only
/// whether the operator matched, so an operator written with no value stripped
/// the CSP off a page it did not otherwise touch and marked it `no-store`.
pub(super) fn injects_into_body(
    headers: &HeaderMap,
    resolved: &Resolved,
    status: u16,
    method: &str,
) -> bool {
    // A response with no body has nothing to inject into, so nothing to clear a
    // CSP or a cache for either. Upstream's `hasResBody` gate covers both
    // (`_original/lib/inspectors/res.js:1097-1113`); without it a `302` came
    // back with `Cache-Control: no-store`, a past `Expires` and no CSP.
    if !super::super::response_has_body(status, method) {
        return false;
    }
    let class = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(res_class);
    let families = BodyFamilies::of(class);
    let writes = |protocol: String| {
        resolved
            .all(&protocol)
            .iter()
            .any(|op| !op.value.is_empty())
    };
    // `weinre://` is an injector too, and upstream clears the same two things
    // for it (`_original/lib/inspectors/weinre.js:37-38`). It has to: a debug
    // agent pushed into a page whose CSP forbids inline scripts never runs, and
    // one the browser caches outlives the rule that asked for it. This port
    // injected the script and left both standing.
    //
    // Upstream reaches JavaScript responses as well, appending the agent source
    // bare; this port's injection is a `<script src>` tag, which only means
    // anything in markup — see `docs/RULES.md`.
    if families.html && resolved.value("weinre").is_some() {
        return true;
    }
    ["Body", "Prepend", "Append"].iter().any(|slot| {
        writes(format!("res{slot}"))
            || (families.html && writes(format!("html{slot}")))
            || (families.js && writes(format!("js{slot}")))
            || (families.css && writes(format!("css{slot}")))
    })
}

/// Drop every spelling of the Content-Security-Policy header
/// (`disableCSP`, `_original/lib/util/index.js:738-744`).
pub(super) fn disable_csp(headers: &mut HeaderMap) {
    for name in [
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-security-policy",
        "x-content-security-policy-report-only",
        "x-webkit-csp",
    ] {
        remove_header(headers, name);
    }
}

/// Make the response uncacheable (`disableResStore`,
/// `_original/lib/util/index.js:986-991`). The `tag` header it also deletes is
/// upstream's typo for `etag`; reproduced, since a rules file must resolve the
/// same way in both implementations.
pub(super) fn disable_res_store(headers: &mut HeaderMap) {
    set_header(headers, "cache-control", "no-store");
    set_header(headers, "expires", &http_date(-60_000_000));
    set_header(headers, "pragma", "no-cache");
    remove_header(headers, "tag");
}
