//! The request head: `apply_request` and the request-side operators it applies
//! that are not headers, cookies, CORS or caching — `auth://`, the client's
//! `x-forwarded-for`, `disable://` on request properties, and the encodings a
//! client may be told the origin can send.

use super::*;

/// Apply request-side operators (headers, method, ua, referer) in place.
pub fn apply_request(parts: &mut request::Parts, resolved: &Resolved) {
    // The client-id a client sent is not the client-id an upstream should read.
    // whistle drops it unless the request asked to keep it — `if (clientId) { if
    // (!options.isPlugin && !req._customClientId && !isKeepClientId(req, …))
    // removeClientId(optHeaders) }` (`_original/lib/inspectors/res.js:717-723`).
    // This port has no client-id of its own to put in its place (see
    // `docs/RULES.md`, the flags it does not implement), so the header simply
    // goes — and `enable://keepClientId`, which does nothing else here, is
    // honoured for this one purpose.
    if !is_enabled(resolved, "keepClientId") {
        parts.headers.remove("x-whistle-client-id");
    }
    apply_header_ops(&mut parts.headers, resolved, "reqHeaders");

    // Both go through the same `setHeader` assignment upstream
    // (`_original/lib/inspectors/req.js:511-519`), so an empty `ua://` sends an
    // empty `User-Agent` rather than none at all — `disable://ua` is the rule
    // that removes it.
    if let Some(ua) = resolved.value("ua") {
        assign_header(&mut parts.headers, "user-agent", ua);
    }
    if let Some(referer) = resolved.value("referer") {
        assign_header(&mut parts.headers, "referer", referer);
    }
    // `getMethod` runs on **every** request, not only one carrying a
    // `method://`: `req.method = util.getMethod(data.method || req.method)`
    // (`_original/lib/inspectors/req.js:536`, impl `util/common.js:1608-1613`).
    // So a client that sent `post` reaches the origin as `POST`, and — more to
    // the point here — the same normalised method is what every body gate then
    // reads. An empty or unusable value falls back to `GET`, as upstream's does.
    let method = resolved
        .value("method")
        .map(str::to_string)
        .unwrap_or_else(|| parts.method.to_string());
    parts.method = method
        .trim()
        .to_ascii_uppercase()
        .parse()
        .unwrap_or(hyper::Method::GET);
    if let Some(ct) = resolved.value("reqType") {
        set_content_type(&mut parts.headers, ct, req_type_alias);
    }
    if let Some(auth) = resolved.get("auth").map(auth_of)
        && let Some(basic) = auth.basic()
    {
        // `"proxy":true` addresses the *proxy* rather than the origin
        // (`handleAuth`, `_original/lib/inspectors/req.js:150-155`).
        let name = match auth.proxy {
            true => "proxy-authorization",
            false => "authorization",
        };
        set_header(&mut parts.headers, name, &basic);
    }
    apply_forwarded_for(&mut parts.headers, resolved);
    apply_req_cors(&mut parts.headers, resolved);
    apply_req_cookies(&mut parts.headers, resolved);
    let del = Deletions::of(resolved, true);
    // `reqCharset` and the type/charset deletions are one operation upstream
    // (`setCharset`, `_original/lib/inspectors/req.js:115`).
    set_charset(
        &mut parts.headers,
        resolved.value("reqCharset"),
        del.drop_type,
        del.drop_charset,
    );
    apply_deletes(&mut parts.headers, &del, true);
    apply_header_replace(&mut parts.headers, resolved, HeaderScope::Request);
    // Before the `disable://` pass, which is where upstream runs it
    // (`_original/lib/inspectors/req.js:579-580`).
    remove_unsupported_encodings(&mut parts.headers);
    // Last, so a `disable://` flag has the final say over what leaves here —
    // including over a `reqHeaders://cookie=…` that set what it strips, which is
    // upstream's order too (`disableReqProps` runs after `handleReq`,
    // `_original/lib/inspectors/req.js:579-581`).
    disable_req_props(&mut parts.headers, resolved);
    // A rule that rewrites the response body cannot survive a `304`, so the
    // request goes out unconditional even without `disable://cache`.
    if res_body_forbids_cache(resolved) {
        disable_req_cache(&mut parts.headers);
    }
}

/// What an `auth://` rule asks for (`getAuthByRules`,
/// `_original/lib/util/index.js:3645-3662`).
///
/// A missing half is not an empty one: `username` and `password` are each
/// `None` when the rule did not name them, and `getAuthBasic`
/// (`util/index.js:3668-3685`) reads the difference — a password with no
/// username becomes `:pass`, a username with no password has no colon at all.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Auth {
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    /// `"proxy":true` — send `Proxy-Authorization` rather than `Authorization`.
    pub(super) proxy: bool,
}

impl Auth {
    /// The header value, or `None` when the rule named neither half
    /// (`getAuthBasic`, `_original/lib/util/index.js:3668-3685`).
    pub(super) fn basic(&self) -> Option<String> {
        let joined = match (&self.username, &self.password) {
            (None, None) => return None,
            // No username: upstream starts the pair with an empty string, so
            // the colon survives and the server still sees two fields.
            (None, Some(p)) => format!(":{p}"),
            // No password: no colon either — `['u'].join(':')` is just `u`.
            (Some(u), None) => u.clone(),
            (Some(u), Some(p)) => format!("{u}:{p}"),
        };
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            joined.as_bytes(),
        );
        Some(format!("Basic {token}"))
    }
}

/// What an `auth://` operator asks for, by whichever of upstream's two roads it
/// travels.
///
/// `getAuthByRules` reads the value **inline** — as JSON, as a
/// `username=…&password=…` query, or as `user:pass`. When it declines, `req.js`
/// hands the same rule to `parseRuleJson` instead (`authObj ? null :
/// reqRules.auth`, `_original/lib/inspectors/req.js:461,:467`), which reads a
/// data object out of it and keeps only `username` / `password` / `proxy`.
///
/// Which road a value takes is decided on the value **as written**, which is why
/// [`RuleOp::value_loaded`] exists: a location has already been replaced by what
/// it held.
pub(super) fn auth_of(op: &RuleOp) -> Auth {
    // A value read out of a location never had the inline reading offered to it:
    // `getAuthByRules` refused it for the slash, and this is the road it was
    // sent down. The documented file — `username: admin` on one line,
    // `password: …` on the next — is the line format, and it only arrives here.
    if op.value_loaded {
        return format_auth(parse_data_object(&op.value, false, true).as_ref());
    }
    match auth_by_rules(&op.value) {
        Some(auth) => auth,
        // Declined inline: upstream reads the matcher itself as a data object,
        // and a value with a slash but no `=` yields nothing at all.
        None => format_auth(parse_data_object(&op.value, false, op.value_is_content).as_ref()),
    }
}

/// `getAuthByRules` (`_original/lib/util/index.js:3644-3661`) — the inline
/// reading of an `auth://` value, or `None` when it declines.
///
/// This port understood only `user:pass`, so the other two shapes — the JSON
/// object and the `username=…&password=…` query — were base64-encoded whole and
/// sent as the credentials themselves. `auth://{"username":"u","password":"p"}`
/// authenticated as the user *`{"username"`* with the password
/// *`"u","password":"p"}`*, which a server answers with a 401 that looks like
/// the rule never ran.
///
/// **A value with a slash in it is not credentials.** `SLASH_RE = /[\\/]/`
/// (`util/index.js:102`) tests the whole value, and when it matches upstream
/// returns nothing — the value is a *location*, and only the other road may read
/// it. This port used to split it on the first colon anyway, on the reading that
/// a password may contain a slash. It may not: measured against whistle 2.10.8,
/// `auth://admin:se/cret` sends **no** `Authorization` header there, and so do
/// the block and `(inline)` spellings of the same text. What the old behaviour
/// did instead was send the local filesystem path — the documented
/// `auth:///Users/john/config/auth.json` reached the origin as
/// `Authorization: Basic base64("/Users/john/config/auth.json")` whenever the
/// file could not be read.
pub(super) fn auth_by_rules(value: &str) -> Option<Auth> {
    let value = value.trim();
    // `auth[0] === '{' && auth[auth.length - 1] === '}'`: a JSON object.
    if value.starts_with('{') && value.ends_with('}') {
        // A JSON object upstream cannot parse becomes `{}` — an auth naming
        // neither half, which produces no header rather than a bad one.
        let parsed = crate::rules::url::parse_json(value);
        return Some(format_auth(parsed.as_ref()));
    }
    // `AUTH_RE = /^(?:username|password)=/` — anchored, and case-sensitive. It
    // is tested *before* the slash, so a password may contain one here.
    if value.starts_with("username=") || value.starts_with("password=") {
        // `parseQuery(auth, null, null, true)`: the raw decoder, so a `%2F` or a
        // `+` in a password reaches the server as written.
        let obj: serde_json::Map<String, serde_json::Value> = value
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        return Some(format_auth(Some(&serde_json::Value::Object(obj))));
    }
    if value.contains('/') || value.contains('\\') {
        return None;
    }
    Some(match value.split_once(':') {
        Some((u, p)) => Auth {
            username: Some(u.to_string()),
            password: Some(p.to_string()),
            proxy: false,
        },
        None => Auth {
            username: Some(value.to_string()),
            password: None,
            proxy: false,
        },
    })
}

/// `formatAuth` (`_original/lib/util/index.js:3632-3643`): read the three
/// fields, stringifying whatever was there and keeping `null` distinct.
pub(super) fn format_auth(obj: Option<&serde_json::Value>) -> Auth {
    let field = |name: &str| match obj.and_then(|o| o.get(name)) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    };
    Auth {
        username: field("username"),
        password: field("password"),
        // `!!obj.proxy`, so the query spelling `proxy=false` is a non-empty
        // string and therefore **true**. Upstream's, and the reason the JSON
        // spelling is the one to reach for when the answer is "no".
        proxy: match obj.and_then(|o| o.get("proxy")) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(serde_json::Value::Number(n)) => n.as_f64() != Some(0.0),
            Some(_) => true,
        },
    }
}

/// `x-forwarded-for` (`_original/lib/inspectors/res.js:690-710`).
///
/// Three rules, none of which this port had:
///
/// * `forwardedFor://` sets the header **only when its value is an IP**
///   (`net.isIP`). Upstream's own documentation points a non-IP value at
///   `reqHeaders://` instead; setting it here let `forwardedFor://hello` reach
///   the origin as a client address.
/// * `disable://clientIp` (and `clientIP`) deletes the header outright.
/// * Otherwise the client's own `X-Forwarded-For` is **removed** rather than
///   forwarded. That is the load-bearing one: without it, any client can claim
///   any address simply by sending the header, and the origin sees a value the
///   proxy vouched for. whistle closes that by default and opens it with
///   `enable://clientIp`.
///
/// The port does not implement upstream's `req.clientIp` *substitution* — it
/// never forwards a client address of its own — so the choice here is between
/// stripping and passing through, and stripping is the one that cannot mislead.
pub(super) fn apply_forwarded_for(headers: &mut HeaderMap, resolved: &Resolved) {
    const XFF: &str = "x-forwarded-for";
    let dis = disabled_flags(resolved);
    // `-M keepXFF` is `enable://clientIp` for every request — still beaten by an
    // explicit `disable://clientIp` below, as the flag is.
    let keep_all = KEEP_CLIENT_XFF.load(std::sync::atomic::Ordering::Relaxed);
    if dis.contains("clientIp") || dis.contains("clientIP") {
        headers.remove(XFF);
        return;
    }
    if let Some(value) = resolved.value("forwardedFor") {
        // `net.isIP`: a v4 or v6 literal, nothing else.
        if value.trim().parse::<std::net::IpAddr>().is_ok() {
            set_header(headers, XFF, value.trim());
            return;
        }
    }
    let en = enabled_flags(resolved);
    if !keep_all && !en.contains("clientIp") && !en.contains("clientIP") {
        headers.remove(XFF);
    }
}

/// Set by the launch when `-M keepXFF` (or `forwardedFor`) named it.
///
/// A process-wide switch rather than a threaded parameter, for the same reason
/// [`super::super::upstream::set_insecure_upstream`] is one: it is decided once, at
/// startup, and every request reads the same answer.
pub(super) static KEEP_CLIENT_XFF: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Called once by the launch; see [`KEEP_CLIENT_XFF`].
pub fn set_keep_client_xff(keep: bool) {
    KEEP_CLIENT_XFF.store(keep, std::sync::atomic::Ordering::Relaxed);
}

/// Strip the request headers a `disable://` flag names (`disableReqProps`,
/// `_original/lib/util/index.js:2977-3009`).
///
/// Every one of these was silently inert before: a user who wrote
/// `disable://cookie` still had the cookie forwarded to the origin, which for
/// the privacy-shaped flags is the wrong way to fail.
pub(super) fn disable_req_props(headers: &mut HeaderMap, resolved: &Resolved) {
    let dis = disabled_flags(resolved);
    let en = enabled_flags(resolved);
    let off = |name: &str| dis.contains(name);
    if off("ua") {
        headers.remove(hyper::header::USER_AGENT);
    }
    // `enable://captureStream` also drops it: whistle wants the origin's bytes
    // uncompressed so it can stream them past the inspector. That one goes
    // through `isEnable`, which a `disable://` of the same name cancels
    // (`_original/lib/util/index.js:675-677`) — unlike the keys above, which
    // upstream reads straight off `req.disable`.
    if off("gzip") || (en.contains("captureStream") && !dis.contains("captureStream")) {
        headers.remove(hyper::header::ACCEPT_ENCODING);
    }
    if ["cookie", "cookies", "reqCookie", "reqCookies"]
        .iter()
        .any(|f| off(f))
    {
        headers.remove(hyper::header::COOKIE);
    }
    // Both spellings, because whistle accepts the correct one and the common
    // misspelling that matches the header's own name.
    if off("referer") || off("referrer") {
        headers.remove(hyper::header::REFERER);
    }
    if off("ajax") {
        headers.remove("x-requested-with");
    }
    if off("cache") {
        disable_req_cache(headers);
    }
    // `Connection: close` goes on the request that leaves here, not on the
    // answer that goes back to the client: upstream writes it into the outgoing
    // `options.headers` (`_original/lib/inspectors/res.js:447-449`) so the hop
    // to the origin is not pooled. Putting it on the response instead tore down
    // the *client's* connection and left the origin socket in the pool — the
    // exact opposite of what the flag asks for. Both spellings, because
    // upstream folds `keepalive` into `keepAlive` before reading it
    // (`res.js:268-270`).
    if off("keepAlive") || off("keepalive") {
        set_header(headers, "connection", "close");
    }
}

/// Narrow `Accept-Encoding` to the codings this proxy can undo *and* redo
/// (`removeUnsupportsHeaders`, `_original/lib/util/index.js:1549-1570`), which
/// upstream runs on every request (`req.js:579`).
///
/// Without it a modern browser asks for `gzip, deflate, br, zstd`, the origin
/// picks zstd, and every body operator silently dies: [`coding::Coding`] cannot
/// round-trip zstd, so the body is passed through untouched and the rule looks
/// like it never matched. That is the whole reason whistle narrows the header
/// rather than trusting the origin to be conservative.
///
/// `deflate` is dropped even though this port can decode it, because upstream
/// drops it too — `removeUnsupportsHeaders` only keeps `deflate` when its
/// caller passes `supportsDeflate`, and `req.js:579` does not. Keeping it would
/// invite the raw-vs-zlib deflate ambiguity back for no gain, since any origin
/// that speaks deflate also speaks gzip.
pub(super) fn remove_unsupported_encodings(headers: &mut HeaderMap) {
    let Some(value) = headers
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return;
    };
    let kept = value
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        // The comparison is against the whole token, so a `q` parameter takes
        // the coding down with it — `gzip;q=1.0` is not `gzip`. Upstream's, and
        // it is why whistle's own requests carry a bare `gzip, br`.
        .filter(|token| token == "gzip" || token == "br")
        .collect::<Vec<_>>()
        .join(", ");
    // A request that asked for *nothing* this proxy can undo keeps the header
    // it arrived with: upstream only assigns when the filtered list is
    // non-empty (`util/index.js:1567-1569`). An origin may still answer with a
    // coding no operator can see through — but that is the client's own header,
    // untouched, rather than one this proxy invented.
    if !kept.is_empty() {
        set_header(headers, "accept-encoding", &kept);
    }
}
