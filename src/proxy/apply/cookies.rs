//! The cookie operators: `reqCookies://` and `resCookies://` — how their lines
//! fold into one list, what one entry says a cookie should be (value,
//! attributes, expiry), and how that is written into a `Cookie` or a
//! `Set-Cookie` header.

use super::*;

/// Collapse every line of a cookie protocol into one ordered `name` → `value`
/// map, first line winning a contested name — the `parseRuleJson` fold, as for
/// headers (`_original/lib/inspectors/req.js:459-468`).
pub(super) fn merge_cookie_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, CookieValue)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_cookie_ops(&op.value, op.value_is_content)),
    )
}

/// What one `reqCookies`/`resCookies` entry says a cookie should be.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum CookieValue {
    /// A bare value — the only shape a query-string spelling can produce.
    Plain(String),
    /// The attribute object a JSON spelling may use:
    /// `{"sid":{"value":"x","httpOnly":true,"maxAge":600}}`. The response side
    /// expands it into `Set-Cookie` attributes ([`cookie_item`]); the request
    /// side has nowhere to put them and takes `value` alone, which is upstream's
    /// `value && typeof value == 'object' ? value.value : value`
    /// (`_original/lib/util/index.js:3079`).
    Attrs(serde_json::Map<String, serde_json::Value>),
    /// An array of either of the above: one name, **several** `Set-Cookie`
    /// lines (`Array.isArray(cookie)`, `_original/lib/util/index.js:3138-3142`).
    /// This is how upstream expires a cookie under both its plain and its
    /// `Secure` spelling at once, and it is reachable from a rule too:
    /// `resCookies://{"sid":[{"value":"a","path":"/"},{"value":"b"}]}`.
    List(Vec<CookieValue>),
}

impl CookieValue {
    /// The value with any attributes dropped — what a `Cookie` header can carry.
    ///
    /// An array has none: upstream reads `.value` off whatever the entry is, and
    /// an array does not have one, so the request side sees an empty value.
    pub(super) fn plain(&self) -> String {
        match self {
            CookieValue::Plain(v) => v.clone(),
            CookieValue::Attrs(map) => json_attr(map, &["value", "Value"])
                .map(str_of_json)
                .unwrap_or_default(),
            CookieValue::List(_) => String::new(),
        }
    }

    /// Parse one JSON value into a cookie entry.
    pub(super) fn of_json(v: serde_json::Value) -> CookieValue {
        match v {
            serde_json::Value::Object(map) => CookieValue::Attrs(map),
            serde_json::Value::Array(items) => {
                CookieValue::List(items.into_iter().map(CookieValue::of_json).collect())
            }
            other => CookieValue::Plain(str_of_json(&other)),
        }
    }
}

/// Parse a `reqCookies`/`resCookies` value into `name` → value entries.
///
/// Like the other JSON-shaped operators, the value is either `{json}` or a
/// query string, so `reqCookies://a=1&b=2` is two cookies. Within that query a
/// name with no `=` gets an **empty value** — it does not delete the cookie;
/// that is `delete://reqCookies.<name>`.
///
/// A value with no `=` *anywhere* is not a query string at all: upstream reads
/// it as a location and tries to load it, so `reqCookies://sid` names a file
/// and sets no cookie (`tryParseMatcher` bails on `indexOf('=') === -1`,
/// `_original/lib/util/index.js:1165-1171`). Same gate as
/// [`parse_header_pairs`].
pub(super) fn parse_cookie_ops(value: &str, is_content: bool) -> Vec<(String, CookieValue)> {
    // The three roads every data value takes ([`parse_data_object`]). The line
    // format is the third, and `resCookies.md` prints it as the way to write
    // several cookies:
    //
    // ```txt
    // ``` cookies.json
    // key1: value1
    // key2: value2
    // ```
    // ```
    //
    // It set no cookie at all here.
    let Some(serde_json::Value::Object(map)) = parse_data_object(value.trim(), false, is_content)
    else {
        return Vec::new();
    };
    map.into_iter()
        .filter(|(name, _)| !name.trim().is_empty())
        .map(|(k, v)| (k.trim().to_string(), CookieValue::of_json(v)))
        .collect()
}

/// A JSON value as a cookie would carry it: a string unquoted, `null` empty,
/// anything else in its JSON spelling — which is what `String(x)` gives too.
pub(super) fn str_of_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The first of `names` present in `map`. whistle accepts several spellings of
/// every cookie attribute (`maxAge` / `maxage` / `MaxAge` / `Max-Age` /
/// `max-age`), so the lookups are spelled out rather than case-folded — folding
/// would also accept spellings upstream rejects.
pub(super) fn json_attr<'a>(
    map: &'a serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<&'a serde_json::Value> {
    names
        .iter()
        .find_map(|n| map.get(*n))
        .filter(|v| !v.is_null())
}

/// Whether an attribute is present and truthy, JavaScript's sense of the word:
/// `false`, `0`, `""` and `null` are all off.
pub(super) fn json_flag(map: &serde_json::Map<String, serde_json::Value>, names: &[&str]) -> bool {
    match json_attr(map, names) {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// whistle's `maxAge` for an already-expired cookie (`EXPIRED_SEC`,
/// `_original/lib/util/index.js:55`). Written as `Max-Age=0`, with an `Expires`
/// in the past — the pair that makes a browser drop the cookie.
pub(super) const EXPIRED_MAX_AGE: i64 = -123456;

/// Render one `Set-Cookie` value (`getCookieItem`,
/// `_original/lib/util/index.js:3093-3117`).
///
/// Attribute order is upstream's, not the RFC's suggestion: value, `Expires`,
/// `Max-Age`, `Secure`, `HttpOnly`, `Partitioned`, `Path`, `Domain`, `SameSite`.
pub(super) fn cookie_item(name: &str, value: &CookieValue) -> String {
    let map = match value {
        // **Not escaped.** `getCookieItem` returns `name + '=' + cookie` for
        // anything that is not an object — `escapeValue` is reached only down
        // the attribute path, on `cookie.value`. So the string spelling passes
        // a `;` through and `resCookies://k=v;path=/` really does set a cookie
        // with a path, which is how the operator's documentation writes it.
        // This port escaped here too, turning that rule into the value
        // `v%3Bpath=/` — a cookie with a nonsense value and no path at all.
        CookieValue::Plain(v) => return format!("{name}={v}"),
        CookieValue::Attrs(map) => map,
        // A nested array. [`cookie_lines`] flattens one level, so this is the
        // second — upstream reaches `getCookieItem` with the array itself, where
        // `typeof array == 'object'` sends it down the attribute path and every
        // lookup on it misses. The result is a bare `name=`.
        CookieValue::List(_) => return format!("{name}="),
    };
    let mut attrs = vec![format!("{name}={}", escape_cookie(&value.plain(), false))];
    // `parseInt` on a non-number yields NaN and the pair is skipped, so a
    // `maxAge` that is not a number leaves the cookie a session cookie.
    if let Some(max_age) = json_attr(map, &["maxAge", "maxage", "MaxAge", "Max-Age", "max-age"])
        .and_then(parse_int_loosely)
    {
        attrs.push(format!("Expires={}", http_date(max_age * 1000)));
        // The expiring form says `Max-Age=0` rather than the sentinel: a
        // negative `Max-Age` is legal but "0" is what every browser acts on.
        let written = if max_age == EXPIRED_MAX_AGE {
            0
        } else {
            max_age
        };
        attrs.push(format!("Max-Age={written}"));
    }
    if json_flag(map, &["secure", "Secure"]) {
        attrs.push("Secure".to_string());
    }
    if json_flag(map, &["httpOnly", "HttpOnly", "httponly"]) {
        attrs.push("HttpOnly".to_string());
    }
    if json_flag(map, &["partitioned", "Partitioned"]) {
        attrs.push("Partitioned".to_string());
    }
    for (keys, label) in [
        (["path", "Path"], "Path"),
        (["domain", "Domain"], "Domain"),
        (["sameSite", "samesite"], "SameSite"),
    ] {
        if let Some(v) = json_attr(map, &keys) {
            let v = str_of_json(v);
            if !v.is_empty() {
                attrs.push(format!("{label}={v}"));
            }
        }
    }
    // `SameSite` has a third spelling upstream reads and the loop above cannot,
    // because two of its three keys are already taken.
    if json_attr(map, &["sameSite", "samesite"]).is_none()
        && let Some(v) = json_attr(map, &["SameSite"])
    {
        let v = str_of_json(v);
        if !v.is_empty() {
            attrs.push(format!("SameSite={v}"));
        }
    }
    attrs.join("; ")
}

/// JavaScript's `parseInt(x, 10)`: a leading integer, or nothing.
///
/// A JSON number is taken whole; a string is read up to its first non-digit, so
/// `"600s"` is 600 and `"s600"` is nothing.
pub(super) fn parse_int_loosely(v: &serde_json::Value) -> Option<i64> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        serde_json::Value::String(s) => {
            let s = s.trim();
            let (sign, digits) = match s.strip_prefix('-') {
                Some(rest) => (-1i64, rest),
                None => (1i64, s.strip_prefix('+').unwrap_or(s)),
            };
            let end = digits
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(digits.len());
            digits[..end].parse::<i64>().ok().map(|n| sign * n)
        }
        _ => None,
    }
}

/// Merge `reqCookies` operators into the request `Cookie` header, keeping the
/// position of a cookie the request already carried (`setReqCookies`,
/// `_original/lib/util/index.js:3053-3092`).
pub(super) fn apply_req_cookies(headers: &mut HeaderMap, resolved: &Resolved) {
    let ops = merge_cookie_ops(resolved, "reqCookies");
    if ops.is_empty() {
        return;
    }
    let mut cookies: Vec<(String, String)> = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| {
            c.split(';')
                .filter_map(|kv| {
                    let kv = kv.trim();
                    match kv.split_once('=') {
                        Some((k, v)) => Some((k.trim().to_string(), v.to_string())),
                        None => (!kv.is_empty()).then(|| (kv.to_string(), String::new())),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    for (name, val) in ops {
        let name = escape_cookie(&name, true);
        // A request cookie is a name and a value; the attribute form's other
        // fields have nowhere to go in a `Cookie` header, and upstream drops
        // them here too.
        let val = escape_cookie(&val.plain(), false);
        match cookies.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = val,
            None => cookies.push((name, val)),
        }
    }

    let joined = cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    set_header(headers, "cookie", &joined);
}

/// The `Set-Cookie` entries that delete a cookie in the client
/// (`parseDelResCookies`, `_original/lib/util/index.js:2776-2795`).
///
/// A response cannot remove a cookie the client already holds; it can only send
/// one back that has already expired. whistle sends **two** per name — plain and
/// `Secure` — because a `Secure` cookie is not overwritten by a non-`Secure` one
/// of the same name, and it cannot tell which kind is out there.
///
/// `host` adds two more, scoped to the parent domain, for a cookie that was set
/// on `.example.com` rather than on the host itself. Upstream reads
/// `req._w2hostname`, which every request carries: it is the `Host` header's
/// hostname, stamped before any rule runs (`_original/biz/index.js:40`).
pub(super) fn expiring_cookies(names: &[String], host: Option<&str>) -> Vec<(String, CookieValue)> {
    let expired = |secure: bool, domain: Option<&str>| {
        let mut map = serde_json::Map::new();
        map.insert("maxAge".into(), serde_json::json!(EXPIRED_MAX_AGE));
        map.insert("path".into(), serde_json::json!("/"));
        if secure {
            map.insert("secure".into(), serde_json::json!(true));
        }
        if let Some(d) = domain {
            map.insert("domain".into(), serde_json::json!(d));
        }
        CookieValue::Attrs(map)
    };
    let domain = host.and_then(parent_domain);
    names
        .iter()
        .map(|name| {
            let mut list = vec![expired(false, None), expired(true, None)];
            if let Some(d) = &domain {
                list.push(expired(false, Some(d)));
                list.push(expired(true, Some(d)));
            }
            (name.clone(), CookieValue::List(list))
        })
        .collect()
}

/// The domain a cookie on this host may have been scoped to (`getDomain`,
/// `_original/lib/util/index.js:2758-2774`).
///
/// Fewer than three labels has no parent worth naming, so `example.com` gets
/// nothing. Exactly three keeps the leading dot (`.example.com`, written by
/// emptying the first label); more drops the first label outright
/// (`a.b.example.com` → `b.example.com`).
pub(super) fn parent_domain(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    match labels.len() {
        0..=2 => None,
        3 => Some(format!(".{}", labels[1..].join("."))),
        _ => Some(labels[1..].join(".")),
    }
}

/// Emit `Set-Cookie` headers for `resCookies` operators, **replacing** any the
/// response already sent under the same name rather than adding a second one.
pub(super) fn apply_res_cookies(
    headers: &mut HeaderMap,
    resolved: &Resolved,
    del: &Deletions,
    info: Option<&ReqInfo>,
) {
    let mut ops = merge_cookie_ops(resolved, "resCookies");
    // A `delete://resCookies.x` becomes an expiring cookie, and it *wins* over
    // a `resCookies://x=…` on the same request: upstream folds the deletions in
    // with `extend(cookies, delKeys)`, so they overwrite (`index.js:3127-3129`).
    if !del.cookies.is_empty() {
        for (name, value) in expiring_cookies(&del.cookies, info.map(|i| i.host.as_str())) {
            match ops.iter_mut().find(|(k, _)| *k == name) {
                Some(slot) => slot.1 = value,
                None => ops.push((name, value)),
            }
        }
    }
    if ops.is_empty() {
        return;
    }
    // Grouped by name, because one name may hold several `Set-Cookie` lines —
    // both in what the response already sent and in what a rule asks for
    // (`addMapArr`, `_original/lib/util/index.js:3119-3123`). A rule replaces a
    // name's whole group rather than one line of it, which is upstream's
    // `extend(curData, result)`.
    let mut existing: Vec<(String, Vec<String>)> = Vec::new();
    for cookie in headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        let name = cookie.split('=').next().unwrap_or(cookie).to_string();
        match existing.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1.push(cookie.to_string()),
            None => existing.push((name, vec![cookie.to_string()])),
        }
    }

    for (name, val) in ops {
        let name = escape_cookie(&name, true);
        let lines = match &val {
            CookieValue::List(items) => items.iter().map(|v| cookie_item(&name, v)).collect(),
            _ => vec![cookie_item(&name, &val)],
        };
        match existing.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = lines,
            None => existing.push((name, lines)),
        }
    }

    headers.remove(hyper::header::SET_COOKIE);
    for (_, lines) in existing {
        for cookie in lines {
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                headers.append(hyper::header::SET_COOKIE, v);
            }
        }
    }
}

/// Percent-encode what may not appear in a cookie name or value
/// (`escapeName`/`escapeValue`, `_original/lib/util/index.js:3029-3050`). A name
/// may not carry `=` either.
pub(super) fn escape_cookie(s: &str, is_name: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let forbidden =
            matches!(c, '\r' | '\n' | ';' | '%') || (c as u32) > 0xFF || (is_name && c == '=');
        if !forbidden {
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
