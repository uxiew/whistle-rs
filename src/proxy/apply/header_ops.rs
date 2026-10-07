//! The header operators: `reqHeaders://` and `resHeaders://`, how their lines
//! fold into one map, and how a value is written into a `HeaderMap` — set,
//! appended, or merged into `Set-Cookie`.

use super::*;

/// Apply every value of a header multi-match protocol.
///
/// The lines are collapsed into **one** map first ([`merge_line_maps`]), so a
/// header named on two lines takes the first line's value — see that function
/// for why the fold, not a top-to-bottom apply, is what upstream does.
pub(super) fn apply_header_ops(headers: &mut HeaderMap, resolved: &Resolved, protocol: &str) {
    let mut ops = merge_header_ops(resolved, protocol);
    // `set-cookie` is not assigned like the others: upstream lifts it out of
    // `data.headers` and *merges* it with what the response already sent
    // (`setCookies`, `_original/lib/inspectors/res.js:89-122`, run at `:926`
    // just before the `extend`), then deletes the key so the extend cannot
    // clobber the result. Overwriting instead dropped every other cookie the
    // origin set — the session cookie next to the one the rule named.
    if protocol == "resHeaders"
        && let Some(i) = ops
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        && merge_set_cookies(headers, &ops[i].1)
    {
        ops.remove(i);
    }
    for (name, values) in ops {
        for (i, value) in values.iter().enumerate() {
            // A JSON array is several headers of the same name, which is what
            // Node does with `headers[name] = ['a', 'b']`.
            match i {
                0 => assign_header(headers, &name, value),
                _ => append_header(headers, &name, value),
            }
        }
    }
}

/// `setCookies` (`_original/lib/inspectors/res.js:89-122`) — fold a `set-cookie`
/// written on `resHeaders://` into the response's own.
///
/// The rule's cookies come first, then every origin cookie whose **name** the
/// rule did not also name. So a rule setting `sid` replaces the origin's `sid`
/// and leaves its `csrf` alone; assigning the header instead would have thrown
/// the `csrf` away, and a login flow with it.
///
/// Returns whether the merge consumed the key. It does not when there is
/// nothing to merge — upstream returns before its `delete data.headers[…]`,
/// leaving the key for the `extend` to assign like any other header, so
/// `resHeaders://set-cookie=` does send one empty `Set-Cookie`.
pub(super) fn merge_set_cookies(headers: &mut HeaderMap, values: &HeaderValues) -> bool {
    let mut cookies: Vec<String> = match values {
        // A plain string is split on commas — `newCookies.split(',')`
        // (`res.js:95`), which is how `resHeaders://set-cookie=a=1,b=2` becomes
        // two cookies. It is also why an `Expires=Wed, 21 Oct …` attribute has
        // to be written in the JSON array form, upstream and here.
        HeaderValues::One(s) if s.is_empty() => return false,
        HeaderValues::One(s) => s.split(',').map(str::to_string).collect(),
        HeaderValues::Many(items) => items.clone(),
    };
    if cookies.is_empty() {
        return false;
    }
    // A cookie with no `=` is keyed on its whole text. Upstream keys it on the
    // string `"undefined"` instead — `var name = index == -1 ? name : …` reads
    // the variable it is declaring — so two different attribute-less cookies
    // collide there. Not reproduced: that is a name collision, not a rule.
    let name_of = |c: &str| c.split_once('=').map_or(c, |(n, _)| n).to_string();
    let claimed: Vec<String> = cookies.iter().map(|c| name_of(c)).collect();
    for existing in headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        if !claimed.contains(&name_of(existing)) {
            cookies.push(existing.to_string());
        }
    }
    headers.remove(hyper::header::SET_COOKIE);
    for cookie in cookies {
        append_header(headers, "set-cookie", &cookie);
    }
    true
}

/// Add a header without replacing one already there.
pub(super) fn append_header(headers: &mut HeaderMap, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.append(name, v);
    }
}

/// What one header operator says a header should be.
///
/// The two shapes are kept apart on purpose even when the list holds one
/// element: `setCookies` splits a plain string on commas and never splits an
/// array (`_original/lib/inspectors/res.js:91-96`), so
/// `resHeaders://set-cookie=a=1,b=2` is two cookies and
/// `resHeaders://{"set-cookie":["a=1,b=2"]}` is one.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum HeaderValues {
    One(String),
    /// The JSON array spelling, which Node writes as one header line per
    /// element.
    Many(Vec<String>),
}

impl HeaderValues {
    /// Add another value under the same name, promoting a single one to a list.
    pub(super) fn push(&mut self, value: String) {
        match self {
            HeaderValues::One(first) => {
                *self = HeaderValues::Many(vec![std::mem::take(first), value]);
            }
            HeaderValues::Many(all) => all.push(value),
        }
    }

    pub(super) fn iter(&self) -> std::slice::Iter<'_, String> {
        match self {
            HeaderValues::One(s) => std::slice::from_ref(s).iter(),
            HeaderValues::Many(items) => items.iter(),
        }
    }
}

/// Collapse every line of a header protocol into one ordered `name` → `value`
/// map, first line winning a contested name.
pub(super) fn merge_header_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, HeaderValues)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_header_pairs(&op.value, op.value_is_content)),
    )
}

/// Parse one header operator value into `name` → `value` pairs: `{json}`, or a
/// query string of `name=value` pairs (`resHeaders://x-a=1&x-b=2` is two
/// headers, as `parseQuery` has it). The `name:value` spelling is a whix
/// convenience, not upstream syntax.
///
/// A value is a *list* because the JSON spelling may give one: upstream assigns
/// the array straight onto the header map, and Node then writes one header line
/// per element. Every other spelling produces a list of one.
pub(super) fn parse_header_pairs(value: &str, is_content: bool) -> Vec<(String, HeaderValues)> {
    let value = value.trim();
    if value.starts_with('{')
        && let Some(map) = crate::rules::url::parse_json(value).and_then(|v| match v {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        })
    {
        return map
            .into_iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => (k, HeaderValues::One(s)),
                serde_json::Value::Array(items) => (
                    k,
                    HeaderValues::Many(items.iter().map(json_header_value).collect()),
                ),
                other => (k, HeaderValues::One(other.to_string())),
            })
            .collect();
    }
    // The query-string spelling, and **only** when the value has no whitespace
    // in it: `parseInlineJSON` returns early on `SPACE_RE.test(text)`
    // (`_original/lib/util/index.js:1128-1133`), which is what keeps `x-a: v=1`
    // out of this branch. It used to reach it here and split at the `=`, giving
    // a header named `x-a: v`.
    if !is_content && !value.contains('=') {
        return Vec::new();
    }
    // Loaded content takes the query road on **whitespace alone** — an `=` is
    // not required, because `parseInlineJSON` only asks `SPACE_RE.test(text)`
    // (`_original/lib/util/index.js:1128-1133`) and `querystring.parse` reads a
    // bare entry as a key with an empty value. That is the difference between
    // a block holding `solo:` naming the header `solo:` — which is not a token,
    // so both proxies send nothing — and splitting it at the colon into a
    // header named `solo`, which is what this port used to send.
    if (is_content && !value.contains(char::is_whitespace)) || (value.contains('=') && !is_content)
    {
        // A name repeated in one value is a *list*, not a contest: Node's
        // `querystring.parse("a=1&a=2")` yields `{a: ["1","2"]}`, whistle
        // assigns that array onto the header map, and Node writes one header
        // line per element. Folding to the last value here sent one header
        // where whistle sends two, which for `set-cookie` or `accept` is the
        // difference between the rule working and half of it vanishing.
        let mut out: Vec<(String, HeaderValues)> = Vec::new();
        // An entry with no `=` is a name with an empty value, which is what
        // `querystring.parse` gives it — dropping it here meant a block holding
        // one bare name set no header where whistle sets an empty one.
        for pair in value.split('&').filter(|pair| !pair.is_empty()) {
            let (name, val) = pair.split_once('=').unwrap_or((pair, ""));
            let (name, val) = (name.trim().to_string(), val.trim().to_string());
            match out.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(val),
                None => out.push((name, HeaderValues::One(val))),
            }
        }
        return out;
    }
    // The line format, one `name: value` per line. This used to be a one-line
    // special case that only ever produced a single pair, so a `{value}` holding
    // three headers set none of them — the shape every data-operator page shows
    // under 行格式. Names are trimmed here, deliberately unlike upstream: a
    // header name with a trailing space is not a valid token and hyper rejects
    // it, so keeping the space faithfully would turn the operator into a silent
    // no-op. Upstream's own `setHeader` throws on it.
    let Some(serde_json::Value::Object(map)) = parse_plain_text(value, false) else {
        return Vec::new();
    };
    map.into_iter()
        .map(|(name, v)| {
            let text = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (name.trim().to_string(), HeaderValues::One(text))
        })
        .collect()
}

/// One element of a JSON header array as it reaches the wire: a string as
/// itself, anything else as JS would stringify it into a header slot.
pub(super) fn json_header_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Assign a header, **including** an empty value.
///
/// The header operators are an assignment upstream, not a conditional one —
/// `extend(req.headers, data.headers)` (`_original/lib/inspectors/req.js:105`)
/// and `extend(_resHeaders, data.headers)` (`res.js:927`) — so
/// `reqHeaders://x-a=` sends `X-A:` with nothing after it. Removing the header
/// instead is a different rule, spelled `delete://reqHeaders.x-a`, and the two
/// are not interchangeable: a server that branches on a header's *presence*
/// sees the opposite of what was asked for.
pub(super) fn assign_header(headers: &mut HeaderMap, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Set (replace) a header this proxy writes itself; an empty value removes it.
///
/// This is the right rule for the headers whistle *computes* — the one place it
/// is explicit is `pragma`, which upstream deletes when the value it worked out
/// is falsy (`if (!_resHeaders.pragma) delete _resHeaders.pragma`,
/// `_original/lib/inspectors/res.js:940-942`). It is the **wrong** rule for a
/// value a rule supplied: see [`assign_header`].
pub(super) fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if value.is_empty() {
        headers.remove(&name);
        return;
    }
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Apply `headerReplace://` operators for one side.
///
/// The value is a JSON object keyed `"<scope>.<name>:<pattern>"`, where the
/// scope is exactly `req.`/`reqH.` or `res.`/`resH.` — upstream tests those four
/// prefixes literally (`parseHeaderReplace`,
/// `_original/lib/util/index.js:2219-2223`), so `reqHeaders.` is not one of
/// them. The pattern follows the same rule as the body operators: `/…/flags` is
/// a regular expression, anything else is a literal.
pub(super) fn apply_header_replace(
    headers: &mut HeaderMap,
    resolved: &Resolved,
    want: HeaderScope,
) {
    let want = want.key();
    for value in collect_values(resolved, "headerReplace") {
        // Order matters here, and `serde_json::Map` sorts: a key with no scope
        // prefix inherits the *previous* key's scope, so the entries have to be
        // seen in the order they were written.
        let Some(entries) = ordered_pairs(value.trim()) else {
            continue;
        };
        // Carried over from the last key that named a scope — *both* the scope
        // and the header name, which is the quirk: upstream writes
        // `name = name || key.substring(…)`, and only a key that named a scope
        // resets `name` to null. So an unscoped key reuses the previous key's
        // header name and contributes nothing but its own pattern.
        //
        // Both start unset, which is upstream's `else if (!prop) return`: a
        // leading unscoped key is dropped rather than defaulting to a side.
        let mut carried: Option<(&str, String)> = None;
        for (key, repl) in &entries {
            let repl = repl.as_str().unwrap_or("");
            // The five prefixes upstream recognises, and the only ones: a
            // `resHeaders.` key matches none of them and is inert.
            let named = [
                ("req.", "req"),
                ("reqH.", "req"),
                ("res.", "res"),
                ("resH.", "res"),
                ("trailer.", "trailer"),
            ]
            .into_iter()
            .find(|(prefix, _)| key.starts_with(prefix))
            .map(|(_, s)| s);
            let colon = key.find(':');
            let (scope, name) = match named {
                // This key names its own scope, so the prefix is sliced off and
                // the name is taken from it. With no `:` that slice is empty
                // (`substring(dot + 1, -1)`), and upstream's `if (!name) return`
                // drops the key.
                Some(scope) => {
                    let Some(colon) = colon else {
                        continue;
                    };
                    let name = key[key.find('.').map(|i| i + 1).unwrap_or(0)..colon].trim();
                    if name.is_empty() {
                        continue;
                    }
                    carried = Some((scope, name.to_string()));
                    (scope, name.to_string())
                }
                // It does not, so it inherits — and its own name portion is
                // ignored entirely, however it is spelled.
                None => match &carried {
                    Some((scope, name)) => (*scope, name.clone()),
                    None => continue,
                },
            };
            if scope != want {
                continue;
            }
            let name = name.as_str();
            // `key.substring(index + 1)`, and `index` is `-1` when there is no
            // colon — so the **whole key** is the pattern. That is what makes
            // the documented `res.x:p1=v1&p2=v2` two substitutions on one
            // header: the second entry is a bare pattern inheriting the first
            // entry's scope and name.
            let pattern = match colon {
                Some(colon) => &key[colon + 1..],
                None => key.as_str(),
            };
            replace_in_header(headers, name, pattern, repl);
        }
    }
}

/// One `headerReplace` substitution on one header, however many times it
/// appears — `handleHeaderReplace` (`_original/lib/util/index.js:2274-2292`).
///
/// Node hands upstream a repeated header in one of two shapes, and the
/// substitution follows the shape: `set-cookie` stays a list and each entry is
/// rewritten on its own; any other name arrives already joined (`, `, or `; `
/// for `cookie`) and is rewritten — and written back — as that one string.
/// This port used to rewrite the first `set-cookie` and drop the rest, which
/// upstream's `plugin.test.js` caught with two cookies in and one out.
///
/// An absent or empty header is left alone.
pub(super) fn replace_in_header(headers: &mut HeaderMap, name: &str, pattern: &str, repl: &str) {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    if values.iter().all(String::is_empty) {
        return;
    }
    if name.eq_ignore_ascii_case("set-cookie") {
        remove_header(headers, name);
        for value in values {
            append_header(headers, name, &replace_once_or_all(&value, pattern, repl));
        }
        return;
    }
    let separator = if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    };
    let joined = values.join(separator);
    set_header(headers, name, &replace_once_or_all(&joined, pattern, repl));
}

/// Which set of headers a `headerReplace://` key addresses.
///
/// Upstream keys these by string (`result.req` / `result.res` / `result.trailer`,
/// `_original/lib/util/index.js:2207-2254`) and applies each set where those
/// headers exist: the request head, the response head, and the trailers that go
/// out after the body (`res.js:945,:1281`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HeaderScope {
    Request,
    Response,
    Trailer,
}

impl HeaderScope {
    /// The scope name upstream's keys carry.
    pub(super) fn key(self) -> &'static str {
        match self {
            HeaderScope::Request => "req",
            HeaderScope::Response => "res",
            HeaderScope::Trailer => "trailer",
        }
    }
}
