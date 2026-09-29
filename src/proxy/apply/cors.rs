//! CORS: `reqCors://` and `resCors://` (and `enable://cors`), how their lines
//! fold, and the headers they write — including the preflight answer.

use super::*;

/// `reqCors://…` — the request half of whistle's CORS negotiation
/// (`setReqCors`, `_original/lib/util/index.js:2899-2921`).
///
/// The value takes the same four shorthand spellings as `resCors` and folds the
/// same way, but only three of the resulting keys mean anything on a request:
/// `origin` (a URL, reduced to its origin, or `*`), `method` and `headers`,
/// which become the two preflight headers. Notably `enable` sets **nothing** —
/// there is no request origin to echo back — so `reqCors://enable` is inert
/// upstream, and is here.
pub(super) fn apply_req_cors(headers: &mut HeaderMap, resolved: &Resolved) {
    let spec = merge_cors_ops(resolved, "reqCors");
    if spec.is_empty() {
        return;
    }
    match spec.get("origin").map(String::as_str) {
        Some("*") => set_header(headers, "origin", "*"),
        Some(url) if is_http_url(url) => set_header(headers, "origin", &parse_origin(url)),
        // `cors['*'] === ''` — the `resCors://*` shorthand — is the other way
        // to ask for a wildcard origin.
        _ if spec.get("*").is_some_and(String::is_empty) => set_header(headers, "origin", "*"),
        _ => {}
    }
    if let Some(method) = spec.get("method") {
        set_header(headers, "access-control-request-method", method);
    }
    if let Some(list) = spec.get("headers") {
        set_header(headers, "access-control-request-headers", list);
    }
}

/// `resCors://…` — the response half of whistle's CORS negotiation
/// (`setResCors`, `_original/lib/util/index.js:2923-2975`).
///
/// The value has four shorthand spellings before it is read as JSON or as a
/// query string (`readRuleList`, `_original/lib/util/index.js:1346-1356`): a
/// URL is an explicit origin, `*` is the wildcard, and `enable`/`credentials`/
/// `use-credentials` turn on echoing the request's own `Origin` with
/// credentials. `resCors://{"methods":"GET,POST","maxAge":600}` spells out the
/// rest.
///
/// Without `info` the request-dependent half is skipped: the origin cannot be
/// echoed and a preflight cannot be recognised.
pub(super) fn apply_res_cors(headers: &mut HeaderMap, resolved: &Resolved, info: Option<&ReqInfo>) {
    let mut spec = merge_cors_ops(resolved, "resCors");
    // whistle has no `enable://cors`; whistle-rs keeps it as an alias for
    // `resCors://enable` so existing rule files still mean something, rather
    // than blasting `*` at every header as it used to.
    if spec.is_empty() && enabled_flags(resolved).contains("cors") {
        spec.insert("enable".to_string(), "true".to_string());
    }
    if spec.is_empty() {
        return;
    }
    write_res_cors(headers, &spec, info);
}

/// Write the CORS headers a resolved spec asks for.
///
/// Split out of [`apply_res_cors`] so the automatic CORS a local-file response
/// carries can reuse it — that is `setResCors(reader, {enable: true}, req)`
/// upstream (`_original/lib/handlers/file-proxy.js:187`), the very same writer
/// with a spec nobody typed.
pub(super) fn write_res_cors(
    headers: &mut HeaderMap,
    spec: &HashMap<String, String>,
    info: Option<&ReqInfo>,
) {
    let custom_origin = match spec.get("origin").map(String::as_str) {
        Some("*") => Some("*".to_string()),
        Some(url) if is_http_url(url) => Some(parse_origin(url)),
        _ => None,
    };
    let is_enable = spec.contains_key("enable");
    let is_star = spec.get("*").is_some_and(String::is_empty);
    let is_options = info.is_some_and(|i| i.method.eq_ignore_ascii_case("OPTIONS"));

    if custom_origin.is_some() || is_enable {
        let origin = custom_origin.or_else(|| req_header(info, "origin").map(str::to_string));
        if let Some(origin) = origin.filter(|o| !o.is_empty()) {
            set_header(headers, "access-control-allow-credentials", "true");
            set_header(headers, "access-control-allow-origin", &origin);
        }
    } else if is_star {
        set_header(headers, "access-control-allow-origin", "*");
    }

    if let Some(methods) = spec.get("methods") {
        set_header(headers, "access-control-allow-methods", methods);
    }
    // On a preflight, `enable`/`*` fill the headers in from the request.
    let auto = is_options && (is_star || is_enable);
    if let Some(list) = spec.get("headers") {
        let op = if is_options { "allow" } else { "expose" };
        set_header(headers, &format!("access-control-{op}-headers"), list);
    } else if auto && let Some(list) = req_header(info, "access-control-request-headers") {
        set_header(headers, "access-control-allow-headers", list);
    }
    if let Some(credentials) = spec.get("credentials") {
        set_header(headers, "access-control-allow-credentials", credentials);
    } else if auto && let Some(method) = req_header(info, "access-control-request-method") {
        // Plural. This was singular here, with a comment calling it upstream's
        // typo — upstream has no such typo (`setResCors`,
        // `_original/lib/util/index.js:2967`, is plural in both of its two
        // branches, and the singular form appears nowhere in its tree). The
        // singular name is not a CORS header at all, so no browser reads it:
        // a preflight answered by `resCors://enable` was missing the one header
        // that lets the real request follow, and the operator looked inert.
        set_header(headers, "access-control-allow-methods", method);
    }
    if let Some(max_age) = spec.get("maxage") {
        set_header(headers, "access-control-max-age", max_age);
    }
}

/// Collapse every line of a CORS protocol into one option map.
///
/// The same `parseRuleJson` fold as headers and cookies, with a key contested
/// by two lines taken from the **first**. The keys are looked up by name below,
/// never walked in order, so unlike [`merge_line_maps`] this can stay a
/// `HashMap`: extending in reverse line order leaves the first line's value in
/// place, which is what upstream's `result.reverse()` + `extend` produces
/// (`_original/lib/util/index.js:1305-1316`).
pub(super) fn merge_cors_ops(resolved: &Resolved, protocol: &str) -> HashMap<String, String> {
    let mut spec: HashMap<String, String> = HashMap::new();
    for op in resolved.all(protocol).iter().rev() {
        spec.extend(parse_cors(&op.value, op.value_is_content));
    }
    spec
}

/// Parse one `resCors` value into whistle's lower-cased option map.
///
/// After the four shortcut spellings the value is an ordinary data object, so
/// it takes the same three roads as any other ([`parse_data_object`]) — the
/// third of which is the **line format**, which is how `resCors.md` spells out
/// a full CORS object:
///
/// ````txt
/// ``` cors.json
/// origin: *
/// methods: POST
/// ```
/// ````
///
/// That did nothing here: this had JSON and a query string and stopped.
pub(super) fn parse_cors(value: &str, is_content: bool) -> HashMap<String, String> {
    let trimmed = value.trim();
    let one = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
    if GEN_URL_RE.is_match(trimmed) {
        return one("origin", trimmed);
    }
    if trimmed == "*" {
        return one("*", "");
    }
    if ["enable", "use-credentials", "usecredentials", "credentials"]
        .contains(&trimmed.to_ascii_lowercase().as_str())
    {
        return one("enable", "true");
    }
    let Some(serde_json::Value::Object(map)) = parse_data_object(trimmed, false, is_content) else {
        return HashMap::new();
    };
    map.into_iter()
        .map(|(k, v)| {
            let v = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (k.trim().to_ascii_lowercase(), v)
        })
        .collect()
}

/// One request header, if the request is known. Names in [`ReqInfo`] are
/// already lower-cased.
pub(super) fn req_header<'a>(info: Option<&'a ReqInfo>, name: &str) -> Option<&'a str> {
    info?
        .headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// `HTTP_RE`, `_original/lib/util/common.js:57`.
pub(super) fn is_http_url(value: &str) -> bool {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    rest.is_some_and(|r| !r.starts_with(['/', '?']) && !r.is_empty())
}

/// Trim a URL down to its origin (`parseOrigin`,
/// `_original/lib/util/index.js:2884-2896`).
pub(super) fn parse_origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("//") else {
        return url.to_string();
    };
    match rest.find('/') {
        Some(i) => format!("{scheme}//{}", &rest[..i]),
        None => url.to_string(),
    }
}
