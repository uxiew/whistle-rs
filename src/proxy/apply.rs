//! Translate resolved rules into concrete request/response mutations.
//!
//! Ported from the request/response inspectors in `_original/lib/inspectors/`
//! (`req.js`, `res.js`) and the handlers. Implements the most-used operators;
//! others parse and resolve but are not yet applied (documented in README).

use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request;
use hyper::http::response;
use hyper::{HeaderMap, Response, StatusCode};

use super::body::{self, DynBody};
use super::upstream::{ProxyKind, Target, parse_proxy};
use crate::rules::{ReqInfo, Resolved};

/// Build the request facts the matcher needs.
pub fn build_req_info(
    method: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> ReqInfo {
    let host = host.to_ascii_lowercase();
    let default_port = if scheme == "https" || scheme == "wss" {
        443
    } else {
        80
    };
    let full_url = if port == default_port {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    };
    ReqInfo {
        method: method.to_string(),
        scheme: scheme.to_string(),
        host,
        port,
        path: path.to_string(),
        full_url,
    }
}

/// Compute the upstream target, honouring `host://` (and `:port`) overrides.
pub fn resolve_target(info: &ReqInfo, resolved: &Resolved) -> Target {
    let mut connect_host = info.host.clone();
    let mut connect_port = info.port;

    if let Some(value) = resolved.value("host") {
        let (h, p) = parse_host_value(value, info.port);
        if let Some(h) = h {
            connect_host = h;
        }
        if let Some(p) = p {
            connect_port = p;
        }
    }

    // First matching proxy operator wins (socks > https-proxy > http-proxy > proxy).
    let proxy = resolved
        .value("socks")
        .and_then(|v| parse_proxy(ProxyKind::Socks, v))
        .or_else(|| {
            resolved
                .value("https-proxy")
                .and_then(|v| parse_proxy(ProxyKind::Https, v))
        })
        .or_else(|| {
            resolved
                .value("http-proxy")
                .and_then(|v| parse_proxy(ProxyKind::Http, v))
        })
        .or_else(|| resolved.value("proxy").and_then(|v| parse_proxy(ProxyKind::Http, v)))
        .or_else(|| {
            resolved
                .value("internal-proxy")
                .and_then(|v| parse_proxy(ProxyKind::Http, v))
        });

    Target {
        connect_host,
        connect_port,
        tls: info.scheme == "https" || info.scheme == "wss",
        sni: info.host.clone(),
        request_port: info.port,
        proxy,
    }
}

/// Parse a `host` operator value (`ip`, `ip:port`, `host:port`, `:port`).
fn parse_host_value(value: &str, _default_port: u16) -> (Option<String>, Option<u16>) {
    let value = value.trim();
    if let Some(port) = value.strip_prefix(':') {
        return (None, port.parse().ok());
    }
    match value.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (Some(h.to_string()), p.parse().ok())
        }
        _ => (Some(value.to_string()), None),
    }
}

/// Short-circuit responses produced without contacting upstream:
/// `redirect`/`location`, mocked `statusCode`, and `file`.
pub fn short_circuit(info: &ReqInfo, resolved: &Resolved) -> Option<Response<DynBody>> {
    if let Some(url) = resolved
        .value("redirect")
        .or_else(|| resolved.value("location"))
    {
        let mut resp = Response::builder()
            .status(StatusCode::FOUND)
            .body(body::empty())
            .unwrap();
        if let Ok(v) = HeaderValue::from_str(url) {
            resp.headers_mut().insert(hyper::header::LOCATION, v);
        }
        return Some(resp);
    }

    if let Some(code) = resolved.value("statusCode") {
        let status = code
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(|c| StatusCode::from_u16(c).ok())
            .unwrap_or(StatusCode::OK);
        return Some(
            Response::builder()
                .status(status)
                .body(body::empty())
                .unwrap(),
        );
    }

    if let Some(path) = resolved.value("file").or_else(|| resolved.value("rawfile")) {
        return Some(serve_file(path, info));
    }

    None
}

/// Serve a local file for `file://` rules.
fn serve_file(path: &str, info: &ReqInfo) -> Response<DynBody> {
    // whistle strips the protocol; here `path` is already the value part.
    let clean = path.trim_start_matches('/');
    let candidates = [path.to_string(), format!("/{clean}")];
    for p in candidates {
        if let Ok(data) = std::fs::read(&p) {
            let ct = guess_content_type(&p);
            return Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, ct)
                .body(body::full(Bytes::from(data)))
                .unwrap();
        }
    }
    let _ = info;
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body::full(Bytes::from_static(b"whistle-rs: file not found")))
        .unwrap()
}

fn guess_content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Apply request-side operators (headers, method, ua, referer) in place.
pub fn apply_request(parts: &mut request::Parts, resolved: &Resolved) {
    apply_header_ops(&mut parts.headers, resolved, "reqHeaders");

    if let Some(ua) = resolved.value("ua") {
        set_header(&mut parts.headers, "user-agent", ua);
    }
    if let Some(referer) = resolved.value("referer") {
        set_header(&mut parts.headers, "referer", referer);
    }
    if let Some(m) = resolved.value("method") {
        if let Ok(method) = m.to_uppercase().parse() {
            parts.method = method;
        }
    }
    if let Some(ct) = resolved.value("reqType") {
        set_header(&mut parts.headers, "content-type", ct);
    }
    if let Some(auth) = resolved.value("auth") {
        // `auth://user:pass` → HTTP Basic Authorization header.
        if !auth.is_empty() {
            let token = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                auth.as_bytes(),
            );
            set_header(&mut parts.headers, "authorization", &format!("Basic {token}"));
        }
    }
    if let Some(xff) = resolved.value("forwardedFor") {
        set_header(&mut parts.headers, "x-forwarded-for", xff);
    }
    apply_req_cookies(&mut parts.headers, resolved);
}

/// Milliseconds to delay before forwarding the request (`reqDelay`).
pub fn req_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved.value("reqDelay").and_then(|v| v.trim().parse().ok())
}

/// Milliseconds to delay before returning the response (`resDelay`).
pub fn res_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved.value("resDelay").and_then(|v| v.trim().parse().ok())
}

/// Apply response-side operators (status replacement, headers) in place.
pub fn apply_response(parts: &mut response::Parts, resolved: &Resolved) {
    if let Some(code) = resolved
        .value("replaceStatus")
        .or_else(|| resolved.value("statusCode"))
    {
        if let Some(status) = code
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(|c| StatusCode::from_u16(c).ok())
        {
            parts.status = status;
        }
    }
    apply_header_ops(&mut parts.headers, resolved, "resHeaders");
    if let Some(ct) = resolved.value("resType") {
        set_header(&mut parts.headers, "content-type", ct);
    }
    if let Some(cors) = resolved.value("resCors") {
        // Minimal CORS: `*` or an explicit origin.
        set_header(&mut parts.headers, "access-control-allow-origin", cors);
    }
    if let Some(name) = resolved.value("attachment") {
        // Force a download; `attachment://` with no name still sets the disposition.
        let disp = if name.is_empty() {
            "attachment".to_string()
        } else {
            format!("attachment; filename=\"{}\"", name.replace('"', ""))
        };
        set_header(&mut parts.headers, "content-disposition", &disp);
    }
    apply_res_cookies(&mut parts.headers, resolved);
}

/// Body operators for a side, keyed by prefix (`req`/`res`): `*Body` (replace),
/// `*Replace` (substring/`/regex/` substitute), `*Prepend`, `*Append`.
fn body_ops_present(resolved: &Resolved, prefix: &str) -> bool {
    ["Body", "Replace", "Prepend", "Append"]
        .iter()
        .any(|s| resolved.value(&format!("{prefix}{s}")).is_some())
}

/// True if any request-body operator applies (so the body must be buffered).
pub fn wants_req_body(resolved: &Resolved) -> bool {
    body_ops_present(resolved, "req")
}

/// True if any response-body operator applies (so the body must be buffered).
pub fn wants_res_body(resolved: &Resolved) -> bool {
    body_ops_present(resolved, "res")
}

/// Transform a buffered request body per the resolved operators.
pub fn transform_req_body(body: Bytes, resolved: &Resolved) -> Bytes {
    transform_body(body, resolved, "req")
}

/// Transform a buffered response body per the resolved operators.
pub fn transform_res_body(body: Bytes, resolved: &Resolved) -> Bytes {
    transform_body(body, resolved, "res")
}

/// Apply `*Body` → `*Replace` → `*Prepend` → `*Append` in that order.
fn transform_body(body: Bytes, resolved: &Resolved, prefix: &str) -> Bytes {
    let mut data: Vec<u8> = match resolved.value(&format!("{prefix}Body")) {
        Some(new) => new.as_bytes().to_vec(),
        None => body.to_vec(),
    };

    if let Some(spec) = resolved.value(&format!("{prefix}Replace")) {
        data = apply_body_replace(data, spec);
    }
    if let Some(pre) = resolved.value(&format!("{prefix}Prepend")) {
        let mut v = pre.as_bytes().to_vec();
        v.extend_from_slice(&data);
        data = v;
    }
    if let Some(app) = resolved.value(&format!("{prefix}Append")) {
        data.extend_from_slice(app.as_bytes());
    }
    Bytes::from(data)
}

/// `*Replace` on a body: `from=to`, literal or `/regex/[i]`. Binary bodies untouched.
fn apply_body_replace(data: Vec<u8>, spec: &str) -> Vec<u8> {
    match String::from_utf8(data) {
        Ok(text) => apply_str_replace(&text, spec).into_bytes(),
        Err(e) => e.into_bytes(), // not UTF-8 text; leave binary body untouched
    }
}

/// Substitute `from=to` in `text`. If `from` is `/regex/[i]`, use a regex; else a
/// literal replace-all. Shared by body `*Replace` and `urlReplace`.
fn apply_str_replace(text: &str, spec: &str) -> String {
    let Some((from, to)) = spec.split_once('=') else {
        return text.to_string();
    };
    if from.starts_with('/') && from.len() > 1 {
        if let Some(end) = from.rfind('/') {
            if end > 0 {
                let body = &from[1..end];
                let flags = &from[end + 1..];
                let pat = if flags.contains('i') {
                    format!("(?i){body}")
                } else {
                    body.to_string()
                };
                if let Ok(re) = regex::Regex::new(&pat) {
                    return re.replace_all(text, to).into_owned();
                }
            }
        }
    }
    text.replace(from, to)
}

/// Rewrite the request path+query per `urlReplace`, `params`, and `urlParams`.
pub fn rewrite_path(path: &str, resolved: &Resolved) -> String {
    let mut p = path.to_string();
    if let Some(spec) = resolved.value("urlReplace") {
        p = apply_str_replace(&p, spec);
    }
    let mut params: Vec<(String, String)> = Vec::new();
    for key in ["params", "urlParams"] {
        for v in collect_values(resolved, key) {
            params.extend(parse_query_pairs(v));
        }
    }
    if !params.is_empty() {
        p = merge_query(&p, &params);
    }
    p
}

/// Parse `k=v&k2=v2` or `{json}` into query pairs.
fn parse_query_pairs(value: &str) -> Vec<(String, String)> {
    let value = value.trim();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            return map
                .into_iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, val)
                })
                .collect();
        }
    }
    value
        .split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Merge `params` into the query string of `path`, overriding same-named keys.
fn merge_query(path: &str, params: &[(String, String)]) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => (path, ""),
    };
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            Some((k.to_string(), v.to_string()))
        })
        .collect();
    for (k, v) in params {
        pairs.retain(|(ek, _)| ek != k);
        pairs.push((k.clone(), v.clone()));
    }
    if pairs.is_empty() {
        return base.to_string();
    }
    let q = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{q}")
}

/// Remove length/encoding headers so hyper recomputes them for a rewritten body.
pub fn strip_length_headers(headers: &mut HeaderMap) {
    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);
}

/// Collect every value for a protocol (multi-match list plus any single).
fn collect_values<'a>(resolved: &'a Resolved, protocol: &str) -> Vec<&'a str> {
    let mut out: Vec<&str> = resolved.all(protocol).iter().map(|o| o.value.as_str()).collect();
    if let Some(op) = resolved.get(protocol) {
        out.push(op.value.as_str());
    }
    out
}

/// Parse `name=value` / bare `name` (delete) / `{json}` into (name, value?) pairs.
/// A `None` value means "delete this cookie".
fn parse_cookie_ops(value: &str) -> Vec<(String, Option<String>)> {
    let value = value.trim();
    let mut out = Vec::new();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            for (k, v) in map {
                let val = match v {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(s) if s.is_empty() => None,
                    serde_json::Value::String(s) => Some(s),
                    other => Some(other.to_string()),
                };
                out.push((k, val));
            }
            return out;
        }
    }
    if let Some(i) = value.find('=') {
        let name = value[..i].trim().to_string();
        let val = value[i + 1..].trim();
        out.push((name, if val.is_empty() { None } else { Some(val.to_string()) }));
    } else if !value.is_empty() {
        out.push((value.to_string(), None));
    }
    out
}

/// Merge `reqCookies` operators into the request `Cookie` header.
fn apply_req_cookies(headers: &mut HeaderMap, resolved: &Resolved) {
    let ops = collect_values(resolved, "reqCookies");
    if ops.is_empty() {
        return;
    }
    // Existing cookies as an ordered list.
    let mut cookies: Vec<(String, String)> = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| {
            c.split(';')
                .filter_map(|kv| {
                    let (k, v) = kv.trim().split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    for value in ops {
        for (name, val) in parse_cookie_ops(value) {
            cookies.retain(|(k, _)| *k != name);
            if let Some(v) = val {
                cookies.push((name, v));
            }
        }
    }

    if cookies.is_empty() {
        headers.remove(hyper::header::COOKIE);
    } else {
        let joined = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(v) = HeaderValue::from_str(&joined) {
            headers.insert(hyper::header::COOKIE, v);
        }
    }
}

/// Emit `Set-Cookie` headers for `resCookies` operators.
fn apply_res_cookies(headers: &mut HeaderMap, resolved: &Resolved) {
    for value in collect_values(resolved, "resCookies") {
        for (name, val) in parse_cookie_ops(value) {
            let sc = match val {
                Some(v) => format!("{name}={v}"),
                None => format!("{name}=; Max-Age=0"),
            };
            if let Ok(v) = HeaderValue::from_str(&sc) {
                headers.append(hyper::header::SET_COOKIE, v);
            }
        }
    }
}

/// Apply every value of a header multi-match protocol.
/// Supports `name=value`, `name:value`, and a JSON object of pairs.
fn apply_header_ops(headers: &mut HeaderMap, resolved: &Resolved, protocol: &str) {
    for op in resolved.all(protocol) {
        apply_header_value(headers, &op.value);
    }
    // Also honour a single-match instance if present.
    if let Some(op) = resolved.get(protocol) {
        apply_header_value(headers, &op.value);
    }
}

fn apply_header_value(headers: &mut HeaderMap, value: &str) {
    let value = value.trim();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    set_header(headers, &k, s);
                } else {
                    set_header(headers, &k, &v.to_string());
                }
            }
            return;
        }
    }
    let (name, val) = if let Some(i) = value.find('=') {
        (&value[..i], &value[i + 1..])
    } else if let Some(i) = value.find(':') {
        (&value[..i], &value[i + 1..])
    } else {
        return;
    };
    set_header(headers, name.trim(), val.trim());
}

/// Set (replace) a header; empty value removes it. whistle treats empty as delete.
fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleManager;

    fn resolve(rules: &str, url: &str) -> Resolved {
        let mut m = RuleManager::new();
        m.set_text(rules);
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let info = build_req_info("GET", scheme, host, if scheme == "https" { 443 } else { 80 }, path);
        m.resolve(&info)
    }

    #[test]
    fn req_cookies_merge_and_delete() {
        let resolved = resolve(
            "example.com reqCookies://a=1\nexample.com reqCookies://b=2\nexample.com reqCookies://old\n",
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::COOKIE, "old=x; keep=y".parse().unwrap());
        apply_req_cookies(&mut headers, &resolved);
        let cookie = headers.get(hyper::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("keep=y"));
        assert!(cookie.contains("a=1"));
        assert!(cookie.contains("b=2"));
        assert!(!cookie.contains("old="));
    }

    #[test]
    fn res_body_replaced() {
        let resolved = resolve("example.com/x resBody://NEW\n", "http://example.com/x");
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(Bytes::from_static(b"OLD"), &resolved);
        assert_eq!(&out[..], b"NEW");
    }

    #[test]
    fn res_body_prepend_append_replace() {
        let resolved = resolve(
            "example.com/x resPrepend://<!--top-->\nexample.com/x resAppend://<!--end-->\nexample.com/x resReplace://foo=bar\n",
            "http://example.com/x",
        );
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(Bytes::from_static(b"a foo b"), &resolved);
        assert_eq!(&out[..], b"<!--top-->a bar b<!--end-->");
    }

    #[test]
    fn res_body_regex_replace() {
        let resolved = resolve("example.com/x resReplace:///\\d+/=N\n", "http://example.com/x");
        let out = transform_res_body(Bytes::from_static(b"id=123 and 45"), &resolved);
        assert_eq!(&out[..], b"id=N and N");
    }

    #[test]
    fn req_body_replaced_only_when_present() {
        let none = resolve("example.com host://1.1.1.1\n", "http://example.com/");
        assert!(!wants_req_body(&none));
        let some = resolve("example.com reqBody://HELLO\n", "http://example.com/");
        assert!(wants_req_body(&some));
        let out = transform_req_body(Bytes::from_static(b"orig"), &some);
        assert_eq!(&out[..], b"HELLO");
    }

    #[test]
    fn auth_and_forwarded_for() {
        let resolved = resolve(
            "example.com auth://user:pass\nexample.com forwardedFor://9.9.9.9\n",
            "http://example.com/",
        );
        let mut parts = hyper::Request::builder()
            .uri("http://example.com/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        apply_request(&mut parts, &resolved);
        assert_eq!(
            parts.headers.get("authorization").unwrap(),
            "Basic dXNlcjpwYXNz"
        );
        assert_eq!(parts.headers.get("x-forwarded-for").unwrap(), "9.9.9.9");
    }

    #[test]
    fn delay_parsing() {
        let resolved = resolve("example.com reqDelay://250\nexample.com resDelay://40\n", "http://example.com/");
        assert_eq!(req_delay_ms(&resolved), Some(250));
        assert_eq!(res_delay_ms(&resolved), Some(40));
    }

    #[test]
    fn url_replace_and_params() {
        let resolved = resolve(
            "example.com/api urlReplace://v1=v2\nexample.com/api params://token=abc\n",
            "http://example.com/api/v1/users?a=1",
        );
        let out = rewrite_path("/api/v1/users?a=1", &resolved);
        assert!(out.starts_with("/api/v2/users?"));
        assert!(out.contains("a=1"));
        assert!(out.contains("token=abc"));
    }

    #[test]
    fn params_override_existing_key() {
        let resolved = resolve("example.com params://a=2\n", "http://example.com/p?a=1&b=3");
        let out = rewrite_path("/p?a=1&b=3", &resolved);
        assert!(out.contains("b=3"));
        assert!(out.contains("a=2"));
        assert!(!out.contains("a=1"));
    }

    #[test]
    fn res_cookies_set() {
        let resolved = resolve("example.com resCookies://sid=abc\n", "http://example.com/");
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved);
        let vals: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(vals.iter().any(|v| v == "sid=abc"));
    }
}
