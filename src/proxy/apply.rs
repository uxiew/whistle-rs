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
use super::upstream::Target;
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

    Target {
        connect_host,
        connect_port,
        tls: info.scheme == "https" || info.scheme == "wss",
        sni: info.host.clone(),
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
    apply_req_cookies(&mut parts.headers, resolved);
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
    apply_res_cookies(&mut parts.headers, resolved);
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
