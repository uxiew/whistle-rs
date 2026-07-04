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
