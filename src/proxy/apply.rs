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

use std::collections::HashMap;

use super::body::{self, DynBody};
use super::upstream::{ProxyKind, Target, parse_proxy};
use crate::rules::{ReqInfo, Resolved, RuleManager};

/// Build the request facts the matcher needs.
pub fn build_req_info(
    method: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &HeaderMap,
    client_ip: Option<String>,
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
    let hdrs = headers
        .iter()
        .map(|(n, v)| (n.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();
    ReqInfo {
        method: method.to_string(),
        scheme: scheme.to_string(),
        host,
        port,
        path: path.to_string(),
        full_url,
        headers: hdrs,
        client_ip,
    }
}

/// Replace operator values of the form `{name}` with the named value's content
/// (whistle's Values store references).
pub fn substitute_values(resolved: &mut Resolved, values: &HashMap<String, String>) {
    fn sub(value: &mut String, values: &HashMap<String, String>) {
        if let Some(name) = value.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if let Some(content) = values.get(name) {
                *value = content.clone();
            }
        }
    }
    for op in resolved.single.values_mut() {
        sub(&mut op.value, values);
    }
    for list in resolved.multi.values_mut() {
        for op in list {
            sub(&mut op.value, values);
        }
    }
}

/// Substitute whistle config variables `${port}` / `${version}` (case-insensitive)
/// anywhere in operator values. Ported from `CONFIG_VAR_RE` in the original util.
pub fn substitute_config_vars(resolved: &mut Resolved, port: u16, version: &str) {
    let port = port.to_string();
    let sub = |value: &mut String| {
        if !value.contains("${") {
            return;
        }
        *value = replace_ci(value, "${port}", &port);
        *value = replace_ci(value, "${version}", version);
    };
    for op in resolved.single.values_mut() {
        sub(&mut op.value);
    }
    for list in resolved.multi.values_mut() {
        for op in list {
            sub(&mut op.value);
        }
    }
}

/// Case-insensitive replace-all of `needle` with `repl`. `needle` is matched
/// ignoring ASCII case; the replacement is inserted verbatim.
fn replace_ci(haystack: &str, needle: &str, repl: &str) -> String {
    let hay_lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(pos) = hay_lower[from..].find(&needle_lower) {
        let abs = from + pos;
        out.push_str(&haystack[last..abs]);
        out.push_str(repl);
        last = abs + needle_lower.len();
        from = last;
    }
    out.push_str(&haystack[last..]);
    out
}

/// Merge additional rules referenced by `rule://name` (from the values store) and
/// `rulesFile://path` (from disk): resolve them against `info` and fill in any
/// operators not already set.
/// Merge an ad-hoc rules text (e.g. produced by a plugin) into the resolved set.
/// Existing single-match operators win; multi-match operators accumulate.
pub fn merge_rules_text(resolved: &mut Resolved, info: &ReqInfo, text: &str) {
    let mut mgr = RuleManager::new();
    mgr.set_text(text);
    let sub = mgr.resolve(info);
    for (k, v) in sub.single {
        resolved.single.entry(k).or_insert(v);
    }
    for (k, mut vs) in sub.multi {
        resolved.multi.entry(k).or_default().append(&mut vs);
    }
}

/// Collect matched `plugin://`/`pipe://` rules as `(name, param)` pairs, where
/// `param` is the `/…` suffix after the plugin name.
pub fn plugin_names(resolved: &Resolved) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for proto in ["plugin", "pipe"] {
        for op in resolved.all(proto) {
            let val = op.value.trim();
            let name = val.split(['/', '?']).next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            let param = val[name.len()..].trim_start_matches('/').to_string();
            if !out.iter().any(|(n, _): &(String, String)| n == name) {
                out.push((name.to_string(), param));
            }
        }
    }
    out
}

pub fn merge_included_rules(
    resolved: &mut Resolved,
    info: &ReqInfo,
    values: &HashMap<String, String>,
) {
    let mut texts: Vec<String> = Vec::new();
    if let Some(name) = resolved.value("rule") {
        if let Some(content) = values.get(name) {
            texts.push(content.clone());
        }
    }
    if let Some(path) = resolved.value("rulesFile") {
        if let Ok(content) = std::fs::read_to_string(path) {
            texts.push(content);
        }
    }
    for text in texts {
        let mut mgr = RuleManager::new();
        mgr.set_text(&text);
        let sub = mgr.resolve(info);
        for (k, v) in sub.single {
            resolved.single.entry(k).or_insert(v);
        }
        for (k, mut vs) in sub.multi {
            resolved.multi.entry(k).or_default().append(&mut vs);
        }
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
                .value("internal-https-proxy")
                .and_then(|v| parse_proxy(ProxyKind::Https, v))
        })
        .or_else(|| {
            resolved
                .value("internal-proxy")
                .or_else(|| resolved.value("internal-http-proxy"))
                .and_then(|v| parse_proxy(ProxyKind::Http, v))
        })
        // Scheme-converting proxies are treated as HTTP proxies (approximation).
        .or_else(|| {
            resolved
                .value("https2http-proxy")
                .or_else(|| resolved.value("http2https-proxy"))
                .and_then(|v| parse_proxy(ProxyKind::Http, v))
        })
        // `pac://<file>` picks the proxy by evaluating FindProxyForURL.
        .or_else(|| {
            let pac_val = resolved.value("pac")?;
            let src = crate::proxy::script::load_script(pac_val)?;
            let result = crate::proxy::script::eval_pac(&src, &info.full_url, &info.host)?;
            parse_pac_result(&result)
        });

    Target {
        connect_host,
        connect_port,
        tls: info.scheme == "https" || info.scheme == "wss",
        sni: info.host.clone(),
        request_port: info.port,
        proxy,
        tls_versions: resolved
            .value("cipher")
            .map(parse_cipher_versions)
            .unwrap_or_default(),
    }
}

/// Parse a `cipher://` value into an upstream TLS version constraint.
///
/// Whistle's `cipher` operator carries Node TLS options as JSON (`minVersion`,
/// `maxVersion`, `secureProtocol`, `ciphers`, …). rustls exposes TLS 1.2 and 1.3
/// only and cannot take OpenSSL cipher strings, so we honour the portable part:
/// the min/max protocol version. Accepts either a JSON object or a bare version
/// token (`cipher://TLSv1.2`). Older pins clamp to the nearest supported version.
fn parse_cipher_versions(value: &str) -> super::upstream::TlsVersions {
    use super::upstream::TlsVersions;
    let value = value.trim();
    let (mut min, mut max) = (None, None);
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            let get = |k: &str| map.get(k).and_then(|v| v.as_str()).map(str::to_string);
            min = get("minVersion");
            max = get("maxVersion");
            // secureProtocol pins a single version (e.g. "TLSv1_2_method").
            if let Some(sp) = get("secureProtocol") {
                min = Some(sp.clone());
                max = Some(sp);
            }
        }
    } else if !value.is_empty() {
        // A bare token pins exactly that version.
        min = Some(value.to_string());
        max = Some(value.to_string());
    }
    let is13 = |s: &Option<String>| s.as_deref().map(cipher_is_13).unwrap_or(false);
    let is12 = |s: &Option<String>| s.as_deref().map(cipher_is_12).unwrap_or(false);
    if is13(&min) {
        TlsVersions::Only13 // min 1.3 ⇒ 1.3 only
    } else if is12(&max) || (max.is_none() && is12(&min)) {
        TlsVersions::Only12 // capped at 1.2 (or the bare `TLSv1.2` token)
    } else if is13(&max) && min.is_none() {
        TlsVersions::Only13
    } else {
        TlsVersions::Default
    }
}

/// True if a version token names TLS 1.3.
fn cipher_is_13(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("1.3") || s.contains("1_3")
}

/// True if a version token names TLS 1.2 (or an older version we clamp up to 1.2).
fn cipher_is_12(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("1.2") || s.contains("1_2") || s.contains("1.1") || s.contains("1_1")
}

/// Collect flag names from `enable`/`disable` operators (split on `,`/`|`/space).
fn flag_set(resolved: &Resolved, protocol: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for v in collect_values(resolved, protocol) {
        for f in v.split([',', '|', ' ']) {
            let f = f.trim();
            if !f.is_empty() {
                set.insert(f.to_string());
            }
        }
    }
    set
}

/// `enable://` flags for a request.
pub fn enabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "enable")
}

/// `disable://` flags for a request.
pub fn disabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "disable")
}

/// True if the request should be aborted (`enable://abort`/`abortReq`/`abortRes`).
pub fn is_aborted(resolved: &Resolved) -> bool {
    let e = enabled_flags(resolved);
    e.contains("abort") || e.contains("abortReq") || e.contains("abortRes")
}

/// Parse a PAC `FindProxyForURL` return value into a proxy (first usable entry).
/// `DIRECT` (or no proxy entry) yields `None` → connect directly.
fn parse_pac_result(result: &str) -> Option<super::upstream::ProxyConfig> {
    for entry in result.split(';') {
        let mut it = entry.split_whitespace();
        let kind = it.next().unwrap_or("").to_ascii_uppercase();
        let hostport = it.next().unwrap_or("");
        match kind.as_str() {
            "DIRECT" => return None,
            "PROXY" | "HTTP" => {
                if let Some(p) = parse_proxy(ProxyKind::Http, hostport) {
                    return Some(p);
                }
            }
            "HTTPS" => {
                if let Some(p) = parse_proxy(ProxyKind::Https, hostport) {
                    return Some(p);
                }
            }
            "SOCKS" | "SOCKS5" => {
                if let Some(p) = parse_proxy(ProxyKind::Socks, hostport) {
                    return Some(p);
                }
            }
            _ => {}
        }
    }
    None
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

    if let Some((proto, value)) = find_file_rule(resolved) {
        return serve_file_family(proto, value, info);
    }

    None
}

/// The local-file / template protocols, in resolution order (base before `x`/`xs`
/// variants doesn't matter — only one is expected per rule).
const FILE_PROTOS: &[&str] = &[
    "file", "rawfile", "tpl", "jsonp", "dust", "xfile", "xrawfile", "xtpl", "xjsonp", "xdust",
    "xsfile", "xsrawfile", "xstpl", "xsjsonp", "xsdust",
];

/// Find a matched local-file/template rule (`file`/`tpl`/`xfile`/…) if any.
fn find_file_rule<'a>(resolved: &'a Resolved) -> Option<(&'static str, &'a str)> {
    FILE_PROTOS
        .iter()
        .find_map(|&p| resolved.value(p).map(|v| (p, v)))
}

/// Serve a matched file-family rule. Returns `None` only for a `x`/`xs` (cross)
/// variant whose file is missing — that falls through to the real server.
fn serve_file_family(proto: &str, value: &str, info: &ReqInfo) -> Option<Response<DynBody>> {
    let raw = proto.contains("rawfile");
    // `tpl`, `dust` and `jsonp` are one protocol in whistle
    // (`_original/lib/handlers/file-proxy.js:14`); none of them has any
    // protocol-specific behaviour of its own.
    let templated = proto.ends_with("tpl") || proto.ends_with("jsonp") || proto.ends_with("dust");
    let cross = proto.starts_with('x');

    match read_file(value) {
        Some(data) => Some(if raw {
            serve_raw_http(&data)
        } else if templated {
            serve_template(&data, value, info)
        } else {
            serve_file_bytes(&data, value, info)
        }),
        None => {
            if cross {
                None // fall through to the real server
            } else {
                Some(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .body(body::full(Bytes::from(format!(
                            "whistle-rs: file not found <strong>{value}</strong>"
                        ))))
                        .unwrap(),
                )
            }
        }
    }
}

/// Cached file contents, valid only while the file's mtime and length are
/// unchanged. Mock files are edited constantly during development, so the
/// cache must never be able to serve a stale body.
struct CachedFile {
    mtime: std::time::SystemTime,
    len: u64,
    data: Arc<Vec<u8>>,
}

/// Files at or below this size are cached; larger ones are streamed from disk
/// every time so a big fixture cannot pin memory.
const MAX_CACHED_FILE: u64 = 1 << 20;

/// Cap on distinct cached paths. Rule files reference a handful of mocks, so a
/// small map suffices; on overflow we clear rather than track recency.
const MAX_CACHE_ENTRIES: usize = 64;

static FILE_CACHE: Lazy<Mutex<HashMap<PathBuf, CachedFile>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Read a file, trying the value verbatim and as an absolute `/`-rooted path.
///
/// Every call still `stat`s the file, so an edit is picked up immediately; only
/// the read of an unchanged file is skipped. The one gap is a rewrite that both
/// preserves the byte length *and* lands within the filesystem's mtime
/// resolution of the previous one — a second-granularity filesystem can then
/// serve the previous body once.
///
/// No sandboxing: `file://` exists to serve arbitrary local paths on the
/// developer's own machine, and the original imposes no restriction on absolute
/// paths either (its only check, `existsUpPath` in
/// `_original/lib/util/index.js:1847`, guards root-*relative* rule paths, a
/// feature whistle-rs does not implement).
fn read_file(path: &str) -> Option<Arc<Vec<u8>>> {
    let clean = path.trim_start_matches('/');
    for candidate in [path.to_string(), format!("/{clean}")] {
        if let Some(data) = read_cached(Path::new(&candidate)) {
            return Some(data);
        }
    }
    None
}

/// Read one path through the mtime-keyed cache.
fn read_cached(path: &Path) -> Option<Arc<Vec<u8>>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let len = meta.len();
    let mtime = meta.modified().ok();

    // A file we cannot stat for mtime is never cached — correctness first.
    if let (Some(mtime), true) = (mtime, len <= MAX_CACHED_FILE) {
        if let Ok(mut cache) = FILE_CACHE.lock() {
            if let Some(hit) = cache.get(path) {
                if hit.mtime == mtime && hit.len == len {
                    return Some(Arc::clone(&hit.data));
                }
            }
            let data = Arc::new(std::fs::read(path).ok()?);
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(
                path.to_path_buf(),
                CachedFile {
                    mtime,
                    len,
                    data: Arc::clone(&data),
                },
            );
            return Some(data);
        }
    }
    std::fs::read(path).ok().map(Arc::new)
}

/// Serve raw file bytes with a guessed content type (`file://`).
fn serve_file_bytes(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .body(body::full(Bytes::copy_from_slice(data)))
        .unwrap()
}

/// Serve a `rawfile://`: the file is a complete HTTP response (status line +
/// headers + blank line + body). Parse it into a real response.
fn serve_raw_http(data: &[u8]) -> Response<DynBody> {
    let text = String::from_utf8_lossy(data);
    // Split head from body on the first blank line.
    let (head, body) = match text.find("\r\n\r\n") {
        Some(i) => (&text[..i], text[i + 4..].to_string()),
        None => match text.find("\n\n") {
            Some(i) => (&text[..i], text[i + 2..].to_string()),
            None => (text.as_ref(), String::new()),
        },
    };
    let mut lines = head.split(|c| c == '\n').map(|l| l.trim_end_matches('\r'));
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
    builder
        .body(body::full(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::OK)
                .body(body::empty())
                .unwrap()
        })
}

/// Serve a `tpl://`/`jsonp://`/`dust://`: substitute `{name}`/`{{name}}` in the
/// file from the request query, and (for jsonp) wrap in a callback. Whistle's
/// full dust/handlebars engines are approximated by simple variable substitution.
fn serve_template(data: &[u8], path: &str, info: &ReqInfo, jsonp: bool) -> Response<DynBody> {
    let mut body = String::from_utf8_lossy(data).into_owned();
    let query = query_params(&info.full_url);
    // Replace {{name}} and {name} with query values (unknown → empty).
    let re = regex::Regex::new(r"\{\{([\w$-]+)\}\}|\{([\w$-]+)\}").unwrap();
    body = re
        .replace_all(&body, |caps: &regex::Captures| {
            let name = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            query.get(name).cloned().unwrap_or_default()
        })
        .into_owned();

    let (ct, out) = if jsonp {
        let cb = query
            .get("callback")
            .or_else(|| query.get("_callback"))
            .cloned()
            .unwrap_or_else(|| "callback".to_string());
        (
            "application/javascript; charset=utf-8",
            format!("{cb}({body})"),
        )
    } else {
        (guess_content_type(path), body)
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, ct)
        .body(body::full(Bytes::from(out)))
        .unwrap()
}

/// Parse the query string of a full URL into a map.
fn query_params(full_url: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(q) = full_url.split_once('?').map(|(_, q)| q) {
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
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
    if let Some(cs) = resolved.value("reqCharset") {
        set_charset(&mut parts.headers, cs);
    }
    if let Some(origin) = resolved.value("reqCors") {
        if !origin.is_empty() {
            set_header(&mut parts.headers, "origin", origin);
        }
    }
    apply_req_cookies(&mut parts.headers, resolved);
    apply_deletes(&mut parts.headers, resolved, true);
    apply_header_replace(&mut parts.headers, resolved, true);
}

/// Apply `delete://` keys for one side. Keys are `scope.name` (or a bare header
/// name); values may list several keys separated by `|`, `,`, or whitespace.
/// Ported from `parseDelProps` / `parseDelReqBody` in the original util.
fn apply_deletes(headers: &mut HeaderMap, resolved: &Resolved, request_side: bool) {
    for value in collect_values(resolved, "delete") {
        for key in value.split(['|', ',', ' ', '\t']) {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let (scope, name) = key.split_once('.').unwrap_or(("header", key));
            match (request_side, scope) {
                (true, "reqHeaders") | (true, "header") => remove_header(headers, name),
                (false, "resHeaders") | (false, "header") => remove_header(headers, name),
                (true, "reqCookies") => remove_cookie(headers, name),
                (false, "resType") => {
                    headers.remove(hyper::header::CONTENT_TYPE);
                }
                (false, "resCharset") => strip_charset(headers),
                _ => {}
            }
        }
    }
}

fn remove_header(headers: &mut HeaderMap, name: &str) {
    if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
        headers.remove(&n);
    }
}

/// Apply `headerReplace://` operators for one side. Value is a JSON object
/// `{"<scope>.<name>:<pattern>": "<replacement>"}` where scope is `req`/`reqH`/
/// `reqHeaders` (request) or `res`/`resH`/`resHeaders` (response); the pattern is
/// a regex applied to that header's value. Ported from `parseHeaderReplace`.
fn apply_header_replace(headers: &mut HeaderMap, resolved: &Resolved, request_side: bool) {
    for value in collect_values(resolved, "headerReplace") {
        let value = value.trim();
        let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
        else {
            continue;
        };
        for (key, repl) in map {
            let repl = repl.as_str().unwrap_or("");
            let Some((scope, rest)) = key.split_once('.') else {
                continue;
            };
            let (name, pattern) = rest.split_once(':').unwrap_or((rest, ""));
            let is_req = matches!(scope, "req" | "reqH" | "reqHeaders");
            let is_res = matches!(scope, "res" | "resH" | "resHeaders");
            if (request_side && !is_req) || (!request_side && !is_res) {
                continue;
            }
            let name = name.trim();
            if let Some(cur) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
            {
                let new = regex_replace(&cur, pattern, repl);
                set_header(headers, name, &new);
            }
        }
    }
}

/// Regex `replace_all` (falls back to literal replace if the pattern is invalid).
fn regex_replace(text: &str, pattern: &str, repl: &str) -> String {
    if pattern.is_empty() {
        return text.to_string();
    }
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace_all(text, repl).into_owned(),
        Err(_) => text.replace(pattern, repl),
    }
}

/// Remove a single cookie from the request `Cookie` header.
fn remove_cookie(headers: &mut HeaderMap, name: &str) {
    let Some(cur) = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return;
    };
    let kept: Vec<&str> = cur
        .split(';')
        .map(|s| s.trim())
        .filter(|kv| kv.split_once('=').map(|(k, _)| k.trim() != name).unwrap_or(true))
        .collect();
    if kept.is_empty() {
        headers.remove(hyper::header::COOKIE);
    } else if let Ok(v) = HeaderValue::from_str(&kept.join("; ")) {
        headers.insert(hyper::header::COOKIE, v);
    }
}

/// Set the charset parameter on the `Content-Type` header (whistle's setCharset).
fn set_charset(headers: &mut HeaderMap, charset: &str) {
    let base = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "text/plain".to_string());
    if let Ok(v) = HeaderValue::from_str(&format!("{base}; charset={charset}")) {
        headers.insert(hyper::header::CONTENT_TYPE, v);
    }
}

/// Drop the charset parameter from `Content-Type` (delete://resCharset).
fn strip_charset(headers: &mut HeaderMap) {
    if let Some(base) = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_string())
    {
        if let Ok(v) = HeaderValue::from_str(&base) {
            headers.insert(hyper::header::CONTENT_TYPE, v);
        }
    }
}

/// Milliseconds to delay before forwarding the request (`reqDelay`).
pub fn req_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved.value("reqDelay").and_then(|v| v.trim().parse().ok())
}

/// Milliseconds to delay before returning the response (`resDelay`).
pub fn res_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved.value("resDelay").and_then(|v| v.trim().parse().ok())
}

/// Request-body throughput cap in KB/s (`reqSpeed`).
pub fn req_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved.value("reqSpeed").and_then(|v| v.trim().parse().ok())
}

/// Response-body throughput cap in KB/s (`resSpeed`).
pub fn res_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved.value("resSpeed").and_then(|v| v.trim().parse().ok())
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
    if let Some(cs) = resolved.value("resCharset") {
        set_charset(&mut parts.headers, cs);
    }
    if let Some(cc) = cache_control(resolved.value("cache")) {
        set_header(&mut parts.headers, "cache-control", &cc);
    }
    apply_res_cookies(&mut parts.headers, resolved);
    apply_deletes(&mut parts.headers, resolved, false);
    apply_header_replace(&mut parts.headers, resolved, false);

    // enable/disable flags with response-side effects.
    let en = enabled_flags(resolved);
    let dis = disabled_flags(resolved);
    if en.contains("cors") {
        set_header(&mut parts.headers, "access-control-allow-origin", "*");
        set_header(&mut parts.headers, "access-control-allow-methods", "*");
        set_header(&mut parts.headers, "access-control-allow-headers", "*");
    }
    if dis.contains("cache") {
        set_header(&mut parts.headers, "cache-control", "no-store");
    }
    if dis.contains("keepAlive") || dis.contains("keepalive") {
        set_header(&mut parts.headers, "connection", "close");
    }
}

/// Map a `cache://` value to a `Cache-Control` header. `no`/`no-cache`/negative →
/// no-cache, `no-store` → no-store, a number → max-age, `reserve`/`keep` → leave
/// the upstream header untouched. Ported from res.js cache handling.
fn cache_control(value: Option<&str>) -> Option<String> {
    let v = value?.trim();
    if v.is_empty() || v == "reserve" || v == "keep" {
        return None;
    }
    let lower = v.to_ascii_lowercase();
    if lower.contains("no-store") {
        return Some("no-store".to_string());
    }
    if let Ok(n) = v.parse::<i64>() {
        if n < 0 {
            return Some("no-cache".to_string());
        }
        return Some(format!("max-age={n}"));
    }
    if lower == "no" || lower == "off" || lower == "no-cache" {
        return Some("no-cache".to_string());
    }
    Some(v.to_string())
}

/// File path to append the request body to (`reqWrite`).
pub fn req_write_path(resolved: &Resolved) -> Option<String> {
    resolved.value("reqWrite").map(str::to_string)
}

/// File path to append the response body to (`resWrite`).
pub fn res_write_path(resolved: &Resolved) -> Option<String> {
    resolved.value("resWrite").map(str::to_string)
}

/// File path to append the raw request (head + body) to (`reqWriteRaw`).
pub fn req_write_raw_path(resolved: &Resolved) -> Option<String> {
    resolved.value("reqWriteRaw").map(str::to_string)
}

/// File path to append the raw response (head + body) to (`resWriteRaw`).
pub fn res_write_raw_path(resolved: &Resolved) -> Option<String> {
    resolved.value("resWriteRaw").map(str::to_string)
}

/// Build the response trailer headers from `trailers://` operators.
pub fn build_trailers(resolved: &Resolved) -> HeaderMap {
    let mut h = HeaderMap::new();
    for value in collect_values(resolved, "trailers") {
        apply_header_value(&mut h, value);
    }
    h
}

/// Content-type-specific body operator prefixes (`css`/`html`/`js`).
const TYPED_BODY_PREFIXES: &[&str] = &["css", "html", "js"];

/// Body operators for a side, keyed by prefix (`req`/`res`): `*Body` (replace),
/// `*Replace` (substring/`/regex/` substitute), `*Prepend`, `*Append`.
fn body_ops_present(resolved: &Resolved, prefix: &str) -> bool {
    let generic = ["Body", "Replace", "Prepend", "Append"]
        .iter()
        .any(|s| resolved.value(&format!("{prefix}{s}")).is_some());
    if generic {
        return true;
    }
    if prefix == "res" && resolved.value("resMerge").is_some() {
        return true;
    }
    // css/html/js typed ops only exist on the response side.
    prefix == "res"
        && TYPED_BODY_PREFIXES.iter().any(|k| {
            ["Body", "Prepend", "Append"]
                .iter()
                .any(|s| resolved.value(&format!("{k}{s}")).is_some())
        })
}

/// Deep-merge `patch` (a JSON object) into `target`; objects merge recursively,
/// other values are overwritten. Ported from whistle's `resMerge`.
fn json_deep_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
            for (k, v) in p {
                json_deep_merge(t.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
        (t, p) => *t = p.clone(),
    }
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
    transform_body(body, resolved, "req", None)
}

/// Transform a buffered response body; `content_type` gates css/html/js ops.
pub fn transform_res_body(body: Bytes, resolved: &Resolved, content_type: Option<&str>) -> Bytes {
    transform_body(body, resolved, "res", content_type)
}

/// Apply `*Body` → `*Replace` → `*Prepend` → `*Append`, then content-type-specific
/// (`css`/`html`/`js`) `Body`/`Prepend`/`Append` for the response.
fn transform_body(
    body: Bytes,
    resolved: &Resolved,
    prefix: &str,
    content_type: Option<&str>,
) -> Bytes {
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

    // resMerge: deep-merge a JSON patch into a JSON response body.
    if prefix == "res" {
        if let Some(patch_src) = resolved.value("resMerge") {
            if let (Ok(mut base), Ok(patch)) = (
                serde_json::from_slice::<serde_json::Value>(&data),
                serde_json::from_str::<serde_json::Value>(patch_src),
            ) {
                json_deep_merge(&mut base, &patch);
                if let Ok(s) = serde_json::to_vec(&base) {
                    data = s;
                }
            }
        }
    }

    // Content-type-specific ops (cssBody/htmlPrepend/jsAppend, …).
    if prefix == "res" {
        if let Some(kind) = content_type.and_then(typed_body_kind) {
            if let Some(new) = resolved.value(&format!("{kind}Body")) {
                data = new.as_bytes().to_vec();
            }
            if let Some(pre) = resolved.value(&format!("{kind}Prepend")) {
                let mut v = pre.as_bytes().to_vec();
                v.extend_from_slice(&data);
                data = v;
            }
            if let Some(app) = resolved.value(&format!("{kind}Append")) {
                data.extend_from_slice(app.as_bytes());
            }
        }
    }
    Bytes::from(data)
}

/// Map a content type to a typed-body prefix (`html`/`css`/`js`).
fn typed_body_kind(content_type: &str) -> Option<&'static str> {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("html") {
        Some("html")
    } else if ct.contains("css") {
        Some("css")
    } else if ct.contains("javascript") || ct.contains("ecmascript") {
        Some("js")
    } else {
        None
    }
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
        let info = build_req_info(
            "GET",
            scheme,
            host,
            if scheme == "https" { 443 } else { 80 },
            path,
            &HeaderMap::new(),
            None,
        );
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
        let out = transform_res_body(Bytes::from_static(b"OLD"), &resolved, None);
        assert_eq!(&out[..], b"NEW");
    }

    #[test]
    fn res_body_prepend_append_replace() {
        let resolved = resolve(
            "example.com/x resPrepend://<!--top-->\nexample.com/x resAppend://<!--end-->\nexample.com/x resReplace://foo=bar\n",
            "http://example.com/x",
        );
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(Bytes::from_static(b"a foo b"), &resolved, None);
        assert_eq!(&out[..], b"<!--top-->a bar b<!--end-->");
    }

    #[test]
    fn res_merge_json_deep() {
        let resolved = resolve(
            "example.com/x resMerge://{\"a\":2,\"c\":{\"d\":1}}\n",
            "http://example.com/x",
        );
        let out = transform_res_body(
            Bytes::from_static(br#"{"a":1,"b":1,"c":{"e":2}}"#),
            &resolved,
            Some("application/json"),
        );
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"], 2); // overwritten
        assert_eq!(v["b"], 1); // kept
        assert_eq!(v["c"]["d"], 1); // added
        assert_eq!(v["c"]["e"], 2); // kept (deep merge)
    }

    #[test]
    fn res_body_regex_replace() {
        let resolved = resolve("example.com/x resReplace:///\\d+/=N\n", "http://example.com/x");
        let out = transform_res_body(Bytes::from_static(b"id=123 and 45"), &resolved, None);
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
    fn speed_parsing() {
        let resolved = resolve("example.com reqSpeed://16\nexample.com resSpeed://20\n", "http://example.com/");
        assert_eq!(req_speed_kbps(&resolved), Some(16.0));
        assert_eq!(res_speed_kbps(&resolved), Some(20.0));
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
    fn delete_headers_and_cookies() {
        let resolved = resolve(
            "example.com delete://x-req|reqCookies.sid\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-req", "1".parse().unwrap());
        h.insert("x-keep", "2".parse().unwrap());
        h.insert(hyper::header::COOKIE, "sid=abc; keep=1".parse().unwrap());
        apply_deletes(&mut h, &resolved, true);
        assert!(h.get("x-req").is_none());
        assert!(h.get("x-keep").is_some());
        let c = h.get(hyper::header::COOKIE).unwrap().to_str().unwrap();
        assert!(!c.contains("sid="));
        assert!(c.contains("keep=1"));
    }

    #[test]
    fn header_replace_regex() {
        let resolved = resolve(
            "example.com headerReplace://{\"resH.x-foo:ba.\":\"XX\"}\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-foo", "bar-baz".parse().unwrap());
        apply_header_replace(&mut h, &resolved, false);
        assert_eq!(h.get("x-foo").unwrap(), "XX-XX");
    }

    #[test]
    fn charset_set_and_strip() {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::CONTENT_TYPE, "text/html".parse().unwrap());
        set_charset(&mut h, "utf-8");
        assert_eq!(
            h.get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        strip_charset(&mut h);
        assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "text/html");
    }

    #[test]
    fn file_family_cross_falls_through() {
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        // xfile with a missing file → no short-circuit (proxy the real server).
        let x = resolve("a.com xfile:///no/such/file.txt\n", "http://a.com/");
        assert!(short_circuit(&info, &x).is_none());
        // plain file missing → a 404 short-circuit.
        let f = resolve("a.com file:///no/such/file.txt\n", "http://a.com/");
        let r = short_circuit(&info, &f).expect("file:// should short-circuit");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn file_protocol_recognised() {
        use crate::rules::protocols::is_file_protocol;
        for p in ["file", "rawfile", "tpl", "jsonp", "dust", "xfile", "xsrawfile", "xtpl"] {
            assert!(is_file_protocol(p), "{p} should be a file protocol");
        }
        assert!(!is_file_protocol("host"));
        assert!(!is_file_protocol("xhost"));
    }

    #[test]
    fn config_vars_substituted() {
        let mut r = resolve(
            "a.com ua://agent-${port}\na.com resType://type-${VERSION}\n",
            "http://a.com/",
        );
        substitute_config_vars(&mut r, 8899, "1.2.3");
        assert_eq!(r.value("ua"), Some("agent-8899"));
        assert_eq!(r.value("resType"), Some("type-1.2.3"));
    }

    #[test]
    fn proxy_variants_resolve() {
        use super::super::upstream::ProxyKind;
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);

        let r = resolve("a.com internal-https-proxy://1.2.3.4:8080\n", "http://a.com/");
        let p = resolve_target(&info, &r).proxy.expect("internal-https-proxy");
        assert_eq!(p.kind, ProxyKind::Https);
        assert_eq!(p.port, 8080);

        let r2 = resolve("a.com internal-http-proxy://1.2.3.4:8081\n", "http://a.com/");
        let p2 = resolve_target(&info, &r2).proxy.expect("internal-http-proxy");
        assert_eq!(p2.kind, ProxyKind::Http);

        // `xproxy` is an alias of `proxy`.
        let r3 = resolve("a.com xproxy://5.6.7.8:3128\n", "http://a.com/");
        let p3 = resolve_target(&info, &r3).proxy.expect("xproxy");
        assert_eq!(p3.kind, ProxyKind::Http);
        assert_eq!(p3.port, 3128);
    }

    #[test]
    fn cipher_maps_to_tls_versions() {
        use super::super::upstream::TlsVersions;
        assert_eq!(parse_cipher_versions("TLSv1.2"), TlsVersions::Only12);
        assert_eq!(parse_cipher_versions("TLSv1.3"), TlsVersions::Only13);
        assert_eq!(
            parse_cipher_versions("{\"maxVersion\":\"TLSv1.2\"}"),
            TlsVersions::Only12
        );
        assert_eq!(
            parse_cipher_versions("{\"minVersion\":\"TLSv1.3\"}"),
            TlsVersions::Only13
        );
        assert_eq!(
            parse_cipher_versions("{\"secureProtocol\":\"TLSv1_2_method\"}"),
            TlsVersions::Only12
        );
        // An OpenSSL cipher string carries no version pin → default (1.2+1.3).
        assert_eq!(
            parse_cipher_versions("{\"ciphers\":\"ECDHE-RSA-AES128-GCM-SHA256\"}"),
            TlsVersions::Default
        );
    }

    #[test]
    fn cipher_sets_target_tls_versions() {
        use super::super::upstream::TlsVersions;
        let resolved = resolve("example.com cipher://TLSv1.2\n", "https://example.com/");
        let info = build_req_info("GET", "https", "example.com", 443, "/", &HeaderMap::new(), None);
        let target = resolve_target(&info, &resolved);
        assert_eq!(target.tls_versions, TlsVersions::Only12);
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
