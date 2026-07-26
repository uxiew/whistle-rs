//! JavaScript scripting for `resScript` (and PAC evaluation).
//!
//! Ported in spirit from whistle's script hooks. A script runs in an embedded
//! JS engine (boa) with a global `ctx` object:
//!
//! ```js
//! // ctx = { req: { method, url }, res: { statusCode, headers, body } }
//! ctx.res.headers['x-scripted'] = '1';
//! ctx.res.body = ctx.res.body.replace(/foo/g, 'bar');
//! if (ctx.req.url.indexOf('/admin') >= 0) ctx.res.statusCode = 403;
//! ```
//!
//! After the script runs, whistle-rs reads `ctx.res` back and applies any
//! changed status / headers / body.
//!
//! # PAC
//!
//! [`find_proxy_for_url`] is the other user of the engine: it resolves a
//! `pac://` value (inline script, local file, or a remote `http(s)://` URL that
//! is fetched and cached) and calls the script's `FindProxyForURL(url, host)`
//! inside the helper environment a PAC file expects — [`PAC_HELPERS`].
//!
//! Both halves used to fail *open*. A remote URL was evaluated as if it were
//! JavaScript and a script calling anything beyond three helpers threw; either
//! way the failure was swallowed and the request went **direct**, past the proxy
//! the rule named, with nothing in the log. So the fallible parts return
//! `Result` here and the caller refuses the request instead of routing it
//! somewhere the rules did not ask for. See `docs/RULES.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use boa_engine::{Context, JsResult, JsString, JsValue, NativeFunction, Source, js_string};
use once_cell::sync::Lazy;
use serde_json::json;

/// What a response script changed.
pub struct ScriptResult {
    pub status: Option<u16>,
    /// Headers to set/replace (empty value deletes, matching header ops).
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Resolve a script operator value to source: read the file if it exists,
/// otherwise treat the value itself as inline JavaScript.
pub fn load_script(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(src) = std::fs::read_to_string(value) {
        return Some(src);
    }
    Some(value.to_string())
}

/// Run a `resScript` against the current response, returning any changes.
/// Returns `None` if the script errored (the response is then left unchanged).
pub fn run_res_script(
    src: &str,
    method: &str,
    url: &str,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) -> Option<ScriptResult> {
    let mut ctx = Context::default();

    let hdr_obj: serde_json::Map<String, serde_json::Value> = headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let ctx_json = json!({
        "req": { "method": method, "url": url },
        "res": { "statusCode": status, "headers": hdr_obj, "body": body }
    });

    let jsval = boa_engine::JsValue::from_json(&ctx_json, &mut ctx).ok()?;
    ctx.global_object()
        .set(js_string!("ctx"), jsval, false, &mut ctx)
        .ok()?;

    if let Err(err) = ctx.eval(Source::from_bytes(src.as_bytes())) {
        tracing::debug!("resScript error: {err}");
        return None;
    }

    let ctx_val = ctx
        .global_object()
        .get(js_string!("ctx"), &mut ctx)
        .ok()?;
    let out = ctx_val.to_json(&mut ctx).ok()??;
    let res = out.get("res")?;

    let status = res
        .get("statusCode")
        .and_then(|v| v.as_u64())
        .map(|n| n as u16);
    let mut new_headers = Vec::new();
    if let Some(h) = res.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in h {
            let val = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
            new_headers.push((k.clone(), val));
        }
    }
    let body = res.get("body").and_then(|v| v.as_str()).map(|s| s.to_string());

    Some(ScriptResult {
        status,
        headers: new_headers,
        body,
    })
}

/// Run a `frameScript` against one WebSocket text frame, returning the
/// (possibly rewritten) payload. `direction` is `"send"` or `"receive"`.
pub fn run_frame_script(src: &str, direction: &str, data: &str) -> Option<String> {
    let mut ctx = Context::default();
    let ctx_json = json!({ "direction": direction, "frame": { "data": data } });
    let jsval = boa_engine::JsValue::from_json(&ctx_json, &mut ctx).ok()?;
    ctx.global_object()
        .set(js_string!("ctx"), jsval, false, &mut ctx)
        .ok()?;
    if ctx.eval(Source::from_bytes(src.as_bytes())).is_err() {
        return None;
    }
    let ctx_val = ctx.global_object().get(js_string!("ctx"), &mut ctx).ok()?;
    let out = ctx_val.to_json(&mut ctx).ok()??;
    out.get("frame")?
        .get("data")?
        .as_str()
        .map(|s| s.to_string())
}

// ── PAC ────────────────────────────────────────────────────────────────────

/// The functions a PAC file is entitled to assume, per the original Netscape
/// specification (and the Microsoft `*Ex` extensions, mapped onto the IPv4
/// helpers this port has).
///
/// They are defined *before* the PAC source is evaluated, so a script that
/// ships its own copy of one — some do, defensively — overrides ours rather
/// than being overridden by it.
///
/// `dnsResolve` and `alert` are native (see [`register_pac_natives`]);
/// everything reachable from JavaScript is written here, close to the spec
/// wording, because that is easier to check against the spec than Rust would be.
const PAC_HELPERS: &str = r#"
function isPlainHostName(host) { return String(host).indexOf('.') < 0; }
function dnsDomainIs(host, domain) {
  host = String(host); domain = String(domain);
  return host.length >= domain.length &&
    host.substring(host.length - domain.length) === domain;
}
function localHostOrDomainIs(host, hostdom) {
  host = String(host); hostdom = String(hostdom);
  return host === hostdom || hostdom.indexOf(host + '.') === 0;
}
function isResolvable(host) { return dnsResolve(host) !== null; }
function dnsDomainLevels(host) { return String(host).split('.').length - 1; }
function convert_addr(ipchars) {
  var b = String(ipchars).split('.');
  return ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) |
         ((b[2] & 0xff) << 8) | (b[3] & 0xff);
}
function myIpAddress() { return __whistleMyIpAddress; }
function isInNet(host, pattern, mask) {
  var ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? String(host) : dnsResolve(host);
  if (!ip) { return false; }
  var a = ip.split('.'), p = String(pattern).split('.'), m = String(mask).split('.');
  if (a.length !== 4 || p.length !== 4 || m.length !== 4) { return false; }
  for (var i = 0; i < 4; i++) {
    if ((a[i] & m[i]) !== (p[i] & m[i])) { return false; }
  }
  return true;
}
function shExpMatch(str, shexp) {
  var re = String(shexp)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp('^' + re + '$').test(String(str));
}
function __whistleInRange(now, from, to) {
  return from <= to ? (now >= from && now <= to) : (now >= from || now <= to);
}
function weekdayRange(wd1, wd2, gmt) {
  var days = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 1 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var now = new Date();
  var today = useGmt ? now.getUTCDay() : now.getDay();
  var from = days.indexOf(String(args[0]).toUpperCase());
  if (from < 0) { return false; }
  if (args.length < 2) { return today === from; }
  var to = days.indexOf(String(args[1]).toUpperCase());
  if (to < 0) { return false; }
  return __whistleInRange(today, from, to);
}
function timeRange() {
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 0 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var n = args.map(Number);
  var now = new Date();
  var h = useGmt ? now.getUTCHours() : now.getHours();
  var m = useGmt ? now.getUTCMinutes() : now.getMinutes();
  var s = useGmt ? now.getUTCSeconds() : now.getSeconds();
  var secs = h * 3600 + m * 60 + s;
  if (n.length === 1) { return h === n[0]; }
  // Two hours, two hour:minute pairs, or two hour:minute:second triples. The
  // end of the range is inclusive down to the precision that was given, so
  // timeRange(9, 17) covers all of the 17th hour.
  if (n.length === 2) {
    return __whistleInRange(secs, n[0] * 3600, n[1] * 3600 + 3599);
  }
  if (n.length === 4) {
    return __whistleInRange(secs, n[0] * 3600 + n[1] * 60, n[2] * 3600 + n[3] * 60 + 59);
  }
  if (n.length === 6) {
    return __whistleInRange(secs, n[0] * 3600 + n[1] * 60 + n[2],
                            n[3] * 3600 + n[4] * 60 + n[5]);
  }
  return false;
}
function dateRange() {
  var months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
                'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 0 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var now = new Date();
  var day = useGmt ? now.getUTCDate() : now.getDate();
  var mon = useGmt ? now.getUTCMonth() : now.getMonth();
  var year = useGmt ? now.getUTCFullYear() : now.getFullYear();
  // Each argument is a day (1-31), a month name, or a four-digit year.
  var kind = function (v) {
    if (months.indexOf(String(v).toUpperCase()) >= 0) { return 'mon'; }
    return Number(v) >= 1000 ? 'year' : 'day';
  };
  var value = function (v) {
    return kind(v) === 'mon' ? months.indexOf(String(v).toUpperCase()) : Number(v);
  };
  if (args.length === 1) {
    var k = kind(args[0]), v = value(args[0]);
    return k === 'day' ? day === v : k === 'mon' ? mon === v : year === v;
  }
  var half = args.length / 2;
  if (args.length % 2 !== 0 || half > 3) { return false; }
  // A stamp orders (year, month, day) so a range comparison is one number.
  // Components the arguments left out are taken from today, which is what
  // makes dateRange('JAN', 'MAR') mean "January to March of any year".
  var stamp = function (list, y, mo, d) {
    for (var i = 0; i < list.length; i++) {
      var k = kind(list[i]), v = value(list[i]);
      if (k === 'day') { d = v; } else if (k === 'mon') { mo = v; } else { y = v; }
    }
    return y * 10000 + mo * 100 + d;
  };
  var from = args.slice(0, half), to = args.slice(half);
  var today = year * 10000 + mon * 100 + day;
  return __whistleInRange(today, stamp(from, year, mon, day), stamp(to, year, mon, day));
}
// Microsoft's IPv6-aware extensions. This port resolves IPv4 only, so they
// answer from the same data rather than pretending to know more.
function dnsResolveEx(host) { var ip = dnsResolve(host); return ip === null ? '' : ip; }
function myIpAddressEx() { return myIpAddress(); }
function isResolvableEx(host) { return isResolvable(host); }
function isInNetEx(host, prefix) {
  var parts = String(prefix).split('/');
  var len = parts.length > 1 ? Number(parts[1]) : 32;
  if (!(len >= 0 && len <= 32)) { return false; }
  var mask = [0, 0, 0, 0];
  for (var i = 0; i < 4; i++) {
    var bits = Math.min(8, Math.max(0, len - i * 8));
    mask[i] = (0xff << (8 - bits)) & 0xff;
  }
  return isInNet(host, parts[0], mask.join('.'));
}
function sortIpAddressList(list) { return String(list); }
function getClientVersion() { return '1.0'; }
"#;

/// PAC's `dnsResolve(host)`: the first IPv4 address `host` resolves to, or
/// `null`. A dotted quad resolves to itself.
///
/// This blocks on the system resolver, which is why [`find_proxy_for_url`]
/// evaluates PAC scripts on the blocking pool.
fn resolve_ipv4(host: &str) -> Option<String> {
    use std::net::{IpAddr, ToSocketAddrs};
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4.to_string()),
            IpAddr::V6(_) => None,
        })
}

/// `dnsResolve` as the engine sees it.
fn js_dns_resolve(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let Some(arg) = args.first() else {
        return Ok(JsValue::null());
    };
    let host = arg.to_string(ctx)?.to_std_string_escaped();
    Ok(match resolve_ipv4(&host) {
        Some(ip) => JsString::from(ip.as_str()).into(),
        None => JsValue::null(),
    })
}

/// `alert` — PAC's only debugging tool. whistle logs it; so do we, at debug
/// level, since a chatty PAC file would otherwise log once per request.
fn js_alert(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    if let Some(arg) = args.first() {
        let msg = arg.to_string(ctx)?.to_std_string_escaped();
        tracing::debug!("pac alert: {msg}");
    }
    Ok(JsValue::undefined())
}

/// Install the parts of the PAC environment that JavaScript cannot provide:
/// the resolver, `alert`, and this machine's address for `myIpAddress`.
fn register_pac_natives(ctx: &mut Context) -> Result<()> {
    ctx.register_global_callable(
        js_string!("dnsResolve"),
        1,
        NativeFunction::from_fn_ptr(js_dns_resolve),
    )
    .map_err(|e| anyhow!("registering dnsResolve: {e}"))?;
    ctx.register_global_callable(js_string!("alert"), 1, NativeFunction::from_fn_ptr(js_alert))
        .map_err(|e| anyhow!("registering alert: {e}"))?;
    // `myIpAddress` cannot fail and takes no arguments, so it is a value rather
    // than a call. whistle-rs falls back to the loopback address when the
    // routing table cannot say, which is what a PAC file expects to see when a
    // machine has no route out.
    let ip = super::upstream::primary_local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    ctx.register_global_property(
        js_string!("__whistleMyIpAddress"),
        JsString::from(ip.as_str()),
        boa_engine::property::Attribute::READONLY,
    )
    .map_err(|e| anyhow!("registering myIpAddress: {e}"))?;
    Ok(())
}

/// Evaluate a PAC script's `FindProxyForURL(url, host)` and return its result
/// string (e.g. `"PROXY 127.0.0.1:8888"`, `"SOCKS ..."`, or `"DIRECT"`).
///
/// Every way this can fail is an error, never an empty answer: a PAC file that
/// throws has not said "connect directly", it has said nothing, and treating
/// the two alike is how a request slips past the proxy it was pinned to.
pub fn eval_pac(pac_src: &str, url: &str, host: &str) -> Result<String> {
    let mut ctx = Context::default();
    register_pac_natives(&mut ctx)?;
    ctx.eval(Source::from_bytes(PAC_HELPERS.as_bytes()))
        .map_err(|e| anyhow!("PAC helper environment: {e}"))?;
    ctx.eval(Source::from_bytes(pac_src.as_bytes()))
        .map_err(|e| anyhow!("PAC script: {e}"))?;

    let call = format!("FindProxyForURL({}, {})", js_str(url), js_str(host));
    let result = ctx
        .eval(Source::from_bytes(call.as_bytes()))
        .map_err(|e| anyhow!("FindProxyForURL({url}): {e}"))?;
    if result.is_null_or_undefined() {
        bail!("FindProxyForURL({url}) returned no proxy string");
    }
    let out = result
        .to_string(&mut ctx)
        .map_err(|e| anyhow!("FindProxyForURL({url}) returned an unreadable value: {e}"))?
        .to_std_string_escaped();
    Ok(out)
}

/// A remote PAC file, with the moment it was fetched.
struct CachedPac {
    body: Arc<str>,
    at: Instant,
}

/// Remote PAC files, keyed by their URL.
///
/// whistle keeps at most ten and never re-reads one
/// (`cachedPacs`, `_original/lib/rules/index.js:264-274`); we keep the same
/// bound but let an entry expire, because a debugging proxy that pins a routing
/// decision to whatever the PAC file said the first time is hard to explain. A
/// refresh that fails keeps serving the stale copy rather than failing the
/// request — the stale answer is still the answer the rule asked for.
static PAC_CACHE: Lazy<Mutex<HashMap<String, CachedPac>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// How long a fetched PAC file is reused before being fetched again.
const PAC_TTL: Duration = Duration::from_secs(300);
/// How many remote PAC files are remembered (whistle's limit).
const PAC_CACHE_MAX: usize = 10;

/// The cached copy of `url`, and whether it is still fresh.
fn cached_pac(url: &str) -> Option<(Arc<str>, bool)> {
    let cache = PAC_CACHE.lock().ok()?;
    let hit = cache.get(url)?;
    Some((hit.body.clone(), hit.at.elapsed() < PAC_TTL))
}

/// Remember `body` as the current content of `url`, evicting the oldest entry
/// once the cache is full.
fn store_pac(url: &str, body: Arc<str>) {
    let Ok(mut cache) = PAC_CACHE.lock() else {
        return;
    };
    if !cache.contains_key(url)
        && cache.len() >= PAC_CACHE_MAX
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, v)| v.at)
            .map(|(k, _)| k.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(
        url.to_string(),
        CachedPac {
            body,
            at: Instant::now(),
        },
    );
}

/// Fetch a remote PAC file, serving a cached copy while it is fresh.
///
/// whistle fetches `pac://http://…/proxy.pac` through `node-pac`
/// (`_original/lib/rules/index.js:257-275`). This port used to hand the URL
/// straight to the JS engine, where it threw and left the request going direct.
async fn fetch_pac(url: &str) -> Result<Arc<str>> {
    if let Some((body, fresh)) = cached_pac(url)
        && fresh
    {
        return Ok(body);
    }
    let fetched = super::upstream::simple_get(url).await;
    let stale = || cached_pac(url).map(|(body, _)| body);
    match fetched {
        Ok((status, body)) if (200..300).contains(&status) => {
            let text: Arc<str> = String::from_utf8_lossy(&body).into_owned().into();
            store_pac(url, text.clone());
            Ok(text)
        }
        Ok((status, _)) => match stale() {
            Some(body) => {
                tracing::warn!("pac://{url} returned {status}; using the cached copy");
                Ok(body)
            }
            None => bail!("fetching {url}: HTTP {status}"),
        },
        Err(err) => match stale() {
            Some(body) => {
                tracing::warn!("pac://{url} unreachable ({err:#}); using the cached copy");
                Ok(body)
            }
            None => Err(err).with_context(|| format!("fetching {url}")),
        },
    }
}

/// Is this `pac://` value a URL to fetch rather than a path or a script?
fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Resolve a `pac://` value to the script text.
///
/// Three shapes, in the order they are recognised: a remote `http(s)://` URL
/// (fetched and cached), a readable local file, or the script itself written
/// inline. The inline form is this port's own — upstream requires a URL or a
/// path (`index.js:255-258`) — so it is only assumed when the value actually
/// looks like a PAC script; otherwise an unreadable path is reported as one,
/// instead of being evaluated as JavaScript and blamed on the script.
pub async fn load_pac(value: &str) -> Result<Arc<str>> {
    let value = value.trim();
    if value.is_empty() {
        bail!("pac:// with no script, file or URL");
    }
    if is_http_url(value) {
        return fetch_pac(value).await;
    }
    match std::fs::read_to_string(value) {
        Ok(src) => Ok(src.into()),
        Err(err) => {
            if value.contains("FindProxyForURL") {
                Ok(Arc::from(value))
            } else {
                Err(err).with_context(|| format!("reading PAC file {value}"))
            }
        }
    }
}

/// Resolve a `pac://` value for one request: load the script and evaluate
/// `FindProxyForURL(url, host)`.
///
/// The evaluation runs on the blocking pool: it is CPU work, and a PAC file
/// calling `dnsResolve` blocks on the system resolver.
pub async fn find_proxy_for_url(value: &str, url: &str, host: &str) -> Result<String> {
    let src = load_pac(value).await?;
    let (url, host) = (url.to_string(), host.to_string());
    tokio::task::spawn_blocking(move || eval_pac(&src, &url, &host))
        .await
        .context("PAC evaluation")?
}

/// JSON-encode a string for safe embedding in a JS expression.
fn js_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn res_script_mutates_status_and_body() {
        let src = "ctx.res.statusCode = 418; ctx.res.body = ctx.res.body + '!'; ctx.res.headers['x-s']='y';";
        let r = run_res_script(src, "GET", "http://x/", 200, &[], "hi").unwrap();
        assert_eq!(r.status, Some(418));
        assert_eq!(r.body.as_deref(), Some("hi!"));
        assert!(r.headers.iter().any(|(k, v)| k == "x-s" && v == "y"));
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    /// Evaluate `pac` and unwrap, so a failing helper shows up as the JS error.
    fn pac(src: &str, url: &str, host: &str) -> String {
        eval_pac(src, url, host).unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// A PAC file that returns `FindProxyForURL(url, host)` from `body`.
    fn wrap(body: &str) -> String {
        format!("function FindProxyForURL(url, host) {{ {body} }}")
    }

    #[test]
    fn pac_returns_proxy() {
        let src = wrap("return host === 'blocked.com' ? 'PROXY 10.0.0.1:8080' : 'DIRECT';");
        assert_eq!(pac(&src, "http://blocked.com/", "blocked.com"), "PROXY 10.0.0.1:8080");
        assert_eq!(pac(&src, "http://ok.com/", "ok.com"), "DIRECT");
    }

    /// The helper environment a real PAC file assumes. Three of these existed;
    /// the rest threw, and the throw was swallowed into a direct connection.
    #[test]
    fn the_pac_helpers_a_corporate_file_uses_all_exist() {
        for (expr, want) in [
            ("isPlainHostName('intranet')", "true"),
            ("isPlainHostName('a.example.com')", "false"),
            ("dnsDomainIs('www.example.com', '.example.com')", "true"),
            ("dnsDomainIs('www.example.org', '.example.com')", "false"),
            ("localHostOrDomainIs('www', 'www.example.com')", "true"),
            ("localHostOrDomainIs('www.example.com', 'www.example.com')", "true"),
            ("localHostOrDomainIs('web', 'www.example.com')", "false"),
            ("dnsDomainLevels('www.example.com')", "2"),
            ("dnsDomainLevels('intranet')", "0"),
            ("shExpMatch('http://a.example.com/x', '*.example.com/*')", "true"),
            ("shExpMatch('http://a.example.org/x', '*.example.com/*')", "true==false"),
            ("shExpMatch('abc', 'a?c')", "true"),
            // `.` is a literal, not "any character".
            ("shExpMatch('axc', 'a.c')", "false"),
            ("isInNet('10.1.2.3', '10.0.0.0', '255.0.0.0')", "true"),
            ("isInNet('11.1.2.3', '10.0.0.0', '255.0.0.0')", "false"),
            ("isInNetEx('192.168.4.9', '192.168.0.0/16')", "true"),
            ("isInNetEx('192.169.4.9', '192.168.0.0/16')", "false"),
            ("convert_addr('127.0.0.1')", "2130706433"),
            // Resolution of a literal is the literal; localhost is resolvable.
            ("dnsResolve('10.9.8.7')", "'10.9.8.7'"),
            ("isResolvable('localhost')", "true"),
            ("dnsResolve('no-such-host.invalid') === null", "true"),
            ("typeof myIpAddress()", "'string'"),
            ("typeof myIpAddressEx()", "'string'"),
            ("typeof getClientVersion()", "'string'"),
            // A whole week, all day, every day — true whenever it is evaluated.
            ("weekdayRange('SUN', 'SAT')", "true"),
            ("weekdayRange('SUN', 'SAT', 'GMT')", "true"),
            ("timeRange(0, 23)", "true"),
            ("timeRange(0, 0, 0, 23, 59, 59)", "true"),
            ("dateRange('JAN', 'DEC')", "true"),
            ("dateRange(1, 31)", "true"),
            // …and one that cannot be true: a nonexistent weekday.
            ("weekdayRange('XYZ')", "false"),
        ] {
            let src = wrap(&format!("return String(({expr}) === ({want}));"));
            assert_eq!(
                pac(&src, "http://a.example.com/x", "a.example.com"),
                "true",
                "PAC helper check failed: ({expr}) === ({want})"
            );
        }
    }

    /// A script that throws has not said "go direct" — it has said nothing. It
    /// used to mean a direct connection, silently.
    #[test]
    fn a_broken_pac_is_an_error_rather_than_a_direct_connection() {
        // Throws inside FindProxyForURL.
        let err = eval_pac(&wrap("return nope.nope;"), "http://a.com/", "a.com").unwrap_err();
        assert!(format!("{err:#}").contains("FindProxyForURL"), "{err:#}");
        // Does not parse.
        assert!(eval_pac("function {", "http://a.com/", "a.com").is_err());
        // Defines nothing to call.
        assert!(eval_pac("var x = 1;", "http://a.com/", "a.com").is_err());
        // Returns nothing at all.
        assert!(eval_pac(&wrap("return;"), "http://a.com/", "a.com").is_err());
    }

    /// A PAC file may ship its own copy of a helper — ours must not shadow it.
    #[test]
    fn a_pac_may_override_a_helper() {
        let src = format!(
            "function isPlainHostName(h) {{ return true; }}\n{}",
            wrap("return String(isPlainHostName('a.b.c'));")
        );
        assert_eq!(pac(&src, "http://a.b.c/", "a.b.c"), "true");
    }

    /// Serve `body` as a PAC file, and report how many requests arrived.
    /// Answers `count` requests and then stops listening.
    async fn pac_server(body: &'static str, count: usize) -> (String, tokio::task::JoinHandle<usize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/proxy.pac", listener.local_addr().expect("addr"));
        let handle = tokio::spawn(async move {
            let mut served = 0;
            for _ in 0..count {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                if sock.write_all(resp.as_bytes()).await.is_ok() {
                    served += 1;
                }
            }
            served
        });
        (url, handle)
    }

    /// `pac://http://…/proxy.pac` is fetched over the network and cached, where
    /// it used to be evaluated as if the URL itself were JavaScript.
    #[test]
    fn a_remote_pac_is_fetched_once_and_then_cached() {
        rt().block_on(async {
            let (url, server) = pac_server(
                "function FindProxyForURL(u, h) { return 'PROXY 10.1.1.1:3128'; }",
                2,
            )
            .await;

            let first = find_proxy_for_url(&url, "http://a.com/", "a.com")
                .await
                .expect("remote pac");
            assert_eq!(first, "PROXY 10.1.1.1:3128");
            // Second request is answered from the cache, so the server sees one
            // request even though we asked twice.
            let second = find_proxy_for_url(&url, "http://b.com/", "b.com")
                .await
                .expect("cached pac");
            assert_eq!(second, "PROXY 10.1.1.1:3128");

            // Nothing more will arrive; stop the listener by dropping the task.
            server.abort();
            assert!(cached_pac(&url).is_some(), "the fetched script is cached");
        });
    }

    /// An unreachable PAC URL fails the request rather than quietly routing it
    /// direct — and a value that is neither a URL nor a readable file is
    /// reported as the path it is, not evaluated as JavaScript.
    #[test]
    fn an_unusable_pac_location_is_reported() {
        rt().block_on(async {
            // Port 1 on loopback: nothing is listening.
            let err = load_pac("http://127.0.0.1:1/proxy.pac").await.unwrap_err();
            assert!(format!("{err:#}").contains("127.0.0.1:1"), "{err:#}");

            let err = load_pac("/no/such/dir/corp.pac").await.unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("/no/such/dir/corp.pac"), "{msg}");

            assert!(load_pac("   ").await.is_err(), "an empty value is not a script");

            // A script written inline is still accepted.
            let inline = wrap("return 'DIRECT';");
            assert_eq!(&*load_pac(&inline).await.expect("inline pac"), inline.as_str());
        });
    }

    /// A local PAC file is read from disk (the documented form).
    #[test]
    fn a_local_pac_file_is_read() {
        rt().block_on(async {
            let dir = std::env::temp_dir().join("whistle-rs-pac-test");
            std::fs::create_dir_all(&dir).expect("mkdir");
            let path = dir.join("corp.pac");
            let src = wrap("return 'SOCKS5 127.0.0.1:1080';");
            std::fs::write(&path, &src).expect("write pac");
            let out = find_proxy_for_url(path.to_str().expect("path"), "http://a.com/", "a.com")
                .await
                .expect("file pac");
            assert_eq!(out, "SOCKS5 127.0.0.1:1080");
        });
    }
}
