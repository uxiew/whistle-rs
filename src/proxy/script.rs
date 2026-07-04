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

use boa_engine::{Context, Source, js_string};
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

/// Evaluate a PAC file's `FindProxyForURL(url, host)` and return its result
/// string (e.g. `"PROXY 127.0.0.1:8888"`, `"SOCKS ..."`, or `"DIRECT"`).
pub fn eval_pac(pac_src: &str, url: &str, host: &str) -> Option<String> {
    let mut ctx = Context::default();
    if ctx.eval(Source::from_bytes(pac_src.as_bytes())).is_err() {
        return None;
    }
    // Minimal PAC helpers so common files evaluate; extend as needed.
    let shim = "function isPlainHostName(h){return h.indexOf('.')<0;}\
                function dnsDomainIs(h,d){return h.length>=d.length && h.substring(h.length-d.length)===d;}\
                function shExpMatch(s,p){p=p.replace(/[.]/g,'\\\\.').replace(/[*]/g,'.*');return new RegExp('^'+p+'$').test(s);}";
    ctx.eval(Source::from_bytes(shim.as_bytes())).ok();

    let call = format!(
        "FindProxyForURL({}, {})",
        js_str(url),
        js_str(host)
    );
    let result = ctx.eval(Source::from_bytes(call.as_bytes())).ok()?;
    result
        .to_json(&mut ctx)
        .ok()??
        .as_str()
        .map(|s| s.to_string())
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

    #[test]
    fn pac_returns_proxy() {
        let pac = "function FindProxyForURL(url, host){ return host==='blocked.com' ? 'PROXY 10.0.0.1:8080' : 'DIRECT'; }";
        assert_eq!(eval_pac(pac, "http://blocked.com/", "blocked.com").as_deref(), Some("PROXY 10.0.0.1:8080"));
        assert_eq!(eval_pac(pac, "http://ok.com/", "ok.com").as_deref(), Some("DIRECT"));
    }
}
