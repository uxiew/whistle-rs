//! Translate resolved rules into concrete request/response mutations.
//!
//! Ported from the request/response inspectors in `_original/lib/inspectors/`
//! (`req.js`, `res.js`) and the handlers. Implements the most-used operators;
//! others parse and resolve but are not yet applied (documented in README).

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request;
use hyper::http::response;
use hyper::{HeaderMap, Response, StatusCode};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use super::body::{self, DynBody};
use super::upstream::{ProxyKind, Target, parse_proxy, parse_proxy_rule};
use crate::rules::{LineProps, ReqInfo, Resolved, RuleManager, RuleOp};

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
        // Set by the caller when it knows them: the client's port comes from the
        // accepted socket, the response head only exists later, and the body is
        // buffered only when a `b:` filter has asked for it.
        client_port: None,
        res: None,
        req_body: None,
    }
}

/// The response facts the second resolution pass needs.
///
/// Read from the response head exactly as it arrived, before any operator or
/// plugin has touched it — upstream stamps `req.statusCode` / `req.resHeaders`
/// from the raw upstream response too (`_original/lib/inspectors/res.js:802-806`).
pub fn build_res_info(
    status: u16,
    headers: &HeaderMap,
    server_ip: Option<String>,
    server_port: Option<u16>,
) -> crate::rules::ResInfo {
    crate::rules::ResInfo {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect(),
        server_ip,
        server_port,
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

/// Merge an ad-hoc rules text (e.g. produced by a plugin) into the resolved set.
/// Existing single-match operators win; multi-match operators accumulate.
///
/// `is_internal_req` carries the request's origin through, so an
/// `internal`/`internalOnly` line inside injected rules is scoped exactly as it
/// would be at top level.
///
/// The manager is **returned, not dropped**: it holds the parsed rules the
/// response phase resolves a second time — see [`merge_response_phase_of`].
#[must_use = "the caller must keep this for the response phase"]
pub fn merge_rules_text(
    resolved: &mut Resolved,
    info: &ReqInfo,
    text: &str,
    is_internal_req: bool,
) -> RuleManager {
    let mut mgr = RuleManager::new();
    mgr.set_text(text);
    merge_resolved(resolved, mgr.resolve_scoped(info, is_internal_req));
    mgr
}

/// Resolve a rules text merged mid-request a second time, now that the response
/// head is in, and fold what it withheld into `resolved`.
///
/// Upstream re-resolves exactly these managers in its response phase —
/// `pRules` (a plugin's rules), `fRules` (the `rulesFile://` manager) and
/// `hRules`, each through `resolveResRules(req, true)`
/// (`_original/lib/plugins/index.js:1326-1335`). This port resolved them once,
/// so a `resHeaders://x=1 includeFilter://s:404` inside an included file never
/// fired.
///
/// The two passes are the same pair the top-level rules take, which is what
/// makes this safe: the request pass **withheld** precisely what this resolves,
/// so nothing is applied twice and nothing is re-decided. (Re-resolving the
/// whole text instead would re-roll a `chance:` on it, and would discard a
/// request-phase verdict the request has already acted on.)
///
/// Costs nothing when the text has no response-dependent line: `resolve_response`
/// answers from the flags its groups precomputed, so `None` here is one
/// comparison per merged text.
///
/// The managers are folded into **one** set rather than merged one at a time, so
/// that the caller can substitute values into it and hand it to
/// [`Resolved::merge_response_phase`] once — which is what lets an `ignore://`
/// inside an included file reach the request phase's operators.
pub fn response_phase_of(
    managers: &[RuleManager],
    info: &ReqInfo,
    is_internal_req: bool,
) -> Option<Resolved> {
    let mut out: Option<Resolved> = None;
    for mgr in managers {
        let Some(extra) = mgr.resolve_response(info, is_internal_req) else {
            continue;
        };
        let acc = out.get_or_insert_with(Resolved::default);
        // Merged rules sort behind everything either pass of the file they were
        // merged into resolved, in the request phase and in this one alike.
        for (protocol, mut op) in extra.single {
            op.order = u64::MAX;
            acc.single.entry(protocol).or_insert(op);
        }
        for (protocol, ops) in extra.multi {
            acc.multi.entry(protocol).or_default().extend(ops.into_iter().map(|mut op| {
                op.order = u64::MAX;
                op
            }));
        }
    }
    out
}

/// Fold a resolution of *another* rules text into `resolved`: existing
/// single-match operators win, multi-match operators accumulate at the end.
///
/// The merged operators are stamped with the last possible [`RuleOp::order`], so
/// the response phase — which inserts by that key — still slots its own
/// operators in front of them, where the operators of the rules file they were
/// merged into already are.
fn merge_resolved(resolved: &mut Resolved, sub: Resolved) {
    for (k, mut v) in sub.single {
        v.order = u64::MAX;
        resolved.single.entry(k).or_insert(v);
    }
    for (k, vs) in sub.multi {
        let list = resolved.multi.entry(k).or_default();
        list.extend(vs.into_iter().map(|mut op| {
            op.order = u64::MAX;
            op
        }));
    }
}

/// Merge the rules pulled in by `rule://<name>` (from the values store) and
/// `rulesFile://<path>` (from disk), resolved in the request's own scope.
///
/// The managers are returned so the response phase can resolve them again —
/// see [`merge_response_phase_of`].
#[must_use = "the caller must keep these for the response phase"]
pub fn merge_included_rules(
    resolved: &mut Resolved,
    info: &ReqInfo,
    values: &HashMap<String, String>,
    is_internal_req: bool,
) -> Vec<RuleManager> {
    let mut texts: Vec<String> = Vec::new();
    if let Some(name) = resolved.value("rule") {
        if let Some(content) = values.get(name) {
            texts.push(content.clone());
        }
    }
    // Every `rulesFile://` line contributes, joined into one rules text — see
    // `accumulated_script_ops`.
    let joined = rules_file_ops(resolved)
        .iter()
        .filter_map(|op| std::fs::read_to_string(&op.value).ok())
        .collect::<Vec<_>>()
        .join("\n");
    if !joined.trim().is_empty() {
        texts.push(joined);
    }
    texts
        .into_iter()
        .map(|text| {
            let mut mgr = RuleManager::new();
            mgr.set_text(&text);
            merge_resolved(resolved, mgr.resolve_scoped(info, is_internal_req));
            mgr
        })
        .collect()
}

/// The `rulesFile://` operators whose contents make up the included rules text.
pub fn rules_file_ops(resolved: &Resolved) -> Vec<&RuleOp> {
    accumulated_script_ops(resolved, "rulesFile", "reqRules")
}

/// The `resScript://` operator that names a script, if any.
///
/// Upstream's `resScript` list can hold *rules text* as well as a script — the
/// `resRules://` spelling marks the former — and only the first entry that is
/// not so marked is ever executed (`_original/lib/rules/rules.js:2258-2272`).
/// This port used the first entry whatever its spelling, so a file of rules
/// written ahead of the script was handed to the JS engine instead of it.
///
/// The `resRules://` entries themselves are **not** applied here: upstream folds
/// them into a rules text that the response phase parses, whereas this port's
/// `resScript` is a JavaScript hook that mutates the response directly. See
/// `docs/ROADMAP.md`.
pub fn res_script_op(resolved: &Resolved) -> Option<&RuleOp> {
    accumulated_script_ops(resolved, "resScript", "resRules")
        .into_iter()
        .find(|op| raw_protocol(op) != Some("resRules"))
}

/// The entries upstream keeps for `rulesFile` / `resScript`
/// (`_original/lib/rules/rules.js:2258-2272`).
///
/// Both protocols accumulate, but the list is filtered before it is read: every
/// line written with the `pure_spelling` alias (`reqRules://` for `rulesFile`,
/// `resRules://` for `resScript`) is kept, because it can only be rules text,
/// while **at most one** line written any other way survives — that one is the
/// candidate *script*, and a second script would have no defined meaning.
///
/// `RuleOp::raw` is what makes the distinction visible after parsing: the
/// aliases all fold to one canonical protocol name, but `raw` still carries the
/// spelling the rules file used.
fn accumulated_script_ops<'a>(
    resolved: &'a Resolved,
    protocol: &str,
    pure_spelling: &str,
) -> Vec<&'a RuleOp> {
    let mut seen_script = false;
    resolved
        .all(protocol)
        .iter()
        .filter(|op| {
            if raw_protocol(op) == Some(pure_spelling) {
                return true;
            }
            !std::mem::replace(&mut seen_script, true)
        })
        .collect()
}

/// The protocol an operator was *written* with, before alias folding.
fn raw_protocol(op: &RuleOp) -> Option<&str> {
    op.raw.split_once("://").map(|(proto, _)| proto)
}

/// How to reach the proxy each upstream-proxy operator names.
///
/// Only the transport is decided here. The scheme conversions two of the names
/// promise are a separate question, answered by [`origin_tls`]: `internal-*` and
/// `https2http-proxy` speak plain HTTP *to* the proxy either way.
fn proxy_kind(proto: &str) -> ProxyKind {
    match proto {
        "socks" => ProxyKind::Socks,
        "https-proxy" | "internal-https-proxy" => ProxyKind::Https,
        _ => ProxyKind::Http,
    }
}

/// The protocol of the matched upstream-proxy rule, if one matched at all.
/// Cheap on purpose: it answers "is there a proxy rule?" without parsing the
/// value or evaluating a PAC script.
fn matched_proxy_proto(resolved: &Resolved) -> Option<&'static str> {
    crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .copied()
        .find(|proto| resolved.value(proto).is_some())
}

/// The winning upstream proxy, with the protocol that supplied it so its line
/// properties can be read back. `Ok(None)` means "no proxy rule matched, or the
/// one that did chose a direct connection".
///
/// Every other outcome is an error, and that is the point: a rule that names a
/// proxy has said where the request must go. When the address is unusable, or a
/// PAC file cannot be fetched or throws, the request cannot go there — and
/// sending it straight to the origin instead would quietly do the one thing the
/// rule ruled out. whistle degrades to a direct connection in both cases (an
/// empty matcher is falsy at `_original/lib/inspectors/res.js:214`; a failed PAC
/// only reaches `logger.error`, `lib/rules/index.js:295`), so this port is
/// deliberately stricter. See `docs/RULES.md`.
async fn find_proxy(
    info: &ReqInfo,
    resolved: &Resolved,
) -> Result<Option<(&'static str, super::upstream::ProxyConfig)>> {
    // Upstream files every proxy spelling under a single `proxy` key, so the
    // first matching *rule line* wins rather than a protocol priority
    // (`PROXY_RE` → `protocol = 'proxy'`, `_original/lib/rules/rules.js:1286`).
    // This port keeps one key per protocol, so rule order is recovered from the
    // winning operator's resolution order.
    let first_by_rule_order = crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .copied()
        .filter_map(|proto| resolved.get(proto).map(|op| (proto, op)))
        .min_by_key(|(_, op)| op.order);
    if let Some((proto, op)) = first_by_rule_order {
        // `parse_proxy_rule` reads the address and the `?host=` override off the
        // matcher as written; whistle's other query flags (`?proxyHost`) are not
        // part of either.
        let mut cfg = parse_proxy_rule(proxy_kind(proto), &op.value)
            .ok_or_else(|| anyhow!("{proto}://{} is not a usable proxy address", op.value))?;
        cfg.tunnel = proxy_tunnel(resolved, proto);
        // The `x`-prefixed spellings ask for a direct connection if the hop
        // fails (`X_RE`, `_original/lib/inspectors/res.js:31`).
        cfg.fallback_direct = op.raw.starts_with('x');
        return Ok(Some((proto, cfg)));
    }
    // `pac://` picks the proxy by evaluating FindProxyForURL, from a local file,
    // an inline script, or a URL that is fetched and cached.
    let Some(pac_val) = resolved.value("pac") else {
        return Ok(None);
    };
    let result = crate::proxy::script::find_proxy_for_url(pac_val, &info.full_url, &info.host)
        .await
        .with_context(|| format!("pac://{pac_val}"))?;
    match parse_pac_result(&result)? {
        Some(cfg) => Ok(Some(("pac", cfg))),
        None => Ok(None),
    }
}

/// `proxyTunnel`: the address the hop connects to is itself a proxy, so CONNECT
/// onward through it. Written on the proxy line, on the `host://` line, or
/// request-wide with `enable://proxyTunnel` (`_original/lib/rules/index.js:85-89`).
fn proxy_tunnel(resolved: &Resolved, proxy_proto: &str) -> bool {
    resolved.props(proxy_proto).has("proxyTunnel")
        || resolved.props("host").has("proxyTunnel")
        || enabled_flags(resolved).contains("proxyTunnel")
}

/// `?proxyHost` / `&proxyHosts` written into an upstream proxy's own URL —
/// whistle's URL-borne spelling of the line property
/// (`PROXY_HOSTS_RE`, `_original/lib/rules/index.js:80,:168`).
fn proxy_host_flag(value: &str) -> bool {
    let Some((_, query)) = value.split_once('?') else {
        return false;
    };
    query
        .split('&')
        .any(|seg| seg.eq_ignore_ascii_case("proxyHost") || seg.eq_ignore_ascii_case("proxyHosts"))
}

/// Does a matched upstream proxy survive next to a matched `host://` rule?
///
/// whistle's default is that `host` wins outright: with both matched, the proxy
/// is dropped and the request goes straight to the host address
/// (`_original/lib/rules/index.js:220-237`). The line properties invert that:
///
/// * `proxyHost` (on either line) — use both: reach the origin through the
///   proxy, but have the proxy connect to the `host://` address (`_phost`);
/// * `proxyHostOnly` — as `proxyHost`, and additionally drop the proxy when no
///   `host://` rule matched, since there is then no host for it to apply;
/// * `proxyFirst` (on either line) — prefer the proxy over the plain host.
///
/// `enable://proxyHost` / `enable://proxyFirst` say the same request-wide.
fn proxy_survives_host(resolved: &Resolved, proxy_proto: &str, host_matched: bool) -> bool {
    let proxy_props = resolved.props(proxy_proto);
    let host_props = resolved.props("host");
    let proxy_host_only = proxy_props.has("proxyHostOnly");
    if !host_matched {
        return !proxy_host_only;
    }
    let enabled = enabled_flags(resolved);
    let url_flag = proxy_proto != "pac"
        && resolved
            .value(proxy_proto)
            .map(proxy_host_flag)
            .unwrap_or(false);
    proxy_host_only
        || url_flag
        || proxy_props.has("proxyHost")
        || host_props.has("proxyHost")
        || enabled.contains("proxyHost")
        || proxy_props.has("proxyFirst")
        || host_props.has("proxyFirst")
        || enabled.contains("proxyFirst")
}

/// Compute the upstream target, honouring `host://` (and `:port`) overrides.
///
/// Fails rather than falling back to a direct connection when a proxy rule
/// matched but could not be honoured; see [`find_proxy`].
pub async fn resolve_target(info: &ReqInfo, resolved: &Resolved) -> Result<Target> {
    let mut connect_host = info.host.clone();
    let mut connect_port = info.port;

    let host_op = resolved.get("host");
    let host_rule = host_op.map(|op| op.value.as_str());
    if let Some(value) = host_rule {
        let (h, p) = parse_host_value(value, info.port);
        if let Some(h) = h {
            connect_host = h;
        }
        if let Some(p) = p {
            connect_port = p;
        }
    }
    // `xhost://` is the pass-through spelling: the address is used if it works
    // and ignored if it does not, where plain `host://` fails the request
    // (`retryXHost`, `_original/lib/inspectors/res.js:571-600`). The `x` is only
    // visible on the matcher as written — both spellings resolve to the same
    // `host` operator (`xhost: 'host'`, `_original/lib/rules/protocols.js:145`).
    let host_fallback_direct = host_op.is_some_and(|op| op.raw.starts_with('x'));

    let matched = find_proxy(info, resolved)
        .await?
        .filter(|(proto, _)| proxy_survives_host(resolved, proto, host_rule.is_some()));
    let (proxy_proto, proxy) = match matched {
        Some((proto, cfg)) => (Some(proto), Some(cfg)),
        None => (None, None),
    };

    let request_tls = info.scheme == "https" || info.scheme == "wss";
    let tls = origin_tls(request_tls, proxy_proto);
    Ok(Target {
        connect_host,
        connect_port,
        tls,
        // Whether the hop stripped the origin's TLS: the request then carries
        // whistle's marker so the whistle on the far side can put it back.
        origin_tls_stripped: request_tls && !tls,
        sni: info.host.clone(),
        request_port: info.port,
        proxy,
        tls_versions: resolved
            .value("cipher")
            .map(parse_cipher_versions)
            .unwrap_or_default(),
        host_fallback_direct,
    })
}

/// Does the connection to the origin speak TLS?
///
/// Normally the request's own scheme decides. Two families of proxy operator
/// exist to override it, and until now neither did — traffic went out in
/// whatever the scheme said, so `http2https-proxy://` left cleartext on the wire
/// that the rule promised to encrypt:
///
/// * `http2https-proxy://` turns an http origin into an https one
///   (`options.protocol = 'https:'`, `_original/lib/inspectors/res.js:236-237`,
///   and `wss = true` for the WebSocket path, `lib/https/index.js:323-324`);
/// * `https2http-proxy://` and the `internal-*` family are hops to another
///   whistle, which wants the request in plaintext so it can inspect it: the
///   origin's TLS is stripped and a marker header carries the fact across
///   (`headers[config.HTTPS_FIELD] = 1; options.protocol = null;`,
///   `res.js:229-234`). Note that this sends cleartext to the proxy — it is what
///   the operator's name asks for, and the receiving whistle restores the
///   scheme, but it is worth knowing before pointing one at a public proxy.
///
/// A `pac://`-chosen proxy converts nothing: whistle reads the conversion off
/// the rule's own protocol, and PAC results carry no whistle protocol.
fn origin_tls(request_tls: bool, proxy_proto: Option<&str>) -> bool {
    match proxy_proto {
        Some("http2https-proxy") => true,
        Some("https2http-proxy" | "internal-proxy" | "internal-http-proxy"
            | "internal-https-proxy") => false,
        _ => request_tls,
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

/// Collect flag names from `enable`/`disable` operators.
///
/// The separators are `|` and `&` — upstream's `parseProps`
/// (`_original/lib/util/common.js:72,98`) recognises no others, so a
/// comma-separated list is one long flag name in both implementations.
fn flag_set(resolved: &Resolved, protocol: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for v in collect_values(resolved, protocol) {
        for f in v.split(['|', '&']) {
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

/// `disable://<flag>` — with the escape hatch upstream gives it: an
/// `enable://<flag>` on the same request wins (`isDisable`,
/// `_original/lib/util/index.js:681-683`).
fn is_disabled(resolved: &Resolved, flag: &str) -> bool {
    disabled_flags(resolved).contains(flag) && !enabled_flags(resolved).contains(flag)
}

/// True if the request should be aborted (`enable://abort`/`abortReq`/`abortRes`).
pub fn is_aborted(resolved: &Resolved) -> bool {
    let e = enabled_flags(resolved);
    e.contains("abort") || e.contains("abortReq") || e.contains("abortRes")
}

/// Parse a PAC `FindProxyForURL` return value into a proxy (first usable entry).
///
/// `DIRECT` — anywhere in the list — yields `Ok(None)`: the script was asked
/// where to send the request and answered "nowhere in particular". A result with
/// no usable entry and no `DIRECT` is an error instead, because the script *did*
/// name somewhere and we could not act on it. `SOCKS4` is such a case: this port
/// speaks SOCKS5 only, and quietly going direct would hide that.
fn parse_pac_result(result: &str) -> Result<Option<super::upstream::ProxyConfig>> {
    for entry in result.split(';') {
        let mut it = entry.split_whitespace();
        let kind = it.next().unwrap_or("").to_ascii_uppercase();
        let hostport = it.next().unwrap_or("");
        let parsed = match kind.as_str() {
            "" => continue,
            "DIRECT" => return Ok(None),
            "PROXY" | "HTTP" => parse_proxy(ProxyKind::Http, hostport),
            "HTTPS" => parse_proxy(ProxyKind::Https, hostport),
            "SOCKS" | "SOCKS5" => parse_proxy(ProxyKind::Socks, hostport),
            _ => None,
        };
        if let Some(p) = parsed {
            return Ok(Some(p));
        }
    }
    bail!("FindProxyForURL returned no usable proxy: {result:?}");
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
pub fn short_circuit(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::template::ProxyEnv<'_>,
) -> Option<Response<DynBody>> {
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
        if !weak_rule_yields(resolved, proto) {
            return serve_file_family(proto, value, info, env);
        }
    }

    None
}

/// `weakRule` — the local-file rule steps aside for a matching `proxy`/`host`
/// rule instead of answering the request, inverting the usual precedence
/// (`filterWeakRule`, `_original/lib/util/index.js:3733-3745`).
///
/// Upstream drops the local rule when a `host://` rule matched, or when a proxy
/// rule matched that is *not* `proxyHostOnly` — that spelling needs a host rule
/// to mean anything, so on its own it does not outrank the file.
/// `enable://weakRule` says the same request-wide.
fn weak_rule_yields(resolved: &Resolved, file_proto: &str) -> bool {
    if !resolved.props(file_proto).has("weakRule") && !enabled_flags(resolved).contains("weakRule") {
        return false;
    }
    if resolved.value("host").is_some() {
        return true;
    }
    matched_proxy_proto(resolved)
        .map(|proto| !resolved.props(proto).has("proxyHostOnly"))
        .unwrap_or(false)
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
fn serve_file_family(
    proto: &str,
    value: &str,
    info: &ReqInfo,
    env: super::template::ProxyEnv<'_>,
) -> Option<Response<DynBody>> {
    let raw = proto.contains("rawfile");
    // `tpl`, `dust` and `jsonp` are one protocol in whistle
    // (`_original/lib/handlers/file-proxy.js:14`); none of them has any
    // protocol-specific behaviour of its own.
    let templated = proto.ends_with("tpl") || proto.ends_with("jsonp") || proto.ends_with("dust");
    let cross = proto.starts_with('x');

    let candidates = FileCandidates::of(proto, value);
    match candidates.read() {
        // The *matched* path drives the content type, not the rule value: with
        // `file:///tmp/mock/` it is `/tmp/mock/index.html` that was served.
        Some((path, data)) => Some(if raw {
            serve_raw_http(&data, &path, info)
        } else if templated {
            serve_template(&data, &path, info, env)
        } else {
            serve_file_bytes(&data, &path, info)
        }),
        // A cross (`x`/`xs`) rule falls through to the real server instead —
        // including when the path was refused (`file-proxy.js:298-303`).
        None if cross => None,
        None => Some(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(body::full(Bytes::from(format!(
                    "whistle-rs: file not found <strong>{}</strong>",
                    encode_html(&candidates.blame)
                ))))
                .unwrap(),
        ),
    }
}

/// The marker whistle reports instead of a path it refused to resolve
/// (`INVALID_PATH`, `_original/lib/handlers/file-proxy.js:29,52`).
const INVALID_PATH: &str = "(Path contains parent directory notation '..')";

/// The paths a file rule may resolve to, in the order whistle tries them.
///
/// A rule value is not simply a path: it can list several with `|`, name a
/// directory, start at the home directory, and — in whistle-rs — omit the
/// leading slash. Building the whole list up front keeps the "first one that is
/// a file wins" rule (`readFiles`, `file-proxy.js:38-58`) a single loop, and
/// keeps the 404 able to name what was actually tried.
struct FileCandidates {
    paths: Vec<String>,
    /// What a 404 should blame: the last path the user actually wrote, or
    /// [`INVALID_PATH`] when that entry was refused for containing `..`.
    blame: String,
}

impl FileCandidates {
    fn of(proto: &str, value: &str) -> FileCandidates {
        let mut paths = Vec::new();
        let mut blame = String::new();
        for entry in split_paths(proto, value) {
            let entry = expand_home(entry);
            if has_parent_ref(&entry) {
                // `joinPath` refuses the path outright (`util/index.js:1847-1849`)
                // and `readFiles` reports it with a fixed marker; it contributes
                // no candidate, so a later `|` alternative can still win.
                blame = INVALID_PATH.to_string();
                continue;
            }
            for candidate in expand_index(&entry) {
                // whistle-rs also accepts a value whose leading slash the rule
                // parser dropped (`file://tmp/x`), which upstream resolves
                // against the rule file's root instead. It is a fallback, so it
                // is tried after the path as written and never blamed in a 404.
                let rooted = format!("/{}", candidate.trim_start_matches('/'));
                blame = candidate.clone();
                if rooted != candidate {
                    paths.push(candidate);
                }
                paths.push(rooted);
            }
        }
        FileCandidates { paths, blame }
    }

    /// The first candidate that is a readable regular file.
    fn read(&self) -> Option<(String, Arc<Vec<u8>>)> {
        self.paths
            .iter()
            .find_map(|p| read_cached(Path::new(p)).map(|data| (p.clone(), data)))
    }
}

/// Split a `a|b|c` multi-path value (`getFiles`, `_original/lib/rules/rules.js:290`).
///
/// whistle only splits when the protocol matches `FILE_PROTO_RE`
/// (`rules.js:96`), whose `x?` prefix admits a *single* `x` — so `xsfile://` and
/// its siblings are never split. whistle-rs reproduces the quirk rather than
/// tidying it up: `|` is a legal character in a POSIX filename, so "fixing" it
/// would change what an existing rule file resolves to.
fn split_paths<'a>(proto: &str, value: &'a str) -> Vec<&'a str> {
    match proto.starts_with("xs") {
        true => vec![value],
        false => value.split('|').collect(),
    }
}

/// `~/x` (and the full-width `～/x`) start at the home directory
/// (`getHomePath`, `_original/lib/util/common.js:557-564`). A bare `~` is left
/// alone: upstream's `/^[~～]\//` requires the slash.
fn expand_home(path: &str) -> String {
    let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("～/")) else {
        return path.to_string();
    };
    match dirs::home_dir() {
        // Upstream falls back to a literal `~` when the OS has no home
        // directory; leaving the path untouched has the same effect.
        Some(home) => format!("{}/{rest}", home.to_string_lossy().trim_end_matches('/')),
        None => path.to_string(),
    }
}

/// whistle's `UP_PATH_REGEXP` (`_original/lib/util/common.js:29`): a `..` that
/// stands alone as a path segment. A file named `a..b` is perfectly fine.
fn has_parent_ref(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

/// A trailing slash means "a directory", which whistle expands into two
/// candidates: the directory name itself, then its `index.html`
/// (`getRuleFiles`, `_original/lib/util/index.js:1433-1437`). The first only
/// ever wins for a *file* that happens to be named like the directory.
fn expand_index(path: &str) -> Vec<String> {
    match path.ends_with(['/', '\\']) {
        true => vec![
            path[..path.len() - 1].to_string(),
            format!("{path}index.html"),
        ],
        false => vec![path.to_string()],
    }
}

/// whistle's `encodeHtml` (`_original/lib/util/common.js:619-635`), so a path
/// echoed into the 404 body cannot inject markup.
fn encode_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '`' => out.push_str("&#96;"),
            _ => out.push(c),
        }
    }
    out
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

/// Read one candidate path through the mtime-keyed cache.
///
/// Every call still `stat`s the file, so an edit is picked up immediately; only
/// the read of an unchanged file is skipped. The one gap is a rewrite that both
/// preserves the byte length *and* lands within the filesystem's mtime
/// resolution of the previous one — a second-granularity filesystem can then
/// serve the previous body once.
///
/// Beyond the `..` check in [`FileCandidates`] there is no sandboxing:
/// `file://` exists to serve arbitrary local paths on the developer's own
/// machine, and the original imposes no restriction on absolute paths either.
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

/// How far into a `rawfile://` whistle looks for the header/body separator
/// before giving up and serving the file as an ordinary body
/// (`MAX_HEADERS_SIZE`, `_original/lib/handlers/file-proxy.js:13,151-158`).
const MAX_RAW_HEADERS: usize = 256 * 1024;

/// Serve a `rawfile://`: the file is a complete HTTP response (status line +
/// headers + blank line + body). Parse it into a real response.
///
/// A file with no blank line in its first [`MAX_RAW_HEADERS`] bytes is not a
/// raw response at all, and whistle serves it verbatim rather than mistaking
/// its first line for a status line.
fn serve_raw_http(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    let budget = &data[..data.len().min(MAX_RAW_HEADERS)];
    let Some((head_end, body_start)) = find_headers_sep(budget) else {
        return serve_file_bytes(data, path, info);
    };
    // Only the head is text; the body stays bytes so a binary payload survives.
    let head = String::from_utf8_lossy(&data[..head_end]);
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
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
        .body(body::full(Bytes::copy_from_slice(&data[body_start..])))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::OK)
                .body(body::empty())
                .unwrap()
        })
}

/// Locate the blank line separating a raw response's head from its body,
/// returning `(head_end, body_start)`.
///
/// whistle accepts every CR/LF spelling of a blank line
/// (`HEADERS_SEP_RE = /(\r?\n(?:\r\n|\r|\n)|\r\r\n?)/`, `file-proxy.js:12`),
/// because a hand-written `.http` fixture rarely has consistent line endings.
fn find_headers_sep(data: &[u8]) -> Option<(usize, usize)> {
    for start in 0..data.len() {
        // `\r?\n` followed by any of `\r\n`, `\r`, `\n`.
        let after_first = start + usize::from(data[start] == b'\r');
        if data.get(after_first) == Some(&b'\n') {
            let second = after_first + 1;
            let end = match (data.get(second), data.get(second + 1)) {
                (Some(b'\r'), Some(b'\n')) => Some(second + 2),
                (Some(b'\r') | Some(b'\n'), _) => Some(second + 1),
                _ => None,
            };
            if let Some(end) = end {
                return Some((start, end));
            }
        }
        // `\r\r\n?` — the alternative whistle tries when the first one fails.
        if data[start] == b'\r' && data.get(start + 1) == Some(&b'\r') {
            let end = start + if data.get(start + 2) == Some(&b'\n') { 3 } else { 2 };
            return Some((start, end));
        }
    }
    None
}

/// Serve a `tpl://`/`jsonp://`/`dust://`: render the file through the two
/// substitution passes in [`super::template`]. The status is always 200 and
/// `content-length` follows from the rendered body, never the file's size.
fn serve_template(
    data: &[u8],
    path: &str,
    info: &ReqInfo,
    env: super::template::ProxyEnv<'_>,
) -> Response<DynBody> {
    let rendered = super::template::render(&String::from_utf8_lossy(data), info, env);
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .body(body::full(Bytes::from(rendered)))
        .unwrap()
}

/// Content type for a served file, following whistle's fallback chain
/// (`_original/lib/handlers/file-proxy.js:255-258`): the file's own extension
/// first, then the *request URL's* extension, then `text/html`.
///
/// That second step is what makes `example.com/a.json file:///tmp/mock` serve
/// JSON even though the mock file has no extension.
fn content_type_for(path: &str, full_url: &str) -> &'static str {
    match content_type_of_ext(path) {
        Some(ct) => ct,
        // Strip query/fragment before looking at the URL's extension.
        None => {
            let pure = full_url
                .split(['?', '#'])
                .next()
                .unwrap_or(full_url);
            content_type_of_ext(pure).unwrap_or("text/html; charset=utf-8")
        }
    }
}

/// Map a path's extension to a content type, or `None` when there is no
/// extension in the final path segment.
fn content_type_of_ext(path: &str) -> Option<&'static str> {
    let last = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = last.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "txt" | "text" => "text/plain; charset=utf-8",
        _ => return None,
    })
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
        set_content_type(&mut parts.headers, ct, req_type_alias);
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
    apply_deletes(&mut parts.headers, &del);
    apply_header_replace(&mut parts.headers, resolved, true);
}

/// The `delete://` keys that apply to one side, already classified.
///
/// whistle does not take a bare name: every key is matched against a fixed set
/// of anchored patterns (`_original/lib/util/index.js:2661-2669`) and anything
/// unrecognised is silently ignored. `delete://server` therefore deletes
/// nothing at all — the header spellings are `resHeaders.server`,
/// `res.headers.server`, `resH.server` (case-insensitive) or the side-agnostic
/// `headers.server` (case-**sensitive**, and only in the plural).
#[derive(Default)]
struct Deletions {
    /// Header names to remove from this side.
    headers: Vec<String>,
    /// Cookie names to remove (request side only).
    cookies: Vec<String>,
    /// `delete://resType` — drop the media type, keeping any charset.
    drop_type: bool,
    /// `delete://resCharset` — drop the charset, keeping the media type.
    drop_charset: bool,
    /// `delete://body` / `delete://res.body` — empty the body outright, which
    /// also discards anything an operator meant to inject (`removeBody`,
    /// `_original/lib/util/index.js:3592-3598`).
    drop_body: bool,
    /// `delete://resBody.a.b` — dotted paths to remove from a JSON body.
    body_props: Vec<String>,
}

impl Deletions {
    /// True when a `delete://` key on its own needs the body buffered.
    fn touches_body(&self) -> bool {
        self.drop_body || !self.body_props.is_empty()
    }
}

impl Deletions {
    /// Classify every `delete://` key for one side.
    fn of(resolved: &Resolved, request_side: bool) -> Deletions {
        let mut del = Deletions::default();
        let side = if request_side { "req" } else { "res" };
        for value in collect_values(resolved, "delete") {
            // `parseProps` splits on `|` and `&` only (`common.js:72,98`).
            for key in value.split(['|', '&']) {
                let key = key.trim();
                if key.is_empty() {
                    continue;
                }
                if let Some(name) = strip_del_scope(key, side, "H", "eaders") {
                    del.headers.push(name.to_string());
                } else if let Some(name) = key.strip_prefix("headers.") {
                    del.headers.push(name.to_string());
                } else if let Some(name) = strip_del_scope(key, side, "C", "ookies")
                    .or_else(|| strip_del_scope(key, "", "C", "ookies"))
                {
                    // `cookies.x` with no side is honoured on both
                    // (`COOKIE_RE`, `_original/lib/util/index.js:2669`).
                    if request_side {
                        del.cookies.push(name.to_string());
                    }
                } else if let Some(path) = strip_del_scope(key, side, "B", "ody") {
                    del.body_props.push(path.to_string());
                } else if key == format!("{side}Type") || key == format!("{side}.type") {
                    del.drop_type = true;
                } else if key == format!("{side}Charset") || key == format!("{side}.charset") {
                    del.drop_charset = true;
                } else if key == "body" || key == format!("{side}.body") {
                    del.drop_body = true;
                }
            }
        }
        del
    }
}

/// Match one of whistle's `^<side>\.?<initial>(?:<rest>s?)?\.(.+)$` delete keys
/// (case-insensitive), returning the trailing name.
///
/// One regex covers `resHeaders.x`, `res.headers.x`, `resHeader.x`, `resH.x` and
/// `res.h.x`; the same shape with `C`/`ookies` covers the cookie spellings.
fn strip_del_scope<'a>(key: &'a str, side: &str, initial: &str, rest: &str) -> Option<&'a str> {
    let tail = key.get(..side.len()).filter(|p| p.eq_ignore_ascii_case(side))?;
    let mut tail = &key[tail.len()..];
    tail = tail.strip_prefix('.').unwrap_or(tail);
    let after_initial = tail.get(..initial.len()).filter(|c| c.eq_ignore_ascii_case(initial))?;
    tail = &tail[after_initial.len()..];
    // The word may be spelled out in full, with an optional plural `s`.
    for word in [rest, &rest[..rest.len() - 1]] {
        if let Some(t) = tail.get(..word.len()).filter(|w| w.eq_ignore_ascii_case(word)) {
            tail = &tail[t.len()..];
            break;
        }
    }
    tail.strip_prefix('.').filter(|name| !name.is_empty())
}

/// Apply the header and cookie deletions for one side.
fn apply_deletes(headers: &mut HeaderMap, del: &Deletions) {
    for name in &del.headers {
        remove_header(headers, name);
    }
    for name in &del.cookies {
        remove_cookie(headers, name);
    }
}

fn remove_header(headers: &mut HeaderMap, name: &str) {
    if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
        headers.remove(&n);
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
fn apply_header_replace(headers: &mut HeaderMap, resolved: &Resolved, request_side: bool) {
    let scopes: [&str; 2] = match request_side {
        true => ["req.", "reqH."],
        false => ["res.", "resH."],
    };
    for value in collect_values(resolved, "headerReplace") {
        let value = value.trim();
        let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
        else {
            continue;
        };
        for (key, repl) in map {
            let repl = repl.as_str().unwrap_or("");
            if !scopes.iter().any(|s| key.starts_with(s)) {
                continue;
            }
            // A key with no `:` has no pattern and is dropped: upstream slices
            // the name up to `indexOf(':')`, which is then empty.
            let Some(colon) = key.find(':') else {
                continue;
            };
            let dot = key.find('.').map(|i| i + 1).unwrap_or(0);
            let name = key[dot..colon].trim();
            if name.is_empty() {
                continue;
            }
            let pattern = &key[colon + 1..];
            // An absent or empty header is left alone (`handleHeaderReplace`).
            if let Some(cur) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_string)
            {
                set_header(headers, name, &replace_once_or_all(&cur, pattern, repl));
            }
        }
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

/// `reqCharset`/`resCharset` and the `delete://…Type`/`…Charset` keys, which
/// upstream resolves in one pass over `Content-Type`
/// (`setCharset`, `_original/lib/util/index.js:3923-3944`).
///
/// The header is split on `;`, the media type is slot 0 and the charset slot 1;
/// dropping the type empties slot 0 rather than removing the header, so
/// `delete://resType` alone leaves a bare `; charset=utf-8` behind. Only when
/// *everything* is empty is the header removed. Faithfully odd.
fn set_charset(
    headers: &mut HeaderMap,
    charset: Option<&str>,
    drop_type: bool,
    drop_charset: bool,
) {
    if charset.is_none() && !drop_type && !drop_charset {
        return;
    }
    let current = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mut parts: Vec<String> = match current.is_empty() {
        true => vec![String::new()],
        false => current.split(';').map(|p| p.trim().to_string()).collect(),
    };
    if drop_type {
        parts[0] = String::new();
    }
    if drop_charset {
        parts.truncate(1);
    } else if let Some(charset) = charset {
        let value = format!("charset={charset}");
        match parts.len() {
            1 => parts.push(value),
            _ => parts[1] = value,
        }
    }
    let joined = parts.join("; ");
    if joined.trim_matches(|c| c == ';' || c == ' ').is_empty() {
        headers.remove(hyper::header::CONTENT_TYPE);
        return;
    }
    if let Ok(v) = HeaderValue::from_str(&joined) {
        headers.insert(hyper::header::CONTENT_TYPE, v);
    }
}

/// Media types whistle recognises by short name, beyond what a file extension
/// lookup gives (`REQ_TYPE`, `_original/lib/inspectors/req.js:31-40`).
fn req_type_alias(name: &str) -> Option<&'static str> {
    Some(match name {
        "urlencoded" | "form" => "application/x-www-form-urlencoded",
        "json" => "application/json",
        "xml" => "application/xml",
        "text" => "text/plain",
        "upload" | "multipart" => "multipart/form-data",
        "defaultType" => "application/octet-stream",
        _ => return None,
    })
}

/// `resType`/`reqType` — set the media type, keeping the existing parameters.
///
/// A value with no `/` is a short name to look up (`resType://json` →
/// `application/json`), and a value with no `;` inherits whatever parameters
/// the current header carries, so `resType://json` on a
/// `text/html; charset=gbk` response yields `application/json;charset=gbk`
/// (`getNewType`, `_original/lib/util/index.js:3946-3956`).
fn set_content_type(headers: &mut HeaderMap, value: &str, alias: fn(&str) -> Option<&'static str>) {
    let mut parts: Vec<String> = value.split(';').map(str::to_string).collect();
    let name = parts[0].clone();
    if !name.is_empty() && !name.contains('/') {
        parts[0] = lookup_type(&name, alias).to_string();
    }
    let mut new_type = parts.join(";");
    if !new_type.contains(';') {
        if let Some(current) = headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .filter(|c| c.contains(';'))
        {
            let mut kept: Vec<String> = current.split(';').map(str::to_string).collect();
            kept[0] = new_type;
            new_type = kept.join(";");
        }
    }
    set_header(headers, "content-type", &new_type);
}

/// Resolve a short type name (`lookupType`,
/// `_original/lib/util/index.js:3664-3666`): the side-specific aliases first,
/// then the same extension table the local-file family uses, then whistle's
/// `application/octet-stream` default.
fn lookup_type(name: &str, alias: fn(&str) -> Option<&'static str>) -> &'static str {
    if name == "sse" {
        return "text/event-stream";
    }
    alias(name)
        // The extension table carries a `charset` for text types; `mime.lookup`
        // does not, and a parameter here would block the `getNewType` merge.
        .or_else(|| content_type_of_ext(&format!("x.{name}")).map(media_type))
        .unwrap_or("application/octet-stream")
}

/// The media type of a `type; parameter` string.
fn media_type(full: &'static str) -> &'static str {
    full.split(';').next().unwrap_or(full)
}

/// The response side has no short-name aliases beyond the extension table.
fn no_type_alias(_: &str) -> Option<&'static str> {
    None
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
///
/// The `resCors` negotiation and the `attachment` filename fallback both need
/// the request that produced this response; without it they degrade to what can
/// be decided from the rule alone. Callers that have the request should use
/// [`apply_response_for`].
pub fn apply_response(parts: &mut response::Parts, resolved: &Resolved) {
    apply_response_for(parts, resolved, None)
}

/// As [`apply_response`], with the request the response answers.
///
/// Operators are applied in whistle's order, which is not the order they are
/// written on the line (`_original/lib/inspectors/res.js:820-950`): cookies and
/// CORS go straight onto the upstream headers, then `resHeaders` — with `cache`
/// and `attachment` folded into it — overwrites them, then `resType`, the
/// charset pass, `headerReplace`, and finally the `delete://` keys.
pub fn apply_response_for(
    parts: &mut response::Parts,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
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
            handle_status_code(&mut parts.headers, status);
        }
    }
    apply_res_cookies(&mut parts.headers, resolved);
    apply_res_cors(&mut parts.headers, resolved, info);

    apply_header_ops(&mut parts.headers, resolved, "resHeaders");
    apply_cache(&mut parts.headers, resolved);
    apply_attachment(&mut parts.headers, resolved, info);

    if let Some(ct) = resolved.value("resType") {
        set_content_type(&mut parts.headers, ct, no_type_alias);
    }
    let del = Deletions::of(resolved, false);
    set_charset(
        &mut parts.headers,
        resolved.value("resCharset"),
        del.drop_type,
        del.drop_charset,
    );
    apply_header_replace(&mut parts.headers, resolved, false);
    apply_deletes(&mut parts.headers, &del);

    // Injected content is useless behind a CSP that forbids it, or cached for
    // the next load; whistle strips both (`res.js:1093-1101`).
    if injects_into_body(&parts.headers, resolved) {
        if !enabled_flags(resolved).contains("keepCSP")
            && !enabled_flags(resolved).contains("keepAllCSP")
        {
            disable_csp(&mut parts.headers);
        }
        if !custom_cache(resolved) && !enabled_flags(resolved).contains("keepCache") {
            disable_res_store(&mut parts.headers);
        }
    }

    disable_res_props(&mut parts.headers, resolved);
}

/// `disable://` flags with response-header effects (`disableResProps`,
/// `_original/lib/util/index.js:3011-3027`), applied last so nothing can undo
/// them. `keepAlive` is whistle-rs's own addition.
fn disable_res_props(headers: &mut HeaderMap, resolved: &Resolved) {
    let dis = disabled_flags(resolved);
    if ["cookie", "cookies", "resCookie", "resCookies"]
        .iter()
        .any(|f| dis.contains(*f))
    {
        headers.remove(hyper::header::SET_COOKIE);
    }
    if dis.contains("cache") {
        // `no-cache`, not the `no-store` that the injection pass writes.
        set_header(headers, "cache-control", "no-cache");
        set_header(headers, "expires", &http_date(-60_000_000));
        set_header(headers, "pragma", "no-cache");
    }
    if dis.contains("csp") {
        disable_csp(headers);
    }
    if dis.contains("keepAlive") || dis.contains("keepalive") {
        set_header(headers, "connection", "close");
    }
}

/// `reqCors://…` — the request half of whistle's CORS negotiation
/// (`setReqCors`, `_original/lib/util/index.js:2899-2921`).
///
/// The value takes the same four shorthand spellings as `resCors` and folds the
/// same way, but only three of the resulting keys mean anything on a request:
/// `origin` (a URL, reduced to its origin, or `*`), `method` and `headers`,
/// which become the two preflight headers. Notably `enable` sets **nothing** —
/// there is no request origin to echo back — so `reqCors://enable` is inert
/// upstream, and is here.
fn apply_req_cors(headers: &mut HeaderMap, resolved: &Resolved) {
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
fn apply_res_cors(headers: &mut HeaderMap, resolved: &Resolved, info: Option<&ReqInfo>) {
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
    } else if auto {
        if let Some(list) = req_header(info, "access-control-request-headers") {
            set_header(headers, "access-control-allow-headers", list);
        }
    }
    if let Some(credentials) = spec.get("credentials") {
        set_header(headers, "access-control-allow-credentials", credentials);
    } else if auto {
        if let Some(method) = req_header(info, "access-control-request-method") {
            // Singular, and not a real CORS header — upstream's typo, kept so
            // both implementations emit the same thing.
            set_header(headers, "access-control-allow-method", method);
        }
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
fn merge_cors_ops(resolved: &Resolved, protocol: &str) -> HashMap<String, String> {
    let mut spec: HashMap<String, String> = HashMap::new();
    for op in resolved.all(protocol).iter().rev() {
        spec.extend(parse_cors(&op.value));
    }
    spec
}

/// Parse one `resCors` value into whistle's lower-cased option map.
fn parse_cors(value: &str) -> HashMap<String, String> {
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
    if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(trimmed) {
        return map
            .into_iter()
            .map(|(k, v)| {
                let v = match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                (k.to_ascii_lowercase(), v)
            })
            .collect();
    }
    // `parseInlineJSON`: a `key=…` value with no whitespace is a query string.
    let inline = trimmed.split('=').next().unwrap_or("");
    if trimmed.contains('=') && !inline.is_empty() && !inline.contains(['\\', '/']) && !trimmed.contains(char::is_whitespace)
    {
        return trimmed
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.to_string()))
            .collect();
    }
    HashMap::new()
}

/// One request header, if the request is known. Names in [`ReqInfo`] are
/// already lower-cased.
fn req_header<'a>(info: Option<&'a ReqInfo>, name: &str) -> Option<&'a str> {
    info?
        .headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// `HTTP_RE`, `_original/lib/util/common.js:57`.
fn is_http_url(value: &str) -> bool {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    rest.is_some_and(|r| !r.starts_with(['/', '?']) && !r.is_empty())
}

/// Trim a URL down to its origin (`parseOrigin`,
/// `_original/lib/util/index.js:2884-2896`).
fn parse_origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("//") else {
        return url.to_string();
    };
    match rest.find('/') {
        Some(i) => format!("{scheme}//{}", &rest[..i]),
        None => url.to_string(),
    }
}

/// `replaceStatus://401`/`407` also advertise the authentication whistle's own
/// login flow expects (`handleStatusCode`, `_original/lib/util/index.js:398-405`).
fn handle_status_code(headers: &mut HeaderMap, status: StatusCode) {
    match status.as_u16() {
        401 => set_header(headers, "www-authenticate", "Basic realm=User Login"),
        407 => set_header(headers, "proxy-authenticate", "Basic realm=User Login"),
        _ => {}
    }
}

/// `cache://` — `Cache-Control` plus the `Expires`/`Pragma` pair whistle always
/// writes with it (`_original/lib/inspectors/res.js:877-897`).
///
/// The accepted spellings are narrow: `no`, `no-cache`, `no-store` (any case) or
/// a leading integer. `cache://reserve`/`keep` mean "leave the upstream headers
/// alone", and anything else — `cache://off`, say — is silently ignored rather
/// than passed through as a header value.
fn apply_cache(headers: &mut HeaderMap, resolved: &Resolved) {
    let Some(value) = resolved.value("cache").map(str::trim) else {
        return;
    };
    if value == "reserve" || value == "keep" {
        return;
    }
    // `parseInt` reads a leading integer and ignores the rest, so `cache://60s`
    // is a minute.
    let max_age = parse_leading_int(value);
    let lower = value.to_ascii_lowercase();
    let no_cache = matches!(lower.as_str(), "no" | "no-cache" | "no-store")
        || max_age.is_some_and(|n| n < 0);
    if !no_cache && !max_age.is_some_and(|n| n >= 0) {
        return;
    }
    let cache_control = match (no_cache, lower == "no-store") {
        (true, true) => "no-store".to_string(),
        (true, false) => "no-cache".to_string(),
        (false, _) => format!("max-age={}", max_age.unwrap_or(0)),
    };
    set_header(headers, "cache-control", &cache_control);
    set_header(headers, "pragma", if no_cache { "no-cache" } else { "" });
    let offset = match no_cache {
        true => -60_000_000,
        false => max_age.unwrap_or(0).saturating_mul(1000),
    };
    set_header(headers, "expires", &http_date(offset));
}

/// The leading integer of `value`, as JavaScript's `parseInt` reads it.
fn parse_leading_int(value: &str) -> Option<i64> {
    let digits = value
        .strip_prefix(['+', '-'])
        .unwrap_or(value)
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let end = usize::from(value.starts_with(['+', '-'])) + digits;
    value.get(..end.min(value.len()))?.parse().ok()
}

/// `cache://reserve`/`keep` and `enable://keepAllCache` mark the response's
/// caching as deliberate, which stops the injection pass from overriding it
/// (`req._customCache`, `_original/lib/inspectors/res.js:878-881`).
fn custom_cache(resolved: &Resolved) -> bool {
    if enabled_flags(resolved).contains("keepAllCache") {
        return true;
    }
    match resolved.value("cache").map(str::trim) {
        Some("reserve") | Some("keep") => true,
        Some(value) => {
            let lower = value.to_ascii_lowercase();
            matches!(lower.as_str(), "no" | "no-cache" | "no-store")
                || parse_leading_int(value).is_some()
        }
        None => false,
    }
}

/// An RFC 1123 date `offset` milliseconds from now, as `Date#toGMTString`
/// renders it.
fn http_date(offset: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = now + offset / 1000;
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let (h, m, s) = (time / 3600, (time % 3600) / 60, time % 60);
    let weekday = DAYS[(days + 4).rem_euclid(7) as usize];
    let (year, month, day) = civil_from_days(days);
    format!(
        "{weekday}, {day:02} {} {year} {h:02}:{m:02}:{s:02} GMT",
        MONTHS[(month - 1) as usize]
    )
}

/// Days since the Unix epoch → `(year, month, day)`. Howard Hinnant's
/// `civil_from_days`, which is exact for the whole range we can produce.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}

/// `attachment://[filename]` — force a download.
///
/// whistle always writes a filename: with no value it falls back to the last
/// path segment of the request URL, or `index.html`
/// (`getFilename`, `_original/lib/util/index.js:957-970`).
fn apply_attachment(headers: &mut HeaderMap, resolved: &Resolved, info: Option<&ReqInfo>) {
    let Some(value) = resolved.value("attachment") else {
        return;
    };
    let name = match value.is_empty() {
        false => value.to_string(),
        true => info.map(|i| url_filename(&i.full_url)).unwrap_or_default(),
    };
    let disposition = match name.is_empty() {
        // Without the request there is no fallback name to compute; a bare
        // `attachment` still forces the download.
        true => "attachment".to_string(),
        false => format!("attachment; filename=\"{}\"", encode_non_latin1(&name)),
    };
    set_header(headers, "content-disposition", &disposition);
}

/// The filename whistle derives from a URL: the last path segment, ignoring
/// query and fragment, or `index.html` when there is none.
fn url_filename(url: &str) -> String {
    let pure = url.split(['?', '#']).next().unwrap_or(url).trim();
    // `getPath` drops the scheme, so the host counts as a segment: a URL with no
    // `/` after it has no filename at all.
    let after_scheme = pure.split_once("://").map(|(_, rest)| rest).unwrap_or(pure);
    match after_scheme.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name.to_string(),
        _ => "index.html".to_string(),
    }
}

/// Percent-encode whitespace and everything outside Latin-1, which is all a
/// header value may not carry (`encodeNonLatin1Char`,
/// `_original/lib/util/common.js:1516,1534-1539`).
fn encode_non_latin1(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_whitespace() && (c as u32) <= 0xFF {
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

/// Would any operator write into this response's body?
///
/// Upstream asks the same question *before* the `safeHtml`/`strictHtml` gate
/// runs — it looks only at whether a rule produced content
/// (`_original/lib/inspectors/res.js:1093`) — so a refused injection still
/// costs the response its CSP and its cacheability.
fn injects_into_body(headers: &HeaderMap, resolved: &Resolved) -> bool {
    let class = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(res_class);
    let families = BodyFamilies::of(class);
    ["Body", "Prepend", "Append"].iter().any(|slot| {
        resolved.value(&format!("res{slot}")).is_some()
            || (families.html && resolved.value(&format!("html{slot}")).is_some())
            || (families.js && resolved.value(&format!("js{slot}")).is_some())
            || (families.css && resolved.value(&format!("css{slot}")).is_some())
    })
}

/// Drop every spelling of the Content-Security-Policy header
/// (`disableCSP`, `_original/lib/util/index.js:738-744`).
fn disable_csp(headers: &mut HeaderMap) {
    for name in [
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-security-policy",
        "x-content-security-policy-report-only",
        "x-webkit-csp",
    ] {
        remove_header(headers, name);
    }
}

/// Make the response uncacheable (`disableResStore`,
/// `_original/lib/util/index.js:986-991`). The `tag` header it also deletes is
/// upstream's typo for `etag`; reproduced, since a rules file must resolve the
/// same way in both implementations.
fn disable_res_store(headers: &mut HeaderMap) {
    set_header(headers, "cache-control", "no-store");
    set_header(headers, "expires", &http_date(-60_000_000));
    set_header(headers, "pragma", "no-cache");
    remove_header(headers, "tag");
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
///
/// `trailers` is one of `parseRuleJson`'s arguments (`_original/lib/inspectors/res.js:845-855`),
/// so several lines fold into one map with the first line winning a contested
/// name, exactly as `resHeaders` does.
pub fn build_trailers(resolved: &Resolved) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, value) in merge_header_ops(resolved, "trailers") {
        set_header(&mut h, &name, &value);
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
    // `delete://body` and `delete://resBody.a` rewrite the body on their own.
    if Deletions::of(resolved, prefix == "req").touches_body() {
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

/// whistle's coarse content classes (`getContentType`,
/// `_original/lib/util/index.js:1475-1510`).
///
/// The order of the tests is upstream's and is load-bearing: `javascript` is
/// looked for before `css`, which is looked for before `html`, so a type that
/// mentions two of them resolves to the first. Only the media type is examined —
/// parameters after the first `;` are dropped before the substring tests, so a
/// `charset=` value cannot smuggle a class in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ResClass {
    Js,
    Css,
    Html,
    Json,
    Xml,
    Text,
    Img,
}

/// Classify a `Content-Type` header the way whistle does. `None` covers both a
/// missing header and a type in none of the classes (e.g. `image/…` aside,
/// `application/octet-stream`).
fn res_class(content_type: &str) -> Option<ResClass> {
    let raw = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    Some(if raw.contains("javascript") {
        ResClass::Js
    } else if raw.contains("css") {
        ResClass::Css
    } else if raw.contains("html") {
        ResClass::Html
    } else if raw.contains("json") {
        ResClass::Json
    } else if raw.contains("xml") {
        ResClass::Xml
    } else if raw.contains("text/") {
        ResClass::Text
    } else if raw.contains("image/") {
        ResClass::Img
    } else {
        return None;
    })
}

/// Which typed-body families a response accepts.
///
/// The nuance that makes `jsAppend` useful at all: **an HTML response accepts
/// the JS *and* the CSS families too** — `isJs = isHtml || resType === 'JS'`
/// (`_original/lib/inspectors/res.js:952-954`). `jsAppend://alert(1)` on a page
/// is the canonical whistle one-liner; it works because the injected script is
/// wrapped in `<script>` before it reaches the markup (see [`wrap_js`]).
#[derive(Clone, Copy)]
struct BodyFamilies {
    html: bool,
    js: bool,
    css: bool,
}

impl BodyFamilies {
    fn of(class: Option<ResClass>) -> BodyFamilies {
        let html = class == Some(ResClass::Html);
        BodyFamilies {
            html,
            js: html || class == Some(ResClass::Js),
            css: html || class == Some(ResClass::Css),
        }
    }
}

/// A URL written where whistle expects script or stylesheet source
/// (`GEN_URL_RE`, `_original/lib/util/index.js:44`). Such a value is linked
/// rather than inlined.
static GEN_URL_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(?i)^\s*(?:https?:)?//\w\S*\s*$").expect("static regex"));

/// `<script>` attributes contributed by the injecting line's properties
/// (`getScriptProps`, `_original/lib/util/index.js:277-303`). The groups are
/// exclusive in upstream's order: the first `crossorigin` spelling wins, and
/// `module` outranks `importmap` outranks `speculationrules`.
fn script_props(props: &LineProps) -> String {
    let mut out = String::new();
    if props.has("use-credentials") || props.has("useCredentials") {
        out.push_str(" crossorigin=\"use-credentials\"");
    } else if props.has("anonymous") {
        out.push_str(" crossorigin=\"anonymous\"");
    } else if props.has("crossorigin") {
        out.push_str(" crossorigin");
    }
    for flag in ["defer", "async", "nomodule"] {
        if props.has(flag) {
            out.push(' ');
            out.push_str(flag);
        }
    }
    if props.has("module") {
        out.push_str(" type=\"module\"");
    } else if props.has("importmap") {
        out.push_str(" type=\"importmap\"");
    } else if props.has("speculationrules") {
        out.push_str(" type=\"speculationrules\"");
    }
    out
}

/// Wrap a `jsXxx` value for injection into markup (`wrapJs`,
/// `_original/lib/util/index.js:305-313`): a bare URL becomes a `src=` script
/// tag, anything else an inline one.
fn wrap_js(js: &str, props: &LineProps) -> String {
    let attrs = script_props(props);
    match GEN_URL_RE.is_match(js) {
        true => format!("<script{attrs} src=\"{}\"></script>", js.trim()),
        false => format!("<script{attrs}>{js}</script>"),
    }
}

/// Wrap a `cssXxx` value for injection into markup (`wrapCss`,
/// `_original/lib/util/index.js:315-322`). Line properties do not apply here —
/// upstream passes none.
fn wrap_css(css: &str) -> String {
    match GEN_URL_RE.is_match(css) {
        true => format!("<link rel=\"stylesheet\" href=\"{}\" />", css.trim()),
        false => format!("<style>{css}</style>"),
    }
}

/// The separator whistle puts between several values landing in the same slot
/// (`joinData`, `_original/lib/util/file-mgr.js:93-109`).
const CRLF: &[u8] = b"\r\n";

/// Prepended to a non-empty `top` on an HTML response unless `disable://doctype`
/// (`_original/lib/util/whistle-transform.js:6,116-118`). Surprising but real:
/// any `resPrepend`/`htmlPrepend` on a page also stamps a doctype in front of it.
const DOCTYPE: &[u8] = b"<!DOCTYPE html>\r\n";

/// The three slots whistle's `WhistleTransform` writes around a body: `top`
/// before it, `body` *instead* of it, `bottom` after it
/// (`_original/lib/util/whistle-transform.js:88-127`).
///
/// Each slot is a list because several operators — and, since they are
/// multi-match, several *lines* per operator — feed it. The parts are joined
/// with CRLF, whistle's separator for everything that lands in one slot.
#[derive(Default)]
struct Injection {
    top: Vec<Vec<u8>>,
    body: Vec<Vec<u8>>,
    bottom: Vec<Vec<u8>>,
    /// Whether the body slot was claimed at all. Distinct from `body` being
    /// non-empty: a `*Body` operator that matched with a blank value still
    /// replaces the body (upstream substitutes an empty *buffer*, which is
    /// truthy, `_original/lib/inspectors/res.js:1005` +
    /// `whistle-transform.js:110-114`), so `resBody://` empties it.
    replaces_body: bool,
}

impl Injection {
    /// Wrap `data` in whatever the slots hold.
    fn apply(self, data: Vec<u8>, doctype: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if !self.top.is_empty() && doctype {
            out.extend_from_slice(DOCTYPE);
        }
        join_into(&mut out, self.top);
        match self.replaces_body {
            true => join_into(&mut out, self.body),
            false => out.extend_from_slice(&data),
        }
        join_into(&mut out, self.bottom);
        out
    }
}

/// Append `pieces` to `out`, CRLF-separated.
fn join_into(out: &mut Vec<u8>, pieces: Vec<Vec<u8>>) {
    for (i, piece) in pieces.into_iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(CRLF);
        }
        out.extend(piece);
    }
}

/// CRLF-join the values of one operator's matching lines, dropping blanks
/// (`joinData`, `_original/lib/util/file-mgr.js:93-109`, whose loop skips falsy
/// entries; the HTML path filters them a step earlier, `index.js:1320-1322`).
fn join_values(values: &[&str]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for value in values.iter().filter(|v| !v.is_empty()) {
        if !out.is_empty() {
            out.extend_from_slice(CRLF);
        }
        out.extend_from_slice(value.as_bytes());
    }
    out
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

/// Merge `patch` into `target` one key deep — jQuery's `extend` without its
/// leading `true`, which is how upstream combines several lines of the same
/// JSON-shaped operator.
fn json_shallow_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
            for (k, v) in p {
                t.insert(k.clone(), v.clone());
            }
        }
        (t, p) => *t = p.clone(),
    }
}

/// Collapse every matching line of a JSON-shaped operator (`resMerge`) into one
/// patch, mirroring `readRuleList`'s JSON branch
/// (`_original/lib/util/index.js:1300-1312`).
///
/// Like [`merge_rule_maps`] the list is reversed and folded onto its own last
/// entry, so the **first** (highest-priority) line wins a contested key. Two
/// details are specific to this branch:
///
/// * the fold is *shallow* unless one of the lines is the literal `true`, which
///   upstream detects with `isDeep` and turns into `extend`'s deep flag. So
///   `resMerge://true` is a marker line that contributes no data of its own and
///   makes the remaining lines merge recursively;
/// * a single line is passed through untouched — the fold only runs for two or
///   more — so a lone non-object `resMerge` keeps whatever meaning it had.
///
/// The combined patch is then always deep-merged *into the body*
/// (`extend(true, obj, params)`, `_original/lib/inspectors/res.js:1046`).
fn merge_json_patches(resolved: &Resolved, protocol: &str) -> Option<serde_json::Value> {
    let mut deep = false;
    let mut patches: Vec<serde_json::Value> = Vec::new();
    for op in resolved.all(protocol) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(op.value.trim()) else {
            // Not JSON at all; upstream's `_parseJSON` yields null and the
            // line is filtered out.
            continue;
        };
        match value {
            serde_json::Value::Bool(true) => deep = true,
            serde_json::Value::Null => {}
            value => patches.push(value),
        }
    }
    if patches.len() < 2 {
        return patches.pop();
    }
    // `extend.apply(null, reversed)`: the last line is the target, and each
    // earlier line is laid over it in turn.
    let mut target = patches.pop()?;
    if !(target.is_object() || target.is_array()) {
        // `if (typeof result[0] !== 'object') { result[0] = {}; }`
        target = serde_json::Value::Object(serde_json::Map::new());
    }
    for src in patches.iter().rev() {
        match deep {
            true => json_deep_merge(&mut target, src),
            false => json_shallow_merge(&mut target, src),
        }
    }
    Some(target)
}

/// The request facts `params://` needs to pick its destination.
///
/// Both are read *after* the request operators have run, because `reqType://`
/// and `method://` are applied before `handleParams` decides
/// (`_original/lib/inspectors/req.js:536,560-561`) — a `reqType://json` line
/// therefore sends the params into the body.
#[derive(Clone, Copy, Default)]
pub struct ReqBodyCtx<'a> {
    /// The method as forwarded (after `method://`).
    pub method: &'a str,
    /// The `Content-Type` as forwarded (after `reqType://` and `reqHeaders://`).
    pub content_type: Option<&'a str>,
}

/// Which kind of request body `params://` merges into, if any.
///
/// `None` means the params address the query string instead — upstream's
/// `hasBody` flag (`handleParams`, `_original/lib/inspectors/req.js:157-232`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParamsBody {
    /// `application/json` (and anything else `getContentType` calls JSON).
    Json,
    /// `application/x-www-form-urlencoded` — **POST only**, as upstream has it.
    Form,
    /// `multipart/…` with a boundary; the boundary is read back from the type.
    Multipart,
}

/// Where `params://` lands for this request, given what the rules resolved.
///
/// Answering `None` when no `params://` (and no `delete://reqBody.…`) matched is
/// what keeps this off the hot path: an unmatched request never looks at its own
/// content type. Both guards are map lookups — `Deletions::of`, which walks and
/// allocates, is reached only once a `delete://` has actually matched.
fn params_body_kind(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> Option<ParamsBody> {
    let asks = !resolved.all("params").is_empty()
        || (!resolved.all("delete").is_empty()
            && !Deletions::of(resolved, true).body_props.is_empty());
    asks.then(|| request_body_kind(ctx)).flatten()
}

/// Classify a request body by method and content type, the way `handleParams`
/// branches on it.
fn request_body_kind(ctx: ReqBodyCtx<'_>) -> Option<ParamsBody> {
    let ct = ctx.content_type?;
    // `isMultipart` tests the content type alone — no method, no body check
    // (`_original/lib/util/index.js:1724-1727`) — and the boundary must be
    // spelled out for the parts to be found at all.
    if ct.to_ascii_lowercase().contains("multipart") {
        return multipart_boundary(ct).map(|_| ParamsBody::Multipart);
    }
    // `isUrlEncoded` is POST-only (`_original/lib/util/common.js:692-695`),
    // while `isJSONContent` accepts any method that may carry a body.
    if ct.to_ascii_lowercase().contains("application/x-www-form-urlencoded") {
        return ctx.method.eq_ignore_ascii_case("POST").then_some(ParamsBody::Form);
    }
    if method_has_body(ctx.method) && matches!(res_class(ct), Some(ResClass::Json)) {
        return Some(ParamsBody::Json);
    }
    None
}

/// `hasRequestBody` (`_original/lib/util/common.js:1591-1604`) — the methods
/// whistle will look for a body on.
fn method_has_body(method: &str) -> bool {
    !matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "CONNECT"
    )
}

/// The `boundary=` of a multipart content type (`BUOUNDARY_RE`,
/// `_original/lib/inspectors/req.js:19`), quoted or bare.
fn multipart_boundary(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    let at = lower.find("boundary=")? + "boundary=".len();
    let rest = &content_type[at..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return (end > 0).then(|| quoted[..end].to_string());
    }
    let end = rest.find(';').unwrap_or(rest.len());
    let bare = rest[..end].trim();
    (!bare.is_empty()).then(|| bare.to_string())
}

/// True if any request-body operator applies (so the body must be buffered).
pub fn wants_req_body(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> bool {
    body_ops_present(resolved, "req") || params_body_kind(resolved, ctx).is_some()
}

/// True if any response-body operator applies (so the body must be buffered).
pub fn wants_res_body(resolved: &Resolved) -> bool {
    body_ops_present(resolved, "res")
}

/// Transform a buffered request body per the resolved operators.
///
/// The request pipeline runs the injection first and `reqReplace` after it
/// (`handleReq` adds the transform, then `handleReplace`,
/// `_original/lib/inspectors/req.js:129-130,573`), so a substitution *does* see
/// what `reqPrepend`/`reqAppend` put there — the opposite of the response side.
pub fn transform_req_body(body: Bytes, resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> Bytes {
    let del = Deletions::of(resolved, true);
    // `delete://body` wipes the body *and* anything an operator meant to put
    // around it (`removeBody`, `_original/lib/util/index.js:3592-3598`).
    if del.drop_body {
        return Bytes::new();
    }
    // Request bodies are never injection-gated: whistle's request transform
    // leaves `isHtml` unset, so `allowInject` lets every operator through.
    let gate = InjectionGate::plain(resolved);
    let mut injection = Injection::default();
    collect_generic(&mut injection, &gate, "req");
    let mut data = injection.apply(body.to_vec(), false);
    if let Some(kind) = params_body_kind(resolved, ctx) {
        data = merge_params_into_body(data, resolved, &del, kind, ctx);
    }
    // whistle gates `reqReplace` on the request's own content type, exactly as
    // it gates `resReplace` on the response's (`_original/lib/inspectors/req.js`
    // mirrors `res.js:129-132`): a request with no `content-type`, or an image
    // one, is left alone.
    let class = ctx.content_type.and_then(res_class);
    Bytes::from(apply_replace(data, resolved, "reqReplace", class))
}

/// `params://` merged into the request body, and `delete://reqBody.…` applied
/// alongside it (`handleParams`, `_original/lib/inspectors/req.js:157-232`).
///
/// The two ride the same transform upstream, which is why the deletions land
/// here rather than in a pass of their own: they are only ever applied to a body
/// whose shape whistle recognises.
fn merge_params_into_body(
    data: Vec<u8>,
    resolved: &Resolved,
    del: &Deletions,
    kind: ParamsBody,
    ctx: ReqBodyCtx<'_>,
) -> Vec<u8> {
    if kind == ParamsBody::Multipart {
        let Some(boundary) = ctx.content_type.and_then(multipart_boundary) else {
            return data;
        };
        return merge_params_into_multipart(data, resolved, del, &boundary);
    }
    // Not UTF-8 means bytes whistle's text transforms never see. (Upstream tries
    // GB18030 first and re-encodes afterwards; this port stays UTF-8, as it does
    // for every other text transform.)
    let mut text = match String::from_utf8(data) {
        Ok(text) => text,
        Err(e) => return e.into_bytes(),
    };
    match kind {
        ParamsBody::Json => {
            let params = merge_params_values(resolved, "params");
            // An empty body becomes the params outright — `JSON.stringify(params)`
            // on the no-buffer branch (`req.js:214-218`).
            if text.trim().is_empty() {
                let mut obj = serde_json::Value::Object(params.into_iter().collect());
                delete_json_props(&mut obj, &del.body_props);
                return serde_json::to_vec(&obj).unwrap_or_default();
            }
            // Only the first JSON-looking span is patched, so a body wrapped in
            // something else keeps its wrapper (`JSON_RE`, `req.js:18,193`).
            let Some((start, end)) = json_span(&text) else {
                return text.into_bytes();
            };
            let Ok(mut base) = serde_json::from_str::<serde_json::Value>(&text[start..end]) else {
                return text.into_bytes();
            };
            // `extend(true, obj, params)` — deep, unlike the fold that built it.
            for (key, value) in params {
                json_deep_merge_key(&mut base, &key, value);
            }
            delete_json_props(&mut base, &del.body_props);
            let Ok(merged) = serde_json::to_string(&base) else {
                return text.into_bytes();
            };
            format!("{}{merged}{}", &text[..start], &text[end..]).into_bytes()
        }
        ParamsBody::Form => {
            let params = merge_params_pairs(resolved, "params");
            text = merge_query_string(&text, &params, &del.body_props);
            text.into_bytes()
        }
        ParamsBody::Multipart => unreachable!("handled above"),
    }
}

/// `params://` merged into a `multipart/form-data` body.
///
/// Upstream rewrites this one *streaming*, part by part, so it never holds a
/// file upload in memory (`_original/lib/inspectors/req.js:226-410`). This port
/// has the whole body in hand already — every other request-body operator
/// buffers — so it splits on the boundary instead, which is far less code for
/// the same result on a well-formed body:
///
/// * a part whose `name=` is in `params` has its **whole** part replaced, so an
///   uploaded file named by a param becomes a plain field (upstream's
///   `toMultipart(name, params[name])` does exactly this);
/// * a part named by `delete://reqBody.<name>` is dropped;
/// * params that matched no part are appended as new parts, in fold order.
///
/// A body that does not start with the boundary is left alone — upstream's
/// `badMultipart` path, which passes the bytes through untouched.
fn merge_params_into_multipart(
    data: Vec<u8>,
    resolved: &Resolved,
    del: &Deletions,
    boundary: &str,
) -> Vec<u8> {
    let start = format!("--{boundary}\r\n").into_bytes();
    if !data.starts_with(&start) {
        return data;
    }
    let sep = format!("\r\n--{boundary}").into_bytes();
    let mut params = merge_params_pairs(resolved, "params");

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut rest = &data[start.len()..];
    loop {
        let Some(at) = find_bytes(rest, &sep) else {
            // No closing boundary: not a body this can rewrite safely.
            return data;
        };
        let part = &rest[..at];
        let name = multipart_part_name(part);
        let deleted = name
            .as_deref()
            .is_some_and(|n| del.body_props.iter().any(|d| d == n));
        // `params[name] = undefined` marks the param consumed, so it is not
        // appended again at the end.
        let replacement = name
            .as_deref()
            .and_then(|n| params.iter().position(|(k, _)| k == n))
            .map(|i| params.remove(i));
        if !deleted {
            match replacement {
                Some((k, v)) => push_multipart_part(&mut out, boundary, &k, &v),
                None => push_multipart_raw(&mut out, boundary, part),
            }
        }
        rest = &rest[at + sep.len()..];
        // `--` after the boundary ends the body; `\r\n` starts the next part.
        if rest.starts_with(b"--") {
            break;
        }
        match rest.strip_prefix(b"\r\n".as_slice()) {
            Some(next) => rest = next,
            None => return data,
        }
    }
    for (name, value) in &params {
        push_multipart_part(&mut out, boundary, name, value);
    }
    if out.is_empty() {
        // Every part was deleted and nothing replaced them: emit an empty body
        // rather than a lone terminator.
        return Vec::new();
    }
    out.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    out
}

/// Append one already-encoded part, with the separator it needs.
fn push_multipart_raw(out: &mut Vec<u8>, boundary: &str, part: &[u8]) {
    match out.is_empty() {
        true => out.extend_from_slice(format!("--{boundary}\r\n").as_bytes()),
        false => out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes()),
    }
    out.extend_from_slice(part);
}

/// Append a plain `name`/`value` field (`toMultipart`,
/// `_original/lib/inspectors/req.js:61-95` — the string branch).
fn push_multipart_part(out: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    let part = format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}");
    push_multipart_raw(out, boundary, part.as_bytes());
}

/// The `name=` of a multipart part, read from the headers ahead of its blank
/// line (`getName` over `NAME_RE`, `_original/lib/inspectors/req.js:41-59`).
fn multipart_part_name(part: &[u8]) -> Option<String> {
    let at = find_bytes(part, b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&part[..at]).ok()?;
    let start = headers.to_ascii_lowercase().find("name=")? + "name=".len();
    let rest = &headers[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.find('"').map(|end| quoted[..end].to_string());
    }
    let end = rest.find([';', '\r']).unwrap_or(rest.len());
    let bare = rest[..end].trim();
    // A `'`-quoted name is unwrapped too (`getName`'s second branch).
    let bare = bare
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(bare);
    (!bare.is_empty()).then(|| bare.to_string())
}

/// Index of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Deep-merge one `params` entry into a JSON value at the top level.
fn json_deep_merge_key(base: &mut serde_json::Value, key: &str, value: serde_json::Value) {
    let serde_json::Value::Object(map) = base else {
        return;
    };
    match map.get_mut(key) {
        Some(slot) => json_deep_merge(slot, &value),
        None => {
            map.insert(key.to_string(), value);
        }
    }
}

/// Transform a buffered response body; `content_type` decides which typed-body
/// families apply and whether injected content is wrapped as markup.
///
/// Operators run in whistle's pipeline order, which is *not* the order they are
/// written: the text transforms (`resMerge`, then `resReplace`) sit ahead of the
/// injecting `WhistleTransform` in the response stream
/// (`_original/lib/inspectors/res.js:1041,1114-1120`; `addTextTransform` splices
/// its sub-pipeline in at the head, `_original/lib/init.js:135-141`). So a
/// substitution never sees prepended or appended content, and `resBody`
/// discards whatever `resMerge`/`resReplace` produced.
pub fn transform_res_body(body: Bytes, resolved: &Resolved, content_type: Option<&str>) -> Bytes {
    let del = Deletions::of(resolved, false);
    if del.drop_body {
        return Bytes::new();
    }
    let class = content_type.and_then(res_class);
    let families = BodyFamilies::of(class);
    // The gate is built from the body as it arrived: whistle decides once, from
    // the *original* first non-whitespace byte, whether injection is allowed.
    let gate = InjectionGate::new(resolved, families.html, &body);

    let mut data = apply_res_merge(body.to_vec(), resolved, class, &del);
    data = apply_replace(data, resolved, "resReplace", class);

    let injection = collect_res_injection(&gate, families);
    // Only an HTML response gets the doctype, and `disable://doctype` opts out.
    let doctype = families.html && !is_disabled(resolved, "doctype");
    Bytes::from(injection.apply(data, doctype))
}

/// Fill the generic (`res*` / `req*`) contribution of each slot, shared by both
/// sides.
///
/// Several lines carrying the same operator are CRLF-joined in resolution order
/// and pushed as one part. That is byte-identical to pushing each line
/// separately — the typed families that follow use the same separator — but it
/// keeps the "matched but blank" case distinguishable, which the body slot
/// needs.
fn collect_generic(injection: &mut Injection, gate: &InjectionGate<'_>, prefix: &str) {
    if let Some(joined) = gate.joined(&format!("{prefix}Body")).filter(Joined::claims_body) {
        injection.replaces_body = true;
        // Pushed even when blank, so that a typed `*Body` behind it is
        // CRLF-*appended* to the empty buffer rather than replacing it — an
        // upstream quirk of `EMPTY_BUFFER` being truthy (`res.js:1085-1087`).
        injection.body.push(joined.bytes);
    }
    // `*Prepend`/`*Append` carry no such marker: upstream assigns the raw value
    // and tests it for truthiness, so an all-blank one contributes nothing
    // (`_original/lib/inspectors/res.js:1008-1009,1082-1092`).
    for (protocol, slot) in [
        (format!("{prefix}Prepend"), &mut injection.top),
        (format!("{prefix}Append"), &mut injection.bottom),
    ] {
        if let Some(joined) = gate.joined(&protocol).filter(|j| !j.bytes.is_empty()) {
            slot.push(joined.bytes);
        }
    }
}

/// Fill all three slots for a response, in whistle's order: the generic `res*`
/// operators first, then `css*`, `html*` and `js*`
/// (`_original/lib/inspectors/res.js:1063-1072`).
///
/// On an HTML response the `js*`/`css*` values are markup-wrapped, since raw
/// JavaScript pasted into a page would only render as text.
fn collect_res_injection(gate: &InjectionGate<'_>, families: BodyFamilies) -> Injection {
    let mut injection = Injection::default();
    collect_generic(&mut injection, gate, "res");

    let html = families.html;
    for (family, enabled) in [
        ("css", families.css),
        ("html", families.html),
        ("js", families.js),
    ] {
        if !enabled {
            continue;
        }
        // whistle orders the families css → html → js in every slot, so the two
        // wrapped families bracket the raw markup one.
        for (suffix, slot) in [
            ("Body", &mut injection.body),
            ("Prepend", &mut injection.top),
            ("Append", &mut injection.bottom),
        ] {
            let protocol = format!("{family}{suffix}");
            let Some(lines) = gate.lines(&protocol) else {
                continue;
            };
            // Unlike the generic operators, each line is wrapped on its own —
            // upstream marks up every entry of the list before joining
            // (`readRuleList`, `_original/lib/util/index.js:955-966`), so two
            // `jsAppend://` lines become two `<script>` tags, not one holding
            // both bodies. Blanks contribute nothing.
            let mut pushed = false;
            for (value, props) in lines.into_iter().filter(|(v, _)| !v.is_empty()) {
                slot.push(match (html, family) {
                    (true, "js") => wrap_js(value, props).into_bytes(),
                    (true, "css") => wrap_css(value).into_bytes(),
                    _ => value.as_bytes().to_vec(),
                });
                pushed = true;
            }
            // A typed `*Body` only claims the slot when it actually contributed
            // — upstream folds it in with `joinArr`/`if (body)`, both of which
            // are truthiness tests (`res.js:1068,1085`), so a blank or wholly
            // refused one leaves the original body in place.
            if suffix == "Body" && pushed {
                injection.replaces_body = true;
            }
        }
    }
    injection
}

/// Decides, per operator, whether its content may be injected into a response
/// body — the `safeHtml` / `strictHtml` line properties.
///
/// Ported from `WhistleTransform#allowInject` + `filterHtml`
/// (`_original/lib/util/whistle-transform.js:66-89`). Three things matter:
///
/// * the decision looks at the **original** upstream body, before any operator
///   has rewritten it, and at its first non-whitespace byte only;
/// * only HTML responses are gated — `allowInject` returns `true` immediately
///   for anything else (`whistle-transform.js:68`), so `safeHtml` on a `jsAppend`
///   for a JavaScript response does nothing;
/// * the gate is **per line**: whistle marks each injected buffer with the
///   properties of the rule line that produced it (`_original/lib/util/index.js:1375-1381`)
///   and filters them individually, so one line may inject while another on the
///   same request is refused.
struct InjectionGate<'a> {
    resolved: &'a Resolved,
    /// The unmodified upstream body the decision is made from.
    body: &'a [u8],
    /// False when nothing is gated (non-HTML response, or the request side).
    html: bool,
    /// `enable://safeHtml` / `enable://strictHtml`, which upstream stamps onto
    /// every injecting rule of the request (`_original/lib/inspectors/res.js:970-987`).
    global: LineProps,
}

impl<'a> InjectionGate<'a> {
    fn new(resolved: &'a Resolved, html: bool, body: &'a [u8]) -> Self {
        let global = if html {
            let enabled = enabled_flags(resolved);
            LineProps::from_actions(
                ["strictHtml", "safeHtml"]
                    .into_iter()
                    .filter(|a| enabled.contains(*a)),
            )
        } else {
            LineProps::default()
        };
        InjectionGate {
            resolved,
            body,
            html,
            global,
        }
    }

    /// A gate that refuses nothing, for the request side.
    fn plain(resolved: &'a Resolved) -> Self {
        InjectionGate::new(resolved, false, &[])
    }

    /// Every line contributing to an injecting operator, in resolution order,
    /// each paired with its own line properties. Lines the gate refuses are
    /// dropped individually, the way `filterHtml` walks the buffer list.
    ///
    /// `None` means the operator contributes nothing here: either it did not
    /// match, or a request-wide `enable://strictHtml`/`safeHtml` shut the whole
    /// injection off — upstream's `allowInject` returns false for that and the
    /// transform then leaves even the body slot alone
    /// (`_original/lib/util/whistle-transform.js:71-83,107-114`). An empty list,
    /// by contrast, is an operator that matched and had every line refused
    /// individually, which the body slot treats differently.
    fn lines(&self, protocol: &str) -> Option<Vec<(&'a str, &'a LineProps)>> {
        let ops = self.resolved.all(protocol);
        if ops.is_empty() || (self.html && !self.global.allows_injection(self.body)) {
            return None;
        }
        Some(
            ops.iter()
                .filter(|op| !self.html || op.props.allows_injection(self.body))
                .map(|op| (op.value.as_str(), &op.props))
                .collect(),
        )
    }

    /// The CRLF-join of an operator's surviving lines, or `None` when it
    /// contributes nothing (see [`InjectionGate::lines`]).
    fn joined(&self, protocol: &str) -> Option<Joined> {
        let kept = self.lines(protocol)?;
        let values: Vec<&str> = kept.iter().map(|(v, _)| *v).collect();
        Some(Joined {
            bytes: join_values(&values),
            // Read from the *ungated* list on purpose: what distinguishes a
            // blank operator from a refused one is what it was written with.
            had_content: self
                .resolved
                .all(protocol)
                .iter()
                .any(|op| !op.value.is_empty()),
        })
    }
}

/// One operator's contribution to a slot, after gating and joining.
struct Joined {
    /// The CRLF-join of the lines that survived the gate.
    bytes: Vec<u8>,
    /// Whether any matching line carried content *before* gating. Together with
    /// `bytes` this separates "matched blank" from "matched and was refused",
    /// which the body slot treats differently — see [`Joined::claims_body`].
    had_content: bool,
}

impl Joined {
    /// Whether a generic `*Body` operator with this contribution replaces the
    /// body.
    ///
    /// A blank one does: upstream never builds a list for it and assigns an
    /// empty buffer instead (`resBody || util.EMPTY_BUFFER`,
    /// `_original/lib/inspectors/res.js:1005`). One whose every line the HTML
    /// gate refused does not: its list survives to the transform, where
    /// `filterHtml` empties it and the join yields the falsy `''`
    /// (`_original/lib/util/whistle-transform.js:47-60,110`).
    fn claims_body(&self) -> bool {
        !self.bytes.is_empty() || !self.had_content
    }
}

/// `resMerge` — deep-merge a JSON patch into a JSON response body
/// (`_original/lib/inspectors/res.js:1022-1069`).
///
/// The gate is narrower than it looks. Upstream only builds the merge transform
/// for a response that is JS, HTML, JSON, or has no `content-type` at all
/// (`res.js:1022`) — so `resMerge` on a `text/plain` body is inert — and it
/// merges into the **first JSON-looking substring** rather than the whole body
/// (`JSON_RE`, `res.js:846`), which is what lets it patch a JSONP payload
/// without disturbing the callback wrapper.
/// `del` carries the `delete://resBody.a.b` paths, which ride the same
/// transform and are therefore gated the same way.
fn apply_res_merge(
    data: Vec<u8>,
    resolved: &Resolved,
    class: Option<ResClass>,
    del: &Deletions,
) -> Vec<u8> {
    let patch = merge_json_patches(resolved, "resMerge");
    if patch.is_none() && del.body_props.is_empty() {
        return data;
    }
    let applies = matches!(
        class,
        None | Some(ResClass::Js) | Some(ResClass::Html) | Some(ResClass::Json)
    );
    if !applies {
        return data;
    }
    let text = match String::from_utf8(data) {
        Ok(text) => text,
        // Not text at all; whistle's transforms only ever see decoded strings.
        Err(e) => return e.into_bytes(),
    };
    // An empty body is replaced by the patch outright (`res.js:1049-1054`).
    if text.is_empty() {
        let Some(mut patch) = patch else {
            return Vec::new();
        };
        delete_json_props(&mut patch, &del.body_props);
        return serde_json::to_vec(&patch).unwrap_or_default();
    }
    // For HTML (and for a typeless response) whistle gives up unless the body
    // *starts* like JSON — `LIKE_JSON_RE`, `res.js:1029`.
    let like_json = text.trim_start().starts_with(['{', '[']);
    if matches!(class, None | Some(ResClass::Html)) && !like_json {
        return text.into_bytes();
    }
    let Some((start, end)) = json_span(&text) else {
        return text.into_bytes();
    };
    let Ok(mut base) = serde_json::from_str::<serde_json::Value>(&text[start..end]) else {
        return text.into_bytes();
    };
    if let Some(patch) = &patch {
        json_deep_merge(&mut base, patch);
    }
    delete_json_props(&mut base, &del.body_props);
    let Ok(merged) = serde_json::to_string(&base) else {
        return text.into_bytes();
    };
    format!("{}{merged}{}", &text[..start], &text[end..]).into_bytes()
}

/// Remove dotted paths from a JSON value (`deleteProps` →
/// `_original/lib/util/common.js:989-1084`). A numeric segment addressing an
/// array element splices it out. The `\.`-escaped and `a[0]` spellings upstream
/// also accepts are not ported.
fn delete_json_props(value: &mut serde_json::Value, paths: &[String]) {
    for path in paths {
        let mut keys = path.split('.').map(str::trim).peekable();
        let mut node = &mut *value;
        while let Some(key) = keys.next() {
            if keys.peek().is_none() {
                match node {
                    serde_json::Value::Object(map) => {
                        map.remove(key);
                    }
                    serde_json::Value::Array(list) => {
                        if let Ok(i) = key.parse::<usize>() {
                            if i < list.len() {
                                list.remove(i);
                            }
                        }
                    }
                    _ => {}
                }
                break;
            }
            let next = match node {
                serde_json::Value::Object(map) => map.get_mut(key),
                serde_json::Value::Array(list) => {
                    key.parse::<usize>().ok().and_then(|i| list.get_mut(i))
                }
                _ => None,
            };
            match next {
                Some(next) => node = next,
                None => break,
            }
        }
    }
}

/// The span whistle's `JSON_RE` (`/{[\w\W]*}|\[[\w\W]*\]/`, `res.js:846`) picks
/// out of a body: from the first `{` to the last `}`, or — only when there is no
/// `{` at all — from the first `[` to the last `]`. Greedy on purpose, so a
/// JSONP wrapper's parentheses stay outside.
fn json_span(text: &str) -> Option<(usize, usize)> {
    if let (Some(s), Some(e)) = (text.find('{'), text.rfind('}')) {
        if s < e {
            return Some((s, e + 1));
        }
    }
    let (s, e) = (text.find('[')?, text.rfind(']')?);
    (s < e).then_some((s, e + 1))
}

/// `resReplace` / `reqReplace` — substitute inside a body.
///
/// The value is a list of `pattern=replacement` pairs (`a=1&b=2`) or a JSON
/// object, each applied in turn (`parseRuleJson` → `handleReplace`,
/// `_original/lib/inspectors/res.js:124-145`). Upstream skips the whole
/// operator for a response with no `content-type` or an image one, so those
/// bodies are handed back untouched.
fn apply_replace(
    data: Vec<u8>,
    resolved: &Resolved,
    protocol: &str,
    class: Option<ResClass>,
) -> Vec<u8> {
    // Upstream refuses the whole operator for a response with no `content-type`
    // or an image one (`handleReplace`, `_original/lib/inspectors/res.js:129-132`).
    if matches!(class, None | Some(ResClass::Img)) {
        return data;
    }
    let pairs = merge_rule_maps(resolved, protocol);
    if pairs.is_empty() {
        return data;
    }
    // Not UTF-8 means a binary body, which whistle's text transforms never see.
    let mut text = match String::from_utf8(data) {
        Ok(text) => text,
        Err(e) => return e.into_bytes(),
    };
    for (pattern, value) in pairs {
        text = replace_once_or_all(&text, &pattern, &value);
    }
    text.into_bytes()
}

/// Collapse every matching line of a key/value operator into one ordered map,
/// the way `readRuleList`'s JSON branch does
/// (`_original/lib/util/index.js:1300-1312`).
///
/// The mechanism is worth spelling out, because it is not "apply each line in
/// turn": upstream **reverses** the list and `extend`s it onto its own last
/// entry. Two consequences, both reproduced here:
///
/// * a key written on several lines takes the **first** (highest-priority)
///   line's value — consistent with first-match-wins everywhere else;
/// * the resulting key *order* is the last line's keys first, then whatever
///   each earlier line adds. Since `handleReplace` and `parsePathReplace` walk
///   that order, the last line's substitutions are applied first
///   (`_original/lib/inspectors/res.js:134-144`,
///   `_original/lib/util/index.js:1014-1022`).
///
/// Shared by `reqReplace`/`resReplace`/`urlReplace`, which all reach the body
/// and path rewriters through `parseRuleJson`.
fn merge_rule_maps(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_replace_pairs(&op.value)),
    )
}

/// The `extend`-over-the-reversed-list core of [`merge_rule_maps`], over lines
/// already parsed into pairs.
///
/// Generic in the value so that `params://` can fold as JSON — the flat
/// `String` view cannot carry a nested object into a JSON request body.
fn merge_line_maps<V>(
    lines: impl DoubleEndedIterator<Item = Vec<(String, V)>>,
) -> Vec<(String, V)> {
    let mut out: Vec<(String, V)> = Vec::new();
    for pairs in lines.rev() {
        for (key, value) in pairs {
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => out.push((key, value)),
            }
        }
    }
    out
}

/// Split a `*Replace` value into `pattern` → `replacement` pairs.
///
/// `parseQuery` (via `tryParseMatcher`) splits on `&` then on the first `=`, so
/// `resReplace://a=1&b=2` is two substitutions, not one that inserts `1&b=2`.
/// A `{json}` value is an object of the same shape.
fn parse_replace_pairs(spec: &str) -> Vec<(String, String)> {
    let spec = spec.trim();
    if spec.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(spec) {
            return map
                .into_iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => s,
                        serde_json::Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    (k, val)
                })
                .collect();
        }
    }
    spec.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (!k.is_empty()).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Apply one `pattern` → `value` substitution the way whistle's transforms do.
///
/// A pattern spelled `/…/[gimu]` is a regular expression (`ORIG_REG_EXP`,
/// `_original/lib/util/index.js:611`), and follows JavaScript's rule that
/// **without the `g` flag only the first match is replaced**. Anything else —
/// including a half-formed `/a/x` — is a literal replace-all
/// (`str.split(key).join(value)`, `_original/lib/util/index.js:2267`).
fn replace_once_or_all(text: &str, pattern: &str, value: &str) -> String {
    let Some((source, flags)) = split_regexp(pattern) else {
        return text.replace(pattern, value);
    };
    // `/.*/ ` and `/.+/` mean "replace the whole body", special-cased upstream
    // so the empty trailing match cannot duplicate the replacement
    // (`ALL_RE`, `_original/lib/util/replace-pattern-transform.js:7,24-27`).
    if matches!(source, ".*" | ".+") {
        return value.to_string();
    }
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    let Ok(re) = regex::Regex::new(&format!("{prefix}{source}")) else {
        return text.to_string();
    };
    let value = js_replacement(value);
    match flags.contains('g') {
        true => re.replace_all(text, value.as_str()).into_owned(),
        false => re.replace(text, value.as_str()).into_owned(),
    }
}

/// Split `/source/flags` into its two halves, or `None` when the pattern is not
/// that shape. Mirrors `ORIG_REG_EXP = /^\/(.+)\/([igmu]{0,4})$/`: the source is
/// greedy (so `/a\/b/` keeps its inner slash) and every flag character must be
/// one of `igmu`.
fn split_regexp(pattern: &str) -> Option<(&str, &str)> {
    let rest = pattern.strip_prefix('/')?;
    let end = rest.rfind('/')?;
    let (source, flags) = (&rest[..end], &rest[end + 1..]);
    let ok = !source.is_empty()
        && flags.len() <= 4
        && flags.chars().all(|c| matches!(c, 'i' | 'g' | 'm' | 'u'));
    ok.then_some((source, flags))
}

/// Rewrite a JavaScript replacement string into the `regex` crate's spelling.
///
/// `$&` is the whole match and `$1`…`$9` are groups in both, but Rust reads
/// `$1x` as a capture *named* `1x`, so every reference is braced. `\$` escapes a
/// reference upstream (`replacePattern`,
/// `_original/lib/util/replace-pattern-transform.js:64-91`); the `$$`-prefixed
/// URL-encoding form is not ported.
fn js_replacement(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'$') {
            chars.next();
            out.push_str("$$"); // an escaped `$` is literal
            continue;
        }
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('&') => {
                chars.next();
                out.push_str("${0}");
            }
            Some(d) if d.is_ascii_digit() => {
                let d = *d;
                chars.next();
                out.push_str(&format!("${{{d}}}"));
            }
            // A lone `$` (or `$$`) is literal; `$$` is Rust's own escape.
            _ => out.push_str("$$"),
        }
    }
    out
}

/// Substitute a `pattern` → `replacement` list in `text`, in order.
fn apply_str_replace(text: &str, pairs: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (pattern, value) in pairs {
        out = replace_once_or_all(&out, pattern, value);
    }
    out
}

/// Rewrite the request path+query per `urlReplace`, `params`, and `urlParams`.
pub fn rewrite_path(path: &str, resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> String {
    let mut p = path.to_string();
    let replacements = merge_rule_maps(resolved, "urlReplace");
    if !replacements.is_empty() {
        // whistle substitutes into the path *without* its leading slash — it
        // slices the URL from one character past the host's `/`
        // (`parsePathReplace`, `_original/lib/util/index.js:1009-1013`), so a
        // pattern anchored with `^/` matches in neither implementation.
        let rest = p.strip_prefix('/');
        let replaced = apply_str_replace(rest.unwrap_or(&p), &replacements);
        p = match rest.is_some() {
            true => format!("/{replaced}"),
            false => replaced,
        };
    }
    // Each protocol collapses to one map of its own, then `urlParams` is laid
    // over `params` (`extend(_params, urlParams)`,
    // `_original/lib/inspectors/req.js:425`). `params` is skipped entirely when
    // the body claimed it — `_params = hasBody ? null : params` (`req.js:421`);
    // `urlParams` always addresses the query.
    let mut params: Vec<(String, String)> = Vec::new();
    if params_body_kind(resolved, ctx).is_none() {
        params.extend(merge_params_pairs(resolved, "params"));
    }
    params.extend(merge_params_pairs(resolved, "urlParams"));
    if !params.is_empty() {
        p = merge_query(&p, &params);
    }
    p
}

/// The `params`/`urlParams` lines of one protocol folded into a flat map, first
/// line winning a contested name.
fn merge_params_pairs(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_params_values(resolved, protocol)
        .into_iter()
        .map(|(k, v)| (k, json_to_param_string(v)))
        .collect()
}

/// The same fold, keeping each value as JSON so a nested object survives into a
/// JSON request body.
fn merge_params_values(resolved: &Resolved, protocol: &str) -> Vec<(String, serde_json::Value)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_param_values(&op.value)),
    )
}

/// Parse `k=v&k2=v2` or `{json}` into `name` → JSON value pairs.
fn parse_param_values(value: &str) -> Vec<(String, serde_json::Value)> {
    let value = value.trim();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            return map.into_iter().collect();
        }
    }
    value
        .split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((
                k.trim().to_string(),
                serde_json::Value::String(v.trim().to_string()),
            ))
        })
        .collect()
}

/// A param value as it appears in a query string or a form body: a JSON string
/// unquoted, anything else serialised.
///
/// Upstream reaches the same place by a different road — `qs.stringify` would
/// spell a nested object `a[b]=1` — so a `params://{"a":{"b":1}}` written
/// against a *form* body differs. Against a JSON body, which is where a nested
/// value belongs, both implementations merge the structure.
fn json_to_param_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Merge `params` into the query string of `path`, overriding same-named keys.
fn merge_query(path: &str, params: &[(String, String)]) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => (path, ""),
    };
    let merged = merge_query_string(query, params, &[]);
    if merged.is_empty() {
        return base.to_string();
    }
    format!("{base}?{merged}")
}

/// `replaceQueryString` (`_original/lib/util/index.js:1738-1800`): overlay
/// `params` on a `k=v&…` string, dropping the names in `del`.
///
/// The surviving original pairs keep their position and order; each replaced or
/// new name is appended in `params` order. Shared by the query string and the
/// urlencoded request body, which upstream runs through the same function.
fn merge_query_string(query: &str, params: &[(String, String)], del: &[String]) -> String {
    let deleted = |name: &str| del.iter().any(|d| d == name);
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .filter(|(k, _)| !deleted(k))
        .collect();
    for (k, v) in params {
        if deleted(k) {
            continue;
        }
        pairs.retain(|(ek, _)| ek != k);
        pairs.push((k.clone(), v.clone()));
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Remove length/encoding headers so hyper recomputes them for a rewritten body.
pub fn strip_length_headers(headers: &mut HeaderMap) {
    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);
}

/// Collect every value for a protocol, in resolution order.
fn collect_values<'a>(resolved: &'a Resolved, protocol: &str) -> Vec<&'a str> {
    resolved.all(protocol).iter().map(|o| o.value.as_str()).collect()
}

/// Collapse every line of a cookie protocol into one ordered `name` → `value`
/// map, first line winning a contested name — the `parseRuleJson` fold, as for
/// headers (`_original/lib/inspectors/req.js:459-468`).
fn merge_cookie_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_cookie_ops(&op.value)),
    )
}

/// Parse a `reqCookies`/`resCookies` value into `name` → `value` pairs.
///
/// Like the other JSON-shaped operators, the value is either `{json}` or a
/// query string, so `reqCookies://a=1&b=2` is two cookies. A name with no `=`
/// gets an **empty value** — it does not delete the cookie; that is
/// `delete://reqCookies.<name>`.
fn parse_cookie_ops(value: &str) -> Vec<(String, String)> {
    let value = value.trim();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            return map
                .into_iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => s,
                        serde_json::Value::Null => String::new(),
                        // A cookie declared as an object carries attributes
                        // upstream (`getCookieItem`); whistle-rs writes only
                        // its serialised form.
                        other => other.to_string(),
                    };
                    (k, val)
                })
                .collect();
        }
    }
    value
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.to_string()),
            None => (pair.trim().to_string(), String::new()),
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// Merge `reqCookies` operators into the request `Cookie` header, keeping the
/// position of a cookie the request already carried (`setReqCookies`,
/// `_original/lib/util/index.js:3053-3092`).
fn apply_req_cookies(headers: &mut HeaderMap, resolved: &Resolved) {
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
        let val = escape_cookie(&val, false);
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

/// Emit `Set-Cookie` headers for `resCookies` operators, **replacing** any the
/// response already sent under the same name rather than adding a second one.
fn apply_res_cookies(headers: &mut HeaderMap, resolved: &Resolved) {
    let ops = merge_cookie_ops(resolved, "resCookies");
    if ops.is_empty() {
        return;
    }
    let mut existing: Vec<(String, String)> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|c| {
            let name = c.split('=').next().unwrap_or(c).to_string();
            (name, c.to_string())
        })
        .collect();

    for (name, val) in ops {
        let name = escape_cookie(&name, true);
        let cookie = format!("{name}={}", escape_cookie(&val, false));
        match existing.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = cookie,
            None => existing.push((name, cookie)),
        }
    }

    headers.remove(hyper::header::SET_COOKIE);
    for (_, cookie) in existing {
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            headers.append(hyper::header::SET_COOKIE, v);
        }
    }
}

/// Percent-encode what may not appear in a cookie name or value
/// (`escapeName`/`escapeValue`, `_original/lib/util/index.js:3029-3050`). A name
/// may not carry `=` either.
fn escape_cookie(s: &str, is_name: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let forbidden = matches!(c, '\r' | '\n' | ';' | '%')
            || (c as u32) > 0xFF
            || (is_name && c == '=');
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

/// Apply every value of a header multi-match protocol.
///
/// The lines are collapsed into **one** map first ([`merge_line_maps`]), so a
/// header named on two lines takes the first line's value — see that function
/// for why the fold, not a top-to-bottom apply, is what upstream does.
fn apply_header_ops(headers: &mut HeaderMap, resolved: &Resolved, protocol: &str) {
    for (name, value) in merge_header_ops(resolved, protocol) {
        set_header(headers, &name, &value);
    }
}

/// Collapse every line of a header protocol into one ordered `name` → `value`
/// map, first line winning a contested name.
fn merge_header_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_header_pairs(&op.value)),
    )
}

/// Parse one header operator value into `name` → `value` pairs: `{json}`, or a
/// query string of `name=value` pairs (`resHeaders://x-a=1&x-b=2` is two
/// headers, as `parseQuery` has it). The `name:value` spelling is a whistle-rs
/// convenience, not upstream syntax.
fn parse_header_pairs(value: &str) -> Vec<(String, String)> {
    let value = value.trim();
    if value.starts_with('{') {
        if let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value) {
            return map
                .into_iter()
                .map(|(k, v)| match v {
                    serde_json::Value::String(s) => (k, s),
                    other => (k, other.to_string()),
                })
                .collect();
        }
    }
    if value.contains('=') {
        return value
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, val)| (name.trim().to_string(), val.trim().to_string()))
            .collect();
    }
    match value.split_once(':') {
        Some((name, val)) => vec![(name.trim().to_string(), val.trim().to_string())],
        None => Vec::new(),
    }
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

    /// Proxy facts for tests that reach the template engine.
    fn test_env() -> super::super::template::ProxyEnv<'static> {
        super::super::template::ProxyEnv { host: "", port: 8899, version: "9.9.9" }
    }

    /// Tests drive the async parts on a runtime of their own; `resolve_target`
    /// is async because a `pac://` rule may have to fetch its script.
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    /// The target `resolved` produces for `info`, which must not fail.
    fn resolved_target(info: &ReqInfo, resolved: &Resolved) -> Target {
        rt().block_on(resolve_target(info, resolved))
            .expect("resolve_target")
    }

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

    /// Request facts for the body operators: a POST carrying `content_type`.
    fn body_ctx(content_type: Option<&str>) -> ReqBodyCtx<'_> {
        ReqBodyCtx { method: "POST", content_type }
    }

    /// As [`resolve`], returning the [`ReqInfo`] as well for the callers that
    /// need it (the include merge, which resolves the included text in the
    /// request's own scope).
    fn resolve_with_info(rules: &str, url: &str) -> (ReqInfo, Resolved) {
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
        let resolved = m.resolve(&info);
        (info, resolved)
    }

    /// `reqCookies` merges into the existing header: a name already present
    /// keeps its position, a new one is appended, and a bare name sets an
    /// **empty** value rather than deleting the cookie (that is
    /// `delete://reqCookies.<name>`).
    #[test]
    fn req_cookies_merge_in_place() {
        let resolved = resolve(
            "example.com reqCookies://a=1&b=2\nexample.com reqCookies://old\n",
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::COOKIE, "old=x; keep=y".parse().unwrap());
        apply_req_cookies(&mut headers, &resolved);
        let cookie = headers.get(hyper::header::COOKIE).unwrap().to_str().unwrap();
        assert_eq!(cookie, "old=; keep=y; a=1; b=2");
    }

    #[test]
    fn res_body_replaced() {
        let resolved = resolve("example.com/x resBody://NEW\n", "http://example.com/x");
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(Bytes::from_static(b"OLD"), &resolved, None);
        assert_eq!(&out[..], b"NEW");
    }

    /// `resReplace` runs *before* the injection — its transform sits ahead of
    /// the `WhistleTransform` in whistle's response pipeline — so it rewrites
    /// the upstream body but never the prepended or appended text.
    #[test]
    fn res_body_prepend_append_replace() {
        let resolved = resolve(
            "example.com/x resPrepend://<!--foo-->\nexample.com/x resAppend://<!--foo-->\nexample.com/x resReplace://foo=bar\n",
            "http://example.com/x",
        );
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(
            Bytes::from_static(b"a foo b"),
            &resolved,
            Some("text/plain"),
        );
        assert_eq!(
            String::from_utf8_lossy(&out),
            "<!--foo-->a bar b<!--foo-->",
            "the substitution must not reach the injected text"
        );
    }

    /// A response with no `content-type` (or an image one) is skipped outright
    /// by `handleReplace` (`_original/lib/inspectors/res.js:129-132`).
    #[test]
    fn res_replace_needs_a_replaceable_content_type() {
        let resolved = resolve("example.com/x resReplace://foo=bar\n", "http://example.com/x");
        for ct in [None, Some("image/png")] {
            let out = transform_res_body(Bytes::from_static(b"a foo b"), &resolved, ct);
            assert_eq!(&out[..], b"a foo b", "{ct:?} should not be rewritten");
        }
        let out = transform_res_body(
            Bytes::from_static(b"a foo b"),
            &resolved,
            Some("text/plain"),
        );
        assert_eq!(&out[..], b"a bar b");
    }

    /// The value is a `&`-separated list of `pattern=replacement` pairs, each
    /// applied in turn (`parseQuery` via `tryParseMatcher`).
    #[test]
    fn res_replace_applies_every_pair() {
        let resolved = resolve(
            "example.com/x resReplace://a=1&b=2\n",
            "http://example.com/x",
        );
        let out = transform_res_body(Bytes::from_static(b"a b a"), &resolved, Some("text/plain"));
        assert_eq!(&out[..], b"1 2 1");
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

    /// `delete://` reaches the body too: a bare `body` empties it (discarding
    /// any injection with it), and `resBody.<path>` removes a JSON property.
    #[test]
    fn delete_reaches_the_body() {
        let resolved = resolve(
            "example.com/x delete://body\nexample.com/x resAppend://tail\n",
            "http://example.com/x",
        );
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(Bytes::from_static(b"keep?"), &resolved, Some("text/plain"));
        assert_eq!(&out[..], b"");

        let resolved = resolve(
            "example.com/x delete://resBody.a&resB.c.d\n",
            "http://example.com/x",
        );
        assert!(wants_res_body(&resolved));
        let out = transform_res_body(
            Bytes::from_static(br#"{"a":1,"b":2,"c":{"d":3,"e":4}}"#),
            &resolved,
            Some("application/json"),
        );
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("a").is_none() && v["c"].get("d").is_none());
        assert_eq!((v["b"].as_i64(), v["c"]["e"].as_i64()), (Some(2), Some(4)));

        // `req.body` is the request's alone.
        let resolved = resolve("example.com/x delete://req.body\n", "http://example.com/x");
        assert!(wants_req_body(&resolved, body_ctx(None)) && !wants_res_body(&resolved));
        assert_eq!(&transform_req_body(Bytes::from_static(b"x"), &resolved, body_ctx(Some("text/plain")))[..], b"");
    }

    /// The `/regexp/flags` form follows JavaScript's `String#replace`: without
    /// the `g` flag only the **first** match is substituted.
    /// `resMerge` only builds its transform for a JS, HTML, JSON or typeless
    /// response (`_original/lib/inspectors/res.js:1022`).
    #[test]
    fn res_merge_is_gated_on_the_content_type() {
        let resolved = resolve(
            "example.com/x resMerge://{\"a\":2}\n",
            "http://example.com/x",
        );
        let body = br#"{"a":1}"#;
        for ct in ["application/json", "text/html", "application/javascript"] {
            let out = transform_res_body(Bytes::from_static(body), &resolved, Some(ct));
            assert_eq!(&out[..], br#"{"a":2}"#, "{ct} should merge");
        }
        for ct in ["text/plain", "application/xml", "image/png"] {
            let out = transform_res_body(Bytes::from_static(body), &resolved, Some(ct));
            assert_eq!(&out[..], body, "{ct} should be left alone");
        }
    }

    /// The patch lands in the first JSON-looking *substring*, so a JSONP
    /// wrapper survives (`JSON_RE`, `_original/lib/inspectors/res.js:846`).
    #[test]
    fn res_merge_patches_a_json_substring() {
        let resolved = resolve(
            "example.com/x resMerge://{\"a\":2}\n",
            "http://example.com/x",
        );
        let out = transform_res_body(
            Bytes::from_static(br#"cb({"a":1});"#),
            &resolved,
            Some("application/javascript"),
        );
        assert_eq!(String::from_utf8_lossy(&out), r#"cb({"a":2});"#);
        // An empty body is replaced by the patch outright.
        let out = transform_res_body(Bytes::new(), &resolved, Some("application/json"));
        assert_eq!(&out[..], br#"{"a":2}"#);
        // An HTML body that does not *start* like JSON is left alone.
        let out = transform_res_body(
            Bytes::from_static(br#"<p>{"a":1}</p>"#),
            &resolved,
            Some("text/html"),
        );
        assert_eq!(String::from_utf8_lossy(&out), r#"<p>{"a":1}</p>"#);
    }

    #[test]
    fn res_body_regex_replace_honours_the_g_flag() {
        let once = resolve("example.com/x resReplace:///\\d+/=N\n", "http://example.com/x");
        let out = transform_res_body(
            Bytes::from_static(b"id=123 and 45"),
            &once,
            Some("text/plain"),
        );
        assert_eq!(&out[..], b"id=N and 45");

        let all = resolve("example.com/x resReplace:///\\d+/g=N\n", "http://example.com/x");
        let out = transform_res_body(
            Bytes::from_static(b"id=123 and 45"),
            &all,
            Some("text/plain"),
        );
        assert_eq!(&out[..], b"id=N and N");
    }

    /// A pattern that is not exactly `/source/[igmu]` is a literal string, not
    /// a regexp — `ORIG_REG_EXP` anchors both ends and admits only those flags.
    #[test]
    fn a_half_formed_regexp_is_a_literal_pattern() {
        assert_eq!(split_regexp("/\\d+/g"), Some(("\\d+", "g")));
        assert_eq!(split_regexp("/a\\/b/"), Some(("a\\/b", "")));
        assert_eq!(split_regexp("/a/x"), None, "`x` is not a whistle flag");
        assert_eq!(split_regexp("/a/gimux"), None);
        assert_eq!(split_regexp("//"), None, "an empty source is not a regexp");
        assert_eq!(split_regexp("a/b"), None);

        let resolved = resolve("example.com/x resReplace:////=Z\n", "http://example.com/x");
        let out = transform_res_body(
            Bytes::from_static(b"a // b // c"),
            &resolved,
            Some("text/plain"),
        );
        assert_eq!(&out[..], b"a Z b Z c", "a literal pattern replaces them all");
    }

    /// `$&` and `$1` reach the replacement, and `/.*/ ` swaps the whole body.
    #[test]
    fn regex_replacement_back_references() {
        let resolved = resolve(
            "example.com/x resReplace:///(\\w+)@(\\w+)/g=$2.$1x\n",
            "http://example.com/x",
        );
        let out = transform_res_body(Bytes::from_static(b"a@b c@d"), &resolved, Some("text/plain"));
        assert_eq!(&out[..], b"b.ax d.cx", "`$1x` is group 1 then a literal x");

        assert_eq!(js_replacement("[$&]"), "[${0}]");
        assert_eq!(js_replacement("\\$1"), "$$1");

        let all = resolve("example.com/x resReplace:///.*/g=ONLY\n", "http://example.com/x");
        let out = transform_res_body(Bytes::from_static(b"whatever"), &all, Some("text/plain"));
        assert_eq!(&out[..], b"ONLY", "`/.*/ ` replaces the body exactly once");
    }

    #[test]
    fn req_body_replaced_only_when_present() {
        let none = resolve("example.com host://1.1.1.1\n", "http://example.com/");
        assert!(!wants_req_body(&none, body_ctx(None)));
        let some = resolve("example.com reqBody://HELLO\n", "http://example.com/");
        assert!(wants_req_body(&some, body_ctx(None)));
        let out = transform_req_body(Bytes::from_static(b"orig"), &some, body_ctx(Some("text/plain")));
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
        let out = rewrite_path("/api/v1/users?a=1", &resolved, body_ctx(None));
        assert!(out.starts_with("/api/v2/users?"));
        assert!(out.contains("a=1"));
        assert!(out.contains("token=abc"));
    }

    #[test]
    fn params_override_existing_key() {
        let resolved = resolve("example.com params://a=2\n", "http://example.com/p?a=1&b=3");
        let out = rewrite_path("/p?a=1&b=3", &resolved, body_ctx(None));
        assert!(out.contains("b=3"));
        assert!(out.contains("a=2"));
        assert!(!out.contains("a=1"));
    }

    // ── `params://` merged into the request body ──

    /// `transform_req_body` for a POST carrying `ct`.
    fn merged_body(rules: &str, ct: Option<&str>, body: &str) -> String {
        let resolved = resolve(rules, "http://example.com/p");
        let out = transform_req_body(Bytes::from(body.to_string()), &resolved, body_ctx(ct));
        String::from_utf8_lossy(&out).into_owned()
    }

    /// A form body takes the params, and the query string does **not** — the
    /// two are exclusive upstream (`_params = hasBody ? null : params`,
    /// `_original/lib/inspectors/req.js:421`). `urlParams` still goes to the
    /// query either way.
    #[test]
    fn params_merge_into_a_form_body() {
        const FORM: &str = "application/x-www-form-urlencoded";
        assert_eq!(
            merged_body("example.com params://b=2\n", Some(FORM), "a=1"),
            "a=1&b=2"
        );
        // A name already in the body is replaced in place.
        assert_eq!(
            merged_body("example.com params://a=9\n", Some(FORM), "a=1&b=2"),
            "b=2&a=9"
        );
        // An empty body becomes the params outright.
        assert_eq!(merged_body("example.com params://a=1\n", Some(FORM), ""), "a=1");

        let resolved = resolve(
            "example.com params://b=2 urlParams://c=3\n",
            "http://example.com/p?a=1",
        );
        let ctx = body_ctx(Some(FORM));
        assert_eq!(rewrite_path("/p?a=1", &resolved, ctx), "/p?a=1&c=3");
        // Without a body to take them, the params land in the query as before.
        assert_eq!(
            rewrite_path("/p?a=1", &resolved, body_ctx(None)),
            "/p?a=1&b=2&c=3"
        );
    }

    /// `isUrlEncoded` is POST-only upstream
    /// (`_original/lib/util/common.js:692-695`), so the same rule on a PUT sends
    /// the params to the query string. Odd, and reproduced.
    #[test]
    fn a_form_body_takes_params_only_on_post() {
        const FORM: &str = "application/x-www-form-urlencoded";
        let resolved = resolve("example.com params://b=2\n", "http://example.com/p");
        let put = ReqBodyCtx { method: "PUT", content_type: Some(FORM) };
        assert!(!wants_req_body(&resolved, put));
        assert_eq!(rewrite_path("/p", &resolved, put), "/p?b=2");

        let post = ReqBodyCtx { method: "POST", content_type: Some(FORM) };
        assert!(wants_req_body(&resolved, post));
        assert_eq!(rewrite_path("/p", &resolved, post), "/p");
    }

    /// A JSON body is patched, deeply, and only across its first JSON-looking
    /// span so a wrapper survives (`JSON_RE`, `_original/lib/inspectors/req.js:18`).
    #[test]
    fn params_merge_into_a_json_body() {
        const JSON: &str = "application/json";
        assert_eq!(
            merged_body("example.com params://b=2\n", Some(JSON), "{\"a\":1}"),
            "{\"a\":1,\"b\":\"2\"}"
        );
        // A `{json}` value keeps its structure and merges deeply — the flat
        // `name=value` view could only have inserted a string.
        assert_eq!(
            merged_body(
                "example.com params://{\"a\":{\"y\":2}}\n",
                Some(JSON),
                "{\"a\":{\"x\":1}}"
            ),
            "{\"a\":{\"x\":1,\"y\":2}}"
        );
        // The wrapper around the JSON span is untouched.
        assert_eq!(
            merged_body("example.com params://b=2\n", Some(JSON), "cb({\"a\":1})"),
            "cb({\"a\":1,\"b\":\"2\"})"
        );
        // An empty body becomes the params, serialised as JSON.
        assert_eq!(
            merged_body("example.com params://a=1\n", Some(JSON), ""),
            "{\"a\":\"1\"}"
        );
        // A GET carries no body upstream, so the params address the query.
        let resolved = resolve("example.com params://b=2\n", "http://example.com/p");
        let get = ReqBodyCtx { method: "GET", content_type: Some(JSON) };
        assert_eq!(rewrite_path("/p", &resolved, get), "/p?b=2");
    }

    /// `delete://reqBody.<path>` rides the same transform upstream, so it only
    /// ever reaches a body whose shape whistle recognises.
    #[test]
    fn delete_req_body_props() {
        assert_eq!(
            merged_body(
                "example.com delete://reqBody.a.x\n",
                Some("application/json"),
                "{\"a\":{\"x\":1,\"y\":2}}"
            ),
            "{\"a\":{\"y\":2}}"
        );
        assert_eq!(
            merged_body(
                "example.com delete://reqBody.a\n",
                Some("application/x-www-form-urlencoded"),
                "a=1&b=2"
            ),
            "b=2"
        );
    }

    /// A multipart body: a part named by a param is replaced whole, one named
    /// by `delete://reqBody.` is dropped, and an unmatched param is appended.
    #[test]
    fn params_merge_into_a_multipart_body() {
        const CT: &str = "multipart/form-data; boundary=X";
        let body = "--X\r\n\
                    Content-Disposition: form-data; name=\"keep\"\r\n\r\nkept\r\n\
                    --X\r\n\
                    Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\
                    Content-Type: application/octet-stream\r\n\r\nRAW\r\n\
                    --X\r\n\
                    Content-Disposition: form-data; name=\"gone\"\r\n\r\nbye\r\n\
                    --X--";
        let out = merged_body(
            "example.com params://file=replaced&extra=new delete://reqBody.gone\n",
            Some(CT),
            body,
        );
        assert_eq!(
            out,
            "--X\r\n\
             Content-Disposition: form-data; name=\"keep\"\r\n\r\nkept\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"file\"\r\n\r\nreplaced\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"extra\"\r\n\r\nnew\r\n\
             --X--"
        );
        // A body that does not open with the boundary is passed through, which
        // is upstream's `badMultipart` path.
        assert_eq!(
            merged_body("example.com params://a=1\n", Some(CT), "not multipart"),
            "not multipart"
        );
        // No boundary in the content type means no parts to find, so the params
        // fall back to the query string.
        let resolved = resolve("example.com params://a=1\n", "http://example.com/p");
        let no_boundary = ReqBodyCtx {
            method: "POST",
            content_type: Some("multipart/form-data"),
        };
        assert!(!wants_req_body(&resolved, no_boundary));
        assert_eq!(rewrite_path("/p", &resolved, no_boundary), "/p?a=1");
    }

    /// A request no `params://` line matched never looks at its own body: the
    /// buffering decision is answered from the resolved set alone.
    #[test]
    fn params_cost_nothing_when_no_rule_asks() {
        let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/p");
        for ct in [
            None,
            Some("application/json"),
            Some("application/x-www-form-urlencoded"),
            Some("multipart/form-data; boundary=X"),
        ] {
            assert!(!wants_req_body(&resolved, body_ctx(ct)));
        }
    }

    #[test]
    fn delete_headers_and_cookies() {
        let resolved = resolve(
            "example.com delete://reqHeaders.x-req&reqCookies.sid\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-req", "1".parse().unwrap());
        h.insert("x-keep", "2".parse().unwrap());
        h.insert(hyper::header::COOKIE, "sid=abc; keep=1".parse().unwrap());
        apply_deletes(&mut h, &Deletions::of(&resolved, true));
        assert!(h.get("x-req").is_none());
        assert!(h.get("x-keep").is_some());
        let c = h.get(hyper::header::COOKIE).unwrap().to_str().unwrap();
        assert!(!c.contains("sid="));
        assert!(c.contains("keep=1"));
    }

    /// whistle matches `delete://` keys against a fixed set of anchored
    /// patterns (`_original/lib/util/index.js:2661-2669`) and ignores anything
    /// else — including a bare header name, and the singular `header.`.
    #[test]
    fn delete_keys_follow_upstreams_spellings() {
        let names = |rule: &str, request_side: bool| {
            let r = resolve(&format!("example.com delete://{rule}\n"), "http://example.com/");
            Deletions::of(&r, request_side).headers
        };
        for spelling in [
            "resHeaders.x-a",
            "resHeader.x-a",
            "resH.x-a",
            "res.headers.x-a",
            "res.h.x-a",
            "RESHEADERS.x-a",
            "headers.x-a",
        ] {
            assert_eq!(names(spelling, false), ["x-a"], "{spelling}");
        }
        for ignored in ["x-a", "header.x-a", "reqHeaders.x-a", "Headers.x-a"] {
            assert!(names(ignored, false).is_empty(), "{ignored} must be inert");
        }
        // The type/charset keys are their own thing, not header names.
        let r = resolve("example.com delete://resType&res.charset\n", "http://example.com/");
        let del = Deletions::of(&r, false);
        assert!(del.drop_type && del.drop_charset && del.headers.is_empty());
    }

    /// A `headerReplace` pattern is a regexp only in the `/…/flags` spelling;
    /// anything else is a literal, replaced everywhere it occurs.
    #[test]
    fn header_replace_patterns() {
        let replaced = |rule: &str, value: &str| {
            let resolved = resolve(
                &format!("example.com headerReplace://{rule}\n"),
                "http://example.com/",
            );
            let mut h = HeaderMap::new();
            h.insert("x-foo", value.parse().unwrap());
            apply_header_replace(&mut h, &resolved, false);
            h.get("x-foo").map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            replaced("{\"resH.x-foo:/ba./g\":\"XX\"}", "bar-baz"),
            Some("XX-XX".to_string())
        );
        assert_eq!(
            replaced("{\"resH.x-foo:ba.\":\"XX\"}", "bar-baz"),
            Some("bar-baz".to_string()),
            "`ba.` is a literal, and `bar-baz` does not contain it"
        );
        assert_eq!(
            replaced("{\"resH.x-foo:ba\":\"XX\"}", "bar-baz"),
            Some("XXr-XXz".to_string())
        );
        // `reqHeaders.`/`resHeaders.` are not among upstream's four prefixes.
        assert_eq!(
            replaced("{\"resHeaders.x-foo:bar\":\"XX\"}", "bar"),
            Some("bar".to_string())
        );
        // A key with no `:` has no pattern at all.
        assert_eq!(
            replaced("{\"res.x-foo\":\"XX\"}", "bar"),
            Some("bar".to_string())
        );
    }

    #[test]
    fn charset_set_and_strip() {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::CONTENT_TYPE, "text/html".parse().unwrap());
        set_charset(&mut h, Some("utf-8"), false, false);
        assert_eq!(
            h.get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        set_charset(&mut h, None, false, true);
        assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "text/html");

        // `delete://resType` empties the media type but keeps the parameters —
        // upstream blanks slot 0 rather than removing the header.
        set_charset(&mut h, Some("gbk"), true, false);
        assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "; charset=gbk");
        // Nothing left at all removes the header.
        set_charset(&mut h, None, true, true);
        assert!(h.get(hyper::header::CONTENT_TYPE).is_none());
    }

    /// `resType://json` is a short name to look up, and a value with no
    /// parameters inherits the ones already on the header (`getNewType`).
    #[test]
    fn res_type_looks_up_short_names() {
        let mut h = HeaderMap::new();
        h.insert(
            hyper::header::CONTENT_TYPE,
            "text/html; charset=gbk".parse().unwrap(),
        );
        set_content_type(&mut h, "json", no_type_alias);
        assert_eq!(
            h.get(hyper::header::CONTENT_TYPE).unwrap(),
            "application/json; charset=gbk"
        );
        // An explicit parameter replaces the lot.
        set_content_type(&mut h, "text/plain;charset=utf-8", no_type_alias);
        assert_eq!(
            h.get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/plain;charset=utf-8"
        );
        // An unknown short name is whistle's octet-stream default; `sse` is the
        // one name that is not a file extension.
        assert_eq!(lookup_type("nosuchtype", no_type_alias), "application/octet-stream");
        assert_eq!(lookup_type("sse", no_type_alias), "text/event-stream");
        // The request side has extra aliases of its own.
        assert_eq!(lookup_type("form", req_type_alias), "application/x-www-form-urlencoded");
        assert_eq!(lookup_type("form", no_type_alias), "application/octet-stream");
    }

    #[test]
    fn file_family_cross_falls_through() {
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        // xfile with a missing file → no short-circuit (proxy the real server).
        let x = resolve("a.com xfile:///no/such/file.txt\n", "http://a.com/");
        assert!(short_circuit(&info, &x, test_env()).is_none());
        // plain file missing → a 404 short-circuit.
        let f = resolve("a.com file:///no/such/file.txt\n", "http://a.com/");
        let r = short_circuit(&info, &f, test_env()).expect("file:// should short-circuit");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    /// Response-side operators must reach a mocked response too — upstream runs
    /// its response inspectors over `file`/`tpl`/`redirect` results as well.
    #[test]
    fn short_circuit_response_takes_response_operators() {
        let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
        let resolved = resolve(
            "a.com file:///definitely/missing/file resHeaders://x-mock=1 resType://json",
            "http://a.com/x",
        );
        let resp = short_circuit(&info, &resolved, test_env()).expect("file:// short-circuits");
        let mut parts = resp.into_parts().0;
        apply_response(&mut parts, &resolved);
        assert_eq!(parts.headers.get("x-mock").map(|v| v.to_str().unwrap()), Some("1"));
        assert!(
            parts
                .headers
                .get("content-type")
                .map(|v| v.to_str().unwrap().contains("json"))
                .unwrap_or(false),
            "resType:// should have set a JSON content type"
        );
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
        let p = resolved_target(&info, &r).proxy.expect("internal-https-proxy");
        assert_eq!(p.kind, ProxyKind::Https);
        assert_eq!(p.port, 8080);

        let r2 = resolve("a.com internal-http-proxy://1.2.3.4:8081\n", "http://a.com/");
        let p2 = resolved_target(&info, &r2).proxy.expect("internal-http-proxy");
        assert_eq!(p2.kind, ProxyKind::Http);

        // `xproxy` is an alias of `proxy`.
        let r3 = resolve("a.com xproxy://5.6.7.8:3128\n", "http://a.com/");
        let p3 = resolved_target(&info, &r3).proxy.expect("xproxy");
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

    // -- the file family -----------------------------------------------------

    /// A throwaway directory of fixtures, removed when the test ends.
    struct Fixtures(PathBuf);

    impl Fixtures {
        fn new(tag: &str) -> Fixtures {
            let dir = std::env::temp_dir().join(format!("whistle-rs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create fixture dir");
            Fixtures(dir)
        }

        /// Write a fixture and return its absolute path.
        fn write(&self, name: &str, body: &[u8]) -> String {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create fixture parent");
            }
            std::fs::write(&path, body).expect("write fixture");
            self.path(name)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for Fixtures {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Every `reqRules://` line contributes to the included rules text, and at
    /// most one line spelled any other way — upstream's filter over the
    /// accumulated list (`_original/lib/rules/rules.js:2258-2272`). This port
    /// used to read only the first line whatever its spelling.
    #[test]
    fn rules_file_lines_accumulate() {
        let fx = Fixtures::new("rulesfile-accum");
        let a = fx.write("a.txt", b"example.com resHeaders://x-a=1\n");
        let b = fx.write("b.txt", b"example.com resHeaders://x-b=2\n");
        let c = fx.write("c.txt", b"example.com resHeaders://x-c=3\n");

        let merged = |rules: &str| {
            let (info, mut resolved) = resolve_with_info(rules, "http://example.com/");
            let _ = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
            let mut h = HeaderMap::new();
            apply_header_ops(&mut h, &resolved, "resHeaders");
            h
        };

        // Two `reqRules://` lines: both are rules text, so both apply.
        let h = merged(&format!(
            "example.com reqRules://{a}\nexample.com reqRules://{b}\n"
        ));
        assert_eq!(h.get("x-a").unwrap(), "1");
        assert_eq!(h.get("x-b").unwrap(), "2");

        // Two `rulesFile://` lines: each is a *candidate script*, and upstream
        // keeps only the first. The second is dropped, not merged.
        let h = merged(&format!(
            "example.com rulesFile://{a}\nexample.com rulesFile://{b}\n"
        ));
        assert_eq!(h.get("x-a").unwrap(), "1");
        assert!(h.get("x-b").is_none());

        // Mixed: every `reqRules://` line plus the first other one.
        let h = merged(&format!(
            "example.com reqRules://{a}\n\
             example.com rulesFile://{b}\n\
             example.com rulesFile://{c}\n"
        ));
        assert_eq!(h.get("x-a").unwrap(), "1");
        assert_eq!(h.get("x-b").unwrap(), "2");
        assert!(h.get("x-c").is_none());

        // The pieces are joined into *one* rules text, so a single-value
        // protocol contested across two files is decided by their order.
        let host_a = fx.write("host-a.txt", b"example.com host://1.1.1.1\n");
        let host_b = fx.write("host-b.txt", b"example.com host://2.2.2.2\n");
        let (info, mut resolved) = resolve_with_info(
            &format!("example.com reqRules://{host_a}\nexample.com reqRules://{host_b}\n"),
            "http://example.com/",
        );
        let _ = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        assert_eq!(resolved.value("host"), Some("1.1.1.1"));
    }

    /// Rules merged in mid-request take the same two passes the top-level rules
    /// do: a response condition inside a `rulesFile://` include (or a plugin's
    /// injected rules) is now answered rather than failing closed.
    ///
    /// Upstream re-resolves the same managers in its response phase
    /// (`_original/lib/plugins/index.js:1326-1335`).
    #[test]
    fn merged_rules_get_the_response_phase_too() {
        let fx = Fixtures::new("merged-res-phase");
        let inc = fx.write(
            "inc.txt",
            b"example.com resHeaders://x-late=1 includeFilter://s:404\n\
              example.com resHeaders://x-always=1\n",
        );

        // `merge_included_rules` + `response_phase_of` is exactly what
        // `serve`'s two phases compose; `status` drives the second.
        let resolve_at = |rules: &str, status: Option<u16>| {
            let (mut info, mut resolved) = resolve_with_info(rules, "http://example.com/");
            let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
            if let Some(status) = status {
                info.res = Some(build_res_info(status, &HeaderMap::new(), None, None));
                if let Some(extra) = response_phase_of(&merged, &info, false) {
                    resolved.merge_response_phase(extra);
                }
            }
            let mut h = HeaderMap::new();
            apply_header_ops(&mut h, &resolved, "resHeaders");
            h
        };

        let rules = format!("example.com rulesFile://{inc}\n");
        // The unconditional line applies from the request phase on.
        assert_eq!(resolve_at(&rules, None).get("x-always").unwrap(), "1");
        assert!(resolve_at(&rules, None).get("x-late").is_none());
        // The conditional one waits for the status, and then holds — or not.
        let on_404 = resolve_at(&rules, Some(404));
        assert_eq!(on_404.get("x-late").unwrap(), "1");
        assert_eq!(on_404.get("x-always").unwrap(), "1");
        assert!(resolve_at(&rules, Some(200)).get("x-late").is_none());

        // The same for rules a plugin injects.
        let (mut info, mut resolved) = resolve_with_info("example.com/x\n", "http://example.com/x");
        let merged = vec![merge_rules_text(
            &mut resolved,
            &info,
            "example.com resHeaders://x-plugin=1 includeFilter://s:500\n",
            false,
        )];
        info.res = Some(build_res_info(500, &HeaderMap::new(), None, None));
        let extra = response_phase_of(&merged, &info, false).expect("a second pass");
        resolved.merge_response_phase(extra);
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        assert_eq!(h.get("x-plugin").unwrap(), "1");
    }

    /// Nothing is applied twice: the request pass withholds exactly what the
    /// second one resolves, so a line whose *exclude* filter is inert in the
    /// request phase does not contribute its operator in both.
    #[test]
    fn a_merged_rule_is_not_resolved_twice() {
        let fx = Fixtures::new("merged-res-phase-once");
        let inc = fx.write(
            "inc.txt",
            b"example.com resHeaders://x-a=1 excludeFilter://s:404\n",
        );
        let (mut info, mut resolved) = resolve_with_info(
            &format!("example.com rulesFile://{inc}\n"),
            "http://example.com/",
        );
        let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        assert!(
            resolved.all("resHeaders").is_empty(),
            "withheld until the status is known"
        );
        info.res = Some(build_res_info(200, &HeaderMap::new(), None, None));
        let extra = response_phase_of(&merged, &info, false).expect("a second pass");
        resolved.merge_response_phase(extra);
        assert_eq!(resolved.all("resHeaders").len(), 1);

        // …and the exclude filter still fires when it should.
        let (mut info, mut resolved) = resolve_with_info(
            &format!("example.com rulesFile://{inc}\n"),
            "http://example.com/",
        );
        let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        info.res = Some(build_res_info(404, &HeaderMap::new(), None, None));
        assert!(response_phase_of(&merged, &info, false).is_some_and(|e| e.all("resHeaders").is_empty()));
    }

    /// An included file that says nothing about the response gets no second
    /// pass at all — the manager answers from its precomputed flags.
    #[test]
    fn a_merged_rule_with_no_response_condition_skips_the_second_pass() {
        let fx = Fixtures::new("merged-res-phase-skip");
        let inc = fx.write("inc.txt", b"example.com resHeaders://x-a=1\n");
        let (mut info, mut resolved) = resolve_with_info(
            &format!("example.com rulesFile://{inc}\n"),
            "http://example.com/",
        );
        let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        info.res = Some(build_res_info(200, &HeaderMap::new(), None, None));
        assert!(response_phase_of(&merged, &info, false).is_none());
    }

    /// `resScript` picks the first line **not** spelled `resRules://` — the only
    /// one upstream ever executes. Before this, a rules file written above the
    /// script was handed to the JS engine in its place.
    #[test]
    fn res_script_skips_the_rules_spelling() {
        let resolved = resolve(
            "example.com resRules:///rules.txt resScript:///script.js\n",
            "http://example.com/",
        );
        assert_eq!(
            res_script_op(&resolved).map(|op| op.value.as_str()),
            Some("/script.js")
        );
        // With no script at all there is nothing to run, rather than the rules
        // file being evaluated as JavaScript.
        let only_rules = resolve("example.com resRules:///rules.txt\n", "http://example.com/");
        assert!(res_script_op(&only_rules).is_none());
        // A second script is dropped before the search, so it can never be
        // reached even if the first is a `resRules://` line.
        let two = resolve(
            "example.com resScript:///one.js resScript:///two.js\n",
            "http://example.com/",
        );
        assert_eq!(
            res_script_op(&two).map(|op| op.value.as_str()),
            Some("/one.js")
        );
    }

    /// Serve a file rule for `GET http://x.com/`, returning status, content type
    /// and body.
    fn serve(proto: &str, value: &str) -> Option<(u16, String, Vec<u8>)> {
        serve_at(proto, value, "http://x.com/")
    }

    /// As [`serve`], but for an explicit request URL (the content-type fallback
    /// and the template variables both read it).
    fn serve_at(proto: &str, value: &str, url: &str) -> Option<(u16, String, Vec<u8>)> {
        let (scheme, rest) = url.split_once("://").expect("absolute url");
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let info = build_req_info("GET", scheme, host, 80, path, &HeaderMap::new(), None);
        let resp = serve_file_family(proto, value, &info, test_env())?;
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
            .expect("collect body")
            .to_bytes()
            .to_vec();
        Some((status, ctype, body))
    }

    #[test]
    fn multi_path_takes_the_first_existing_file() {
        let fx = Fixtures::new("multipath");
        let missing = fx.path("nope.json");
        let present = fx.write("b.json", b"{\"from\":\"b\"}");
        let later = fx.write("c.json", b"{\"from\":\"c\"}");

        let value = format!("{missing}|{present}|{later}");
        let (status, ctype, body) = serve("file", &value).expect("served");
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json; charset=utf-8");
        assert_eq!(body, b"{\"from\":\"b\"}");
    }

    #[test]
    fn xs_rules_never_split_on_pipe() {
        // whistle's split regex only admits a single `x` (`rules.js:96`), so an
        // `xs` rule treats `|` as part of the filename. Reproduced deliberately.
        let fx = Fixtures::new("xspipe");
        let present = fx.write("only.json", b"ok");
        let value = format!("{}|{present}", fx.path("nope.json"));

        // `xfile` splits and finds the second path…
        assert!(serve("xfile", &value).is_some());
        // …`xsfile` does not, so it falls through to the real server.
        assert!(serve("xsfile", &value).is_none());
    }

    #[test]
    fn parent_directory_paths_are_refused() {
        let fx = Fixtures::new("uppath");
        let target = fx.write("secret.txt", b"nope");
        let escaped = format!("{}/sub/../secret.txt", fx.0.to_string_lossy());
        assert!(std::path::Path::new(&target).exists());

        let (status, _, body) = serve("file", &escaped).expect("served");
        assert_eq!(status, 404);
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("(Path contains parent directory notation &#39;..&#39;)"),
            "{body}"
        );
        // A `..` inside a segment is an ordinary filename, not an escape.
        assert!(!has_parent_ref("/tmp/a..b/c"));
        assert!(has_parent_ref("../a") && has_parent_ref("a/../b") && has_parent_ref("a/.."));
    }

    #[test]
    fn refused_path_still_lets_a_later_alternative_win() {
        let fx = Fixtures::new("uppath2");
        let present = fx.write("ok.txt", b"ok");
        let value = format!("../escape|{present}");
        let (status, _, body) = serve("file", &value).expect("served");
        assert_eq!((status, body.as_slice()), (200, b"ok".as_slice()));
    }

    #[test]
    fn trailing_slash_expands_to_index_html() {
        let fx = Fixtures::new("indexhtml");
        fx.write("site/index.html", b"<h1>home</h1>");
        let value = format!("{}/", fx.path("site"));

        let (status, ctype, body) = serve("file", &value).expect("served");
        assert_eq!(status, 200);
        // The content type comes from the *matched* path, not the rule value.
        assert_eq!(ctype, "text/html; charset=utf-8");
        assert_eq!(body, b"<h1>home</h1>");

        // The directory itself is tried first, and only wins for a real file.
        assert_eq!(
            expand_index("/a/b/"),
            vec!["/a/b".to_string(), "/a/b/index.html".to_string()]
        );
        assert_eq!(expand_index("/a/b"), vec!["/a/b".to_string()]);
    }

    #[test]
    fn home_prefix_expands_to_the_home_directory() {
        let home = dirs::home_dir().expect("a home directory");
        let home = home.to_string_lossy();
        assert_eq!(expand_home("~/mock.json"), format!("{home}/mock.json"));
        // The full-width tilde is accepted too, a bare `~` is not.
        assert_eq!(expand_home("～/mock.json"), format!("{home}/mock.json"));
        assert_eq!(expand_home("~mock.json"), "~mock.json");
        assert_eq!(expand_home("/tmp/~/x"), "/tmp/~/x");

        assert!(
            FileCandidates::of("file", "~/mock.json")
                .paths
                .contains(&format!("{home}/mock.json"))
        );
    }

    #[test]
    fn template_rules_render_the_file() {
        let fx = Fixtures::new("tpl");
        let path = fx.write("api.json", br#"{"cb":"{callback}","m":"${method.replace(GET,get)}"}"#);
        let (status, ctype, body) =
            serve_at("tpl", &path, "http://x.com/api?callback=cb1").expect("served");
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json; charset=utf-8");
        assert_eq!(String::from_utf8_lossy(&body), r#"{"cb":"cb1","m":"get"}"#);
    }

    #[test]
    fn raw_file_parses_a_complete_response() {
        let fx = Fixtures::new("rawfile");
        let path = fx.write(
            "res.http",
            b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"nope\"}",
        );
        let (status, ctype, body) = serve("rawfile", &path).expect("served");
        assert_eq!(status, 404);
        assert_eq!(ctype, "application/json");
        assert_eq!(body, b"{\"error\":\"nope\"}");
    }

    #[test]
    fn raw_file_without_a_blank_line_is_served_verbatim() {
        // No separator means it was never a raw response; whistle serves the
        // file rather than eating its first line as a status line.
        let fx = Fixtures::new("rawplain");
        let path = fx.write("plain.txt", b"HTTP/1.1 200 OK\r\nnot really a response");
        let (status, ctype, body) = serve("rawfile", &path).expect("served");
        assert_eq!(status, 200);
        assert_eq!(ctype, "text/plain; charset=utf-8");
        assert_eq!(body, b"HTTP/1.1 200 OK\r\nnot really a response");
    }

    #[test]
    fn raw_file_keeps_a_binary_body() {
        let fx = Fixtures::new("rawbin");
        let mut fixture = b"HTTP/1.1 200 OK\nContent-Type: image/png\n\n".to_vec();
        let payload = [0x89u8, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe];
        fixture.extend_from_slice(&payload);
        let path = fx.write("img.http", &fixture);

        let (status, ctype, body) = serve("rawfile", &path).expect("served");
        assert_eq!((status, ctype.as_str()), (200, "image/png"));
        assert_eq!(body, payload, "lossy UTF-8 would have mangled these bytes");
    }

    #[test]
    fn headers_separator_accepts_every_line_ending() {
        // `HEADERS_SEP_RE`, file-proxy.js:12.
        for sep in ["\r\n\r\n", "\r\n\r", "\r\n\n", "\n\r\n", "\n\r", "\n\n", "\r\r\n", "\r\r"] {
            let data = format!("head{sep}body");
            let (head_end, body_start) = find_headers_sep(data.as_bytes()).expect(sep);
            assert_eq!(&data[..head_end], "head", "{sep:?}");
            assert_eq!(&data[body_start..], "body", "{sep:?}");
        }
        assert_eq!(find_headers_sep(b"head\nbody"), None);
    }

    #[test]
    fn a_separator_past_the_header_budget_is_ignored() {
        // whistle stops looking after MAX_HEADERS_SIZE (file-proxy.js:13,151-158).
        let mut data = vec![b'x'; MAX_RAW_HEADERS + 16];
        data.extend_from_slice(b"\r\n\r\nbody");
        assert!(find_headers_sep(&data[..data.len().min(MAX_RAW_HEADERS)]).is_none());
    }

    #[test]
    fn missing_file_404s_with_an_escaped_path() {
        let (status, ctype, body) = serve("file", "/nonexistent/<script>").expect("served");
        assert_eq!(status, 404);
        assert_eq!(ctype, "text/html; charset=utf-8");
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("&lt;script&gt;"), "{body}");
        assert!(!body.contains("<script>"), "{body}");
    }

    #[test]
    fn the_file_cache_never_serves_stale_bytes() {
        let fx = Fixtures::new("cache");
        let path = fx.write("mock.json", b"{\"v\":1}");
        assert_eq!(serve("file", &path).expect("served").2, b"{\"v\":1}");

        // A mock edited mid-session must be picked up, even at the same length.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&path, b"{\"v\":2}").expect("rewrite fixture");
        assert_eq!(serve("file", &path).expect("served").2, b"{\"v\":2}");
    }

    #[test]
    fn cipher_sets_target_tls_versions() {
        use super::super::upstream::TlsVersions;
        let resolved = resolve("example.com cipher://TLSv1.2\n", "https://example.com/");
        let info = build_req_info("GET", "https", "example.com", 443, "/", &HeaderMap::new(), None);
        let target = resolved_target(&info, &resolved);
        assert_eq!(target.tls_versions, TlsVersions::Only12);
    }

    // ── host / proxy precedence (proxyFirst, proxyHost, proxyHostOnly) ──

    /// The upstream target `rules` produce for `url`, or the error that stopped
    /// the request from being sent anywhere.
    fn try_target(rules: &str, url: &str) -> Result<Target> {
        let resolved = resolve(rules, url);
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
        rt().block_on(resolve_target(&info, &resolved))
    }

    /// The upstream target `rules` produce for `url`.
    fn target(rules: &str, url: &str) -> Target {
        try_target(rules, url).unwrap_or_else(|e| panic!("resolve_target: {e:#}"))
    }

    const HOST_AND_PROXY: &str = "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\n";

    /// With both a `host://` and a `proxy://` rule matched, whistle uses the
    /// host and drops the proxy (`_original/lib/rules/index.js:220-237`).
    #[test]
    fn host_outranks_proxy_by_default() {
        let t = target(HOST_AND_PROXY, "http://example.com/");
        assert_eq!(t.connect_host, "1.2.3.4");
        assert!(t.proxy.is_none(), "the proxy must lose to the host rule");
    }

    /// `xhost://` resolves to the same `host` operator as `host://`
    /// (`xhost: 'host'`, `_original/lib/rules/protocols.js:145`) — the only
    /// thing that tells them apart is the matcher as written, which is what
    /// carries the pass-through behaviour to the forwarding layer.
    #[test]
    fn only_the_x_spelling_of_host_falls_back() {
        let t = target("example.com xhost://10.0.0.9:8443\n", "http://example.com/");
        assert_eq!((t.connect_host.as_str(), t.connect_port), ("10.0.0.9", 8443));
        assert!(t.host_fallback_direct, "xhost:// is the pass-through spelling");

        let t = target("example.com host://10.0.0.9:8443\n", "http://example.com/");
        assert_eq!((t.connect_host.as_str(), t.connect_port), ("10.0.0.9", 8443));
        assert!(!t.host_fallback_direct, "host:// fails the request instead");

        // `hosts://` is the third spelling and is *not* the x one.
        let t = target("example.com hosts://10.0.0.9\n", "http://example.com/");
        assert!(!t.host_fallback_direct);
    }

    /// A proxy rule with no host rule to lose to is used as-is.
    #[test]
    fn proxy_alone_is_untouched() {
        let t = target("example.com proxy://127.0.0.1:8888\n", "http://example.com/");
        assert_eq!(t.proxy.expect("proxy").port, 8888);
    }

    /// `proxyFirst` and `proxyHost` (on either line) keep both, so the request
    /// goes through the proxy to the host address.
    #[test]
    fn proxy_first_and_proxy_host_keep_both() {
        for rules in [
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyFirst\n",
            "example.com host://1.2.3.4 lineProps://proxyFirst\nexample.com proxy://127.0.0.1:8888\n",
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyHost\n",
            "example.com host://1.2.3.4 lineProps://proxyHost\nexample.com proxy://127.0.0.1:8888\n",
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\nexample.com enable://proxyFirst\n",
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\nexample.com enable://proxyHost\n",
        ] {
            let t = target(rules, "http://example.com/");
            assert!(t.proxy.is_some(), "proxy should survive: {rules}");
            assert_eq!(t.connect_host, "1.2.3.4", "host override still applies");
        }
    }

    /// `?proxyHost` in the proxy's own URL says the same thing, and is not part
    /// of the proxy address.
    #[test]
    fn proxy_host_flag_in_the_proxy_url() {
        let t = target(
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888?proxyHost\n",
            "http://example.com/",
        );
        let p = t.proxy.expect("?proxyHost should keep the proxy");
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8888, "the query flag must not leak into the address");
    }

    /// `proxyHostOnly` keeps both when a host rule matched, and discards the
    /// proxy when none did.
    #[test]
    fn proxy_host_only_requires_a_host_rule() {
        let with_host = target(
            "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
            "http://example.com/",
        );
        assert!(with_host.proxy.is_some());
        assert_eq!(with_host.connect_host, "1.2.3.4");

        let without_host = target(
            "example.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
            "http://example.com/",
        );
        assert!(
            without_host.proxy.is_none(),
            "proxyHostOnly with no host rule drops the proxy"
        );
        assert_eq!(without_host.connect_host, "example.com");
    }

    // ── ignore://proxy, unusable proxies, scheme-converting proxies ──

    /// `ignore://proxy` names the whole upstream-proxy family, because whistle
    /// keeps one key for all of them (`resolveProxy`,
    /// `_original/lib/rules/rules.js:2419-2443`). Naming one spelling drops only
    /// that one. Every one of these used to traverse the hop regardless.
    #[test]
    fn ignore_proxy_drops_every_proxy_protocol() {
        for proto in crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS {
            let t = target(
                &format!("example.com {proto}://127.0.0.1:8888\nexample.com ignore://proxy\n"),
                "http://example.com/",
            );
            assert!(t.proxy.is_none(), "ignore://proxy must drop {proto}://");
        }

        // The x-spelling of the family says the same thing.
        let t = target(
            "example.com socks://127.0.0.1:1080\nexample.com ignore://xproxy\n",
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "ignore://xproxy must drop the family");

        // Naming one protocol leaves the others alone.
        let t = target(
            "example.com proxy://127.0.0.1:8888\nexample.com ignore://socks\n",
            "http://example.com/",
        );
        assert_eq!(
            t.proxy.expect("ignore://socks must not touch proxy://").port,
            8888
        );
        let t = target(
            "example.com socks://127.0.0.1:1080\nexample.com ignore://socks\n",
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "ignore://socks drops socks://");
    }

    /// An ignored proxy does not fall through to a `pac://` rule: whistle
    /// returns before it would consult PAC (`_original/lib/rules/index.js:238`).
    /// A `pac://` rule with no proxy rule to ignore is still honoured, and
    /// `ignore://pac` is what suppresses that one.
    #[test]
    fn ignoring_the_proxy_does_not_fall_through_to_pac() {
        // A rule token cannot contain whitespace, so a PAC script reaches a rule
        // as a path (or a URL) rather than inline.
        let fx = Fixtures::new("pac-ignore");
        let pac = fx.write(
            "corp.pac",
            b"function FindProxyForURL(u, h) { return 'PROXY 10.0.0.1:3128'; }",
        );

        let t = target(
            &format!("example.com proxy://127.0.0.1:8888\nexample.com pac://{pac}\nexample.com ignore://proxy\n"),
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "ignore://proxy must not fall back to PAC");

        let t = target(&format!("example.com pac://{pac}\n"), "http://example.com/");
        assert_eq!(t.proxy.expect("pac chooses the proxy").port, 3128);

        let t = target(
            &format!("example.com pac://{pac}\nexample.com ignore://pac\n"),
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "ignore://pac drops the PAC rule");
    }

    /// A proxy rule whose value is empty or unusable fails the request. It used
    /// to be skipped, which turned "route this through a proxy" into a direct
    /// connection with nothing said about it.
    #[test]
    fn an_unusable_proxy_value_fails_rather_than_going_direct() {
        for rules in [
            "example.com proxy://\n",
            "example.com proxy:// \n",
            "example.com socks://\n",
            "example.com http-proxy://@\n",
            "example.com proxy://?proxyHost\n",
        ] {
            let err = try_target(rules, "http://example.com/")
                .expect_err(&format!("{rules:?} must not resolve to a direct connection"));
            assert!(
                format!("{err:#}").contains("proxy address"),
                "{rules:?}: {err:#}"
            );
        }
    }

    /// A PAC file that answers with something we cannot use is an error too;
    /// only `DIRECT` means "no proxy".
    #[test]
    fn a_pac_result_we_cannot_use_is_not_a_direct_connection() {
        assert!(parse_pac_result("DIRECT").expect("DIRECT parses").is_none());
        assert!(parse_pac_result("PROXY 1.2.3.4:8080; DIRECT").expect("parses").is_some());
        // Unknown entry, then DIRECT: the DIRECT still wins.
        assert!(parse_pac_result("SOCKS4 1.2.3.4:1080; DIRECT").expect("parses").is_none());
        // …but on its own, an entry we cannot honour is not a direct connection.
        assert!(parse_pac_result("SOCKS4 1.2.3.4:1080").is_err());
        assert!(parse_pac_result("PROXY").is_err());
        assert!(parse_pac_result("").is_err());
    }

    /// `http2https-proxy://` upgrades an http origin to TLS
    /// (`_original/lib/inspectors/res.js:236-237`), and the `internal-*` /
    /// `https2http-proxy://` family strips an https origin's TLS for the hop
    /// and marks the request instead (`res.js:229-234`). Neither conversion
    /// happened before: the scheme travelled unchanged, so `http2https-proxy`
    /// left in cleartext what the rule promised to encrypt.
    #[test]
    fn scheme_converting_proxies_change_the_origin_connection() {
        let t = target(
            "example.com http2https-proxy://127.0.0.1:8888\n",
            "http://example.com/",
        );
        assert!(t.tls, "http2https-proxy must reach the origin over TLS");
        assert!(!t.origin_tls_stripped);

        // …and an origin that is already https stays https.
        let t = target(
            "example.com http2https-proxy://127.0.0.1:8888\n",
            "https://example.com/",
        );
        assert!(t.tls);

        for proto in [
            "https2http-proxy",
            "internal-proxy",
            "internal-http-proxy",
            "internal-https-proxy",
        ] {
            let t = target(
                &format!("example.com {proto}://127.0.0.1:8888\n"),
                "https://example.com/",
            );
            assert!(!t.tls, "{proto} hands the origin request over in plaintext");
            assert!(t.origin_tls_stripped, "{proto} must mark the stripped TLS");

            // An http origin has no TLS to strip, so nothing is marked.
            let t = target(
                &format!("example.com {proto}://127.0.0.1:8888\n"),
                "http://example.com/",
            );
            assert!(!t.tls);
            assert!(!t.origin_tls_stripped);
        }

        // A plain proxy converts nothing.
        let t = target("example.com proxy://127.0.0.1:8888\n", "https://example.com/");
        assert!(t.tls);
        assert!(!t.origin_tls_stripped);

        // The conversion belongs to the proxy, so a proxy that lost to a
        // `host://` rule cannot convert anything on its way out.
        let t = target(
            "example.com http2https-proxy://127.0.0.1:8888\nexample.com host://10.0.0.9\n",
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "host:// wins by default");
        assert!(!t.tls, "no proxy survived, so no scheme upgrade");
        let t = target(
            "example.com https2http-proxy://127.0.0.1:8888\nexample.com host://10.0.0.9\n",
            "https://example.com/",
        );
        assert!(t.proxy.is_none());
        assert!(t.tls, "…and none to strip either");
        assert!(!t.origin_tls_stripped);
    }

    /// Every protocol in the family list is one `find_proxy` actually reads,
    /// with the transport its name implies. The list lives in the rules layer
    /// (it is what `ignore://proxy` means); this is the check that the two
    /// halves cannot drift apart.
    #[test]
    fn every_family_protocol_resolves_with_its_transport() {
        for proto in crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS {
            let t = target(
                &format!("example.com {proto}://127.0.0.1:8888\n"),
                "http://example.com/",
            );
            let p = t.proxy.unwrap_or_else(|| panic!("{proto}:// must resolve"));
            assert_eq!(p.kind, proxy_kind(proto), "transport for {proto}");
            assert_eq!(p.port, 8888);
        }
    }

    // ── weakRule ──

    /// `weakRule` on a local-file line makes it yield to a matching proxy or
    /// host rule (`filterWeakRule`, `_original/lib/util/index.js:3733`).
    #[test]
    fn weak_rule_yields_to_proxy_or_host() {
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        for rules in [
            "a.com file:///no/such/file lineProps://weakRule\na.com proxy://127.0.0.1:8888\n",
            "a.com file:///no/such/file lineProps://weakRule\na.com host://1.2.3.4\n",
            "a.com file:///no/such/file\na.com host://1.2.3.4\na.com enable://weakRule\n",
        ] {
            let r = resolve(rules, "http://a.com/");
            assert!(
                short_circuit(&info, &r, test_env()).is_none(),
                "the file rule should step aside: {rules}"
            );
        }
    }

    /// Without something to yield *to*, the file rule still answers — including
    /// when the only proxy rule is `proxyHostOnly` with no host rule to apply.
    #[test]
    fn weak_rule_keeps_the_file_when_nothing_outranks_it() {
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        for rules in [
            "a.com file:///no/such/file lineProps://weakRule\n",
            "a.com file:///no/such/file lineProps://weakRule\na.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
            // No weakRule: the file rule wins over the proxy as usual.
            "a.com file:///no/such/file\na.com proxy://127.0.0.1:8888\n",
        ] {
            let r = resolve(rules, "http://a.com/");
            assert!(
                short_circuit(&info, &r, test_env()).is_some(),
                "the file rule should answer: {rules}"
            );
        }
    }

    // ── safeHtml / strictHtml injection gating ──

    /// Body after applying the response operators of `rules` to `body`, served
    /// as `content_type`.
    fn inject(rules: &str, body: &'static str, content_type: &str) -> String {
        let resolved = resolve(rules, "http://example.com/x");
        let out = transform_res_body(
            Bytes::from_static(body.as_bytes()),
            &resolved,
            Some(content_type),
        );
        String::from_utf8(out.to_vec()).unwrap()
    }

    const HTML: &str = "text/html; charset=utf-8";

    /// Markup accepts injection whatever the line says — the decision is made
    /// from the body's first non-whitespace byte.
    #[test]
    fn injection_into_markup_always_allowed() {
        for props in ["", " lineProps://safeHtml", " lineProps://strictHtml"] {
            let rules = format!("example.com/x htmlAppend://<!--tail-->{props}\n");
            assert_eq!(
                inject(&rules, "<html></html>", HTML),
                "<html></html><!--tail-->",
                "markup should accept injection with{props:?}"
            );
        }
    }

    /// `safeHtml` refuses a JSON-looking body; `strictHtml` refuses anything
    /// that is not markup (`_original/lib/util/whistle-transform.js:66-89`).
    #[test]
    fn safe_and_strict_html_refuse_non_markup() {
        let json = "{\"a\":1}";
        assert_eq!(
            inject("example.com/x htmlAppend://<!--t-->\n", json, HTML),
            "{\"a\":1}<!--t-->",
            "an unguarded line still injects into JSON"
        );
        assert_eq!(
            inject("example.com/x htmlAppend://<!--t--> lineProps://safeHtml\n", json, HTML),
            json
        );
        assert_eq!(
            inject("example.com/x htmlAppend://<!--t--> lineProps://strictHtml\n", json, HTML),
            json
        );
        // Bare text is "safe" but not markup: only strictHtml refuses it.
        assert_eq!(
            inject("example.com/x htmlAppend://<!--t--> lineProps://safeHtml\n", "hello", HTML),
            "hello<!--t-->"
        );
        assert_eq!(
            inject("example.com/x htmlAppend://<!--t--> lineProps://strictHtml\n", "hello", HTML),
            "hello"
        );
    }

    /// The gate is per line: a guarded line is dropped while an unguarded one
    /// on the same request still injects.
    #[test]
    fn gating_is_per_line() {
        let out = inject(
            "example.com/x htmlAppend://<!--guarded--> lineProps://safeHtml\n\
             example.com/x htmlPrepend://<!--free--> disable://doctype\n",
            "{\"a\":1}",
            HTML,
        );
        assert_eq!(out, "<!--free-->{\"a\":1}");
    }

    /// Non-HTML responses are not gated at all: upstream's `allowInject`
    /// returns before it ever looks at the properties.
    #[test]
    fn gating_only_applies_to_html_responses() {
        let out = inject(
            "example.com/x resAppend:///*t*/ lineProps://strictHtml\n",
            "{\"a\":1}",
            "application/json",
        );
        assert_eq!(out, "{\"a\":1}/*t*/");
    }

    /// The generic body operators are gated too — upstream filters
    /// `resBody`/`resPrepend`/`resAppend` through the same list.
    #[test]
    fn generic_body_operators_are_gated() {
        assert_eq!(
            inject(
                "example.com/x resPrepend://<!--p--> lineProps://strictHtml\n",
                "plain text",
                HTML
            ),
            "plain text"
        );
        assert_eq!(
            inject(
                "example.com/x resBody://replaced lineProps://safeHtml\n",
                "[1,2]",
                HTML
            ),
            "[1,2]",
            "safeHtml must keep a JSON body rather than replace it"
        );
    }

    /// `enable://strictHtml` applies the strict gate to every line of the
    /// request (`_original/lib/inspectors/res.js:970-987`).
    #[test]
    fn enable_strict_html_gates_every_line() {
        let out = inject(
            "example.com/x htmlAppend://<!--t-->\nexample.com/x enable://strictHtml\n",
            "hello",
            HTML,
        );
        assert_eq!(out, "hello");
    }

    // ── typed body operators (html/js/css) ──

    /// `jsXxx`/`cssXxx` reach an **HTML** response too, not just a JS or CSS
    /// one: `isJs = isHtml || resType === 'JS'`
    /// (`_original/lib/inspectors/res.js:952-954`). Raw JavaScript cannot go
    /// into markup as-is, so it arrives wrapped.
    #[test]
    fn js_and_css_operators_reach_html_responses() {
        let out = inject(
            "example.com/x jsAppend://alert(1) disable://doctype\n",
            "<p>hi</p>",
            HTML,
        );
        assert_eq!(out, "<p>hi</p><script>alert(1)</script>");

        let out = inject(
            "example.com/x cssPrepend://body{color:red} disable://doctype\n",
            "<p>hi</p>",
            HTML,
        );
        assert_eq!(out, "<style>body{color:red}</style><p>hi</p>");
    }

    /// A bare URL is linked rather than inlined (`GEN_URL_RE` → `wrapJs`/`wrapCss`).
    #[test]
    fn a_url_value_becomes_a_script_or_link_tag() {
        let out = inject(
            "example.com/x jsAppend://https://cdn.test/a.js disable://doctype\n",
            "<p>hi</p>",
            HTML,
        );
        assert_eq!(out, "<p>hi</p><script src=\"https://cdn.test/a.js\"></script>");

        let out = inject(
            "example.com/x cssAppend:////cdn.test/a.css disable://doctype\n",
            "<p>hi</p>",
            HTML,
        );
        assert_eq!(
            out,
            "<p>hi</p><link rel=\"stylesheet\" href=\"//cdn.test/a.css\" />"
        );
        // Not a URL: an inline script that merely starts with a comment.
        assert!(!GEN_URL_RE.is_match("// just a comment"));
    }

    /// Line properties become `<script>` attributes (`getScriptProps`).
    #[test]
    fn line_props_become_script_attributes() {
        let out = inject(
            "example.com/x jsAppend://https://cdn.test/a.js lineProps://defer|module|anonymous disable://doctype\n",
            "<p>hi</p>",
            HTML,
        );
        assert_eq!(
            out,
            "<p>hi</p><script crossorigin=\"anonymous\" defer type=\"module\" src=\"https://cdn.test/a.js\"></script>"
        );
        assert_eq!(script_props(&LineProps::default()), "");
        // The crossorigin spellings are exclusive, most specific first.
        let props = LineProps::from_actions(["useCredentials", "anonymous", "crossorigin"]);
        assert_eq!(script_props(&props), " crossorigin=\"use-credentials\"");
    }

    /// On a JS or CSS response the value goes in raw — there is no markup to
    /// wrap it into — and the generic `res*` operator comes first, CRLF-joined.
    #[test]
    fn typed_operators_are_unwrapped_outside_html() {
        let out = inject(
            "example.com/x jsAppend://alert(1)\nexample.com/x resAppend:///*tail*/\n",
            "var a;",
            "application/javascript",
        );
        assert_eq!(out, "var a;/*tail*/\r\nalert(1)");
        // A CSS response ignores the JS family entirely.
        let out = inject(
            "example.com/x jsAppend://alert(1)\nexample.com/x cssAppend://a{}\n",
            "b{}",
            "text/css",
        );
        assert_eq!(out, "b{}a{}");
    }

    /// Every slot orders its contributors `res*` → `css*` → `html*` → `js*`
    /// (`_original/lib/inspectors/res.js:1063-1072`), joined with CRLF.
    #[test]
    fn html_slots_keep_the_upstream_family_order() {
        let out = inject(
            "example.com/x resAppend://R\nexample.com/x cssAppend://C\n\
             example.com/x htmlAppend://H\nexample.com/x jsAppend://J\n\
             example.com/x disable://doctype\n",
            "<p></p>",
            HTML,
        );
        assert_eq!(
            out,
            "<p></p>R\r\n<style>C</style>\r\nH\r\n<script>J</script>"
        );
    }

    /// A `*Body` operator replaces the body while `top`/`bottom` still wrap it.
    #[test]
    fn body_operators_replace_and_stay_wrapped() {
        let out = inject(
            "example.com/x htmlBody://<b>new</b>\nexample.com/x resPrepend://<!--t-->\n\
             example.com/x resAppend://<!--b-->\nexample.com/x disable://doctype\n",
            "<p>old</p>",
            HTML,
        );
        assert_eq!(out, "<!--t--><b>new</b><!--b-->");
        // A blank `resBody` empties the body (`resBody || util.EMPTY_BUFFER`).
        assert_eq!(inject("example.com/x resBody://\n", "keep?", "text/plain"), "");
    }

    /// whistle stamps a doctype in front of any `top` it injects into an HTML
    /// response (`_original/lib/util/whistle-transform.js:116-118`), and
    /// `disable://doctype` is the only way out.
    #[test]
    fn html_prepends_carry_a_doctype() {
        assert_eq!(
            inject("example.com/x resPrepend://<!--t-->\n", "<p></p>", HTML),
            "<!DOCTYPE html>\r\n<!--t--><p></p>"
        );
        assert_eq!(
            inject(
                "example.com/x resPrepend://<!--t--> disable://doctype\n",
                "<p></p>",
                HTML
            ),
            "<!--t--><p></p>"
        );
        // `enable://` wins over `disable://` for the same flag (`isDisable`).
        assert_eq!(
            inject(
                "example.com/x resPrepend://<!--t--> disable://doctype enable://doctype\n",
                "<p></p>",
                HTML
            ),
            "<!DOCTYPE html>\r\n<!--t--><p></p>"
        );
        // Only HTML, and only when something is actually prepended.
        assert_eq!(
            inject("example.com/x resAppend://<!--t-->\n", "<p></p>", HTML),
            "<p></p><!--t-->"
        );
        assert_eq!(
            inject("example.com/x resPrepend://x\n", "y", "text/plain"),
            "xy"
        );
    }

    // ── multi-match body operators ──
    //
    // Every operator below is in upstream's `multiMatchs`
    // (`_original/lib/rules/protocols.js:186-226`), so several lines of the same
    // one all take effect. How they combine differs per family, and each test
    // names the mechanism it covers.

    /// The injecting operators CRLF-join their lines in resolution order
    /// (`joinData`, `_original/lib/util/file-mgr.js:93-109`).
    #[test]
    fn several_injection_lines_are_crlf_joined() {
        assert_eq!(
            inject(
                "example.com/x resAppend://one\nexample.com/x resAppend://two\n",
                "body",
                "text/plain",
            ),
            "bodyone\r\ntwo"
        );
        assert_eq!(
            inject(
                "example.com/x resPrepend://one\nexample.com/x resPrepend://two\n\
                 example.com/x disable://doctype\n",
                "body",
                "text/plain",
            ),
            "one\r\ntwobody"
        );
        // `*Body` replaces once, with the join of every line.
        assert_eq!(
            inject(
                "example.com/x resBody://one\nexample.com/x resBody://two\n",
                "gone",
                "text/plain",
            ),
            "one\r\ntwo"
        );
    }

    /// Each line of a typed family is wrapped on its own before the join, so two
    /// `jsAppend://` lines are two `<script>` tags rather than one holding both
    /// (`readRuleList` wraps per list entry, `_original/lib/util/index.js:955-966`).
    #[test]
    fn several_typed_lines_are_wrapped_separately() {
        assert_eq!(
            inject(
                "example.com/x jsAppend://a()\nexample.com/x jsAppend://b()\n",
                "<p></p>",
                HTML,
            ),
            "<p></p><script>a()</script>\r\n<script>b()</script>"
        );
        // …and each keeps the attributes of *its own* line.
        assert_eq!(
            inject(
                "example.com/x jsAppend://https://a.test/a.js lineProps://defer\n\
                 example.com/x jsAppend://https://b.test/b.js lineProps://module\n",
                "<p></p>",
                HTML,
            ),
            "<p></p><script defer src=\"https://a.test/a.js\"></script>\r\n\
             <script type=\"module\" src=\"https://b.test/b.js\"></script>"
        );
    }

    /// Accumulation follows the matcher's order, so an `important` line leads
    /// even when it is written last.
    #[test]
    fn important_lines_lead_the_accumulation() {
        assert_eq!(
            inject(
                "example.com/x resAppend://normal\n$example.com/x resAppend://important\n",
                "body",
                "text/plain",
            ),
            "bodyimportant\r\nnormal"
        );
        // The same order decides who wins a contested `*Replace` pattern.
        let out = transform_res_body(
            Bytes::from_static(b"x"),
            &resolve(
                "example.com/x resReplace://x=normal\n$example.com/x resReplace://x=important\n",
                "http://example.com/x",
            ),
            Some("text/plain"),
        );
        assert_eq!(out, Bytes::from_static(b"important"));
    }

    /// `*Replace` lines collapse into one pattern map rather than running as
    /// separate passes: every pattern applies, and a pattern written twice takes
    /// the first line's replacement (`readRuleList`'s JSON branch reverses the
    /// list and `extend`s it, `_original/lib/util/index.js:1300-1312`).
    #[test]
    fn several_replace_lines_merge_into_one_map() {
        let replace = |rules: &str, body: &'static str| {
            String::from_utf8(
                transform_res_body(
                    Bytes::from_static(body.as_bytes()),
                    &resolve(rules, "http://example.com/x"),
                    Some("text/plain"),
                )
                .to_vec(),
            )
            .unwrap()
        };
        assert_eq!(
            replace(
                "example.com/x resReplace://a=1\nexample.com/x resReplace://b=2\n",
                "a b",
            ),
            "1 2"
        );
        // Contested pattern: the higher-priority line's replacement wins.
        assert_eq!(
            replace(
                "example.com/x resReplace://a=first\nexample.com/x resReplace://a=second\n",
                "a",
            ),
            "first"
        );
        // Substitutions still chain, and the *last* line's patterns run first —
        // upstream's merged key order. Here `x`→`y` (line two) runs before
        // `y`→`z` (line one), so the body ends up fully rewritten.
        assert_eq!(
            replace(
                "example.com/x resReplace://y=z\nexample.com/x resReplace://x=y\n",
                "x",
            ),
            "z"
        );
    }

    /// `resMerge` lines collapse into one patch the same way — first line wins a
    /// contested key — and the fold is shallow unless a `resMerge://true` marker
    /// line turns on `extend`'s deep flag (`isDeep`,
    /// `_original/lib/util/index.js:1206-1212`).
    #[test]
    fn several_merge_lines_collapse_into_one_patch() {
        let merge = |rules: &str| {
            String::from_utf8(
                transform_res_body(
                    Bytes::from_static(b"{\"keep\":0}"),
                    &resolve(rules, "http://example.com/x"),
                    Some("application/json"),
                )
                .to_vec(),
            )
            .unwrap()
        };
        // Disjoint keys from both lines land, and the body's own key survives.
        assert_eq!(
            merge("example.com/x resMerge://{\"a\":1}\nexample.com/x resMerge://{\"b\":2}\n"),
            "{\"a\":1,\"b\":2,\"keep\":0}"
        );
        // Contested key: the first line wins.
        assert_eq!(
            merge("example.com/x resMerge://{\"a\":1}\nexample.com/x resMerge://{\"a\":2}\n"),
            "{\"a\":1,\"keep\":0}"
        );
        // Shallow by default, so the second line's nested object is replaced
        // wholesale rather than merged into.
        assert_eq!(
            merge(
                "example.com/x resMerge://{\"n\":{\"a\":1}}\n\
                 example.com/x resMerge://{\"n\":{\"b\":2}}\n"
            ),
            "{\"keep\":0,\"n\":{\"a\":1}}"
        );
        // …unless a marker line asks for a deep fold. It contributes no data.
        assert_eq!(
            merge(
                "example.com/x resMerge://{\"n\":{\"a\":1}}\n\
                 example.com/x resMerge://{\"n\":{\"b\":2}}\n\
                 example.com/x resMerge://true\n"
            ),
            "{\"keep\":0,\"n\":{\"a\":1,\"b\":2}}"
        );
    }

    /// `urlReplace` merges its lines into one map like the body `*Replace`
    /// operators, then `parsePathReplace` walks it
    /// (`_original/lib/util/index.js:1014-1022`).
    #[test]
    fn several_url_replace_lines_rewrite_one_path() {
        let resolved = resolve(
            "example.com/api urlReplace://v1=v2\nexample.com/api urlReplace://old=new\n",
            "http://example.com/api/v1/old",
        );
        assert_eq!(rewrite_path("/api/v1/old", &resolved, body_ctx(None)), "/api/v2/new");
    }

    /// The request side accumulates through the same code path.
    #[test]
    fn several_request_body_lines_accumulate() {
        let resolved = resolve(
            "example.com reqPrepend://p1\nexample.com reqPrepend://p2\n\
             example.com reqAppend://a1\nexample.com reqAppend://a2\n",
            "http://example.com/",
        );
        let out = transform_req_body(Bytes::from_static(b"BODY"), &resolved, body_ctx(Some("text/plain")));
        assert_eq!(out, Bytes::from_static(b"p1\r\np2BODYa1\r\na2"));
    }

    /// A blank line inside an accumulating operator is dropped before the join —
    /// it must not leave a stray separator behind — while a `*Body` that is blank
    /// on *every* line still empties the body.
    #[test]
    fn blank_lines_drop_out_of_the_join() {
        assert_eq!(
            inject(
                "example.com/x resAppend://one\nexample.com/x resAppend://\n",
                "body",
                "text/plain",
            ),
            "bodyone"
        );
        assert_eq!(
            inject(
                "example.com/x resBody://\nexample.com/x resBody://kept\n",
                "gone",
                "text/plain",
            ),
            "kept"
        );
        assert_eq!(
            inject(
                "example.com/x resBody://\nexample.com/x resBody://\n",
                "gone",
                "text/plain",
            ),
            ""
        );
    }

    /// The injection gate is per line, so one refused line does not take the
    /// others down with it (`filterHtml` walks the buffer list,
    /// `_original/lib/util/whistle-transform.js:47-60`). The refused line is
    /// written first here, where a first-match-wins resolution would have let it
    /// silence the whole operator.
    #[test]
    fn the_gate_refuses_accumulated_lines_one_by_one() {
        assert_eq!(
            inject(
                "example.com/x htmlAppend://<!--refused--> lineProps://strictHtml\n\
                 example.com/x htmlAppend://<!--kept-->\n",
                "{\"json\":1}",
                HTML,
            ),
            "{\"json\":1}<!--kept-->"
        );
        // A `resBody` whose every line the gate refuses leaves the body alone,
        // where a blank one would have emptied it (`filterHtml` reduces the list
        // to the falsy `''`, `whistle-transform.js:110`).
        assert_eq!(
            inject(
                "example.com/x resBody://gone lineProps://strictHtml\n",
                "{\"json\":1}",
                HTML,
            ),
            "{\"json\":1}"
        );
        // A request-wide `enable://strictHtml` shuts the injection off wholesale
        // (`allowInject` returns false), so even a blank `resBody` — which would
        // otherwise empty the body — does nothing.
        assert_eq!(
            inject(
                "example.com/x resBody:// enable://strictHtml\n",
                "{\"json\":1}",
                HTML,
            ),
            "{\"json\":1}"
        );
        // Without it, the blank line empties the body as usual.
        assert_eq!(
            inject("example.com/x resBody://\n", "{\"json\":1}", HTML),
            ""
        );
    }

    /// The content classes, in upstream's test order.
    #[test]
    fn content_classes_match_upstream() {
        assert_eq!(res_class("text/html; charset=utf-8"), Some(ResClass::Html));
        assert_eq!(res_class("application/javascript"), Some(ResClass::Js));
        assert_eq!(res_class("text/css"), Some(ResClass::Css));
        assert_eq!(res_class("application/json"), Some(ResClass::Json));
        assert_eq!(res_class("image/png"), Some(ResClass::Img));
        assert_eq!(res_class("text/plain"), Some(ResClass::Text));
        assert_eq!(res_class("application/octet-stream"), None);
        assert_eq!(res_class(""), None);
        // Parameters are stripped before the substring tests, so a filename in
        // the type cannot promote an opaque body to HTML.
        assert_eq!(res_class("application/octet-stream; name=a.html"), None);
        // `application/ecmascript` is not `javascript` to whistle.
        assert_eq!(res_class("application/ecmascript"), None);
    }

    /// Header operators take a `&`-separated list of pairs, like the other
    /// JSON-shaped operators; `enable`/`disable` split on `|` and `&` only.
    #[test]
    fn header_and_flag_value_lists() {
        let resolved = resolve(
            "example.com resHeaders://x-a=1&x-b=2\nexample.com enable://p|q&r\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        assert_eq!(h.get("x-a").unwrap(), "1");
        assert_eq!(h.get("x-b").unwrap(), "2");

        let flags = enabled_flags(&resolved);
        assert!(flags.contains("p") && flags.contains("q") && flags.contains("r"));
        // A comma is not a separator upstream, so it stays part of the name.
        let commas = resolve("example.com enable://p,q\n", "http://example.com/");
        assert!(enabled_flags(&commas).contains("p,q"));
    }

    /// Request parts for the operator tests below.
    fn req_parts(headers: &[(&str, &str)]) -> request::Parts {
        let mut builder = hyper::Request::builder().uri("http://example.com/");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(()).unwrap().into_parts().0
    }

    /// Two lines naming the **same** header: the first one wins.
    ///
    /// This is the `parseRuleJson` fold (`_original/lib/util/index.js:1305-1316`),
    /// not a top-to-bottom apply — upstream reverses the list and `extend`s it,
    /// so the highest-priority line's value survives, consistent with
    /// first-match-wins everywhere else. Lines naming *different* headers all
    /// contribute.
    #[test]
    fn contested_header_takes_the_first_line() {
        let resolved = resolve(
            "example.com resHeaders://x-a=first&x-only-1=1\n\
             example.com resHeaders://x-a=second&x-only-2=2\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        assert_eq!(h.get("x-a").unwrap(), "first");
        assert_eq!(h.get("x-only-1").unwrap(), "1");
        assert_eq!(h.get("x-only-2").unwrap(), "2");

        // `important` reorders the lines, and the fold follows the resolution
        // order rather than the source order.
        let important = resolve(
            "example.com resHeaders://x-a=plain\n\
             example.com resHeaders://x-a=important lineProps://important\n",
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &important, "resHeaders");
        assert_eq!(h.get("x-a").unwrap(), "important");
    }

    /// The same fold reaches `reqHeaders`, `trailers`, and both cookie
    /// operators — every protocol upstream hands to `parseRuleJson`
    /// (`_original/lib/inspectors/req.js:459-468`, `res.js:845-855`).
    #[test]
    fn contested_key_takes_the_first_line_everywhere() {
        let resolved = resolve(
            "example.com reqHeaders://x-a=first  reqCookies://sid=first  trailers://x-t=first\n\
             example.com reqHeaders://x-a=second reqCookies://sid=second trailers://x-t=second\n",
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &resolved);
        assert_eq!(parts.headers.get("x-a").unwrap(), "first");
        assert_eq!(parts.headers.get("cookie").unwrap(), "sid=first");
        assert_eq!(build_trailers(&resolved).get("x-t").unwrap(), "first");

        let res = resolve(
            "example.com resCookies://sid=first\nexample.com resCookies://sid=second\n",
            "http://example.com/",
        );
        let mut parts = res_parts(&[]);
        apply_response(&mut parts, &res);
        assert_eq!(parts.headers.get("set-cookie").unwrap(), "sid=first");
    }

    /// `resCors` folds too: the first line's `origin` wins, and a key only a
    /// later line mentions still lands.
    #[test]
    fn contested_cors_key_takes_the_first_line() {
        let resolved = resolve(
            "example.com resCors://{\"origin\":\"http://a.test\"}\n\
             example.com resCors://origin=http://b.test&methods=GET\n",
            "http://example.com/",
        );
        let mut parts = res_parts(&[]);
        apply_response(&mut parts, &resolved);
        assert_eq!(
            parts.headers.get("access-control-allow-origin").unwrap(),
            "http://a.test"
        );
        assert_eq!(
            parts.headers.get("access-control-allow-methods").unwrap(),
            "GET"
        );
    }

    /// `reqCors` is `setReqCors` (`_original/lib/util/index.js:2899-2921`): a
    /// URL origin is reduced to its origin, `*` passes through, and `method` /
    /// `headers` become the preflight request headers. `enable` sets nothing —
    /// there is no origin to echo on the request side.
    #[test]
    fn req_cors_sets_origin_and_preflight_headers() {
        let resolved = resolve(
            "example.com reqCors://http://a.test/page?q=1\n",
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &resolved);
        assert_eq!(parts.headers.get("origin").unwrap(), "http://a.test");

        let star = resolve(
            "example.com reqCors://* reqCors://method=PUT&headers=x-a\n",
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &star);
        assert_eq!(parts.headers.get("origin").unwrap(), "*");
        assert_eq!(
            parts.headers.get("access-control-request-method").unwrap(),
            "PUT"
        );
        assert_eq!(
            parts.headers.get("access-control-request-headers").unwrap(),
            "x-a"
        );

        // `enable` is the response-side spelling; on a request it is inert.
        let enable = resolve("example.com reqCors://enable\n", "http://example.com/");
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &enable);
        assert!(parts.headers.get("origin").is_none());
    }

    // ── response header operators ──

    /// Response parts carrying `headers`, for the operator tests below.
    fn res_parts(headers: &[(&str, &str)]) -> response::Parts {
        let mut builder = Response::builder().status(200);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(()).unwrap().into_parts().0
    }

    /// Header value after applying `rules` to a response carrying `headers`.
    fn res_header(rules: &str, headers: &[(&str, &str)], name: &str) -> Option<String> {
        let resolved = resolve(rules, "http://example.com/x");
        let mut parts = res_parts(headers);
        apply_response(&mut parts, &resolved);
        parts
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// `cache://` accepts a leading integer or one of three no-cache spellings,
    /// and writes `Expires`/`Pragma` alongside `Cache-Control`. Anything else —
    /// `cache://off`, say — is ignored rather than passed through.
    #[test]
    fn cache_operator_spellings() {
        let cc = |v: &str| res_header(&format!("example.com cache://{v}\n"), &[], "cache-control");
        assert_eq!(cc("600"), Some("max-age=600".to_string()));
        assert_eq!(cc("60s"), Some("max-age=60".to_string()), "parseInt semantics");
        assert_eq!(cc("-1"), Some("no-cache".to_string()));
        assert_eq!(cc("no"), Some("no-cache".to_string()));
        assert_eq!(cc("No-Cache"), Some("no-cache".to_string()));
        assert_eq!(cc("no-store"), Some("no-store".to_string()));
        assert_eq!(cc("off"), None, "not a spelling whistle recognises");
        assert_eq!(cc("keep"), None);
        assert_eq!(cc("reserve"), None);
        // `keep`/`reserve` leave the upstream header where it was.
        assert_eq!(
            res_header(
                "example.com cache://keep\n",
                &[("cache-control", "max-age=5")],
                "cache-control"
            ),
            Some("max-age=5".to_string())
        );
        let resolved = resolve("example.com cache://no\n", "http://example.com/x");
        let mut parts = res_parts(&[]);
        apply_response(&mut parts, &resolved);
        assert_eq!(parts.headers.get("pragma").unwrap(), "no-cache");
        assert!(
            parts
                .headers
                .get("expires")
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(" GMT")
        );
    }

    /// Injecting into a body costs the response its CSP and its cacheability
    /// (`_original/lib/inspectors/res.js:1093-1101`).
    #[test]
    fn injection_strips_csp_and_caching() {
        let html = [
            ("content-type", "text/html"),
            ("content-security-policy", "default-src 'self'"),
            ("cache-control", "max-age=600"),
        ];
        assert_eq!(
            res_header(
                "example.com jsAppend://alert(1)\n",
                &html,
                "content-security-policy"
            ),
            None,
            "an injected script must not be blocked by the page's own CSP"
        );
        assert_eq!(
            res_header("example.com jsAppend://alert(1)\n", &html, "cache-control"),
            Some("no-store".to_string())
        );
        // `enable://keepCSP` and `enable://keepCache` opt out of each.
        assert!(
            res_header(
                "example.com jsAppend://alert(1) enable://keepCSP|keepCache\n",
                &html,
                "content-security-policy"
            )
            .is_some()
        );
        assert_eq!(
            res_header(
                "example.com jsAppend://alert(1) enable://keepCache\n",
                &html,
                "cache-control"
            ),
            Some("max-age=600".to_string())
        );
        // An explicit `cache://` is the author's decision and survives.
        assert_eq!(
            res_header(
                "example.com jsAppend://alert(1) cache://60\n",
                &html,
                "cache-control"
            ),
            Some("max-age=60".to_string())
        );
        // No injecting operator for *this* content type: nothing is stripped.
        assert!(
            res_header(
                "example.com cssAppend://a{}\n",
                &[
                    ("content-type", "application/javascript"),
                    ("content-security-policy", "default-src 'self'")
                ],
                "content-security-policy"
            )
            .is_some()
        );
    }

    /// `attachment://` always names the file; with no value whistle falls back
    /// to the request URL's last segment (`getFilename`).
    #[test]
    fn attachment_names_the_download() {
        assert_eq!(
            res_header("example.com attachment://报告.pdf\n", &[], "content-disposition"),
            Some("attachment; filename=\"%E6%8A%A5%E5%91%8A.pdf\"".to_string()),
            "a header value cannot carry non-Latin-1 bytes"
        );
        assert_eq!(encode_non_latin1("a b.pdf"), "a%20b.pdf");
        let resolved = resolve("example.com attachment://\n", "http://example.com/d/report.csv");
        let info = build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/d/report.csv",
            &HeaderMap::new(),
            None,
        );
        let mut parts = res_parts(&[]);
        apply_response_for(&mut parts, &resolved, Some(&info));
        assert_eq!(
            parts.headers.get("content-disposition").unwrap(),
            "attachment; filename=\"report.csv\""
        );
        assert_eq!(url_filename("http://a.com/x/y.pdf?q=1"), "y.pdf");
        assert_eq!(url_filename("http://a.com/"), "index.html");
        assert_eq!(url_filename("http://a.com"), "index.html");
    }

    /// `replaceStatus://401` also advertises the challenge whistle sends with it.
    #[test]
    fn replace_status_advertises_authentication() {
        assert_eq!(
            res_header("example.com replaceStatus://401\n", &[], "www-authenticate"),
            Some("Basic realm=User Login".to_string())
        );
        assert_eq!(
            res_header("example.com replaceStatus://407\n", &[], "proxy-authenticate"),
            Some("Basic realm=User Login".to_string())
        );
    }

    /// `resCors` negotiates rather than blanket-allowing: an explicit origin or
    /// `enable` implies credentials, `*` does not, and a preflight fills the
    /// requested methods/headers in from the request.
    #[test]
    fn res_cors_negotiates() {
        let cors = |rule: &str, method: &str, req_headers: &[(&str, &str)], name: &str| {
            let resolved = resolve(
                &format!("example.com resCors://{rule}\n"),
                "http://example.com/x",
            );
            let mut hm = HeaderMap::new();
            for (k, v) in req_headers {
                hm.insert(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            let info = build_req_info(method, "http", "example.com", 80, "/x", &hm, None);
            let mut parts = res_parts(&[]);
            apply_response_for(&mut parts, &resolved, Some(&info));
            parts.headers.get(name).map(|v| v.to_str().unwrap().to_string())
        };

        // `*` allows any origin but never credentials.
        assert_eq!(
            cors("*", "GET", &[], "access-control-allow-origin"),
            Some("*".to_string())
        );
        assert_eq!(cors("*", "GET", &[], "access-control-allow-credentials"), None);

        // `enable` echoes the caller's origin, with credentials.
        let origin = [("origin", "https://app.test")];
        assert_eq!(
            cors("enable", "GET", &origin, "access-control-allow-origin"),
            Some("https://app.test".to_string())
        );
        assert_eq!(
            cors("enable", "GET", &origin, "access-control-allow-credentials"),
            Some("true".to_string())
        );
        // …and does nothing at all when the request carries no origin.
        assert_eq!(cors("enable", "GET", &[], "access-control-allow-origin"), None);

        // An explicit URL is trimmed to its origin.
        assert_eq!(
            cors(
                "https://app.test/some/path",
                "GET",
                &[],
                "access-control-allow-origin"
            ),
            Some("https://app.test".to_string())
        );

        // The JSON form spells the rest out; `headers` is *expose* off-preflight.
        let json = r#"{"methods":"GET,POST","headers":"x-a","maxAge":600}"#;
        assert_eq!(
            cors(json, "GET", &[], "access-control-allow-methods"),
            Some("GET,POST".to_string())
        );
        assert_eq!(
            cors(json, "GET", &[], "access-control-expose-headers"),
            Some("x-a".to_string())
        );
        assert_eq!(
            cors(json, "OPTIONS", &[], "access-control-allow-headers"),
            Some("x-a".to_string())
        );
        assert_eq!(
            cors(json, "GET", &[], "access-control-max-age"),
            Some("600".to_string())
        );

        // A preflight completes itself from the request's own asks.
        let preflight = [
            ("access-control-request-headers", "x-token"),
            ("access-control-request-method", "PUT"),
        ];
        assert_eq!(
            cors("*", "OPTIONS", &preflight, "access-control-allow-headers"),
            Some("x-token".to_string())
        );
        assert_eq!(
            cors("*", "OPTIONS", &preflight, "access-control-allow-method"),
            Some("PUT".to_string()),
            "upstream writes the singular, non-standard name here"
        );

        // The query-string form.
        assert_eq!(
            cors("methods=GET&maxAge=30", "GET", &[], "access-control-max-age"),
            Some("30".to_string())
        );
    }

    /// `enable://cors` is not an upstream flag; whistle-rs keeps it as an alias
    /// for `resCors://enable` rather than as a blanket `*`.
    #[test]
    fn enable_cors_is_an_alias_for_res_cors_enable() {
        let resolved = resolve("example.com enable://cors\n", "http://example.com/x");
        let mut hm = HeaderMap::new();
        hm.insert("origin", "https://app.test".parse().unwrap());
        let info = build_req_info("GET", "http", "example.com", 80, "/x", &hm, None);
        let mut parts = res_parts(&[]);
        apply_response_for(&mut parts, &resolved, Some(&info));
        assert_eq!(
            parts.headers.get("access-control-allow-origin").unwrap(),
            "https://app.test"
        );
        // An explicit `resCors` wins over the alias.
        let resolved = resolve(
            "example.com enable://cors resCors://*\n",
            "http://example.com/x",
        );
        let mut parts = res_parts(&[]);
        apply_response_for(&mut parts, &resolved, Some(&info));
        assert_eq!(parts.headers.get("access-control-allow-origin").unwrap(), "*");
    }

    /// `resCookies` replaces a `Set-Cookie` the response already sent under the
    /// same name instead of adding a second one (`setResCookies`).
    /// `reqReplace` is gated on the *request's* content type, mirroring the way
    /// `resReplace` is gated on the response's (`res.js:129-132`): a request
    /// with no `content-type`, or an image one, is left alone.
    #[test]
    fn req_replace_is_gated_on_the_request_content_type() {
        let resolved = resolve(
            "example.com reqReplace://old=new\n",
            "http://example.com/",
        );
        let body = || Bytes::from_static(b"old");

        assert_eq!(
            &transform_req_body(body(), &resolved, body_ctx(Some("text/plain")))[..],
            b"new",
            "text is rewritten"
        );
        assert_eq!(
            &transform_req_body(body(), &resolved, body_ctx(None))[..],
            b"old",
            "no content-type: left alone"
        );
        assert_eq!(
            &transform_req_body(body(), &resolved, body_ctx(Some("image/png")))[..],
            b"old",
            "images are left alone"
        );
    }

    #[test]
    fn res_cookies_replace_by_name() {
        let resolved = resolve(
            "example.com resCookies://sid=new&theme=dark\n",
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        headers.append(hyper::header::SET_COOKIE, "sid=old; Path=/".parse().unwrap());
        headers.append(hyper::header::SET_COOKIE, "other=1".parse().unwrap());
        apply_res_cookies(&mut headers, &resolved);
        let vals: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(vals, ["sid=new", "other=1", "theme=dark"]);

        // A `;` in a value would end the cookie early, so it is encoded.
        let resolved = resolve("example.com resCookies://a=x;Secure\n", "http://example.com/");
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved);
        assert_eq!(headers.get(hyper::header::SET_COOKIE).unwrap(), "a=x%3BSecure");
    }
}


