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
        // accepted socket, where the request came from is `serve`'s to say, the
        // response head only exists later, and the body is buffered only when a
        // `b:` filter has asked for it.
        client_port: None,
        from: Default::default(),
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

/// The request facts a backtick operator value renders against — see
/// [`render_backticks`]. Copied rather than borrowed so it can ride along
/// beside the `&mut Resolved` these functions take.
#[derive(Clone, Copy)]
pub struct TplCtx<'a> {
    pub info: &'a ReqInfo,
    pub env: super::template::ProxyEnv<'a>,
}

/// whistle's `renderTpl` (`_original/lib/rules/rules.js:762-772`): an operator
/// whose **whole** value is wrapped in backticks is a template, rendered against
/// the request with `resolveTplVar` before anything else looks at it.
///
/// Upstream matches `TPL_RE = /^((?:[\w.-]+:)?\/\/)?(`.*`)$/` against the rule's
/// whole matcher, so the optional first group is the `proto://` prefix. Here the
/// protocol has already been split off, which leaves exactly the second group:
/// the value must open and close with a backtick and nothing may sit outside
/// them. `.*` does not cross a newline upstream and a token cannot contain one
/// here, so the two agree.
///
/// Returns `None` when the value is not a template, which is also the answer for
/// the two protocols upstream opts out at parse time (`rule.isTpl = false` for
/// `log://` and `weinre://`, `rules.js:1357-1359`) — their values are channel
/// names, and a backtick in one is a backtick.
fn render_backticks(op: &crate::rules::RuleOp, tpl: TplCtx<'_>) -> Option<String> {
    if op.protocol == "log" || op.protocol == "weinre" {
        return None;
    }
    // A lone backtick is not a pair: `strip_suffix` on the empty remainder says
    // so, which is upstream's `(`.*`)` needing two characters.
    let inner = op
        .value
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))?;
    Some(super::template::render_vars(inner, tpl.info, tpl.env))
}

/// Replace operator values of the form `{name}` with the named value's content
/// (whistle's Values store references), after rendering a backtick template.
///
/// The two are one function because upstream's `resolveVar`
/// (`_original/lib/rules/rules.js:774-783`) is: `renderTpl` runs first, and
/// whether it *found* a template then decides what happens to the result of
/// every `${name}` lookup below it.
pub fn substitute_values(
    resolved: &mut Resolved,
    values: &HashMap<String, String>,
    tpl: TplCtx<'_>,
) {
    fn sub(op: &mut crate::rules::RuleOp, values: &HashMap<String, String>, tpl: TplCtx<'_>) {
        // `renderTpl` first, so the backticks are gone before the value store is
        // consulted — and remember whether there were any.
        let is_tpl = match render_backticks(op, tpl) {
            Some(rendered) => {
                op.value = rendered;
                true
            }
            None => false,
        };
        let value = &mut op.value;
        // The whole value is a reference: it is replaced by the content, which
        // is how a mock body or a rules text gets in.
        if let Some(name) = value.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
            && let Some(content) = values.get(name)
        {
            let name = name.to_string();
            *value = content.clone();
            // What came back is the content, not a place to find it — see
            // `RuleOp::value_is_content`.
            op.value_is_content = true;
            // The name outlives the substitution because the file family guesses
            // a content type from it — see `RuleOp::value_key`.
            op.value_key = Some(name);
            return;
        }
        // `${name}` anywhere *inside* a value, which is the other half of
        // `resolveVar` (`VAR_RE = /\${([^{}]+)}/g`,
        // `_original/lib/rules/rules.js:39,:774-783`) and the half this port did
        // not have. `resHeaders://x-v=${myval}` used to reach the origin with
        // the six literal characters `${myval}` in it.
        //
        // A name with no value is left as written — upstream returns the whole
        // match from its replacer when the lookup misses — so a typo shows up
        // as itself rather than as an empty string.
        //
        // When the value *was* a backtick template, what the store hands back is
        // rendered too (`rule.isTpl && key ? resolveTplVar(key, req) : key`,
        // `rules.js:779`). That is the only way a stored value ever sees the
        // request: a named value is written once and reused, so the backticks on
        // the rule line are what say "render what this expands to".
        if value.contains("${") {
            *value = substitute_braced(value, |name| {
                let stored = values.get(name)?;
                Some(match is_tpl && !stored.is_empty() {
                    true => super::template::render_vars(stored, tpl.info, tpl.env),
                    false => stored.clone(),
                })
            });
        }
    }
    for op in resolved.single.values_mut() {
        sub(op, values, tpl);
    }
    for list in resolved.multi.values_mut() {
        for op in list {
            sub(op, values, tpl);
        }
    }
}

/// Replace every `${name}` in `text` with whatever `lookup` returns for it,
/// leaving a name it does not know exactly as written.
///
/// Upstream's `VAR_RE` is `/\${([^{}]+)}/g` — a name may not itself contain
/// braces, which is what stops `${a${b}}` from being read as one reference.
fn substitute_braced(text: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        let (before, from) = rest.split_at(at);
        out.push_str(before);
        let body = &from[2..];
        match body.find(['{', '}']) {
            // A closing brace with no opening one between: a complete reference.
            Some(end) if body.as_bytes()[end] == b'}' && end > 0 => {
                match lookup(&body[..end]) {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(&from[..end + 3]),
                }
                rest = &body[end + 1..];
            }
            // Unterminated, empty, or nested — not a reference. Emit the `${`
            // and carry on, so the scan cannot loop.
            _ => {
                out.push_str("${");
                rest = body;
            }
        }
    }
    out.push_str(rest);
    out
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

/// Merge a rules text resolved mid-request — a `rule://` value, a
/// `rulesFile://` include, a plugin's injected rules — into the set already
/// resolved from the file that pulled it in.
///
/// **What is merged wins.** Upstream's `mergeRule`
/// (`_original/lib/util/index.js:2147-2170`) returns the *new* rule for a
/// single-value protocol and puts the new list first for a multi-match one, so
/// an included file overrides the file that included it and a plugin's rules
/// override both. This port had it the other way round — `or_insert` and
/// `extend` — so a rule you pulled in specifically to override something lost
/// to the thing it was meant to override.
///
/// The order key follows the precedence rather than contradicting it. It was
/// `u64::MAX`, which is what made merged operators lose; it is now the lowest
/// possible, so they win the `min_by_key` that picks an upstream proxy and sort
/// ahead of the host file's operators when the response phase inserts by the
/// same key. Equal keys keep insertion order, so several merged sets stay in
/// the sequence they were merged in.
fn merge_resolved(resolved: &mut Resolved, sub: Resolved) {
    for (k, mut v) in sub.single {
        v.order = MERGED_ORDER;
        resolved.single.insert(k, v);
    }
    for (k, vs) in sub.multi {
        let list = resolved.multi.entry(k).or_default();
        for (at, mut op) in vs.into_iter().enumerate() {
            op.order = MERGED_ORDER;
            list.insert(at, op);
        }
    }
}

/// The resolution order stamped on every operator merged in mid-request, chosen
/// so that merged operators win every contest decided by this key. See
/// [`merge_resolved`].
const MERGED_ORDER: u64 = 0;

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
    if let Some(name) = resolved.value("rule")
        && let Some(content) = values.get(name)
    {
        texts.push(content.clone());
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
/// `dest` is where the request is *addressed* — its own URL, unless a
/// URL-replacement rule moved it (see [`super::dest::Destination`]). `host://`
/// then overrides the address to connect to without changing that, which is why
/// the two are separate: a request forwarded to `http://localhost:5173` and then
/// pinned with `host://10.0.0.1` connects to `10.0.0.1:5173` and still asks for
/// `localhost`. Upstream stacks them the same way — `req.options` comes from the
/// URL rule and `getServerIp` from the host rule.
///
/// Fails rather than falling back to a direct connection when a proxy rule
/// matched but could not be honoured; see [`find_proxy`].
pub async fn resolve_target(
    info: &ReqInfo,
    dest: &super::dest::Destination,
    resolved: &Resolved,
) -> Result<Target> {
    let mut connect_host = dest.host.clone();
    let mut connect_port = dest.port;

    let host_op = resolved.get("host");
    let host_rule = host_op.map(|op| op.value.as_str());
    if let Some(value) = host_rule {
        let (h, p) = parse_host_value(value, dest.port);
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

    let request_tls = super::dest::is_tls(&dest.scheme);
    let tls = origin_tls(request_tls, proxy_proto);
    let cipher = resolved.value("cipher");
    // A cipher string that names nothing this build has fails the request, as
    // it fails at context creation in Node. See `parse_cipher_suites`.
    let tls_ciphers = match cipher.map(parse_cipher_suites).transpose() {
        Ok(policy) => policy.flatten(),
        Err(e) => bail!("cipher://: {e}"),
    };
    let disabled = disabled_flags(resolved);
    Ok(Target {
        tls_ciphers,
        // Read straight off `disable`, as upstream reads them.
        no_proxy_ua: disabled.contains("proxyUA"),
        proxy_connection_close: disabled.contains("proxyConnection"),
        connect_host,
        connect_port,
        tls,
        // Whether the hop stripped the origin's TLS: the request then carries
        // whistle's marker so the whistle on the far side can put it back.
        origin_tls_stripped: request_tls && !tls,
        sni: dest.host.clone(),
        request_port: dest.port,
        proxy,
        tls_versions: cipher.map(parse_cipher_versions).unwrap_or_default(),
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

/// Read the `ciphers` half of a `cipher://` value.
///
/// The other half — `minVersion`/`maxVersion` — is [`parse_cipher_versions`].
/// This one is the OpenSSL cipher string, which [`super::ciphers`] evaluates
/// over the suites this build has.
///
/// `Err` is upstream's own answer to a string that selects nothing: OpenSSL
/// throws `no cipher match` at context creation, so the request fails rather
/// than quietly going out under a policy nobody asked for.
fn parse_cipher_suites(
    value: &str,
) -> Result<Option<std::sync::Arc<super::ciphers::CipherPolicy>>, super::ciphers::NoCipherMatch> {
    let value = value.trim();
    // A bare token is a version pin, not a cipher list — see
    // `parse_cipher_versions`. Only the JSON form carries Node's `ciphers`.
    if !value.starts_with('{') {
        return Ok(None);
    }
    let spec = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
        .ok()
        .and_then(|m| m.get("ciphers").and_then(|v| v.as_str()).map(str::to_string));
    let Some(spec) = spec.filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    super::ciphers::evaluate(&spec).map(|p| Some(std::sync::Arc::new(p)))
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

/// `enable://ignoreSend` / `enable://ignoreReceive` — drop every data frame of
/// one direction of a WebSocket session (`initStatus`,
/// `_original/lib/socket-mgr.js:86-97`).
///
/// The frame is still *captured*: upstream records it with `ignore: true` so the
/// Network view shows what was discarded rather than a silent gap
/// (`socket-mgr.js:401,:531`). Discarding a frame without saying so would make a
/// session look like the peer never sent anything.
///
/// A direction `pauseSend`/`pauseReceive` also names is **not** reported as
/// ignored: upstream reads the two flags as one status per direction and takes
/// the pause branch first (`if (enable.pauseSend) … else if (enable.ignoreSend)`,
/// `initStatus`, `_original/lib/socket-mgr.js:86-97`), so the flags cannot both
/// apply. See [`paused_ws_dirs`].
pub fn ignored_ws_dirs(resolved: &Resolved) -> (bool, bool) {
    let e = enabled_flags(resolved);
    let (pause_send, pause_receive) = paused_ws_dirs(resolved);
    (
        e.contains("ignoreSend") && !pause_send,
        e.contains("ignoreReceive") && !pause_receive,
    )
}

/// `enable://pauseSend` / `enable://pauseReceive` — hold one direction of a
/// WebSocket session instead of delivering it, until someone releases it
/// (`PAUSE_STATUS`, `initStatus`, `_original/lib/socket-mgr.js:13,:86-97`).
///
/// A pause is only half a feature without the release: upstream's console sets
/// the direction back to 0 through `/cgi-bin/socket/change-status`
/// (`changeStatus`, `socket-mgr.js:907-918`), and this port answers
/// `POST /api/ws/release` for the same purpose. Held frames are captured and
/// flagged as they arrive, so the console can show what is waiting rather than
/// only that something is.
pub fn paused_ws_dirs(resolved: &Resolved) -> (bool, bool) {
    let e = enabled_flags(resolved);
    (e.contains("pauseSend"), e.contains("pauseReceive"))
}

/// `disable://ping` / `disable://pong` — suppress the keep-alive the proxy
/// writes on a direction it is holding, as `(ping, pong)`.
///
/// Upstream guards each leg with its own flag: the pong that goes to the
/// **server** while the client's send direction is held is `disable.pong`
/// (`res.write(PONG)`, `_original/lib/socket-mgr.js:366-368`), and the ping that
/// goes to the **client** while the receive direction is held is `disable.ping`
/// (`req.write(PING)`, `:496-498`). Read straight off `disable`, without the
/// `enable://` cancellation, which is how upstream reads them.
///
/// These meant nothing here until there was a keep-alive to suppress — the
/// port used to inject none, so `docs/ROADMAP.md` recorded them as having
/// nothing to disable. Holding a direction brought one, and with it these.
pub fn ws_keepalive_disabled(resolved: &Resolved) -> (bool, bool) {
    let d = disabled_flags(resolved);
    (d.contains("ping"), d.contains("pong"))
}

/// True when the request must be destroyed **before** it is sent
/// (`needAbortReq`, `_original/lib/util/index.js:3893-3903`, applied from the
/// `data` inspector at `_original/lib/inspectors/data.js:534-539` — which runs
/// before `res`, so an abort here means the origin is never contacted).
///
/// `abortRes` is deliberately absent: it lets the request go out and destroys
/// the answer instead — see [`aborts_response`].
pub fn aborts_request(resolved: &Resolved) -> bool {
    aborts(resolved, "abortReq")
}

/// True when the response must be destroyed **after** its head has arrived
/// (`needAbortRes`, `_original/lib/util/index.js:3905-3915`, applied at
/// `_original/lib/inspectors/res.js:1175-1179`, after `resDelay://`).
pub fn aborts_response(resolved: &Resolved) -> bool {
    aborts(resolved, "abortRes")
}

/// The shape both abort gates share: a `disable://` of either spelling cancels
/// the abort outright, and only then does an `enable://` arm it.
///
/// The `disable://` arm is the half this port was missing, which made
/// `enable://abort` unconditional — a rule you could arm on a whole domain and
/// then not exempt one path from.
///
/// Upstream also arms on `req._filters.abort`, set by a `filter://abort` line.
/// This port reads `filter://` only as a match condition (`src/rules/mod.rs`),
/// so there is no filter bag to consult; `enable://` is the whole vocabulary
/// here.
fn aborts(resolved: &Resolved, side: &str) -> bool {
    let dis = disabled_flags(resolved);
    if dis.contains("abort") || dis.contains(side) {
        return false;
    }
    let en = enabled_flags(resolved);
    en.contains("abort") || en.contains(side)
}

/// The coding an `enable://gzip|br|deflate` flag demands the response leave under,
/// or `None` when no such flag is set (`getEnableEncoding`,
/// `_original/lib/util/index.js:1534-1548`).
///
/// The precedence is upstream's — `br` beats `gzip` beats `deflate` — and it is
/// the one case where a body that arrived uncompressed goes out compressed. The
/// caller hands this to [`coding::reencode`], which lets it win over the body's
/// own coding.
pub fn forced_encoding(resolved: &Resolved) -> Option<super::coding::Coding> {
    let e = enabled_flags(resolved);
    if e.contains("br") {
        Some(super::coding::Coding::Brotli)
    } else if e.contains("gzip") {
        Some(super::coding::Coding::Gzip)
    } else if e.contains("deflate") {
        Some(super::coding::Coding::Deflate)
    } else {
        None
    }
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

/// The operator families that share **one slot**.
///
/// None of these names is in upstream's `protocols` array, so `parseRule` files
/// every one of them under the same `rule` list
/// (`_original/lib/rules/rules.js:1313-1316`) and `getRule` returns the first
/// match (`rules.js:799-800`). They cannot coexist: whichever line was written
/// first wins outright and the rest do not apply.
///
/// This port keeps a key per protocol, so the slot has to be reconstructed —
/// see [`slot_winner`]. Without it the port applied a fixed protocol priority
/// (redirect, then statusCode, then file) *and* let a destination rewrite apply
/// alongside a mock, so
///
/// ```text
/// example.com      http://127.0.0.1:9000
/// example.com/api  file:///mock/api.json
/// ```
///
/// forwarded upstream in whistle and served the mock here — a silent
/// disagreement in either direction depending on which line came first.
fn slot_protocols() -> impl Iterator<Item = &'static str> {
    ["redirect", "location", "statusCode"]
        .into_iter()
        .chain(FILE_PROTOS.iter().copied())
        .chain(std::iter::once(crate::rules::protocols::URL_REPLACE))
}

/// Which of the shared-slot operators was written first, if any.
///
/// `RuleOp::order` is the resolution order — important lines first, then source
/// order — which is exactly the sequence `getRule` walks.
pub fn slot_winner(resolved: &Resolved) -> Option<(&'static str, &RuleOp)> {
    slot_protocols()
        .filter_map(|proto| resolved.get(proto).map(|op| (proto, op)))
        // A `rule://<name>` is this port's values-store include, not a
        // destination, so it is not competing for this slot.
        .filter(|(proto, op)| {
            *proto != crate::rules::protocols::URL_REPLACE || !op.raw.starts_with("rule://")
        })
        .min_by_key(|(_, op)| op.order)
}

/// Short-circuit responses produced without contacting upstream:
/// `redirect`/`location`, mocked `statusCode`, and the local-file family.
///
/// Only the operator that won the shared slot may answer — see [`slot_winner`].
pub fn short_circuit(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::template::ProxyEnv<'_>,
) -> Option<Response<DynBody>> {
    let mut resp = short_circuit_inner(info, resolved, env)?;
    mark_self_generated(resp.headers_mut());
    Some(resp)
}

/// The header whistle puts on every response it makes itself — `x-server`, set
/// from `config.appName` by `wrapResponse` (`_original/lib/util/index.js:1080-1090`).
///
/// It answers the question a mocked response otherwise leaves open: did this
/// come from the origin or from the proxy? Worth having for the same reason
/// upstream has it, and worth spelling honestly: this is not whistle, so it does
/// not say `Whistle`. A tool keying off the exact upstream value will not see
/// it, which is the correct outcome — it is not talking to whistle.
fn mark_self_generated(headers: &mut HeaderMap) {
    set_header(headers, "x-server", "whistle-rs");
}

fn short_circuit_inner(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::template::ProxyEnv<'_>,
) -> Option<Response<DynBody>> {
    let (proto, op) = slot_winner(resolved)?;
    match proto {
        "redirect" | "location" => {
            let mut resp = Response::builder()
                .status(StatusCode::FOUND)
                .body(body::empty())
                .unwrap();
            if let Ok(v) = HeaderValue::from_str(&op.value) {
                resp.headers_mut().insert(hyper::header::LOCATION, v);
            }
            Some(resp)
        }
        "statusCode" => {
            let status = op
                .value
                .trim()
                .parse::<u16>()
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::OK);
            Some(
                Response::builder()
                    .status(status)
                    .body(body::empty())
                    .unwrap(),
            )
        }
        // The destination rewrite won: nothing is answered here, the request
        // goes out to where it now points.
        p if p == crate::rules::protocols::URL_REPLACE => None,
        // A file rule, unless `weakRule` hands the request to a proxy instead.
        _ if weak_rule_yields(resolved, proto) => None,
        _ => {
            let cors = auto_cors_wanted(resolved, proto, info);
            // A preflight is answered here and the file is never opened —
            // upstream does the same (`file-proxy.js:249-252`). It has to: the
            // browser sends `OPTIONS` before the real request, and a mock that
            // answers it with the file's own bytes (or a 404, for a rule keyed
            // to the real method) fails the preflight and the real request
            // never follows.
            if cors && info.method.eq_ignore_ascii_case("OPTIONS") {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(body::empty())
                    .unwrap();
                write_auto_cors(resp.headers_mut(), info);
                return Some(resp);
            }
            let mut resp = serve_file_family(proto, op, info, env)?;
            if cors {
                write_auto_cors(resp.headers_mut(), info);
            }
            Some(resp)
        }
    }
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

/// Does a local-file response carry CORS headers it was never asked for?
///
/// whistle adds them whenever the request came from a page on another origin —
/// `isAutoCors` is `!req.disable.autoCors && req.headers.origin`, with a line
/// property to turn it off (`_original/lib/handlers/file-proxy.js:178-191`).
///
/// This port had the writer and not the trigger, and `docs/LINE_PROPS.md` said
/// so while drawing the wrong conclusion — that implementing the automatic CORS
/// in order to have something for `disableAutoCors` to disable would be putting
/// the cart before the horse. The automatic CORS *is* the horse: mocking an API
/// with `file://` from a page on another origin is one of the things whistle is
/// for, and without it the browser rejects the response before any code sees it.
fn auto_cors_wanted(resolved: &Resolved, proto: &str, info: &ReqInfo) -> bool {
    let props = resolved.props(proto);
    // Upstream reads both spellings; the second is its own typo, kept because
    // rules in the wild are written against it.
    if props.has("disableAutoCors") || props.has("disabledAutoCors") {
        return false;
    }
    if disabled_flags(resolved).contains("autoCors") {
        return false;
    }
    req_header(Some(info), "origin").is_some_and(|o| !o.is_empty())
}

/// The CORS headers a local-file response carries — `{enable: true}`, which
/// echoes the request's own `Origin` with credentials, and on a preflight fills
/// in the asked-for method and headers.
fn write_auto_cors(headers: &mut HeaderMap, info: &ReqInfo) {
    let mut spec: HashMap<String, String> = HashMap::new();
    spec.insert("enable".to_string(), "true".to_string());
    write_res_cors(headers, &spec, Some(info));
}

/// The local-file / template protocols, in resolution order (base before `x`/`xs`
/// variants doesn't matter — only one is expected per rule).
const FILE_PROTOS: &[&str] = &[
    "file", "rawfile", "tpl", "jsonp", "dust", "xfile", "xrawfile", "xtpl", "xjsonp", "xdust",
    "xsfile", "xsrawfile", "xstpl", "xsjsonp", "xsdust",
];


/// Serve a matched file-family rule. Returns `None` only for a `x`/`xs` (cross)
/// variant whose file is missing — that falls through to the real server.
fn serve_file_family(
    proto: &str,
    op: &RuleOp,
    info: &ReqInfo,
    env: super::template::ProxyEnv<'_>,
) -> Option<Response<DynBody>> {
    let value = op.value.as_str();
    let raw = proto.contains("rawfile");
    // `tpl`, `dust` and `jsonp` are one protocol in whistle
    // (`_original/lib/handlers/file-proxy.js:14`); none of them has any
    // protocol-specific behaviour of its own.
    let templated = proto.ends_with("tpl") || proto.ends_with("jsonp") || proto.ends_with("dust");
    let cross = proto.starts_with('x');

    // A value that *is* content rather than a location is served as the body.
    // Two ways to get one: the `(text)` inline form, and a whole-value `{name}`
    // the values store answered — both are `readRuleValue`'s `if (rule.value)`
    // arm upstream (`_original/lib/util/index.js:1178-1180`). `<path>` is the
    // third bracket form and means the opposite: a path pinned in place, which
    // the matcher has already honoured by not extending it.
    //
    // A body that came from the values store guesses its type from the *name*
    // it was stored under — `rule.key` at `file-proxy.js:270-272` — because that
    // is the only place `mock.json`'s extension is written down. An inline
    // `(text)` has no such name and falls back to the request URL.
    if op.value_is_content {
        let bytes = value.as_bytes().to_vec();
        let named = op.value_key.as_deref().unwrap_or(&info.full_url);
        return Some(if raw {
            serve_raw_value(&bytes)
        } else if templated {
            serve_template(&bytes, named, info, env)
        } else {
            serve_file_range(&bytes, named, info)
        });
    }
    let value = match crate::rules::url::fixed_value(value) {
        Some((crate::rules::url::Fixed::Inline, text)) => {
            let bytes = text.into_bytes();
            return Some(if raw {
                serve_raw_value(&bytes)
            } else if templated {
                serve_template(&bytes, &info.full_url, info, env)
            } else {
                serve_file_range(&bytes, &info.full_url, info)
            });
        }
        Some((crate::rules::url::Fixed::Verbatim, path)) => std::borrow::Cow::Owned(path),
        None => std::borrow::Cow::Borrowed(value),
    };

    let candidates = FileCandidates::of(proto, &value);
    match candidates.read() {
        // The *matched* path drives the content type, not the rule value: with
        // `file:///tmp/mock/` it is `/tmp/mock/index.html` that was served.
        //
        // Only this arm names the proxy in a `Server` header: upstream builds it
        // alongside the content type in the `readFiles` callback
        // (`file-proxy.js:315-318`), so a body that never touched the filesystem
        // — inline, values store, or the 404 — does not carry one.
        Some((path, data)) => Some(if raw {
            serve_raw_http(&data, &path, info)
        } else if templated {
            with_server(serve_template(&data, &path, info, env))
        } else {
            with_server(serve_file_range(&data, &path, info))
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
            let entry = expand_home(&decode_path(entry));
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

/// Turn a candidate into a filesystem path — upstream's `decodePath`
/// (`_original/lib/util/index.js:1403-1418`, reached from `getTempFilePath`).
///
/// Two things happen there, and both matter once a rule maps a directory: the
/// query string and fragment come off (`getPureUrl`), because
/// `/static/app.js?v=2` names the file `app.js`; and the rest is
/// percent-decoded, because a request for `/a%20b.js` is asking for `a b.js`.
/// Undecodable escapes are left as written, which is upstream's fallback too.
fn decode_path(path: &str) -> String {
    let pure = match path.find(['?', '#']) {
        Some(i) => &path[..i],
        None => path,
    };
    if !pure.contains('%') {
        return pure.to_string();
    }
    let mut out = Vec::with_capacity(pure.len());
    let bytes = pure.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(h), Some(l)) if let Some(byte) = from_hex(*h, *l) => {
                out.push(byte);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| pure.to_string())
}

/// Two hex digits → the byte they spell, or `None` if they do not.
fn from_hex(high: u8, low: u8) -> Option<u8> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    Some(digit(high)? << 4 | digit(low)?)
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
    if let (Some(mtime), true) = (mtime, len <= MAX_CACHED_FILE)
        && let Ok(mut cache) = FILE_CACHE.lock()
    {
        if let Some(hit) = cache.get(path)
            && hit.mtime == mtime
            && hit.len == len
        {
            return Some(Arc::clone(&hit.data));
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
    std::fs::read(path).ok().map(Arc::new)
}

// ---------------------------------------------------------------------------
// Operator values read from a file or a URL (`readRuleValue`)
// ---------------------------------------------------------------------------

/// The operators whose value upstream *reads* rather than uses
/// (`readRuleValue`, `_original/lib/util/index.js:1189-1213`), when that value
/// carries JSON or `k=v` pairs.
///
/// The set is not a property of the protocol table: it is whoever passes a rule
/// to `parseRuleJson`. Every caller in the tree contributes —
/// `_original/lib/inspectors/req.js:463-472` (`reqHeaders`, `reqCookies`,
/// `auth`, `params`, `reqCors`, `reqReplace`, `urlReplace`, `urlParams`),
/// `lib/inspectors/res.js:830-841` (`resHeaders`, `resCookies`, `resCors`,
/// `resReplace`, `resMerge`, `trailers`), `lib/rules/index.js:691` (`cipher`),
/// and the tunnel/HTTPS paths at `lib/tunnel.js:343,:752` and
/// `lib/https/index.js:671-680,:746`, which add no name the first two do not.
const LOADABLE_JSON_OPS: &[&str] = &[
    "reqHeaders",
    "reqCookies",
    "auth",
    "params",
    "urlParams",
    "reqCors",
    "reqReplace",
    "urlReplace",
    "resHeaders",
    "resCookies",
    "resCors",
    "resReplace",
    "resMerge",
    "trailers",
    "cipher",
];

/// The operators whose value upstream reads as **content** — `getRuleValue`
/// (`_original/lib/util/index.js:1409-1416`), from
/// `lib/inspectors/req.js:545-548` and `lib/inspectors/res.js:984` — split by
/// whether a URL value means "fetch this" or "this URL".
///
/// `readRuleValue`'s `checkUrl` argument is what splits them: it is
/// `isJsHtml || isCssHtml` (`util/index.js:1339`), so for the `js*`/`css*`
/// families a URL value is handed back **as the URL** when the response is HTML
/// — that is how `jsAppend://https://cdn/a.js` becomes `<script src=…>`. On a
/// non-HTML response the same value is fetched and inlined instead. This port
/// cannot make that choice here: the loader runs in the request phase, before
/// there is a response to classify. So those two families load from a **file**
/// only, and a URL keeps the meaning this port already documents.
const LOADABLE_TEXT_OPS: &[&str] = &[
    "reqBody",
    "reqPrepend",
    "reqAppend",
    "resBody",
    "resPrepend",
    "resAppend",
    "htmlBody",
    "htmlPrepend",
    "htmlAppend",
];

/// The `js*`/`css*` families: a file value loads, a URL value does not — see
/// [`LOADABLE_TEXT_OPS`].
const LOADABLE_FILE_ONLY_OPS: &[&str] = &[
    "jsBody",
    "jsPrepend",
    "jsAppend",
    "cssBody",
    "cssPrepend",
    "cssAppend",
];

/// Where an operator's value says its content lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ValueSource {
    /// One or more local paths, `|`-separated as upstream's `readFileText` has
    /// them (`_original/lib/util/file-mgr.js:157-166`).
    File(String),
    /// An `http(s)://` URL, fetched once per matching request.
    Url(String),
}

/// The value of a loadable operator is a **location** only when it looks like
/// one: an `http(s)://` URL, or a path that starts at the root, the home
/// directory, a Windows drive, or an explicit `./` / `../`.
///
/// **Deliberately narrower than upstream, and the narrowing is the interesting
/// part.** whistle has no shape test at all: for the text operators *every*
/// non-inline value is a path, and for the JSON ones every value that is not
/// `{json}` and not `k=v`. A bare `resBody://patched` there is a read of
/// `./patched` relative to the rules file's root — `rule.root`, which only
/// exists for rules a plugin or an `@`-include brought in — or, with no root, to
/// whistle's own working directory. It fails, and the operator quietly sets an
/// empty body.
///
/// This port has no `rule.root` to resolve against, and a path relative to the
/// proxy's working directory is not something a rules file can rely on. So a
/// bare value stays the literal it already is here (`docs/RULES.md` documents
/// `resBody://` as taking replacement text), and every spelling that *works*
/// upstream — an absolute path, `~/…`, a URL — loads. The difference is
/// confined to values that upstream reads from a relative path, which is to say
/// values that upstream almost always fails to read.
///
/// The JSON operators additionally keep any value containing `=`: those pairs
/// are the operator's own syntax, and upstream reaches the same place by a
/// longer road — it reads the path, gets nothing, and then falls back to parsing
/// the matcher as a query string (`tryParseMatcher`,
/// `_original/lib/util/index.js:1165-1171,:1303`). Skipping the read that can
/// only fail is what keeps a `urlReplace:///api/v1=/api/v2` rule from
/// `stat()`-ing a nonexistent file on every request.
fn value_source(op: &RuleOp) -> Option<ValueSource> {
    // Already content, not a location: the `(inline)` form and a whole-value
    // `{name}` the values store answered. Upstream's `if (rule.value)` returns
    // before it looks at a disk (`util/index.js:1177-1179`).
    if op.value_is_content {
        return None;
    }
    let value = op.value.trim();
    if value.is_empty() {
        return None;
    }
    // A URL on `re[qs]Cors://` is the **origin**, not a location: upstream tests
    // `isCors` and folds a `GEN_URL_RE` value into `{ origin: value }` before
    // `readRuleValue` is ever reached (`_original/lib/util/index.js:1344,:1361-1370`).
    // `GEN_URL_RE` (`:44`) also admits the scheme-relative `//host`, so both
    // spellings are excluded here.
    if is_cors_origin(op, value) {
        return None;
    }
    // [`is_http_url`] is whistle's `HTTP_RE` (`util/common.js:58`), which is the
    // test `pluginMgr.resolveKey` uses to decide that a value is fetched rather
    // than read (`lib/plugins/index.js:1521-1528`). It wants an explicit scheme,
    // which is what keeps the POSIX path `//srv/x` from being read as a URL.
    if is_http_url(value) {
        let loadable = LOADABLE_JSON_OPS.contains(&op.protocol.as_str())
            || LOADABLE_TEXT_OPS.contains(&op.protocol.as_str());
        return loadable.then(|| ValueSource::Url(value.to_string()));
    }
    if !looks_like_path(value) {
        return None;
    }
    if LOADABLE_JSON_OPS.contains(&op.protocol.as_str()) {
        return (!value.contains('=')).then(|| ValueSource::File(value.to_string()));
    }
    let loadable = LOADABLE_TEXT_OPS.contains(&op.protocol.as_str())
        || LOADABLE_FILE_ONLY_OPS.contains(&op.protocol.as_str());
    loadable.then(|| ValueSource::File(value.to_string()))
}

/// Is this a `re[qs]Cors://` value that whistle reads as an origin URL rather
/// than as somewhere to read from? See [`value_source`].
fn is_cors_origin(op: &RuleOp, value: &str) -> bool {
    if op.protocol != "reqCors" && op.protocol != "resCors" {
        return false;
    }
    // `GEN_URL_RE = /^\s*(?:https?:)?\/\/\w[^\s]*\s*$/i` — a word character has
    // to follow the `//`, which is what separates `//cdn.test/x` from a path.
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .or_else(|| value.strip_prefix("//"));
    matches!(rest.and_then(|r| r.chars().next()), Some(c) if c.is_alphanumeric() || c == '_')
}

/// Does this value name a filesystem path outright? See [`value_source`] for why
/// the question is asked at all.
fn looks_like_path(value: &str) -> bool {
    let first = value.split('|').next().unwrap_or(value);
    if first.starts_with('/')
        || first.starts_with("~/")
        || first.starts_with("～/")
        || first.starts_with("./")
        || first.starts_with("../")
        || first.starts_with('\\')
    {
        return true;
    }
    // `C:\x` / `C:/x` — upstream's `FILE_RE` (`_original/lib/rules/rules.js:35`)
    // spells the same drive-letter test.
    let bytes = first.as_bytes();
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// How long a URL-valued operator may hold a request up.
///
/// Upstream's own budget for the same fetch — `TIMEOUT = 16000` in
/// `_original/lib/util/http-mgr.js:14`, which `pluginMgr.requestText` reaches
/// through `util.request`. There it is an *idle* timer rearmed on every chunk;
/// here it is a deadline on the whole exchange, which can only be stricter. A
/// value that never arrives must not be able to hold a request open forever,
/// and this is the only place a rule can make an outbound call before the
/// request it belongs to has gone anywhere.
const VALUE_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);

/// The most a URL-valued operator may contribute (`MAX_URL_VAL_LEN`,
/// `_original/lib/plugins/index.js:1497`).
///
/// Upstream enforces it *while* reading and aborts the response; this port asks
/// the shared one-shot helper for the whole body and then rejects an oversized
/// one, because [`super::upstream::simple_get`] collects before it returns and
/// growing a second, capped variant of it is not this change's business. The
/// deadline above is what bounds the exchange in the meantime.
const MAX_URL_VALUE: usize = 256 * 1024;

/// Read the content an operator's value points at.
///
/// `None` is a failure, and every failure is the same one: upstream's file read
/// yields `undefined` and its URL fetch yields `''` for a non-200, a timeout or
/// an oversized body (`requestValue`, `_original/lib/plugins/index.js:1500-1512`).
/// What the caller does with it differs by family — see [`load_rule_values`].
async fn read_value_source(source: &ValueSource) -> Option<String> {
    match source {
        // `readFileText` splits on `|` and joins what it read with CRLF, missing
        // files dropping out (`_original/lib/util/file-mgr.js:96-102,:157-166`).
        // That is *not* the first-one-wins of a `file://` rule: several files
        // concatenate into one value.
        ValueSource::File(spec) => {
            let mut parts: Vec<String> = Vec::new();
            for entry in spec.split('|') {
                let path = expand_home(&decode_path(entry.trim()));
                if has_parent_ref(&path) {
                    tracing::warn!("rule value {path}: refused, path contains '..'");
                    continue;
                }
                match read_cached(Path::new(&path)) {
                    // A rule value is a string; a binary mock body has to go
                    // through `file://`, which never decodes.
                    Some(data) => parts.push(String::from_utf8_lossy(&data).into_owned()),
                    // Only `debug`: `a|b` is written precisely so that a missing
                    // alternative is normal. The caller warns once when *nothing*
                    // was read, which is the case worth a line per request.
                    None => tracing::debug!("rule value {path}: not readable"),
                }
            }
            (!parts.is_empty()).then(|| parts.join("\r\n"))
        }
        ValueSource::Url(url) => {
            let fetch = super::upstream::simple_get(url);
            match tokio::time::timeout(VALUE_FETCH_TIMEOUT, fetch).await {
                Ok(Ok((200, bytes))) if bytes.len() <= MAX_URL_VALUE => {
                    Some(String::from_utf8_lossy(&bytes).into_owned())
                }
                Ok(Ok((200, bytes))) => {
                    tracing::warn!("rule value {url}: {} bytes exceeds the limit", bytes.len());
                    None
                }
                Ok(Ok((status, _))) => {
                    tracing::warn!("rule value {url}: responded {status}");
                    None
                }
                Ok(Err(err)) => {
                    tracing::warn!("rule value {url}: {err}");
                    None
                }
                Err(_) => {
                    tracing::warn!("rule value {url}: timed out");
                    None
                }
            }
        }
    }
}

/// Load every operator value that names a file or a URL, in place.
///
/// This is upstream's `readRuleValue` (`_original/lib/util/index.js:1189-1213`),
/// moved to one pass over the resolved set instead of one call per consumer.
/// Upstream reads at the moment each inspector wants the value, which lets it
/// pass a `checkUrl`/`needRawData` pair per call site; doing it once here costs
/// a rule set that uses the feature at most one read per *distinct* location,
/// however many operators name it, and costs a rule set that does not use it a
/// walk over the operators it already has — no syscall, no allocation, no await
/// that yields.
///
/// **Failure differs by family, and both halves are upstream's.**
///
/// * A JSON-valued operator keeps its value as written. Upstream reads the path,
///   gets nothing back, and `tryParseMatcher` then parses the *matcher* as a
///   query string (`util/index.js:1165-1171,:1303,:1327`) — so an unreadable
///   `reqHeaders://x=1` still sets the header. Blanking it here would break
///   rules that never asked for this feature.
/// * A text-valued operator becomes **empty**, which is `readFileText`'s `''`
///   and, downstream, `data.body = reqBody || util.EMPTY_BUFFER`
///   (`lib/inspectors/req.js:548`). It deliberately does not fall back to the
///   text as written: that text is a path, and sending a path to an origin as a
///   request body is the fail-open this exists to avoid.
///
/// Loaded values are marked [`RuleOp::value_is_content`], so a second call —
/// the response phase merges operators that were withheld from the request pass
/// — reads nothing twice.
pub async fn load_rule_values(resolved: &mut Resolved, at: &ReqInfo) {
    fn ops_mut(resolved: &mut Resolved) -> impl Iterator<Item = &mut RuleOp> {
        resolved
            .single
            .values_mut()
            .chain(resolved.multi.values_mut().flatten())
    }
    let mut wanted: HashMap<ValueSource, Option<String>> = HashMap::new();
    for op in ops_mut(resolved) {
        if let Some(source) = value_source(op) {
            wanted.entry(source).or_default();
        }
    }
    if wanted.is_empty() {
        return;
    }
    for (source, slot) in wanted.iter_mut() {
        *slot = read_value_source(source).await;
    }
    for op in ops_mut(resolved) {
        let Some(source) = value_source(op) else {
            continue;
        };
        match wanted.get(&source).and_then(Option::as_ref) {
            Some(content) => {
                op.value = content.clone();
                op.value_is_content = true;
            }
            // See the failure note above: the JSON operators keep their text so
            // upstream's `tryParseMatcher` fallback still holds, the text ones
            // are emptied so a path can never reach an origin as a body.
            None if LOADABLE_JSON_OPS.contains(&op.protocol.as_str()) => {
                tracing::warn!(
                    "{} {} -> {}://{}: nothing loaded, value kept as written",
                    at.method,
                    at.full_url,
                    op.protocol,
                    op.value
                );
            }
            None => {
                tracing::warn!(
                    "{} {} -> {}://{}: nothing loaded, value emptied",
                    at.method,
                    at.full_url,
                    op.protocol,
                    op.value
                );
                op.value = String::new();
                op.value_is_content = true;
            }
        }
    }
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

/// Name the proxy that served a local file, as upstream names itself in the
/// header block it builds beside the content type (`server: config.appName`,
/// `_original/lib/handlers/file-proxy.js:315-318`).
///
/// Spelled honestly, for the reason [`mark_self_generated`] gives: this is not
/// whistle. It is a *response* header the mock carries, not proxy bookkeeping,
/// which is why it is set here and not on everything the proxy answers.
fn with_server(mut resp: Response<DynBody>) -> Response<DynBody> {
    set_header(resp.headers_mut(), "server", "whistle-rs");
    resp
}

/// Serve `file://` bytes, honouring a `Range` request header.
///
/// Only this shape of response is rangeable: `getRawResByPath` asks for a range
/// unless the protocol is `rawfile` (`file-proxy.js:100-102`), and the template
/// branch never reaches it at all. So `rawfile://` and `tpl://` answer 200 with
/// the whole body however the client asks.
fn serve_file_range(data: &[u8], path: &str, info: &ReqInfo) -> Response<DynBody> {
    let Some((start, end)) = parse_range(info, data.len()) else {
        return serve_file_bytes(data, path, info);
    };
    Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(
            hyper::header::CONTENT_TYPE,
            content_type_for(path, &info.full_url),
        )
        .header(
            hyper::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", data.len()),
        )
        .header(hyper::header::ACCEPT_RANGES, "bytes")
        .body(body::full(Bytes::copy_from_slice(&data[start..=end])))
        .unwrap()
}

/// whistle's `parseRange` (`_original/lib/util/index.js:3346-3382`), returning
/// the inclusive byte range to serve, or `None` for "send the whole thing".
///
/// It is reproduced with its arithmetic intact rather than corrected, because
/// two of its answers are load-bearing for anyone who already has mocks:
///
/// * a **suffix** range (`bytes=-500`) computes its start as `size - end` and
///   then compares it against `end` itself, so `start > end` and the range is
///   dropped — whistle answers 200 with the whole body, never the last 500
///   bytes;
/// * **several** ranges collapse into one spanning the lowest start and the
///   highest end, so `bytes=0-1,5-6` serves bytes 0 through 6 as a single 206
///   rather than a multipart response.
///
/// A zero-length body is never ranged (`size &&` guards the whole function).
fn parse_range(info: &ReqInfo, size: usize) -> Option<(usize, usize)> {
    if size == 0 {
        return None;
    }
    let header = req_header(Some(info), "range")?;
    let spec = header.trim_start();
    // `BYTES_RANGE_RE = /^\s*bytes=/i` — the `=` has to follow the unit
    // immediately, so `bytes =0-5` is not a range at all.
    let spec = spec
        .get(..6)
        .filter(|unit| unit.eq_ignore_ascii_case("bytes="))
        .map(|_| spec[6..].trim())?;
    if spec.is_empty() {
        return None;
    }
    // `parseInt(s, 10)`: skip leading whitespace, take a sign and then the
    // leading digits, and answer `NaN` if there are none. Splitting on every
    // `-` first is what makes `bytes=-3-5` an absent start and an end of `3`.
    let leading_int = |s: &str| {
        let s = s.trim_start();
        let digits = s.strip_prefix('+').unwrap_or(s);
        let len = digits.bytes().take_while(u8::is_ascii_digit).count();
        digits[..len].parse::<i64>().ok()
    };

    let size = size as i64;
    let (mut start, mut end) = (size, -1i64);
    for item in spec.split(',') {
        let mut parts = item.split('-');
        let (first, second) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let (s, e) = match (leading_int(first), leading_int(second)) {
            (None, None) => continue,
            (None, Some(e)) => (size - e, e),
            (Some(s), None) => (s, size - 1),
            (Some(s), Some(e)) => (s, e),
        };
        start = start.min(s);
        end = end.max(e);
    }
    if start < 0 || end < 0 || start > end || end >= size {
        return None;
    }
    Some((start as usize, end as usize))
}

/// Serve a `rawfile://` whose value *is* the response text, not a path to it
/// (`getRawResByValue`, `_original/lib/handlers/file-proxy.js:84-98`).
///
/// It differs from the path form twice. With no blank line anywhere, `parseRes`
/// is handed nothing and returns bare `{200, {}}`, so the body goes out with
/// **no content type at all** — where a path with no blank line falls back to
/// the file handler's own header block. And `content-encoding` is deleted
/// (`fromValue`, `file-proxy.js:71-73`): a value is written as literal text in
/// a rules file, so it cannot be the compressed bytes the header claims, and
/// leaving it in makes the client fail to decode a body it can read.
fn serve_raw_value(data: &[u8]) -> Response<DynBody> {
    match find_headers_sep(data) {
        Some((head_end, body_start)) => {
            let mut resp =
                raw_response(&data[..head_end], Bytes::copy_from_slice(&data[body_start..]));
            resp.headers_mut().remove(hyper::header::CONTENT_ENCODING);
            resp
        }
        None => Response::builder()
            .status(StatusCode::OK)
            .body(body::full(Bytes::copy_from_slice(data)))
            .unwrap(),
    }
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
        // Not a raw response, so it is served as an ordinary file — header block
        // and all, which is what `reader.headers || headers` falls back to at
        // `file-proxy.js:348`.
        return with_server(serve_file_bytes(data, path, info));
    };
    raw_response(
        &data[..head_end],
        Bytes::copy_from_slice(&data[body_start..]),
    )
}

/// Build a response from a raw HTTP head and a body
/// (`parseRes`, `_original/lib/handlers/file-proxy.js:61-78`).
///
/// Only the head is decoded as text; the body stays bytes so a binary payload
/// survives. A head whose first line carries no numeric status is served as 200
/// — upstream assigns `statusLine[1]` unchecked and then throws while writing
/// the response, which reaches the client as a reset connection.
fn raw_response(head: &[u8], body: Bytes) -> Response<DynBody> {
    let head = String::from_utf8_lossy(head);
    // `CRLF_RE = /\r\n|\r|\n/g` (`file-proxy.js:10`) — a lone CR ends a header
    // line too, so `.http` fixtures written on any platform parse.
    let mut lines = head.split(['\n', '\r']).filter(|l| !l.is_empty());
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
    builder.body(body::full(body)).unwrap_or_else(|_| {
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
///
/// Types and spellings are whatever the `mime` package upstream depends on
/// answers for that extension; the `; charset=utf-8` suffix follows upstream's
/// `util.isText` (`_original/lib/util/index.js:1494-1531`), which is a substring
/// test — anything naming `javascript`, `css`, `html`, `json`, `xml` or starting
/// `text/` is text, and only `image/*` that got past those is not. That is why
/// `image/svg+xml` carries a charset and `image/png` does not.
///
/// The table is a subset of `mime`'s several hundred entries, covering what a
/// mock tree holds. An extension outside it falls back to the request URL's, as
/// it would for a file with no extension at all.
fn content_type_of_ext(path: &str) -> Option<&'static str> {
    let last = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = last.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "xhtml" => "application/xhtml+xml; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        // A source map is JSON, and `.map` is how every bundler spells it.
        "json" | "map" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "yaml" | "yml" => "text/yaml; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "svg" => "image/svg+xml; charset=utf-8",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "bin" => "application/octet-stream",
        "txt" | "text" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

/// Apply request-side operators (headers, method, ua, referer) in place.
pub fn apply_request(parts: &mut request::Parts, resolved: &Resolved) {
    apply_header_ops(&mut parts.headers, resolved, "reqHeaders");

    // Both go through the same `setHeader` assignment upstream
    // (`_original/lib/inspectors/req.js:511-519`), so an empty `ua://` sends an
    // empty `User-Agent` rather than none at all — `disable://ua` is the rule
    // that removes it.
    if let Some(ua) = resolved.value("ua") {
        assign_header(&mut parts.headers, "user-agent", ua);
    }
    if let Some(referer) = resolved.value("referer") {
        assign_header(&mut parts.headers, "referer", referer);
    }
    // `getMethod` runs on **every** request, not only one carrying a
    // `method://`: `req.method = util.getMethod(data.method || req.method)`
    // (`_original/lib/inspectors/req.js:536`, impl `util/common.js:1608-1613`).
    // So a client that sent `post` reaches the origin as `POST`, and — more to
    // the point here — the same normalised method is what every body gate then
    // reads. An empty or unusable value falls back to `GET`, as upstream's does.
    let method = resolved
        .value("method")
        .map(str::to_string)
        .unwrap_or_else(|| parts.method.to_string());
    parts.method = method
        .trim()
        .to_ascii_uppercase()
        .parse()
        .unwrap_or(hyper::Method::GET);
    if let Some(ct) = resolved.value("reqType") {
        set_content_type(&mut parts.headers, ct, req_type_alias);
    }
    if let Some(auth) = resolved.value("auth").map(parse_auth)
        && let Some(basic) = auth.basic()
    {
        // `"proxy":true` addresses the *proxy* rather than the origin
        // (`handleAuth`, `_original/lib/inspectors/req.js:150-155`).
        let name = match auth.proxy {
            true => "proxy-authorization",
            false => "authorization",
        };
        set_header(&mut parts.headers, name, &basic);
    }
    apply_forwarded_for(&mut parts.headers, resolved);
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
    apply_deletes(&mut parts.headers, &del, true);
    apply_header_replace(&mut parts.headers, resolved, HeaderScope::Request);
    // Before the `disable://` pass, which is where upstream runs it
    // (`_original/lib/inspectors/req.js:579-580`).
    remove_unsupported_encodings(&mut parts.headers);
    // Last, so a `disable://` flag has the final say over what leaves here —
    // including over a `reqHeaders://cookie=…` that set what it strips, which is
    // upstream's order too (`disableReqProps` runs after `handleReq`,
    // `_original/lib/inspectors/req.js:579-581`).
    disable_req_props(&mut parts.headers, resolved);
    // A rule that rewrites the response body cannot survive a `304`, so the
    // request goes out unconditional even without `disable://cache`.
    if res_body_forbids_cache(resolved) {
        disable_req_cache(&mut parts.headers);
    }
}

/// What an `auth://` rule asks for (`getAuthByRules`,
/// `_original/lib/util/index.js:3645-3662`).
///
/// A missing half is not an empty one: `username` and `password` are each
/// `None` when the rule did not name them, and `getAuthBasic`
/// (`util/index.js:3668-3685`) reads the difference — a password with no
/// username becomes `:pass`, a username with no password has no colon at all.
#[derive(Debug, Default, PartialEq)]
struct Auth {
    username: Option<String>,
    password: Option<String>,
    /// `"proxy":true` — send `Proxy-Authorization` rather than `Authorization`.
    proxy: bool,
}

impl Auth {
    /// The header value, or `None` when the rule named neither half
    /// (`getAuthBasic`, `_original/lib/util/index.js:3668-3685`).
    fn basic(&self) -> Option<String> {
        let joined = match (&self.username, &self.password) {
            (None, None) => return None,
            // No username: upstream starts the pair with an empty string, so
            // the colon survives and the server still sees two fields.
            (None, Some(p)) => format!(":{p}"),
            // No password: no colon either — `['u'].join(':')` is just `u`.
            (Some(u), None) => u.clone(),
            (Some(u), Some(p)) => format!("{u}:{p}"),
        };
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            joined.as_bytes(),
        );
        Some(format!("Basic {token}"))
    }
}

/// Parse an `auth://` value in all three shapes upstream accepts.
///
/// This port understood only `user:pass`, so the other two — the JSON object
/// and the `username=…&password=…` query — were base64-encoded whole and sent
/// as the credentials themselves. `auth://{"username":"u","password":"p"}`
/// authenticated as the user *`{"username"`* with the password
/// *`"u","password":"p"}`*, which a server answers with a 401 that looks like
/// the rule never ran.
///
/// The one shape not honoured here is upstream's fourth: a value containing a
/// slash is a **file reference**, read through `readRuleValue`
/// (`getAuthByRules` returns nothing for it, `util/index.js:3654-3656`, and
/// `req.js:464` then feeds the rule to `parseRuleJson` instead). This port has
/// no rule-value loader, so rather than answer such a rule with silence it
/// keeps splitting on the first colon — which is what `auth://u:pa/ss`, a
/// password with a slash in it, needs anyway.
fn parse_auth(value: &str) -> Auth {
    let value = value.trim();
    // `auth[0] === '{' && auth[auth.length - 1] === '}'`: a JSON object.
    if value.starts_with('{') && value.ends_with('}') {
        // A JSON object upstream cannot parse becomes `{}` — an auth naming
        // neither half, which produces no header rather than a bad one.
        let parsed = serde_json::from_str::<serde_json::Value>(value).ok();
        return format_auth(parsed.as_ref());
    }
    // `AUTH_RE = /^(?:username|password)=/` — anchored, and case-sensitive.
    if value.starts_with("username=") || value.starts_with("password=") {
        // `parseQuery(auth, null, null, true)`: the raw decoder, so a `%2F` or a
        // `+` in a password reaches the server as written.
        let obj: serde_json::Map<String, serde_json::Value> = value
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        return format_auth(Some(&serde_json::Value::Object(obj)));
    }
    match value.split_once(':') {
        Some((u, p)) => Auth {
            username: Some(u.to_string()),
            password: Some(p.to_string()),
            proxy: false,
        },
        None => Auth {
            username: Some(value.to_string()),
            password: None,
            proxy: false,
        },
    }
}

/// `formatAuth` (`_original/lib/util/index.js:3632-3643`): read the three
/// fields, stringifying whatever was there and keeping `null` distinct.
fn format_auth(obj: Option<&serde_json::Value>) -> Auth {
    let field = |name: &str| match obj.and_then(|o| o.get(name)) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    };
    Auth {
        username: field("username"),
        password: field("password"),
        // `!!obj.proxy`, so the query spelling `proxy=false` is a non-empty
        // string and therefore **true**. Upstream's, and the reason the JSON
        // spelling is the one to reach for when the answer is "no".
        proxy: match obj.and_then(|o| o.get("proxy")) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(serde_json::Value::Number(n)) => n.as_f64() != Some(0.0),
            Some(_) => true,
        },
    }
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
    /// Cookie names to remove.
    ///
    /// On the request side this drops the cookie from the outgoing `Cookie`
    /// header. On the response side there is nothing to drop — the cookie lives
    /// in the *client*, so it is removed by sending an already-expired
    /// `Set-Cookie` back ([`expiring_cookies`]).
    cookies: Vec<String>,
    /// `delete://trailer.x` — trailing header names to drop after the body
    /// (`TRAILER_RE`, `_original/lib/util/index.js:2663,:2812`). Response side
    /// only, and unlike every other key here it is *not* scoped by `req`/`res`.
    trailers: Vec<String>,
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
                    del.cookies.push(name.to_string());
                } else if !request_side
                    && let Some(name) = key
                        .to_ascii_lowercase()
                        .find("trailer.")
                        .map(|i| &key[i + "trailer.".len()..])
                        .filter(|n| !n.is_empty())
                {
                    // `TRAILER_RE` is unanchored at the front, so `resTrailer.x`
                    // and a bare `trailer.x` both match — and so, upstream, does
                    // anything else ending in `trailer.<name>`.
                    del.trailers.push(name.to_string());
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
fn apply_deletes(headers: &mut HeaderMap, del: &Deletions, request_side: bool) {
    for name in &del.headers {
        remove_header(headers, name);
    }
    // Only the request side has a cookie to strip: on the response side the
    // cookie is already in the client, and the deletion is a `Set-Cookie` that
    // expires it instead — see [`expiring_cookies`].
    if request_side {
        for name in &del.cookies {
            remove_cookie(headers, name);
        }
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
fn apply_header_replace(headers: &mut HeaderMap, resolved: &Resolved, want: HeaderScope) {
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

/// The entries of a `headerReplace://` value, in source order, in either
/// spelling upstream accepts.
///
/// `readRuleList` reads these operators as JSON **or** as a query string
/// (`parseRuleJson` → `tryParseMatcher` → `parseQuery`,
/// `_original/lib/util/index.js`), and the query-string form is the shorter of
/// the two: `headerReplace://resH.x-origin:/yes/=no`. This port took only the
/// JSON one, so that rule parsed, matched, and rewrote nothing — silently,
/// which is the failure mode the whole audit keeps turning up.
///
/// Splitting is upstream's `parseQuery`: `&` between entries, the **first** `=`
/// between key and value. A key here is `<scope>.<name>:<pattern>` and the
/// pattern may well contain `/` and `:`, which is why only the first `=` counts.
fn ordered_pairs(text: &str) -> Option<Vec<(String, serde_json::Value)>> {
    if text.starts_with('{') {
        return json_object_in_order(text);
    }
    if text.is_empty() {
        return None;
    }
    let pairs: Vec<(String, serde_json::Value)> = text
        .split('&')
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((k, v)) => (k.to_string(), serde_json::Value::String(v.to_string())),
            // A key with no `=` replaces its pattern with nothing, which is how
            // `parseQuery` reads a bare name — an empty string, not a missing
            // entry.
            None => (entry.to_string(), serde_json::Value::String(String::new())),
        })
        .collect();
    (!pairs.is_empty()).then_some(pairs)
}

/// Parse a JSON object into its entries **in source order**.
///
/// `serde_json::Map` is a `BTreeMap` by default, which sorts — fine everywhere a
/// key is looked up by name, wrong wherever one entry's meaning depends on the
/// one before it (see [`apply_header_replace`]). Returns `None` for anything
/// that is not a JSON object.
fn json_object_in_order(text: &str) -> Option<Vec<(String, serde_json::Value)>> {
    use serde::de::{MapAccess, Visitor};

    struct Ordered;

    impl<'de> Visitor<'de> for Ordered {
        type Value = Vec<(String, serde_json::Value)>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut out = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                out.push((k, v));
            }
            Ok(out)
        }
    }

    let mut de = serde_json::Deserializer::from_str(text);
    serde::Deserializer::deserialize_map(&mut de, Ordered).ok()
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
    fn key(self) -> &'static str {
        match self {
            HeaderScope::Request => "req",
            HeaderScope::Response => "res",
            HeaderScope::Trailer => "trailer",
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
    if !new_type.contains(';')
        && let Some(current) = headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .filter(|c| c.contains(';'))
    {
        let mut kept: Vec<String> = current.split(';').map(str::to_string).collect();
        kept[0] = new_type;
        new_type = kept.join(";");
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
    resolved
        .value("reqDelay")
        .and_then(parse_leading_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Milliseconds to delay before returning the response (`resDelay`).
pub fn res_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved
        .value("resDelay")
        .and_then(parse_leading_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Request-body throughput cap in kilobits/s (`reqSpeed`) — see
/// [`super::body::throttled`] for why the unit is bits.
pub fn req_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved.value("reqSpeed").and_then(parse_leading_number)
}

/// Response-body throughput cap in kilobits/s (`resSpeed`).
pub fn res_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved.value("resSpeed").and_then(parse_leading_number)
}

/// JavaScript's `parseFloat`: the longest numeric prefix, ignoring whatever
/// follows.
///
/// whistle reads these values with `parseFloat`/`parseInt`
/// (`_original/lib/inspectors/res.js:917-921`,
/// `lib/util/index.js:3687-3693`), so `resSpeed://20kb` and `resDelay://500ms`
/// are 20 and 500 there. Rust's `parse` rejects them outright, which turned a
/// value with a unit suffix — the way anyone would first write one — into no
/// throttle and no delay at all.
fn parse_leading_number(value: &str) -> Option<f64> {
    let text = value.trim();
    let end = text
        .char_indices()
        .take_while(|(i, c)| {
            c.is_ascii_digit() || *c == '.' || (*i == 0 && (*c == '-' || *c == '+'))
        })
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    text[..end].parse().ok()
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
/// charset pass, `headerReplace`, the `Location` re-encode, and — last of all,
/// after the injection's CSP and cache strips — the `delete://` keys.
pub fn apply_response_for(
    parts: &mut response::Parts,
    resolved: &Resolved,
    info: Option<&ReqInfo>,
) {
    if let Some(code) = resolved
        .value("replaceStatus")
        .or_else(|| resolved.value("statusCode"))
        && let Some(status) = code
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(|c| StatusCode::from_u16(c).ok())
        // `replaceStatus != _res.statusCode` (`res.js:827`). Without the guard a
        // `replaceStatus://401` on a response that was *already* a 401 wrote a
        // `WWW-Authenticate: Basic` the origin had not asked for — and a browser
        // answers that with a login box.
        && status != parts.status
    {
        parts.status = status;
        // `disable://userLogin` suppresses the challenge without suppressing the
        // status change (`isDisableUserLogin`,
        // `_original/lib/util/index.js:3558-3563`); `enable://userLogin` wins
        // over it. Upstream also reads the two from the line's own properties,
        // which this port does not carry this far.
        let en = enabled_flags(resolved);
        if en.contains("userLogin") || !disabled_flags(resolved).contains("userLogin") {
            handle_status_code(&mut parts.headers, status);
        }
    }
    // `disable://301` — hand back a `302` instead, so the browser does not cache
    // the redirect permanently (`_original/lib/inspectors/res.js:833-835`). This
    // is the flag you reach for once a site has already taught the browser a
    // `301` you now need to override, and it was not implemented.
    if parts.status == StatusCode::MOVED_PERMANENTLY && disabled_flags(resolved).contains("301") {
        parts.status = StatusCode::FOUND;
    }
    // Resolved before the cookies, because `delete://resCookies.x` is *served*
    // as a cookie rather than applied as a removal — see [`expiring_cookies`].
    let del = Deletions::of(resolved, false);
    apply_res_cookies(&mut parts.headers, resolved, &del, info);
    apply_res_cors(&mut parts.headers, resolved, info);

    apply_header_ops(&mut parts.headers, resolved, "resHeaders");
    apply_cache(&mut parts.headers, resolved);
    apply_attachment(&mut parts.headers, resolved, info);

    if let Some(ct) = resolved.value("resType") {
        set_content_type(&mut parts.headers, ct, no_type_alias);
    }
    set_charset(
        &mut parts.headers,
        resolved.value("resCharset"),
        del.drop_type,
        del.drop_charset,
    );
    apply_header_replace(&mut parts.headers, resolved, HeaderScope::Response);
    // Node's URL layer only speaks ASCII, so a `Location` carrying anything else
    // reaches the browser as mojibake; whistle percent-encodes it right here,
    // after `headerReplace` has had its say (`res.js:946-949`). A rule that
    // redirects to a path with a non-Latin-1 character in it needs this.
    //
    // Read as UTF-8 rather than through `to_str`, which refuses the very bytes
    // this exists to encode; a value that is not UTF-8 at all is left alone,
    // since there is no encoding to read it under. That last part is where this
    // is *wider* than upstream: Node hands its header values over as latin-1
    // strings, one character per byte, so an **origin's** raw-UTF-8 `Location`
    // matches nothing in `G_NON_LATIN1_RE` and passes through unencoded there.
    // Encoding it is the conformant answer and the one a browser follows.
    if let Some(location) = parts
        .headers
        .get(hyper::header::LOCATION)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .map(encode_non_latin1)
    {
        assign_header(&mut parts.headers, "location", &location);
    }

    // Injected content is useless behind a CSP that forbids it, or cached for
    // the next load; whistle strips both (`res.js:1093-1101`).
    if injects_into_body(
        &parts.headers,
        resolved,
        parts.status.as_u16(),
        info.map_or("GET", |i| i.method.as_str()),
    ) {
        if !enabled_flags(resolved).contains("keepCSP")
            && !enabled_flags(resolved).contains("keepAllCSP")
        {
            disable_csp(&mut parts.headers);
        }
        if !custom_cache(resolved) && !enabled_flags(resolved).contains("keepCache") {
            disable_res_store(&mut parts.headers);
        }
    }

    // After the strip above, not before it, which is upstream's order
    // (`res.js:1160-1165` against `:1097-1104`) and the whole point of the
    // operator: `resAppend://x delete://resHeaders.cache-control` has to be able
    // to take away the `Cache-Control: no-store` the injection just wrote, and
    // deleting first left it standing.
    apply_deletes(&mut parts.headers, &del, false);

    disable_res_props(&mut parts.headers, resolved);
    apply_show_host(&mut parts.headers, resolved, info);
    annotate_response_for(&mut parts.headers, resolved, info);
}

/// `disable://` flags with response-header effects (`disableResProps`,
/// `_original/lib/util/index.js:3011-3027`), applied last so nothing can undo
/// them.
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
}

/// `enable://showHost` — report the address the request was actually sent to,
/// as `x-host-ip` (`_original/lib/inspectors/res.js:1197-1199`).
///
/// The value is the connected peer, which through an upstream proxy is the
/// proxy's address — the same `req.hostIp` [`serverIp:`] filters on, so the
/// header and the condition can never disagree. whistle falls back to
/// `127.0.0.1` when it has no address at all, and so does this.
fn apply_show_host(headers: &mut HeaderMap, resolved: &Resolved, info: Option<&ReqInfo>) {
    if !enabled_flags(resolved).contains("showHost") {
        return;
    }
    let ip = info
        .and_then(|i| i.res.as_ref())
        .and_then(|r| r.server_ip.as_deref())
        .unwrap_or("127.0.0.1");
    set_header(headers, "x-host-ip", ip);
}

/// `x-forwarded-for` (`_original/lib/inspectors/res.js:690-710`).
///
/// Three rules, none of which this port had:
///
/// * `forwardedFor://` sets the header **only when its value is an IP**
///   (`net.isIP`). Upstream's own documentation points a non-IP value at
///   `reqHeaders://` instead; setting it here let `forwardedFor://hello` reach
///   the origin as a client address.
/// * `disable://clientIp` (and `clientIP`) deletes the header outright.
/// * Otherwise the client's own `X-Forwarded-For` is **removed** rather than
///   forwarded. That is the load-bearing one: without it, any client can claim
///   any address simply by sending the header, and the origin sees a value the
///   proxy vouched for. whistle closes that by default and opens it with
///   `enable://clientIp`.
///
/// The port does not implement upstream's `req.clientIp` *substitution* — it
/// never forwards a client address of its own — so the choice here is between
/// stripping and passing through, and stripping is the one that cannot mislead.
fn apply_forwarded_for(headers: &mut HeaderMap, resolved: &Resolved) {
    const XFF: &str = "x-forwarded-for";
    let dis = disabled_flags(resolved);
    if dis.contains("clientIp") || dis.contains("clientIP") {
        headers.remove(XFF);
        return;
    }
    if let Some(value) = resolved.value("forwardedFor") {
        // `net.isIP`: a v4 or v6 literal, nothing else.
        if value.trim().parse::<std::net::IpAddr>().is_ok() {
            set_header(headers, XFF, value.trim());
            return;
        }
    }
    let en = enabled_flags(resolved);
    if !en.contains("clientIp") && !en.contains("clientIP") {
        headers.remove(XFF);
    }
}

/// `responseFor://` — annotate the response with who answered it, as
/// `x-whistle-response-for` (`setResponseFor`,
/// `_original/lib/util/index.js:3214-3261`, called from `res.js:1200-1206`).
///
/// Two forms. A plain value is emitted verbatim. `name=a,b,req.c` names
/// *headers* to read: bare names from the response, `req.`-prefixed ones from
/// the request, with the address actually reached appended — so a response can
/// carry a chain of who served it without anyone having to guess.
///
/// **This used to be a different operator entirely.** The port fetched the value
/// as a URL, on every matching request, and wrote the result onto the *outgoing
/// request* — an unrequested outbound call to whatever a rules file named, and
/// headers the client never saw. Nothing upstream makes a network call here.
fn annotate_response_for(headers: &mut HeaderMap, resolved: &Resolved, info: Option<&ReqInfo>) {
    let Some(spec) = resolved.value("responseFor") else {
        return;
    };
    let server_ip = info
        .and_then(|i| i.res.as_ref())
        .and_then(|r| r.server_ip.as_deref())
        .unwrap_or("127.0.0.1");

    let Some(names) = spec.strip_prefix("name=") else {
        set_header(headers, "x-whistle-response-for", spec);
        return;
    };

    // Response-header lookups keep their position; request-header ones are
    // collected and appended after, which is upstream's `result.concat(reqResult)`.
    let (mut from_res, mut from_req) = (Vec::new(), Vec::new());
    for name in names.to_ascii_lowercase().split(',') {
        let name = name.trim();
        match name.strip_prefix("req.") {
            Some(req_name) => {
                if let Some(v) = info.and_then(|i| header_of(&i.headers, req_name)) {
                    from_req.push(v);
                }
            }
            None => {
                if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
                    from_res.push(v.to_string());
                }
            }
        }
    }
    if !from_res.iter().any(|v| v == server_ip) {
        from_res.push(server_ip.to_string());
    }
    from_res.extend(from_req);
    set_header(headers, "x-whistle-response-for", &from_res.join(", "));
}

/// One request header by name, from the captured pairs.
fn header_of(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

/// Strip the request headers a `disable://` flag names (`disableReqProps`,
/// `_original/lib/util/index.js:2977-3009`).
///
/// Every one of these was silently inert before: a user who wrote
/// `disable://cookie` still had the cookie forwarded to the origin, which for
/// the privacy-shaped flags is the wrong way to fail.
fn disable_req_props(headers: &mut HeaderMap, resolved: &Resolved) {
    let dis = disabled_flags(resolved);
    let en = enabled_flags(resolved);
    let off = |name: &str| dis.contains(name);
    if off("ua") {
        headers.remove(hyper::header::USER_AGENT);
    }
    // `enable://captureStream` also drops it: whistle wants the origin's bytes
    // uncompressed so it can stream them past the inspector. That one goes
    // through `isEnable`, which a `disable://` of the same name cancels
    // (`_original/lib/util/index.js:675-677`) — unlike the keys above, which
    // upstream reads straight off `req.disable`.
    if off("gzip") || (en.contains("captureStream") && !dis.contains("captureStream")) {
        headers.remove(hyper::header::ACCEPT_ENCODING);
    }
    if ["cookie", "cookies", "reqCookie", "reqCookies"]
        .iter()
        .any(|f| off(f))
    {
        headers.remove(hyper::header::COOKIE);
    }
    // Both spellings, because whistle accepts the correct one and the common
    // misspelling that matches the header's own name.
    if off("referer") || off("referrer") {
        headers.remove(hyper::header::REFERER);
    }
    if off("ajax") {
        headers.remove("x-requested-with");
    }
    if off("cache") {
        disable_req_cache(headers);
    }
    // `Connection: close` goes on the request that leaves here, not on the
    // answer that goes back to the client: upstream writes it into the outgoing
    // `options.headers` (`_original/lib/inspectors/res.js:447-449`) so the hop
    // to the origin is not pooled. Putting it on the response instead tore down
    // the *client's* connection and left the origin socket in the pool — the
    // exact opposite of what the flag asks for. Both spellings, because
    // upstream folds `keepalive` into `keepAlive` before reading it
    // (`res.js:268-270`).
    if off("keepAlive") || off("keepalive") {
        set_header(headers, "connection", "close");
    }
}

/// Narrow `Accept-Encoding` to the codings this proxy can undo *and* redo
/// (`removeUnsupportsHeaders`, `_original/lib/util/index.js:1549-1570`), which
/// upstream runs on every request (`req.js:579`).
///
/// Without it a modern browser asks for `gzip, deflate, br, zstd`, the origin
/// picks zstd, and every body operator silently dies: [`coding::Coding`] cannot
/// round-trip zstd, so the body is passed through untouched and the rule looks
/// like it never matched. That is the whole reason whistle narrows the header
/// rather than trusting the origin to be conservative.
///
/// `deflate` is dropped even though this port can decode it, because upstream
/// drops it too — `removeUnsupportsHeaders` only keeps `deflate` when its
/// caller passes `supportsDeflate`, and `req.js:579` does not. Keeping it would
/// invite the raw-vs-zlib deflate ambiguity back for no gain, since any origin
/// that speaks deflate also speaks gzip.
fn remove_unsupported_encodings(headers: &mut HeaderMap) {
    let Some(value) = headers
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return;
    };
    let kept = value
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        // The comparison is against the whole token, so a `q` parameter takes
        // the coding down with it — `gzip;q=1.0` is not `gzip`. Upstream's, and
        // it is why whistle's own requests carry a bare `gzip, br`.
        .filter(|token| token == "gzip" || token == "br")
        .collect::<Vec<_>>()
        .join(", ");
    // A request that asked for *nothing* this proxy can undo keeps the header
    // it arrived with: upstream only assigns when the filtered list is
    // non-empty (`util/index.js:1567-1569`). An origin may still answer with a
    // coding no operator can see through — but that is the client's own header,
    // untouched, rather than one this proxy invented.
    if !kept.is_empty() {
        set_header(headers, "accept-encoding", &kept);
    }
}

/// Make a request unconditional: drop the validators that let an origin answer
/// `304 Not Modified` (`disableReqCache`, `_original/lib/util/index.js:974-982`).
///
/// A `304` has no body, so anything meant to rewrite one has nothing to work on.
/// That is why whistle applies this whenever a **response-body operator**
/// matched, not only for `disable://cache` — see [`res_body_forbids_cache`].
fn disable_req_cache(headers: &mut HeaderMap) {
    for name in [
        "if-modified-since",
        "if-none-match",
        "last-modified",
        "etag",
    ] {
        headers.remove(name);
    }
    set_header(headers, "pragma", "no-cache");
    set_header(headers, "cache-control", "no-cache");
}

/// The response-body operators that make a conditional request unanswerable
/// (`BODY_PROTOCOLS` + `notAllowCache`, `_original/lib/inspectors/res.js:33-60`,
/// applied at `res.js:1328`).
///
/// Without this a rule works on the first load and silently stops working on a
/// reload, because the origin answers `304` and there is no body to rewrite —
/// intermittent in exactly the way that reads as a bug in the proxy.
const BODY_PROTOCOLS: &[&str] = &[
    "attachment",
    "resReplace",
    "resBody",
    "resPrepend",
    "resAppend",
    "htmlBody",
    "htmlPrepend",
    "htmlAppend",
    "jsBody",
    "jsPrepend",
    "jsAppend",
    "cssBody",
    "cssPrepend",
    "cssAppend",
    "resWrite",
    "resWriteRaw",
    "resMerge",
];

/// The two tool protocols that inject a script into an HTML response, and so
/// need one to inject into.
///
/// Upstream busts the cache for these the moment the rule matches
/// (`util.disableReqCache(req.headers)`, `_original/lib/inspectors/log.js:30`
/// and `weinre.js:26`) — and unlike `notAllowCache`, which reads the response
/// phase's protocols from the request pass and therefore never fires, these two
/// are request-phase and really do run. Measured against whistle 2.10.8: a
/// `log://` rule reaches the origin with `pragma: no-cache`.
const SCRIPT_INJECTORS: &[&str] = &["log", "weinre"];

/// True when a rule on this request will want to rewrite or inject into the
/// response body, and therefore cannot tolerate a `304`.
/// See [`BODY_PROTOCOLS`] and [`SCRIPT_INJECTORS`].
fn res_body_forbids_cache(resolved: &Resolved) -> bool {
    BODY_PROTOCOLS
        .iter()
        .chain(SCRIPT_INJECTORS)
        .any(|p| resolved.value(p).is_some())
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
    write_res_cors(headers, &spec, info);
}

/// Write the CORS headers a resolved spec asks for.
///
/// Split out of [`apply_res_cors`] so the automatic CORS a local-file response
/// carries can reuse it — that is `setResCors(reader, {enable: true}, req)`
/// upstream (`_original/lib/handlers/file-proxy.js:187`), the very same writer
/// with a spec nobody typed.
fn write_res_cors(
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
    } else if auto
        && let Some(list) = req_header(info, "access-control-request-headers")
    {
        set_header(headers, "access-control-allow-headers", list);
    }
    if let Some(credentials) = spec.get("credentials") {
        set_header(headers, "access-control-allow-credentials", credentials);
    } else if auto
        && let Some(method) = req_header(info, "access-control-request-method")
    {
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
    // Neither a no-cache spelling nor a usable max-age: nothing to write.
    if !no_cache && max_age.is_none_or(|n| n < 0) {
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
fn injects_into_body(headers: &HeaderMap, resolved: &Resolved, status: u16, method: &str) -> bool {
    // A response with no body has nothing to inject into, so nothing to clear a
    // CSP or a cache for either. Upstream's `hasResBody` gate covers both
    // (`_original/lib/inspectors/res.js:1097-1113`); without it a `302` came
    // back with `Cache-Control: no-store`, a past `Expires` and no CSP.
    if !super::response_has_body(status, method) {
        return false;
    }
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

/// File to write the request body to (`reqWrite`), or `None` when the method
/// carries no body.
///
/// The gate is upstream's: `util.hasRequestBody(req) ? getWriteFilePath(…) :
/// null` (`_original/lib/inspectors/req.js:582-584`). Without it a `GET` through
/// a `reqWrite://` rule created an empty file, which reads as "the capture
/// worked and the request had no body" rather than "there was never a body to
/// capture".
pub fn req_write_path(resolved: &Resolved, method: &str) -> Option<String> {
    method_allows_body(method).then(|| resolved.value("reqWrite"))?.map(str::to_string)
}

/// File to write the response body to (`resWrite`), named for the status.
pub fn res_write_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved.value("resWrite").map(|f| writer_file(f, status))
}

/// File to write the raw request (head + body) to (`reqWriteRaw`).
///
/// Not gated on the method: the head is worth dumping whether or not a body
/// followed it, and upstream does not gate it either (`req.js:586`).
pub fn req_write_raw_path(resolved: &Resolved) -> Option<String> {
    resolved.value("reqWriteRaw").map(str::to_string)
}

/// File to write the raw response (head + body) to (`resWriteRaw`), named for
/// the status.
pub fn res_write_raw_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved.value("resWriteRaw").map(|f| writer_file(f, status))
}

/// `getWriterFile` (`_original/lib/inspectors/res.js:147-153`): a response that
/// is not a `200` is written to `<file>.<status>` instead.
///
/// The point is that a rule left running collects its failures separately —
/// a run of 502s lands in `dump.502` rather than overwriting the good capture
/// in `dump`, which is exactly when you want both.
fn writer_file(file: &str, status: u16) -> String {
    match status {
        200 => file.to_string(),
        other => format!("{file}.{other}"),
    }
}

/// `enable://forceReqWrite` — write a dump file even though it already exists.
///
/// One flag for all four operators: upstream passes `isEnable(req,
/// 'forceReqWrite')` as the `force` argument on both the request side
/// (`_original/lib/inspectors/req.js:601`) and the response side
/// (`res.js:1304`), despite the name.
pub fn forces_write(resolved: &Resolved) -> bool {
    enabled_flags(resolved).contains("forceReqWrite")
        && !disabled_flags(resolved).contains("forceReqWrite")
}

/// How many bytes of a request body may be read into memory before the
/// operators that rewrite it give up and let it stream past.
///
/// whistle's `MAX_REQ_SIZE` is 2MB, raised to `BIG_MAX_REQ_SIZE` (16MB) by
/// `enable://reqMergeBigData` (`_original/lib/inspectors/req.js:19-20,:163`).
/// This port has no `config.strict`, so the 1MB strict variant has no spelling
/// here and the plain 2MB is the floor.
///
/// Upstream also raises it from its own settings (the `enableBigData` argument);
/// there is no such setting here, so the rule flag is the only way up — which is
/// the way a user would reach for anyway, since it is per-request.
pub fn req_body_limit(resolved: &Resolved) -> usize {
    /// `BIG_MAX_REQ_SIZE` (`req.js:20`).
    const BIG: usize = 16 * 1024 * 1024;
    // `isEnable` is the flag minus its cancellation, the same shape
    // [`forces_write`] uses (`_original/lib/util/index.js:676-679`).
    let on = enabled_flags(resolved).contains("reqMergeBigData")
        && !disabled_flags(resolved).contains("reqMergeBigData");
    match on {
        true => BIG,
        false => REQ_BODY_LIMIT,
    }
}

/// The bound when no rule has been resolved yet — whistle's `MAX_REQ_SIZE`
/// (`_original/lib/inspectors/req.js:19`).
///
/// The body-filter pass reads a request body *in order to decide which rules
/// apply*, so it cannot ask a rule how much to read: [`req_body_limit`]'s raised
/// bound is unavailable to it by construction. Upstream is in the same position
/// and answers the same way — `resolveBodyFilter` buffers a prefix and matches
/// on that.
pub const REQ_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// Build the response trailer headers from `trailers://` operators.
///
/// `trailers` is one of `parseRuleJson`'s arguments (`_original/lib/inspectors/res.js:845-855`),
/// so several lines fold into one map with the first line winning a contested
/// name, exactly as `resHeaders` does.
///
/// `delete://trailer.<name>` then removes one, and it applies *after* the
/// operators — upstream deletes from the merged map on the way out
/// (`delProps.trailers`, `_original/lib/inspectors/res.js:1275-1280`), so a
/// request carrying both spellings of a name ends up without it.
pub fn build_trailers(resolved: &Resolved) -> HeaderMap {
    let mut h = HeaderMap::new();
    // `disable://trailers` / `disable://trailer` cancel the whole trailer
    // section — the rule's *and* the origin's (`_original/lib/inspectors/res.js:
    // 1252-1260`, which returns before `addTrailers` is reached).
    if trailers_disabled(resolved) {
        return h;
    }
    for (name, values) in merge_header_ops(resolved, "trailers") {
        for (i, value) in values.iter().enumerate() {
            match i {
                0 => assign_header(&mut h, &name, value),
                _ => append_header(&mut h, &name, value),
            }
        }
    }
    // `headerReplace://trailer.x:…` rewrites a trailer, then the deletions run,
    // which is upstream's order on the way out (`res.js:1275-1281`).
    apply_header_replace(&mut h, resolved, HeaderScope::Trailer);
    for name in &Deletions::of(resolved, false).trailers {
        remove_header(&mut h, name);
    }
    h
}

/// `disable://trailers` / `disable://trailer` — send no trailer section at all.
///
/// Both spellings, and both cancel the origin's trailers as well as the rule's:
/// upstream's guard is on the way *out*, after the two have been merged
/// (`_original/lib/inspectors/res.js:1252-1260`).
pub fn trailers_disabled(resolved: &Resolved) -> bool {
    let dis = disabled_flags(resolved);
    dis.contains("trailers") || dis.contains("trailer")
}

/// `disable://trailerHeader` — send the trailers without announcing them.
///
/// A separate flag from [`trailers_disabled`], and it does something different:
/// upstream skips only `addTrailerNames`, which is what writes the `Trailer:`
/// header naming what is coming (`_original/lib/inspectors/res.js:1215-1223`).
/// The trailers themselves still go.
pub fn trailer_header_announced(resolved: &Resolved) -> bool {
    !disabled_flags(resolved).contains("trailerHeader")
}

/// Header names an HTTP trailer section may not carry (`ILLEGAL_TRAILERS`,
/// `_original/lib/util/common.js:34-53`).
///
/// The list is upstream's, verbatim and in its order. It is not decoration: a
/// `Content-Length` or `Transfer-Encoding` arriving after the body contradicts
/// the framing that just delivered it, and a `Set-Cookie` or `Authorization`
/// there is a credential a client is not required to look at.
const ILLEGAL_TRAILERS: &[&str] = &[
    "host",
    "transfer-encoding",
    "content-length",
    "cache-control",
    "te",
    "max-forwards",
    "authorization",
    "set-cookie",
    "content-encoding",
    "content-type",
    "content-range",
    "trailer",
    "connection",
    "upgrade",
    "http2-settings",
    "proxy-connection",
    "keep-alive",
];

/// `removeIllegalTrailers` (`_original/lib/util/common.js:410-414`), applied to
/// the merged map immediately before it goes on the wire (`res.js:1285`).
pub fn remove_illegal_trailers(trailers: &mut HeaderMap) {
    for name in ILLEGAL_TRAILERS {
        trailers.remove(*name);
    }
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
    /// Not one of `getContentType`'s classes. `handleReplace` substitutes the
    /// string `FORM` for a urlencoded **request** body before its gate
    /// (`_original/lib/inspectors/req.js:435`), which is the only reason
    /// `reqReplace://` reaches a form POST at all — `getContentType` puts
    /// `application/x-www-form-urlencoded` in no class, and the gate refuses
    /// anything unclassified. Never produced for a response.
    Form,
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

/// The class `reqReplace://` is gated on (`handleReplace`,
/// `_original/lib/inspectors/req.js:429-438`).
///
/// It is *not* the response gate with the request's content type substituted,
/// which is what this port had — and why `reqReplace://` was a silent no-op on
/// the commonest request body there is. Two things differ:
///
/// * a method that carries no body is refused before the type is looked at
///   (`hasRequestBody`, `common.js:1591-1604`);
/// * a urlencoded body is mapped to a class of its own — `type =
///   isUrlEncoded(req) ? 'FORM' : getContentType(type)` — because
///   `getContentType` puts `application/x-www-form-urlencoded` in no class at
///   all, and the next line refuses everything unclassified.
fn req_replace_class(ctx: ReqBodyCtx<'_>) -> Option<ResClass> {
    if !method_has_body(ctx.method) {
        return None;
    }
    let ct = ctx.content_type?;
    // `isUrlEncoded` is POST-only (`_original/lib/util/common.js:692-695`), so a
    // `PUT` carrying a form body takes the ordinary path and is refused.
    if ctx.method.eq_ignore_ascii_case("POST")
        && ct.to_ascii_lowercase().contains("application/x-www-form-urlencoded")
    {
        return Some(ResClass::Form);
    }
    res_class(ct)
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
    // A method that carries no body has nothing to buffer *for*: its injections
    // are dropped (see [`transform_req_body`]) and its rewrites have nothing to
    // rewrite, so buffering would cost a copy to reach the same empty body.
    if !method_allows_body(ctx.method) {
        return false;
    }
    body_ops_present(resolved, "req") || params_body_kind(resolved, ctx).is_some()
}

/// Whether a request with this method may carry a body at all
/// (`hasRequestBody`, `_original/lib/util/common.js:1591-1605`).
///
/// The list is upstream's, and it is about the *method*, not about whether this
/// particular request happens to have arrived with bytes: `GET`, `HEAD`,
/// `OPTIONS` and `CONNECT` are the four whistle refuses to give a body to.
///
/// The method compared is the one being **forwarded** — after `method://` — so
/// rewriting a `GET` into a `POST` makes the injection apply, which is the order
/// upstream reads it in too (`handleReq` runs after the method is set).
pub fn method_allows_body(method: &str) -> bool {
    !matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "CONNECT"
    )
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
    //
    // The method is the one gate. `GET`, `HEAD`, `OPTIONS` and `CONNECT` get no
    // body, so `reqBody`/`reqPrepend`/`reqAppend` are dropped rather than
    // applied (`delete data.top/bottom/body`,
    // `_original/lib/inspectors/req.js:116-120`) — handing a GET eight bytes of
    // payload is the kind of thing a CDN answers with a 400.
    //
    // Only the *injections* go. `reqReplace` and `delete://reqBody.x` rewrite a
    // body that is already there, and on these methods there is nothing there to
    // rewrite, so they are left to be no-ops of their own accord.
    let mut data = if method_allows_body(ctx.method) {
        let gate = InjectionGate::plain(resolved);
        let mut injection = Injection::default();
        collect_generic(&mut injection, &gate, "req");
        injection.apply(body.to_vec(), false)
    } else {
        body.to_vec()
    };
    if let Some(kind) = params_body_kind(resolved, ctx) {
        data = merge_params_into_body(data, resolved, &del, kind, ctx);
    }
    Bytes::from(apply_replace(
        data,
        resolved,
        "reqReplace",
        req_replace_class(ctx),
    ))
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
                        if let Ok(i) = key.parse::<usize>()
                            && i < list.len()
                        {
                            list.remove(i);
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
    if let (Some(s), Some(e)) = (text.find('{'), text.rfind('}'))
        && s < e
    {
        return Some((s, e + 1));
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

/// The `resReplace://` substitutions in force for a response of this content
/// type, in the order they apply.
///
/// The same list [`apply_replace`] walks, exposed for the body layer that runs
/// on a response still arriving ([`crate::proxy::restream`]). It carries the
/// content-type gate with it so the two paths cannot come to different answers
/// about whether the operator reaches this body at all: upstream refuses the
/// whole operator for a response with no `content-type` or an image one
/// (`handleReplace`, `_original/lib/inspectors/res.js:129-132`).
/// What the injecting operators mean for a body that is **still arriving**.
///
/// The buffered path reaches these bytes by concatenation, which needs an
/// ending. These three do not need one: `resPrepend://` goes before the first
/// byte, `resAppend://` after the last, and `resBody://` says there is no origin
/// body at all. See [`crate::proxy::body::surround`].
pub struct StreamInjection {
    /// `resPrepend://`, its lines already CRLF-joined.
    pub top: Vec<u8>,
    /// `resAppend://`, likewise. Never delivered on a stream that does not end,
    /// which is the honest answer rather than a missing feature: there is no
    /// "after" a body that never finishes.
    pub bottom: Vec<u8>,
    /// `resBody://` — the body *is* this, and the origin's is not waited for.
    pub replacement: Option<Vec<u8>>,
}

/// The injection for a response whose body is still arriving, or `None` when no
/// operator asks for one.
///
/// Only the generic `res*` family is collected. The typed families
/// (`htmlPrepend`, `jsAppend`, …) are absent because they are selected by the
/// response being HTML/JS/CSS, and a body that is still arriving here is an
/// event stream — none of those.
///
/// The gate is [`InjectionGate::plain`]: no doctype is stamped and nothing is
/// refused. Both follow from the response not being HTML — upstream stamps a
/// doctype only there, and its `allowInject` returns true whenever `isHtml` is
/// unset (`_original/lib/util/whistle-transform.js:80-83`). `safeHtml` and
/// `strictHtml` gate HTML injection specifically and so have nothing to say.
pub fn res_stream_injection(resolved: &Resolved) -> Option<StreamInjection> {
    let mut injection = Injection::default();
    collect_generic(&mut injection, &InjectionGate::plain(resolved), "res");
    let (mut top, mut bottom) = (Vec::new(), Vec::new());
    join_into(&mut top, std::mem::take(&mut injection.top));
    join_into(&mut bottom, std::mem::take(&mut injection.bottom));
    let replacement = injection.replaces_body.then(|| {
        let mut body = Vec::new();
        join_into(&mut body, std::mem::take(&mut injection.body));
        body
    });
    let empty = top.is_empty() && bottom.is_empty() && replacement.is_none();
    (!empty).then_some(StreamInjection {
        top,
        bottom,
        replacement,
    })
}

pub fn res_replace_pairs(resolved: &Resolved, content_type: Option<&str>) -> Vec<(String, String)> {
    let class = content_type.and_then(res_class);
    if matches!(class, None | Some(ResClass::Img)) {
        return Vec::new();
    }
    merge_rule_maps(resolved, "resReplace")
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
    if spec.starts_with('{')
        && let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(spec)
    {
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
    // Expanded by hand rather than through the `regex` crate's own replacement
    // syntax: `$$1` has to percent-encode the group, and no replacement string
    // can express that. See [`crate::rules::replace::expand`].
    let expand = |caps: &regex::Captures<'_>| {
        let groups: Vec<&str> = (0..=9).map(|n| caps.get(n).map_or("", |m| m.as_str())).collect();
        crate::rules::replace::expand(value, &groups)
    };
    match flags.contains('g') {
        true => re.replace_all(text, expand).into_owned(),
        false => re.replace(text, expand).into_owned(),
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

/// Substitute a `pattern` → `replacement` list in `text`, in order.
fn apply_str_replace(text: &str, pairs: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (pattern, value) in pairs {
        out = replace_once_or_all(&out, pattern, value);
    }
    out
}

/// The `delete://` keys that address the request's **URL** rather than its
/// headers (`parseDelQuery`, `_original/lib/util/index.js:2674-2699`).
///
/// These live here rather than in [`Deletions`] because upstream applies them
/// from the URL-rewriting pass, not the header pass: the path indices go to
/// `parsePathReplace` alongside `urlReplace://` and the query names to
/// `deleteQuery` after it (`_original/lib/inspectors/req.js:557,562-570`).
#[derive(Default)]
struct DelQuery {
    /// `delete://query.<name>` — query-string names to drop. Also spelled
    /// `params.<name>` and `url[.]Param[s].<name>`.
    names: Vec<String>,
    /// The same words with nothing after them: drop the query string outright,
    /// `?` and all.
    clear: bool,
    /// `delete://pathname…`, absent when no key named a segment.
    paths: Option<DelPaths>,
}

/// Which path segments `delete://pathname…` names.
#[derive(Default)]
struct DelPaths {
    /// A bare `delete://pathname`: the whole path goes, the query stays.
    all: bool,
    /// `delete://pathname.last` — the final segment, and a trailing slash left
    /// where it was.
    last: bool,
    /// Segment indices, counted from the end when negative. `first` is `0`.
    indices: Vec<i64>,
}

/// What one `pathname…` key names.
enum PathKey {
    All,
    Last,
    Index(i64),
}

impl DelQuery {
    /// Classify every `delete://` key that addresses the URL.
    fn of(resolved: &Resolved) -> DelQuery {
        let mut del = DelQuery::default();
        for value in collect_values(resolved, "delete") {
            // Same split as [`Deletions::of`] — `parseProps` takes `|` and `&`.
            for key in value.split(['|', '&']) {
                let key = key.trim();
                match strip_query_scope(key) {
                    Some(Some(name)) => del.names.push(name.to_string()),
                    Some(None) => del.clear = true,
                    None => match strip_pathname_scope(key) {
                        Some(PathKey::All) => del.paths.get_or_insert_default().all = true,
                        Some(PathKey::Last) => del.paths.get_or_insert_default().last = true,
                        Some(PathKey::Index(i)) => {
                            del.paths.get_or_insert_default().indices.push(i)
                        }
                        None => {}
                    },
                }
            }
        }
        del
    }
}

/// Strip whistle's query-string prefix — `query`, `params` or `url[.]Param[s]`,
/// all case-insensitive (`QUERY_RE` / `QUERY_STRING_RE`,
/// `_original/lib/util/index.js:2670-2671`).
///
/// `Some(None)` is the bare form (drop the whole query string), `Some(Some(n))`
/// names one parameter.
fn strip_query_scope(key: &str) -> Option<Option<&str>> {
    for prefix in ["query", "params", "urlParams", "urlParam", "url.Params", "url.Param"] {
        let Some(head) = key.get(..prefix.len()).filter(|h| h.eq_ignore_ascii_case(prefix)) else {
            continue;
        };
        let rest = &key[head.len()..];
        if rest.is_empty() {
            return Some(None);
        }
        if let Some(name) = rest.strip_prefix('.').filter(|n| !n.is_empty()) {
            return Some(Some(name));
        }
    }
    None
}

/// Match `PATH_INDEX_RE` (`_original/lib/util/index.js:2672`).
///
/// The dot before the index is optional in the regex, so `pathname-1` names the
/// same segment as `pathname.-1`, and `pathnamelast` the same as
/// `pathname.last`. A trailing dot with nothing after it matches neither branch
/// and is ignored, exactly as the regex ignores it.
///
/// `first`/`last` are matched **case-sensitively** even though the regex is
/// not. That is upstream's, not an oversight here: the regex accepts
/// `pathname.LAST`, but `parseDelQuery` then keys the map on the *matched
/// spelling* and `parsePathReplace` looks up the literal `last` and coerces
/// every other key with `+key` — `+'LAST'` is `NaN`, so the key is silently
/// dropped (`util/index.js:2688,1037-1047`). Only the word `pathname` itself is
/// case-insensitive all the way through.
fn strip_pathname_scope(key: &str) -> Option<PathKey> {
    let head = key.get(.."pathname".len()).filter(|h| h.eq_ignore_ascii_case("pathname"))?;
    let rest = &key[head.len()..];
    if rest.is_empty() {
        return Some(PathKey::All);
    }
    let idx = rest.strip_prefix('.').unwrap_or(rest);
    if idx == "first" {
        return Some(PathKey::Index(0));
    }
    if idx == "last" {
        return Some(PathKey::Last);
    }
    // `-?\d+`: a leading `+` is not one of the shapes upstream accepts, and
    // Rust's integer parser would take it.
    (!idx.starts_with('+'))
        .then(|| idx.parse::<i64>().ok())
        .flatten()
        .map(PathKey::Index)
}

/// `delete://pathname…` — drop path segments (`parsePathReplace`'s `delPaths`
/// arm, `_original/lib/util/index.js:1023-1058`).
///
/// Segments are counted in the path *without* its leading slash — the same
/// slice `urlReplace://` substitutes into — so `pathname.0` names `a` in
/// `/a/b/c`. The query string is split off first and put back untouched.
fn delete_path_segments(path: &str, del: &DelPaths) -> String {
    let (head, rest) = match path.strip_prefix('/') {
        Some(rest) => ("/", rest),
        None => ("", path),
    };
    let (cur, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // `if (curPath)`: a URL that is nothing but a query string has no segment to
    // name, and upstream leaves it alone.
    if cur.is_empty() {
        return path.to_string();
    }
    if del.all {
        // Deliberate divergence: upstream assigns the query to `curPath` and
        // then appends it again two lines later (`util/index.js:1033,1057`), so
        // a bare `delete://pathname` on `/a?x=1` produces `/?x=1?x=1`. That is a
        // malformed request line no origin parses; the query goes on once here.
        return format!("{head}{query}");
    }
    let mut segs: Vec<Option<&str>> = cur.split('/').map(Some).collect();
    let len = segs.len() as i64;
    let mut indices = del.indices.clone();
    if del.last {
        indices.push(len - 1);
    }
    for i in indices {
        let i = if i < 0 { len + i } else { i };
        if (0..len).contains(&i) {
            segs[i as usize] = None;
        }
    }
    let mut kept: Vec<&str> = segs.into_iter().flatten().collect();
    // `pathname.last` leaves a trailing slash where the segment was: upstream
    // pushes an empty segment back when the new last one is non-empty
    // (`util/index.js:1051-1053`). `pathname.-1` does not — the two spellings
    // name the same segment and disagree about the slash.
    if del.last && kept.last().is_some_and(|s| !s.is_empty()) {
        kept.push("");
    }
    format!("{head}{}{query}", kept.join("/"))
}

/// `deleteQuery` (`_original/lib/util/index.js:2701-2721`): drop the named
/// pairs from the query string, or all of it when `clear`.
///
/// Names are compared raw, before any percent-decoding, because that is what
/// upstream compares — `delete://query.a%20b` names the parameter spelled that
/// way on the wire.
fn delete_query(path: &str, names: &[String], clear: bool) -> String {
    let Some(i) = path.find('?') else {
        return path.to_string();
    };
    if clear {
        return path[..i].to_string();
    }
    let query = &path[i + 1..];
    if query.is_empty() {
        return path.to_string();
    }
    let kept = query
        .split('&')
        .filter(|item| {
            let name = item.split_once('=').map_or(*item, |(k, _)| k);
            !names.iter().any(|n| n == name)
        })
        .collect::<Vec<_>>()
        .join("&");
    // The `?` goes too when nothing survives.
    match kept.is_empty() {
        true => path[..i].to_string(),
        false => format!("{}?{kept}", &path[..i]),
    }
}

/// Rewrite the request path+query per `urlReplace`, `params`, `urlParams`, and
/// the `delete://` keys that name a query parameter or a path segment.
pub fn rewrite_path(path: &str, resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> String {
    let mut p = path.to_string();
    let del = DelQuery::of(resolved);
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
    // `urlReplace://` runs **after** the params merge, which is upstream's order:
    // `handleParams` writes the query first (`req.js:561`) and `parsePathReplace`
    // rewrites the URL that results (`:569`). Reversed, a `urlReplace` pattern
    // aimed at what a `params://` on the same line had just written never saw it.
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
    // The path deletions are `parsePathReplace`'s second half, so they run in
    // the same pass as `urlReplace://` and after it
    // (`_original/lib/util/index.js:1023-1058`).
    if let Some(paths) = &del.paths {
        p = delete_path_segments(&p, paths);
    }
    // `deleteQuery` runs last, over whatever the query string has become
    // (`_original/lib/inspectors/req.js:570`) — so a name it drops is dropped
    // even when a `params://` on the same line had just written it.
    if del.clear || !del.names.is_empty() {
        p = delete_query(&p, &del.names, del.clear);
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
    if value.starts_with('{')
        && let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
    {
        return map.into_iter().collect();
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
fn merge_cookie_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, CookieValue)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_cookie_ops(&op.value)),
    )
}

/// What one `reqCookies`/`resCookies` entry says a cookie should be.
#[derive(Clone, Debug, PartialEq)]
enum CookieValue {
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
    fn plain(&self) -> String {
        match self {
            CookieValue::Plain(v) => v.clone(),
            CookieValue::Attrs(map) => json_attr(map, &["value", "Value"])
                .map(str_of_json)
                .unwrap_or_default(),
            CookieValue::List(_) => String::new(),
        }
    }

    /// Parse one JSON value into a cookie entry.
    fn of_json(v: serde_json::Value) -> CookieValue {
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
/// query string, so `reqCookies://a=1&b=2` is two cookies. A name with no `=`
/// gets an **empty value** — it does not delete the cookie; that is
/// `delete://reqCookies.<name>`.
fn parse_cookie_ops(value: &str) -> Vec<(String, CookieValue)> {
    let value = value.trim();
    if value.starts_with('{')
        && let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
    {
        return map
            .into_iter()
            .map(|(k, v)| (k, CookieValue::of_json(v)))
            .collect();
    }
    value
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), CookieValue::Plain(v.to_string())),
            None => (pair.trim().to_string(), CookieValue::Plain(String::new())),
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// A JSON value as a cookie would carry it: a string unquoted, `null` empty,
/// anything else in its JSON spelling — which is what `String(x)` gives too.
fn str_of_json(v: &serde_json::Value) -> String {
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
fn json_attr<'a>(
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
fn json_flag(map: &serde_json::Map<String, serde_json::Value>, names: &[&str]) -> bool {
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
const EXPIRED_MAX_AGE: i64 = -123456;

/// Render one `Set-Cookie` value (`getCookieItem`,
/// `_original/lib/util/index.js:3093-3117`).
///
/// Attribute order is upstream's, not the RFC's suggestion: value, `Expires`,
/// `Max-Age`, `Secure`, `HttpOnly`, `Partitioned`, `Path`, `Domain`, `SameSite`.
fn cookie_item(name: &str, value: &CookieValue) -> String {
    let map = match value {
        CookieValue::Plain(v) => return format!("{name}={}", escape_cookie(v, false)),
        CookieValue::Attrs(map) => map,
        // A nested array. [`cookie_lines`] flattens one level, so this is the
        // second — upstream reaches `getCookieItem` with the array itself, where
        // `typeof array == 'object'` sends it down the attribute path and every
        // lookup on it misses. The result is a bare `name=`.
        CookieValue::List(_) => return format!("{name}="),
    };
    let mut attrs = vec![format!(
        "{name}={}",
        escape_cookie(&value.plain(), false)
    )];
    // `parseInt` on a non-number yields NaN and the pair is skipped, so a
    // `maxAge` that is not a number leaves the cookie a session cookie.
    if let Some(max_age) = json_attr(map, &["maxAge", "maxage", "MaxAge", "Max-Age", "max-age"])
        .and_then(parse_int_loosely)
    {
        attrs.push(format!("Expires={}", http_date(max_age * 1000)));
        // The expiring form says `Max-Age=0` rather than the sentinel: a
        // negative `Max-Age` is legal but "0" is what every browser acts on.
        let written = if max_age == EXPIRED_MAX_AGE { 0 } else { max_age };
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
fn parse_int_loosely(v: &serde_json::Value) -> Option<i64> {
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
/// on `.example.com` rather than on the host itself. It is `Some` only for a
/// request that arrived through an intercepted tunnel: upstream reads
/// `req._w2hostname`, which is set on the tunnel path alone
/// (`_original/lib/https/index.js:707`), so a plain forward-proxy request gets
/// the two host-scoped entries and no more.
fn expiring_cookies(names: &[String], host: Option<&str>) -> Vec<(String, CookieValue)> {
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
fn parent_domain(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    match labels.len() {
        0..=2 => None,
        3 => Some(format!(".{}", labels[1..].join("."))),
        _ => Some(labels[1..].join(".")),
    }
}

/// Emit `Set-Cookie` headers for `resCookies` operators, **replacing** any the
/// response already sent under the same name rather than adding a second one.
fn apply_res_cookies(
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
        // Only a tunnelled request has a hostname here; see `expiring_cookies`.
        let host = info.filter(|i| i.from.tunnel).map(|i| i.host.as_str());
        for (name, value) in expiring_cookies(&del.cookies, host) {
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
            CookieValue::List(items) => {
                items.iter().map(|v| cookie_item(&name, v)).collect()
            }
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
    let mut ops = merge_header_ops(resolved, protocol);
    // `set-cookie` is not assigned like the others: upstream lifts it out of
    // `data.headers` and *merges* it with what the response already sent
    // (`setCookies`, `_original/lib/inspectors/res.js:89-122`, run at `:926`
    // just before the `extend`), then deletes the key so the extend cannot
    // clobber the result. Overwriting instead dropped every other cookie the
    // origin set — the session cookie next to the one the rule named.
    if protocol == "resHeaders"
        && let Some(i) = ops.iter().position(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
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
fn merge_set_cookies(headers: &mut HeaderMap, values: &HeaderValues) -> bool {
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
fn append_header(headers: &mut HeaderMap, name: &str, value: &str) {
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
enum HeaderValues {
    One(String),
    /// The JSON array spelling, which Node writes as one header line per
    /// element.
    Many(Vec<String>),
}

impl HeaderValues {
    /// Add another value under the same name, promoting a single one to a list.
    fn push(&mut self, value: String) {
        match self {
            HeaderValues::One(first) => {
                *self = HeaderValues::Many(vec![std::mem::take(first), value]);
            }
            HeaderValues::Many(all) => all.push(value),
        }
    }

    fn iter(&self) -> std::slice::Iter<'_, String> {
        match self {
            HeaderValues::One(s) => std::slice::from_ref(s).iter(),
            HeaderValues::Many(items) => items.iter(),
        }
    }
}

/// Collapse every line of a header protocol into one ordered `name` → `value`
/// map, first line winning a contested name.
fn merge_header_ops(resolved: &Resolved, protocol: &str) -> Vec<(String, HeaderValues)> {
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
///
/// A value is a *list* because the JSON spelling may give one: upstream assigns
/// the array straight onto the header map, and Node then writes one header line
/// per element. Every other spelling produces a list of one.
fn parse_header_pairs(value: &str) -> Vec<(String, HeaderValues)> {
    let value = value.trim();
    if value.starts_with('{')
        && let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(value)
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
    if value.contains('=') {
        // A name repeated in one value is a *list*, not a contest: Node's
        // `querystring.parse("a=1&a=2")` yields `{a: ["1","2"]}`, whistle
        // assigns that array onto the header map, and Node writes one header
        // line per element. Folding to the last value here sent one header
        // where whistle sends two, which for `set-cookie` or `accept` is the
        // difference between the rule working and half of it vanishing.
        //
        // Names are trimmed, deliberately unlike upstream: `qs.parse` leaves
        // `x-t = v` with the name `"x-t "`, and a header name with a trailing
        // space is not a valid token — hyper rejects it, so faithfully keeping
        // the space would turn the operator into a silent no-op. Upstream's own
        // `setHeader` throws on it.
        let mut out: Vec<(String, HeaderValues)> = Vec::new();
        for (name, val) in value.split('&').filter_map(|pair| pair.split_once('=')) {
            let (name, val) = (name.trim().to_string(), val.trim().to_string());
            match out.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(val),
                None => out.push((name, HeaderValues::One(val))),
            }
        }
        return out;
    }
    match value.split_once(':') {
        Some((name, val)) => vec![(
            name.trim().to_string(),
            HeaderValues::One(val.trim().to_string()),
        )],
        None => Vec::new(),
    }
}

/// One element of a JSON header array as it reaches the wire: a string as
/// itself, anything else as JS would stringify it into a header slot.
fn json_header_value(v: &serde_json::Value) -> String {
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
fn assign_header(headers: &mut HeaderMap, name: &str, value: &str) {
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
        rt().block_on(resolve_target(info, &crate::proxy::dest::Destination::of(info, resolved), resolved))
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

    /// A method that carries no body is not given one
    /// (`hasRequestBody` → `delete data.top/bottom/body`,
    /// `_original/lib/inspectors/req.js:116-120`).
    ///
    /// Measured before the fix: a `GET` through a `reqBody://INJECTED` rule
    /// reached the origin as `{"method":"GET","len":"8","body":"INJECTED"}`.
    /// A GET with a payload is what a CDN answers with a 400.
    #[test]
    fn a_bodyless_method_is_not_given_a_body() {
        let resolved = resolve(
            "example.com reqBody://INJECTED\n",
            "http://example.com/",
        );
        let sent = |method: &str| {
            let ctx = ReqBodyCtx { method, content_type: None };
            let out = transform_req_body(Bytes::new(), &resolved, ctx);
            String::from_utf8(out.to_vec()).expect("utf-8")
        };

        // The four upstream refuses, in the spellings a client might send.
        for method in ["GET", "HEAD", "OPTIONS", "CONNECT", "get", " Head "] {
            assert_eq!(sent(method), "", "{method} must carry no body");
        }
        // …and the ones that do take one.
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(sent(method), "INJECTED", "{method} takes the injection");
        }

        // Nothing is buffered for a method that will discard it anyway.
        let get = ReqBodyCtx { method: "GET", content_type: None };
        let post = ReqBodyCtx { method: "POST", content_type: None };
        assert!(!wants_req_body(&resolved, get));
        assert!(wants_req_body(&resolved, post));
    }

    /// The gate reads the method being **forwarded**, so `method://post` on a
    /// GET restores the injection — upstream sets the method before
    /// `handleReq` runs.
    #[test]
    fn rewriting_the_method_decides_whether_a_body_applies() {
        let resolved = resolve(
            "example.com reqBody://INJECTED method://post\n",
            "http://example.com/",
        );
        // The caller passes the rewritten method, which is what `serve` does.
        let ctx = ReqBodyCtx { method: "POST", content_type: None };
        assert!(wants_req_body(&resolved, ctx));
        assert_eq!(
            &transform_req_body(Bytes::new(), &resolved, ctx)[..],
            b"INJECTED"
        );
        assert!(method_allows_body("POST") && !method_allows_body("GET"));
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

        // `\$1` escapes the reference, so the literal `$1` survives.
        let esc = resolve(
            "example.com/x resReplace:///(\\w+)@/g=\\$1-$1\n",
            "http://example.com/x",
        );
        let out = transform_res_body(Bytes::from_static(b"a@"), &esc, Some("text/plain"));
        assert_eq!(&out[..], b"$1-a");

        let all = resolve("example.com/x resReplace:///.*/g=ONLY\n", "http://example.com/x");
        let out = transform_res_body(Bytes::from_static(b"whatever"), &all, Some("text/plain"));
        assert_eq!(&out[..], b"ONLY", "`/.*/ ` replaces the body exactly once");
    }

    /// The `$$`-prefixed spelling of a reference inserts the group
    /// **percent-encoded** (`encode = $2[1] === '$'`,
    /// `_original/lib/util/replace-pattern-transform.js:78-88`). Previously the
    /// whole form was silently literal, so a rule asking for an encoded group
    /// got the characters `$$1` in its output.
    #[test]
    fn an_encoding_back_reference_percent_encodes_the_group() {
        let body = |rule: &str, input: &'static str| {
            let resolved = resolve(
                &format!("example.com/x resReplace://{rule}\n"),
                "http://example.com/x",
            );
            let out =
                transform_res_body(Bytes::from_static(input.as_bytes()), &resolved, Some("text/plain"));
            String::from_utf8(out.to_vec()).expect("utf-8")
        };

        // A rule value cannot carry a space — the line parser splits on
        // whitespace — so the space under test lives in the *input*.
        //
        // `$$1` encodes; a plain `$1` on the same line does not.
        assert_eq!(body("/(.+)/=[$$1][$1]", "a b"), "[a%20b][a b]");
        // `$$&` (the whole match, encoded) cannot travel through a rule value:
        // `&` separates the pairs of a `resReplace`. Same expansion, called
        // where the rule layer would have called it.
        assert_eq!(replace_once_or_all("a b", "/a.b/", "$$&"), "a%20b");
        // Reserved characters an encoded group is there to protect.
        assert_eq!(body("/(.+)/=$$1", "x/y?z=1&w"), "x%2Fy%3Fz%3D1%26w");
        // Non-ASCII goes out as UTF-8 percent-escapes, as in JavaScript.
        assert_eq!(body("/(.+)/=$$1", "中"), "%E4%B8%AD");
        // An empty group encodes to nothing rather than to a stray `%`.
        assert_eq!(body("/x(z?)/=[$$1]", "x"), "[]");
        // `\$$1` escapes the whole reference, `\\$$1` keeps one backslash
        // and still encodes.
        assert_eq!(body("/(.+)/=\\$$1", "a b"), "$$1");
        assert_eq!(body("/(.+)/=\\\\$$1", "a b"), "\\a%20b");
        // A `$b`-prefixed reference names a value list this port has no
        // counterpart for, so it is left exactly as written.
        assert_eq!(body("/(a)/=[$b1]", "a"), "[$b1]");
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

    /// `auth://` takes three shapes, not one (`getAuthByRules`,
    /// `_original/lib/util/index.js:3645-3662`, `getAuthBasic` at `:3668-3685`,
    /// `handleAuth` at `req.js:150-155`).
    ///
    /// This port understood only `user:pass` and base64-encoded everything else
    /// whole, so `auth://{"username":"u","password":"p"}` authenticated as the
    /// user `{"username"` with the password `"u","password":"p"}` — a 401 that
    /// reads as the rule never having run. The `"proxy":true` field, which
    /// moves the credentials to `Proxy-Authorization`, had nowhere to land at
    /// all.
    ///
    /// The expectations are upstream's own: `getAuthByRules`, `formatAuth`,
    /// `getAuthBasic` and `parseQuery` were lifted verbatim and run over these
    /// inputs.
    #[test]
    fn auth_takes_a_json_object_and_a_query_string_too() {
        let sent = |value: &str| {
            let resolved = resolve(
                &format!("example.com auth://{value}\n"),
                "http://example.com/",
            );
            let mut parts = req_parts(&[]);
            apply_request(&mut parts, &resolved);
            for name in ["authorization", "proxy-authorization"] {
                if let Some(v) = parts.headers.get(name) {
                    return Some(format!("{name}: {}", v.to_str().unwrap()));
                }
            }
            None
        };
        let auth = |v: &str| Some(format!("authorization: {v}"));
        let proxy = |v: &str| Some(format!("proxy-authorization: {v}"));

        // ── `user:pass`, which already worked ──
        assert_eq!(sent("user:pass"), auth("Basic dXNlcjpwYXNz"));
        // Only the *first* colon splits.
        assert_eq!(sent("u:p:q"), auth("Basic dTpwOnE="));
        // A username with no password carries no colon either.
        assert_eq!(sent("user"), auth("Basic dXNlcg=="));
        assert_eq!(sent("user:"), auth("Basic dXNlcjo="));
        assert_eq!(sent(":pass"), auth("Basic OnBhc3M="));

        // ── the JSON object ──
        assert_eq!(sent(r#"{"username":"u","password":"p"}"#), auth("Basic dTpw"));
        // `"proxy":true` re-addresses the credentials at the proxy.
        assert_eq!(
            sent(r#"{"username":"u","password":"p","proxy":true}"#),
            proxy("Basic dTpw")
        );
        assert_eq!(sent(r#"{"username":"u"}"#), auth("Basic dQ=="));
        // A password alone still gets its colon, so the server sees two fields.
        assert_eq!(sent(r#"{"password":"p"}"#), auth("Basic OnA="));
        assert_eq!(sent(r#"{"username":null,"password":"p"}"#), auth("Basic OnA="));
        // Non-strings are stringified (`String(username)`).
        assert_eq!(sent(r#"{"username":123,"password":true}"#), auth("Basic MTIzOnRydWU="));
        // Naming neither half sends nothing — and so does a JSON object
        // upstream cannot parse, which it turns into an empty one.
        assert_eq!(sent("{}"), None);
        // (A value with a space in it would be two tokens on the line, so the
        // unparseable case is spelled without one.)
        assert_eq!(sent("{not-json}"), None);
        // `!!obj.proxy`, so the JSON `false` really is false.
        assert_eq!(sent(r#"{"username":"u","proxy":false}"#), auth("Basic dQ=="));
        // …but the *string* `"false"` is not.
        assert_eq!(sent(r#"{"username":"u","proxy":"false"}"#), proxy("Basic dQ=="));

        // ── `username=…&password=…` ──
        assert_eq!(sent("username=u&password=p"), auth("Basic dTpw"));
        assert_eq!(sent("username=u"), auth("Basic dQ=="));
        assert_eq!(sent("password=p"), auth("Basic OnA="));
        assert_eq!(sent("username=u&password=p&proxy=1"), proxy("Basic dTpw"));
        // Every query value is a non-empty string, so `proxy=false` is **true**
        // here. Use the JSON spelling when the answer is no.
        assert_eq!(sent("username=u&password=p&proxy=false"), proxy("Basic dTpw"));
        // Values are taken raw: `parseQuery` is given the escaping decoder, so
        // a `%2F` reaches the server as `%2F` and a `+` stays a `+`.
        assert_eq!(sent("username=u&password=p%2Fx"), auth("Basic dTpwJTJGeA=="));
        assert_eq!(sent("username=a+b&password=p"), auth("Basic YStiOnA="));
        // Only the first `=` splits a pair.
        assert_eq!(sent("username=u&password=a=b"), auth("Basic dTphPWI="));
        assert_eq!(sent("username=u&password="), auth("Basic dTo="));
        // `AUTH_RE` is anchored *and* case-sensitive, so this is not the query
        // form at all — it falls through to the colon split and is sent whole.
        assert_eq!(
            sent("Username=u&password=p"),
            auth("Basic VXNlcm5hbWU9dSZwYXNzd29yZD1w")
        );

        // Deliberate divergence: upstream reads a value containing a slash as a
        // *file reference* and sends nothing when it cannot (`SLASH_RE`,
        // `util/index.js:3654-3656`). With no rule-value loader here, splitting
        // on the colon is what a password with a slash in it needs.
        assert_eq!(sent("u:pa/ss"), auth("Basic dTpwYS9zcw=="));
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
        apply_deletes(&mut h, &Deletions::of(&resolved, true), true);
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

    /// `headerReplace://` is read as JSON **or** as a query string, and the
    /// second is the shorter spelling people actually write. This port took
    /// only the first, so `headerReplace://resH.x-a:/yes/=no` parsed, matched
    /// and rewrote nothing.
    ///
    /// Found by putting the same rule through real whistle and through this
    /// port and comparing the answers — see the differential bench in the
    /// commit that added it.
    #[test]
    fn header_replace_reads_the_query_string_spelling_too() {
        let replaced = |rule: &str| {
            let resolved = resolve(
                &format!("example.com headerReplace://{rule}\n"),
                "http://example.com/",
            );
            let mut h = HeaderMap::new();
            h.insert("x-a", "yes".parse().unwrap());
            h.insert("x-b", "keep".parse().unwrap());
            apply_header_replace(&mut h, &resolved, HeaderScope::Response);
            h.get("x-a").map(|v| v.to_str().unwrap().to_string())
        };
        // The two spellings mean the same thing.
        assert_eq!(replaced("resH.x-a:/yes/=no"), Some("no".to_string()));
        assert_eq!(replaced(r#"{"resH.x-a:/yes/":"no"}"#), Some("no".to_string()));
        // `&` separates entries and the *first* `=` splits one — a pattern may
        // contain `/` and `:` but the value starts after the first `=`.
        assert_eq!(replaced("resH.x-b:/keep/=x&resH.x-a:/yes/=no"), Some("no".to_string()));
        // A literal pattern, not a regexp, in the same spelling.
        assert_eq!(replaced("resH.x-a:yes=no"), Some("no".to_string()));
        // Scope inheritance still works across the query-string form: the
        // second key names no scope, so it reuses `x-a`.
        assert_eq!(replaced("resH.x-a:/nope/=x&:/yes/=no"), Some("no".to_string()));
    }

    /// The form the documentation leads with — several `pattern=value` pairs on
    /// one header (`res.header-name:p1=v1&p2=v2`,
    /// <https://wproxy.org/docs/rules/headerReplace.html>).
    ///
    /// The second pair carries **no colon at all**, and upstream's
    /// `key.substring(index + 1)` with `index === -1` makes the whole key the
    /// pattern. This port required a colon and dropped the pair — so only the
    /// first of the documented pairs applied. The earlier test here happened to
    /// write the second pattern as `:/yes/`, with a colon, and walked straight
    /// past the bug.
    #[test]
    fn several_patterns_may_share_one_header() {
        let replaced = |rule: &str| {
            let resolved = resolve(
                &format!("example.com headerReplace://{rule}\n"),
                "http://example.com/",
            );
            let mut h = HeaderMap::new();
            h.insert("x-mark", "html-and-more".parse().unwrap());
            apply_header_replace(&mut h, &resolved, HeaderScope::Response);
            h.get("x-mark").map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(replaced("res.x-mark:html=X&more=Y"), Some("X-and-Y".to_string()));
        // Three of them, and a regexp among the bare ones.
        assert_eq!(
            replaced("res.x-mark:html=X&/and/=AND&more=Y"),
            Some("X-AND-Y".to_string())
        );
        // A *scoped* key with no colon has an empty name and is dropped, which
        // is the case the colon check was written for.
        assert_eq!(replaced("res.x-mark"), Some("html-and-more".to_string()));
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
            apply_header_replace(&mut h, &resolved, HeaderScope::Response);
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

    /// An unscoped key inherits the previous key's scope **and its header
    /// name**, keeping only its own pattern — upstream nulls `name` when a key
    /// names a scope and otherwise leaves it standing
    /// (`parseHeaderReplace`, `_original/lib/util/index.js:2214-2233`). Two
    /// substitutions on one header therefore need only name it once.
    #[test]
    fn an_unscoped_header_replace_key_inherits_the_previous_one() {
        let replaced = |rule: &str, value: &str| {
            let resolved = resolve(
                &format!("example.com headerReplace://{rule}\n"),
                "http://example.com/",
            );
            let mut h = HeaderMap::new();
            h.insert("x-foo", value.parse().unwrap());
            apply_header_replace(&mut h, &resolved, HeaderScope::Response);
            h.get("x-foo").map(|v| v.to_str().unwrap().to_string())
        };

        // Both entries land on `x-foo`: the second names no header at all.
        assert_eq!(
            replaced(r#"{"res.x-foo:a":"1",":b":"2"}"#, "ab"),
            Some("12".to_string())
        );
        // A leading unscoped key has nothing to inherit and is dropped.
        assert_eq!(replaced(r#"{":a":"1"}"#, "ab"), Some("ab".to_string()));
        // The inherited scope is the *previous* one, so a `req.` key in between
        // takes the following unscoped key with it — away from this side.
        assert_eq!(
            replaced(r#"{"res.x-foo:a":"1","req.x-foo:b":"2",":a":"9"}"#, "aa"),
            Some("11".to_string()),
            "the trailing key inherited `req` and must not touch the response"
        );
    }

    /// `enable://gzip|br|deflate` forces the response's outgoing coding, with
    /// upstream's `br` > `gzip` > `deflate` precedence (`getEnableEncoding`,
    /// `_original/lib/util/index.js:1534-1548`).
    #[test]
    fn forced_encoding_follows_upstream_precedence() {
        use super::super::coding::Coding;
        let forced = |rule: &str| {
            forced_encoding(&resolve(&format!("example.com {rule}\n"), "http://example.com/"))
        };
        assert_eq!(forced("host://1.1.1.1"), None);
        assert_eq!(forced("enable://gzip"), Some(Coding::Gzip));
        assert_eq!(forced("enable://deflate"), Some(Coding::Deflate));
        assert_eq!(forced("enable://br"), Some(Coding::Brotli));
        // br wins over gzip wins over deflate.
        assert_eq!(forced("enable://gzip|deflate"), Some(Coding::Gzip));
        assert_eq!(forced("enable://br|gzip|deflate"), Some(Coding::Brotli));
    }

    /// `enable://showHost` reports the address the request actually reached
    /// (`req.hostIp || LOCALHOST`, `_original/lib/inspectors/res.js:1197-1199`).
    /// Previously the flag was inert.
    #[test]
    fn enable_show_host_reports_the_address_reached() {
        let header = |rules: &str, server_ip: Option<&str>| {
            let resolved = resolve(rules, "http://example.com/");
            let mut info = build_req_info(
                "GET",
                "http",
                "example.com",
                80,
                "/",
                &HeaderMap::new(),
                None,
            );
            info.res = Some(build_res_info(
                200,
                &HeaderMap::new(),
                server_ip.map(str::to_string),
                Some(80),
            ));
            let mut parts = res_parts(&[]);
            apply_response_for(&mut parts, &resolved, Some(&info));
            parts.headers.get("x-host-ip").map(|v| v.to_str().unwrap().to_string())
        };

        assert_eq!(
            header("example.com enable://showHost\n", Some("93.184.216.34")),
            Some("93.184.216.34".to_string())
        );
        // No address — nothing connected — falls back to whistle's own literal
        // rather than omitting the header the rule asked for.
        assert_eq!(
            header("example.com enable://showHost\n", None),
            Some("127.0.0.1".to_string())
        );
        // Inert without the flag.
        assert_eq!(header("example.com host://1.1.1.1\n", Some("1.1.1.1")), None);
        // It runs after `resHeaders://`, as upstream does, so the flag wins.
        assert_eq!(
            header(
                "example.com enable://showHost resHeaders://x-host-ip=mine\n",
                Some("93.184.216.34")
            ),
            Some("93.184.216.34".to_string())
        );
    }

    /// `responseFor://` annotates the **response** with who served it. It used
    /// to fetch its value as a URL — an unrequested outbound call on every
    /// matching request, to whatever a rules file named — and write the result
    /// onto the outgoing *request*, where the client never saw it. Nothing
    /// upstream makes a network call here.
    #[test]
    fn response_for_annotates_rather_than_fetches() {
        let annotate = |rules: &str, res_headers: Vec<(&str, &str)>, req_headers: Vec<(&str, &str)>| {
            let mut mgr = RuleManager::new();
            mgr.set_text(rules);
            let mut hm = HeaderMap::new();
            for (k, v) in &req_headers {
                hm.insert(
                    hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            let mut info = build_req_info("GET", "http", "example.com", 80, "/x", &hm, None);
            info.res = Some(crate::rules::ResInfo {
                status: 200,
                headers: Vec::new(),
                server_ip: Some("10.0.0.9".into()),
                server_port: Some(80),
            });
            let resolved = mgr.resolve(&info);
            let mut out = HeaderMap::new();
            for (k, v) in &res_headers {
                out.insert(
                    hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            annotate_response_for(&mut out, &resolved, Some(&info));
            out.get("x-whistle-response-for")
                .map(|v| v.to_str().unwrap().to_string())
        };

        // A plain value is emitted as written.
        assert_eq!(
            annotate("example.com responseFor://svc-a\n", vec![], vec![]),
            Some("svc-a".into())
        );
        // `name=` reads headers: response ones in place, `req.` ones appended,
        // with the address actually reached added if it is not already there.
        assert_eq!(
            annotate(
                "example.com responseFor://name=server,req.host\n",
                vec![("server", "nginx")],
                vec![("host", "example.com")],
            ),
            Some("nginx, 10.0.0.9, example.com".into())
        );
        // A named header that is not present contributes nothing.
        assert_eq!(
            annotate("example.com responseFor://name=absent\n", vec![], vec![]),
            Some("10.0.0.9".into())
        );
        // No rule, no header.
        assert_eq!(annotate("example.com host://1.1.1.1\n", vec![], vec![]), None);
    }

    /// whistle reads a speed or a delay with `parseFloat`/`parseInt`, so a value
    /// carrying its unit works. Rust's `parse` rejected it outright, turning
    /// `resSpeed://20kb` — the way anyone would first write it — into no
    /// throttle at all.
    #[test]
    fn a_speed_or_delay_may_carry_its_unit() {
        let of = |text: &str| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
            mgr.resolve(&info)
        };
        assert_eq!(res_speed_kbps(&of("a.com resSpeed://20kb\n")), Some(20.0));
        assert_eq!(req_speed_kbps(&of("a.com reqSpeed://3\n")), Some(3.0));
        assert_eq!(res_delay_ms(&of("a.com resDelay://500ms\n")), Some(500));
        // Upstream's `> 0` guard: a zero or negative delay is no delay.
        assert_eq!(res_delay_ms(&of("a.com resDelay://0\n")), None);
        assert_eq!(res_delay_ms(&of("a.com resDelay://-5\n")), None);
        // Nothing numeric at all stays nothing.
        assert_eq!(res_speed_kbps(&of("a.com resSpeed://fast\n")), None);
    }

    /// `x-forwarded-for` — the header a client must not be able to dictate.
    ///
    /// whistle strips the client's by default (`res.js:690-710`); this port
    /// forwarded it, so any client could claim any address and have the proxy
    /// pass it on as if vouched for. It also set a `forwardedFor://` value that
    /// was not an address at all.
    #[test]
    fn forwarded_for_is_an_address_or_nothing() {
        let out = |rules: &str, incoming: Option<&str>| {
            let mut mgr = RuleManager::new();
            mgr.set_text(rules);
            let mut hm = HeaderMap::new();
            if let Some(v) = incoming {
                hm.insert("x-forwarded-for", v.parse().unwrap());
            }
            let info = build_req_info("GET", "http", "a.com", 80, "/", &hm, None);
            let resolved = mgr.resolve(&info);
            let mut headers = hm.clone();
            apply_forwarded_for(&mut headers, &resolved);
            headers
                .get("x-forwarded-for")
                .map(|v| v.to_str().unwrap().to_string())
        };

        // The client's claim does not survive by default.
        assert_eq!(out("a.com host://1.1.1.1\n", Some("10.0.0.5")), None);
        // …unless the rules ask for it.
        assert_eq!(
            out("a.com enable://clientIp\n", Some("10.0.0.5")).as_deref(),
            Some("10.0.0.5")
        );
        // A rule may set one, if it is an address.
        assert_eq!(
            out("a.com forwardedFor://203.0.113.7\n", None).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(out("a.com forwardedFor://2001:db8::1\n", None).as_deref(), Some("2001:db8::1"));
        // A non-address value sets nothing — and does not rescue the client's.
        assert_eq!(out("a.com forwardedFor://hello\n", Some("10.0.0.5")), None);
        // `disable://clientIp` removes it whatever else said.
        assert_eq!(
            out("a.com forwardedFor://203.0.113.7 disable://clientIp\n", None),
            None
        );
    }

    /// `urlReplace://` rewrites the URL that `params://` produced, not the one
    /// before it — `handleParams` writes the query first
    /// (`_original/lib/inspectors/req.js:561`) and `parsePathReplace` runs over
    /// the result (`:569`). Reversed, a pattern aimed at what `params://` had
    /// just written never saw it.
    #[test]
    fn url_replace_sees_what_params_wrote() {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com params://token=SECRET urlReplace://SECRET=redacted\n");
        let info = build_req_info("GET", "http", "example.com", 80, "/api", &HeaderMap::new(), None);
        let resolved = mgr.resolve(&info);
        let out = rewrite_path("/api", &resolved, ReqBodyCtx::default());
        assert_eq!(out, "/api?token=redacted");
    }

    /// A rules text merged in mid-request **wins**: upstream's `mergeRule`
    /// returns the new rule for a single-value protocol and puts the new list
    /// first for a multi-match one, so an included file overrides the file that
    /// included it. This port had it reversed, which meant a rule pulled in
    /// specifically to override something lost to the thing it was overriding.
    #[test]
    fn a_merged_rule_wins_the_contest() {
        let dir = std::env::temp_dir().join(format!("whistle-rs-merge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let inc = dir.join("inc.txt");
        std::fs::write(&inc, "example.com resHeaders://x-src=inc host://9.9.9.9\n").expect("write");

        let mut mgr = RuleManager::new();
        mgr.set_text(&format!(
            "example.com resHeaders://x-src=main host://1.1.1.1 rulesFile://{}\n",
            inc.display()
        ));
        let info = build_req_info("GET", "http", "example.com", 80, "/x", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        let _keep = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);

        // Single-value: the included one replaces the including one.
        assert_eq!(resolved.value("host"), Some("9.9.9.9"));
        // Multi-match: the included one comes first, and these fold first-wins.
        let mut headers = HeaderMap::new();
        apply_header_ops(&mut headers, &resolved, "resHeaders");
        assert_eq!(headers.get("x-src").map(|v| v.to_str().unwrap()), Some("inc"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `${name}` inside an operator's value reads the values store. This port
    /// only ever replaced a value that *was* exactly `{name}`, so
    /// `resHeaders://x-v=${myval}` reached the origin with the eight literal
    /// characters in it — silently, which is the worst way for a value
    /// reference to fail.
    #[test]
    fn a_braced_reference_reads_the_values_store() {
        let values: HashMap<String, String> = [
            ("myval".to_string(), "hello".to_string()),
            ("host".to_string(), "10.0.0.9".to_string()),
        ]
        .into_iter()
        .collect();
        let of = |text: &str, proto: &str| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            let info =
                build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
            let mut resolved = mgr.resolve(&info);
            substitute_values(&mut resolved, &values, TplCtx { info: &info, env: test_env() });
            resolved.value(proto).map(str::to_string)
        };

        // Inside a value, with text around it.
        assert_eq!(
            of("a.com resHeaders://x-v=${myval}\n", "resHeaders").as_deref(),
            Some("x-v=hello")
        );
        // More than one, and one of them repeated.
        assert_eq!(
            of("a.com resHeaders://a=${myval}&b=${host}&c=${myval}\n", "resHeaders").as_deref(),
            Some("a=hello&b=10.0.0.9&c=hello")
        );
        // The whole-value form still replaces with the content itself.
        assert_eq!(of("a.com resBody://{myval}\n", "resBody").as_deref(), Some("hello"));
        // A name with no value is left as written, so a typo shows as itself
        // rather than as an empty string.
        assert_eq!(
            of("a.com resHeaders://x=${nope}\n", "resHeaders").as_deref(),
            Some("x=${nope}")
        );
        // Shapes that are not references are not touched, and do not hang.
        for text in ["x=$notabrace", "x=${", "x=${}", "x=${a${b}}", "x=}{"] {
            let line = format!("a.com resHeaders://{text}\n");
            assert_eq!(of(&line, "resHeaders").as_deref(), Some(text), "{text}");
        }
    }

    /// Resolve `text` against a GET of `http://a.com/p?q=1`, substitute
    /// `values`, and hand back the set — the two passes a request makes before
    /// any operator is applied.
    fn substituted(text: &str, values: &HashMap<String, String>) -> Resolved {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/p?q=1", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(&mut resolved, values, TplCtx { info: &info, env: test_env() });
        resolved
    }

    /// A value wrapped in backticks is a template rendered against the request
    /// (`renderTpl`, `_original/lib/rules/rules.js:762-772`). Without this the
    /// backticks reached the origin as two literal characters wrapped around an
    /// unexpanded `${…}`.
    #[test]
    fn a_backtick_value_renders_against_the_request() {
        let none = HashMap::new();
        let of = |text: &str, proto: &str| {
            substituted(text, &none).value(proto).map(str::to_string)
        };

        assert_eq!(
            of("a.com reqHeaders://`x-m=${method}`\n", "reqHeaders").as_deref(),
            Some("x-m=GET")
        );
        // The whole vocabulary is shared with `tpl://`: `.key` subpaths,
        // `${{…}}` encoding and the `.replace(…)` modifier all come along.
        assert_eq!(
            of("a.com reqHeaders://`x-q=${query.q}`\n", "reqHeaders").as_deref(),
            Some("x-q=1")
        );
        assert_eq!(
            of("a.com reqHeaders://`x-u=${{url}}`\n", "reqHeaders").as_deref(),
            Some("x-u=http%3A%2F%2Fa.com%2Fp%3Fq%3D1")
        );
        // Not a template: the backticks have to wrap the *whole* value, and one
        // backtick is not a pair.
        for value in ["x=`${method}`&y=2", "`", "x=${method}"] {
            let line = format!("a.com reqHeaders://{value}\n");
            assert_eq!(of(&line, "reqHeaders").as_deref(), Some(value), "{value}");
        }
        // A name outside the whitelist survives, as it does in a `tpl://` file.
        assert_eq!(
            of("a.com reqHeaders://`x=${nosuchvar}`\n", "reqHeaders").as_deref(),
            Some("x=${nosuchvar}")
        );
    }

    /// `resolveVar`'s subtlety (`rules.js:774-783`): when the value *was* a
    /// backtick template, what the values store hands back for a `${key}` is
    /// rendered too. It is the only way a stored value ever sees the request —
    /// it is written once and reused by every rule that names it.
    #[test]
    fn a_backtick_value_renders_what_the_values_store_returned() {
        let values: HashMap<String, String> =
            [("hdr".to_string(), "x-m=${method}".to_string())].into_iter().collect();
        let of = |text: &str| {
            substituted(text, &values).value("reqHeaders").map(str::to_string)
        };

        assert_eq!(of("a.com reqHeaders://`${hdr}`\n").as_deref(), Some("x-m=GET"));
        // Without the backticks the stored text is used as written — upstream
        // renders it only when `rule.isTpl`.
        assert_eq!(of("a.com reqHeaders://${hdr}\n").as_deref(), Some("x-m=${method}"));
    }

    /// `log://` and `weinre://` opt out at parse time upstream
    /// (`rule.isTpl = false`, `rules.js:1357-1359`): their values name a
    /// channel, and a backtick in one is a backtick.
    #[test]
    fn the_tool_protocols_opt_out_of_backtick_rendering() {
        let none = HashMap::new();
        let resolved = substituted("a.com log://`${method}`\n", &none);
        assert_eq!(resolved.value("log"), Some("`${method}`"));
    }

    /// Read `spec` as an operator value would be read, on a runtime of its own.
    fn loaded(text: &str) -> Resolved {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        rt().block_on(load_rule_values(&mut resolved, &info));
        resolved
    }

    /// A scratch directory for the value files these tests read.
    fn value_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("whistle-rs-values-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// `reqHeaders:///etc/whistle/headers.json` used to set **nothing**: the
    /// path was handed to the header parser, which found no `=` and no `{`, and
    /// the rule quietly did nothing at all.
    #[test]
    fn an_operator_value_can_name_a_file() {
        let dir = value_dir("read");
        let json = dir.join("h.json");
        std::fs::write(&json, r#"{"x-from-file":"1","x-b":"2"}"#).unwrap();
        let body = dir.join("body.txt");
        std::fs::write(&body, "MOCKED").unwrap();

        let resolved = loaded(&format!(
            "a.com reqHeaders://{}\na.com reqBody://{}\n",
            json.display(),
            body.display()
        ));
        let mut headers = HeaderMap::new();
        apply_header_ops(&mut headers, &resolved, "reqHeaders");
        assert_eq!(headers.get("x-from-file").unwrap(), "1");
        assert_eq!(headers.get("x-b").unwrap(), "2");
        assert_eq!(resolved.value("reqBody"), Some("MOCKED"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `readFileText` splits on `|` and **joins** what it read
    /// (`_original/lib/util/file-mgr.js:96-102,:157-166`) — which is not the
    /// first-one-wins of a `file://` rule. A missing alternative drops out of
    /// the join rather than ending it.
    #[test]
    fn several_paths_in_one_value_join_rather_than_race() {
        let dir = value_dir("join");
        std::fs::write(dir.join("a.txt"), "first").unwrap();
        std::fs::write(dir.join("c.txt"), "third").unwrap();

        let resolved = loaded(&format!(
            "a.com resBody://{}|{}|{}\n",
            dir.join("a.txt").display(),
            dir.join("gone.txt").display(),
            dir.join("c.txt").display()
        ));
        assert_eq!(resolved.value("resBody"), Some("first\r\nthird"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The two failure behaviours, which are not the same one.
    ///
    /// A JSON-valued operator keeps its text, because upstream's
    /// `tryParseMatcher` (`_original/lib/util/index.js:1165-1171,:1303`) parses
    /// the matcher as a query string once the read comes back empty. A
    /// text-valued one is emptied instead: its text is a path, and a path must
    /// never reach an origin as a request body.
    #[test]
    fn a_value_that_cannot_be_read_never_reaches_the_origin_as_a_path() {
        let missing = "/nonexistent-whistle-rs/value.json";
        let resolved = loaded(&format!(
            "a.com reqHeaders://{missing}\na.com reqBody://{missing}\na.com resBody://{missing}\n"
        ));
        assert_eq!(resolved.value("reqHeaders"), Some(missing));
        assert_eq!(resolved.value("reqBody"), Some(""));
        assert_eq!(resolved.value("resBody"), Some(""));

        // A `..` segment is refused before any read, exactly as `joinPath` does.
        let resolved = loaded("a.com resBody:///tmp/../etc/passwd\n");
        assert_eq!(resolved.value("resBody"), Some(""));
    }

    /// Values that are **not** locations are not read — a rule set that does not
    /// use the feature must cost a walk over its own operators and nothing else.
    ///
    /// Asserted on the gate rather than on the outcome: a value the loader
    /// wrongly claimed would still *look* untouched afterwards (a failed read
    /// leaves a JSON operator's text alone), and a wrongly claimed URL would
    /// quietly become an outbound request with a 16-second budget.
    #[test]
    fn only_a_value_shaped_like_a_location_is_read() {
        let untouched = [
            // Pairs are the JSON operators' own syntax; upstream reaches the
            // same place the long way, by reading the path and falling back.
            ("urlReplace", "/api/v1=/api/v2"),
            ("reqHeaders", "x-a=1"),
            ("resHeaders", "{\"x-a\":\"1\"}"),
            // A bare relative value stays the literal this port documents.
            ("resBody", "console.log('patched')"),
            ("resAppend", "tail"),
            ("reqBody", "INJECTED"),
            // A URL on the js/css families still means `<script src=…>`.
            ("jsAppend", "https://cdn.test/a.js"),
            ("cssAppend", "https://cdn.test/a.css"),
            // …and a URL on `re[qs]Cors://` is the allowed **origin**, which
            // upstream folds into `{origin: …}` before it would read anything.
            ("resCors", "https://app.test"),
            ("reqCors", "//app.test"),
            // Operators outside the loadable set keep their value whatever its
            // shape: `file://` does its own reading, `redirect://` is a target.
            ("resType", "/json"),
            ("redirect", "https://b.com/x"),
            ("file", "/tmp/mock.json"),
            ("rulesFile", "/tmp/extra.rules"),
        ];
        for (proto, value) in untouched {
            let resolved = resolve(&format!("a.com {proto}://{value}\n"), "http://a.com/");
            let op = resolved.get(proto).expect(proto);
            assert_eq!(value_source(op), None, "{proto}://{value}");
        }

        // The mirror image, so the gate cannot be "always no".
        for (proto, value, want) in [
            ("reqHeaders", "/etc/h.json", ValueSource::File("/etc/h.json".into())),
            ("resBody", "~/mock.html", ValueSource::File("~/mock.html".into())),
            ("jsAppend", "/tmp/d.js", ValueSource::File("/tmp/d.js".into())),
            (
                "resBody",
                "https://cdn.test/m.json",
                ValueSource::Url("https://cdn.test/m.json".into()),
            ),
        ] {
            let resolved = resolve(&format!("a.com {proto}://{value}\n"), "http://a.com/");
            let op = resolved.get(proto).expect(proto);
            assert_eq!(value_source(op), Some(want), "{proto}://{value}");
        }
    }

    /// `readRuleValue` returns before it looks at a disk when `rule.value` is
    /// set (`_original/lib/util/index.js:1177-1179`) — the `(inline)` form and a
    /// whole-value `{name}` the values store answered.
    #[test]
    fn content_short_circuits_the_read() {
        let values: HashMap<String, String> =
            [("mock".to_string(), "/etc/passwd".to_string())].into_iter().collect();
        let mut mgr = RuleManager::new();
        mgr.set_text("a.com reqBody://(/etc/passwd)\na.com resBody://{mock}\n");
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(&mut resolved, &values, TplCtx { info: &info, env: test_env() });
        rt().block_on(load_rule_values(&mut resolved, &info));

        // Both are content: the path text survives instead of being opened.
        assert_eq!(resolved.value("reqBody"), Some("/etc/passwd"));
        assert_eq!(resolved.value("resBody"), Some("/etc/passwd"));
    }

    /// `file://`, `redirect://`, `statusCode://` and a bare destination URL
    /// share **one slot** upstream — none of their names is a protocol, so all
    /// of them land in the same list and the first match wins outright.
    ///
    /// This port had a fixed protocol priority instead (redirect, statusCode,
    /// file) *and* let a destination rewrite apply alongside a mock, so the two
    /// implementations disagreed in whichever direction the file happened to be
    /// written.
    #[test]
    fn the_short_circuit_family_shares_one_slot() {
        let winner = |text: &str, url: &str| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            let (scheme, rest) = url.split_once("://").expect("absolute");
            let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}")))
                .unwrap_or((rest, "/".into()));
            let info =
                build_req_info("GET", scheme, host, 80, &path, &HeaderMap::new(), None);
            let resolved = mgr.resolve(&info);
            slot_winner(&resolved).map(|(p, _)| p)
        };

        // Written first wins, whatever the protocols are.
        let forward_first = "example.com http://127.0.0.1:9000\nexample.com/api file:///mock.json\n";
        assert_eq!(winner(forward_first, "http://example.com/api"), Some("rule"));
        let mock_first = "example.com/api file:///mock.json\nexample.com http://127.0.0.1:9000\n";
        assert_eq!(winner(mock_first, "http://example.com/api"), Some("file"));

        // …including against the two that used to be hard-coded ahead of file.
        let file_first = "a.com file:///mock.json\na.com redirect://http://x/\n";
        assert_eq!(winner(file_first, "http://a.com/"), Some("file"));
        let redirect_first = "a.com redirect://http://x/\na.com file:///mock.json\n";
        assert_eq!(winner(redirect_first, "http://a.com/"), Some("redirect"));
        let status_first = "a.com statusCode://204\na.com file:///mock.json\n";
        assert_eq!(winner(status_first, "http://a.com/"), Some("statusCode"));

        // An important line still wins over an earlier normal one — importance
        // is part of the resolution order the slot is decided by.
        let important = "a.com file:///mock.json\na.com statusCode://204 lineProps://important\n";
        assert_eq!(winner(important, "http://a.com/"), Some("statusCode"));

        // `rule://<name>` is the values-store include, not a destination, so it
        // does not compete.
        assert_eq!(winner("a.com rule://mocks\n", "http://a.com/"), None);
    }

    /// A header name repeated inside one operator value is a **list**, not a
    /// contest. Node's `querystring.parse("a=1&a=2")` yields `{a: ["1","2"]}`
    /// and writes one header line per element; folding to the last value sent
    /// one header where whistle sends two.
    #[test]
    fn a_repeated_header_name_sends_every_value() {
        let pairs = parse_header_pairs("x-a=1&x-b=2&x-a=3");
        assert_eq!(pairs.len(), 2, "two distinct names");
        let x_a = &pairs.iter().find(|(n, _)| n == "x-a").expect("x-a").1;
        assert_eq!(x_a.iter().cloned().collect::<Vec<_>>(), ["1", "3"]);

        // …and it reaches the header map as two lines.
        let mut mgr = RuleManager::new();
        mgr.set_text("a.com resHeaders://x-a=1&x-a=2\n");
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let resolved = mgr.resolve(&info);
        let mut headers = HeaderMap::new();
        apply_header_ops(&mut headers, &resolved, "resHeaders");
        let sent: Vec<&str> = headers
            .get_all("x-a")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(sent, ["1", "2"]);

        // Names are still trimmed — deliberately unlike upstream, whose
        // `qs.parse` would leave `"x-t "`, a name hyper rejects outright.
        let pairs = parse_header_pairs("x-t = spaced");
        assert_eq!(pairs[0].0, "x-t");
        assert_eq!(pairs[0].1.iter().next().map(String::as_str), Some("spaced"));
    }

    /// A merged-in operator has to win *strictly*, not tie. `MERGED_ORDER` is
    /// zero, and an `$`-important rule on a file's first line used to land on
    /// zero too — a tie that `min_by_key` breaks by iteration order, which is a
    /// map's rather than the file's, so which rule won was not something you
    /// could read off the rules.
    #[test]
    fn a_merged_operator_outranks_even_the_first_important_line() {
        use crate::rules::order_key;

        assert!(
            MERGED_ORDER < order_key(0, true),
            "an important first line must still rank after a merged operator"
        );
        assert!(order_key(0, true) < order_key(1, true));
        // Importance occupies the high half of the key, so any line index that
        // fits the low 32 bits still sorts ahead of the first normal line.
        assert!(order_key(u32::MAX as usize - 1, true) < order_key(0, false));

        // And it decides the shared slot the same way.
        let dir = std::env::temp_dir().join(format!("whistle-rs-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let inc = dir.join("inc.txt");
        std::fs::write(&inc, "a.com statusCode://204\n").expect("write");
        let mut mgr = RuleManager::new();
        mgr.set_text(&format!(
            "$a.com redirect://http://elsewhere/ rulesFile://{}\n",
            inc.display()
        ));
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        let _keep = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        assert_eq!(
            slot_winner(&resolved).map(|(p, _)| p),
            Some("statusCode"),
            "the merged rule wins the slot outright"
        );
        std::fs::remove_dir_all(&dir).ok();
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

    /// A `ReqInfo` for a request a page on `https://app.test` made.
    fn cross_origin(method: &str) -> ReqInfo {
        let mut h = HeaderMap::new();
        h.insert("origin", "https://app.test".parse().unwrap());
        build_req_info(method, "http", "a.com", 80, "/api", &h, None)
    }

    /// Mocking an API with `file://` from a page on another origin is one of
    /// the things whistle is for, and the browser rejects the response unless
    /// the proxy says who may read it. whistle adds the headers by itself
    /// (`isAutoCors`, `_original/lib/handlers/file-proxy.js:178-191`); this port
    /// had the writer and not the trigger.
    #[test]
    fn a_local_file_answer_carries_cors_for_a_cross_origin_page() {
        let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
        let resp = short_circuit(&cross_origin("GET"), &resolved, test_env()).expect("file://");
        let h = resp.headers();
        assert_eq!(h.get("access-control-allow-origin").unwrap(), "https://app.test");
        assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
    }

    /// …and a same-origin request gets none, because none is needed. The
    /// trigger is the `Origin` header, exactly as upstream reads it.
    #[test]
    fn a_same_origin_request_gets_no_cors_headers() {
        let info = build_req_info("GET", "http", "a.com", 80, "/api", &HeaderMap::new(), None);
        let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
        let resp = short_circuit(&info, &resolved, test_env()).expect("file://");
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    /// The half that decides whether the real request ever happens: a preflight
    /// is answered 200 with the CORS headers and the file is never opened. Here
    /// the file does not exist, so serving it would 404 the preflight and the
    /// browser would stop.
    #[test]
    fn a_preflight_is_answered_without_opening_the_file() {
        let mut h = HeaderMap::new();
        h.insert("origin", "https://app.test".parse().unwrap());
        h.insert("access-control-request-method", "PUT".parse().unwrap());
        h.insert("access-control-request-headers", "x-token".parse().unwrap());
        let info = build_req_info("OPTIONS", "http", "a.com", 80, "/api", &h, None);
        let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
        let resp = short_circuit(&info, &resolved, test_env()).expect("file://");
        assert_eq!(resp.status(), StatusCode::OK, "not the file's 404");
        let hs = resp.headers();
        assert_eq!(hs.get("access-control-allow-origin").unwrap(), "https://app.test");
        assert_eq!(hs.get("access-control-allow-methods").unwrap(), "PUT");
        assert_eq!(hs.get("access-control-allow-headers").unwrap(), "x-token");
    }

    /// Both ways of turning it off, including upstream's own misspelling.
    #[test]
    fn auto_cors_can_be_turned_off() {
        for rule in [
            "a.com/api file:///no/such/mock.json lineProps://disableAutoCors",
            "a.com/api file:///no/such/mock.json lineProps://disabledAutoCors",
            "a.com/api file:///no/such/mock.json disable://autoCors",
        ] {
            let resolved = resolve(&format!("{rule}\n"), "http://a.com/api");
            let resp = short_circuit(&cross_origin("GET"), &resolved, test_env()).expect("file://");
            assert!(
                resp.headers().get("access-control-allow-origin").is_none(),
                "{rule} should have silenced it"
            );
            // …and with it off, the preflight is the file's own answer again.
            let resp = short_circuit(&cross_origin("OPTIONS"), &resolved, test_env()).expect("f");
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{rule}");
        }
    }

    /// `log://` and `weinre://` inject a script into an HTML response, so they
    /// need a response with HTML in it. Upstream busts the cache for both the
    /// moment the rule matches (`log.js:30`, `weinre.js:26`); this port did it
    /// for the body operators and not for these two.
    ///
    /// Found by the differential bench: whistle reached the origin with
    /// `pragma: no-cache` under `log://mytag` and this port did not.
    #[test]
    fn a_script_injector_busts_the_cache_too() {
        let bust = |rule: &str| {
            let resolved = resolve(&format!("a.com {rule}\n"), "http://a.com/");
            res_body_forbids_cache(&resolved)
        };
        assert!(bust("log://mytag"));
        assert!(bust("weinre://myid"));
        assert!(bust("resBody://(x)"), "the body operators, as before");
        assert!(!bust("reqHeaders://x-a=1"), "and nothing else");
    }

    /// Every response the proxy makes itself says so — upstream's `x-server`
    /// (`wrapResponse`, `_original/lib/util/index.js:1080-1090`). It answers the
    /// question a mock otherwise leaves open: origin, or proxy?
    #[test]
    fn a_self_made_response_says_who_made_it() {
        let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
        for rule in ["statusCode://204", "redirect://http://b.com/", "file:///nope"] {
            let resolved = resolve(&format!("a.com/x {rule}\n"), "http://a.com/x");
            let resp = short_circuit(&info, &resolved, test_env()).expect("an answer");
            assert_eq!(
                resp.headers().get("x-server").map(|v| v.to_str().unwrap()),
                Some("whistle-rs"),
                "{rule}"
            );
        }
    }

    /// Only the file family. `redirect://` and `statusCode://` are answered by
    /// a different handler upstream and carry no automatic CORS.
    #[test]
    fn redirect_and_status_code_carry_no_automatic_cors() {
        for rule in ["redirect://http://b.com/", "statusCode://204"] {
            let resolved = resolve(&format!("a.com/api {rule}\n"), "http://a.com/api");
            let resp = short_circuit(&cross_origin("GET"), &resolved, test_env()).expect("answer");
            assert!(resp.headers().get("access-control-allow-origin").is_none(), "{rule}");
        }
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
        let op = RuleOp {
            protocol: proto.to_string(),
            value: value.to_string(),
            ..Default::default()
        };
        let resp = serve_file_family(proto, &op, &info, test_env())?;
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

    /// Mapping a path onto a directory is the whole point of a `file://` rule,
    /// and it works because the pattern's leftover URL is appended to the
    /// operator's value (`joinUrl`, `_original/lib/rules/rules.js:334-366`).
    /// Nothing appended it here: every request under `static.test` served the
    /// directory itself, which is not a file, so all of them 404'd.
    #[test]
    fn a_directory_rule_maps_the_rest_of_the_path_onto_it() {
        let fx = Fixtures::new("dirmap");
        fx.write("js/app.js", b"console.log(1)");
        fx.write("index.html", b"<h1>root</h1>");
        let dir = fx.path("");

        let served = |rules: &str, url: &str| -> Option<(u16, Vec<u8>)> {
            let mut mgr = RuleManager::new();
            mgr.set_text(rules);
            let (scheme, rest) = url.split_once("://").expect("absolute url");
            let (host, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            let info = build_req_info("GET", scheme, host, 80, path, &HeaderMap::new(), None);
            let resp = short_circuit(&info, &mgr.resolve(&info), test_env())?;
            let status = resp.status().as_u16();
            let body = rt()
                .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
                .expect("collect body")
                .to_bytes()
                .to_vec();
            Some((status, body))
        };

        let rules = format!("static.test file://{}\n", dir.trim_end_matches('/'));
        assert_eq!(
            served(&rules, "http://static.test/js/app.js"),
            Some((200, b"console.log(1)".to_vec()))
        );
        // A directory with nothing more to add falls back to its `index.html`.
        assert_eq!(
            served(&rules, "http://static.test/"),
            Some((200, b"<h1>root</h1>".to_vec()))
        );
        // The query string is not part of a filename.
        assert_eq!(
            served(&rules, "http://static.test/js/app.js?v=2"),
            Some((200, b"console.log(1)".to_vec()))
        );
        // A path pattern contributes only what it did not consume.
        let scoped = format!("static.test/assets file://{}\n", dir.trim_end_matches('/'));
        assert_eq!(
            served(&scoped, "http://static.test/assets/js/app.js"),
            Some((200, b"console.log(1)".to_vec()))
        );
        // …and `<>` pins the value, whatever the request asked for.
        let pinned = format!("static.test file://<{}index.html>\n", dir);
        assert_eq!(
            served(&pinned, "http://static.test/js/app.js"),
            Some((200, b"<h1>root</h1>".to_vec()))
        );
    }

    /// `file://(text)` answers with the text itself — whistle's inline value
    /// (`docs/docs/rules/file.md`, "内联值"). It used to be read as a filename,
    /// so every inline mock 404'd.
    #[test]
    fn a_bracketed_value_is_the_response_body() {
        let (status, ctype, body) = serve_at(
            "file",
            "({\"status\":\"ok\"})",
            "http://api.test/data.json",
        )
        .expect("served");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"status\":\"ok\"}");
        // With no file to name the type, the request URL does.
        assert_eq!(ctype, "application/json; charset=utf-8");
        // A template renders the inline text like it renders a file's.
        let (_, _, body) = serve_at("tpl", "(hello {name})", "http://api.test/x?name=world")
            .expect("served");
        assert_eq!(body, b"hello world");
    }

    /// Each `|` alternative takes the request's remaining path, not just the
    /// last: joining the value whole would leave the first alternative pointing
    /// at the bare directory.
    #[test]
    fn every_alternative_path_takes_the_rest_of_the_url() {
        let fx = Fixtures::new("altjoin");
        fx.write("second/js/app.js", b"from second");
        let value = format!("{}|{}", fx.path("first"), fx.path("second"));

        let mut mgr = RuleManager::new();
        mgr.set_text(&format!("static.test file://{value}\n"));
        let info = build_req_info(
            "GET",
            "http",
            "static.test",
            80,
            "/js/app.js",
            &HeaderMap::new(),
            None,
        );
        let resp = short_circuit(&info, &mgr.resolve(&info), test_env()).expect("served");
        assert_eq!(resp.status().as_u16(), 200);
        let body = rt()
            .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
            .expect("collect body")
            .to_bytes();
        assert_eq!(body.as_ref(), b"from second");
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

    /// A raw response's header lines end at any of `\r\n`, `\r` or `\n`
    /// (`CRLF_RE`, `file-proxy.js:10`). Splitting on `\n` alone read a
    /// CR-terminated fixture as one long status line, so every header in it was
    /// dropped — the body and the status arrived, the headers silently did not.
    #[test]
    fn raw_file_header_lines_end_at_a_bare_cr() {
        let fx = Fixtures::new("rawcr");
        let path = fx.write("cr.http", b"HTTP/1.1 202 Accepted\rX-Sep: cr\r\rcr body");
        let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
        let op = RuleOp {
            protocol: "rawfile".into(),
            value: path,
            ..Default::default()
        };
        let resp = serve_file_family("rawfile", &op, &info, test_env()).expect("served");
        assert_eq!(resp.status().as_u16(), 202);
        assert_eq!(
            resp.headers().get("x-sep").and_then(|v| v.to_str().ok()),
            Some("cr")
        );
    }

    /// A `rawfile://` head with no status line: upstream takes the first line's
    /// second word as the status code and throws while writing the response,
    /// which the client sees as a reset connection. Serving it as 200 is a
    /// deliberate deviation — there is no behaviour there to be faithful to.
    #[test]
    fn a_raw_response_with_no_status_line_falls_back_to_200() {
        let fx = Fixtures::new("rawnostatus");
        let path = fx.write("h.http", b"X-Only: header\r\n\r\nbody");
        let (status, _, body) = serve("rawfile", &path).expect("served");
        assert_eq!((status, body.as_slice()), (200, b"body".as_slice()));
    }

    /// Only a file read off disk carries `Server` (`file-proxy.js:315-318`);
    /// an inline value, a values-store body and the 404 are all built elsewhere
    /// and carry none. The asymmetry is upstream's and is worth keeping: the
    /// header says the bytes came from the filesystem.
    #[test]
    fn only_a_file_read_from_disk_names_the_proxy_in_server() {
        let fx = Fixtures::new("srvhdr");
        let path = fx.write("a.txt", b"body");
        let served = |proto: &str, value: &str| {
            let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
            let op = RuleOp {
                protocol: proto.into(),
                value: value.into(),
                ..Default::default()
            };
            let resp = serve_file_family(proto, &op, &info, test_env()).expect("served");
            resp.headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(served("file", &path).as_deref(), Some("whistle-rs"));
        assert_eq!(served("tpl", &path).as_deref(), Some("whistle-rs"));
        assert_eq!(served("file", "(inline)"), None);
        assert_eq!(served("file", &fx.path("nope.txt")), None);
        // A parsed raw response brings its own headers and replaces the block
        // `Server` lives in; one with no blank line falls back to it.
        let raw = fx.write("r.http", b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nb");
        assert_eq!(served("rawfile", &raw), None);
        assert_eq!(served("rawfile", &path).as_deref(), Some("whistle-rs"));
    }

    /// The name a body was stored under is the only place its extension is
    /// written, so it is what the content type is guessed from
    /// (`rule.key`, `file-proxy.js:270-272`). Without this, `file://{mock.json}`
    /// served JSON as `text/html` and a browser rendered it as a page.
    #[test]
    fn a_values_key_names_the_file_its_type_is_guessed_from() {
        let typed = |key: Option<&str>, url: &str| {
            let (host, path) = url.split_once('/').expect("host and path");
            let info = build_req_info("GET", "http", host, 80, path, &HeaderMap::new(), None);
            let op = RuleOp {
                protocol: "file".into(),
                value: "{\"a\":1}".into(),
                value_is_content: true,
                value_key: key.map(str::to_string),
                ..Default::default()
            };
            let resp = serve_file_family("file", &op, &info, test_env()).expect("served");
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(typed(Some("mock.json"), "x.com/echo"), "application/json; charset=utf-8");
        // A key with no extension of its own falls back to the request URL's,
        // and then to `text/html` — the same chain a nameless inline value takes.
        assert_eq!(typed(Some("mockbody"), "x.com/thing.css"), "text/css; charset=utf-8");
        assert_eq!(typed(None, "x.com/thing.css"), "text/css; charset=utf-8");
        assert_eq!(typed(Some("mockbody"), "x.com/echo"), "text/html; charset=utf-8");
    }

    /// `util.isText` is a substring test, so a type merely *naming* xml or html
    /// is text — which is why an SVG carries a charset and a PNG does not
    /// (`_original/lib/util/index.js:1494-1531`).
    #[test]
    fn a_content_type_carries_a_charset_only_when_it_is_text() {
        for (ext, want) in [
            ("svg", "image/svg+xml; charset=utf-8"),
            ("xhtml", "application/xhtml+xml; charset=utf-8"),
            ("map", "application/json; charset=utf-8"),
            ("md", "text/markdown; charset=utf-8"),
            ("csv", "text/csv; charset=utf-8"),
            ("yml", "text/yaml; charset=utf-8"),
            ("png", "image/png"),
            ("woff2", "font/woff2"),
            ("mp4", "video/mp4"),
            ("zip", "application/zip"),
        ] {
            assert_eq!(content_type_of_ext(&format!("a.{ext}")), Some(want), "{ext}");
        }
    }

    /// Serve a file rule for a `GET` carrying one request header.
    fn serve_with_header(
        proto: &str,
        value: &str,
        name: &str,
        header: &str,
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            header.parse().expect("header value"),
        );
        let info = build_req_info("GET", "http", "x.com", 80, "/", &headers, None);
        let op = RuleOp {
            protocol: proto.into(),
            value: value.into(),
            ..Default::default()
        };
        let resp = serve_file_family(proto, &op, &info, test_env()).expect("served");
        let status = resp.status().as_u16();
        let heads = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = rt()
            .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
            .expect("collect body")
            .to_bytes()
            .to_vec();
        (status, heads, body)
    }

    #[test]
    fn a_range_request_serves_part_of_a_file() {
        let fx = Fixtures::new("range");
        let path = fx.write("r.txt", b"ranged-0123456789-end");
        let (status, heads, body) = serve_with_header("file", &path, "range", "bytes=0-5");
        assert_eq!((status, body.as_slice()), (206, b"ranged".as_slice()));
        assert!(heads.contains(&("content-range".into(), "bytes 0-5/21".into())), "{heads:?}");
        assert!(heads.contains(&("accept-ranges".into(), "bytes".into())), "{heads:?}");
        // An inline value is rangeable too — it is the same `if (!isRawFile)`
        // arm upstream (`file-proxy.js:280-289`).
        let (status, _, body) = serve_with_header("file", "(0123456789)", "range", "bytes=2-4");
        assert_eq!((status, body.as_slice()), (206, b"234".as_slice()));
    }

    /// `rawfile://` asks for no range at all (`file-proxy.js:100-102`) and
    /// `tpl://` never reaches the code that would; both answer whole.
    #[test]
    fn raw_and_template_responses_ignore_a_range_request() {
        let fx = Fixtures::new("rangeskip");
        let raw = fx.write("r.http", b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nabcdefgh");
        let (status, _, body) = serve_with_header("rawfile", &raw, "range", "bytes=0-3");
        assert_eq!((status, body.as_slice()), (200, b"abcdefgh".as_slice()));

        let tpl = fx.write("t.txt", b"abcdefgh${nothing}");
        let (status, _, body) = serve_with_header("tpl", &tpl, "range", "bytes=0-3");
        assert_eq!(status, 200);
        assert_eq!(body.len(), 18);
    }

    /// whistle's range arithmetic, quirks included: a suffix range compares its
    /// computed start against the *suffix length* and loses, and several ranges
    /// collapse into the one span that covers them all.
    #[test]
    fn range_parsing_reproduces_upstreams_arithmetic() {
        let parsed = |spec: &str, size: usize| {
            let mut headers = HeaderMap::new();
            headers.insert(hyper::header::RANGE, spec.parse().expect("range value"));
            let info = build_req_info("GET", "http", "x.com", 80, "/", &headers, None);
            parse_range(&info, size)
        };
        assert_eq!(parsed("bytes=0-5", 21), Some((0, 5)));
        assert_eq!(parsed("bytes=7-", 21), Some((7, 20)));
        assert_eq!(parsed("bytes=0-20", 21), Some((20 - 20, 20)));
        assert_eq!(parsed("BYTES=0-5", 21), Some((0, 5)));
        assert_eq!(parsed("  bytes=0-5", 21), Some((0, 5)));
        // `bytes=0-1,5-6` is one span, not two parts.
        assert_eq!(parsed("bytes=0-1,5-6", 21), Some((0, 6)));
        // A suffix range: start becomes `21 - 5 = 16`, which is compared against
        // the end `5` and rejected. Upstream sends the whole body.
        assert_eq!(parsed("bytes=-5", 21), None);
        assert_eq!(parsed("bytes=10-99", 21), None);
        assert_eq!(parsed("bytes=9-2", 21), None);
        assert_eq!(parsed("bytes=abc", 21), None);
        assert_eq!(parsed("bytes=", 21), None);
        assert_eq!(parsed("items=0-5", 21), None);
        // `bytes =0-5` — the `=` has to follow the unit immediately.
        assert_eq!(parsed("bytes =0-5", 21), None);
        // Nothing is ranged out of an empty body.
        assert_eq!(parsed("bytes=0-1", 0), None);
    }

    /// The inline form of `rawfile://` parses what it is given and no more: with
    /// no blank line, `parseRes` receives nothing and answers a bare `{200, {}}`,
    /// so the body goes out untyped (`getRawResByValue`, `file-proxy.js:84-98`).
    /// The path form falls back to the file handler's header block instead.
    #[test]
    fn an_inline_raw_response_without_a_blank_line_is_untyped() {
        let info = build_req_info("GET", "http", "x.com", 80, "/a.json", &HeaderMap::new(), None);
        let op = RuleOp {
            protocol: "rawfile".into(),
            value: "(no-blank-line)".into(),
            ..Default::default()
        };
        let resp = serve_file_family("rawfile", &op, &info, test_env()).expect("served");
        assert_eq!(resp.status().as_u16(), 200);
        assert!(resp.headers().get(hyper::header::CONTENT_TYPE).is_none());
    }

    /// A raw response written as a *value* cannot be the compressed bytes a
    /// `content-encoding` claims — it was typed into a rules file — so upstream
    /// drops the header (`fromValue`, `file-proxy.js:71-73`). Keeping it made
    /// the client try to gunzip plain text and fail on a body it could read.
    /// A raw response read from a *file* keeps it: that one can really be gzip.
    #[test]
    fn a_raw_response_from_a_value_loses_its_content_encoding() {
        let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nplain";
        let encoding_of = |op: &RuleOp| {
            serve_file_family("rawfile", op, &info, test_env())
                .expect("served")
                .headers()
                .get(hyper::header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap_or_default().to_string())
        };
        let from_value = RuleOp {
            protocol: "rawfile".into(),
            value: String::from_utf8_lossy(head).into_owned(),
            value_is_content: true,
            ..Default::default()
        };
        assert_eq!(encoding_of(&from_value), None);

        let fx = Fixtures::new("rawenc");
        let from_file = RuleOp {
            protocol: "rawfile".into(),
            value: fx.write("r.http", head),
            ..Default::default()
        };
        assert_eq!(encoding_of(&from_file).as_deref(), Some("gzip"));
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
        rt().block_on(resolve_target(&info, &crate::proxy::dest::Destination::of(&info, &resolved), &resolved))
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
                "example.com/x resAppend://normal\n\
                 example.com/x resAppend://important lineProps://important\n",
                "body",
                "text/plain",
            ),
            "bodyimportant\r\nnormal"
        );
        // The same order decides who wins a contested `*Replace` pattern.
        let out = transform_res_body(
            Bytes::from_static(b"x"),
            &resolve(
                "example.com/x resReplace://x=normal\n\
                 example.com/x resReplace://x=important lineProps://important\n",
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

    /// `delete://` also names query parameters and path segments
    /// (`parseDelQuery`, `_original/lib/util/index.js:2674-2699`, applied by
    /// `deleteQuery` and `parsePathReplace`'s `delPaths` arm at
    /// `req.js:557,562-570`).
    ///
    /// None of these keys were parsed anywhere in this port, so every one of
    /// them was a rule that resolved, matched, and did nothing — the shape of
    /// bug you debug by rereading your own rules file.
    ///
    /// The expectations are upstream's own output: `parseDelQuery`,
    /// `parsePathReplace` and `deleteQuery` were lifted verbatim and run over
    /// these inputs, which is why the odd ones are here — `pathname.last` leaves
    /// a trailing slash where `pathname.-1` does not, and `pathname.LAST`
    /// matches the pattern and then does nothing at all.
    #[test]
    fn delete_names_query_parameters_and_path_segments() {
        let out = |rule: &str, path: &str| {
            let resolved = resolve(
                &format!("example.com {rule}\n"),
                &format!("http://example.com{path}"),
            );
            rewrite_path(path, &resolved, body_ctx(None))
        };

        // ── query parameters ──
        assert_eq!(out("delete://query.a", "/p?a=1&b=2"), "/p?b=2");
        // Every spelling `QUERY_RE` takes, and it is case-insensitive.
        for spelling in ["query", "params", "urlParams", "urlParam", "url.Param", "url.Params", "QUERY"] {
            assert_eq!(
                out(&format!("delete://{spelling}.a"), "/p?a=1&b=2"),
                "/p?b=2",
                "{spelling}"
            );
        }
        // Repeats of a named parameter all go.
        assert_eq!(out("delete://query.a", "/p?a=1&a=2&b=3"), "/p?b=3");
        // The `?` goes with the last surviving pair.
        assert_eq!(out("delete://query.a|query.b", "/p?a=1&b=2"), "/p");
        // A valueless pair is named by the bare token.
        assert_eq!(out("delete://query.a", "/p?a"), "/p");
        // Nothing to delete from.
        assert_eq!(out("delete://query.a", "/p"), "/p");
        // An empty query string is left exactly as it is — upstream returns
        // before it can drop the `?`.
        assert_eq!(out("delete://query.a", "/p?"), "/p?");
        // The bare form clears the whole query string, `?` and all…
        assert_eq!(out("delete://query", "/p?a=1&b=2"), "/p");
        assert_eq!(out("delete://urlparams", "/p?a=1&b=2"), "/p");
        // …and that one *does* drop a lone `?`.
        assert_eq!(out("delete://query", "/p?"), "/p");
        // A key with nothing after the dot matches neither pattern.
        assert_eq!(out("delete://query.", "/p?a=1"), "/p?a=1");

        // ── path segments ──
        assert_eq!(out("delete://pathname.0", "/a/b/c"), "/b/c");
        assert_eq!(out("delete://pathname.first", "/a/b/c"), "/b/c");
        // `last` leaves a trailing slash behind; `-1` names the same segment
        // and does not.
        assert_eq!(out("delete://pathname.last", "/a/b/c"), "/a/b/");
        assert_eq!(out("delete://pathname.-1", "/a/b/c"), "/a/b");
        assert_eq!(out("delete://pathname.-2", "/a/b/c"), "/a/c");
        // A path already ending in `/` has an empty last segment, so `last`
        // removes that and the slash is put straight back.
        assert_eq!(out("delete://pathname.last", "/a/b/c/"), "/a/b/c/");
        // Several indices are counted against the *original* path.
        assert_eq!(out("delete://pathname.1|pathname.2", "/a/b/c/d"), "/a/d");
        // Out of range is a no-op, either way round.
        assert_eq!(out("delete://pathname.99", "/a/b"), "/a/b");
        assert_eq!(out("delete://pathname.-9", "/a/b/c"), "/a/b/c");
        // The dot is optional, and `pathname` is case-insensitive.
        assert_eq!(out("delete://pathname-1", "/a/b/c"), "/a/b");
        assert_eq!(out("delete://pathname0", "/a/b/c"), "/b/c");
        assert_eq!(out("delete://pathnamelast", "/a/b/c"), "/a/b/");
        assert_eq!(out("delete://PATHNAME", "/a/b/c"), "/");
        // …but `first`/`last` are not: the key matches and then evaporates.
        assert_eq!(out("delete://pathname.LAST", "/a/b/c"), "/a/b/c");
        assert_eq!(out("delete://pathname.First", "/a/b/c"), "/a/b/c");
        // `all` is not one of the words the pattern accepts.
        assert_eq!(out("delete://pathname.all", "/a/b/c"), "/a/b/c");
        // A `+` is not one of the shapes `-?\d+` accepts.
        assert_eq!(out("delete://pathname.+1", "/a/b/c"), "/a/b/c");
        // The bare form drops the path and keeps the query — and beats an index
        // named on the same line.
        assert_eq!(out("delete://pathname", "/a/b/c"), "/");
        assert_eq!(out("delete://pathname|pathname.0", "/a/b/c"), "/");
        // Deliberate divergence: upstream emits the query twice here
        // (`/?x=1?x=1`), which is a request line no origin parses.
        assert_eq!(out("delete://pathname", "/a/b/c?x=1"), "/?x=1");
        // Nothing but a query string has no segment to name.
        assert_eq!(out("delete://pathname", "/?x=1"), "/?x=1");
        assert_eq!(out("delete://pathname.last", "/a?x=1"), "/?x=1");

        // ── together, and against the operators they run beside ──
        assert_eq!(out("delete://pathname.last|query.a", "/a/b?a=1&b=2"), "/a/?b=2");
        // `deleteQuery` runs after `params://`, so it wins over a parameter the
        // same line had just written (`req.js:568-570`).
        assert_eq!(out("params://a=9 delete://query.a", "/p?b=2"), "/p?b=2");
        // …and the path deletion runs with `urlReplace://`, over its output.
        assert_eq!(out("urlReplace://b=x delete://pathname.-1", "/a/b/c"), "/a/x");
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
            cors("*", "OPTIONS", &preflight, "access-control-allow-methods"),
            Some("PUT".to_string()),
            "the header a browser actually reads, and the one upstream writes"
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

    /// …but a **form POST** is not one of the bodies it leaves alone, which is
    /// where this port had it wrong (`handleReplace`,
    /// `_original/lib/inspectors/req.js:434-438`).
    ///
    /// `getContentType` puts `application/x-www-form-urlencoded` in no class,
    /// and the gate refuses everything unclassified — so upstream substitutes
    /// the class `FORM` for it first. Without that substitution `reqReplace://`
    /// was inert against the single commonest request body there is, and
    /// silently so.
    #[test]
    fn req_replace_reaches_a_form_post() {
        let resolved = resolve("example.com reqReplace://old=new\n", "http://example.com/");
        let sent = |method: &str, ct: Option<&str>| {
            let ctx = ReqBodyCtx { method, content_type: ct };
            let out = transform_req_body(Bytes::from_static(b"q=old"), &resolved, ctx);
            String::from_utf8(out.to_vec()).expect("utf-8")
        };
        let form = Some("application/x-www-form-urlencoded");

        assert_eq!(sent("POST", form), "q=new");
        // The charset parameter does not change the answer.
        assert_eq!(
            sent("POST", Some("application/x-www-form-urlencoded; charset=UTF-8")),
            "q=new"
        );
        // `isUrlEncoded` is POST-only, so a `PUT` carrying the same body takes
        // the ordinary path — and `getContentType` gives it no class.
        assert_eq!(sent("PUT", form), "q=old");
        // A method that carries no body is refused before the type is looked
        // at (`hasRequestBody`, `common.js:1591-1604`).
        assert_eq!(sent("GET", Some("text/plain")), "q=old");
        assert_eq!(sent("OPTIONS", Some("text/plain")), "q=old");
        // The classes that did already work still do.
        assert_eq!(sent("POST", Some("application/json")), "q=new");
        assert_eq!(sent("PUT", Some("text/plain")), "q=new");
    }

    /// A `set-cookie` written on `resHeaders://` **merges** with the response's
    /// own, by cookie name (`setCookies`,
    /// `_original/lib/inspectors/res.js:89-122`, run at `:926` just before the
    /// `extend` that would otherwise clobber it).
    ///
    /// The port assigned the header instead, so a rule setting `sid` also threw
    /// away the `csrf` cookie the origin sent beside it — and the JSON array
    /// spelling was worse still: it stringified the array into the header value
    /// and sent `Set-Cookie: ["sid=new","theme=dark"]`.
    ///
    /// Expectations are upstream's own output, from a verbatim `setCookies`.
    #[test]
    fn res_headers_set_cookie_merges_with_the_origins() {
        let sent = |rule: &str, origin: &[&str]| {
            let resolved = resolve(
                &format!("example.com resHeaders://{rule}\n"),
                "http://example.com/",
            );
            let mut parts = res_parts(&[]);
            for c in origin {
                parts
                    .headers
                    .append(hyper::header::SET_COOKIE, c.parse().unwrap());
            }
            apply_response(&mut parts, &resolved);
            parts
                .headers
                .get_all(hyper::header::SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };

        // The named cookie is replaced; the others survive, after it.
        assert_eq!(
            sent("set-cookie=sid=new", &["sid=old; Path=/", "csrf=abc"]),
            ["sid=new", "csrf=abc"]
        );
        // The JSON array spelling is a list of cookies, not a header value.
        assert_eq!(
            sent(r#"{"set-cookie":["sid=new","theme=dark"]}"#, &["sid=old", "csrf=abc"]),
            ["sid=new", "theme=dark", "csrf=abc"]
        );
        // A plain string is split on commas, so this is two cookies…
        assert_eq!(sent("set-cookie=a=1,b=2", &["sid=old"]), ["a=1", "b=2", "sid=old"]);
        // …and an array element is not, which is the only way to write a cookie
        // whose attributes contain a comma (an `Expires=Wed, 21 Oct …`).
        assert_eq!(
            sent(r#"{"set-cookie":["a=1,b=2"]}"#, &["sid=old"]),
            ["a=1,b=2", "sid=old"]
        );
        // Nothing to merge with.
        assert_eq!(sent("set-cookie=sid=new", &[]), ["sid=new"]);
        // A cookie with no `=` is a name of its own, and does not collide.
        assert_eq!(sent("set-cookie=flag", &["sid=old"]), ["flag", "sid=old"]);
        assert_eq!(sent("set-cookie=sid=new", &["sid=old", "flag"]), ["sid=new", "flag"]);
        // An empty value is not a merge: it falls through to the assignment,
        // like any other empty header value.
        assert_eq!(sent("set-cookie=", &["sid=old"]), [""]);
        // The name is matched however it is spelled on the rule.
        assert_eq!(
            sent(r#"{"Set-Cookie":"sid=new"}"#, &["sid=old", "csrf=abc"]),
            ["sid=new", "csrf=abc"]
        );
    }

    /// The JSON array spelling is several header lines for every header, not
    /// only `set-cookie` — Node writes one line per element of
    /// `headers[name] = ['a', 'b']`.
    #[test]
    fn a_json_array_header_value_is_several_headers() {
        let resolved = resolve(
            r#"example.com reqHeaders://{"x-a":["1","2"],"x-b":"3"}"#,
            "http://example.com/",
        );
        let mut parts = req_parts(&[("x-a", "arrived")]);
        apply_request(&mut parts, &resolved);
        let values: Vec<_> = parts
            .headers
            .get_all("x-a")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, ["1", "2"], "the arrived value is replaced, not added to");
        assert_eq!(parts.headers.get("x-b").unwrap(), "3");
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
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        let vals: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(vals, ["sid=new", "other=1", "theme=dark"]);

        // A `;` in a value would end the cookie early, so it is encoded.
        let resolved = resolve("example.com resCookies://a=x;Secure\n", "http://example.com/");
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        assert_eq!(headers.get(hyper::header::SET_COOKIE).unwrap(), "a=x%3BSecure");
    }

    /// One `Set-Cookie`, rendered from `resCookies`, for a given JSON spec.
    fn set_cookie(rule: &str) -> String {
        let resolved = resolve(
            &format!("example.com resCookies://{rule}\n"),
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        headers
            .get(hyper::header::SET_COOKIE)
            .expect("a cookie")
            .to_str()
            .unwrap()
            .to_string()
    }

    /// A cookie declared as an object carries attributes, in upstream's order
    /// (`getCookieItem`, `_original/lib/util/index.js:3093-3117`). Previously
    /// the object was serialised into the value, so
    /// `{"sid":{"value":"x","httpOnly":true}}` produced the literal JSON as the
    /// cookie's value and set no attributes at all.
    #[test]
    fn a_cookie_object_becomes_attributes() {
        let out = set_cookie(
            r#"{"sid":{"value":"x","httpOnly":true,"secure":true,"path":"/a","domain":"example.com","sameSite":"Lax","partitioned":true}}"#,
        );
        assert_eq!(
            out,
            "sid=x; Secure; HttpOnly; Partitioned; Path=/a; Domain=example.com; SameSite=Lax"
        );

        // A falsy flag is absent, exactly as in JavaScript — and `Value` /
        // `Path` are read in their capitalised spellings too.
        assert_eq!(
            set_cookie(r#"{"a":{"Value":"1","httpOnly":false,"secure":0,"Path":"/"}}"#),
            "a=1; Path=/"
        );

        // No `value` at all leaves the cookie empty rather than dropping it:
        // upstream's `escapeValue(undefined)` is the empty string.
        assert_eq!(set_cookie(r#"{"a":{"httpOnly":true}}"#), "a=; HttpOnly");

        // The value is escaped inside the attribute form too.
        assert_eq!(set_cookie(r#"{"a":{"value":"x;y"}}"#), "a=x%3By");
    }

    /// One name may carry an **array**, and then it emits several `Set-Cookie`
    /// lines — how upstream expires a cookie under both its plain and its
    /// `Secure` spelling in one go (`Array.isArray(cookie)`,
    /// `_original/lib/util/index.js:3138-3142`).
    #[test]
    fn a_cookie_array_becomes_several_headers() {
        let resolved = resolve(
            r#"example.com resCookies://{"sid":[{"value":"a","path":"/"},{"value":"b","secure":true}]}"#,
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        let vals: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(vals, ["sid=a; Path=/", "sid=b; Secure"]);

        // Every line of the array replaces what the response sent under that
        // name — the group is one unit, not an addition to it.
        let mut headers = HeaderMap::new();
        headers.append(hyper::header::SET_COOKIE, "sid=old".parse().unwrap());
        headers.append(hyper::header::SET_COOKIE, "keep=1".parse().unwrap());
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        let vals: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            vals,
            ["sid=a; Path=/", "sid=b; Secure", "keep=1"],
            "the replaced name keeps its position, and an untouched one survives"
        );
    }

    /// `delete://resCookies.x` cannot remove a cookie the client already holds,
    /// so it sends one back that has already expired — twice per name, plain and
    /// `Secure`, because a `Secure` cookie is not overwritten by a plain one
    /// (`parseDelResCookies`, `_original/lib/util/index.js:2776-2795`).
    /// Previously the key was parsed and then dropped on the response side, so
    /// the rule did nothing at all.
    #[test]
    fn deleting_a_response_cookie_expires_it() {
        let lines = |rule: &str, info: Option<&ReqInfo>| {
            let resolved = resolve(
                &format!("example.com delete://{rule}\n"),
                "http://example.com/",
            );
            let mut headers = HeaderMap::new();
            apply_res_cookies(
                &mut headers,
                &resolved,
                &Deletions::of(&resolved, false),
                info,
            );
            headers
                .get_all(hyper::header::SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };

        let out = lines("resCookies.sid", None);
        assert_eq!(out.len(), 2, "one plain and one Secure: {out:?}");
        assert!(out[0].starts_with("sid=; Expires="), "{:?}", out[0]);
        assert!(out[0].ends_with("; Max-Age=0; Path=/"), "{:?}", out[0]);
        assert!(out[1].contains("; Secure; Path=/"), "{:?}", out[1]);
        // The `Expires` is in the past, which together with `Max-Age=0` is what
        // actually drops the cookie. Compared against a date this proxy renders
        // itself rather than a literal, which would rot.
        let expires = out[0]
            .split("; Expires=")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .expect("an Expires");
        assert_ne!(expires, http_date(0), "an expiry now is not an expiry");
        assert_eq!(expires, http_date(EXPIRED_MAX_AGE * 1000));

        // A bare `cookies.x` is honoured on this side too (`COOKIE_RE`).
        assert_eq!(lines("cookies.sid", None).len(), 2);
        // …and the request-side spelling is not.
        assert!(lines("reqCookies.sid", None).is_empty());

        // A tunnelled request adds two domain-scoped entries, because the
        // cookie may have been set on the parent domain.
        let mut info = build_req_info(
            "GET",
            "https",
            "a.b.example.com",
            443,
            "/",
            &HeaderMap::new(),
            None,
        );
        info.from.tunnel = true;
        let out = lines("resCookies.sid", Some(&info));
        assert_eq!(out.len(), 4, "{out:?}");
        assert!(out[2].contains("Domain=b.example.com"), "{:?}", out[2]);
        // Three labels keep the leading dot; two have no parent at all.
        assert_eq!(parent_domain("b.example.com").as_deref(), Some(".example.com"));
        assert_eq!(parent_domain("example.com"), None);
        // A forward-proxy request gets no domain-scoped entries.
        info.from.tunnel = false;
        assert_eq!(lines("resCookies.sid", Some(&info)).len(), 2);
    }

    /// The deletion wins over a `resCookies://` for the same name on the same
    /// request: upstream folds the deletions in *over* the operators
    /// (`extend(cookies, delKeys)`, `_original/lib/util/index.js:3127-3129`).
    #[test]
    fn deleting_a_cookie_beats_setting_it() {
        let resolved = resolve(
            "example.com resCookies://sid=new delete://resCookies.sid\n",
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        apply_res_cookies(&mut headers, &resolved, &Deletions::of(&resolved, false), None);
        let out: Vec<_> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(out.len(), 2, "the expiring pair, not the value: {out:?}");
        assert!(out.iter().all(|c| c.contains("Max-Age=0")), "{out:?}");
    }

    /// `delete://trailer.x` drops a trailing header, and unlike every other
    /// delete key it is not scoped by `req`/`res` (`TRAILER_RE` is unanchored).
    #[test]
    fn deleting_a_trailer_drops_it() {
        let resolved = resolve(
            "example.com trailers://x-a=1&x-b=2 delete://trailer.x-a\n",
            "http://example.com/",
        );
        let t = build_trailers(&resolved);
        assert!(t.get("x-a").is_none(), "the deleted trailer is gone");
        assert_eq!(t.get("x-b").unwrap(), "2", "the other one stays");

        // The deletion applies after the operators, so both spellings of a
        // name on one request end up without it.
        let resolved = resolve(
            "example.com trailers://x-a=1 delete://resTrailer.x-a\n",
            "http://example.com/",
        );
        assert!(build_trailers(&resolved).get("x-a").is_none());
        // It is not a response *header* deletion.
        let resolved = resolve("example.com delete://trailer.x-a\n", "http://example.com/");
        assert!(Deletions::of(&resolved, false).headers.is_empty());
    }

    /// `maxAge` emits the `Expires`/`Max-Age` pair, and the sentinel whistle
    /// uses for a deletion is written as `Max-Age=0` (`EXPIRED_SEC`).
    #[test]
    fn a_cookie_max_age_expires_it() {
        let out = set_cookie(r#"{"a":{"value":"1","maxAge":600}}"#);
        assert!(out.starts_with("a=1; Expires="), "got {out}");
        assert!(out.ends_with(" GMT; Max-Age=600"), "got {out}");

        let out = set_cookie(&format!(r#"{{"a":{{"value":"1","maxAge":{EXPIRED_MAX_AGE}}}}}"#));
        assert!(out.ends_with("; Max-Age=0"), "got {out}");

        // Every spelling upstream accepts, and only those.
        for key in ["maxAge", "maxage", "MaxAge", "Max-Age", "max-age"] {
            assert!(
                set_cookie(&format!(r#"{{"a":{{"value":"1","{key}":60}}}}"#))
                    .ends_with("; Max-Age=60"),
                "{key} should be read"
            );
        }
        // `parseInt` semantics: a leading integer, or the attribute is skipped.
        assert_eq!(set_cookie(r#"{"a":{"value":"1","maxAge":"600s"}}"#).split("; ").last(), Some("Max-Age=600"));
        assert_eq!(set_cookie(r#"{"a":{"value":"1","maxAge":"soon"}}"#), "a=1");
    }

    /// The request side has nowhere to put attributes, so it takes the value
    /// alone — upstream's `typeof value == 'object' ? value.value : value`.
    #[test]
    fn a_cookie_object_is_only_a_value_on_the_request() {
        let resolved = resolve(
            r#"example.com reqCookies://{"sid":{"value":"x","httpOnly":true}}"#,
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        apply_req_cookies(&mut headers, &resolved);
        assert_eq!(headers.get(hyper::header::COOKIE).unwrap(), "sid=x");
    }

    /// The request method is uppercased on **every** request, not only one
    /// carrying a `method://` (`req.method = util.getMethod(data.method ||
    /// req.method)`, `_original/lib/inspectors/req.js:536`, impl
    /// `util/common.js:1608-1613`).
    ///
    /// It matters beyond tidiness: the normalised method is what every
    /// body gate downstream reads, so a client sending `post` was treated as a
    /// method that carries no body and had its `reqBody://` silently dropped.
    #[test]
    fn the_method_is_uppercased_whether_or_not_a_rule_names_one() {
        let sent = |rule: &str, arrived: &str| {
            let resolved = resolve(
                &format!("example.com {rule}\n"),
                "http://example.com/",
            );
            let mut parts = hyper::Request::builder()
                .method(arrived)
                .uri("http://example.com/")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            apply_request(&mut parts, &resolved);
            parts.method.to_string()
        };

        // No `method://` at all: the client's own spelling is normalised.
        assert_eq!(sent("host://1.1.1.1", "post"), "POST");
        assert_eq!(sent("host://1.1.1.1", "GET"), "GET");
        // A rule's value is normalised the same way, and trimmed.
        assert_eq!(sent("method://put", "GET"), "PUT");
        // An unusable value falls back to `GET`, as `getMethod` does.
        assert_eq!(sent("method://", "POST"), "GET");
    }

    /// `replaceStatus://` only writes the auth challenge when the status
    /// actually changed (`replaceStatus != _res.statusCode`,
    /// `_original/lib/inspectors/res.js:826-832`).
    ///
    /// Without the guard a rule pinned to `401` wrote a `WWW-Authenticate:
    /// Basic` onto a response that was *already* a 401 and had deliberately not
    /// asked for one — and a browser answers that header with a login box.
    #[test]
    fn replace_status_only_challenges_when_the_status_changed() {
        let challenge = |rule: &str, from: u16| {
            let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
            let mut parts = Response::builder()
                .status(from)
                .body(())
                .unwrap()
                .into_parts()
                .0;
            apply_response(&mut parts, &resolved);
            (
                parts.status.as_u16(),
                parts
                    .headers
                    .get("www-authenticate")
                    .map(|v| v.to_str().unwrap().to_string()),
            )
        };

        // A real change still challenges.
        assert_eq!(
            challenge("replaceStatus://401", 200),
            (401, Some("Basic realm=User Login".to_string()))
        );
        // Replacing a status with itself does not.
        assert_eq!(challenge("replaceStatus://401", 401), (401, None));
        // `disable://userLogin` suppresses the challenge without suppressing
        // the status change (`isDisableUserLogin`, `util/index.js:3558-3563`)…
        assert_eq!(
            challenge("replaceStatus://401 disable://userLogin", 200),
            (401, None)
        );
        // …and `enable://userLogin` wins over it.
        assert_eq!(
            challenge("replaceStatus://401 disable://userLogin enable://userLogin", 200),
            (401, Some("Basic realm=User Login".to_string()))
        );
        // 407 takes the proxy spelling.
        let resolved = resolve("example.com replaceStatus://407\n", "http://example.com/");
        let mut parts = res_parts(&[]);
        apply_response(&mut parts, &resolved);
        assert_eq!(
            parts.headers.get("proxy-authenticate").unwrap(),
            "Basic realm=User Login"
        );
    }

    /// `disable://301` hands back a `302` instead
    /// (`_original/lib/inspectors/res.js:833-835`).
    ///
    /// This is the flag you reach for once a site has taught the browser a
    /// permanent redirect you now need to override, and it did nothing.
    #[test]
    fn disable_301_downgrades_the_redirect() {
        let status = |rule: &str, from: u16| {
            let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
            let mut parts = Response::builder().status(from).body(()).unwrap().into_parts().0;
            apply_response(&mut parts, &resolved);
            parts.status.as_u16()
        };
        assert_eq!(status("disable://301", 301), 302);
        // Only a 301, and only with the flag.
        assert_eq!(status("disable://301", 302), 302);
        assert_eq!(status("disable://301", 308), 308);
        assert_eq!(status("host://1.1.1.1", 301), 301);
        // It runs after `replaceStatus://`, so a rule that *produces* a 301 is
        // downgraded too.
        assert_eq!(status("replaceStatus://301 disable://301", 200), 302);
    }

    /// `Location` is percent-encoded on the way out (`encodeNonLatin1Char`,
    /// `_original/lib/inspectors/res.js:946-949`).
    ///
    /// Node's URL layer only speaks ASCII, so a redirect to a path with a
    /// non-Latin-1 character in it reached the browser as mojibake — or, here,
    /// as a header value hyper would not carry at all.
    #[test]
    fn location_is_re_encoded() {
        let location = |rules: &str, arrived: &str| {
            let resolved = resolve(rules, "http://example.com/");
            let mut parts = res_parts(&[("location", arrived)]);
            apply_response(&mut parts, &resolved);
            parts
                .headers
                .get("location")
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            location("example.com host://1.1.1.1\n", "/搜索"),
            Some("/%E6%90%9C%E7%B4%A2".to_string())
        );
        // ASCII is left exactly as it is.
        assert_eq!(
            location("example.com host://1.1.1.1\n", "https://a.test/x?y=1"),
            Some("https://a.test/x?y=1".to_string())
        );
        // The encode runs *after* the header operators, so a `Location` a rule
        // wrote is encoded too — upstream's order, `extend` at `res.js:927`
        // against the encode at `:946`.
        assert_eq!(
            location("example.com resHeaders://location=/搜\n", "/x/y"),
            Some("/%E6%90%9C".to_string())
        );
    }

    /// `delete://resHeaders.x` runs **after** the injection's CSP and
    /// cache strips (`_original/lib/inspectors/res.js:1160-1165` against
    /// `:1097-1104`), so it can take away what they just wrote.
    ///
    /// Deleting first left the `Cache-Control: no-store` standing, which is the
    /// one header anyone writes this pair of rules to get rid of.
    #[test]
    fn a_delete_outlives_the_injections_own_headers() {
        let resolved = resolve(
            "example.com resAppend://x delete://resHeaders.cache-control\n",
            "http://example.com/",
        );
        let mut parts = res_parts(&[("content-type", "text/html"), ("cache-control", "max-age=60")]);
        apply_response(&mut parts, &resolved);
        assert!(
            parts.headers.get("cache-control").is_none(),
            "the injection's own no-store must be deletable"
        );
        // …and the injection still writes it when nothing deleted it.
        let kept = resolve("example.com resAppend://x\n", "http://example.com/");
        let mut parts = res_parts(&[("content-type", "text/html")]);
        apply_response(&mut parts, &kept);
        assert_eq!(parts.headers.get("cache-control").unwrap(), "no-store");
    }

    /// An empty header value is a value, not a deletion
    /// (`extend(req.headers, data.headers)`,
    /// `_original/lib/inspectors/req.js:105`; `res.js:927` on the other side).
    ///
    /// The port removed the header instead, which is a different rule with a
    /// different spelling (`delete://reqHeaders.x`) and the opposite meaning to
    /// any server that branches on a header being *present*. `ua://` and
    /// `referer://` ride the same assignment and had the same bug.
    #[test]
    fn an_empty_header_value_is_sent_not_deleted() {
        let resolved = resolve(
            "example.com reqHeaders://x-a=&x-b=1 ua:// referer://\n",
            "http://example.com/",
        );
        let mut parts = req_parts(&[
            ("x-a", "arrived"),
            ("user-agent", "MyUA"),
            ("referer", "http://ref.test/"),
        ]);
        apply_request(&mut parts, &resolved);
        for name in ["x-a", "user-agent", "referer"] {
            assert_eq!(
                parts.headers.get(name).map(|v| v.to_str().unwrap()),
                Some(""),
                "{name} must be sent empty, not dropped"
            );
        }
        assert_eq!(parts.headers.get("x-b").unwrap(), "1");

        // The response side assigns the same way.
        let res = resolve("example.com resHeaders://x-a=\n", "http://example.com/");
        let mut parts = res_parts(&[("x-a", "arrived")]);
        apply_response(&mut parts, &res);
        assert_eq!(parts.headers.get("x-a").map(|v| v.to_str().unwrap()), Some(""));

        // Removal is still available, under its own name.
        let del = resolve(
            "example.com reqHeaders://x-a=1 delete://reqHeaders.x-a\n",
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &del);
        assert!(parts.headers.get("x-a").is_none());
    }

    /// Every `disable://` flag that strips a request header
    /// (`disableReqProps`, `_original/lib/util/index.js:2977-3009`). None of
    /// these were applied before: the request went out with the cookie, the
    /// referer and the user-agent a rule had asked to withhold, which is a
    /// privacy promise the proxy was quietly breaking.
    #[test]
    fn disable_strips_request_headers() {
        let sent = |rule: &str, name: &str| {
            let resolved = resolve(
                &format!("example.com {rule}\n"),
                "http://example.com/",
            );
            let mut parts = req_parts(&[
                ("cookie", "sid=secret"),
                ("user-agent", "MyUA"),
                ("referer", "http://ref.test/"),
                ("accept-encoding", "gzip"),
                ("x-requested-with", "XMLHttpRequest"),
            ]);
            apply_request(&mut parts, &resolved);
            parts.headers.get(name).map(|v| v.to_str().unwrap().to_string())
        };

        assert_eq!(sent("disable://ua", "user-agent"), None);
        assert_eq!(sent("disable://gzip", "accept-encoding"), None);
        assert_eq!(sent("disable://referer", "referer"), None);
        // whistle takes the misspelling too, because it matches the header name.
        assert_eq!(sent("disable://referrer", "referer"), None);
        assert_eq!(sent("disable://ajax", "x-requested-with"), None);
        for spelling in ["cookie", "cookies", "reqCookie", "reqCookies"] {
            assert_eq!(sent(&format!("disable://{spelling}"), "cookie"), None, "{spelling}");
        }
        // `enable://captureStream` drops the encoding too: whistle wants the
        // origin's bytes uncompressed (`isEnable`, `util/index.js:675-677`).
        assert_eq!(sent("enable://captureStream", "accept-encoding"), None);
        // …unless the same request also disables it, which is what `isEnable`
        // means — `enable` alone is not enough.
        assert_eq!(
            sent("enable://captureStream disable://captureStream", "accept-encoding"),
            Some("gzip".to_string())
        );
        // A flag nobody set leaves everything alone.
        assert_eq!(sent("host://1.1.1.1", "cookie"), Some("sid=secret".to_string()));
    }

    /// The two abort gates are two different moments, and each has its own
    /// `disable://` cancellation (`needAbortReq`/`needAbortRes`,
    /// `_original/lib/util/index.js:3893-3915`).
    ///
    /// The port collapsed all three spellings into one before-the-request gate,
    /// which got `abortRes` wrong (it must let the request reach the origin) and
    /// ignored `disable://` entirely — so `enable://abort` on a domain could not
    /// be exempted for a single path, the one thing a `disable://` line is for.
    #[test]
    fn the_abort_gates_are_two_moments_and_both_can_be_cancelled() {
        let gates = |rules: &str| {
            let r = resolve(&format!("example.com {rules}\n"), "http://example.com/");
            (aborts_request(&r), aborts_response(&r))
        };

        // `abort` arms both, but the request gate fires first, so the origin is
        // never contacted.
        assert_eq!(gates("enable://abort"), (true, true));
        // `abortReq` stops at the request; `abortRes` lets it through and kills
        // the answer.
        assert_eq!(gates("enable://abortReq"), (true, false));
        assert_eq!(gates("enable://abortRes"), (false, true));

        // A `disable://` of the same name cancels its own gate…
        assert_eq!(gates("enable://abort disable://abortReq"), (false, true));
        assert_eq!(gates("enable://abort disable://abortRes"), (true, false));
        // …and `disable://abort` cancels both, whatever armed them.
        assert_eq!(gates("enable://abort disable://abort"), (false, false));
        assert_eq!(gates("enable://abortReq|abortRes disable://abort"), (false, false));

        // Nothing set: nothing aborts.
        assert_eq!(gates("host://1.1.1.1"), (false, false));
    }

    /// `disable://keepAlive` closes the hop to the **origin**, not the client's
    /// connection (`_original/lib/inspectors/res.js:447-449`).
    ///
    /// The port had it backwards: it wrote `Connection: close` onto the response
    /// and left the origin socket pooled, so the one connection the flag exists
    /// to un-pool stayed up and the browser's was torn down instead — a rule
    /// that made every page slower while doing nothing it promised.
    #[test]
    fn disable_keep_alive_closes_the_origin_hop() {
        for spelling in ["keepAlive", "keepalive"] {
            let resolved = resolve(
                &format!("example.com disable://{spelling}\n"),
                "http://example.com/",
            );
            let mut parts = req_parts(&[]);
            apply_request(&mut parts, &resolved);
            assert_eq!(
                parts.headers.get("connection").map(|v| v.to_str().unwrap()),
                Some("close"),
                "{spelling} must close the outgoing request"
            );
            // …and the answer to the client is left alone.
            let mut res = res_parts(&[]);
            apply_response(&mut res, &resolved);
            assert!(
                res.headers.get("connection").is_none(),
                "{spelling} must not touch the response"
            );
        }
        // Nothing set: the request keeps whatever framing it arrived with.
        let none = resolve("example.com host://1.1.1.1\n", "http://example.com/");
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &none);
        assert!(parts.headers.get("connection").is_none());
    }

    /// Every request's `Accept-Encoding` is narrowed to what this proxy can
    /// round-trip (`removeUnsupportsHeaders`,
    /// `_original/lib/util/index.js:1549-1570`, run at `req.js:579`).
    ///
    /// This was missing entirely, and it is the quiet reason a body operator
    /// "stops working" on a modern browser: Chrome asks for
    /// `gzip, deflate, br, zstd`, the origin answers zstd, `coding.rs` cannot
    /// undo it, and `resReplace://` searches a compressed stream for its
    /// pattern, finds nothing, and reports nothing.
    #[test]
    fn accept_encoding_is_narrowed_to_what_can_be_round_tripped() {
        let sent = |arrived: &str| {
            let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/");
            let mut parts = req_parts(&[("accept-encoding", arrived)]);
            apply_request(&mut parts, &resolved);
            parts
                .headers
                .get("accept-encoding")
                .map(|v| v.to_str().unwrap().to_string())
        };

        // What a browser actually sends.
        assert_eq!(sent("gzip, deflate, br, zstd"), Some("gzip, br".into()));
        // Order is the client's, not a fixed one, and the separator is `, `.
        assert_eq!(sent("br,gzip"), Some("br, gzip".into()));
        assert_eq!(sent("  GZIP , BR  "), Some("gzip, br".into()));
        // `deflate` goes, though this port could decode it — upstream's caller
        // does not pass `supportsDeflate`.
        assert_eq!(sent("deflate"), Some("deflate".into()), "left alone: nothing survived");
        assert_eq!(sent("gzip, deflate"), Some("gzip".into()));
        // A `q` parameter takes the coding with it: the comparison is against
        // the whole token.
        assert_eq!(sent("gzip;q=1.0, br;q=0.9"), Some("gzip;q=1.0, br;q=0.9".into()));
        assert_eq!(sent("gzip;q=1.0, br"), Some("br".into()));
        // Empty tokens are not codings.
        assert_eq!(sent("gzip,,br"), Some("gzip, br".into()));
        // A request that asked for nothing keeps its header, whatever it was.
        assert_eq!(sent("zstd"), Some("zstd".into()));
        assert_eq!(sent("identity"), Some("identity".into()));
        // No header, nothing to narrow.
        let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/");
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &resolved);
        assert!(parts.headers.get("accept-encoding").is_none());

        // `disable://gzip` still wins: it runs after this
        // (`req.js:579-580`).
        let off = resolve("example.com disable://gzip\n", "http://example.com/");
        let mut parts = req_parts(&[("accept-encoding", "gzip, deflate, br, zstd")]);
        apply_request(&mut parts, &off);
        assert!(parts.headers.get("accept-encoding").is_none());
    }

    /// `disable://cache` strips the conditional headers *and* asks for no cache
    /// (`disableReqCache`, `_original/lib/util/index.js:974-982`).
    #[test]
    fn disable_cache_strips_the_conditional_headers() {
        let resolved = resolve("example.com disable://cache\n", "http://example.com/");
        let mut parts = req_parts(&[
            ("if-none-match", "\"v1\""),
            ("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ("etag", "\"v1\""),
            ("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
        ]);
        apply_request(&mut parts, &resolved);
        for gone in ["if-none-match", "if-modified-since", "etag", "last-modified"] {
            assert!(parts.headers.get(gone).is_none(), "{gone} must be stripped");
        }
        assert_eq!(parts.headers.get("pragma").unwrap(), "no-cache");
        assert_eq!(parts.headers.get("cache-control").unwrap(), "no-cache");
    }

    /// The half that matters more, because nobody asks for it: **any** response
    /// body operator busts the request's cache
    /// (`notAllowCache(resRules) && disableReqCache(req.headers)`,
    /// `_original/lib/inspectors/res.js:1328`).
    ///
    /// Without it a `resBody://` is silently inert on a reload: the conditional
    /// request reaches the origin, the origin answers `304 Not Modified` with no
    /// body, and there is nothing for the operator to rewrite. Measured against
    /// a running proxy before the fix — the first load said `REWRITTEN`, the
    /// reload said `304` — which is the worst shape of bug to be handed, an
    /// operator that works until you press reload.
    #[test]
    fn a_response_body_operator_busts_the_request_cache() {
        let conditional = || {
            req_parts(&[
                ("if-none-match", "\"v1\""),
                ("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ])
        };
        let survives = |rule: &str| {
            let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
            let mut parts = conditional();
            apply_request(&mut parts, &resolved);
            parts.headers.contains_key("if-none-match")
        };

        // Every operator on upstream's list, not just the obvious one.
        for rule in [
            "resBody://x",
            "resPrepend://x",
            "resAppend://x",
            "resReplace://a=b",
            "resMerge://{}",
            "htmlAppend://x",
            "jsPrepend://x",
            "cssBody://x",
            "attachment://f.txt",
            "resWrite:///tmp/whistle-rs-test-write",
            "resWriteRaw:///tmp/whistle-rs-test-write-raw",
        ] {
            assert!(!survives(rule), "{rule} must bust the cache");
        }

        // A rule that cannot change the body leaves the conditional request
        // alone — this is not a blanket "disable caching for everything".
        for rule in ["host://1.1.1.1", "resHeaders://x-a=1", "resType://json"] {
            assert!(survives(rule), "{rule} must not touch the cache headers");
        }
    }

    /// A response-body operator strips them too, without anyone asking
    /// (`notAllowCache`, `_original/lib/inspectors/res.js:33-60,:1328`).
    ///
    /// This is the failure that looks like a bug rather than a gap: a rule that
    /// rewrites the body works on the first request and silently does nothing on
    /// a reload, because the origin answers `304` with no body to rewrite.
    #[test]
    fn a_body_operator_forbids_a_conditional_request() {
        let conditional_survives = |rule: &str| {
            let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
            let mut parts = req_parts(&[("if-none-match", "\"v1\"")]);
            apply_request(&mut parts, &resolved);
            parts.headers.get("if-none-match").is_some()
        };

        // Every operator on upstream's list, spot-checked across its families.
        for rule in [
            "resBody://x",
            "resReplace://a=b",
            "resPrepend://x",
            "resAppend://x",
            "htmlAppend://x",
            "jsPrepend://x",
            "cssBody://x",
            "resMerge://{}",
            "attachment://f.txt",
            "resWrite:///tmp/x",
            "resWriteRaw:///tmp/x",
        ] {
            assert!(!conditional_survives(rule), "{rule} must forbid a 304");
        }

        // A rule that does not touch the body leaves the request conditional —
        // stripping it unasked would cost every such request its 304.
        for rule in ["host://1.1.1.1", "resHeaders://x-a=1", "replaceStatus://500"] {
            assert!(conditional_survives(rule), "{rule} must keep the 304 path");
        }
    }

}


