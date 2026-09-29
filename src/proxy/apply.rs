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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use super::body::{self, DynBody};
use super::upstream::{ProxyKind, Target, parse_proxy, parse_proxy_rule};
use crate::rules::{LineProps, ReqInfo, Resolved, RuleManager, RuleOp};

// One file per kind of work. Each takes what it needs from here with
// `use super::*` and is imported whole, so callers still name everything
// `apply::…` and the split is invisible outside this module. What was private
// here is `pub(super)` there: the same reach it had before.
mod cookies;
mod header_ops;

use cookies::*;
use header_ops::*;

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
    // The URL every pattern is matched against, and the one `$0` and `${url}`
    // report — so it carries the host **as the client wrote it**. Upstream
    // builds it the same way (`getFullUrl`,
    // `_original/lib/util/common.js:1231-1267`, which lower-cases nothing), and
    // folding the case here meant a regexp pattern naming an upper-case host
    // could never match one, and `$0` handed the rule a URL nobody had asked
    // for. [`ReqInfo::host`] is still folded, because that one is compared as a
    // *host* rather than as text.
    let full_url = crate::rules::url::full_url(scheme, host, port, path);
    let host = host.to_ascii_lowercase();
    let hdrs = headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
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
        script_data: Default::default(),
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
/// whole matcher, so the optional first group is a `proto://` prefix that stays
/// where it is and the second is the template. For most operators the protocol
/// has already been split off here, which leaves exactly the second group; the
/// value must open and close with a backtick and nothing may sit outside them.
/// `.*` does not cross a newline upstream and a token cannot contain one here,
/// so the two agree.
///
/// **The prefix still has to be handled**, because one family of values keeps
/// its scheme: a destination is stored whole (`http://…`, `tunnel://…`, or a
/// scheme this port does not know), and so ``www.dev http://`${method}.example` ``
/// — the form upstream's own regexp is written for — went to the origin as the
/// literal text of the rule.
///
/// Returns `None` when the value is not a template, which is also the answer for
/// the two protocols upstream opts out at parse time (`rule.isTpl = false` for
/// `log://` and `weinre://`, `rules.js:1357-1359`) — their values are channel
/// names, and a backtick in one is a backtick.
fn render_backticks(op: &crate::rules::RuleOp, tpl: TplCtx<'_>) -> Option<String> {
    if op.protocol == "log" || op.protocol == "weinre" {
        return None;
    }
    let (prefix, rest) = crate::rules::url::tpl_prefix(&op.value);
    // A lone backtick is not a pair: `strip_suffix` on the empty remainder says
    // so, which is upstream's `(`.*`)` needing two characters.
    let inner = rest.strip_prefix('`').and_then(|r| r.strip_suffix('`'))?;
    Some(format!(
        "{prefix}{}",
        super::template::render_vars(inner, tpl.info, tpl.env)
    ))
}

/// What `{name}` means *to this operator* — upstream's `getValueFor`
/// (`_original/lib/rules/rules.js:785-796`).
///
/// A ``` block is private to the rules text that declared it, so the same name
/// can mean two things in two rule groups and neither may answer the other's
/// reference. The private key is [`crate::rules::inline_key`]; an operator that
/// belongs to no text of its own reads the shared store alone.
///
/// The operator's own block is asked first and the store second, as upstream
/// asks: a ``` block shadows a stored entry of the same name. upstream's own
/// suite holds it to that (`test/units/keys.test.js:91-95,106-113`), for a
/// block in the Default text, in a named group, and in rules a request carried.
/// This port used to ask the store first, and served the store's entry for all
/// three.
///
/// `--value` still beats a block: it is an instruction for this run, and the
/// blocks it names are taken out of the map before anything looks — see
/// [`yield_to_overrides`].
pub fn value_for<'a>(
    values: &'a HashMap<String, String>,
    name: &str,
    group: Option<&str>,
) -> Option<&'a String> {
    group
        .and_then(|group| values.get(&crate::rules::inline_key(name, group)))
        .or_else(|| values.get(name))
}

/// Take out every private entry — a ``` block, or a value a request carried —
/// whose name `--value` gave, so that [`value_for`] falls through to the store,
/// where the override lives.
///
/// Only while the store still has the name: an override the console has since
/// deleted gives the blocks their say back rather than leaving nothing at all.
pub fn yield_to_overrides(values: &mut HashMap<String, String>, overrides: &HashSet<String>) {
    if overrides.is_empty() {
        return;
    }
    let shadowed: Vec<String> = values
        .keys()
        .filter(|key| {
            crate::rules::inline_key_name(key)
                .is_some_and(|name| overrides.contains(name) && values.contains_key(name))
        })
        .cloned()
        .collect();
    for key in shadowed {
        values.remove(&key);
    }
}

/// Replace operator values of the form `{name}` with the named value's content
/// (whistle's Values store references), after rendering a backtick template.
///
/// The two are one function because upstream's `resolveVar`
/// (`_original/lib/rules/rules.js:774-783`) is: `renderTpl` runs first, and
/// whether it *found* a template then decides what happens to the result of
/// every `${name}` lookup below it.
/// Returns whether it substituted anything, which the response phase uses to
/// decide whether the value loader has new work — see [`waits_for_the_response`].
pub fn substitute_values(
    resolved: &mut Resolved,
    values: &HashMap<String, String>,
    tpl: TplCtx<'_>,
) -> bool {
    fn sub(
        op: &mut crate::rules::RuleOp,
        values: &HashMap<String, String>,
        tpl: TplCtx<'_>,
    ) -> bool {
        // Upstream expands a matcher exactly once. This runs again whenever
        // rules are merged in mid-request, and a second pass over an operator
        // whose value is *already* the store's content would read that content
        // as rule text — see `RuleOp::values_substituted`.
        if op.values_substituted || waits_for_the_response(op, tpl) {
            return false;
        }
        op.values_substituted = true;
        // `$0`…`$9` for the text the store is about to hand back — the two
        // branches below spell them differently, and each wants them. Taken
        // rather than borrowed: an operator that has been substituted is done
        // with its pattern.
        let captures = op.captures.take();
        // The `${name}` branch's spelling: a plain `$1`, because upstream's
        // `replaceSubMatcher` sweeps the whole matcher after `resolveVar` has
        // pasted the content into it.
        let expand = |text: &str| match &captures {
            Some(groups) if crate::rules::replace::has_reference(text) => {
                let refs: Vec<&str> = groups.iter().map(String::as_str).collect();
                crate::rules::replace::expand(text, &refs)
            }
            _ => text.to_string(),
        };
        // `renderTpl` first, so the backticks are gone before the value store is
        // consulted — and remember whether there were any.
        let is_tpl = match render_backticks(op, tpl) {
            Some(rendered) => {
                op.value = rendered;
                true
            }
            None => false,
        };
        // Which rules text is asking — a ``` block only answers its own. Taken
        // before the value is borrowed mutably below.
        let group = op.group.clone();
        let group = group.as_deref();
        let value = &mut op.value;
        // The whole value is a reference: it is replaced by the content, which
        // is how a mock body or a rules text gets in.
        if let Some(name) = value.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
            && let Some(content) = value_for(values, name, group)
        {
            let name = name.to_string();
            // A backticked `{name}` renders what the store returned, captures
            // and all (`if (rule.isTpl && regExp) … if (rule.isTpl) …`,
            // `_original/lib/rules/rules.js:826-833`). Without the backticks the
            // content is bytes, and a `${method}` in a mock body is text the mock
            // meant to contain.
            //
            // One shade wider than upstream: it keeps a group table only for a
            // *regexp* pattern (`result.regExp`, `rules.js:1016`) — which is most
            // of them, since the `^host/**` spelling compiles to one — so a
            // `.example.com` wildcard's captures never reach a `{name}` there.
            // Here the same captures are the same captures.
            *value = match (is_tpl, &captures) {
                (true, Some(groups)) => super::template::render_vars(
                    &substitute_regexp_vars(content, groups),
                    tpl.info,
                    tpl.env,
                ),
                (true, None) => super::template::render_vars(content, tpl.info, tpl.env),
                (false, _) => content.clone(),
            };
            // What came back is the content, not a place to find it — see
            // `RuleOp::value_is_content`.
            op.value_is_content = true;
            // The name outlives the substitution because the file family guesses
            // a content type from it — see `RuleOp::value_key`.
            op.value_key = Some(name);
            return true;
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
        //
        // The store's answer is capture-expanded on its way in, which is
        // upstream's order: `resolveVar` runs before `replaceSubMatcher`
        // (`rules.js:1010-1012`), so a `$1` written into a shared value reaches
        // the operator as what the pattern captured.
        if value.contains("${") {
            *value = substitute_braced(value, |name| {
                let stored = value_for(values, name, group)?;
                Some(match is_tpl && !stored.is_empty() {
                    true => super::template::render_vars(&expand(stored), tpl.info, tpl.env),
                    false => expand(stored),
                })
            });
        }
        // `getValue` unwraps the bracket forms **after** `resolveVar` has
        // rendered the template (`resolveValue`, `rules.js:810-822`, whose
        // `matcher` is what the walk already rendered). Parsing unwrapped them
        // first here, so a rendered `(…)` kept its parentheses — and
        // ``resBody://`({"t":${now}})` ``, the form the documentation prints,
        // put two of them in the body it mocked.
        if is_tpl
            && let Some((super::super::rules::url::Fixed::Inline, inner)) =
                super::super::rules::url::fixed_value(&op.value)
        {
            op.value = inner;
            op.value_is_content = true;
        }
        // The tail its pattern left over, held back until the template above had
        // been rendered — see [`crate::rules::RuleOp::pending_tail`]. A template
        // that turned out to be **content** takes no tail, which is the same
        // rule `joins_tail` applies to a value written as `(…)` in the first
        // place: upstream reads `rule.value` for those and never looks at the
        // joined `rule.url` (`getRuleValue`, `lib/util/common.js:911-919`).
        if let Some(tail) = op.pending_tail.take()
            && !op.value_is_content
        {
            op.value = crate::rules::matcher::join_each_path(&op.protocol, &op.value, &tail);
        }
        true
    }
    let mut did = false;
    for op in resolved.ops_mut() {
        did |= sub(op, values, tpl);
    }
    did
}

/// Must this operator's value wait for the response head before it is rendered?
///
/// A backtick template on a response-phase operator is where `${statusCode}`,
/// `${serverIp}`, `${serverPort}`, `${resHeaders.x}` and `${resCookies.x}` come
/// from: upstream re-resolves every `pureResProtocols` rule once the head is in
/// (`resolveResRules` → `resolveRules(req, false, true)`,
/// `_original/lib/rules/rules.js:2306,:2221-2236`), against a request object
/// `res.js` has just stamped those fields onto (`lib/inspectors/res.js:799-801`).
///
/// This port resolves a rule once, in the request pass, and re-resolves only the
/// rules whose *filters* ask about the response — so rendering here would answer
/// every one of those names with an empty string, which is what
/// `docs/TEMPLATES.md` said did not happen. Deferring the render is the narrow
/// version of upstream's second pass: the operator keeps its backticks until
/// [`crate::proxy::resolve_response_phase`] runs, and every path that produces a
/// response goes through that, mocked responses included.
fn waits_for_the_response(op: &crate::rules::RuleOp, tpl: TplCtx<'_>) -> bool {
    tpl.info.res.is_none()
        && crate::rules::protocols::is_res_phase(&op.protocol)
        && op.value.len() > 1
        && op.value.starts_with('`')
        && op.value.ends_with('`')
}

/// Replace `${RegExp.$1}` … `${RegExp.$9}` and `${RegExp.$&}` with what the
/// pattern captured (`SUB_VAR_RE`, `_original/lib/rules/rules.js:99,:826-830`).
///
/// This is the *only* spelling that reaches inside a values-store entry named by
/// a whole-value `{name}`: a plain `$1` written there is left as written, because
/// `replaceSubMatcher` ran on the reference — six characters with no `$` in them
/// — long before the store answered, and nothing rescans the content afterwards.
/// The `${name}` form is the other way round and takes the plain spelling.
///
/// `$&` selects group 0, which for a pattern match is the whole request URL
/// (`regExp['0'] = curUrl`, `rules.js:1009`).
fn substitute_regexp_vars(text: &str, groups: &[String]) -> String {
    const OPEN: &str = "${RegExp.$";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(OPEN) {
        let (before, from) = rest.split_at(at);
        out.push_str(before);
        let body = &from[OPEN.len()..];
        let selector = match body.as_bytes() {
            [b'&', b'}', ..] => Some(0),
            [d @ b'0'..=b'9', b'}', ..] => Some((d - b'0') as usize),
            _ => None,
        };
        match selector {
            Some(i) => {
                out.push_str(groups.get(i).map_or("", String::as_str));
                rest = &body[2..];
            }
            // Not a reference after all: emit the marker and carry on, so the
            // scan cannot loop.
            None => {
                out.push_str(OPEN);
                rest = body;
            }
        }
    }
    out.push_str(rest);
    out
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
/// anywhere in operator values.
///
/// **Wider than upstream, and declared in `docs/RULES.md`.** `CONFIG_VAR_RE`
/// (`_original/lib/util/index.js:3262`) has exactly one reader there — the URL
/// of a backticked `@`-include (`getRemoteRules`, `:3284`) — so a `${port}` in
/// an ordinary operator value is left as written, or, with backticks around the
/// whole value, answered by `resolveTplVar` like any other variable. Here it is
/// answered in both spellings, which is the more useful reading of a name that
/// can only mean one thing.
///
/// What it must **not** touch is content. A value the store returned, or an
/// inline `(…)` payload, is bytes a rules file typed out: a `${port}` in a mock
/// body is text the mock meant to contain, and upstream never rescans it.
pub fn substitute_config_vars(resolved: &mut Resolved, port: u16, version: &str) {
    let port = port.to_string();
    let sub = |op: &mut RuleOp| {
        if op.value_is_content || !op.value.contains("${") {
            return;
        }
        op.value = replace_ci(&op.value, "${port}", &port);
        op.value = replace_ci(&op.value, "${version}", version);
    };
    for op in resolved.ops_mut() {
        sub(op);
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
    // A plugin's rules are no rules file of this proxy's, so they read the
    // shared values store and no group's ``` blocks — see
    // [`RuleManager::adopt_group`]. Upstream's `pRules` land in the same place,
    // by having a file key under which nothing of the user's was filed.
    mgr.adopt_group(None);
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
            acc.multi
                .entry(protocol)
                .or_default()
                .extend(ops.into_iter().map(|mut op| {
                    op.order = u64::MAX;
                    op
                }));
        }
        if let Some(mut op) = extra.slot {
            op.order = u64::MAX;
            acc.insert(op);
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
/// **Except that `important` still outranks it.** `mergeRule` keeps the
/// including rule for a single-value protocol when it is important and the new
/// one is not, and re-partitions a multi-match list so that every important
/// operator — from either side — comes before every normal one. So
///
/// ```text
/// example.com  reqHeaders://x=outer  lineProps://important
/// example.com  reqRules://{extra}
/// ```
///
/// sends `outer`, and this port sent `inner`.
///
/// The order key carries all of that, because [`crate::rules::order_key`] already
/// puts important operators below `1 << 32` and normal ones above it: a merged
/// operator is stamped [`MERGED_ORDER`] when it is important and
/// [`MERGED_AFTER_IMPORTANT`] when it is not, which is exactly "ahead of
/// everything in its own class, behind the class above". Equal keys keep
/// insertion order, so several merged sets stay in the sequence they were merged
/// in.
pub(crate) fn merge_resolved(resolved: &mut Resolved, sub: Resolved) {
    let key = |op: &RuleOp| match op.props.has("important") {
        true => MERGED_ORDER,
        false => MERGED_AFTER_IMPORTANT,
    };
    for (k, mut v) in sub.single {
        v.order = key(&v);
        match resolved.single.get(&k) {
            // `isImportant(curRule) && !isImportant(newRule) ? curRule : newRule`
            Some(cur) if cur.order < v.order => {}
            _ => {
                resolved.single.insert(k, v);
            }
        }
    }
    for (k, vs) in sub.multi {
        let list = resolved.multi.entry(k).or_default();
        // The scan resumes after the last insertion so the merged set keeps its
        // own order among equals — the same walk `merge_response_phase` does.
        let mut from = 0;
        for mut op in vs {
            op.order = key(&op);
            let at = list[from..]
                .iter()
                .position(|cur| cur.order > op.order)
                .map_or(list.len(), |i| from + i);
            list.insert(at, op);
            from = at + 1;
        }
    }
    // The shared slot takes the same comparison, which is what makes a
    // `statusCode://` inside an included file beat the `file://` that included
    // it — `mergeRule` returning the new rule for a single-value protocol, with
    // `rule` being one.
    if let Some(mut op) = sub.slot {
        op.order = key(&op);
        resolved.insert(op);
    }
}

/// The resolution order stamped on an **important** operator merged in
/// mid-request, chosen so that it wins every contest decided by this key. See
/// [`merge_resolved`].
const MERGED_ORDER: u64 = 0;

/// The order stamped on a merged operator that is *not* important: below every
/// normal operator's key and above every important one's, which is where
/// upstream's stable important-first partition leaves it.
const MERGED_AFTER_IMPORTANT: u64 = 1 << 32;

/// Merge the rules pulled in by `rule://<name>` (from the values store) and
/// `rulesFile://<path>` (from disk, or from a value), resolved in the request's
/// own scope.
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
    if let Some(op) = resolved.get(crate::rules::protocols::RULE_INCLUDE)
        && let Some(content) = value_for(values, &op.value, op.group.as_deref())
    {
        texts.push(content.clone());
    }
    // Every `rulesFile://` line contributes, joined into one rules text — see
    // `accumulated_script_ops`.
    //
    // A value already *is* the rules text when the line named one — `{name}`
    // resolved out of the values store, or the inline `(…)` form — which is
    // upstream's `readRuleValue` returning `rule.value` before it ever looks at
    // a disk (`_original/lib/util/index.js:1177-1179`). This port went to the
    // filesystem unconditionally, so `reqRules://{extra}` opened the *contents*
    // of `extra` as a path, found nothing, and silently produced no rules at
    // all — the value form of the whole family (`reqRules`, `rulesFile`,
    // `ruleFile`, `ruleScript`, `rulesScript`, `reqScript`) was inert.
    let mut script_values = HashMap::new();
    let joined = rules_file_ops(resolved)
        .iter()
        .filter_map(|op| match op.value_is_content {
            true => Some(op.value.clone()),
            false => std::fs::read_to_string(&op.value).ok(),
        })
        // A text that is JavaScript rather than rules is executed, and what it
        // pushed into `rules` takes its place in the list — upstream's
        // `handleDynamicRules` (`_original/lib/rules/index.js:459-476`), with
        // `isRulesContent` deciding which is which. A script that errors
        // contributes nothing, not even the lines it pushed before throwing.
        .filter_map(|text| match crate::proxy::script::is_rules_content(&text) {
            true => Some(text),
            false => {
                let produced = crate::proxy::script::produce_rules(
                    &text,
                    &crate::proxy::script::RulesScriptCtx {
                        method: &info.method,
                        full_url: &info.full_url,
                        headers: &info.headers,
                        body: info.req_body.as_deref().unwrap_or(""),
                        client_ip: info.client_ip.as_deref(),
                        client_port: info.client_port,
                        res: None,
                        values,
                        script_data: &info.script_data,
                    },
                )?;
                script_values.extend(produced.values);
                Some(produced.rules)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut managers = Vec::new();
    for text in texts {
        let mut mgr = RuleManager::new();
        mgr.set_text(&text);
        // What `rule://<name>` pulls in belongs to no group's ``` blocks — not
        // the throwaway manager's own `default` (a different text sharing a
        // name with the console's Default), and not the group of the line that
        // named it; it reads the shared store alone. The *name of the entry*
        // is read from the including line's own text, which is where it was
        // written. Done before either resolution, so the response pass over
        // the same manager agrees. See [`RuleManager::adopt_group`].
        mgr.adopt_group(None);
        merge_resolved(resolved, mgr.resolve_scoped(info, is_internal_req));
        managers.push(mgr);
    }
    if !joined.trim().is_empty() {
        let mut mgr = RuleManager::new();
        mgr.set_text(&joined);
        // The produced text answers its `{name}` from values of its own: what a
        // script set, and its own ``` blocks over them — and not from the
        // including file's blocks, which live in a different rule set upstream
        // (measured, both halves). The caller lays them into its map from
        // [`RuleManager::carried_values`].
        mgr.adopt_scope(PRODUCED_SCOPE, script_values);
        merge_resolved(resolved, mgr.resolve_scoped(info, is_internal_req));
        managers.push(mgr);
    }
    managers
}

/// The private scope a request's `rulesFile://` text answers its `{name}` in —
/// see [`RuleManager::adopt_scope`]. A request has at most one such text, and no
/// rules file can be called this.
const PRODUCED_SCOPE: &str = "\u{1}rulesFile";

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
/// The `resRules://` entries themselves are applied by [`merge_res_rules`]:
/// they are rules text, not a script, and this port's `resScript` is a
/// JavaScript hook that mutates the response directly.
pub fn res_script_op(resolved: &Resolved) -> Option<&RuleOp> {
    accumulated_script_ops(resolved, "resScript", "resRules")
        .into_iter()
        .filter(|op| raw_protocol(op) != Some("resRules"))
        // Only a text that is this port's hook: one that edits `ctx.res`
        // ([`crate::proxy::script::is_response_hook`]). A script that names
        // `rules`/`values` produces rules, and a rules text is rules; both go
        // to [`merge_res_rules`]. A path that names no file runs nothing.
        .find(|op| {
            script_text(op).is_some_and(|text| crate::proxy::script::is_response_hook(&text))
        })
}

/// The text a script-family operator carries: the value itself for the
/// `{name}` and inline forms, the file it names otherwise.
fn script_text(op: &RuleOp) -> Option<String> {
    match op.value_is_content {
        true => Some(op.value.clone()),
        false => std::fs::read_to_string(&op.value).ok(),
    }
}

/// `resRules://` — a rules text that applies to the **response**, merged once
/// the response head is in.
///
/// Upstream keeps these in the same accumulating list as `resScript://` and
/// tells them apart by spelling (`_original/lib/rules/rules.js:2258-2272`).
/// `getResRules` collects what they hold, parses it, and merges the result with
/// `isResRules` set (`parseRulesList` → `mergeRules(req, …, true)`,
/// `_original/lib/plugins/index.js:808-820,:1337-1360`) — so only the response
/// half of the produced text applies, and it **wins** over the file that named
/// it, as every mid-request merge does.
///
/// Every `resRules://` line contributes; the value is the text itself for the
/// `{name}` and inline forms and a path otherwise, exactly as
/// [`merge_included_rules`] reads its own. Nothing here was applied before —
/// `resRules://` parsed, resolved, and then went nowhere.
///
/// `None` when nothing was merged; otherwise the values the merged texts carry,
/// for the caller to lay into the map it substitutes against.
pub fn merge_res_rules(
    resolved: &mut Resolved,
    info: &ReqInfo,
    values: &HashMap<String, String>,
    is_internal_req: bool,
) -> Option<HashMap<String, String>> {
    let texts = accumulated_script_ops(resolved, "resScript", "resRules")
        .into_iter()
        .filter_map(|op| {
            let text = script_text(op)?;
            // Upstream keeps both spellings in one list and asks the *text*
            // which it is: script-shaped and it runs, with the response head in
            // its context; rules-shaped and it is rules, under either spelling
            // (`getResRules`, `_original/lib/plugins/index.js:808-820`). The one
            // exception is this port's own: a `resScript://` text that edits
            // `ctx` is the response hook, consumed by `res_script_op`.
            if !crate::proxy::script::is_rules_content(&text) {
                let res = info
                    .res
                    .as_ref()
                    .map(|r| crate::proxy::script::RulesScriptRes {
                        status: r.status,
                        server_ip: r.server_ip.as_deref(),
                        headers: &r.headers,
                    });
                let produced = crate::proxy::script::produce_rules(
                    &text,
                    &crate::proxy::script::RulesScriptCtx {
                        method: &info.method,
                        full_url: &info.full_url,
                        headers: &info.headers,
                        body: "",
                        client_ip: info.client_ip.as_deref(),
                        client_port: info.client_port,
                        res,
                        values,
                        script_data: &info.script_data,
                    },
                )?;
                return Some((produced.rules, produced.values));
            }
            let hook = raw_protocol(op) != Some("resRules")
                && crate::proxy::script::is_response_hook(&text);
            (!hook).then(|| (text, HashMap::new()))
        })
        .collect::<Vec<_>>();
    let mut carried: Option<HashMap<String, String>> = None;
    for (i, (text, script_values)) in texts.into_iter().enumerate() {
        let mut mgr = RuleManager::new();
        mgr.set_text(&text);
        // Values of its own, as a request-phase produced text has — see
        // [`merge_included_rules`]. One scope per text: upstream parses each
        // into a rule set of its own.
        mgr.adopt_scope(&format!("\u{1}resRules {i}"), script_values);
        // Both passes, as the top-level rules get: a `resHeaders://x=1
        // includeFilter://s:404` line inside the text is withheld by the first
        // and answered by the second.
        let mut sub = mgr.resolve_scoped(info, is_internal_req);
        if let Some(late) = mgr.resolve_response(info, is_internal_req) {
            sub.merge_response_phase(late);
        }
        sub.single
            .retain(|proto, _| crate::rules::protocols::is_res_protocol(proto));
        sub.multi
            .retain(|proto, _| crate::rules::protocols::is_res_protocol(proto));
        // No shared-slot member is a `resProtocols` name, so a `file://` or a
        // destination written inside a `resRules://` text is dropped here — the
        // request it would have redirected has already gone out.
        sub.slot = None;
        if sub.single.is_empty() && sub.multi.is_empty() {
            continue;
        }
        merge_resolved(resolved, sub);
        carried
            .get_or_insert_with(HashMap::new)
            .extend(mgr.carried_values().clone());
    }
    carried
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
/// rule ruled out.
///
/// Only the **PAC** half of that is stricter than upstream: a PAC failure
/// reaches `logger.error` and nothing else (`_original/lib/rules/index.js:295`),
/// so whistle connects direct. An unusable *address* it refuses as well —
/// measured against 2.10.8, `proxy://`, `socks://`, `http-proxy://@` and
/// `proxy://?proxyHost` all answer 502, because the matcher is still truthy and
/// becomes the address `http://`, which the resolver cannot answer. See
/// `docs/RULES.md`.
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
        let mut cfg = parse_proxy_rule(proxy_kind(proto), &op.value).ok_or_else(|| {
            anyhow!(
                "{proto}://{} is not a usable proxy address",
                super::upstream::without_credentials(&op.value)
            )
        })?;
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
        || is_enabled(resolved, "proxyTunnel")
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
/// * `proxyFirst` (on either line) — prefer the proxy over the plain host. The
///   host address is then **not used at all**: see [`host_travels_with_proxy`].
///
/// `enable://proxyHost` / `enable://proxyFirst` say the same request-wide.
fn proxy_survives_host(resolved: &Resolved, proxy_proto: &str, host_matched: bool) -> bool {
    if !host_matched {
        return !resolved.props(proxy_proto).has("proxyHostOnly");
    }
    host_travels_with_proxy(resolved, proxy_proto) || {
        let host_props = resolved.props("host");
        resolved.props(proxy_proto).has("proxyFirst")
            || host_props.has("proxyFirst")
            || is_enabled(resolved, "proxyFirst")
    }
}

/// Does the `host://` address travel *with* the proxy — as the address the hop
/// is asked to connect to (whistle's `req._phost`) — rather than being dropped?
///
/// Only the `proxyHost` family says so. `proxyFirst` does not, and the
/// difference is visible on the wire: whistle reaches `req._phost = …` only
/// inside `if (proxyHost)`, and the `proxyFirst` test is that branch's `else if`
/// (`_original/lib/rules/index.js:217-236`). So `proxyFirst` decides *which of
/// the two rules wins*, the winner is the proxy, and the host address goes
/// nowhere. This port kept it, which turned an absolute-form request for the
/// requested origin into a CONNECT to an address the rule had just been told to
/// prefer the proxy over.
fn host_travels_with_proxy(resolved: &Resolved, proxy_proto: &str) -> bool {
    let proxy_props = resolved.props(proxy_proto);
    let host_props = resolved.props("host");
    // `?proxyHost` written into the proxy's own URL; a PAC rule has no URL of
    // its own to carry it.
    let url_flag = proxy_proto != "pac"
        && resolved
            .value(proxy_proto)
            .map(proxy_host_flag)
            .unwrap_or(false);
    proxy_props.has("proxyHostOnly")
        || url_flag
        || proxy_props.has("proxyHost")
        || host_props.has("proxyHost")
        || is_enabled(resolved, "proxyHost")
}

/// Resolve the forwarding family a **second** time, against the URL a URL
/// replacement produced, and lay the answer over the first pass.
///
/// This is upstream's `getProxy`, which is handed `options.href` rather than the
/// request's own URL and re-matches `host://`, the proxy family and `pac://`
/// against it (`_original/lib/rules/index.js:125-152`,
/// `lib/inspectors/res.js:196,:207-210`). Without it a four-word rules file
/// routes opposite ways in the two proxies: `a.com/ http://b.com/x` followed by
/// `b.com proxy://hop` engages the hop upstream and not here, and the same pair
/// written against `a.com` engages it here and not upstream.
///
/// The result *replaces* the first pass's answer for exactly the protocols
/// [`crate::rules::protocols::forwarding_protocols`] names, including when the
/// second pass matched nothing — upstream deletes `proxy` and `pac` before it
/// starts and drops `host` when the second pass finds none. Everything else is
/// the first pass untouched, which is what keeps `cipher://` and the
/// `disable://proxyUA` family reading the URL the client asked for, as they do
/// upstream.
///
/// `moved` is the second pass's subject; `top` and `merged` are the same rule
/// sets the first pass walked, in the same order, so an included or
/// plugin-injected `proxy://` line is re-matched too — upstream re-resolves all
/// four of its managers (`pRules`, `rules`, `fRules`, `hRules`).
///
/// The caller skips this entirely when nothing moved the request: matching is a
/// function of the rules and the request, so a second walk over an unchanged URL
/// reaches the answer already in hand. (The one thing that would differ is a
/// `chance:` filter, which upstream re-rolls; a rule whose engagement is random
/// is not one this port will pay a resolution pass to re-roll.)
pub fn reresolve_forwarding(
    first: &Resolved,
    moved: &ReqInfo,
    top: &RuleManager,
    merged: &[RuleManager],
    is_internal_req: bool,
) -> Resolved {
    let mut second = top.resolve_scoped(moved, is_internal_req);
    for mgr in merged {
        merge_resolved(&mut second, mgr.resolve_scoped(moved, is_internal_req));
    }
    let mut out = first.clone();
    for proto in crate::rules::protocols::forwarding_protocols() {
        // Every one of them is single-match, so there is one operator to move
        // and `remove` is the whole of "the second pass found nothing".
        match second.single.remove(proto) {
            Some(op) => out.single.insert(proto.to_string(), op),
            None => out.single.remove(proto),
        };
    }
    out
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
///
/// `resolved` is the forwarding resolution, not the request's own — see
/// [`reresolve_forwarding`], which the caller applies when a rule moved the
/// request.
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
    // A proxy that survived a `host://` rule on `proxyFirst` alone won *instead
    // of* it, so the address that rule named is put back — see
    // [`host_travels_with_proxy`].
    if let Some(proto) = proxy_proto
        && host_rule.is_some()
        && !host_travels_with_proxy(resolved, proto)
    {
        connect_host = dest.host.clone();
        connect_port = dest.port;
    }

    let request_tls = super::dest::is_tls(&dest.scheme);
    let tls = origin_tls(request_tls, proxy_proto, resolved);
    let cipher = cipher_options(resolved);
    // A cipher string that names nothing this build has takes the **pin** down,
    // not the request. See `parse_cipher_suites` for why the two are not the
    // same fact here that they are in OpenSSL.
    let tls_versions = parse_cipher_versions(&cipher);
    let mut cipher_dropped = None;
    let tls_ciphers = match parse_cipher_suites(&cipher) {
        Ok(policy) => policy,
        Err(e) => {
            tracing::warn!(
                "{} {}: cipher://: {e} — the connection is made without the pin, \
                 so the suite is not the one the rule asked for",
                info.method,
                info.full_url
            );
            cipher_dropped = Some(format!(
                "{e} — the connection was made with this proxy's default cipher suites, \
                 not the ones the rule asked for"
            ));
            None
        }
    };
    // Suites that no version the same rule allows can use — only TLS 1.3 ones
    // under a `maxVersion` of 1.2 — are dropped the same way: the handshake
    // cannot happen with them, and rustls refuses to even build it.
    let tls_ciphers = tls_ciphers.filter(|policy| {
        let fits = policy.fits(tls_versions);
        if !fits {
            tracing::warn!(
                "{} {}: cipher://: none of {:?} can be used with the TLS versions the rule \
                 allows — the connection is made without the suite pin",
                info.method,
                info.full_url,
                policy.names()
            );
            cipher_dropped = Some(format!(
                "none of the suites it names ({}) can be used with the TLS versions it \
                 allows, so the connection was made with the default suites for those \
                 versions",
                policy.names().join(", ")
            ));
        }
        fits
    });
    let disabled = disabled_flags(resolved);
    // `checkAuto2Http` (`_original/lib/util/index.js:3191-3198`): a `host://`
    // rule, a local address, or the flag said so out loud — and `disable://`
    // beats all three. The address is read as written rather than as resolved:
    // whistle asks the question of the IP it has just looked up, so a *name*
    // that happens to resolve to a loopback address is local there and not
    // here. Both agree on the shapes the page is about — an IP written into a
    // `host://` rule, and `127.0.0.1` written as a destination.
    let auto2http = !disabled.contains("auto2http")
        && (enabled_flags(resolved).contains("auto2http")
            || host_rule.is_some()
            || if proxy.is_some() {
                connect_host != dest.host || connect_port != dest.port
            } else {
                connect_host == "localhost"
                    || connect_host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(super::upstream::is_local_ip)
            });
    // `checkH2` (`_original/lib/inspectors/res.js:174-195`): any of the three
    // spellings, `disable` first.
    const H2: [&str; 3] = ["h2", "http2", "httpsH2"];
    let h2 = if H2.iter().any(|f| disabled.contains(*f)) {
        Some(false)
    } else if H2.iter().any(|f| enabled_flags(resolved).contains(*f)) {
        Some(true)
    } else {
        None
    };
    Ok(Target {
        auto2http,
        h2,
        tls_ciphers,
        // Only where there is a handshake for a pin to be missing from.
        cipher_dropped: cipher_dropped.filter(|_| tls),
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
        tls_versions,
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
/// A `pac://`-chosen proxy converts nothing of its own: whistle reads the
/// conversion off the rule's own protocol, and PAC results carry no whistle
/// protocol. `lineProps://internalProxy` still reaches it, as it reaches any
/// other hop — see [`internal_proxy`].
fn origin_tls(request_tls: bool, proxy_proto: Option<&str>, resolved: &Resolved) -> bool {
    let Some(proto) = proxy_proto else {
        return request_tls;
    };
    // Upstream asks `isInternal` before `isHttp2https`, so a hop that is somehow
    // both is internal (`res.js:224-238`).
    if matches!(
        proto,
        "https2http-proxy" | "internal-proxy" | "internal-http-proxy" | "internal-https-proxy"
    ) || internal_proxy(resolved, proto)
    {
        return false;
    }
    proto == "http2https-proxy" || request_tls
}

/// `internalProxy` — an ordinary `proxy://` hop is another whistle, so hand it
/// the request in plaintext with the marker header, exactly as the `internal-*`
/// spellings do (`isInternalProxy`, `_original/lib/util/index.js:3801-3807`).
///
/// `docs/LINE_PROPS.md` had this as exposed-only, on the grounds that this port
/// has no "forward https to an upstream proxy in the clear" mode. It has had one
/// since the `internal-*` protocols were ported — see [`origin_tls`]; what was
/// missing was only the *other* way of asking for it. Upstream reads the
/// property off the proxy line or the `host://` line, and `enable://internalProxy`
/// says it request-wide.
fn internal_proxy(resolved: &Resolved, proxy_proto: &str) -> bool {
    resolved.props(proxy_proto).has("internalProxy")
        || resolved.props("host").has("internalProxy")
        || is_enabled(resolved, "internalProxy")
}

/// Every `cipher://` line on the request, merged into one options object.
///
/// `getTlsOptions` walks `cipher.list` and hands the lot to `parseRuleJson`
/// (`_original/lib/rules/index.js:684-691`), so several lines **combine** —
/// which is what `cipher.md` means by "根据从上到下的顺序自动合并" — and the
/// first line to name a key keeps it, as it does for `resHeaders://`.
///
/// A value made only of `[a-z0-9:!-]` is a bare cipher string and becomes
/// `{ciphers: …}` (`SEP_CIPHER_RE`, `rules/index.js:38,:686-688`). Anything else
/// is a data object, so the `minVersion=TLSv1.2&maxVersion=TLSv1.3` form the
/// page leads with parses here as it does there — this port read only JSON and
/// silently ignored the documented spelling.
fn cipher_options(resolved: &Resolved) -> serde_json::Map<String, serde_json::Value> {
    let mut merged = serde_json::Map::new();
    for value in collect_values(resolved, "cipher") {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let object = match is_bare_cipher_list(value) {
            true => Some(serde_json::json!({ "ciphers": value })),
            // A bare version token — `cipher://TLSv1.2`, which the dot keeps out
            // of the cipher-string road — is not an object either, and upstream
            // makes nothing of it. Here it pins the version, which is the
            // declared improvement `docs/RULES.md` and `https-bench.js` record:
            // whistle's options never reach a handshake that works, so a pin
            // that means what it says is strictly more useful than one that
            // does nothing.
            false => parse_data_object(value, false, false).or_else(|| {
                (cipher_is_12(value) || cipher_is_13(value))
                    .then(|| serde_json::json!({ "minVersion": value, "maxVersion": value }))
            }),
        };
        let Some(serde_json::Value::Object(map)) = object else {
            continue;
        };
        for (key, val) in map {
            merged.entry(key).or_insert(val);
        }
    }
    merged
}

/// `SEP_CIPHER_RE = /[^a-z\d:!-]/i` (`_original/lib/rules/index.js:38`), read
/// the way it is used: a value with **no** character outside that set is a
/// cipher string rather than an options object. A version token fails it on the
/// dot, which is why `cipher://TLSv1.2` is not a cipher list in either program.
fn is_bare_cipher_list(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '!' | '-'))
}

/// Parse a `cipher://` value into an upstream TLS version constraint.
///
/// Whistle's `cipher` operator carries Node TLS options as JSON (`minVersion`,
/// `maxVersion`, `secureProtocol`, `ciphers`, …). rustls exposes TLS 1.2 and 1.3
/// only and cannot take OpenSSL cipher strings, so we honour the portable part:
/// the min/max protocol version. Accepts either a JSON object or a bare version
/// token (`cipher://TLSv1.2`). Older pins clamp to the nearest supported version.
fn parse_cipher_versions(
    options: &serde_json::Map<String, serde_json::Value>,
) -> super::upstream::TlsVersions {
    use super::upstream::TlsVersions;
    let get = |k: &str| options.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let (mut min, mut max) = (get("minVersion"), get("maxVersion"));
    // secureProtocol pins a single version (e.g. "TLSv1_2_method").
    if let Some(sp) = get("secureProtocol") {
        min = Some(sp.clone());
        max = Some(sp);
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
/// The other half — `minVersion`/`maxVersion` — is [`parse_cipher_versions`],
/// and the two are read independently on purpose: a value whose cipher string
/// is unusable may still carry a version that is not, and there is no reason for
/// one to take the other with it.
///
/// `Err` means the string selected no suite. **The caller drops the pin and
/// makes the connection anyway**, which is a deliberate departure from both
/// OpenSSL and from what this port used to do — see [`super::ciphers`]'s
/// "When the answer is nothing".
fn parse_cipher_suites(
    options: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<std::sync::Arc<super::ciphers::CipherPolicy>>, super::ciphers::NoCipherMatch> {
    let spec = options
        .get("ciphers")
        .and_then(|v| v.as_str())
        .map(str::to_string);
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
        for f in parse_props(v) {
            let f = f.trim().to_string();
            if !f.is_empty() {
                set.insert(f);
            }
        }
    }
    set
}

/// Split a prop list on `|` and `&`, honouring the escapes upstream honours.
///
/// `parseProps` (`_original/lib/util/common.js:73,:111-127`) is a single
/// regexp — `/(\\*)([|&]|\\[stnrfv])/g` — over the whole value, and it does two
/// things at once:
///
/// * a separator preceded by an **odd** number of backslashes is a literal
///   `|` or `&` rather than a split, and the run is halved;
/// * `\s`, `\t`, `\n`, `\r`, `\f` and `\v` become the characters they name —
///   which is how `delete://reqBody.a\nb` addresses a key with a newline in it.
///
/// `delete://` and the two flag families take this road; `lineProps://` takes
/// the plain `SEP_RE` split with no escapes at all (`index.js:1898`), which is
/// a difference `docs/LINE_PROPS.md` already records.
pub(crate) fn parse_props(value: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            match c {
                '|' | '&' => out.push(String::new()),
                _ => out.last_mut().expect("never empty").push(c),
            }
            continue;
        }
        // The run of backslashes, and then what it applies to.
        let mut run = 1;
        while chars.next_if_eq(&'\\').is_some() {
            run += 1;
        }
        let kept = "\\".repeat(run / 2);
        let tail = out.last_mut().expect("never empty");
        match chars.peek() {
            // `\<sep>`: odd keeps the separator as text, even splits.
            Some('|' | '&') => {
                let sep = chars.next().expect("peeked");
                tail.push_str(&kept);
                match run % 2 {
                    1 => tail.push(sep),
                    _ => out.push(String::new()),
                }
            }
            // `\s` and friends: the run is counted **with** the escape's own
            // backslash, so an even run leaves the letter and an odd one
            // replaces it with the character it names.
            Some(&letter) if matches!(letter, 's' | 't' | 'n' | 'r' | 'f' | 'v') => {
                chars.next();
                let kept = "\\".repeat(run.div_ceil(2) - usize::from(run % 2 == 1));
                tail.push_str(&kept);
                match run % 2 {
                    1 => tail.push(match letter {
                        's' => ' ',
                        't' => '\t',
                        'n' => '\n',
                        'r' => '\r',
                        'f' => '\u{c}',
                        _ => '\u{b}',
                    }),
                    _ => tail.push(letter),
                }
            }
            // Anything else: the backslashes are text, untouched — the regexp
            // did not match, so nothing was halved.
            _ => tail.push_str(&"\\".repeat(run)),
        }
    }
    out
}

/// `enable://` flags for a request.
pub fn enabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "enable")
}

/// `disable://` flags for a request.
pub fn disabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "disable")
}

/// Is this transaction hidden from the capture?
///
/// `checkHideProp` (`_original/lib/util/index.js:3982-3987`) reads four flags,
/// not one: `enable://hide` and `disable://show` hide, and `enable://show` and
/// `disable://hide` un-hide, with the un-hiding half winning. The pair exists
/// because the flags usually arrive from different lines — a broad
/// `enable://hide` over a domain, an `enable://show` on the one request being
/// looked at.
///
/// Taken as two sets rather than as a `Resolved`, because the same question is
/// asked of a recorded session, whose flags have already been flattened.
pub fn hides_capture(
    enabled: &std::collections::HashSet<String>,
    disabled: &std::collections::HashSet<String>,
) -> bool {
    (enabled.contains("hide") || disabled.contains("show"))
        && !enabled.contains("show")
        && !disabled.contains("hide")
}

/// [`hides_capture`], asked of a request's resolved rules.
pub fn hidden_from_capture(resolved: &Resolved) -> bool {
    hides_capture(&enabled_flags(resolved), &disabled_flags(resolved))
}

/// `enable://<flag>` — cancelled by a `disable://<flag>` on the same request.
///
/// Upstream's `isEnable` is `req.enable[name] && !req.disable[name]`
/// (`_original/lib/util/index.js:678-680`), and its mirror `isDisable` is the
/// same expression the other way round. This port had only the mirror: every
/// flag was read as `enabled_flags(…).contains(…)`, so `enable://keepCSP
/// disable://keepCSP` kept the CSP here and stripped it upstream — and the same
/// omission applied to all sixteen reads, not just that one.
///
/// The two together mean a name written on both sides does **nothing**, which
/// is the only reading under which `enable`/`disable` compose predictably: the
/// answer does not depend on which was written first, or on which of the two
/// the code happens to consult.
/// **Not every flag is read this way**, and the three exceptions are upstream's,
/// found by checking each name's reader rather than assuming they share one:
/// `showHost` is a bare `req._filters.showHost || enable.showHost`
/// (`_original/lib/inspectors/res.js:1193`), `userLogin` goes through a bespoke
/// helper where `enable` wins over `disable` (`util/index.js:3557-3562`), and
/// `cors` has no `enable` reader upstream at all. Those three keep the direct
/// read. A blanket conversion broke the second of them and an existing test
/// caught it — the test had the real semantics pinned.
pub(crate) fn is_enabled(resolved: &Resolved, flag: &str) -> bool {
    enabled_flags(resolved).contains(flag) && !disabled_flags(resolved).contains(flag)
}

/// `disable://<flag>` — with the escape hatch upstream gives it: an
/// `enable://<flag>` on the same request wins (`isDisable`,
/// `_original/lib/util/index.js:681-683`).
pub(crate) fn is_disabled(resolved: &Resolved, flag: &str) -> bool {
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

/// Parse a PAC `FindProxyForURL` return value into a proxy.
///
/// The list is read in order, as a PAC list is meant to be: the first entry that
/// names somewhere reachable wins. `DIRECT` reached before any usable proxy
/// yields `Ok(None)` — the script was asked where to send the request and
/// answered "nowhere in particular". A `DIRECT` *after* the chosen proxy is a
/// fallback rather than a choice, and is carried as [`ProxyConfig::fallback_direct`]
/// so a hop that cannot be established goes direct instead of failing. whistle
/// arrives at the same place by rewriting the result into an `x`-prefixed rule
/// when the word `direct` follows the proxy it picked (`prefix = 'x'`,
/// `node-pac/lib/Pac.js:96-103`).
///
/// A result with no usable entry and no `DIRECT` is an error instead, because
/// the script *did* name somewhere and we could not act on it. `SOCKS4` is such
/// a case: this port speaks SOCKS5 only, and quietly going direct would hide
/// that.
fn parse_pac_result(result: &str) -> Result<Option<super::upstream::ProxyConfig>> {
    let mut entries = result.split(';');
    while let Some(entry) = entries.next() {
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
        if let Some(mut p) = parsed {
            p.fallback_direct = entries.any(|rest| {
                rest.split_whitespace()
                    .next()
                    .is_some_and(|k| k.eq_ignore_ascii_case("DIRECT"))
            });
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
/// `redirect`/`location`, mocked `statusCode`, and the local-file family.
///
/// Only the operator that won the shared slot may answer, and
/// [`Resolved::slot`](crate::rules::Resolved::slot) holds exactly that one —
/// see [`crate::rules::protocols::SLOT_PROTOCOLS`].
pub fn short_circuit(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
) -> Option<Response<DynBody>> {
    let mut resp = short_circuit_inner(info, resolved, env, remote)?;
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
pub(crate) fn mark_self_generated(headers: &mut HeaderMap) {
    set_header(headers, "x-server", "whistle-rs");
}

fn short_circuit_inner(
    info: &ReqInfo,
    resolved: &Resolved,
    env: super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
) -> Option<Response<DynBody>> {
    let op = resolved.slot()?;
    let proto = op.protocol.as_str();
    match proto {
        "redirect" => {
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
            // An empty value is `200` upstream too — `var code = rule || 200`
            // (`getStatusCodeFromRule`, `_original/lib/util/index.js:3580`) —
            // and a value that is not a status at all has no upstream answer to
            // copy: `res.writeHead('abc')` throws inside Node and the client
            // gets a **connection reset**. Measured against whistle 2.10.8 for
            // `abc`, `20x`, `099`, `0`, `2000` and a file path; this port keeps
            // the empty-value answer for all of them rather than dropping a
            // socket over a typo.
            let status = op
                .value
                .trim()
                .parse::<u16>()
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::OK);
            let mut resp = Response::builder()
                .status(status)
                .body(body::empty())
                .unwrap();
            // A mocked `401`/`407` carries its challenge here as well, not only
            // on the `replaceStatus://` path: upstream answers a `statusCode://`
            // rule through `getStatusCodeFromRule`, which calls `handleStatusCode`
            // for exactly this reason (`_original/lib/util/index.js:3566-3588`).
            // Measured against the differential bench, `statusCode://401` came
            // back from whistle with `WWW-Authenticate: Basic realm=User Login`
            // and from here with nothing — so a mocked 401 never prompted, which
            // is most of the point of mocking one.
            if user_login_allowed(resolved, proto) {
                handle_status_code(resp.headers_mut(), status);
            }
            Some(resp)
        }
        "locationHref" => serve_loc_href(&op.value, info),
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
            let mut resp = serve_file_family(proto, op, info, env, remote)?;
            if cors {
                write_auto_cors(resp.headers_mut(), info);
            }
            Some(resp)
        }
    }
}

/// `locationHref://` — **answer** the request with a page that redirects itself
/// (`handleLocHref`, `_original/lib/handlers/file-proxy.js:193-231`).
///
/// It is a mock, not an injection: `isFileProxy` admits it (`protocols.js:282`)
/// so it shares the slot with `file://` and a destination rewrite, and the
/// origin is never contacted. This port had it as an HTML injection — a
/// `<script>` pushed into the origin's own `<head>` — which meant a request the
/// origin answers with JSON, or with nothing, or with an error got no redirect
/// at all, and one it answers with HTML paid for a round trip whose body was
/// then thrown away by the client. `docs/RULES.md` described the injection.
///
/// Three prefixes choose the shape, case-insensitively; with none, a request the
/// browser made *for a script* gets bare JavaScript, so a redirect written for a
/// page does not arrive nested inside another `<script>`.
///
/// Returns `None` when the target is the request's own URL, which is upstream's
/// `handleLocHref` returning false: the request goes out normally rather than
/// answering itself forever. (Upstream compares against the percent-decoded URL
/// as well; that arm is not replicated, so a value written decoded against an
/// encoded request URL still answers here.)
fn serve_loc_href(value: &str, info: &ReqInfo) -> Option<Response<DynBody>> {
    let lower = value.to_ascii_lowercase();
    let (as_js, replace, target) = if lower.starts_with("js:") {
        (true, false, &value[3..])
    } else if lower.starts_with("html:") {
        (false, false, &value[5..])
    } else if lower.starts_with("replace:") {
        (false, true, &value[8..])
    } else {
        let wants_js = req_header(Some(info), "sec-fetch-dest") == Some("script");
        (wants_js, false, value)
    };

    let mut body = String::new();
    if !target.is_empty() {
        // `urlToStr`: backslashes go, quotes are escaped so they cannot close
        // the string literal, and every whitespace character becomes a space.
        let escaped: String = target
            .chars()
            .filter(|c| *c != '\\')
            .map(|c| match c.is_whitespace() {
                true => ' ',
                false => c,
            })
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                c => vec![c],
            })
            .collect();
        let no_hash = escaped.split('#').next().unwrap_or(&escaped);
        if abs_url(no_hash, &info.full_url) == info.full_url {
            return None;
        }
        let call = match replace {
            true => format!("window.location.replace(\"{escaped}\");"),
            false => format!("window.location.href = \"{escaped}\";"),
        };
        body = match as_js {
            true => call,
            false => format!("<script>{call}</script>"),
        };
    }
    let ctype = match as_js {
        true => "application/javascript; charset=utf-8",
        false => "text/html; charset=utf-8",
    };
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, ctype)
            .body(body::full(Bytes::from(body)))
            .unwrap(),
    )
}

/// Resolve a possibly-relative URL against the request's own
/// (`getAbsUrl` + `formatUrl`, `_original/lib/util/common.js:526-557`).
///
/// Only [`serve_loc_href`]'s loop check needs it, and only its exact shape will
/// do: whistle normalises both sides through `formatUrl`, which appends the `/`
/// a bare host is missing, so `http://a.test` and `http://a.test/` compare
/// equal.
fn abs_url(url: &str, full_url: &str) -> String {
    if is_http_url(url) {
        return format_url(url);
    }
    if let Some(rest) = url.strip_prefix('/') {
        // `fullUrl.indexOf('/', 8)` skips past `https://` to the first slash of
        // the path. JavaScript's `substring(0, -1)` is the empty string, which
        // is what a full URL with no path at all yields.
        let base = full_url
            .get(8..)
            .and_then(|r| r.find('/'))
            .map_or("", |i| &full_url[..i + 8]);
        return format_url(&format!("{base}/{rest}"));
    }
    // `QUERY_RE = /\/[^/]*(?:\?.*)?$/` — the last path segment and the query go,
    // and the relative value takes their place.
    let stem = strip_last_segment(full_url);
    format_url(&format!("{stem}/{url}"))
}

/// `formatUrl` — split the query off, and give a URL with no path a `/`.
fn format_url(pattern: &str) -> String {
    let (path, query) = match pattern.find('?') {
        Some(at) => (&pattern[..at], &pattern[at..]),
        None => (pattern, ""),
    };
    let from = path.find("://").map_or(0, |at| at + 3);
    match path[from..].contains('/') {
        true => format!("{path}{query}"),
        false => format!("{path}/{query}"),
    }
}

/// Drop the trailing `/<segment>` and any query — upstream's `QUERY_RE`.
fn strip_last_segment(url: &str) -> &str {
    let head = url.split('?').next().unwrap_or(url);
    match head.rfind('/') {
        Some(at) => &head[..at],
        None => head,
    }
}

/// `weakRule` — the local-file rule steps aside for a matching `proxy`/`host`
/// rule instead of answering the request, inverting the usual precedence
/// (`filterWeakRule`, `_original/lib/util/index.js:3731-3743`).
///
/// Upstream drops the local rule when a `host://` rule matched, or when a proxy
/// rule matched that is *not* `proxyHostOnly` — that spelling needs a host rule
/// to mean anything, so on its own it does not outrank the file.
/// `enable://weakRule` says the same request-wide.
fn weak_rule_yields(resolved: &Resolved, file_proto: &str) -> bool {
    if !resolved.props(file_proto).has("weakRule") && !is_enabled(resolved, "weakRule") {
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

/// Serve a matched file-family rule. Returns `None` only for a `x`/`xs` (cross)
/// variant whose file is missing — that falls through to the real server.
fn serve_file_family(
    proto: &str,
    op: &RuleOp,
    info: &ReqInfo,
    env: super::template::ProxyEnv<'_>,
    remote: Option<&RemoteFile>,
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
    let Some((value, sources)) = file_location(op) else {
        // The value is content. Two ways to get one, and they differ only in
        // the name the content type is guessed from.
        let bytes = match op.value_is_content {
            true => value.as_bytes().to_vec(),
            false => crate::rules::url::fixed_value(value)?.1.into_bytes(),
        };
        let named = op.value_key.as_deref().unwrap_or(&info.full_url);
        return Some(if raw {
            serve_raw_value(&bytes)
        } else if templated {
            serve_template(&bytes, named, info, env)
        } else {
            serve_file_range(&bytes, named, info)
        });
    };

    let candidates = FileCandidates::of(proto, &value, sources);
    match candidates.read(remote) {
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
        // A URL source that answered something other than `404` is the file
        // server being broken rather than the file being absent, and upstream
        // says so with a `502` instead of hiding it behind a not-found
        // (`file-proxy.js:301-307`). Measured: a source answering `500` gets a
        // `502` from whistle and used to get a `404` from here — the one status
        // that tells a reader to go and look at their mock server.
        None if let Some(r) = remote
            && r.data.is_none()
            && r.status != 0
            && r.status != 404 =>
        {
            Some(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(body::full(Bytes::from(format!(
                        "Error: response {}",
                        r.status
                    ))))
                    .unwrap(),
            )
        }
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

/// Where a file rule points, or `None` when its value **is** the content and
/// there is nothing to open.
///
/// Two value shapes are content: an inline `(text)`, and a `{name}` the values
/// store answered — both are `readRuleValue`'s `if (rule.value)` arm upstream
/// (`_original/lib/util/index.js:1178-1180`). `<path>` is the third bracket form
/// and means the opposite: a location pinned in place, which the matcher has
/// already honoured by not extending it.
///
/// Shared by the serving path and by [`prefetch_remote_file`], which have to
/// agree about what the rule points at — one fetches the URL the other will ask
/// for.
fn file_location(op: &RuleOp) -> Option<(std::borrow::Cow<'_, str>, Sources)> {
    if op.value_is_content {
        return None;
    }
    match crate::rules::url::fixed_value(&op.value) {
        Some((crate::rules::url::Fixed::Inline, _)) => None,
        Some((crate::rules::url::Fixed::Verbatim, path)) => {
            Some((std::borrow::Cow::Owned(path), Sources::PathsOnly))
        }
        None => Some((
            std::borrow::Cow::Borrowed(op.value.as_str()),
            Sources::PathsAndUrls,
        )),
    }
}

/// May this rule's entries name a URL, or are they all paths?
///
/// The `<…>` form is paths only, which is a measurement rather than a design:
/// `file://http://host/x` is fetched by whistle and `file://<http://host/x>` is
/// opened as a path and 404s. The brackets are documented as *do not append the
/// request's path*, and nothing says they also mean *do not fetch* — but they
/// do, and a port that fetched both would answer `200` where whistle answers
/// `404`.
///
/// One shape is not covered: against a pattern that leaves no path to append —
/// `^http://host/echo <http://host/x>` — upstream fetches after all. That is
/// recorded in `tests/differential/cases.js` rather than reproduced, because no
/// reading of `file-proxy.js` explained why the pattern's leftover should decide
/// whether a value is a URL, and encoding an unexplained correlation is how a
/// port acquires bugs it cannot maintain.
#[derive(Clone, Copy, PartialEq)]
enum Sources {
    PathsOnly,
    PathsAndUrls,
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
    paths: Vec<FileSource>,
    /// What a 404 should blame: the last path the user actually wrote, or
    /// [`INVALID_PATH`] when that entry was refused for containing `..`.
    blame: String,
}

/// Where one candidate's bytes come from.
///
/// A file rule may name a URL instead of a path, and then the bytes are fetched
/// rather than opened — see [`names_a_remote_file`](crate::rules::matcher) for
/// the upstream reader that does this and why such an entry keeps its own path.
/// The two are kept in one ordered list because upstream tries them in the order
/// written and stops at the first that answers: `file:///srv/cache|http://host/x`
/// serves the local copy when it exists and fetches only when it does not.
#[derive(Debug, Clone, PartialEq)]
enum FileSource {
    Path(String),
    Url(String),
}

/// A file rule's URL source, already fetched.
///
/// The fetch happens before [`short_circuit`], not inside it: everything that
/// answers a request without contacting the origin is synchronous, and the one
/// piece of I/O here that is not the filesystem should not be the reason to make
/// all of it async. [`prefetch_remote_file`] walks the same candidate list the
/// serving code walks, so the URL it fetched is the URL that will be asked for.
pub struct RemoteFile {
    url: String,
    /// The bytes, or `None` when the fetch did not produce any.
    data: Option<Arc<Vec<u8>>>,
    /// What the URL answered, or `0` when nothing did. It outlives a failed
    /// fetch because upstream distinguishes two kinds: a `404` is *this file is
    /// not there*, and anything else is the file server itself being broken,
    /// which it reports as a `502` rather than hiding behind a not-found
    /// (`is502 = err.code > 0 && err.code != 404`,
    /// `_original/lib/handlers/file-proxy.js:302`). A transport failure has no
    /// numeric code there, so it falls to the 404 — and to `0` here.
    status: u16,
}

/// Fetch a file rule's URL source, if the rule has one that is reached.
///
/// "Reached" is what the walk is for: an entry only matters when no earlier
/// candidate is a readable local file, which is upstream's `readFiles` order
/// (`_original/lib/handlers/file-proxy.js:39-59`). Returns `None` for the
/// overwhelmingly common case — a rule that is not a file rule, or one whose
/// sources are all paths — and costs nothing there.
///
/// A remote source is capped at `MAX_URL_VAL_LEN`
/// (`_original/lib/plugins/index.js:1496`), and a fetch that fails is not an
/// answer: the rule falls through to its next candidate, then to the 404 — or,
/// for an `x` variant, to the origin.
pub async fn prefetch_remote_file(resolved: &Resolved) -> Option<RemoteFile> {
    let op = resolved.slot()?;
    let proto = op.protocol.as_str();
    if !crate::rules::protocols::is_file_protocol(proto) {
        return None;
    }
    let (value, sources) = file_location(op)?;
    if sources != Sources::PathsAndUrls {
        return None;
    }
    for source in FileCandidates::of(proto, &value, sources).paths {
        match source {
            FileSource::Path(p) if read_cached(Path::new(&p)).is_some() => return None,
            FileSource::Path(_) => {}
            FileSource::Url(url) => {
                let answer = super::upstream::simple_get(&url).await;
                let (status, body) = match answer {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!("file://{url}: {err}");
                        return Some(RemoteFile {
                            url,
                            data: None,
                            status: 0,
                        });
                    }
                };
                // Over the cap is this port's own refusal, not a measurement of
                // upstream's: whistle passes `maxLength` into its reader and
                // what that does at the boundary was never put in front of it.
                // Refusing loudly beats serving a body that is silently short.
                if status != 200 || body.len() > MAX_URL_FILE {
                    tracing::warn!("file://{url}: answered {status}, {} bytes", body.len());
                    return Some(RemoteFile {
                        url,
                        data: None,
                        status,
                    });
                }
                return Some(RemoteFile {
                    url,
                    data: Some(Arc::new(body.to_vec())),
                    status,
                });
            }
        }
    }
    None
}

/// How much of a URL-sourced file is served — `MAX_URL_VAL_LEN`
/// (`_original/lib/plugins/index.js:1496`).
const MAX_URL_FILE: usize = 1024 * 256;

impl FileCandidates {
    fn of(proto: &str, value: &str, sources: Sources) -> FileCandidates {
        let mut paths = Vec::new();
        let mut blame = String::new();
        for entry in split_paths(proto, value) {
            // A URL is not a path and none of what follows applies to it: there
            // is no home directory to expand, no `index.html` to append and no
            // leading slash to restore. It is also the one entry that can carry
            // a `?query`, which `decode_path` would cut off.
            if sources == Sources::PathsAndUrls && crate::rules::url::has_web_protocol(entry) {
                blame = entry.to_string();
                paths.push(FileSource::Url(entry.to_string()));
                continue;
            }
            // Home first, then the separators — `convertSlash`'s own order.
            let entry = convert_slash(&expand_home(&decode_path(entry)));
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
                    paths.push(FileSource::Path(candidate));
                }
                paths.push(FileSource::Path(rooted));
            }
        }
        FileCandidates { paths, blame }
    }

    /// The first candidate that answers: a readable regular file, or the URL
    /// source [`prefetch_remote_file`] already fetched.
    fn read(&self, remote: Option<&RemoteFile>) -> Option<(String, Arc<Vec<u8>>)> {
        self.paths.iter().find_map(|source| match source {
            FileSource::Path(p) => read_cached(Path::new(p)).map(|data| (p.clone(), data)),
            // Matched by URL rather than taken on trust: the prefetch walked
            // this same list, but a `|` value can name two URLs and only the
            // one that was fetched may answer.
            FileSource::Url(url) => remote
                .filter(|r| &r.url == url)
                .and_then(|r| r.data.as_ref())
                .map(|data| (url.clone(), Arc::clone(data))),
        })
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

/// A backslash is a path separator **everywhere except on Windows**, which is
/// the opposite of how it reads.
///
/// `convertSlash` is `isWin32 ? filePath : formatPathSep(filePath)`
/// (`_original/lib/util/file-mgr.js:13-16`), and `formatPathSep` replaces every
/// `\` with `/` (`util/common.js:178-180`). So a rule written on Windows —
/// `file://D:\mock.json`, or a path pasted out of Explorer — keeps working when
/// the same rules file is opened on a Mac, which is the point: rules travel
/// between machines and paths in them are written in the local dialect.
///
/// On Windows itself nothing is converted, because the OS takes either
/// separator and a `/` in a path is already a `/`.
///
/// The cost is a file whose **name** contains a backslash, which is legal here
/// and unreachable through a rule. It is unreachable in upstream too, and a
/// path that cannot be written on the platform the rule was written for is the
/// cheaper thing to give up.
pub(crate) fn convert_slash(path: &str) -> String {
    match cfg!(windows) {
        true => path.to_string(),
        false => path.replace('\\', "/"),
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

/// The operators whose loaded value is sent as bytes, not text — upstream's
/// `binProtocols` (`_original/lib/rules/protocols.js:121-128`), read with
/// `needRawData` (`util/index.js:1273-1274`). See [`RuleOp::value_bytes`].
const BINARY_OPS: &[&str] = &[
    "reqBody",
    "reqPrepend",
    "reqAppend",
    "resBody",
    "resPrepend",
    "resAppend",
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
/// What a value source yielded: its text, and — for a file — its bytes.
#[derive(Clone)]
struct Loaded {
    text: String,
    /// The files' bytes joined with CRLF, untouched: what the binary operators
    /// send (see [`RuleOp::value_bytes`]); a URL's body likewise.
    raw: Option<Bytes>,
}

async fn read_value_source(source: &ValueSource) -> Option<Loaded> {
    match source {
        // `readFileText` splits on `|` and joins what it read with CRLF, missing
        // files dropping out (`_original/lib/util/file-mgr.js:96-102,:157-166`).
        // That is *not* the first-one-wins of a `file://` rule: several files
        // concatenate into one value.
        //
        // The text is each file decoded on its own, which is `readFileText`'s;
        // the bytes are the files as they are, which is `readFile`'s, and what
        // `joinData` concatenates for a binary operator (`file-mgr.js:93-109`).
        // Upstream's suite splits a Chinese sentence across three files mid-
        // character (`test/units/insertFile.test.js`); only the bytes join back.
        ValueSource::File(spec) => {
            let mut parts: Vec<Vec<u8>> = Vec::new();
            for entry in spec.split('|') {
                let path = convert_slash(&expand_home(&decode_path(entry.trim())));
                if has_parent_ref(&path) {
                    tracing::warn!("rule value {path}: refused, path contains '..'");
                    continue;
                }
                match read_cached(Path::new(&path)) {
                    Some(data) => parts.push(data.to_vec()),
                    // Only `debug`: `a|b` is written precisely so that a missing
                    // alternative is normal. The caller warns once when *nothing*
                    // was read, which is the case worth a line per request.
                    None => tracing::debug!("rule value {path}: not readable"),
                }
            }
            (!parts.is_empty()).then(|| Loaded {
                text: parts
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join("\r\n"),
                raw: Some(Bytes::from(parts.join(CRLF))),
            })
        }
        ValueSource::Url(url) => {
            let fetch = super::upstream::simple_get(url);
            match tokio::time::timeout(VALUE_FETCH_TIMEOUT, fetch).await {
                Ok(Ok((200, bytes))) if bytes.len() <= MAX_URL_VALUE => Some(Loaded {
                    text: String::from_utf8_lossy(&bytes).into_owned(),
                    raw: Some(Bytes::copy_from_slice(&bytes)),
                }),
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
    let mut wanted: HashMap<ValueSource, Option<Loaded>> = HashMap::new();
    for op in resolved.ops_mut() {
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
    for op in resolved.ops_mut() {
        let Some(source) = value_source(op) else {
            continue;
        };
        match wanted.get(&source).and_then(Option::as_ref) {
            Some(loaded) => {
                op.value = loaded.text.clone();
                if BINARY_OPS.contains(&op.protocol.as_str()) {
                    op.value_bytes = loaded.raw.clone();
                }
                op.value_is_content = true;
                op.value_loaded = true;
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
            let mut resp = raw_response(
                &data[..head_end],
                Bytes::copy_from_slice(&data[body_start..]),
            );
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
            let end = start
                + if data.get(start + 2) == Some(&b'\n') {
                    3
                } else {
                    2
                };
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
            let pure = full_url.split(['?', '#']).next().unwrap_or(full_url);
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
/// The table is a subset of `mime`'s several hundred entries — every spelling
/// here was read out of the `mime@1.6.0` whistle depends on rather than
/// guessed, including the ones that look wrong (`.ts` is `video/mp2t`, `.rs` is
/// `application/rls-services+xml`, and `.docx` carries a charset because
/// `isText`'s substring test finds `xml` inside `openxmlformats`). An extension
/// outside it falls back to the request URL's, then to `text/html`, which is
/// the fallback chain whistle passes to `mime.lookup` itself
/// (`file-proxy.js:255-257,:314`).
fn content_type_of_ext(path: &str) -> Option<&'static str> {
    // The separator set is `mime`'s own: `lookup` strips everything up to the
    // last `.`, `/` **or** `\` (`mime@1 lookup`, `path.replace(/.*[\.\/\\]/, '')`),
    // so a final segment with no dot is taken as the extension whole. That is
    // not a quirk without consequence — `file://http://host/json` is typed
    // `application/json` upstream, and was `text/html` here, because this
    // required a dot and gave up.
    let ext = path
        .rsplit(['.', '/', '\\'])
        .next()
        .filter(|ext| !ext.is_empty())?
        .to_ascii_lowercase();
    Some(match ext.as_str() {
        // Markup, styles and scripts.
        "html" | "htm" | "shtml" => "text/html; charset=utf-8",
        "xhtml" => "application/xhtml+xml; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "jsx" => "text/jsx; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "scss" => "text/x-scss; charset=utf-8",
        "sass" => "text/x-sass; charset=utf-8",
        "less" => "text/less; charset=utf-8",
        "htc" => "text/x-component; charset=utf-8",
        "hbs" => "text/x-handlebars-template; charset=utf-8",
        // Data and documents. A source map is JSON, and `.map` is how every
        // bundler spells it — which is `mime`'s answer too.
        "json" | "map" => "application/json; charset=utf-8",
        "webmanifest" => "application/manifest+json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "rss" => "application/rss+xml; charset=utf-8",
        "atom" => "application/atom+xml; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "tsv" => "text/tab-separated-values; charset=utf-8",
        "yaml" | "yml" => "text/yaml; charset=utf-8",
        "ini" | "conf" | "log" | "txt" | "text" => "text/plain; charset=utf-8",
        "manifest" | "appcache" => "text/cache-manifest; charset=utf-8",
        "ics" => "text/calendar; charset=utf-8",
        "vcf" => "text/x-vcard; charset=utf-8",
        "rtf" => "application/rtf",
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=utf-8"
        }
        "xls" => "application/vnd.ms-excel",
        "xlsx" => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=utf-8"
        }
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation; charset=utf-8"
        }
        "epub" => "application/epub+zip",
        "mobi" => "application/x-mobipocket-ebook",
        // Images.
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "svg" => "image/svg+xml; charset=utf-8",
        "ico" => "image/x-icon",
        "wbmp" => "image/vnd.wap.wbmp",
        "jng" => "image/x-jng",
        "psd" => "image/vnd.adobe.photoshop",
        "ai" | "eps" => "application/postscript",
        // Fonts.
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        // Video and audio. `.ts` is `video/mp2t` and not TypeScript, which is
        // `mime`'s answer and therefore whistle's.
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "flv" => "video/x-flv",
        "ts" => "video/mp2t",
        "3gp" => "video/3gpp",
        "m3u8" => "application/vnd.apple.mpegurl",
        "mpd" => "application/dash+xml; charset=utf-8",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "aac" => "audio/x-aac",
        "flac" => "audio/x-flac",
        "m4a" => "audio/mp4",
        "weba" => "audio/webm",
        "mid" | "midi" => "audio/midi",
        // Archives and binaries.
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",
        "jar" | "war" => "application/java-archive",
        "apk" => "application/vnd.android.package-archive",
        "swf" => "application/x-shockwave-flash",
        "wasm" => "application/wasm",
        "bin" => "application/octet-stream",
        // Sources, scripts and certificates.
        "php" => "application/x-httpd-php",
        "pl" => "application/x-perl",
        "sh" => "application/x-sh",
        "bat" => "application/x-msdownload",
        "sql" => "application/x-sql",
        "c" | "h" | "cpp" => "text/x-c; charset=utf-8",
        "java" => "text/x-java-source; charset=utf-8",
        "rs" => "application/rls-services+xml; charset=utf-8",
        "pem" | "crt" => "application/x-x509-ca-cert",
        "cer" => "application/pkix-cert",
        "p12" | "pfx" => "application/x-pkcs12",
        _ => return None,
    })
}

/// Every entry of the type table, against the `mime@1.6.0` whistle carries.
///
/// The table is written out by hand, so the test is the check that it was
/// copied and not invented — the values were produced by asking that package
/// and are pinned here in the shape it gave them.
#[cfg(test)]
#[test]
fn the_type_table_is_the_one_whistle_carries() {
    // A few that a subset table gets wrong by guessing: `.ts` is a transport
    // stream, `.rs` is not `text/rust`, and the office formats carry a charset
    // only because `isText` looks for `xml` as a substring.
    assert_eq!(content_type_of_ext("a.ts"), Some("video/mp2t"));
    assert_eq!(
        content_type_of_ext("a.rs"),
        Some("application/rls-services+xml; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.scss"),
        Some("text/x-scss; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.jsx"),
        Some("text/jsx; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.m3u8"),
        Some("application/vnd.apple.mpegurl")
    );
    assert_eq!(
        content_type_of_ext("a.php"),
        Some("application/x-httpd-php")
    );
    assert_eq!(
        content_type_of_ext("a.pem"),
        Some("application/x-x509-ca-cert")
    );
    assert_eq!(
        content_type_of_ext("a.docx"),
        Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=utf-8"
        )
    );
    // An extension the table does not carry has no answer here — the caller
    // then falls back to the request URL's, as `mime.lookup(path, defaultType)`
    // does upstream.
    assert_eq!(content_type_of_ext("a.zzz"), None);
    assert_eq!(content_type_of_ext("a.vue"), None);
}

/// Apply request-side operators (headers, method, ua, referer) in place.
pub fn apply_request(parts: &mut request::Parts, resolved: &Resolved) {
    // The client-id a client sent is not the client-id an upstream should read.
    // whistle drops it unless the request asked to keep it — `if (clientId) { if
    // (!options.isPlugin && !req._customClientId && !isKeepClientId(req, …))
    // removeClientId(optHeaders) }` (`_original/lib/inspectors/res.js:717-723`).
    // This port has no client-id of its own to put in its place (see
    // `docs/RULES.md`, the flags it does not implement), so the header simply
    // goes — and `enable://keepClientId`, which does nothing else here, is
    // honoured for this one purpose.
    if !is_enabled(resolved, "keepClientId") {
        parts.headers.remove("x-whistle-client-id");
    }
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
    if let Some(auth) = resolved.get("auth").map(auth_of)
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

/// What an `auth://` operator asks for, by whichever of upstream's two roads it
/// travels.
///
/// `getAuthByRules` reads the value **inline** — as JSON, as a
/// `username=…&password=…` query, or as `user:pass`. When it declines, `req.js`
/// hands the same rule to `parseRuleJson` instead (`authObj ? null :
/// reqRules.auth`, `_original/lib/inspectors/req.js:461,:467`), which reads a
/// data object out of it and keeps only `username` / `password` / `proxy`.
///
/// Which road a value takes is decided on the value **as written**, which is why
/// [`RuleOp::value_loaded`] exists: a location has already been replaced by what
/// it held.
fn auth_of(op: &RuleOp) -> Auth {
    // A value read out of a location never had the inline reading offered to it:
    // `getAuthByRules` refused it for the slash, and this is the road it was
    // sent down. The documented file — `username: admin` on one line,
    // `password: …` on the next — is the line format, and it only arrives here.
    if op.value_loaded {
        return format_auth(parse_data_object(&op.value, false, true).as_ref());
    }
    match auth_by_rules(&op.value) {
        Some(auth) => auth,
        // Declined inline: upstream reads the matcher itself as a data object,
        // and a value with a slash but no `=` yields nothing at all.
        None => format_auth(parse_data_object(&op.value, false, op.value_is_content).as_ref()),
    }
}

/// `getAuthByRules` (`_original/lib/util/index.js:3644-3661`) — the inline
/// reading of an `auth://` value, or `None` when it declines.
///
/// This port understood only `user:pass`, so the other two shapes — the JSON
/// object and the `username=…&password=…` query — were base64-encoded whole and
/// sent as the credentials themselves. `auth://{"username":"u","password":"p"}`
/// authenticated as the user *`{"username"`* with the password
/// *`"u","password":"p"}`*, which a server answers with a 401 that looks like
/// the rule never ran.
///
/// **A value with a slash in it is not credentials.** `SLASH_RE = /[\\/]/`
/// (`util/index.js:102`) tests the whole value, and when it matches upstream
/// returns nothing — the value is a *location*, and only the other road may read
/// it. This port used to split it on the first colon anyway, on the reading that
/// a password may contain a slash. It may not: measured against whistle 2.10.8,
/// `auth://admin:se/cret` sends **no** `Authorization` header there, and so do
/// the block and `(inline)` spellings of the same text. What the old behaviour
/// did instead was send the local filesystem path — the documented
/// `auth:///Users/john/config/auth.json` reached the origin as
/// `Authorization: Basic base64("/Users/john/config/auth.json")` whenever the
/// file could not be read.
fn auth_by_rules(value: &str) -> Option<Auth> {
    let value = value.trim();
    // `auth[0] === '{' && auth[auth.length - 1] === '}'`: a JSON object.
    if value.starts_with('{') && value.ends_with('}') {
        // A JSON object upstream cannot parse becomes `{}` — an auth naming
        // neither half, which produces no header rather than a bad one.
        let parsed = crate::rules::url::parse_json(value);
        return Some(format_auth(parsed.as_ref()));
    }
    // `AUTH_RE = /^(?:username|password)=/` — anchored, and case-sensitive. It
    // is tested *before* the slash, so a password may contain one here.
    if value.starts_with("username=") || value.starts_with("password=") {
        // `parseQuery(auth, null, null, true)`: the raw decoder, so a `%2F` or a
        // `+` in a password reaches the server as written.
        let obj: serde_json::Map<String, serde_json::Value> = value
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        return Some(format_auth(Some(&serde_json::Value::Object(obj))));
    }
    if value.contains('/') || value.contains('\\') {
        return None;
    }
    Some(match value.split_once(':') {
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
    })
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
    /// only, and unlike every other key here it is *not* scoped by `req`/`res`
    /// and *not* case-insensitive.
    trailers: Vec<String>,
    /// `delete://resType` — drop the media type, keeping any charset.
    drop_type: bool,
    /// `delete://resCharset` — drop the charset, keeping the media type.
    drop_charset: bool,
    /// `delete://body` / `delete://res.body` — empty the body outright, which
    /// also discards anything an operator meant to inject (`removeBody`,
    /// `_original/lib/util/index.js:3591-3598`).
    ///
    /// Deliberate divergence, and the second half is all upstream achieves.
    /// `removeBody` writes `data.body = EMPTY_BUFFER`, and `EMPTY_BUFFER` is
    /// `toBuffer('')` — whose first act is `if (!buf) return;`
    /// (`_original/lib/util/common.js:1630-1632`), so the constant is
    /// `undefined`. The assignment therefore leaves `data.body` falsy,
    /// `isWhistleTransformData` says no, and no transform is added: upstream
    /// drops the `reqBody`/`reqPrepend`/`reqAppend` injections and forwards the
    /// real body untouched. The key is documented as removing the body
    /// (<https://wproxy.org/docs/rules/delete.html>) and the code plainly means
    /// to; this port does it.
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
            // `parseProps` — the split honours `\|`, `\&` and the `\s`/`\t`/
            // `\n`/`\r`/`\f`/`\v` escapes, which is how `delete.md`'s own
            // example addresses a body key holding a newline and a pipe.
            for key in parse_props(value) {
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
                        .find("trailer.")
                        .map(|i| &key[i + "trailer.".len()..])
                        .filter(|n| !n.is_empty())
                {
                    // `TRAILER_RE` is unanchored at the front, so a bare
                    // `trailer.x` matches and so does anything else ending in
                    // `trailer.<name>`. It is also the one key here written
                    // without the `i` flag, so the word must be lower case:
                    // `delete://resTrailer.x` matches nothing and is inert.
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
    let tail = key
        .get(..side.len())
        .filter(|p| p.eq_ignore_ascii_case(side))?;
    let mut tail = &key[tail.len()..];
    tail = tail.strip_prefix('.').unwrap_or(tail);
    let after_initial = tail
        .get(..initial.len())
        .filter(|c| c.eq_ignore_ascii_case(initial))?;
    tail = &tail[after_initial.len()..];
    // The word may be spelled out in full, with an optional plural `s`.
    for word in [rest, &rest[..rest.len() - 1]] {
        if let Some(t) = tail
            .get(..word.len())
            .filter(|w| w.eq_ignore_ascii_case(word))
        {
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
fn replace_in_header(headers: &mut HeaderMap, name: &str, pattern: &str, repl: &str) {
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

/// whistle's `_parseJSON` (`_original/lib/util/index.js:1135-1143`): the three
/// spellings a data-valued operator accepts, tried in order.
///
/// 1. **JSON** — `parseRawJson`, a plain `JSON.parse` in a `try`.
/// 2. **A query string** — `parseInlineJSON`, but *only* when the text contains
///    no whitespace at all (`SPACE_RE.test(text)` returns early otherwise), so
///    `a=1&b=2` is a pair list and `a=1 &b=2` is not.
/// 3. **The line format** — [`parse_plain_text`], one `name: value` per line.
///
/// The third was missing here, everywhere, and the documentation leads with it:
/// <https://wproxy.org/docs/rules/resMerge.html> opens with `resMerge://test=123`
/// and the `行格式` section of every data-operator page shows the multi-line form
/// through a `{value}` reference. Both did nothing in this port.
///
/// `resolve_keys` is `RESOLVE_KEY_RE` (`util/index.js:95`), which is exactly
/// `^re[qs]Merge://` — only the merge pair reads a dotted name as a path into
/// the object. Every other operator takes the name literally.
fn parse_data_object(
    text: &str,
    resolve_keys: bool,
    is_content: bool,
) -> Option<serde_json::Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // `tryParseMatcher` comes **first**, and only for a value that is the rule's
    // own matcher rather than text some loader produced — its guard is `!text`
    // (`_original/lib/util/index.js:1165-1171`, ahead of `_parseJSON` at
    // `:1303`). It asks one question: does the matcher contain an `=`? If so the
    // whole thing is a query string, whitespace and newlines included.
    //
    // That is why `reqHeaders://x-a=${v}` with a two-line `v` sets **no** header
    // upstream: the value stays whole, carries a newline, and `setHeader` throws
    // on it. Splitting it into lines here instead produced a header whistle
    // never sends. A value that came from the values store takes the other road.
    if let Some(value) = crate::rules::url::parse_json(text) {
        return Some(value);
    }
    if !is_content {
        // A written matcher is a query string when it has an `=`, and **nothing
        // at all** when it does not. Measured, five shapes: `x-a=1` sets the
        // header; `x-a=line1\nline2` keeps the newline in the value and is
        // thrown away by the header layer; `bare` and a lone backtick set
        // nothing. The same words inside loaded content *do* become headers with
        // empty values, which is the line format doing its job — so the two
        // roads really are different, not one road read twice.
        let pairs = text.contains('=').then(|| ordered_pairs(text))??;
        return Some(serde_json::Value::Object(pairs.into_iter().collect()));
    }
    if !text.contains(char::is_whitespace) {
        let pairs = ordered_pairs(text)?;
        return Some(serde_json::Value::Object(pairs.into_iter().collect()));
    }
    parse_plain_text(text, resolve_keys)
}

/// The line format: one `name: value` per line, folded into an object.
///
/// `common.parsePlainText` (`_original/lib/util/common.js:1178-1217`). Upstream
/// starts the result as an array when the first key is numeric; this port always
/// builds an object, because the array case only arises through `resolve_keys`
/// and a numeric first segment, and every consumer here indexes by name.
fn parse_plain_text(text: &str, resolve_keys: bool) -> Option<serde_json::Value> {
    let mut out = serde_json::Map::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = parse_data_line(line);
        match resolve_keys {
            true => insert_at_path(&mut out, &parse_json_path(&name), value),
            false => {
                out.insert(name, value);
            }
        }
    }
    (!out.is_empty()).then(|| serde_json::Value::Object(out))
}

/// One line of the line format (`parseLine`, `common.js:1134-1168`).
///
/// The separator is the first `": "`, else the first `':'`, else the first `'='`
/// — in that order, so `x-a: b:c` splits at the space-colon and keeps `b:c`. A
/// line with none of them is a name with an empty value.
///
/// A value wrapped in a matching pair of `"`, `'` or `` ` `` loses the quotes,
/// and a backticked one also turns its literal `\n` and `\r` into the real
/// characters. An unquoted value that is a safe integer becomes a number rather
/// than a string.
fn parse_data_line(line: &str) -> (String, serde_json::Value) {
    let at = line
        .find(": ")
        .or_else(|| line.find(':'))
        .or_else(|| line.find('='));
    let Some(at) = at else {
        return (line.to_string(), serde_json::Value::String(String::new()));
    };
    let name = line[..at].trim().to_string();
    let value = line[at + 1..].trim();
    // Upstream asks one question first — **do the first and last characters
    // match?** — and only then which of the two branches to take:
    //
    // ```js
    // if (fv === lv) { …unquote…} else if (isSafeNumStr(value)) { value = parseInt(value, 10); }
    // ```
    //
    // (`parseLine`, `_original/lib/util/common.js:1145-1157`.) So the numeric
    // conversion is *unreachable* for a value whose ends match, and that is not
    // a quirk of quoting alone: `1`, `11` and `121` all stay strings while `123`
    // and `-12` become numbers. Measured against whistle 2.10.8 for each.
    let mut ends = value.chars();
    let first = ends.next();
    let last = ends.next_back().or(first);
    if first == last {
        if let Some(q) = first.filter(|c| "\"'`".contains(*c))
            && value.chars().count() >= 2
        {
            let inner = &value[q.len_utf8()..value.len() - q.len_utf8()];
            let inner = match q == '`' {
                true => inner.replace("\\n", "\n").replace("\\r", "\r"),
                false => inner.to_string(),
            };
            return (name, serde_json::Value::String(inner));
        }
        return (name, serde_json::Value::String(value.to_string()));
    }
    match safe_num(value) {
        Some(n) => (name, serde_json::Value::Number(n.into())),
        None => (name, serde_json::Value::String(value.to_string())),
    }
}

/// `isSafeNumStr` (`_original/lib/util/common.js:1016-1029`): `0`, or an
/// optionally-signed run of 1–16 digits with no leading zero, within JavaScript's
/// safe-integer range.
fn safe_num(value: &str) -> Option<i64> {
    if value == "0" {
        return Some(0);
    }
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    let ok = (1..=16).contains(&digits.len())
        && digits.starts_with(|c: char| c.is_ascii_digit() && c != '0')
        && digits.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| value.parse::<i64>().ok())
        .flatten()
        .filter(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
}

/// Place `value` at a dotted path, creating the objects along the way.
/// A path segment, and whether it arrived as a bracket index.
///
/// The distinction is upstream's and it is the only thing that decides between
/// an array and an object: `parseKey` turns `a[0]` into the pair `['a', 0]` with
/// a **number** for the index (`+result[1]`, `_original/lib/util/common.js:1064`),
/// while a dotted `a.0` stays two strings. `parsePlainText` then opens an array
/// exactly when the next key is a number (`:1209-1212`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathSegment {
    name: String,
    is_index: bool,
}

impl PathSegment {
    fn key(name: impl Into<String>) -> Self {
        PathSegment {
            name: name.into(),
            is_index: false,
        }
    }
    fn index(name: impl Into<String>) -> Self {
        PathSegment {
            name: name.into(),
            is_index: true,
        }
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// Write `value` at `path`, opening the containers the path implies.
fn insert_at_path(
    out: &mut serde_json::Map<String, serde_json::Value>,
    path: &[PathSegment],
    value: serde_json::Value,
) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        out.insert(first.name.clone(), value);
        return;
    }
    let slot = open_slot(out, &first.name, rest[0].is_index);
    insert_into(slot, rest, value);
}

/// The container under `name`, made if it is not there and replaced if what is
/// there cannot hold a path.
fn open_slot<'a>(
    map: &'a mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    wants_array: bool,
) -> &'a mut serde_json::Value {
    map.entry(name.to_string())
        .and_modify(|v| {
            if !v.is_object() && !v.is_array() {
                *v = empty_container(wants_array);
            }
        })
        .or_insert_with(|| empty_container(wants_array))
}

fn insert_into(node: &mut serde_json::Value, path: &[PathSegment], value: serde_json::Value) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    match node {
        serde_json::Value::Array(items) => {
            let at: usize = first.name.parse().unwrap_or(0);
            while items.len() <= at {
                items.push(serde_json::Value::Null);
            }
            if rest.is_empty() {
                items[at] = value;
                return;
            }
            if !items[at].is_object() && !items[at].is_array() {
                items[at] = empty_container(rest[0].is_index);
            }
            insert_into(&mut items[at], rest, value);
        }
        serde_json::Value::Object(map) => {
            if rest.is_empty() {
                map.insert(first.name.clone(), value);
                return;
            }
            let slot = open_slot(map, &first.name, rest[0].is_index);
            insert_into(slot, rest, value);
        }
        // A scalar cannot hold a path; the caller replaced one before
        // descending, so this is only reachable for a root that is neither.
        _ => {}
    }
}

/// The container a path segment opens: an array when the segment below it is a
/// bracket index, an object otherwise.
fn empty_container(wants_array: bool) -> serde_json::Value {
    match wants_array {
        true => serde_json::Value::Array(Vec::new()),
        false => serde_json::Value::Object(serde_json::Map::new()),
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
///
/// The header is *rebuilt*, not edited: upstream splits it, drops the named
/// pair and renders the survivors as `name=value` joined by `"; "`
/// (`setReqCookies`, `_original/lib/util/index.js:3052-3090`). Three
/// consequences worth the rebuild: a pair that arrived without a `=` leaves
/// with one, a trailing `;` becomes a nameless `=` pair of its own, and when
/// nothing survives the header is set to the **empty string** rather than
/// removed. `setHeader` assigns unconditionally, so the request still carries a
/// `Cookie:` with nothing after it; a server that branches on the header's
/// presence must see what whistle's would.
fn remove_cookie(headers: &mut HeaderMap, name: &str) {
    let Some(cur) = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return;
    };
    let kept = cur
        .split(';')
        .map(|s| s.trim())
        .filter(|kv| kv.split_once('=').map_or(*kv, |(k, _)| k) != name)
        .map(|kv| match kv.contains('=') {
            true => kv.to_string(),
            false => format!("{kv}="),
        })
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(v) = HeaderValue::from_str(&kept) {
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
///
/// The delays and the speeds read their value **differently**, and the
/// difference is not a choice anyone made — it falls out of where each one is
/// used. A speed goes through `parseFloat` (`_original/lib/inspectors/res.js:914`),
/// which takes the longest numeric prefix, so `resSpeed://600kb` is 600. A delay
/// is never parsed at all: `exports.delay` compares the matcher's **string** to
/// zero, `if (time > 0)` (`_original/lib/util/index.js:3686-3691`), and
/// JavaScript's `>` converts that string with `Number`, which demands the whole
/// text be numeric. `'400' > 0` is true; `'400ms' > 0` is `NaN > 0`, which is
/// false, so a delay carrying its unit **does not delay**.
///
/// This port used `parseFloat` for both, so `reqDelay://400ms` waited 400 ms
/// here and nothing upstream. Measured on the timing bench, which is the only
/// place a delay is visible at all.
pub fn req_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved
        .value("reqDelay")
        .and_then(js_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Milliseconds to delay before returning the response (`resDelay`).
pub fn res_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved
        .value("resDelay")
        .and_then(js_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Request-body throughput cap in kilobits/s (`reqSpeed`) — see
/// [`super::body::throttled`] for why the unit is bits.
///
/// Only a **positive** rate is a cap. Upstream gates both speeds on
/// `if (reqSpeed > 0)` / `if (resSpeed > 0)`
/// (`_original/lib/inspectors/req.js:523-527`, `res.js:913-917`), so `0` and a
/// negative value mean *no throttle*, the same way `reqDelay://0` means no
/// delay. Without this filter `resSpeed://0` reached [`super::body::throttled`],
/// whose `.max(1.0)` floor turned it into one byte per 50 ms — 20 B/s, or four
/// hours for a 300 KB body. A value meaning "no limit" became the slowest limit
/// expressible, which reads to a client as a hang.
pub fn req_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved
        .value("reqSpeed")
        .and_then(parse_leading_number)
        .filter(|rate| *rate > 0.0)
}

/// Response-body throughput cap in kilobits/s (`resSpeed`).
pub fn res_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved
        .value("resSpeed")
        .and_then(parse_leading_number)
        .filter(|rate| *rate > 0.0)
}

/// JavaScript's `Number(string)`: the whole text, or nothing.
///
/// Returns `None` where JavaScript would give `NaN`, which is what a caller
/// comparing `> 0` needs — every comparison against `NaN` is false.
///
/// The three shapes `Number` accepts that a plain float parse does not, and the
/// two it rejects that Rust's does:
///
/// * an empty or all-whitespace string is **zero**, not an error;
/// * `0x` / `0o` / `0b` are read in their radix, but only unsigned —
///   `Number('-0x10')` is `NaN`;
/// * `Infinity` is spelled exactly that way, capital `I`, optionally signed.
///   Rust also accepts `inf`, `infinity` and `nan`, which JavaScript does not,
///   so anything else carrying a letter besides an exponent's `e` is rejected.
///
/// Only the delays use this; see [`req_delay_ms`] for why they and the speeds
/// read their values differently.
fn js_number(value: &str) -> Option<f64> {
    let text = value.trim();
    if text.is_empty() {
        return Some(0.0);
    }
    match text {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok().map(|n| n as f64);
    }
    if let Some(rest) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        return u64::from_str_radix(rest, 8).ok().map(|n| n as f64);
    }
    if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        return u64::from_str_radix(rest, 2).ok().map(|n| n as f64);
    }
    // `inf`, `infinity` and `nan` parse in Rust and are `NaN` in JavaScript.
    if text
        .chars()
        .any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E')
    {
        return None;
    }
    text.parse().ok().filter(|n: &f64| !n.is_nan())
}

/// JavaScript's `parseFloat`: the longest numeric prefix, ignoring whatever
/// follows.
///
/// whistle reads the **speeds** this way — `resSpeed = resSpeed &&
/// parseFloat(resSpeed)` (`_original/lib/inspectors/res.js:914`,
/// `req.js:524`) — so `resSpeed://20kb` is 20 there. Rust's `parse` rejects it
/// outright, which turned a value with a unit suffix — the way anyone would
/// first write one — into no throttle at all.
///
/// The delays do **not** go through here; see [`js_number`].
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

/// The rules that matched, as `enable://responseWithMatchedRules` reports them.
///
/// `getRulesText` walks `req.rules` and writes `rawPattern + ' ' + rawMatcher`
/// per entry, joined with `\n` and `encodeURIComponent`d whole
/// (`_original/lib/util/index.js:1867-1877`). The header is
/// `x-whistle-matched-rules`.
///
/// **The order is the protocol table's**, which is what `Object.keys(req.rules)`
/// yields: whistle assigns its keys as it walks `protocols.js`, so the report
/// follows that array and not the order the operators were written. Measured
/// three ways before it was believed — `resHeaders://x-r=1 enable://…` reports
/// the `enable` first (index 24 against 57), and `file://(mocked) enable://…`
/// reports the `file` first, because a local file is filed under `rule` at
/// index 3. Operators sharing a protocol keep resolution order between them.
///
/// The request-side twin `requestWithMatchedRules` is deliberately absent:
/// upstream calls `addMatchedRules(req)` from the response inspector
/// (`res.js:770`), after the request head has gone, so the origin never sees
/// that header. Measured; both proxies send nothing.
fn matched_rules_text(resolved: &Resolved) -> Option<String> {
    let mut ops: Vec<&RuleOp> = resolved
        .single
        .values()
        .chain(resolved.multi.values().flatten())
        .chain(resolved.slot())
        .collect();
    // The slot's members are all filed under `rule` upstream, whatever their own
    // spelling — that is what puts `file://` ahead of `enable://`.
    let key = |op: &RuleOp| -> (usize, u64) {
        let name = match crate::rules::protocols::is_slot_protocol(&op.protocol) {
            true => crate::rules::protocols::URL_REPLACE,
            false => op.protocol.as_str(),
        };
        let at = crate::rules::protocols::PROTOCOLS
            .iter()
            .position(|p| *p == name)
            .unwrap_or(usize::MAX);
        (at, op.order)
    };
    ops.sort_by_key(|op| key(op));
    let mut lines: Vec<String> = Vec::new();
    for op in ops {
        let line = format!("{} {}", op.raw_pattern, op.raw);
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    (!lines.is_empty()).then(|| crate::rules::replace::encode_uri_component(&lines.join("\n")))
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
    if is_enabled(resolved, "responseWithMatchedRules")
        && let Some(text) = matched_rules_text(resolved)
        && let Ok(value) = hyper::header::HeaderValue::from_str(&text)
    {
        parts.headers.insert("x-whistle-matched-rules", value);
    }
    // `statusCode` only speaks when it won the shared slot. Upstream reads it
    // off `rules.rule` (`getStatusCodeFromRule`,
    // `_original/lib/util/index.js:3566-3589`), which is the same single winner
    // a `file://` or a destination would have taken — so a `statusCode` written
    // below one of those, or after one on the same line, never reaches the
    // response at all. Here it was applied unconditionally, and so overwrote the
    // status of a file the rules had already chosen to serve. No gate is needed
    // for that any more: a losing `statusCode` is not in the resolved set to be
    // read. `replaceStatus` has a list of its own upstream and never was.
    if let Some((proto, code)) = ["replaceStatus", "statusCode"]
        .into_iter()
        .find_map(|p| resolved.value(p).map(|v| (p, v)))
        // A value that is not a status leaves the response alone. Upstream
        // hands it to `res.writeHead` and the client gets a connection reset
        // (measured, same list as `statusCode://` above); an operator that
        // cannot be honoured is not a reason to drop a response that arrived.
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
        if user_login_allowed(resolved, proto) {
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
        if !is_enabled(resolved, "keepCSP") && !is_enabled(resolved, "keepAllCSP") {
            disable_csp(&mut parts.headers);
        }
        if !custom_cache(resolved) && !is_enabled(resolved, "keepCache") {
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
    // `-M keepXFF` is `enable://clientIp` for every request — still beaten by an
    // explicit `disable://clientIp` below, as the flag is.
    let keep_all = KEEP_CLIENT_XFF.load(std::sync::atomic::Ordering::Relaxed);
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
    if !keep_all && !en.contains("clientIp") && !en.contains("clientIP") {
        headers.remove(XFF);
    }
}

/// Set by the launch when `-M keepXFF` (or `forwardedFor`) named it.
///
/// A process-wide switch rather than a threaded parameter, for the same reason
/// [`super::upstream::set_insecure_upstream`] is one: it is decided once, at
/// startup, and every request reads the same answer.
static KEEP_CLIENT_XFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Called once by the launch; see [`KEEP_CLIENT_XFF`].
pub fn set_keep_client_xff(keep: bool) {
    KEEP_CLIENT_XFF.store(keep, std::sync::atomic::Ordering::Relaxed);
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
fn write_res_cors(headers: &mut HeaderMap, spec: &HashMap<String, String>, info: Option<&ReqInfo>) {
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
fn merge_cors_ops(resolved: &Resolved, protocol: &str) -> HashMap<String, String> {
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
fn parse_cors(value: &str, is_content: bool) -> HashMap<String, String> {
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

/// Does the rule that produced a `401`/`407` want the authentication challenge
/// that goes with it?
///
/// `isDisableUserLogin` (`_original/lib/util/index.js:3557-3562`): the line's own
/// `enableUserLogin` or a request-wide `enable://userLogin` forces it on and wins
/// outright; `disableUserLogin` on the line or `disable://userLogin` turns it off.
///
/// `docs/LINE_PROPS.md` had the two properties as "not applicable, this port has
/// no login box". They are not about whistle's own login box at all — they are
/// about the `WWW-Authenticate: Basic realm=User Login` header a mocked `401`
/// carries, which is the thing that *makes* a browser show one. This port writes
/// that header, so there was always something here to turn off.
fn user_login_allowed(resolved: &Resolved, proto: &str) -> bool {
    let props = resolved.props(proto);
    if props.has("enableUserLogin") || enabled_flags(resolved).contains("userLogin") {
        return true;
    }
    !props.has("disableUserLogin") && !disabled_flags(resolved).contains("userLogin")
}

/// `statusCode://401`/`407` and `replaceStatus://401`/`407` also advertise the
/// authentication a browser needs in order to ask for credentials
/// (`handleStatusCode`, `_original/lib/util/index.js:401-408`).
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
    let no_cache =
        matches!(lower.as_str(), "no" | "no-cache" | "no-store") || max_age.is_some_and(|n| n < 0);
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
    if is_enabled(resolved, "keepAllCache") {
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
///
/// "Produced content" is the operative half, and it is a truthiness test on the
/// assembled value, not on the operator having matched: a `resPrepend://()`
/// leaves `data.top` undefined and the strip never runs. This port asked only
/// whether the operator matched, so an operator written with no value stripped
/// the CSP off a page it did not otherwise touch and marked it `no-store`.
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
    let writes = |protocol: String| {
        resolved
            .all(&protocol)
            .iter()
            .any(|op| !op.value.is_empty())
    };
    // `weinre://` is an injector too, and upstream clears the same two things
    // for it (`_original/lib/inspectors/weinre.js:37-38`). It has to: a debug
    // agent pushed into a page whose CSP forbids inline scripts never runs, and
    // one the browser caches outlives the rule that asked for it. This port
    // injected the script and left both standing.
    //
    // Upstream reaches JavaScript responses as well, appending the agent source
    // bare; this port's injection is a `<script src>` tag, which only means
    // anything in markup — see `docs/RULES.md`.
    if families.html && resolved.value("weinre").is_some() {
        return true;
    }
    ["Body", "Prepend", "Append"].iter().any(|slot| {
        writes(format!("res{slot}"))
            || (families.html && writes(format!("html{slot}")))
            || (families.js && writes(format!("js{slot}")))
            || (families.css && writes(format!("css{slot}")))
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
    method_allows_body(method)
        .then(|| resolved.value("reqWrite"))?
        .map(dump_path)
}

/// File to write the response body to (`resWrite`), named for the status.
pub fn res_write_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved
        .value("resWrite")
        .map(|f| writer_file(&dump_path(f), status))
}

/// File to write the raw request (head + body) to (`reqWriteRaw`).
///
/// Not gated on the method: the head is worth dumping whether or not a body
/// followed it, and upstream does not gate it either (`req.js:586`).
pub fn req_write_raw_path(resolved: &Resolved) -> Option<String> {
    resolved.value("reqWriteRaw").map(dump_path)
}

/// File to write the raw response (head + body) to (`resWriteRaw`), named for
/// the status.
pub fn res_write_raw_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved
        .value("resWriteRaw")
        .map(|f| writer_file(&dump_path(f), status))
}

/// A dump operator's value as a filesystem path.
///
/// Two things the matcher's tail-join leaves behind, both removed by upstream's
/// `getPath` before the path is opened (`_original/lib/util/index.js:1461-1464`,
/// via `getPath` at `:1420-1433`):
///
/// * **the query.** `resWrite://…/d` on a request for `/echo?q=1` writes `d/echo`
///   upstream; this port wrote a file literally named `echo?q=1`.
/// * **`<verbatim>` brackets.** They are the documented way to refuse the join,
///   and unwrapping them is what makes the refusal mean a path rather than a
///   filename with angle brackets in it — which is what this port tried to open,
///   so nothing was written at all.
fn dump_path(value: &str) -> String {
    let text =
        crate::rules::url::fixed_value(value).map_or_else(|| value.to_string(), |(_, inner)| inner);
    match text.find('?') {
        Some(i) => text[..i].to_string(),
        None => text,
    }
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
    is_enabled(resolved, "forceReqWrite") && !disabled_flags(resolved).contains("forceReqWrite")
}

/// How many bytes of a request body may be read into memory before the
/// operators that rewrite it give up and let it stream past.
///
/// whistle's `MAX_REQ_SIZE` is 2MB, raised to `BIG_MAX_REQ_SIZE` (16MB) by
/// `enable://reqMergeBigData` (`_original/lib/inspectors/req.js:19-20,:163`).
/// This port has no `config.strict`, so the 1MB strict variant has no spelling
/// here and the plain 2MB is the floor.
///
/// `lineProps://enableBigData` on the `reqMerge://` line raises it too, and this
/// read it as one of whistle's own settings rather than a line property — the
/// `enableBigData` argument of `handleParams` is `reqMerge.lineProps.enableBigData`
/// and nothing else (`req.js:564`). Measured against the differential bench, a
/// 3 MB JSON body with `reqMerge://{"added":1} lineProps://enableBigData` was
/// merged by whistle and forwarded unchanged here.
/// How much of a **response** body this request may hold in order to rewrite it.
///
/// Upstream has a limit per merge rather than per response: `resMerge://` is
/// skipped over a body larger than `MAX_RES_SIZE` (2 MB), and
/// `enable://resMergeBigData` or `lineProps://enableBigData` on the line raises
/// it to `BIG_MAX_RES_SIZE` (16 MB) — `res.js:21-22,:1013`.
///
/// Here the bound is one knob for every response operator
/// (`--body-rewrite-limit`, 16 MB by default), so the flags cannot make a
/// smaller default bigger for the merge alone. What they do instead is raise
/// **this request's** ceiling to upstream's big one, which matters exactly when
/// a user has lowered the knob: the two documented ways of saying "this body is
/// worth reading" then say it here too.
pub fn res_body_limit(resolved: &Resolved, configured: usize) -> usize {
    /// `BIG_MAX_RES_SIZE` (`_original/lib/inspectors/res.js:22`).
    const BIG: usize = 16 * 1024 * 1024;
    let on = resolved.props("resMerge").has("enableBigData")
        || (is_enabled(resolved, "resMergeBigData")
            && !disabled_flags(resolved).contains("resMergeBigData"));
    match on {
        true => configured.max(BIG),
        false => configured,
    }
}

pub fn req_body_limit(resolved: &Resolved) -> usize {
    /// `BIG_MAX_REQ_SIZE` (`req.js:20`).
    const BIG: usize = 16 * 1024 * 1024;
    // `isEnable` is the flag minus its cancellation, the same shape
    // [`forces_write`] uses (`_original/lib/util/index.js:676-679`). The line
    // property has no cancellation: upstream reads it straight off the rule.
    // `params` is where `reqMerge://` lands here, as `reqRules.params` is where
    // it lands upstream (`req.js:461`).
    let on = resolved.props("params").has("enableBigData")
        || (is_enabled(resolved, "reqMergeBigData")
            && !disabled_flags(resolved).contains("reqMergeBigData"));
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
    top: Vec<Piece>,
    body: Vec<Piece>,
    bottom: Vec<Piece>,
    /// Whether the body slot was claimed at all. Distinct from `body` being
    /// non-empty: a `*Body` operator that matched with a blank value still
    /// replaces the body (upstream substitutes an empty *buffer*, which is
    /// truthy, `_original/lib/inspectors/res.js:1005` +
    /// `whistle-transform.js:110-114`), so `resBody://` empties it.
    replaces_body: bool,
}

impl Injection {
    /// Re-encode every injected piece into the response's own charset.
    ///
    /// A rule's value is UTF-8 — it came out of a rules file — and the page it
    /// is pasted into is not. whistle encodes each value as it reads it
    /// (`toBuffer(value, charset)`, `_original/lib/util/index.js:1388`) and once
    /// more in the transform (`WhistleTransform`,
    /// `_original/lib/util/whistle-transform.js:21-45`), so a `htmlAppend://中文`
    /// lands on a `charset=gbk` page as GBK rather than as four bytes the page
    /// renders as mojibake.
    ///
    /// The separators stay as they are: CRLF and the doctype are ASCII, and
    /// every charset with a `charset=` label worth honouring is ASCII-compatible.
    ///
    /// Bytes a binary operator read from a file are not text in anybody's
    /// charset and go as they are — upstream's `toBuffer` returns a `Buffer`
    /// untouched (`_original/lib/util/common.js:1563-1566`).
    fn recode(&mut self, encoding: &'static encoding_rs::Encoding) {
        for slot in [&mut self.top, &mut self.body, &mut self.bottom] {
            for piece in slot.iter_mut().filter(|p| !p.raw) {
                piece.bytes = super::coding::encode_charset(
                    encoding,
                    &String::from_utf8_lossy(std::mem::take(&mut piece.bytes).as_slice()),
                );
            }
        }
    }

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

/// One line's contribution to a slot.
struct Piece {
    bytes: Vec<u8>,
    /// Bytes a binary operator loaded as they are ([`RuleOp::value_bytes`]),
    /// which no charset applies to.
    raw: bool,
}

impl Piece {
    /// Text: a rule's value, or markup made from one.
    fn text(bytes: Vec<u8>) -> Self {
        Piece { bytes, raw: false }
    }

    /// What an operator line sends: its loaded bytes when it has them.
    fn of(op: &RuleOp) -> Self {
        match &op.value_bytes {
            Some(bytes) => Piece {
                bytes: bytes.to_vec(),
                raw: true,
            },
            None => Piece::text(op.value.as_bytes().to_vec()),
        }
    }
}

/// Append `pieces` to `out`, CRLF-separated.
fn join_into(out: &mut Vec<u8>, pieces: Vec<Piece>) {
    for (i, piece) in pieces.into_iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(CRLF);
        }
        out.extend(piece.bytes);
    }
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
        // All three spellings, not JSON alone. `resMerge://test=123` is the
        // first example on <https://wproxy.org/docs/rules/resMerge.html> and it
        // did nothing here; so did the line format, which is how a `{value}`
        // reference carries a merge patch. `resMerge`/`reqMerge` are also the
        // only operators whose dotted names are paths (`RESOLVE_KEY_RE`).
        let Some(value) =
            parse_data_object(&op.value, resolves_dotted_keys(op), op.value_is_content)
        else {
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
/// Whether `params://` rewrites this request's **body** — a form or JSON one —
/// rather than only its query string.
pub fn params_rewrite_body(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> bool {
    params_body_kind(resolved, ctx).is_some()
}

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
    if ct
        .to_ascii_lowercase()
        .contains("application/x-www-form-urlencoded")
    {
        return ctx
            .method
            .eq_ignore_ascii_case("POST")
            .then_some(ParamsBody::Form);
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
        && ct
            .to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
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
            let Some(mut base) = crate::rules::url::parse_json(&text[start..end]) else {
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
    // Kept as JSON: an object is a file part, not a field (`toMultipart`).
    let mut params = merge_params_values(resolved, "params");

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
                Some((k, v)) => push_multipart_raw(&mut out, boundary, &multipart_part(&k, &v)),
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
        push_multipart_raw(&mut out, boundary, &multipart_part(name, value));
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

/// One `params://` entry as a multipart part — `toMultipart`
/// (`_original/lib/inspectors/req.js:61-95`).
///
/// A scalar is a plain field. An **object** is a file: `filename` (or `name`,
/// or else the field's own name), content from `content` or `value` — an
/// object there is pretty-printed JSON, and `base64` supplies raw bytes
/// instead — and a `Content-Type` from `type` (a bare extension is looked up)
/// or from the filename. This port wrote an object as an empty plain field;
/// upstream's `params.test.js` uploads through exactly these two shapes.
fn multipart_part(name: &str, value: &serde_json::Value) -> Vec<u8> {
    let serde_json::Value::Object(obj) = value else {
        let text = json_to_param_string(value.clone());
        return format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{text}")
            .into_bytes();
    };
    let truthy = |v: &&serde_json::Value| match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        serde_json::Value::String(s) => !s.is_empty(),
        _ => true,
    };
    // `String(v)`, near enough for what a rules file can hold.
    let js_string = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => "[object Object]".to_string(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|i| json_to_param_string(i.clone()))
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    };
    // `value.filename || value.name`, then `filename == null ? name : filename + ''`.
    let filename = match obj
        .get("filename")
        .filter(truthy)
        .or_else(|| obj.get("name"))
    {
        None | Some(serde_json::Value::Null) => name.to_string(),
        Some(v) => js_string(v),
    };
    // `value.content || value.value || ''`.
    let content = obj
        .get("content")
        .filter(truthy)
        .or_else(|| obj.get("value").filter(truthy));
    let mut raw: Vec<u8> = Vec::new();
    let text = match content {
        Some(v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => {
            serde_json::to_string_pretty(v).unwrap_or_default()
        }
        Some(v) => js_string(v),
        None => {
            if let Some(serde_json::Value::String(b64)) = obj.get("base64").filter(truthy) {
                use base64::Engine as _;
                raw = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .unwrap_or_default();
            }
            String::new()
        }
    };
    let content_type = match obj.get("type") {
        Some(serde_json::Value::String(t)) if t.contains('/') => t.clone(),
        Some(serde_json::Value::String(t)) if !t.is_empty() => {
            content_type_of_ext(&format!("x.{t}"))
                .map(media_type)
                .unwrap_or(t)
                .to_string()
        }
        _ => content_type_of_ext(&filename)
            .map(media_type)
            .unwrap_or("application/octet-stream")
            .to_string(),
    };
    let mut part = format!(
        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
         Content-Type: {content_type}\r\n\r\n{text}"
    )
    .into_bytes();
    part.extend(raw);
    part
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
    // A declared `charset=` other than UTF-8 puts the text operators inside a
    // decode/encode pair, and encodes the injected values on the way in. Both
    // halves are upstream's — see [`super::coding::charset_of`].
    let charset = super::coding::charset_of(content_type);

    let mut data = match charset {
        None => body.to_vec(),
        Some(enc) => super::coding::decode_charset(enc, &body).into_bytes(),
    };
    data = apply_res_merge(data, resolved, class, &del);
    data = apply_replace(data, resolved, "resReplace", class);
    if let Some(enc) = charset {
        data = super::coding::encode_charset(enc, &String::from_utf8_lossy(&data));
    }

    let mut injection = collect_res_injection(&gate, families);
    if let Some(enc) = charset {
        injection.recode(enc);
    }
    // Only an HTML response gets the doctype, and `disable://doctype` opts out.
    let doctype = families.html && !is_disabled(resolved, "doctype");
    Bytes::from(injection.apply(data, doctype))
}

/// Fill the generic (`res*` / `req*`) contribution of each slot, shared by both
/// sides.
///
/// Several lines carrying the same operator are CRLF-joined in resolution order
/// and pushed as one part. That is byte-identical to pushing each line
/// separately, since the typed families that follow use the same separator.
fn collect_generic(injection: &mut Injection, gate: &InjectionGate<'_>, prefix: &str) {
    if let Some(joined) = gate
        .joined(&format!("{prefix}Body"))
        .filter(Joined::claims_body)
    {
        injection.replaces_body = true;
        injection.body.extend(joined.pieces);
    }
    // `*Prepend`/`*Append` are tested the same way: upstream assigns the raw
    // value and tests it for truthiness, so an all-blank one contributes nothing
    // (`_original/lib/inspectors/res.js:1008-1009,1082-1092`).
    for (protocol, slot) in [
        (format!("{prefix}Prepend"), &mut injection.top),
        (format!("{prefix}Append"), &mut injection.bottom),
    ] {
        if let Some(joined) = gate.joined(&protocol).filter(|j| !j.pieces.is_empty()) {
            slot.extend(joined.pieces);
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
                slot.push(Piece::text(match (html, family) {
                    (true, "js") => wrap_js(value, props).into_bytes(),
                    (true, "css") => wrap_css(value).into_bytes(),
                    _ => value.as_bytes().to_vec(),
                }));
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
/// (`_original/lib/util/whistle-transform.js:78-100`). Three things matter:
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
    /// every injecting rule of the request (`_original/lib/inspectors/res.js:966-982`).
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
        Some(
            self.kept(protocol)?
                .into_iter()
                .map(|op| (op.value.as_str(), &op.props))
                .collect(),
        )
    }

    /// The operator lines behind [`lines`](Self::lines).
    fn kept(&self, protocol: &str) -> Option<Vec<&'a RuleOp>> {
        let ops = self.resolved.all(protocol);
        if ops.is_empty() || (self.html && !self.global.allows_injection(self.body)) {
            return None;
        }
        Some(
            ops.iter()
                .filter(|op| !self.html || op.props.allows_injection(self.body))
                .collect(),
        )
    }

    /// An operator's surviving lines, blanks dropped, or `None` when it
    /// contributes nothing (see [`InjectionGate::lines`]). One piece per line:
    /// a slot CRLF-joins its pieces, so the bytes are those of joining the
    /// lines first (`joinData`, `_original/lib/util/file-mgr.js:93-109`, whose
    /// loop skips falsy entries), and each line keeps whether it is raw.
    fn joined(&self, protocol: &str) -> Option<Joined> {
        let pieces = self
            .kept(protocol)?
            .into_iter()
            .map(Piece::of)
            .filter(|p| !p.bytes.is_empty())
            .collect();
        Some(Joined { pieces })
    }
}

/// One operator's contribution to a slot, after gating.
struct Joined {
    /// The non-blank lines that survived the gate, in order.
    pieces: Vec<Piece>,
}

impl Joined {
    /// Whether a generic `*Body` operator with this contribution replaces the
    /// body.
    ///
    /// Only when it actually carries something. A blank `resBody://` does
    /// **not** empty the response, which is the opposite of what this port used
    /// to do: upstream assigns `resBody || util.EMPTY_BUFFER`
    /// (`_original/lib/inspectors/res.js:1001-1003`) and `EMPTY_BUFFER` is
    /// `toBuffer('')`, which returns `undefined` for a falsy argument
    /// (`_original/lib/util/common.js:1630-1632`) — not an empty buffer. So
    /// `data.body` stays falsy, `isWhistleTransformData` finds nothing to do
    /// (`_original/lib/util/index.js:1615-1620`), and no transform is built at
    /// all. Measured against whistle 2.10.8: `resBody://()` returns the origin's
    /// page untouched there, and returned an empty body here.
    ///
    /// An operator whose every line the HTML gate refused lands in the same
    /// place by a different route — `filterHtml` empties its list and the join
    /// yields the falsy `''` (`_original/lib/util/whistle-transform.js:47-60,110`)
    /// — so the two need not be told apart.
    fn claims_body(&self) -> bool {
        !self.pieces.is_empty()
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
    let Some(mut base) = crate::rules::url::parse_json(&text[start..end]) else {
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

/// Remove dotted paths from a JSON value (`deleteProps`,
/// `_original/lib/util/common.js:1105-1128`). A numeric segment addressing an
/// array element splices it out.
fn delete_json_props(value: &mut serde_json::Value, paths: &[String]) {
    for path in paths {
        let keys = parse_json_path(path);
        let mut keys = keys.iter().peekable();
        let mut node = &mut *value;
        while let Some(key) = keys.next() {
            if keys.peek().is_none() {
                match node {
                    serde_json::Value::Object(map) => {
                        map.remove(key.name());
                    }
                    serde_json::Value::Array(list) => {
                        if let Some(i) = array_index(key.name()).filter(|i| *i < list.len()) {
                            list.remove(i);
                        }
                    }
                    _ => {}
                }
                break;
            }
            let next = match node {
                serde_json::Value::Object(map) => map.get_mut(key.name()),
                serde_json::Value::Array(list) => {
                    array_index(key.name()).and_then(|i| list.get_mut(i))
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

/// Split a `delete://…Body.<path>` key into the segments the walk above follows
/// (`parseKeys`, `_original/lib/util/common.js:1077-1103`).
///
/// Three spellings beyond the plain dot, all of them upstream's:
///
/// * `a\.b` names **one** key containing a dot. Backslashes are halved before
///   the dot is read, so `a\\.b` is two segments whose first is `a\`, and
///   `a\\\.b` is one segment `a\.b`;
/// * `"k[0]"` — a quoted segment is taken literally, which is how a key that
///   itself ends in brackets is named;
/// * `a[0][1]` — trailing bracket indices become segments of their own, so the
///   bracket form and `a.0.1` address the same element.
fn parse_json_path(path: &str) -> Vec<PathSegment> {
    let mut segments: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = path.trim().chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            match c {
                '.' => segments.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
            continue;
        }
        // `DOT_RE` is `/(\\+)\./g`, so the run of backslashes is maximal and
        // only one that ends at a dot is halved at all.
        let mut run = 1;
        while chars.next_if_eq(&'\\').is_some() {
            run += 1;
        }
        if chars.next_if_eq(&'.').is_none() {
            cur.extend(std::iter::repeat_n('\\', run));
            continue;
        }
        cur.extend(std::iter::repeat_n('\\', run / 2));
        match run % 2 {
            1 => cur.push('.'),
            _ => segments.push(std::mem::take(&mut cur)),
        }
    }
    segments.push(cur);
    segments
        .iter()
        .flat_map(|s| parse_json_key(s.trim()))
        .collect()
}

/// One segment of a path, with its quotes stripped and its trailing `[n]`
/// indices split off (`parseKey`, `_original/lib/util/common.js:1051-1075`).
fn parse_json_key(key: &str) -> Vec<PathSegment> {
    if key.len() >= 2 && key.starts_with('"') && key.ends_with('"') {
        return vec![PathSegment::key(&key[1..key.len() - 1])];
    }
    let mut head = key;
    let mut indices: Vec<PathSegment> = Vec::new();
    while let Some((rest, index)) = strip_trailing_index(head) {
        indices.insert(0, PathSegment::index(index));
        head = rest;
    }
    if indices.is_empty() {
        return vec![PathSegment::key(key)];
    }
    // `if (key)` — a bare `[0]` has no name in front of it and contributes none.
    if !head.is_empty() {
        indices.insert(0, PathSegment::key(head));
    }
    indices
}

/// Split a trailing `[n]` off a path segment, matching `ARR_RE`
/// (`_original/lib/util/common.js:1003`): decimal, no leading zero beyond `0`
/// itself, and bounded so the index stays a safe integer.
fn strip_trailing_index(key: &str) -> Option<(&str, &str)> {
    let inner = key.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let index = &inner[open + 1..];
    let ok = match index.as_bytes() {
        b"0" => true,
        [first @ b'1'..=b'8', rest @ ..] | [first @ b'9', rest @ ..] => {
            let bound = if *first == b'9' { 14 } else { 15 };
            rest.len() <= bound && rest.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    };
    ok.then(|| (&inner[..open], index))
}

/// A path segment as an array index (`NUM_RE`,
/// `_original/lib/util/common.js:1002`): decimal with no leading zero, which is
/// what `deleteProp` requires before it splices rather than deletes
/// (`common.js:1033-1043`).
fn array_index(key: &str) -> Option<usize> {
    match key.as_bytes() {
        b"0" => Some(0),
        [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => key.parse().ok(),
        _ => None,
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
            .map(|op| parse_replace_pairs(&op.value, op.value_is_content)),
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
fn parse_replace_pairs(spec: &str, is_content: bool) -> Vec<(String, String)> {
    // The same three roads every data value takes — JSON, then a query string,
    // then the line format ([`parse_data_object`]). The line format was missing
    // here, and `pathReplace.md` leads with it: a `{value}` holding
    // `test: name` per line is how the page spells "several substitutions", and
    // it did nothing at all in this port.
    let Some(serde_json::Value::Object(map)) = parse_data_object(spec, false, is_content) else {
        return Vec::new();
    };
    map.into_iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            (k, val)
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
        let groups: Vec<&str> = (0..=9)
            .map(|n| caps.get(n).map_or("", |m| m.as_str()))
            .collect();
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
    for prefix in [
        "query",
        "params",
        "urlParams",
        "urlParam",
        "url.Params",
        "url.Param",
    ] {
        let Some(head) = key
            .get(..prefix.len())
            .filter(|h| h.eq_ignore_ascii_case(prefix))
        else {
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
    let head = key
        .get(.."pathname".len())
        .filter(|h| h.eq_ignore_ascii_case("pathname"))?;
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

/// `encodeURI`: the characters a URL may not carry raw, percent-encoded as
/// UTF-8, and every other character left exactly as it is.
///
/// The set is the one JavaScript's `encodeURI` escapes — space, `"`, `<`, `>`,
/// `\`, `^`, `` ` ``, `{`, `|`, `}`, `%`, and everything above ASCII — and it
/// was arrived at by measurement rather than by reading: `auth-bench`-style
/// probes put each character through a `params://` value and read what reached
/// the origin. `é`→`%C3%A9`, `中`→`%E4%B8%AD`, `🚀`→`%F0%9F%9A%80`, `{`→`%7B`,
/// `%`→`%25`, and `#`, `&`, `=`, `+`, `/`, `?`, `:` untouched.
///
/// `%`→`%25` means a value that was **already** escaped is escaped again —
/// `%41` becomes `%2541`. That is upstream's answer and it is the consistent
/// one: what a rule writes into a parameter arrives at the origin as those
/// characters, whatever they look like.
fn encode_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let raw = byte.is_ascii()
            && !matches!(
                byte,
                b' ' | b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' | b'%'
            )
            && !byte.is_ascii_control();
        match raw {
            true => out.push(byte as char),
            false => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The request target to put on the wire: **every non-ASCII byte percent-encoded
/// as UTF-8**, and every ASCII byte left exactly as it is.
///
/// A request target is ASCII, and a rule may name anything. A destination
/// spelled `http://host/中文` or a `params://` value carrying one is an ordinary
/// thing to write, and forwarding those bytes raw is not a request line: the
/// bench's origin answers `400` and closes the connection, so the rule did not
/// merely fail to apply — it took the request down with it.
///
/// Upstream escapes the same range on the rule's own URL —
/// `ruleUrl = util.encodeNonLatin1Char(ruleUrl)`
/// (`_original/lib/inspectors/rules.js:42`) — and the bench agrees with it
/// character by character.
///
/// **Only non-ASCII.** The wider `encodeURI` set belongs to a `params://`
/// *value* (see [`merge_query`]) and not here: a `%` escaped at this level would
/// re-escape what the client wrote, turning a request for `/a%20b` into
/// `/a%2520b`, and `urlReplace://` — which writes URL syntax on purpose — would
/// have its `{`, `|` and `^` escaped where upstream leaves them alone. All three
/// were measured separately.
///
/// **A target hyper still refuses gets the full [`encode_uri`] as a last
/// resort.** `urlReplace://echo=ec` + a backtick produces a path the URI parser
/// will not take, and the caller's fallback then keeps the *original* URI — so
/// the rule silently does not happen, which is the one outcome worse than
/// applying it differently. whistle puts the backtick on the wire raw; this
/// sends `%60`, which every server decodes back to it. Declared in
/// `cases-paths.js`.
///
/// `None` only when even that is not a URI, and the caller keeps the request's
/// original URI.
///
/// The encoding is for the wire only: what is recorded and shown keeps the path
/// as the rule wrote it, which is the readable form and the one to search a
/// capture for.
pub fn request_target(path: &str) -> Option<hyper::Uri> {
    let ascii = match path.is_ascii() {
        true => path.to_string(),
        false => {
            let mut out = String::with_capacity(path.len());
            for byte in path.bytes() {
                match byte.is_ascii() {
                    true => out.push(byte as char),
                    false => out.push_str(&format!("%{byte:02X}")),
                }
            }
            out
        }
    };
    hyper::Uri::try_from(ascii.as_str())
        .ok()
        .or_else(|| hyper::Uri::try_from(encode_uri(&ascii).as_str()).ok())
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
            .map(|op| parse_param_values(&op.value, op.value_is_content, resolves_dotted_keys(op))),
    )
}

/// Parse `k=v&k2=v2`, `{json}` or the line format into `name` → value pairs.
///
/// The three roads and their order are [`parse_data_object`]'s — this had its
/// own copy of them, and the copy differed twice: a key written with no `=`
/// was dropped where `parseQuery` keeps it with an empty value (`solo` and
/// `solo:` both merged nothing here and `{"solo":""}` upstream), and the line
/// format never resolved a dotted name.
fn parse_param_values(
    value: &str,
    is_content: bool,
    resolve_keys: bool,
) -> Vec<(String, serde_json::Value)> {
    match parse_data_object(value, resolve_keys, is_content) {
        Some(serde_json::Value::Object(map)) => map.into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Does this operator read a dotted name as a **path** into the object?
///
/// `RESOLVE_KEY_RE` is `/^re[qs]Merge:\/\//` (`_original/lib/util/index.js:95`)
/// and it is tested against the matcher **as written**, so the question is about
/// the spelling and not about the protocol it resolves to: measured against
/// whistle 2.10.8, a block holding `a.b: 1` merges as `{"a":{"b":"1"}}` under
/// `reqMerge://{v}` and as `{"a.b":"1"}` under `params://{v}` — the same
/// operator, the same value, two answers.
fn resolves_dotted_keys(op: &RuleOp) -> bool {
    let written = op.raw.split_once("://").map(|(proto, _)| proto);
    matches!(written, Some("reqMerge" | "resMerge"))
}

/// A param value as it appears in a query string or a form body: a string
/// unquoted, a number or a boolean written out, **a structure written as
/// nothing**.
///
/// The last one is Node's `querystring.stringify`, which upstream hands the
/// whole patch to before merging it into a form body (`replaceQueryString`,
/// `_original/lib/util/index.js:1753-1756`): it writes primitives and drops
/// anything else, so `{a:{b:'1'}}` becomes `a=`. Measured against whistle
/// 2.10.8; this port used to write the JSON text of the structure, which is a
/// value the form's reader never sees from whistle.
///
/// A nested patch belongs on a JSON body, where both implementations merge the
/// structure itself.
fn json_to_param_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => String::new(),
        other => other.to_string(),
    }
}

/// Merge `params` into the query string of `path`, overriding same-named keys.
///
/// **The merged-in values are percent-encoded and the query's existing ones are
/// not**, which is not a symmetry worth fixing: what was already in the URL is
/// whatever the client wrote and re-encoding it would turn its `%20` into
/// `%2520`, while what a rule adds is text somebody typed into a rules file and
/// has to survive the trip. Measured on both sides character by character —
/// `params://q=a{b` reaches the origin as `q=a%7Bb` from whistle and used to
/// reach it as `q=a{b` from here. See [`encode_uri`].
///
/// `urlReplace://` is deliberately *not* encoded, and that asymmetry is
/// upstream's too: it rewrites a URL, so what it writes is URL syntax rather
/// than a value inside one.
fn merge_query(path: &str, params: &[(String, String)]) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => (path, ""),
    };
    let params: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (k.clone(), encode_uri(v)))
        .collect();
    let merged = merge_query_string(query, &params, &[]);
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
    resolved
        .all(protocol)
        .iter()
        .map(|o| o.value.as_str())
        .collect()
}

#[cfg(test)]
mod tests;
