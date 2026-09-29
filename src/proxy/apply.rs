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
mod body_ops;
mod cache;
mod content_types;
mod cookies;
mod cors;
mod deletes;
mod files;
mod header_ops;
mod local;
mod op_data;
mod pacing;
mod path_query;
mod req_ops;
mod res_ops;
mod trailers;
mod value_sources;
mod writes;

pub use body_ops::*;
use cache::*;
use content_types::*;
use cookies::*;
use cors::*;
use deletes::*;
pub use files::*;
pub use header_ops::*;
pub use local::*;
use op_data::*;
pub use pacing::*;
pub use path_query::*;
pub use req_ops::*;
pub use res_ops::*;
pub use trailers::*;
pub use value_sources::*;
pub use writes::*;

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

// ---------------------------------------------------------------------------
// Operator values read from a file or a URL (`readRuleValue`)
// ---------------------------------------------------------------------------

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
