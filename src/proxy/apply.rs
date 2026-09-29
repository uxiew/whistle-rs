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
mod flags;
mod header_ops;
mod local;
mod op_data;
mod pacing;
mod path_query;
mod req_ops;
mod res_ops;
mod route;
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
pub use flags::*;
pub use header_ops::*;
pub use local::*;
use op_data::*;
pub use pacing::*;
pub use path_query::*;
pub use req_ops::*;
pub use res_ops::*;
pub use route::*;
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
