//! Substitution in operator values before they are applied: backtick templates,
//! `{name}` references to the Values store (and `--value` overriding them),
//! regexp captures `$1`…, and `${…}` config variables.

use super::*;

/// The request facts a backtick operator value renders against — see
/// [`render_backticks`]. Copied rather than borrowed so it can ride along
/// beside the `&mut Resolved` these functions take.
#[derive(Clone, Copy)]
pub struct TplCtx<'a> {
    pub info: &'a ReqInfo,
    pub env: super::super::template::ProxyEnv<'a>,
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
pub(super) fn render_backticks(op: &crate::rules::RuleOp, tpl: TplCtx<'_>) -> Option<String> {
    if op.protocol == "log" || op.protocol == "weinre" {
        return None;
    }
    let (prefix, rest) = crate::rules::url::tpl_prefix(&op.value);
    // A lone backtick is not a pair: `strip_suffix` on the empty remainder says
    // so, which is upstream's `(`.*`)` needing two characters.
    let inner = rest.strip_prefix('`').and_then(|r| r.strip_suffix('`'))?;
    Some(format!(
        "{prefix}{}",
        super::super::template::render_vars(inner, tpl.info, tpl.env)
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
                (true, Some(groups)) => super::super::template::render_vars(
                    &substitute_regexp_vars(content, groups),
                    tpl.info,
                    tpl.env,
                ),
                (true, None) => super::super::template::render_vars(content, tpl.info, tpl.env),
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
                    true => super::super::template::render_vars(&expand(stored), tpl.info, tpl.env),
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
            && let Some((super::super::super::rules::url::Fixed::Inline, inner)) =
                super::super::super::rules::url::fixed_value(&op.value)
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
pub(super) fn waits_for_the_response(op: &crate::rules::RuleOp, tpl: TplCtx<'_>) -> bool {
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
pub(super) fn substitute_regexp_vars(text: &str, groups: &[String]) -> String {
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
pub(super) fn substitute_braced(text: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
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
pub(super) fn replace_ci(haystack: &str, needle: &str, repl: &str) -> String {
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
