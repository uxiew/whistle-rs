//! Rules that arrive after resolution and are folded into it: a plugin's
//! rules text, `rule://` and `rulesFile://` includes, `resRules://` and
//! `resScript://`, and the response phase that resolves them a second time
//! once the response head is in.

use super::*;

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
pub(super) const MERGED_ORDER: u64 = 0;

/// The order stamped on a merged operator that is *not* important: below every
/// normal operator's key and above every important one's, which is where
/// upstream's stable important-first partition leaves it.
pub(super) const MERGED_AFTER_IMPORTANT: u64 = 1 << 32;

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
pub(super) const PRODUCED_SCOPE: &str = "\u{1}rulesFile";

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
pub(super) fn script_text(op: &RuleOp) -> Option<String> {
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
pub(super) fn accumulated_script_ops<'a>(
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
