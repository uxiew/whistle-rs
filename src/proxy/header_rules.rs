//! Rules a request brings with it, in its own headers.
//!
//! whistle reads five headers off an arriving request and parses their contents
//! as a rules text scoped to that one request — `initHeaderRules`
//! (`_original/lib/rules/index.js:576-638`). It is how one proxy serves many
//! environments: each request names its own, and nothing is stored.
//!
//! **The headers are removed either way.** `getValue` (`:558-570`) deletes
//! before it decides whether to return, so a rules text a client wrote never
//! reaches the origin — and would not be honoured by a whistle further up the
//! chain — whatever mode this proxy is in. That half this port has always done;
//! [`take`] is where it lives now, and the reading below is what was added.
//!
//! **Whether they are read is a mode, and the default is no.** See
//! [`crate::config::HeaderRules`] for the three settings and for why a proxy
//! that honoured these by default would be one any client on the network could
//! redirect.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::HeaderRules;
use crate::rules::{ReqInfo, Resolved, RuleManager};

/// The rules text itself.
pub const RULES_HEADER: &str = "x-whistle-rule-value";
/// One more line, appended to it.
pub const HOST_HEADER: &str = "x-whistle-rule-host";
/// The name of a values entry, whose content is prepended.
pub const KEY_HEADER: &str = "x-whistle-rule-key";
/// The name of a rule group, whose text is appended. `multiEnv` only.
pub const NAME_HEADER: &str = "x-whistle-rule-name";
/// A JSON object of values private to the composed text.
pub const KV_HEADER: &str = "x-whistle-key-value";

/// The file name the composed text belongs to, which is what makes the values
/// in [`KV_HEADER`] private to it — upstream's `var file = 'Header Rules'`
/// (`_original/lib/rules/index.js:621`), passed to both `toPrivateValues` and
/// the manager it builds.
pub const FILE: &str = "Header Rules";

/// The four headers removed from **every** request, whatever the mode.
///
/// [`NAME_HEADER`] is deliberately not here: `getValue` is what deletes, and it
/// is never called for that one outside `multiEnv`
/// (`config.multiEnv && util.trimStr(getValue(req, NAME_HEADER))`,
/// `rules/index.js:586` — the `&&` short-circuits). Measured against whistle
/// 2.10.8, which strips the four and forwards the fifth to the origin.
pub const ALWAYS_TAKEN: [&str; 4] = [RULES_HEADER, HOST_HEADER, KEY_HEADER, KV_HEADER];

/// What one request's headers carried, already percent-decoded.
///
/// Absent fields are `None` rather than empty: upstream distinguishes them
/// through `isString`/`trimStr`, and an empty `x-whistle-rule-key` must not
/// send a lookup for the empty name into the values store.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Carried {
    /// [`RULES_HEADER`].
    pub rules: Option<String>,
    /// [`HOST_HEADER`], trimmed.
    pub host: Option<String>,
    /// [`KEY_HEADER`], trimmed.
    pub key: Option<String>,
    /// [`NAME_HEADER`], trimmed. Only ever set under
    /// [`HeaderRules::Request`](crate::config::HeaderRules::Request).
    pub name: Option<String>,
    /// [`KV_HEADER`], raw JSON.
    pub kv: Option<String>,
}

impl Carried {
    /// Did the request carry anything at all?
    pub fn is_empty(&self) -> bool {
        self == &Carried::default()
    }
}

/// Take the rules-carrying headers off a request, returning what they said.
///
/// The removal is unconditional and the *reading* is the mode's: under
/// [`HeaderRules::Off`] this still strips the four and returns nothing, which
/// is exactly what upstream does with `config.strict` set.
///
/// `multi_env` is asked separately from `mode` because the fifth header is
/// taken whenever `-M multiEnv` was named — that is the only condition under
/// which upstream calls `getValue` for it, and `strict` suppresses what the
/// call *returns* rather than the call. See
/// [`crate::config::Config::multi_env`].
pub fn take(headers: &mut hyper::HeaderMap, mode: HeaderRules, multi_env: bool) -> Carried {
    let mut out = Carried::default();
    // A header whose value is not valid UTF-8 is dropped rather than lossily
    // repaired: whistle reads `req.headers[key]`, which Node has already
    // decoded as latin1, and a rules text is not a place to guess. It is still
    // *removed*, which is the half that matters for what reaches the origin.
    let mut grab = |name: &str| -> Option<String> {
        let raw = headers.remove(name)?;
        if !mode.reads_headers() {
            return None;
        }
        let text = raw.to_str().ok()?;
        // `isString(str)` is `str && typeof str === 'string'`, so an empty
        // header is not a value — the same rule the frame separator follows.
        if text.is_empty() {
            return None;
        }
        Some(decode_uri_component(text))
    };
    out.rules = grab(RULES_HEADER);
    out.host = grab(HOST_HEADER).and_then(trimmed);
    out.key = grab(KEY_HEADER).and_then(trimmed);
    out.kv = grab(KV_HEADER);
    // `config.multiEnv && ... getValue(req, NAME_HEADER)`: outside that mode the
    // call never happens, so the header is neither read nor removed. Inside it
    // the call happens whatever `strict` says — and the delete is inside the
    // call — so `-M strict|multiEnv` consumes the header and returns nothing.
    if multi_env {
        out.name = grab(NAME_HEADER).and_then(trimmed);
    }
    out
}

/// `util.trimStr`: trim, and treat what is left of an all-space value as absent.
fn trimmed(s: String) -> Option<String> {
    let t = s.trim();
    match t.is_empty() {
        true => None,
        false => Some(t.to_string()),
    }
}

/// `decodeURIComponent`, including the part where it throws.
///
/// Upstream wraps the call in `try { return value && decodeURIComponent(value) }
/// catch (e) {}` and then returns the **raw** value (`rules/index.js:566-569`),
/// so a malformed escape does not mangle the text — it leaves it alone. The
/// general percent-decoder in [`crate::proxy::template`] repairs per-escape
/// instead, which is right for a query string and wrong here: a rules text that
/// decoded halfway is a different rules text.
fn decode_uri_component(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // Fewer than two hex digits after a `%` is a `URIError` too, which the
        // `zip` below reports as `None`.
        match bytes.get(i + 1).copied().and_then(hex).zip(bytes.get(i + 2).copied().and_then(hex)) {
            Some((hi, lo)) => {
                out.push((hi << 4) | lo);
                i += 3;
            }
            None => return s.to_string(),
        }
    }
    // Malformed UTF-8 is a `URIError` too, and the raw text is what survives it.
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Put the five headers together into one rules text — `initHeaderRules`'s
/// composition (`_original/lib/rules/index.js:591-607`), in its order:
///
/// ```text
/// values[key]            <- prepended, and only if the store knows the name
/// x-whistle-rule-value
/// x-whistle-rule-host    <- appended
/// groups[name]           <- appended, multiEnv only
/// ```
///
/// `lookup_value` and `lookup_group` are the two stores, passed in so this
/// function is a pure composition and can be tested as one. Both are asked for
/// a *stored text*: upstream reads `values.get(keyHeader)` and
/// `globalRules.get(nameHeader)`, neither of which resolves anything.
///
/// Returns `None` when nothing composed to a non-empty text, which is the case
/// upstream's `if (ruleValue)` guards: no manager is built and no merge happens.
pub fn compose(
    carried: &Carried,
    lookup_value: impl FnOnce(&str) -> Option<String>,
    lookup_group: impl FnOnce(&str) -> Option<String>,
) -> Option<String> {
    let mut text = carried
        .rules
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if let Some(host) = &carried.host {
        text.push('\n');
        text.push_str(host);
    }
    // Only a name the store answers contributes anything; an unknown one is
    // silently nothing, because `trimStr(values.get(key))` is falsy.
    if let Some(found) = carried.key.as_deref().and_then(lookup_value).and_then(trimmed) {
        text = format!("{found}\n{text}");
    }
    if let Some(found) = carried.name.as_deref().and_then(lookup_group).and_then(trimmed) {
        text.push('\n');
        text.push_str(&found);
    }
    match text.trim().is_empty() {
        true => None,
        false => Some(text),
    }
}

/// The values in [`KV_HEADER`], filed under the private key so that only the
/// composed text can read them — upstream's
/// `util.toPrivateValues(util.parseJSON(kvHeader), file)` (`:622`), which is
/// this port's [`crate::rules::inline_key`] by another name.
///
/// A body that is not a JSON object is nothing: `parseJSON` returns `undefined`
/// on a parse error and `toPrivateValues` passes it straight back. Values that
/// are not strings are rendered the way a rules text would read them, which is
/// what `String(v)` amounts to in the lookup that follows.
pub fn private_values(kv: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(text) = kv else { return out };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    for (name, value) in map {
        let rendered = match value {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };
        out.insert(crate::rules::inline_key(&name, FILE), rendered);
    }
    out
}

/// Resolve a composed text against one request and fold it into `resolved`,
/// with the precedence the mode asks for.
///
/// Upstream's `initRules` (`rules/index.js:643-657`) is two lines, and the
/// difference between the modes is which of them runs:
///
/// ```js
/// if (config.multiEnv || req._headerRulesFirst) {
///   req.rules = resolveReqRules(req);                          // the stored rules
///   util.mergeRules(req, req.headerRulesMgr.resolveReqRules(req));  // the request's win
/// } else {
///   req.rules = req.headerRulesMgr.resolveReqRules(req);
///   util.mergeRules(req, resolveReqRules(req));                // the stored ones win
/// }
/// ```
///
/// `mergeRules`'s second argument is the winner — `mergeRule` puts
/// `newRule.list` in front (`_original/lib/util/index.js:2170`) — which this
/// port already spells [`crate::proxy::apply::merge_resolved`], important lines
/// and all. So the port is the same swap.
///
/// The manager is **returned, not dropped**: the response phase resolves it a
/// second time, exactly as upstream re-resolves `hRules` there
/// (`_original/lib/plugins/index.js:1326-1335`).
#[must_use = "the caller must keep this for the response phase"]
pub fn merge(
    resolved: &mut Resolved,
    info: &ReqInfo,
    text: &str,
    mode: HeaderRules,
    is_internal_req: bool,
) -> RuleManager {
    let mut mgr = RuleManager::new();
    mgr.set_text(text);
    // The composed text is a rules file of its own, under the name the private
    // values were filed against — which is what lets a `{name}` in it reach the
    // JSON the request carried and nothing else. See [`RuleManager::adopt_group`].
    mgr.adopt_group(Some(Arc::from(FILE)));
    let from_header = mgr.resolve_scoped(info, is_internal_req);
    if mode.beats_stored_rules() {
        crate::proxy::apply::merge_resolved(resolved, from_header);
    } else {
        let mut base = from_header;
        crate::proxy::apply::merge_resolved(&mut base, std::mem::take(resolved));
        *resolved = base;
    }
    mgr
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    /// The half that was already true, and stays true: whatever the mode, a
    /// rules text a client wrote does not reach the origin.
    #[test]
    fn the_four_are_taken_even_when_nothing_reads_them() {
        let mut h = headers(&[
            (RULES_HEADER, "a"),
            (HOST_HEADER, "b"),
            (KEY_HEADER, "c"),
            (KV_HEADER, "{}"),
            ("x-other", "kept"),
        ]);
        let got = take(&mut h, HeaderRules::Off, false);
        assert!(got.is_empty(), "nothing is read: {got:?}");
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-other"));
    }

    /// `x-whistle-rule-name` is the one upstream forwards, because the function
    /// that deletes is the one it never calls outside `multiEnv`.
    #[test]
    fn the_name_header_survives_every_mode_but_one() {
        for mode in [HeaderRules::Off, HeaderRules::Console] {
            let mut h = headers(&[(NAME_HEADER, "staging")]);
            let got = take(&mut h, mode, false);
            assert_eq!(got.name, None, "{mode:?}");
            assert!(h.contains_key(NAME_HEADER), "{mode:?} must forward it");
        }
        let mut h = headers(&[(NAME_HEADER, "staging")]);
        let got = take(&mut h, HeaderRules::Request, true);
        assert_eq!(got.name.as_deref(), Some("staging"));
        assert!(!h.contains_key(NAME_HEADER));
    }

    /// `-M strict|multiEnv`: the call that deletes still runs, and the value it
    /// would have returned is what `strict` takes away. Found by
    /// `tests/differential/header-rules-bench.js` when this was one flag —
    /// upstream consumed the header and this port forwarded it.
    #[test]
    fn strict_takes_the_reading_and_leaves_the_delete() {
        let mut h = headers(&[(NAME_HEADER, "staging"), (RULES_HEADER, "r")]);
        let got = take(&mut h, HeaderRules::Off, true);
        assert!(got.is_empty(), "nothing is read: {got:?}");
        assert!(h.is_empty(), "everything is still taken: {h:?}");
    }

    #[test]
    fn values_arrive_percent_decoded() {
        let mut h = headers(&[(RULES_HEADER, "example.com%20file%3A%2F%2F%2Ftmp%2Fx")]);
        let got = take(&mut h, HeaderRules::Console, false);
        assert_eq!(got.rules.as_deref(), Some("example.com file:///tmp/x"));
    }

    /// A rules text that is not percent-encoded at all is not mangled, which is
    /// what makes both spellings work — measured, upstream honours either.
    #[test]
    fn a_raw_rules_text_survives_the_decoder() {
        let mut h = headers(&[(RULES_HEADER, "example.com resHeaders://x-a=1")]);
        let got = take(&mut h, HeaderRules::Console, false);
        assert_eq!(got.rules.as_deref(), Some("example.com resHeaders://x-a=1"));
    }

    /// `decodeURIComponent` throws for these, and the raw text is what upstream
    /// keeps. A per-escape repair would hand the parser a different rules text.
    #[test]
    fn a_malformed_escape_leaves_the_text_alone() {
        for raw in ["a%zz", "100%", "%E4%00%A0", "%"] {
            assert_eq!(decode_uri_component(raw), raw, "{raw}");
        }
        assert_eq!(decode_uri_component("%E4%B8%AD"), "中");
    }

    #[test]
    fn composition_is_in_upstreams_order() {
        let carried = Carried {
            rules: Some("  R  ".into()),
            host: Some("H".into()),
            key: Some("k".into()),
            name: Some("n".into()),
            kv: None,
        };
        let text = compose(
            &carried,
            |k| (k == "k").then(|| "K".to_string()),
            |n| (n == "n").then(|| "N".to_string()),
        );
        assert_eq!(text.as_deref(), Some("K\nR\nH\nN"));
    }

    /// A name neither store answers contributes nothing rather than an empty
    /// line — `trimStr(values.get(key))` being falsy is what upstream tests.
    #[test]
    fn an_unknown_name_contributes_nothing() {
        let carried = Carried {
            rules: Some("R".into()),
            key: Some("nope".into()),
            name: Some("nope".into()),
            ..Carried::default()
        };
        assert_eq!(
            compose(&carried, |_| None, |_| Some("   ".into())).as_deref(),
            Some("R")
        );
    }

    /// Nothing composed means no manager and no merge — upstream's
    /// `if (ruleValue)`.
    #[test]
    fn nothing_composes_to_nothing() {
        assert_eq!(compose(&Carried::default(), |_| None, |_| None), None);
        let only_key = Carried {
            key: Some("k".into()),
            ..Carried::default()
        };
        assert_eq!(compose(&only_key, |_| None, |_| None), None);
    }

    #[test]
    fn private_values_are_filed_under_the_header_rules_file() {
        let vals = private_values(Some(r#"{"pv":"FROMKV","n":7}"#));
        assert_eq!(
            vals.get(&crate::rules::inline_key("pv", FILE)).map(String::as_str),
            Some("FROMKV")
        );
        assert_eq!(
            vals.get(&crate::rules::inline_key("n", FILE)).map(String::as_str),
            Some("7")
        );
        // Not under the plain name: a request may not overwrite the store.
        assert!(!vals.contains_key("pv"));
    }

    #[test]
    fn a_kv_header_that_is_not_an_object_is_nothing() {
        for text in ["[1,2]", "not json", "\"s\"", "null"] {
            assert!(private_values(Some(text)).is_empty(), "{text}");
        }
    }
}
