//! whistle rules engine (parse + match + resolve).
//!
//! Ported from `_original/lib/rules/`. The original is ~9k lines with an
//! enormous surface of edge cases; this port implements the load-bearing core:
//!
//! * line parsing: `pattern op1 op2 …` (comments, blank lines, shorthands)
//! * pattern kinds: regexp (`/re/i`), wildcard (`*`), and scheme/host/path
//!   prefix matching
//! * operator parsing for the full protocol set (see [`protocols`])
//! * per-line properties (`lineProps://…`, see [`LineProps`])
//! * per-request resolution with first-match-wins (and multi-match for the
//!   protocols whistle allows to repeat)
//!
//! What is intentionally simplified vs. the original is documented inline and in
//! the project README.

pub mod matcher;
pub mod protocols;
pub mod storage;

use regex::Regex;
use std::collections::{BTreeSet, HashMap};

/// Every line property whistle's editor offers
/// (`LINE_PROPS_HINTS` in `_original/biz/webui/htdocs/src/js/rules-hint.js:69`),
/// plus the spellings only the runtime knows about. Unknown actions are kept
/// too — whistle never validates them — so this list is documentation, not a
/// filter. See `docs/LINE_PROPS.md` for what each one does and which are wired
/// up in this port.
pub const LINE_PROP_ACTIONS: &[&str] = &[
    "important",
    "safeHtml",
    "strictHtml",
    "disableAutoCors",
    "disableUserLogin",
    "enableUserLogin",
    "internal",
    "internalOnly",
    "internalProxy",
    "proxyFirst",
    "proxyHost",
    "proxyHostOnly",
    "proxyTunnel",
    "weakRule",
    "enableBigData",
    // Undocumented but honoured by the original runtime.
    "disabledAutoCors",
    "originUrl",
];

/// Per-line properties declared with `lineProps://<action>[|&<action>…]`.
///
/// `lineProps` (`resolveMatchFilter` in `_original/lib/rules/rules.js:1552`,
/// `parseLineProps` in `_original/lib/util/index.js:1877`) is the line-scoped
/// counterpart of the global `enable://`/`disable://` switches: the actions
/// listed on a rule line only affect the operators written on *that* line.
/// Every operator of a line therefore carries a copy — see [`RuleOp::props`].
///
/// Actions are stored verbatim, exactly like the original's `{action: true}`
/// map, so spellings this port does not act on still reach consumers that do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineProps {
    actions: BTreeSet<String>,
}

/// Shared empty set, so [`Resolved::props`] can hand out a reference for
/// protocols that never matched.
static NO_PROPS: LineProps = LineProps {
    actions: BTreeSet::new(),
};

impl LineProps {
    /// Merge one `lineProps://` payload. Separators are `|` and `&`
    /// (`SEP_RE = /[|&]/` in the original); empty segments are dropped, so
    /// `lineProps://`, `lineProps://|` and `lineProps://a||b` all behave.
    fn merge(&mut self, spec: &str) {
        for action in spec.split(['|', '&']) {
            if !action.is_empty() {
                self.actions.insert(action.to_string());
            }
        }
    }

    /// Build properties from explicit action names, as if a line had declared
    /// them.
    ///
    /// The proxy layer folds the request-scoped `enable://safeHtml` /
    /// `enable://strictHtml` switches into the same gate as the per-line ones —
    /// upstream stamps them onto every injecting rule of the request
    /// (`_original/lib/inspectors/res.js:970-987`).
    pub fn from_actions<'a>(actions: impl IntoIterator<Item = &'a str>) -> Self {
        let mut props = LineProps::default();
        for action in actions {
            props.merge(action);
        }
        props
    }

    /// Is `action` set on this line?
    pub fn has(&self, action: &str) -> bool {
        self.actions.contains(action)
    }

    /// True when the line declared no properties at all.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// The declared actions, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.actions.iter().map(String::as_str)
    }

    /// `important` — like CSS's `!important`, this line's operators outrank the
    /// same protocol from non-important lines regardless of file position
    /// (`isImportant` in `_original/lib/util/index.js:2141`).
    pub fn important(&self) -> bool {
        self.has("important")
    }

    /// `internal` / `internalOnly` — whether a rule carrying these properties
    /// applies to a request with this origin. `internalOnly` restricts the line
    /// to whistle's own outgoing requests, `internal` widens it to both.
    /// Ported from `checkInternal` (`_original/lib/rules/rules.js:910`).
    pub fn allows_scope(&self, is_internal_req: bool) -> bool {
        if is_internal_req {
            self.has("internal") || self.has("internalOnly")
        } else {
            !self.has("internalOnly")
        }
    }

    /// `safeHtml` / `strictHtml` — should this line's `htmlXxx`/`jsXxx`/`cssXxx`
    /// content be injected into `body`?
    ///
    /// Ported from `WhistleTransform#allowInject` + `filterHtml`
    /// (`_original/lib/util/whistle-transform.js:47`). A body whose first
    /// non-whitespace byte is `<` (or which is blank) is proper markup and
    /// always accepts injection; otherwise `strictHtml` refuses outright and
    /// `safeHtml` refuses only JSON-looking bodies (`{`/`[`). Callers must gate
    /// on the response actually being HTML — non-HTML bodies never reach this.
    pub fn allows_injection(&self, body: &[u8]) -> bool {
        let first = body.iter().find(|b| !b.is_ascii_whitespace());
        match first {
            None | Some(b'<') => true,
            Some(b'{') | Some(b'[') => !self.has("strictHtml") && !self.has("safeHtml"),
            Some(_) => !self.has("strictHtml"),
        }
    }
}

/// One resolved operator on a rule line, e.g. `host://127.0.0.1:8080`.
#[derive(Debug, Clone, Default)]
pub struct RuleOp {
    /// Protocol name (`host`, `resHeaders`, `redirect`, …).
    pub protocol: String,
    /// Value after `protocol://` (or the shorthand's implied value).
    pub value: String,
    /// The original token as written, for diagnostics.
    pub raw: String,
    /// Properties of the line this operator was written on. Copied per operator
    /// so that resolution — which mixes operators from many lines — keeps each
    /// one's line scope.
    pub props: LineProps,
}

/// How a rule's pattern decides whether a request matches.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// `/regexp/flags` — tested against the full request URL.
    Regex(Regex),
    /// Scheme/host/path prefix match (the common whistle case).
    Prefix {
        /// Restrict to this scheme (`http`/`https`/`ws`/…) if present.
        scheme: Option<String>,
        /// Exact host (lowercased). Empty means "any host".
        host: String,
        /// Leading-dot wildcard, e.g. `.example.com` matches subdomains.
        host_suffix: bool,
        /// Explicit port written in the pattern (`example.com:8080`), which
        /// scopes the rule to that port. `None` means "any port".
        port: Option<u16>,
        /// Path prefix (may be empty).
        path: String,
    },
    /// Matches every request (bare operator lines aren't produced here, but
    /// kept for completeness / `*` patterns collapse to this when trivial).
    Any,
}

/// A single parsed rule line.
#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: Pattern,
    pub ops: Vec<RuleOp>,
    pub raw_line: String,
    /// `$`-prefixed exact/important patterns win over normal ones.
    pub important: bool,
    /// `!`-prefixed pattern: the rule applies to every request the pattern does
    /// *not* match (`NON_RE`, `_original/lib/rules/rules.js:19`; the inversion
    /// itself is at `rules.js:994-998`).
    pub negate: bool,
    /// Extra `filter`/`includeFilter`/`excludeFilter` conditions.
    pub filters: Vec<Filter>,
    /// `lineProps://…` declared on this line (also mirrored onto every op).
    pub props: LineProps,
}

impl Rule {
    /// Effective importance: whistle's `lineProps://important`, plus this port's
    /// `$`-prefix shorthand. Important rules are resolved before normal ones,
    /// per protocol — mirroring the original, which splices important rules to
    /// the front of each protocol's rule list (`_original/lib/rules/rules.js:1393`).
    pub fn is_important(&self) -> bool {
        self.important || self.props.important()
    }
}

/// A `filter`/`includeFilter`/`excludeFilter` match condition on a rule.
///
/// Whether a set of filters lets a rule through is decided by
/// [`matcher::filters_match`], which mirrors upstream's `matchExcludeFilters`
/// (`_original/lib/rules/rules.js:1967`): include filters are **or**-ed, and any
/// matching exclude filter vetoes the rule.
#[derive(Debug, Clone)]
pub struct Filter {
    /// `excludeFilter://` negates: the rule is skipped when the condition holds.
    pub exclude: bool,
    /// A `!` written in front of the condition's value (`m:!GET`), in front of a
    /// URL pattern (`includeFilter://!*.cdn.com`), or straight after a header
    /// key (`reqH.x-tag!:v`) inverts the condition
    /// (`_original/lib/rules/rules.js:1565,1652`).
    ///
    /// It only ever inverts a *known* answer — see [`Cond::Deferred`].
    pub negate: bool,
    pub cond: Cond,
}

/// What a [`Filter`] tests.
///
/// Conditions are evaluated to `Option<bool>`: `None` says "the fact this tests
/// is not knowable yet", which upstream's `getFilterResult`
/// (`_original/lib/rules/rules.js:1809`) collapses to `false` *without* applying
/// `not`. Everything therefore fails closed.
#[derive(Debug, Clone)]
pub enum Cond {
    /// `m:GET` / `method:GET` — request method (always case-insensitive).
    Method(CondValue),
    /// `host:example.com` — request host.
    Host(CondValue),
    /// `reqH.<key>:<value>` (and the `h:`/`header:`/`req…` spellings) — a
    /// request header. Upstream tests *containment*, not equality.
    ReqHeader { name: String, value: CondValue },
    /// `clientIp:1.2.3.4` — the client's IP.
    ClientIp(CondValue),
    /// `i:1.2.3.4` / `ip:` — client **or** server IP. The server IP is not known
    /// while rules are resolved, so in practice this tests the client's.
    Ip(CondValue),
    /// `chance:0.25` / `chance:25%` — sample a fraction of requests, upstream's
    /// `Math.random() < probability` (`_original/lib/rules/rules.js:1860-1868`).
    /// A value that is not a number is stored as `NaN`, which never matches —
    /// the same coercion JS performs.
    Chance(f64),
    /// A URL pattern, written exactly like a rule's own pattern (regexp,
    /// wildcard, or scheme/host/path prefix). This is the fallback for anything
    /// that is not a recognised condition name.
    Url(Pattern),
    /// Recognised, but the fact it tests does not exist while rules are being
    /// resolved. Never matches; see [`Deferred`].
    Deferred(Deferred),
}

/// Conditions this port parses but cannot answer at rule-resolution time.
///
/// whistle resolves rules again in the response phase, so upstream can answer
/// these later; this port resolves once, before the request is sent. Rather
/// than let such a condition fall through to the URL-pattern fallback — where
/// it would be a nonsense regexp that quietly matches nothing (or, worse,
/// something) — it is parsed, recorded, and evaluated as "unknown", which makes
/// its filter fail closed. `docs/RULES.md` lists what each one would need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deferred {
    /// `s:` / `statusCode:` — needs the response.
    StatusCode,
    /// `resH.<key>:` / `res:<key>=` — needs the response headers.
    ResHeader,
    /// `serverIp:` — needs the resolved upstream address.
    ServerIp,
    /// `clientPort:` — needs the accepted socket's peer port.
    ClientPort,
    /// `serverPort:` — needs the upstream socket's port.
    ServerPort,
    /// `remoteAddress:` — needs the upstream socket's address.
    RemoteAddress,
    /// `remotePort:` — needs the upstream socket's port.
    RemotePort,
    /// `b:` / `body:` — needs the request body buffered before rules resolve.
    Body,
    /// `env:` — needs the plugin environment store.
    Env,
    /// `from:` — needs the request's origin flags (tunnel, composer, SNI, …).
    From,
}

/// The right-hand side of a filter condition.
///
/// Any condition's value may be written as `/regexp/[i]` instead of a literal:
/// upstream funnels every one of them through `util.toRegExp`
/// (`_original/lib/util/index.js:723`), whose `REG_EXP_RE` is
/// `^/(.+)/(i?u?|ui)$`. A `/…/` that fails to compile degrades to a literal,
/// exactly like `toRegExp` returning `null`.
#[derive(Debug, Clone)]
pub enum CondValue {
    /// `/re/[i]`.
    Regex(Regex),
    /// A literal, lowercased — all literal comparisons are case-insensitive.
    Literal(String),
}

impl CondValue {
    /// Parse a condition's value. `always_ignore_case` mirrors the second
    /// argument of `util.toRegExp`, which whistle passes only for the method
    /// condition (`_original/lib/rules/rules.js:1603`).
    fn parse(raw: &str, always_ignore_case: bool) -> Self {
        Self::as_regex(raw, always_ignore_case)
            .unwrap_or_else(|| CondValue::Literal(raw.to_lowercase()))
    }

    /// `/body/flags` → a compiled regexp, or `None` when this is a literal (or
    /// a regexp Rust's engine cannot compile — JS-only constructs such as
    /// lookbehind degrade to a literal rather than dropping the rule).
    fn as_regex(raw: &str, always_ignore_case: bool) -> Option<Self> {
        let rest = raw.strip_prefix('/')?;
        let end = rest.rfind('/')?;
        let (body, flags) = (&rest[..end], &rest[end + 1..]);
        // `(.+)` — an empty body is not a regexp, and `u` is implied in Rust.
        if body.is_empty() || !matches!(flags, "" | "i" | "u" | "iu" | "ui") {
            return None;
        }
        let src = if always_ignore_case || flags.contains('i') {
            format!("(?i){body}")
        } else {
            body.to_string()
        };
        Regex::new(&src).ok().map(CondValue::Regex)
    }

    /// Scalar comparison (`m:`, `i:`, `host:`): whistle compares the whole
    /// value, so this is equality — case-insensitively, since the literal was
    /// lowercased at parse time.
    pub fn matches(&self, actual: &str) -> bool {
        match self {
            CondValue::Regex(re) => re.is_match(actual),
            CondValue::Literal(lit) => actual.eq_ignore_ascii_case(lit),
        }
    }

    /// Header comparison: upstream's `filterHeader`
    /// (`_original/lib/rules/rules.js:1922-1945`) tests **containment**, not
    /// equality — which is what makes `reqH.content-type:json` match
    /// `application/json`. An empty expected value therefore matches any value,
    /// i.e. it is a presence test.
    ///
    /// Upstream additionally compares against `encodeURIComponent(value)`; that
    /// arm is unreachable, because the haystack is lowercased while
    /// `encodeURIComponent` emits upper-case hex, so it is not ported.
    pub fn matches_header(&self, actual: &str) -> bool {
        match self {
            CondValue::Regex(re) => re.is_match(actual),
            CondValue::Literal(lit) => actual.to_lowercase().contains(lit.as_str()),
        }
    }
}

/// Parsed request facts the matcher needs. Built by the proxy layer.
#[derive(Debug, Clone, Default)]
pub struct ReqInfo {
    pub method: String,
    pub scheme: String,
    /// Lowercased host without port.
    pub host: String,
    pub port: u16,
    /// Path plus query string (starts with `/`).
    pub path: String,
    /// `scheme://host[:port]/path` used for regex/prefix matching.
    pub full_url: String,
    /// Request headers as (lowercased-name, value) pairs, for filter conditions.
    pub headers: Vec<(String, String)>,
    /// Client IP, if known, for `filter://i:` conditions.
    pub client_ip: Option<String>,
}

/// The winning operators for a request, keyed by protocol.
#[derive(Debug, Default, Clone)]
pub struct Resolved {
    /// First-match-wins single-value protocols.
    pub single: HashMap<String, RuleOp>,
    /// Accumulated values for multi-match protocols (top-to-bottom order).
    pub multi: HashMap<String, Vec<RuleOp>>,
}

impl Resolved {
    pub fn get(&self, protocol: &str) -> Option<&RuleOp> {
        self.single.get(protocol)
    }
    pub fn value(&self, protocol: &str) -> Option<&str> {
        self.single.get(protocol).map(|o| o.value.as_str())
    }
    pub fn all(&self, protocol: &str) -> &[RuleOp] {
        self.multi.get(protocol).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Line properties of the winning operator for `protocol` (empty when the
    /// protocol did not match). This is how `lineProps` stays *line*-scoped
    /// after resolution: the original consults `req.rules.<protocol>.lineProps`,
    /// i.e. the properties of the line that won that protocol — never a union
    /// across lines.
    pub fn props(&self, protocol: &str) -> &LineProps {
        self.single
            .get(protocol)
            .map(|o| &o.props)
            .unwrap_or(&NO_PROPS)
    }

    /// Shorthand for `props(protocol).has(action)`.
    pub fn has_prop(&self, protocol: &str, action: &str) -> bool {
        self.props(protocol).has(action)
    }
}

/// A named group of rules that can be individually enabled/disabled.
#[derive(Debug, Clone)]
pub struct RuleGroup {
    /// Display name (e.g. "default", "debug-rules", "staging").
    pub name: String,
    /// Raw source text of this group.
    pub text: String,
    /// Whether this group participates in rule resolution.
    pub enabled: bool,
    /// Parsed rules from `text`.
    rules: Vec<Rule>,
}

impl RuleGroup {
    pub fn new(name: &str, text: &str, enabled: bool) -> Self {
        let rules = parse_text(text);
        RuleGroup {
            name: name.to_string(),
            text: text.to_string(),
            enabled,
            rules,
        }
    }

    /// Re-parse rules from the current text.
    fn reparse(&mut self) {
        self.rules = parse_text(&self.text);
    }

    /// Number of parsed rules in this group.
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Holds rule groups and answers match queries.
#[derive(Debug, Default)]
pub struct RuleManager {
    /// Ordered list of rule groups. Rules from earlier groups take precedence
    /// (first-match-wins across groups, top to bottom).
    groups: Vec<RuleGroup>,
}

impl RuleManager {
    pub fn new() -> Self {
        RuleManager {
            groups: Vec::new(),
        }
    }

    /// Total number of parsed rules across all groups.
    pub fn len(&self) -> usize {
        self.groups.iter().map(|g| g.rules.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|g| g.rules.is_empty())
    }

    /// The current rules source text of the default group (backward compat).
    pub fn text(&self) -> &str {
        self.groups
            .iter()
            .find(|g| g.name == "default")
            .map(|g| g.text.as_str())
            .unwrap_or("")
    }

    /// Replace all rules in the default group (backward compat for UI single-text editor).
    pub fn set_text(&mut self, text: &str) {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == "default") {
            g.text = text.to_string();
            g.reparse();
        } else {
            self.groups
                .insert(0, RuleGroup::new("default", text, true));
        }
    }

    /// Append rules parsed from `text` to the default group.
    pub fn append_text(&mut self, text: &str) {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == "default") {
            if !g.text.is_empty() && !g.text.ends_with('\n') {
                g.text.push('\n');
            }
            g.text.push_str(text);
            g.reparse();
        } else {
            self.groups
                .insert(0, RuleGroup::new("default", text, true));
        }
    }

    /// Resolve the winning operators for a request, considering only enabled
    /// groups. Rules from earlier groups take precedence.
    pub fn resolve(&self, req: &ReqInfo) -> Resolved {
        self.resolve_scoped(req, false)
    }

    /// Like [`resolve`](Self::resolve) for a request whose origin is known, so
    /// that the `internal`/`internalOnly` line properties can be honoured. Pass
    /// `true` for requests whistle itself issues (plugin calls, internal paths).
    pub fn resolve_scoped(&self, req: &ReqInfo, is_internal_req: bool) -> Resolved {
        let all_rules: Vec<&Rule> = self
            .groups
            .iter()
            .filter(|g| g.enabled)
            .flat_map(|g| &g.rules)
            .collect();
        matcher::resolve_refs_scoped(&all_rules, req, is_internal_req)
    }

    // ── Group management API ──

    /// Immutable access to all groups.
    pub fn groups(&self) -> &[RuleGroup] {
        &self.groups
    }

    /// Add a new group (appended at the end). Returns false if name already exists.
    pub fn add_group(&mut self, name: &str, text: &str, enabled: bool) -> bool {
        if self.groups.iter().any(|g| g.name == name) {
            return false;
        }
        self.groups.push(RuleGroup::new(name, text, enabled));
        true
    }

    /// Remove a group by name. Returns true if found and removed.
    pub fn remove_group(&mut self, name: &str) -> bool {
        let before = self.groups.len();
        self.groups.retain(|g| g.name != name);
        self.groups.len() < before
    }

    /// Toggle a group's enabled state. Returns the new state, or None if not found.
    pub fn toggle_group(&mut self, name: &str) -> Option<bool> {
        self.groups.iter_mut().find(|g| g.name == name).map(|g| {
            g.enabled = !g.enabled;
            g.enabled
        })
    }

    /// Update a group's text. Returns false if not found.
    pub fn update_group(&mut self, name: &str, text: &str) -> bool {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == name) {
            g.text = text.to_string();
            g.reparse();
            true
        } else {
            false
        }
    }

    /// Rename a group. Returns false if old name not found or new name already exists.
    pub fn rename_group(&mut self, old_name: &str, new_name: &str) -> bool {
        if self.groups.iter().any(|g| g.name == new_name) {
            return false;
        }
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == old_name) {
            g.name = new_name.to_string();
            true
        } else {
            false
        }
    }
}

/// Strip a `#` comment: the `#` and everything after it, **anywhere** on the
/// line — whistle's `removeComment` (`_original/lib/util/common.js:2043`) is a
/// global `/#[^\r\n]*/g`.
///
/// Deliberately aggressive: upstream also eats a `#` inside a URL fragment, so
/// `example.com/a#b file:///x` loses `#b`. Matched rather than "improved", so a
/// rules file behaves the same in both implementations.
fn remove_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Collapse whistle's multi-line rule blocks into single lines.
///
/// ```text
/// line`
/// proxy://127.0.0.1:8080
/// www.example.com
/// api.example.com
/// `
/// ```
/// becomes `proxy://127.0.0.1:8080 www.example.com api.example.com`
/// (`MULTI_TO_ONE_RE` + `toLine`, `_original/lib/rules/rules.js:21,:369-375`).
///
/// One deviation: upstream's replacement keeps the `` line` `` opener and the
/// closing backtick in the collapsed text, where they survive as extra pattern
/// tokens that can never match. We drop them instead — same effective rules,
/// without the dead entries.
///
/// Comments are stripped *before* this runs, matching `mergeLines`; the other
/// order would change what a `#` inside a block does.
fn merge_lines(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut block: Option<Vec<String>> = None;
    for raw in text.lines() {
        let trimmed = raw.trim();
        match &mut block {
            None => {
                if trimmed == "line`" {
                    block = Some(Vec::new());
                } else {
                    out.push(raw.to_string());
                }
            }
            Some(parts) => {
                if trimmed == "`" {
                    out.push(parts.join(" "));
                    block = None;
                } else if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
            }
        }
    }
    // An unterminated block still yields its rule rather than vanishing.
    if let Some(parts) = block {
        if !parts.is_empty() {
            out.push(parts.join(" "));
        }
    }
    out.join("\n")
}

/// Parse whole rules text into a list of [`Rule`]s.
/// Mirrors `parseText` in `_original/lib/rules/rules.js:1738`.
pub fn parse_text(text: &str) -> Vec<Rule> {
    // Order matters: whistle's `mergeLines` strips comments over the whole text
    // and only then collapses `line`…`` blocks.
    let stripped: String = text
        .lines()
        .map(remove_comment)
        .collect::<Vec<_>>()
        .join("\n");
    let merged = merge_lines(&stripped);

    let mut out = Vec::new();
    for raw_line in merged.lines() {
        let tokens: Vec<&str> = raw_line.split_whitespace().collect();
        if tokens.len() < 2 {
            // A lone token isn't a rule (whistle needs pattern + ≥1 operator).
            continue;
        }
        out.extend(parse_line(&tokens, raw_line));
    }
    out
}

/// Parse one logical rule line into **one rule per pattern**.
///
/// whistle splits a line's tokens into patterns and operators regardless of
/// order, then produces a rule for every (operator set × pattern) pair — which
/// is what makes `host://1.1.1.1 a.com b.com` apply to *both* hosts, and what
/// the multi-line `line`…`` block relies on. Returning a single rule silently
/// dropped every pattern after the first.
fn parse_line(tokens: &[&str], raw_line: &str) -> Vec<Rule> {
    // Classify every token once. A token that looks like a pattern is one;
    // everything else is an operator, filter or line property.
    let (pattern_toks, op_toks): (Vec<&str>, Vec<&str>) =
        tokens.iter().copied().partition(|t| looks_like_pattern(t));

    // No pattern at all: whistle treats the first token as the pattern, which
    // keeps `a.com host://x`-shaped lines working when `a.com` is not
    // recognised as a pattern by itself.
    let (pattern_toks, op_toks) = if pattern_toks.is_empty() {
        (vec![tokens[0]], tokens[1..].to_vec())
    } else {
        (pattern_toks, op_toks)
    };

    // Separate line properties, filter conditions and ordinary operators.
    let mut props = LineProps::default();
    let mut ops: Vec<RuleOp> = Vec::new();
    let mut filters: Vec<Filter> = Vec::new();
    for t in &op_toks {
        if let Some(spec) = line_props_spec(t) {
            props.merge(spec);
        } else if is_filter_token(t) {
            // A filter whose condition does not parse is dropped, never demoted
            // to an operator named `includeFilter`.
            filters.extend(parse_filter(t));
        } else if let Some(op) = parse_op(t) {
            ops.push(op);
        }
    }
    // `lineProps` is a modifier, not an operator: a line carrying nothing else
    // configures nothing (the original drops it the same way).
    if ops.is_empty() && filters.is_empty() {
        return Vec::new();
    }
    for op in &mut ops {
        op.props = props.clone();
    }

    pattern_toks
        .into_iter()
        .filter_map(|tok| {
            let parsed = parse_pattern(tok)?;
            Some(Rule {
                pattern: parsed.pattern,
                ops: ops.clone(),
                raw_line: raw_line.to_string(),
                important: parsed.important,
                negate: parsed.negate,
                filters: filters.clone(),
                props: props.clone(),
            })
        })
        .collect()
}

/// The `lineProps://…` payload of `tok`, if it declares line properties.
///
/// Also recognises the two legacy spellings `includeFilter://safeHtml` and
/// `includeFilter://strictHtml`, which the original rewrites to `lineProps://`
/// before parsing (`formatShorthand`, `_original/lib/rules/rules.js:224`).
fn line_props_spec(tok: &str) -> Option<&str> {
    if let Some(spec) = tok.strip_prefix("lineProps://") {
        return Some(spec);
    }
    match tok {
        "includeFilter://safeHtml" => Some("safeHtml"),
        "includeFilter://strictHtml" => Some("strictHtml"),
        _ => None,
    }
}

/// What a condition prefix builds, before its value has been parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondKind {
    Method,
    Host,
    Ip,
    ClientIp,
    ReqHeader,
    Chance,
    /// Recognised, but unanswerable here — see [`Deferred`].
    Later(Deferred),
}

/// Every condition spelling whistle understands: `(name, kind, props, pure)`.
///
/// Upstream splits them across two regexes
/// (`_original/lib/rules/rules.js:57-60`):
///
/// * `PROPS_FILTER_RE` — `<name>:<value>`, after any of
///   `filter`/`includeFilter`/`excludeFilter`/`ignore` (the `props` column);
/// * `PURE_FILTER_RE` — `<name>.<value>` or `<name>=<value>`, after
///   `includeFilter`/`excludeFilter` only, for a slightly different name set
///   (the `pure` column).
///
/// The distinction is worth keeping: a spelling upstream does *not* recognise
/// falls through to its URL-pattern branch and matches nothing, so accepting
/// more here would make rules fire that upstream leaves inert.
///
/// Order does not matter — a name only wins if the character right after it is
/// a separator that name allows, so `host` can never be read as `h`.
const COND_SPECS: &[(&str, CondKind, bool, bool)] = &[
    ("m", CondKind::Method, true, false),
    ("method", CondKind::Method, true, false),
    ("i", CondKind::Ip, true, false),
    ("ip", CondKind::Ip, true, false),
    ("h", CondKind::ReqHeader, true, false),
    ("header", CondKind::ReqHeader, true, false),
    // `host:` is this port's own spelling (upstream has only the pure form, and
    // routes it to proxy-host filtering rather than to the request's host).
    ("host", CondKind::Host, true, true),
    ("clientIp", CondKind::ClientIp, true, true),
    ("clientIP", CondKind::ClientIp, true, true),
    ("req", CondKind::ReqHeader, true, true),
    ("reqH", CondKind::ReqHeader, true, true),
    ("reqHeader", CondKind::ReqHeader, true, true),
    ("reqHeaders", CondKind::ReqHeader, true, true),
    ("chance", CondKind::Chance, true, true),
    ("probability", CondKind::Chance, true, true),
    ("s", CondKind::Later(Deferred::StatusCode), true, false),
    ("statusCode", CondKind::Later(Deferred::StatusCode), true, true),
    ("b", CondKind::Later(Deferred::Body), true, false),
    ("body", CondKind::Later(Deferred::Body), true, false),
    ("res", CondKind::Later(Deferred::ResHeader), true, true),
    ("resH", CondKind::Later(Deferred::ResHeader), true, true),
    ("resHeader", CondKind::Later(Deferred::ResHeader), true, true),
    ("resHeaders", CondKind::Later(Deferred::ResHeader), true, true),
    ("serverIp", CondKind::Later(Deferred::ServerIp), true, true),
    ("serverIP", CondKind::Later(Deferred::ServerIp), true, true),
    ("clientPort", CondKind::Later(Deferred::ClientPort), true, true),
    ("serverPort", CondKind::Later(Deferred::ServerPort), true, true),
    ("remoteAddress", CondKind::Later(Deferred::RemoteAddress), true, true),
    ("remotePort", CondKind::Later(Deferred::RemotePort), true, true),
    ("env", CondKind::Later(Deferred::Env), true, true),
    ("from", CondKind::Later(Deferred::From), true, true),
];

/// `Some(excludes)` when `proto` is one of the filter operators.
///
/// NOTE: upstream reads `filter://` as an *exclude* filter
/// (`isInclude = matcher[1] === 'n'`, `_original/lib/rules/rules.js:1563`). This
/// port has always treated it as an include, and its docs and examples say so;
/// the divergence is recorded in `docs/RULES.md` rather than flipped underneath
/// existing rules files.
fn filter_excludes(proto: &str) -> Option<bool> {
    match proto {
        "filter" | "includeFilter" => Some(false),
        "excludeFilter" => Some(true),
        _ => None,
    }
}

/// Is this token a filter condition (as opposed to an operator or a pattern)?
///
/// Used by [`parse_line`] so that a filter whose condition does not parse is
/// dropped instead of degrading into an operator named `includeFilter`.
fn is_filter_token(tok: &str) -> bool {
    split_protocol(tok).is_some_and(|(proto, _)| filter_excludes(proto).is_some())
}

/// Parse a `filter://` / `includeFilter://` / `excludeFilter://` token.
///
/// Returns `None` for a token that is not a filter at all, and for one whose
/// condition is unusable (an empty payload, an empty header key) — upstream
/// drops those too (`resolveMatchFilter`, `_original/lib/rules/rules.js:1556`).
fn parse_filter(tok: &str) -> Option<Filter> {
    let (proto, spec) = split_protocol(tok)?;
    let exclude = filter_excludes(proto)?;
    // `.`/`=` separated conditions are an includeFilter/excludeFilter-only form.
    let pure_ok = proto != "filter";
    if spec.is_empty() {
        return None;
    }
    let (cond, negate) = parse_cond(spec, pure_ok)?;
    Some(Filter {
        exclude,
        negate,
        cond,
    })
}

/// Parse the payload of a filter token into a condition plus its negation flag.
fn parse_cond(spec: &str, pure_ok: bool) -> Option<(Cond, bool)> {
    match split_cond_name(spec, pure_ok) {
        Some((kind, rest)) => build_cond(kind, rest),
        // Anything unrecognised is a URL pattern, matched exactly like a rule's
        // own pattern. Only here may a `!` precede the payload: with a condition
        // name present it belongs to the value, so `includeFilter://!m:GET` is a
        // (negated) URL pattern upstream, not a method condition.
        None => {
            let (negate, body) = strip_negation(spec);
            let pattern = parse_pattern(body)?.pattern;
            Some((Cond::Url(pattern), negate))
        }
    }
}

/// Split `<name><sep><rest>` when `<name>` is a known condition and `<sep>` is a
/// separator that name accepts.
fn split_cond_name(spec: &str, pure_ok: bool) -> Option<(CondKind, &str)> {
    for &(name, kind, props, pure) in COND_SPECS {
        let Some(rest) = spec.strip_prefix(name) else {
            continue;
        };
        let sep = rest.as_bytes().first()?;
        let accepted = match sep {
            b':' => props,
            b'.' | b'=' => pure && pure_ok,
            _ => false,
        };
        if accepted {
            return Some((kind, &rest[1..]));
        }
    }
    None
}

/// `!value` → negated. Upstream folds the flag with `not = !not`, so a token can
/// carry it in more than one place (`_original/lib/rules/rules.js:1565`).
fn strip_negation(value: &str) -> (bool, &str) {
    match value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, value),
    }
}

/// Build the condition for `kind` from everything after its separator.
fn build_cond(kind: CondKind, rest: &str) -> Option<(Cond, bool)> {
    let (negate, rest) = strip_negation(rest);
    let cond = match kind {
        // whistle compiles method regexps with a forced `i` flag.
        CondKind::Method => Cond::Method(CondValue::parse(rest, true)),
        CondKind::Host => Cond::Host(CondValue::parse(rest, false)),
        CondKind::Ip => Cond::Ip(CondValue::parse(rest, false)),
        CondKind::ClientIp => Cond::ClientIp(CondValue::parse(rest, false)),
        CondKind::ReqHeader => {
            let (key, key_negate, value) = split_keyed_value(rest, true)?;
            return Some((
                Cond::ReqHeader {
                    name: key.to_lowercase(),
                    value: CondValue::parse(value, false),
                },
                negate != key_negate,
            ));
        }
        CondKind::Chance => {
            let (key, key_negate, _) = split_keyed_value(rest, false)?;
            return Some((Cond::Chance(parse_probability(key)), negate != key_negate));
        }
        CondKind::Later(what) => Cond::Deferred(what),
    };
    Some((cond, negate))
}

/// Split a keyed condition (`<key>=<value>`, or `<key>:<value>` for headers)
/// into its key, whether the key carried a trailing `!`, and its value.
///
/// Upstream looks for `=` first and only falls back to `:` for header-shaped
/// conditions, which is why `chance:50%` keeps its `%` and why
/// `reqH.referer:http://x` splits at the *first* colon
/// (`_original/lib/rules/rules.js:1645-1660`). A key left empty by its `!`
/// drops the whole filter.
fn split_keyed_value(rest: &str, colon_separates: bool) -> Option<(&str, bool, &str)> {
    let sep = rest
        .find('=')
        .or_else(|| if colon_separates { rest.find(':') } else { None });
    let (key, value) = match sep {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let (key, negate) = match key.strip_suffix('!') {
        Some(k) => (k, true),
        None => (key, false),
    };
    if key.is_empty() {
        return None;
    }
    Some((key, negate, value))
}

/// `chance:0.25` / `chance:25%` → the probability to sample at.
///
/// A value JS would coerce to `NaN` stays `NaN` here, so the comparison against
/// a random number is false however it is written — including for a bare `%`,
/// which upstream's length check also leaves alone.
fn parse_probability(key: &str) -> f64 {
    let parsed = match key.strip_suffix('%') {
        Some(n) => n.parse::<f64>().map(|v| v / 100.0),
        None => key.parse::<f64>(),
    };
    parsed.unwrap_or(f64::NAN)
}

/// Heuristic: does this token read as a match pattern (vs. an operator)?
fn looks_like_pattern(tok: &str) -> bool {
    // Both pattern prefixes have to come off first, or `!/re/` and `!:8080`
    // would not be recognised for what they are.
    let t = tok.strip_prefix('!').unwrap_or(tok);
    let t = t.strip_prefix('$').unwrap_or(t);
    if t.starts_with('/') || t.starts_with(':') {
        return true; // regexp or port pattern
    }
    // Line properties and filters are neither pattern nor operator. Classifying
    // one as a pattern would both lose its effect and mint a rule that can
    // never match, so they are excluded before anything else is considered.
    if line_props_spec(t).is_some() {
        return false;
    }
    if is_filter_token(t) {
        return false;
    }
    // An operator has a known `protocol://` prefix.
    if let Some((proto, _)) = split_protocol(t) {
        if protocols::is_protocol(proto) {
            return false;
        }
    }
    // A bare host:port / ip is an operator (hosts shorthand), not a pattern.
    if is_host_shorthand(t) {
        return false;
    }
    true
}

/// Split `proto://rest` → `(proto, rest)`.
fn split_protocol(tok: &str) -> Option<(&str, &str)> {
    tok.find("://").map(|i| (&tok[..i], &tok[i + 3..]))
}

/// Recognise a bare `host:port` / `ip[:port]` operator (whistle's hosts form).
fn is_host_shorthand(tok: &str) -> bool {
    if tok.contains("://") || tok.starts_with('/') {
        return false;
    }
    // ipv4[:port] or hostname:port
    let host_port = tok.rsplit_once(':');
    match host_port {
        Some((h, p)) => !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty(),
        None => {
            // bare ipv4 like 127.0.0.1
            tok.split('.').count() == 4 && tok.split('.').all(|o| o.parse::<u8>().is_ok())
        }
    }
}

/// Parse one operator token into a [`RuleOp`].
/// Mirrors `formatShorthand` + operator handling in the original.
///
/// Line properties are left at their default here and stamped on by
/// [`parse_line`], which is the only place that has seen the whole line.
fn parse_op(tok: &str) -> Option<RuleOp> {
    if let Some((proto, rest)) = split_protocol(tok) {
        if protocols::is_protocol(proto) {
            // Normalise alias protocols (e.g. `hosts` → `host`) to canonical names.
            let canon = protocols::canonical(proto).unwrap_or(proto);
            return Some(RuleOp {
                protocol: canon.to_string(),
                value: rest.to_string(),
                raw: tok.to_string(),
                props: LineProps::default(),
            });
        }
        // Unknown scheme (e.g. a plain proxy target) — treat as a proxy URL.
        return Some(RuleOp {
            protocol: proto.to_string(),
            value: rest.to_string(),
            raw: tok.to_string(),
            props: LineProps::default(),
        });
    }
    if is_host_shorthand(tok) {
        return Some(RuleOp {
            protocol: "host".to_string(),
            value: tok.to_string(),
            raw: tok.to_string(),
            props: LineProps::default(),
        });
    }
    // Bare path / file shorthand → file operator.
    if tok.starts_with('/') || tok.starts_with('~') || tok.starts_with('.') {
        return Some(RuleOp {
            protocol: "file".to_string(),
            value: tok.to_string(),
            raw: tok.to_string(),
            props: LineProps::default(),
        });
    }
    None
}

/// A pattern token after its `!` / `$` prefixes have been peeled off.
struct ParsedPattern {
    pattern: Pattern,
    /// `$` — this port's important-rule shorthand. (Upstream spells importance
    /// `lineProps://important` and uses `$` for exact-URL matching, so its
    /// `!$url` "negative exact" form has no equivalent here.)
    important: bool,
    /// `!` — invert the pattern test.
    negate: bool,
}

/// Parse a pattern token into a [`Pattern`] plus its prefix modifiers.
///
/// The order mirrors `parseRule` (`_original/lib/rules/rules.js:1235-1252`),
/// whose `// 位置不能变` comment marks exactly this: `!` comes off first, the
/// port-pattern test runs on what is left — so `!:8080` is a *negated* port
/// pattern while `$:8080` is not a port pattern at all — and only then is the
/// `$` prefix handled.
fn parse_pattern(tok: &str) -> Option<ParsedPattern> {
    let (negate, tok) = match tok.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, tok),
    };
    let done = |pattern, important| {
        Some(ParsedPattern {
            pattern,
            important,
            negate,
        })
    };

    // Port pattern: `:8080` scopes the rule to one port.
    if let Some(re) = port_pattern(tok) {
        return done(Pattern::Regex(re), false);
    }

    let important = tok.starts_with('$');
    let tok = tok.strip_prefix('$').unwrap_or(tok);

    // Regexp pattern: /body/flags
    if tok.starts_with('/') && tok.len() > 1 {
        if let Some(end) = tok.rfind('/') {
            if end > 0 {
                let body = &tok[1..end];
                let flags = &tok[end + 1..];
                let mut pat = String::new();
                if flags.contains('i') {
                    pat.push_str("(?i)");
                }
                pat.push_str(body);
                if let Ok(re) = Regex::new(&pat) {
                    return done(Pattern::Regex(re), important);
                }
            }
        }
    }

    // Everything below is a literal pattern, and whistle refuses to negate
    // those: `parseWildcard` bails out for a negated wildcard
    // (`rules.js:1171-1173`) and a negated plain pattern falls into the
    // `else if (not) return;` at `rules.js:1266`. Dropping the rule — rather
    // than inventing an inversion the original does not have — keeps a rules
    // file behaving the same in both implementations.
    if negate {
        return None;
    }

    // Wildcard pattern → regex.
    if tok.contains('*') {
        let re = wildcard_to_regex(tok);
        if let Ok(re) = Regex::new(&re) {
            return done(Pattern::Regex(re), important);
        }
    }

    // Scheme/host/path prefix.
    done(parse_prefix(tok), important)
}

/// Compile a `:8080`-style port pattern.
///
/// `PORT_PATTERN_RE = /^!?:\d{1,5}$/` (`_original/lib/rules/rules.js:71`) and
/// the compilation at `rules.js:1249-1252`: `^[\w]+://[^/?]+:<port>/`. Matching
/// the URL text means the port has to be *spelled out*, so `:80` does not match
/// `http://example.com/` in either implementation.
///
/// Anything less than a real port test is dangerous: this port used to fall
/// through to the prefix parser, which dropped the port, ended up with an empty
/// host and matched **every** request.
fn port_pattern(tok: &str) -> Option<Regex> {
    let digits = tok.strip_prefix(':')?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Regex::new(&format!(r"^[\w]+://[^/?]+:{digits}/")).ok()
}

/// Build a scheme/host/path prefix pattern from a plain token.
fn parse_prefix(tok: &str) -> Pattern {
    let (scheme, rest) = match tok.find("://") {
        Some(i) => (Some(tok[..i].to_lowercase()), &tok[i + 3..]),
        None => (None, tok),
    };
    let (host_part, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    // An explicit port scopes the rule to that port. The original matches the
    // pattern as a literal prefix of the request URL, port and all, so dropping
    // it here (as this port used to) made `example.com:8080` match every port.
    // A `:port` that is not a valid u16 is left as part of the host, which then
    // simply never matches — better than silently widening the rule.
    let (host_no_port, port) = match host_part.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, Some(port)),
            Err(_) => (host_part, None),
        },
        None => (host_part, None),
    };
    let (host_suffix, host) = if let Some(stripped) = host_no_port.strip_prefix('.') {
        (true, stripped.to_lowercase())
    } else {
        (false, host_no_port.to_lowercase())
    };
    if host.is_empty() && path.is_empty() && scheme.is_none() && port.is_none() {
        return Pattern::Any;
    }
    Pattern::Prefix {
        scheme,
        host,
        host_suffix,
        port,
        path,
    }
}

/// Convert a whistle wildcard pattern to an anchored regex string.
/// `*` → `.*`, other regex metacharacters escaped.
fn wildcard_to_regex(tok: &str) -> String {
    let mut out = String::from("^");
    for ch in tok.chars() {
        match ch {
            '*' => out.push_str(".*"),
            c if "\\.+?()[]{}|^$".contains(c) => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse().unwrap())
            }
            _ => (
                host_port.to_string(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path: path.clone(),
            full_url: url.into(),
            client_ip: None,
            headers: Default::default(),
        }
    }

    #[test]
    fn disabled_group_skipped() {
        let mut mgr = RuleManager::new();
        mgr.add_group("a", "example.com host://1.2.3.4", true);
        mgr.add_group("b", "example.com host://5.6.7.8", false);

        let r = mgr.resolve(&req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("1.2.3.4"));
        assert_eq!(mgr.len(), 2); // both parsed
    }

    #[test]
    fn toggle_changes_resolution() {
        let mut mgr = RuleManager::new();
        mgr.add_group("main", "example.com host://1.1.1.1", true);
        assert!(mgr.resolve(&req("http://example.com/")).single.contains_key("host"));

        mgr.toggle_group("main");
        assert!(mgr.resolve(&req("http://example.com/")).single.is_empty());
    }

    #[test]
    fn add_remove_groups() {
        let mut mgr = RuleManager::new();
        assert!(mgr.add_group("a", "", true));
        assert!(!mgr.add_group("a", "", true)); // duplicate
        assert_eq!(mgr.groups().len(), 1);

        assert!(mgr.remove_group("a"));
        assert!(!mgr.remove_group("a")); // already removed
        assert_eq!(mgr.groups().len(), 0);
    }

    #[test]
    fn set_text_backward_compat() {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com host://1.1.1.1");
        assert_eq!(mgr.groups().len(), 1);
        assert_eq!(mgr.groups()[0].name, "default");
        assert!(mgr.resolve(&req("http://example.com/")).single.contains_key("host"));

        mgr.set_text("other.com host://2.2.2.2");
        assert_eq!(mgr.groups().len(), 1);
        assert!(mgr.resolve(&req("http://example.com/")).single.is_empty());
    }
}


#[cfg(test)]
mod line_props_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        let port = if scheme == "https" { 443 } else { 80 };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path,
            full_url: url.into(),
            client_ip: None,
            headers: Default::default(),
        }
    }

    fn one(text: &str) -> Rule {
        let rules = parse_text(text);
        assert_eq!(rules.len(), 1, "expected exactly one rule from {text:?}");
        rules.into_iter().next().unwrap()
    }

    // ── parsing ──

    /// Separators are `|` *and* `&` (`SEP_RE = /[|&]/`), and empty segments
    /// are dropped rather than stored as an empty action.
    #[test]
    fn both_separators_and_empty_segments() {
        let r = one("example.com file:///tmp/x lineProps://a|b&c||d");
        let got: Vec<&str> = r.props.iter().collect();
        assert_eq!(got, vec!["a", "b", "c", "d"]);
    }

    /// Several `lineProps://` tokens on one line merge, like the original's
    /// repeated `extend(lineProps, …)`.
    #[test]
    fn multiple_tokens_merge() {
        let r = one("example.com file:///tmp/x lineProps://important lineProps://safeHtml");
        assert!(r.props.has("important"));
        assert!(r.props.has("safeHtml"));
    }

    /// `lineProps://` with an empty payload is a no-op, not an empty action.
    #[test]
    fn empty_payload_is_noop() {
        let r = one("example.com file:///tmp/x lineProps://");
        assert!(r.props.is_empty());
        assert_eq!(r.ops.len(), 1, "lineProps must not become an operator");
    }

    /// whistle never validates action names — unknown ones are kept so that
    /// consumers this port does not implement still receive them.
    #[test]
    fn unknown_actions_preserved() {
        let r = one("example.com file:///tmp/x lineProps://totallyMadeUp");
        assert!(r.props.has("totallyMadeUp"));
    }

    /// A line whose only non-pattern token is `lineProps://` configures nothing.
    #[test]
    fn line_props_alone_is_not_a_rule() {
        assert!(parse_text("example.com lineProps://important").is_empty());
    }

    /// Every operator on the line carries the line's properties, since
    /// resolution mixes operators from many lines.
    #[test]
    fn props_copied_onto_every_op() {
        let r = one("example.com host://1.2.3.4 resType://json lineProps://safeHtml");
        assert_eq!(r.ops.len(), 2);
        assert!(r.ops.iter().all(|op| op.props.has("safeHtml")));
    }

    /// The two legacy `includeFilter://` spellings are rewritten to
    /// `lineProps://` before parsing (`formatShorthand`,
    /// `_original/lib/rules/rules.js:224-229`), so they must become properties
    /// rather than filter conditions.
    #[test]
    fn legacy_include_filter_aliases() {
        let r = one("example.com htmlAppend://<!--x--> includeFilter://safeHtml");
        assert!(r.props.has("safeHtml"));
        assert!(r.filters.is_empty(), "must not become a filter condition");
        assert!(one("example.com htmlAppend://<!--x--> includeFilter://strictHtml")
            .props
            .has("strictHtml"));
    }

    // ── important ──

    /// `lineProps://important` outranks an earlier normal line for the same
    /// protocol, exactly like the `$` prefix already does.
    #[test]
    fn important_wins_over_earlier_normal_line() {
        let rules = parse_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2 lineProps://important",
        );
        let refs: Vec<&Rule> = rules.iter().collect();
        let r = matcher::resolve_refs(&refs, &req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("2.2.2.2"));
    }

    /// Without it, first-match-wins still holds.
    #[test]
    fn without_important_first_line_wins() {
        let rules = parse_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2",
        );
        let refs: Vec<&Rule> = rules.iter().collect();
        let r = matcher::resolve_refs(&refs, &req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("1.1.1.1"));
    }

    // ── internal / internalOnly scoping ──

    #[test]
    fn internal_only_is_hidden_from_client_requests() {
        let rules = parse_text("example.com host://1.1.1.1 lineProps://internalOnly");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.is_empty());
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.contains_key("host"));
    }

    #[test]
    fn internal_applies_to_both_origins() {
        let rules = parse_text("example.com host://1.1.1.1 lineProps://internal");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.contains_key("host"));
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.contains_key("host"));
    }

    /// A plain line is invisible to whistle's own outgoing requests.
    #[test]
    fn plain_line_is_client_only() {
        let rules = parse_text("example.com host://1.1.1.1");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.contains_key("host"));
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.is_empty());
    }

    // ── safeHtml / strictHtml injection gating ──

    #[test]
    fn injection_gating() {
        let plain = LineProps::default();
        let mut safe = LineProps::default();
        safe.merge("safeHtml");
        let mut strict = LineProps::default();
        strict.merge("strictHtml");

        // Real markup: everyone injects.
        for p in [&plain, &safe, &strict] {
            assert!(p.allows_injection(b"  <html></html>"));
        }
        // JSON-looking: safeHtml and strictHtml both refuse.
        assert!(plain.allows_injection(b"{\"a\":1}"));
        assert!(!safe.allows_injection(b"{\"a\":1}"));
        assert!(!strict.allows_injection(b"[1,2]"));
        // Bare text: only strictHtml refuses.
        assert!(safe.allows_injection(b"hello"));
        assert!(!strict.allows_injection(b"hello"));
        // Empty body counts as markup.
        assert!(strict.allows_injection(b""));
    }
}

#[cfg(test)]
mod filter_parse_tests {
    use super::*;

    /// The single filter parsed from a one-line rule.
    fn cond_of(token: &str) -> Filter {
        let text = format!("example.com host://1.1.1.1 {token}");
        let rules = parse_text(&text);
        assert_eq!(rules.len(), 1, "expected one rule from {text:?}");
        let mut filters = rules.into_iter().next().unwrap().filters;
        assert_eq!(filters.len(), 1, "expected one filter from {token:?}");
        filters.remove(0)
    }

    /// Filters parsed from a token, which may be none.
    fn filters_of(token: &str) -> Vec<Filter> {
        let text = format!("example.com host://1.1.1.1 {token}");
        parse_text(&text).into_iter().next().unwrap().filters
    }

    // ── condition spellings ──

    /// Upstream's canonical request-header syntax, in every spelling its two
    /// regexes accept (`_original/lib/rules/rules.js:57-60`).
    #[test]
    fn request_header_spellings() {
        for token in [
            "includeFilter://reqH.x-tag:yes",
            "includeFilter://reqH.x-tag=yes",
            "includeFilter://req.x-tag:yes",
            "includeFilter://reqHeader.x-tag:yes",
            "includeFilter://reqHeaders.x-tag:yes",
            "includeFilter://reqH:x-tag=yes",
            "filter://reqH:x-tag=yes",
            "filter://h:x-tag=yes",
            "filter://header:x-tag=yes",
            "filter://h:x-tag:yes",
        ] {
            match cond_of(token).cond {
                Cond::ReqHeader { name, value } => {
                    assert_eq!(name, "x-tag", "{token}");
                    assert!(value.matches_header("yes"), "{token}");
                }
                other => panic!("{token} parsed as {other:?}"),
            }
        }
    }

    /// Header keys are case-folded, since `ReqInfo` stores them lowercased.
    #[test]
    fn header_key_is_lowercased() {
        match cond_of("includeFilter://reqH.X-Tag:yes").cond {
            Cond::ReqHeader { name, .. } => assert_eq!(name, "x-tag"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// A header condition with no value at all is a presence test.
    #[test]
    fn header_without_a_value_matches_anything() {
        match cond_of("includeFilter://reqH.x-tag").cond {
            Cond::ReqHeader { name, value } => {
                assert_eq!(name, "x-tag");
                assert!(value.matches_header("whatever"));
                assert!(value.matches_header(""));
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    /// The `.`/`=` form belongs to `includeFilter`/`excludeFilter`; upstream's
    /// `PROPS_FILTER_RE` is the only one `filter://` reaches, so `filter://`
    /// with a dotted name is a URL pattern — as it is upstream.
    #[test]
    fn pure_form_is_not_available_to_plain_filter() {
        assert!(matches!(
            cond_of("filter://reqH.x-tag:yes").cond,
            Cond::Url(_)
        ));
        assert!(matches!(
            cond_of("includeFilter://reqH.x-tag:yes").cond,
            Cond::ReqHeader { .. }
        ));
    }

    /// Names are matched whole: the separator that follows decides, so `host`
    /// is never mistaken for `h`, nor `statusCode` for `s`.
    #[test]
    fn longer_names_are_not_shadowed() {
        assert!(matches!(cond_of("filter://host:example.com").cond, Cond::Host(_)));
        assert!(matches!(
            cond_of("filter://statusCode:200").cond,
            Cond::Deferred(Deferred::StatusCode)
        ));
        assert!(matches!(cond_of("filter://ip:1.2.3.4").cond, Cond::Ip(_)));
        assert!(matches!(
            cond_of("includeFilter://reqHeaders.x:1").cond,
            Cond::ReqHeader { .. }
        ));
    }

    /// Every condition upstream defers to the response phase is recognised, so
    /// it cannot be mistaken for a URL pattern.
    #[test]
    fn deferred_conditions_are_recognised() {
        let cases = [
            ("filter://s:200", Deferred::StatusCode),
            ("filter://statusCode:200", Deferred::StatusCode),
            ("includeFilter://resH.content-type:json", Deferred::ResHeader),
            ("includeFilter://resHeaders.x:1", Deferred::ResHeader),
            ("filter://serverIp:1.2.3.4", Deferred::ServerIp),
            ("includeFilter://serverIp=1.2.3.4", Deferred::ServerIp),
            ("filter://clientPort:8080", Deferred::ClientPort),
            ("filter://serverPort:8080", Deferred::ServerPort),
            ("filter://remoteAddress:1.2.3.4", Deferred::RemoteAddress),
            ("filter://remotePort:80", Deferred::RemotePort),
            ("filter://b:keyword", Deferred::Body),
            ("filter://body:keyword", Deferred::Body),
            ("filter://env:x=1", Deferred::Env),
            ("filter://from:composer", Deferred::From),
        ];
        for (token, want) in cases {
            match cond_of(token).cond {
                Cond::Deferred(got) => assert_eq!(got, want, "{token}"),
                other => panic!("{token} parsed as {other:?}"),
            }
        }
    }

    // ── regexp-valued conditions ──

    /// Any condition's value may be a `/regexp/[i]`.
    #[test]
    fn regexp_values() {
        assert!(matches!(
            cond_of("filter://m:/^P/").cond,
            Cond::Method(CondValue::Regex(_))
        ));
        assert!(matches!(
            cond_of("includeFilter://reqH.x-tag:/^ye/i").cond,
            Cond::ReqHeader {
                value: CondValue::Regex(_),
                ..
            }
        ));
        assert!(matches!(
            cond_of("filter://i:/^10\\./").cond,
            Cond::Ip(CondValue::Regex(_))
        ));
    }

    /// whistle compiles method regexps with a forced `i` flag
    /// (`util.toRegExp(value, true)`), unlike every other condition.
    #[test]
    fn method_regexps_ignore_case_without_the_flag() {
        match cond_of("filter://m:/^post$/").cond {
            Cond::Method(v) => assert!(v.matches("POST")),
            other => panic!("parsed as {other:?}"),
        }
        match cond_of("filter://host:/^EXAMPLE\\.com$/").cond {
            Cond::Host(v) => assert!(!v.matches("example.com"), "no implicit `i` here"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// `REG_EXP_RE` is `^/(.+)/(i?u?|ui)$`: an empty body or an unknown flag is
    /// a literal, and so is a pattern Rust's engine cannot compile.
    #[test]
    fn near_misses_degrade_to_literals() {
        for token in [
            "filter://m:／/",     // not a slash at all
            "filter://m://",      // empty body
            "filter://m:/GET/g",  // flag whistle's regex does not accept
            "filter://m:/(?<=x)/", // valid in JS, unsupported by Rust's engine
        ] {
            assert!(
                matches!(cond_of(token).cond, Cond::Method(CondValue::Literal(_))),
                "{token} should be a literal"
            );
        }
    }

    // ── chance ──

    #[test]
    fn chance_values() {
        let p = |token: &str| match cond_of(token).cond {
            Cond::Chance(p) => p,
            other => panic!("{token} parsed as {other:?}"),
        };
        assert_eq!(p("includeFilter://chance:0.25"), 0.25);
        assert_eq!(p("includeFilter://chance:25%"), 0.25);
        assert_eq!(p("includeFilter://probability:1"), 1.0);
        assert_eq!(p("includeFilter://chance=0.5"), 0.5);
        assert_eq!(p("filter://chance:0"), 0.0);
        // Anything JS would coerce to NaN stays NaN, and NaN never matches.
        assert!(p("includeFilter://chance:half").is_nan());
        assert!(p("includeFilter://chance:%").is_nan());
    }

    // ── negation ──

    /// `!` may sit in front of a condition's value, after a header key, or in
    /// front of a URL pattern.
    #[test]
    fn negation_spellings() {
        assert!(cond_of("filter://m:!GET").negate);
        assert!(cond_of("includeFilter://reqH.x-tag!:yes").negate);
        assert!(cond_of("includeFilter://!*.cdn.example.com").negate);
        assert!(!cond_of("filter://m:GET").negate);
        // A `!` in front of a condition *name* is not a negation: upstream's
        // props regex requires the name first, so this is a URL pattern.
        assert!(matches!(cond_of("includeFilter://!m:GET").cond, Cond::Url(_)));
    }

    /// A header condition can carry a `!` in both places, and they cancel —
    /// upstream folds each one in with `not = !not`.
    #[test]
    fn double_negation_cancels() {
        let f = cond_of("includeFilter://reqH.!x-tag!:yes");
        assert!(!f.negate);
        match f.cond {
            Cond::ReqHeader { name, .. } => assert_eq!(name, "x-tag"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// The value's `!` is only read before the *key*: once the key separator
    /// has been passed, a `!` is part of the expected value.
    #[test]
    fn bang_after_the_separator_is_literal() {
        let f = cond_of("includeFilter://reqH.x-tag:!yes");
        assert!(!f.negate);
        match f.cond {
            Cond::ReqHeader { value, .. } => {
                assert!(value.matches_header("!yes"));
                assert!(!value.matches_header("yes"));
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    // ── URL-pattern fallback ──

    /// An unrecognised condition is a URL pattern, parsed with the same engine
    /// as a rule's own pattern — wildcards and prefixes included, where the old
    /// "strip the slashes and hope it is a regex" fallback dropped them.
    #[test]
    fn url_fallback_uses_the_pattern_engine() {
        for token in [
            "includeFilter://*/cgi-*",
            "excludeFilter://www.test.com",
            "includeFilter://https://www.test.com/path",
            "excludeFilter:///admin/",
        ] {
            assert!(
                matches!(cond_of(token).cond, Cond::Url(_)),
                "{token} should be a URL pattern"
            );
        }
    }

    // ── graceful degradation ──

    /// A filter that cannot be parsed is dropped, and must never be demoted to
    /// an operator called `includeFilter`.
    #[test]
    fn unusable_filters_are_dropped_not_demoted() {
        for token in [
            "includeFilter://",
            "includeFilter://reqH.:yes",
            "includeFilter://reqH.!:yes",
        ] {
            assert!(filters_of(token).is_empty(), "{token} should be dropped");
            let rules = parse_text(&format!("example.com host://1.1.1.1 {token}"));
            assert_eq!(rules[0].ops.len(), 1, "{token} must not become an operator");
        }
    }

    /// `excludeFilter://` is the only spelling that excludes here.
    #[test]
    fn exclude_flag() {
        assert!(cond_of("excludeFilter://m:GET").exclude);
        assert!(!cond_of("includeFilter://m:GET").exclude);
        assert!(!cond_of("filter://m:GET").exclude);
    }
}

#[cfg(test)]
mod pattern_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => {
                (h.to_string(), p.parse().unwrap())
            }
            _ => (
                host_port.to_string(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path,
            full_url: url.into(),
            ..Default::default()
        }
    }

    /// Does `text`'s rule match `url`?
    fn hits(text: &str, url: &str) -> bool {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        mgr.resolve(&req(url)).value("host").is_some()
    }

    // ── `:port` patterns ──

    /// `:8080` scopes a rule to one port, on any host. It used to reach the
    /// prefix parser, which dropped the port and left an empty host — i.e. a
    /// pattern that quietly matched **every** request.
    #[test]
    fn port_pattern_matches_only_that_port() {
        let text = ":8080 host://1.1.1.1";
        assert!(hits(text, "http://any.test:8080/"));
        assert!(hits(text, "https://other.test:8080/deep/path?q=1"));
        assert!(!hits(text, "http://any.test/"), "port 80 must not match");
        assert!(!hits(text, "http://other.test:9999/"));
        assert!(!hits(text, "http://any.test:18080/"), "not a suffix match");
    }

    /// Like upstream, the port has to be spelled out in the URL: the compiled
    /// pattern is `^[\w]+://[^/?]+:<port>/`, so a default port does not match.
    #[test]
    fn default_port_is_not_spelled_out() {
        assert!(!hits(":80 host://1.1.1.1", "http://any.test/"));
        assert!(hits(":80 host://1.1.1.1", "http://any.test:80/"));
    }

    /// `!:8080` is recognised as *both* a port pattern and a negation — the
    /// ordering upstream marks with `// 位置不能变`.
    #[test]
    fn negated_port_pattern() {
        let text = "!:8080 host://1.1.1.1";
        assert!(!hits(text, "http://any.test:8080/"));
        assert!(hits(text, "http://any.test/"));
        // …and it must not be mistaken for a `host:port` operator.
        let rules = parse_text("!:8080 statusCode://418");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ops.len(), 1);
        assert_eq!(rules[0].ops[0].protocol, "statusCode");
    }

    /// A port written into an ordinary pattern scopes it just the same —
    /// upstream matches the pattern as a literal prefix of the URL, port
    /// included.
    #[test]
    fn explicit_port_in_a_host_pattern() {
        let text = "example.test:8080 host://1.1.1.1";
        assert!(hits(text, "http://example.test:8080/"));
        assert!(!hits(text, "http://example.test/"));
        assert!(!hits(text, "http://other.test:8080/"));
        // A portless pattern still matches any port.
        assert!(hits("example.test host://1.1.1.1", "http://example.test:8080/"));
    }

    /// A `:` that is not a port stays part of the host, which then matches
    /// nothing — rather than being dropped and widening the rule.
    #[test]
    fn unparsable_port_does_not_widen_the_pattern() {
        assert!(!hits("example.test:99999 host://1.1.1.1", "http://example.test/"));
        assert!(!hits(": host://1.1.1.1", "http://example.test/"));
    }

    // ── `!` negation ──

    /// `!/re/` matches every request the regexp does not
    /// (`_original/lib/rules/rules.js:994-998`).
    #[test]
    fn negated_regexp_inverts_the_match() {
        let text = "!/example\\.test/ host://1.1.1.1";
        assert!(!hits(text, "http://example.test/"));
        assert!(hits(text, "http://other.test/"));
    }

    /// Only the *pattern* test is inverted: filter conditions still have to
    /// hold as written.
    #[test]
    fn negation_leaves_filters_alone() {
        let text = "!/example\\.test/ host://1.1.1.1 filter://m:POST";
        assert!(!hits(text, "http://other.test/"), "GET fails the filter");

        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let post = |url: &str| {
            let mut r = req(url);
            r.method = "POST".into();
            r
        };
        assert!(mgr.resolve(&post("http://other.test/")).value("host").is_some());
        assert!(
            mgr.resolve(&post("http://example.test/")).value("host").is_none(),
            "the negated pattern still excludes example.test"
        );
    }

    /// Upstream refuses to negate a literal pattern: `parseWildcard` bails out
    /// for a negated wildcard (`rules.js:1171-1173`) and a negated plain
    /// pattern hits `else if (not) return;` (`rules.js:1266`). Both drop the
    /// rule, so this port drops it too rather than inventing an inversion.
    #[test]
    fn literal_patterns_cannot_be_negated() {
        assert!(parse_text("!example.test host://1.1.1.1").is_empty());
        assert!(parse_text("!*.example.test host://1.1.1.1").is_empty());
        // Other patterns on the same line are unaffected.
        let rules = parse_text("!example.test other.test host://1.1.1.1");
        assert_eq!(rules.len(), 1);
        assert!(hits("!example.test other.test host://1.1.1.1", "http://other.test/"));
    }

    /// The `$` important shorthand still works, and survives a `!` in front.
    #[test]
    fn important_prefix_after_negation() {
        let rules = parse_text("$example.test host://1.1.1.1");
        assert!(rules[0].is_important());
        assert!(!rules[0].negate);
        // `!$…` parses as negate + important; being literal, it is dropped.
        assert!(parse_text("!$example.test host://1.1.1.1").is_empty());
    }
}

#[cfg(test)]
mod parse_text_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port: if scheme == "https" { 443 } else { 80 },
            path,
            full_url: url.into(),
            client_ip: None,
            headers: Default::default(),
        }
    }

    fn host_for(text: &str, url: &str) -> Option<String> {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        mgr.resolve(&req(url)).value("host").map(str::to_string)
    }

    // ── one rule per pattern ──

    /// whistle expands a line into one rule per pattern; taking only the first
    /// silently dropped every other host on the line.
    #[test]
    fn every_pattern_on_a_line_gets_the_operator() {
        let text = "host://9.9.9.9 a.com b.com c.com";
        for h in ["a.com", "b.com", "c.com"] {
            assert_eq!(
                host_for(text, &format!("http://{h}/")).as_deref(),
                Some("9.9.9.9"),
                "{h} should match"
            );
        }
        assert_eq!(host_for(text, "http://d.com/"), None);
    }

    /// The same holds for the pattern-first spelling.
    #[test]
    fn pattern_first_form_also_expands() {
        let text = "a.com b.com host://8.8.8.8";
        assert_eq!(host_for(text, "http://a.com/").as_deref(), Some("8.8.8.8"));
        assert_eq!(host_for(text, "http://b.com/").as_deref(), Some("8.8.8.8"));
    }

    /// Filters and line properties must not be mistaken for patterns — doing so
    /// both loses their effect and mints a rule that can never match.
    #[test]
    fn filters_and_props_are_not_patterns() {
        let rules = parse_text("a.com host://1.1.1.1 excludeFilter://m:GET lineProps://important");
        assert_eq!(rules.len(), 1, "only `a.com` is a pattern");
        assert_eq!(rules[0].filters.len(), 1);
        assert!(rules[0].props.has("important"));
    }

    // ── comments ──

    /// whistle's removeComment is a global `/#[^\r\n]*/g`, so a trailing comment
    /// is stripped rather than parsed as extra tokens.
    #[test]
    fn trailing_comment_is_stripped() {
        assert_eq!(
            host_for("a.com host://1.1.1.1   # 说明文字", "http://a.com/").as_deref(),
            Some("1.1.1.1")
        );
        let rules = parse_text("a.com host://1.1.1.1 # b.com c.com");
        assert_eq!(rules.len(), 1, "commented-out patterns must not become rules");
    }

    #[test]
    fn whole_line_comment_still_ignored() {
        assert!(parse_text("# a.com host://1.1.1.1").is_empty());
        assert!(parse_text("   # indented").is_empty());
    }

    // ── multi-line blocks ──

    #[test]
    fn multi_line_block_collapses() {
        let text = "line`\nhost://7.7.7.7\nwww.example.com\napi.example.com\n`";
        assert_eq!(
            host_for(text, "http://www.example.com/").as_deref(),
            Some("7.7.7.7")
        );
        assert_eq!(
            host_for(text, "http://api.example.com/").as_deref(),
            Some("7.7.7.7")
        );
        // The block markers must not survive as rules of their own.
        assert_eq!(parse_text(text).len(), 2);
    }

    #[test]
    fn rules_around_a_block_still_parse() {
        let text = "before.com host://1.1.1.1\nline`\nhost://2.2.2.2\ninside.com\n`\nafter.com host://3.3.3.3";
        assert_eq!(host_for(text, "http://before.com/").as_deref(), Some("1.1.1.1"));
        assert_eq!(host_for(text, "http://inside.com/").as_deref(), Some("2.2.2.2"));
        assert_eq!(host_for(text, "http://after.com/").as_deref(), Some("3.3.3.3"));
    }

    /// Comments are stripped before blocks are collapsed, so a `#` inside a
    /// block comments out that line only.
    #[test]
    fn comment_inside_a_block() {
        let text = "line`\nhost://4.4.4.4\nkept.com\n# skipped.com\n`";
        assert_eq!(host_for(text, "http://kept.com/").as_deref(), Some("4.4.4.4"));
        assert_eq!(host_for(text, "http://skipped.com/"), None);
    }

    /// An unterminated block still yields its rule rather than vanishing.
    #[test]
    fn unterminated_block_is_salvaged() {
        assert_eq!(
            host_for("line`\nhost://5.5.5.5\nlonely.com", "http://lonely.com/").as_deref(),
            Some("5.5.5.5")
        );
    }
}
