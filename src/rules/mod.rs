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
#[derive(Debug, Clone)]
pub struct Filter {
    /// `excludeFilter://` negates: the rule is skipped when the condition holds.
    pub exclude: bool,
    pub cond: Cond,
}

/// What a [`Filter`] tests.
#[derive(Debug, Clone)]
pub enum Cond {
    /// `m:GET` — request method (case-insensitive).
    Method(String),
    /// `host:example.com` — request host (exact, case-insensitive).
    Host(String),
    /// `h:name[=value]` — request header presence or exact value.
    Header { name: String, value: Option<String> },
    /// `i:1.2.3.4` — client IP.
    ClientIp(String),
    /// Fallback: a regex tested against the full request URL.
    Url(Regex),
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

/// Strip a `#`/`//` line comment (outside of the value) — whistle's
/// `removeComment` (simplified: honours a leading `#`).
fn remove_comment(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return "";
    }
    line
}

/// Parse whole rules text into a list of [`Rule`]s.
/// Mirrors `parseText` in `_original/lib/rules/rules.js:1738`.
pub fn parse_text(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = remove_comment(raw_line);
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            // A lone token isn't a rule (whistle needs pattern + ≥1 operator).
            continue;
        }
        if let Some(rule) = parse_line(&tokens, raw_line) {
            out.push(rule);
        }
    }
    out
}

/// Parse a single tokenised line into a [`Rule`].
fn parse_line(tokens: &[&str], raw_line: &str) -> Option<Rule> {
    // whistle also supports "operators first, then patterns"; we detect the
    // common case: the first token is the pattern, the rest are operators.
    // If the *first* token carries a protocol and later tokens look like
    // patterns, we swap (the reversed form).
    let (pattern_tok, op_toks): (&str, Vec<&str>) = if looks_like_pattern(tokens[0]) {
        (tokens[0], tokens[1..].to_vec())
    } else if let Some(pat) = tokens[1..].iter().find(|t| looks_like_pattern(t)) {
        // Reversed form: gather ops (everything that isn't a pattern) and use
        // the first pattern found. Keeps behaviour close to the original's
        // `indexOfPattern` handling without its full generality.
        let ops: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|t| !looks_like_pattern(t))
            .collect();
        (*pat, ops)
    } else {
        (tokens[0], tokens[1..].to_vec())
    };

    let important = pattern_tok.starts_with('$');
    let pattern = parse_pattern(pattern_tok)?;

    // Separate line properties, filter conditions and ordinary operators.
    let mut props = LineProps::default();
    let mut ops: Vec<RuleOp> = Vec::new();
    let mut filters: Vec<Filter> = Vec::new();
    for t in &op_toks {
        if let Some(spec) = line_props_spec(t) {
            props.merge(spec);
        } else if let Some(f) = parse_filter(t) {
            filters.push(f);
        } else if let Some(op) = parse_op(t) {
            ops.push(op);
        }
    }
    // `lineProps` is a modifier, not an operator: a line carrying nothing else
    // configures nothing (the original drops it the same way).
    if ops.is_empty() && filters.is_empty() {
        return None;
    }
    for op in &mut ops {
        op.props = props.clone();
    }
    Some(Rule {
        pattern,
        ops,
        raw_line: raw_line.to_string(),
        important,
        filters,
        props,
    })
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

/// Parse a `filter://` / `includeFilter://` / `excludeFilter://` token.
fn parse_filter(tok: &str) -> Option<Filter> {
    let (proto, spec) = split_protocol(tok)?;
    let exclude = match proto {
        "filter" | "includeFilter" => false,
        "excludeFilter" => true,
        _ => return None,
    };
    let cond = if let Some(v) = spec.strip_prefix("m:").or_else(|| spec.strip_prefix("method:")) {
        Cond::Method(v.to_string())
    } else if let Some(v) = spec.strip_prefix("host:") {
        Cond::Host(v.to_lowercase())
    } else if let Some(v) = spec
        .strip_prefix("i:")
        .or_else(|| spec.strip_prefix("ip:"))
        .or_else(|| spec.strip_prefix("clientIp:"))
    {
        Cond::ClientIp(v.to_string())
    } else if let Some(v) = spec.strip_prefix("h:").or_else(|| spec.strip_prefix("header:")) {
        let (name, value) = match v.split_once('=') {
            Some((n, val)) => (n.to_lowercase(), Some(val.to_string())),
            None => (v.to_lowercase(), None),
        };
        Cond::Header { name, value }
    } else {
        // Fallback: treat as a regex over the full URL.
        let body = spec.trim_matches('/');
        match Regex::new(body) {
            Ok(re) => Cond::Url(re),
            Err(_) => return None,
        }
    };
    Some(Filter { exclude, cond })
}

/// Heuristic: does this token read as a match pattern (vs. an operator)?
fn looks_like_pattern(tok: &str) -> bool {
    let t = tok.strip_prefix('$').unwrap_or(tok);
    if t.starts_with('/') {
        return true; // regexp
    }
    // A line-property token is neither pattern nor operator; classifying it as a
    // pattern would hijack the reversed (operators-first) form.
    if line_props_spec(t).is_some() {
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

/// Parse a pattern token into a [`Pattern`].
fn parse_pattern(tok: &str) -> Option<Pattern> {
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
                    return Some(Pattern::Regex(re));
                }
            }
        }
    }

    // Wildcard pattern → regex.
    if tok.contains('*') {
        let re = wildcard_to_regex(tok);
        if let Ok(re) = Regex::new(&re) {
            return Some(Pattern::Regex(re));
        }
    }

    // Scheme/host/path prefix.
    Some(parse_prefix(tok))
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
    // Strip an explicit port from the host part for matching purposes.
    let host_no_port = host_part.rsplit_once(':').map_or(host_part, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host_part
        }
    });
    let (host_suffix, host) = if let Some(stripped) = host_no_port.strip_prefix('.') {
        (true, stripped.to_lowercase())
    } else {
        (false, host_no_port.to_lowercase())
    };
    if host.is_empty() && path.is_empty() && scheme.is_none() {
        return Pattern::Any;
    }
    Pattern::Prefix {
        scheme,
        host,
        host_suffix,
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
