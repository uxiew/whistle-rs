//! whistle rules engine (parse + match + resolve).
//!
//! Ported from `_original/lib/rules/`. The original is ~9k lines with an
//! enormous surface of edge cases; this port implements the load-bearing core:
//!
//! * line parsing: `pattern op1 op2 …` (comments, blank lines, shorthands)
//! * pattern kinds: regexp (`/re/i`), wildcard (`*`), and scheme/host/path
//!   prefix matching
//! * operator parsing for the full protocol set (see [`protocols`])
//! * per-request resolution with first-match-wins (and multi-match for the
//!   protocols whistle allows to repeat)
//!
//! What is intentionally simplified vs. the original is documented inline and in
//! the project README.

pub mod matcher;
pub mod protocols;

use regex::Regex;
use std::collections::HashMap;

/// One resolved operator on a rule line, e.g. `host://127.0.0.1:8080`.
#[derive(Debug, Clone)]
pub struct RuleOp {
    /// Protocol name (`host`, `resHeaders`, `redirect`, …).
    pub protocol: String,
    /// Value after `protocol://` (or the shorthand's implied value).
    pub value: String,
    /// The original token as written, for diagnostics.
    pub raw: String,
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
}

/// Parsed request facts the matcher needs. Built by the proxy layer.
#[derive(Debug, Clone)]
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
}

/// Holds every parsed rule and answers match queries.
#[derive(Debug, Default)]
pub struct RuleManager {
    rules: Vec<Rule>,
}

impl RuleManager {
    pub fn new() -> Self {
        RuleManager { rules: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Replace all rules with those parsed from `text` (whistle rules DSL).
    pub fn set_text(&mut self, text: &str) {
        self.rules = parse_text(text);
    }

    /// Append rules parsed from `text`.
    pub fn append_text(&mut self, text: &str) {
        self.rules.extend(parse_text(text));
    }

    /// Resolve the winning operators for a request. See [`matcher`].
    pub fn resolve(&self, req: &ReqInfo) -> Resolved {
        matcher::resolve(&self.rules, req)
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
    let ops: Vec<RuleOp> = op_toks.iter().filter_map(|t| parse_op(t)).collect();
    if ops.is_empty() {
        return None;
    }
    Some(Rule {
        pattern,
        ops,
        raw_line: raw_line.to_string(),
        important,
    })
}

/// Heuristic: does this token read as a match pattern (vs. an operator)?
fn looks_like_pattern(tok: &str) -> bool {
    let t = tok.strip_prefix('$').unwrap_or(tok);
    if t.starts_with('/') {
        return true; // regexp
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
fn parse_op(tok: &str) -> Option<RuleOp> {
    if let Some((proto, rest)) = split_protocol(tok) {
        if protocols::is_protocol(proto) {
            return Some(RuleOp {
                protocol: proto.to_string(),
                value: rest.to_string(),
                raw: tok.to_string(),
            });
        }
        // Unknown scheme (e.g. a plain proxy target) — treat as a proxy URL.
        return Some(RuleOp {
            protocol: proto.to_string(),
            value: rest.to_string(),
            raw: tok.to_string(),
        });
    }
    if is_host_shorthand(tok) {
        return Some(RuleOp {
            protocol: "host".to_string(),
            value: tok.to_string(),
            raw: tok.to_string(),
        });
    }
    // Bare path / file shorthand → file operator.
    if tok.starts_with('/') || tok.starts_with('~') || tok.starts_with('.') {
        return Some(RuleOp {
            protocol: "file".to_string(),
            value: tok.to_string(),
            raw: tok.to_string(),
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
