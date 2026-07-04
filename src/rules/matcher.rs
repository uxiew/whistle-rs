//! Match resolution — decide which rules apply to a request and pick the
//! winning operator per protocol.
//!
//! Ported from the resolution walk in `_original/lib/rules/rules.js`
//! (`resolveRules`/`resolveReqRules`). whistle's precedence rules are intricate;
//! we implement the widely-relied-on core:
//!
//! * rules are considered top-to-bottom
//! * `important` (`$`-prefixed) rules take precedence over normal ones
//! * single-value protocols use first-match-wins (respecting importance)
//! * multi-match protocols accumulate every matching value in order

use super::{Pattern, ReqInfo, Resolved, Rule, protocols};

/// Does `rule`'s pattern match `req`?
pub fn matches(rule: &Rule, req: &ReqInfo) -> bool {
    match &rule.pattern {
        Pattern::Any => true,
        Pattern::Regex(re) => re.is_match(&req.full_url),
        Pattern::Prefix {
            scheme,
            host,
            host_suffix,
            path,
        } => {
            if let Some(s) = scheme {
                if !scheme_matches(s, &req.scheme) {
                    return false;
                }
            }
            if !host.is_empty() {
                if *host_suffix {
                    // `.example.com` matches the domain and any subdomain.
                    if req.host != *host && !req.host.ends_with(&format!(".{host}")) {
                        return false;
                    }
                } else if req.host != *host {
                    return false;
                }
            }
            if !path.is_empty() && !req.path.starts_with(path.as_str()) {
                return false;
            }
            true
        }
    }
}

/// whistle treats `http`/`https`/`ws`/`wss`/`tunnel` with some equivalence.
fn scheme_matches(pat: &str, req: &str) -> bool {
    if pat == req {
        return true;
    }
    // ws rules also apply to their http transport and vice-versa is not implied;
    // keep this conservative: exact, plus http<->ws family upgrades.
    matches!(
        (pat, req),
        ("http", "ws") | ("https", "wss") | ("ws", "http") | ("wss", "https")
    )
}

/// Walk all rules and build the [`Resolved`] set for `req`.
pub fn resolve(rules: &[Rule], req: &ReqInfo) -> Resolved {
    let mut resolved = Resolved::default();

    // Two passes so important rules win: first important, then normal. Within a
    // pass we keep first-match order.
    for pass_important in [true, false] {
        for rule in rules.iter().filter(|r| r.important == pass_important) {
            if !matches(rule, req) {
                continue;
            }
            for op in &rule.ops {
                if protocols::is_multi_match(&op.protocol) {
                    resolved
                        .multi
                        .entry(op.protocol.clone())
                        .or_default()
                        .push(op.clone());
                } else {
                    // first-match-wins (importance handled by pass order)
                    resolved
                        .single
                        .entry(op.protocol.clone())
                        .or_insert_with(|| op.clone());
                }
            }
        }
    }

    apply_ignores(&mut resolved);
    resolved
}

/// `ignore://<proto>[,<proto>…]` removes those protocols from the resolved set;
/// `ignore://all` clears everything. Ported from whistle's `ignore` handling.
fn apply_ignores(resolved: &mut Resolved) {
    let ignores = resolved.multi.remove("ignore").unwrap_or_default();
    for op in ignores {
        for name in op.value.split(['|', ',', ' ']) {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if name == "all" {
                resolved.single.clear();
                resolved.multi.clear();
                return;
            }
            resolved.single.remove(name);
            resolved.multi.remove(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_text;

    fn req(url: &str) -> ReqInfo {
        // Minimal URL splitter for tests.
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
            host: host.to_lowercase(),
            port,
            path,
            full_url: url.to_string(),
        }
    }

    #[test]
    fn hosts_shorthand_maps_host() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("www.example.com 127.0.0.1:8080\n");
        let r = m.resolve(&req("http://www.example.com/api"));
        assert_eq!(r.value("host"), Some("127.0.0.1:8080"));
        // Different host should not match.
        let r2 = m.resolve(&req("http://other.com/api"));
        assert!(r2.value("host").is_none());
    }

    #[test]
    fn explicit_host_operator() {
        let rules = parse_text("example.com host://10.0.0.1:9000\n");
        assert_eq!(rules.len(), 1);
        let m = {
            let mut mm = crate::rules::RuleManager::new();
            mm.set_text("example.com host://10.0.0.1:9000\n");
            mm
        };
        let r = m.resolve(&req("https://example.com/"));
        assert_eq!(r.value("host"), Some("10.0.0.1:9000"));
    }

    #[test]
    fn regex_pattern_matches_url() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("/\\.js$/ resType://application/javascript\n");
        let r = m.resolve(&req("http://cdn.test.com/app.js"));
        assert_eq!(r.value("resType"), Some("application/javascript"));
        let r2 = m.resolve(&req("http://cdn.test.com/app.css"));
        assert!(r2.value("resType").is_none());
    }

    #[test]
    fn wildcard_pattern() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("*.example.com/api/* redirect://https://api.internal/\n");
        let r = m.resolve(&req("http://a.example.com/api/users"));
        assert_eq!(r.value("redirect"), Some("https://api.internal/"));
    }

    #[test]
    fn multi_match_headers_accumulate() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text(
            "example.com reqHeaders://x-a=1\nexample.com reqHeaders://x-b=2\n",
        );
        let r = m.resolve(&req("http://example.com/"));
        assert_eq!(r.all("reqHeaders").len(), 2);
    }

    #[test]
    fn important_rule_wins() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1\n$example.com host://2.2.2.2\n");
        let r = m.resolve(&req("http://example.com/"));
        assert_eq!(r.value("host"), Some("2.2.2.2"));
    }

    #[test]
    fn ignore_drops_protocol() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.2.3.4\nexample.com ignore://host\n");
        let r = m.resolve(&req("http://example.com/"));
        assert!(r.value("host").is_none());
    }

    #[test]
    fn ignore_all_clears_everything() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.2.3.4\nexample.com resHeaders://x=1\nexample.com ignore://all\n");
        let r = m.resolve(&req("http://example.com/"));
        assert!(r.value("host").is_none());
        assert!(r.all("resHeaders").is_empty());
    }

    #[test]
    fn host_suffix_pattern() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text(".example.com host://5.5.5.5\n");
        let r = m.resolve(&req("http://foo.example.com/"));
        assert_eq!(r.value("host"), Some("5.5.5.5"));
        let r2 = m.resolve(&req("http://example.com/"));
        assert_eq!(r2.value("host"), Some("5.5.5.5"));
    }
}
