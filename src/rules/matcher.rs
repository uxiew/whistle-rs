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

use super::{Cond, Filter, Pattern, ReqInfo, Resolved, Rule, protocols};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Does `rule`'s pattern (and all its filter conditions) match `req`?
pub fn matches(rule: &Rule, req: &ReqInfo) -> bool {
    if !pattern_matches(rule, req) {
        return false;
    }
    filters_match(&rule.filters, req)
}

/// Does the rule's pattern accept `req`? `!`-prefixed patterns invert the
/// answer — and only the pattern's: whistle applies `not` to the pattern test
/// alone, leaving the filter conditions to hold as written
/// (`_original/lib/rules/rules.js:994-998`).
fn pattern_matches(rule: &Rule, req: &ReqInfo) -> bool {
    pattern_accepts(&rule.pattern, req) != rule.negate
}

fn pattern_accepts(pattern: &Pattern, req: &ReqInfo) -> bool {
    match pattern {
        Pattern::Any => true,
        Pattern::Regex(re) => re.is_match(&req.full_url),
        Pattern::Prefix {
            scheme,
            host,
            host_suffix,
            port,
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
            // An explicit port in the pattern scopes the rule to it.
            if let Some(p) = port {
                if req.port != *p {
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

/// Do a rule's filter conditions let `req` through?
///
/// Ported from `matchExcludeFilters` (`_original/lib/rules/rules.js:1967-1991`),
/// whose final `hasIncludeFilter ? !include || exclude : exclude` says:
///
/// * include filters are **or**-ed — one of them holding is enough, which is
///   what upstream's docs mean by "多个过滤器间为「或」匹配"
///   (`_original/docs/docs/rules/filters.md:8`);
/// * a single matching exclude filter vetoes the rule, whatever the includes
///   decided;
/// * a rule with only exclude filters applies unless one of them holds.
///
/// Once either verdict is settled the remaining filters of that kind are not
/// evaluated — upstream guards its loop the same way, which matters for a
/// `chance:` filter: it must draw no more random numbers than upstream does.
fn filters_match(filters: &[Filter], req: &ReqInfo) -> bool {
    let mut has_include = false;
    let (mut include, mut exclude) = (false, false);
    for f in filters {
        if f.exclude {
            exclude = exclude || filter_holds(f, req);
        } else {
            has_include = true;
            include = include || filter_holds(f, req);
        }
    }
    if has_include && !include {
        return false;
    }
    !exclude
}

/// One filter's verdict.
///
/// `!` inverts a *known* answer only: upstream's `getFilterResult`
/// (`_original/lib/rules/rules.js:1809`) returns `false` for an unknown one
/// before it ever consults `not`. So a condition this port cannot evaluate
/// leaves an include filter unsatisfied *and* an exclude filter inert, however
/// it is written — the subsystem fails closed in both directions.
fn filter_holds(f: &Filter, req: &ReqInfo) -> bool {
    match cond_holds(&f.cond, req) {
        Some(held) => held != f.negate,
        None => false,
    }
}

/// Evaluate one condition. `None` means "not knowable while rules are being
/// resolved" — the request has not been sent yet.
fn cond_holds(cond: &Cond, req: &ReqInfo) -> Option<bool> {
    match cond {
        Cond::Method(v) => Some(v.matches(&req.method)),
        Cond::Host(v) => Some(v.matches(&req.host)),
        Cond::Url(p) => Some(pattern_accepts(p, req)),
        // An absent header is a known `false` (so `reqH.x-tag!:v` holds for a
        // request without the header), unlike an unknowable fact.
        Cond::ReqHeader { name, value } => Some(
            req.headers
                .iter()
                .any(|(n, v)| n == name && value.matches_header(v)),
        ),
        // whistle checks the client IP and then the server IP, but the server
        // IP is only known once the connection is made — at rule-resolution
        // time both implementations have the client's alone
        // (`_original/lib/rules/rules.js:1875-1880`).
        Cond::Ip(v) | Cond::ClientIp(v) => req.client_ip.as_deref().map(|ip| v.matches(ip)),
        Cond::Chance(p) => Some(random_unit() < *p),
        Cond::Deferred(_) => None,
    }
}

/// A uniform draw from `[0, 1)`, whistle's `Math.random()` for `chance:`.
///
/// Sampling needs to be cheap and roughly uniform, not unpredictable, so this
/// is a xorshift64 kept in a global rather than a new dependency. Two threads
/// racing on it can draw the same number; for sampling that is harmless, and
/// avoiding a lock keeps the matcher allocation- and contention-free.
fn random_unit() -> f64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        // Seed on first use; the fallback is the golden-ratio constant, which
        // only matters if the clock is unreadable.
        x = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    // Top 53 bits → the same resolution as a JS double in [0, 1).
    (x >> 11) as f64 / (1u64 << 53) as f64
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
    let refs: Vec<&Rule> = rules.iter().collect();
    resolve_refs(&refs, req)
}

/// Like [`resolve`] but takes borrowed rule references (for cross-group resolution).
///
/// Treats the request as client-originated; see [`resolve_refs_scoped`] when the
/// origin is known.
pub fn resolve_refs(rules: &[&Rule], req: &ReqInfo) -> Resolved {
    resolve_refs_scoped(rules, req, false)
}

/// Like [`resolve_refs`], but aware of whether whistle itself issued the request,
/// so the `internal` / `internalOnly` line properties can gate an entire rule
/// line out of consideration.
///
/// This is the one line property that affects *matching* rather than the effect
/// of an operator. Ported from `checkInternal`
/// (`_original/lib/rules/rules.js:910`), which — unlike what the upstream docs
/// suggest — is evaluated in the main scan loop for every protocol, not just the
/// proxy family.
pub fn resolve_refs_scoped(rules: &[&Rule], req: &ReqInfo, is_internal_req: bool) -> Resolved {
    let mut resolved = Resolved::default();

    // Two passes so important rules win: first important, then normal. Within a
    // pass we keep first-match order. `is_important` folds `lineProps://important`
    // in with this port's `$`-prefix shorthand.
    for pass_important in [true, false] {
        for rule in rules.iter().filter(|r| r.is_important() == pass_important) {
            if !rule.props.allows_scope(is_internal_req) || !matches(rule, req) {
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
            ..Default::default()
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
    fn alias_protocols_normalise_to_canonical() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text(
            "a.com hosts://10.0.0.1:9000\n\
             b.com html://<!--x-->\n\
             c.com status://404\n\
             d.com download://f.bin\n\
             e.com tlsOptions://TLSv1.2\n\
             f.com resType://text/plain skip://resType\n\
             g.com pathReplace://a=b\n\
             h.com reqMerge://k=v\n",
        );
        assert_eq!(m.resolve(&req("http://a.com/")).value("host"), Some("10.0.0.1:9000"));
        assert_eq!(m.resolve(&req("http://b.com/")).value("htmlAppend"), Some("<!--x-->"));
        assert_eq!(m.resolve(&req("http://c.com/")).value("statusCode"), Some("404"));
        assert_eq!(m.resolve(&req("http://d.com/")).value("attachment"), Some("f.bin"));
        assert_eq!(m.resolve(&req("http://e.com/")).value("cipher"), Some("TLSv1.2"));
        // `skip` is an alias of `ignore`: it should drop the resType operator.
        assert_eq!(m.resolve(&req("http://f.com/")).value("resType"), None);
        assert_eq!(m.resolve(&req("http://g.com/")).value("urlReplace"), Some("a=b"));
        // `params` is multi-match, so it accumulates in the list.
        let h = m.resolve(&req("http://h.com/"));
        assert!(h.all("params").iter().any(|o| o.value == "k=v"));
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
    fn filter_method_include() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1 includeFilter://m:POST\n");
        let mut r = req("http://example.com/");
        assert!(m.resolve(&r).value("host").is_none()); // GET
        r.method = "POST".into();
        assert!(m.resolve(&r).value("host").is_some());
    }

    #[test]
    fn exclude_filter_method() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1 excludeFilter://m:GET\n");
        let r = req("http://example.com/"); // GET => excluded
        assert!(m.resolve(&r).value("host").is_none());
    }

    #[test]
    fn header_filter() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1 includeFilter://h:x-env=prod\n");
        let mut r = req("http://example.com/");
        assert!(m.resolve(&r).value("host").is_none());
        r.headers.push(("x-env".into(), "prod".into()));
        assert!(m.resolve(&r).value("host").is_some());
    }

    #[test]
    fn client_ip_filter() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1 includeFilter://i:10.0.0.5\n");
        let mut r = req("http://example.com/");
        assert!(m.resolve(&r).value("host").is_none());
        r.client_ip = Some("10.0.0.5".into());
        assert!(m.resolve(&r).value("host").is_some());
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
    fn url_scheme_pattern_not_treated_as_operator() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("http://example.com/api host://1.1.1.1\n");
        assert_eq!(m.len(), 1);
        let r = m.resolve(&req("http://example.com/api/x"));
        assert_eq!(r.value("host"), Some("1.1.1.1"));
        // https request should not match an http:// pattern
        let r2 = m.resolve(&req("https://example.com/api/x"));
        assert!(r2.value("host").is_none());
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

#[cfg(test)]
mod filter_tests {
    use super::*;
    use crate::rules::RuleManager;

    /// A GET request the tests decorate with headers or a client IP.
    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
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
            ..Default::default()
        }
    }

    /// Does a rule carrying `token` apply to `req`?
    fn hits(token: &str, req: &ReqInfo) -> bool {
        let mut mgr = RuleManager::new();
        mgr.set_text(&format!("example.com host://1.1.1.1 {token}\n"));
        mgr.resolve(req).value("host").is_some()
    }

    /// Does a rule carrying every one of `tokens` apply to `req`?
    fn hits_all(tokens: &[&str], req: &ReqInfo) -> bool {
        let mut mgr = RuleManager::new();
        mgr.set_text(&format!("example.com host://1.1.1.1 {}\n", tokens.join(" ")));
        mgr.resolve(req).value("host").is_some()
    }

    fn with_header(url: &str, name: &str, value: &str) -> ReqInfo {
        let mut r = req(url);
        r.headers.push((name.into(), value.into()));
        r
    }

    // ── request headers ──

    /// The gap this work closed: upstream's own spelling used to fall through
    /// to the URL-regex fallback and silently never match.
    #[test]
    fn upstream_header_spelling_matches() {
        let tagged = with_header("http://example.com/", "x-tag", "yes");
        assert!(hits("includeFilter://reqH.x-tag:yes", &tagged));
        assert!(!hits("includeFilter://reqH.x-tag:no", &tagged));
        assert!(!hits("includeFilter://reqH.x-other:yes", &tagged));
        // …and the spelling this port already had keeps working.
        assert!(hits("includeFilter://h:x-tag=yes", &tagged));
    }

    /// Header values are matched by *containment*, case-insensitively — which
    /// is what makes upstream's own `reqH.content-type:json` example work.
    #[test]
    fn header_values_match_by_containment() {
        let json = with_header("http://example.com/", "content-type", "application/JSON; charset=utf-8");
        assert!(hits("includeFilter://reqH.content-type:json", &json));
        assert!(!hits("includeFilter://reqH.content-type:xml", &json));
    }

    /// A header condition without a value is a presence test.
    #[test]
    fn header_presence() {
        let tagged = with_header("http://example.com/", "x-tag", "");
        assert!(hits("includeFilter://reqH.x-tag", &tagged));
        assert!(!hits("includeFilter://reqH.x-tag", &req("http://example.com/")));
    }

    /// A regexp value anchors what containment cannot.
    #[test]
    fn header_regexp_value() {
        let tagged = with_header("http://example.com/", "x-tag", "yes-please");
        assert!(hits("includeFilter://reqH.x-tag:/^yes/", &tagged));
        assert!(!hits("includeFilter://reqH.x-tag:/^please/", &tagged));
        assert!(hits("includeFilter://reqH.x-tag:/^YES/i", &tagged));
    }

    /// `!` after the key inverts, and an absent header is a *known* false — so
    /// the negated condition holds for a request without the header.
    #[test]
    fn negated_header() {
        let token = "includeFilter://reqH.x-tag!:yes";
        assert!(!hits(token, &with_header("http://example.com/", "x-tag", "yes")));
        assert!(hits(token, &with_header("http://example.com/", "x-tag", "no")));
        assert!(hits(token, &req("http://example.com/")));
    }

    /// `excludeFilter://` skips the rule when the condition holds.
    #[test]
    fn exclude_on_a_header() {
        let token = "excludeFilter://reqH.x-tag:yes";
        assert!(!hits(token, &with_header("http://example.com/", "x-tag", "yes")));
        assert!(hits(token, &req("http://example.com/")));
    }

    /// Repeated headers are all considered; upstream sees node's joined value.
    #[test]
    fn any_of_a_repeated_header_may_match() {
        let mut r = with_header("http://example.com/", "x-tag", "alpha");
        r.headers.push(("x-tag".into(), "beta".into()));
        assert!(hits("includeFilter://reqH.x-tag:beta", &r));
        assert!(hits("includeFilter://reqH.x-tag:alpha", &r));
        assert!(!hits("includeFilter://reqH.x-tag:gamma", &r));
    }

    /// The key runs up to the first `=`, and only then to a `:` — upstream's
    /// order, which is why a value containing `=` needs the colon spelling to
    /// be written last.
    #[test]
    fn key_split_prefers_equals() {
        let r = with_header("http://example.com/", "cookie", "b=2");
        assert!(!hits("includeFilter://reqH.cookie:b=2", &r), "key is `cookie:b`");
        assert!(hits("includeFilter://reqH.cookie=b=2", &r));
    }

    // ── method / host ──

    #[test]
    fn method_regexp() {
        let mut post = req("http://example.com/");
        post.method = "POST".into();
        assert!(hits("includeFilter://m:/^P/", &post));
        assert!(!hits("includeFilter://m:/^P/", &req("http://example.com/")));
        // Method regexps ignore case even without the flag.
        assert!(hits("includeFilter://m:/^post$/", &post));
    }

    #[test]
    fn negated_method() {
        assert!(!hits("includeFilter://m:!GET", &req("http://example.com/")));
        let mut post = req("http://example.com/");
        post.method = "POST".into();
        assert!(hits("includeFilter://m:!GET", &post));
    }

    #[test]
    fn host_condition() {
        let r = req("http://example.com/");
        assert!(hits("includeFilter://host:example.com", &r));
        assert!(hits("includeFilter://host:/^EXAMPLE\\./i", &r));
        assert!(!hits("includeFilter://host:other.com", &r));
    }

    // ── IPs ──

    /// `i:` and `clientIp:` both test the client's IP; with no IP known the
    /// condition is unanswerable, and fails closed.
    #[test]
    fn ip_conditions() {
        let mut r = req("http://example.com/");
        assert!(!hits("includeFilter://i:10.0.0.5", &r), "unknown IP must fail closed");
        assert!(!hits("includeFilter://i:!10.0.0.5", &r), "…even negated");

        r.client_ip = Some("10.0.0.5".into());
        assert!(hits("includeFilter://i:10.0.0.5", &r));
        assert!(hits("includeFilter://clientIp:10.0.0.5", &r));
        assert!(hits("includeFilter://clientIp=10.0.0.5", &r));
        assert!(hits("includeFilter://i:/^10\\./", &r));
        assert!(!hits("includeFilter://i:10.0.0.6", &r));
        // A literal that is not an IP simply never equals one.
        assert!(!hits("includeFilter://i:localhost", &r));
    }

    // ── chance ──

    /// Only the boundaries are deterministic, so only they are asserted:
    /// `Math.random() < 0` is never true and `Math.random() < 1` always is.
    #[test]
    fn chance_boundaries() {
        let r = req("http://example.com/");
        for _ in 0..200 {
            assert!(!hits("includeFilter://chance:0", &r));
            assert!(hits("includeFilter://chance:1", &r));
            assert!(hits("includeFilter://chance:100%", &r));
            // A probability that is not a number never samples anything.
            assert!(!hits("includeFilter://chance:half", &r));
        }
    }

    /// An `excludeFilter://chance:1` excludes every request, and a negated
    /// `chance:0` holds for every one.
    #[test]
    fn chance_respects_exclude_and_negation() {
        let r = req("http://example.com/");
        for _ in 0..50 {
            assert!(!hits("excludeFilter://chance:1", &r));
            assert!(hits("includeFilter://chance:!0", &r));
        }
    }

    /// The sampler stays inside `[0, 1)` and does not get stuck.
    #[test]
    fn random_unit_is_in_range_and_varies() {
        let draws: Vec<f64> = (0..1000).map(|_| random_unit()).collect();
        assert!(draws.iter().all(|&x| (0.0..1.0).contains(&x)));
        assert!(draws.windows(2).any(|w| w[0] != w[1]));
    }

    // ── conditions that cannot be answered yet ──

    /// Everything the response phase would decide fails closed: an include
    /// filter is never satisfied, and an exclude filter never fires — however
    /// it is written.
    #[test]
    fn deferred_conditions_fail_closed() {
        let r = with_header("http://example.com/", "x-tag", "yes");
        for cond in [
            "s:200",
            "statusCode:/^2/",
            "b:keyword",
            "env:x=1",
            "from:composer",
            "clientPort:8080",
            "serverPort:8080",
            "remoteAddress:1.2.3.4",
            "remotePort:80",
        ] {
            assert!(!hits(&format!("includeFilter://{cond}"), &r), "include {cond}");
            assert!(
                hits(&format!("excludeFilter://{cond}"), &r),
                "exclude {cond} must not fire"
            );
        }
        for cond in ["resH.content-type:json", "serverIp:1.2.3.4"] {
            assert!(!hits(&format!("includeFilter://{cond}"), &r), "include {cond}");
            assert!(
                hits(&format!("excludeFilter://{cond}"), &r),
                "exclude {cond} must not fire"
            );
        }
        // Negation cannot rescue an unknown answer: upstream's
        // `getFilterResult` returns `false` before it consults `not`.
        assert!(!hits("includeFilter://s:!200", &r));
        assert!(!hits("includeFilter://serverIp:!1.2.3.4", &r));
        assert!(hits("excludeFilter://s:!200", &r));
    }

    // ── combining filters ──

    /// Include filters are or-ed, per `matchExcludeFilters`
    /// (`_original/lib/rules/rules.js:1988`) and upstream's own documentation.
    #[test]
    fn include_filters_are_ored() {
        let tagged = with_header("http://example.com/", "x-tag", "yes");
        assert!(hits_all(
            &["includeFilter://reqH.x-tag:yes", "includeFilter://m:POST"],
            &tagged
        ));
        assert!(!hits_all(
            &["includeFilter://reqH.x-tag:no", "includeFilter://m:POST"],
            &tagged
        ));
    }

    /// `filter://` **excludes**, like `excludeFilter://` — `isInclude` is true
    /// for i**n**cludeFilter alone (`_original/lib/rules/rules.js:1563`).
    /// Reading it as an include did not make a whistle rules file fail, it made
    /// it do the opposite of what it asked.
    #[test]
    fn plain_filter_excludes() {
        let mut post = req("http://example.com/");
        post.method = "POST".into();
        assert!(!hits("filter://m:POST", &post), "POST is filtered out");
        assert!(hits("filter://m:POST", &req("http://example.com/")), "GET is not");

        let tagged = with_header("http://example.com/", "x-tag", "yes");
        assert!(!hits("filter://reqH:x-tag=yes", &tagged));
        assert!(hits("filter://reqH:x-tag=yes", &req("http://example.com/")));
    }

    /// `ignore://<condition>` excludes the same way; `ignore://<protocol>` is
    /// untouched and still drops that protocol from the resolved set.
    #[test]
    fn ignore_with_a_condition_excludes() {
        let mut post = req("http://example.com/");
        post.method = "POST".into();
        assert!(!hits("ignore://m:POST", &post));
        assert!(hits("ignore://m:POST", &req("http://example.com/")));

        let mut mgr = RuleManager::new();
        mgr.set_text("example.com host://1.1.1.1\nexample.com ignore://host\n");
        assert!(mgr.resolve(&req("http://example.com/")).value("host").is_none());
    }

    /// A matching exclude filter vetoes the rule even when an include matched.
    #[test]
    fn exclude_beats_include() {
        let tagged = with_header("http://example.com/", "x-tag", "yes");
        assert!(!hits_all(
            &["includeFilter://reqH.x-tag:yes", "excludeFilter://m:GET"],
            &tagged
        ));
    }

    // ── URL-pattern fallback ──

    /// A filter that is not a condition is a URL pattern, matched with the
    /// same engine as a rule's own pattern.
    #[test]
    fn url_pattern_filters() {
        let cgi = req("http://example.com/cgi-bin/x");
        assert!(hits("includeFilter://*/cgi-*", &cgi));
        assert!(!hits("includeFilter://*/cgi-*", &req("http://example.com/api")));
        assert!(hits("includeFilter:///cgi-bin/", &cgi));
        assert!(hits("excludeFilter://other.com", &cgi));
        assert!(!hits("excludeFilter://example.com", &cgi));
        // `!` inverts a URL pattern, which a rule's own pattern cannot do.
        assert!(hits("includeFilter://!other.com", &cgi));
        assert!(!hits("includeFilter://!example.com", &cgi));
    }
}
