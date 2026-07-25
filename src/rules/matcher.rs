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

use super::{
    Cond, CondValue, Filter, HeaderScope, Pattern, ReqInfo, Resolved, Rule, RuleOp, order_key,
    protocols,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Does `rule`'s pattern (and all its filter conditions) match `req`?
pub fn matches(rule: &Rule, req: &ReqInfo) -> bool {
    if !pattern_matches(rule, req) {
        return false;
    }
    filters_match(&rule.filters, req, false)
}

/// Would this rule match if its `b:` conditions were satisfied?
///
/// The question the proxy has to answer *before* it reads the body: is it worth
/// buffering at all. Every other condition is evaluated as usual — a `b:` line
/// scoped to one host, or to `POST`, costs nothing on the requests it excludes —
/// and only the body conditions are assumed true, because assuming them false
/// would mean never buffering and so never being able to answer them.
///
/// Mirrors upstream's `resolveBodyFilter`, which runs `getRule` over the
/// `_bodyFilters` list while `req._reqBody` is still undefined; its body arm
/// returns `false` there, so the same optimism is spelled as skipping the arm
/// (`_original/lib/rules/rules.js:1903-1906,2455-2465`).
pub fn matches_but_for_body(rule: &Rule, req: &ReqInfo, is_internal_req: bool) -> bool {
    rule.props.allows_scope(is_internal_req)
        && pattern_matches(rule, req)
        && filters_match(&rule.filters, req, true)
}

/// Does the rule's pattern accept `req`? `!`-prefixed patterns invert the
/// answer — and only the pattern's: whistle applies `not` to the pattern test
/// alone, leaving the filter conditions to hold as written
/// (`_original/lib/rules/rules.js:994-998`).
fn pattern_matches(rule: &Rule, req: &ReqInfo) -> bool {
    pattern_accepts(&rule.pattern, req) != rule.negate
}

/// `/`, `\` and `?` all end a path segment upstream (`isPathSeparator`,
/// `_original/lib/rules/rules.js:307`).
fn is_path_separator(c: char) -> bool {
    c == '/' || c == '\\' || c == '?'
}

/// Does a prefix match end on a path boundary?
///
/// A bare prefix test would make `example.com/path/to` match
/// `/path/toxxx`, which upstream explicitly rejects — its docs give exactly
/// that case (`docs/docs/rules/pattern.md`, "路径前缀匹配（以 `/` 为边界）").
/// The condition is upstream's, at `_original/lib/rules/rules.js:1091-1097`:
/// the whole path matched, or the next character is a separator, or the
/// pattern itself ended on one.
///
/// A pattern carrying a query is exempt: there the semantics are "same path,
/// query is a prefix", which the plain `starts_with` already gives.
fn path_match_ends_cleanly(pattern_path: &str, req_path: &str) -> bool {
    if pattern_path.contains('?') {
        return true;
    }
    if pattern_path.ends_with(is_path_separator) {
        return true;
    }
    match req_path[pattern_path.len()..].chars().next() {
        None => true,
        Some(c) => is_path_separator(c),
    }
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
            if !path.is_empty() {
                if !req.path.starts_with(path.as_str()) {
                    return false;
                }
                if !path_match_ends_cleanly(path, &req.path) {
                    return false;
                }
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
fn filters_match(filters: &[Filter], req: &ReqInfo, assume_body: bool) -> bool {
    let mut has_include = false;
    let (mut include, mut exclude) = (false, false);
    for f in filters {
        if f.exclude {
            exclude = exclude || filter_holds(f, req, assume_body);
        } else {
            has_include = true;
            include = include || filter_holds(f, req, assume_body);
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
fn filter_holds(f: &Filter, req: &ReqInfo, assume_body: bool) -> bool {
    match cond_holds(&f.cond, req, assume_body) {
        Some(held) => held != f.negate,
        None => false,
    }
}

/// Evaluate one condition. `None` means "not knowable" — either the fact has no
/// equivalent here at all ([`crate::rules::Deferred`]) or it belongs to the
/// response and this is the request phase, where [`ReqInfo::res`] is `None`.
fn cond_holds(cond: &Cond, req: &ReqInfo, assume_body: bool) -> Option<bool> {
    match cond {
        Cond::Method(v) => Some(v.matches(&req.method)),
        Cond::Host(v) => Some(v.matches(&req.host)),
        Cond::Url(p) => Some(pattern_accepts(p, req)),
        Cond::Header { name, value, scope } => header_holds(req, name, value, *scope),
        // whistle documents `i:` as client-or-server, but only ever tests the
        // client's — see [`Cond::Ip`].
        Cond::Ip(v) | Cond::ClientIp(v) => req.client_ip.as_deref().map(|ip| v.matches(ip)),
        // The raw socket's address and port. This port honours no header that
        // overrides the client IP, so `remoteAddress:` and `clientIp:` read the
        // same socket here; upstream separates them only for a request that
        // arrived through another whistle (`lib/init.js:167-187`).
        Cond::RemoteAddress(v) => req.client_ip.as_deref().map(|ip| v.matches(ip)),
        Cond::ClientPort(v) | Cond::RemotePort(v) => {
            req.client_port.map(|p| v.matches(&p.to_string()))
        }
        Cond::Chance(p) => Some(random_unit() < *p),
        // ── response phase ──
        Cond::StatusCode(v) => req.res.as_ref().map(|r| v.matches(&r.status.to_string())),
        // A response whose server address was never known keeps `serverIp:`
        // unanswerable rather than guessing at it.
        Cond::ServerIp(v) => req
            .res
            .as_ref()
            .and_then(|r| r.server_ip.as_deref())
            .map(|ip| v.matches(ip)),
        Cond::ServerPort(v) => req
            .res
            .as_ref()
            .and_then(|r| r.server_port)
            .map(|p| v.matches(&p.to_string())),
        // The body, when it was buffered for exactly this. `assume_body` is the
        // pre-resolution question "would this line want it?", which cannot
        // answer with the body it is asking for.
        Cond::Body(v) => match assume_body {
            true => Some(true),
            false => req.req_body.as_deref().map(|b| v.matches_header(b)),
        },
        // whistle's own process environment (`env = process.env`,
        // `_original/lib/rules/rules.js:14`). A variable that is not set is a
        // *known* `false`, exactly as an absent header is, so `env:X!=v` holds
        // for a process without `X`.
        Cond::Env { name, value } => Some(match std::env::var(name) {
            Ok(actual) => value.matches_header(&actual),
            Err(_) => false,
        }),
        Cond::Deferred(_) => None,
    }
}

/// One header condition, in whichever message its spelling names.
///
/// Ported from `filterHeader` (`_original/lib/rules/rules.js:1917-1946`) and its
/// three call sites (`:1953-1961`). Two details are upstream's and both matter:
///
/// * a header the message does not carry is a *known* `false`, not an unknown —
///   so `reqH.x-tag!:v` holds for a request without the header;
/// * the `h:`/`header:` spelling passes `req.resHeaders` as a fallback, so it
///   reads the response's header when the request has none. In the request
///   phase there are no response headers, which is exactly upstream's state
///   there, and the condition answers "no".
fn header_holds(
    req: &ReqInfo,
    name: &str,
    value: &CondValue,
    scope: HeaderScope,
) -> Option<bool> {
    let res_headers = || req.res.as_ref().map(|r| r.headers.as_slice());
    match scope {
        HeaderScope::Request => Some(header_matches(&req.headers, name, value)),
        // Unknown until the response head is in, so that a rule carrying it is
        // resolved again rather than answered "no" too early.
        HeaderScope::Response => res_headers().map(|h| header_matches(h, name, value)),
        HeaderScope::RequestThenResponse => {
            if req.headers.iter().any(|(n, _)| n == name) {
                return Some(header_matches(&req.headers, name, value));
            }
            match res_headers() {
                Some(h) => Some(header_matches(h, name, value)),
                // The request has no such header; in the request phase that is
                // upstream's known `false` (`value == null` with no
                // `resHeaders`).
                None => Some(false),
            }
        }
    }
}

/// Does any `name` header in `headers` satisfy `value`?
fn header_matches(headers: &[(String, String)], name: &str, value: &CondValue) -> bool {
    headers
        .iter()
        .any(|(n, v)| n == name && value.matches_header(v))
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
    resolve_walk(rules, req, is_internal_req, true)
}

/// Like [`resolve_refs_scoped`] for a rule set that is resolved *once*: nothing
/// is withheld, because no response phase will follow to supply it.
///
/// This is how rules that arrive mid-request are resolved — a plugin's, or a
/// `rule://` / `rulesFile://` include. They are merged into the request's
/// resolved set and then forgotten, so a response-phase operator withheld from
/// them would never come back. Their response conditions fail closed instead,
/// which is where the whole subsystem sat before the response phase existed.
pub fn resolve_refs_once(rules: &[&Rule], req: &ReqInfo, is_internal_req: bool) -> Resolved {
    resolve_walk(rules, req, is_internal_req, false)
}

/// The resolution walk. `defer_res_phase` withholds the operators a second pass
/// will resolve; see [`resolve_response_ops`].
fn resolve_walk(
    rules: &[&Rule],
    req: &ReqInfo,
    is_internal_req: bool,
    defer_res_phase: bool,
) -> Resolved {
    let mut resolved = Resolved::default();

    // Two passes so important rules win: first important, then normal. Within a
    // pass we keep first-match order. `is_important` folds `lineProps://important`
    // in with this port's `$`-prefix shorthand.
    for pass_important in [true, false] {
        for (index, rule) in rules.iter().enumerate() {
            if rule.is_important() != pass_important {
                continue;
            }
            if !rule.props.allows_scope(is_internal_req) || !matches(rule, req) {
                continue;
            }
            // A line whose filters ask about the response has not said anything
            // about the response *yet*. Its response-phase operators are left
            // for [`resolve_response_ops`], which is where upstream decides
            // them too; everything else on the line applies now.
            let defer_res = defer_res_phase && rule.needs_response_phase(req);
            for op in &rule.ops {
                if defer_res && protocols::is_res_phase(&op.protocol) {
                    continue;
                }
                take(&mut resolved, op, order_key(index, pass_important));
            }
        }
    }

    apply_ignores(&mut resolved);
    resolved
}

/// Add `op` to `resolved` under its protocol's arity rule, stamped with `order`.
fn take(resolved: &mut Resolved, op: &RuleOp, order: u64) {
    let mut op = op.clone();
    op.order = order;
    if protocols::is_multi_match(&op.protocol) {
        resolved
            .multi
            .entry(op.protocol.clone())
            .or_default()
            .push(op);
    } else {
        // first-match-wins (importance handled by pass order)
        resolved.single.entry(op.protocol.clone()).or_insert(op);
    }
}

/// Resolve the operators [`resolve_refs_scoped`] withheld, now that `req`
/// carries the response head ([`ReqInfo::res`]).
///
/// This is the second half of upstream's two-phase resolution
/// (`resolveResRules` → `pluginMgr.getResRules`, `_original/lib/rules/rules.js:2306`,
/// `lib/plugins/index.js:1322`), narrowed to what this port actually withheld:
///
/// * only rules whose filters ask about the response are walked — every other
///   rule was resolved completely in the request phase, and walking it again
///   would resolve its operators a second time;
/// * only [`protocols::RES_PHASE_PROTOCOLS`] operators are kept, mirroring
///   `pureResProtocols`, so no rule can change where a request went after it has
///   gone there;
/// * `ignore://` is kept unapplied, because these ignores have to reach the
///   *request* phase's operators as well — see
///   [`Resolved::apply_response_ignores`].
///
/// `candidates` are the rules that withheld something, each with the
/// [`order_key`] of its line, in ascending key order — that is, the order the
/// request pass would have visited them in. [`crate::rules::RuleManager::resolve_response`]
/// selects them; the selection is the pass's whole cost when nothing matches.
pub fn resolve_response_ops(
    candidates: &[(u64, &Rule)],
    req: &ReqInfo,
    is_internal_req: bool,
) -> Resolved {
    let mut resolved = Resolved::default();
    for (order, rule) in candidates {
        if !rule.props.allows_scope(is_internal_req) || !matches(rule, req) {
            continue;
        }
        for op in &rule.ops {
            if protocols::is_res_phase(&op.protocol) || op.protocol == "ignore" {
                take(&mut resolved, op, *order);
            }
        }
    }
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
            // `xproxy`/`xsocks`/… name the same operator as their base spelling
            // once `canonical` has folded them, so an ignore has to be folded
            // the same way to find the key it means.
            let name = protocols::canonical(name).unwrap_or(name);
            if name == "proxy" {
                ignore_upstream_proxies(resolved);
                continue;
            }
            resolved.single.remove(name);
            resolved.multi.remove(name);
        }
    }
}

/// `ignore://proxy` drops **every** upstream-proxy operator, not only the one
/// literally spelled `proxy://`.
///
/// whistle needs no such loop because all nine spellings share a single
/// protocol key, so `util.isIgnored(filter, 'proxy')` sees whichever one matched
/// (`resolveProxy`, `_original/lib/rules/rules.js:2419-2443`; see
/// [`protocols::UPSTREAM_PROXY_PROTOCOLS`]). Naming one spelling still drops
/// only that one, which needs no special case here: the key is the name.
///
/// Dropping a proxy that matched takes the PAC fallback with it. whistle returns
/// before it would consult `resolvePacRule()` when `ignoreProxy` is set
/// (`_original/lib/rules/index.js:171,:238-241`), so `ignore://proxy` means "go
/// direct", not "fall through to whatever the PAC file picks". With no proxy
/// operator matched at all there is nothing to ignore, and a `pac://` rule is
/// still honoured — `ignore://pac` is what suppresses that one.
fn ignore_upstream_proxies(resolved: &mut Resolved) {
    let matched = protocols::UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .any(|proto| resolved.get(proto).is_some());
    for proto in protocols::UPSTREAM_PROXY_PROTOCOLS {
        resolved.single.remove(*proto);
        resolved.multi.remove(*proto);
    }
    if matched {
        resolved.single.remove("pac");
        resolved.multi.remove("pac");
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

    /// A multi-match list keeps the two-pass order: `important` lines first,
    /// source order within a pass. Everything downstream that accumulates —
    /// the body operators most visibly — inherits its precedence from this.
    #[test]
    fn a_multi_match_list_leads_with_the_important_lines() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text(
            "example.com resAppend://n1\n$example.com resAppend://i1\n\
             example.com resAppend://n2\n$example.com resAppend://i2\n",
        );
        let r = m.resolve(&req("http://example.com/"));
        let values: Vec<&str> = r.all("resAppend").iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["i1", "i2", "n1", "n2"]);
        // The winner the single-value accessors report is the list's head.
        assert_eq!(r.value("resAppend"), Some("i1"));
    }

    /// `all` is total: a single-match protocol reports its one winner, so
    /// accumulating callers need no special case.
    #[test]
    fn all_reports_a_single_match_winner_too() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.1.1.1\nexample.com host://2.2.2.2\n");
        let r = m.resolve(&req("http://example.com/"));
        let values: Vec<&str> = r.all("host").iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["1.1.1.1"]);
        assert!(r.all("nothing-matched").is_empty());
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

    /// `ignore://proxy` names the family, so every spelling goes. Missing this
    /// means a rule saying "do not use the proxy" still routes through it.
    #[test]
    fn ignore_proxy_drops_every_proxy_spelling() {
        for proto in protocols::UPSTREAM_PROXY_PROTOCOLS {
            let mut m = crate::rules::RuleManager::new();
            m.set_text(&format!(
                "example.com {proto}://10.0.0.1:8888\nexample.com ignore://proxy\n"
            ));
            let r = m.resolve(&req("http://example.com/"));
            assert!(
                r.value(proto).is_none(),
                "ignore://proxy must drop {proto}://"
            );
        }
    }

    /// The specific spelling works too — upstream tests both the generic name
    /// and the matched protocol (`_original/lib/rules/index.js:161-166`) — and
    /// it drops only that one.
    #[test]
    fn ignoring_one_proxy_spelling_spares_the_others() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com socks://10.0.0.1:1080\nexample.com ignore://socks\n");
        assert!(m.resolve(&req("http://example.com/")).value("socks").is_none());

        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com socks://10.0.0.1:1080\nexample.com ignore://http-proxy\n");
        assert!(
            m.resolve(&req("http://example.com/")).value("socks").is_some(),
            "ignoring a different spelling leaves socks:// alone"
        );
    }

    /// An `ignore://` naming an alias is folded to the canonical protocol
    /// first, as upstream's `ignore[aliasProtocols[name] || name]` does
    /// (`resolveIgnore`, `_original/lib/util/index.js:1891-1920`). The x-spelling
    /// of a proxy is an alias of its base here, so it names the family.
    #[test]
    fn an_ignored_alias_is_folded_to_its_protocol() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com socks://10.0.0.1:1080\nexample.com ignore://xproxy\n");
        assert!(m.resolve(&req("http://example.com/")).value("socks").is_none());

        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com host://1.2.3.4\nexample.com ignore://hosts\n");
        assert!(m.resolve(&req("http://example.com/")).value("host").is_none());
    }

    /// Ignoring a proxy that matched takes the PAC fallback with it: upstream
    /// returns before `resolvePacRule()` (`index.js:238-241`), so the request
    /// goes direct rather than quietly picking up a PAC-chosen proxy instead.
    #[test]
    fn ignoring_a_matched_proxy_also_drops_the_pac_fallback() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text(
            "example.com proxy://10.0.0.1:8888\nexample.com pac:///tmp/x.pac\nexample.com ignore://proxy\n",
        );
        let r = m.resolve(&req("http://example.com/"));
        assert!(r.value("proxy").is_none());
        assert!(r.value("pac").is_none(), "the PAC fallback goes too");
    }

    /// …but with no proxy operator matched, `ignoreProxy` stays false upstream
    /// and PAC is still consulted. Only `ignore://pac` suppresses that.
    #[test]
    fn ignore_proxy_alone_leaves_pac_standing() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com pac:///tmp/x.pac\nexample.com ignore://proxy\n");
        assert!(m.resolve(&req("http://example.com/")).value("pac").is_some());

        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com pac:///tmp/x.pac\nexample.com ignore://pac\n");
        assert!(m.resolve(&req("http://example.com/")).value("pac").is_none());
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

    /// A path prefix must end on a `/`, `\\` or `?` boundary — upstream's docs
    /// spell out that `example.com/path/to` does **not** match `/path/toxxx`
    /// (`_original/docs/docs/rules/pattern.md`), and its matcher enforces it at
    /// `rules.js:1091-1097`.
    ///
    /// A plain `starts_with` made every path rule match more URLs than written:
    /// `example.com/api` also caught `/apifoo` and `/apikeys`.
    #[test]
    fn path_prefix_stops_at_a_segment_boundary() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com/path/to host://1.1.1.1\n");
        let hit = |u: &str| m.resolve(&req(u)).value("host").is_some();

        assert!(hit("http://example.com/path/to"), "exact path");
        assert!(hit("http://example.com/path/to/xxx?q=1"), "deeper path");
        assert!(hit("http://example.com/path/to?q=1"), "query follows");
        assert!(!hit("http://example.com/path/toxxx"), "no boundary after `to`");
        assert!(!hit("http://example.com/path/tox/y"), "no boundary after `to`");
    }

    /// A pattern already ending on a separator imposes no further boundary, and
    /// one carrying a query keeps its "same path, query is a prefix" rule.
    #[test]
    fn boundary_exemptions() {
        let mut m = crate::rules::RuleManager::new();
        m.set_text("example.com/path/ host://1.1.1.1\n");
        assert!(m.resolve(&req("http://example.com/path/anything")).value("host").is_some());

        let mut q = crate::rules::RuleManager::new();
        q.set_text("example.com/path/to?xxx host://2.2.2.2\n");
        let hit = |u: &str| q.resolve(&req(u)).value("host").is_some();
        assert!(hit("http://example.com/path/to?xxx"));
        assert!(hit("http://example.com/path/to?xxxyyy&z"), "query prefix");
        assert!(!hit("http://example.com/path/to/yyy?xxx"), "path must be exact");
        assert!(!hit("http://example.com/path/to"), "query required");
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

/// The response phase: what a second resolution adds once the head is in.
///
/// Every case here is the pair "does hold" / "does not hold", because the point
/// of the phase is that the same rule now answers both ways depending on the
/// response — a rule that always applied would prove nothing.
#[cfg(test)]
mod response_phase_tests {
    use super::*;
    use crate::rules::{ResInfo, RuleManager};

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
            client_ip: Some("127.0.0.1".into()),
            ..Default::default()
        }
    }

    /// A response head with `status` and nothing else.
    fn res(status: u16) -> ResInfo {
        ResInfo {
            status,
            ..Default::default()
        }
    }

    fn res_with(status: u16, headers: &[(&str, &str)]) -> ResInfo {
        ResInfo {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    /// Both passes, wired exactly as `crate::proxy::serve` wires them.
    fn resolve(text: &str, req: &ReqInfo, res: Option<ResInfo>) -> Resolved {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let mut resolved = mgr.resolve(req);
        let mut with_res = req.clone();
        with_res.res = res;
        if let Some(extra) = mgr.resolve_response(&with_res, false) {
            resolved.merge_response_phase(extra);
        }
        resolved
    }

    /// The value `protocol` ends up with after both passes.
    fn value(text: &str, status: u16, protocol: &str) -> Option<String> {
        resolve(text, &req("http://example.com/"), Some(res(status)))
            .value(protocol)
            .map(str::to_string)
    }

    // ── the conditions that just came alive ──

    #[test]
    fn an_include_filter_on_the_status_holds_only_for_that_status() {
        let text = "example.com resHeaders://x-hit=1 includeFilter://s:200\n";
        assert_eq!(value(text, 200, "resHeaders").as_deref(), Some("x-hit=1"));
        assert_eq!(value(text, 404, "resHeaders"), None);
        // …and nothing at all before the response arrives.
        let early = resolve(text, &req("http://example.com/"), None);
        assert!(early.value("resHeaders").is_none());
    }

    #[test]
    fn a_status_regexp_matches_the_family() {
        let text = "example.com resType://text/plain includeFilter://statusCode:/^2/\n";
        assert_eq!(value(text, 204, "resType").as_deref(), Some("text/plain"));
        assert_eq!(value(text, 301, "resType"), None);
    }

    /// Negation works now that the answer is known — which it could not while
    /// the condition was unanswerable, since `getFilterResult` drops `not` for
    /// an unknown (`_original/lib/rules/rules.js:1809`).
    #[test]
    fn a_negated_status_holds_for_every_other_status() {
        let text = "example.com resHeaders://x-hit=1 includeFilter://s:!200\n";
        assert_eq!(value(text, 500, "resHeaders").as_deref(), Some("x-hit=1"));
        assert_eq!(value(text, 200, "resHeaders"), None);
    }

    #[test]
    fn an_exclude_filter_on_the_status_now_fires() {
        let text = "example.com resHeaders://x-hit=1 excludeFilter://s:404\n";
        assert_eq!(value(text, 200, "resHeaders").as_deref(), Some("x-hit=1"));
        assert_eq!(
            value(text, 404, "resHeaders"),
            None,
            "the operator was withheld from the request pass so this could fire"
        );
    }

    /// Response headers match by containment, like every other header condition
    /// — upstream's own example is `resH.content-type:json`.
    #[test]
    fn a_response_header_condition_matches_by_containment() {
        let text = "example.com resAppend://<!--tail--> includeFilter://resH.content-type:json\n";
        let hit = |ct: &str| {
            resolve(
                text,
                &req("http://example.com/"),
                Some(res_with(200, &[("content-type", ct)])),
            )
            .value("resAppend")
            .is_some()
        };
        assert!(hit("application/JSON; charset=utf-8"));
        assert!(!hit("text/html"));
        // A response without the header at all is a known "no".
        assert!(resolve(text, &req("http://example.com/"), Some(res(200)))
            .value("resAppend")
            .is_none());
    }

    /// `h:`/`header:` reads the request first and the response only when the
    /// request has no such header (`filterHeader(req.headers, filter.header,
    /// req.resHeaders)`, `_original/lib/rules/rules.js:1953`).
    #[test]
    fn the_bare_header_spelling_falls_back_to_the_response() {
        let text = "example.com resHeaders://x-hit=1 includeFilter://h:x-tag=yes\n";
        let head = res_with(200, &[("x-tag", "yes")]);
        assert!(
            resolve(text, &req("http://example.com/"), Some(head.clone()))
                .value("resHeaders")
                .is_some(),
            "the response's header answers when the request has none"
        );

        // With the request carrying the key, the response is never consulted —
        // so a request value that disagrees loses, it does not fall through.
        let mut tagged = req("http://example.com/");
        tagged.headers.push(("x-tag".into(), "no".into()));
        assert!(
            resolve(text, &tagged, Some(head))
                .value("resHeaders")
                .is_none()
        );
    }

    #[test]
    fn the_server_address_answers_once_the_request_has_gone() {
        let text = "example.com resHeaders://x-hit=1 includeFilter://serverIp:10.0.0.7\n";
        let sent_to = |ip: Option<&str>| ResInfo {
            status: 200,
            server_ip: ip.map(str::to_string),
            ..Default::default()
        };
        let hit = |ip: Option<&str>| {
            resolve(text, &req("http://example.com/"), Some(sent_to(ip)))
                .value("resHeaders")
                .is_some()
        };
        assert!(hit(Some("10.0.0.7")));
        assert!(!hit(Some("10.0.0.8")));
        // An address this port never learned leaves the condition unanswerable,
        // so the filter fails closed rather than matching a guess.
        assert!(!hit(None));
    }

    #[test]
    fn the_server_port_answers_too() {
        let text = "example.com resHeaders://x-hit=1 includeFilter://serverPort:8443\n";
        let sent_to = |port: u16| ResInfo {
            status: 200,
            server_port: Some(port),
            ..Default::default()
        };
        let hit = |port: u16| {
            resolve(text, &req("http://example.com/"), Some(sent_to(port)))
                .value("resHeaders")
                .is_some()
        };
        assert!(hit(8443));
        assert!(!hit(443));
    }

    /// The client socket's port is known in the *request* phase — it is not a
    /// response fact, it just had nowhere to travel before.
    #[test]
    fn the_client_port_answers_in_the_request_phase() {
        for token in ["clientPort:54321", "remotePort:54321"] {
            let text = format!("example.com host://10.0.0.1 includeFilter://{token}\n");
            let mut r = req("http://example.com/");
            r.client_port = Some(54321);
            assert_eq!(
                resolve(&text, &r, None).value("host"),
                Some("10.0.0.1"),
                "{token}"
            );
            r.client_port = Some(1234);
            assert!(resolve(&text, &r, None).value("host").is_none(), "{token}");
            // Unknown stays unknown, and fails closed.
            r.client_port = None;
            assert!(resolve(&text, &r, None).value("host").is_none(), "{token}");
        }
    }

    #[test]
    fn the_remote_address_is_the_client_socket() {
        let text = "example.com host://10.0.0.1 includeFilter://remoteAddress:127.0.0.1\n";
        assert_eq!(
            resolve(text, &req("http://example.com/"), None).value("host"),
            Some("10.0.0.1")
        );
        let mut elsewhere = req("http://example.com/");
        elsewhere.client_ip = Some("10.9.9.9".into());
        assert!(resolve(text, &elsewhere, None).value("host").is_none());
    }

    // ── what the second pass may and may not touch ──

    /// A request-phase operator is decided before the request is sent and never
    /// revisited, so a response condition can never turn it on. Upstream is the
    /// same: `host` is absent from the response pass's protocol list.
    #[test]
    fn a_request_phase_operator_is_never_decided_by_the_response() {
        let text = "example.com host://10.0.0.1 includeFilter://s:200\n";
        assert!(value(text, 200, "host").is_none());
        assert!(value(text, 404, "host").is_none());
    }

    /// …and the rule's *other* operators still apply in the request phase when
    /// only an exclude filter mentions the response, which is what upstream's
    /// request pass does with the status still unknown.
    #[test]
    fn an_excluded_response_condition_leaves_the_request_operators_alone() {
        let text = "example.com host://10.0.0.1 resHeaders://x-hit=1 excludeFilter://s:404\n";
        assert_eq!(value(text, 404, "host").as_deref(), Some("10.0.0.1"));
        assert_eq!(value(text, 404, "resHeaders"), None);
        assert_eq!(value(text, 200, "resHeaders").as_deref(), Some("x-hit=1"));
    }

    /// `ignore://` resolved in the response phase reaches operators the request
    /// phase had already resolved — from other lines included.
    #[test]
    fn a_response_phase_ignore_drops_a_request_phase_operator() {
        let text = "example.com resHeaders://x-hit=1\n\
                    example.com ignore://resHeaders includeFilter://s:404\n";
        assert_eq!(value(text, 200, "resHeaders").as_deref(), Some("x-hit=1"));
        assert_eq!(value(text, 404, "resHeaders"), None);
    }

    /// `ignore://all` in the response phase clears the response-phase operators
    /// and only those — upstream's `isResRules` restriction
    /// (`_original/lib/util/index.js:2083`).
    #[test]
    fn a_response_phase_ignore_all_spares_the_request_phase() {
        let text = "example.com host://10.0.0.1 resHeaders://x-hit=1\n\
                    example.com ignore://all includeFilter://s:404\n";
        let r = resolve(text, &req("http://example.com/"), Some(res(404)));
        assert!(r.value("resHeaders").is_none());
        assert_eq!(r.value("host"), Some("10.0.0.1"), "the request had gone already");
    }

    // ── precedence ──

    /// The winner is the one written first, whichever pass resolved it. Getting
    /// this wrong is silent: both rules apply, the wrong one just wins.
    #[test]
    fn source_order_decides_across_the_two_passes() {
        let conditional = "example.com replaceStatus://500 includeFilter://s:404\n";
        let plain = "example.com replaceStatus://502\n";
        assert_eq!(
            value(&format!("{conditional}{plain}"), 404, "replaceStatus").as_deref(),
            Some("500"),
            "the conditional line is written first"
        );
        assert_eq!(
            value(&format!("{plain}{conditional}"), 404, "replaceStatus").as_deref(),
            Some("502"),
            "the plain line is written first"
        );
    }

    /// The same for a multi-match protocol, where every value survives and only
    /// the order changes.
    #[test]
    fn a_multi_match_list_keeps_source_order_across_the_passes() {
        let text = "example.com resAppend://a\n\
                    example.com resAppend://b includeFilter://s:404\n\
                    example.com resAppend://c\n";
        let r = resolve(text, &req("http://example.com/"), Some(res(404)));
        let values: Vec<&str> = r.all("resAppend").iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["a", "b", "c"]);
    }

    /// An important line still outranks the lines above it, in either pass.
    #[test]
    fn importance_outranks_source_order_across_the_passes() {
        let text = "example.com resAppend://normal\n\
                    $example.com resAppend://important includeFilter://s:404\n";
        let r = resolve(text, &req("http://example.com/"), Some(res(404)));
        let values: Vec<&str> = r.all("resAppend").iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["important", "normal"]);
    }

    /// Two operators of one line keep the order they were written in.
    #[test]
    fn operators_of_one_line_keep_their_order() {
        let text = "example.com resAppend://first resAppend://second includeFilter://s:200\n";
        let r = resolve(text, &req("http://example.com/"), Some(res(200)));
        let values: Vec<&str> = r.all("resAppend").iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["first", "second"]);
    }

    // ── the pass is skipped when nothing needs it ──

    /// The common case: no rule mentions the response, so there is no second
    /// pass at all — not an empty one.
    #[test]
    fn no_second_pass_when_no_rule_mentions_the_response() {
        for text in [
            "example.com resHeaders://x=1\n",
            "example.com resHeaders://x=1 includeFilter://m:GET\n",
            "example.com resHeaders://x=1 includeFilter://reqH.x-tag:1\n",
            // A response condition with nothing to say about the response: the
            // request pass answered it (with "no") and that is final.
            "example.com host://10.0.0.1 includeFilter://s:200\n",
            "",
        ] {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            assert!(!mgr.may_need_response_phase(), "{text:?}");
            let mut with_res = req("http://example.com/");
            with_res.res = Some(res(200));
            assert!(mgr.resolve_response(&with_res, false).is_none(), "{text:?}");
        }
    }

    /// …and it does run for the rules that need it.
    #[test]
    fn a_second_pass_runs_when_a_rule_needs_it() {
        for text in [
            "example.com resHeaders://x=1 includeFilter://s:200\n",
            "example.com resHeaders://x=1 excludeFilter://resH.x-tag:1\n",
            "example.com resHeaders://x=1 includeFilter://serverIp:1.2.3.4\n",
            "example.com ignore://resHeaders includeFilter://s:404\n",
        ] {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            assert!(mgr.may_need_response_phase(), "{text:?}");
            let mut with_res = req("http://example.com/");
            with_res.res = Some(res(200));
            assert!(mgr.resolve_response(&with_res, false).is_some(), "{text:?}");
        }
    }

    /// `h:` needs the response phase only when the request cannot answer it,
    /// so the spelling costs nothing on a request that carries the header.
    #[test]
    fn the_bare_header_spelling_needs_the_response_only_when_the_request_cannot_answer() {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com resHeaders://x=1 includeFilter://h:x-tag=yes\n");
        assert!(mgr.may_need_response_phase(), "the static answer is conservative");

        let mut tagged = req("http://example.com/");
        tagged.headers.push(("x-tag".into(), "yes".into()));
        tagged.res = Some(res(200));
        assert!(mgr.resolve_response(&tagged, false).is_none());

        let mut bare = req("http://example.com/");
        bare.res = Some(res(200));
        assert!(mgr.resolve_response(&bare, false).is_some());
    }

    /// Rules that arrive mid-request — a plugin's, a `rule://` include — are
    /// resolved once and then forgotten, so nothing may be withheld from them:
    /// there is no second pass that would hand it back.
    ///
    /// The response condition fails closed there, as it did before the response
    /// phase existed. Withholding instead would silently *lose* the operator.
    #[test]
    fn a_single_pass_resolution_withholds_nothing() {
        let text = "example.com resHeaders://x-hit=1 excludeFilter://s:404\n";
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let r = req("http://example.com/");
        assert_eq!(
            mgr.resolve_once(&r, false).value("resHeaders"),
            Some("x-hit=1"),
            "the exclude filter is inert, so the operator applies"
        );
        assert!(
            mgr.resolve(&r).value("resHeaders").is_none(),
            "the two-phase resolution waits for the response instead"
        );
    }

    /// A rule that already applied keeps applying: a response condition on one
    /// line must not disturb an unconditional line's operators.
    #[test]
    fn an_unrelated_rule_is_untouched_by_the_second_pass() {
        let text = "example.com resHeaders://x-always=1\n\
                    example.com resType://text/plain includeFilter://s:404\n";
        for status in [200, 404] {
            let r = resolve(text, &req("http://example.com/"), Some(res(status)));
            assert_eq!(
                r.all("resHeaders").len(),
                1,
                "status {status}: resolved once, not twice"
            );
            assert_eq!(r.value("resHeaders"), Some("x-always=1"));
        }
    }
}


/// `b:` — the request body condition, and the two-stage decision that feeds it.
#[cfg(test)]
mod body_filter_tests {
    use super::*;
    use crate::rules::RuleManager;

    fn post(url: &str, body: Option<&str>) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
        let (host, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        ReqInfo {
            method: "POST".into(),
            scheme: scheme.into(),
            host,
            port: 80,
            path,
            full_url: url.into(),
            req_body: body.map(str::to_string),
            ..Default::default()
        }
    }

    fn mgr(text: &str) -> RuleManager {
        let mut m = RuleManager::new();
        m.set_text(text);
        m
    }

    /// A rules file that never mentions the body never asks for it, so the
    /// request keeps streaming.
    #[test]
    fn no_body_filter_means_no_buffering() {
        for text in [
            "example.com host://1.1.1.1\n",
            "example.com resHeaders://x=1 includeFilter://m:POST\n",
            "example.com resBody://x\n",
        ] {
            assert!(
                !mgr(text).needs_request_body(&post("http://example.com/", None), false),
                "{text:?}"
            );
        }
    }

    /// A `b:` line asks for the body only on the requests its *other* conditions
    /// already let through — the pattern, the method, everything but the body
    /// itself.
    #[test]
    fn a_body_filter_asks_only_where_it_could_apply() {
        let m = mgr("example.com/api resBody://hit includeFilter://b:secret\n");
        assert!(m.needs_request_body(&post("http://example.com/api/x", None), false));
        assert!(!m.needs_request_body(&post("http://other.test/api/x", None), false));
        assert!(!m.needs_request_body(&post("http://example.com/other", None), false));

        // An exclude filter vetoes the line, so the body is not read for it.
        // (A second *include* filter would not: include filters are or-ed, so
        // the line could still apply on the body condition alone.)
        let m = mgr("example.com resBody://hit includeFilter://b:secret excludeFilter://m:POST\n");
        assert!(!m.needs_request_body(&post("http://example.com/", None), false));
    }

    /// The condition compares by containment, like a header's, and a `/re/`
    /// value is matched against the body as it arrived.
    #[test]
    fn the_body_condition_matches_by_containment() {
        let m = mgr("example.com resBody://hit includeFilter://b:SEcReT\n");
        let hit = m.resolve(&post("http://example.com/", Some("id=1&token=secret")));
        assert_eq!(hit.value("resBody"), Some("hit"));
        let miss = m.resolve(&post("http://example.com/", Some("id=1")));
        assert!(miss.value("resBody").is_none());

        let m = mgr("example.com resBody://hit includeFilter://b:/\"id\":\\d+/\n");
        assert_eq!(
            m.resolve(&post("http://example.com/", Some("{\"id\":42}")))
                .value("resBody"),
            Some("hit")
        );
        assert!(
            m.resolve(&post("http://example.com/", Some("{\"id\":\"x\"}")))
                .value("resBody")
                .is_none()
        );
    }

    /// With no body buffered the condition is unknown and fails closed, in both
    /// directions — upstream bails before it consults `not`
    /// (`_original/lib/rules/rules.js:1903-1906`).
    #[test]
    fn an_unbuffered_body_fails_closed() {
        for text in [
            "example.com resBody://hit includeFilter://b:secret\n",
            "example.com resBody://hit includeFilter://b:!secret\n",
        ] {
            assert!(
                mgr(text)
                    .resolve(&post("http://example.com/", None))
                    .value("resBody")
                    .is_none(),
                "{text:?}"
            );
        }
        // An *exclude* filter is inert instead, so the rule still applies.
        assert_eq!(
            mgr("example.com resBody://hit excludeFilter://b:secret\n")
                .resolve(&post("http://example.com/", None))
                .value("resBody"),
            Some("hit")
        );
    }

    /// An empty body is still a body: `!` flips it, because the answer is known.
    #[test]
    fn an_empty_body_is_a_known_answer() {
        let m = mgr("example.com resBody://hit includeFilter://b:!secret\n");
        assert_eq!(
            m.resolve(&post("http://example.com/", Some("")))
                .value("resBody"),
            Some("hit")
        );
    }

    /// `env:` reads whistle's own process environment
    /// (`env = process.env`, `_original/lib/rules/rules.js:14,1961`).
    #[test]
    fn env_reads_the_process_environment() {
        // Scoped to this test's own variable name so nothing else can collide.
        let key = "WHISTLE_RS_ENV_FILTER_TEST";
        unsafe { std::env::set_var(key, "production") };
        let m = mgr(&format!(
            "example.com resBody://hit includeFilter://env:{key}=produc\n"
        ));
        assert_eq!(
            m.resolve(&post("http://example.com/", None)).value("resBody"),
            Some("hit"),
            "compared by containment, like a header"
        );

        // An unset variable is a *known* false, so `!` flips it.
        let m = mgr("example.com resBody://hit includeFilter://env:WHISTLE_RS_UNSET_XYZ=v\n");
        assert!(
            m.resolve(&post("http://example.com/", None))
                .value("resBody")
                .is_none()
        );
        let m = mgr("example.com resBody://hit includeFilter://env:WHISTLE_RS_UNSET_XYZ!=v\n");
        assert_eq!(
            m.resolve(&post("http://example.com/", None)).value("resBody"),
            Some("hit")
        );
        unsafe { std::env::remove_var(key) };
    }
}

