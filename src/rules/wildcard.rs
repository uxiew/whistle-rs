//! whistle's two wildcard pattern kinds, ported from
//! `_original/lib/rules/rules.js` (`parseWildcard`, `isRegUrl`, and the helpers
//! `domainToRegExp` / `pathToRegExp` / `queryToRegExp`).
//!
//! whistle draws a line most ports miss, and it is worth stating plainly because
//! `*` behaves differently on each side of it (`docs/docs/rules/pattern.md`):
//!
//! * **A plain pattern** may use `*` in the **host** only — `*.example.com`,
//!   `**.example.com:8*`. `*` is a legal character in a URL path, so in the path
//!   it stays a literal, and the path is matched as an ordinary prefix.
//! * **A `^`-prefixed pattern** turns `*` into a wildcard **everywhere** — host,
//!   path and query — and a trailing `$` anchors the end.
//!
//! Both forms capture what their stars matched, which a rule reads back as
//! `$1`…`$9` in an operator's value.
//!
//! The star vocabulary is positional, and each position has its own idea of how
//! far a star may reach:
//!
//! | | `*` | `**` | `***` |
//! |---|---|---|---|
//! | host | `[^/?.]*` (no dots) | `[^/?]*` | — |
//! | path | `[^?/]*` (one segment) | `[^?]*` | `.*` (past the `?`) |
//! | query | `[^&]*` (one value) | `.*` | — |

use regex::Regex;

/// A host-wildcard pattern: a regexp for `scheme://host[:port]`, and a path
/// matched the ordinary way.
///
/// The split is upstream's. `parseWildcard` compiles only the part before the
/// path into a regexp and leaves `path` to the same prefix/boundary test every
/// plain pattern gets (`_original/lib/rules/rules.js:1021-1064`) — which is what
/// keeps a literal `*` in a path literal.
#[derive(Debug, Clone)]
pub struct Wildcard {
    /// Anchored at the start, wrapping the whole host part in group 1 so the
    /// match's length says where the path begins.
    pre: Regex,
    /// The path (and query) as written, matched literally.
    path: String,
    /// A `$`-prefixed pattern matches the path exactly rather than as a prefix.
    is_exact: bool,
    /// The pattern carried a `?`, so what follows the match is more query.
    has_query: bool,
}

/// What a successful [`Wildcard::match_url`] leaves behind.
pub struct WildcardMatch<'u> {
    /// The part of the URL the pattern did not consume.
    pub tail: std::borrow::Cow<'u, str>,
    /// `$0`…`$9`, collected only when the line has a `$` to put them in. `$0`
    /// is the host part the pattern matched, as upstream's `regObj[0]` is
    /// (`rules.js:1032-1034`).
    pub groups: Option<[String; 10]>,
}

impl Wildcard {
    /// Does `url` match, and what is left of it?
    pub fn match_url<'u>(&self, url: &'u str, want_groups: bool) -> Option<WildcardMatch<'u>> {
        let caps = self.pre.captures(url)?;
        let whole = caps.get(1)?;
        let groups = want_groups.then(|| {
            std::array::from_fn(|i| caps.get(i + 1).map_or("", |m| m.as_str()).to_string())
        });
        let rest = &url[whole.end()..];

        if self.is_exact {
            // Either the whole remainder is the path, or it is the path plus a
            // query string — `filePath === wPath || getPureUrl(filePath) === wPath`.
            let pure = rest.split_once('?').map_or(rest, |(p, _)| p);
            if rest != self.path && pure != self.path {
                return None;
            }
            return Some(WildcardMatch {
                tail: relative_query(&self.path, rest),
                groups,
            });
        }

        let tail = rest.strip_prefix(self.path.as_str())?;
        // The same segment-boundary rule a plain prefix pattern obeys.
        let clean = self.has_query
            || tail.is_empty()
            || self.path.ends_with('/')
            || tail.starts_with(['?', '/']);
        if !clean {
            return None;
        }
        Some(WildcardMatch {
            tail: match self.has_query && !tail.is_empty() {
                true => std::borrow::Cow::Owned(format!("?{tail}")),
                false => std::borrow::Cow::Borrowed(tail),
            },
            groups,
        })
    }
}

/// The tail an exact match contributes — upstream's `getRelativePath`
/// (`_original/lib/rules/rules.js:848-858`): an exact pattern consumed the path,
/// so only a query string can be left, and only when the pattern did not carry
/// one of its own.
///
/// Upstream's third test — whether the *destination* already has a `?`, which
/// decides between `?q=1` and `&q=1` — is not made here, because
/// [`crate::rules::url::join_url`] makes it for every other pattern kind and
/// makes it the same way. This port made that test against the **pattern**
/// instead of the destination, which inverted the first one: a pattern that
/// carried its own query, and had therefore consumed the request's, appended it
/// a second time as `&q=1`.
fn relative_query<'u>(path: &str, rest: &'u str) -> std::borrow::Cow<'u, str> {
    if path.contains('?') {
        return std::borrow::Cow::Borrowed("");
    }
    match rest.find('?') {
        Some(i) => std::borrow::Cow::Borrowed(&rest[i..]),
        None => std::borrow::Cow::Borrowed(""),
    }
}

/// How [`parse`] read a token.
pub enum Parsed {
    /// Not a wildcard at all — the caller falls back to a plain prefix pattern.
    NotWildcard,
    /// A wildcard the original refuses to build (a negated one), so the whole
    /// rule is dropped rather than given an inversion upstream does not have.
    Dropped,
    Wildcard(Box<Wildcard>),
}

/// Compile a host-wildcard pattern — `parseWildcard`
/// (`_original/lib/rules/rules.js:1155-1220`).
pub fn parse(pattern: &str, negate: bool) -> Parsed {
    // `WILDCARD_RE = /^(\$?((?:[a-z*]+):\/\/)?([^/?]*))/`
    let after_exact = pattern.strip_prefix('$').unwrap_or(pattern);
    let (protocol, after_protocol) = match scheme_prefix(after_exact) {
        Some(i) => after_exact.split_at(i),
        None => ("", after_exact),
    };
    let domain: &str = match after_protocol.find(['/', '?']) {
        Some(i) => &after_protocol[..i],
        None => after_protocol,
    };
    let pre_len = pattern.len() - after_exact.len() + protocol.len() + domain.len();

    let start_with_dot = dot_domain(domain);
    if !start_with_dot
        && !protocol.contains('*')
        && !domain.contains('*')
        && !domain.contains('~')
    {
        return Parsed::NotWildcard;
    }
    if negate {
        return Parsed::Dropped;
    }

    let rest_path = &pattern[pre_len..];
    let mut path = match rest_path.is_empty() {
        true => "/".to_string(),
        false => rest_path.to_string(),
    };
    let is_exact = pattern.starts_with('$');
    let has_query = path.contains('?');
    if path.starts_with('?') {
        path.insert(0, '/');
    }

    // A domain of nothing but stars matches across the path too, so the path is
    // folded into the regexp instead of being matched separately.
    let all_stars = domain.len() > 2 && domain.chars().all(|c| c == '*');
    let mut pre = if all_stars {
        "[^?]*".to_string()
    } else {
        let mut written = format!("{protocol}{domain}");
        // A lone `*` host followed by a path also matches a host with a dot in
        // it — upstream widens the star by appending another.
        if !start_with_dot && (domain == "*" || domain == "~") && path.starts_with('/') {
            written.push('*');
        }
        let mut pre = expand_domain_stars(&escape_regexp(&written, false));
        if !domain.is_empty() && !domain.ends_with('*') && !domain.contains(':') {
            // No port written, so any port is allowed.
            pre.push_str("(?::\\d+)?");
        }
        if start_with_dot {
            // `.example.com` matches the domain itself and any subdomain.
            pre = pre.replacen("\\.", "(?:[^/?.]*\\.)?", 1);
        }
        pre
    };
    pre = match protocol {
        "" => format!("[a-z]+://{pre}"),
        "//" => format!("[a-z]+:{pre}"),
        _ => pre,
    };
    let trailer = match rest_path.is_empty() {
        // Nothing after the host, so the host part may run to the path.
        true => "[^/?]*",
        false => "",
    };
    let tail = match all_stars {
        true => escape_regexp(&path, true),
        false => String::new(),
    };
    let source = format!("^({pre}{trailer}){tail}");
    match Regex::new(&source) {
        Ok(pre) => Parsed::Wildcard(Box::new(Wildcard {
            pre,
            // With the path folded into the regexp there is nothing left to
            // match separately.
            path: match all_stars {
                true => String::new(),
                false => path,
            },
            is_exact,
            has_query: has_query && !all_stars,
        })),
        Err(_) => Parsed::NotWildcard,
    }
}

/// Compile a filter's URL pattern — `resolveFilterPattern`
/// (`_original/lib/rules/rules.js:1465-1540`).
///
/// A filter is **not** matched like a rule's own pattern, and the difference is
/// the one that bites: `includeFilter://*/cgi-*` really does wildcard the path,
/// because a filter that is not a `*/`-form falls through to `isRegUrl('^' +
/// filter)` — every filter is read as if it had been written with a caret. A
/// rule pattern of the same text treats that `*` as a literal.
///
/// The `*/`- and `/`-led forms have a compiler of their own: the leading stars
/// stand for the host (one star run up to three characters keeps the match
/// inside a single host component), and the rest is a path whose stars expand
/// like any other path's.
pub fn parse_filter(payload: &str) -> Option<Regex> {
    let wildcard = if payload.starts_with('/') && !payload.starts_with("//") {
        "/"
    } else {
        let stars = payload.bytes().take_while(|b| *b == b'*').count();
        match stars > 0 && payload[stars..].starts_with('/') {
            true => &payload[..stars + 1],
            false => return parse_reg_url(&format!("^{payload}")),
        }
    };
    let mut path = escape_regexp(&payload[wildcard.len()..], false);
    if path.contains('*') {
        path = expand_stars(&path, path_star);
    } else if !path.is_empty() && !path.ends_with('/') {
        // A path without a trailing slash still has to end on a boundary.
        path.push_str("(?:[/?]|$)");
    }
    let host = match wildcard.len() > 3 {
        true => "[^?]",
        false => "[^/?]",
    };
    Regex::new(&format!("^[a-z]+://{host}+/{path}")).ok()
}

/// Compile a `^`-prefixed wildcard URL — `isRegUrl`
/// (`_original/lib/rules/rules.js:138-218`).
///
/// Returns the anchored regexp, whose groups are the pattern's stars in order.
/// The whole-match group is `$0`, which for this kind is the matched URL.
pub fn parse_reg_url(pattern: &str) -> Option<Regex> {
    let mut url = pattern;
    // `DOT_PATTERN_RE = /^\.[\w-]+(?:[?$]|$)/` — a bare suffix like `.js` is
    // treated as if it had been written `^.js`.
    let dotted = dot_pattern(url);
    let (mut ignore_case, mut has_start_symbol) = (false, false);
    let mut has_end_symbol = false;
    let mut start_with_dot = false;

    let carets = url.bytes().take_while(|b| *b == b'^').count();
    if dotted || carets > 0 {
        has_start_symbol = true;
        // One caret means case-insensitive; two mean case-sensitive.
        ignore_case = dotted || carets == 1;
        url = &url[carets..];
        if let Some(stripped) = url.strip_suffix('$') {
            has_end_symbol = true;
            url = stripped;
        }
    } else {
        start_with_dot = like_reg_url_dotted(url);
        if start_with_dot || like_reg_url(url) {
            has_start_symbol = true;
            ignore_case = true;
        }
    }
    if !has_start_symbol {
        return None;
    }

    // `REG_URL_RE = /^((?:[a-z*]+:)?\/\/)?([^/?]*)/`
    let (protocol, after_protocol) = match reg_url_scheme(url) {
        Some(i) => url.split_at(i),
        None => ("", url),
    };
    let mut domain: &str = match after_protocol.find(['/', '?']) {
        Some(i) => &after_protocol[..i],
        None => after_protocol,
    };
    let rest = &url[protocol.len() + domain.len()..];
    let (mut pathname, query) = match rest.find('?') {
        Some(i) => (rest[..i].to_string(), &rest[i..]),
        None => (rest.to_string(), ""),
    };

    let protocol = match protocol {
        "" | "//" => "[a-z]+://".to_string(),
        p => escape_regexp(p, false).replacen('*', "([a-z:]*)", 1),
    };
    if start_with_dot {
        domain = &domain[1..];
    }
    let mut domain = escape_regexp(domain, false);
    if domain.len() > 2 && domain.chars().all(|c| c == '*') {
        domain = "([^?]*)".to_string();
    } else if !domain.is_empty() {
        domain = expand_domain_stars(&domain);
    } else {
        domain = "[^/?]*".to_string();
    }
    if start_with_dot {
        domain = format!("(?:[^/?.]*\\.)?{domain}");
    }

    if !pathname.is_empty() {
        pathname = expand_stars(&escape_regexp(&pathname, false), path_star);
    } else if is_suffix(&domain) {
        // A bare suffix pattern (`.js`) matches the *end of the path*, not a
        // host — upstream swaps the two roles (`rules.js:200-203`).
        let anchor = match has_end_symbol || !query.is_empty() {
            true => "",
            false => "(?:\\??.*)$",
        };
        pathname = format!("/[^?]+{domain}{anchor}");
        domain = "[^/?]+".to_string();
    } else if !query.is_empty() || has_end_symbol {
        pathname = "/".to_string();
    }

    let query = match query.is_empty() {
        true => String::new(),
        false => expand_stars(&escape_regexp(query, false), query_star),
    };
    let end = match has_end_symbol {
        true => "$",
        false => "",
    };
    let flags = match ignore_case {
        true => "(?i)",
        false => "",
    };
    Regex::new(&format!("{flags}^{protocol}{domain}{pathname}{query}{end}")).ok()
}

/// `LIKE_REG_URL_RE = /^(?:(?:(?:https?|wss?|tunnel):)?\/\/)?\*+\/[^?*]*\*/` —
/// a pattern whose host is nothing but stars and whose path carries one is read
/// as a `^` pattern even without the caret.
fn like_reg_url(url: &str) -> bool {
    let rest = strip_optional_scheme(url);
    let stars = rest.bytes().take_while(|b| *b == b'*').count();
    if stars == 0 {
        return false;
    }
    let Some(path) = rest[stars..].strip_prefix('/') else {
        return false;
    };
    match path.find(['?', '*']) {
        Some(i) => path.as_bytes()[i] == b'*',
        None => false,
    }
}

/// `LIKE_REG_URL_RE2` — the same, for a `.domain.tld/path*` shape.
fn like_reg_url_dotted(url: &str) -> bool {
    let rest = strip_optional_scheme(url);
    let Some(rest) = rest.strip_prefix('.') else {
        return false;
    };
    let Some(dot) = rest.find(['.', '/', '?']) else {
        return false;
    };
    if rest.as_bytes()[dot] != b'.' || dot == 0 {
        return false;
    }
    let after = &rest[dot + 1..];
    let Some(slash) = after.find(['/', '?']) else {
        return false;
    };
    if after.as_bytes()[slash] != b'/' || slash == 0 {
        return false;
    }
    let path = &after[slash + 1..];
    match path.find(['?', '*']) {
        Some(i) => path.as_bytes()[i] == b'*',
        None => false,
    }
}

/// Strip the optional `(?:(?:https?|wss?|tunnel):)?//` prefix the two
/// "looks like a regexp URL" shapes allow.
fn strip_optional_scheme(url: &str) -> &str {
    for scheme in ["http:", "https:", "ws:", "wss:", "tunnel:"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            return rest.strip_prefix("//").unwrap_or(url);
        }
    }
    url.strip_prefix("//").unwrap_or(url)
}

/// `DOT_PATTERN_RE = /^\.[\w-]+(?:[?$]|$)/`
fn dot_pattern(url: &str) -> bool {
    let Some(rest) = url.strip_prefix('.') else {
        return false;
    };
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(rest.len());
    end > 0 && matches!(rest[end..].chars().next(), None | Some('?') | Some('$'))
}

/// `DOT_DOMAIN_RE = /^\.[^./?]+\.[^/?]/`
fn dot_domain(domain: &str) -> bool {
    let Some(rest) = domain.strip_prefix('.') else {
        return false;
    };
    let Some(dot) = rest.find(['.', '/', '?']) else {
        return false;
    };
    rest.as_bytes()[dot] == b'.' && dot > 0 && rest[dot + 1..].starts_with(|c| c != '/' && c != '?')
}

/// `SUFFIX_RE = /^\\\.[\w-]+$/` — an escaped `.ext` and nothing else.
fn is_suffix(domain: &str) -> bool {
    let Some(rest) = domain.strip_prefix("\\.") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

/// Where a `scheme://` prefix ends — `(?:[a-z*]+):\/\/` in `WILDCARD_RE`.
fn scheme_prefix(url: &str) -> Option<usize> {
    let i = url.find("://")?;
    let ok = i > 0
        && url[..i]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'*');
    ok.then_some(i + 3)
}

/// Where `REG_URL_RE`'s `((?:[a-z*]+:)?\/\/)?` prefix ends.
fn reg_url_scheme(url: &str) -> Option<usize> {
    if let Some(i) = url.find("://")
        && i > 0
        && url[..i].bytes().all(|b| b.is_ascii_lowercase() || b == b'*')
    {
        return Some(i + 3);
    }
    url.starts_with("//").then_some(2)
}

/// `escapeRegExp` (`_original/lib/util/common.js:930-938`). `*` is escaped only
/// when `with_star` is set, because the star runs are what the expanders below
/// are looking for.
fn escape_regexp(s: &str, with_star: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "|\\{}()[]^$+?.".contains(c) || (with_star && c == '*') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `DOMAIN_STAR_RE = /([*~]+)(\\.)?/g` with `domainToRegExp`
/// (`_original/lib/rules/rules.js:113-123`).
///
/// A star run followed by an escaped dot swallows the dot too, and three or more
/// stars make the whole thing optional — which is how `***.example.com` matches
/// `example.com` itself.
fn expand_domain_stars(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let bytes = escaped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'*' && bytes[i] != b'~' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let run = bytes[i..]
            .iter()
            .take_while(|b| **b == b'*' || **b == b'~')
            .count();
        i += run;
        let mut piece = match run > 1 {
            true => "([^/?]*)".to_string(),
            false => "([^/?.]*)".to_string(),
        };
        if escaped[i..].starts_with("\\.") {
            i += 2;
            piece.push_str("\\.");
            if run > 2 {
                piece = format!("(?:{piece})?");
            }
        }
        out.push_str(&piece);
    }
    out
}

/// `pathToRegExp` (`rules.js:125-131`).
fn path_star(run: usize) -> &'static str {
    match run {
        1 => "([^?/]*)",
        2 => "([^?]*)",
        _ => "(.*)",
    }
}

/// `queryToRegExp` (`rules.js:133-135`).
fn query_star(run: usize) -> &'static str {
    match run > 1 {
        true => "(.*)",
        false => "([^&]*)",
    }
}

/// `STAR_RE = /\*+/g` with the given expander.
fn expand_stars(escaped: &str, expand: fn(usize) -> &'static str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let bytes = escaped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'*' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let run = bytes[i..].iter().take_while(|b| **b == b'*').count();
        out.push_str(expand(run));
        i += run;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(pattern: &str, url: &str) -> bool {
        match parse(pattern, false) {
            Parsed::Wildcard(w) => w.match_url(url, false).is_some(),
            _ => panic!("{pattern} is not a wildcard"),
        }
    }

    /// The examples from `_original/docs/docs/rules/pattern.md`, "域名通配符".
    #[test]
    fn a_host_star_stops_at_a_dot() {
        assert!(hits("https://*.example.com/path/to", "https://www.example.com/path/to"));
        assert!(hits(
            "https://*.example.com/path/to",
            "https://abc.example.com/path/to/xxx?query"
        ));
        assert!(!hits("https://*.example.com/path/to", "https://a.b.example.com/path/to"));
        // `**` crosses dots, and a star in the port matches part of it.
        assert!(hits("https://**.example.com:8*/path/to", "https://a.b.example.com:8080/path/to"));
        assert!(hits("https://**.example.com:8*/path/to", "https://foo-bar.example.com:8888/path/to"));
    }

    /// The bug this replaced: `*.example.com` compiled to `^.*\.example\.com`,
    /// which any URL merely *mentioning* the domain satisfies. A rule scoped to
    /// one site applied to every site that linked to it.
    #[test]
    fn a_leading_star_cannot_escape_into_the_path() {
        assert!(!hits("*.example.com", "http://evil.test/?next=a.example.com"));
        assert!(!hits("*.example.com/api", "http://evil.test/api?x=a.example.com"));
        assert!(hits("*.example.com", "http://a.example.com/"));
    }

    /// A `*` in a path is a literal there, so the pattern only matches a URL
    /// that really contains one (`pattern.md`: "`*` 也是 URL 路径中的合法字符").
    #[test]
    fn a_path_star_is_literal_without_the_caret() {
        assert!(hits("*.example.com/api/*", "http://a.example.com/api/*"));
        assert!(!hits("*.example.com/api/*", "http://a.example.com/api/users"));
    }

    /// …and with the caret it is a wildcard, in the path and the query alike.
    #[test]
    fn a_caret_makes_every_star_a_wildcard() {
        let re = parse_reg_url("^https://example.com/path/to/a*b").expect("compiles");
        assert!(re.is_match("https://example.com/path/to/axxxb/more?query"));
        assert!(!re.is_match("https://example.com/path/to/a/b"));

        let re = parse_reg_url("^https://example.com/path/to/a**b").expect("compiles");
        assert!(re.is_match("https://example.com/path/to/a/b"));
        assert!(!re.is_match("https://example.com/path/to/a/xxxx?query=b"));

        let re = parse_reg_url("^https://example.com/path/to/a***b").expect("compiles");
        assert!(re.is_match("https://example.com/path/to/a/xxxx?query=b"));

        // A trailing `$` forbids anything after the match.
        let re = parse_reg_url("^https://*.example.com/path/*/to$").expect("compiles");
        assert!(re.is_match("https://a.example.com/path/xxx/to"));
        assert!(!re.is_match("https://b.example.com/path/xxx/to?query"));

        // Query wildcards.
        let re = parse_reg_url("^https://example.com/path/to?query=a*b").expect("compiles");
        assert!(re.is_match("https://example.com/path/to?query=ab&q2=xxx"));
        assert!(!re.is_match("https://example.com/path/to?query=a&q2=b"));
    }

    /// The capture example from `pattern.md`, "通配符匹配传值".
    #[test]
    fn stars_capture_in_order() {
        let re = parse_reg_url("^http://*.example.com/v0/users/**").expect("compiles");
        let caps = re
            .captures("http://www.example.com/v0/users/alice/test.html?q=1")
            .expect("matches");
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("www"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("alice/test.html"));
    }

    /// A host wildcard leaves the rest of the URL for the destination to take.
    #[test]
    fn a_host_wildcard_reports_what_it_left() {
        let Parsed::Wildcard(w) = parse("*.example.com/api", false) else {
            panic!("not a wildcard");
        };
        let m = w.match_url("http://a.example.com/api/users?x=1", true).expect("matches");
        assert_eq!(m.tail, "/users?x=1");
        assert_eq!(m.groups.expect("asked for groups")[1], "a");
        // The boundary rule still applies.
        assert!(w.match_url("http://a.example.com/apixxx", false).is_none());
    }

    /// A pattern with no wildcard at all is not one, and the caller falls back
    /// to plain prefix matching.
    #[test]
    fn a_pattern_without_stars_is_not_a_wildcard() {
        assert!(matches!(parse("example.com/api", false), Parsed::NotWildcard));
        assert!(matches!(parse("http://example.com", false), Parsed::NotWildcard));
        // A negated wildcard is dropped rather than inverted.
        assert!(matches!(parse("*.example.com", true), Parsed::Dropped));
        // A leading-dot host is a wildcard even with no star.
        assert!(matches!(parse(".example.com/x", false), Parsed::Wildcard(_)));
    }
}

