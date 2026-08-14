//! URL arithmetic shared by the matcher and the proxy, ported from the helpers
//! at the top of `_original/lib/rules/rules.js` (`joinUrl`, `joinQuery`,
//! `setProtocol`, `isPathSeparator`) and `lib/util/common.js` (`formatUrl`,
//! `hasProtocol`).
//!
//! These are small, but they are exactly the places where a rule's destination
//! is decided, so they are written out rather than approximated: whether
//! `file:///dir` picks up the request's remaining path, and whether
//! `http://localhost:5173` inherits its query string, is all decided here.

/// `/`, `\` and `?` all end a path segment (`isPathSeparator`,
/// `_original/lib/rules/rules.js:307-309`).
pub fn is_path_separator(c: char) -> bool {
    c == '/' || c == '\\' || c == '?'
}

/// Does `url` start with a `scheme://`? whistle's `hasProtocol`
/// (`_original/lib/util/common.js:491-493`) — any run of alphanumerics, dots
/// and dashes, so it admits protocols nothing here implements.
pub fn has_protocol(url: &str) -> bool {
    let Some(i) = url.find("://") else {
        return false;
    };
    i > 0
        && url[..i]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Give `target` a scheme if it lacks one, taking `source`'s
/// (`setProtocol`, `_original/lib/rules/rules.js:294-305`).
///
/// `//host/path` is already scheme-relative and only gains the scheme itself;
/// anything else gains the `//` as well, so a bare `localhost:5173` becomes a
/// URL rather than being read as a scheme of its own.
pub fn set_protocol(target: &str, source_scheme: &str) -> String {
    if has_protocol(target) {
        return target.to_string();
    }
    let separator = match target.starts_with("//") {
        true => "",
        false => "//",
    };
    format!("{source_scheme}:{separator}{target}")
}

/// The URL a pattern is matched against, assembled from its parts — the port's
/// spelling of `getFullUrl` (`_original/lib/util/common.js:1231-1267`).
///
/// The port is elided when it is the scheme's default, because that is the form
/// the client's own request line and `Host` header produce, and a pattern
/// written without a port has to match it.
pub fn full_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let default_port = match scheme {
        "https" | "wss" => 443,
        _ => 80,
    };
    match port == default_port {
        true => format!("{scheme}://{host}{path}"),
        false => format!("{scheme}://{host}:{port}{path}"),
    }
}

/// Ensure a URL has a path (`formatUrl`, `_original/lib/util/common.js:513-523`):
/// `http://a.com?q` → `http://a.com/?q`.
pub fn format_url(url: &str) -> String {
    let (base, query) = split_query(url);
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    match base[scheme_end..].contains('/') {
        true => url.to_string(),
        false => format!("{base}/{query}"),
    }
}

/// Split at the first `?`, keeping it on the query side.
fn split_query(url: &str) -> (&str, &str) {
    match url.find('?') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    }
}

/// Concatenate two query strings (`joinQuery`,
/// `_original/lib/rules/rules.js:317-332`).
///
/// `second` still carries its leading `?`, which is dropped. The `&` between
/// them is omitted when either side already provides one — and, upstream's
/// quirk, when the first side is a bare `?`.
fn join_query(first: &str, second: &str) -> String {
    if first.is_empty() || second.is_empty() {
        return format!("{first}{second}");
    }
    let second = &second[1..];
    let separator = match first.len() < 2
        || second.is_empty()
        || first.ends_with('&')
        || second.starts_with('&')
    {
        true => "",
        false => "&",
    };
    format!("{first}{separator}{second}")
}

/// Append the tail of a matched URL to a rule's destination (`joinUrl`,
/// `_original/lib/rules/rules.js:334-366`).
///
/// This is the "automatic path concatenation" whistle's pattern documentation
/// describes: with `www.example.com/path http://localhost:5173`, a request for
/// `/path/x/y?q` is forwarded to `http://localhost:5173/x/y?q`. The two query
/// strings are lifted out first and rejoined at the end, so the tail's path
/// lands on the destination's path and not after its `?`.
pub fn join_url(base: &str, tail: &str) -> String {
    if base.is_empty() || tail.is_empty() {
        return format!("{base}{tail}");
    }
    let (base_path, base_query) = split_query(base);
    let (tail_path, tail_query) = split_query(tail);

    let joined = match (
        tail_path.is_empty(),
        base_path.ends_with(is_path_separator),
        tail_path.starts_with(is_path_separator),
    ) {
        (true, _, _) => base_path.to_string(),
        // Both sides carry the separator — keep one.
        (false, true, true) => format!("{}{tail_path}", &base_path[..base_path.len() - 1]),
        (false, true, false) | (false, false, true) => format!("{base_path}{tail_path}"),
        (false, false, false) => format!("{base_path}/{tail_path}"),
    };

    let query = join_query(base_query, tail_query);
    match has_web_protocol(&joined) {
        true => format_url(&format!("{joined}{query}")),
        false => format!("{joined}{query}"),
    }
}

/// Split `TPL_RE`'s first group — `(?:[\w.-]+:)?//` — off the front of a value.
///
/// whistle tests a rule's **whole matcher** for a backtick template, and its
/// regexp allows a scheme in front of the backticks: `TPL_RE =
/// /^((?:[\w.-]+:)?\/\/)?(`.*`)$/` (`_original/lib/rules/rules.js:72,:768`).
/// The prefix is put back untouched around the rendered body, so
/// ``http://`${method}.example` `` is a template and this returns the two halves
/// of it. Most operators have had their protocol split off long before this, and
/// then there is no prefix to find; a **destination** keeps its scheme in the
/// value, which is the case that needs asking.
pub fn tpl_prefix(value: &str) -> (&str, &str) {
    let Some(at) = value.find("//") else {
        return ("", value);
    };
    let named = value[..at].strip_suffix(':').is_some_and(|name| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'))
    });
    match at == 0 || named {
        true => value.split_at(at + 2),
        false => ("", value),
    }
}

/// Is the value a backtick template — [`tpl_prefix`] and then a `` `…` `` body?
pub fn is_backtick_template(value: &str) -> bool {
    let (_, rest) = tpl_prefix(value);
    rest.len() > 1 && rest.starts_with('`') && rest.ends_with('`')
}

/// The bracket forms that pin an operator's value in place (`getValue`,
/// `_original/lib/rules/rules.js:271-287`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixed {
    /// `proto://(text)` — the value *is* the content, not a location.
    Inline,
    /// `proto://<path>` — this exact path, whatever else the request asked for.
    Verbatim,
}

/// Recognise a bracketed value, returning its kind and the value with the
/// brackets removed and the scheme, if any, left in place.
///
/// The brackets wrap the part after `scheme://`, so `file://<~/mock/index.html>`
/// unwraps to `file://~/mock/index.html`. A value has to be bracketed at both
/// ends to count, exactly as upstream's `url[0]` / `url[len]` test requires.
///
/// **Narrower than upstream on purpose.** whistle applies this test to every
/// operator's value, which means `htmlAppend://<script>…</script>` loses its
/// final `>` — the whole token is `<…>`-shaped. This port only asks the question
/// where the bracket forms are documented and useful: the URL-replacement rule
/// and the local-file family (`docs/docs/rules/file.md`,
/// `docs/docs/rules/http.md`, both under "禁用路径拼接"). Injected markup is left
/// intact.
pub fn fixed_value(value: &str) -> Option<(Fixed, String)> {
    let (scheme, rest) = match value.find("://") {
        Some(i) if has_protocol(value) => value.split_at(i + 3),
        // A scheme-relative destination — `//host/path`, which inherits the
        // request's own scheme (https://wproxy.org/docs/rules/inherit.html,
        // "禁用路径拼接：使用 < > 或 ( ) 包裹路径"). Upstream cuts the protocol at
        // `matcher.indexOf('://') + 3`, which is **2** on a matcher with no
        // `://` at all, so `//<a.com/x>` splits into `//` and `<a.com/x>` and
        // the brackets are read exactly as they are on `http://<a.com/x>`
        // (`resolveValue`, `_original/lib/rules/rules.js:811-843`).
        _ if value.starts_with("//") => value.split_at(2),
        _ => ("", value),
    };
    if rest.len() < 2 {
        return None;
    }
    // The brackets are matched as bytes and only *then* sliced away. Slicing
    // first panics the moment a value starts with a multi-byte character —
    // `resHeaders://x=报告` has no brackets at all, but `&rest[1..len-1]` cuts
    // through the middle of one. This is now on the path of every operator, so
    // that panic would have been a rules file crashing the parser.
    let kind = match (rest.as_bytes()[0], rest.as_bytes()[rest.len() - 1]) {
        (b'(', b')') => Fixed::Inline,
        (b'<', b'>') => Fixed::Verbatim,
        _ => return None,
    };
    // Both brackets are one byte, so these indices are char boundaries.
    Some((kind, format!("{scheme}{}", &rest[1..rest.len() - 1])))
}

/// Is this value a bare reference into the values store (`{name}`)?
///
/// Its content is substituted whole
/// ([`crate::proxy::apply::substitute_values`]), so nothing may be appended to
/// the reference itself.
pub fn is_values_key(value: &str) -> bool {
    let rest = match value.find("://") {
        Some(i) if has_protocol(value) => &value[i + 3..],
        _ => value,
    };
    rest.len() > 2 && rest.starts_with('{') && rest.ends_with('}')
}

/// `WEB_PROTOCOL_RE` (`_original/lib/rules/rules.js:22`) — the schemes a request
/// can actually have, which is what makes a joined value a *URL* rather than a
/// path.
pub fn has_web_protocol(url: &str) -> bool {
    web_scheme(url).is_some()
}

/// The web scheme `url` is written with, if it is written with one.
pub fn web_scheme(url: &str) -> Option<&str> {
    let i = url.find("://")?;
    matches!(&url[..i], "http" | "https" | "ws" | "wss" | "tunnel").then(|| &url[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table from upstream's own pattern documentation
    /// (`_original/docs/docs/rules/http.md`, "自动路径拼接").
    #[test]
    fn a_destination_picks_up_the_rest_of_the_path() {
        for (base, tail, want) in [
            ("http://www.test.com/path/xxx", "", "http://www.test.com/path/xxx"),
            (
                "http://www.test.com/path/xxx",
                "/a/b/c?query",
                "http://www.test.com/path/xxx/a/b/c?query",
            ),
            // No path on either side: the join has to invent the `/`.
            ("http://localhost:5173", "/a/b", "http://localhost:5173/a/b"),
            ("http://localhost:5173", "", "http://localhost:5173"),
            // A base with no path at all still ends up a well-formed URL.
            ("http://localhost:5173", "?q=1", "http://localhost:5173/?q=1"),
            // Exactly one separator survives when both sides bring one.
            ("http://a.com/dir/", "/x", "http://a.com/dir/x"),
            ("http://a.com/dir/", "x", "http://a.com/dir/x"),
            // Two query strings meet.
            ("http://a.com/p?a=1", "/x?b=2", "http://a.com/p/x?a=1&b=2"),
            ("http://a.com/p?a=1&", "/x?b=2", "http://a.com/p/x?a=1&b=2"),
            // A file path is not a URL, so it is left exactly as joined.
            ("/Users/me/mock", "/x/y", "/Users/me/mock/x/y"),
            ("/Users/me/mock/", "/x/y", "/Users/me/mock/x/y"),
        ] {
            assert_eq!(join_url(base, tail), want, "join_url({base:?}, {tail:?})");
        }
    }

    #[test]
    fn a_scheme_less_destination_inherits_the_request_scheme() {
        assert_eq!(set_protocol("localhost:5173", "https"), "https://localhost:5173");
        assert_eq!(set_protocol("//a.com/x", "https"), "https://a.com/x");
        assert_eq!(set_protocol("http://a.com/x", "https"), "http://a.com/x");
        // A protocol whistle does not know is still a protocol.
        assert_eq!(set_protocol("weird://a.com", "http"), "weird://a.com");
    }

    /// The bracket test runs on **every** operator's value now, so it has to
    /// survive text it was never shown before. Slicing the brackets away before
    /// checking for them panicked the moment a value began with a multi-byte
    /// character — a rules file taking the parser down with it.
    #[test]
    fn a_non_ascii_value_is_not_a_bracket_form() {
        for value in [
            "x=报告",
            "报告",
            "resHeaders://x=搜索",
            "位置",
            "(报告)",
            "<搜索>",
            "中",
            "",
        ] {
            // The assertion is that this returns rather than panicking.
            let got = fixed_value(value);
            match value {
                "(报告)" => assert_eq!(got, Some((Fixed::Inline, "报告".into()))),
                "<搜索>" => assert_eq!(got, Some((Fixed::Verbatim, "搜索".into()))),
                _ => assert_eq!(got, None, "{value:?}"),
            }
        }
    }

    /// `//host/path` is the destination that inherits the request's scheme, and
    /// it takes the same two bracket forms as a spelled-out one. Read only for
    /// a `://` scheme, the brackets stayed in the value: `//<a.com/x>` became
    /// the host `<a.com` and answered 502, on a rule the documentation gives as
    /// its example (https://wproxy.org/docs/rules/inherit.html).
    #[test]
    fn a_scheme_relative_destination_takes_the_bracket_forms() {
        assert_eq!(fixed_value("//<a.com/x>"), Some((Fixed::Verbatim, "//a.com/x".into())));
        assert_eq!(fixed_value("//(a.com/x)"), Some((Fixed::Inline, "//a.com/x".into())));
        // Only *both* brackets count, and only around something.
        assert_eq!(fixed_value("//a.com/x"), None);
        assert_eq!(fixed_value("//<a.com/x"), None);
        assert_eq!(fixed_value("//"), None);
        // The spelled-out schemes are unchanged.
        assert_eq!(fixed_value("http://<a.com/x>"), Some((Fixed::Verbatim, "http://a.com/x".into())));
    }

    /// A pattern is written against the URL the client's own request line
    /// produces, so the default port must not appear in it.
    #[test]
    fn a_default_port_is_left_out_of_a_full_url() {
        assert_eq!(full_url("http", "a.com", 80, "/x"), "http://a.com/x");
        assert_eq!(full_url("https", "a.com", 443, "/x"), "https://a.com/x");
        assert_eq!(full_url("wss", "a.com", 443, "/x"), "wss://a.com/x");
        assert_eq!(full_url("http", "a.com", 443, "/x"), "http://a.com:443/x");
        assert_eq!(full_url("https", "a.com", 80, "/x"), "https://a.com:80/x");
        assert_eq!(full_url("http", "a.com", 8080, "/x?q=1"), "http://a.com:8080/x?q=1");
    }

    #[test]
    fn only_a_real_scheme_counts_as_a_protocol() {
        assert!(has_protocol("http://a.com"));
        assert!(has_protocol("some-thing.v2://a"));
        assert!(!has_protocol("//a.com/x"));
        assert!(!has_protocol("a.com/x"));
        assert!(!has_protocol("/a/b://c"));
    }
}
