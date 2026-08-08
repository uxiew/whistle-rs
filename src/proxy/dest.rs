//! Where a request is actually sent — whistle's URL-replacement rule.
//!
//! A rule whose operator is a bare URL replaces the request's own URL wholesale:
//!
//! ```text
//! www.example.com          http://localhost:5173
//! www.example.com/api      https://staging.internal/v2
//! ```
//!
//! Upstream files such an operator under the `rule` protocol because no operator
//! of that name exists (`_original/lib/rules/rules.js:1313-1316`), then hands its
//! resolved URL to `parseUrl` as the request's options
//! (`util.rule.getUrl(req.rules.rule)`, `lib/inspectors/rules.js:40-44`). The
//! request's remaining path has already been appended by then
//! ([`crate::rules::url::join_url`]), which is what makes the first rule above
//! forward `/a/b?q` to `http://localhost:5173/a/b?q`.
//!
//! It is worth being precise about how this differs from `host://`, because the
//! two are easy to confuse and the difference is visible to the origin server:
//!
//! | | socket goes to | `Host:` header | path | scheme/TLS |
//! |---|---|---|---|---|
//! | `host://1.2.3.4` | the new address | **unchanged** | unchanged | unchanged |
//! | `http://localhost:5173` | the new address | **the new host** | rewritten | the new scheme |
//!
//! So `host://` is "resolve this name differently" and a URL replacement is "ask
//! a different server for a different thing".

use crate::rules::url::{self, web_scheme};
use crate::rules::{ReqInfo, Resolved, protocols};

/// The scheme, address and path a request is forwarded to.
///
/// Always populated: with no URL-replacement rule in play it simply mirrors the
/// request's own URL, so every consumer can read it unconditionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub scheme: String,
    /// Lowercased host, without the port.
    pub host: String,
    pub port: u16,
    /// Path plus query string, always starting with `/`.
    pub path: String,
    /// Did a rule move the request off its own URL? Only then do the `Host`
    /// header and the request line need rewriting.
    pub replaced: bool,
}

impl Destination {
    /// Read the request's destination out of its resolved rules.
    pub fn of(info: &ReqInfo, resolved: &Resolved) -> Destination {
        replacement_url(resolved)
            .and_then(|value| Destination::parse(value, info))
            .unwrap_or_else(|| Destination::unchanged(info))
    }

    /// The request's own URL, as it arrived.
    fn unchanged(info: &ReqInfo) -> Destination {
        Destination {
            scheme: info.scheme.clone(),
            host: info.host.clone(),
            port: info.port,
            path: info.path.clone(),
            replaced: false,
        }
    }

    /// Parse a replacement URL, inheriting the request's scheme when it has none
    /// (`setProtocol`, `_original/lib/rules/rules.js:294-305`).
    ///
    /// `None` for a value with no host to connect to, which leaves the request
    /// on its own URL — the same as upstream, whose `parseUrl` yields no
    /// hostname and whose `getOptions` then falls back to the request's.
    fn parse(value: &str, info: &ReqInfo) -> Option<Destination> {
        // `http://<a.com/x>` names that exact URL — the brackets only ever said
        // "do not append the request's remaining path", which the matcher has
        // already honoured by not appending it.
        let value = url::fixed_value(value).map_or_else(|| value.to_string(), |(_, v)| v);
        let url = url::set_protocol(value.trim(), &info.scheme);
        let (scheme, rest) = url.split_once("://")?;
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        // Credentials in the authority are whistle's own spelling for proxies,
        // not for destinations; if one appears here it is dropped rather than
        // sent on, which is what `parseUrl` does with `url.auth`.
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return None;
        }
        // `tunnel://` names an address, not a way of speaking to it: a request
        // that reached this code is already HTTP, so it stays HTTP. Upstream
        // reaches the same place — its `getOptions` only ever asks whether the
        // protocol is `https:`.
        let scheme = match scheme {
            "tunnel" => info.scheme.clone(),
            other => other.to_ascii_lowercase(),
        };
        let mut dest = Destination {
            port: port.unwrap_or(default_port(&scheme)),
            host: host.to_ascii_lowercase(),
            path: match path.is_empty() {
                true => "/".to_string(),
                false => path.to_string(),
            },
            scheme,
            // Settled just below, once there is something to compare against.
            replaced: false,
        };
        // A rule that resolves to exactly where the request was already going
        // changes nothing, and saying so keeps the `Host` header untouched.
        dest.replaced = dest != Destination::unchanged(info);
        Some(dest)
    }

    /// `host[:port]`, with the port elided when it is the scheme's default —
    /// the `Host` header the origin should see.
    pub fn authority(&self) -> String {
        match self.port == default_port(&self.scheme) {
            true => self.host.clone(),
            false => format!("{}:{}", self.host, self.port),
        }
    }
}

/// The URL a URL-replacement rule names, if one applies.
///
/// The `rule://` spelling is excluded: it is this port's values-store include
/// (see [`protocols::RULE_INCLUDE`]), and upstream can only ever read it as the
/// unusable URL `rule://<name>`.
///
/// The destination rewrite shares one slot with `file://`, `redirect://` and
/// `statusCode://` — see [`protocols::SLOT_PROTOCOLS`]. Asking for it by name
/// is asking whether it *won* that slot: if one of the others was written first
/// it answers the request and this rewrite does not happen at all.
fn replacement_url(resolved: &Resolved) -> Option<&String> {
    resolved.get(protocols::URL_REPLACE).map(|op| &op.value)
}

/// Split an authority into host and port, unwrapping a bracketed IPv6 literal.
fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return match tail.strip_prefix(':') {
            Some(port) => Some((host, Some(port.parse().ok()?))),
            None => Some((host, None)),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some((host, Some(port.parse().ok()?)))
        }
        // A bare `::1`-style literal, or a name with nothing after the colon.
        _ => Some((authority, None)),
    }
}

/// The port a scheme implies when the URL does not spell one out.
fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" | "wss" => 443,
        _ => 80,
    }
}

/// Does this destination speak TLS?
pub fn is_tls(scheme: &str) -> bool {
    matches!(scheme, "https" | "wss")
}

/// Whether a value read as a URL at all — used to keep a `web_scheme`-less
/// value from being reported as a destination in diagnostics.
pub fn looks_like_url(value: &str) -> bool {
    web_scheme(value).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleManager;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").expect("a scheme");
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match split_host_port(authority).expect("an authority") {
            (h, Some(p)) => (h.to_string(), p),
            (h, None) => (h.to_string(), default_port(scheme)),
        };
        crate::proxy::apply::build_req_info(
            "GET",
            scheme,
            &host,
            port,
            path,
            &hyper::HeaderMap::new(),
            None,
        )
    }

    fn dest(rules: &str, url: &str) -> Destination {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let info = req(url);
        Destination::of(&info, &mgr.resolve(&info))
    }

    /// The rule whistle's getting-started guide leads with.
    #[test]
    fn a_bare_url_forwards_the_request() {
        let d = dest("www.example.com http://localhost:5173\n", "https://www.example.com/a/b?q=1");
        assert!(d.replaced);
        assert_eq!(d.scheme, "http");
        assert_eq!(d.host, "localhost");
        assert_eq!(d.port, 5173);
        // The path the pattern did not consume comes along.
        assert_eq!(d.path, "/a/b?q=1");
        assert_eq!(d.authority(), "localhost:5173");
    }

    /// The table from `_original/docs/docs/rules/http.md`.
    #[test]
    fn a_path_pattern_maps_onto_the_destination_path() {
        for (url, want) in [
            ("http://www.example.com/path1", "/path/xxx"),
            ("http://www.example.com/path1/a/b/c?query", "/path/xxx/a/b/c?query"),
            ("http://www.example.com/path1/", "/path/xxx/"),
        ] {
            let d = dest("www.example.com/path1 http://www.test.com/path/xxx\n", url);
            assert_eq!(d.path, want, "{url}");
            assert_eq!(d.host, "www.test.com");
            assert_eq!(d.port, 80);
        }
    }

    /// `< >` fixes the destination in place (`docs/docs/rules/http.md`,
    /// "禁用路径拼接").
    #[test]
    fn angle_brackets_stop_the_path_from_being_appended() {
        let d = dest(
            "www.example.com/path1 http://<www.test.com/path/xxx>\n",
            "http://www.example.com/path1/a/b/c",
        );
        assert_eq!(d.host, "www.test.com");
        assert_eq!(d.path, "/path/xxx");
    }

    /// A scheme-less destination inherits the request's, so an https site keeps
    /// its encryption when it is pointed somewhere else.
    #[test]
    fn a_scheme_less_destination_keeps_the_request_scheme() {
        let d = dest("a.com //b.com/x\n", "https://a.com/y");
        assert_eq!((d.scheme.as_str(), d.host.as_str(), d.port), ("https", "b.com", 443));
        let d = dest("a.com b.com:8080\n", "https://a.com/y");
        assert_eq!((d.scheme.as_str(), d.host.as_str(), d.port), ("https", "b.com", 8080));
    }

    /// No rule, or a rule pointing where the request was already going, leaves
    /// the request alone — which is what keeps the `Host` header untouched.
    #[test]
    fn an_unmoved_request_is_not_marked_replaced() {
        assert!(!dest("a.com host://1.2.3.4\n", "http://a.com/x").replaced);
        assert!(!dest("a.com/x http://a.com/x\n", "http://a.com/x").replaced);
        let plain = dest("", "http://a.com/x");
        assert_eq!(
            (plain.scheme.as_str(), plain.host.as_str(), plain.port, plain.path.as_str()),
            ("http", "a.com", 80, "/x")
        );
    }

    /// `rule://<name>` is this port's values-store include, not a destination.
    #[test]
    fn the_rule_spelling_is_not_a_destination() {
        assert!(!dest("a.com rule://mocks\n", "http://a.com/x").replaced);
    }
}
