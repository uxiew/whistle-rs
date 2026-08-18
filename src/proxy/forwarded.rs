//! What a front proxy claims about a request, and whether to believe it.
//!
//! A proxy sitting behind another one sees the wrong client address, the wrong
//! scheme and sometimes the wrong host: the connection it accepted is the front
//! proxy's, not the client's. The convention is for the front proxy to say what
//! it knows in headers, and whistle reads four of them
//! (`handleForwardedProps`, `_original/lib/util/index.js:3697-3728`, and
//! `getFullUrl`, `lib/util/common.js:1231-1266`):
//!
//! | Header | What it claims | Gate |
//! |---|---|---|
//! | `x-forwarded-host` | the host the client asked for | `-M x-forwarded-host` |
//! | `x-forwarded-proto` | the scheme the client used | `-M x-forwarded-proto` |
//! | `x-forwarded-for` | the client's address | `-M keepXFF` — see [`super::apply`] |
//! | `x-whistle-real-host` | the host, again, in whistle's own spelling | **none upstream** |
//! | `x-whistle-forwarded-props` | *"turn the three gates on for me"* | **none upstream** |
//!
//! **The last two are where this port diverges, and the reason is the same
//! one.** A header is written by whoever sent the request. When the gate is a
//! mode, an operator decided once, at startup, that a front proxy is there and
//! is to be believed. When the gate is a header, the *sender* decides — and a
//! proxy has no way to tell an operator's front proxy from any client on the
//! network, because the header is the only evidence and the sender wrote it.
//!
//! Measured against whistle 2.10.8, with no mode set at all:
//!
//! * `x-whistle-real-host: <other origin>` sent the request to that other
//!   origin. `getFullUrl` reads it before anything else and there is no flag on
//!   the path (`common.js:1233,:1252-1266`);
//! * `x-whistle-forwarded-props: host` made `x-forwarded-host` be honoured for
//!   that one request, and `…: proto` made `x-forwarded-proto` decide the
//!   scheme the rules matched — so `https://…` patterns fired on a plain HTTP
//!   request the client had labelled.
//!
//! This port answers both by **removing them and not reading them** — except
//! that `x-whistle-real-host` is honoured under `-M x-forwarded-host`, whose
//! entire subject is "a front proxy is telling me the host". Removing them
//! matters as much as not reading them: leaving them on meant handing the
//! origin, and any whistle further up the chain, a claim this proxy had already
//! decided not to trust. It is the same leak the rules-carrying headers had —
//! see [`super::header_rules`].

use crate::config::Config;

/// The host the client asked for, per a front proxy.
pub const FWD_HOST: &str = "x-forwarded-host";
/// The scheme the client used, per a front proxy.
pub const FWD_PROTO: &str = "x-forwarded-proto";
/// The same claim as [`FWD_HOST`], in whistle's own spelling — and read with no
/// gate at all upstream.
pub const REAL_HOST: &str = "x-whistle-real-host";
/// A request asking for the three gates to be opened for itself.
pub const FWD_PROPS: &str = "x-whistle-forwarded-props";

/// The two headers this port takes off **every** request whatever the mode,
/// because it will not act on either and neither may travel on.
pub const ALWAYS_TAKEN: [&str; 2] = [REAL_HOST, FWD_PROPS];

/// What a front proxy claimed, once this proxy has decided what to believe.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Forwarded {
    /// A `host[:port]` to use instead of the one the request addressed.
    pub host: Option<String>,
    /// `Some(true)` if the request is to be matched as `https`/`wss`,
    /// `Some(false)` if it is to be matched as plain — a front proxy that says
    /// `x-forwarded-proto: http` is answering the question too.
    pub https: Option<bool>,
}

impl Forwarded {
    pub fn is_empty(&self) -> bool {
        self == &Forwarded::default()
    }
}

/// Take the forwarding headers off a request, returning what this proxy will
/// act on.
///
/// `x-forwarded-host` and `x-forwarded-proto` are removed **only when they are
/// consumed** — upstream's `delete` lives inside the `if (enableFwd…)` branch
/// (`util/index.js:3714-3727`), so without the mode they travel on to the
/// origin untouched. Measured on both, and matched here: a front proxy's claim
/// is information the origin may legitimately want, and dropping it silently
/// would be this port inventing a policy.
///
/// [`REAL_HOST`] and [`FWD_PROPS`] are removed either way — see the module
/// documentation for why they are not read.
pub fn take(headers: &mut hyper::HeaderMap, cfg: &Config) -> Forwarded {
    let real_host = headers.remove(REAL_HOST);
    for name in ALWAYS_TAKEN {
        headers.remove(name);
    }

    let mut out = Forwarded::default();
    if cfg.trust_forwarded_host {
        // Removed first and used second. Upstream deletes `x-forwarded-host`
        // the moment the gate is open and it is present, and only *then* asks
        // which spelling wins — `delete headers[FWD_HOST_HEADER]` sits above
        // `headers[REAL_HOST] = headers[REAL_HOST] || host` (`:3714-3720`). A
        // short-circuit that skipped the delete left the losing claim on the
        // request, which the bench caught: whistle sent neither header to the
        // origin and this port sent `x-forwarded-host`.
        //
        // The `||` is why the whistle spelling wins when both are there.
        let fwd_host = headers.remove(FWD_HOST);
        out.host = real_host
            .or(fwd_host)
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string);
    }
    if cfg.trust_forwarded_proto {
        out.https = headers
            .remove(FWD_PROTO)
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .map(|p| p.trim().eq_ignore_ascii_case("https"));
    }
    out
}

/// Split a claimed `host[:port]` into its parts, given the scheme's default
/// port.
///
/// **A claim whose port is not a number is a hostname, not an error.** Upstream
/// does no parsing at all — it assigns `headers.host` and lets the connection
/// fail — so a front proxy sending nonsense gets a 502 there. Refusing the
/// claim instead would send the request to the *original* destination, quietly,
/// which is the worse failure: an operator who switched this mode on wants a
/// front proxy's mistake to look like a mistake. Measured: whistle answers 502
/// for `x-forwarded-host: :::not-a-host`, and so does this now.
///
/// `None` is only for a claim with no hostname in it at all, which names
/// nothing to fail on either.
///
/// IPv6 literals keep their brackets, which is what a `Host` header carries and
/// what the rules match against.
pub fn split_host(claimed: &str, default_port: u16) -> Option<(String, u16)> {
    let claimed = claimed.trim();
    if claimed.is_empty() {
        return None;
    }
    if let Some(rest) = claimed.strip_prefix('[') {
        // `[::1]:8080` — the colon that matters is the one after the bracket.
        if let Some((inside, after)) = rest.split_once(']').filter(|(i, _)| !i.is_empty()) {
            let host = format!("[{inside}]");
            return match after.strip_prefix(':').map(str::parse::<u16>) {
                Some(Ok(port)) => Some((host, port)),
                None if after.is_empty() => Some((host, default_port)),
                // A bracketed literal with junk after it: the whole claim is
                // the name, and the name will not resolve.
                _ => Some((claimed.to_string(), default_port)),
            };
        }
        return Some((claimed.to_string(), default_port));
    }
    match claimed.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => match port.parse() {
            Ok(port) => Some((host.to_string(), port)),
            Err(_) => Some((claimed.to_string(), default_port)),
        },
        _ => Some((claimed.to_string(), default_port)),
    }
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

    fn trusting(host: bool, proto: bool) -> Config {
        Config {
            trust_forwarded_host: host,
            trust_forwarded_proto: proto,
            ..Config::default()
        }
    }

    /// The default: nothing is believed, the two ungated headers are taken
    /// anyway, and the two gated ones travel on because upstream's delete is
    /// inside the branch that did not run.
    #[test]
    fn nothing_is_believed_by_default_and_two_are_taken_anyway() {
        let mut h = headers(&[
            (FWD_HOST, "elsewhere.test"),
            (FWD_PROTO, "https"),
            (REAL_HOST, "elsewhere.test"),
            (FWD_PROPS, "host,proto,ip"),
        ]);
        let got = take(&mut h, &Config::default());
        assert!(got.is_empty(), "{got:?}");
        assert!(!h.contains_key(REAL_HOST), "not read, so not forwarded");
        assert!(!h.contains_key(FWD_PROPS), "not read, so not forwarded");
        assert!(h.contains_key(FWD_HOST), "upstream forwards this one");
        assert!(h.contains_key(FWD_PROTO), "and this one");
    }

    /// `x-whistle-forwarded-props` cannot open a gate here. Upstream lets it —
    /// measured, with no mode set, `props: host` was enough to redirect the
    /// request — and that is the divergence this file exists to name.
    #[test]
    fn a_request_cannot_open_its_own_gate() {
        let mut h = headers(&[
            (FWD_PROPS, "host,proto,ip"),
            (FWD_HOST, "elsewhere.test"),
            (FWD_PROTO, "https"),
        ]);
        assert!(take(&mut h, &Config::default()).is_empty());
    }

    #[test]
    fn the_host_gate_reads_both_spellings() {
        let mut h = headers(&[(FWD_HOST, "front.test:8443")]);
        let got = take(&mut h, &trusting(true, false));
        assert_eq!(got.host.as_deref(), Some("front.test:8443"));
        assert!(!h.contains_key(FWD_HOST), "consumed, so removed");

        let mut h = headers(&[(REAL_HOST, "front.test")]);
        assert_eq!(take(&mut h, &trusting(true, false)).host.as_deref(), Some("front.test"));

        // Both: upstream's `||` keeps the whistle spelling.
        let mut h = headers(&[(REAL_HOST, "real.test"), (FWD_HOST, "fwd.test")]);
        let got = take(&mut h, &trusting(true, false));
        assert_eq!(got.host.as_deref(), Some("real.test"));
    }

    /// A front proxy saying `http` is answering the question, not declining it —
    /// upstream's `req.isHttps = proto === 'https'` assigns either way.
    #[test]
    fn the_proto_gate_hears_both_answers() {
        for (sent, expect) in [("https", true), ("HTTPS", true), ("http", false), ("gopher", false)]
        {
            let mut h = headers(&[(FWD_PROTO, sent)]);
            let got = take(&mut h, &trusting(false, true));
            assert_eq!(got.https, Some(expect), "{sent}");
            assert!(!h.contains_key(FWD_PROTO), "{sent}: consumed, so removed");
        }
        // Absent is not an answer.
        let mut h = HeaderMap::new();
        assert_eq!(take(&mut h, &trusting(false, true)).https, None);
    }

    /// Each gate opens one door. A proxy told to trust the host does not
    /// thereby trust the scheme.
    #[test]
    fn the_two_gates_are_separate() {
        let mut h = headers(&[(FWD_HOST, "front.test"), (FWD_PROTO, "https")]);
        let got = take(&mut h, &trusting(true, false));
        assert_eq!(got.host.as_deref(), Some("front.test"));
        assert_eq!(got.https, None);
        assert!(h.contains_key(FWD_PROTO), "still untrusted, so still forwarded");
    }

    #[test]
    fn a_claimed_host_is_split_the_way_a_host_header_is() {
        assert_eq!(split_host("a.test", 80), Some(("a.test".into(), 80)));
        assert_eq!(split_host("a.test", 443), Some(("a.test".into(), 443)));
        assert_eq!(split_host("a.test:8080", 80), Some(("a.test".into(), 8080)));
        assert_eq!(split_host("[::1]", 80), Some(("[::1]".into(), 80)));
        assert_eq!(split_host("[::1]:8080", 80), Some(("[::1]".into(), 8080)));
        assert_eq!(split_host(" a.test:8080 ", 80), Some(("a.test".into(), 8080)));
    }

    /// Nonsense is a hostname that will not resolve, which is a 502 — the same
    /// answer upstream gives, and a visible one. Only a claim with no hostname
    /// at all is nothing.
    #[test]
    fn nonsense_is_a_name_that_will_not_resolve() {
        for claimed in [":8080", "a.test:no", "[]", "[::1]junk", ":::not-a-host"] {
            assert_eq!(
                split_host(claimed, 80),
                Some((claimed.to_string(), 80)),
                "{claimed}"
            );
        }
        for claimed in ["", "   "] {
            assert_eq!(split_host(claimed, 80), None, "{claimed:?}");
        }
    }

    /// The losing spelling is still consumed. Upstream deletes
    /// `x-forwarded-host` above the `||` that decides, so neither claim reaches
    /// the origin — found by `forwarded-bench.js`.
    #[test]
    fn the_losing_host_claim_is_still_taken() {
        let mut h = headers(&[(REAL_HOST, "real.test"), (FWD_HOST, "fwd.test")]);
        let got = take(&mut h, &trusting(true, false));
        assert_eq!(got.host.as_deref(), Some("real.test"));
        assert!(!h.contains_key(FWD_HOST), "the losing claim must not travel on");
    }
}
