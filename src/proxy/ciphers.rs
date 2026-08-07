//! What `cipher://`'s `ciphers` option can and cannot mean here.
//!
//! whistle's `cipher://` carries Node's TLS options, and `ciphers` there is an
//! **OpenSSL cipher string** — a small language of its own: names joined by `:`,
//! group aliases (`HIGH`, `DEFAULT`, `ALL`), exclusions (`!aNULL`, `-RC4`),
//! promotions (`+SHA`), and an ordering directive (`@STRENGTH`). rustls has none
//! of that. It has a fixed list of suites and lets you choose a subset of it,
//! and nothing in it accepts a string.
//!
//! So the full semantics genuinely cannot be ported, and `docs/ROADMAP.md` has
//! said so for as long as the operator has existed. What it did **not** say is
//! that the option was being dropped in silence: `parse_cipher_versions` read
//! `minVersion`/`maxVersion` and walked past `ciphers` without a word. A rule
//! that pinned a suite configured nothing, said nothing, and looked exactly like
//! a rule that had worked.
//!
//! This is the part that can be honoured, and a voice for the part that cannot:
//!
//! * a token naming a suite rustls has — in either the IANA spelling
//!   (`TLS_AES_128_GCM_SHA256`) or OpenSSL's (`ECDHE-RSA-AES128-GCM-SHA256`) —
//!   selects that suite;
//! * every other token is **reported**, once, naming itself, so an `@STRENGTH`
//!   or a `!aNULL` is visibly not honoured rather than invisibly ignored;
//! * if nothing at all could be selected, the option is dropped entirely rather
//!   than narrowed to nothing — an empty suite list fails every handshake, which
//!   is not what asking for a cipher meant.
//!
//! Restricting suites can only narrow what the proxy will negotiate, never
//! widen it: the selection is an intersection with what rustls already offers,
//! so a `cipher://` cannot talk this port into a suite it would otherwise
//! refuse.

use rustls::SupportedCipherSuite;
use rustls::crypto::ring::cipher_suite as ring;

/// Every suite rustls's ring provider has, with the two spellings each is
/// written in. The IANA name is what TLS 1.3 and Node both use; the OpenSSL
/// name is what a `ciphers` string usually carries for TLS 1.2.
///
/// The order is rustls's own preference order, and the selection preserves it —
/// OpenSSL's `ciphers` string is also a *preference* list, but rustls does not
/// take an ordering, so only the membership is honoured.
const SUITES: &[(SupportedCipherSuite, &str, &str)] = &[
    (ring::TLS13_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", ""),
    (ring::TLS13_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", ""),
    (
        ring::TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_CHACHA20_POLY1305_SHA256",
        "",
    ),
    (
        ring::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
    ),
    (
        ring::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
    ),
    (
        ring::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
    ),
    (
        ring::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ),
    (
        ring::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ),
    (
        ring::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ),
];

/// Which suites a `cipher://` selected, as a bitmask over [`SUITES`].
///
/// A mask rather than a list so that [`super::upstream::Target`] stays `Copy`
/// and so that the client-config cache has a key it can hash — there are nine
/// suites, and a `u16` holds the answer with room to spare. **Zero means no
/// selection**, which is not the same as "no suites": it is the ordinary case,
/// and it leaves rustls's own list alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Suites(u16);

impl Suites {
    /// No selection — rustls decides, as it does for every request without a
    /// `cipher://ciphers`.
    pub const ALL: Suites = Suites(0);

    /// Is anything selected?
    pub fn is_all(self) -> bool {
        self.0 == 0
    }

    /// The selected suites, in rustls's preference order.
    pub fn selected(self) -> Vec<SupportedCipherSuite> {
        SUITES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, (suite, _, _))| *suite)
            .collect()
    }
}

/// What a `ciphers` string asked for, and what could not be given.
pub struct Requested {
    /// The suites named that rustls has.
    pub suites: Suites,
    /// The tokens that name nothing rustls can select — an OpenSSL group alias,
    /// an exclusion, an ordering directive, or a suite this build does not
    /// carry. Reported so the gap is audible.
    pub unhonoured: Vec<String>,
}

/// Read an OpenSSL `ciphers` string as far as rustls can follow it.
///
/// Splitting is OpenSSL's: `:` is the separator, and `,`/space are accepted too
/// because Node's own documentation writes lists both ways and a rule is typed
/// by hand.
pub fn parse(spec: &str) -> Requested {
    let mut mask = 0u16;
    let mut unhonoured = Vec::new();
    for token in spec.split([':', ',', ' ']).map(str::trim).filter(|t| !t.is_empty()) {
        match index_of(token) {
            Some(i) => mask |= 1 << i,
            None => unhonoured.push(token.to_string()),
        }
    }
    Requested {
        // Selecting nothing is not a selection. An empty suite list makes every
        // handshake fail, which no `cipher://` was asking for — so a string this
        // port understood none of leaves rustls's own list in place, and says so
        // through `unhonoured`.
        suites: Suites(mask),
        unhonoured,
    }
}

/// The index in [`SUITES`] of a suite named by either spelling, case-insensitively.
fn index_of(token: &str) -> Option<usize> {
    SUITES.iter().position(|(_, iana, openssl)| {
        token.eq_ignore_ascii_case(iana) || (!openssl.is_empty() && token.eq_ignore_ascii_case(openssl))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suite_is_recognised_by_either_spelling() {
        let iana = parse("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        let openssl = parse("ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(iana.suites, openssl.suites, "one suite, two names");
        assert!(iana.unhonoured.is_empty());
        assert_eq!(iana.suites.selected().len(), 1);
    }

    /// TLS 1.3 suites have one name in both worlds, and OpenSSL uses it too.
    #[test]
    fn a_tls13_suite_has_a_single_spelling() {
        let r = parse("TLS_AES_128_GCM_SHA256");
        assert_eq!(r.suites.selected().len(), 1);
        assert!(r.unhonoured.is_empty());
    }

    /// The whole reason this module exists: what cannot be honoured is named.
    #[test]
    fn what_cannot_be_honoured_is_reported_rather_than_dropped() {
        let r = parse("HIGH:!aNULL:!MD5:@STRENGTH");
        assert!(r.suites.is_all(), "none of those name a suite rustls has");
        assert_eq!(r.unhonoured, ["HIGH", "!aNULL", "!MD5", "@STRENGTH"]);
    }

    /// A mixed string honours what it can and reports the rest, rather than
    /// taking all of it or none of it.
    #[test]
    fn a_mixed_string_keeps_the_half_that_maps() {
        let r = parse("ECDHE-RSA-AES128-GCM-SHA256:!RC4:DES-CBC3-SHA");
        assert_eq!(r.suites.selected().len(), 1);
        assert_eq!(r.unhonoured, ["!RC4", "DES-CBC3-SHA"]);
    }

    /// Separators: OpenSSL's `:`, and the spellings a person types.
    #[test]
    fn the_list_may_be_separated_three_ways() {
        for spec in [
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384",
        ] {
            assert_eq!(parse(spec).suites.selected().len(), 2, "{spec}");
        }
    }

    /// No selection is the ordinary case and must not be confused with an empty
    /// one, which would fail every handshake.
    #[test]
    fn an_empty_string_selects_everything_rather_than_nothing() {
        let r = parse("");
        assert!(r.suites.is_all());
        assert!(r.unhonoured.is_empty());
        assert!(r.suites.selected().is_empty(), "and `selected` is not consulted");
    }

    /// The mask is a subset of what rustls offers, so a rule can only ever
    /// narrow the negotiation.
    #[test]
    fn every_selectable_suite_is_one_rustls_actually_has() {
        let all: Vec<_> = SUITES.iter().map(|(_, iana, _)| *iana).collect();
        let r = parse(&all.join(":"));
        assert!(r.unhonoured.is_empty(), "the table names its own suites");
        assert_eq!(r.suites.selected().len(), SUITES.len());
        let provider = rustls::crypto::ring::default_provider();
        for suite in r.suites.selected() {
            assert!(
                provider.cipher_suites.contains(&suite),
                "{:?} is not in the provider",
                suite.suite()
            );
        }
    }
}
