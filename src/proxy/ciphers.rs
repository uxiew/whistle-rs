//! OpenSSL cipher strings, evaluated.
//!
//! whistle's `cipher://` carries Node's TLS options, and `ciphers` there is an
//! OpenSSL cipher string. The earlier note in `docs/ROADMAP.md` called this
//! unreachable because "rustls does not accept a cipher string", which is true
//! and beside the point: **the string is a language, and a language can be
//! evaluated.** What rustls has is a smaller universe of cipher suites to
//! evaluate it over — which is exactly the position an OpenSSL build compiled
//! without 3DES is in, and OpenSSL evaluates the same strings there without
//! complaint.
//!
//! So this is not a translation or an approximation. `HIGH:!aNULL:!MD5` over
//! these nine suites has an exact answer, and it is the same answer OpenSSL
//! would give if these nine were all it had.
//!
//! # The two lists
//!
//! OpenSSL 1.1.1+ splits cipher configuration in two: `cipher_list` for TLS 1.2
//! and below, `ciphersuites` for TLS 1.3. Node's single `ciphers` option feeds
//! both, and the split is observable — measured against Node 26 / OpenSSL 3.6:
//!
//! ```text
//! ciphers=ECDHE-RSA-AES128-GCM-SHA256  ->  TLSv1.3 TLS_AES_256_GCM_SHA384
//! ciphers=TLS_AES_128_GCM_SHA256       ->  TLSv1.3 TLS_AES_128_GCM_SHA256
//! ```
//!
//! A TLS 1.2 name does **not** constrain TLS 1.3 — the first line negotiated
//! 1.3 with the default suite, not the one that was asked for. A TLS 1.3 name
//! does. Reproduced here, because getting it wrong is not cosmetic: applying a
//! TLS 1.2 pin to the 1.3 list leaves no 1.3 suite to offer, and the connection
//! silently **downgrades to TLS 1.2** — a rule that meant "prefer this suite"
//! would then have weakened the connection.
//!
//! # When the answer is nothing
//!
//! A string that selects no suite at all is an error in OpenSSL — it throws at
//! context creation, before any connection. Measured, on Node 26 / OpenSSL 3.6:
//! `not-a-version`, `NOTREAL`, `!ALL`, `-ALL` and `ZZZ:YYY` all throw
//! `ERR_SSL_NO_CIPHER_MATCH`, while `TLS_AES_128_GCM_SHA256` and `aNULL` do not.
//!
//! [`evaluate`] returns that answer, and it names the tokens that came up empty.
//! **What the caller does with it is not what OpenSSL does**: the pin is
//! dropped, the connection is made without it, and the reason is logged. This
//! port used to fail the request instead. Three things changed the answer, and
//! the first is the one that decides it:
//!
//! * **"no match" here is not the same fact as "no match" there.** OpenSSL fails
//!   when a string selects nothing out of its own large universe; this fails when
//!   it selects nothing out of rustls's nine suites. `ciphers: "3DES"` is a
//!   perfectly good string that works against an OpenSSL built with 3DES — and
//!   no evaluation can conjure an algorithm that is not compiled in. Failing the
//!   request would import a limitation of *this build* into somebody's traffic,
//!   under a message about their rule.
//! * **`cipher://` does nothing at all in whistle 2.10.8** — measured across
//!   every spelling, bare token and JSON alike: the connection stays at TLS 1.3
//!   with the default suite. It builds the options and then only ever merges
//!   them into the socket options *while retrying a ciphers error*
//!   (`_original/lib/inspectors/res.js:495-497`,
//!   `lib/util/common.js:1769-1771`), so the first, successful handshake never
//!   sees them. There is therefore no upstream behaviour to be faithful to here,
//!   only the question of what a proxy that *does* implement it should do — and
//!   where this port does more than upstream, doing more must not mean breaking
//!   what upstream serves.
//! * **This port already has an answer for an unusable rule value, and it is not
//!   this one.** `statusCode://abc`, `replaceStatus://1`, `method://GET;` — every
//!   one of them leaves the operator inert, and each has a differential case
//!   saying so. One operator that takes the request down instead is a surprise,
//!   not a safeguard.
//!
//! The argument for failing was that a pin nobody noticed had failed is worse
//! than an outage. It does not survive: a 502 does not say the pin failed
//! either — it says the site is down, and the log line is what actually tells
//! you, in both designs. So the log line does the work and the request lives.
//! `https-bench.js` measures the whole family.

use rustls::SupportedCipherSuite;
use rustls::crypto::ring::cipher_suite as ring;

/// How a suite is classified, which is all an OpenSSL alias ever asks about.
struct Attrs {
    /// Key exchange. TLS 1.3 negotiates it separately, so its suites have none.
    kx: Kx,
    /// Authentication. Likewise separate in TLS 1.3.
    au: Au,
    enc: Enc,
    /// Symmetric key size, which is what `HIGH`/`MEDIUM` and `@STRENGTH` read.
    bits: u16,
    prf: Prf,
}

#[derive(PartialEq, Clone, Copy)]
enum Kx {
    Ecdhe,
    /// TLS 1.3: not part of the suite.
    None13,
}
#[derive(PartialEq, Clone, Copy)]
enum Au {
    Rsa,
    Ecdsa,
    /// TLS 1.3: not part of the suite.
    None13,
}
#[derive(PartialEq, Clone, Copy)]
enum Enc {
    AesGcm,
    Chacha20,
}
#[derive(PartialEq, Clone, Copy)]
enum Prf {
    Sha256,
    Sha384,
}

/// One suite this build can offer, with every name it answers to.
struct Suite {
    rustls: SupportedCipherSuite,
    /// The IANA name, which is also OpenSSL's name for a TLS 1.3 suite.
    iana: &'static str,
    /// OpenSSL's own spelling, empty for TLS 1.3 where the two agree.
    openssl: &'static str,
    tls13: bool,
    attrs: Attrs,
}

/// Every suite rustls's ring provider carries, in its own preference order.
///
/// This is the universe the cipher string is evaluated over. It is smaller than
/// OpenSSL's, and every alias naming something outside it — `3DES`, `RC4`,
/// `kRSA`, `DH`, `PSK` — correctly selects nothing.
static SUITES: &[Suite] = &[
    Suite {
        rustls: ring::TLS13_AES_256_GCM_SHA384,
        iana: "TLS_AES_256_GCM_SHA384",
        openssl: "",
        tls13: true,
        attrs: Attrs {
            kx: Kx::None13,
            au: Au::None13,
            enc: Enc::AesGcm,
            bits: 256,
            prf: Prf::Sha384,
        },
    },
    Suite {
        rustls: ring::TLS13_AES_128_GCM_SHA256,
        iana: "TLS_AES_128_GCM_SHA256",
        openssl: "",
        tls13: true,
        attrs: Attrs {
            kx: Kx::None13,
            au: Au::None13,
            enc: Enc::AesGcm,
            bits: 128,
            prf: Prf::Sha256,
        },
    },
    Suite {
        rustls: ring::TLS13_CHACHA20_POLY1305_SHA256,
        iana: "TLS_CHACHA20_POLY1305_SHA256",
        openssl: "",
        tls13: true,
        attrs: Attrs {
            kx: Kx::None13,
            au: Au::None13,
            enc: Enc::Chacha20,
            bits: 256,
            prf: Prf::Sha256,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        iana: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        openssl: "ECDHE-ECDSA-AES256-GCM-SHA384",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Ecdsa,
            enc: Enc::AesGcm,
            bits: 256,
            prf: Prf::Sha384,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        iana: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        openssl: "ECDHE-ECDSA-AES128-GCM-SHA256",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Ecdsa,
            enc: Enc::AesGcm,
            bits: 128,
            prf: Prf::Sha256,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        iana: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        openssl: "ECDHE-ECDSA-CHACHA20-POLY1305",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Ecdsa,
            enc: Enc::Chacha20,
            bits: 256,
            prf: Prf::Sha256,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        iana: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        openssl: "ECDHE-RSA-AES256-GCM-SHA384",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Rsa,
            enc: Enc::AesGcm,
            bits: 256,
            prf: Prf::Sha384,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        iana: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        openssl: "ECDHE-RSA-AES128-GCM-SHA256",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Rsa,
            enc: Enc::AesGcm,
            bits: 128,
            prf: Prf::Sha256,
        },
    },
    Suite {
        rustls: ring::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        iana: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        openssl: "ECDHE-RSA-CHACHA20-POLY1305",
        tls13: false,
        attrs: Attrs {
            kx: Kx::Ecdhe,
            au: Au::Rsa,
            enc: Enc::Chacha20,
            bits: 256,
            prf: Prf::Sha256,
        },
    },
];

/// Does one OpenSSL alias describe this suite?
///
/// `None` when the word is not an alias this evaluator knows. `Some(false)` is a
/// word it knows that does not apply — including every family OpenSSL has and
/// this build does not, which is why `3DES` selects nothing rather than failing
/// to parse.
fn alias_matches(word: &str, s: &Suite) -> Option<bool> {
    let a = &s.attrs;
    let aes = a.enc == Enc::AesGcm;
    Some(match word.to_ascii_uppercase().as_str() {
        // Everything, and the ordinary default. This build has no NULL or
        // export suites, so the two are the same set here.
        "ALL" | "DEFAULT" => true,
        "COMPLEMENTOFALL" | "COMPLEMENTOFDEFAULT" => false,

        // Strength classes. Every suite here is an AEAD of at least 128 bits.
        "HIGH" => true,
        "MEDIUM" | "LOW" | "EXP" | "EXPORT" | "EXPORT40" | "EXPORT56" => false,

        // Key exchange. `RSA` is OpenSSL's name for *kRSA* — static RSA key
        // exchange — which is not what `ECDHE-RSA-…` uses and not something
        // this build has at all. Authentication is `aRSA`; conflating them is
        // the single easiest way to read one of these strings backwards.
        "ECDHE" | "EECDH" | "KEECDH" | "KECDHE" | "ECDH" => a.kx == Kx::Ecdhe,
        "KRSA" | "RSA" | "DH" | "DHE" | "EDH" | "KDHE" | "KEDH" | "ADH" | "AECDH" | "PSK"
        | "SRP" | "KGOST" | "GOST" => false,

        // Authentication.
        "ARSA" => a.au == Au::Rsa,
        "AECDSA" | "ECDSA" => a.au == Au::Ecdsa,
        "ANULL" | "ADSS" | "DSS" | "DSA" | "AGOST" => false,

        // Bulk cipher.
        "AES" | "AESGCM" => aes,
        "AES128" | "AES128GCM" => aes && a.bits == 128,
        "AES256" | "AES256GCM" => aes && a.bits == 256,
        "CHACHA20" | "CHACHA20POLY1305" => a.enc == Enc::Chacha20,
        "3DES" | "DES" | "RC2" | "RC4" | "IDEA" | "SEED" | "CAMELLIA" | "ARIA" | "ENULL"
        | "NULL" | "AESCCM" | "AESCCM8" => false,

        // MAC / PRF.
        "SHA256" => a.prf == Prf::Sha256,
        "SHA384" => a.prf == Prf::Sha384,
        "MD5" | "SHA1" | "SHA" | "AEAD" => false,

        // Protocol vintage. Aliases are only ever evaluated over the TLS 1.2
        // suites (see `evaluate`), so `TLSv1.2` is all of them and `TLSv1.3`
        // names a list this expression cannot reach.
        "TLSV1.2" => true,
        "TLSV1.3" | "SSLV3" | "TLSV1" | "TLSV1.0" | "TLSV1.1" | "SSLV2" => false,

        _ => return None,
    })
}

/// What one token of a cipher string selects, or `None` if it names nothing
/// this evaluator recognises.
///
/// A token may be a conjunction: OpenSSL's **infix** `+` is a logical AND, so
/// `ECDHE+AESGCM` is "ECDHE *and* AES-GCM". (The *leading* `+` is a different
/// operator entirely — see [`evaluate`].)
fn token_selects(token: &str, s: &Suite) -> Option<bool> {
    // A full suite name, in either spelling, selects exactly itself.
    if token.eq_ignore_ascii_case(s.iana)
        || (!s.openssl.is_empty() && token.eq_ignore_ascii_case(s.openssl))
    {
        return Some(true);
    }
    // …but a name that belongs to *some* suite must not fall through to the
    // alias table, or a typo would silently become an alias miss.
    if names_a_suite(token) {
        return Some(false);
    }
    let mut all = true;
    for word in token.split('+') {
        all &= alias_matches(word, s)?;
    }
    Some(all)
}

/// Is this token the full name of one of our suites?
fn names_a_suite(token: &str) -> bool {
    SUITES.iter().any(|s| {
        token.eq_ignore_ascii_case(s.iana)
            || (!s.openssl.is_empty() && token.eq_ignore_ascii_case(s.openssl))
    })
}

/// A `ciphers` string that selected nothing at all.
#[derive(Debug)]
pub struct NoCipherMatch {
    /// The tokens that came up empty, for a message worth reading.
    pub tokens: Vec<String>,
}

impl std::fmt::Display for NoCipherMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no cipher match: {} names no cipher suite this build has. \
             Available: TLS 1.3 AES-GCM/ChaCha20, TLS 1.2 ECDHE with AES-GCM/ChaCha20",
            self.tokens.join(", ")
        )
    }
}

/// A `ciphers` string, evaluated into the two lists rustls needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CipherPolicy {
    /// Indices into [`SUITES`], in the order the expression produced — TLS 1.3
    /// first, as rustls orders its own list.
    order: Vec<usize>,
}

impl CipherPolicy {
    /// The suites to offer, in order.
    pub fn suites(&self) -> Vec<SupportedCipherSuite> {
        self.order.iter().map(|&i| SUITES[i].rustls).collect()
    }

    /// The suite names, for logging what a rule actually did.
    pub fn names(&self) -> Vec<&'static str> {
        self.order
            .iter()
            .map(|&i| match SUITES[i].openssl.is_empty() {
                true => SUITES[i].iana,
                false => SUITES[i].openssl,
            })
            .collect()
    }
}

/// Evaluate an OpenSSL cipher string over the suites this build has.
///
/// The algorithm is OpenSSL's own, left to right over an ordered list:
///
/// * a plain token **appends** the suites it selects that are not already in the
///   list and have not been permanently removed;
/// * `!token` removes them and blacklists them, so a later token cannot bring
///   them back;
/// * `-token` removes them, and a later token can;
/// * `+token` moves the ones already in the list to the **end** (deprioritise);
/// * `@STRENGTH` sorts the list by key size, strongest first.
///
/// The TLS 1.3 half follows what Node does, which was measured rather than
/// assumed: a string that names no TLS 1.3 suite leaves all three in place, and
/// one that names any restricts to those. See the module doc for why applying
/// the TLS 1.2 half to TLS 1.3 would be a downgrade rather than a pin.
pub fn evaluate(spec: &str) -> Result<CipherPolicy, NoCipherMatch> {
    let mut list: Vec<usize> = Vec::new();
    let mut banned: Vec<usize> = Vec::new();
    let mut named13: Vec<usize> = Vec::new();
    let mut empty_tokens: Vec<String> = Vec::new();

    for raw in spec
        .split([':', ',', ' '])
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        // `@STRENGTH` and `@SECLEVEL=n` are directives, not selections.
        if let Some(directive) = raw.strip_prefix('@') {
            if directive.eq_ignore_ascii_case("STRENGTH") {
                list.sort_by_key(|&i| std::cmp::Reverse(SUITES[i].attrs.bits));
            }
            // `@SECLEVEL=n` sets a floor this build is already above: every
            // suite here is a ≥128-bit AEAD with forward secrecy or TLS 1.3.
            continue;
        }
        let (op, token) = match raw.as_bytes()[0] {
            b'!' => ('!', &raw[1..]),
            b'-' => ('-', &raw[1..]),
            b'+' => ('+', &raw[1..]),
            _ => (' ', raw),
        };
        if token.is_empty() {
            continue;
        }

        // A TLS 1.3 suite addresses the *other* list, and only by name. This is
        // the whole of what an alias may not do: measured against Node,
        // `CHACHA20` leaves TLS 1.3 at its default while
        // `TLS_CHACHA20_POLY1305_SHA256` pins it. An alias reaching the 1.3 list
        // would silently narrow it on strings that never meant to.
        if let Some(i) = SUITES
            .iter()
            .position(|s| s.tls13 && token.eq_ignore_ascii_case(s.iana))
        {
            if op == ' ' && !named13.contains(&i) {
                named13.push(i);
            }
            continue;
        }

        // Everything else is evaluated over the TLS 1.2 universe, which is what
        // an OpenSSL cipher list has always been about.
        let hit: Vec<usize> = SUITES
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.tls13)
            .filter(|(_, s)| token_selects(token, s) == Some(true))
            .map(|(i, _)| i)
            .collect();
        if hit.is_empty() {
            // Worth naming later if the whole string turns out empty: whether
            // the word was unknown or merely absent from this build, something
            // was asked for and not given.
            empty_tokens.push(raw.to_string());
            continue;
        }
        match op {
            '!' => {
                list.retain(|i| !hit.contains(i));
                banned.extend(hit);
            }
            '-' => list.retain(|i| !hit.contains(i)),
            '+' => {
                // Deprioritise: the ones already in the list move to the end,
                // keeping their order. A `+` never *adds* a suite — that is what
                // distinguishes it from a plain token.
                let moving: Vec<usize> = list.iter().copied().filter(|i| hit.contains(i)).collect();
                list.retain(|i| !moving.contains(i));
                list.extend(moving);
            }
            _ => {
                for i in hit {
                    if !banned.contains(&i) && !list.contains(&i) {
                        list.push(i);
                    }
                }
            }
        }
    }

    // Nothing at all was selected — neither list. OpenSSL throws `no cipher
    // match` at context creation, before any connection, and so does this.
    // Measured, not assumed; see the module doc.
    if list.is_empty() && named13.is_empty() {
        return Err(NoCipherMatch {
            tokens: match empty_tokens.is_empty() {
                true => vec![spec.trim().to_string()],
                false => empty_tokens,
            },
        });
    }

    // A string that named no TLS 1.3 suite leaves all three in place. That is
    // Node's behaviour and the alternative is a downgrade: with no 1.3 suite to
    // offer, a connection that could have been TLS 1.3 falls back to 1.2.
    let mut order: Vec<usize> = match named13.is_empty() {
        true => SUITES
            .iter()
            .enumerate()
            .filter(|(_, s)| s.tls13)
            .map(|(i, _)| i)
            .collect(),
        false => named13,
    };
    order.extend(list);
    Ok(CipherPolicy { order })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names the policy selected, TLS 1.2 ones only — the half a cipher
    /// string is really about.
    fn tls12(spec: &str) -> Vec<&'static str> {
        let p = evaluate(spec).expect("a policy");
        p.order
            .iter()
            .filter(|&&i| !SUITES[i].tls13)
            .map(|&i| SUITES[i].openssl)
            .collect()
    }

    /// The TLS 1.3 names selected.
    fn tls13(spec: &str) -> Vec<&'static str> {
        let p = evaluate(spec).expect("a policy");
        p.order
            .iter()
            .filter(|&&i| SUITES[i].tls13)
            .map(|&i| SUITES[i].iana)
            .collect()
    }

    /// The finding that matters most, because getting it wrong downgrades the
    /// connection: a TLS 1.2 name must leave all three TLS 1.3 suites in place.
    /// Measured against Node 26 / OpenSSL 3.6 — see the module doc.
    #[test]
    fn a_tls12_pin_does_not_touch_the_tls13_suites() {
        assert_eq!(
            tls12("ECDHE-RSA-AES128-GCM-SHA256"),
            ["ECDHE-RSA-AES128-GCM-SHA256"]
        );
        assert_eq!(
            tls13("ECDHE-RSA-AES128-GCM-SHA256").len(),
            3,
            "all three, or the connection downgrades to 1.2 to find a suite"
        );
    }

    /// An **alias** never reaches the TLS 1.3 list, even when it plainly
    /// describes those suites. Measured against Node: `CHACHA20` leaves TLS 1.3
    /// at `TLS_AES_256_GCM_SHA384`, where the explicit name pins it. Reading
    /// this the other way narrows 1.3 on strings that never meant to.
    #[test]
    fn an_alias_never_reaches_the_tls13_list() {
        for alias in ["CHACHA20", "AESGCM", "AES128", "ECDHE+AESGCM", "HIGH"] {
            assert_eq!(tls13(alias).len(), 3, "{alias} must leave TLS 1.3 alone");
        }
        // …and the TLS 1.2 half of the same strings is still selected.
        assert_eq!(tls12("CHACHA20").len(), 2);
    }

    /// …and a TLS 1.3 name does constrain them, which Node also does.
    #[test]
    fn a_tls13_name_selects_only_that_tls13_suite() {
        assert_eq!(tls13("TLS_AES_128_GCM_SHA256"), ["TLS_AES_128_GCM_SHA256"]);
        assert!(
            tls12("TLS_AES_128_GCM_SHA256").is_empty(),
            "as OpenSSL empties it"
        );
    }

    /// The whole point: an ordinary string people actually write evaluates to
    /// an ordinary answer, with nothing to warn about.
    #[test]
    fn the_strings_people_write_just_work() {
        assert_eq!(
            tls12("HIGH:!aNULL:!MD5").len(),
            6,
            "every suite here is HIGH"
        );
        assert_eq!(tls12("DEFAULT").len(), 6);
        assert_eq!(tls12("ALL").len(), 6);
        assert_eq!(tls12("AESGCM").len(), 4, "the four AES-GCM suites");
        assert_eq!(tls12("CHACHA20").len(), 2);
        assert_eq!(tls12("ECDHE").len(), 6);
    }

    /// OpenSSL's infix `+` is a logical AND, and `ECDHE+AESGCM` is one of the
    /// most-written cipher strings there is.
    #[test]
    fn an_infix_plus_is_a_conjunction() {
        assert_eq!(tls12("ECDHE+AESGCM").len(), 4);
        assert_eq!(tls12("ECDHE+CHACHA20").len(), 2);
        assert_eq!(tls12("aRSA+AES256").len(), 1);
        assert_eq!(tls12("aRSA+AES256"), ["ECDHE-RSA-AES256-GCM-SHA384"]);
    }

    /// `RSA` is *key exchange*, `aRSA` is authentication. Confusing them reads
    /// the string backwards, and this build has no kRSA suites at all —
    /// confirmed against OpenSSL, which answers `RSA` with `AES256-GCM-SHA384`,
    /// a static-RSA suite rustls does not implement.
    #[test]
    fn rsa_is_key_exchange_and_arsa_is_authentication() {
        assert_eq!(tls12("aRSA").len(), 3);
        assert!(evaluate("RSA").is_err(), "kRSA: this build has none");
    }

    /// Removal, permanent and otherwise.
    #[test]
    fn exclusion_removes_and_bang_forbids() {
        assert_eq!(tls12("AESGCM:-AES128").len(), 2, "the 256-bit AES-GCM pair");
        // `-` allows a later token to bring them back; `!` does not.
        assert_eq!(tls12("ALL:-AESGCM:AES128").len(), 4);
        assert_eq!(
            tls12("ALL:!AESGCM:AES128").len(),
            2,
            "only the ChaCha20 pair"
        );
        assert_eq!(tls12("HIGH:!CHACHA20").len(), 4);
    }

    /// `@STRENGTH` sorts by key size, strongest first.
    #[test]
    fn strength_sorts_the_list() {
        let sorted = tls12("AESGCM:@STRENGTH");
        let bits: Vec<u16> = sorted
            .iter()
            .map(|n| SUITES.iter().find(|s| s.openssl == *n).unwrap().attrs.bits)
            .collect();
        assert_eq!(bits, [256, 256, 128, 128]);
    }

    /// A family OpenSSL has and this build does not selects nothing — the same
    /// answer OpenSSL gives when compiled without it.
    #[test]
    fn a_family_this_build_lacks_selects_nothing() {
        for spec in ["3DES", "RC4", "DES-CBC3-SHA", "DH", "PSK", "aNULL"] {
            assert!(evaluate(spec).is_err(), "{spec} should select nothing");
        }
    }

    /// And the error names what came up empty, which OpenSSL's own message does
    /// not do.
    #[test]
    fn the_error_names_the_tokens_that_found_nothing() {
        let err = evaluate("3DES:RC4").expect_err("nothing to select");
        assert_eq!(err.tokens, ["3DES", "RC4"]);
        assert!(err.to_string().contains("no cipher match"));
    }

    /// An unknown word is not a parse failure — it simply selects nothing, and
    /// only matters if the whole string came up empty. `HIGH` carries this one.
    #[test]
    fn an_unknown_word_alongside_a_real_one_is_survivable() {
        assert_eq!(tls12("HIGH:!NOTACIPHER").len(), 6);
        assert!(evaluate("NOTACIPHER").is_err());
    }

    /// Every suite named is one the provider really carries, so a policy can
    /// only ever narrow what is negotiated.
    #[test]
    fn every_selected_suite_is_one_the_provider_has() {
        let provider = rustls::crypto::ring::default_provider();
        for suite in evaluate("ALL").expect("all").suites() {
            assert!(
                provider.cipher_suites.contains(&suite),
                "{:?}",
                suite.suite()
            );
        }
    }

    /// The separators a person actually types.
    #[test]
    fn the_list_may_be_separated_three_ways() {
        for spec in ["AES128:AES256", "AES128,AES256", "AES128 AES256"] {
            assert_eq!(tls12(spec).len(), 4, "{spec}");
        }
    }
}
