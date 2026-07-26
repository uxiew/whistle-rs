//! The `sni` hook — a plugin that chooses the certificate for an intercepted
//! TLS connection, or declines the interception altogether.
//!
//! ## What is different about this hook
//!
//! Every other hook in this plugin system runs on a *request*. This one runs on
//! a *connection*, before there is a request to run on: the only thing known
//! when it is called is what the client put in its ClientHello. So its payload
//! is not the request context the other hooks share — there is no method, no
//! URL, no headers, no body, and there never can be. What it gets is the server
//! name, the address the tunnel was opened to, and the client's own address.
//!
//! It is also the only hook that can decide **not** to look: answering
//! `{"intercept": false}` leaves the connection encrypted end to end and relays
//! it to the origin untouched. Nothing else in this system can turn interception
//! off, because nothing else runs early enough to.
//!
//! ## The wire
//!
//! ```text
//! POST /sni
//! { "servername": "api.example.com", "value": "staging",
//!   "tunnelHost": "api.example.com", "port": 443, "clientIp": "127.0.0.1",
//!   "certCacheName": "mycerts", "certCacheTime": 1737849600 }
//! ```
//!
//! `servername` is what the ClientHello asked for, falling back to the CONNECT
//! authority when the client sent no SNI. `value` is the `(…)` argument of
//! `sniCallback://name(value)` — upstream's `req.originalReq.sniValue`. The two
//! `certCache*` fields name the certificate this proxy already holds for this
//! server name **from this plugin**, so a plugin that would only re-issue the
//! same one can say `{"reuse": true}` instead (upstream's `certCacheName` /
//! `certCacheTime`, `lib/plugins/load-plugin.js:231-238`).
//!
//! The reply is a JSON object, and there are four things it can say:
//!
//! | reply | meaning |
//! |-------|---------|
//! | `{"intercept": true}` | intercept, with whistle-rs's own generated certificate |
//! | `{"intercept": false}` | **do not intercept** — relay the connection opaquely |
//! | `{"key": "…", "cert": "…", "mtime": 0}` | intercept, presenting this certificate |
//! | `{"reuse": true}` | intercept, with the certificate this plugin last supplied |
//!
//! A bare JSON `true` / `false` is accepted as shorthand for the first two,
//! which is also what upstream's hook writes on the wire
//! (`lib/plugins/load-plugin.js:1848-1851`).
//!
//! Anything else — `204`, an empty body, a field we do not recognise — is this
//! protocol's "nothing to say", and means the generated certificate.
//!
//! ## What a broken plugin means
//!
//! **It means the generated certificate**: unreachable, slow, non-200, garbage
//! in the body — the connection is intercepted exactly as it would have been
//! with no `sniCallback://` rule at all, and a `WARN` names the plugin and the
//! server name.
//!
//! This is the one place in whistle-rs where the failure policy is a **policy
//! call rather than an implementation detail**, and it is worth being explicit
//! about why, because the project's settled posture elsewhere is to fail closed
//! (a broken gate blocks, a failing PAC is a `502`, origin TLS verification is
//! on by default).
//!
//! The reason it does not apply here is that "closed" has two readings and they
//! point in opposite directions:
//!
//! * *Do not present a certificate the operator did not sanction* → a failure
//!   should stop intercepting, i.e. behave as if the plugin had said `false`.
//! * *Do not silently stop debugging traffic the operator asked to see* → a
//!   failure should keep intercepting with the certificate the proxy would have
//!   generated anyway.
//!
//! whistle-rs takes the second, for two reasons. The certificate it falls back
//! to is its own, signed by the root the user deliberately installed — it is not
//! a third party's identity, and presenting it is precisely what this proxy does
//! for every other host. And a plugin restart would otherwise punch a silent
//! hole in the capture that looks exactly like a working proxy. Upstream lands
//! in the same place (`loadCert`'s error path keeps whatever certificate is
//! cached and otherwise falls through to the generated one,
//! `lib/plugins/index.js:245-247`, `lib/https/load-cert.js:41-53`).
//!
//! A deployment that wants the other reading — where a `sniCallback` plugin
//! going down means the connection is passed through rather than intercepted —
//! would need this to be configurable. It is not, today, and that is recorded as
//! a limitation rather than pretended away.

use std::time::Duration;

/// How long to wait for a certificate before giving up and generating one.
///
/// The same budget as the gate ([`super::auth::AUTH_TIMEOUT`]) so the plugin
/// protocol has one answer to "how long is a plugin allowed to think", but the
/// consequence of spending it is very different: this one sits inside a TLS
/// handshake, so every millisecond is a millisecond the client is waiting with
/// nothing to show for it.
pub const SNI_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on a certificate reply. Upstream caps the same thing at the same
/// size (`MAX_CERT_SIZE`, `_original/lib/plugins/index.js:237`).
///
/// A certificate chain and a key are kilobytes; a reply bigger than this is a
/// plugin that has gone wrong, and parsing it would be work done on behalf of
/// the mistake.
pub const MAX_CERT_BYTES: usize = 72 * 1024;

/// What the proxy tells an `sni` hook. Everything here is known from the
/// ClientHello and the socket — there is no request yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniReq {
    /// The name the ClientHello asked for, or the CONNECT authority when the
    /// client sent no SNI. This is the name the certificate has to satisfy.
    pub servername: String,
    /// The `(…)` argument of `sniCallback://name(value)`.
    pub value: String,
    /// The host half of the address the tunnel was opened to. Differs from
    /// [`servername`](Self::servername) when the client resolved the name
    /// itself, or named one host and asked for another.
    pub tunnel_host: String,
    /// The port half of the same address.
    pub port: u16,
    /// The client's address, when known.
    pub client_ip: Option<String>,
    /// The plugin that supplied the certificate this proxy currently holds for
    /// [`servername`](Self::servername), if it holds one and this plugin is the
    /// one that supplied it.
    pub cert_cache_name: Option<String>,
    /// The `mtime` that certificate came with (`0` when it came without one).
    pub cert_cache_time: u64,
}

/// A certificate a plugin supplied, still in PEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCert {
    /// PEM certificate — a leaf, optionally followed by a chain.
    pub cert_pem: String,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key_pem: String,
    /// Issue time the plugin stamped on it, echoed back in
    /// [`SniReq::cert_cache_time`] next time. `0` means "not stated".
    pub mtime: u64,
}

/// What an `sni` hook decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniVerdict {
    /// No opinion: intercept with whistle-rs's own generated certificate, which
    /// is what would have happened had no rule matched. Also the answer for
    /// every failure — see the module docs.
    Generated,
    /// Intercept, presenting this certificate.
    Cert(Box<PluginCert>),
    /// Intercept with the certificate this plugin last supplied for this server
    /// name. Falls back to [`Generated`](Self::Generated) if there is none.
    Reuse,
    /// Do not intercept: relay the connection to the origin opaquely.
    Bypass,
}

/// The `POST /sni` payload.
pub fn payload(req: &SniReq) -> serde_json::Value {
    let mut v = serde_json::json!({
        "servername": req.servername,
        "value": req.value,
        "tunnelHost": req.tunnel_host,
        "port": req.port,
        "clientIp": req.client_ip,
    });
    // Only present when there is a cached certificate from *this* plugin to
    // name, so a plugin can test for the field rather than for a sentinel.
    if let Some(name) = &req.cert_cache_name {
        v["certCacheName"] = serde_json::json!(name);
        v["certCacheTime"] = serde_json::json!(req.cert_cache_time);
    }
    v
}

/// Interpret a `200` reply body.
///
/// Lenient in the same way the rest of this protocol is: an unrecognised shape
/// is "nothing to say", not an error. The one shape that is checked strictly is
/// the certificate itself — both halves must be present and non-empty, because
/// a half-supplied certificate is a mistake and serving the generated one
/// instead is the safe reading of it.
pub fn parse_reply(bytes: &[u8]) -> SniVerdict {
    if bytes.len() > MAX_CERT_BYTES {
        return SniVerdict::Generated;
    }
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return SniVerdict::Generated;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return SniVerdict::Generated;
    };
    // A bare boolean is upstream's own wire format, and the obvious thing to
    // write by hand.
    if let Some(intercept) = v.as_bool() {
        return if intercept {
            SniVerdict::Generated
        } else {
            SniVerdict::Bypass
        };
    }
    if v.get("intercept").and_then(|b| b.as_bool()) == Some(false) {
        return SniVerdict::Bypass;
    }
    let text = |key: &str| {
        v.get(key)
            .and_then(|s| s.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let (Some(cert_pem), Some(key_pem)) = (text("cert"), text("key")) {
        return SniVerdict::Cert(Box::new(PluginCert {
            cert_pem,
            key_pem,
            mtime: v.get("mtime").and_then(|m| m.as_u64()).unwrap_or(0),
        }));
    }
    if v.get("reuse").and_then(|b| b.as_bool()) == Some(true) {
        return SniVerdict::Reuse;
    }
    SniVerdict::Generated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(v: SniVerdict) -> PluginCert {
        match v {
            SniVerdict::Cert(c) => *c,
            other => panic!("expected a certificate, got {other:?}"),
        }
    }

    /// The four shapes the protocol defines, in their canonical spelling.
    #[test]
    fn the_four_return_shapes() {
        assert_eq!(parse_reply(br#"{"intercept":true}"#), SniVerdict::Generated);
        assert_eq!(parse_reply(br#"{"intercept":false}"#), SniVerdict::Bypass);
        assert_eq!(parse_reply(br#"{"reuse":true}"#), SniVerdict::Reuse);
        let c = cert(parse_reply(
            br#"{"key":"-----BEGIN PRIVATE KEY-----\nk\n","cert":"-----BEGIN CERTIFICATE-----\nc\n","mtime":42}"#,
        ));
        assert!(c.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(c.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(c.mtime, 42);
    }

    /// Upstream writes a bare `true` / `false` on the wire; both are accepted.
    #[test]
    fn a_bare_boolean_is_shorthand() {
        assert_eq!(parse_reply(b"false"), SniVerdict::Bypass);
        assert_eq!(parse_reply(b"true"), SniVerdict::Generated);
    }

    /// Every malformed shape means "nothing to say" — never a bypass, and never
    /// a certificate built from half a reply.
    #[test]
    fn malformed_replies_mean_the_generated_certificate() {
        for body in [
            &b""[..],
            b"   \n",
            b"not json at all",
            b"[1,2,3]",
            b"{}",
            // Only one half of a certificate.
            br#"{"cert":"-----BEGIN CERTIFICATE-----"}"#,
            br#"{"key":"-----BEGIN PRIVATE KEY-----"}"#,
            // Present but empty, which is the same mistake spelled differently.
            br#"{"cert":"","key":""}"#,
            br#"{"cert":"  ","key":"x"}"#,
            // `intercept` is only consulted for `false`; a non-boolean is noise.
            br#"{"intercept":"false"}"#,
            br#"{"reuse":"yes"}"#,
        ] {
            assert_eq!(
                parse_reply(body),
                SniVerdict::Generated,
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// A reply past the cap is refused whole rather than parsed — including one
    /// that would otherwise have been a valid certificate.
    #[test]
    fn an_oversized_reply_is_refused() {
        let huge = format!(
            r#"{{"key":"k","cert":"{}"}}"#,
            "c".repeat(MAX_CERT_BYTES + 1)
        );
        assert_eq!(parse_reply(huge.as_bytes()), SniVerdict::Generated);
    }

    /// The cache fields appear only when there is something to name, so a plugin
    /// can test for the field itself.
    #[test]
    fn the_cache_fields_are_absent_until_there_is_a_cache() {
        let mut req = SniReq {
            servername: "a.example.com".into(),
            value: "staging".into(),
            tunnel_host: "a.example.com".into(),
            port: 443,
            client_ip: Some("127.0.0.1".into()),
            ..SniReq::default()
        };
        let bare = payload(&req);
        assert!(bare.get("certCacheName").is_none());
        assert!(bare.get("certCacheTime").is_none());
        assert_eq!(bare["servername"], "a.example.com");
        assert_eq!(bare["value"], "staging");
        assert_eq!(bare["port"], 443);

        req.cert_cache_name = Some("mycerts".into());
        req.cert_cache_time = 99;
        let cached = payload(&req);
        assert_eq!(cached["certCacheName"], "mycerts");
        assert_eq!(cached["certCacheTime"], 99);
    }
}
