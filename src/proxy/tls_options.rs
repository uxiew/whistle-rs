//! What a `tlsOptions://` rule says about the origin handshake besides its
//! versions and cipher suites: **who this proxy is** to the origin — a client
//! certificate — and **whom it trusts** there.
//!
//! [`cipher.md`] opens with it: "配置双向认证（mTLS）所需的客户端证书". Upstream
//! reads `key`/`cert`, or `pfx` and its passphrase, off the merged `cipher`
//! options and hands them to `tls.connect` (`getClientCert`,
//! `_original/lib/rules/index.js:740-845`; `setClientCert`,
//! `lib/util/index.js`). This port parsed the options, kept the version and the
//! suites, and built every origin connection `with_no_client_auth()`: a rule
//! that named a certificate connected without one, and an origin that demands
//! one answered with a handshake alert.
//!
//! # What is read
//!
//! | option | |
//! |---|---|
//! | `key` + `cert` | PEM, each a path or the text itself (a value that starts `-----`). `cert` may hold a chain, leaf first |
//! | `pfx` + `passphrase` (or `pwd`) | a PKCS#12 file's path |
//! | `base` | a directory the paths above are relative to |
//! | `ca` | PEM, a path or the text: the roots the origin's certificate must chain to, **instead of** the built-in ones — Node's meaning |
//! | `rejectUnauthorized=false` | do not verify this origin's certificate |
//!
//! The last two matter more here than upstream, which verifies nothing unless
//! started with `--safe`: they are how one rule reaches a private-CA origin
//! without `--insecure-upstream` turning verification off for every origin.
//!
//! # What is not
//!
//! [`UNSUPPORTED`] — the options Node passes to OpenSSL that rustls has no
//! equivalent for. They are named on the request's session rather than
//! ignored in silence. (Upstream applies most of them only while retrying a
//! handshake that failed on its ciphers, so on a connection that works they
//! do nothing there either — see `docs/RULES.md`.)
//!
//! # A certificate that cannot be used fails the request
//!
//! A key file that is not there, a key that is not the certificate's, a PFX
//! whose passphrase is wrong: upstream connects without a certificate and
//! lets the origin refuse. Here the request stops with the reason, before
//! anything is dialled. A rule that names an identity and a connection made
//! without it are two different things, and the second is the one that ends
//! up in an access log under nobody's name.
//!
//! [`cipher.md`]: https://wproxy.org/docs/rules/cipher.html

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// Options `tls.connect` takes that this port's TLS library cannot honour.
pub const UNSUPPORTED: &[&str] = &[
    "crl",
    "allowPartialTrustChain",
    "sessionIdContext",
    "sigalgs",
    "dhparam",
    "ecdhCurve",
    "secureOptions",
    "sessionTimeout",
    "honorCipherOrder",
];

/// The identity and trust one `tlsOptions://` rule set adds to a handshake.
pub struct TlsExtras {
    /// A digest of everything below. Two rules that name the same certificate
    /// and the same trust share a connection; any difference and they do not —
    /// it is part of the pool's key and of the TLS configuration cache's.
    pub id: String,
    /// The client certificate and the key that signs for it.
    identity: Option<Arc<CertifiedKey>>,
    /// `ca`: the only roots the origin's certificate may chain to.
    roots: Option<Arc<rustls::RootCertStore>>,
    /// `rejectUnauthorized=false`.
    insecure: bool,
}

impl std::fmt::Debug for TlsExtras {
    /// By what it is, never by what it holds: this ends up in a `Target`'s
    /// debug output, and a private key has no business in a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsExtras")
            .field("id", &self.id)
            .field("client_certificate", &self.identity.is_some())
            .field("ca", &self.roots.is_some())
            .field("insecure", &self.insecure)
            .finish()
    }
}

impl TlsExtras {
    /// `base` with this rule's identity and trust laid over it.
    ///
    /// The session store is **new**, not `base`'s. rustls resumes a session by
    /// server name out of the configuration's store, and a ticket issued to a
    /// connection that presented a certificate is that client's as far as the
    /// origin is concerned — shared, the next request to the same host under a
    /// rule with *no* certificate could resume into it and be served as
    /// somebody it never claimed to be.
    pub fn apply(&self, base: &rustls::ClientConfig) -> rustls::ClientConfig {
        let mut cfg = base.clone();
        cfg.resumption = rustls::client::Resumption::in_memory_sessions(32);
        if let Some(identity) = &self.identity {
            cfg.client_auth_cert_resolver = Arc::new(Presents(identity.clone()));
        }
        let provider = cfg.crypto_provider().clone();
        if self.insecure {
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(super::upstream::AcceptAnyServerCert(provider)));
        } else if let Some(roots) = &self.roots
            // `ca` under `--insecure-upstream` stays unverified: the flag said
            // every origin, and a rule cannot take that back for one.
            && !super::upstream::insecure_upstream()
        {
            match rustls::client::WebPkiServerVerifier::builder_with_provider(
                roots.clone(),
                provider,
            )
            .build()
            {
                Ok(verifier) => cfg.dangerous().set_certificate_verifier(verifier),
                // An empty store; `extras_of` refuses one before it gets here.
                Err(err) => tracing::warn!("tlsOptions ca: {err}; the built-in roots are used"),
            }
        }
        cfg
    }
}

#[cfg(test)]
impl TlsExtras {
    /// Extras that are nothing but a name, for a test about what tells two
    /// connections apart.
    pub(crate) fn named(id: &str) -> Arc<TlsExtras> {
        Arc::new(TlsExtras {
            id: id.to_string(),
            identity: None,
            roots: None,
            insecure: false,
        })
    }
}

/// Always this certificate, whatever the origin's list of acceptable issuers
/// says: the rule named it, and an origin that does not want it will say so.
#[derive(Debug)]
struct Presents(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for Presents {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The options in `options` that [`UNSUPPORTED`] lists, as the rule spelled
/// them.
pub fn unsupported(options: &serde_json::Map<String, serde_json::Value>) -> Vec<&'static str> {
    UNSUPPORTED
        .iter()
        .copied()
        .filter(|name| options.contains_key(*name))
        .collect()
}

/// A string option, or `None` when it is absent, empty or not a string —
/// upstream's `util.getString`.
fn text<'a>(
    options: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a str> {
    options
        .get(name)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Is this the PEM itself rather than where to find it? `CERT_RE = /^\s*-----/`
/// (`_original/lib/rules/index.js:39`).
fn is_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----")
}

/// Where a path option points, under `base` when there is one.
fn located(base: Option<&str>, path: &str) -> PathBuf {
    match base {
        Some(base) if !Path::new(path).is_absolute() => Path::new(base).join(path),
        _ => PathBuf::from(path),
    }
}

/// One option's bytes: the text itself, or the file it names.
async fn material(base: Option<&str>, name: &str, value: &str) -> Result<Vec<u8>, String> {
    if is_pem(value) {
        return Ok(value.as_bytes().to_vec());
    }
    let path = located(base, value);
    tokio::fs::read(&path)
        .await
        .map_err(|err| format!("tlsOptions: cannot read {name} {}: {err}", path.display()))
}

/// What says a file has changed: its length and when it was last written.
/// A path that cannot be read stamps as nothing, and the read that follows
/// says why.
async fn stamp(base: Option<&str>, value: &str) -> String {
    if is_pem(value) {
        return String::new();
    }
    match tokio::fs::metadata(located(base, value)).await {
        Ok(meta) => format!(
            "{}:{:?}",
            meta.len(),
            meta.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        ),
        Err(_) => String::new(),
    }
}

/// Identities already loaded, by what named them. A rule is read on every
/// request it matches; its certificate is parsed once.
static LOADED: Mutex<Option<HashMap<String, Arc<TlsExtras>>>> = Mutex::new(None);

/// How many are kept before the map is emptied and started again. Upstream
/// keeps sixty for an hour (`clientCerts`, `_original/lib/rules/index.js:21`).
const LOADED_MAX: usize = 64;

/// Read the identity and trust a request's merged `tlsOptions://` names.
///
/// `Ok(None)` is the ordinary case: the rule, if there is one, is about
/// versions and suites only. `Err` is a sentence for the request's session.
pub async fn extras_of(
    options: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<Arc<TlsExtras>>, String> {
    let base = text(options, "base");
    let (key, cert) = (text(options, "key"), text(options, "cert"));
    let pfx = text(options, "pfx");
    let passphrase = text(options, "pwd")
        .or_else(|| text(options, "passphrase"))
        .unwrap_or("");
    let ca = text(options, "ca");
    // `rejectUnauthorized: false`, or the `=false` of the query-string form.
    let insecure = match options.get("rejectUnauthorized") {
        Some(serde_json::Value::Bool(flag)) => !flag,
        Some(serde_json::Value::String(s)) => matches!(s.trim(), "false" | "0"),
        _ => false,
    };
    // Upstream asks for the pair first and the bundle second
    // (`rules/index.js:770-806`); half a pair is not a pair.
    let pair = key.zip(cert);
    let bundle = if pair.is_none() { pfx } else { None };
    if pair.is_none() && bundle.is_none() && ca.is_none() && !insecure {
        if key.is_some() != cert.is_some() {
            return Err(format!(
                "tlsOptions: a client certificate needs both `key` and `cert`; only `{}` was given",
                if key.is_some() { "key" } else { "cert" }
            ));
        }
        return Ok(None);
    }

    // What this request named, and the state of the files it named: the
    // cache's key. Inline PEM is in the key as itself, which is what makes two
    // different inline certificates two entries.
    let mut named =
        format!("{base:?}\n{key:?}\n{cert:?}\n{bundle:?}\n{passphrase}\n{ca:?}\n{insecure}");
    for path in [key, cert, bundle, ca].into_iter().flatten() {
        named.push('\n');
        named.push_str(&stamp(base, path).await);
    }
    if let Some(found) = LOADED
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|loaded| loaded.get(&named))
    {
        return Ok(Some(found.clone()));
    }

    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let identity = match (pair, bundle) {
        (Some((key, cert)), _) => {
            let key = material(base, "key", key).await?;
            let cert = material(base, "cert", cert).await?;
            Some(identity_from_pem(&key, &cert)?)
        }
        (None, Some(path)) => {
            let data = material(base, "pfx", path).await?;
            Some(identity_from_pfx(&data, passphrase)?)
        }
        (None, None) => None,
    };
    if let Some((certified, key_der)) = &identity {
        digest.update(b"identity");
        for cert in &certified.cert {
            digest.update(cert.as_ref());
        }
        digest.update(key_der);
    }
    let roots = match ca {
        Some(ca) => {
            let pem = material(base, "ca", ca).await?;
            let mut store = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert.map_err(|err| format!("tlsOptions: ca is not PEM: {err}"))?;
                digest.update(b"ca");
                digest.update(cert.as_ref());
                store.add(cert).map_err(|err| {
                    format!("tlsOptions: ca holds an unusable certificate: {err}")
                })?;
            }
            if store.is_empty() {
                return Err("tlsOptions: ca holds no certificate".to_string());
            }
            Some(Arc::new(store))
        }
        None => None,
    };
    if insecure {
        digest.update(b"insecure");
    }
    let id: String = digest
        .finish()
        .as_ref()
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    let extras = Arc::new(TlsExtras {
        id,
        identity: identity.map(|(certified, _)| Arc::new(certified)),
        roots,
        insecure,
    });
    let mut loaded = LOADED.lock().unwrap();
    let loaded = loaded.get_or_insert_with(HashMap::new);
    if loaded.len() >= LOADED_MAX {
        loaded.clear();
    }
    loaded.insert(named, extras.clone());
    Ok(Some(extras))
}

/// A certificate chain and its key as rustls signs with them, plus the key's
/// bytes for the digest.
type Identity = (CertifiedKey, Vec<u8>);

/// `key` + `cert`, both PEM.
fn identity_from_pem(key: &[u8], cert: &[u8]) -> Result<Identity, String> {
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert[..])
        .collect::<Result<_, _>>()
        .map_err(|err| format!("tlsOptions: cert is not PEM: {err}"))?;
    if chain.is_empty() {
        return Err("tlsOptions: cert holds no certificate".to_string());
    }
    let key = rustls_pemfile::private_key(&mut &key[..])
        .map_err(|err| format!("tlsOptions: key is not PEM: {err}"))?
        .ok_or_else(|| {
            // An encrypted key has a PEM block too, just not one of the three
            // this reads; say which it is, because "holds no key" about a file
            // that plainly holds one is no help.
            match String::from_utf8_lossy(key).contains("ENCRYPTED") {
                true => "tlsOptions: key is encrypted; decrypt it first \
                         (openssl pkey -in client.key -out client.plain.key), or use a pfx \
                         with its passphrase"
                    .to_string(),
                false => "tlsOptions: key holds no private key".to_string(),
            }
        })?;
    certified(chain, key)
}

/// `pfx` + its passphrase: a PKCS#12 bundle.
fn identity_from_pfx(data: &[u8], passphrase: &str) -> Result<Identity, String> {
    let store = p12_keystore::KeyStore::from_pkcs12(
        data,
        passphrase,
        p12_keystore::Pkcs12ImportPolicy::Relaxed,
    )
    .map_err(|err| {
        format!("tlsOptions: pfx could not be opened (wrong passphrase, or not PKCS#12): {err}")
    })?;
    let (_, chain) = store
        .private_key_chain()
        .ok_or_else(|| "tlsOptions: pfx holds no private key".to_string())?;
    let certs: Vec<CertificateDer<'static>> = chain
        .certs()
        .iter()
        .map(|cert| CertificateDer::from(cert.as_der().to_vec()))
        .collect();
    if certs.is_empty() {
        return Err("tlsOptions: pfx holds a key and no certificate for it".to_string());
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()));
    certified(certs, key)
}

/// Pair a chain with its key, and check that they are a pair.
fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Identity, String> {
    let key_der = key.secret_der().to_vec();
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|err| format!("tlsOptions: the private key cannot be used: {err}"))?;
    let certified = CertifiedKey::new(chain, signer);
    match certified.keys_match() {
        // `Unknown` is a key type rustls cannot compare; the origin will say.
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(err) => {
            return Err(format!(
                "tlsOptions: the private key does not belong to the certificate ({err})"
            ));
        }
    }
    Ok((certified, key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// A CA, and a client certificate it signed with its key, all PEM.
    struct Made {
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
    }

    fn make(name: &str) -> Made {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).expect("ca");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .signed_by(&key, &ca, &ca_key)
            .expect("cert");
        Made {
            ca_pem: ca.pem(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// No identity and no trust named: nothing to add, and no error — the
    /// rule is about versions or suites.
    #[test]
    fn a_rule_about_versions_only_adds_nothing() {
        rt().block_on(async {
            let o = options(&[("minVersion", "TLSv1.2".into()), ("ciphers", "HIGH".into())]);
            assert!(extras_of(&o).await.expect("ok").is_none());
            assert!(
                extras_of(&serde_json::Map::new())
                    .await
                    .expect("ok")
                    .is_none()
            );
        });
    }

    /// Inline PEM and the same PEM in files are one identity; a different
    /// certificate is a different one; and the key never shows in `Debug`.
    #[test]
    fn a_key_and_cert_are_an_identity_by_path_or_inline() {
        rt().block_on(async {
            let made = make("client.test");
            let dir = std::env::temp_dir().join(format!("wrs-tlsopt-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("dir");
            std::fs::write(dir.join("c.key"), &made.key_pem).expect("key");
            std::fs::write(dir.join("c.crt"), &made.cert_pem).expect("cert");

            let inline = extras_of(&options(&[
                ("key", made.key_pem.clone().into()),
                ("cert", made.cert_pem.clone().into()),
            ]))
            .await
            .expect("inline")
            .expect("an identity");
            let by_path = extras_of(&options(&[
                ("key", dir.join("c.key").to_str().unwrap().into()),
                ("cert", dir.join("c.crt").to_str().unwrap().into()),
            ]))
            .await
            .expect("paths")
            .expect("an identity");
            let by_base = extras_of(&options(&[
                ("base", dir.to_str().unwrap().into()),
                ("key", "c.key".into()),
                ("cert", "c.crt".into()),
            ]))
            .await
            .expect("base")
            .expect("an identity");
            assert_eq!(inline.id, by_path.id);
            assert_eq!(inline.id, by_base.id);
            assert!(inline.identity.is_some() && inline.roots.is_none() && !inline.insecure);

            let other = make("other.test");
            let different = extras_of(&options(&[
                ("key", other.key_pem.clone().into()),
                ("cert", other.cert_pem.clone().into()),
            ]))
            .await
            .expect("other")
            .expect("an identity");
            assert_ne!(inline.id, different.id);

            let shown = format!("{inline:?}");
            assert!(shown.contains("client_certificate: true"), "{shown}");
            assert!(
                !shown.contains("PRIVATE") && !shown.contains("BEGIN"),
                "{shown}"
            );
        });
    }

    /// Every way the material can be unusable stops here, with a sentence —
    /// not at the origin, as a handshake alert about a certificate that was
    /// never sent.
    #[test]
    fn unusable_material_is_an_error_that_says_what() {
        rt().block_on(async {
            let made = make("client.test");
            let other = make("other.test");
            for (pairs, want) in [
                // A file that is not there.
                (
                    vec![("key", "/no/such/client.key".into()), ("cert", made.cert_pem.clone().into())],
                    "cannot read key /no/such/client.key",
                ),
                // A key that belongs to some other certificate.
                (
                    vec![("key", other.key_pem.clone().into()), ("cert", made.cert_pem.clone().into())],
                    "does not belong to the certificate",
                ),
                // Half a pair.
                (vec![("cert", made.cert_pem.clone().into())], "needs both `key` and `cert`"),
                // Text that is PEM-shaped and holds nothing.
                (
                    vec![("key", made.key_pem.clone().into()), ("cert", "-----BEGIN X-----\n-----END X-----".into())],
                    "cert holds no certificate",
                ),
                // An encrypted key, which needs a passphrase this cannot apply.
                (
                    vec![
                        ("key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----".into()),
                        ("cert", made.cert_pem.clone().into()),
                    ],
                    "key is encrypted",
                ),
                // Not a PKCS#12 file at all.
                (vec![("pfx", "/no/such/client.p12".into())], "cannot read pfx"),
                // A `ca` with nothing in it.
                (vec![("ca", "-----BEGIN X-----\n-----END X-----".into())], "ca holds no certificate"),
            ] {
                let err = extras_of(&options(&pairs)).await.expect_err(want);
                assert!(err.contains(want), "{err} (wanted {want})");
            }
        });
    }

    /// `ca` and `rejectUnauthorized` are trust, not identity, and each makes
    /// its own entry.
    #[test]
    fn trust_options_stand_on_their_own() {
        rt().block_on(async {
            let made = make("client.test");
            let trusting = extras_of(&options(&[("ca", made.ca_pem.clone().into())]))
                .await
                .expect("ca")
                .expect("extras");
            assert!(trusting.roots.is_some() && trusting.identity.is_none());
            for value in [serde_json::Value::Bool(false), "false".into()] {
                let lax = extras_of(&options(&[("rejectUnauthorized", value)]))
                    .await
                    .expect("flag")
                    .expect("extras");
                assert!(lax.insecure);
                assert_ne!(lax.id, trusting.id);
            }
            // `true` is the default, and names nothing.
            assert!(
                extras_of(&options(&[("rejectUnauthorized", true.into())]))
                    .await
                    .expect("flag")
                    .is_none()
            );
        });
    }

    /// The configuration an identity produces presents the certificate, and
    /// does not share the base configuration's resumable sessions.
    #[test]
    fn applying_an_identity_gives_a_configuration_of_its_own() {
        rt().block_on(async {
            let made = make("client.test");
            let extras = extras_of(&options(&[
                ("key", made.key_pem.clone().into()),
                ("cert", made.cert_pem.clone().into()),
            ]))
            .await
            .expect("ok")
            .expect("extras");
            let base = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            assert!(!base.client_auth_cert_resolver.has_certs());
            let cfg = extras.apply(&base);
            assert!(cfg.client_auth_cert_resolver.has_certs());
        });
    }

    #[test]
    fn options_this_build_cannot_honour_are_named() {
        let o = options(&[
            ("dhparam", "x".into()),
            ("secureOptions", 4.into()),
            ("minVersion", "TLSv1.2".into()),
            ("key", "k".into()),
        ]);
        assert_eq!(unsupported(&o), ["dhparam", "secureOptions"]);
        assert!(unsupported(&serde_json::Map::new()).is_empty());
    }
}
