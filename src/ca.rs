//! Certificate authority for HTTPS interception (MITM).
//!
//! Ported from `_original/lib/https/ca.js`. whistle generates a self-signed root
//! CA once, persists it, and signs a short-lived leaf certificate per SNI host
//! on demand. The user installs the root CA to trust intercepted traffic.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

/// How many signed hosts to keep acceptors for, matching upstream's
/// `cachePairs = new LRU({ max: 5120 })` (`_original/lib/https/ca.js:38`).
/// Without a bound, one connection per made-up SNI name grows the process
/// without limit.
const MAX_CACHED_HOSTS: usize = 5120;

/// Bounded per-host cache.
///
/// Eviction is first-in-first-out rather than least-recently-used: the entries
/// are interchangeable (regenerating one costs a single signature) and FIFO
/// keeps the hot path a plain hash lookup with no bookkeeping write.
struct HostCache<V> {
    by_host: HashMap<String, V>,
    inserted: VecDeque<String>,
}

/// The generated leaf certificates, one per signed name.
type AcceptorCache = HostCache<Leaf>;

/// A leaf this proxy signed, and when — so it is replaced before it expires.
#[derive(Clone)]
struct Leaf {
    acceptor: TlsAcceptor,
    issued: SystemTime,
}

impl Leaf {
    /// Still worth serving: signed less than [`LEAF_REISSUE_AFTER`] ago. A clock
    /// that moved backwards reads as fresh, which only delays the re-issue.
    fn fresh(&self) -> bool {
        self.issued
            .elapsed()
            .map_or(true, |age| age < LEAF_REISSUE_AFTER)
    }
}

// Derived `Default` would demand `V: Default`, which neither value here has.
impl<V> Default for HostCache<V> {
    fn default() -> Self {
        HostCache {
            by_host: HashMap::new(),
            inserted: VecDeque::new(),
        }
    }
}

impl<V: Clone> HostCache<V> {
    fn get(&self, host: &str) -> Option<V> {
        self.by_host.get(host).cloned()
    }

    fn insert(&mut self, host: String, value: V) {
        if self.by_host.insert(host.clone(), value).is_none() {
            self.inserted.push_back(host);
        }
        while self.inserted.len() > MAX_CACHED_HOSTS {
            if let Some(oldest) = self.inserted.pop_front() {
                self.by_host.remove(&oldest);
            }
        }
    }

    fn remove(&mut self, host: &str) {
        if self.by_host.remove(host).is_some() {
            self.inserted.retain(|h| h != host);
        }
    }
}

/// A certificate a `sniCallback` plugin supplied, kept so the next connection
/// to the same server name does not have to ask again.
///
/// Upstream keeps the same thing, under the same name and for the same reason
/// (`ca.remoteCerts`, `_original/lib/https/ca.js`; read and written by
/// `lib/https/load-cert.js:12,:38-50`). Holding the PEM alongside the built
/// acceptor is what makes "the plugin sent the same certificate again" a string
/// comparison instead of a second parse and key check.
#[derive(Clone)]
struct RemoteCert {
    /// Which plugin supplied it — reported back to that plugin as
    /// `certCacheName`, and the reason a *different* plugin's rule never sees a
    /// cache hit it did not put there.
    plugin: String,
    /// The `mtime` the plugin stamped on it, reported back as `certCacheTime`.
    mtime: u64,
    cert_pem: String,
    key_pem: String,
    acceptor: TlsAcceptor,
}

/// The root CA, a cache of per-host TLS acceptors, and the certificates
/// `sniCallback` plugins have supplied.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    /// PEM of the root certificate (for serving to the user to install).
    ca_cert_pem: String,
    acceptors: Mutex<AcceptorCache>,
    /// Plugin-supplied certificates, keyed by the server name they were
    /// supplied for. Bounded the same way the generated ones are, and for the
    /// same reason: one entry per made-up SNI name would otherwise grow forever.
    remote_certs: Mutex<HostCache<RemoteCert>>,
    /// Certificates supplied by hand in `--cert-dir`, keyed by **every name the
    /// certificate carries**. Read once at startup and never evicted: the
    /// directory is small, somebody put each file there on purpose, and a
    /// certificate that fell out of a cache would be silently replaced by a
    /// forged one — which is the failure the whole feature exists to avoid.
    custom_certs: std::collections::HashMap<String, TlsAcceptor>,
    /// Where the root actually came from. Not always the storage directory: a
    /// `root.crt` in `--cert-dir` replaces it, and a startup line naming the
    /// file that is *not* in use would send somebody to install the wrong one.
    ca_cert_path: std::path::PathBuf,
}

/// Hold `certs/root.lock` while deciding whether a root exists and writing one
/// if not, so starts that race on an empty directory make one root between
/// them: the first writes it, the rest wait and read it. Without this each wrote
/// its own and kept using it, while the disk kept only the last.
///
/// The binary already has the whole directory to itself (`crate::dir_lock`);
/// this is for embedders, which may share a directory to share a root. A
/// filesystem that cannot lock gets the old behaviour rather than no CA.
fn creation_lock(cert_path: &std::path::Path) -> Option<std::fs::File> {
    let dir = cert_path.parent()?;
    crate::private_fs::create_dir(dir).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("root.lock"))
        .ok()?;
    match file.lock() {
        Ok(()) => Some(file),
        Err(e) => {
            tracing::debug!("cannot lock {}: {e}", dir.join("root.lock").display());
            None
        }
    }
}

impl CertAuthority {
    /// Load the persisted root CA, or generate and persist a fresh one.
    pub fn load_or_create(config: &Config) -> Result<Arc<Self>> {
        let cert_path = config.root_ca_cert_path();
        let key_path = config.root_ca_key_path();

        // A `root.key` + `root.crt` in the certificate directory replaces the
        // root CA outright. It is the only way to supply one — the console's own
        // upload form refuses a root (`gui/https.md`) — and it is why the flag
        // takes a directory rather than a pair of paths.
        let custom_root = config.cert_dir.as_ref().and_then(|dir| {
            let cert = ["crt", "cer", "pem"]
                .iter()
                .map(|ext| dir.join(format!("root.{ext}")))
                .find(|p| p.exists())?;
            let key = dir.join("root.key");
            key.exists().then_some((cert, key))
        });
        let (cert_path, key_path, _creating) = match custom_root {
            Some((cert, key)) => {
                tracing::info!("root CA supplied by hand: {}", cert.display());
                (cert, key, None)
            }
            None => {
                let lock = creation_lock(&cert_path);
                (cert_path, key_path, lock)
            }
        };

        let (ca_cert, ca_key, ca_cert_pem) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            let ca_key = KeyPair::from_pem(&key_pem).context("parsing root CA key")?;
            // Written world-readable by versions before the key was protected;
            // anyone who can read it can mint certificates every client of
            // this proxy trusts.
            crate::private_fs::tighten(&key_path);
            if let Some(dir) = key_path.parent() {
                crate::private_fs::tighten(dir);
            }
            let params =
                CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing root CA cert")?;
            let ca_cert = params
                .self_signed(&ca_key)
                .context("re-issuing root CA from stored params")?;
            (ca_cert, ca_key, cert_pem)
        } else {
            let (ca_cert, ca_key) = generate_root_ca()?;
            let cert_pem = ca_cert.pem();
            if let Some(dir) = cert_path.parent() {
                crate::private_fs::create_dir(dir).ok();
            }
            // The certificate is public — it is what clients are asked to
            // trust. The key is not.
            std::fs::write(&cert_path, cert_pem.as_bytes())
                .with_context(|| format!("writing {}", cert_path.display()))?;
            crate::private_fs::write(&key_path, ca_key.serialize_pem().as_bytes())
                .with_context(|| format!("writing {}", key_path.display()))?;
            (ca_cert, ca_key, cert_pem)
        };

        let custom_certs = config
            .cert_dir
            .as_deref()
            .map(load_custom_certs)
            .unwrap_or_default();
        if !custom_certs.is_empty() {
            let mut names: Vec<&str> = custom_certs.keys().map(String::as_str).collect();
            names.sort_unstable();
            tracing::info!("certificates supplied by hand for: {}", names.join(", "));
        }

        Ok(Arc::new(CertAuthority {
            ca_cert,
            ca_key,
            ca_cert_pem,
            acceptors: Mutex::new(AcceptorCache::default()),
            remote_certs: Mutex::new(HostCache::default()),
            custom_certs,
            ca_cert_path: cert_path,
        }))
    }

    /// The file the root certificate was read from — the one to install.
    pub fn root_cert_path(&self) -> &std::path::Path {
        &self.ca_cert_path
    }

    /// PEM of the root certificate.
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// DER of the root certificate, for a client that has to be told to trust it.
    pub fn root_cert_der(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// A `TlsAcceptor` presenting a leaf certificate for `host`.
    ///
    /// Certificates are shared across sibling subdomains where upstream shares
    /// them (see [`cert_host`]), so a busy proxy signs one certificate per
    /// parent domain rather than one per hostname.
    pub fn acceptor_for(&self, host: &str) -> Result<TlsAcceptor> {
        let host = host.to_ascii_lowercase();
        // A certificate somebody put in the directory wins over one this proxy
        // would sign. Exact name first, then the wildcard the certificate may
        // carry instead — upstream looks the same two up, in the same order
        // (`existsCustomCert`, `_original/lib/https/ca.js:161-173`).
        if let Some(acc) = self.custom_cert(&host) {
            return Ok(acc);
        }
        let key = {
            let cache = self.acceptors.lock().unwrap();
            cert_host(&host, |name| cache.by_host.contains_key(name))
        };
        if let Some(leaf) = self.acceptors.lock().unwrap().get(&key)
            && leaf.fresh()
        {
            return Ok(leaf.acceptor);
        }
        let acceptor = self.build_acceptor(&key)?;
        let leaf = Leaf {
            acceptor: acceptor.clone(),
            issued: SystemTime::now(),
        };
        self.acceptors.lock().unwrap().insert(key, leaf);
        Ok(acceptor)
    }

    fn build_acceptor(&self, host: &str) -> Result<TlsAcceptor> {
        let (chain, key) = self.sign_leaf(host)?;
        acceptor_from_der(chain, key).context("building server config for intercepted host")
    }

    /// What this proxy currently holds for `host` from the `sniCallback` plugin
    /// `plugin`, as `(mtime, acceptor)`.
    ///
    /// Scoped to one plugin deliberately: the cache entry is *that plugin's*
    /// answer, so a different plugin matching the same name must not be told it
    /// has a certificate cached, nor be able to reuse one it never issued.
    pub fn plugin_cert(&self, host: &str, plugin: &str) -> Option<(u64, TlsAcceptor)> {
        let cache = self.remote_certs.lock().unwrap();
        let entry = cache.by_host.get(&host.to_ascii_lowercase())?;
        (entry.plugin == plugin).then(|| (entry.mtime, entry.acceptor.clone()))
    }

    /// Adopt the certificate `plugin` supplied for `host`.
    ///
    /// Returns an error when the material does not form a usable certificate and
    /// key pair; the caller falls back to the generated certificate, so a plugin
    /// cannot take the listener down by answering with rubbish. Re-supplying
    /// byte-identical material costs a string comparison rather than a parse and
    /// a key check — the same short-circuit upstream takes
    /// (`lib/https/load-cert.js:37-42`).
    pub fn set_plugin_cert(
        &self,
        host: &str,
        plugin: &str,
        cert_pem: &str,
        key_pem: &str,
        mtime: u64,
    ) -> Result<TlsAcceptor> {
        let host = host.to_ascii_lowercase();
        {
            let cache = self.remote_certs.lock().unwrap();
            if let Some(entry) = cache.by_host.get(&host)
                && entry.plugin == plugin
                && entry.cert_pem == cert_pem
                && entry.key_pem == key_pem
            {
                return Ok(entry.acceptor.clone());
            }
        }
        let acceptor = acceptor_from_pem(cert_pem, key_pem)?;
        self.remote_certs.lock().unwrap().insert(
            host,
            RemoteCert {
                plugin: plugin.to_string(),
                mtime,
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                acceptor: acceptor.clone(),
            },
        );
        Ok(acceptor)
    }

    /// Drop the plugin-supplied certificate for `host`, if any.
    pub fn forget_plugin_cert(&self, host: &str) {
        self.remote_certs
            .lock()
            .unwrap()
            .remove(&host.to_ascii_lowercase());
    }

    /// Sign a leaf certificate for `host`, returning a rustls cert chain + key.
    ///
    /// `CertificateParams::new` reads an IP literal as an `iPAddress` SAN and
    /// anything else as a `dNSName`, which is the distinction upstream draws by
    /// hand (`net.isIP(hostname) ? {type: 7} : {type: 2}`,
    /// `_original/lib/https/ca.js:237-246`).
    fn sign_leaf(
        &self,
        host: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let leaf_key = KeyPair::generate().context("generating leaf key")?;
        let mut params = CertificateParams::new(vec![host.to_string()]).context("leaf params")?;
        params.distinguished_name.push(DnType::CommonName, host);
        // Relative to now, as upstream's `createCert(…, isShortPeriod)` is: a
        // fixed window would quietly start issuing expired certificates.
        params.not_before = (SystemTime::now() - LEAF_BACKDATE).into();
        params.not_after = (SystemTime::now() + LEAF_LIFETIME).into();
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("signing leaf cert")?;

        let chain = vec![leaf_cert.der().clone(), self.ca_cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((chain, key))
    }
}

/// Seconds in a day, for the certificate validity windows.
const ONE_DAY: u64 = 24 * 60 * 60;

/// How far a leaf is backdated, so a client whose clock runs slow still
/// accepts it.
///
/// With [`LEAF_LIFETIME`] this is whistle 2.10.10's window (`ca.js`, `MIN_DATE`
/// and `MAX_DATE`, avwo/whistle#1360): 43 days in all. It used to be 20 days
/// back and 365 forward — 385 days, as in 2.10.8 — and Chromium refuses a
/// certificate valid for longer than the CA/Browser Forum allows at the time it
/// was issued: 200 days for one issued from 2026-03-15, 100 from 2027-03-15, 47
/// from 2029-03-15 (`HasTooLongValidity`, `net/cert/cert_verify_proc.cc`). It
/// checks that only under a root it counts as publicly trusted, which on
/// Android means one in the **system** store — and that is where a tester often
/// has to put this root, since apps targeting Android 7 and later ignore
/// user-installed ones. The page then fails with `ERR_CERT_VALIDITY_TOO_LONG`,
/// the upstream report was from an Android WebView. 43 days is under every step
/// of that schedule.
const LEAF_BACKDATE: Duration = Duration::from_secs(7 * ONE_DAY);

/// How long a leaf is valid from the moment it is signed. See [`LEAF_BACKDATE`].
const LEAF_LIFETIME: Duration = Duration::from_secs(36 * ONE_DAY);

/// When a cached leaf is signed again: two days before it would expire, so a
/// proxy left running for weeks never hands out one that is about to. Upstream
/// gets the same by emptying its whole cache every 34 days.
const LEAF_REISSUE_AFTER: Duration = Duration::from_secs(34 * ONE_DAY);

/// Build the TLS acceptor whistle-rs presents to an intercepted client.
///
/// One place, so a certificate that came from a plugin is offered under exactly
/// the same terms as one this CA generated — same ALPN list above all. A plugin
/// that could silently narrow the offer to HTTP/1.1 would change how every
/// request on that connection is proxied, which is not what "choose a
/// certificate" is supposed to mean.
fn acceptor_from_der(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, rustls::Error> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    // Offer HTTP/2 and HTTP/1.1; the negotiated protocol is checked after accept.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Parse a PEM certificate chain and private key into a TLS acceptor.
///
/// This is the validation boundary for certificate material that came from a
/// plugin, so every failure has to be an `Err` and none of them may be a panic:
/// the reply is attacker-adjacent input arriving in the middle of a handshake,
/// and the listener has to survive it. rustls does the load-bearing check —
/// `with_single_cert` refuses a key whose `SubjectPublicKeyInfo` does not match
/// the leaf certificate's, so a valid-looking pair that does not actually go
/// together is rejected here rather than at handshake time on every connection.
/// The hand-supplied certificate for `host`, if the directory carried one.
///
/// Two lookups, in upstream's order: the name itself, then the wildcard form
/// with the first label replaced — a certificate for `*.example.com` answers for
/// `api.example.com` and not for `example.com`, which is what a wildcard means.
impl CertAuthority {
    fn custom_cert(&self, host: &str) -> Option<TlsAcceptor> {
        if self.custom_certs.is_empty() {
            return None;
        }
        let host = host.split(':').next().unwrap_or(host);
        if let Some(acc) = self.custom_certs.get(host) {
            return Some(acc.clone());
        }
        let (_, rest) = host.split_once('.')?;
        self.custom_certs.get(&format!("*.{rest}")).cloned()
    }

    /// Whether a hand-supplied certificate covers `host` — the question
    /// `enable://capture` asks when deciding whether a connection is worth
    /// intercepting without being told to.
    pub fn has_custom_cert(&self, host: &str) -> bool {
        self.custom_cert(host).is_some()
    }
}

/// Read a directory of `<name>.key` + `<name>.(crt|cer|pem)` pairs into a map
/// from **every name each certificate carries** to an acceptor serving it.
///
/// The filename only pairs the two files; what a certificate answers for comes
/// out of its own `subjectAltName`, which is the only reading a TLS client would
/// accept anyway. Upstream does exactly this, and **ignores a certificate with
/// no SANs at all** (`parseCert` returns nothing without them,
/// `_original/lib/https/ca.js:272-279`) — a certificate that names nothing
/// cannot be matched to a request.
///
/// Nothing here is fatal. A directory that does not exist, a file that is not a
/// certificate, a key that does not match — each is logged and skipped, because
/// the alternative is a proxy that will not start over one stale file in a
/// directory somebody forgot about.
fn load_custom_certs(dir: &std::path::Path) -> std::collections::HashMap<String, TlsAcceptor> {
    use std::collections::HashMap;

    let Ok(entries) = std::fs::read_dir(dir) else {
        tracing::warn!(
            "cert dir {}: cannot be read, so nothing is loaded",
            dir.display()
        );
        return HashMap::new();
    };
    // Stem → (cert path, key path, mtime of the certificate).
    let mut pairs: HashMap<String, (Option<std::path::PathBuf>, Option<std::path::PathBuf>, u64)> =
        HashMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let (Some(stem), Some(ext)) = (
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string),
            path.extension().and_then(|s| s.to_str()),
        ) else {
            continue;
        };
        // `root` is the CA itself and is loaded by `load_or_create`, not here.
        if stem == "root" {
            continue;
        }
        let slot = pairs.entry(stem).or_insert((None, None, 0));
        match ext {
            "key" => slot.1 = Some(path),
            "crt" | "cer" | "pem" => {
                let mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // A stem with two certificate files keeps the newer one, which
                // is upstream's `cert.mtime >= mtime` test.
                if slot.0.is_none() || mtime > slot.2 {
                    slot.0 = Some(path);
                    slot.2 = mtime;
                }
            }
            _ => {}
        }
    }

    // Oldest first, and the first claim on a name wins: upstream sorts by mtime
    // and skips a name it already has (`if (!pairs[item.value])`,
    // `ca.js:285-300`). So adding a newer certificate does not silently take a
    // name away from one that was already answering for it.
    let mut stems: Vec<(String, std::path::PathBuf, std::path::PathBuf, u64)> = pairs
        .into_iter()
        .filter_map(|(stem, (cert, key, mtime))| Some((stem, cert?, key?, mtime)))
        .collect();
    stems.sort_by_key(|(stem, _, _, mtime)| (*mtime, stem.clone()));

    let mut out: HashMap<String, TlsAcceptor> = HashMap::new();
    for (stem, cert_path, key_path, _) in stems {
        let (Ok(cert_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) else {
            tracing::warn!("cert {stem}: cannot be read, skipped");
            continue;
        };
        let names = match certificate_names(&cert_pem) {
            Ok(names) if !names.is_empty() => names,
            Ok(_) => {
                tracing::warn!(
                    "cert {stem}: no subjectAltName, so there is no request it could answer — skipped"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!("cert {stem}: {e:#}, skipped");
                continue;
            }
        };
        let acceptor = match acceptor_from_pem(&cert_pem, &key_pem) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("cert {stem}: {e:#}, skipped");
                continue;
            }
        };
        for name in names {
            out.entry(name).or_insert_with(|| acceptor.clone());
        }
    }
    out
}

/// Every DNS name and IP address a certificate carries, lower-cased.
fn certificate_names(cert_pem: &str) -> Result<Vec<String>> {
    use rcgen::SanType;
    // `from_ca_cert_pem` performs no CA validation — it says so — and it does
    // extract the subject alternative names, which is the whole reason it is
    // used on a leaf here.
    let params = CertificateParams::from_ca_cert_pem(cert_pem).context("not a certificate")?;
    Ok(params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::DnsName(name) => Some(name.to_string().to_ascii_lowercase()),
            SanType::IpAddress(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect())
}

pub fn acceptor_from_pem(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parsing the plugin's certificate")?;
    if chain.is_empty() {
        anyhow::bail!("the plugin's `cert` holds no CERTIFICATE block");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parsing the plugin's private key")?
        .ok_or_else(|| anyhow::anyhow!("the plugin's `key` holds no PRIVATE KEY block"))?;
    acceptor_from_der(chain, key).context("the plugin's certificate and key do not form a pair")
}

/// The name to put on the certificate for `host`, which may be a wildcard
/// shared with the host's siblings.
///
/// Ported from `getDomain` (`_original/lib/https/ca.js:132-160`), quirks
/// included: three-label names only collapse to `*.rest` when the middle label
/// is longer than three characters, the suffix is `com`/`net`, the middle label
/// is `url`, or the leading label contains something outside `[a-z0-9-]` — a
/// rule the original annotates "for tencent cdn". `is_cached` lets an existing
/// certificate win over the rule, exactly as upstream consults its cache first.
fn cert_host(host: &str, is_cached: impl Fn(&str) -> bool) -> String {
    if is_cached(host) || host.parse::<IpAddr>().is_ok() {
        return host.to_string();
    }
    let mut labels: Vec<&str> = host.split('.').collect();
    let prefix = labels[0];
    labels[0] = "*";
    let wildcard = labels.join(".");
    if is_cached(&wildcard) {
        return wildcard;
    }
    if labels.len() < 3 {
        return host.to_string();
    }
    let odd_prefix = prefix
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-'));
    if labels.len() > 3
        || odd_prefix
        || labels[1].len() > 3
        || labels[2] == "com"
        || labels[2] == "net"
        || labels[1] == "url"
    {
        return wildcard;
    }
    host.to_string()
}

/// Generate a fresh self-signed root CA.
fn generate_root_ca() -> Result<(Certificate, KeyPair)> {
    let ca_key = KeyPair::generate().context("generating root CA key")?;
    let mut params = CertificateParams::new(Vec::<String>::new()).context("root CA params")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "whistle-rs Root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "whistle-rs");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // A year in the past, ten years ahead — upstream's non-short period
    // (`createCert`, `_original/lib/https/ca.js:558-568`).
    params.not_before = (SystemTime::now() - Duration::from_secs(365 * ONE_DAY)).into();
    params.not_after = (SystemTime::now() + Duration::from_secs(10 * 365 * ONE_DAY)).into();
    let ca_cert = params
        .self_signed(&ca_key)
        .context("self-signing root CA")?;
    Ok((ca_cert, ca_key))
}

#[cfg(all(test, unix))]
mod key_permission_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    fn config(label: &str) -> Config {
        let dir =
            std::env::temp_dir().join(format!("whistle-rs-keyperm-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Config {
            storage_dir: dir,
            persist_sessions: false,
            ..Config::default()
        }
    }

    /// A new root key is its owner's alone, in a directory only its owner can
    /// enter. The certificate is public and may stay readable.
    #[test]
    fn a_new_root_key_is_owner_only() {
        let config = config("new");
        CertAuthority::load_or_create(&config).expect("ca");
        assert_eq!(mode(&config.root_ca_key_path()), 0o600);
        assert_eq!(
            mode(config.root_ca_key_path().parent().expect("dir")),
            0o700
        );
    }

    /// Installs made before this wrote the key `0644`; loading it narrows it.
    #[test]
    fn a_world_readable_key_from_before_is_narrowed_on_load() {
        let config = config("old");
        CertAuthority::load_or_create(&config).expect("first start");
        let key = config.root_ca_key_path();
        let dir = key.parent().expect("dir").to_path_buf();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        CertAuthority::load_or_create(&config).expect("second start");
        assert_eq!(mode(&key), 0o600);
        assert_eq!(mode(&dir), 0o700);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA over a storage directory nobody else touches — two of these running
    /// concurrently must not race to write the same root key.
    fn ca(label: &str) -> Arc<CertAuthority> {
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-ca-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )),
            ..Config::default()
        };
        CertAuthority::load_or_create(&config).expect("root CA")
    }

    /// Several starts on an empty directory at once — two embedders, or one
    /// beside the binary — each found no root and wrote its own, the later over
    /// the earlier. One of them then signed with a key no longer on disk, so the
    /// certificate a user trusted from disk did not cover it; and the files
    /// could end up one start's certificate with another's key. Threads stand
    /// in for processes: the lock is on an open file, not on a pid.
    #[test]
    fn concurrent_first_starts_agree_on_one_root() {
        let dir = std::env::temp_dir().join(format!("whistle-rs-ca-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = Arc::new(Config {
            storage_dir: dir,
            ..Config::default()
        });
        let start = Arc::new(std::sync::Barrier::new(8));
        let roots: std::collections::HashSet<String> = (0..8)
            .map(|_| {
                let (config, start) = (config.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    let ca = CertAuthority::load_or_create(&config).expect("root CA");
                    ca.root_cert_pem().to_string()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().expect("thread"))
            .collect();
        assert_eq!(roots.len(), 1, "every start uses the same root");

        let on_disk = std::fs::read_to_string(config.root_ca_cert_path()).expect("root.crt");
        assert!(roots.contains(&on_disk), "and it is the one on disk");
        let key = KeyPair::from_pem(
            &std::fs::read_to_string(config.root_ca_key_path()).expect("root.key"),
        )
        .expect("key");
        let der = rustls_pemfile::certs(&mut on_disk.as_bytes())
            .next()
            .expect("a certificate")
            .expect("PEM");
        let spki = key.public_key_der();
        assert!(
            der.windows(spki.len()).any(|w| w == spki.as_slice()),
            "root.key is the key root.crt was issued for"
        );
    }

    /// Nothing cached: the collapsing rule alone decides.
    fn collapsed(host: &str) -> String {
        cert_host(host, |_| false)
    }

    #[test]
    fn subdomains_share_one_wildcard_certificate() {
        assert_eq!(collapsed("www.example.com"), "*.example.com");
        assert_eq!(collapsed("a.b.google.co.uk"), "*.b.google.co.uk");
        // Middle label longer than three characters.
        assert_eq!(collapsed("api.github.io"), "*.github.io");
        // Leading label outside [a-z0-9-].
        assert_eq!(collapsed("a_b.qq.cn"), "*.qq.cn");
    }

    #[test]
    fn names_upstream_keeps_exact_stay_exact() {
        // Fewer than three labels.
        assert_eq!(collapsed("example.com"), "example.com");
        assert_eq!(collapsed("localhost"), "localhost");
        // Three labels, short middle label, suffix that is neither com nor net.
        assert_eq!(collapsed("a.qq.cn"), "a.qq.cn");
        // IP literals are never wildcarded.
        assert_eq!(collapsed("127.0.0.1"), "127.0.0.1");
        assert_eq!(collapsed("::1"), "::1");
    }

    /// An already-issued certificate wins over the collapsing rule, so a name
    /// that was signed exactly keeps being served exactly (`ca.js:132-141`).
    #[test]
    fn an_existing_certificate_wins_over_the_rule() {
        assert_eq!(
            cert_host("www.example.com", |n| n == "www.example.com"),
            "www.example.com"
        );
        // And a cached wildcard captures a name the rule would have left exact.
        assert_eq!(cert_host("a.qq.cn", |n| n == "*.qq.cn"), "*.qq.cn");
    }

    #[test]
    fn one_acceptor_serves_a_whole_domain() {
        let ca = ca("share");
        ca.acceptor_for("www.example.com").expect("first host");
        ca.acceptor_for("static.example.com").expect("sibling host");
        ca.acceptor_for("shop.example.com")
            .expect("another sibling");
        let cache = ca.acceptors.lock().unwrap();
        assert_eq!(cache.by_host.len(), 1, "siblings share `*.example.com`");
        assert!(cache.by_host.contains_key("*.example.com"));
    }

    #[test]
    fn the_acceptor_cache_stays_bounded() {
        let mut cache = AcceptorCache::default();
        let ca = ca("bound");
        let leaf = Leaf {
            acceptor: ca.acceptor_for("example.com").expect("acceptor"),
            issued: SystemTime::now(),
        };
        for i in 0..MAX_CACHED_HOSTS + 10 {
            cache.insert(format!("h{i}.test"), leaf.clone());
        }
        assert_eq!(cache.by_host.len(), MAX_CACHED_HOSTS);
        assert_eq!(cache.inserted.len(), MAX_CACHED_HOSTS);
        assert!(
            cache.get("h0.test").is_none(),
            "the oldest entry was evicted"
        );
        assert!(
            cache.get("h5129.test").is_some(),
            "the newest entry survives"
        );
    }

    /// An IP-address host gets a certificate with an `iPAddress` SAN, which is
    /// what a client verifies when it connects to `https://127.0.0.1/`.
    #[test]
    fn ip_hosts_get_a_certificate() {
        let ca = ca("ip");
        ca.acceptor_for("127.0.0.1").expect("IPv4 leaf");
        ca.acceptor_for("::1").expect("IPv6 leaf");
        let cache = ca.acceptors.lock().unwrap();
        assert!(cache.by_host.contains_key("127.0.0.1"));
        assert!(cache.by_host.contains_key("::1"));
    }

    /// Complete a real TLS handshake against the acceptor we hand out for
    /// `requested`, with a client that trusts only our root. rustls checks the
    /// chain, the validity window and the SAN, so this is the only assertion
    /// that proves an intercepted connection actually works.
    fn handshake_as(ca: &Arc<CertAuthority>, requested: &str) -> Result<()> {
        let acceptor = ca.acceptor_for(requested)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_cert.der().clone())?;
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(requested.to_string())?;

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await?;
                    acceptor.accept(stream).await?;
                    anyhow::Ok(())
                });
                let stream = tokio::net::TcpStream::connect(addr).await?;
                tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
                    .connect(name, stream)
                    .await
                    .context("client rejected the intercepted certificate")?;
                server.await??;
                anyhow::Ok(())
            })
    }

    /// The leaf is usable right now — valid window, correct SAN, chains to the
    /// root the user installed. A hard-coded validity window would silently
    /// stop satisfying this.
    #[test]
    fn clients_accept_the_intercepted_certificate() {
        let ca = ca("handshake");
        handshake_as(&ca, "www.example.com").expect("wildcard-covered subdomain");
        handshake_as(&ca, "example.com").expect("apex domain");
        handshake_as(&ca, "127.0.0.1").expect("IPv4 literal");
    }

    /// Short enough for Chromium under a root it counts as public: 47 days is
    /// the tightest step of `HasTooLongValidity`'s schedule, and the window has
    /// to contain now. See [`LEAF_BACKDATE`].
    #[test]
    fn a_leaf_is_valid_for_less_than_chromium_s_shortest_limit() {
        let ca = ca("lifetime");
        let (chain, _) = ca.sign_leaf("example.com").expect("leaf");
        let params = CertificateParams::from_ca_cert_der(&chain[0]).expect("parse leaf");
        let (from, to) = (
            params.not_before.unix_timestamp(),
            params.not_after.unix_timestamp(),
        );
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(from < now && now < to);
        let days = (to - from) / ONE_DAY as i64;
        assert!(
            days <= 47,
            "a leaf valid for {days} days is refused by Chromium"
        );
        assert_eq!(
            days, 43,
            "whistle 2.10.10's window: 7 days back, 36 forward"
        );
    }

    /// A proxy left running outlives its leaves; the cache must not hand one
    /// out after it expired.
    #[test]
    fn a_cached_leaf_is_signed_again_before_it_expires() {
        let ca = ca("reissue");
        ca.acceptor_for("example.com").unwrap();
        let signed_at =
            |ca: &CertAuthority| ca.acceptors.lock().unwrap().by_host["example.com"].issued;
        let first = signed_at(&ca);
        ca.acceptor_for("example.com").unwrap();
        assert_eq!(signed_at(&ca), first, "a fresh leaf is reused");

        let old = SystemTime::now() - LEAF_REISSUE_AFTER - Duration::from_secs(60);
        ca.acceptors
            .lock()
            .unwrap()
            .by_host
            .get_mut("example.com")
            .unwrap()
            .issued = old;
        ca.acceptor_for("example.com").unwrap();
        let again = signed_at(&ca);
        assert!(
            again > old + LEAF_REISSUE_AFTER,
            "an old leaf is signed again"
        );
        assert_eq!(
            ca.acceptors.lock().unwrap().inserted.len(),
            1,
            "replaced, not added"
        );
    }

    /// The shared wildcard must not stretch beyond its domain: the certificate
    /// minted for `www.example.com` is not served for an unrelated host.
    #[test]
    fn a_wildcard_does_not_cover_a_neighbouring_domain() {
        let ca = ca("scope");
        ca.acceptor_for("www.example.com").unwrap();
        ca.acceptor_for("www.evil.com").unwrap();
        let cache = ca.acceptors.lock().unwrap();
        assert!(cache.by_host.contains_key("*.example.com"));
        assert!(cache.by_host.contains_key("*.evil.com"));
        assert_eq!(
            cache.by_host.len(),
            2,
            "each domain has its own certificate"
        );
    }

    /// A certificate somebody put in `--cert-dir` is served instead of a forged
    /// one, for **every name it carries** — its `subjectAltName` entries, not
    /// its filename, because a name in the filename is a name no TLS client
    /// would ever look at.
    #[test]
    fn a_hand_supplied_certificate_answers_for_the_names_it_carries() {
        let dir = std::env::temp_dir().join(format!("wrs-certdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let _ = std::fs::remove_file(dir.join("one.crt"));

        // A leaf with two names, written the way somebody would put it there.
        let mut params =
            CertificateParams::new(vec!["pinned.test".to_string(), "*.wild.test".to_string()])
                .expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "pinned.test");
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self-signed");
        std::fs::write(dir.join("one.crt"), cert.pem()).expect("write cert");
        std::fs::write(dir.join("one.key"), key.serialize_pem()).expect("write key");

        let loaded = load_custom_certs(&dir);
        let mut names: Vec<&str> = loaded.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["*.wild.test", "pinned.test"], "the SANs, not `one`");

        let ca = CertAuthority::load_or_create(&crate::config::Config {
            storage_dir: dir.join("store"),
            cert_dir: Some(dir.clone()),
            ..crate::config::Config::default()
        })
        .expect("ca");
        assert!(ca.has_custom_cert("pinned.test"));
        // A wildcard covers one label and not the bare domain, which is what a
        // wildcard means everywhere else.
        assert!(ca.has_custom_cert("api.wild.test"));
        assert!(!ca.has_custom_cert("wild.test"));
        assert!(!ca.has_custom_cert("deeper.api.wild.test"));
        assert!(!ca.has_custom_cert("somewhere.else"));
        // A port is not part of a name.
        assert!(ca.has_custom_cert("pinned.test:8443"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Nothing in that directory is allowed to stop the proxy starting, and a
    /// certificate with no `subjectAltName` names nothing a request could match,
    /// so it is skipped — upstream's `parseCert` returns nothing for one too.
    #[test]
    fn an_unusable_file_in_the_cert_dir_is_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("wrs-certdir-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // Not a certificate at all.
        std::fs::write(dir.join("junk.crt"), b"-----BEGIN CERTIFICATE-----\nnope\n").ok();
        std::fs::write(dir.join("junk.key"), b"nor this").ok();
        // A certificate with no SANs: `new(vec![])` names nothing.
        let params = CertificateParams::new(Vec::<String>::new()).expect("params");
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self-signed");
        std::fs::write(dir.join("nosan.crt"), cert.pem()).ok();
        std::fs::write(dir.join("nosan.key"), key.serialize_pem()).ok();
        // A certificate with no key beside it is half a pair and not usable.
        std::fs::write(dir.join("lonely.crt"), cert.pem()).ok();

        assert!(load_custom_certs(&dir).is_empty());
        // And a directory that is not there at all is simply nothing.
        assert!(load_custom_certs(&dir.join("no-such-place")).is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `root.crt` + `root.key` in the directory **replace the root CA**, which
    /// is the only way to supply one — the console's upload form refuses a root
    /// (`gui/https.md`) — and `root` is therefore not loaded as a leaf.
    #[test]
    fn a_root_in_the_cert_dir_becomes_the_root() {
        let dir = std::env::temp_dir().join(format!("wrs-certdir-root-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let mut params = CertificateParams::new(vec!["ignored.test".to_string()]).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Somebody Else's Root");
        let key = KeyPair::generate().expect("key");
        let root = params.self_signed(&key).expect("self-signed");
        std::fs::write(dir.join("root.crt"), root.pem()).expect("write cert");
        std::fs::write(dir.join("root.key"), key.serialize_pem()).expect("write key");

        // Not loaded as a leaf, even though it carries a name.
        assert!(
            load_custom_certs(&dir).is_empty(),
            "`root` is the CA, not a leaf"
        );

        let ca = CertAuthority::load_or_create(&crate::config::Config {
            storage_dir: dir.join("store"),
            cert_dir: Some(dir.clone()),
            ..crate::config::Config::default()
        })
        .expect("ca");
        assert_eq!(ca.root_cert_path(), dir.join("root.crt"));
        assert!(
            ca.root_cert_pem().contains("BEGIN CERTIFICATE"),
            "and it is the one served for installing"
        );
        // Nothing was written into the storage directory: the root came from
        // elsewhere and generating one beside it would be a second, unused CA.
        assert!(!dir.join("store").join("certs").join("root.crt").exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
