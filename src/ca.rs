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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

/// How many signed hosts to keep acceptors for, matching upstream's
/// `cachePairs = new LRU({ max: 5120 })` (`_original/lib/https/ca.js:38`).
/// Without a bound, one connection per made-up SNI name grows the process
/// without limit.
const MAX_CACHED_HOSTS: usize = 5120;

/// Bounded cache of per-host TLS acceptors.
///
/// Eviction is first-in-first-out rather than least-recently-used: the entries
/// are interchangeable (regenerating one costs a single signature) and FIFO
/// keeps the hot path a plain hash lookup with no bookkeeping write.
#[derive(Default)]
struct AcceptorCache {
    by_host: HashMap<String, TlsAcceptor>,
    inserted: VecDeque<String>,
}

impl AcceptorCache {
    fn get(&self, host: &str) -> Option<TlsAcceptor> {
        self.by_host.get(host).cloned()
    }

    fn insert(&mut self, host: String, acceptor: TlsAcceptor) {
        if self.by_host.insert(host.clone(), acceptor).is_none() {
            self.inserted.push_back(host);
        }
        while self.inserted.len() > MAX_CACHED_HOSTS {
            if let Some(oldest) = self.inserted.pop_front() {
                self.by_host.remove(&oldest);
            }
        }
    }
}

/// The root CA plus a cache of per-host TLS acceptors.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    /// PEM of the root certificate (for serving to the user to install).
    ca_cert_pem: String,
    acceptors: Mutex<AcceptorCache>,
}

impl CertAuthority {
    /// Load the persisted root CA, or generate and persist a fresh one.
    pub fn load_or_create(config: &Config) -> Result<Arc<Self>> {
        let cert_path = config.root_ca_cert_path();
        let key_path = config.root_ca_key_path();

        let (ca_cert, ca_key, ca_cert_pem) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            let ca_key = KeyPair::from_pem(&key_pem).context("parsing root CA key")?;
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
                std::fs::create_dir_all(dir).ok();
            }
            std::fs::write(&cert_path, cert_pem.as_bytes())
                .with_context(|| format!("writing {}", cert_path.display()))?;
            std::fs::write(&key_path, ca_key.serialize_pem().as_bytes())
                .with_context(|| format!("writing {}", key_path.display()))?;
            (ca_cert, ca_key, cert_pem)
        };

        Ok(Arc::new(CertAuthority {
            ca_cert,
            ca_key,
            ca_cert_pem,
            acceptors: Mutex::new(AcceptorCache::default()),
        }))
    }

    /// PEM of the root certificate.
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// A `TlsAcceptor` presenting a leaf certificate for `host`.
    ///
    /// Certificates are shared across sibling subdomains where upstream shares
    /// them (see [`cert_host`]), so a busy proxy signs one certificate per
    /// parent domain rather than one per hostname.
    pub fn acceptor_for(&self, host: &str) -> Result<TlsAcceptor> {
        let host = host.to_ascii_lowercase();
        let key = {
            let cache = self.acceptors.lock().unwrap();
            cert_host(&host, |name| cache.by_host.contains_key(name))
        };
        if let Some(acc) = self.acceptors.lock().unwrap().get(&key) {
            return Ok(acc);
        }
        let acc = self.build_acceptor(&key)?;
        self.acceptors
            .lock()
            .unwrap()
            .insert(key, acc.clone());
        Ok(acc)
    }

    fn build_acceptor(&self, host: &str) -> Result<TlsAcceptor> {
        let (chain, key) = self.sign_leaf(host)?;
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("building server config for intercepted host")?;
        // Offer HTTP/2 and HTTP/1.1; the negotiated protocol is checked after accept.
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(cfg)))
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
        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("leaf params")?;
        params
            .distinguished_name
            .push(DnType::CommonName, host);
        // Validity is relative to now, as upstream's `createCert(…, isShortPeriod)`
        // is (`ca.js:552-568`): backdated 20 days so a client with a slow clock
        // still accepts it, and valid for a year. A fixed window would quietly
        // start issuing expired certificates once it elapsed.
        params.not_before = (SystemTime::now() - Duration::from_secs(20 * ONE_DAY)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(365 * ONE_DAY)).into();
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

        let chain = vec![
            leaf_cert.der().clone(),
            self.ca_cert.der().clone(),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((chain, key))
    }
}

/// Seconds in a day, for the certificate validity windows.
const ONE_DAY: u64 = 24 * 60 * 60;

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
    let ca_cert = params.self_signed(&ca_key).context("self-signing root CA")?;
    Ok((ca_cert, ca_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA over a storage directory nobody else touches — two of these running
    /// concurrently must not race to write the same root key.
    fn ca(label: &str) -> Arc<CertAuthority> {
        let mut config = Config::default();
        config.storage_dir = std::env::temp_dir().join(format!(
            "whistle-rs-ca-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        CertAuthority::load_or_create(&config).expect("root CA")
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
        assert_eq!(cert_host("www.example.com", |n| n == "www.example.com"), "www.example.com");
        // And a cached wildcard captures a name the rule would have left exact.
        assert_eq!(cert_host("a.qq.cn", |n| n == "*.qq.cn"), "*.qq.cn");
    }

    #[test]
    fn one_acceptor_serves_a_whole_domain() {
        let ca = ca("share");
        ca.acceptor_for("www.example.com").expect("first host");
        ca.acceptor_for("static.example.com").expect("sibling host");
        ca.acceptor_for("shop.example.com").expect("another sibling");
        let cache = ca.acceptors.lock().unwrap();
        assert_eq!(cache.by_host.len(), 1, "siblings share `*.example.com`");
        assert!(cache.by_host.contains_key("*.example.com"));
    }

    #[test]
    fn the_acceptor_cache_stays_bounded() {
        let mut cache = AcceptorCache::default();
        let ca = ca("bound");
        let acceptor = ca.acceptor_for("example.com").expect("acceptor");
        for i in 0..MAX_CACHED_HOSTS + 10 {
            cache.insert(format!("h{i}.test"), acceptor.clone());
        }
        assert_eq!(cache.by_host.len(), MAX_CACHED_HOSTS);
        assert_eq!(cache.inserted.len(), MAX_CACHED_HOSTS);
        assert!(cache.get("h0.test").is_none(), "the oldest entry was evicted");
        assert!(cache.get("h5129.test").is_some(), "the newest entry survives");
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
        assert_eq!(cache.by_host.len(), 2, "each domain has its own certificate");
    }
}
