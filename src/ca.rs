//! Certificate authority for HTTPS interception (MITM).
//!
//! Ported from `_original/lib/https/ca.js`. whistle generates a self-signed root
//! CA once, persists it, and signs a short-lived leaf certificate per SNI host
//! on demand. The user installs the root CA to trust intercepted traffic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

/// The root CA plus a cache of per-host TLS acceptors.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    /// PEM of the root certificate (for serving to the user to install).
    ca_cert_pem: String,
    acceptors: Mutex<HashMap<String, TlsAcceptor>>,
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
            acceptors: Mutex::new(HashMap::new()),
        }))
    }

    /// PEM of the root certificate.
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// A `TlsAcceptor` presenting a leaf certificate for `host`, cached per host.
    pub fn acceptor_for(&self, host: &str) -> Result<TlsAcceptor> {
        let key = host.to_ascii_lowercase();
        if let Some(acc) = self.acceptors.lock().unwrap().get(&key) {
            return Ok(acc.clone());
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
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2044, 1, 1);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

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
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2044, 1, 1);
    let ca_cert = params.self_signed(&ca_key).context("self-signing root CA")?;
    Ok((ca_cert, ca_key))
}
