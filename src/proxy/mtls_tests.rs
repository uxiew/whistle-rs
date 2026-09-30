//! A client certificate on the origin leg, end to end through
//! [`forward_with_addr`]: an origin that demands one is reached with the rule's
//! identity and not without it, and a connection made with an identity is
//! never lent to a request that has none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::BodyExt;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::super::body::{self, DynBody};
use super::super::pool::ConnPool;
use super::super::timing::Timings;
use super::super::tls_options::{self, TlsExtras};
use super::*;

/// A CA for client certificates, and one certificate it issued.
struct Client {
    ca: rcgen::Certificate,
    key_pem: String,
    cert_pem: String,
}

fn client(name: &str) -> Client {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).expect("ca");
    let key = rcgen::KeyPair::generate().expect("key");
    let mut leaf = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    leaf.distinguished_name
        .push(rcgen::DnType::CommonName, name);
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let cert = leaf.signed_by(&key, &ca, &ca_key).expect("cert");
    Client {
        ca,
        key_pem: key.serialize_pem(),
        cert_pem: cert.pem(),
    }
}

/// A TLS origin for `localhost` that **requires** a certificate issued by
/// `trusted`, and answers with the number of certificates the client showed.
/// Returns its port and how many TCP connections it has accepted.
async fn demanding_origin(trusted: &rcgen::Certificate) -> (u16, Arc<AtomicUsize>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted.der().clone()).expect("client ca");
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![test_tls::LEAF.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(test_tls::LEAF.key_pair.serialize_der().into()),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let shown = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .map_or(0, |chain| chain.len());
                let service = hyper::service::service_fn(
                    move |_req: Request<hyper::body::Incoming>| async move {
                        Ok::<_, std::convert::Infallible>(Response::new(body::full(format!(
                            "certificates: {shown}"
                        ))))
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, connections)
}

fn target(port: u16, extras: Option<Arc<TlsExtras>>) -> Target {
    Target {
        tls_ciphers: None,
        tls_extras: extras,
        cipher_dropped: None,
        no_proxy_ua: false,
        proxy_connection_close: false,
        connect_host: "127.0.0.1".into(),
        connect_port: port,
        tls: true,
        origin_tls_stripped: false,
        sni: "localhost".into(),
        request_port: port,
        proxy: None,
        tls_versions: TlsVersions::Default,
        host_fallback_direct: false,
        auto2http: false,
        h2: None,
    }
}

fn get(port: u16, pool: &ConnPool) -> Request<DynBody> {
    let mut req = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", format!("localhost:{port}"))
        .body(body::empty())
        .unwrap();
    req.extensions_mut().insert(pool.clone());
    req
}

/// The body on success, the error's text otherwise.
async fn fetch(target: &Target, req: Request<DynBody>) -> Result<String, String> {
    let timings = Timings::new();
    let (resp, _) = forward_with_addr(target, req, &timings)
        .await
        .map_err(|err| format!("{err:#}"))?;
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|err| format!("{err:#}"))?
        .to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn extras(pairs: &[(&str, &str)]) -> Arc<TlsExtras> {
    let options: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
        .collect();
    tls_options::extras_of(&options)
        .await
        .expect("readable")
        .expect("an identity")
}

/// The defect this guards against: every origin connection was built
/// `with_no_client_auth()`, so a rule naming a certificate connected without
/// one and the origin refused the handshake.
#[tokio::test]
async fn an_origin_that_demands_a_certificate_gets_the_rules() {
    let me = client("alice");
    let (port, _) = demanding_origin(&me.ca).await;
    let pool = ConnPool::new();

    // No rule, no certificate: the origin will not talk.
    let bare = fetch(&target(port, None), get(port, &pool)).await;
    assert!(bare.is_err(), "{bare:?}");

    // The rule's certificate: it does.
    let mine = extras(&[("key", &me.key_pem), ("cert", &me.cert_pem)]).await;
    let ok = fetch(&target(port, Some(mine)), get(port, &pool)).await;
    assert_eq!(ok.as_deref(), Ok("certificates: 1"));

    // A certificate some other CA issued: shown, and refused.
    let stranger = client("mallory");
    let theirs = extras(&[("key", &stranger.key_pem), ("cert", &stranger.cert_pem)]).await;
    let refused = fetch(&target(port, Some(theirs)), get(port, &pool)).await;
    assert!(refused.is_err(), "{refused:?}");
}

/// Wait for the pool to hold `n` idle connections: parking happens on a task
/// of its own, a poll or two after the body was read.
async fn settle(pool: &ConnPool, n: usize) {
    for _ in 0..200 {
        if pool.idle() == n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("pool holds {}, expected {n}", pool.idle());
}

/// A connection the origin authenticated belongs to the identity that made
/// it. On one client's pool: the request with the certificate connects, the
/// one without may not borrow that connection — it dials its own, and is
/// refused — and the certificate's next request finds its connection still
/// there.
#[tokio::test]
async fn an_authenticated_connection_is_not_lent_to_a_request_without_the_identity() {
    let me = client("alice");
    let (port, connections) = demanding_origin(&me.ca).await;
    let pool = ConnPool::new();
    let mine = extras(&[("key", &me.key_pem), ("cert", &me.cert_pem)]).await;
    let with = target(port, Some(mine));
    let without = target(port, None);

    assert_eq!(
        fetch(&with, get(port, &pool)).await.as_deref(),
        Ok("certificates: 1")
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    // The authenticated connection is idle in the pool, there for the taking:
    // without this wait the next request dials for itself only because the
    // first connection has not been parked yet, and the test proves nothing.
    settle(&pool, 1).await;

    let anonymous = fetch(&without, get(port, &pool)).await;
    assert!(
        anonymous.is_err(),
        "borrowed the authenticated connection: {anonymous:?}"
    );
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "the anonymous request must have dialled for itself"
    );
    let dialled = connections.load(Ordering::SeqCst);
    settle(&pool, 1).await;

    assert_eq!(
        fetch(&with, get(port, &pool)).await.as_deref(),
        Ok("certificates: 1")
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        dialled,
        "and the identity's own connection was reused"
    );
}

/// `ca`: the origin's certificate has to chain to the rule's roots, and to
/// nothing else. The fixture origin's certificate is issued by the test CA,
/// which a test build trusts by default; a rule naming a different CA must
/// make the same origin untrusted.
#[tokio::test]
async fn a_rules_ca_replaces_the_roots_the_origin_is_checked_against() {
    let me = client("alice");
    let (port, _) = demanding_origin(&me.ca).await;
    let pool = ConnPool::new();
    // The origin's real issuer, named by the rule: trusted.
    let issuer = test_tls::CA.cert.pem();
    let right = extras(&[
        ("key", &me.key_pem),
        ("cert", &me.cert_pem),
        ("ca", &issuer),
    ])
    .await;
    assert_eq!(
        fetch(&target(port, Some(right)), get(port, &pool))
            .await
            .as_deref(),
        Ok("certificates: 1")
    );
    // Some other CA, named by the rule: the origin no longer verifies.
    let other = me.ca.pem();
    let wrong = extras(&[("key", &me.key_pem), ("cert", &me.cert_pem), ("ca", &other)]).await;
    let err = fetch(&target(port, Some(wrong)), get(port, &pool))
        .await
        .expect_err("an origin the rule's roots do not cover");
    assert!(err.contains("TLS"), "{err}");
    // …unless the rule also says not to check.
    let lax = extras(&[
        ("key", &me.key_pem),
        ("cert", &me.cert_pem),
        ("ca", &other),
        ("rejectUnauthorized", "false"),
    ])
    .await;
    assert_eq!(
        fetch(&target(port, Some(lax)), get(port, &pool))
            .await
            .as_deref(),
        Ok("certificates: 1")
    );
}
