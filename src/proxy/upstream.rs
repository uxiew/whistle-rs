//! Outbound forwarding to the real server.
//!
//! We open the connection ourselves (rather than using a pooled high-level
//! client) so that whistle's `host://` override can redirect the destination IP
//! while the `Host` header and TLS SNI still carry the original hostname — the
//! defining behaviour of a debugging proxy.
//!
//! Supports reaching the origin directly or through an upstream HTTP/HTTPS proxy
//! (`proxy://`, `http-proxy://`, `https-proxy://`, `internal-proxy://`) or a
//! SOCKS5 proxy (`socks://`). Ported from the request dispatch in
//! `_original/lib/inspectors/res.js:200-700`, its agent construction in
//! `lib/config.js:230-264`, and the tunnel path in `lib/tunnel.js:440-560`.
//!
//! The one decision that shapes everything here is absolute-form versus
//! `CONNECT`. whistle sends the request straight to the proxy with an absolute
//! URI only for a plain HTTP proxy reaching a plain HTTP origin; TLS, SOCKS, an
//! HTTPS proxy or a `host://` override each open a tunnel first (`res.js:292-297`).
//! See [`uses_absolute_form`].
//!
//! One hop is refused outright: an upstream proxy that turns out to be *this*
//! process. See [`self_loop`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::outcome::{self, Phase, stopped};
use super::timing::Timings;

use super::body::DynBody;

/// Which kind of upstream proxy to route through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// Plain HTTP proxy (absolute-form for http, CONNECT for https).
    Http,
    /// HTTP proxy reached over TLS.
    Https,
    /// SOCKS5 proxy.
    Socks,
}

/// Credentials written into an upstream proxy's URL (`proxy://user:pass@host`).
///
/// Kept as the raw `user[:pass]` string because whistle uses it two different
/// ways and the two disagree when the password is absent: the HTTP hop base64s
/// the credential *verbatim* (`'Basic ' + toBuffer(proxyOptions.auth).toString('base64')`,
/// `_original/lib/inspectors/res.js:291`), while the SOCKS hop splits it at the
/// first colon with an empty password (`getAuths`, `_original/lib/config.js:285-309`).
/// So `proxy://user@host` sends `Basic dXNlcg==` — not `Basic dXNlcjo=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuth(String);

impl ProxyAuth {
    /// The `Proxy-Authorization` value: `Basic <base64 of the raw credential>`.
    pub fn header_value(&self) -> String {
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.0.as_bytes(),
        );
        format!("Basic {token}")
    }

    /// SOCKS5 username/password, split at the first colon (password may be empty).
    pub fn user_pass(&self) -> (&str, &str) {
        match self.0.split_once(':') {
            Some((u, p)) => (u, p),
            None => (self.0.as_str(), ""),
        }
    }
}

/// Where a proxy hop connects instead of the requested origin — whistle's
/// `req._phost`.
///
/// It comes from a `host://` rule that survived alongside the proxy, or from
/// the proxy URL's own `?host=` query (`P_HOST_RE`,
/// `_original/lib/rules/index.js:81,:243`). The `host://` rule wins when both
/// are present, because whistle only reads the query `if (!req._phost)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOverride {
    pub host: String,
    /// Absent when the override named no port: the request's own port is then
    /// kept (`options.port` is left alone, `_original/lib/inspectors/res.js:377-382`).
    pub port: Option<u16>,
}

/// A parsed upstream proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
    /// `?host=` written into the proxy URL. See [`HostOverride`]; a `host://`
    /// rule takes precedence and is folded into [`Target::connect_host`]
    /// instead.
    pub host_override: Option<HostOverride>,
    /// `proxyTunnel`: the address this hop connects to is itself a proxy, so
    /// CONNECT onward through it to the real origin. See [`Target::hop_addr`].
    pub tunnel: bool,
    /// The `x`-prefixed spellings (`xproxy://`, `xsocks://`, …) ask for a direct
    /// connection if the hop cannot be made (`X_RE`,
    /// `_original/lib/inspectors/res.js:31,:546-560`).
    pub fallback_direct: bool,
}

/// Which TLS protocol versions to offer on the upstream (origin) handshake.
/// Derived from the `cipher` operator's `minVersion`/`maxVersion`. rustls
/// supports TLS 1.2 and 1.3 only, so older pins are clamped to the nearest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsVersions {
    /// Offer both TLS 1.2 and 1.3 (the shared default config).
    #[default]
    Default,
    /// Pin to TLS 1.2 only.
    Only12,
    /// Pin to TLS 1.3 only.
    Only13,
}

/// Where and how to reach the upstream.
#[derive(Debug, Clone)]
pub struct Target {
    /// Host/IP to actually reach (may differ from `sni` via `host://`).
    pub connect_host: String,
    pub connect_port: u16,
    /// Whether the origin speaks TLS.
    pub tls: bool,
    /// True when [`Self::tls`] is false only because an `internal-*` /
    /// `https2http-proxy` hop stripped the origin's TLS. The request then
    /// carries whistle's `x-whistle-https-request` marker so the whistle on the
    /// far side of the hop restores the scheme
    /// (`_original/lib/inspectors/res.js:229-234`, `lib/init.js:190-193`).
    pub origin_tls_stripped: bool,
    /// SNI / certificate hostname + `Host` header (the original request host).
    pub sni: String,
    /// The original request port (for the `Host` header / absolute-form URIs).
    pub request_port: u16,
    /// Optional upstream proxy to route through.
    pub proxy: Option<ProxyConfig>,
    /// TLS version constraint for the origin handshake (`cipher` operator).
    pub tls_versions: TlsVersions,
    /// The `cipher` operator's `ciphers` string, evaluated. `None` when the
    /// rule named none — see [`super::ciphers`].
    pub tls_ciphers: Option<Arc<super::ciphers::CipherPolicy>>,
    /// `disable://proxyUA` — do not echo the client's `User-Agent` on the
    /// CONNECT to an upstream proxy (`_original/lib/inspectors/res.js:329-333`).
    pub no_proxy_ua: bool,
    /// `disable://proxyConnection` — ask the upstream proxy to close rather than
    /// keep the connection alive (`res.js:314-318`).
    pub proxy_connection_close: bool,
    /// True when [`Self::connect_host`] came from an `xhost://` rule rather than
    /// a `host://` one: the address is a preference, not a requirement, and a
    /// connection that cannot be *established* to it is retried against the
    /// requested host (`retryXHost`, `_original/lib/inspectors/res.js:571-600`).
    pub host_fallback_direct: bool,
    /// May an https leg that will not come up be retried in cleartext?
    ///
    /// whistle's `auto2http` (`checkAuto2Http`,
    /// `_original/lib/util/index.js:3191-3198`), which `host.md` documents as
    /// the convenience that lets `www.example.com 127.0.0.1:5173` reach a local
    /// dev server over https: the origin leg's handshake fails against a server
    /// that speaks plain HTTP, and the request is sent again without TLS.
    pub auto2http: bool,
}

impl Target {
    /// The address this connection is actually made to.
    ///
    /// Normally the requested origin. A `host://` rule has already been folded
    /// into [`Self::connect_host`] by the time a `Target` is built; a proxy
    /// URL's own `?host=` is applied here instead, and only when no `host://`
    /// rule spoke first — the same precedence as whistle's
    /// `if (!req._phost && P_HOST_RE.test(proxy.matcher))`
    /// (`_original/lib/rules/index.js:243`).
    fn hop_addr(&self) -> (&str, u16) {
        let direct = (self.connect_host.as_str(), self.connect_port);
        if direct.0 != self.sni || direct.1 != self.request_port {
            return direct;
        }
        match self.proxy.as_ref().and_then(|p| p.host_override.as_ref()) {
            Some(o) => (o.host.as_str(), o.port.unwrap_or(self.request_port)),
            None => direct,
        }
    }

    /// True when something redirected the connection away from the requested
    /// host — a `host://` rule or a proxy URL's `?host=`. whistle calls this
    /// `req._phost`, and it is one of the conditions that force a CONNECT
    /// tunnel rather than an absolute-form request
    /// (`_original/lib/inspectors/res.js:296`).
    fn has_host_override(&self) -> bool {
        let (host, port) = self.hop_addr();
        host != self.sni || port != self.request_port
    }

    /// Does this hop CONNECT twice — once to the overridden address, then again
    /// through it to the real origin? See [`ProxyConfig::tunnel`].
    ///
    /// Both halves are required: whistle guards the second CONNECT with
    /// `req._phost && req._proxyTunnel` (`_original/lib/util/index.js:889`,
    /// `lib/tunnel.js:535-537`). Without an override there is no further
    /// upstream to tunnel through, and the flag does nothing.
    fn uses_proxy_tunnel(&self) -> bool {
        self.proxy.as_ref().is_some_and(|p| p.tunnel) && self.has_host_override()
    }

    /// The second, forgiving attempt an `x`-prefixed rule buys — or `None` when
    /// no rule on this request asked for one.
    ///
    /// Two rules do, and whistle keeps them strictly apart: the proxy check runs
    /// first and the host check is its `else if`, so a request with any proxy
    /// rule never takes the `xhost://` path (`_original/lib/inspectors/res.js:545-573`).
    ///
    /// * `xproxy://` &co. — drop the hop and go straight to the origin;
    /// * `xhost://` — drop the address override and go to the host that was
    ///   requested, on the port that was requested (whistle re-resolves it with
    ///   `lookupHost`, which does *not* re-apply host rules, and restores
    ///   `originPort`, `res.js:571-591`).
    fn fallback_target(&self) -> Option<Target> {
        if let Some(proxy) = &self.proxy {
            return proxy.fallback_direct.then(|| Target {
                proxy: None,
                ..self.clone()
            });
        }
        self.host_fallback_direct.then(|| Target {
            connect_host: self.sni.clone(),
            connect_port: self.request_port,
            host_fallback_direct: false,
            ..self.clone()
        })
    }

    /// The same hop in cleartext — `auto2http`'s retry, or `None` when this
    /// request did not ask for one.
    ///
    /// whistle reaches it as the third rung of one ladder: an `x`-prefixed
    /// proxy rule is tried first, then `xhost://`, and `auto2http` is their
    /// `else if` (`_original/lib/inspectors/res.js:541-600`) — so a request
    /// carrying a [`Self::fallback_target`] never gets here on the same
    /// failure, and this port keeps that order.
    ///
    /// It is also **later** there than here. whistle downgrades on the first
    /// failure only when the error looks like TLS (`checkTlsError` — a hang-up
    /// inside `TLSSocket`, a 502, or anything OpenSSL said) and otherwise
    /// retries https once more before downgrading anyway. Here any failure to
    /// bring the leg up takes the retry immediately: the second https attempt
    /// upstream makes exists to survive a flaky socket, and a port that has
    /// already established the connection once knows the answer without it.
    fn cleartext_target(&self) -> Option<Target> {
        (self.tls && self.auto2http).then(|| Target {
            tls: false,
            auto2http: false,
            ..self.clone()
        })
    }
}

// ── self-loop guard ────────────────────────────────────────────────────────
//
// `proxy://127.0.0.1:<our own port>` is a rule that routes a request back into
// the process that is making it. The copy that arrives matches the same rule
// and is proxied to us again, so the recursion is unbounded: each turn holds
// two sockets open and the machine dies with "Too many open files" rather than
// with an error naming the rule. whistle refuses the hop instead —
// `isProxyPort(port) && isLocalAddress(ip)` (`_original/lib/util/index.js:1703`,
// `:896`) is checked before every proxied connection, and answered with a 302
// to whistle's own UI on the HTTP path (`lib/inspectors/res.js:302-316`) or a
// "Self loop" error on the tunnel path (`lib/tunnel.js:457-465`,
// `lib/https/index.js:339-343`).

/// Where this process accepts proxy traffic; the input to [`self_loop`].
#[derive(Default)]
struct Listen {
    /// Every port we serve on: the main proxy port and `--socks-port`.
    /// whistle's `isProxyPort` compares against the same list
    /// (`config.port`, `httpsPort`, `httpPort`, `socksPort`, `realPort`).
    ports: Vec<u16>,
    /// The addresses proxies in this process bound to. Empty for a proxy bound
    /// to all interfaces, which needs no entry: [`is_local_ip`] already answers
    /// for loopback and the unspecified address.
    binds: Vec<IpAddr>,
}

static LISTEN: Lazy<RwLock<Listen>> = Lazy::new(Default::default);

/// Register where a proxy listens, so [`self_loop`] can recognise it.
///
/// Called from [`crate::proxy::run`] before the first connection is served;
/// until then no port matches and the guard simply never fires.
///
/// **Registers rather than replaces**, because a process may run more than one
/// proxy: [`crate::embed::Proxy`] is a library handle and an application can
/// start several. Replacing meant the second one erased the first one's
/// self-loop protection, so a rule pointing the first proxy at itself recursed
/// until the process ran out of sockets — the exact thing this guard exists to
/// prevent.
///
/// The trade-off is stated rather than hidden: an embedded proxy that is shut
/// down leaves its port registered for the life of the process, so a *different*
/// proxy later reached on that same port would be refused as a loop. That errs
/// toward refusing a connection instead of recursing into one, which is the
/// side to err on.
pub fn register_listen(bind: Option<IpAddr>, ports: &[u16]) {
    if let Ok(mut listen) = LISTEN.write() {
        for port in ports {
            if !listen.ports.contains(port) {
                listen.ports.push(*port);
            }
        }
        if let Some(bind) = bind
            && !listen.binds.contains(&bind)
        {
            listen.binds.push(bind);
        }
    }
}

/// Forget every registration. Tests only: production registers once per proxy
/// and never unregisters — see [`register_listen`].
#[cfg(test)]
fn reset_listen() {
    if let Ok(mut listen) = LISTEN.write() {
        *listen = Listen::default();
    }
}

/// Is `port` one this proxy itself serves on? (whistle's `isProxyPort`.)
fn is_own_port(port: u16) -> bool {
    LISTEN
        .read()
        .map(|l| l.ports.contains(&port))
        .unwrap_or(false)
}

/// This machine's primary outbound address.
///
/// whistle keeps every interface address (`addressList`,
/// `_original/lib/util/index.js:896-908`) so that naming the machine's LAN
/// address is recognised as naming itself. Enumerating interfaces needs a
/// platform crate; we ask the routing table instead, which covers the same
/// case for the address traffic actually leaves by. Connecting a UDP socket
/// sends no packets — it only fixes the local address the kernel would pick —
/// and the peer is a documentation address (RFC 5737) that is never contacted.
static PRIMARY_LOCAL_IP: Lazy<Option<IpAddr>> = Lazy::new(|| {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("192.0.2.1", 80)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
});

/// This machine's primary outbound address, when the routing table can say.
/// Also what a PAC file's `myIpAddress()` reports (`crate::proxy::script`).
pub fn primary_local_ip() -> Option<IpAddr> {
    *PRIMARY_LOCAL_IP
}

/// Does `ip` name this machine? (whistle's `isLocalAddress`.)
pub(crate) fn is_local_ip(ip: IpAddr) -> bool {
    // `0.0.0.0` is how a proxy value spells "everything local"; whistle treats
    // it as local too, via `isLocalIp`.
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    if LISTEN.read().is_ok_and(|l| l.binds.contains(&ip)) {
        return true;
    }
    *PRIMARY_LOCAL_IP == Some(ip)
}

/// The address a hop would loop back to, if routing `target` would hand the
/// request to this very proxy.
///
/// Only the **proxy hop** is examined here; a direct connection to our own port
/// is [`direct_self_loop`]'s, because whether *that* recurses depends on the
/// name the request carries, which only the caller knows.
pub async fn self_loop(target: &Target) -> Option<SocketAddr> {
    let proxy = target.proxy.as_ref()?;
    // The port check is first and needs no I/O, so the common request pays
    // nothing: only a hop that already names one of our ports is resolved.
    if !is_own_port(proxy.port) {
        return None;
    }
    resolve_ips(&proxy.host, proxy.port)
        .await
        .into_iter()
        .find(|ip| is_local_ip(*ip))
        .map(|ip| SocketAddr::new(ip, proxy.port))
}

/// The address a **direct** connection would reach this proxy at, if it would.
///
/// Whether that loops is the caller's to decide. The copy that arrives is
/// origin-form, and the proxy answers it from the console when its `Host` is a
/// name for the console — `curl -x localhost:8899 http://127.0.0.1:8899/rootCA.crt`
/// is how that is reached, and it must not be refused. Under any other name the
/// arrival is forwarded again (`top_level`), to the same place. whistle answers
/// a direct hop to its own port with a 302 to its UI by address
/// (`_original/lib/inspectors/res.js:409-424`), and so does the caller.
pub async fn direct_self_loop(target: &Target) -> Option<SocketAddr> {
    if target.proxy.is_some() || !is_own_port(target.connect_port) {
        return None;
    }
    resolve_ips(&target.connect_host, target.connect_port)
        .await
        .into_iter()
        .find(|ip| is_local_ip(*ip))
        .map(|ip| SocketAddr::new(ip, target.connect_port))
}

/// A header on every request this process sends **directly** to a port it
/// serves on itself, carrying [`loop_nonce`].
///
/// The backstop for [`direct_self_loop`], which only knows the addresses
/// [`is_local_ip`] knows — loopback, the bound ones, the primary one. A name
/// that resolves to this machine by another interface would otherwise be
/// forwarded to itself until the sockets ran out. Seeing its own nonce come
/// back is proof, whatever the address. Only on requests to our port number:
/// an origin elsewhere never sees it.
pub const LOOP_HEADER: &str = "x-whistle-rs-loop";

static LOOP_NONCE: Lazy<String> = Lazy::new(|| {
    use std::hash::{BuildHasher, Hasher};
    // `RandomState` is seeded from the OS once per process: random enough to be
    // this process's, without a dependency for it.
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::process::id().into());
    format!("{:016x}", h.finish())
});

/// This process's value for [`LOOP_HEADER`].
pub fn loop_nonce() -> &'static str {
    &LOOP_NONCE
}

/// Resolve a proxy host to the addresses it would connect to. A hostname is
/// looked up (whistle resolves the proxy URL the same way, `getServerIp`);
/// failure yields no addresses, so an unresolvable host is not a self-loop and
/// fails later, at connect time, with its own error.
async fn resolve_ips(host: &str, port: u16) -> Vec<IpAddr> {
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(err) => {
            tracing::debug!("resolving proxy host {host}: {err}");
            Vec::new()
        }
    }
}

/// Whether to skip verification of the **origin's** certificate.
///
/// whistle sets `rejectUnauthorized = false` by default and only verifies with
/// `--safe` (`_original/lib/config.js:74`). whistle-rs inverts that: verifying
/// is the default and this opts out, because a debugging proxy that silently
/// accepts any upstream certificate cannot tell its user when the connection it
/// is inspecting has itself been intercepted. See `--insecure-upstream`.
static INSECURE_UPSTREAM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Opt out of origin certificate verification, process-wide. Call before
/// serving; the TLS configs are built once, on first use.
pub fn set_insecure_upstream(insecure: bool) {
    INSECURE_UPSTREAM.store(insecure, std::sync::atomic::Ordering::Relaxed);
}

/// Is origin certificate verification off? Read by the TLS builder, and by the
/// console's status endpoint — a proxy running with verification disabled
/// should be able to say so.
pub fn insecure_upstream() -> bool {
    INSECURE_UPSTREAM.load(std::sync::atomic::Ordering::Relaxed)
}

/// A verifier that accepts any certificate. Only reachable behind
/// `--insecure-upstream`; see [`INSECURE_UPSTREAM`] for why that is opt-in.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_client_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    build_client_config_with(versions, None)
}

/// [`build_client_config`], additionally narrowing the cipher suites offered.
///
/// The narrowing is an **intersection** with what the provider already carries,
/// so a `cipher://` can only ever reduce what this port will negotiate. A
/// selection that matched nothing never reaches here — see [`super::ciphers`].
fn build_client_config_with(
    versions: &[&'static rustls::SupportedProtocolVersion],
    ciphers: Option<&super::ciphers::CipherPolicy>,
) -> Arc<ClientConfig> {
    if let Some(policy) = ciphers {
        let wanted = policy.suites();
        let mut provider = rustls::crypto::ring::default_provider();
        // Ordered as the expression produced them: rustls offers them in this
        // order, though the server is free to prefer its own.
        provider.cipher_suites = wanted.clone();
        provider.cipher_suites.retain(|cs| wanted.contains(cs));
        let provider = Arc::new(provider);
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .expect("the provider carries every version asked for");
        let cfg = if insecure_upstream() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        return Arc::new(cfg);
    }
    if insecure_upstream() {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let cfg = ClientConfig::builder_with_protocol_versions(versions)
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
            .with_no_client_auth();
        return Arc::new(cfg);
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Shared rustls client config trusting the webpki root store (TLS 1.2 + 1.3).
static CLIENT_CONFIG: Lazy<Arc<ClientConfig>> =
    Lazy::new(|| build_client_config(rustls::ALL_VERSIONS));
/// TLS-1.2-only client config (`cipher` pin).
static CLIENT_CONFIG_12: Lazy<Arc<ClientConfig>> =
    Lazy::new(|| build_client_config(&[&rustls::version::TLS12]));
/// TLS-1.3-only client config (`cipher` pin).
static CLIENT_CONFIG_13: Lazy<Arc<ClientConfig>> =
    Lazy::new(|| build_client_config(&[&rustls::version::TLS13]));

/// Configs for the version pins that also narrow the cipher suites.
///
/// Kept apart from the three statics above so that the overwhelmingly common
/// case — no `cipher://ciphers` at all — stays a clone of an already-built
/// `Arc` and never touches a lock. Building a `ClientConfig` parses the root
/// store, so a rule that names suites is worth caching rather than rebuilding
/// per request; the map is bounded by the number of distinct `cipher://` values
/// in the rules, which is bounded by the rules file.
type SuiteConfigCache =
    RwLock<HashMap<(TlsVersions, super::ciphers::CipherPolicy), Arc<ClientConfig>>>;
static SUITE_CONFIGS: Lazy<SuiteConfigCache> = Lazy::new(|| RwLock::new(HashMap::new()));

/// Pick the origin TLS config for a target's TLS constraints.
fn client_config_for(
    versions: TlsVersions,
    ciphers: Option<&Arc<super::ciphers::CipherPolicy>>,
) -> Arc<ClientConfig> {
    let Some(policy) = ciphers else {
        return match versions {
            TlsVersions::Default => CLIENT_CONFIG.clone(),
            TlsVersions::Only12 => CLIENT_CONFIG_12.clone(),
            TlsVersions::Only13 => CLIENT_CONFIG_13.clone(),
        };
    };
    let key = (versions, (**policy).clone());
    if let Some(cfg) = SUITE_CONFIGS.read().unwrap().get(&key) {
        return cfg.clone();
    }
    let built = build_client_config_with(protocol_versions(versions), Some(policy));
    SUITE_CONFIGS.write().unwrap().insert(key, built.clone());
    built
}

/// The rustls version list a [`TlsVersions`] stands for.
///
/// `static` rather than a match arm returning a borrow: a `&[&…]` built in the
/// arm would be a temporary, and the whole point is a `'static` slice the
/// builder can keep.
static ONLY_12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
static ONLY_13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn protocol_versions(
    versions: TlsVersions,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match versions {
        TlsVersions::Default => rustls::ALL_VERSIONS,
        TlsVersions::Only12 => ONLY_12,
        TlsVersions::Only13 => ONLY_13,
    }
}

/// A type-erased async stream so direct/proxied/TLS paths share one signature.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

pub(crate) struct BoxedIo(Box<dyn IoStream>);

impl AsyncRead for BoxedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// The client's own `Proxy-Authorization`, taken off the request as it arrives
/// and kept here — in the request's extensions — instead of in its headers.
///
/// It is the client's credential **for this proxy**. Left in the headers it went
/// on to every origin the client visited: whistle 2.10.8 forwards it too,
/// measured, and a corporate proxy password configured in a browser reached
/// every site browsed through here. RFC 9110 lets a proxy pass it to the *next
/// proxy* when proxies authenticate cooperatively, which is the one use kept:
/// [`Hop`] offers it to an upstream proxy that has no credentials of its own. A
/// `Proxy-Authorization` a rule sets (`auth://{"proxy":true,…}`) is the
/// operator's choice and stays in the headers.
#[derive(Clone)]
pub struct ClientProxyAuth(pub String);

/// Take the client's `Proxy-Authorization` out of the headers; see
/// [`ClientProxyAuth`]. Call before the request-side rules run.
pub fn take_client_proxy_auth(parts: &mut hyper::http::request::Parts) {
    if let Some(value) = parts.headers.remove(hyper::header::PROXY_AUTHORIZATION)
        && let Ok(text) = value.to_str()
    {
        parts.extensions.insert(ClientProxyAuth(text.to_string()));
    }
}

/// What the client request contributes to the hop between us and an upstream
/// proxy. whistle builds the CONNECT's headers from the client's rather than
/// sending a bare CONNECT (`_original/lib/inspectors/res.js:317-354`).
#[derive(Default)]
struct Hop {
    /// The client's `User-Agent`, echoed on the CONNECT (`res.js:333-337`).
    user_agent: Option<String>,
    /// The client's own `Proxy-Authorization`, used when the proxy URL carries
    /// no credentials of its own (`res.js:290-294`).
    client_proxy_auth: Option<String>,
    /// `disable://proxyUA` — see [`Target::no_proxy_ua`].
    no_proxy_ua: bool,
    /// `disable://proxyConnection` — see [`Target::proxy_connection_close`].
    proxy_connection_close: bool,
}

impl Hop {
    fn from_request(req: &Request<DynBody>) -> Self {
        let get = |name: hyper::header::HeaderName| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Hop {
            user_agent: get(hyper::header::USER_AGENT),
            // A rule's `Proxy-Authorization` if it set one, else the client's.
            client_proxy_auth: get(hyper::header::PROXY_AUTHORIZATION).or_else(|| {
                req.extensions()
                    .get::<ClientProxyAuth>()
                    .map(|a| a.0.clone())
            }),
            ..Hop::default()
        }
    }

    /// Carry the connection-shaping `disable://` flags across from the target,
    /// which is where the rules put them — a `Hop` is otherwise built from the
    /// request's own headers and knows nothing about the rule set.
    fn with_target(mut self, target: &Target) -> Self {
        self.no_proxy_ua = target.no_proxy_ua;
        self.proxy_connection_close = target.proxy_connection_close;
        self
    }

    /// The `Proxy-Authorization` to present on this hop, if any.
    fn proxy_auth(&self, proxy: &ProxyConfig) -> Option<String> {
        match &proxy.auth {
            Some(auth) => Some(auth.header_value()),
            None => self.client_proxy_auth.clone(),
        }
    }
}

/// Does this hop send the request in absolute-form to the proxy rather than
/// tunnelling it with CONNECT?
///
/// whistle takes the absolute-form path only when everything below is false
/// (`_original/lib/inspectors/res.js:292-297`): a TLS origin, a SOCKS proxy, an
/// HTTPS proxy, or a `host://` override travelling with the proxy (`req._phost`)
/// each force a CONNECT tunnel instead.
fn uses_absolute_form(target: &Target) -> bool {
    match &target.proxy {
        Some(p) => p.kind == ProxyKind::Http && !target.tls && !target.has_host_override(),
        None => false,
    }
}

/// Forward `req` to `target` and return the upstream response (body still
/// streaming). The request URI arrives origin-form with a `Host` header.
pub async fn forward(target: &Target, req: Request<DynBody>) -> Result<Response<Incoming>> {
    // Nobody is going to read these phases, but measuring them costs a few
    // atomics on a path that is about to open a socket.
    forward_with_addr(target, req, &Timings::new())
        .await
        .map(|(resp, _)| resp)
}

/// [`forward`], additionally reporting the address the request actually reached
/// — the origin's on a direct connection, the upstream proxy's on a hop.
///
/// This is the only moment that address exists: a named origin is handed
/// straight to `TcpStream::connect`, which picks among the resolver's answers
/// without telling us, and asking the resolver again can answer differently
/// under round-robin DNS. `serverIp:` is evaluated in the response phase from
/// what this returns, so it matches on the address that was used rather than on
/// a second guess. `None` means the connection never got far enough to have a
/// peer (or the platform declined to say), and the condition then stays
/// unanswerable rather than matching.
pub async fn forward_with_addr(
    target: &Target,
    req: Request<DynBody>,
    timings: &Timings,
) -> Result<(Response<Incoming>, Option<SocketAddr>)> {
    let fallback = target.fallback_target();
    match forward_once(target, req, timings).await {
        Ok(out) => Ok(out),
        // `xproxy://` and `xhost://` mean "this way, or the ordinary way if that
        // fails" (`X_RE`, `_original/lib/inspectors/res.js:546-560,:571-600`).
        // Only a failure to *establish* the connection retries: past that point
        // the request has been written to a socket the caller no longer owns a
        // copy of, and whistle's own retry is likewise guarded on the connection
        // not having been piped yet (`piped`, `res.js:529,:673-680`).
        Err(RetryableError::Connect(err)) if fallback.is_some() => {
            let next = fallback.expect("checked");
            tracing::debug!(
                "{}:{} failed ({err:#}); falling back to {}:{}",
                target.connect_host,
                target.connect_port,
                next.connect_host,
                next.connect_port
            );
            // The retry overwrites the phases of the attempt that failed, which
            // is right: they belong to a connection that was never used.
            let first = format!("{err:#}");
            forward_once(&next, err.into_request(), timings)
                .await
                .map_err(|retry| {
                    retry.into_inner().context(format!(
                        "falling back to {}:{} after {}:{} failed ({first})",
                        next.connect_host,
                        next.connect_port,
                        target.connect_host,
                        target.connect_port
                    ))
                })
        }
        // `auto2http`: an https leg that will not come up, to an address this
        // request has reason to think speaks plain HTTP — see
        // [`Target::cleartext_target`].
        Err(RetryableError::Connect(err)) if target.cleartext_target().is_some() => {
            let next = target.cleartext_target().expect("checked");
            tracing::debug!(
                "https to {}:{} failed ({err:#}); retrying in cleartext (auto2http)",
                target.connect_host,
                target.connect_port
            );
            let first = format!("{err:#}");
            forward_once(&next, err.into_request(), timings)
                .await
                .map_err(|retry| {
                    retry.into_inner().context(format!(
                        "retrying in cleartext after https to {}:{} failed ({first})",
                        target.connect_host, target.connect_port
                    ))
                })
        }
        Err(err) => Err(err.into_inner()),
    }
}

/// Open an opaque byte pipe to `target`, through an upstream proxy when one is
/// configured — the tunnel counterpart of [`forward`].
///
/// The origin leg stays **raw** whatever the target says: on this path the client
/// is performing its own TLS handshake, so wrapping the leg in a second one would
/// hand the client our certificate for a connection we just agreed not to
/// intercept. whistle arrives at the same arrangement by construction — its
/// tunnel path always CONNECTs and never wraps the origin leg itself
/// (`_original/lib/tunnel.js:436-470`).
///
/// The `x`-prefixed rules keep their forgiveness: a connection that cannot be
/// *established* is retried once against [`Target::fallback_target`], which is
/// what whistle's tunnel path does too (`retryXHost`, `lib/tunnel.js:570-617`).
///
/// `timings` gets the phases of the attempt that was used — or of the one that
/// failed last, which is how a relayed tunnel's session shows how far it got.
pub(crate) async fn tunnel_stream(target: &Target, timings: &Timings) -> Result<BoxedIo> {
    let mut target = target.clone();
    target.tls = false;
    target.origin_tls_stripped = false;
    let fallback = target.fallback_target();
    match tunnel_once(&target, timings).await {
        Ok(io) => Ok(io),
        Err(err) => match fallback {
            None => Err(err),
            Some(next) => {
                tracing::debug!(
                    "tunnel to {}:{} failed ({err:#}); falling back to {}:{}",
                    target.connect_host,
                    target.connect_port,
                    next.connect_host,
                    next.connect_port
                );
                tunnel_once(&next, timings).await.map_err(|retry| {
                    retry.context(format!(
                        "falling back to {}:{} after {}:{} failed ({err:#})",
                        next.connect_host,
                        next.connect_port,
                        target.connect_host,
                        target.connect_port
                    ))
                })
            }
        },
    }
}

/// One attempt at [`tunnel_stream`], with no fallback of its own.
///
/// Nothing is ever written on this path, so unlike [`forward_once`] there is no
/// request to hand back: every failure here is a failure to connect.
async fn tunnel_once(target: &Target, timings: &Timings) -> Result<BoxedIo> {
    if let Some(addr) = self_loop(target).await {
        return Err(stopped(Phase::Rules, anyhow!("Self loop ({addr})")));
    }
    // No request exists on this path, so the CONNECT to an upstream proxy carries
    // no `User-Agent` or client `Proxy-Authorization` to echo. The proxy URL's own
    // credentials still apply, which is how a proxy rule normally carries them.
    origin_stream(target, &Hop::default().with_target(target), timings)
        .await
        .map(|(io, _)| io)
}

/// A failure from [`forward_once`], tagged with whether the request survived it.
enum RetryableError {
    /// The connection was never established, so nothing was sent and the
    /// request is handed back intact for another attempt.
    ///
    /// Boxed because it carries a whole `Request` (248 bytes against the other
    /// variant's 8). Unboxed it sets the size of the `Result` every successful
    /// forward returns — 248 bytes for a 184-byte payload — to pay for a case
    /// that only arises when a connection fails.
    Connect(Box<UnsentRequest>),
    /// The request is gone — written to the wire, or consumed by a failed
    /// handshake. Retrying it is not possible, only reporting it.
    Sent(anyhow::Error),
}

/// A request that was never written, and the error that stopped it.
struct UnsentRequest {
    error: anyhow::Error,
    request: Request<DynBody>,
}

impl UnsentRequest {
    fn into_request(self) -> Request<DynBody> {
        self.request
    }
}

impl std::fmt::Display for UnsentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl RetryableError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            RetryableError::Connect(unsent) => unsent.error,
            RetryableError::Sent(err) => err,
        }
    }
}

/// One attempt at [`forward_with_addr`], with no fallback of its own.
async fn forward_once(
    target: &Target,
    mut req: Request<DynBody>,
    timings: &Timings,
) -> Result<(Response<Incoming>, Option<SocketAddr>), RetryableError> {
    // Refused before anything is sent: a proxy hop pointing back at us would
    // recurse until the process runs out of sockets. A caller that can answer
    // more helpfully checks [`self_loop`] itself; this is the backstop on the
    // one path every request takes into the network.
    if let Some(addr) = self_loop(target).await {
        return Err(RetryableError::Connect(Box::new(UnsentRequest {
            error: stopped(Phase::Rules, anyhow!("Self loop ({addr})")),
            request: req,
        })));
    }
    if target.proxy.is_none() && is_own_port(target.connect_port) {
        req.headers_mut().insert(
            LOOP_HEADER,
            hyper::header::HeaderValue::from_static(loop_nonce()),
        );
    }
    let hop = Hop::from_request(&req).with_target(target);

    // Connect before touching the request. Nothing is sent yet, so a hop that
    // cannot be established hands `req` back untouched — which is what lets an
    // `xproxy://` fall back to a direct connection with the *same* request,
    // rather than one already rewritten for a proxy that is not there.
    let (stream, peer) = match origin_stream(target, &hop, timings).await {
        Ok(out) => out,
        Err(error) => {
            return Err(RetryableError::Connect(Box::new(UnsentRequest {
                error,
                request: req,
            })));
        }
    };

    // A plain HTTP proxy fetching an http origin uses absolute-form + Proxy-Auth.
    if uses_absolute_form(target) {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        // whistle names the *requested* host in the absolute URI, taken from the
        // `Host` header so a header rule that rewrote it is honoured
        // (`options.path = 'http://' + (headers.host || options.host) + path`,
        // `_original/lib/inspectors/res.js:606-612`). Using the connect address
        // instead would hand a `host://` override to the upstream proxy.
        let authority = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| join_host_port(&target.connect_host, target.connect_port, 80));
        let abs = format!("http://{authority}{path}");
        *req.uri_mut() = abs.parse::<Uri>().unwrap_or_else(|_| req.uri().clone());
        if let Some(proxy) = &target.proxy
            && let Some(auth) = hop.proxy_auth(proxy)
            && let Ok(v) = hyper::header::HeaderValue::from_str(&auth)
        {
            req.headers_mut()
                .insert(hyper::header::PROXY_AUTHORIZATION, v);
        }
    }

    // `wait` from here: hyper writes the request and resolves on the response
    // head, with no observation point in between — so this is `send` + `wait`
    // and is reported as `wait` alone. See `timing`.
    let waiting = Instant::now();
    let resp = send(TokioIo::new(stream), req)
        .await
        .map_err(RetryableError::Sent)?;
    timings.wait(waiting);
    Ok((resp, peer))
}

/// Render `host:port` for a URL authority, omitting the default port and
/// bracketing an IPv6 literal.
fn join_host_port(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// How long a connection attempt may take before it is abandoned.
///
/// Upstream's number (`TIMEOUT`, `_original/lib/inspectors/res.js:22`), and its
/// scope: whistle arms the timer only while the socket is *connecting* and
/// clears it on `connect`/`secureConnect` (`res.js:653-673`), so a slow response
/// is never cut off — only a destination that will not answer at all.
///
/// Without it the wait is the operating system's, which for a packet-dropping
/// destination is 75 seconds on macOS and longer on Linux, with the request and
/// its buffers held the whole time.
///
/// **One deliberate correction.** Upstream computes this as
/// `config.timeout < 16000 && config.timeout > 0 ? 0 : 16000` — so configuring a
/// timeout *shorter* than 16s disables the connect timeout entirely, which
/// cannot be what was meant. This port takes the smaller of the two instead: a
/// configured timeout may tighten the connect budget, never remove it.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);

/// The connect timeout in force, which a configured request timeout may lower.
static CONNECT_BUDGET: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(CONNECT_TIMEOUT.as_millis() as u64);

/// Narrow the connect budget to `timeout_ms` when that is the stricter of the
/// two. Call before serving.
pub fn set_request_timeout(timeout_ms: u64) {
    let budget = CONNECT_TIMEOUT.as_millis() as u64;
    CONNECT_BUDGET.store(
        budget.min(timeout_ms.max(1)),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Open a TCP connection, timing the name lookup apart from the connect.
///
/// `TcpStream::connect((host, port))` does both and reports one duration, so
/// this does what tokio's own `ToSocketAddrs` does — resolve, then try each
/// answer in turn — with a stopwatch between the halves. Behaviour is unchanged;
/// only the reporting is finer. The budget covers both, as it did when they were
/// one call: a name that will not resolve is a destination that will not answer.
///
/// Returns the moment the *connect* began, so the caller can decide what else
/// belongs in that phase — for a proxied hop, opening the tunnel does.
///
/// Each half's failure is tagged with its own phase — a name that did not
/// resolve and an address that did not answer are different problems with
/// different fixes, and the session says which. A timeout belongs to whichever
/// half was still running when the budget ran out.
async fn dial(host: &str, port: u16, timings: &Timings) -> Result<(TcpStream, Instant)> {
    let deadline = tokio::time::Instant::now() + connect_budget();
    let looking_up = Instant::now();
    let addrs: Vec<SocketAddr> = within(deadline, tokio::net::lookup_host((host, port)))
        .await
        .map_err(outcome::at(Phase::Dns))?
        .collect();
    timings.dns(looking_up);
    if addrs.is_empty() {
        // `connect` would say "could not resolve to any addresses", which is
        // this — a lookup that answered nothing.
        return Err(stopped(Phase::Dns, anyhow!("{host} has no addresses")));
    }
    let connecting = Instant::now();
    let tcp = within(deadline, TcpStream::connect(&addrs[..]))
        .await
        .map_err(outcome::at(Phase::Connect))?;
    Ok((tcp, connecting))
}

/// The connect budget in force — [`CONNECT_TIMEOUT`], or less.
fn connect_budget() -> std::time::Duration {
    std::time::Duration::from_millis(CONNECT_BUDGET.load(std::sync::atomic::Ordering::Relaxed))
}

/// Await a connection attempt, giving up after [`CONNECT_TIMEOUT`].
#[cfg(test)]
async fn connect_within<F, T>(connect: F) -> Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    within(tokio::time::Instant::now() + connect_budget(), connect).await
}

/// Await `step` of a connection attempt, giving up at `deadline`.
async fn within<F, T>(deadline: tokio::time::Instant, step: F) -> Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    match tokio::time::timeout_at(deadline, step).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(anyhow!(
            "timed out after {}s",
            connect_budget().as_secs_f32()
        )),
    }
}

/// Establish a stream to the origin (through a proxy if configured), TLS-wrapping
/// it when the origin speaks TLS.
///
/// Also reports the socket's peer address — the origin's on a direct connection,
/// the proxy's on a hop, which is whistle's `req.hostIp` in both cases
/// (`setHostsInfo` is fed the resolved *proxy* address when a proxy rule
/// matched, `_original/lib/inspectors/res.js:238,:259`). It is the only place
/// the chosen address is ever visible, so `serverIp:` gets it from here.
async fn origin_stream(
    target: &Target,
    hop: &Hop,
    timings: &Timings,
) -> Result<(BoxedIo, Option<SocketAddr>)> {
    let (dst_host, dst_port) = target.hop_addr();
    // When the TCP connect began. `connect` ends when there is a byte pipe to
    // the origin, so on a proxied hop it also covers the proxy's own TLS and its
    // CONNECT/SOCKS negotiation: HAR has no phase for those, and the connection
    // is not established until they are done.
    let connecting;
    let (base, peer): (BoxedIo, Option<SocketAddr>) = match &target.proxy {
        None => {
            let (tcp, at) = dial(dst_host, dst_port, timings)
                .await
                .with_context(|| format!("connecting to {dst_host}:{dst_port}"))?;
            connecting = at;
            tcp.set_nodelay(true).ok();
            let peer = tcp.peer_addr().ok();
            (BoxedIo(Box::new(tcp)), peer)
        }
        Some(proxy) => {
            let (ptcp, at) = dial(proxy.host.as_str(), proxy.port, timings)
                .await
                .with_context(|| format!("connecting to proxy {}:{}", proxy.host, proxy.port))?;
            connecting = at;
            ptcp.set_nodelay(true).ok();
            let peer = ptcp.peer_addr().ok();
            // Optionally TLS to the proxy itself (https-proxy). Everything from
            // here to a byte pipe to the origin is the proxy's to fail: its
            // handshake, its CONNECT, its SOCKS negotiation.
            let pstream: BoxedIo = if proxy.kind == ProxyKind::Https {
                let connector = TlsConnector::from(CLIENT_CONFIG.clone());
                let name = ServerName::try_from(proxy.host.clone()).map_err(|_| {
                    stopped(Phase::Proxy, anyhow!("invalid proxy host {}", proxy.host))
                })?;
                BoxedIo(Box::new(
                    connector
                        .connect(name, ptcp)
                        .await
                        .context("proxy TLS")
                        .map_err(outcome::at(Phase::Proxy))?,
                ))
            } else {
                BoxedIo(Box::new(ptcp))
            };
            let stream = match proxy.kind {
                ProxyKind::Socks => socks5_connect(pstream, dst_host, dst_port, &proxy.auth)
                    .await
                    .map_err(outcome::at(Phase::Proxy))?,
                ProxyKind::Http | ProxyKind::Https => {
                    if uses_absolute_form(target) {
                        // Plain http via a plain proxy: absolute-form, no CONNECT.
                        timings.connect(connecting);
                        return Ok((pstream, peer));
                    }
                    let tunnelled = http_connect(pstream, dst_host, dst_port, hop, proxy, false)
                        .await
                        .with_context(|| format!("via proxy {}:{}", proxy.host, proxy.port))
                        .map_err(outcome::at(Phase::Proxy))?;
                    if target.uses_proxy_tunnel() {
                        // The address we just reached is itself a proxy: ask it,
                        // through the tunnel we now hold, for the real origin.
                        http_connect(
                            tunnelled,
                            &target.sni,
                            target.request_port,
                            hop,
                            proxy,
                            true,
                        )
                        .await
                        .with_context(|| format!("via proxy tunnel {dst_host}:{dst_port}"))
                        .map_err(outcome::at(Phase::Proxy))?
                    } else {
                        tunnelled
                    }
                }
            };
            (stream, peer)
        }
    };

    timings.connect(connecting);
    if target.tls {
        let connector = TlsConnector::from(client_config_for(
            target.tls_versions,
            target.tls_ciphers.as_ref(),
        ));
        let server_name = ServerName::try_from(target.sni.clone())
            .map_err(|_| stopped(Phase::Tls, anyhow!("invalid SNI host {}", target.sni)))?;
        let shaking_hands = Instant::now();
        let tls = connector
            .connect(server_name, base)
            .await
            .context("upstream TLS handshake")
            .map_err(outcome::at(Phase::Tls))?;
        timings.ssl(shaking_hands);
        Ok((BoxedIo(Box::new(tls)), peer))
    } else {
        Ok((base, peer))
    }
}

/// Drive one HTTP/1.1 request/response over an established connection.
async fn send<I>(io: I, req: Request<DynBody>) -> Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("upstream handshake")
        .map_err(outcome::at(Phase::Response))?;
    // `with_upgrades()` keeps the connection usable for protocol upgrades
    // (WebSocket); a plain `conn.await` tears the socket down on 101.
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!("upstream connection error: {err}");
        }
    });
    let resp = sender.send_request(req).await.map_err(|err| {
        // hyper reports a request body that failed while it was being written
        // as a *user* error: the client's upload broke, not the server.
        let phase = match err.is_user() {
            true => Phase::Request,
            false => Phase::Response,
        };
        stopped(
            phase,
            anyhow::Error::new(err).context("sending upstream request"),
        )
    })?;
    Ok(resp)
}

/// The header a `proxyTunnel` hop sends on its **inner** CONNECT, asking the
/// whistle at the far end of the first tunnel to intercept rather than blindly
/// relay (`headers['x-whistle-policy'] = 'intercept'`,
/// `_original/lib/util/patch.js:135-138`, set because `setProxyAgent` always
/// passes `enableIntercept: true`, `lib/inspectors/res.js:472`).
const POLICY_HEADER: &str = "X-Whistle-Policy";

/// Issue a CONNECT to an HTTP proxy, tunnelling to `host:port`.
///
/// The hop headers mirror whistle's `proxyHeaders`
/// (`_original/lib/inspectors/res.js:317-354`): `Host`, a keep-alive
/// `Proxy-Connection`, the client's `User-Agent`, and `Proxy-Authorization`.
/// whistle can suppress the last two with `disable://proxyUA` /
/// `disable://proxyConnection`; those flags do not reach this layer.
///
/// `inner` marks the second CONNECT of a `proxyTunnel` chain, which travels
/// *inside* the first tunnel and is addressed to a further proxy. It carries
/// the same headers plus [`POLICY_HEADER`], which is what upstream's rewritten
/// CONNECT does (`_original/lib/util/patch.js:120-140`) — including the
/// `Proxy-Authorization`. That is worth stating plainly, because there are two
/// credentials it can be, and the second is the surprising one:
///
/// * the credential written into the proxy URL (`proxy://user:pass@first`) —
///   one rule names both hops and supplies one credential, so the second proxy
///   is shown the one written for the first;
/// * failing that, the **client's own** `Proxy-Authorization`, via
///   [`Hop::proxy_auth`] — a credential the client aimed at *us*, forwarded one
///   hop further than the client can see.
///
/// Both are kept, matching upstream: every address involved was named by the
/// rule its author wrote, and withholding the credential would make an
/// authenticated second hop silently unreachable. Point a `proxyTunnel` chain at
/// a proxy you do not control and this is what leaves.
async fn http_connect(
    mut s: BoxedIo,
    host: &str,
    port: u16,
    hop: &Hop,
    proxy: &ProxyConfig,
    inner: bool,
) -> Result<BoxedIo> {
    let authority = join_host_port(host, port, 0);
    // `keep-alive` unless a rule asked otherwise — upstream picks between the
    // two the same way (`res.js:314-318`).
    let keep = match hop.proxy_connection_close {
        true => "close",
        false => "keep-alive",
    };
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: {keep}\r\n"
    );
    if let Some(ua) = &hop.user_agent
        && !hop.no_proxy_ua
        && is_header_value(ua)
    {
        req.push_str(&format!("User-Agent: {ua}\r\n"));
    }
    if let Some(auth) = hop.proxy_auth(proxy)
        && is_header_value(&auth)
    {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    if inner {
        req.push_str(&format!("{POLICY_HEADER}: intercept\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .await
        .context("proxy CONNECT write")?;

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        s.read_exact(&mut byte)
            .await
            .context("proxy CONNECT read")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("proxy CONNECT response too large");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let ok = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|c| c.starts_with('2'))
        .unwrap_or(false);
    if !ok {
        bail!(
            "proxy CONNECT rejected: {}",
            head.lines().next().unwrap_or("")
        );
    }
    Ok(s)
}

/// True if `v` is safe to splice into our hand-written CONNECT request line.
/// The value reaches us from the client, so a CR/LF would let it forge extra
/// headers on the hop to the proxy.
fn is_header_value(v: &str) -> bool {
    !v.is_empty() && !v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Perform a SOCKS5 handshake + CONNECT to `host:port`.
async fn socks5_connect(
    mut s: BoxedIo,
    host: &str,
    port: u16,
    auth: &Option<ProxyAuth>,
) -> Result<BoxedIo> {
    // Greeting. A credential written into the rule is offered *instead of*
    // no-auth rather than alongside it, which is how whistle offers it:
    // `getAuths` returns either `[socks.auth.None()]` or a list built only from
    // the credentials, never both (`_original/lib/config.js:285-309`). Offering
    // both let a proxy that also accepts anonymous connections select no-auth,
    // and the credential the rule named was then never sent — the one thing its
    // author asked for, dropped without a word.
    if auth.is_some() {
        s.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.context("socks greeting")?;
    if sel[0] != 0x05 {
        bail!("not a SOCKS5 proxy");
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = auth
                .as_ref()
                .ok_or_else(|| anyhow!("proxy requires auth but none given"))?
                .user_pass();
            if u.len() > 255 || p.len() > 255 {
                bail!("SOCKS5 credentials exceed the 255-byte field limit");
            }
            let mut req = vec![0x01, u.len() as u8];
            req.extend_from_slice(u.as_bytes());
            req.push(p.len() as u8);
            req.extend_from_slice(p.as_bytes());
            s.write_all(&req).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await.context("socks auth")?;
            if ar[1] != 0x00 {
                bail!("SOCKS5 auth failed");
            }
        }
        0xFF => bail!("SOCKS5: no acceptable auth method"),
        m => bail!("SOCKS5: unsupported auth method {m}"),
    }

    // CONNECT request. Hostnames go over the wire unresolved so the proxy does
    // the DNS (`localDNS: false`, `_original/lib/config.js:1116`).
    let mut req = vec![0x05, 0x01, 0x00];
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                bail!("SOCKS5 hostname exceeds the 255-byte field limit");
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.context("socks reply")?;
    if head[1] != 0x00 {
        bail!("SOCKS5 connect failed (code {})", head[1]);
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        t => bail!("SOCKS5: bad address type {t}"),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

/// Fetch a URL with a simple GET and return `(status, body)`. Used by
/// `responseFor` to prefetch another request's response.
pub async fn simple_get(url: &str) -> Result<(u16, Bytes)> {
    simple_request("GET", url, None).await
}

/// POST a JSON body to a URL and return `(status, body)`. Used by the plugin
/// runtime to dispatch to remote (Node/HTTP) plugins.
pub async fn simple_post_json(url: &str, json: &str) -> Result<(u16, Bytes)> {
    simple_request("POST", url, Some(json)).await
}

/// Split an absolute URL into a direct [`Target`] and its origin-form path.
fn parse_absolute_url(url: &str) -> Result<(Target, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("bad url {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let tls = scheme.eq_ignore_ascii_case("https");
    let (host, port) = split_host_port(authority, if tls { 443 } else { 80 });
    let target = Target {
        tls_ciphers: None,
        no_proxy_ua: false,
        proxy_connection_close: false,
        connect_host: host.clone(),
        connect_port: port,
        tls,
        origin_tls_stripped: false,
        sni: host,
        request_port: port,
        proxy: None,
        tls_versions: TlsVersions::Default,
        host_fallback_direct: false,
        auto2http: false,
    };
    Ok((target, path.to_string()))
}

/// One-shot HTTP request to an absolute URL, returning `(status, body)`.
///
/// Deliberately minimal: no pooling, no redirects, no retries — the plugin
/// runtime layers its own retry policy on top, and plugin endpoints are local.
async fn simple_request(method: &str, url: &str, json: Option<&str>) -> Result<(u16, Bytes)> {
    let (target, path) = parse_absolute_url(url)?;
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", &target.sni);
    if json.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(match json {
            Some(j) => super::body::full(Bytes::from(j.to_owned())),
            None => super::body::empty(),
        })
        .context("building plugin request")?;
    let resp = forward(&target, req).await?;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, bytes))
}

/// Split an authority into host and port the way Node's URL parser does.
///
/// An IPv6 literal is bracketed in a URL (`[::1]:8080`); the brackets are part
/// of the authority but not of the host, and `TcpStream::connect` wants the
/// address without them. Anything after the last colon that is not all digits
/// is part of the host (a bare `::1` has no port).
fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        // `[v6]` or `[v6]:port` — never split inside the brackets.
        if let Some((v6, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (v6.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p))
            if !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                // A bare IPv6 literal has several colons and no port at all.
                && !h.contains(':') =>
        {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

/// whistle's `P_HOST_RE` (`_original/lib/rules/index.js:81`): a `?host=` /
/// `&host=` parameter in a proxy operator's own URL, naming the address the
/// **proxy** should connect to instead of the requested origin.
///
/// The character class is upstream's, verbatim (`[\w.:-]+`): it admits an IPv6
/// literal's colons, which is also how a port is written, so the split is left
/// to [`split_host_port`] exactly as whistle leaves it to `parseUrl`. An
/// unbracketed IPv6 address is therefore not expressible here — upstream has
/// the same hole, since `[` and `]` are outside the class.
fn parse_host_query(value: &str) -> Option<HostOverride> {
    let (_, query) = value.split_once('?')?;
    let raw = query.split('&').find_map(|seg| {
        let (k, v) = seg.split_once('=')?;
        k.eq_ignore_ascii_case("host").then_some(v)
    })?;
    if raw.is_empty()
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return None;
    }
    // A port of 0 is how "no port given" comes back; whistle's `parseUrl` leaves
    // `port` undefined for the same input and keeps the request's own port.
    let (host, port) = split_host_port(raw, 0);
    if host.is_empty() {
        return None;
    }
    Some(HostOverride {
        host,
        port: (port != 0).then_some(port),
    })
}

/// Parse a proxy operator as it was **written on the rule line**, query flags
/// and all: `[user[:pass]@]host[:port][?host=…]`.
///
/// Separate from [`parse_proxy`] because most callers already hold a bare
/// address; this one additionally understands the `?host=` override that
/// whistle reads straight off the matcher.
pub fn parse_proxy_rule(kind: ProxyKind, matcher: &str) -> Option<ProxyConfig> {
    let mut cfg = parse_proxy(kind, matcher)?;
    cfg.host_override = parse_host_query(matcher);
    Some(cfg)
}

/// Parse a proxy operator value: `[user[:pass]@]host[:port]`.
pub fn parse_proxy(kind: ProxyKind, value: &str) -> Option<ProxyConfig> {
    let value = value.trim().trim_start_matches("//");
    // The authority ends at the first `/`, `?` or `#`. A proxy URL may carry a
    // path and a query, and neither is part of the address: whistle keeps only
    // `hostname` and `port` off `parseUrl(proxyUrl)`
    // (`_original/lib/inspectors/res.js:277-286`). This port read the whole
    // string, so `proxy://127.0.0.1:8888/x` asked the resolver for a host named
    // `127.0.0.1:8888/x` and the hop was never made.
    let value = &value[..value.find(['/', '?', '#']).unwrap_or(value.len())];
    if value.is_empty() {
        return None;
    }
    // The credential ends at the *last* `@`, so a password may itself contain one.
    let (auth, hostport) = match value.rsplit_once('@') {
        Some((creds, hp)) if !creds.is_empty() => (Some(ProxyAuth(creds.to_string())), hp),
        Some((_, hp)) => (None, hp),
        None => (None, value),
    };
    let default_port = match kind {
        ProxyKind::Socks => 1080,
        ProxyKind::Https => 443,
        ProxyKind::Http => 80,
    };
    let (host, port) = split_host_port(hostport, default_port);
    if host.is_empty() {
        return None;
    }
    Some(ProxyConfig {
        kind,
        host,
        port,
        auth,
        host_override: None,
        tunnel: false,
        fallback_direct: false,
    })
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// Both tests here write `CONNECT_BUDGET`, which is process-global, and
    /// cargo runs tests in parallel. Restoring the default at the end of each
    /// is not enough — the problem was never ordering. One test's restore was
    /// landing in the middle of the other's measurement, so the timeout test
    /// waited the full 16 seconds it had just shortened to 300ms and failed
    /// its own bound.
    static BUDGET: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold the budget for the duration of a test. Poisoning is ignored: a
    /// panicking test has already failed, and blocking its neighbour on that
    /// would turn one failure into two.
    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        BUDGET.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A connection attempt that never resolves has to be given up on, or the
    /// request waits out the operating system's TCP timeout — over a minute on
    /// macOS, longer on Linux — with its buffers held the whole time. That is
    /// what a packet-dropping destination looks like from here.
    ///
    /// The attempt is a future that never completes rather than a real socket to
    /// a black-holed address: the reserved ranges one would reach for
    /// (TEST-NET-1 and friends) are answered by the fake-IP mode of every
    /// desktop VPN client, this machine's included, and a test that passes only
    /// on an unmanaged network is not a test. What is being pinned here is ours
    /// — that we stop waiting — and tokio owns the rest.
    #[test]
    fn a_connection_that_never_completes_is_given_up_on() {
        let _guard = exclusive();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        set_request_timeout(300);
        let started = std::time::Instant::now();
        let err = rt
            .block_on(connect_within(std::future::pending::<
                std::io::Result<TcpStream>,
            >()))
            .expect_err("a connection that never completes must not succeed");
        let waited = started.elapsed();
        // Restore the default for whatever runs next; `exclusive` is what keeps
        // a neighbour from seeing the shortened one.
        set_request_timeout(CONNECT_TIMEOUT.as_millis() as u64);

        assert!(
            waited < std::time::Duration::from_secs(3),
            "waited {waited:?}"
        );
        assert!(
            waited >= std::time::Duration::from_millis(250),
            "gave up early: {waited:?}"
        );
        assert!(format!("{err:#}").contains("timed out"), "{err:#}");
    }

    /// A configured timeout may tighten the connect budget and never remove it —
    /// upstream's own expression disables the timeout for any value under 16s,
    /// which cannot have been the intent.
    #[test]
    fn a_short_timeout_tightens_rather_than_disables() {
        let _guard = exclusive();
        let budget = || CONNECT_BUDGET.load(std::sync::atomic::Ordering::Relaxed);
        set_request_timeout(1_000);
        assert_eq!(budget(), 1_000);
        set_request_timeout(360_000);
        assert_eq!(budget(), CONNECT_TIMEOUT.as_millis() as u64);
        // Zero would mean "no budget at all", which is never what is wanted.
        set_request_timeout(0);
        assert_eq!(budget(), 1);
        set_request_timeout(CONNECT_TIMEOUT.as_millis() as u64);
    }
}

#[cfg(test)]
mod tests {
    /// The opt-out is process-wide and read when a TLS config is first built,
    /// so it must be set before serving starts. Guarding the default here
    /// because "verifies unless asked not to" is the security property.
    #[test]
    fn upstream_verification_is_on_unless_opted_out() {
        assert!(!insecure_upstream(), "verification must default to on");
        // Build the shared configs before flipping the flag. They are `Lazy` and
        // read it exactly once, so a config first built by a neighbouring test
        // inside the window below would cache the permissive setting for the
        // life of the process — the same shape of race as `LISTEN` and
        // `CONNECT_BUDGET`, and the reason production must call the setter
        // before serving starts.
        let _ = super::client_config_for(super::TlsVersions::Default, None);
        let _ = super::client_config_for(super::TlsVersions::Only12, None);
        let _ = super::client_config_for(super::TlsVersions::Only13, None);
        set_insecure_upstream(true);
        assert!(insecure_upstream());
        set_insecure_upstream(false);
        assert!(!insecure_upstream());
    }

    use super::*;
    use tokio::net::TcpListener;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn target(host: &str, port: u16, proxy: Option<ProxyConfig>) -> Target {
        Target {
            tls_ciphers: None,
            no_proxy_ua: false,
            proxy_connection_close: false,
            connect_host: host.to_string(),
            connect_port: port,
            tls: false,
            origin_tls_stripped: false,
            sni: host.to_string(),
            request_port: port,
            proxy,
            tls_versions: TlsVersions::Default,
            host_fallback_direct: false,
            auto2http: false,
        }
    }

    fn get(url: &str, host_header: &str) -> Request<DynBody> {
        Request::builder()
            .method("GET")
            .uri(url)
            .header("host", host_header)
            .header("user-agent", "probe/1.0")
            .body(super::super::body::empty())
            .expect("request")
    }

    /// Read one request head (up to the blank line) from `s`.
    async fn read_head(s: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while s.read_exact(&mut byte).await.is_ok() {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn parse_http_proxy_with_auth() {
        let p = parse_proxy(ProxyKind::Http, "user:pass@127.0.0.1:8888").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8888);
        assert_eq!(p.auth.unwrap().header_value(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn parse_socks_default_port() {
        let p = parse_proxy(ProxyKind::Socks, "10.0.0.1").unwrap();
        assert_eq!(p.port, 1080);
        assert!(p.auth.is_none());
    }

    /// whistle base64s the credential verbatim, so a password-less one is
    /// `base64("user")` and not `base64("user:")` (`res.js:291`). The SOCKS hop
    /// splits the same string with an empty password (`config.js:285-309`).
    #[test]
    fn credentials_without_a_password_still_travel() {
        let p = parse_proxy(ProxyKind::Http, "user@127.0.0.1:8888").unwrap();
        let auth = p.auth.expect("auth survives a missing password");
        assert_eq!(auth.header_value(), "Basic dXNlcg==");
        assert_eq!(auth.user_pass(), ("user", ""));

        // A password may itself contain '@' — the credential ends at the last one.
        let p2 = parse_proxy(ProxyKind::Socks, "u:p@ss@10.0.0.1:1080").unwrap();
        assert_eq!(p2.host, "10.0.0.1");
        assert_eq!(p2.auth.unwrap().user_pass(), ("u", "p@ss"));
    }

    #[test]
    fn ipv6_proxy_addresses_keep_their_address() {
        let p = parse_proxy(ProxyKind::Http, "[::1]:8888").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 8888);

        // Bracketless and portless: every colon belongs to the address.
        let p2 = parse_proxy(ProxyKind::Socks, "fe80::1").unwrap();
        assert_eq!(p2.host, "fe80::1");
        assert_eq!(p2.port, 1080);

        let p3 = parse_proxy(ProxyKind::Https, "[2001:db8::5]").unwrap();
        assert_eq!(p3.host, "2001:db8::5");
        assert_eq!(p3.port, 443);
    }

    #[test]
    fn authority_rendering_brackets_ipv6_and_drops_the_default_port() {
        assert_eq!(join_host_port("a.com", 80, 80), "a.com");
        assert_eq!(join_host_port("a.com", 8080, 80), "a.com:8080");
        assert_eq!(join_host_port("::1", 443, 0), "[::1]:443");
        assert_eq!(join_host_port("[::1]", 443, 0), "[::1]:443");
    }

    /// Only a plain HTTP proxy reaching a plain HTTP origin uses absolute-form;
    /// TLS, SOCKS, an HTTPS proxy and a `host://` override all force a CONNECT
    /// (`_original/lib/inspectors/res.js:292-297`).
    #[test]
    fn absolute_form_is_reserved_for_the_plain_http_hop() {
        let http = || parse_proxy(ProxyKind::Http, "127.0.0.1:1").unwrap();
        assert!(uses_absolute_form(&target("a.com", 80, Some(http()))));
        assert!(!uses_absolute_form(&target("a.com", 80, None)));

        let mut tls = target("a.com", 443, Some(http()));
        tls.tls = true;
        assert!(!uses_absolute_form(&tls));

        let socks = parse_proxy(ProxyKind::Socks, "127.0.0.1:1").unwrap();
        assert!(!uses_absolute_form(&target("a.com", 80, Some(socks))));

        let https = parse_proxy(ProxyKind::Https, "127.0.0.1:1").unwrap();
        assert!(!uses_absolute_form(&target("a.com", 80, Some(https))));

        let mut phost = target("a.com", 80, Some(http()));
        phost.connect_host = "10.0.0.9".into();
        assert!(!uses_absolute_form(&phost));
    }

    /// A hop that names one of our own ports on an address of this machine is
    /// refused before a socket is opened — whistle's "Self loop"
    /// (`_original/lib/tunnel.js:457-465`). Everything one step away from that
    /// (another local port, our port elsewhere, a direct connection) still goes.
    ///
    /// The ports registered here are outside the ephemeral range, so they can
    /// never collide with a listener another test bound to port 0.
    #[test]
    fn a_proxy_pointing_back_at_us_is_refused() {
        rt().block_on(async {
            let cfg = |v: &str| parse_proxy(ProxyKind::Http, v).unwrap();
            // Nothing is registered until the server starts: no port matches.
            assert!(
                self_loop(&target("a.com", 80, Some(cfg("127.0.0.1:8899"))))
                    .await
                    .is_none()
            );

            // Registration is additive, so another test starting a proxy of
            // its own can no longer erase these — which is what made this test
            // fail about one run in four.
            register_listen(None, &[8899, 1080]);

            let looped = target("a.com", 80, Some(cfg("127.0.0.1:8899")));
            assert_eq!(
                self_loop(&looped).await.map(|a| a.to_string()),
                Some("127.0.0.1:8899".to_string())
            );
            let err = forward(&looped, get("/", "a.com")).await.unwrap_err();
            assert!(format!("{err:#}").contains("Self loop"), "{err:#}");

            // The SOCKS port counts too, and a hostname is resolved first.
            let socks = parse_proxy(ProxyKind::Socks, "localhost:1080").unwrap();
            assert!(self_loop(&target("a.com", 80, Some(socks))).await.is_some());

            // A different local port is somebody else's proxy.
            assert!(
                self_loop(&target("a.com", 80, Some(cfg("127.0.0.1:8898"))))
                    .await
                    .is_none()
            );
            // Our port number on another machine is not us.
            assert!(
                self_loop(&target("a.com", 80, Some(cfg("203.0.113.7:8899"))))
                    .await
                    .is_none()
            );
            // A direct connection to our own port cannot recurse; not checked.
            assert!(self_loop(&target("127.0.0.1", 8899, None)).await.is_none());

            reset_listen();
        });
    }

    #[test]
    fn crlf_never_reaches_the_connect_request() {
        assert!(is_header_value("Mozilla/5.0"));
        assert!(!is_header_value("evil\r\nX-Injected: 1"));
        assert!(!is_header_value("evil\nX-Injected: 1"));
        assert!(!is_header_value(""));
    }

    /// End to end: a plain HTTP request through an HTTP proxy is sent
    /// absolute-form, and the URI names the requested host — not the address we
    /// happen to be connecting to (`res.js:606-612`).
    #[test]
    fn plain_http_traverses_the_proxy_in_absolute_form() {
        rt().block_on(async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = proxy.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .await
                    .unwrap();
                head
            });

            let cfg =
                parse_proxy(ProxyKind::Http, &format!("bob:s3cr3t@127.0.0.1:{port}")).unwrap();
            let resp = forward(
                &target("example.com", 80, Some(cfg)),
                get("/p?q=1", "example.com"),
            )
            .await
            .expect("forward through proxy");
            assert_eq!(resp.status(), 200);

            let head = seen.await.unwrap();
            assert!(
                head.starts_with("GET http://example.com/p?q=1 HTTP/1.1\r\n"),
                "absolute-form request line, got: {head:?}"
            );
            assert!(
                head.to_lowercase().contains(
                    "proxy-authorization: basic Ym9iOnMzY3IzdA=="
                        .to_lowercase()
                        .as_str()
                )
            );
        });
    }

    /// A `host://` override travelling with the proxy switches the hop to
    /// CONNECT, and the tunnel target is the overridden address while the
    /// request inside still carries the original `Host`.
    #[test]
    fn a_host_override_tunnels_with_connect() {
        rt().block_on(async {
            // The "origin" the proxy will be asked to reach.
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let head = read_head(&mut s).await;
                let body = head.lines().next().unwrap_or("").to_string();
                s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            });

            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = proxy.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                // Splice the tunnel onto the real origin.
                let mut up = TcpStream::connect(("127.0.0.1", origin_port))
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
                head
            });

            let cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{proxy_port}")).unwrap();
            let mut t = target("example.com", 80, Some(cfg));
            t.connect_host = "127.0.0.1".into();
            t.connect_port = origin_port;

            let resp = forward(&t, get("/x", "example.com"))
                .await
                .expect("tunnelled");
            assert_eq!(resp.status(), 200);
            let echoed = resp.into_body().collect().await.unwrap().to_bytes();
            // Inside the tunnel the request is origin-form, not absolute-form.
            assert_eq!(echoed, Bytes::from("GET /x HTTP/1.1"));

            let head = seen.await.unwrap();
            assert!(
                head.starts_with(&format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n")),
                "CONNECT to the overridden address, got: {head:?}"
            );
            let lower = head.to_lowercase();
            assert!(
                lower.contains("proxy-connection: keep-alive\r\n"),
                "{head:?}"
            );
            assert!(lower.contains("user-agent: probe/1.0\r\n"), "{head:?}");
        });
    }

    /// `disable://proxyUA` and `disable://proxyConnection` shape that CONNECT:
    /// upstream omits the echoed `User-Agent` for the first and asks the proxy
    /// to close instead of keeping alive for the second
    /// (`_original/lib/inspectors/res.js:314-318,:329-333`). Both were parsed
    /// here and neither reached the wire.
    #[test]
    fn the_connect_headers_answer_to_their_disable_flags() {
        rt().block_on(async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = proxy.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                let head = read_head(&mut s).await;
                // Refused: the CONNECT head is all this test is about.
                s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await
                    .unwrap();
                head
            });

            let cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{proxy_port}")).unwrap();
            let mut t = target("example.com", 443, Some(cfg));
            t.tls = true;
            t.no_proxy_ua = true;
            t.proxy_connection_close = true;
            let _ = forward(&t, get("/x", "example.com")).await;

            let head = seen.await.unwrap().to_lowercase();
            assert!(head.contains("proxy-connection: close\r\n"), "{head:?}");
            assert!(
                !head.contains("user-agent:"),
                "the UA is not echoed: {head:?}"
            );
        });
    }

    /// A refusing proxy surfaces as an error rather than a silent direct
    /// connection — the request must never leak past the proxy it was pinned to.
    #[test]
    fn a_refused_connect_fails_the_request() {
        rt().block_on(async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = proxy.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .unwrap();
            });

            let cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{port}")).unwrap();
            let mut t = target("example.com", 80, Some(cfg));
            t.connect_host = "10.0.0.9".into();
            let err = forward(&t, get("/x", "example.com")).await.unwrap_err();
            assert!(format!("{err:#}").contains("407"), "{err:#}");
        });
    }

    /// SOCKS5: hostnames go over the wire unresolved (ATYP 3) and IPv6 uses
    /// ATYP 4 rather than being spelled out as a domain name.
    #[test]
    fn socks5_addresses_the_origin_by_name_or_ipv6() {
        for (host, want_atyp, want_addr) in [
            ("example.com", 0x03u8, b"example.com".to_vec()),
            ("::1", 0x04, std::net::Ipv6Addr::LOCALHOST.octets().to_vec()),
            ("127.0.0.1", 0x01, vec![127, 0, 0, 1]),
        ] {
            rt().block_on(async {
                let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = socks.local_addr().unwrap().port();
                let seen = tokio::spawn(async move {
                    let (mut s, _) = socks.accept().await.unwrap();
                    let mut greeting = [0u8; 4];
                    s.read_exact(&mut greeting[..3]).await.unwrap();
                    let nmethods = greeting[1] as usize;
                    if nmethods > 1 {
                        s.read_exact(&mut greeting[3..3 + nmethods - 1])
                            .await
                            .unwrap();
                    }
                    s.write_all(&[0x05, 0x02]).await.unwrap(); // demand user/pass
                    let mut hdr = [0u8; 2];
                    s.read_exact(&mut hdr).await.unwrap();
                    let mut user = vec![0u8; hdr[1] as usize];
                    s.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    s.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    s.read_exact(&mut pass).await.unwrap();
                    s.write_all(&[0x01, 0x00]).await.unwrap();

                    let mut req = [0u8; 4];
                    s.read_exact(&mut req).await.unwrap();
                    let len = match req[3] {
                        0x01 => 4,
                        0x04 => 16,
                        _ => {
                            let mut l = [0u8; 1];
                            s.read_exact(&mut l).await.unwrap();
                            l[0] as usize
                        }
                    };
                    let mut addr = vec![0u8; len + 2];
                    s.read_exact(&mut addr).await.unwrap();
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    // Play the origin inside the tunnel.
                    read_head(&mut s).await;
                    s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                        .await
                        .unwrap();
                    (req[3], len, addr, user, pass)
                });

                let cfg = parse_proxy(ProxyKind::Socks, &format!("bob@127.0.0.1:{port}")).unwrap();
                let resp = forward(&target(host, 80, Some(cfg)), get("/", host))
                    .await
                    .expect("socks forward");
                assert_eq!(resp.status(), 204);

                let (atyp, len, addr, user, pass) = seen.await.unwrap();
                assert_eq!(atyp, want_atyp, "address type for {host}");
                assert_eq!(&addr[..len], &want_addr[..], "address bytes for {host}");
                assert_eq!(user, b"bob", "username for {host}");
                assert!(pass.is_empty(), "empty password for {host}");
            });
        }
    }

    /// A SOCKS greeting offers the credential *instead of* no-auth, never both.
    ///
    /// Offering both let a proxy that also accepts anonymous connections choose
    /// no-auth, and the credential written into the rule was then never sent.
    /// whistle offers one or the other — `getAuths` returns `[None()]` or a list
    /// built only from the credentials (`_original/lib/config.js:285-309`) — and
    /// the difference is visible in the greeting bytes on the wire.
    #[test]
    fn a_socks_credential_is_offered_instead_of_no_auth() {
        for (value, want) in [
            ("bob:s3cr3t@127.0.0.1", vec![0x05u8, 0x01, 0x02]),
            ("bob@127.0.0.1", vec![0x05, 0x01, 0x02]),
            ("127.0.0.1", vec![0x05, 0x01, 0x00]),
        ] {
            rt().block_on(async {
                let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = socks.local_addr().unwrap().port();
                let seen = tokio::spawn(async move {
                    let (mut s, _) = socks.accept().await.unwrap();
                    let mut head = [0u8; 2];
                    s.read_exact(&mut head).await.unwrap();
                    let mut methods = vec![0u8; head[1] as usize];
                    s.read_exact(&mut methods).await.unwrap();
                    // Nothing past the greeting: the assertion is the greeting.
                    [&head[..], &methods[..]].concat()
                });

                let cfg = parse_proxy(
                    ProxyKind::Socks,
                    &value.replace("127.0.0.1", &format!("127.0.0.1:{port}")),
                )
                .unwrap();
                let _ = forward(&target("a.com", 80, Some(cfg)), get("/", "a.com")).await;
                assert_eq!(seen.await.unwrap(), want, "greeting for socks://{value}");
            });
        }
    }

    /// A proxy URL may carry a path and a query, and the address stops before
    /// both — whistle keeps only `hostname` and `port` off `parseUrl(proxyUrl)`.
    /// Read whole, `127.0.0.1:8888/x` became a hostname the resolver could never
    /// answer, and the hop was silently never made.
    #[test]
    fn a_proxy_address_stops_at_the_path_and_the_query() {
        for value in [
            "127.0.0.1:8888",
            "127.0.0.1:8888/",
            "127.0.0.1:8888/some/path",
            "127.0.0.1:8888/some/path?a=1",
            "127.0.0.1:8888?a=1",
            "127.0.0.1:8888#frag",
            "//127.0.0.1:8888/some/path",
        ] {
            let p = parse_proxy(ProxyKind::Http, value).unwrap_or_else(|| panic!("{value}"));
            assert_eq!((p.host.as_str(), p.port), ("127.0.0.1", 8888), "{value}");
        }
        // The credential is inside the authority, so it survives the cut.
        let p = parse_proxy(ProxyKind::Http, "bob:s3cr3t@127.0.0.1:8888/x").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("127.0.0.1", 8888));
        assert_eq!(p.auth.unwrap().header_value(), "Basic Ym9iOnMzY3IzdA==");
        // A value that is only a path names no address at all.
        assert!(parse_proxy(ProxyKind::Http, "/some/path").is_none());
    }

    /// `?host=` in a proxy URL names where the *proxy* should connect
    /// (`P_HOST_RE`, `_original/lib/rules/index.js:81,:243`). A missing port
    /// means "keep the request's own", which is why it is `None` here rather
    /// than a guessed 80.
    #[test]
    fn a_proxy_url_can_carry_its_own_host_override() {
        let p = parse_proxy_rule(ProxyKind::Http, "127.0.0.1:8888?host=10.0.0.9:8080").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("127.0.0.1", 8888));
        assert_eq!(
            p.host_override,
            Some(HostOverride {
                host: "10.0.0.9".into(),
                port: Some(8080)
            })
        );

        let no_port = parse_proxy_rule(ProxyKind::Http, "127.0.0.1?host=10.0.0.9").unwrap();
        assert_eq!(
            no_port.host_override,
            Some(HostOverride {
                host: "10.0.0.9".into(),
                port: None
            })
        );

        // It may sit anywhere in the query, beside whistle's other flags.
        let mixed =
            parse_proxy_rule(ProxyKind::Socks, "1.2.3.4?proxyHost&host=a.internal").unwrap();
        assert_eq!(mixed.host_override.unwrap().host, "a.internal");

        // No query, an empty value, or a character outside upstream's
        // `[\w.:-]+` leaves the origin alone.
        assert!(
            parse_proxy_rule(ProxyKind::Http, "1.2.3.4:8888")
                .unwrap()
                .host_override
                .is_none()
        );
        assert!(
            parse_proxy_rule(ProxyKind::Http, "1.2.3.4?host=")
                .unwrap()
                .host_override
                .is_none()
        );
        assert!(
            parse_proxy_rule(ProxyKind::Http, "1.2.3.4?host=a/b")
                .unwrap()
                .host_override
                .is_none()
        );
        assert!(
            parse_proxy_rule(ProxyKind::Http, "1.2.3.4?hosts=x")
                .unwrap()
                .host_override
                .is_none()
        );
        // The address still parses when the query is present.
        assert!(parse_proxy_rule(ProxyKind::Http, "?host=x").is_none());
    }

    /// A `host://` rule outranks the proxy URL's own `?host=` — whistle only
    /// reads the query `if (!req._phost)` (`lib/rules/index.js:243`) — and
    /// either one forces a CONNECT tunnel.
    #[test]
    fn the_host_rule_outranks_the_proxy_urls_own_override() {
        let cfg = parse_proxy_rule(ProxyKind::Http, "127.0.0.1:1?host=10.0.0.9:8080").unwrap();
        let mut t = target("example.com", 80, Some(cfg));
        assert_eq!(t.hop_addr(), ("10.0.0.9", 8080));
        assert!(t.has_host_override());
        assert!(!uses_absolute_form(&t), "an override always tunnels");

        // A `host://` rule has already been folded into connect_host by now.
        t.connect_host = "192.168.1.5".into();
        t.connect_port = 8000;
        assert_eq!(t.hop_addr(), ("192.168.1.5", 8000));

        // Without a port, the request's own is kept.
        let cfg = parse_proxy_rule(ProxyKind::Http, "127.0.0.1:1?host=10.0.0.9").unwrap();
        let t = target("example.com", 8080, Some(cfg));
        assert_eq!(t.hop_addr(), ("10.0.0.9", 8080));

        // No proxy, no override: straight to the origin, and still no
        // absolute-form (that needs a proxy).
        let plain = target("example.com", 80, None);
        assert_eq!(plain.hop_addr(), ("example.com", 80));
        assert!(!plain.has_host_override());
    }

    /// `proxyTunnel` needs both halves: the flag *and* an address to tunnel
    /// through (`req._phost && req._proxyTunnel`,
    /// `_original/lib/util/index.js:889`).
    #[test]
    fn proxy_tunnel_needs_an_address_to_tunnel_through() {
        let mut cfg = parse_proxy(ProxyKind::Http, "127.0.0.1:1").unwrap();
        cfg.tunnel = true;
        assert!(!target("a.com", 80, Some(cfg.clone())).uses_proxy_tunnel());

        cfg.host_override = Some(HostOverride {
            host: "10.0.0.9".into(),
            port: Some(8080),
        });
        assert!(target("a.com", 80, Some(cfg.clone())).uses_proxy_tunnel());

        // The flag is what asks for the second CONNECT; an override alone is
        // just a redirected first one.
        cfg.tunnel = false;
        assert!(!target("a.com", 80, Some(cfg)).uses_proxy_tunnel());
    }

    /// End to end: `?host=` sends the CONNECT to the override, and the request
    /// inside the tunnel still names the requested host.
    #[test]
    fn the_proxy_urls_host_override_redirects_the_connect() {
        rt().block_on(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or("").to_string();
                s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{line}",
                        line.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            });

            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = proxy.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let mut up = TcpStream::connect(("127.0.0.1", origin_port))
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
                head
            });

            let cfg = parse_proxy_rule(
                ProxyKind::Http,
                &format!("127.0.0.1:{proxy_port}?host=127.0.0.1:{origin_port}"),
            )
            .unwrap();
            let resp = forward(
                &target("example.com", 80, Some(cfg)),
                get("/x", "example.com"),
            )
            .await
            .expect("tunnelled via ?host=");
            assert_eq!(resp.status(), 200);
            let echoed = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(echoed, Bytes::from("GET /x HTTP/1.1"));

            let head = seen.await.unwrap();
            assert!(
                head.starts_with(&format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n")),
                "CONNECT to the ?host= address, got: {head:?}"
            );
        });
    }

    /// End to end: `proxyTunnel` CONNECTs twice — once to the overridden
    /// address, then through that tunnel to the real origin, with the
    /// intercept policy on the inner hop (`_original/lib/util/patch.js:120-140`).
    #[test]
    fn proxy_tunnel_connects_onward_through_the_overridden_address() {
        rt().block_on(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            });

            // The second proxy: answers the *inner* CONNECT and reaches the origin.
            let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let second_port = second.local_addr().unwrap().port();
            let inner_seen = tokio::spawn(async move {
                let (mut s, _) = second.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let mut up = TcpStream::connect(("127.0.0.1", origin_port))
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
                head
            });

            // The first proxy: answers the outer CONNECT, splices to the second.
            let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let first_port = first.local_addr().unwrap().port();
            let outer_seen = tokio::spawn(async move {
                let (mut s, _) = first.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let mut up = TcpStream::connect(("127.0.0.1", second_port))
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
                head
            });

            let mut cfg = parse_proxy_rule(
                ProxyKind::Http,
                &format!("bob:s3cr3t@127.0.0.1:{first_port}?host=127.0.0.1:{second_port}"),
            )
            .unwrap();
            cfg.tunnel = true;
            let resp = forward(
                &target("example.com", 443, Some(cfg)),
                get("/", "example.com"),
            )
            .await
            .expect("double CONNECT");
            assert_eq!(resp.status(), 204);

            let outer = outer_seen.await.unwrap();
            assert!(
                outer.starts_with(&format!("CONNECT 127.0.0.1:{second_port} HTTP/1.1\r\n")),
                "outer CONNECT names the further proxy, got: {outer:?}"
            );
            let inner = inner_seen.await.unwrap();
            assert!(
                inner.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                "inner CONNECT names the real origin, got: {inner:?}"
            );
            assert!(
                inner
                    .to_lowercase()
                    .contains("x-whistle-policy: intercept\r\n"),
                "{inner:?}"
            );
            // One rule, one credential: it authenticates both hops (patch.js
            // copies the CONNECT headers onto the inner request).
            assert!(
                inner.contains("Proxy-Authorization: Basic Ym9iOnMzY3IzdA==\r\n"),
                "{inner:?}"
            );
        });
    }

    /// `xproxy://` and friends fall back to a direct connection when the hop
    /// cannot be made (`X_RE`, `_original/lib/inspectors/res.js:546-560`), and
    /// the plain spellings still fail closed.
    #[test]
    fn an_x_proxy_falls_back_to_a_direct_connection() {
        rt().block_on(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
                head
            });

            // A port nothing listens on: bind it, read the port, drop it.
            let dead_port = {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                l.local_addr().unwrap().port()
            };

            let mut cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{dead_port}")).unwrap();
            cfg.fallback_direct = true;
            let resp = forward(
                &target("127.0.0.1", origin_port, Some(cfg.clone())),
                get("/x", "example.com"),
            )
            .await
            .expect("falls back to direct");
            assert_eq!(resp.status(), 204);
            // The retry sends the request the client wrote, origin-form —
            // not the absolute-form one the proxy would have received.
            let head = seen.await.unwrap();
            assert!(head.starts_with("GET /x HTTP/1.1\r\n"), "{head:?}");

            // Without the flag the same rule fails closed.
            cfg.fallback_direct = false;
            let err = forward(
                &target("127.0.0.1", origin_port, Some(cfg)),
                get("/x", "example.com"),
            )
            .await
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("connecting to proxy"),
                "{err:#}"
            );
        });
    }

    /// `xhost://` is the pass-through spelling of `host://`: when the address it
    /// names cannot be reached, the request goes to the host that was actually
    /// asked for instead of failing (`retryXHost`,
    /// `_original/lib/inspectors/res.js:571-600`). Plain `host://` still fails.
    #[test]
    fn an_x_host_falls_back_to_the_requested_address() {
        rt().block_on(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            let seen = tokio::spawn(async move {
                let (mut s, _) = origin.accept().await.unwrap();
                let head = read_head(&mut s).await;
                s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
                head
            });
            // A port nothing listens on: bind it, read the port, drop it.
            let dead_port = {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                l.local_addr().unwrap().port()
            };

            // The request asked for 127.0.0.1:<origin>; the rule redirected it
            // to the dead port.
            let mut t = target("127.0.0.1", origin_port, None);
            t.connect_port = dead_port;
            t.host_fallback_direct = true;
            let resp = forward(&t, get("/x", "example.com"))
                .await
                .expect("falls back to the requested host");
            assert_eq!(resp.status(), 204);
            // The retry carries the request the client wrote, untouched.
            let head = seen.await.unwrap();
            assert!(head.starts_with("GET /x HTTP/1.1\r\n"), "{head:?}");

            // `host://` — the same address, without the pass-through — fails closed.
            t.host_fallback_direct = false;
            assert!(forward(&t, get("/x", "example.com")).await.is_err());
        });
    }

    /// whistle checks the proxy rule first and the host rule in its `else if`
    /// (`res.js:545-573`), so a request with *any* proxy rule never takes the
    /// `xhost://` fallback — the connection it failed to make was to the proxy,
    /// not to the address `xhost://` named.
    #[test]
    fn a_proxy_rule_takes_the_x_host_fallback_off_the_table() {
        let mut cfg = parse_proxy(ProxyKind::Http, "127.0.0.1:1").unwrap();
        cfg.fallback_direct = false;
        let mut t = target("10.0.0.9", 80, Some(cfg.clone()));
        t.host_fallback_direct = true;
        assert!(t.fallback_target().is_none());

        // An `xproxy://` still falls back, and to the origin — not to a target
        // that also dropped the host override.
        cfg.fallback_direct = true;
        let mut t = target("10.0.0.9", 80, Some(cfg));
        t.host_fallback_direct = true;
        let next = t.fallback_target().expect("the proxy hop falls back");
        assert!(next.proxy.is_none());
        assert_eq!(next.connect_host, "10.0.0.9");

        // With no proxy at all, `xhost://` restores the requested address.
        let mut t = target("example.com", 443, None);
        t.connect_host = "10.0.0.9".into();
        t.connect_port = 8443;
        t.host_fallback_direct = true;
        let next = t.fallback_target().expect("the host override falls back");
        assert_eq!(
            (next.connect_host.as_str(), next.connect_port),
            ("example.com", 443)
        );
        assert!(!next.host_fallback_direct, "one retry, not a loop");
    }

    /// A proxy that answers and *then* fails is not retried: the request has
    /// been written and cannot be replayed. whistle guards its own retry the
    /// same way (`piped`, `res.js:529`).
    #[test]
    fn the_fallback_stops_once_the_request_is_on_the_wire() {
        rt().block_on(async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = proxy.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = proxy.accept().await.unwrap();
                read_head(&mut s).await;
                // Accept the tunnel, then hang up mid-conversation.
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                read_head(&mut s).await;
                drop(s);
            });

            let mut cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{port}")).unwrap();
            cfg.fallback_direct = true;
            let mut t = target("example.com", 80, Some(cfg));
            // An override forces CONNECT, so the proxy gets to answer first.
            t.connect_host = "10.0.0.9".into();
            assert!(forward(&t, get("/x", "example.com")).await.is_err());
        });
    }

    /// The address a request actually reached, which is the only thing
    /// `serverIp:` can honestly answer with: the origin's on a direct
    /// connection, the *proxy's* on a hop — whistle's `req.hostIp` is the
    /// proxy's address too (`_original/lib/inspectors/res.js:238,:259`).
    #[test]
    fn forwarding_reports_the_address_the_request_reached() {
        rt().block_on(async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut s, _) = origin.accept().await.unwrap();
                    tokio::spawn(async move {
                        read_head(&mut s).await;
                        s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                            .await
                            .unwrap();
                    });
                }
            });

            // Direct: the origin's own address, resolved from the name we asked for.
            let (_, addr) = forward_with_addr(
                &target("localhost", origin_port, None),
                get("/", "localhost"),
                &Timings::new(),
            )
            .await
            .expect("direct");
            let addr = addr.expect("a connected socket has a peer");
            assert!(addr.ip().is_loopback(), "{addr}");
            assert_eq!(addr.port(), origin_port);

            // Through a proxy: the proxy's address, as whistle reports it.
            let cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{origin_port}")).unwrap();
            let (_, via) = forward_with_addr(
                &target("example.com", 80, Some(cfg)),
                get("/", "example.com"),
                &Timings::new(),
            )
            .await
            .expect("proxied");
            assert_eq!(
                via.map(|a| a.to_string()),
                Some(format!("127.0.0.1:{origin_port}"))
            );
        });
    }
}
