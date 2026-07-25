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

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

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

/// A parsed upstream proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

/// Which TLS protocol versions to offer on the upstream (origin) handshake.
/// Derived from the `cipher` operator's `minVersion`/`maxVersion`. rustls
/// supports TLS 1.2 and 1.3 only, so older pins are clamped to the nearest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
}

impl Target {
    /// True when a `host://` rule redirected the connection away from the
    /// requested host. whistle calls this `req._phost`, and it is one of the
    /// conditions that force a CONNECT tunnel rather than an absolute-form
    /// request (`_original/lib/inspectors/res.js:296`).
    fn has_host_override(&self) -> bool {
        self.connect_host != self.sni || self.connect_port != self.request_port
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
    /// The address we bound to, or `None` when bound to all interfaces.
    bind: Option<IpAddr>,
}

static LISTEN: Lazy<RwLock<Listen>> = Lazy::new(Default::default);

/// Record where this proxy listens, so [`self_loop`] can recognise itself.
/// Called once from [`crate::proxy::run`] before the first connection is served;
/// until then no port matches and the guard simply never fires.
pub fn set_listen(bind: Option<IpAddr>, ports: &[u16]) {
    if let Ok(mut listen) = LISTEN.write() {
        listen.bind = bind;
        listen.ports = ports.to_vec();
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
fn is_local_ip(ip: IpAddr) -> bool {
    // `0.0.0.0` is how a proxy value spells "everything local"; whistle treats
    // it as local too, via `isLocalIp`.
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    if LISTEN.read().ok().and_then(|l| l.bind) == Some(ip) {
        return true;
    }
    *PRIMARY_LOCAL_IP == Some(ip)
}

/// The address a hop would loop back to, if routing `target` would hand the
/// request to this very proxy.
///
/// Only the **proxy hop** is examined. A direct connection to our own port
/// cannot recurse in this port: the request we send is origin-form, so the
/// copy that arrives is not a proxy request and is answered by the web UI.
/// whistle 302s that case as well (`res.js:409-420`); reproducing the redirect
/// would turn `curl -x localhost:8899 http://localhost:8899/rootCA.crt` into a
/// redirect loop here, since we would send the client back through the proxy.
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
static INSECURE_UPSTREAM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Opt out of origin certificate verification, process-wide. Call before
/// serving; the TLS configs are built once, on first use.
pub fn set_insecure_upstream(insecure: bool) {
    INSECURE_UPSTREAM.store(insecure, std::sync::atomic::Ordering::Relaxed);
}

fn insecure_upstream() -> bool {
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

fn build_client_config(versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<ClientConfig> {
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

/// Pick the origin TLS config for a target's version constraint.
fn client_config_for(versions: TlsVersions) -> Arc<ClientConfig> {
    match versions {
        TlsVersions::Default => CLIENT_CONFIG.clone(),
        TlsVersions::Only12 => CLIENT_CONFIG_12.clone(),
        TlsVersions::Only13 => CLIENT_CONFIG_13.clone(),
    }
}

/// A type-erased async stream so direct/proxied/TLS paths share one signature.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

struct BoxedIo(Box<dyn IoStream>);

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
            client_proxy_auth: get(hyper::header::PROXY_AUTHORIZATION),
        }
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
pub async fn forward(target: &Target, mut req: Request<DynBody>) -> Result<Response<Incoming>> {
    // Refused before anything is sent: a proxy hop pointing back at us would
    // recurse until the process runs out of sockets. A caller that can answer
    // more helpfully checks [`self_loop`] itself; this is the backstop on the
    // one path every request takes into the network.
    if let Some(addr) = self_loop(target).await {
        bail!("Self loop ({addr})");
    }
    let hop = Hop::from_request(&req);

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
        if let Some(proxy) = &target.proxy {
            if let Some(v) = hop.proxy_auth(proxy) {
                if let Ok(v) = hyper::header::HeaderValue::from_str(&v) {
                    req.headers_mut()
                        .insert(hyper::header::PROXY_AUTHORIZATION, v);
                }
            }
        }
    }

    let stream = origin_stream(target, &hop).await?;
    send(TokioIo::new(stream), req).await
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

/// Establish a stream to the origin (through a proxy if configured), TLS-wrapping
/// it when the origin speaks TLS.
async fn origin_stream(target: &Target, hop: &Hop) -> Result<BoxedIo> {
    let base: BoxedIo = match &target.proxy {
        None => {
            let tcp = TcpStream::connect((target.connect_host.as_str(), target.connect_port))
                .await
                .with_context(|| {
                    format!("connecting to {}:{}", target.connect_host, target.connect_port)
                })?;
            tcp.set_nodelay(true).ok();
            BoxedIo(Box::new(tcp))
        }
        Some(proxy) => {
            let ptcp = TcpStream::connect((proxy.host.as_str(), proxy.port))
                .await
                .with_context(|| format!("connecting to proxy {}:{}", proxy.host, proxy.port))?;
            ptcp.set_nodelay(true).ok();
            // Optionally TLS to the proxy itself (https-proxy).
            let pstream: BoxedIo = if proxy.kind == ProxyKind::Https {
                let connector = TlsConnector::from(CLIENT_CONFIG.clone());
                let name = ServerName::try_from(proxy.host.clone())
                    .map_err(|_| anyhow!("invalid proxy host {}", proxy.host))?;
                BoxedIo(Box::new(connector.connect(name, ptcp).await.context("proxy TLS")?))
            } else {
                BoxedIo(Box::new(ptcp))
            };
            match proxy.kind {
                ProxyKind::Socks => {
                    socks5_connect(pstream, &target.connect_host, target.connect_port, &proxy.auth)
                        .await?
                }
                ProxyKind::Http | ProxyKind::Https => {
                    if uses_absolute_form(target) {
                        // Plain http via a plain proxy: absolute-form, no CONNECT.
                        return Ok(pstream);
                    }
                    http_connect(
                        pstream,
                        &target.connect_host,
                        target.connect_port,
                        hop,
                        proxy,
                    )
                    .await?
                }
            }
        }
    };

    if target.tls {
        let connector = TlsConnector::from(client_config_for(target.tls_versions));
        let server_name = ServerName::try_from(target.sni.clone())
            .map_err(|_| anyhow!("invalid SNI host {}", target.sni))?;
        let tls = connector
            .connect(server_name, base)
            .await
            .context("upstream TLS handshake")?;
        Ok(BoxedIo(Box::new(tls)))
    } else {
        Ok(base)
    }
}

/// Drive one HTTP/1.1 request/response over an established connection.
async fn send<I>(io: I, req: Request<DynBody>) -> Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("upstream handshake")?;
    // `with_upgrades()` keeps the connection usable for protocol upgrades
    // (WebSocket); a plain `conn.await` tears the socket down on 101.
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!("upstream connection error: {err}");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .context("sending upstream request")?;
    Ok(resp)
}

/// Issue a CONNECT to an HTTP proxy, tunnelling to `host:port`.
///
/// The hop headers mirror whistle's `proxyHeaders`
/// (`_original/lib/inspectors/res.js:317-354`): `Host`, a keep-alive
/// `Proxy-Connection`, the client's `User-Agent`, and `Proxy-Authorization`.
/// whistle can suppress the last two with `disable://proxyUA` /
/// `disable://proxyConnection`; those flags do not reach this layer.
async fn http_connect(
    mut s: BoxedIo,
    host: &str,
    port: u16,
    hop: &Hop,
    proxy: &ProxyConfig,
) -> Result<BoxedIo> {
    let authority = join_host_port(host, port, 0);
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(ua) = &hop.user_agent {
        if is_header_value(ua) {
            req.push_str(&format!("User-Agent: {ua}\r\n"));
        }
    }
    if let Some(auth) = hop.proxy_auth(proxy) {
        if is_header_value(&auth) {
            req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.context("proxy CONNECT write")?;

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        s.read_exact(&mut byte).await.context("proxy CONNECT read")?;
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
        bail!("proxy CONNECT rejected: {}", head.lines().next().unwrap_or(""));
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
    // Greeting: offer no-auth (and user/pass if we have credentials).
    if auth.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
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
    let (scheme, rest) = url.split_once("://").ok_or_else(|| anyhow!("bad url {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let tls = scheme.eq_ignore_ascii_case("https");
    let (host, port) = split_host_port(authority, if tls { 443 } else { 80 });
    let target = Target {
        connect_host: host.clone(),
        connect_port: port,
        tls,
        origin_tls_stripped: false,
        sni: host,
        request_port: port,
        proxy: None,
        tls_versions: TlsVersions::Default,
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

/// Parse a proxy operator value: `[user[:pass]@]host[:port]`.
pub fn parse_proxy(kind: ProxyKind, value: &str) -> Option<ProxyConfig> {
    let value = value.trim().trim_start_matches("//");
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
    Some(ProxyConfig { kind, host, port, auth })
}

#[cfg(test)]
mod tests {
    /// The opt-out is process-wide and read when a TLS config is first built,
    /// so it must be set before serving starts. Guarding the default here
    /// because "verifies unless asked not to" is the security property.
    #[test]
    fn upstream_verification_is_on_unless_opted_out() {
        assert!(!insecure_upstream(), "verification must default to on");
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
            connect_host: host.to_string(),
            connect_port: port,
            tls: false,
            origin_tls_stripped: false,
            sni: host.to_string(),
            request_port: port,
            proxy,
            tls_versions: TlsVersions::Default,
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
            assert!(self_loop(&target("a.com", 80, Some(cfg("127.0.0.1:8899")))).await.is_none());

            set_listen(None, &[8899, 1080]);

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
            assert!(self_loop(&target("a.com", 80, Some(cfg("127.0.0.1:8898")))).await.is_none());
            // Our port number on another machine is not us.
            assert!(self_loop(&target("a.com", 80, Some(cfg("203.0.113.7:8899")))).await.is_none());
            // A direct connection to our own port cannot recurse; not checked.
            assert!(self_loop(&target("127.0.0.1", 8899, None)).await.is_none());

            set_listen(None, &[]);
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

            let cfg = parse_proxy(ProxyKind::Http, &format!("bob:s3cr3t@127.0.0.1:{port}")).unwrap();
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
            assert!(head.to_lowercase().contains("proxy-authorization: basic Ym9iOnMzY3IzdA=="
                .to_lowercase()
                .as_str()));
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
                let body = format!("{}", head.lines().next().unwrap_or(""));
                s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
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
                let mut up = TcpStream::connect(("127.0.0.1", origin_port)).await.unwrap();
                tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
                head
            });

            let cfg = parse_proxy(ProxyKind::Http, &format!("127.0.0.1:{proxy_port}")).unwrap();
            let mut t = target("example.com", 80, Some(cfg));
            t.connect_host = "127.0.0.1".into();
            t.connect_port = origin_port;

            let resp = forward(&t, get("/x", "example.com")).await.expect("tunnelled");
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
            assert!(lower.contains("proxy-connection: keep-alive\r\n"), "{head:?}");
            assert!(lower.contains("user-agent: probe/1.0\r\n"), "{head:?}");
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
                        s.read_exact(&mut greeting[3..3 + nmethods - 1]).await.unwrap();
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
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    // Play the origin inside the tunnel.
                    read_head(&mut s).await;
                    s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
                    (req[3], len, addr, user, pass)
                });

                let cfg =
                    parse_proxy(ProxyKind::Socks, &format!("bob@127.0.0.1:{port}")).unwrap();
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
}
