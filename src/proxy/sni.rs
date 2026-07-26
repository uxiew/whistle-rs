//! The SNI stage of an intercepted TLS tunnel: read the ClientHello, choose the
//! certificate, and decide whether to intercept at all.
//!
//! ## Why the ClientHello is read here rather than by rustls
//!
//! The obvious way to get a plugin into a TLS handshake is
//! [`tokio_rustls::LazyConfigAcceptor`], which hands over the ClientHello and
//! lets arbitrary async work happen before the `ServerConfig` is supplied. It
//! would do for two of the three answers a `sniCallback` plugin can give.
//!
//! It cannot do the third. `{"intercept": false}` means *relay this connection
//! to the origin untouched*, and by then rustls has swallowed the ClientHello:
//! `StartHandshake` owns the socket and never gives it back, and no rustls API
//! reproduces the bytes it consumed. A connection the plugin declined would have
//! to be dropped, which is not what declining means.
//!
//! So the bytes are read here, kept, and replayed — to rustls when the
//! connection is intercepted ([`Prefixed`]), or to the origin when it is not
//! ([`relay`]). Parsing is still rustls's: [`peek_client_hello`] drives a
//! [`rustls::server::Acceptor`] purely as a ClientHello parser and then throws
//! it away, so nothing here interprets a byte of TLS on its own authority.
//! Upstream reaches the same arrangement from the same constraint — it peeks the
//! first chunk, parses SNI out of it by hand, and `next(chunk)`s it back into
//! the stream when the certificate callback declines
//! (`_original/lib/https/index.js:1281-1308`).
//!
//! The cost of that choice is one extra ClientHello parse per intercepted
//! connection. It is measured in [`crate::proxy::bench`]; against the key
//! exchange and signature that follow it, it does not show up.
//!
//! ## Which name the certificate is for
//!
//! The name the client will *check* is the one it put in its ClientHello, so
//! that is the one the certificate is signed for — falling back to the CONNECT
//! authority only when the client sent no SNI at all. That is upstream's
//! `useSNI || socket.tunnelHostname` (`lib/https/index.js:1281-1296`).
//!
//! Before this module existed, whistle-rs signed for the CONNECT authority
//! unconditionally. Where the two agree — nearly always — nothing changes.
//! Where they differ the old behaviour was a broken handshake, because the
//! client checks the name it asked for: a SOCKS5 client that resolves DNS itself
//! opens the tunnel to `93.184.216.34` and then asks for `example.com`, and got
//! back a certificate for the IP address.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::AppState;
use crate::plugins::sni::{SniReq, SniVerdict};

/// Ceiling on the bytes held while waiting for a complete ClientHello.
///
/// A ClientHello is one or two kilobytes, and a post-quantum key share takes it
/// to about four. This is generous enough to never bind in practice and small
/// enough that a client which opens tunnels and dribbles bytes into them cannot
/// use them as memory.
const MAX_HELLO_BYTES: usize = 64 * 1024;

/// One socket read while peeking. Sized so a whole ClientHello normally arrives
/// in a single read, as it does off a loopback or a warm TCP connection.
const PEEK_CHUNK: usize = 8 * 1024;

/// What the client's ClientHello said, and the bytes it came in.
pub struct Hello {
    /// Every byte read from the client while looking for the ClientHello. These
    /// have left the socket, so whoever handles the connection next has to be
    /// given them back.
    pub prefix: Vec<u8>,
    /// The server name the ClientHello asked for. `None` when the client sent no
    /// SNI extension, sent one rustls will not accept (an IP literal, say), or
    /// sent something that is not a ClientHello at all.
    pub server_name: Option<String>,
}

/// Read the client's ClientHello without consuming it.
///
/// **Infallible by construction**: every failure — a read error, an early EOF,
/// bytes that are not TLS, a ClientHello past [`MAX_HELLO_BYTES`] — comes back
/// as "no server name" with whatever was read still in hand. The connection then
/// proceeds exactly as it would have without this function, and rustls (or the
/// origin) produces the real error on its own terms. Peeking must never be the
/// reason a connection fails.
pub async fn peek_client_hello<S>(stream: &mut S) -> Hello
where
    S: AsyncRead + Unpin,
{
    let mut acceptor = rustls::server::Acceptor::default();
    let mut prefix: Vec<u8> = Vec::new();
    // How much of `prefix` rustls has taken. `read_tls` reads at most one TLS
    // message per call, so this trails `prefix.len()` until the hello is whole.
    let mut fed = 0usize;

    loop {
        // Hand over everything rustls has not seen yet, then ask.
        while fed < prefix.len() {
            let mut cursor = &prefix[fed..];
            match acceptor.read_tls(&mut cursor) {
                Ok(0) | Err(_) => break,
                Ok(n) => fed += n,
            }
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let server_name = accepted.client_hello().server_name().map(str::to_string);
                // `accepted` is dropped here: it owns a half-built connection
                // over bytes we are about to replay, and the handshake that
                // matters is the one the caller starts.
                return Hello {
                    prefix,
                    server_name,
                };
            }
            // Not a ClientHello, or not one rustls will parse. Hand the bytes
            // back untouched and let the real handshake say so.
            Err(_) => return Hello { prefix, server_name: None },
            Ok(None) => {}
        }
        if prefix.len() >= MAX_HELLO_BYTES {
            return Hello { prefix, server_name: None };
        }
        let mut chunk = [0u8; PEEK_CHUNK];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Hello { prefix, server_name: None },
            Ok(n) => prefix.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A stream that yields `prefix` before anything the socket has to say.
///
/// This is how the bytes [`peek_client_hello`] took out of the socket are put
/// back. Once the prefix is drained the buffer is freed and every read is a
/// direct call through, so what an intercepted connection carries for the rest
/// of its life is one integer comparison per read.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let n = std::cmp::min(buf.remaining(), me.prefix.len() - me.pos);
            buf.put_slice(&me.prefix[me.pos..me.pos + n]);
            me.pos += n;
            if me.pos == me.prefix.len() {
                me.prefix = Vec::new();
                me.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// What to do with an intercepted TLS connection.
pub enum Decision {
    /// Intercept with whistle-rs's own generated certificate — what happens with
    /// no `sniCallback://` rule, and what every plugin failure falls back to.
    Generated,
    /// Intercept, presenting a certificate a plugin chose.
    Plugin(TlsAcceptor),
    /// Do not intercept: relay the connection to the origin opaquely.
    Bypass,
}

/// Consult the `sniCallback://` rules for this connection.
///
/// The common answer is [`Decision::Generated`] and it is reached without
/// building anything: a rules file with no `sniCallback://` in it costs one
/// `bool` per group, precomputed when the group parsed. That is what keeps a
/// connection nobody wrote a rule for identical to one from before this hook
/// existed.
pub async fn decide(
    state: &Arc<AppState>,
    servername: &str,
    tunnel_host: &str,
    port: u16,
    peer: SocketAddr,
    has_sni: bool,
) -> Decision {
    // Scoped so the read guard cannot cross the `.await` below.
    let matched = {
        let rules = state.rules.read().unwrap();
        if !rules.has_sni_callback() {
            return Decision::Generated;
        }
        let info = connection_req_info(servername, port, peer, has_sni);
        rules
            .resolve(&info)
            .value("sniCallback")
            .and_then(parse_rule)
    };
    let Some((plugin, value)) = matched else {
        return Decision::Generated;
    };

    let cached = state.ca.plugin_cert(servername, &plugin);
    let req = SniReq {
        servername: servername.to_string(),
        value,
        tunnel_host: tunnel_host.to_string(),
        port,
        client_ip: Some(peer.ip().to_string()),
        cert_cache_name: cached.as_ref().map(|_| plugin.clone()),
        cert_cache_time: cached.as_ref().map(|(m, _)| *m).unwrap_or(0),
    };

    match state.plugins.sni_cert(&plugin, &req).await {
        // The plugin declined the interception.
        Ok(SniVerdict::Bypass) => {
            tracing::info!("sniCallback {plugin}: not intercepting {servername}");
            Decision::Bypass
        }
        Ok(SniVerdict::Cert(cert)) => {
            match state.ca.set_plugin_cert(
                servername,
                &plugin,
                &cert.cert_pem,
                &cert.key_pem,
                cert.mtime,
            ) {
                Ok(acceptor) => {
                    tracing::debug!("sniCallback {plugin}: serving its certificate for {servername}");
                    Decision::Plugin(acceptor)
                }
                // Unusable material is a failure to communicate, not a
                // withdrawal: say so loudly, keep whatever was cached, and fall
                // back to the certificate this proxy would have generated.
                Err(e) => {
                    tracing::warn!(
                        "sniCallback {plugin}: unusable certificate for {servername}: {e:#}; \
                         generated certificate used instead"
                    );
                    Decision::Generated
                }
            }
        }
        Ok(SniVerdict::Reuse) => match cached {
            Some((_, acceptor)) => Decision::Plugin(acceptor),
            None => {
                tracing::debug!(
                    "sniCallback {plugin}: asked to reuse a certificate for {servername}, \
                     but none is cached; generated certificate used instead"
                );
                Decision::Generated
            }
        },
        // The plugin was asked and said nothing, which retires whatever it
        // supplied before — it is no longer offering a certificate for this name.
        Ok(SniVerdict::Generated) => {
            if cached.is_some() {
                state.ca.forget_plugin_cert(servername);
            }
            Decision::Generated
        }
        // The plugin could not be asked. Its last certificate, if we have one,
        // is a better answer than changing what a live client is being served
        // because a local process restarted.
        Err(reason) => {
            tracing::warn!(
                "sniCallback {plugin} ({servername}): {reason}; {}",
                if cached.is_some() {
                    "its cached certificate used"
                } else {
                    "generated certificate used"
                }
            );
            match cached {
                Some((_, acceptor)) => Decision::Plugin(acceptor),
                None => Decision::Generated,
            }
        }
    }
}

/// The facts a rule can match on at SNI time.
///
/// There is no request yet, so most of a [`ReqInfo`](crate::rules::ReqInfo) is
/// genuinely unknown and is left that way rather than invented: no method (so
/// `method:` matches nothing), no headers (so `reqH.` conditions fail closed),
/// no body. What *is* known is the URL, the client, and where the connection
/// came from, and those are filled in.
///
/// Upstream matches on less — it resolves against a socket carrying only
/// `fullUrl = 'https://' + servername` (`lib/https/index.js:1294`) — so a
/// `clientIp:` condition on an `sniCallback` line works here and does not there.
fn connection_req_info(
    servername: &str,
    port: u16,
    peer: SocketAddr,
    has_sni: bool,
) -> crate::rules::ReqInfo {
    let mut info = super::apply::build_req_info(
        "",
        "https",
        servername,
        port,
        "/",
        &hyper::HeaderMap::new(),
        Some(peer.ip().to_string()),
    );
    info.client_port = Some(peer.port());
    info.from = crate::rules::ReqOrigin {
        tunnel: true,
        sni: has_sni,
        composer: false,
    };
    info
}

/// Parse `sniCallback://[whistle.|plugin.]<name>(<value>)` into the plugin name
/// and its argument.
///
/// The grammar is `pipe://`'s, which is where whistle puts every rule value that
/// carries an opaque argument, and it is parsed by the same code — see
/// [`crate::plugins::parse_sni_rule`].
fn parse_rule(value: &str) -> Option<(String, String)> {
    crate::plugins::parse_sni_rule(value)
}

/// Relay a declined connection to its origin, byte for byte.
///
/// The ClientHello [`peek_client_hello`] took goes out first, so the origin sees
/// the connection the client actually opened — same extensions, same ALPN offer,
/// same session tickets — and the TLS session that results is between those two
/// and no one else.
///
/// The origin is the address the tunnel was opened to, and it is reached
/// directly. No rule has been resolved for a connection at this point beyond the
/// one that got us here, so there is no `proxy://` or `host://` to honour, and
/// pretending otherwise would mean resolving a request that does not exist.
pub async fn relay<S>(mut client: Prefixed<S>, host: &str, port: u16) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut origin = TcpStream::connect((host, port)).await?;
    origin.set_nodelay(true).ok();
    tokio::io::copy_bidirectional(&mut client, &mut origin).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A real ClientHello, produced by rustls itself so the bytes are not a
    /// hand-written approximation of one.
    fn client_hello_for(name: &str) -> Vec<u8> {
        let mut roots = rustls::RootCertStore::empty();
        roots.roots.clear();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    /// The name the client asked for is read off the ClientHello, and every byte
    /// of it is still available afterwards.
    #[test]
    fn the_client_hello_is_read_without_being_consumed() {
        rt().block_on(async {
            let hello = client_hello_for("api.example.com");
            let mut stream = std::io::Cursor::new(hello.clone());
            let peeked = peek_client_hello(&mut stream).await;
            assert_eq!(peeked.server_name.as_deref(), Some("api.example.com"));
            assert_eq!(peeked.prefix, hello, "the bytes are kept, not consumed");
        });
    }

    /// A hello that arrives in dribs and drabs is still read: the loop asks the
    /// socket again for as long as rustls says the message is incomplete.
    #[test]
    fn a_split_client_hello_is_reassembled() {
        rt().block_on(async {
            let hello = client_hello_for("split.example.com");
            let (a, b) = tokio::io::duplex(64 * 1024);
            let writer = tokio::spawn(async move {
                let mut a = a;
                for byte in hello {
                    a.write_all(&[byte]).await.unwrap();
                    a.flush().await.unwrap();
                }
                a
            });
            let mut b = b;
            let peeked = peek_client_hello(&mut b).await;
            writer.await.unwrap();
            assert_eq!(peeked.server_name.as_deref(), Some("split.example.com"));
        });
    }

    /// Anything that is not a ClientHello comes back as "no name", with the
    /// bytes intact — the peek never decides a connection is broken.
    #[test]
    fn non_tls_bytes_are_handed_back_untouched() {
        rt().block_on(async {
            let raw = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n".to_vec();
            let mut stream = std::io::Cursor::new(raw.clone());
            let peeked = peek_client_hello(&mut stream).await;
            assert!(peeked.server_name.is_none());
            assert_eq!(peeked.prefix, raw);
        });
    }

    /// An empty stream is not a crash, and a truncated one is not either.
    #[test]
    fn eof_is_not_a_failure() {
        rt().block_on(async {
            let mut empty = std::io::Cursor::new(Vec::new());
            let peeked = peek_client_hello(&mut empty).await;
            assert!(peeked.server_name.is_none());
            assert!(peeked.prefix.is_empty());

            let hello = client_hello_for("truncated.example.com");
            let mut half = std::io::Cursor::new(hello[..hello.len() / 2].to_vec());
            let peeked = peek_client_hello(&mut half).await;
            assert!(peeked.server_name.is_none());
            assert_eq!(peeked.prefix.len(), hello.len() / 2);
        });
    }

    /// Replaying the prefix reproduces the original stream exactly, and the
    /// buffer is dropped the moment it runs out.
    #[test]
    fn the_prefix_is_replayed_then_gets_out_of_the_way() {
        rt().block_on(async {
            let mut s = Prefixed::new(b"hello ".to_vec(), std::io::Cursor::new(b"world".to_vec()));
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"hello world");
            assert!(s.prefix.is_empty(), "the buffer is freed once drained");

            // Reads smaller than the prefix still come out in order.
            let mut s = Prefixed::new(b"abcd".to_vec(), std::io::Cursor::new(b"ef".to_vec()));
            let mut buf = [0u8; 3];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"abc");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, b"def");
        });
    }

    /// The whole point of the peek: a real client completes a real handshake
    /// against an acceptor fed the replayed bytes. If the prefix were dropped,
    /// reordered or duplicated, this is where it would show.
    #[test]
    fn a_handshake_survives_the_peek_and_replay() {
        rt().block_on(async {
            let config = crate::config::Config {
                storage_dir: std::env::temp_dir()
                    .join(format!("whistle-rs-sni-peek-{}", std::process::id())),
                ..crate::config::Config::default()
            };
            let ca = crate::ca::CertAuthority::load_or_create(&config).unwrap();

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_ca = ca.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let hello = peek_client_hello(&mut stream).await;
                let name = hello.server_name.clone().expect("SNI");
                let acceptor = server_ca.acceptor_for(&name).unwrap();
                let tls = acceptor
                    .accept(Prefixed::new(hello.prefix, stream))
                    .await
                    .expect("handshake over the replayed prefix");
                (name, tls.get_ref().1.server_name().map(str::to_string))
            });

            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.root_cert_der()).unwrap();
            let client_cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let stream = TcpStream::connect(addr).await.unwrap();
            let name = rustls::pki_types::ServerName::try_from("www.example.com").unwrap();
            tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
                .connect(name, stream)
                .await
                .expect("client accepted the certificate chosen from its own SNI");

            let (peeked, negotiated) = server.await.unwrap();
            assert_eq!(peeked, "www.example.com");
            // rustls saw the same name off the replayed bytes as the peek did.
            assert_eq!(negotiated.as_deref(), Some("www.example.com"));
        });
    }

    // ── the decision ───────────────────────────────────────────────────────

    /// A plugin server that answers `/sni` with one canned reply and records
    /// every request it was asked, so a test can assert what was *not* called.
    struct FakeSni {
        url: String,
        seen: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl FakeSni {
        /// Start a plugin whose `/sni` answers `status` with `body`.
        async fn start(status: u16, body: &str) -> Self {
            use tokio::io::AsyncWriteExt;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorder = seen.clone();
            let body = body.to_string();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let (body, recorder) = (body.clone(), recorder.clone());
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while sock.read_exact(&mut byte).await.is_ok() {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head = String::from_utf8_lossy(&head).into_owned();
                        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                        let len: usize = head
                            .to_ascii_lowercase()
                            .split("content-length:")
                            .nth(1)
                            .and_then(|r| r.split("\r\n").next())
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        let mut payload = vec![0u8; len];
                        sock.read_exact(&mut payload).await.ok();
                        recorder
                            .lock()
                            .unwrap()
                            .push((path.clone(), String::from_utf8_lossy(&payload).into_owned()));
                        let (status, out) = if path == "/manifest" {
                            (200, r#"{"name":"certs","version":"1","hooks":["sni"]}"#.to_string())
                        } else if path == "/sni" {
                            (status, body)
                        } else {
                            (404, String::new())
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                            out.len()
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.flush().await.ok();
                    });
                }
            });
            FakeSni { url, seen }
        }

        fn paths(&self) -> Vec<String> {
            self.seen.lock().unwrap().iter().map(|(p, _)| p.clone()).collect()
        }

        fn last_payload(&self) -> String {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(p, _)| p == "/sni")
                .map(|(_, b)| b.clone())
                .unwrap_or_default()
        }
    }

    /// State over a storage directory nobody else touches, with `rules` loaded
    /// and `plugin` registered under the name `certs`.
    fn state_with(rules: &str, plugin: Option<&FakeSni>) -> Arc<AppState> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let config = crate::config::Config {
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-sni-{}-{n}", std::process::id())),
            persist_sessions: false,
            ..crate::config::Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).unwrap();
        let mut mgr = crate::rules::RuleManager::new();
        mgr.set_text(rules);
        let mut plugins = crate::plugins::Plugins::new();
        if let Some(p) = plugin {
            plugins.register_remote("certs", &p.url);
        }
        Arc::new(AppState::with_plugins(config, mgr, ca, plugins))
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:51234".parse().unwrap()
    }

    async fn decide_for(state: &Arc<AppState>, servername: &str) -> Decision {
        decide(state, servername, servername, 443, peer(), true).await
    }

    /// A self-signed certificate and key in PEM, as a plugin would supply them.
    fn plugin_pem(common_name: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["plugin.test".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn json_cert(cert_pem: &str, key_pem: &str, mtime: u64) -> String {
        serde_json::json!({ "cert": cert_pem, "key": key_pem, "mtime": mtime }).to_string()
    }

    /// **The hard requirement.** A connection nobody wrote a rule for must not
    /// reach the plugin runtime at all — not the registry, not the manifest,
    /// not the hook. The precomputed flag is what makes that true, so a
    /// registered `sni` plugin sitting right there is part of the test.
    #[test]
    fn a_connection_with_no_rule_never_asks() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            // Rules exist, and one even names the plugin — through a scheme that
            // has nothing to do with certificates.
            let state = state_with("example.com plugin://certs\nother.com resHeaders://x=1", Some(&plugin));
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
            assert!(plugin.paths().is_empty(), "the plugin was contacted: {:?}", plugin.paths());
            assert!(!state.rules.read().unwrap().has_sni_callback());
        });
    }

    /// A rule that exists but matches a different name is the same answer, and
    /// still no plugin call.
    #[test]
    fn a_rule_for_another_host_is_not_this_connection() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with("other.example.com sniCallback://certs", Some(&plugin));
            assert!(state.rules.read().unwrap().has_sni_callback());
            assert!(matches!(decide_for(&state, "www.example.com").await, Decision::Generated));
            assert!(plugin.paths().is_empty());
        });
    }

    /// `{"intercept": true}` — intercept with the certificate whistle-rs would
    /// have generated anyway.
    #[test]
    fn intercept_true_means_the_generated_certificate() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":true}"#).await;
            let state = state_with("example.com sniCallback://certs(staging)", Some(&plugin));
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
            // And the plugin was told what it needs to decide.
            let payload: serde_json::Value =
                serde_json::from_str(&plugin.last_payload()).unwrap();
            assert_eq!(payload["servername"], "example.com");
            assert_eq!(payload["value"], "staging");
            assert_eq!(payload["port"], 443);
            assert_eq!(payload["clientIp"], "127.0.0.1");
            assert!(payload.get("certCacheName").is_none(), "nothing cached yet");
        });
    }

    /// `{"intercept": false}` — do not intercept.
    #[test]
    fn intercept_false_means_no_interception() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Bypass));
        });
    }

    /// `{key, cert}` — and the certificate a client is actually served is the
    /// plugin's, not one this CA signed.
    #[test]
    fn a_supplied_certificate_is_the_one_served() {
        rt().block_on(async {
            let (cert_pem, key_pem) = plugin_pem("supplied-by-plugin");
            let plugin = FakeSni::start(200, &json_cert(&cert_pem, &key_pem, 7)).await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            let Decision::Plugin(acceptor) = decide_for(&state, "example.com").await else {
                panic!("expected the plugin's certificate");
            };

            // Complete a handshake and read back the leaf the server presented.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                acceptor.accept(s).await.ok();
            });
            let served = leaf_presented_by(addr, "plugin.test", &cert_pem).await;
            let expected = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(served, expected, "the plugin's own leaf was served");

            // A CA-generated leaf for the same name is a different certificate,
            // which is what makes the assertion above mean something.
            let generated = state.ca.acceptor_for("example.com").unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                generated.accept(s).await.ok();
            });
            let ca_leaf = leaf_presented_by(addr, "example.com", state.ca.root_cert_pem()).await;
            assert_ne!(ca_leaf, served);
        });
    }

    /// Connect, trusting only `trusted_pem`, and return the leaf the server sent.
    async fn leaf_presented_by(
        addr: SocketAddr,
        server_name: &'static str,
        trusted_pem: &str,
    ) -> rustls::pki_types::CertificateDer<'static> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut trusted_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let stream = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from(server_name).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, stream)
            .await
            .expect("handshake");
        tls.get_ref()
            .1
            .peer_certificates()
            .expect("peer certificates")[0]
            .clone()
            .into_owned()
    }

    /// `{"reuse": true}` — the certificate this plugin supplied last time, and
    /// the generated one when it never supplied any.
    #[test]
    fn reuse_returns_the_cached_certificate() {
        rt().block_on(async {
            // Nothing cached: reuse degrades to the generated certificate.
            let plugin = FakeSni::start(200, r#"{"reuse":true}"#).await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));

            // Now seed the cache the way a real reply would, and ask again.
            let (cert_pem, key_pem) = plugin_pem("cached");
            state
                .ca
                .set_plugin_cert("example.com", "certs", &cert_pem, &key_pem, 11)
                .unwrap();
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Plugin(_)));

            // And the plugin is now told what is cached, so it can skip re-issuing.
            let payload: serde_json::Value =
                serde_json::from_str(&plugin.last_payload()).unwrap();
            assert_eq!(payload["certCacheName"], "certs");
            assert_eq!(payload["certCacheTime"], 11);
        });
    }

    /// A cached certificate belongs to the plugin that supplied it: a rule
    /// pointing somewhere else must not be handed it, nor told it exists.
    #[test]
    fn the_cache_is_scoped_to_one_plugin() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"reuse":true}"#).await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            let (cert_pem, key_pem) = plugin_pem("someone else's");
            state
                .ca
                .set_plugin_cert("example.com", "other-plugin", &cert_pem, &key_pem, 3)
                .unwrap();
            assert!(state.ca.plugin_cert("example.com", "certs").is_none());
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
            let payload: serde_json::Value =
                serde_json::from_str(&plugin.last_payload()).unwrap();
            assert!(payload.get("certCacheName").is_none());
        });
    }

    /// Every malformed reply ends at the generated certificate — never a bypass,
    /// never a half-built acceptor, and never a panic. Unusable PEM is the case
    /// that matters most: it is the one shape that gets as far as rustls.
    #[test]
    fn a_malformed_reply_never_breaks_the_listener() {
        rt().block_on(async {
            let (good_cert, good_key) = plugin_pem("good");
            let (other_cert, _) = plugin_pem("other");
            let (_, other_key) = plugin_pem("mismatched");
            for body in [
                "not json".to_string(),
                "{}".to_string(),
                r#"{"cert":"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n","key":"x"}"#.to_string(),
                // Well-formed PEM on both sides, but not each other's pair.
                json_cert(&other_cert, &other_key, 0),
                // A certificate with no key.
                json_cert(&good_cert, "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n", 0),
                // A key with no certificate.
                json_cert("", &good_key, 0),
            ] {
                let plugin = FakeSni::start(200, &body).await;
                let state = state_with("example.com sniCallback://certs", Some(&plugin));
                assert!(
                    matches!(decide_for(&state, "example.com").await, Decision::Generated),
                    "{body}"
                );
                // Whatever happened, the proxy can still serve this host.
                state.ca.acceptor_for("example.com").expect("generated cert still works");
            }
        });
    }

    /// A plugin that cannot be asked keeps serving whatever it last supplied —
    /// a local process restarting must not change the certificate under a live
    /// client — and falls back to the generated one when it supplied nothing.
    #[test]
    fn a_failing_plugin_keeps_its_last_certificate() {
        rt().block_on(async {
            let plugin = FakeSni::start(500, "boom").await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));

            let (cert_pem, key_pem) = plugin_pem("survives a restart");
            state
                .ca
                .set_plugin_cert("example.com", "certs", &cert_pem, &key_pem, 5)
                .unwrap();
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Plugin(_)));
        });
    }

    /// Saying nothing is the plugin *withdrawing* its certificate, which is not
    /// the same as failing to answer — the entry goes.
    #[test]
    fn an_empty_answer_retires_the_cached_certificate() {
        rt().block_on(async {
            let plugin = FakeSni::start(204, "").await;
            let state = state_with("example.com sniCallback://certs", Some(&plugin));
            let (cert_pem, key_pem) = plugin_pem("withdrawn");
            state
                .ca
                .set_plugin_cert("example.com", "certs", &cert_pem, &key_pem, 1)
                .unwrap();
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
            assert!(state.ca.plugin_cert("example.com", "certs").is_none());
        });
    }

    /// A rule naming a plugin that is not registered, or one with no `sni` hook,
    /// is not a reason to break a handshake.
    #[test]
    fn a_rule_naming_no_usable_plugin_is_harmless() {
        rt().block_on(async {
            let state = state_with("example.com sniCallback://nobody", None);
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
            // `echo` is registered but declares no `sni` hook.
            let state = state_with("example.com sniCallback://echo", None);
            assert!(matches!(decide_for(&state, "example.com").await, Decision::Generated));
        });
    }

    /// The built-in: `sniCallback://no-mitm` declines, in process, with no
    /// certificate of its own.
    #[test]
    fn the_builtin_declines_interception() {
        rt().block_on(async {
            let state = state_with("pinned.example.com sniCallback://no-mitm", None);
            assert!(matches!(decide_for(&state, "pinned.example.com").await, Decision::Bypass));
            assert!(matches!(decide_for(&state, "other.example.com").await, Decision::Generated));
        });
    }

    /// The rule matches on the name in the ClientHello, so the same connection
    /// gets different answers depending on what the client asked for.
    #[test]
    fn the_rule_matches_the_name_the_client_asked_for() {
        rt().block_on(async {
            let state = state_with("pinned.example.com sniCallback://no-mitm", None);
            // Tunnel opened to an address, SNI naming the pinned host.
            let d = decide(&state, "pinned.example.com", "93.184.216.34", 443, peer(), true).await;
            assert!(matches!(d, Decision::Bypass));
            // Same tunnel address, a different name asked for.
            let d = decide(&state, "www.example.com", "93.184.216.34", 443, peer(), true).await;
            assert!(matches!(d, Decision::Generated));
        });
    }

    /// The rule grammar: package prefixes stripped, `(value)` captured, and an
    /// empty name refused.
    #[test]
    fn the_rule_value_grammar() {
        assert_eq!(
            parse_rule("mycerts"),
            Some(("mycerts".to_string(), String::new()))
        );
        assert_eq!(
            parse_rule("whistle.mycerts(staging)"),
            Some(("mycerts".to_string(), "staging".to_string()))
        );
        assert_eq!(
            parse_rule("plugin.mycerts(a/b (c))"),
            Some(("mycerts".to_string(), "a/b (c)".to_string()))
        );
        assert_eq!(parse_rule(""), None);
        assert_eq!(parse_rule("()"), None);
    }
}
