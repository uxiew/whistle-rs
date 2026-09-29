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
use tokio_rustls::TlsAcceptor;

use super::{AppState, upstream};
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
            Err(_) => {
                return Hello {
                    prefix,
                    server_name: None,
                };
            }
            Ok(None) => {}
        }
        if prefix.len() >= MAX_HELLO_BYTES {
            return Hello {
                prefix,
                server_name: None,
            };
        }
        // Straight into the buffer's spare capacity: a stack array here would be
        // zeroed on every pass *and* would make this future — which is held for
        // the life of the connection — carry it.
        prefix.reserve(PEEK_CHUNK);
        match stream.read_buf(&mut prefix).await {
            Ok(0) | Err(_) => {
                return Hello {
                    prefix,
                    server_name: None,
                };
            }
            Ok(_) => {}
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
    /// Read the tunnel, but there is no handshake to make: it is carrying
    /// cleartext, and [`Carried`] says which kind. Upstream feeds a cleartext
    /// `HTTP/1.x` tunnel back into its own HTTP server and a cleartext `h2`
    /// preface into an HTTP/2 one (`_original/lib/https/index.js:1204-1221,:1274-1276`).
    Cleartext(Carried),
    /// Do not intercept: relay the connection opaquely to the carried target,
    /// which is where this connection's `host://` and proxy rules have landed.
    ///
    /// Boxed because a `Target` is an order of magnitude larger than the other
    /// variants' payloads, and this one is reached only when a plugin declines.
    Bypass(Box<upstream::Target>),
    /// The rules for this connection cannot be honoured — a proxy rule matched
    /// and no proxy could be derived from it. Nothing is served: failing open
    /// would put the bytes on the wire the rule said to divert.
    Unroutable(String),
}

/// Where a connection goes when it is relayed rather than intercepted.
///
/// A connection we have promised not to read has no *request* to rewrite, but a
/// URL-replacement rule can still move the address it is relayed to — upstream's
/// tunnel path rewrites `tunnelUrl` from the `rule` slot for exactly that
/// (`_original/lib/tunnel.js:415-427`) and then hands the rewritten URL to
/// `getProxy` (`:434`), so `host://` and the proxy family are matched against
/// where the connection is going rather than where it said it was going. A proxy
/// rule that cannot be honoured closes the connection rather than quietly
/// putting the bytes on the wire it was told to divert.
async fn relay_decision(
    state: &Arc<AppState>,
    info: &crate::rules::ReqInfo,
    resolved: &crate::rules::Resolved,
) -> Decision {
    let dest = super::dest::Destination::of(info, resolved);
    // No values pass here, because the connection's own resolution had none:
    // `decide` matches against the live rule set and nothing else.
    let forwarding = dest.replaced.then(|| {
        let rules = state.rules.read().unwrap();
        super::apply::reresolve_forwarding(resolved, &dest.moved_req_info(info), &rules, &[], false)
    });
    let forwarding = forwarding.as_ref().unwrap_or(resolved);
    match super::apply::resolve_target(info, &dest, forwarding).await {
        Ok(target) => Decision::Bypass(Box::new(target)),
        Err(err) => Decision::Unroutable(format!("{err:#}")),
    }
}

/// Consult the `sniCallback://` rules for this connection.
///
/// The common answer is [`Decision::Generated`] and it is reached without
/// building anything: a rules file with no `sniCallback://` in it costs one
/// `bool` per group, precomputed when the group parsed. That is what keeps a
/// connection nobody wrote a rule for identical to one from before this hook
/// existed.
/// Does a rule ask for this connection to be relayed rather than read?
///
/// Read straight off `disable`, without the `enable://` cancellation, as
/// upstream reads it. The three spellings are one question there and one here.
fn no_intercept(resolved: &crate::rules::Resolved) -> bool {
    let disabled = crate::proxy::apply::disabled_flags(resolved);
    ["intercept", "https", "capture"]
        .iter()
        .any(|f| disabled.contains(*f))
}

/// What is actually travelling inside a `CONNECT` tunnel.
///
/// A tunnel is opened to an address, not to a protocol, and the client may put
/// anything through it. Upstream sniffs the first chunk and branches three ways
/// (`_original/lib/https/index.js:1176-1221`); this port used to assume TLS and
/// hand every tunnel to the TLS acceptor, which breaks the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
    /// A TLS record — `chunk[0] == 22`.
    Tls,
    /// A cleartext HTTP/1.x request line (`HTTP_RE`, `lib/https/index.js:1118`).
    Http,
    /// The cleartext HTTP/2 preface (`HTTP2_RE`, `:1119`).
    H2c,
    /// Anything else. Upstream passes it through untouched, which is the only
    /// thing a proxy can do with a protocol it does not speak.
    Opaque,
}

/// Classify the first bytes of a tunnel — upstream's two regexes and its one
/// byte test, in upstream's order.
///
/// The HTTP test is deliberately upstream's `/^(\w+)\s+(\S+)\s+HTTP\/1.\d$/im`
/// rather than a list of methods: it is multi-line and anchored per line, and it
/// is what decides that a tunnel carrying `GET / HTTP/1.1` is a request and not
/// a handshake. `\w+` accepts any method, including one nobody has registered.
pub fn carried_protocol(prefix: &[u8]) -> Carried {
    // Only the head is examined, as upstream examines only its first chunk.
    let head = &prefix[..prefix.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    if http_request_line(&text) {
        return Carried::Http;
    }
    if text.lines().any(|line| line.trim_end() == "PRI * HTTP/2.0") {
        return Carried::H2c;
    }
    match head.first() {
        Some(22) => Carried::Tls,
        _ => Carried::Opaque,
    }
}

/// `HTTP_RE = /^(\w+)\s+(\S+)\s+HTTP\/1.\d$/im` — a request line on a line of
/// its own, anywhere in the chunk.
fn http_request_line(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_end_matches('\r');
        let mut parts = line.split_ascii_whitespace();
        let (Some(method), Some(target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        // `$` after the version, so nothing may follow it on the line — which is
        // why the whole line is split and the fourth field must be absent.
        method.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !target.is_empty()
            && version.len() == "HTTP/1.x".len()
            && version.starts_with("HTTP/1.")
            && version.as_bytes()[7].is_ascii_digit()
    })
}

/// Is this authority an IP literal — `net.isIP` (`_original/lib/https/index.js:1287`)?
///
/// A bracketed IPv6 authority is unwrapped first: whichever way the CONNECT line
/// spelled it, `net.isIP` is given the address alone.
fn is_ip_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>().is_ok()
}

/// The second gate: does this **ClientHello** decline interception, given what
/// the client did or did not name?
///
/// Upstream is one expression (`lib/https/index.js:1285-1291`), and it asks a
/// different question of each half of the connections:
///
/// ```text
/// useSNI ? disable.captureSNI
///        : (disable.captureNoSNI || (net.isIP(servername) && !isCaptureIp()))
/// ```
///
/// The clause that matters without any rule at all is the last one. **A tunnel
/// to a bare IP address, whose ClientHello named no server, is not decrypted** —
/// `isCaptureIp()` is false unless something asks for it
/// (`enable://capture`, `enable://captureIp`, `enable://captureIP`), and
/// `disable://captureIp` / `disable://captureIP` refuse even then. So
/// `https://10.0.0.5/` goes through whistle untouched while `https://api.test/`
/// is read, and this port used to read both. Measured: whistle 2.10.8 answers a
/// CONNECT to `127.0.0.1:<tls port>` with the **origin's own** certificate, and
/// a CONNECT to `localhost:<same port>` with one it forged.
///
/// TLS forbids an IP literal in SNI, so "the authority is an IP" and "the client
/// named nothing" almost always arrive together; they are still two conditions
/// here because upstream writes them as two.
///
/// Upstream has a fourth way to say yes — a `user-agent` the console has marked
/// for capture (`isCaptureUA`, `uaCache`, `lib/https/index.js:66-68`). There is
/// no such list here, so that term is a constant `false`, which is also what it
/// is upstream for every UA nobody has marked.
///
/// The flags are read straight off `enable`/`disable`, without the cancellation
/// `isEnable` applies elsewhere — as upstream reads them here.
fn declines_at_client_hello(
    resolved: &crate::rules::Resolved,
    has_sni: bool,
    servername: &str,
) -> bool {
    let disabled = crate::proxy::apply::disabled_flags(resolved);
    // Before the ClientHello is even looked at, upstream asks what the tunnel is
    // carrying and lets four flags answer for a whole class of them
    // (`lib/https/index.js:1204-1216`). `forHttps` means "capture only HTTPS",
    // so a cleartext tunnel is passed through; `forHttp` is its mirror.
    let enabled = crate::proxy::apply::enabled_flags(resolved);
    if enabled.contains("forHttp") || disabled.contains("captureHttps") {
        return true;
    }
    if has_sni {
        return disabled.contains("captureSNI");
    }
    if disabled.contains("captureNoSNI") {
        return true;
    }
    if !is_ip_literal(servername) {
        return false;
    }
    if disabled.contains("captureIp") || disabled.contains("captureIP") {
        return true;
    }
    !["capture", "captureIp", "captureIP"]
        .iter()
        .any(|f| enabled.contains(*f))
}

/// The same question for a tunnel that turned out to be carrying **cleartext**:
/// `enable://forHttps` and `disable://captureHttp` each pass it through
/// (`_original/lib/https/index.js:1205`).
///
/// The mirror flags — `forHttp` and `captureHttps` — belong to the TLS half and
/// live in [`declines_at_client_hello`].
fn declines_cleartext(resolved: &crate::rules::Resolved) -> bool {
    crate::proxy::apply::enabled_flags(resolved).contains("forHttps")
        || crate::proxy::apply::disabled_flags(resolved).contains("captureHttp")
}

pub async fn decide(
    state: &Arc<AppState>,
    servername: &str,
    tunnel_host: &str,
    port: u16,
    peer: SocketAddr,
    has_sni: bool,
    carried: Carried,
) -> Decision {
    // A tunnel carrying something this proxy does not speak is passed through,
    // whatever the rules say about certificates — upstream's
    // `if (!isHttpH2 && chunk[0] != 22) return next(chunk)`
    // (`_original/lib/https/index.js:1219-1221`). There is nothing to read, so
    // there is nothing for a rule to read it *as*; the connection is still
    // routed, which is all a relay ever was.
    if carried == Carried::Opaque {
        let (info, resolved) = {
            let rules = state.rules.read().unwrap();
            let info = connection_req_info(servername, port, peer, has_sni);
            let resolved = rules.resolve(&info);
            (info, resolved)
        };
        return relay_decision(state, &info, &resolved).await;
    }
    // Interception switched off globally: every TLS connection is relayed, and
    // the answer is the same one a plugin's `false` produces — the connection is
    // still *routed* by its rules, it is simply not read. whistle spells this
    // `-M pureProxy`; here it is `--no-intercept-https`.
    if !state.config.intercepts_https() {
        let (info, resolved) = {
            let rules = state.rules.read().unwrap();
            let info = connection_req_info(servername, port, peer, has_sni);
            let resolved = rules.resolve(&info);
            (info, resolved)
        };
        return relay_decision(state, &info, &resolved).await;
    }
    // Scoped so the read guard cannot cross the `.await` below. `Resolved` owns
    // its contents, so it outlives the guard and is kept: a declined connection
    // still has to be routed, and re-resolving would mean matching twice.
    // A tunnel to a bare IP whose ClientHello named nothing is the one shape
    // that declines interception with **no rule written at all**, so it cannot
    // take the fast path below — see [`declines_at_client_hello`]. Two string
    // parses, and only for a connection addressed by address.
    let bare_ip = !has_sni && is_ip_literal(servername);
    let cleartext = carried != Carried::Tls;
    let (matched, info, resolved, relay) = {
        let rules = state.rules.read().unwrap();
        // Two questions, both answered from a `bool` per group: does anything
        // want to choose a certificate, and does anything want this connection
        // left alone? A rules file that asks neither costs exactly this much.
        if !bare_ip && !rules.has_sni_callback() && !rules.has_no_intercept() {
            return match cleartext {
                true => Decision::Cleartext(carried),
                false => Decision::Generated,
            };
        }
        let info = connection_req_info(servername, port, peer, has_sni);
        let resolved = rules.resolve(&info);
        // `disable://intercept` — and its two other spellings — mean "route this
        // connection but do not read it" (`disable.intercept || disable.https ||
        // disable.capture`, `_original/lib/tunnel.js:167-169`). It is the answer
        // a certificate-pinned client needs, and it outranks `sniCallback://`:
        // asking a plugin which certificate to forge for a connection nobody is
        // going to forge one for is a question with no use for its answer.
        //
        // Decided here and acted on below, because the relay is an `.await` and
        // the read guard must not cross one. The second half is the ClientHello's
        // own gate, which upstream reaches only after the tunnel's — same order,
        // same effect, and `sniCallback://` loses to either for the same reason.
        let relay = no_intercept(&resolved)
            || match cleartext {
                true => declines_cleartext(&resolved),
                false => declines_at_client_hello(&resolved, has_sni, servername),
            };
        let matched = match relay || cleartext {
            true => None,
            // A cleartext tunnel has no handshake, so nothing to ask a
            // certificate plugin about.
            false => resolved.value("sniCallback").and_then(parse_rule),
        };
        (matched, info, resolved, relay)
    };
    if relay {
        return relay_decision(state, &info, &resolved).await;
    }
    if cleartext {
        return Decision::Cleartext(carried);
    }
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
        // The plugin declined the interception. The connection still obeys its
        // rules about *where it goes* — declining to read a connection is not
        // declining to route it, and whistle's declined path is literally its
        // ordinary tunnel path (`next(chunk)` → `rollBackTunnel` →
        // `handleTunnel`, `_original/lib/tunnel.js:259-271,:298`), which resolves
        // `host://` and the proxy family through `rules.getProxy`.
        Ok(SniVerdict::Bypass) => {
            tracing::info!("sniCallback {plugin}: not intercepting {servername}");
            relay_decision(state, &info, &resolved).await
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
                    tracing::debug!(
                        "sniCallback {plugin}: serving its certificate for {servername}"
                    );
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

/// The facts a rule can match on about a connection, before any request in it.
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
///
/// Two stages read it, and it is deliberately one definition: this one, where
/// the name comes from the ClientHello, and the connection's abort gate
/// ([`super::tunnel_aborted`]), where nothing has been read yet and the name is
/// the address the client asked to reach. A rule that decides one should decide
/// the other the same way.
pub(super) fn connection_req_info(
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
/// `target` is where the connection goes, and it comes from the rules that
/// matched it: `host://` redirects the address, the `proxy://` family routes the
/// hop through an upstream proxy. Declining to *read* a connection is not
/// declining to route it, and whistle's declined path is its ordinary tunnel path
/// (`_original/lib/tunnel.js:259-271`), which resolves both.
///
/// What a relayed connection does *not* get is anything that would require
/// reading it: no capture, no request rules, no response phase. There is no
/// request here — only bytes we agreed not to look at.
///
/// `enable://abort` is not missing from that list: a connection the rules refuse
/// never gets this far, having been turned away at the CONNECT or the SOCKS
/// handshake, before the client was told anything was open — see
/// [`super::tunnel_aborted`].
///
/// `origin` is the leg [`upstream::tunnel_stream`] opened to `target`; the
/// caller opens it, because whether it opened is what the tunnel's session
/// records.
pub(crate) async fn relay<S>(mut client: Prefixed<S>, mut origin: upstream::BoxedIo) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut client, &mut origin).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

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
                            (
                                200,
                                r#"{"name":"certs","version":"1","hooks":["sni"]}"#.to_string(),
                            )
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
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(p, _)| p.clone())
                .collect()
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

    /// Like [`state_with`], but with interception switched off globally.
    fn relaying_state(rules: &str) -> Arc<AppState> {
        let state = state_with(rules, None);
        let mut config = state.config.clone();
        config.intercept_https = false;
        let ca = crate::ca::CertAuthority::load_or_create(&config).unwrap();
        let mut mgr = crate::rules::RuleManager::new();
        mgr.set_text(rules);
        Arc::new(AppState::with_plugins(
            config,
            mgr,
            ca,
            crate::plugins::Plugins::new(),
        ))
    }

    /// `--no-intercept-https` relays every TLS connection — but relaying is not
    /// the same as ignoring: the connection still goes where its rules say.
    ///
    /// The field behind this switch existed and nothing read it, so the setting
    /// was inert and the console's Status pane reported it as if it were not.
    #[tokio::test]
    async fn interception_off_relays_but_still_routes() {
        // No rule at all: relayed straight to the address asked for.
        let state = relaying_state("");
        match decide_for(&state, "example.test").await {
            Decision::Bypass(target) => {
                assert_eq!(target.connect_host, "example.test");
                assert_eq!(target.connect_port, 443);
            }
            _ => panic!("expected a relay"),
        }

        // `host://` still moves the socket, exactly as it does for a connection
        // a plugin declined to intercept.
        let state = relaying_state(
            "example.test host://10.0.0.9
",
        );
        match decide_for(&state, "example.test").await {
            Decision::Bypass(target) => assert_eq!(target.connect_host, "10.0.0.9"),
            _ => panic!("expected a relay"),
        }

        // And a proxy rule that cannot be honoured still closes the connection
        // rather than putting the bytes on the wire it was told to divert.
        let state = relaying_state(
            "example.test proxy://
",
        );
        assert!(
            matches!(
                decide_for(&state, "example.test").await,
                Decision::Unroutable(_)
            ),
            "an unusable proxy rule must not fail open"
        );
    }

    /// With interception on and no `sniCallback://` rule, nothing changes: the
    /// connection is intercepted with a generated certificate as before.
    #[tokio::test]
    async fn interception_on_is_unchanged() {
        let state = state_with("example.test host://10.0.0.9\n", None);
        assert!(matches!(
            decide_for(&state, "example.test").await,
            Decision::Generated
        ));
    }

    /// `disable://intercept` relays the connection instead of reading it —
    /// what a certificate-pinned client needs, and one of whistle's
    /// most-reached-for flags (`disable.intercept || disable.https ||
    /// disable.capture`, `_original/lib/tunnel.js:167-169`). This port had only
    /// the global `--no-intercept-https` and no way to say it per host.
    #[tokio::test]
    async fn disable_intercept_relays_the_connection() {
        for spelling in ["intercept", "https", "capture"] {
            let state = state_with(&format!("example.test disable://{spelling}\n"), None);
            assert!(
                matches!(
                    decide_for(&state, "example.test").await,
                    Decision::Bypass(_)
                ),
                "disable://{spelling} should relay"
            );
        }
        // …and it names one connection, not all of them.
        let state = state_with("example.test disable://intercept\n", None);
        assert!(matches!(
            decide_for(&state, "other.test").await,
            Decision::Generated
        ));
    }

    /// A relayed connection is still **routed**: `host://` lands in the target
    /// the bypass carries, which is what makes "do not read this, but do send
    /// it somewhere else" expressible.
    #[tokio::test]
    async fn a_relayed_connection_is_still_routed() {
        let state = state_with("example.test disable://intercept host://10.0.0.9\n", None);
        match decide_for(&state, "example.test").await {
            Decision::Bypass(target) => assert_eq!(target.connect_host, "10.0.0.9"),
            _ => panic!("expected a routed bypass"),
        }
    }

    /// The flag outranks `sniCallback://`: choosing a certificate to forge for
    /// a connection nobody will forge one for is a question with no use for its
    /// answer, so the plugin is never asked.
    #[tokio::test]
    async fn disable_intercept_outranks_the_certificate_hook() {
        let plugin = FakeSni::start(200, r#"{"intercept":true}"#).await;
        let state = state_with(
            "example.test disable://intercept sniCallback://sni\n",
            Some(&plugin),
        );
        assert!(matches!(
            decide_for(&state, "example.test").await,
            Decision::Bypass(_)
        ));
        assert!(
            plugin.seen.lock().unwrap().is_empty(),
            "the hook must not be asked"
        );
    }

    async fn decide_for(state: &Arc<AppState>, servername: &str) -> Decision {
        decide(
            state,
            servername,
            servername,
            443,
            peer(),
            true,
            Carried::Tls,
        )
        .await
    }

    /// A CONNECT whose ClientHello named nothing, so the authority is all there
    /// is to go on — the shape `declines_at_client_hello` is about.
    async fn decide_without_sni(state: &Arc<AppState>, authority: &str) -> Decision {
        decide(
            state,
            authority,
            authority,
            443,
            peer(),
            false,
            Carried::Tls,
        )
        .await
    }

    /// **A tunnel to a bare IP that named no server is not decrypted**, and no
    /// rule has to say so — `net.isIP(servername) && !isCaptureIp()`
    /// (`_original/lib/https/index.js:1287`).
    ///
    /// Measured before it was written: whistle 2.10.8 answers a CONNECT to
    /// `127.0.0.1:<tls port>` with the **origin's own** certificate and one to
    /// `localhost:<the same port>` with one it forged. This port read both.
    #[test]
    fn a_bare_ip_with_no_sni_is_relayed_unless_asked_for() {
        rt().block_on(async {
            let bypass = |d: &Decision| matches!(d, Decision::Bypass(_));

            // No rules at all: the address alone decides.
            let plain = state_with("", None);
            assert!(bypass(&decide_without_sni(&plain, "127.0.0.1").await));
            assert!(bypass(&decide_without_sni(&plain, "::1").await));
            assert!(bypass(&decide_without_sni(&plain, "[::1]").await));
            // A name is read, with or without SNI…
            assert!(matches!(
                decide_without_sni(&plain, "example.com").await,
                Decision::Generated
            ));
            assert!(matches!(
                decide_for(&plain, "example.com").await,
                Decision::Generated
            ));
            // …and so is an IP whose client *did* name a server, which TLS does
            // not allow but the expression still distinguishes.
            assert!(matches!(
                decide_for(&plain, "127.0.0.1").await,
                Decision::Generated
            ));

            // Three spellings ask for it back.
            for rules in [
                "127.0.0.1 enable://capture",
                "127.0.0.1 enable://captureIp",
                "127.0.0.1 enable://captureIP",
            ] {
                let state = state_with(rules, None);
                assert!(
                    matches!(
                        decide_without_sni(&state, "127.0.0.1").await,
                        Decision::Generated
                    ),
                    "{rules}"
                );
            }
            // …and `disable://` refuses even then, which is the only thing that
            // flag is for.
            for rules in [
                "127.0.0.1 enable://capture disable://captureIp",
                "127.0.0.1 enable://captureIp disable://captureIP",
            ] {
                let state = state_with(rules, None);
                assert!(
                    bypass(&decide_without_sni(&state, "127.0.0.1").await),
                    "{rules}"
                );
            }
        });
    }

    /// What a tunnel is carrying, by upstream's two regexes and its one byte
    /// test (`_original/lib/https/index.js:1118-1119,:1178,:1218-1221`).
    #[test]
    fn a_tunnel_is_classified_by_its_first_bytes() {
        let of = |bytes: &[u8]| carried_protocol(bytes);
        // A TLS record: handshake, any version.
        assert_eq!(of(&[0x16, 0x03, 0x01, 0x02, 0x00]), Carried::Tls);
        // Cleartext HTTP/1.x, whatever the method — `\w+`, not a list.
        for line in [
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST /x?y=1 HTTP/1.0\r\n\r\n",
            "PROPFIND / HTTP/1.1\r\n",
            "X9 /a HTTP/1.9\r\n",
        ] {
            assert_eq!(of(line.as_bytes()), Carried::Http, "{line:?}");
        }
        // The regexp is multi-line, so a request line further in still counts —
        // which is how a chunk that opens with a blank line is read.
        assert_eq!(of(b"\r\nGET / HTTP/1.1\r\n"), Carried::Http);
        // The cleartext HTTP/2 preface.
        assert_eq!(of(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Carried::H2c);
        // Anything else is somebody else's protocol.
        for bytes in [
            &b"SSH-2.0-OpenSSH_9.0\r\n"[..],
            &[0x00, 0x01, 0x02, 0x03][..],
            &b"GET / HTTP/3.0\r\n"[..],
            // Three fields are required, and nothing may follow the version.
            &b"GET /\r\n"[..],
            &b"GET / HTTP/1.1 extra\r\n"[..],
            &[][..],
        ] {
            assert_eq!(
                of(bytes),
                Carried::Opaque,
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    /// A tunnel carrying cleartext is read as cleartext, and one carrying
    /// something else is passed through — neither is handed to a TLS acceptor.
    #[test]
    fn a_tunnel_that_is_not_tls_is_not_handshaken() {
        rt().block_on(async {
            let state = state_with("", None);
            let at = |c| async move {
                decide(
                    &state_with("", None),
                    "probe.test",
                    "probe.test",
                    443,
                    peer(),
                    false,
                    c,
                )
                .await
            };
            assert!(matches!(
                at(Carried::Http).await,
                Decision::Cleartext(Carried::Http)
            ));
            assert!(matches!(
                at(Carried::H2c).await,
                Decision::Cleartext(Carried::H2c)
            ));
            assert!(matches!(at(Carried::Opaque).await, Decision::Bypass(_)));
            assert!(matches!(at(Carried::Tls).await, Decision::Generated));

            // The four flags that decide by what the tunnel carries. Each one
            // rules out its own half and leaves the other alone.
            let dec = |rules: &str, c| {
                let s = state_with(rules, None);
                async move { decide(&s, "probe.test", "probe.test", 443, peer(), false, c).await }
            };
            for (rules, half) in [
                ("probe.test enable://forHttps", Carried::Http),
                ("probe.test disable://captureHttp", Carried::Http),
                ("probe.test enable://forHttp", Carried::Tls),
                ("probe.test disable://captureHttps", Carried::Tls),
            ] {
                assert!(
                    matches!(dec(rules, half).await, Decision::Bypass(_)),
                    "{rules}"
                );
                let other = match half {
                    Carried::Http => Carried::Tls,
                    _ => Carried::Http,
                };
                assert!(
                    !matches!(dec(rules, other).await, Decision::Bypass(_)),
                    "{rules} must leave the other half alone"
                );
            }
            // And `disable://intercept` still covers both, as the gate before
            // the sniff does upstream.
            let _ = state;
            for c in [Carried::Http, Carried::Tls] {
                assert!(matches!(
                    dec("probe.test disable://intercept", c).await,
                    Decision::Bypass(_)
                ));
            }
        });
    }

    /// The other two clauses of the same expression: one for each half of the
    /// connections, by whether the client named a server.
    #[test]
    fn capture_sni_and_capture_no_sni_each_rule_out_one_half() {
        rt().block_on(async {
            let bypass = |d: &Decision| matches!(d, Decision::Bypass(_));
            let sni = state_with("example.com disable://captureSNI", None);
            assert!(bypass(&decide_for(&sni, "example.com").await));
            // It says nothing about a connection that named nothing.
            assert!(matches!(
                decide_without_sni(&sni, "example.com").await,
                Decision::Generated
            ));

            let no_sni = state_with("example.com disable://captureNoSNI", None);
            assert!(bypass(&decide_without_sni(&no_sni, "example.com").await));
            assert!(matches!(
                decide_for(&no_sni, "example.com").await,
                Decision::Generated
            ));
        });
    }

    /// A self-signed certificate and key in PEM, as a plugin would supply them.
    fn plugin_pem(common_name: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["plugin.test".to_string()]).unwrap();
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
            let state = state_with(
                "example.com plugin://certs\nother.com resHeaders://x=1",
                Some(&plugin),
            );
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
            assert!(
                plugin.paths().is_empty(),
                "the plugin was contacted: {:?}",
                plugin.paths()
            );
            assert!(!state.rules.read().unwrap().has_sni_callback());
        });
    }

    /// The flag is a cache, so it has to be rebuilt every time the rules are.
    /// A stale `false` would silently disable the hook; a stale `true` would put
    /// a rule resolution back inside every handshake.
    #[test]
    fn editing_the_rules_updates_the_flag() {
        let mut mgr = crate::rules::RuleManager::new();
        assert!(!mgr.has_sni_callback());
        mgr.set_text("a.com sniCallback://certs");
        assert!(mgr.has_sni_callback());
        mgr.set_text("a.com resHeaders://x=1");
        assert!(!mgr.has_sni_callback(), "the rule was edited away");
        mgr.append_text("b.com sniCallback://certs");
        assert!(mgr.has_sni_callback(), "appended into the default group");

        // A second group, and the enabled flag it is read through.
        let mut mgr = crate::rules::RuleManager::new();
        mgr.add_group("extra", "c.com sniCallback://certs", true);
        assert!(mgr.has_sni_callback());
        mgr.toggle_group("extra");
        assert!(
            !mgr.has_sni_callback(),
            "a disabled group does not choose certificates"
        );
        mgr.toggle_group("extra");
        assert!(mgr.has_sni_callback());
        mgr.update_group("extra", "c.com resHeaders://x=1");
        assert!(!mgr.has_sni_callback(), "the group's text was replaced");
    }

    /// A rule that exists but matches a different name is the same answer, and
    /// still no plugin call.
    #[test]
    fn a_rule_for_another_host_is_not_this_connection() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with("other.example.com sniCallback://certs", Some(&plugin));
            assert!(state.rules.read().unwrap().has_sni_callback());
            assert!(matches!(
                decide_for(&state, "www.example.com").await,
                Decision::Generated
            ));
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
            // And the plugin was told what it needs to decide.
            let payload: serde_json::Value = serde_json::from_str(&plugin.last_payload()).unwrap();
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Bypass(_)
            ));
        });
    }

    /// Declining to *read* a connection is not declining to *route* it. Upstream's
    /// declined path is its ordinary tunnel path, which resolves `host://`
    /// (`rollBackTunnel` → `handleTunnel` → `rules.getProxy`,
    /// `_original/lib/tunnel.js:259-271,:436`), and so does this one.
    #[test]
    fn a_declined_connection_still_honours_host() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with(
                "example.com sniCallback://certs\n\
                 example.com host://127.0.0.1:8443\n",
                Some(&plugin),
            );
            let Decision::Bypass(target) = decide_for(&state, "example.com").await else {
                panic!("the plugin declined");
            };
            assert_eq!(target.connect_host, "127.0.0.1");
            assert_eq!(target.connect_port, 8443);
            // The name is still the one the client asked for — `host://` moves
            // the address, not the identity, and the client is about to do its
            // own handshake against that identity.
            assert_eq!(target.sni, "example.com");
            assert_eq!(target.request_port, 443);
        });
    }

    /// And the proxy family: a declined connection routed through an upstream
    /// proxy reaches the proxy, not the origin.
    #[test]
    fn a_declined_connection_still_honours_a_proxy_rule() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with(
                "example.com sniCallback://certs\n\
                 example.com proxy://127.0.0.1:9999\n",
                Some(&plugin),
            );
            let Decision::Bypass(target) = decide_for(&state, "example.com").await else {
                panic!("the plugin declined");
            };
            let proxy = target.proxy.expect("the proxy rule must survive");
            assert_eq!(proxy.host, "127.0.0.1");
            assert_eq!(proxy.port, 9999);
        });
    }

    /// A proxy rule that cannot be honoured closes the connection. Sending the
    /// bytes direct instead would put them on exactly the wire the rule said to
    /// divert them from — the same reason the request path answers 502 here.
    #[test]
    fn a_declined_connection_with_an_unhonourable_proxy_is_refused() {
        rt().block_on(async {
            let plugin = FakeSni::start(200, r#"{"intercept":false}"#).await;
            let state = state_with(
                "example.com sniCallback://certs\n\
                 example.com proxy://\n",
                Some(&plugin),
            );
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Unroutable(_)
            ));
        });
    }

    /// The relay reaches the address the rules chose, and the ClientHello is the
    /// first thing that arrives there — the origin has to see the connection the
    /// client actually opened.
    #[test]
    fn the_relay_reaches_the_address_the_rules_chose() {
        rt().block_on(async {
            // Stands in for the origin at the address `host://` names.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("accept");
                let mut buf = vec![0u8; 5];
                tokio::io::AsyncReadExt::read_exact(&mut sock, &mut buf)
                    .await
                    .expect("read");
                buf
            });

            // A client socket whose "already read" prefix is the ClientHello.
            let hello = client_hello_for("example.com");
            let (client, mut peer_end) = tokio::io::duplex(4096);
            let prefixed = Prefixed::new(hello.clone(), client);

            let target = upstream::Target {
                // A tunnel this port agreed not to intercept performs its own
                // handshake; no suite of ours is offered on it.
                tls_ciphers: None,
                cipher_dropped: None,
                no_proxy_ua: false,
                proxy_connection_close: false,
                connect_host: addr.ip().to_string(),
                connect_port: addr.port(),
                // Set on purpose, to pin that the relay ignores it: the client is
                // doing the handshake, so a second one from this end would serve
                // it our certificate for a connection we declined to intercept.
                tls: true,
                origin_tls_stripped: false,
                sni: "example.com".to_string(),
                request_port: 443,
                proxy: None,
                tls_versions: upstream::TlsVersions::Default,
                host_fallback_direct: false,
                auto2http: false,
                h2: None,
            };
            let relaying = tokio::spawn(async move {
                let origin = upstream::tunnel_stream(&target, &Default::default()).await?;
                relay(prefixed, origin).await
            });

            assert_eq!(
                seen.await.expect("origin task"),
                hello[..5].to_vec(),
                "the origin must see the client's own ClientHello first"
            );
            // Close the client end so the copy finishes rather than hanging.
            tokio::io::AsyncWriteExt::shutdown(&mut peer_end).await.ok();
            drop(peer_end);
            relaying.await.expect("relay task").ok();
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));

            // Now seed the cache the way a real reply would, and ask again.
            let (cert_pem, key_pem) = plugin_pem("cached");
            state
                .ca
                .set_plugin_cert("example.com", "certs", &cert_pem, &key_pem, 11)
                .unwrap();
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Plugin(_)
            ));

            // And the plugin is now told what is cached, so it can skip re-issuing.
            let payload: serde_json::Value = serde_json::from_str(&plugin.last_payload()).unwrap();
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
            let payload: serde_json::Value = serde_json::from_str(&plugin.last_payload()).unwrap();
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));

            let (cert_pem, key_pem) = plugin_pem("survives a restart");
            state
                .ca
                .set_plugin_cert("example.com", "certs", &cert_pem, &key_pem, 5)
                .unwrap();
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Plugin(_)
            ));
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
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
            assert!(state.ca.plugin_cert("example.com", "certs").is_none());
        });
    }

    /// A rule naming a plugin that is not registered, or one with no `sni` hook,
    /// is not a reason to break a handshake.
    #[test]
    fn a_rule_naming_no_usable_plugin_is_harmless() {
        rt().block_on(async {
            let state = state_with("example.com sniCallback://nobody", None);
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
            // `echo` is registered but declares no `sni` hook.
            let state = state_with("example.com sniCallback://echo", None);
            assert!(matches!(
                decide_for(&state, "example.com").await,
                Decision::Generated
            ));
        });
    }

    /// The built-in: `sniCallback://no-mitm` declines, in process, with no
    /// certificate of its own.
    #[test]
    fn the_builtin_declines_interception() {
        rt().block_on(async {
            let state = state_with("pinned.example.com sniCallback://no-mitm", None);
            assert!(matches!(
                decide_for(&state, "pinned.example.com").await,
                Decision::Bypass(_)
            ));
            assert!(matches!(
                decide_for(&state, "other.example.com").await,
                Decision::Generated
            ));
        });
    }

    /// The rule matches on the name in the ClientHello, so the same connection
    /// gets different answers depending on what the client asked for.
    #[test]
    fn the_rule_matches_the_name_the_client_asked_for() {
        rt().block_on(async {
            let state = state_with("pinned.example.com sniCallback://no-mitm", None);
            // Tunnel opened to an address, SNI naming the pinned host.
            let d = decide(
                &state,
                "pinned.example.com",
                "93.184.216.34",
                443,
                peer(),
                true,
                Carried::Tls,
            )
            .await;
            assert!(matches!(d, Decision::Bypass(_)));
            // Same tunnel address, a different name asked for.
            let d = decide(
                &state,
                "www.example.com",
                "93.184.216.34",
                443,
                peer(),
                true,
                Carried::Tls,
            )
            .await;
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
