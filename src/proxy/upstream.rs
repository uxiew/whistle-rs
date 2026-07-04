//! Outbound forwarding to the real server.
//!
//! We open the connection ourselves (rather than using a pooled high-level
//! client) so that whistle's `host://` override can redirect the destination IP
//! while the `Host` header and TLS SNI still carry the original hostname — the
//! defining behaviour of a debugging proxy.
//!
//! Supports reaching the origin directly or through an upstream HTTP/HTTPS proxy
//! (`proxy://`, `http-proxy://`, `https-proxy://`, `internal-proxy://`) or a
//! SOCKS5 proxy (`socks://`). Ported from `_original/lib/handlers/http-proxy.js`
//! and the tunnel logic in `lib/tunnel.js`.

use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, anyhow, bail};
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

/// A parsed upstream proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

/// Where and how to reach the upstream.
#[derive(Debug, Clone)]
pub struct Target {
    /// Host/IP to actually reach (may differ from `sni` via `host://`).
    pub connect_host: String,
    pub connect_port: u16,
    /// Whether the origin speaks TLS.
    pub tls: bool,
    /// SNI / certificate hostname + `Host` header (the original request host).
    pub sni: String,
    /// The original request port (for the `Host` header / absolute-form URIs).
    pub request_port: u16,
    /// Optional upstream proxy to route through.
    pub proxy: Option<ProxyConfig>,
}

/// Shared rustls client config trusting the webpki root store.
static CLIENT_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
});

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

/// Forward `req` to `target` and return the upstream response (body still
/// streaming). The request URI arrives origin-form with a `Host` header.
pub async fn forward(target: &Target, mut req: Request<DynBody>) -> Result<Response<Incoming>> {
    // A plain HTTP proxy fetching an http origin uses absolute-form + Proxy-Auth.
    let absolute_form = matches!(&target.proxy, Some(p) if p.kind != ProxyKind::Socks) && !target.tls;
    if absolute_form {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let authority = if target.connect_port == 80 {
            target.connect_host.clone()
        } else {
            format!("{}:{}", target.connect_host, target.connect_port)
        };
        let abs = format!("http://{authority}{path}");
        *req.uri_mut() = abs.parse::<Uri>().unwrap_or_else(|_| req.uri().clone());
        if let Some(ProxyConfig { auth: Some((u, p)), .. }) = &target.proxy {
            if let Ok(v) = hyper::header::HeaderValue::from_str(&basic_auth(u, p)) {
                req.headers_mut()
                    .insert(hyper::header::PROXY_AUTHORIZATION, v);
            }
        }
    }

    let stream = origin_stream(target).await?;
    send(TokioIo::new(stream), req).await
}

/// Establish a stream to the origin (through a proxy if configured), TLS-wrapping
/// it when the origin speaks TLS.
async fn origin_stream(target: &Target) -> Result<BoxedIo> {
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
                    if target.tls {
                        http_connect(
                            pstream,
                            &target.connect_host,
                            target.connect_port,
                            &proxy.auth,
                        )
                        .await?
                    } else {
                        // Plain http via proxy: request is absolute-form, no CONNECT.
                        return Ok(pstream);
                    }
                }
            }
        }
    };

    if target.tls {
        let connector = TlsConnector::from(CLIENT_CONFIG.clone());
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
async fn http_connect(
    mut s: BoxedIo,
    host: &str,
    port: u16,
    auth: &Option<(String, String)>,
) -> Result<BoxedIo> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((u, p)) = auth {
        req.push_str(&format!("Proxy-Authorization: {}\r\n", basic_auth(u, p)));
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

/// Perform a SOCKS5 handshake + CONNECT to `host:port`.
async fn socks5_connect(
    mut s: BoxedIo,
    host: &str,
    port: u16,
    auth: &Option<(String, String)>,
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
                .ok_or_else(|| anyhow!("proxy requires auth but none given"))?;
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

    // CONNECT request.
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
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

/// Build a `Basic <base64>` credential string.
fn basic_auth(user: &str, pass: &str) -> String {
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{user}:{pass}").as_bytes(),
    );
    format!("Basic {token}")
}

/// Parse a proxy operator value: `[user:pass@]host[:port]`.
pub fn parse_proxy(kind: ProxyKind, value: &str) -> Option<ProxyConfig> {
    let value = value.trim().trim_start_matches("//");
    if value.is_empty() {
        return None;
    }
    let (auth, hostport) = match value.rsplit_once('@') {
        Some((creds, hp)) => {
            let auth = creds
                .split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()));
            (auth, hp)
        }
        None => (None, value),
    };
    let default_port = match kind {
        ProxyKind::Socks => 1080,
        ProxyKind::Https => 443,
        ProxyKind::Http => 80,
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (hostport.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some(ProxyConfig { kind, host, port, auth })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_proxy_with_auth() {
        let p = parse_proxy(ProxyKind::Http, "user:pass@127.0.0.1:8888").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8888);
        assert_eq!(p.auth, Some(("user".into(), "pass".into())));
    }

    #[test]
    fn parse_socks_default_port() {
        let p = parse_proxy(ProxyKind::Socks, "10.0.0.1").unwrap();
        assert_eq!(p.port, 1080);
        assert!(p.auth.is_none());
    }
}
