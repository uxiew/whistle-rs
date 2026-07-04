//! Outbound forwarding to the real server.
//!
//! We open the connection ourselves (rather than using a pooled high-level
//! client) so that whistle's `host://` override can redirect the destination IP
//! while the `Host` header and TLS SNI still carry the original hostname — the
//! defining behaviour of a debugging proxy.

use std::sync::Arc;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

use super::body::DynBody;
use once_cell::sync::Lazy;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Where and how to reach the upstream.
#[derive(Debug, Clone)]
pub struct Target {
    /// Host/IP to actually connect to (may differ from `sni` via `host://`).
    pub connect_host: String,
    pub connect_port: u16,
    /// Whether to speak TLS to the upstream.
    pub tls: bool,
    /// SNI / certificate hostname (the original request host).
    pub sni: String,
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

/// Forward `req` to `target` and return the upstream response (body still
/// streaming). The request URI must already be origin-form with a `Host` header.
pub async fn forward(target: &Target, req: Request<DynBody>) -> Result<Response<Incoming>> {
    let tcp = TcpStream::connect((target.connect_host.as_str(), target.connect_port))
        .await
        .with_context(|| {
            format!(
                "connecting to {}:{}",
                target.connect_host, target.connect_port
            )
        })?;
    tcp.set_nodelay(true).ok();

    if target.tls {
        let connector = TlsConnector::from(CLIENT_CONFIG.clone());
        let server_name = ServerName::try_from(target.sni.clone())
            .with_context(|| format!("invalid SNI host {}", target.sni))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("upstream TLS handshake")?;
        send(TokioIo::new(tls), req).await
    } else {
        send(TokioIo::new(tcp), req).await
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
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!("upstream connection error: {err}");
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .context("sending upstream request")?;
    Ok(resp)
}
