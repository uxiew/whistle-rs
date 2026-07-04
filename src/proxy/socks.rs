//! Inbound SOCKS5 server (whistle's `socksPort`).
//!
//! Accepts SOCKS5 clients, performs the handshake, then funnels the tunnel into
//! the same interception pipeline as CONNECT — TLS-decrypting when the client
//! starts a TLS handshake, otherwise serving plain HTTP. Ported from the SOCKS
//! server wired up in `_original/lib/index.js`.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::AppState;

/// Bind the SOCKS5 port and serve until the process exits.
pub async fn run(state: Arc<AppState>, port: u16) -> Result<()> {
    let host = state
        .config
        .host
        .unwrap_or_else(|| "0.0.0.0".parse().unwrap());
    let listener = TcpListener::bind((host, port)).await?;
    tracing::info!("whistle-rs SOCKS5 listening on {host}:{port}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("socks accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(state, stream, peer.ip()).await {
                tracing::debug!("socks connection error: {e}");
            }
        });
    }
}

async fn handle(state: Arc<AppState>, mut stream: TcpStream, peer: IpAddr) -> Result<()> {
    let (host, port) = handshake(&mut stream).await?;
    // Peek the first byte to tell TLS (0x16 handshake record) from plain HTTP.
    let mut b = [0u8; 1];
    let tls = matches!(stream.peek(&mut b).await, Ok(n) if n > 0 && b[0] == 0x16);
    super::serve_tunnel(state, stream, host, port, peer, tls).await
}

/// Minimal SOCKS5 server handshake: no-auth greeting + a CONNECT request.
async fn handshake(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("not a SOCKS5 client");
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // Select "no authentication".
    stream.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("bad SOCKS5 request");
    }
    if req[1] != 0x01 {
        // Only CONNECT is supported.
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        bail!("SOCKS5: unsupported command {}", req[1]);
    }

    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        t => bail!("SOCKS5: bad address type {t}"),
    };
    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    // Reply success (bound address is not meaningful for us).
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok((host, port))
}
