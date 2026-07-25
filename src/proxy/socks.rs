//! Inbound SOCKS5 server (whistle's `socksPort`).
//!
//! Accepts SOCKS5 clients, performs the handshake, then funnels the tunnel into
//! the same interception pipeline as CONNECT — TLS-decrypting when the client
//! starts a TLS handshake, otherwise serving plain HTTP. Ported from the SOCKS
//! server wired up in `_original/lib/index.js:151-206`, which does exactly the
//! same thing by issuing a CONNECT against whistle's own HTTP port.
//!
//! Scope matches upstream's: SOCKS5 only (no SOCKS4), `CONNECT` only — neither
//! `BIND` nor `UDP ASSOCIATE` is offered, and no authentication is required.

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

/// SOCKS5 method: no authentication required.
const AUTH_NONE: u8 = 0x00;
/// SOCKS5 method: none of the client's offers is acceptable.
const AUTH_UNACCEPTABLE: u8 = 0xFF;

/// Minimal SOCKS5 server handshake: no-auth greeting + a CONNECT request.
///
/// whistle registers exactly one method on its SOCKS server,
/// `socks.auth.None()` (`_original/lib/index.js:205`) — the port is a debugging
/// entry point and carries no credentials of its own.
async fn handshake(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("not a SOCKS5 client");
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // Selecting a method the client never offered desynchronises the stream —
    // it would read our reply as the first byte of something else. Say so
    // instead, as RFC 1928 requires.
    if !methods.contains(&AUTH_NONE) {
        stream.write_all(&[0x05, AUTH_UNACCEPTABLE]).await.ok();
        bail!("SOCKS5: client offered no acceptable auth method");
    }
    stream.write_all(&[0x05, AUTH_NONE]).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Drive `handshake` against a client that sends `greeting` and then reads
    /// `expect` reply bytes. Returns the reply and the parsed destination.
    fn exchange(greeting: impl Into<Vec<u8>>, expect: usize) -> (Vec<u8>, Option<(String, u16)>) {
        let greeting = greeting.into();
        rt().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::spawn(async move {
                let mut s = TcpStream::connect(addr).await.unwrap();
                s.write_all(&greeting).await.unwrap();
                let mut reply = vec![0u8; expect];
                s.read_exact(&mut reply).await.expect("server reply");
                reply
            });
            let (mut server, _) = listener.accept().await.unwrap();
            let dst = handshake(&mut server).await.ok();
            let reply = client.await.unwrap();
            drop(server);
            (reply, dst)
        })
    }

    #[test]
    fn a_domain_connect_reaches_the_pipeline() {
        let mut greeting = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        greeting.extend_from_slice(b"example.com");
        greeting.extend_from_slice(&443u16.to_be_bytes());
        let (reply, dst) = exchange(greeting, 12);
        assert_eq!(&reply[..2], &[0x05, 0x00]);
        assert_eq!(dst, Some(("example.com".to_string(), 443)));
    }

    #[test]
    fn an_ipv6_connect_keeps_its_address() {
        let mut greeting = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
        greeting.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        greeting.extend_from_slice(&8080u16.to_be_bytes());
        let (_, dst) = exchange(greeting, 12);
        assert_eq!(dst, Some(("::1".to_string(), 8080)));
    }

    /// Answering with a method the client never offered would desynchronise the
    /// stream: the client reads our `0x00` as the start of its own next frame.
    #[test]
    fn an_unofferable_method_is_refused_not_assumed() {
        // Offers user/password (0x02) only.
        let (reply, dst) = exchange(vec![0x05, 0x01, 0x02], 2);
        assert_eq!(reply, vec![0x05, 0xFF]);
        assert!(dst.is_none());
    }

    #[test]
    fn only_connect_is_offered() {
        // UDP ASSOCIATE (0x03) — upstream's SOCKS server has no UDP path either.
        let (reply, dst) =
            exchange(vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0, 80], 12);
        assert_eq!(&reply[..2], &[0x05, 0x00], "the greeting still succeeds");
        assert_eq!(reply[2], 0x05);
        assert_eq!(reply[3], 0x07, "command not supported");
        assert!(dst.is_none());
    }
}
