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

use std::net::{Ipv6Addr, SocketAddr};
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
            if let Err(e) = handle(state, stream, peer).await {
                tracing::debug!("socks connection error: {e}");
            }
        });
    }
}

async fn handle(state: Arc<AppState>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let (host, port) = handshake(&mut stream).await?;
    // The same gate the CONNECT path has, at the same moment: before the client
    // is told the connection is open. Upstream reaches it by construction —
    // its SOCKS front end opens the connection by issuing a CONNECT against
    // whistle's own port, so a refused tunnel comes back as a failed CONNECT
    // and the client is denied rather than accepted
    // (`_original/lib/index.js:166-193`). This port funnels SOCKS into the
    // interception pipeline directly, so the gate has to be named here.
    if super::tunnel_aborted(&state, &host, port, peer) {
        // RFC 1928's REP for a connection a policy refused, which is exactly
        // what this is. Upstream's `deny()` writes whatever its SOCKS library
        // chose; that byte is not in the sources read for this port, so the
        // reply is picked on its own merits rather than guessed at.
        reply(&mut stream, REP_NOT_ALLOWED).await.ok();
        return Ok(());
    }
    reply(&mut stream, REP_SUCCESS).await?;
    // Peek the first byte to tell TLS (0x16 handshake record) from plain HTTP.
    let mut b = [0u8; 1];
    let tls = matches!(stream.peek(&mut b).await, Ok(n) if n > 0 && b[0] == 0x16);
    super::serve_tunnel(state, stream, host, port, peer, tls).await
}

/// SOCKS5 method: no authentication required.
const AUTH_NONE: u8 = 0x00;
/// SOCKS5 method: none of the client's offers is acceptable.
const AUTH_UNACCEPTABLE: u8 = 0xFF;

/// SOCKS5 reply: the connection is open.
const REP_SUCCESS: u8 = 0x00;
/// SOCKS5 reply: connection not allowed by ruleset.
const REP_NOT_ALLOWED: u8 = 0x02;
/// SOCKS5 reply: the command is not one this server offers.
const REP_CMD_UNSUPPORTED: u8 = 0x07;

/// Answer the client's CONNECT request with `rep`.
///
/// The bound address a SOCKS5 reply carries is the one the server allocated for
/// the connection, and this server allocates none — the tunnel is served
/// in-process — so it goes out as `0.0.0.0:0`.
async fn reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Minimal SOCKS5 server handshake: no-auth greeting + a CONNECT request.
///
/// whistle registers exactly one method on its SOCKS server,
/// `socks.auth.None()` (`_original/lib/index.js:205`) — the port is a debugging
/// entry point and carries no credentials of its own.
///
/// Stops at the parsed destination without answering it: whether the connection
/// is accepted at all is a question for the rules, and [`handle`] asks it before
/// writing a reply.
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
        reply(stream, REP_CMD_UNSUPPORTED).await.ok();
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
    ///
    /// A destination that parsed is answered the way [`handle`] answers one no
    /// rule refuses, so the bytes the client reads here are the bytes the server
    /// sends.
    fn exchange(greeting: impl Into<Vec<u8>>, expect: usize) -> (Vec<u8>, Option<(String, u16)>) {
        let greeting = greeting.into();
        rt().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::spawn(async move {
                let mut s = TcpStream::connect(addr).await.unwrap();
                s.write_all(&greeting).await.unwrap();
                let mut buf = vec![0u8; expect];
                s.read_exact(&mut buf).await.expect("server reply");
                buf
            });
            let (mut server, _) = listener.accept().await.unwrap();
            let dst = handshake(&mut server).await.ok();
            if dst.is_some() {
                reply(&mut server, REP_SUCCESS).await.unwrap();
            }
            let bytes = client.await.unwrap();
            drop(server);
            (bytes, dst)
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

    /// Drive [`handle`] for a client asking to reach `host:443` and return the
    /// twelve bytes it reads back: the two-byte method selection and then the
    /// ten-byte reply to its CONNECT.
    fn connect_to(state: Arc<AppState>, host: &str) -> Vec<u8> {
        let host = host.to_string();
        rt().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::spawn(async move {
                let mut s = TcpStream::connect(addr).await.unwrap();
                let mut greeting = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.len() as u8];
                greeting.extend_from_slice(host.as_bytes());
                greeting.extend_from_slice(&443u16.to_be_bytes());
                s.write_all(&greeting).await.unwrap();
                let mut buf = vec![0u8; 12];
                s.read_exact(&mut buf).await.expect("server reply");
                buf
            });
            let (server, peer) = listener.accept().await.unwrap();
            // An accepted connection goes on to serve a tunnel, and waits there
            // for a ClientHello this client never sends — so it is driven to the
            // reply and no further.
            let served = tokio::spawn(handle(state, server, peer));
            let bytes = client.await.unwrap();
            served.abort();
            bytes
        })
    }

    /// A SOCKS client whose connection the rules refuse is *denied*, not
    /// accepted and then reset — it must never be told the tunnel is open.
    /// Upstream gets this for free: its SOCKS front end opens the tunnel by
    /// issuing a CONNECT against whistle's own port and denies the client when
    /// that does not come back `200` (`_original/lib/index.js:174-193`).
    #[test]
    fn an_aborted_socks_connection_is_denied_rather_than_accepted() {
        let state = crate::proxy::tunnel_abort_tests::state_with("blocked.test enable://abort");
        let got = connect_to(state.clone(), "blocked.test");
        assert_eq!(&got[..2], &[0x05, AUTH_NONE], "the greeting still succeeds");
        assert_eq!(got[2], 0x05);
        assert_eq!(got[3], REP_NOT_ALLOWED, "connection not allowed by ruleset");
        // The refusal is a session, so it shows in the console rather than
        // looking like a client that hung up.
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.front().expect("the refusal is recorded");
        assert_eq!(session.method, "CONNECT");
        assert_eq!(session.url, "https://blocked.test/");
    }

    /// The same rules leave a destination they do not name alone: the gate
    /// refuses connections, it does not stand in front of the SOCKS port.
    #[test]
    fn a_socks_connection_no_rule_refuses_is_accepted() {
        let state = crate::proxy::tunnel_abort_tests::state_with("blocked.test enable://abort");
        let got = connect_to(state.clone(), "allowed.test");
        assert_eq!(got[3], REP_SUCCESS);
        assert!(state.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn only_connect_is_offered() {
        // UDP ASSOCIATE (0x03) — upstream's SOCKS server has no UDP path either.
        let (reply, dst) = exchange(
            vec![0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0, 80],
            12,
        );
        assert_eq!(&reply[..2], &[0x05, 0x00], "the greeting still succeeds");
        assert_eq!(reply[2], 0x05);
        assert_eq!(reply[3], 0x07, "command not supported");
        assert!(dst.is_none());
    }
}
