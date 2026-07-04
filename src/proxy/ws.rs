//! Minimal WebSocket frame codec + a scripted tunnel for `frameScript`.
//!
//! When a `frameScript` rule matches a WebSocket upgrade, the raw byte tunnel is
//! replaced by a frame-aware pump: each text frame's payload is passed through
//! the script (which may rewrite it) before being re-encoded and forwarded.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A decoded WebSocket frame (control/data), payload already unmasked.
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Read a single frame; `Ok(None)` on clean EOF.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut h = [0u8; 2];
    match r.read_exact(&mut h).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let len7 = (h[1] & 0x7f) as usize;
    let len = if len7 == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await?;
        u16::from_be_bytes(b) as usize
    } else if len7 == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b).await?;
        u64::from_be_bytes(b) as usize
    } else {
        len7
    };
    let mut key = [0u8; 4];
    if masked {
        r.read_exact(&mut key).await?;
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}

/// Encode + write a frame. `mask` must be true for client→server frames.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    mask: bool,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(payload.len() + 14);
    buf.push((if fin { 0x80 } else { 0 }) | (opcode & 0x0f));
    let mlen = payload.len();
    let mbit = if mask { 0x80 } else { 0 };
    if mlen < 126 {
        buf.push(mbit | mlen as u8);
    } else if mlen <= 0xffff {
        buf.push(mbit | 126);
        buf.extend_from_slice(&(mlen as u16).to_be_bytes());
    } else {
        buf.push(mbit | 127);
        buf.extend_from_slice(&(mlen as u64).to_be_bytes());
    }
    if mask {
        // A fixed non-zero key is a valid mask; the peer unmasks with it.
        let key = [0x37u8, 0xfa, 0x21, 0x3d];
        buf.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            buf.push(b ^ key[i % 4]);
        }
    } else {
        buf.extend_from_slice(payload);
    }
    w.write_all(&buf).await?;
    w.flush().await
}

/// Frame-aware bidirectional tunnel that runs `script` on each text frame.
pub async fn scripted_tunnel<A, B>(client: A, upstream: B, script: String)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let up = tokio::spawn(pump(cr, uw, true, script.clone()));
    let down = tokio::spawn(pump(ur, cw, false, script));
    let _ = tokio::join!(up, down);
}

async fn pump<R, W>(mut r: R, mut w: W, to_server: bool, script: String)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let direction = if to_server { "send" } else { "receive" };
    loop {
        let frame = match read_frame(&mut r).await {
            Ok(Some(f)) => f,
            _ => break,
        };
        let mut payload = frame.payload;
        if frame.opcode == 0x1 {
            // Text frame: allow the script to rewrite it.
            if let Ok(text) = String::from_utf8(payload.clone()) {
                if let Some(new) =
                    crate::proxy::script::run_frame_script(&script, direction, &text)
                {
                    payload = new.into_bytes();
                }
            }
        }
        if write_frame(&mut w, frame.fin, frame.opcode, &payload, to_server)
            .await
            .is_err()
        {
            break;
        }
        if frame.opcode == 0x8 {
            break; // close
        }
    }
}
