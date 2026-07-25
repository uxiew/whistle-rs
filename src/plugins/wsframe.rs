//! WebSocket frame hooks — a plugin that sees every data frame of a tunnelled
//! WebSocket session, in both directions, and may rewrite or drop it.
//!
//! This is the third member of the plugin family. The buffered hooks
//! ([`super`]) act on a whole request or response; the streaming hooks
//! ([`super::pipe`]) act on a body's bytes as they flow; this one acts on a
//! WebSocket's *messages*, which are neither.
//!
//! ## Why a long-lived stream rather than one HTTP request per frame
//!
//! A frame hook has to answer before the frame can be forwarded — the plugin is
//! allowed to rewrite or drop it — so **one local round-trip per frame is the
//! floor for any correct design**. What a transport can still choose is what it
//! spends *around* that round-trip.
//!
//! `POST /ws/frame` per frame would spend a TCP connect, a request head and a
//! response head on every single frame (or a connection pool, and then the
//! ordering problem of a pool). A WebSocket is a stream of many small messages;
//! paying an HTTP transaction per message is the wrong shape.
//!
//! So a session opens **one connection per direction** and keeps it for the
//! life of the tunnel, exactly as [`super::pipe`] does for a body. Per frame the
//! wire then costs six bytes of record header and nothing else, ordering is the
//! stream's own, and the plugin can hold per-session state because the two ends
//! of the connection *are* the session.
//!
//! ## Why records, when `pipe` deliberately refused to invent framing
//!
//! [`super::pipe`] argues at length against inventing a framing layer when
//! HTTP/1.1 chunked encoding already is one. That argument does not carry over,
//! and the difference is worth naming: a piped body is *one* stream of bytes
//! with *one* set of metadata, so chunked framing is all it needs. A frame hook
//! transports *many* messages, each with its own boundary, opcode and FIN bit —
//! and chunk boundaries are not message boundaries (nothing in HTTP, hyper or
//! Node promises that one write arrives as one `'data'` event).
//!
//! So there is a record layer, and it is six bytes:
//!
//! ```text
//! flags:u8  opcode:u8  length:u32be  payload:length
//! flags: 0x01 FIN, 0x02 DROP (plugin → proxy only)
//! ```
//!
//! Length-prefixed and binary, so a payload crosses byte-for-byte. A JSON or
//! base64 envelope would have inflated every binary frame by a third and forced
//! the very text round-trip the WebSocket hook must not do.
//!
//! ## The exchange
//!
//! ```text
//! proxy → plugin   POST /ws/frames HTTP/1.1
//!                  x-whistle-rs-ws: <base64 JSON metadata, direction included>
//!                  transfer-encoding: chunked
//! plugin → proxy   HTTP/1.1 200 OK          (head only — sent immediately)
//! proxy → plugin   <record>                 (one data frame)
//! plugin → proxy   <record>                 (the verdict for that frame)
//! ```
//!
//! Strictly one record in, one record out, in order. The plugin may change the
//! payload or set DROP; it may not change the opcode or the FIN bit, and the
//! proxy ignores those fields on the way back. That is deliberate — see
//! `run_hooks` in [`crate::proxy::ws`]: letting a plugin retype a frame or
//! restructure a fragmented message is a corruption waiting to happen, and
//! nothing a hook legitimately wants needs it.
//!
//! ## Failure is always recoverable
//!
//! Unlike a piped body, a frame hook can be abandoned *at any moment*: the proxy
//! still owns the frame stream, so a plugin that is down, that stops answering,
//! or that dies mid-session simply stops being consulted and frames flow on
//! untouched. A misbehaving plugin never closes a WebSocket.
//!
//! ## Latency, honestly
//!
//! A hooked frame is delayed by one loopback round-trip plus the plugin's own
//! work. Measured against the Node SDK on the same host (debug build, 500
//! sequential echo round-trips, so two hooked frames each): 0.084 ms per
//! round-trip unhooked, 0.129 ms hooked — about **20 µs per hooked frame** at
//! the median, 37 µs at the mean, 75 µs at p95.
//!
//! Frames are not pipelined: frame *n+1* is not offered until frame *n*'s
//! verdict is in, because a hook that reorders a WebSocket is worse than a hook
//! that is slow. Sessions with no frame-hook plugin never open a connection and
//! never pay a byte of this — the same benchmark with the plugin *running but
//! not named by any matching rule* measures 0.084 ms, the unhooked figure.

use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::json;
use tokio::sync::mpsc::Sender;

use super::RustPlugin;
use crate::proxy::body::{self, BodyError, DynBody};

/// Header carrying the base64-encoded JSON metadata of a hooked session.
pub const WS_META_HEADER: &str = "x-whistle-rs-ws";

/// The plugin endpoint serving the frame hook.
const FRAMES_PATH: &str = "/ws/frames";

/// How long to wait for the plugin to accept the session. Only bounds a local
/// handshake, and failing it costs the WebSocket nothing.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for one frame's verdict before abandoning the hook.
///
/// A hook that stops answering would otherwise stall its direction of the
/// WebSocket forever. On a timeout the hook is dropped rather than retried: a
/// late reply would be read as the *next* frame's verdict, and a desynchronised
/// hook is worse than no hook.
const VERDICT_TIMEOUT: Duration = Duration::from_secs(5);

/// Records in flight towards the plugin. One is enough — the exchange is
/// strictly synchronous — but a little slack keeps the send from parking.
const CHANNEL_RECORDS: usize = 2;

/// Bytes of record header: flags, opcode, and a 32-bit payload length.
const RECORD_HEADER: usize = 6;

/// Payloads at or above this size ride as their own chunk instead of being
/// copied into the header buffer. A WebSocket frame can be megabytes.
const CHUNK_SEPARATELY: usize = 64 * 1024;

const FLAG_FIN: u8 = 0x01;
const FLAG_DROP: u8 = 0x02;

/// Which way a frame is travelling.
///
/// The vocabulary is the WebSocket one used by the capture and by
/// `frameScript` — `send` is client→server — rather than the request/response
/// pair the HTTP hooks use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Dir {
    /// Client → server.
    #[default]
    Send,
    /// Server → client.
    Receive,
}

impl Dir {
    /// The label a plugin sees as `ctx.direction`.
    pub fn label(self) -> &'static str {
        match self {
            Dir::Send => "send",
            Dir::Receive => "receive",
        }
    }
}

/// Metadata handed to a frame hook when the session opens — everything about
/// the WebSocket except the frames themselves.
#[derive(Debug, Default, Clone)]
pub struct FrameMeta {
    /// The captured session's id: the same id `/frames.json` files these frames
    /// under, so a plugin's log lines line up with the Network view.
    pub id: u64,
    pub method: String,
    /// The full `ws://…` / `wss://…` URL of the handshake.
    pub url: String,
    /// The `/…` suffix after the plugin name.
    pub param: String,
    /// The `(…)` value of `pipe://name(value)`.
    pub pipe_value: Option<String>,
    pub client_ip: Option<String>,
    /// The handshake request's headers (names lowercased).
    pub headers: Vec<(String, String)>,
    /// Which direction this hook is watching.
    pub dir: Dir,
}

impl FrameMeta {
    /// Serialise for [`WS_META_HEADER`]. Absent fields are omitted.
    fn to_json(&self) -> serde_json::Value {
        let mut v = json!({
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "param": self.param,
            "direction": self.dir.label(),
            "headers": self.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        });
        if let Some(value) = &self.pipe_value {
            v["pipeValue"] = json!(value);
        }
        if let Some(ip) = &self.client_ip {
            v["clientIp"] = json!(ip);
        }
        v
    }
}

/// One frame offered to a hook.
pub struct HookFrame<'a> {
    /// Final frame of its message (the WebSocket FIN bit).
    pub fin: bool,
    /// WebSocket opcode: `0x0` continuation, `0x1` text, `0x2` binary.
    pub opcode: u8,
    /// The unmasked payload — raw bytes. Never decoded to text on the way
    /// through: a binary frame that survives a UTF-8 round-trip is a coincidence.
    pub payload: &'a [u8],
}

/// What a hook decided about one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the frame exactly as it arrived.
    Keep,
    /// Forward the frame with this payload instead.
    Replace(Bytes),
    /// Do not forward the frame.
    Drop,
}

/// A live frame hook: one plugin, watching one direction of one session.
pub enum FrameHook {
    /// A native plugin, called in-process. No I/O, no failure mode.
    Native {
        name: String,
        plugin: Arc<dyn RustPlugin>,
        meta: FrameMeta,
    },
    /// A remote plugin, over its own long-lived connection.
    Remote(RemoteHook),
}

impl FrameHook {
    /// The plugin's name, for logs.
    pub fn name(&self) -> &str {
        match self {
            FrameHook::Native { name, .. } => name,
            FrameHook::Remote(r) => &r.name,
        }
    }

    /// Offer one frame and wait for the verdict.
    ///
    /// An `Err` means the hook is finished, not that the frame is: the caller
    /// forwards the frame untouched and stops consulting this hook.
    pub async fn exchange(&mut self, frame: &HookFrame<'_>) -> anyhow::Result<Verdict> {
        match self {
            FrameHook::Native { plugin, meta, .. } => Ok(plugin.on_ws_frame(meta, frame)),
            FrameHook::Remote(r) => r.exchange(frame).await,
        }
    }
}

/// The proxy's end of a remote plugin's frame connection.
pub struct RemoteHook {
    name: String,
    /// Records towards the plugin.
    tx: Sender<Result<Bytes, BodyError>>,
    /// Verdicts coming back.
    reader: RecordReader,
}

impl RemoteHook {
    async fn exchange(&mut self, frame: &HookFrame<'_>) -> anyhow::Result<Verdict> {
        if frame.payload.len() > u32::MAX as usize {
            anyhow::bail!("frame of {} bytes exceeds the record format", frame.payload.len());
        }
        self.send(frame).await?;
        let record = tokio::time::timeout(VERDICT_TIMEOUT, self.reader.next())
            .await
            .map_err(|_| anyhow::anyhow!("no verdict within {VERDICT_TIMEOUT:?}"))??;
        Ok(if record.dropped {
            Verdict::Drop
        } else {
            // The payload already exists as owned bytes off the wire, so there
            // is nothing to gain from comparing it against the original.
            Verdict::Replace(record.payload)
        })
    }

    /// Write one record, as either one chunk or two.
    async fn send(&self, frame: &HookFrame<'_>) -> anyhow::Result<()> {
        let big = frame.payload.len() >= CHUNK_SEPARATELY;
        let mut head = BytesMut::with_capacity(if big {
            RECORD_HEADER
        } else {
            RECORD_HEADER + frame.payload.len()
        });
        head.put_u8(if frame.fin { FLAG_FIN } else { 0 });
        head.put_u8(frame.opcode);
        head.put_u32(frame.payload.len() as u32);
        if !big {
            head.extend_from_slice(frame.payload);
        }
        let stopped = || anyhow::anyhow!("plugin stopped reading frames");
        self.tx.send(Ok(head.freeze())).await.map_err(|_| stopped())?;
        if big {
            let payload = Bytes::copy_from_slice(frame.payload);
            self.tx.send(Ok(payload)).await.map_err(|_| stopped())?;
        }
        Ok(())
    }
}

/// One decoded record.
struct Record {
    dropped: bool,
    payload: Bytes,
}

/// Reassembles records from the plugin's response stream, which knows nothing
/// of record boundaries.
struct RecordReader {
    body: DynBody,
    buf: BytesMut,
}

impl RecordReader {
    /// The next record, reading more of the stream as needed.
    async fn next(&mut self) -> anyhow::Result<Record> {
        loop {
            if let Some(record) = take_record(&mut self.buf) {
                return Ok(record);
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buf.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => anyhow::bail!("frame stream failed: {e}"),
                None => anyhow::bail!("plugin closed the frame stream"),
            }
        }
    }
}

/// Split one complete record off the front of `buf`, or `None` if it has not
/// all arrived yet.
fn take_record(buf: &mut BytesMut) -> Option<Record> {
    if buf.len() < RECORD_HEADER {
        return None;
    }
    let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
    if buf.len() < RECORD_HEADER + len {
        return None;
    }
    let head = buf.split_to(RECORD_HEADER);
    Some(Record {
        dropped: head[0] & FLAG_DROP != 0,
        payload: buf.split_to(len).freeze(),
    })
}

/// Open a frame hook on a remote plugin for one direction.
///
/// Costs a connection attempt and nothing else when it fails — no frame has
/// been read, let alone held up, by the time this resolves.
pub(super) async fn connect(
    name: &str,
    base_url: &str,
    meta: &FrameMeta,
) -> anyhow::Result<RemoteHook> {
    let (mut sender, authority) = super::pipe::dial(base_url).await?;
    let (tx, records) = body::channel(CHANNEL_RECORDS);
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        meta.to_json().to_string(),
    );
    let req = Request::builder()
        .method("POST")
        .uri(FRAMES_PATH)
        .header(hyper::header::HOST, authority)
        .header(WS_META_HEADER, encoded)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(records)?;

    let resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| anyhow::anyhow!("no response within {HANDSHAKE_TIMEOUT:?}"))??;
    if resp.status() != hyper::StatusCode::OK {
        anyhow::bail!("plugin answered {}", resp.status());
    }
    Ok(RemoteHook {
        name: name.to_string(),
        tx,
        reader: RecordReader {
            body: body::from_incoming(resp.into_body()),
            buf: BytesMut::new(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn meta() -> FrameMeta {
        FrameMeta {
            id: 9,
            method: "GET".into(),
            url: "ws://example.com/chat".into(),
            pipe_value: Some("tag".into()),
            dir: Dir::Receive,
            ..Default::default()
        }
    }

    fn frame<'a>(opcode: u8, payload: &'a [u8]) -> HookFrame<'a> {
        HookFrame {
            fin: true,
            opcode,
            payload,
        }
    }

    /// A fake plugin speaking raw HTTP/1.1 so the test owns every byte on the
    /// wire. `respond` is handed the accepted socket.
    async fn fake_plugin<F, Fut>(respond: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            respond(sock).await
        });
        (format!("http://{addr}"), handle)
    }

    /// Read the request head, returning it.
    async fn read_head(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while sock.read_exact(&mut byte).await.is_ok() {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        buf
    }

    /// Wrap `payload` in one chunked HTTP body chunk.
    fn chunk(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Build a verdict record the way a plugin would.
    fn record(flags: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![flags, opcode];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// The record codec: header split from payload, several records in one
    /// buffer, and a partial record left alone until the rest arrives.
    #[test]
    fn records_reassemble_from_arbitrary_pieces() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&record(FLAG_FIN, 0x1, b"hello")[..4]);
        assert!(take_record(&mut buf).is_none(), "a partial header must wait");

        buf.clear();
        buf.extend_from_slice(&record(FLAG_FIN, 0x1, b"hello"));
        buf.extend_from_slice(&record(FLAG_DROP, 0x2, b""));
        let first = take_record(&mut buf).expect("first record");
        assert_eq!(first.payload, Bytes::from_static(b"hello"));
        assert!(!first.dropped);
        let second = take_record(&mut buf).expect("second record");
        assert!(second.dropped);
        assert!(take_record(&mut buf).is_none());
        assert!(buf.is_empty());
    }

    /// A payload that is not valid UTF-8 crosses the codec byte for byte —
    /// the property the whole binary-safe record format exists for.
    #[test]
    fn binary_payloads_are_not_text() {
        let payload: Vec<u8> = (0u8..=255).chain(0u8..=255).collect();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&record(FLAG_FIN, 0x2, &payload));
        let got = take_record(&mut buf).expect("record");
        assert_eq!(got.payload.len(), payload.len());
        assert_eq!(got.payload, Bytes::from(payload));
    }

    /// The round-trip: the proxy sends a frame, the plugin answers, and the
    /// verdict comes back as a rewrite and then as a drop.
    #[test]
    fn exchanges_frames_with_a_plugin() {
        rt().block_on(async {
            let (url, plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await
                    .expect("head");
                // Answer the first frame with a rewrite, the second with a drop.
                let mut seen = Vec::new();
                let mut buf = [0u8; 512];
                let mut answered = 0;
                while answered < 2 {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    // The request is chunked; the record payloads we expect are
                    // short enough to look for directly.
                    if answered == 0 && seen.windows(2).any(|w| w == b"hi") {
                        sock.write_all(&chunk(&record(FLAG_FIN, 0x1, b"HI!")))
                            .await
                            .expect("verdict");
                        answered = 1;
                    } else if answered == 1 && seen.windows(4).any(|w| w == b"gone") {
                        sock.write_all(&chunk(&record(FLAG_DROP, 0x1, b"")))
                            .await
                            .expect("verdict");
                        answered = 2;
                    }
                }
            })
            .await;

            let mut hook = connect("t", &url, &meta()).await.expect("connect");
            assert_eq!(
                hook.exchange(&frame(0x1, b"hi")).await.expect("verdict"),
                Verdict::Replace(Bytes::from_static(b"HI!"))
            );
            assert_eq!(
                hook.exchange(&frame(0x1, b"gone")).await.expect("verdict"),
                Verdict::Drop
            );
            plugin.await.expect("plugin task");
        });
    }

    /// A plugin that is not listening must not become a hook at all — the
    /// session then runs exactly as if the rule had never named it.
    #[test]
    fn unreachable_plugin_never_hooks() {
        rt().block_on(async {
            let addr = {
                let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                l.local_addr().expect("addr")
            };
            assert!(connect("gone", &format!("http://{addr}"), &meta()).await.is_err());
        });
    }

    /// A plugin that declines the session (any non-200) is equally inert.
    #[test]
    fn declining_plugin_never_hooks() {
        rt().block_on(async {
            let (url, plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .expect("head");
            })
            .await;
            assert!(connect("no", &url, &meta()).await.is_err());
            plugin.await.expect("plugin task");
        });
    }

    /// A plugin that hangs up mid-session ends the hook rather than the frame:
    /// the caller is told, and forwards the frame itself.
    #[test]
    fn hangup_mid_session_ends_the_hook() {
        rt().block_on(async {
            let (url, plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await
                    .expect("head");
                // Accept the session, then vanish without answering.
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
            })
            .await;

            let mut hook = connect("flaky", &url, &meta()).await.expect("connect");
            let err = hook.exchange(&frame(0x1, b"anyone there")).await;
            assert!(err.is_err(), "a vanished plugin must end the hook");
            plugin.await.expect("plugin task");
        });
    }

    /// The metadata a plugin receives, including the direction it is watching.
    #[test]
    fn metadata_serialisation() {
        let m = FrameMeta {
            id: 4,
            method: "GET".into(),
            url: "ws://a/b".into(),
            param: "x".into(),
            pipe_value: Some("v".into()),
            client_ip: Some("1.2.3.4".into()),
            headers: vec![("origin".into(), "http://a".into())],
            dir: Dir::Receive,
        };
        let v = m.to_json();
        assert_eq!(v["id"], 4);
        assert_eq!(v["direction"], "receive");
        assert_eq!(v["pipeValue"], "v");
        assert_eq!(v["headers"][0][0], "origin");

        let bare = FrameMeta::default().to_json();
        assert_eq!(bare["direction"], "send");
        assert!(bare.get("pipeValue").is_none());
        assert!(bare.get("clientIp").is_none());
    }
}
