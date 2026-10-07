//! Streaming ("pipe") plugin hooks — a plugin that sees body bytes *as they
//! arrive* and whose output streams straight on to the next stage.
//!
//! ## Why HTTP and not whistle's CONNECT + `transproto`
//!
//! Upstream whistle establishes a pipe by opening an HTTP `CONNECT` to the
//! plugin port, waiting for `200 Connection Established`, writing a single `'1'`
//! ack byte, and then exchanging bodies over a bespoke length-prefixed framing
//! (`'\n' <len> '\n' <payload>`, EOF `'\n0\n'` — `lib/util/transproto.js`).
//!
//! We deliberately do **not** port that. whistle-rs already speaks its own
//! plugin protocol (JSON over HTTP, capability-gated by `GET /manifest`), and
//! plugins are written against *our* SDK, so upstream wire compatibility buys
//! nothing here. Meanwhile HTTP/1.1 already frames a stream — chunked transfer
//! encoding is exactly the length-prefixed framing `transproto` reinvents — and
//! hyper implements it on both ends. Reusing it means no framing layer of our
//! own to get wrong, metadata that rides along as headers, and a plugin author
//! who receives Node's own `(req, res)` pair: a readable of body bytes and a
//! writable for the transformed ones. That is the same shape upstream hands its
//! `reqRead`/`resRead` hooks, reached without the machinery.
//!
//! The trade-off is stated plainly: **a whistle plugin written for `pipe://`
//! cannot be dropped in here**, and vice versa. See `docs/PLUGINS.md`.
//!
//! ## The exchange
//!
//! ```text
//! proxy → plugin   POST /pipe/{request,response} HTTP/1.1
//!                  x-whistle-rs-pipe: <base64 JSON metadata>
//!                  transfer-encoding: chunked
//! plugin → proxy   HTTP/1.1 200 OK           (head only — sent immediately)
//! proxy → plugin   <body bytes, as they arrive>
//! plugin → proxy   <transformed bytes, as they are produced>
//! ```
//!
//! ## Why the head comes first
//!
//! Not one byte of the original body is read until the plugin's response *head*
//! has arrived. That ordering is what makes failure free: a plugin that is down,
//! slow to accept, or answers anything but `200` costs us a connection attempt
//! and nothing else — the body is still untouched, so it is forwarded verbatim.
//! Once the head is in hand we commit, and from then on a plugin that dies
//! fails the body, exactly as a dying origin would. The SDK therefore writes its
//! `200` the instant a pipe handler is entered, before waiting for input.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

use crate::proxy::body::{self, BodyError, DynBody};

/// Header carrying the base64-encoded JSON metadata for the piped body.
///
/// Metadata travels as one opaque header rather than a field per item so that
/// URLs, header values and rule text never have to survive header escaping.
pub const META_HEADER: &str = "x-whistle-rs-pipe";

/// How long to wait for the plugin to accept the stream before giving up and
/// forwarding the body untouched. Generous: it only bounds a local handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Body frames in flight between the proxy and the plugin socket. Small on
/// purpose — this is a pipe, not a buffer.
const CHANNEL_FRAMES: usize = 4;

/// Which streaming hook to invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// The request body, on its way upstream.
    Request,
    /// The response body, on its way back to the client.
    Response,
}

impl Dir {
    /// The plugin endpoint serving this hook.
    pub fn path(self) -> &'static str {
        match self {
            Dir::Request => "/pipe/request",
            Dir::Response => "/pipe/response",
        }
    }

    /// Short label for logs.
    pub(super) fn label(self) -> &'static str {
        match self {
            Dir::Request => "pipeRequest",
            Dir::Response => "pipeResponse",
        }
    }
}

/// Metadata handed to a streaming hook alongside the body bytes.
///
/// It is the same information the buffered hooks get in their JSON payload —
/// minus the body, which is the stream itself.
#[derive(Debug, Default, Clone)]
pub struct PipeMeta {
    /// Correlation id, shared with this request's buffered hooks.
    pub id: u64,
    pub method: String,
    pub url: String,
    /// The `/…` suffix after the plugin name.
    pub param: String,
    /// The `(…)` value of `pipe://name(value)` — whistle's `pipeValue`.
    pub pipe_value: Option<String>,
    pub client_ip: Option<String>,
    /// Request headers for [`Dir::Request`], response headers for [`Dir::Response`].
    pub headers: Vec<(String, String)>,
    /// Upstream status code — [`Dir::Response`] only.
    pub status: Option<u16>,
}

impl PipeMeta {
    /// Serialise for the [`META_HEADER`]. Absent fields are simply omitted.
    fn to_json(&self) -> serde_json::Value {
        let mut v = json!({
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "param": self.param,
            "headers": self.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        });
        if let Some(value) = &self.pipe_value {
            v["pipeValue"] = json!(value);
        }
        if let Some(ip) = &self.client_ip {
            v["clientIp"] = json!(ip);
        }
        if let Some(status) = self.status {
            v["statusCode"] = json!(status);
        }
        v
    }
}

/// Route `body` through a remote plugin's streaming hook.
///
/// Returns the plugin's output stream on success and the **original body,
/// untouched**, on any failure — see the module docs for why that is always
/// possible.
pub async fn transform(
    name: &str,
    base_url: &str,
    dir: Dir,
    meta: &PipeMeta,
    body: DynBody,
) -> DynBody {
    // The plugin's input is a channel we have not written to yet, so opening the
    // connection and sending the head consumes nothing from `body`.
    let (tx, plugin_input) = body::channel(CHANNEL_FRAMES);
    let (mut sender, req) = match connect(base_url, dir, meta, plugin_input).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("{} {}: {e:#}; body forwarded unchanged", dir.label(), name);
            return body;
        }
    };

    // Await the head before feeding a single byte: until this resolves, `body`
    // has not been read from, so every failure below can still forward it.
    let resp = match tokio::time::timeout(HANDSHAKE_TIMEOUT, sender.send_request(req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            tracing::warn!("{} {name}: {e}; body forwarded unchanged", dir.label());
            return body;
        }
        Err(_) => {
            tracing::warn!(
                "{} {name}: no response within {:?}; body forwarded unchanged",
                dir.label(),
                HANDSHAKE_TIMEOUT
            );
            return body;
        }
    };
    if resp.status() != hyper::StatusCode::OK {
        tracing::warn!(
            "{} {name}: plugin answered {}; body forwarded unchanged",
            dir.label(),
            resp.status()
        );
        return body;
    }

    // Committed. From here the plugin owns the body: pump the original into it
    // and hand its output onward.
    let label = format!("{} {name}", dir.label());
    let (ended_tx, ended) = tokio::sync::oneshot::channel();
    tokio::spawn(pump(label, body, tx, ended));
    Output {
        inner: body::from_incoming(resp.into_body()),
        ended: Some(ended_tx),
    }
    .boxed()
}

/// The plugin's output, which tells [`pump`] to stop when it has ended.
///
/// Once the plugin has finished answering, no byte it reads afterwards can
/// change what it answered — but a plugin on Node keeps reading anyway (an
/// ended response drains the rest of its request, `req._dump()`), so the pump
/// would go on feeding it for as long as the source flowed. For an event stream
/// that is forever, and the origin connection with it: upstream's "pipe may
/// cause request hangs and memory leaks", fixed in 2.10.10 (avwo/whistle#1351),
/// in this port's shape. The same signal covers a consumer that stops reading —
/// a client that left — because dropping this drops the sender.
struct Output {
    inner: DynBody,
    /// Dropped, and so heard by [`pump`], at the end or when nobody wants more.
    ended: Option<tokio::sync::oneshot::Sender<()>>,
}

impl hyper::body::Body for Output {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None | Some(Err(_)))) {
            this.ended = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Open an HTTP/1.1 connection to a local plugin endpoint, returning the
/// request sender and the authority to address it by.
///
/// Shared with the frame transport ([`super::wsframe`]): both dial a plugin the
/// same way and differ only in what they then send over the connection.
pub(super) async fn dial(
    base_url: &str,
) -> anyhow::Result<(hyper::client::conn::http1::SendRequest<DynBody>, String)> {
    let (host, port) = host_port(base_url)?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    // Latency, not throughput, is what matters for a per-frame pipe.
    tcp.set_nodelay(true).ok();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("plugin connection closed: {e}");
        }
    });
    Ok((sender, format!("{host}:{port}")))
}

/// Open a connection to the plugin and build the streaming request around
/// `input` (the body the plugin will read).
async fn connect(
    base_url: &str,
    dir: Dir,
    meta: &PipeMeta,
    input: DynBody,
) -> anyhow::Result<(
    hyper::client::conn::http1::SendRequest<DynBody>,
    Request<DynBody>,
)> {
    let (sender, authority) = dial(base_url).await?;
    let uri: Uri = dir.path().parse()?;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        meta.to_json().to_string(),
    );
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(hyper::header::HOST, authority)
        .header(META_HEADER, encoded)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(input)?;
    Ok((sender, req))
}

/// Copy `body`'s frames into the plugin connection until either side ends, or
/// the plugin's output has ([`Output`]) — dropping `body` then, which is what
/// lets go of the origin or the client behind it.
///
/// Errors are forwarded rather than swallowed: once the plugin has taken over a
/// body, silently truncating it would hand the client a plausible-looking lie.
async fn pump(
    label: String,
    mut body: DynBody,
    tx: Sender<Result<Bytes, BodyError>>,
    mut ended: tokio::sync::oneshot::Receiver<()>,
) {
    let stopped = || {
        tracing::debug!(
            "{label}: the plugin's output has ended; the rest of the input is not needed"
        )
    };
    loop {
        let frame = tokio::select! {
            _ = &mut ended => return stopped(),
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else { return };
        let send = match frame {
            Ok(f) => match f.into_data() {
                Ok(data) => tokio::select! {
                    _ = &mut ended => return stopped(),
                    sent = tx.send(Ok(data)) => sent,
                },
                // Trailers cannot be represented mid-pipe; the plugin's own
                // output decides the final framing.
                Err(_) => continue,
            },
            Err(e) => {
                tracing::debug!("{label}: source body failed: {e}");
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        if send.is_err() {
            // The plugin hung up; nothing left to feed.
            tracing::debug!("{label}: plugin stopped reading");
            return;
        }
    }
}

/// Split a plugin base URL into `(host, port)`.
///
/// Plugins are local processes, so only plain HTTP is supported — a TLS plugin
/// endpoint is rejected here rather than silently mis-piped.
fn host_port(base_url: &str) -> anyhow::Result<(String, u16)> {
    let rest = match base_url.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme.eq_ignore_ascii_case("http") {
                anyhow::bail!("streaming hooks need an http:// plugin endpoint, got {scheme}://");
            }
            rest
        }
        None => base_url,
    };
    let host_port = rest.split(['/', '?']).next().unwrap_or("").trim();
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse::<u16>().unwrap_or(80))
        }
        _ => (host_port, 80),
    };
    if host.is_empty() {
        anyhow::bail!("plugin endpoint {base_url} has no host");
    }
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;

    /// The terminating chunk of an HTTP/1.1 chunked body.
    const CHUNKED_END: &[u8] = b"\r\n0\r\n\r\n";

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Drain a body into `(concatenated bytes, per-frame sizes)`.
    async fn drain(mut body: DynBody) -> (Vec<u8>, Vec<usize>) {
        let mut out = Vec::new();
        let mut frames = Vec::new();
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                frames.push(data.len());
                out.extend_from_slice(&data);
            }
        }
        (out, frames)
    }

    /// A fake plugin speaking raw HTTP/1.1, so the test controls exactly how the
    /// response bytes hit the wire. `respond` receives the accepted socket.
    async fn fake_plugin<F, Fut>(respond: F) -> (String, tokio::task::JoinHandle<Vec<u8>>)
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            respond(sock).await
        });
        (format!("http://{addr}"), handle)
    }

    /// Read request bytes until the head is complete, returning what was read.
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

    fn meta() -> PipeMeta {
        PipeMeta {
            id: 7,
            method: "GET".into(),
            url: "http://example.com/x".into(),
            pipe_value: Some("shout".into()),
            ..Default::default()
        }
    }

    /// The whole point: bytes cross the plugin one frame at a time, and the
    /// transformed frames come back one at a time too — nothing is buffered.
    #[test]
    fn streams_frame_by_frame() {
        rt().block_on(async {
            // Plugin: 200 immediately, then uppercase each chunk as it arrives.
            let (url, plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await
                    .expect("head");
                // Echo the request's chunked framing straight back, uppercased:
                // chunk-size hex and CRLFs survive `to_ascii_uppercase`, so the
                // echo is itself a valid chunked response whose payloads are the
                // request's payloads, shouted.
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                while !seen.ends_with(CHUNKED_END) {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    if sock
                        .write_all(&buf[..n].to_ascii_uppercase())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                seen
            })
            .await;

            let (tx, source) = body::channel(4);
            let out = transform("t", &url, Dir::Response, &meta(), source).await;

            tokio::spawn(async move {
                for part in ["one", "two", "three"] {
                    tx.send(Ok(Bytes::from_static(part.as_bytes())))
                        .await
                        .expect("send");
                }
            });

            let (bytes, frames) = drain(out).await;
            assert_eq!(String::from_utf8_lossy(&bytes), "ONETWOTHREE");
            // Three sends → three frames out. One frame would mean buffering.
            assert_eq!(frames, vec![3, 3, 5]);
            let seen = plugin.await.expect("plugin task");
            assert!(String::from_utf8_lossy(&seen).contains("one"));
        });
    }

    /// A response arriving in awkward pieces (one byte per write, chunk headers
    /// split across reads) must reassemble exactly.
    #[test]
    fn response_split_across_reads() {
        rt().block_on(async {
            let payload = "the quick brown fox jumps over the lazy dog";
            let (url, plugin) = fake_plugin(move |mut sock| async move {
                read_head(&mut sock).await;
                // Head and body, dribbled out one byte at a time.
                let mut wire = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
                for chunk in payload.as_bytes().chunks(7) {
                    wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    wire.extend_from_slice(chunk);
                    wire.extend_from_slice(b"\r\n");
                }
                wire.extend_from_slice(b"0\r\n\r\n");
                for byte in wire {
                    if sock.write_all(&[byte]).await.is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                // Drain the request so the client never writes into a closed
                // socket while it is still reading our reply.
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                while !seen.ends_with(CHUNKED_END) {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                seen
            })
            .await;

            let out = transform("t", &url, Dir::Response, &meta(), body::full("in")).await;
            let (bytes, _) = drain(out).await;
            assert_eq!(String::from_utf8_lossy(&bytes), payload);
            plugin.await.expect("plugin task");
        });
    }

    /// An endless source (an event stream, a long upload) that sends a frame
    /// every few milliseconds until nobody takes them, and says when that was.
    fn endless_source() -> (DynBody, tokio::sync::oneshot::Receiver<()>) {
        let (tx, body) = body::channel(1);
        let (gone_tx, gone) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            while tx.send(Ok(Bytes::from_static(b"tick\n"))).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = gone_tx.send(());
        });
        (body, gone)
    }

    /// Once the plugin's own answer has ended, nothing more it reads can change
    /// it — so the source is let go, rather than fed to a plugin that keeps
    /// draining it (as Node does, `req._dump()`) for as long as it flows. An
    /// event stream would otherwise hold its origin open for good: upstream's
    /// "pipe may cause request hangs and memory leaks", fixed in 2.10.10
    /// (avwo/whistle#1351), in this port's shape.
    #[test]
    fn the_source_is_let_go_once_the_plugin_has_answered() {
        rt().block_on(async {
            let (url, _plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(
                    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\nDONE\r\n0\r\n\r\n",
                )
                .await
                .expect("answer");
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
                Vec::new()
            })
            .await;
            let (source, gone) = endless_source();
            let out = transform("t", &url, Dir::Response, &meta(), source).await;
            let (bytes, _) = drain(out).await;
            assert_eq!(bytes, b"DONE");
            tokio::time::timeout(Duration::from_secs(3), gone)
                .await
                .expect("the source is still being read after the plugin answered")
                .ok();
        });
    }

    /// A client that leaves mid-stream lets go of the source too.
    #[test]
    fn the_source_is_let_go_when_the_client_leaves() {
        rt().block_on(async {
            let (url, _plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await
                    .expect("head");
                // An echo that never ends: the request's chunks are valid
                // response chunks.
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Vec::new()
            })
            .await;
            let (source, gone) = endless_source();
            let mut out = transform("t", &url, Dir::Response, &meta(), source).await;
            let first = out.frame().await.expect("a frame").expect("ok");
            assert!(first.is_data());
            drop(out);
            tokio::time::timeout(Duration::from_secs(3), gone)
                .await
                .expect("the source is still being read after the client left")
                .ok();
        });
    }

    /// A plugin that is not listening must cost the body nothing.
    #[test]
    fn unreachable_plugin_forwards_body_unchanged() {
        rt().block_on(async {
            // Bind then drop, so the port is almost certainly free.
            let addr = {
                let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                l.local_addr().expect("addr")
            };
            let out = transform(
                "gone",
                &format!("http://{addr}"),
                Dir::Response,
                &meta(),
                body::full("untouched"),
            )
            .await;
            let (bytes, _) = drain(out).await;
            assert_eq!(bytes, b"untouched");
        });
    }

    /// A plugin that declines (any non-200) leaves the body intact: its head
    /// arrives before we have read a byte, so there is still something to
    /// forward — and the plugin must never have seen the payload.
    #[test]
    fn declining_plugin_forwards_body_unchanged() {
        rt().block_on(async {
            let (url, plugin) = fake_plugin(|mut sock| async move {
                read_head(&mut sock).await;
                sock.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .expect("head");
                // Whatever the proxy sends after being declined.
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf)).await
                {
                    seen.extend_from_slice(&buf[..n]);
                }
                seen
            })
            .await;

            let out = transform("no", &url, Dir::Response, &meta(), body::full("original")).await;
            let (bytes, _) = drain(out).await;
            assert_eq!(bytes, b"original");
            let seen = plugin.await.expect("plugin task");
            assert!(
                !String::from_utf8_lossy(&seen).contains("original"),
                "a declined plugin must not receive the body, got {seen:?}"
            );
        });
    }

    /// A plugin that hangs without answering must not hold the body hostage
    /// forever — but five seconds is too long for a unit test, so this only
    /// asserts the timeout is what governs (the constant is the contract).
    #[test]
    fn handshake_timeout_is_bounded() {
        assert!(HANDSHAKE_TIMEOUT <= Duration::from_secs(10));
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(
            host_port("http://127.0.0.1:9000").unwrap(),
            ("127.0.0.1".to_string(), 9000)
        );
        assert_eq!(
            host_port("localhost:1234").unwrap(),
            ("localhost".to_string(), 1234)
        );
        assert_eq!(
            host_port("example.com").unwrap(),
            ("example.com".to_string(), 80)
        );
        assert!(host_port("https://example.com").is_err());
        assert!(host_port("http://").is_err());
    }

    #[test]
    fn metadata_serialisation() {
        let m = PipeMeta {
            id: 3,
            method: "POST".into(),
            url: "http://a/b".into(),
            param: "x".into(),
            pipe_value: Some("v".into()),
            client_ip: Some("1.2.3.4".into()),
            headers: vec![("k".into(), "v".into())],
            status: Some(201),
        };
        let v = m.to_json();
        assert_eq!(v["id"], 3);
        assert_eq!(v["pipeValue"], "v");
        assert_eq!(v["statusCode"], 201);
        assert_eq!(v["headers"][0][0], "k");

        // Absent optionals are omitted rather than serialised as null.
        let bare = PipeMeta::default().to_json();
        assert!(bare.get("pipeValue").is_none());
        assert!(bare.get("statusCode").is_none());
        assert!(bare.get("clientIp").is_none());
    }
}
