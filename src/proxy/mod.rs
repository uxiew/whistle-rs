//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
pub mod body;
pub mod persist;
pub mod script;
pub mod socks;
pub mod template;
pub mod upstream;
pub mod webui;
pub mod ws;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::rules::{ReqInfo, Resolved, RuleManager};
use body::DynBody;

/// Maximum number of captured transactions kept in memory.
pub const MAX_SESSIONS: usize = 500;

/// Request header that marks a request as *whistle-internal*: issued by the
/// proxy (or its tooling) rather than by a client being debugged. It is what
/// makes the `lineProps://internal` and `lineProps://internalOnly` rule lines
/// visible — see [`crate::rules::LineProps::allows_scope`].
///
/// whistle marks such requests with a per-process secret header
/// (`config.PROXY_ID_HEADER = 'x-whistle-proxy-id-' + uid`,
/// `_original/lib/config.js:89`), set by the HTTP client it uses for its own
/// calls (`setInternalOptions`, `_original/lib/util/common.js:1268`) and deleted
/// again the moment the proxy sees it (`checkPluginReqOnce`,
/// `_original/lib/util/index.js:3414-3425`). This port uses a fixed, documented
/// name rather than a secret one: it has no privileged internal service to
/// protect, and a stable name is what lets a client — or whistle-rs's own
/// tooling — deliberately exercise an `internal` rule.
///
/// Any non-empty value marks the request. The header is removed before the
/// rules run, so it never reaches a `includeFilter://reqH.` condition, the session
/// capture, or the origin server.
pub const INTERNAL_REQ_HEADER: &str = "x-whistle-internal-req";

/// Strip the internal-request marker, reporting whether it was present.
fn take_internal_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(INTERNAL_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Maximum number of captured WebSocket frames kept in memory (across all
/// connections). Whistle surfaces every frame; we keep a bounded ring buffer.
const MAX_FRAMES: usize = 2000;

/// Collect a whole [`DynBody`] into memory. Its boxed error type is unsized, so
/// it needs flattening before `?` can carry it into `anyhow`.
async fn collect_body(body: DynBody) -> Result<Bytes> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// Monotonic id handed to plugins so their request and response hooks can be
/// correlated. Distinct from a [`Session`] id, which is only assigned once the
/// transaction is recorded — far too late for the request hook.
fn next_plugin_req_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Shared server state.
pub struct AppState {
    pub config: Config,
    pub rules: RwLock<RuleManager>,
    pub ca: Arc<CertAuthority>,
    /// Named values store (name → content), editable via the UI.
    pub values: RwLock<std::collections::HashMap<String, String>>,
    /// Registered plugins (Rust + remote/Node), keyed by name.
    pub plugins: crate::plugins::Plugins,
    /// Bounded ring buffer of recent transactions (whistle's session capture).
    pub sessions: Mutex<VecDeque<Session>>,
    /// Bounded ring buffer of captured WebSocket frames, keyed by session id.
    pub ws_frames: Mutex<VecDeque<WsFrame>>,
    next_id: AtomicU64,
    /// Optional session persistence (JSONL on disk).
    session_store: Option<persist::SessionStore>,
}

impl AppState {
    /// Construct fresh server state with a default plugin registry (built-ins +
    /// any `--plugin name=host:port` remotes from the config).
    pub fn new(config: Config, rules: RuleManager, ca: Arc<CertAuthority>) -> Self {
        let mut plugins = crate::plugins::Plugins::new();
        for (name, addr) in &config.plugins {
            plugins.register_remote(name, addr);
        }
        Self::with_plugins(config, rules, ca, plugins)
    }

    /// Construct server state with a pre-built plugin registry (used when Node
    /// plugin subprocesses have already been spawned and registered).
    pub fn with_plugins(
        config: Config,
        rules: RuleManager,
        ca: Arc<CertAuthority>,
        plugins: crate::plugins::Plugins,
    ) -> Self {
        let values = RwLock::new(config.values.clone());
        AppState {
            config,
            rules: RwLock::new(rules),
            ca,
            values,
            plugins,
            sessions: Mutex::new(VecDeque::new()),
            ws_frames: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
            session_store: None,
        }
    }

    /// Attach a session store for persistence. Must be called after the
    /// tokio runtime is available (store spawns a background task).
    pub fn enable_persistence(&mut self, store: persist::SessionStore) {
        self.session_store = Some(store);
    }

    /// Set the next session ID counter (used after loading history).
    pub fn set_next_id(&self, id: u64) {
        self.next_id.store(id, Ordering::Relaxed);
    }

    /// Record a transaction, assigning it an id which is returned so callers
    /// (e.g. WebSocket tunnels) can correlate later frames with it.
    fn record(&self, mut session: Session) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        session.id = id;
        // Persist to disk before inserting into the in-memory ring buffer.
        if let Some(store) = &self.session_store {
            store.persist(&session);
        }
        let mut q = self.sessions.lock().unwrap();
        if q.len() >= MAX_SESSIONS {
            q.pop_front();
        }
        q.push_back(session);
        id
    }

    /// Clear all in-memory sessions and WebSocket frames.
    pub fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
        self.ws_frames.lock().unwrap().clear();
    }

    /// Record one captured WebSocket frame in the bounded ring buffer.
    pub fn record_frame(&self, frame: WsFrame) {
        let mut q = self.ws_frames.lock().unwrap();
        if q.len() >= MAX_FRAMES {
            q.pop_front();
        }
        q.push_back(frame);
    }
}

/// Longest body prefix retained for the inspection preview (per body).
pub const BODY_PREVIEW_CAP: usize = 16 * 1024;

/// A streaming decompressor for the capture preview. It decodes `Content-Encoding`
/// so the preview shows readable text; the *proxied* body is never touched.
enum BodyDecoder {
    /// No (or unknown) encoding — bytes stored verbatim.
    Identity,
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    /// A decode error occurred — stop decoding this body.
    Failed,
}

impl Default for BodyDecoder {
    fn default() -> Self {
        BodyDecoder::Identity
    }
}

/// Build a decoder for a `Content-Encoding` value (identity for none/unknown).
fn make_decoder(encoding: Option<&str>) -> BodyDecoder {
    // Take the first token of e.g. "gzip" / "br" / "gzip, chunked".
    let enc = encoding
        .map(|e| e.split(',').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    match enc.as_str() {
        "gzip" | "x-gzip" => BodyDecoder::Gzip(flate2::write::GzDecoder::new(Vec::new())),
        "deflate" => BodyDecoder::Deflate(flate2::write::ZlibDecoder::new(Vec::new())),
        "br" => BodyDecoder::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 4096))),
        _ => BodyDecoder::Identity,
    }
}

/// Feed compressed `bytes` to a `Write` decoder, then copy any newly-decoded
/// output (beyond what's already in `data`) into `data`, bounded to the cap.
/// Returns false on a decode error.
fn drain_decoder<D>(
    dec: &mut D,
    get_ref: impl Fn(&D) -> &[u8],
    bytes: &[u8],
    data: &mut Vec<u8>,
    cap: usize,
) -> bool
where
    D: std::io::Write,
{
    if dec.write_all(bytes).is_err() {
        return false;
    }
    let _ = dec.flush();
    let out = get_ref(dec);
    if out.len() > data.len() {
        let room = cap.saturating_sub(data.len());
        let new = &out[data.len()..];
        let take = room.min(new.len());
        data.extend_from_slice(&new[..take]);
    }
    true
}

/// Mutable capture state for one body, filled as the body streams past.
/// Memory is bounded to `cap`; `total` still counts every raw byte.
#[derive(Default)]
pub struct CaptureState {
    /// Decoded body prefix (≤ `cap` bytes) kept for the preview.
    data: Vec<u8>,
    /// Total raw bytes observed (may exceed `data.len()`).
    total: usize,
    /// The body's Content-Type, for text-vs-binary rendering.
    content_type: Option<String>,
    /// Streaming decoder for the body's Content-Encoding.
    decoder: BodyDecoder,
    /// Preview byte cap (`None` → [`BODY_PREVIEW_CAP`] default).
    cap: Option<usize>,
}

impl CaptureState {
    fn cap(&self) -> usize {
        self.cap.unwrap_or(BODY_PREVIEW_CAP)
    }

    /// Record raw `bytes` flowing through, decoding into a bounded preview.
    fn append(&mut self, bytes: &[u8]) {
        self.total += bytes.len();
        let cap = self.cap();
        if self.data.len() >= cap {
            return; // preview already full — stop decoding/copying
        }
        let mut failed = false;
        match &mut self.decoder {
            BodyDecoder::Identity => {
                let room = cap - self.data.len();
                let take = room.min(bytes.len());
                self.data.extend_from_slice(&bytes[..take]);
            }
            BodyDecoder::Failed => {}
            BodyDecoder::Gzip(d) => {
                failed = !drain_decoder(d, |d| d.get_ref(), bytes, &mut self.data, cap)
            }
            BodyDecoder::Deflate(d) => {
                failed = !drain_decoder(d, |d| d.get_ref(), bytes, &mut self.data, cap)
            }
            BodyDecoder::Brotli(d) => {
                failed = !drain_decoder(d.as_mut(), |d| d.get_ref(), bytes, &mut self.data, cap)
            }
        }
        if failed {
            self.decoder = BodyDecoder::Failed;
        }
    }
}

/// A shareable handle to a body's [`CaptureState`]. Cloning shares the state, so
/// the copy stored in a [`Session`] sees updates made by the streaming tee.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<CaptureState>>);

impl Capture {
    /// A fresh, empty capture for a body of the given content type/encoding,
    /// keeping at most `cap` decoded preview bytes.
    pub fn new(content_type: Option<String>, content_encoding: Option<&str>, cap: usize) -> Self {
        Capture(Arc::new(Mutex::new(CaptureState {
            content_type,
            decoder: make_decoder(content_encoding),
            cap: Some(cap),
            ..Default::default()
        })))
    }

    /// A capture already populated from a fully-buffered body.
    pub(crate) fn from_bytes(
        bytes: &[u8],
        content_type: Option<String>,
        content_encoding: Option<&str>,
        cap: usize,
    ) -> Self {
        let c = Capture::new(content_type, content_encoding, cap);
        c.0.lock().unwrap().append(bytes);
        c
    }

    /// Append streamed bytes to the shared state.
    pub fn append(&self, bytes: &[u8]) {
        self.0.lock().unwrap().append(bytes);
    }

    /// Total bytes seen so far.
    fn total(&self) -> usize {
        self.0.lock().unwrap().total
    }

    /// A `(len, truncated, text)` snapshot of the preview. `len` is the raw
    /// (wire) byte count; `text` is the decoded preview (or a binary marker).
    pub fn snapshot(&self) -> (usize, bool, String) {
        let st = self.0.lock().unwrap();
        let truncated = st.data.len() >= st.cap()
            || (matches!(st.decoder, BodyDecoder::Identity) && st.total > st.data.len());
        let text = if is_textual(st.content_type.as_deref()) {
            String::from_utf8_lossy(&st.data).into_owned()
        } else {
            format!("[binary, {} bytes]", st.total)
        };
        (st.total, truncated, text)
    }
}

impl serde::Serialize for Capture {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (len, truncated, text) = self.snapshot();
        let mut o = s.serialize_struct("BodyCapture", 3)?;
        o.serialize_field("len", &len)?;
        o.serialize_field("truncated", &truncated)?;
        o.serialize_field("text", &text)?;
        o.end()
    }
}

/// Whether a body of this content type should be previewed as text.
fn is_textual(content_type: Option<&str>) -> bool {
    match content_type {
        None => true, // no type → try as text
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/")
                || ct.contains("json")
                || ct.contains("xml")
                || ct.contains("javascript")
                || ct.contains("ecmascript")
                || ct.contains("html")
                || ct.contains("css")
                || ct.contains("urlencoded")
        }
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use std::io::Write;

    fn preview(data: Vec<u8>, ct: &str, enc: &str) -> (usize, bool, String) {
        let cap = Capture::new(Some(ct.into()), Some(enc), BODY_PREVIEW_CAP);
        cap.append(&data);
        let v = serde_json::to_value(&cap).unwrap();
        (
            v["len"].as_u64().unwrap() as usize,
            v["truncated"].as_bool().unwrap(),
            v["text"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn gzip_preview_decoded() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"{\"hi\":\"gzipped\"}").unwrap();
        let gz = e.finish().unwrap();
        let (len, _, text) = preview(gz.clone(), "application/json", "gzip");
        assert_eq!(len, gz.len()); // len = wire (compressed) bytes
        assert_eq!(text, "{\"hi\":\"gzipped\"}");
    }

    #[test]
    fn deflate_preview_decoded() {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"deflated-body").unwrap();
        let df = e.finish().unwrap();
        let (_, _, text) = preview(df, "text/plain", "deflate");
        assert_eq!(text, "deflated-body");
    }

    #[test]
    fn brotli_preview_decoded() {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(b"brotli-body-text").unwrap();
        }
        let (_, _, text) = preview(out, "text/plain", "br");
        assert_eq!(text, "brotli-body-text");
    }

    #[test]
    fn unknown_encoding_shows_binary() {
        let (_, _, text) = preview(vec![0u8, 159, 146, 150], "application/octet-stream", "zstd");
        assert!(text.starts_with("[binary"), "got {text}");
    }

    #[test]
    fn identity_text_passthrough() {
        let (len, trunc, text) = preview(b"plain body".to_vec(), "text/plain", "identity");
        assert_eq!(len, 10);
        assert!(!trunc);
        assert_eq!(text, "plain body");
    }

    #[test]
    fn iso8601_conversion() {
        assert_eq!(super::iso8601_utc(0), "1970-01-01T00:00:00.000Z");
        // 1_000_000_000 s since epoch = 2001-09-09T01:46:40Z
        assert_eq!(super::iso8601_utc(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
        // milliseconds are preserved
        assert_eq!(super::iso8601_utc(1_609_459_200_123), "2021-01-01T00:00:00.123Z");
    }
}

/// One captured request/response transaction.
#[derive(Clone, Default, serde::Serialize)]
pub struct Session {
    pub id: u64,
    /// Unix time in milliseconds when the request was received.
    pub time_ms: u128,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub client_ip: Option<String>,
    /// Where the request was sent (or "short-circuit").
    pub target: String,
    pub duration_ms: u128,
    /// `log://` channel labels attached to this request (whistle's log tags).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    /// Outgoing request headers (as forwarded upstream).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub req_headers: Vec<(String, String)>,
    /// Response headers (as returned to the client).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub res_headers: Vec<(String, String)>,
    /// Request body preview (filled as the body streams), if captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_body: Option<Capture>,
    /// Response body preview (filled as the body streams), if captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_body: Option<Capture>,
}

/// Read a single header as an owned string, if present and valid UTF-8.
fn header_str(headers: &hyper::HeaderMap, name: hyper::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Collect header name/value pairs for display.
fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

/// True if a request carries a body worth capturing.
fn has_request_body(headers: &hyper::HeaderMap) -> bool {
    headers.contains_key(hyper::header::CONTENT_LENGTH)
        || headers.contains_key(hyper::header::TRANSFER_ENCODING)
}

/// Convert a plugin-produced response into a real HTTP response.
fn plugin_response(resp: crate::plugins::PluginResp) -> Response<DynBody> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(body::full(Bytes::from(resp.body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::OK)
                .body(body::empty())
                .unwrap()
        })
}

/// One captured WebSocket frame, as surfaced in the Network view.
#[derive(Clone, serde::Serialize)]
pub struct WsFrame {
    /// Id of the [`Session`] this frame belongs to.
    pub session: u64,
    /// Unix time in milliseconds when the frame was seen.
    pub time_ms: u128,
    /// `"send"` (client→server) or `"receive"` (server→client).
    pub dir: &'static str,
    /// Frame type: `text`, `binary`, `close`, `ping`, `pong`, `continuation`.
    pub opcode: &'static str,
    /// Payload length in bytes.
    pub len: usize,
    /// A short preview: UTF-8 text (truncated) for text frames, else hex.
    pub preview: String,
}

impl WsFrame {
    /// Build a frame record, deriving the opcode name and a bounded preview.
    fn new(session: u64, dir: &'static str, opcode: u8, payload: &[u8]) -> Self {
        let name = match opcode {
            0x0 => "continuation",
            0x1 => "text",
            0x2 => "binary",
            0x8 => "close",
            0x9 => "ping",
            0xa => "pong",
            _ => "unknown",
        };
        // Text/continuation → UTF-8 preview; everything else → hex.
        let preview = if opcode == 0x1 || opcode == 0x0 {
            match std::str::from_utf8(payload) {
                Ok(s) => truncate_preview(s),
                Err(_) => hex_preview(payload),
            }
        } else {
            hex_preview(payload)
        };
        WsFrame {
            session,
            time_ms: now_ms(),
            dir,
            opcode: name,
            len: payload.len(),
            preview,
        }
    }
}

/// Truncate a text preview to a sane length for the UI feed.
fn truncate_preview(s: &str) -> String {
    const MAX: usize = 512;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let cut: String = s.chars().take(MAX).collect();
        format!("{cut}… (+{} bytes)", s.len() - cut.len())
    }
}

/// Hex-encode the first 64 bytes of a binary/control payload.
fn hex_preview(payload: &[u8]) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(MAX * 2);
    for b in payload.iter().take(MAX) {
        out.push_str(&format!("{b:02x}"));
    }
    if payload.len() > MAX {
        out.push_str(&format!("… (+{} bytes)", payload.len() - MAX));
    }
    out
}

/// Collect `log://` channel labels for a resolved request.
fn log_labels(resolved: &Resolved) -> Vec<String> {
    resolved.all("log").iter().map(|o| o.value.clone()).collect()
}

/// Milliseconds since the Unix epoch (best-effort).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Format Unix-epoch milliseconds as an ISO-8601 UTC timestamp (for HAR export).
/// Uses Howard Hinnant's civil-from-days algorithm; no external date crate.
pub(crate) fn iso8601_utc(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 → civil (year, month, day)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Where a request originated, which decides how we derive its target.
#[derive(Clone)]
enum Origin {
    /// A normal absolute-form forward-proxy request.
    Forward,
    /// A request seen inside an intercepted tunnel (CONNECT or SOCKS). `tls`
    /// indicates the tunnel was TLS-decrypted (scheme https) vs. plain (http).
    Mitm { host: String, port: u16, tls: bool },
}

/// Start the proxy and serve until the process exits.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let addr = SocketAddr::new(
        state
            .config
            .host
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
        state.config.port,
    );
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("whistle-rs listening on http://{addr}");

    // Teach the forwarding layer which addresses are *us*, so a `proxy://` rule
    // naming this proxy is refused instead of recursing into it. Registered
    // before the first connection is accepted; see `upstream::self_loop`.
    let mut own_ports = vec![state.config.port];
    own_ports.extend(state.config.socks_port);
    upstream::set_listen(state.config.host, &own_ports);
    tracing::info!(
        "root CA: {} (download at http://{}/rootCA.crt)",
        state.config.root_ca_cert_path().display(),
        addr
    );

    // Optional inbound SOCKS5 server.
    if let Some(socks_port) = state.config.socks_port {
        let socks_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = socks::run(socks_state, socks_port).await {
                tracing::error!("SOCKS server error: {e}");
            }
        });
    }

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        let peer_ip = peer.ip();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { top_level(state, req, peer_ip).await }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("connection from {peer} closed: {err}");
            }
        });
    }
}

/// Entry point for every request arriving on the main port.
async fn top_level(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: IpAddr,
) -> Result<Response<DynBody>, Infallible> {
    let client_ip = Some(peer.to_string());
    if req.method() == hyper::Method::CONNECT {
        return Ok(handle_connect(state, req, peer));
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return Ok(guard(serve(state, req, Origin::Forward, client_ip).await));
    }
    Ok(webui::handle(&state, req).await)
}

/// Handle a CONNECT: acknowledge, then intercept the tunnel with MITM.
fn handle_connect(state: Arc<AppState>, req: Request<Incoming>, peer: IpAddr) -> Response<DynBody> {
    let Some((host, port)) = authority_host_port(req.uri()) else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"bad CONNECT target")))
            .unwrap();
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // A CONNECT tunnel is (almost always) TLS; intercept it.
                if let Err(err) =
                    serve_tunnel(state, TokioIo::new(upgraded), host, port, peer, true).await
                {
                    tracing::debug!("mitm error: {err}");
                }
            }
            Err(err) => tracing::debug!("connect upgrade failed: {err}"),
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(body::empty())
        .unwrap()
}

/// Serve HTTP over an intercepted tunnel stream, optionally TLS-decrypting first.
/// Shared by CONNECT interception and the SOCKS server.
pub(crate) async fn serve_tunnel<S>(
    state: Arc<AppState>,
    stream: S,
    host: String,
    port: u16,
    peer: IpAddr,
    tls: bool,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if tls {
        let acceptor = state.ca.acceptor_for(&host)?;
        let tls_stream = acceptor.accept(stream).await?;
        let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
        if is_h2 {
            serve_intercepted_h2(state, TokioIo::new(tls_stream), host, port, peer).await
        } else {
            serve_intercepted(state, TokioIo::new(tls_stream), host, port, peer, true).await
        }
    } else {
        serve_intercepted(state, TokioIo::new(stream), host, port, peer, false).await
    }
}

/// Serve an intercepted HTTP/2 connection (ALPN negotiated `h2`). Upstream
/// forwarding stays HTTP/1.1 — hyper translates request/response between them.
async fn serve_intercepted_h2<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: IpAddr,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls: true,
        };
        let client_ip = Some(peer.to_string());
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, client_ip).await)) }
    });

    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Run the HTTP/1.1 server over an already-prepared tunnel IO.
async fn serve_intercepted<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: IpAddr,
    tls: bool,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls,
        };
        let client_ip = Some(peer.to_string());
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, client_ip).await)) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

/// Turn an internal error into a 502 so the service signature stays infallible.
fn guard(result: Result<Response<DynBody>>) -> Response<DynBody> {
    match result {
        Ok(resp) => resp,
        Err(err) => {
            // `{err:#}` includes the full anyhow context chain (e.g. the
            // underlying rustls reason behind "upstream TLS handshake").
            tracing::debug!("request failed: {err:#}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(body::full(Bytes::from(format!("whistle-rs: {err:#}"))))
                .unwrap()
        }
    }
}

/// Core request pipeline: match rules, apply them, forward upstream.
async fn serve(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    origin: Origin,
    client_ip: Option<String>,
) -> Result<Response<DynBody>> {
    // Consumed before anything else looks at the headers, exactly like whistle
    // deletes its own marker on arrival: rule filters, plugins, the capture and
    // the origin server must never see it.
    let is_internal_req = take_internal_marker(req.headers_mut());

    // Derive scheme/host/port/path for matching.
    let (scheme, host, port, path) = match &origin {
        Origin::Forward => {
            let uri = req.uri();
            let host = uri.host().unwrap_or_default().to_string();
            let scheme = uri.scheme_str().unwrap_or("http").to_string();
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            (scheme, host, port, path)
        }
        Origin::Mitm { host, port, tls } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let scheme = if *tls { "https" } else { "http" };
            (scheme.to_string(), host.clone(), *port, path)
        }
    };

    let info = apply::build_req_info(
        req.method().as_str(),
        &scheme,
        &host,
        port,
        &path,
        req.headers(),
        client_ip.clone(),
    );
    let mut resolved = state
        .rules
        .read()
        .unwrap()
        .resolve_scoped(&info, is_internal_req);
    {
        let values = state.values.read().unwrap();
        apply::substitute_values(&mut resolved, &values);
        apply::merge_included_rules(&mut resolved, &info, &values, is_internal_req);
        apply::substitute_values(&mut resolved, &values);
    }
    apply::substitute_config_vars(&mut resolved, state.config.port, crate::config::VERSION);
    let started = Instant::now();
    let time_ms = now_ms();

    // Plugins matched by `plugin://name` / `pipe://name`, minus any that aren't
    // registered. `pipe://` drives the *streaming* hooks and `plugin://` the
    // buffered ones, so the two are kept apart; a `pipe://` rule naming a plugin
    // with no streaming hook falls back to the buffered path, which is what
    // `pipe://` meant before the streaming hooks existed.
    let mut plugin_matches: Vec<(String, String)> = Vec::new();
    let mut pipe_matches: Vec<crate::plugins::PluginMatch> = Vec::new();
    for m in crate::plugins::matched(&resolved) {
        if !state.plugins.contains(&m.name) {
            continue;
        }
        let streams = m.via_pipe
            && matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.has_pipe_hook());
        if streams {
            pipe_matches.push(m);
        } else {
            plugin_matches.push((m.name.clone(), m.param.clone()));
        }
    }
    let plugin_names: Vec<String> = plugin_matches.iter().map(|(n, _)| n.clone()).collect();

    // Correlates this request's plugin hooks with each other. Session ids are
    // only assigned once a transaction is recorded, which is too late here.
    let plugin_req_id = next_plugin_req_id();

    // Normalise the request body to `DynBody` so a plugin can optionally be
    // handed it. Buffering happens *only* when a matched plugin's manifest
    // declares `requestBody` — otherwise the body stays a lazy stream and the
    // proxy's streaming fast path is untouched.
    let (req, plugin_req_body): (Request<DynBody>, Option<Bytes>) = {
        let (parts, incoming) = req.into_parts();
        let wants_body = !plugin_matches.is_empty()
            && has_request_body(&parts.headers)
            && state.plugins.any_wants_request_body(&plugin_names).await;
        if wants_body {
            let bytes = incoming.collect().await?.to_bytes();
            (
                Request::from_parts(parts, body::full(bytes.clone())),
                Some(bytes),
            )
        } else {
            (
                Request::from_parts(parts, body::from_incoming(incoming)),
                None,
            )
        }
    };

    // Request hook: a matched plugin may inject rules, rewrite request headers,
    // and/or answer the request directly (Rust in-process or remote).
    let mut plugin_set_headers: Vec<(String, String)> = Vec::new();
    let mut plugin_remove_headers: Vec<String> = Vec::new();
    if !plugin_matches.is_empty() {
        let preq_headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        for (name, param) in plugin_matches.iter() {
            let preq = crate::plugins::PluginReq {
                id: plugin_req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                headers: preq_headers.clone(),
                client_ip: client_ip.clone(),
                param: param.clone(),
                body: plugin_req_body.clone().map(|b| b.to_vec()),
            };
            let Some(result) = state.plugins.on_request(name, &preq).await else {
                continue;
            };
            if let Some(rules) = result.rules {
                apply::merge_rules_text(&mut resolved, &info, &rules, is_internal_req);
                let values = state.values.read().unwrap();
                apply::substitute_values(&mut resolved, &values);
            }
            plugin_set_headers.extend(result.set_headers);
            plugin_remove_headers.extend(result.remove_headers);
            if let Some(resp) = result.response {
                tracing::info!("{} {} -> plugin {name}", info.method, info.full_url);
                let response = plugin_response(resp);
                state.record(Session {
                    id: 0,
                    time_ms,
                    method: info.method.clone(),
                    url: info.full_url.clone(),
                    status: response.status().as_u16(),
                    client_ip: client_ip.clone(),
                    target: format!("plugin:{name}"),
                    duration_ms: started.elapsed().as_millis(),
                    log: log_labels(&resolved),
                    res_headers: header_pairs(response.headers()),
                    ..Default::default()
                });
                return Ok(response);
            }
        }
    }

    // enable://abort drops the request without contacting upstream.
    if apply::is_aborted(&resolved) {
        tracing::info!("{} {} -> aborted", info.method, info.full_url);
        return Err(anyhow::anyhow!("aborted by enable://abort"));
    }

    // Short-circuit rules (redirect, mocked status, file) skip the upstream.
    // `${host}` is whistle's own bind address, empty when bound to all
    // interfaces — see ProxyEnv.
    let bind_host = state.config.host.map(|h| h.to_string()).unwrap_or_default();
    let proxy_env = template::ProxyEnv {
        host: &bind_host,
        port: state.config.port,
        version: crate::config::VERSION,
    };
    if let Some(resp) = apply::short_circuit(&info, &resolved, proxy_env) {
        tracing::info!("{} {} -> short-circuit", info.method, info.full_url);
        // Response-side operators apply to a mocked response too: upstream runs
        // its response inspectors over `file`/`tpl`/`redirect` responses just as
        // it does over real ones, so `resHeaders://` and friends must land here
        // as well.
        let (mut parts, body) = resp.into_parts();
        apply::apply_response_for(&mut parts, &resolved, Some(&info));
        let resp = Response::from_parts(parts, body);
        state.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: "short-circuit".to_string(),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            res_headers: header_pairs(resp.headers()),
            ..Default::default()
        });
        return Ok(resp);
    }

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(
            &state, req, &info, &resolved, &scheme, &host, port, client_ip, time_ms, started,
        )
        .await;
    }

    let target = apply::resolve_target(&info, &resolved);

    // A proxy rule that names this proxy would send the request back to us, be
    // matched by the same rule, and recurse until the sockets run out. whistle
    // answers the request from its own UI port instead of making the hop
    // (`_original/lib/inspectors/res.js:302-316`); `upstream::forward` refuses
    // the same hop with a "Self loop" error for every path that reaches it.
    if let Some(addr) = upstream::self_loop(&target).await {
        let location = format!(
            "http://{}{}",
            SocketAddr::new(addr.ip(), state.config.port),
            info.path
        );
        tracing::warn!(
            "{} {} -> self loop via {addr}; redirecting to {location}",
            info.method,
            info.full_url
        );
        let resp = Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, &location)
            .body(body::empty())
            .expect("static 302");
        state.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: format!("self-loop {addr}"),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            res_headers: header_pairs(resp.headers()),
            ..Default::default()
        });
        return Ok(resp);
    }

    // Rewrite to origin-form + apply request-side rules. (Plugins that wanted to
    // handle this request already returned above; any rules they injected have
    // been merged into `resolved`.)
    let (mut parts, incoming) = req.into_parts();
    let new_path = apply::rewrite_path(&info.path, &resolved);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &host, port, &scheme);
    parts.headers.remove("proxy-connection");
    apply::apply_request(&mut parts, &resolved);
    // Plugin header rewrites land after the rule operators, so a plugin can
    // override what the rules set.
    for name in &plugin_remove_headers {
        parts.headers.remove(name.to_ascii_lowercase().as_str());
    }
    for (k, v) in &plugin_set_headers {
        set_header_raw(&mut parts.headers, k, v);
    }
    // responseFor: prefetch another URL and annotate this request with its result.
    if let Some(url) = resolved.value("responseFor") {
        if let Ok((status, body)) = upstream::simple_get(url).await {
            set_header_raw(&mut parts.headers, "x-whistle-response-for-url", url);
            set_header_raw(&mut parts.headers, "x-whistle-response-for-status", &status.to_string());
            set_header_raw(
                &mut parts.headers,
                "x-whistle-response-for-length",
                &body.len().to_string(),
            );
        }
    }

    // Buffer + transform the request body only when a body/speed/write operator applies.
    let req_speed = apply::req_speed_kbps(&resolved);
    let req_write = apply::req_write_path(&resolved);
    let req_write_raw = apply::req_write_raw_path(&resolved);
    let req_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let req_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let mut req_body_cap: Option<Capture> = None;
    let req_body: DynBody = if apply::wants_req_body(&resolved)
        || req_speed.is_some()
        || req_write.is_some()
        || req_write_raw.is_some()
    {
        let bytes = collect_body(incoming).await?;
        let new = apply::transform_req_body(bytes, &resolved, req_ct.as_deref());
        if let Some(path) = &req_write {
            write_body_file(path, &new);
        }
        if let Some(path) = &req_write_raw {
            let head = format!("{} {} HTTP/1.1\r\n{}", parts.method, parts.uri, header_dump(&parts.headers));
            write_raw_file(path, &head, &new);
        }
        if !new.is_empty() {
            req_body_cap = Some(Capture::from_bytes(
                &new,
                req_ct.clone(),
                req_enc.as_deref(),
                state.config.body_preview_cap,
            ));
        }
        apply::strip_length_headers(&mut parts.headers);
        match req_speed {
            Some(kbps) => body::throttled(new, kbps),
            None => body::full(new),
        }
    } else if has_request_body(&parts.headers) {
        // No transform: stream through, copying a bounded preview for inspection.
        let cap = Capture::new(req_ct.clone(), req_enc.as_deref(), state.config.body_preview_cap);
        req_body_cap = Some(cap.clone());
        body::tee(incoming, cap)
    } else {
        incoming
    };
    // Streaming request hook: a `pipe://` plugin sees the body as the client
    // sends it, and what it emits is what goes upstream. No-op (and no cost)
    // when nothing matched.
    let req_body = pipe_body(
        &state,
        &pipe_matches,
        crate::plugins::pipe::Dir::Request,
        crate::plugins::pipe::PipeMeta {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            client_ip: client_ip.clone(),
            headers: header_pairs(&parts.headers),
            ..Default::default()
        },
        &mut parts.headers,
        req_body,
    )
    .await;

    // Capture the outgoing request headers (as forwarded).
    let req_header_pairs = header_pairs(&parts.headers);
    let out_req = Request::from_parts(parts, req_body);

    if let Some(ms) = apply::req_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    tracing::info!(
        "{} {} -> {}:{} ({})",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port,
        if target.tls { "https" } else { "http" }
    );

    let upstream_resp = upstream::forward(&target, out_req).await?;

    if let Some(ms) = apply::res_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // Apply response-side rules.
    let (mut parts, body) = upstream_resp.into_parts();
    apply::apply_response_for(&mut parts, &resolved, Some(&info));

    // Response hook, part 1: plugins that did *not* ask for the response body
    // run here, so the response can keep streaming. Such a plugin may still
    // replace the body outright — that needs no knowledge of the original.
    let mut plugin_res_override: Option<Vec<u8>> = None;
    let mut plugin_wants_res_body = false;
    for (name, param) in plugin_matches.iter() {
        let Some(manifest) = state.plugins.manifest(name).await else {
            continue;
        };
        if !manifest.on_response {
            continue;
        }
        if manifest.response_body {
            plugin_wants_res_body = true;
            continue; // handled below, once the body is in hand
        }
        let pres = crate::plugins::PluginRes {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
            param: param.clone(),
            body: None,
        };
        if let Some(result) = state.plugins.on_response(name, &pres).await {
            if let Some(new) = apply_plugin_res_result(&mut parts, result) {
                plugin_res_override = Some(new);
            }
        }
    }

    // Streaming response hook: a `pipe://` plugin transforms upstream bytes as
    // they arrive. Deliberately *before* the buffering decision below, so a
    // piped response still takes the streaming branch — the whole point of the
    // hook is that it never forces a body into memory.
    let body = pipe_body(
        &state,
        &pipe_matches,
        crate::plugins::pipe::Dir::Response,
        crate::plugins::pipe::PipeMeta {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            client_ip: client_ip.clone(),
            headers: header_pairs(&parts.headers),
            status: Some(parts.status.as_u16()),
            ..Default::default()
        },
        &mut parts.headers,
        body::from_incoming(body),
    )
    .await;

    let res_speed = apply::res_speed_kbps(&resolved);
    let res_script = resolved
        .value("resScript")
        .and_then(script::load_script);
    let weinre = resolved.value("weinre").map(|s| s.to_string());
    let location_href = resolved.value("locationHref").map(|s| s.to_string());
    let res_write = apply::res_write_path(&resolved);
    let res_write_raw = apply::res_write_raw_path(&resolved);
    let trailers = apply::build_trailers(&resolved);
    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let mut res_body_cap: Option<Capture> = None;
    let res_body: DynBody = if apply::wants_res_body(&resolved)
        || res_speed.is_some()
        || res_script.is_some()
        || weinre.is_some()
        || location_href.is_some()
        || res_write.is_some()
        || res_write_raw.is_some()
        || !trailers.is_empty()
        || plugin_wants_res_body
        || plugin_res_override.is_some()
    {
        // A plugin that replaced the body outright makes the upstream bytes
        // irrelevant — don't wait on them.
        let bytes = match &plugin_res_override {
            Some(new) => Bytes::from(new.clone()),
            None => collect_body(body).await?,
        };
        let mut new = apply::transform_res_body(bytes, &resolved, res_ct.as_deref());

        // Response hook, part 2: plugins that asked for the body.
        for (name, param) in plugin_matches.iter() {
            let Some(manifest) = state.plugins.manifest(name).await else {
                continue;
            };
            if !manifest.on_response || !manifest.response_body {
                continue;
            }
            let pres = crate::plugins::PluginRes {
                id: plugin_req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                status: parts.status.as_u16(),
                headers: header_pairs(&parts.headers),
                param: param.clone(),
                body: Some(new.to_vec()),
            };
            if let Some(result) = state.plugins.on_response(name, &pres).await {
                if let Some(replaced) = apply_plugin_res_result(&mut parts, result) {
                    new = Bytes::from(replaced);
                }
            }
        }
            if let Some(src) = &res_script {
                let hv: Vec<(String, String)> = parts
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body_str = String::from_utf8_lossy(&new).into_owned();
                if let Some(r) = script::run_res_script(
                    src,
                    &info.method,
                    &info.full_url,
                    parts.status.as_u16(),
                    &hv,
                    &body_str,
                ) {
                    if let Some(st) = r.status {
                        if let Ok(s) = StatusCode::from_u16(st) {
                            parts.status = s;
                        }
                    }
                    for (k, v) in r.headers {
                        set_header_raw(&mut parts.headers, &k, &v);
                    }
                    if let Some(b) = r.body {
                        new = Bytes::from(b);
                    }
                }
            }
            // weinre: inject a debug <script> into HTML responses.
            if let Some(id) = &weinre {
                if is_html(&parts.headers) {
                    let src = weinre_src(id, &state.config);
                    let tag = format!("<script src=\"{src}\"></script>");
                    new = inject_into_html(&new, &tag);
                }
            }
            // locationHref: inject a client-side redirect into HTML responses.
            if let Some(url) = &location_href {
                if is_html(&parts.headers) {
                    let safe = url.replace('\\', "\\\\").replace('\'', "\\'");
                    let tag = format!("<script>location.href='{safe}'</script>");
                    new = inject_into_html(&new, &tag);
                }
            }
            if let Some(path) = &res_write {
                write_body_file(path, &new);
            }
            if let Some(path) = &res_write_raw {
                let head = format!(
                    "HTTP/1.1 {}\r\n{}",
                    parts.status,
                    header_dump(&parts.headers)
                );
                write_raw_file(path, &head, &new);
            }
            apply::strip_length_headers(&mut parts.headers);
            if !new.is_empty() {
                res_body_cap = Some(Capture::from_bytes(
                    &new,
                    res_ct.clone(),
                    res_enc.as_deref(),
                    state.config.body_preview_cap,
                ));
            }
            if !trailers.is_empty() {
                // Trailers need chunked transfer; ensure HTTP/1.1 (upstream may be 1.0).
                parts.version = hyper::Version::HTTP_11;
                let names = trailers
                    .keys()
                    .map(|k| k.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                set_header_raw(&mut parts.headers, "trailer", &names);
                body::with_trailers(new, trailers)
            } else {
                match res_speed {
                    Some(kbps) => body::throttled(new, kbps),
                    None => body::full(new),
                }
            }
        } else {
            // No transform: stream through, copying a bounded preview for inspection.
            let cap = Capture::new(res_ct.clone(), res_enc.as_deref(), state.config.body_preview_cap);
            res_body_cap = Some(cap.clone());
            body::tee(body, cap)
        };

    let mut target_desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        target_desc.push_str(" (via proxy)");
    }
    state.record(Session {
        id: 0,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: parts.status.as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc,
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(&resolved),
        req_headers: req_header_pairs,
        res_headers: header_pairs(&parts.headers),
        req_body: req_body_cap,
        res_body: res_body_cap,
    });

    Ok(Response::from_parts(parts, res_body))
}

/// Hand `body` to every matched `pipe://` plugin that serves the streaming hook
/// for `dir`, chaining them in rule order so the second sees the first's output.
///
/// Returns `body` untouched — same allocation, same laziness — when no plugin
/// takes it, which is what keeps a request without streaming plugins on exactly
/// the path it was on before. When one does take it, the length headers go: a
/// transform may change the body's size, and the framing is chunked from here on.
async fn pipe_body(
    state: &AppState,
    matches: &[crate::plugins::PluginMatch],
    dir: crate::plugins::pipe::Dir,
    meta: crate::plugins::pipe::PipeMeta,
    headers: &mut hyper::HeaderMap,
    body: DynBody,
) -> DynBody {
    if matches.is_empty() {
        return body;
    }
    let mut active = Vec::new();
    for m in matches {
        if matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.serves_pipe(dir)) {
            active.push(m);
        }
    }
    if active.is_empty() {
        return body;
    }
    apply::strip_length_headers(headers);
    let mut body = body;
    for m in active {
        let meta = crate::plugins::pipe::PipeMeta {
            param: m.param.clone(),
            pipe_value: m.pipe_value.clone(),
            ..meta.clone()
        };
        body = state.plugins.pipe(&m.name, dir, &meta, body).await;
    }
    body
}

/// Apply a plugin response-hook result to the response head. Returns the
/// replacement body, if the plugin supplied one.
fn apply_plugin_res_result(
    parts: &mut hyper::http::response::Parts,
    result: crate::plugins::PluginResResult,
) -> Option<Vec<u8>> {
    if let Some(code) = result.status {
        if let Ok(s) = StatusCode::from_u16(code) {
            parts.status = s;
        }
    }
    for name in &result.remove_headers {
        parts.headers.remove(name.to_ascii_lowercase().as_str());
    }
    for (k, v) in &result.set_headers {
        set_header_raw(&mut parts.headers, k, v);
    }
    result.body
}

/// True if the request asks to upgrade the protocol (e.g. a WebSocket handshake).
fn is_upgrade(req: &Request<DynBody>) -> bool {
    let headers = req.headers();
    let conn_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    conn_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// True if the upgrade handshake targets the WebSocket protocol (as opposed to
/// some other `Upgrade:` protocol we should tunnel opaquely).
fn is_websocket(req: &Request<DynBody>) -> bool {
    req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Forward an upgrade handshake and, on `101`, tunnel bytes both ways.
/// This is how WebSocket (`ws://`/`wss://`) traffic is proxied. WebSocket
/// upgrades are tunnelled frame-by-frame so each frame is captured; any other
/// `Upgrade:` protocol is tunnelled as an opaque byte stream.
#[allow(clippy::too_many_arguments)]
async fn serve_upgrade(
    state: &Arc<AppState>,
    mut req: Request<DynBody>,
    info: &ReqInfo,
    resolved: &Resolved,
    scheme: &str,
    host: &str,
    port: u16,
    client_ip: Option<String>,
    time_ms: u128,
    started: Instant,
) -> Result<Response<DynBody>> {
    let target = apply::resolve_target(info, resolved);
    let frame_script = resolved.value("frameScript").and_then(script::load_script);
    let websocket = is_websocket(&req);
    // Which plugins may hook this session's frames. Resolving the plan contacts
    // nothing and allocates nothing unless a rule named a registered plugin;
    // the plugins themselves are dialled later, from inside the tunnel.
    let frame_plan = websocket
        .then(|| ws::FramePlan::new(&state.plugins, resolved, info))
        .unwrap_or_default();
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream handshake request (upgrades carry no body).
    let (mut parts, _body) = req.into_parts();
    let new_path = apply::rewrite_path(&info.path, resolved);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, host, port, scheme);
    parts.headers.remove("proxy-connection");
    apply::apply_request(&mut parts, resolved);
    let out_req = Request::from_parts(parts, body::empty());

    tracing::info!(
        "{} {} -> upgrade {}:{}",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port
    );

    let mut resp = upstream::forward(&target, out_req).await?;

    let mut target_desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        target_desc.push_str(" (via proxy)");
    }
    let session_id = state.record(Session {
        id: 0,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: resp.status().as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc,
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(resolved),
        res_headers: header_pairs(resp.headers()),
        ..Default::default()
    });

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade; relay its response verbatim.
        let (p, b) = resp.into_parts();
        return Ok(Response::from_parts(p, body::from_incoming(b)));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut resp);
    let (p, _b) = resp.into_parts();
    let state = state.clone();

    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok((client_io, upstream_io)) => {
                let c = TokioIo::new(client_io);
                let u = TokioIo::new(upstream_io);
                if websocket {
                    // Frame-aware tunnel: capture every frame, run the script on
                    // text frames when a frameScript rule matched, and offer each
                    // data frame to the plugins the plan named.
                    ws::capturing_tunnel(c, u, frame_script, frame_plan, state, session_id).await;
                } else {
                    // Non-WebSocket upgrade: opaque byte passthrough.
                    let mut c = c;
                    let mut u = u;
                    if let Err(err) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
                        tracing::debug!("upgrade tunnel closed: {err}");
                    }
                }
            }
            Err(err) => tracing::debug!("upgrade failed: {err}"),
        }
    });

    // Relay the 101 (with Sec-WebSocket-Accept etc.) so the client handshake completes.
    Ok(Response::from_parts(p, body::empty()))
}

/// Append a captured body to a file (`reqWrite`/`resWrite`). Best-effort.
fn write_body_file(path: &str, data: &Bytes) {
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(data) {
                tracing::debug!("write body to {path} failed: {e}");
            }
        }
        Err(e) => tracing::debug!("open {path} for write failed: {e}"),
    }
}

/// Serialise headers as `name: value\r\n` lines.
fn header_dump(headers: &hyper::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(value.to_str().unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// Append a raw message (head + blank line + body + separator) to a file.
fn write_raw_file(path: &str, head: &str, body: &Bytes) {
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = f.write_all(head.as_bytes());
            let _ = f.write_all(b"\r\n");
            let _ = f.write_all(body);
            let _ = f.write_all(b"\r\n\r\n");
        }
        Err(e) => tracing::debug!("open {path} for raw write failed: {e}"),
    }
}

/// True if the response declares an HTML content type.
fn is_html(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// Build the weinre target-script URL. If `id` is already a URL/path use it as-is;
/// otherwise build the conventional weinre target URL served on the proxy host.
fn weinre_src(id: &str, config: &Config) -> String {
    let id = id.trim();
    if id.contains("://") || id.starts_with('/') {
        return id.to_string();
    }
    let host = config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let anchor = if id.is_empty() {
        String::new()
    } else {
        format!("#{id}")
    };
    format!(
        "//{host}:{port}/weinre/target/target-script-min.js{anchor}",
        port = config.port
    )
}

/// Inject `tag` into HTML: before `</head>`, else after `<body>`, else prepend.
fn inject_into_html(body: &Bytes, tag: &str) -> Bytes {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    if let Some(i) = lower.find("</head>") {
        let mut out = String::with_capacity(text.len() + tag.len());
        out.push_str(&text[..i]);
        out.push_str(tag);
        out.push_str(&text[i..]);
        return Bytes::from(out);
    }
    if let Some(i) = lower.find("<body") {
        if let Some(close) = text[i..].find('>') {
            let pos = i + close + 1;
            let mut out = String::with_capacity(text.len() + tag.len());
            out.push_str(&text[..pos]);
            out.push_str(tag);
            out.push_str(&text[pos..]);
            return Bytes::from(out);
        }
    }
    let mut out = String::with_capacity(text.len() + tag.len());
    out.push_str(tag);
    out.push_str(&text);
    Bytes::from(out)
}

/// Set/replace a header (empty value deletes); used by response scripts.
fn set_header_raw(headers: &mut hyper::HeaderMap, name: &str, value: &str) {
    let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if value.is_empty() {
        headers.remove(&name);
    } else if let Ok(v) = hyper::header::HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Ensure a correct `Host` header for the upstream request.
fn ensure_host_header(
    headers: &mut hyper::HeaderMap,
    host: &str,
    port: u16,
    scheme: &str,
) {
    let default_port = if scheme == "https" { 443 } else { 80 };
    let value = if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    if let Ok(v) = hyper::header::HeaderValue::from_str(&value) {
        headers.insert(hyper::header::HOST, v);
    }
}

/// Parse `host:port` out of a CONNECT authority.
fn authority_host_port(uri: &Uri) -> Option<(String, u16)> {
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(443);
    Some((host, port))
}

#[cfg(test)]
mod pipe_wiring_tests {
    use super::*;
    use crate::plugins::pipe::{Dir, PipeMeta};

    /// Server state backed by a throwaway storage dir, so running the tests
    /// never touches the developer's real `~/.whistle-rs`.
    /// A private storage dir per call: these tests run in parallel threads, and
    /// sharing one made them race to write the root CA, which surfaced as an
    /// occasional "PEM error: malformed".
    fn state() -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-pipe-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, RuleManager::new(), ca))
    }

    fn headers_with_length() -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::CONTENT_LENGTH, "9".parse().unwrap());
        h
    }

    /// The non-negotiable: with no streaming plugin matched, the body comes back
    /// still lazy. Proven by sending its frames only *after* `pipe_body` has
    /// returned — a body that had been collected could not carry them.
    #[test]
    fn no_pipe_plugin_leaves_the_body_streaming() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            let (tx, source) = body::channel(4);

            let out = pipe_body(&state, &[], Dir::Response, PipeMeta::default(), &mut headers, source).await;

            // Nothing was read, so these frames still reach the client.
            tokio::spawn(async move {
                for part in ["not ", "buffered"] {
                    tx.send(Ok(Bytes::from_static(part.as_bytes()))).await.ok();
                }
            });
            let bytes = collect_body(out).await.expect("body");
            assert_eq!(bytes, Bytes::from_static(b"not buffered"));
            // And the framing headers are untouched — only a plugin that
            // actually takes the stream may change the body's length.
            assert_eq!(headers.get(hyper::header::CONTENT_LENGTH).unwrap(), "9");
        });
    }

    /// A `pipe://` match whose plugin declares no streaming hook is equally
    /// inert — the fallback to the buffered path must not disturb the body.
    #[test]
    fn matched_plugin_without_the_hook_is_inert() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            // `stamp` serves the buffered response hook, never a streaming one.
            let matches = vec![crate::plugins::PluginMatch {
                name: "stamp".to_string(),
                param: String::new(),
                pipe_value: None,
                via_pipe: true,
            }];
            let out = pipe_body(
                &state,
                &matches,
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                body::full("as-is"),
            )
            .await;
            assert_eq!(collect_body(out).await.expect("body"), Bytes::from_static(b"as-is"));
            assert_eq!(headers.get(hyper::header::CONTENT_LENGTH).unwrap(), "9");
        });
    }

    /// A plugin that does take the stream transforms it and drops the length
    /// headers, since the transform may change the body's size.
    #[test]
    fn pipe_plugin_takes_the_stream_and_drops_length() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            let matches = vec![crate::plugins::PluginMatch {
                name: "upper".to_string(),
                param: String::new(),
                pipe_value: Some("v".to_string()),
                via_pipe: true,
            }];
            let out = pipe_body(
                &state,
                &matches,
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                body::full("shout"),
            )
            .await;
            assert_eq!(collect_body(out).await.expect("body"), Bytes::from_static(b"SHOUT"));
            assert!(headers.get(hyper::header::CONTENT_LENGTH).is_none());
        });
    }
}

#[cfg(test)]
mod internal_req_tests {
    use super::*;

    fn marked(value: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(INTERNAL_REQ_HEADER, value.parse().unwrap());
        h
    }

    /// The marker flags the request *and* is consumed, so nothing downstream —
    /// a `includeFilter://reqH.` condition, a plugin, the capture, the origin server —
    /// ever sees it.
    #[test]
    fn marker_is_consumed() {
        let mut h = marked("1");
        assert!(take_internal_marker(&mut h));
        assert!(h.get(INTERNAL_REQ_HEADER).is_none());
    }

    /// A missing or empty marker is an ordinary client request; an empty one is
    /// still stripped.
    #[test]
    fn unmarked_request_is_client_scoped() {
        assert!(!take_internal_marker(&mut hyper::HeaderMap::new()));
        let mut h = marked("");
        assert!(!take_internal_marker(&mut h));
        assert!(h.get(INTERNAL_REQ_HEADER).is_none());
    }

    /// The end of the chain: the flag the pipeline derives from the header is
    /// what makes `internalOnly` lines visible and plain lines invisible.
    #[test]
    fn scope_reaches_rule_resolution() {
        let mut mgr = RuleManager::new();
        mgr.set_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2 lineProps://internalOnly\n",
        );
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        assert_eq!(mgr.resolve_scoped(&info, false).value("host"), Some("1.1.1.1"));
        assert_eq!(mgr.resolve_scoped(&info, true).value("host"), Some("2.2.2.2"));
    }
}
