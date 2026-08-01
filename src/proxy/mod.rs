//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
#[cfg(test)]
mod bench;
pub mod body;
pub mod coding;
pub mod dest;
pub mod persist;
pub mod script;
pub mod sni;
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

/// Request header saying "this request was https before the hop that carried it
/// here" — whistle's `config.HTTPS_FIELD`
/// (`'x-whistle-https-request'`, `_original/lib/util/common.js:160`).
///
/// An `internal-*` or `https2http-proxy://` hop deliberately hands the next
/// whistle a plaintext request so it can be inspected, and sets this header so
/// the scheme is not lost on the way (`_original/lib/inspectors/res.js:229-234`).
/// We set it when we are the sending side and honour it when we are the
/// receiving one (`lib/init.js:190-193`), which is what makes a chain of two
/// whistles behave like one.
pub const HTTPS_REQ_HEADER: &str = "x-whistle-https-request";

/// Add [`HTTPS_REQ_HEADER`] when the hop we are about to make strips the
/// origin's TLS, so the whistle on the far side knows the request was https.
fn mark_stripped_tls(headers: &mut hyper::HeaderMap, target: &upstream::Target) {
    if target.origin_tls_stripped {
        headers.insert(
            hyper::header::HeaderName::from_static(HTTPS_REQ_HEADER),
            hyper::header::HeaderValue::from_static("1"),
        );
    }
}

/// Strip the stripped-TLS marker, reporting whether it was present. Like the
/// internal marker it is consumed on arrival, so it never reaches a rule
/// condition, the capture, or the origin.
fn take_https_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(HTTPS_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Request header saying "the Web UI replayed this" — whistle's
/// `config.FROM_COM_HEADER` (`'x-whistle-composer-<uid>'`,
/// `_original/lib/config.js:93`), the marker behind `from:composer`.
///
/// Sent by [`webui::do_replay`] on the loopback hop through our own port and
/// consumed here, so it reaches neither the rules' header conditions nor the
/// origin — whistle deletes its own the same way
/// (`parseClientInfo`, `_original/lib/util/index.js:3391-3396`). The name is
/// fixed rather than per-process for the same reason the internal marker's is:
/// a stable one is what lets a client exercise the condition deliberately.
pub const COMPOSER_REQ_HEADER: &str = "x-whistle-composer";

/// Strip the composer marker, reporting whether it was present.
fn take_composer_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(COMPOSER_REQ_HEADER) {
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
    /// Told about every completed transaction, for a program that has embedded
    /// this proxy and wants the traffic rather than the console. Set once,
    /// before serving; see [`AppState::observe`].
    observer: std::sync::OnceLock<SessionObserver>,
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
            observer: std::sync::OnceLock::new(),
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

    /// Be told about every transaction as it completes.
    ///
    /// For an **embedding** program: a proxy inside another application usually
    /// wants the traffic delivered, not polled out of `/sessions.json`. The
    /// callback runs on the request's own task, after the response has gone to
    /// the client and before the session enters the ring buffer, so it must be
    /// quick — hand the work to a channel if it is not.
    ///
    /// Settable once, before serving. A second call is ignored rather than
    /// replacing the first, so a library consumer cannot silently lose the
    /// observer another part of the program installed.
    pub fn observe(&self, f: impl Fn(&Session) + Send + Sync + 'static) {
        let _ = self.observer.set(Box::new(f));
    }

    /// Record a transaction, assigning it an id which is returned so callers
    /// (e.g. WebSocket tunnels) can correlate later frames with it.
    fn record(&self, mut session: Session) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        session.id = id;
        if let Some(observe) = self.observer.get() {
            observe(&session);
        }
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

/// A callback told about each completed transaction — see [`AppState::observe`].
pub type SessionObserver = Box<dyn Fn(&Session) + Send + Sync>;

/// Longest body prefix retained for the inspection preview (per body).
pub const BODY_PREVIEW_CAP: usize = 16 * 1024;

/// A streaming decompressor for the capture preview. It decodes `Content-Encoding`
/// so the preview shows readable text; the *proxied* body is never touched.
#[derive(Default)]
enum BodyDecoder {
    /// No (or unknown) encoding — bytes stored verbatim.
    #[default]
    Identity,
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    /// A decode error occurred — stop decoding this body.
    Failed,
    /// Nothing left to decode: the preview filled up, or the body ended. The
    /// decompressor has been dropped, and with it the decompressed bytes it
    /// was holding — see [`CaptureState::release_decoder`].
    Done,
}

impl BodyDecoder {
    /// Whether this variant owns a decompressor (and therefore a buffer).
    fn is_decompressor(&self) -> bool {
        matches!(
            self,
            BodyDecoder::Gzip(_) | BodyDecoder::Deflate(_) | BodyDecoder::Brotli(_)
        )
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
            // Preview already full — stop decoding/copying. `release_decoder`
            // has already run, so there is no buffer left to grow either.
            return;
        }
        let mut failed = false;
        match &mut self.decoder {
            BodyDecoder::Identity => {
                let room = cap - self.data.len();
                let take = room.min(bytes.len());
                self.data.extend_from_slice(&bytes[..take]);
            }
            BodyDecoder::Failed | BodyDecoder::Done => {}
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
        } else if self.data.len() >= cap {
            self.release_decoder();
        }
    }

    /// Drop the decompressor once it can contribute nothing further.
    ///
    /// A `write`-side decompressor accumulates *everything* it has inflated in
    /// an internal `Vec`, which [`drain_decoder`] only ever reads a bounded
    /// prefix of. Holding one after the preview is complete pins the whole
    /// decompressed body: a 16 MiB response of highly compressible bytes
    /// arrives as one 16 KiB frame that inflates in full before the 16 KiB
    /// preview is taken off the front of it. The capture then lives on in the
    /// session ring — 500 entries deep — still holding all 16 MiB.
    ///
    /// Only a decompressor is released. `Identity` stays as it is, because
    /// [`Capture::snapshot`] reads that variant to decide `truncated`.
    fn release_decoder(&mut self) {
        if self.decoder.is_decompressor() {
            self.decoder = BodyDecoder::Done;
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
        {
            let mut st = c.0.lock().unwrap();
            st.append(bytes);
            // The whole body was in `bytes`; nothing follows it.
            st.release_decoder();
        }
        c
    }

    /// The body has ended, so no further bytes can arrive. Releases the
    /// decompressor for a body that finished before filling the preview —
    /// without this, every small compressed response leaves an inflate state
    /// and its buffer alive for as long as the session is retained.
    pub fn finish(&self) {
        self.0.lock().unwrap().release_decoder();
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

    /// Bytes the capture's decompressor is still holding.
    fn decoder_bytes(cap: &Capture) -> usize {
        match &cap.0.lock().unwrap().decoder {
            BodyDecoder::Gzip(d) => d.get_ref().len(),
            BodyDecoder::Deflate(d) => d.get_ref().len(),
            BodyDecoder::Brotli(d) => d.get_ref().len(),
            _ => 0,
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A `write`-side decompressor keeps everything it has inflated, and the
    /// capture outlives the body by up to [`MAX_SESSIONS`] entries. Once the
    /// preview is full the decompressor must be let go, or one highly
    /// compressible response pins its whole decompressed size for as long as
    /// the session is retained.
    #[test]
    fn a_full_preview_releases_the_decompressor() {
        let body = gzip(&vec![b'a'; 8 * 1024 * 1024]);
        assert!(body.len() < BODY_PREVIEW_CAP, "8 MiB of 'a' fits in one frame");
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&body);

        let (len, truncated, text) = cap.snapshot();
        assert_eq!(len, body.len(), "len still counts wire bytes");
        assert!(truncated);
        assert_eq!(text.len(), BODY_PREVIEW_CAP, "the preview is still filled");
        assert!(text.bytes().all(|b| b == b'a'), "and still decoded");
        assert_eq!(
            decoder_bytes(&cap),
            0,
            "8 MiB of inflated bytes must not outlive the preview that needed 16 KiB of them"
        );
    }

    /// A body that ends before filling the preview never trips the cap, so the
    /// release has to happen at end-of-stream too.
    #[test]
    fn a_finished_body_releases_the_decompressor() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&gzip(b"small enough to fit"));
        assert!(decoder_bytes(&cap) > 0, "still decoding: the body may continue");

        cap.finish();
        assert_eq!(decoder_bytes(&cap), 0);
        let (_, _, text) = cap.snapshot();
        assert_eq!(text, "small enough to fit", "the preview survives the release");
    }

    /// Releasing must not disturb an identity capture: [`Capture::snapshot`]
    /// reads that variant to decide whether the preview was truncated.
    #[test]
    fn releasing_leaves_an_identity_capture_alone() {
        let cap = Capture::new(Some("text/plain".into()), None, 8);
        cap.append(b"0123456789");
        cap.finish();
        let (len, truncated, text) = cap.snapshot();
        assert_eq!((len, truncated, text.as_str()), (10, true, "01234567"));
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

/// Convert a plugin-produced response into a real HTTP response, body and all.
///
/// The body stays a `Bytes` rather than becoming a stream because every response
/// operator and every plugin response hook still has to run over it — see
/// [`finish_local_response`].
fn plugin_response(resp: crate::plugins::PluginResp) -> Response<Bytes> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    let body = Bytes::from(resp.body);
    builder.body(body.clone()).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(body)
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
    /// True when `enable://ignoreSend|ignoreReceive` discarded this frame: it
    /// was seen and recorded, but never delivered to the peer. Upstream marks
    /// the same thing (`ignore`, `_original/lib/socket-mgr.js:401,:531`) so the
    /// view shows a dropped frame rather than a gap.
    pub ignored: bool,
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
            ignored: false,
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
    /// indicates the tunnel was TLS-decrypted (scheme https) vs. plain (http);
    /// `sni` says the ClientHello named a server, which is what `from:sni`
    /// asks (`checkSNI`, `_original/lib/https/index.js:1281`).
    Mitm {
        host: String,
        port: u16,
        tls: bool,
        sni: bool,
    },
}

/// Start the proxy and serve until the process exits.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let (listener, _addr) = bind(&state).await?;
    accept_loop(state, listener, None).await
}

/// Bind the proxy's listening socket and announce it, without accepting yet.
///
/// Split out of [`run`] for the sake of an **embedding** program: with
/// `port: 0` the operating system chooses the port, and the only way to learn
/// which one is to ask the bound socket. Returning it before the accept loop
/// starts means the embedder can hand the address to whatever it is configuring
/// without racing the first connection. See [`crate::embed`].
pub async fn bind(state: &Arc<AppState>) -> Result<(TcpListener, SocketAddr)> {
    let requested = SocketAddr::new(
        state
            .config
            .host
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
        state.config.port,
    );
    let listener = TcpListener::bind(requested).await?;
    let addr = listener.local_addr().unwrap_or(requested);
    tracing::info!("whistle-rs listening on http://{addr}");

    // Teach the forwarding layer which addresses are *us*, so a `proxy://` rule
    // naming this proxy is refused instead of recursing into it. Registered
    // before the first connection is accepted; see `upstream::self_loop`.
    // The *bound* port, not the requested one, or port 0 would register nothing.
    let mut own_ports = vec![addr.port()];
    own_ports.extend(state.config.socks_port);
    upstream::set_listen(state.config.host, &own_ports);
    tracing::info!(
        "root CA: {} (download at http://{}/rootCA.crt)",
        state.config.root_ca_cert_path().display(),
        addr
    );
    Ok((listener, addr))
}

/// Accept connections until `shutdown` resolves (or forever, if it is `None`).
///
/// The optional shutdown is what lets an embedded proxy be stopped: a binary
/// runs until the process ends, but a proxy inside another program has to be
/// able to go away without taking its host with it.
pub async fn accept_loop(
    state: Arc<AppState>,
    listener: TcpListener,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<()> {
    // Optional inbound SOCKS5 server.
    if let Some(socks_port) = state.config.socks_port {
        let socks_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = socks::run(socks_state, socks_port).await {
                tracing::error!("SOCKS server error: {e}");
            }
        });
    }

    // `Either` rather than a `select!` per iteration: with no shutdown channel
    // there is nothing to poll, and the binary's hot loop should not pay for a
    // feature only the library uses.
    let mut shutdown = shutdown;
    loop {
        let accepted = match &mut shutdown {
            None => listener.accept().await,
            Some(stop) => tokio::select! {
                biased;
                _ = &mut *stop => {
                    tracing::info!("whistle-rs shutting down");
                    return Ok(());
                }
                accepted = listener.accept() => accepted,
            },
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { top_level(state, req, peer).await }
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
    peer: SocketAddr,
) -> Result<Response<DynBody>, Infallible> {
    if req.method() == hyper::Method::CONNECT {
        return Ok(handle_connect(state, req, peer));
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return Ok(guard(serve(state, req, Origin::Forward, peer).await));
    }
    Ok(webui::handle(&state, req).await)
}

/// Handle a CONNECT: acknowledge, then intercept the tunnel with MITM.
fn handle_connect(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: SocketAddr,
) -> Response<DynBody> {
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
    mut stream: S,
    host: String,
    port: u16,
    peer: SocketAddr,
    tls: bool,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if tls {
        // Read the ClientHello before deciding anything, because two decisions
        // depend on it: which name the certificate has to be for, and what an
        // `sniCallback://` plugin is being asked about. The bytes are replayed
        // either way — see [`sni`].
        let hello = sni::peek_client_hello(&mut stream).await;
        let has_sni = hello.server_name.is_some();
        // The name the client will check is the one it asked for; the tunnel's
        // own hostname is only the fallback for a client that asked for nothing
        // (upstream's `useSNI || socket.tunnelHostname`).
        let servername = hello.server_name.unwrap_or_else(|| host.clone());
        let stream = sni::Prefixed::new(hello.prefix, stream);
        let acceptor =
            match sni::decide(&state, &servername, &host, port, peer, has_sni).await {
                sni::Decision::Generated => state.ca.acceptor_for(&servername)?,
                sni::Decision::Plugin(acceptor) => acceptor,
                sni::Decision::Bypass(target) => return sni::relay(stream, &target).await,
                // A proxy rule that cannot be honoured closes the connection
                // rather than quietly sending the bytes direct — the same call
                // the request path makes, where it answers 502.
                sni::Decision::Unroutable(why) => {
                    return Err(anyhow::anyhow!("tunnel to {host}:{port} not routable: {why}"));
                }
            };
        let tls_stream = acceptor.accept(stream).await?;
        let conn = tls_stream.get_ref().1;
        let is_h2 = conn.alpn_protocol() == Some(b"h2");
        // Read once, off the completed handshake: whether the client named a
        // server in its ClientHello. Costs nothing — rustls already parsed it to
        // pick a certificate. Deliberately not taken from `has_sni` above, so
        // `from:sni` keeps answering off the handshake rustls actually
        // completed, exactly as it did before the peek existed.
        let sni = conn.server_name().is_some();
        if is_h2 {
            serve_intercepted_h2(state, TokioIo::new(tls_stream), host, port, peer, sni).await
        } else {
            serve_intercepted(state, TokioIo::new(tls_stream), host, port, peer, true, sni).await
        }
    } else {
        // No handshake, so no SNI — a plain-HTTP tunnel is `from:tunnel` but
        // never `from:sni`.
        serve_intercepted(state, TokioIo::new(stream), host, port, peer, false, false).await
    }
}

/// Serve an intercepted HTTP/2 connection (ALPN negotiated `h2`). Upstream
/// forwarding stays HTTP/1.1 — hyper translates request/response between them.
async fn serve_intercepted_h2<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: SocketAddr,
    sni: bool,
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
            sni,
        };
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, peer).await)) }
    });

    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Run the HTTP/1.1 server over an already-prepared tunnel IO.
#[allow(clippy::too_many_arguments)]
async fn serve_intercepted<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: SocketAddr,
    tls: bool,
    sni: bool,
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
            sni,
        };
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, peer).await)) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

/// Resolve the rules a second time, now that the response head is in, and fold
/// the result into `resolved`.
///
/// This is whistle's response phase (`pluginMgr.getResRules` →
/// `rulesMgr.resolveResRules`, `_original/lib/plugins/index.js:1322-1336`),
/// which runs for **every** response — from the origin or from a rule that
/// answered locally — before any response operator or plugin hook has touched
/// it. Same here: `res` is built from the head exactly as it arrived.
///
/// Costs nothing when no rule mentions the response: the manager answers that
/// from a list of candidate lines its groups precompute, and this returns
/// without walking a single rule.
///
/// Locking: takes the two `std::sync` read locks one after the other, never
/// nested and never across an `.await` — there is none here, which is what lets
/// this be called from `serve`'s future.
fn resolve_response_phase(
    state: &AppState,
    info: &mut ReqInfo,
    resolved: &mut Resolved,
    res: crate::rules::ResInfo,
    is_internal_req: bool,
    merged: &[crate::rules::RuleManager],
) {
    info.res = Some(res);
    // Rules merged in mid-request get the same second pass. Upstream re-resolves
    // its `pRules`/`fRules`/`hRules` here too
    // (`_original/lib/plugins/index.js:1326-1335`); each manager answers from
    // its own precomputed flags, so a text with no response-dependent line
    // costs one comparison.
    if let Some(mut extra) = apply::response_phase_of(merged, info, is_internal_req) {
        {
            let values = state.values.read().unwrap();
            apply::substitute_values(&mut extra, &values);
        }
        apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
        resolved.merge_response_phase(extra);
    }
    let extra = {
        let rules = state.rules.read().unwrap();
        rules.resolve_response(info, is_internal_req)
    };
    let Some(mut extra) = extra else {
        return;
    };
    tracing::debug!(
        "{} {} -> re-resolving rules for status {}",
        info.method,
        info.full_url,
        info.res.as_ref().map(|r| r.status).unwrap_or_default()
    );
    {
        let values = state.values.read().unwrap();
        apply::substitute_values(&mut extra, &values);
    }
    apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
    resolved.merge_response_phase(extra);
}

/// The address the request actually went to.
///
/// It comes from the socket: `TcpStream::connect` picks among the resolver's
/// answers without saying which, and asking the resolver a second time can
/// answer differently under round-robin DNS, so the connected peer is the only
/// honest source. Through an upstream proxy that peer is the *proxy*, which is
/// what whistle reports too (`req.hostIp` is set from the resolved proxy
/// address when a proxy rule matched, `_original/lib/inspectors/res.js:238,:259`).
///
/// The `connect_host` fallback covers the case where no connection was made at
/// all; `serverIp:` then stays unanswerable and fails closed rather than
/// matching on a guess.
fn known_server_ip(target: &upstream::Target, reached: Option<SocketAddr>) -> Option<String> {
    reached.map(|a| a.ip().to_string()).or_else(|| {
        target
            .connect_host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string())
    })
}

/// The response-side operators that act on the body once it is in hand.
///
/// Gathered in one place because more than one exit produces a response: the
/// origin's, a `plugin://` hook's, and a short-circuit rule's. whistle runs the
/// same response inspectors over all three (`_original/lib/inspectors/res.js`
/// is reached whether the bytes came from a server, a plugin, or a local file),
/// so they must run the same set here too.
struct ResBodyOps {
    /// `resSpeed://` — throttle, in kB/s.
    speed: Option<f64>,
    /// `resScript://` — the loaded source, not the rule value.
    script: Option<String>,
    /// `weinre://` — debug-agent id to inject.
    weinre: Option<String>,
    /// `locationHref://` — client-side redirect to inject.
    location_href: Option<String>,
    /// `resWrite://` / `resWriteRaw://` — dump paths.
    write: Option<String>,
    write_raw: Option<String>,
    /// `trailers://` — trailing headers to append after the body.
    trailers: hyper::HeaderMap,
    /// Any content operator (`resReplace`, `htmlAppend`, `resBody`, …).
    content: bool,
}

impl ResBodyOps {
    fn of(resolved: &Resolved) -> Self {
        ResBodyOps {
            speed: apply::res_speed_kbps(resolved),
            script: apply::res_script_op(resolved)
                .map(|op| op.value.as_str())
                .and_then(script::load_script),
            weinre: resolved.value("weinre").map(|s| s.to_string()),
            location_href: resolved.value("locationHref").map(|s| s.to_string()),
            write: apply::res_write_path(resolved),
            write_raw: apply::res_write_raw_path(resolved),
            trailers: apply::build_trailers(resolved),
            content: apply::wants_res_body(resolved),
        }
    }

    /// True when at least one of these needs the whole body in memory. A
    /// response no operator touches never gets collected — that is what keeps
    /// the streaming path streaming.
    fn needs_body(&self) -> bool {
        self.content
            || self.speed.is_some()
            || self.script.is_some()
            || self.weinre.is_some()
            || self.location_href.is_some()
            || self.write.is_some()
            || self.write_raw.is_some()
            || !self.trailers.is_empty()
    }
}

/// The operators that rewrite an already-transformed body: `resScript://`, the
/// two HTML injections, and the two dump paths. Runs after
/// [`apply::transform_res_body`] and after any plugin response-body hook.
fn inject_res_body(
    state: &AppState,
    parts: &mut hyper::http::response::Parts,
    mut new: Bytes,
    ops: &ResBodyOps,
    info: &ReqInfo,
) -> Bytes {
    if let Some(src) = &ops.script {
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
            if let Some(st) = r.status
                && let Ok(s) = StatusCode::from_u16(st)
            {
                parts.status = s;
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
    if let Some(id) = &ops.weinre
        && is_html(&parts.headers)
    {
        let src = weinre_src(id, &state.config);
        let tag = format!("<script src=\"{src}\"></script>");
        new = inject_into_html(&new, &tag);
    }
    // locationHref: inject a client-side redirect into HTML responses.
    if let Some(url) = &ops.location_href
        && is_html(&parts.headers)
    {
        let safe = url.replace('\\', "\\\\").replace('\'', "\\'");
        let tag = format!("<script>location.href='{safe}'</script>");
        new = inject_into_html(&new, &tag);
    }
    if let Some(path) = &ops.write {
        write_body_file(path, &new);
    }
    if let Some(path) = &ops.write_raw {
        let head = format!(
            "HTTP/1.1 {}\r\n{}",
            parts.status,
            header_dump(&parts.headers)
        );
        write_raw_file(path, &head, &new);
    }
    new
}

/// Frame a finished in-memory body: drop the now-stale length headers, then
/// hand it to whichever of `trailers://` / `resSpeed://` asked for it.
fn finish_res_body(
    parts: &mut hyper::http::response::Parts,
    new: Bytes,
    ops: ResBodyOps,
) -> DynBody {
    apply::strip_length_headers(&mut parts.headers);
    if !ops.trailers.is_empty() {
        // Trailers need chunked transfer; ensure HTTP/1.1 (upstream may be 1.0).
        parts.version = hyper::Version::HTTP_11;
        let names = ops
            .trailers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        set_header_raw(&mut parts.headers, "trailer", &names);
        body::with_trailers(new, ops.trailers)
    } else {
        match ops.speed {
            Some(kbps) => body::throttled(new, kbps),
            None => body::full(new),
        }
    }
}

/// The plugin audience a locally produced response still owes its hooks to.
///
/// [`Default`] is nobody — two empty slices — which is what a path with no
/// plugin in sight passes, so the hook loops below cost one `is_empty` each.
#[derive(Default)]
struct ResHooks<'a> {
    /// Plugins matched for this request, in rule order: the `POST /response`
    /// audience. Held as `(name, param)` because that is what the request hook
    /// already built.
    plugins: &'a [(String, String)],
    /// `pipe://` plugins matched for this request, in rule order.
    pipes: &'a [crate::plugins::PluginMatch],
    /// Correlation id, shared with the request hook of the same request.
    req_id: u64,
    /// The client address, as the request hook reported it.
    client_ip: Option<String>,
}

/// Serve an [`auth`](crate::plugins::auth) gate's refusal exactly as the gate
/// produced it: no response-phase rules, no response operators, no plugin hooks.
///
/// Upstream pins it the same way, and this is what its pinning *means*: the
/// denial comes back as `* ignore://!statusCode|!resBody|!resType|!resCharset …`
/// (`_original/lib/plugins/index.js:936-959`), and `ignore://!x` is an inverted
/// whitelist — `ignoreRules` walks every resolved rule and deletes all but the
/// excluded names, plugin rules included (`lib/util/index.js:2068-2092,:2008`).
/// So on a refusal no user rule applies, which is the property worth keeping: a
/// gate a `resHeaders://` line or another plugin can rewrite is not a gate.
///
/// Returns the response and the body preview to record with it, like
/// [`finish_local_response`] — the transaction is still logged.
fn pin_refusal(state: &AppState, res: Response<Bytes>) -> (Response<DynBody>, Option<Capture>) {
    let (parts, bytes) = res.into_parts();
    let ct = header_str(&parts.headers, hyper::header::CONTENT_TYPE);
    let enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let capture = (!bytes.is_empty()).then(|| {
        Capture::from_bytes(&bytes, ct, enc.as_deref(), state.config.body_preview_cap)
    });
    (Response::from_parts(parts, body::full(bytes)), capture)
}

/// Finish a response this proxy produced itself — a `plugin://` hook's answer,
/// or a short-circuit rule's — by resolving the response phase and running every
/// response operator over it.
///
/// whistle reaches its response inspectors on both paths: a `plugin://` rule
/// proxies the request to the plugin's own server, so the plugin's answer comes
/// back as an ordinary response and goes through `handleResponse`
/// (`pluginMgr.getResRules`, `_original/lib/inspectors/res.js:825`), and a
/// locally served `file://` takes the same route. `res` is built from the head
/// as produced, before any operator has touched it — which is what lets `s:`
/// filter on a `statusCode://404` this port answered.
///
/// `hooks` is the plugin audience for the finished response. Upstream reaches its
/// response-side plugin machinery on both these paths as well: a `plugin://`
/// answer travels back as an ordinary response and goes through `handleResponse`
/// (`_original/lib/inspectors/res.js:825`), and a `pipe://` plugin is resolved
/// from its own rule with no regard for who produced the bytes
/// (`resolvePipePlugin`, `_original/lib/plugins/index.js:1173`).
///
/// `res` is the response as produced, body and all — it is wholly in memory on
/// both these paths, which is what lets the body operators and the buffered hooks
/// run over it without waiting on anything.
///
/// Returns the finished response and the body preview to record with it.
async fn finish_local_response(
    state: &Arc<AppState>,
    info: &mut ReqInfo,
    resolved: &mut Resolved,
    merged_rules: &[crate::rules::RuleManager],
    is_internal_req: bool,
    res: Response<Bytes>,
    hooks: ResHooks<'_>,
) -> (Response<DynBody>, Option<Capture>) {
    let (mut parts, bytes) = res.into_parts();
    resolve_response_phase(
        state,
        info,
        resolved,
        // No connection was made, so `serverIp:`/`serverPort:` stay unanswerable
        // and fail closed rather than matching on a guess.
        apply::build_res_info(parts.status.as_u16(), &parts.headers, None, None),
        is_internal_req,
        merged_rules,
    );
    if let Some(ms) = apply::res_delay_ms(resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    apply::apply_response_for(&mut parts, resolved, Some(info));

    // Response hook, part 1: plugins that did not ask for the body. Such a
    // plugin may still replace it outright — that needs no knowledge of the
    // original. The plugin that produced this response is in the audience too:
    // upstream builds the response pipeline from *every* matched plugin, so one
    // that both answers and hooks the response does see its own answer.
    let mut bytes = bytes;
    let mut hook_replaced = false;
    let mut wants_body = false;
    for (name, param) in hooks.plugins {
        let Some(manifest) = state.plugins.manifest(name).await else {
            continue;
        };
        if !manifest.on_response {
            continue;
        }
        if manifest.response_body {
            wants_body = true;
            continue; // handled below, once the body is in hand
        }
        let pres = crate::plugins::PluginRes {
            id: hooks.req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
            param: param.clone(),
            body: None,
        };
        if let Some(result) = state.plugins.on_response(name, &pres).await
            && let Some(new) = apply_plugin_res_result(&mut parts, result)
        {
            bytes = Bytes::from(new);
            hook_replaced = true;
        }
    }

    // Streaming hook: a `pipe://` plugin transforms the bytes on their way out.
    // The body is wholly in memory on this path — a plugin's answer, or a mocked
    // response — so it is framed, piped and collected straight back. That is the
    // same work the streaming path does, in a different order, and it keeps one
    // implementation of the hook rather than two.
    if !hooks.pipes.is_empty() {
        let piped = pipe_body(
            state,
            hooks.pipes,
            crate::plugins::pipe::Dir::Response,
            crate::plugins::pipe::PipeMeta {
                id: hooks.req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                client_ip: hooks.client_ip.clone(),
                headers: header_pairs(&parts.headers),
                status: Some(parts.status.as_u16()),
                ..Default::default()
            },
            &mut parts.headers,
            body::full(bytes.clone()),
        )
        .await;
        // A plugin that serves no response pipe hands the body back untouched,
        // so this collects the same bytes. One that takes it may change the
        // length — `pipe_body` has already dropped the headers for that.
        match collect_body(piped).await {
            Ok(new) => bytes = new,
            // The transform broke mid-stream. There is nothing left to send but
            // what the pipe managed to produce, which is nothing.
            Err(err) => {
                tracing::debug!("response pipe failed: {err:#}");
                bytes = Bytes::new();
                hook_replaced = true;
            }
        }
    }

    let ops = ResBodyOps::of(resolved);
    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let (new, res_enc) = if ops.needs_body() || wants_body {
        // Decode before rewriting, re-encode after — the same treatment the
        // upstream path gives a compressed body. A plugin answer or a mocked
        // response rarely arrives encoded, but `enable://gzip` can still ask for
        // one on the way out, and a plugin is free to send `Content-Encoding`.
        let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref());
        let mut new = apply::transform_res_body(decoded.body, resolved, res_ct.as_deref());

        // Response hook, part 2: plugins that asked for the body. It sits
        // between the content operators and the injections — the same slot the
        // streaming path gives it.
        for (name, param) in hooks.plugins {
            let Some(manifest) = state.plugins.manifest(name).await else {
                continue;
            };
            if !manifest.on_response || !manifest.response_body {
                continue;
            }
            let pres = crate::plugins::PluginRes {
                id: hooks.req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                status: parts.status.as_u16(),
                headers: header_pairs(&parts.headers),
                param: param.clone(),
                body: Some(new.to_vec()),
            };
            if let Some(result) = state.plugins.on_response(name, &pres).await
                && let Some(replaced) = apply_plugin_res_result(&mut parts, result)
            {
                new = Bytes::from(replaced);
                hook_replaced = true;
            }
        }
        let new = inject_res_body(state, &mut parts, new, &ops, info);
        let (new, encoded_as) =
            coding::reencode(new, decoded.restore, apply::forced_encoding(resolved));
        coding::set_content_encoding(&mut parts.headers, encoded_as);
        (new, encoded_as.header_value().map(str::to_string))
    } else {
        (bytes, res_enc)
    };
    let capture = (!new.is_empty()).then(|| {
        Capture::from_bytes(
            &new,
            res_ct,
            res_enc.as_deref(),
            state.config.body_preview_cap,
        )
    });
    // `finish_res_body` drops the length headers, which a body nothing rewrote
    // still has correctly set — so only take that route when something did.
    let body = match ops.needs_body() {
        true => finish_res_body(&mut parts, new, ops),
        false => {
            // A hook that replaced the body invalidated the length its producer
            // declared; dropping the header lets hyper write the true one.
            if hook_replaced {
                apply::strip_length_headers(&mut parts.headers);
            }
            body::full(new)
        }
    };
    (Response::from_parts(parts, body), capture)
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
    peer: SocketAddr,
) -> Result<Response<DynBody>> {
    let client_ip = Some(peer.ip().to_string());
    // Consumed before anything else looks at the headers, exactly like whistle
    // deletes its own marker on arrival: rule filters, plugins, the capture and
    // the origin server must never see it.
    let is_internal_req = take_internal_marker(req.headers_mut());
    // Consumed here too: an upstream whistle stripped this request's TLS for the
    // hop, and the scheme it arrived under is not the one the rules should see.
    let was_https = take_https_marker(req.headers_mut());
    // Consumed here too, and for the same reason: it is this proxy's own marker,
    // not the client's, so nothing downstream may see it.
    let from_composer = take_composer_marker(req.headers_mut());

    // Derive scheme/host/port/path for matching.
    let (scheme, host, port, path) = match &origin {
        Origin::Forward => {
            let uri = req.uri();
            let host = uri.host().unwrap_or_default().to_string();
            let mut scheme = uri.scheme_str().unwrap_or("http").to_string();
            if was_https && scheme == "http" {
                scheme = "https".to_string();
            }
            // Read after the marker, so a request restored to https and carrying
            // no explicit port lands on 443 rather than 80.
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            (scheme, host, port, path)
        }
        Origin::Mitm { host, port, tls, .. } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let scheme = if *tls { "https" } else { "http" };
            (scheme.to_string(), host.clone(), *port, path)
        }
    };

    let mut info = apply::build_req_info(
        req.method().as_str(),
        &scheme,
        &host,
        port,
        &path,
        req.headers(),
        client_ip.clone(),
    );
    // The accepted socket's port, for `clientPort:` / `remotePort:` filters.
    info.client_port = Some(peer.port());
    // Where the request came from, for `from:`. All of it is known before the
    // rules resolve — which is what makes `from:!tunnel` a real answer rather
    // than a filter that fails closed.
    info.from = crate::rules::ReqOrigin {
        tunnel: matches!(origin, Origin::Mitm { .. }),
        sni: matches!(origin, Origin::Mitm { sni: true, .. }),
        composer: from_composer,
    };

    // A `b:` filter reads the request body, so the body has to be in hand
    // *before* the rules resolve. Whether any line asks is answered from the
    // per-group candidate list each group precomputes; a rules file that never
    // mentions the body costs one `is_empty()` per group and the body keeps
    // streaming untouched.
    //
    // Locking: the read guard is dropped before the `.await` below — no guard
    // may cross one here, which is also why this cannot share the acquisition
    // with the resolution that follows.
    let needs_req_body = {
        let rules = state.rules.read().unwrap();
        rules.needs_request_body(&info, is_internal_req)
    };
    // Normalising to `DynBody` here rather than at the plugin hook lets both
    // reasons to buffer share one decision point.
    let (req, prebuffered): (Request<DynBody>, Option<Bytes>) = {
        let (parts, incoming) = req.into_parts();
        if needs_req_body {
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
    if let Some(bytes) = &prebuffered {
        // Set even when empty: upstream's `req._reqBody` is a string either way,
        // so `b:!x` holds for a request with no body rather than failing closed.
        info.req_body = Some(String::from_utf8_lossy(bytes).into_owned());
    }

    let mut resolved = state
        .rules
        .read()
        .unwrap()
        .resolve_scoped(&info, is_internal_req);
    // Rules merged in mid-request — a `rule://` value, the `rulesFile://` join,
    // and any a plugin injects below. Their parsed form is kept because the
    // response phase resolves them a second time, exactly as it does the
    // top-level rules (`apply::merge_response_phase_of`).
    let mut merged_rules: Vec<crate::rules::RuleManager> = {
        let values = state.values.read().unwrap();
        apply::substitute_values(&mut resolved, &values);
        let managers = apply::merge_included_rules(&mut resolved, &info, &values, is_internal_req);
        apply::substitute_values(&mut resolved, &values);
        managers
    };
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

    // Hand a plugin the request body if its manifest declares `requestBody`.
    // Buffering happens *only* then — otherwise the body stays a lazy stream and
    // the proxy's streaming fast path is untouched. A `b:` filter may already
    // have bought the bytes above, in which case this costs nothing but the
    // manifest lookup.
    let (req, plugin_req_body): (Request<DynBody>, Option<Bytes>) = {
        let wants_body = !plugin_matches.is_empty()
            && has_request_body(req.headers())
            && state.plugins.any_wants_request_body(&plugin_names).await;
        match (wants_body, prebuffered) {
            (false, _) => (req, None),
            (true, Some(bytes)) => (req, Some(bytes)),
            (true, None) => {
                let (parts, body) = req.into_parts();
                let bytes = collect_body(body).await?;
                (
                    Request::from_parts(parts, body::full(bytes.clone())),
                    Some(bytes),
                )
            }
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
                merged_rules.push(apply::merge_rules_text(
                    &mut resolved,
                    &info,
                    &rules,
                    is_internal_req,
                ));
                let values = state.values.read().unwrap();
                apply::substitute_values(&mut resolved, &values);
            }
            plugin_set_headers.extend(result.set_headers);
            plugin_remove_headers.extend(result.remove_headers);
            let blocked = result.blocked;
            if let Some(resp) = result.response {
                tracing::info!("{} {} -> plugin {name}", info.method, info.full_url);
                let target = format!("plugin:{name}");
                // The plugin answered, but it is not the last word: every
                // response operator still runs, exactly as it does over the
                // origin's answer. Skipping this left `resHeaders://`,
                // `replaceStatus://`, `resType://`, `trailers://` and the whole
                // body family silently inert on a path users reach on purpose.
                // An answer is an ordinary response: every response operator and
                // every response hook runs over it. A *refusal* from the auth
                // gate is served as produced — see [`pin_refusal`].
                let (response, res_body) = if blocked {
                    pin_refusal(&state, plugin_response(resp))
                } else {
                    finish_local_response(
                        &state,
                        &mut info,
                        &mut resolved,
                        &merged_rules,
                        is_internal_req,
                        plugin_response(resp),
                        ResHooks {
                            plugins: &plugin_matches,
                            pipes: &pipe_matches,
                            req_id: plugin_req_id,
                            client_ip: client_ip.clone(),
                        },
                    )
                    .await
                };
                state.record(Session {
                    id: 0,
                    time_ms,
                    method: info.method.clone(),
                    url: info.full_url.clone(),
                    status: response.status().as_u16(),
                    client_ip: client_ip.clone(),
                    target,
                    duration_ms: started.elapsed().as_millis(),
                    log: log_labels(&resolved),
                    res_headers: header_pairs(response.headers()),
                    res_body,
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
        // as well — and so must the response-phase rules, which is why a
        // `statusCode://404` this port answered can be filtered on with `s:404`.
        // Every short-circuit body is already in memory, so collecting it costs
        // nothing but lets the body operators run over it as well.
        let (parts, body) = resp.into_parts();
        let bytes = collect_body(body).await?;
        let (resp, res_body) = finish_local_response(
            &state,
            &mut info,
            &mut resolved,
            &merged_rules,
            is_internal_req,
            Response::from_parts(parts, bytes),
            ResHooks {
                plugins: &plugin_matches,
                pipes: &pipe_matches,
                req_id: plugin_req_id,
                client_ip: client_ip.clone(),
            },
        )
        .await;
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
            res_body,
            ..Default::default()
        });
        return Ok(resp);
    }

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(&state, req, &info, &resolved, client_ip, time_ms, started).await;
    }

    // Where the request is addressed, which is its own URL unless a rule pointed
    // it somewhere else — `www.example.com http://localhost:5173` and friends.
    // Resolved before the target because the target is *how* to reach it.
    let dest = dest::Destination::of(&info, &resolved);

    // Fails the request rather than silently connecting direct when a proxy rule
    // matched but could not be honoured (unusable address, unreachable or
    // throwing PAC file) — see `apply::find_proxy`.
    let target = apply::resolve_target(&info, &dest, &resolved).await?;

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
    // The origin is asked for the destination's host, not the client's — that
    // is the whole difference between a URL replacement and `host://`.
    ensure_host_header(&mut parts.headers, &dest.host, dest.port, &dest.scheme);
    parts.headers.remove("proxy-connection");
    mark_stripped_tls(&mut parts.headers, &target);
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
    if let Some(url) = resolved.value("responseFor")
        && let Ok((status, body)) = upstream::simple_get(url).await
    {
        set_header_raw(&mut parts.headers, "x-whistle-response-for-url", url);
        set_header_raw(&mut parts.headers, "x-whistle-response-for-status", &status.to_string());
        set_header_raw(
            &mut parts.headers,
            "x-whistle-response-for-length",
            &body.len().to_string(),
        );
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
    // Read after the request operators, because `method://` and `reqType://`
    // decide whether `params://` addresses the body or the query string — as
    // they do upstream (`_original/lib/inspectors/req.js:536,560-561`). That is
    // also why the path is rewritten here rather than before `apply_request`.
    let req_method = parts.method.to_string();
    let body_ctx = apply::ReqBodyCtx {
        method: &req_method,
        content_type: req_ct.as_deref(),
    };
    // From the destination's path, not the request's: a URL-replacement rule has
    // already decided what is being asked for, and `urlReplace`/`params` then
    // rewrite *that* — the same order as upstream, where `req.options` is built
    // before the request inspectors run.
    let new_path = apply::rewrite_path(&dest.path, &resolved, body_ctx);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    let req_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let mut req_body_cap: Option<Capture> = None;
    let req_body: DynBody = if apply::wants_req_body(&resolved, body_ctx)
        || req_speed.is_some()
        || req_write.is_some()
        || req_write_raw.is_some()
    {
        let bytes = collect_body(incoming).await?;
        let new = apply::transform_req_body(bytes, &resolved, body_ctx);
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

    let (upstream_resp, server_addr) = upstream::forward_with_addr(&target, out_req).await?;

    let (mut parts, body) = upstream_resp.into_parts();

    // Response phase: rules whose filters ask about the response are resolved
    // here, against the head as the origin sent it — before `resDelay://` (so a
    // delay can be conditioned on the status), before any response operator, and
    // before the plugin response hooks, which is upstream's order too
    // (`_original/lib/inspectors/res.js:823-826`).
    resolve_response_phase(
        &state,
        &mut info,
        &mut resolved,
        apply::build_res_info(
            parts.status.as_u16(),
            &parts.headers,
            known_server_ip(&target, server_addr),
            Some(target.connect_port),
        ),
        is_internal_req,
        &merged_rules,
    );

    if let Some(ms) = apply::res_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // Apply response-side rules.
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
        if let Some(result) = state.plugins.on_response(name, &pres).await
            && let Some(new) = apply_plugin_res_result(&mut parts, result)
        {
            plugin_res_override = Some(new);
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

    let ops = ResBodyOps::of(&resolved);
    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let mut res_body_cap: Option<Capture> = None;
    let res_body: DynBody =
        if ops.needs_body() || plugin_wants_res_body || plugin_res_override.is_some() {
            // A plugin that replaced the body outright makes the upstream bytes
            // irrelevant — don't wait on them.
            let bytes = match &plugin_res_override {
                Some(new) => Bytes::from(new.clone()),
                None => collect_body(body).await?,
            };
            // Decompress before rewriting. Every body operator works on text,
            // and most origins answer compressed — so without this a
            // `resReplace://` against a gzipped page searched the deflate
            // stream for its pattern, found nothing, and silently did nothing.
            // whistle reaches the same place from the other end: any body
            // transform sets `_needGunzip`, which puts a decoder in front of it
            // and a re-encoder behind (`addZipTransform`,
            // `_original/lib/inspectors/data.js:` and `inspectors/rules.js:60-140`).
            let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref());
            let mut new = apply::transform_res_body(decoded.body, &resolved, res_ct.as_deref());

            // Response hook, part 2: plugins that asked for the body. It sits
            // between the content operators and the injections, which is why
            // those two halves are separate functions.
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
                if let Some(result) = state.plugins.on_response(name, &pres).await
                    && let Some(replaced) = apply_plugin_res_result(&mut parts, result)
                {
                    new = Bytes::from(replaced);
                }
            }
            let new = inject_res_body(&state, &mut parts, new, &ops, &info);
            // Put the coding back on, so the client gets what the header
            // promises. `enable://gzip|br|deflate` asks for a *different* one
            // than arrived (`getEnableEncoding`,
            // `_original/lib/util/index.js:1534-1548`) — the only case where the
            // body leaves compressed that arrived plain.
            let (new, encoded_as) =
                coding::reencode(new, decoded.restore, apply::forced_encoding(&resolved));
            coding::set_content_encoding(&mut parts.headers, encoded_as);
            if !new.is_empty() {
                res_body_cap = Some(Capture::from_bytes(
                    &new,
                    res_ct.clone(),
                    // The preview decodes what it is told the body is, so it has
                    // to be told what the body *now* is, not what arrived.
                    encoded_as.header_value(),
                    state.config.body_preview_cap,
                ));
            }
            finish_res_body(&mut parts, new, ops)
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
    if let Some(code) = result.status
        && let Ok(s) = StatusCode::from_u16(code)
    {
        parts.status = s;
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
async fn serve_upgrade(
    state: &Arc<AppState>,
    mut req: Request<DynBody>,
    info: &ReqInfo,
    resolved: &Resolved,
    client_ip: Option<String>,
    time_ms: u128,
    started: Instant,
) -> Result<Response<DynBody>> {
    let dest = dest::Destination::of(info, resolved);
    let target = apply::resolve_target(info, &dest, resolved).await?;
    let frame_script = resolved.value("frameScript").and_then(script::load_script);
    let websocket = is_websocket(&req);
    // Which plugins may hook this session's frames. Resolving the plan contacts
    // nothing and allocates nothing unless a rule named a registered plugin;
    // the plugins themselves are dialled later, from inside the tunnel.
    let frame_plan = if websocket {
        ws::FramePlan::new(&state.plugins, resolved, info)
    } else {
        ws::FramePlan::default()
    };
    // Which directions `enable://ignoreSend|ignoreReceive` silences. Read here
    // rather than inside the plan: the plan collapses to its default when no
    // plugin is named, and these flags have to survive that.
    let frame_ignore = ws::IgnoreDirs::of(resolved);
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream handshake request (upgrades carry no body, so
    // `params://` can only address the query string here).
    let (mut parts, _body) = req.into_parts();
    let new_path = apply::rewrite_path(&dest.path, resolved, apply::ReqBodyCtx::default());
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &dest.host, dest.port, &dest.scheme);
    parts.headers.remove("proxy-connection");
    mark_stripped_tls(&mut parts.headers, &target);
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
                    ws::capturing_tunnel(
                        c,
                        u,
                        frame_script,
                        frame_plan,
                        frame_ignore,
                        state,
                        session_id,
                    )
                    .await;
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
    if let Some(i) = lower.find("<body")
        && let Some(close) = text[i..].find('>')
    {
        let pos = i + close + 1;
        let mut out = String::with_capacity(text.len() + tag.len());
        out.push_str(&text[..pos]);
        out.push_str(tag);
        out.push_str(&text[pos..]);
        return Bytes::from(out);
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
    let default_port = if dest::is_tls(scheme) { 443 } else { 80 };
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

    /// The stripped-TLS marker travels only on a hop that actually strips TLS,
    /// and is consumed on arrival like the internal one
    /// (`_original/lib/inspectors/res.js:229-234`, `lib/init.js:190-193`).
    #[test]
    fn the_stripped_tls_marker_is_set_by_the_hop_and_consumed_on_arrival() {
        let target = |tls: bool, stripped: bool| upstream::Target {
            connect_host: "example.com".into(),
            connect_port: 80,
            tls,
            origin_tls_stripped: stripped,
            sni: "example.com".into(),
            request_port: 443,
            proxy: None,
            tls_versions: upstream::TlsVersions::Default,
            host_fallback_direct: false,
        };

        let mut h = hyper::HeaderMap::new();
        mark_stripped_tls(&mut h, &target(false, true));
        assert_eq!(h.get(HTTPS_REQ_HEADER).expect("marker"), "1");
        // Consumed on the way in, so it never reaches a rule condition or the
        // origin — and it says the request was https before the hop.
        assert!(take_https_marker(&mut h));
        assert!(h.get(HTTPS_REQ_HEADER).is_none());

        // An ordinary hop marks nothing.
        let mut h = hyper::HeaderMap::new();
        mark_stripped_tls(&mut h, &target(true, false));
        assert!(h.get(HTTPS_REQ_HEADER).is_none());
        assert!(!take_https_marker(&mut h));
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

#[cfg(test)]
mod local_response_tests {
    use super::*;

    /// State with `rules` loaded, on a storage dir of its own — these tests run
    /// in parallel and sharing one made them race to write the root CA.
    fn state_with(rules: &str) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-local-res-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("ca");
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        Arc::new(AppState::new(config, mgr, ca))
    }

    /// Run `rules` against a locally produced response, exactly as `serve`'s
    /// plugin and short-circuit exits do.
    fn finish(
        rules: &str,
        status: u16,
        res_headers: &[(&str, &str)],
        body: &str,
    ) -> (hyper::http::response::Parts, Bytes) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state_with(rules);
            let mut info = apply::build_req_info(
                "GET",
                "http",
                "example.com",
                80,
                "/",
                &hyper::HeaderMap::new(),
                Some("127.0.0.1".to_string()),
            );
            let mut resolved = state.rules.read().unwrap().resolve_scoped(&info, false);
            let resp = crate::plugins::PluginResp {
                status,
                headers: res_headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            };
            let (resp, _) = finish_local_response(
                &state,
                &mut info,
                &mut resolved,
                &[],
                false,
                plugin_response(resp),
                ResHooks::default(),
            )
            .await;
            let (parts, body) = resp.into_parts();
            let bytes = collect_body(body).await.expect("body");
            (parts, bytes)
        })
    }

    /// The fix: a plugin's answer is not the last word. Response-side operators
    /// run over it, as they do over the origin's answer — upstream reaches its
    /// response inspectors on this path too, because a `plugin://` rule is a
    /// proxy hop to the plugin's own server.
    #[test]
    fn a_plugin_answer_takes_the_response_operators() {
        let (parts, body) = finish(
            "example.com plugin://echo resHeaders://x-late=1 replaceStatus://503 \
             resType://json resAppend://!\n",
            200,
            &[("content-type", "text/plain")],
            "answered",
        );
        assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(parts.headers.get("x-late").unwrap(), "1");
        assert!(
            parts
                .headers
                .get(hyper::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("application/json"),
            "resType:// applies to a plugin's answer"
        );
        assert_eq!(body, Bytes::from_static(b"answered!"));
    }

    /// And the *response phase* runs on it: a filter about the response can be
    /// answered, because the plugin's head is in hand before any operator has
    /// touched it. `s:404` here sees the plugin's own 404, not the 200 the
    /// `replaceStatus://` on the same line would later write.
    #[test]
    fn a_plugin_answer_gets_the_response_phase() {
        let rules = "example.com plugin://echo\n\
                     example.com resHeaders://x-notfound=1 includeFilter://s:404\n";
        let (parts, _) = finish(rules, 404, &[], "");
        assert_eq!(parts.headers.get("x-notfound").unwrap(), "1");
        let (parts, _) = finish(rules, 200, &[], "");
        assert!(parts.headers.get("x-notfound").is_none());
    }

    /// A response no operator touches is handed back byte-for-byte, with its
    /// framing headers intact — nothing here may cost a plugin its `content-length`.
    #[test]
    fn an_untouched_answer_keeps_its_framing() {
        let (parts, body) = finish(
            "example.com plugin://echo\n",
            201,
            &[("content-length", "2"), ("x-plugin", "yes")],
            "hi",
        );
        assert_eq!(parts.status, StatusCode::CREATED);
        assert_eq!(parts.headers.get("content-length").unwrap(), "2");
        assert_eq!(parts.headers.get("x-plugin").unwrap(), "yes");
        assert_eq!(body, Bytes::from_static(b"hi"));
    }

    /// The short-circuit exit shares the same finisher, so a mocked response
    /// now takes the body operators too — not just the header ones.
    #[test]
    fn a_short_circuit_answer_takes_the_body_operators() {
        let (parts, body) = finish(
            "example.com statusCode://200 resBody://base\n\
             example.com resAppend://+more\n",
            200,
            &[],
            "",
        );
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(body, Bytes::from_static(b"base+more"));
    }

    /// A refusal from the auth gate is served as produced. The contrast is the
    /// point: the very same rules that rewrite an *answer* must not touch a
    /// refusal — which is what upstream's `ignore://!statusCode|…` pinning says.
    #[test]
    fn a_refusal_is_served_as_produced() {
        let rules = "example.com plugin://gate resHeaders://x-late=1 \
                     replaceStatus://200 resAppend://!\n";

        // The answer path: every operator lands, 403 included.
        let (parts, body) = finish(rules, 403, &[], "denied");
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(parts.headers.get("x-late").unwrap(), "1");
        assert_eq!(body, Bytes::from_static(b"denied!"));

        // The refusal path: nothing lands — not the header, not the append, and
        // above all not the status rewrite that would have made a 403 a 200.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (parts, body) = rt.block_on(async {
            let state = state_with(rules);
            let res = plugin_response(crate::plugins::PluginResp {
                status: 403,
                headers: vec![("content-length".to_string(), "6".to_string())],
                body: b"denied".to_vec(),
            });
            let (resp, capture) = pin_refusal(&state, res);
            assert!(capture.is_some(), "a refusal is still recorded");
            let (parts, body) = resp.into_parts();
            (parts, collect_body(body).await.expect("body"))
        });
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        assert!(parts.headers.get("x-late").is_none());
        assert_eq!(body, Bytes::from_static(b"denied"));
        // And its framing survives: nothing rewrote the body, so the length the
        // gate declared is still the truth.
        assert_eq!(parts.headers.get("content-length").unwrap(), "6");
    }

    // -- the plugin response hooks on a locally produced response -------------

    /// A plugin that hooks the response **with the body**. No built-in does, and
    /// the buffered half of the hook is the half that rewrites bytes.
    struct BodyHookPlugin;

    impl crate::plugins::RustPlugin for BodyHookPlugin {
        fn name(&self) -> &str {
            "bodyhook"
        }

        fn manifest(&self) -> crate::plugins::PluginManifest {
            crate::plugins::PluginManifest {
                on_response: true,
                response_hook: true,
                response_body: true,
                ..crate::plugins::PluginManifest::none(self.name())
            }
        }

        fn on_request(&self, _req: &crate::plugins::PluginReq) -> crate::plugins::PluginResult {
            crate::plugins::PluginResult::default()
        }

        fn on_response(
            &self,
            res: &crate::plugins::PluginRes,
        ) -> crate::plugins::PluginResResult {
            // The header proves the body arrived; the body proves what comes
            // back replaces it.
            let seen = res.body.clone().unwrap_or_default();
            crate::plugins::PluginResResult {
                set_headers: vec![("x-saw-body".to_string(), seen.len().to_string())],
                body: Some([b"<", seen.as_slice(), b">"].concat()),
                ..Default::default()
            }
        }
    }

    /// As [`finish`], but passing the plugin audience `serve` passes: the matched
    /// `plugin://` and `pipe://` sets, split the same way and resolved from the
    /// same rules.
    fn finish_hooked(
        rules: &str,
        extra: Option<Box<dyn crate::plugins::RustPlugin>>,
        status: u16,
        res_headers: &[(&str, &str)],
        body: &str,
    ) -> (hyper::http::response::Parts, Bytes) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = {
                let base = state_with(rules);
                match extra {
                    None => base,
                    // `AppState` owns its registry, so an extra plugin means
                    // building one — same config, same rules, same CA.
                    Some(plugin) => {
                        let mut plugins = crate::plugins::Plugins::new();
                        plugins.register_rust(plugin);
                        let mut mgr = RuleManager::new();
                        mgr.set_text(rules);
                        Arc::new(AppState::with_plugins(
                            base.config.clone(),
                            mgr,
                            base.ca.clone(),
                            plugins,
                        ))
                    }
                }
            };
            let mut info = apply::build_req_info(
                "GET",
                "http",
                "example.com",
                80,
                "/",
                &hyper::HeaderMap::new(),
                Some("127.0.0.1".to_string()),
            );
            let mut resolved = state.rules.read().unwrap().resolve_scoped(&info, false);

            // The same split `serve` does: a `pipe://` naming a plugin with a
            // streaming hook drives the stream, everything else the buffered hook.
            let mut plugins: Vec<(String, String)> = Vec::new();
            let mut pipes: Vec<crate::plugins::PluginMatch> = Vec::new();
            for m in crate::plugins::matched(&resolved) {
                if !state.plugins.contains(&m.name) {
                    continue;
                }
                let streams = m.via_pipe
                    && matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.has_pipe_hook());
                if streams {
                    pipes.push(m);
                } else {
                    plugins.push((m.name.clone(), m.param.clone()));
                }
            }

            let resp = crate::plugins::PluginResp {
                status,
                headers: res_headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            };
            let (resp, _) = finish_local_response(
                &state,
                &mut info,
                &mut resolved,
                &[],
                false,
                plugin_response(resp),
                ResHooks {
                    plugins: &plugins,
                    pipes: &pipes,
                    req_id: 7,
                    client_ip: Some("127.0.0.1".to_string()),
                },
            )
            .await;
            let (parts, body) = resp.into_parts();
            let bytes = collect_body(body).await.expect("body");
            (parts, bytes)
        })
    }

    /// The gap this closes: a plugin's own response hook never ran over a
    /// response the proxy produced itself. Upstream reaches it — a `plugin://`
    /// answer comes back from the plugin's server as an ordinary response, so
    /// the response-side plugin machinery runs over it like any other.
    #[test]
    fn a_local_answer_reaches_the_buffered_response_hook() {
        // `stamp` declares the response hook without the body, so it runs in
        // part 1, before the body is even looked at.
        let (parts, body) = finish_hooked(
            "example.com plugin://echo plugin://stamp\n",
            None,
            200,
            &[],
            "answered",
        );
        assert_eq!(
            parts.headers.get("x-stamped-by").map(|v| v.to_str().unwrap()),
            Some("whistle-rs"),
            "the response hook of a matched plugin must see a local answer"
        );
        assert_eq!(body, Bytes::from_static(b"answered"));
    }

    /// The same for a short-circuit rule's response: nothing about
    /// `statusCode://` makes it invisible to a matched plugin.
    #[test]
    fn a_short_circuit_answer_reaches_the_buffered_response_hook() {
        let (parts, _) = finish_hooked(
            "example.com statusCode://204 plugin://stamp\n",
            None,
            204,
            &[],
            "",
        );
        assert!(parts.headers.get("x-stamped-by").is_some());
    }

    /// Part 2 of the hook: a plugin that asked for the body gets it, and what it
    /// returns replaces it — with the framing corrected, because the length the
    /// producer declared is no longer the truth.
    #[test]
    fn the_body_half_of_the_hook_rewrites_a_local_answer() {
        let (parts, body) = finish_hooked(
            "example.com plugin://bodyhook\n",
            Some(Box::new(BodyHookPlugin)),
            200,
            &[("content-length", "8")],
            "answered",
        );
        assert_eq!(parts.headers.get("x-saw-body").unwrap(), "8");
        assert_eq!(body, Bytes::from_static(b"<answered>"));
        // The stale `content-length: 8` must not survive a body that is now 10
        // bytes long; hyper writes the true one from a measurable body.
        assert!(
            parts.headers.get(hyper::header::CONTENT_LENGTH).is_none(),
            "a hook that replaced the body invalidated the declared length"
        );
    }

    /// The streaming hook reaches this path too. `pipe://upper` never sees a
    /// whole body — it maps frames — so this also pins that a local answer is
    /// handed to it as a body rather than as bytes.
    #[test]
    fn a_local_answer_reaches_the_streaming_response_hook() {
        let (_, body) = finish_hooked(
            "example.com plugin://echo pipe://upper\n",
            None,
            200,
            &[],
            "answered",
        );
        assert_eq!(body, Bytes::from_static(b"ANSWERED"));
    }

    /// Hooks and operators compose in the documented order: the operators run
    /// first (they are the response's own rules), then the plugin sees what they
    /// produced.
    #[test]
    fn the_operators_run_before_the_hook_sees_the_response() {
        let (parts, body) = finish_hooked(
            "example.com plugin://bodyhook resAppend://!\n",
            Some(Box::new(BodyHookPlugin)),
            200,
            &[],
            "answered",
        );
        assert_eq!(body, Bytes::from_static(b"<answered!>"));
        assert_eq!(parts.headers.get("x-saw-body").unwrap(), "9");
    }

    /// And a response with no plugin in the audience is still handed back
    /// untouched — the hooks cost an `is_empty` check, not a copy.
    #[test]
    fn no_plugin_means_no_change_and_no_lost_framing() {
        let (parts, body) = finish_hooked(
            "example.com statusCode://200\n",
            None,
            200,
            &[("content-length", "2"), ("x-mock", "yes")],
            "hi",
        );
        assert_eq!(parts.headers.get("content-length").unwrap(), "2");
        assert_eq!(parts.headers.get("x-mock").unwrap(), "yes");
        assert_eq!(body, Bytes::from_static(b"hi"));
    }
}

#[cfg(test)]
mod req_origin_tests {
    use super::*;

    /// The composer marker is consumed exactly like the internal one: the rules'
    /// header conditions, the plugins, the capture and the origin must never see
    /// this proxy's own bookkeeping. whistle deletes its `FROM_COM_HEADER` on
    /// arrival for the same reason (`_original/lib/util/index.js:3391-3396`).
    #[test]
    fn the_composer_marker_is_consumed() {
        let mut h = hyper::HeaderMap::new();
        h.insert(COMPOSER_REQ_HEADER, "1".parse().unwrap());
        assert!(take_composer_marker(&mut h));
        assert!(h.get(COMPOSER_REQ_HEADER).is_none());

        assert!(!take_composer_marker(&mut hyper::HeaderMap::new()));
        let mut h = hyper::HeaderMap::new();
        h.insert(COMPOSER_REQ_HEADER, "".parse().unwrap());
        assert!(!take_composer_marker(&mut h));
        assert!(h.get(COMPOSER_REQ_HEADER).is_none());
    }

    /// `from:tunnel` and `from:sni` are read off the origin, and they are not the
    /// same fact: a tunnel carrying plain HTTP has no ClientHello to have named a
    /// server, and a forward-proxy request has no tunnel.
    #[test]
    fn the_origin_decides_tunnel_and_sni() {
        let of = |origin: &Origin| crate::rules::ReqOrigin {
            tunnel: matches!(origin, Origin::Mitm { .. }),
            sni: matches!(origin, Origin::Mitm { sni: true, .. }),
            composer: false,
        };
        let mitm = |tls, sni| Origin::Mitm {
            host: "example.com".into(),
            port: 443,
            tls,
            sni,
        };
        assert_eq!(of(&mitm(true, true)), crate::rules::ReqOrigin {
            tunnel: true, sni: true, composer: false,
        });
        assert_eq!(of(&mitm(false, false)), crate::rules::ReqOrigin {
            tunnel: true, sni: false, composer: false,
        });
        assert_eq!(of(&Origin::Forward), crate::rules::ReqOrigin::default());
    }
}

