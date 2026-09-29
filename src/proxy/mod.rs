//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
#[cfg(test)]
mod bench;
pub mod body;
pub mod ciphers;
pub mod coding;
pub mod dest;
#[cfg(test)]
mod failure_tests;
pub mod forwarded;
pub mod header_rules;
pub mod outcome;
pub mod persist;
pub mod restream;
pub mod script;
pub mod sni;
pub mod socks;
pub mod template;
pub mod timing;
pub mod upstream;
pub mod webui;
pub mod ws;

use std::collections::{HashMap, VecDeque};
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

/// Maximum number of captured transactions kept in memory, when nothing says
/// otherwise — [`crate::config::Config::req_cache_size`] is what the running
/// proxy reads, and `-R/--req-cache-size` is how a user changes it.
pub const MAX_SESSIONS: usize = crate::config::DEFAULT_REQ_CACHE_SIZE;

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

/// The headers whistle reads rules out of, and removes either way — see
/// [`header_rules`], which is where reading them lives.
pub use header_rules::ALWAYS_TAKEN as HEADER_RULE_HEADERS;

/// Proxy-internal markers a client may not forge.
///
/// `x-whistle-client-port` is deleted the moment a request is read
/// (`_original/lib/init.js:181`, and again on the upgrade and tunnel paths);
/// `x-whistle-alpn-protocol` is deleted where it is consumed (`init.js:224`).
/// Both name facts about the *connection*, which the connection already
/// answers — a client sending them is either an upstream whistle (whose values
/// this port does not read) or someone spoofing them at the origin.
///
/// `x-whistle-client-id` is not here because it survives
/// `enable://keepClientId`, and that is decided from the rules — see
/// [`apply::apply_request`].
pub const CONNECTION_MARKER_HEADERS: [&str; 2] =
    ["x-whistle-client-port", "x-whistle-alpn-protocol"];

/// Take the rules-carrying headers and the connection markers off a request on
/// its way in, returning what the first four said.
///
/// The removal is unconditional in both proxies — see [`header_rules::take`].
/// What the mode decides is whether the contents are *returned* here or
/// dropped on the floor.
fn take_header_rules(
    headers: &mut hyper::HeaderMap,
    cfg: &crate::config::Config,
) -> header_rules::Carried {
    let carried = header_rules::take(headers, cfg.header_rules, cfg.multi_env);
    for name in CONNECTION_MARKER_HEADERS {
        headers.remove(name);
    }
    carried
}

/// Strip the composer marker, reporting whether it was present.
fn take_composer_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(COMPOSER_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Collect a whole [`DynBody`] into memory. Its boxed error type is unsized, so
/// it needs flattening before `?` can carry it into `anyhow`.
async fn collect_body(body: DynBody) -> Result<Bytes> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// As [`collect_body`], but giving up past `limit` bytes rather than reading
/// whatever the client decides to send. See [`body::collect_capped`] for what
/// happens at the limit, and why it is not an error.
async fn collect_capped_body(body: DynBody, limit: usize) -> Result<body::Capped> {
    match body::collect_capped(body, limit).await {
        Ok(capped) => Ok(capped),
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
    /// The live WebSocket sessions a rule paused, so the console can find one
    /// and let it go again. Only `enable://pauseSend|pauseReceive` puts an entry
    /// here, and the tunnel removes its own when it ends, so this holds exactly
    /// the connections someone is waiting on — see [`ws::SessionPause`].
    pub ws_pause: Mutex<HashMap<u64, Arc<ws::SessionPause>>>,
    /// The live WebSocket sessions the console can write into — one entry per
    /// intercepted connection, removed when it ends.
    ///
    /// whistle's Frames panel has a Composer that sends a frame to either end
    /// of a live connection (`gui/network.md`), which is the one thing a
    /// capture cannot tell you: what the *other* side does with a message you
    /// have not seen it receive. See [`ws::SessionWriters`].
    pub ws_write: Mutex<HashMap<u64, Arc<ws::SessionWriters>>>,
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
            ws_pause: Mutex::new(HashMap::new()),
            ws_write: Mutex::new(HashMap::new()),
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

    /// Bring back the sessions on disk that are within `persist_days`, and
    /// write every session completed from now on — what `persist_sessions`
    /// promises. Needs a tokio runtime: the writer is a task.
    ///
    /// One place for it, because there are two ways to start a proxy and the
    /// embedding one did not do it at all: `.persist_sessions(true)` set the
    /// flag and nothing read it.
    pub fn start_history(&mut self) {
        let dir = self.config.sessions_dir();
        let loaded =
            persist::SessionStore::load(&dir, self.config.req_cache_size, self.config.persist_days);
        if !loaded.is_empty() {
            let max_id = loaded.iter().map(|s| s.id).max().unwrap_or(0);
            let mut q = self.sessions.lock().unwrap();
            q.extend(loaded);
            tracing::info!("loaded {} sessions from disk", q.len());
            drop(q);
            self.set_next_id(max_id + 1);
        }
        let store = persist::SessionStore::new(dir, self.config.persist_days);
        self.enable_persistence(store);
    }

    /// Set the next session ID counter (used after loading history).
    pub fn set_next_id(&self, id: u64) {
        self.next_id.store(id, Ordering::Relaxed);
    }

    /// Be told about every transaction as it completes.
    ///
    /// For an **embedding** program: a proxy inside another application usually
    /// wants the traffic delivered, not polled out of `/sessions.json`. The
    /// callback runs on the request's own task once the transaction is over —
    /// the response has reached the client, or failed, or the client left — so
    /// it must be quick; hand the work to a channel if it is not. Each request
    /// is delivered exactly once, failed ones included, with
    /// [`Session::error`] saying where a failed one stopped.
    ///
    /// A forwarded response is in the console from the moment its head
    /// arrives, and reaches this callback only when its body ends; a stream
    /// that never ends is never delivered. A WebSocket is over, for this
    /// purpose, once its handshake is: the frames that follow are not part of
    /// the session.
    ///
    /// Settable once, before serving. A second call is ignored rather than
    /// replacing the first, so a library consumer cannot silently lose the
    /// observer another part of the program installed.
    pub fn observe(&self, f: impl Fn(&Session) + Send + Sync + 'static) {
        let _ = self.observer.set(Box::new(f));
    }

    /// Record a transaction, assigning it an id which is returned so callers
    /// (e.g. WebSocket tunnels) can correlate later frames with it.
    /// Take the next session id without recording anything yet.
    ///
    /// A transaction's frames are cut out of its **bodies**, and the request
    /// body streams long before the response head arrives — so the id has to
    /// exist before the session does. [`Self::record`] keeps an id that was
    /// reserved this way rather than allocating a second one.
    fn reserve_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Record a transaction that is already over — answered here, failed, or
    /// aborted. Returns its id.
    fn record(&self, mut session: Session) -> u64 {
        let id = self.assign_id(&mut session);
        if !is_hidden(&session) {
            self.complete(&session);
            self.show(session);
        }
        id
    }

    /// Record a transaction whose response is still arriving: it is in the
    /// console from now on, and [`Self::complete`] is owed the session
    /// returned once it is over — the observer and the history on disk get it
    /// then, with the whole body preview, every phase and, if it came to that,
    /// why it failed. `None` for a hidden one, which is owed nothing.
    fn record_open(&self, mut session: Session) -> (u64, Option<Session>) {
        let id = self.assign_id(&mut session);
        if is_hidden(&session) {
            return (id, None);
        }
        self.show(session.clone());
        (id, Some(session))
    }

    /// The id a session is recorded under: the one reserved for it, or the next.
    fn assign_id(&self, session: &mut Session) -> u64 {
        if session.id == 0 {
            session.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        session.id
    }

    /// Put a session in the console's ring, evicting the oldest past the cap.
    fn show(&self, session: Session) {
        let mut q = self.sessions.lock().unwrap();
        let cap = self.config.req_cache_size.max(1);
        while q.len() >= cap {
            q.pop_front();
        }
        q.push_back(session);
    }

    /// Hand a finished transaction to the observer and to the history on disk.
    ///
    /// `enable://hide` never gets here — the request happens, and the console
    /// never hears about it. Upstream gates its own data server on the same
    /// question (`isHide`, `_original/lib/util/index.js:3990-3996`, read by
    /// `inspectors/data.js:59`), so a hidden request is not shown, not stored
    /// and not replayable there either.
    fn complete(&self, session: &Session) {
        if let Some(observe) = self.observer.get() {
            observe(session);
        }
        if let Some(store) = &self.session_store {
            store.persist(session);
        }
    }

    /// Clear all in-memory sessions and WebSocket frames.
    ///
    /// Memory only: what persistence wrote to disk stays there and comes back
    /// on the next start. That is the console's "clear" — tidying the view —
    /// and [`Self::purge_sessions`] is the one that deletes.
    pub fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
        self.ws_frames.lock().unwrap().clear();
    }

    /// Forget every session, in memory and on disk. Returns how many session
    /// files were deleted (0 when nothing is persisted).
    pub async fn purge_sessions(&self) -> usize {
        self.clear_sessions();
        match &self.session_store {
            Some(store) => store.purge().await,
            None => 0,
        }
    }

    /// Record one captured WebSocket frame in the bounded ring buffer.
    pub fn record_frame(&self, frame: WsFrame) {
        let mut q = self.ws_frames.lock().unwrap();
        let cap = self.config.frame_cache_size.max(1);
        while q.len() >= cap {
            q.pop_front();
        }
        q.push_back(frame);
    }
}

/// Is this transaction hidden from the capture — `enable://hide`?
///
/// Upstream's `checkHideProp` (`_original/lib/util/index.js:3982-3987`) reads
/// four flags, not one: `enable://hide` and `disable://show` hide, and
/// `enable://show` and `disable://hide` un-hide, with the un-hiding half
/// winning. The pair exists because the flags can arrive from different rule
/// lines — a broad `enable://hide` over a whole domain, and a narrow
/// `enable://show` on the one request being looked at.
///
/// Upstream also has a Composer-only pair (`enable://hideComposer`) and a
/// server-wide capture switch; neither is here — this port has no
/// `captureData` mode, and a session does not record whether the Composer sent
/// it.
fn is_hidden(session: &Session) -> bool {
    let flags = |protocol: &str| -> std::collections::HashSet<String> {
        session
            .rules
            .iter()
            .filter(|op| op.protocol == protocol)
            .flat_map(|op| crate::proxy::apply::parse_props(&op.value))
            .map(|f| f.trim().to_string())
            .collect()
    };
    apply::hides_capture(&flags("enable"), &flags("disable"))
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
        .map(|e| {
            e.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
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
    /// For a capture read back from history: whether it was short of the body
    /// when it was written. What decided that then — the cap it was taken
    /// under, whether it arrived compressed — is not stored, and re-deriving it
    /// from what is got it wrong both ways (see [`Capture::restored`]).
    restored_truncated: Option<bool>,
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

    /// Whether the preview falls short of the body: it either hit the cap,
    /// bytes went past uncompressed after it was full, or decoding failed and
    /// nothing after the failure was kept.
    ///
    /// One predicate rather than three, because [`Capture::snapshot`],
    /// [`Capture::preview_bytes`] and [`Capture::replay_body`] each have to
    /// answer it and three copies of it would drift.
    fn is_truncated(&self) -> bool {
        if let Some(truncated) = self.restored_truncated {
            return truncated;
        }
        self.data.len() >= self.cap()
            || matches!(self.decoder, BodyDecoder::Failed)
            || (matches!(self.decoder, BodyDecoder::Identity) && self.total > self.data.len())
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

    /// A capture read back from history, with the facts about it that were
    /// written down with it rather than re-derived.
    ///
    /// Rebuilding one by feeding the kept bytes through [`Capture::from_bytes`]
    /// derived `truncated` from them, under a cap made up for the occasion: a
    /// body cut at the preview limit came back whole, and a whole body that had
    /// arrived gzipped — kept decoded, and so longer than its wire length —
    /// came back cut short.
    pub(crate) fn restored(
        bytes: &[u8],
        content_type: Option<String>,
        total: usize,
        truncated: bool,
        undecodable: bool,
    ) -> Self {
        Capture(Arc::new(Mutex::new(CaptureState {
            data: bytes.to_vec(),
            total,
            content_type,
            decoder: if undecodable {
                BodyDecoder::Failed
            } else {
                BodyDecoder::Done
            },
            cap: None,
            restored_truncated: Some(truncated),
        })))
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
        let truncated = st.is_truncated();
        let text = if is_textual(st.content_type.as_deref()) {
            String::from_utf8_lossy(&st.data).into_owned()
        } else {
            format!("[binary, {} bytes]", st.total)
        };
        (st.total, truncated, text)
    }

    /// Whether [`Capture::snapshot`]'s `text` is a marker rather than the body.
    pub fn is_binary(&self) -> bool {
        !is_textual(self.0.lock().unwrap().content_type.as_deref())
    }

    /// Whether undoing the body's `Content-Encoding` failed part-way, so what
    /// was kept is the decoder's output up to the failure and nothing after.
    pub fn is_undecodable(&self) -> bool {
        matches!(self.0.lock().unwrap().decoder, BodyDecoder::Failed)
    }

    /// The preview as **bytes**, with what is needed to serve them.
    ///
    /// Deliberately *not* built on [`Capture::snapshot`], for the same reason
    /// [`Capture::replay_body`] is not: `snapshot` renders the preview for a
    /// human and loses the body doing it — `from_utf8_lossy` flattens every
    /// invalid byte to U+FFFD, and a non-textual type is replaced outright by a
    /// `[binary, N bytes]` marker. That marker *was* the whole story the console
    /// got for a PNG, which is why it could show neither the image, nor its
    /// bytes, nor offer it as a download.
    pub fn preview_bytes(&self) -> BodyBytes {
        let st = self.0.lock().unwrap();
        BodyBytes {
            bytes: Bytes::copy_from_slice(&st.data),
            content_type: st.content_type.clone(),
            total: st.total,
            truncated: st.is_truncated(),
        }
    }

    /// What a replay can honestly re-send of this body — see [`ReplayBody`].
    ///
    /// Deliberately *not* built on [`Capture::snapshot`]: that renders the
    /// preview for a human, lossily. `from_utf8_lossy` turns any byte that is
    /// not valid UTF-8 into U+FFFD, and a non-textual content type is replaced
    /// outright by a `[binary, N bytes]` marker — replaying either would send
    /// a body the client never sent, under the original's `content-type`. The
    /// stored bytes are neither: they are the body as decoded, byte for byte,
    /// up to the preview cap.
    pub fn replay_body(&self) -> ReplayBody {
        let st = self.0.lock().unwrap();
        if matches!(st.decoder, BodyDecoder::Failed) {
            // The decompressor gave up part-way, so `data` is a prefix of
            // something that was never the body. Sending it would be a lie the
            // length header would make look deliberate.
            return ReplayBody::Undecodable;
        }
        // Nothing kept of a body that had bytes is not an empty body: a preview
        // limit of 0, or a body from history none of which was written down.
        if st.data.is_empty() && !st.is_truncated() {
            return ReplayBody::Empty;
        }
        let bytes = Bytes::copy_from_slice(&st.data);
        match !st.is_truncated() {
            true => ReplayBody::Whole(bytes),
            false => ReplayBody::Partial {
                bytes,
                of: st.total,
            },
        }
    }
}

/// A captured body as the bytes it is, for the console's hex view, its image
/// preview and its download — and for a HAR entry, which has to carry a body no
/// text field can hold.
#[derive(Clone, Debug)]
pub struct BodyBytes {
    /// The decoded preview, byte for byte, up to the preview cap.
    pub bytes: Bytes,
    /// The `Content-Type` recorded for the body, if it had one.
    pub content_type: Option<String>,
    /// Raw (wire) bytes seen. Exceeds `bytes.len()` when the preview was capped
    /// — and, for a body that arrived compressed, is not comparable to it.
    pub total: usize,
    /// The preview is short of the body: it must not be offered as the whole.
    pub truncated: bool,
}

/// What of a captured request body a replay can re-send.
///
/// The capture is a **bounded, decoded** preview, not the bytes that crossed the
/// wire, so a replay is only ever as faithful as the preview is. Naming the
/// cases is what lets [`webui`] set the framing headers to match what it
/// actually sends, and lets the console say so when the two differ — before
/// this, `do_replay` copied every captured header and sent an empty body, so
/// replaying a POST re-sent its `content-length: 402` with zero bytes behind it.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplayBody {
    /// Nothing was captured: the request had no body, or none was recorded.
    Empty,
    /// The whole body, decoded. Whatever `content-encoding` it arrived under has
    /// been undone, so the header must go with it.
    Whole(Bytes),
    /// The first bytes of a body that did not fit the preview. `of` is the raw
    /// (wire) byte count seen — which, for a body that arrived compressed, is
    /// not the size of what is being sent.
    Partial { bytes: Bytes, of: usize },
    /// The capture cannot stand in for the body at all: decoding it failed
    /// part-way, so it holds a prefix of nothing in particular.
    Undecodable,
}

impl ReplayBody {
    /// The bytes to send, if any.
    pub fn bytes(&self) -> Option<&Bytes> {
        match self {
            ReplayBody::Whole(b) | ReplayBody::Partial { bytes: b, .. } => Some(b),
            ReplayBody::Empty | ReplayBody::Undecodable => None,
        }
    }

    /// A one-word name for the console, so a replay that differs from what was
    /// captured says which way it differs.
    pub fn kind(&self) -> &'static str {
        match self {
            ReplayBody::Empty => "empty",
            ReplayBody::Whole(_) => "whole",
            ReplayBody::Partial { .. } => "partial",
            ReplayBody::Undecodable => "undecodable",
        }
    }
}

impl serde::Serialize for Capture {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (len, truncated, text) = self.snapshot();
        let mut o = s.serialize_struct("BodyCapture", 5)?;
        o.serialize_field("len", &len)?;
        o.serialize_field("truncated", &truncated)?;
        o.serialize_field("text", &text)?;
        // Whether `text` is the body or a marker standing in for it. The console
        // needs to know, and re-deriving [`is_textual`] from the Content-Type in
        // TypeScript would be a second copy of a rule this side already applied
        // — the kind that drifts silently and is only noticed as a body that
        // renders as mojibake.
        o.serialize_field("binary", &self.is_binary())?;
        // Why a `truncated` body is short when it is not the preview limit: its
        // encoding would not decode, so `text` is what came out before it broke.
        o.serialize_field("undecodable", &self.is_undecodable())?;
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
        assert!(
            body.len() < BODY_PREVIEW_CAP,
            "8 MiB of 'a' fits in one frame"
        );
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
        assert!(
            decoder_bytes(&cap) > 0,
            "still decoding: the body may continue"
        );

        cap.finish();
        assert_eq!(decoder_bytes(&cap), 0);
        let (_, _, text) = cap.snapshot();
        assert_eq!(
            text, "small enough to fit",
            "the preview survives the release"
        );
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

    /// A body that fitted the preview replays byte for byte.
    #[test]
    fn a_whole_body_replays_whole() {
        let cap = Capture::from_bytes(b"name=third&tags=a", Some("text/plain".into()), None, 64);
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from_static(b"name=third&tags=a"))
        );
    }

    /// A body the preview could not hold replays as its prefix, and says so.
    /// Sending it as if it were whole is the failure this case exists to
    /// prevent: a 200 KB upload would be re-sent as its first 16 KB under a
    /// `content-length` copied from the original, and nothing would say which
    /// of the two the origin saw.
    #[test]
    fn a_capped_body_replays_as_a_prefix_that_admits_it() {
        let cap = Capture::new(Some("text/plain".into()), None, 8);
        cap.append(b"0123456789");
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Partial {
                bytes: Bytes::from_static(b"01234567"),
                of: 10,
            }
        );
    }

    /// The bytes, not the preview *text*. A JPEG is stored verbatim and shown
    /// as `[binary, N bytes]`; a replay built on `snapshot` would have posted
    /// that sentence to the origin under `image/jpeg`.
    #[test]
    fn a_binary_body_replays_as_its_bytes_not_as_its_marker() {
        let raw = [0u8, 159, 146, 150];
        let cap = Capture::from_bytes(&raw, Some("image/jpeg".into()), None, 64);
        assert!(cap.snapshot().2.starts_with("[binary"));
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from(raw.to_vec()))
        );
    }

    /// A compressed body is replayed **decoded** — which is why the replay drops
    /// `content-encoding` with it (see `webui::replay_request`).
    #[test]
    fn a_compressed_body_replays_decoded() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&gzip(b"deflate me"));
        cap.finish();
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from_static(b"deflate me"))
        );
    }

    /// A decode that failed leaves a prefix of something that was never a body.
    /// Replaying it would be a fabrication the length header made look
    /// deliberate, so nothing is sent and the console is told why.
    #[test]
    fn a_body_that_would_not_decode_is_not_replayed() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(b"this was never gzip");
        assert_eq!(cap.replay_body(), ReplayBody::Undecodable);
        assert_eq!(cap.replay_body().bytes(), None);
    }

    #[test]
    fn a_request_without_a_body_replays_without_one() {
        assert_eq!(Capture::default().replay_body(), ReplayBody::Empty);
    }

    /// The gap this closes: a PNG reached the console as the sentence
    /// `[binary, 4 bytes]` and nothing else, so there was no hex view, no image
    /// and no download to build — the bytes were discarded at serialization.
    #[test]
    fn a_binary_body_keeps_its_bytes_beside_its_marker() {
        let raw = [0x89, b'P', b'N', b'G'];
        let cap = Capture::from_bytes(&raw, Some("image/png".into()), None, 64);
        assert_eq!(cap.snapshot().2, "[binary, 4 bytes]");

        let pv = cap.preview_bytes();
        assert_eq!(pv.bytes, Bytes::from(raw.to_vec()));
        assert_eq!(pv.content_type.as_deref(), Some("image/png"));
        assert_eq!(pv.total, 4);
        assert!(!pv.truncated);
    }

    /// A compressed body is served to the console **decoded**, like everything
    /// else read out of the capture: what the hex view shows is the body, not
    /// the transfer encoding it arrived under.
    #[test]
    fn the_bytes_the_console_gets_are_decoded() {
        let cap = Capture::new(Some("application/octet-stream".into()), Some("gzip"), 4096);
        cap.append(&gzip(&[0u8, 1, 2, 3, 255]));
        cap.finish();
        assert_eq!(
            cap.preview_bytes().bytes,
            Bytes::from_static(&[0, 1, 2, 3, 255])
        );
    }

    /// The bytes a capped preview holds are a prefix, and the flag that says so
    /// travels with them — a download offered as the whole file would be wrong
    /// in a way the file itself could not reveal.
    #[test]
    fn a_capped_preview_hands_over_a_prefix_that_admits_it() {
        let cap = Capture::new(Some("image/png".into()), None, 8);
        cap.append(&[b'x'; 200]);
        let pv = cap.preview_bytes();
        assert_eq!(pv.bytes.len(), 8);
        assert_eq!(pv.total, 200);
        assert!(pv.truncated);
    }

    /// Whether `text` is the body or a marker standing in for it, decided on
    /// this side so the console does not have to re-derive it.
    #[test]
    fn the_capture_says_whether_its_text_is_a_marker() {
        let binary = |ct: &str| {
            let v = serde_json::to_value(Capture::new(Some(ct.into()), None, 64)).unwrap();
            v["binary"].as_bool().unwrap()
        };
        assert!(binary("image/png"));
        assert!(binary("application/octet-stream"));
        assert!(!binary("text/html; charset=utf-8"));
        assert!(!binary("application/json"));
    }

    #[test]
    fn iso8601_conversion() {
        assert_eq!(super::iso8601_utc(0), "1970-01-01T00:00:00.000Z");
        // 1_000_000_000 s since epoch = 2001-09-09T01:46:40Z
        assert_eq!(
            super::iso8601_utc(1_000_000_000_000),
            "2001-09-09T01:46:40.000Z"
        );
        // milliseconds are preserved
        assert_eq!(
            super::iso8601_utc(1_609_459_200_123),
            "2021-01-01T00:00:00.123Z"
        );
    }
}

/// One operator a rule applied to a request, as recorded on its [`Session`].
///
/// This is the answer to "which rules matched?" — the question the console
/// exists to answer and the one it could not, because [`Resolved`] was consulted
/// for each decision and then dropped. What survived was the `log://` labels,
/// which the General tab showed under a heading people read as the matched
/// rules; a request whose `host://` rule never fired looked exactly like one
/// whose did.
///
/// Only the three fields that identify an operator are kept, not the whole
/// [`RuleOp`]: a session lives in a 500-deep ring, so what it holds is copied
/// 500 times over.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MatchedOp {
    /// Canonical protocol name (`host`, `resHeaders`, `redirect`, …) — the
    /// alias in the file has already been resolved to it.
    pub protocol: String,
    /// The value the operator resolved to. It is not always what was written:
    /// a `${name}` reference has been substituted by the time a request is
    /// recorded, which is exactly the difference worth seeing next to `raw`.
    pub value: String,
    /// The token as written on the line, shorthand and all.
    pub raw: String,
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
    ///
    /// Not "the rules that matched" — that is [`Session::rules`]. The two were
    /// conflated by the console for as long as only this one existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    /// Every operator that applied to this request, in resolution order — see
    /// [`matched_ops`]. Empty when no rule matched, which is the common case and
    /// costs nothing: an empty `Vec` allocates nothing and serializes to nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MatchedOp>,
    /// Request headers: the outgoing ones when the request was forwarded, and
    /// the client's own when it was answered here.
    ///
    /// The two are the same list seen from the two sides of a hop that a mocked
    /// request never makes — see [`capture_client_request`]. Which one a session
    /// holds follows from its `target`.
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
    /// Where the time went, when the request left the proxy at all. A request a
    /// rule answered has no phases, and reports none rather than a row of zeros
    /// — see [`timing::Timings`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<timing::Timings>,
    /// Why the request did not complete, when it did not — see [`outcome`].
    /// Absent for every request that got its whole answer, including one whose
    /// origin answered `502`: that is the origin's answer, not a failure here.
    #[serde(skip_serializing_if = "outcome::Outcome::is_ok")]
    pub error: outcome::Outcome,
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

/// Capture what the client sent, on a path that answers without forwarding it.
///
/// A short-circuit (`file://`, `redirect://`, `statusCode://`, a template) and a
/// plugin-answered request never build an outgoing request, so the recording
/// sites there had nothing to put in `req_headers`/`req_body` and left both
/// empty. The console's Request Header and Request Body tabs were therefore
/// blank for **every mocked request** — and looking at what the client sent to
/// an endpoint you have just mocked is an ordinary thing to want to do. It is an
/// inspection gap in the primary tool, not merely a limit on replay.
///
/// The headers are the client's own rather than a forwarded request's, because
/// on these paths there is no forwarded request to report. Showing the
/// rule-rewritten headers instead would name a hop that never happened.
///
/// The body is read to its end and discarded, keeping only the bounded preview.
/// Nothing downstream is waiting for these bytes, but the preview is what the
/// console shows and the total is what the traffic column counts — and reading
/// it is what a keep-alive connection needs anyway before the next request on it
/// can be framed. Memory is the preview cap, not the upload: a 1 GB POST to a
/// mocked endpoint costs 16 KiB here, because [`Capture`] stops copying once the
/// preview is full.
async fn capture_client_request(
    req: &mut Request<DynBody>,
    preview_cap: usize,
) -> (Vec<(String, String)>, Option<Capture>) {
    let headers = header_pairs(req.headers());
    if !has_request_body(req.headers()) {
        return (headers, None);
    }
    let capture = Capture::new(
        header_str(req.headers(), hyper::header::CONTENT_TYPE),
        header_str(req.headers(), hyper::header::CONTENT_ENCODING).as_deref(),
        preview_cap,
    );
    // Taken out rather than moved out of the request: the plugin path answers
    // from inside a loop over the matched plugins, where a move out of `req`
    // would be a move in a previous iteration.
    let body = std::mem::replace(req.body_mut(), body::empty());
    drain_into_capture(body, &capture).await;
    (headers, Some(capture))
}

/// Read `body` to its end, keeping only what `capture` has room for.
///
/// A client that hangs up mid-body ends the loop rather than failing the
/// request: the answer is already decided on these paths, and what arrived is
/// what there is to show.
async fn drain_into_capture(mut body: DynBody, capture: &Capture) {
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    capture.append(data);
                }
            }
            Err(err) => {
                tracing::debug!("client body ended early: {err:#}");
                break;
            }
        }
    }
    capture.finish();
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
    /// True while `enable://pauseSend|pauseReceive` is holding this frame: it
    /// was seen and recorded, and is waiting for someone to release it from the
    /// console. Cleared when it goes out; a frame still marked when the
    /// connection ended never reached the peer at all.
    pub held: bool,
}

impl WsFrame {
    /// Build a frame record, deriving the opcode name and a bounded preview.
    /// A frame cut out of an ordinary **body** — an SSE event, or a piece of a
    /// stream a `x-whistle-custom-frame-separator` named.
    ///
    /// It is filed as a `text` frame, which is what it is: whistle shows these
    /// in the same Frames panel as a WebSocket's, and the direction is the only
    /// thing that tells them apart there (`emitFrame`,
    /// `_original/lib/inspectors/data.js:67-75`).
    /// A frame the **console** sent into a live connection.
    ///
    /// Recorded like any other, because it is one: it went out on the wire and
    /// the peer cannot tell it from traffic. The direction says which way.
    pub(crate) fn console_frame(session: u64, dir: &str, payload: &[u8]) -> Self {
        let dir = match dir {
            "send" => "send",
            _ => "receive",
        };
        WsFrame::new(session, dir, 0x1, payload)
    }

    fn body_frame(session: u64, dir: &'static str, payload: &[u8]) -> Self {
        WsFrame::new(session, dir, 0x1, payload)
    }

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
            held: false,
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
    resolved
        .all("log")
        .iter()
        .map(|o| o.value.clone())
        .collect()
}

/// Collect every operator that applied to a request, in the order the rules file
/// would read them: important lines first, then source order — which is exactly
/// what [`crate::rules::order_key`] encodes and what decided each contest.
///
/// Called once per recorded session, at the point the session is built, so the
/// list is taken *after* the response phase has folded its operators in
/// ([`Resolved::merge_response_phase`]). Reading it earlier would report a
/// `resHeaders://` withheld by an `includeFilter://s:404` as never having
/// matched, on the requests where it did.
///
/// **A request no rule matched pays nothing.** The set is empty, the walk runs
/// zero times, and `Vec::new` does not allocate — so the common case is a couple
/// of `HashMap::is_empty`-shaped walks and a null pointer, not a heap allocation
/// holding nothing.
///
/// Ties are broken by protocol name so the list is stable between two identical
/// requests: the operators come out of a `HashMap`, whose iteration order is not.
/// Within one protocol the sort is stable, so several `reqHeaders://` written on
/// one line keep the order they were written in — which is the order in which
/// they are applied.
///
/// Only operators that **applied** are here, which is why the shared slot
/// contributes at most one: a `statusCode://` that lost to a `file://` did
/// nothing, and reporting it as a match would say the opposite.
fn matched_ops(resolved: &Resolved) -> Vec<MatchedOp> {
    let mut ops: Vec<(u64, &crate::rules::RuleOp)> =
        resolved.ops().map(|op| (op.order, op)).collect();
    ops.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.protocol.cmp(&y.protocol)));
    ops.into_iter()
        .map(|(_, op)| MatchedOp {
            protocol: op.protocol.clone(),
            value: op.value.clone(),
            raw: op.raw.clone(),
        })
        .collect()
}

#[cfg(test)]
mod forced_encoding_tests {
    use super::*;

    fn ops(rule: &str, has_body: bool) -> ResBodyOps {
        ops_ct(rule, has_body, None)
    }

    fn ops_ct(rule: &str, has_body: bool, streaming_ct: Option<&str>) -> ResBodyOps {
        let mut m = RuleManager::new();
        m.set_text(&format!("example.com {rule}\n"));
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        ResBodyOps::of(&m.resolve(&info), has_body, 200, streaming_ct)
    }

    /// An event stream is never collected, whatever the rule asks for.
    ///
    /// Collecting one does not delay the response, it withholds it: the body
    /// ends when the server says so, which for SSE is typically never, so the
    /// client receives nothing at all. Verified against a live SSE origin —
    /// before this gate, `enable://gzip` and `resReplace://` each produced not
    /// one byte in three seconds where the unruled host streamed events.
    #[test]
    fn an_event_stream_is_never_collected() {
        for rule in [
            "enable://gzip",
            "resReplace://tick=TOCK",
            "resBody://(x)",
            "resSpeed://10",
            "resAppend://(x)",
        ] {
            for ct in [
                "text/event-stream",
                "text/event-stream; charset=utf-8",
                "  TEXT/EVENT-STREAM ;charset=utf-8",
            ] {
                let ops = ops_ct(rule, true, Some(ct));
                assert!(
                    !ops.needs_body(),
                    "`{rule}` on `{ct}` would hold the stream shut"
                );
            }
        }
    }

    /// …and the gate is only about event streams. Any other type still gets
    /// every operator, or the fix would have bought the hang with the feature.
    #[test]
    fn an_ordinary_response_is_still_transformed() {
        for ct in [
            "text/html",
            "application/json",
            "text/event",
            "application/event-stream",
        ] {
            assert!(
                ops_ct("resReplace://a=b", true, Some(ct)).needs_body(),
                "{ct}"
            );
        }
        // A response with no content type at all is transformed as before.
        assert!(ops_ct("resReplace://a=b", true, None).needs_body());
        // `text/event-streamlike` *does* count as a stream: upstream's `SSE_RE`
        // is not anchored at the end. Pinned as **documented**, not as desired —
        // it is upstream's answer, and diverging here would be a divergence
        // nobody asked for.
        assert!(is_event_stream(Some("text/event-streamlike")));
    }

    /// A `Resolved` for one rule line, for the gate tests below.
    fn resolved_for(rule: &str) -> Resolved {
        let mut m = RuleManager::new();
        m.set_text(&format!("example.com {rule}\n"));
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        m.resolve(&info)
    }

    /// Not being collected is not the same as not being rewritten.
    /// `resReplace://` travels with the stream, so the operator that the gate
    /// above drops from the buffered path is picked up here instead.
    #[test]
    fn a_substitution_rides_along_with_an_event_stream() {
        let r = resolved_for("resReplace://tick=TOCK");
        let mut t = stream_replace(&r, Some("text/event-stream"), None)
            .expect("a substitution for an event stream");
        assert_eq!(
            String::from_utf8(t.push(b"data: tick\n\n")).unwrap(),
            "data: TOCK\n\n"
        );
    }

    /// The three refusals, each for its own reason — see [`stream_replace`].
    #[test]
    fn a_stream_that_cannot_be_substituted_is_left_alone() {
        let r = resolved_for("resReplace://tick=TOCK");
        assert!(
            stream_replace(&r, Some("text/html"), None).is_none(),
            "a body with an end belongs to the buffered path"
        );
        assert!(
            stream_replace(&r, Some("text/event-stream"), Some("gzip")).is_none(),
            "a compressed stream cannot be searched for a plaintext pattern"
        );
        assert!(
            stream_replace(&resolved_for("log://x"), Some("text/event-stream"), None).is_none(),
            "no substitutions means no transform to install"
        );
        // `identity` is the spelling of "no coding", so it is not a refusal.
        assert!(stream_replace(&r, Some("text/event-stream"), Some("identity")).is_some());
    }

    /// The operator gate and the stream gate must agree about which bodies
    /// `resReplace://` reaches, or a substitution would be applied on one path
    /// and skipped on the other for the same response.
    #[test]
    fn the_content_type_gate_is_the_same_on_both_paths() {
        // Upstream refuses the operator outright for an image, and an event
        // stream can carry one — `text/event-stream` is only the usual case.
        let r = resolved_for("resReplace://a=b");
        assert!(apply::res_replace_pairs(&r, Some("image/png")).is_empty());
        assert!(apply::res_replace_pairs(&r, None).is_empty());
        assert!(!apply::res_replace_pairs(&r, Some("text/event-stream")).is_empty());
    }

    /// `resPrepend://` and `resAppend://` do not need a body either — one goes
    /// before the first byte, the other after the last.
    #[test]
    fn an_event_stream_can_be_prepended_to_and_appended_to() {
        let r = resolved_for("resPrepend://(BEFORE) resAppend://(AFTER)");
        let inject = stream_injection(&r, Some("text/event-stream")).expect("an injection");
        assert_eq!(inject.top, b"BEFORE");
        assert_eq!(inject.bottom, b"AFTER");
        assert!(
            inject.replacement.is_none(),
            "the origin's body still flows"
        );
        // A body with an end belongs to the buffered path, which also applies
        // the typed families and the HTML gating this one cannot.
        assert!(stream_injection(&r, Some("text/html")).is_none());
    }

    /// `resBody://` says there is no origin body to wait for, which is what
    /// makes it usable as a mock for a stream that would never end.
    #[test]
    fn res_body_replaces_a_stream_rather_than_waiting_for_it() {
        // No space inside the parentheses: a rules line is whitespace-separated
        // tokens, so a multi-word body is named with `{a-value}` or a file.
        let r = resolved_for("resBody://(data:mocked)");
        let inject = stream_injection(&r, Some("text/event-stream")).expect("an injection");
        assert_eq!(inject.replacement.as_deref(), Some(&b"data:mocked"[..]));
    }

    /// Nothing here reads the origin's bytes, so unlike the substitution an
    /// encoded stream is no obstacle.
    #[test]
    fn an_injection_does_not_care_what_the_stream_is_encoded_as() {
        let r = resolved_for("resPrepend://(X)");
        assert!(stream_injection(&r, Some("text/event-stream")).is_some());
        assert!(
            stream_replace(
                &resolved_for("resReplace://a=b"),
                Some("text/event-stream"),
                Some("gzip")
            )
            .is_none(),
            "…where the substitution still refuses one"
        );
    }

    /// A line with none of these operators installs nothing.
    #[test]
    fn a_stream_no_operator_touches_gets_no_injection() {
        assert!(stream_injection(&resolved_for("log://x"), Some("text/event-stream")).is_none());
    }

    /// `disable://trailers` costs no buffering, so an event stream keeps it
    /// where it loses the operators that need the whole body.
    #[test]
    fn an_event_stream_still_drops_the_trailers_it_was_told_to() {
        let ops = ops_ct("disable://trailers", true, Some("text/event-stream"));
        assert!(ops.no_trailers);
        assert!(!ops.needs_body(), "and still does not hold the stream shut");
    }

    /// Gating the rule operators was not enough: a plugin declaring
    /// `responseBody` reaches the same collection through its own door, and is
    /// not a rule operator. Measured against a live SSE origin — not one byte
    /// in six seconds, not even a response head.
    #[test]
    fn a_plugin_asking_for_the_body_cannot_hold_an_event_stream_shut_either() {
        let sse = Some("text/event-stream");
        let ops = ops_ct("resReplace://a=b", true, sse);
        assert!(!must_collect_body(&ops, true, false, sse));
        // …and the gate is only about event streams: an ordinary response is
        // still collected for the hook that asked for it.
        let html = Some("text/html");
        let ops = ops_ct("log://x", true, html);
        assert!(must_collect_body(&ops, true, false, html));
    }

    /// The one door an event stream may pass through. A plugin that replaced
    /// the body outright hands over bytes that are already in hand, so the
    /// origin's stream is never awaited and nothing is withheld.
    #[test]
    fn an_overridden_body_is_collected_even_for_an_event_stream() {
        let sse = Some("text/event-stream");
        let ops = ops_ct("log://x", true, sse);
        assert!(must_collect_body(&ops, false, true, sse));
    }

    /// The bug: `enable://gzip` standing alone left `needs_body` false, so the
    /// response took the streaming path, `reencode` was never reached, and the
    /// flag did nothing at all. It only ever appeared to work when some *other*
    /// operator on the line happened to buffer the body for it.
    #[test]
    fn a_forced_encoding_alone_asks_for_the_buffered_path() {
        for flag in ["enable://gzip", "enable://br", "enable://deflate"] {
            let ops = ops(flag, true);
            assert!(ops.force_encoding.is_some(), "{flag}");
            assert!(
                ops.needs_body(),
                "{flag} must buffer, or it cannot be applied"
            );
        }
    }

    /// A response with no body has nothing to encode, so the flag must not drag
    /// it onto the buffered path — gzipping nothing produces a 20-byte header
    /// that says "nothing".
    #[test]
    fn a_response_with_no_body_is_not_buffered_to_encode_it() {
        let ops = ops("enable://gzip", false);
        assert!(ops.force_encoding.is_none());
        assert!(!ops.needs_body());
    }

    /// The streaming fast path is what most traffic takes, and nothing here may
    /// pull it onto the buffered one.
    #[test]
    fn a_response_no_operator_touches_still_streams() {
        assert!(!ops("log://x", true).needs_body());
    }

    /// A body that could not be decoded goes out exactly as it arrived,
    /// **including its header**. `reencode` refuses to force a coding onto such
    /// a body and reports `Identity` — and stamping that removes the header, so
    /// a `zstd` response would reach the client as zstd bytes labelled plain.
    /// That is worse than the flag doing nothing: it arrived readable and would
    /// leave unreadable.
    #[test]
    fn a_body_that_was_never_decoded_keeps_the_coding_it_arrived_under() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-encoding", "zstd".parse().expect("a header value"));
        let restore = coding::Restore {
            coding: coding::Coding::Identity,
            plain: false,
        };
        let now = restore_content_encoding(
            &mut headers,
            restore,
            coding::Coding::Identity,
            Some("zstd".to_string()),
        );
        assert_eq!(headers.get("content-encoding").expect("kept"), "zstd");
        // …and the capture is told what the body is really under, so the
        // preview does not try to read zstd as text.
        assert_eq!(now.as_deref(), Some("zstd"));
    }

    /// The ordinary case still stamps what was actually applied — including
    /// removing the header when a gzipped body was rewritten and goes out plain.
    #[test]
    fn a_decoded_body_is_labelled_with_what_went_back_on() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().expect("a header value"));
        let restore = coding::Restore {
            coding: coding::Coding::Gzip,
            plain: true,
        };
        let now = restore_content_encoding(
            &mut headers,
            restore,
            coding::Coding::Identity,
            Some("gzip".to_string()),
        );
        assert!(headers.get("content-encoding").is_none(), "must be removed");
        assert_eq!(now, None);

        let mut headers = hyper::HeaderMap::new();
        let now = restore_content_encoding(&mut headers, restore, coding::Coding::Brotli, None);
        assert_eq!(headers.get("content-encoding").expect("set"), "br");
        assert_eq!(now.as_deref(), Some("br"));
    }
}

#[cfg(test)]
mod client_capture_tests {
    use super::*;

    /// A request with a body, as the client sent it.
    fn posted(body: &'static [u8], content_type: &str) -> Request<DynBody> {
        Request::builder()
            .method("POST")
            .uri("http://example.com/api/items")
            .header("content-type", content_type)
            .header("content-length", body.len())
            .header("x-tenant", "acme")
            .body(body::full(Bytes::from_static(body)))
            .expect("a request")
    }

    /// The gap this closes: a mocked request recorded neither its headers nor
    /// its body, so the console's Request Header and Request Body tabs were
    /// blank for every request a rule answered locally.
    #[tokio::test]
    async fn a_request_answered_locally_still_records_what_the_client_sent() {
        let mut req = posted(br#"{"name":"third"}"#, "application/json");
        let (headers, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;

        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "x-tenant")
                .map(|(_, v)| v.as_str()),
            Some("acme"),
        );
        let (len, truncated, text) = body.expect("a captured body").snapshot();
        assert_eq!(
            (len, truncated, text.as_str()),
            (16, false, r#"{"name":"third"}"#)
        );
    }

    /// Memory is the preview cap, not the upload. A large POST to a mocked
    /// endpoint must not be held whole just to be shown.
    #[tokio::test]
    async fn a_large_upload_costs_the_preview_not_the_body() {
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header("content-type", "text/plain")
            .header("content-length", 200_000)
            .body(body::full(Bytes::from(vec![b'x'; 200_000])))
            .expect("a request");
        let (_, body) = capture_client_request(&mut req, 4096).await;

        let capture = body.expect("a captured body");
        let (len, truncated, text) = capture.snapshot();
        // The total is honest — it is what the traffic column counts — while
        // only the preview was kept.
        assert_eq!(len, 200_000);
        assert!(truncated);
        assert_eq!(text.len(), 4096);
    }

    /// A `GET` has no body to capture, and must not be given an empty one: an
    /// empty capture reads as "there was a body and it was empty".
    #[tokio::test]
    async fn a_request_without_a_body_captures_only_its_headers() {
        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("accept", "*/*")
            .body(body::empty())
            .expect("a request");
        let (headers, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        assert!(body.is_none());
        assert_eq!(headers.len(), 1);
    }

    /// The body is taken out of the request, not left to be sent twice. The
    /// plugin path answers from inside a loop and goes on to use `req`.
    #[tokio::test]
    async fn capturing_leaves_the_request_without_its_body() {
        let mut req = posted(b"payload", "text/plain");
        let _ = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        let left = collect_body(std::mem::replace(req.body_mut(), body::empty()))
            .await
            .expect("an empty body");
        assert!(left.is_empty());
    }

    /// A compressed upload is previewed decoded, the same as on the forwarded
    /// path — the tab shows what was sent, not the deflate stream.
    #[tokio::test]
    async fn a_compressed_upload_is_previewed_decoded() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"upload me").expect("gzip");
        let gz = e.finish().expect("gzip");
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .header("content-type", "text/plain")
            .header("content-encoding", "gzip")
            .header("content-length", gz.len())
            .body(body::full(Bytes::from(gz)))
            .expect("a request");
        let (_, body) = capture_client_request(&mut req, BODY_PREVIEW_CAP).await;
        assert_eq!(body.expect("a captured body").snapshot().2, "upload me");
    }
}

#[cfg(test)]
mod matched_ops_tests {
    use super::*;

    /// Resolve `text` against `GET http://example.com/api` and record what
    /// matched, the way a session does.
    fn matched(text: &str) -> Vec<MatchedOp> {
        let mut m = RuleManager::new();
        m.set_text(text);
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/api",
            &hyper::HeaderMap::new(),
            None,
        );
        matched_ops(&m.resolve(&info))
    }

    /// The list a session carries has to be readable as the rules file: the
    /// important line first, then source order. Anything else and the console
    /// would show a *set* of operators, leaving "which one won" — the question
    /// two lines setting `host://` are asked about — unanswerable.
    #[test]
    fn the_operators_come_out_in_the_order_that_decided_them() {
        let ops = matched(concat!(
            "example.com reqHeaders://x-a=1\n",
            "example.com resHeaders://x-b=2\n",
            "example.com reqHeaders://x-c=3 lineProps://important\n",
        ));
        let seen: Vec<(&str, &str)> = ops
            .iter()
            .map(|o| (o.protocol.as_str(), o.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                // `$` marks the line important, so it resolves first.
                ("reqHeaders", "x-c=3"),
                ("reqHeaders", "x-a=1"),
                ("resHeaders", "x-b=2"),
            ]
        );
    }

    /// Two `reqHeaders://` on one line share an order key, and the order they
    /// are *applied* in is the order they were written in. A sort that lost it
    /// would show the losing header on top for a line that sets the same name
    /// twice.
    #[test]
    fn operators_sharing_a_line_keep_the_order_they_were_written_in() {
        let ops = matched("example.com reqHeaders://x-a=1 reqHeaders://x-a=2\n");
        let seen: Vec<&str> = ops.iter().map(|o| o.value.as_str()).collect();
        assert_eq!(seen, ["x-a=1", "x-a=2"]);
    }

    /// The token as written is kept beside what it resolved to, because they
    /// are not the same thing: a shorthand names a protocol it does not spell,
    /// and `example.com 1.2.3.4` is the form most likely to be doubted.
    #[test]
    fn a_shorthand_is_reported_under_the_protocol_it_means() {
        let ops = matched("example.com 1.2.3.4\n");
        assert_eq!(
            ops,
            [MatchedOp {
                protocol: "host".into(),
                value: "1.2.3.4".into(),
                raw: "1.2.3.4".into(),
            }]
        );
    }

    /// The hot path: a request no rule matched records an empty list, and an
    /// empty `Vec` neither allocates nor serializes. This is the majority of
    /// traffic through a proxy whose rules file names one host.
    #[test]
    fn a_request_no_rule_matched_carries_nothing() {
        let ops = matched("other.example.net host://1.2.3.4\n");
        assert!(ops.is_empty());
        assert_eq!(ops.capacity(), 0, "an empty list must not have allocated");
        let session = Session {
            rules: ops,
            ..Default::default()
        };
        let json = serde_json::to_value(&session).expect("a session serializes");
        assert!(json.get("rules").is_none(), "{json}");
    }

    /// Which rules matched is the thing the detail view is for, so it has to
    /// survive the trip through `/session.json`.
    #[test]
    fn the_operators_reach_the_console() {
        let session = Session {
            rules: matched("example.com http://localhost:5173 log://api\n"),
            ..Default::default()
        };
        let json = serde_json::to_value(&session).expect("a session serializes");
        let rules = json["rules"].as_array().expect("an array");
        assert!(
            rules
                .iter()
                .any(|r| r["protocol"] == "log" && r["value"] == "api"),
            "{json}"
        );
        // …and the pair of fields earns its keep on the forwarding shorthand:
        // `raw` is the token as typed, `value` is where the request was
        // actually sent — path and all. Reporting only one of them would leave
        // "why did /api go there" a question the console cannot answer.
        let replace = rules
            .iter()
            .find(|r| r["raw"] == "http://localhost:5173")
            .expect("the forwarding operator");
        assert_eq!(replace["value"], "http://localhost:5173/api");
    }
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
    let requested = SocketAddr::new(state.config.bind_ip(), state.config.port);
    let listener = TcpListener::bind(requested).await?;
    let addr = listener.local_addr().unwrap_or(requested);
    tracing::info!("whistle-rs listening on http://{addr}");

    // Teach the forwarding layer which addresses are *us*, so a `proxy://` rule
    // naming this proxy is refused instead of recursing into it. Registered
    // before the first connection is accepted; see `upstream::self_loop`.
    // The *bound* port, not the requested one, or port 0 would register nothing.
    let mut own_ports = vec![addr.port()];
    own_ports.extend(state.config.socks_port);
    own_ports.extend(state.config.ui_port);
    upstream::register_listen(Some(state.config.bind_ip()), &own_ports);

    // The same fact the include layer needs for a `${port}` in a backticked
    // `@` source: `--port 0` means the operating system chose, and this is the
    // first moment anyone knows what it chose.
    state.rules.write().unwrap().set_include_port(addr.port());
    tracing::info!(
        "root CA: {} (download at http://{}/rootCA.crt)",
        // The file actually in use, which `--cert-dir` may have replaced.
        state.ca.root_cert_path().display(),
        addr
    );
    // The address to give a phone. `0.0.0.0:8899` is not something anyone can
    // type into a Wi-Fi proxy field, and `mobile.md` is an entire page about
    // typing exactly that in — whistle's own `w2 status` prints the reachable
    // URLs for the same reason. This prints the one a device on the same network
    // should use, when it is not the address that was bound anyway.
    // Who else can reach it, said once, where the operator is looking.
    if addr.ip().is_loopback() {
        tracing::info!(
            "only this machine can use the proxy (bound to {}); to use it from a phone \
             or another machine, restart with -H 0.0.0.0 — and set a console login \
             (-n/-w) first",
            addr.ip()
        );
    } else if state.config.ui_username.is_none() && state.config.ui_password.is_none() {
        tracing::warn!(
            "listening on {addr} with no console login: anyone who can reach this port \
             can use the proxy and rewrite its rules, which read and write files on this \
             machine. Set -n/-w, or bind 127.0.0.1"
        );
    }
    if addr.ip().is_unspecified() {
        let candidates = lan_addresses();
        if !candidates.is_empty() {
            let urls: Vec<String> = candidates
                .iter()
                .map(|ip| format!("http://{ip}:{}", addr.port()))
                .collect();
            tracing::info!(
                "on this network: {} — set one as the proxy on a phone (try each \
                 if unsure), then open http://rootca.pro/ to install the certificate",
                urls.join("  ")
            );
        }
    }
    Ok((listener, addr))
}

/// The addresses a device on the same network might reach this machine at.
///
/// No interface enumeration and no new dependency: a UDP socket *connected* to
/// an address sends nothing, and the kernel fills in the local address it would
/// have used to get there. Asking that once per private range is asking "if
/// something on a 10.x network talked to me, which of my addresses would it be
/// talking to" — and the answers, deduplicated, are the candidates.
///
/// **Several, not one.** A single probe against a public address returns
/// whatever holds the default route, which on a machine running a VPN is the
/// tunnel — an address no phone on the Wi-Fi can reach. Upstream sidesteps the
/// same problem by listing every interface and telling you to try them in turn
/// (`getIpList`, `_original/bin/util.js:33-49`, and the FAQ's "试看看"), and this
/// keeps that shape.
///
/// Only private addresses are offered. A public one is either a server, where
/// this line is not the advice anyone needs, or a VPN's, where it is wrong.
pub(crate) fn lan_addresses() -> Vec<std::net::IpAddr> {
    let probe = |target: &str| -> Option<std::net::IpAddr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect(target).ok()?;
        Some(sock.local_addr().ok()?.ip())
    };
    let private = |ip: &std::net::IpAddr| match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(_) => false,
    };
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    // `224.0.0.1` — the all-hosts multicast group — first, and it is the one
    // that works. Link-local multicast is not carried through a tunnel, so the
    // kernel answers with the physical interface even on a machine whose default
    // route belongs to a VPN. Measured here: with a full-tunnel VPN running,
    // every unicast probe below answers with the tunnel's own address and this
    // one answers `192.168.2.203`, which is what the phone on the same Wi-Fi can
    // actually reach.
    //
    // Then one target per RFC 1918 range, which adds a second interface on a
    // machine that has one and costs nothing on a machine that does not.
    for target in [
        "224.0.0.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80",
        "192.168.0.1:80",
    ] {
        if let Some(ip) = probe(target)
            && private(&ip)
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod lan_tests {
    /// Whatever this machine's network looks like, the answer has a shape: only
    /// private IPv4 addresses, and no duplicates.
    ///
    /// It cannot assert *which* addresses without asserting a fact about the
    /// machine running the test — a CI container may have none, and this one has
    /// a VPN that hides them from every unicast probe. What it can hold is that
    /// nothing public, loopback or repeated ever reaches the line a person is
    /// about to type into a phone.
    #[test]
    fn the_addresses_offered_are_private_and_distinct() {
        let found = super::lan_addresses();
        let mut seen = std::collections::HashSet::new();
        for ip in &found {
            assert!(seen.insert(*ip), "{ip} offered twice");
            match ip {
                std::net::IpAddr::V4(v4) => {
                    assert!(v4.is_private(), "{v4} is not an address on a local network");
                    assert!(!v4.is_loopback(), "{v4} is this machine talking to itself");
                }
                std::net::IpAddr::V6(v6) => panic!("{v6}: only IPv4 is offered"),
            }
        }
    }
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
    // The console on its own port, when `-P/--uiport` named one. Upstream
    // starts a second plain HTTP server for exactly this case and serves the UI
    // and nothing else on it (`customUIPort`, `_original/biz/init.js:8-19`);
    // this is that server. A port equal to the proxy's is not a second server
    // in either program — there the console already answers.
    if let Some(ui_port) = state.config.ui_port.filter(|p| *p != state.config.port) {
        let ui_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_console(ui_state, ui_port).await {
                tracing::error!("console server error: {e}");
            }
        });
    }

    // Optional inbound SOCKS5 server.
    if let Some(socks_port) = state.config.socks_port {
        let socks_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = socks::run(socks_state, socks_port).await {
                tracing::error!("SOCKS server error: {e}");
            }
        });
    }

    // `@` includes, before the first connection is answered.
    //
    // The socket is already bound, so a client connecting during a slow fetch
    // waits in the backlog rather than being refused — and a rules file that
    // says `@https://intra/rules.txt` is *in effect* for the first request
    // rather than for the second. Each fetch is capped at 16 s and a proxy
    // whose rules name no include does no work here at all.
    let resolves_includes = state.rules.read().unwrap().resolves_includes();
    if resolves_includes {
        let landed = crate::rules::include::load_pending(&state.rules).await;
        tracing::info!("resolved {landed} rules include(s)");
        let poller = state.clone();
        tokio::spawn(async move { crate::rules::include::poll(&poller.rules).await });
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

/// Serve the console, and only the console, on its own port.
///
/// Every request here is the UI's: there is no proxying, no CONNECT and no
/// rules — a client that wants those has the proxy port. That is upstream's
/// arrangement too, whose UI server is a bare `http.createServer()` with the
/// web UI's own handler on it and nothing of the proxy attached
/// (`_original/biz/init.js:8-19`).
async fn run_console(state: Arc<AppState>, port: u16) -> Result<()> {
    let addr = SocketAddr::new(state.config.bind_ip(), port);
    serve_console(state, TcpListener::bind(addr).await?).await
}

/// [`run_console`] on a socket that is already bound. Split out so a test can
/// bind port 0 and keep holding it: dropping a probe listener and re-binding
/// its number lost the port to a parallel test about one run in twenty.
async fn serve_console(state: Arc<AppState>, listener: TcpListener) -> Result<()> {
    tracing::info!("console listening on http://{}", listener.local_addr()?);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("console accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(webui::handle(&state, req).await) }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("console connection from {peer} closed: {err}");
            }
        });
    }
}

#[cfg(test)]
mod websocket_flag_tests {
    use super::*;

    fn req(upgrade: Option<&str>) -> Request<DynBody> {
        let mut b = Request::builder().method("GET").uri("http://a.com/ws");
        if let Some(u) = upgrade {
            b = b.header(hyper::header::UPGRADE, u);
        }
        b.body(body::empty()).expect("request")
    }

    fn resolved(rules: &str) -> Resolved {
        let mut m = RuleManager::new();
        m.set_text(rules);
        let info = apply::build_req_info(
            "GET",
            "http",
            "a.com",
            80,
            "/ws",
            &hyper::HeaderMap::new(),
            None,
        );
        m.resolve(&info)
    }

    /// `enable://websocket` is the flag for a client that speaks WebSocket
    /// under a name of its own: upstream reads
    /// `socket.enable.websocket || util.isWebSocket(headers)`
    /// (`_original/lib/https/index.js:81`), so the header decides unless the
    /// flag overrules it.
    #[test]
    fn a_nonstandard_upgrade_is_a_websocket_when_the_flag_says_so() {
        let none = resolved("");
        assert!(is_websocket(&req(Some("websocket")), &none));
        assert!(is_websocket(&req(Some("WebSocket")), &none));
        assert!(!is_websocket(&req(Some("ws-custom")), &none));
        assert!(!is_websocket(&req(None), &none));

        let on = resolved("a.com enable://websocket");
        assert!(is_websocket(&req(Some("ws-custom")), &on));
        assert!(is_websocket(&req(None), &on));
        // `disable://` beats it, as it beats every flag (`isEnable`,
        // `_original/lib/util/index.js:678-680`).
        let off = resolved("a.com enable://websocket\na.com disable://websocket");
        assert!(!is_websocket(&req(Some("ws-custom")), &off));
    }
}

#[cfg(test)]
mod hide_tests {
    use super::*;

    fn session(rules: &[(&str, &str)]) -> Session {
        let mut s = Session {
            id: 0,
            time_ms: 0,
            method: "GET".into(),
            url: "http://a.com/".into(),
            status: 200,
            client_ip: None,
            target: String::new(),
            duration_ms: 0,
            log: Vec::new(),
            rules: Vec::new(),
            req_headers: Vec::new(),
            res_headers: Vec::new(),
            req_body: None,
            res_body: None,
            timings: None,
            error: Default::default(),
        };
        s.rules = rules
            .iter()
            .map(|(protocol, value)| MatchedOp {
                protocol: (*protocol).to_string(),
                value: (*value).to_string(),
                raw: format!("{protocol}://{value}"),
            })
            .collect();
        s
    }

    /// `checkHideProp` (`_original/lib/util/index.js:3982-3987`) is four flags:
    /// two that hide and two that un-hide, with un-hiding winning.
    #[test]
    fn hide_and_the_three_flags_that_argue_with_it() {
        assert!(!is_hidden(&session(&[])));
        assert!(is_hidden(&session(&[("enable", "hide")])));
        assert!(is_hidden(&session(&[("disable", "show")])));
        // Un-hiding wins, from either side.
        assert!(!is_hidden(&session(&[
            ("enable", "hide"),
            ("enable", "show")
        ])));
        assert!(!is_hidden(&session(&[
            ("enable", "hide"),
            ("disable", "hide")
        ])));
        assert!(!is_hidden(&session(&[
            ("disable", "show"),
            ("enable", "show")
        ])));
        // The value is a prop list, so one line may carry several flags.
        assert!(is_hidden(&session(&[("enable", "gzip|hide")])));
        assert!(!is_hidden(&session(&[("enable", "gzip|hide|show")])));
        // A flag that merely contains the word is not the word.
        assert!(!is_hidden(&session(&[("enable", "hideComposer")])));
    }
}

#[cfg(test)]
mod console_port_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A state with its own storage directory, so two tests never race over one
    /// root CA.
    fn state(ui_port: Option<u16>) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-console-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ui_port,
            ..Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, RuleManager::new(), ca))
    }

    /// No `-H`: this machine only. It used to be every interface, which made a
    /// fresh start an open proxy — and an open console — for the whole network.
    #[tokio::test]
    async fn with_no_host_it_listens_on_loopback() {
        let config = Config {
            port: 0,
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-bind-default-{}", std::process::id())),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        let s = Arc::new(AppState::new(config, RuleManager::new(), ca));
        let (_listener, addr) = bind(&s).await.expect("bind");
        assert!(addr.ip().is_loopback(), "bound {addr}");
        assert!(!s.config.listens_beyond_loopback());
    }

    /// `-P/--uiport` serves the console, and only the console: the page and the
    /// capture API answer, and a request that would be a *proxy* request on the
    /// other port is not one here.
    #[tokio::test]
    async fn the_console_answers_on_its_own_port() {
        // Bound here and handed over, never dropped and re-bound: the port is
        // ours from this line on, and connects queue in the backlog until the
        // server task first polls `accept`.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let state = state(Some(port));
        let server = state.clone();
        tokio::spawn(async move { serve_console(server, listener).await });

        let url = format!("http://127.0.0.1:{port}");
        let page = reqwest_get(&format!("{url}/")).await.expect("index");
        assert!(
            page.starts_with("HTTP/1.1 200"),
            "index: {}",
            &page[..40.min(page.len())]
        );
        assert!(page.contains("<!doctype html>") || page.contains("<!DOCTYPE html>"));

        let api = reqwest_get(&format!("{url}/sessions.json"))
            .await
            .expect("sessions");
        assert!(
            api.starts_with("HTTP/1.1 200"),
            "sessions: {}",
            &api[..40.min(api.len())]
        );

        // Nothing here proxies: an unknown path is a 404 from the UI, not a
        // gateway error from a forward that was never attempted.
        let missing = reqwest_get(&format!("{url}/nope")).await.expect("404");
        assert!(
            missing.starts_with("HTTP/1.1 404"),
            "unknown: {}",
            &missing[..40.min(missing.len())]
        );
    }

    /// One raw GET, so the test needs no HTTP client dependency.
    async fn reqwest_get(url: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.strip_prefix("http://").unwrap_or(url);
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let mut stream = tokio::net::TcpStream::connect(authority).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// Entry point for every request arriving on the main port.
async fn top_level(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    if req.method() == hyper::Method::CONNECT {
        return handle_connect(state, req, peer);
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    // …unless the path opens with the escape hatch. Everything addressed to the
    // proxy's own port is its console, and `/-/` (or `/_/`) is how upstream lets
    // a client say "this one is an ordinary request, not an instruction to you"
    // — it strips the prefix and lets the request fall through to the rules
    // (`_original/biz/index.js:114-129`, and the FAQ's answer to "how do I reach
    // the proxy port without being taken for an internal request").
    //
    // The request then names *this* proxy, so what happens next is a rule's to
    // decide: `http://127.0.0.1:8899/x https://api.example.com/x` is the FAQ's
    // own example. With no rule it meets the self-loop guard and answers 302,
    // which is what upstream does with it too.
    if let Some(uri) = bypass_console(&req) {
        *req.uri_mut() = uri;
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    // …and unless it names somebody else. "Addressed to the proxy's own port"
    // is what the `Host` says, not where the socket went: an origin-form
    // request for `api.example.com` is a client with no proxy configured — a
    // hosts-file entry, a WebSocket library pointed at the proxy — and whistle
    // forwards it like any other (`_original/biz/index.js:98-106`,
    // `lib/upgrade.js:23-24`: the console only under one of its names, or this
    // machine's address on the proxy port). This port sent every such request
    // to the console, which after the rebinding check answered 403.
    //
    // A name that resolves back to this proxy is not served the console under
    // it — that is the rebinding attack — but redirected to the console's
    // address, in `serve`.
    if let Some(uri) = forwarded_by_name(&state, &req) {
        // This proxy sent the request here itself: `serve` did not know the
        // name for one of its own addresses. Refused rather than sent round
        // again — see `upstream::LOOP_HEADER`.
        if req
            .headers()
            .get(upstream::LOOP_HEADER)
            .is_some_and(|v| v == upstream::loop_nonce())
        {
            return Ok(loop_detected(&uri));
        }
        *req.uri_mut() = uri;
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    req.headers_mut().remove(upstream::LOOP_HEADER);
    Ok(webui::handle(&state, req).await)
}

/// The absolute-form URI of an origin-form request whose `Host` is not a name
/// for the console, or `None` when it is one (or says nothing).
fn forwarded_by_name<B>(state: &Arc<AppState>, req: &Request<B>) -> Option<hyper::Uri> {
    let host = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
    if host.is_empty() || webui::host_names_console(state, host) {
        return None;
    }
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    format!("http://{host}{path}").parse().ok()
}

/// `508 Loop Detected` for a request this proxy forwarded to itself.
fn loop_detected(uri: &hyper::Uri) -> Response<DynBody> {
    tracing::warn!("{uri} came back to this proxy after it forwarded it; refusing");
    Response::builder()
        .status(StatusCode::LOOP_DETECTED)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(format!(
            "whistle-rs: {uri} resolves to this proxy, which forwarded it to itself\n"
        ))))
        .expect("static 508")
}

/// `/-/…` and `/_/…` on the proxy's own port: the absolute-form URI the request
/// would have had if the client had gone through the proxy properly.
///
/// Returns `None` when the path carries neither prefix, or when there is no
/// `Host` header to build an authority from — a request with neither is not one
/// this proxy can forward anywhere.
fn bypass_console(req: &Request<Incoming>) -> Option<hyper::Uri> {
    let path_and_query = req.uri().path_and_query()?.as_str();
    let rest = path_and_query
        .strip_prefix("/-/")
        .or_else(|| path_and_query.strip_prefix("/_/"))?;
    let host = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
    format!("http://{host}/{rest}").parse().ok()
}

/// Handle a CONNECT: acknowledge, then intercept the tunnel with MITM.
fn handle_connect(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    let Some((host, port)) = authority_host_port(req.uri()) else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"bad CONNECT target")))
            .unwrap());
    };

    // The last moment a tunnel can be refused: everything below this line has
    // already told the client it is open. See [`tunnel_aborted`].
    if tunnel_aborted(&state, &host, port, peer) {
        return Err(Destroyed);
    }

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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(body::empty())
        .unwrap())
}

/// Does a rule refuse to carry this connection — and, when one does, record the
/// refusal so an aborted tunnel is visible rather than simply absent.
///
/// This is whistle's tunnel-side abort. Upstream tests it twice on a CONNECT it
/// carries: once before the origin is dialled (`needAbortReq`,
/// `_original/lib/tunnel.js:372-374`) and once instead of writing the CONNECT
/// reply (`needAbortRes`, `tunnel.js:748-750`). Both end in the same
/// `reqSocket.destroy()`, so the client observes the same thing either way — a
/// CONNECT that is never answered — and here the two collapse into one gate,
/// because hyper hands over the tunnel's bytes only *after* the answer to the
/// CONNECT has gone out. What that costs is `abortRes`'s one distinguishing
/// effect: upstream has dialled the origin by the time it fires, and this port
/// has not. Buying it back would mean acknowledging the CONNECT first, and then
/// neither gate can produce the silence the abort exists for.
///
/// `disable://tunnel` is the third arm of the same two predicates — on a tunnel
/// it *is* an abort (`_original/lib/util/index.js:3900,:3912`) — and, like the
/// other two, `disable://abort` calls it off, that being the first thing both
/// predicates test (`util/index.js:3893,:3905`).
///
/// Upstream skips this gate entirely on a tunnel it decides to intercept
/// (`tunnel.js:251-277` dispatches to the MITM server and returns, so
/// `handleTunnel` is never reached) and lets the abort bite on each request
/// inside instead. This port cannot follow it there: the interception decision
/// needs the ClientHello, which only arrives once the CONNECT has been
/// acknowledged. So the gate runs for every connection, intercepted or relayed,
/// and an aborted CONNECT is one refused session rather than N refused requests.
/// Requests inside a tunnel that is *not* refused still meet the request-side
/// gate in [`serve`], and a path-scoped `enable://abort` only ever reaches that
/// one — a connection has no path to match.
///
/// The connection is matched on the [`ReqInfo`] the SNI stage already defines
/// ([`sni::connection_req_info`]): the address, the client, `from:tunnel`, and
/// nothing invented. One resolution per connection is what upstream pays too
/// (`rules.initRules(req)` per CONNECT, `tunnel.js:155-160`), and against the
/// TLS handshake that follows it does not show up.
fn tunnel_aborted(state: &Arc<AppState>, host: &str, port: u16, peer: SocketAddr) -> bool {
    let started = Instant::now();
    let time_ms = now_ms();
    // Scoped so the read guard is dropped before anything is recorded.
    let (info, resolved) = {
        let rules = state.rules.read().unwrap();
        // No ClientHello has been read yet, so this connection has named no
        // server: `from:sni` is false, not unknown.
        let info = sni::connection_req_info(host, port, peer, false);
        let resolved = rules.resolve(&info);
        (info, resolved)
    };
    let disabled = apply::disabled_flags(&resolved);
    let refuses_tunnel = disabled.contains("tunnel")
        && !disabled.contains("abort")
        && !(disabled.contains("abortReq") && disabled.contains("abortRes"));
    if !apply::aborts_request(&resolved) && !apply::aborts_response(&resolved) && !refuses_tunnel {
        return false;
    }
    tracing::info!("CONNECT {} -> aborted", info.full_url);
    state.record(Session {
        id: 0,
        time_ms,
        // Upstream records the tunnel under the method the client sent, which
        // for a SOCKS client is the CONNECT its own front end issued against
        // whistle's port (`_original/lib/index.js:166-173`).
        method: "CONNECT".to_string(),
        // The URL the rules matched, so the row and the rule agree.
        url: info.full_url.clone(),
        // Nothing answered and nothing will: upstream writes the string
        // `'aborted'` here (`tunnel.js:31-36`) where this port has a number, and
        // 0 is the console's "no status" (it already paints it as a warning).
        status: 0,
        client_ip: Some(peer.ip().to_string()),
        // Not "somewhere, aborted": no address was dialled at all.
        target: "aborted".to_string(),
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(&resolved),
        rules: matched_ops(&resolved),
        // A connection has no request headers the rules were allowed to see —
        // see [`sni::connection_req_info`] — so showing some here would be
        // showing what did not take part in the decision.
        error: aborted(
            "tunnel refused by a rule (enable://abort, abortReq, abortRes or disable://tunnel)",
        ),
        ..Default::default()
    });
    true
}

#[cfg(test)]
pub(crate) mod tunnel_abort_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// State over a storage directory nobody else touches, with `rules` loaded.
    pub(crate) fn state_with(rules: &str) -> Arc<AppState> {
        state_with_plugins(rules, crate::plugins::Plugins::new())
    }

    /// [`state_with`], with `plugins` as the registry.
    pub(crate) fn state_with_plugins(
        rules: &str,
        plugins: crate::plugins::Plugins,
    ) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = crate::config::Config {
            port: 0,
            host: Some("127.0.0.1".parse().unwrap()),
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-abort-{}-{n}", std::process::id())),
            persist_sessions: false,
            ..crate::config::Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("root CA");
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        Arc::new(AppState::with_plugins(config, mgr, ca, plugins))
    }

    pub(crate) fn peer() -> SocketAddr {
        "127.0.0.1:51234".parse().unwrap()
    }

    /// Would `rules` refuse a tunnel to `example.com:443`?
    fn refuses(rules: &str) -> bool {
        tunnel_aborted(&state_with(rules), "example.com", 443, peer())
    }

    /// The tunnel gate is armed and called off by exactly the flags the request
    /// gate is, because it is the same pair of predicates
    /// (`needAbortReq`/`needAbortRes`, `_original/lib/util/index.js:3891-3913`)
    /// read at a different moment.
    #[test]
    fn a_tunnel_is_refused_by_either_spelling_and_spared_by_either_cancellation() {
        for rules in [
            "example.com enable://abort",
            "example.com enable://abortReq",
            "example.com enable://abortRes",
            // One side cancelled still leaves the other armed, and on a tunnel
            // both end in the same silence.
            "example.com enable://abort disable://abortReq",
            "example.com enable://abort disable://abortRes",
        ] {
            assert!(refuses(rules), "{rules}");
        }
        for rules in [
            "",
            "example.com enable://abort disable://abort",
            "example.com enable://abortReq disable://abortReq",
            // A different host's rule is a different host's rule.
            "other.test enable://abort",
        ] {
            assert!(!refuses(rules), "{rules}");
        }
    }

    /// `disable://tunnel` has no meaning anywhere else — upstream reads it only
    /// as the last arm of these two predicates (`util/index.js:3900,:3912`), so
    /// this is the one path on which it does anything at all.
    #[test]
    fn disable_tunnel_refuses_the_connection_and_disable_abort_calls_it_off() {
        assert!(refuses("example.com disable://tunnel"));
        assert!(!refuses("example.com disable://tunnel disable://abort"));
        // Each predicate tests its own cancellation before it reaches the tunnel
        // arm, so cancelling both named gates cancels that arm with them.
        assert!(!refuses(
            "example.com disable://tunnel disable://abortReq disable://abortRes"
        ));
    }

    /// A connection has no path, so a path-scoped abort cannot match one — and
    /// must not, or `example.com/api enable://abort` would take the whole host
    /// off the air instead of one endpoint. The request inside still meets the
    /// request-side gate.
    #[test]
    fn a_path_scoped_abort_leaves_the_tunnel_alone() {
        assert!(!refuses("example.com/api enable://abort"));
    }

    /// A refused tunnel is a session, not a silence: whistle emits the request
    /// event before the gate and marks the result `aborted`
    /// (`_original/lib/tunnel.js:338,:31-36`), so the console shows what was
    /// refused. Recording nothing would make an abort indistinguishable from a
    /// rule that never fired.
    #[test]
    fn an_aborted_tunnel_is_recorded_rather_than_vanishing() {
        let state = state_with("example.com enable://abort log://blocked");
        assert!(tunnel_aborted(&state, "example.com", 443, peer()));
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.front().expect("the refusal is recorded");
        assert_eq!(session.method, "CONNECT");
        assert_eq!(session.url, "https://example.com/");
        assert_eq!(session.status, 0, "nothing answered");
        assert_eq!(session.target, "aborted", "nothing was dialled");
        assert_eq!(session.client_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(session.log, ["blocked"]);
        assert!(
            session.rules.iter().any(|op| op.protocol == "enable"),
            "the rule that refused it is on the row"
        );
    }

    /// A tunnel nobody refused is not recorded here at all — this gate exists to
    /// stop connections, not to log every CONNECT twice.
    #[test]
    fn a_tunnel_no_rule_refuses_is_left_unrecorded() {
        let state = state_with("example.com enable://abort");
        assert!(!tunnel_aborted(&state, "other.test", 443, peer()));
        assert!(state.sessions.lock().unwrap().is_empty());
    }

    /// Start a proxy on an ephemeral port with `rules` loaded.
    pub(crate) async fn proxy_with(rules: &str) -> (Arc<AppState>, SocketAddr) {
        proxy_with_plugins(rules, crate::plugins::Plugins::new()).await
    }

    /// [`proxy_with`], with `plugins` as the registry.
    pub(crate) async fn proxy_with_plugins(
        rules: &str,
        plugins: crate::plugins::Plugins,
    ) -> (Arc<AppState>, SocketAddr) {
        let state = state_with_plugins(rules, plugins);
        let (listener, addr) = bind(&state).await.expect("bind");
        let serving = state.clone();
        tokio::spawn(async move {
            accept_loop(serving, listener, None).await.ok();
        });
        (state, addr)
    }

    /// `/-/` and `/_/` on the proxy's own port say "this is an ordinary request".
    ///
    /// Everything addressed to that port origin-form is the console, so a client
    /// with no proxy configured cannot otherwise reach a rule at all. Upstream
    /// strips the prefix and lets the request fall through
    /// (`_original/biz/index.js:114-129`); measured against whistle 2.10.8 with
    /// the FAQ's own example, both proxies land the request on the origin the
    /// rule names, and both answer the console's 404 without the prefix.
    #[tokio::test]
    async fn the_console_port_has_an_escape_hatch() {
        // A one-line origin, so the test can see *where* the request landed.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let origin = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("?").to_string();
                    let body = format!("LANDED {path}");
                    let res = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    sock.write_all(res.as_bytes()).await.ok();
                });
            }
        });

        // The pattern names the proxy's own port, which the test does not know
        // yet — so it is written as the regexp that any of them matches.
        let (_state, addr) = proxy_with(&format!(
            r"/^http:\/\/127\.0\.0\.1:\d+\/hop$/ http://{origin}/landed"
        ))
        .await;

        let get = |path: String| async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.ok();
            String::from_utf8_lossy(&got).to_string()
        };

        for prefix in ["/-/", "/_/"] {
            let answer = get(format!("{prefix}hop")).await;
            assert!(answer.starts_with("HTTP/1.1 200"), "{prefix}: {answer}");
            assert!(answer.contains("LANDED /landed"), "{prefix}: {answer}");
        }
        // Without the prefix the same path is the console's to answer.
        let answer = get("/hop".to_string()).await;
        assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    }

    /// End to end: the client's CONNECT is never answered. Upstream destroys the
    /// socket (`_original/lib/tunnel.js:372-374,:748-750`) rather than refusing
    /// with a status, and a status is what the whole feature is trying not to
    /// produce — a `502` to a CONNECT is a *served* answer a client can report,
    /// cache and retry against.
    #[tokio::test]
    async fn a_refused_connect_gets_no_reply_at_all() {
        let (state, addr) = proxy_with("blocked.test enable://abort").await;

        let mut refused = tokio::net::TcpStream::connect(addr).await.unwrap();
        refused
            .write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        // A reset is an error rather than a clean EOF; both mean the same thing
        // here, which is that nothing was written back.
        refused.read_to_end(&mut got).await.ok();
        assert!(
            got.is_empty(),
            "expected silence, got {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(state.sessions.lock().unwrap().len(), 1);

        // And a tunnel no rule refuses is still acknowledged, so the gate is
        // refusing connections rather than the CONNECT handler being broken.
        let mut allowed = tokio::net::TcpStream::connect(addr).await.unwrap();
        allowed
            .write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        allowed
            .read_exact(&mut head)
            .await
            .expect("a CONNECT reply");
        assert_eq!(&head, b"HTTP/1.1 200");
    }

    /// An aborted *request* is recorded too, for the same reason an aborted
    /// tunnel is: a row that never appears is indistinguishable from a rule
    /// that never matched, and which of those happened is the only thing the
    /// user wants to know when they write `enable://abort`.
    #[tokio::test]
    async fn an_aborted_request_is_recorded_rather_than_vanishing() {
        let (state, addr) = proxy_with("blocked.test enable://abort").await;

        let mut refused = tokio::net::TcpStream::connect(addr).await.unwrap();
        refused
            .write_all(b"GET http://blocked.test/a HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        refused.read_to_end(&mut got).await.ok();
        assert!(
            got.is_empty(),
            "an abort answers nothing, got {:?}",
            String::from_utf8_lossy(&got)
        );

        let sessions = state.sessions.lock().unwrap();
        let session = sessions.iter().next().expect("the abort is on the list");
        assert_eq!(session.method, "GET");
        assert_eq!(session.url, "http://blocked.test/a");
        assert_eq!(session.status, 0, "nothing answered");
        assert_eq!(session.target, "aborted", "and nothing was dialled");
        assert!(
            session.rules.iter().any(|r| r.raw == "enable://abort"),
            "the rule that did it is named: {:?}",
            session.rules
        );
    }

    /// A gateway error is a response this proxy made itself, and says so.
    ///
    /// It is the most common thing a debugging proxy ever has to tell its user —
    /// "I could not reach that" — and it went out as an unattributed body with
    /// no declared type, so it could not be told apart from an origin's own
    /// answer. whistle stamps the identical response through `wrapResponse`
    /// (`_original/lib/util/index.js:1080-1109`).
    #[tokio::test]
    async fn a_gateway_error_names_the_proxy_that_made_it() {
        // A port bound only long enough to know nothing else has it.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (_state, addr) = proxy_with(&format!("{dead} proxy://{dead}")).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // `Connection: close`, or the answer keeps the socket open and reading
        // to the end never ends.
        client
            .write_all(
                format!(
                    "GET http://{dead}/a HTTP/1.1\r\nHost: {dead}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.ok();
        let got = String::from_utf8_lossy(&got).to_lowercase();

        assert!(got.starts_with("http/1.1 502"), "{got}");
        assert!(got.contains("x-server: whistle-rs"), "{got}");
        assert!(
            got.contains("content-type: text/plain; charset=utf-8"),
            "{got}"
        );
    }
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
        let started = Instant::now();
        let time_ms = now_ms();
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
        // A tunnel is opened to an address, not to a protocol. This port used to
        // assume TLS and hand every one of them to the acceptor, which turns a
        // tunnel carrying anything else into a TLS alert — see [`sni::Carried`].
        let carried = sni::carried_protocol(&hello.prefix);
        // A client that closed the tunnel without sending a byte asked for
        // nothing, and leaves no session: that is a connection opened and
        // abandoned, which clients do all the time.
        let asked = !hello.prefix.is_empty();
        let stream = sni::Prefixed::new(hello.prefix, stream);
        // The session a tunnel leaves when nothing inside it is read — relayed,
        // refused, or turned away at the handshake. Built only then: it costs a
        // second rule resolution, which an intercepted tunnel never pays.
        let session = || Tunnel {
            state: &state,
            session: tunnel_session(&state, &servername, port, peer, has_sni, time_ms),
            started,
        };
        let acceptor =
            match sni::decide(&state, &servername, &host, port, peer, has_sni, carried).await {
                sni::Decision::Generated => match state.ca.acceptor_for(&servername) {
                    Ok(acceptor) => acceptor,
                    Err(err) => {
                        let err = err.context(format!("a certificate for {servername}"));
                        if asked {
                            session().fail("intercept", outcome::Phase::Internal, &err);
                        }
                        return Err(err);
                    }
                },
                sni::Decision::Plugin(acceptor) => acceptor,
                sni::Decision::Bypass(target) => {
                    return relay_recorded(stream, &target, asked.then(session)).await;
                }
                // Cleartext inside the tunnel: no handshake to make, and the
                // same two servers the SOCKS path already reaches for.
                sni::Decision::Cleartext(sni::Carried::H2c) => {
                    // `tls: false`: the connection genuinely is not encrypted, so
                    // an `https://` pattern must not match it. Upstream reaches
                    // its h2 server before it ever sets `socket.curUrl` to an
                    // `https://` URL (`_original/lib/https/index.js:1280-1282`
                    // returns above `:1297`), which is the same reading.
                    return serve_intercepted_h2(
                        state,
                        TokioIo::new(stream),
                        host,
                        port,
                        peer,
                        false,
                        false,
                    )
                    .await;
                }
                sni::Decision::Cleartext(_) => {
                    return serve_intercepted(
                        state,
                        TokioIo::new(stream),
                        host,
                        port,
                        peer,
                        false,
                        false,
                    )
                    .await;
                }
                // A proxy rule that cannot be honoured closes the connection
                // rather than quietly sending the bytes direct — the same call
                // the request path makes, where it answers 502.
                sni::Decision::Unroutable(why) => {
                    let err = anyhow::anyhow!("tunnel to {host}:{port} not routable: {why}");
                    if asked {
                        session().fail("", outcome::Phase::Rules, &err);
                    }
                    return Err(err);
                }
            };
        let tls_stream = match acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(err) => {
                if asked {
                    session().fail_at(
                        "intercept",
                        outcome::Failure::new(outcome::Phase::ClientTls, client_tls_failure(&err)),
                    );
                }
                return Err(err.into());
            }
        };
        let conn = tls_stream.get_ref().1;
        let is_h2 = conn.alpn_protocol() == Some(b"h2");
        // Read once, off the completed handshake: whether the client named a
        // server in its ClientHello. Costs nothing — rustls already parsed it to
        // pick a certificate. Deliberately not taken from `has_sni` above, so
        // `from:sni` keeps answering off the handshake rustls actually
        // completed, exactly as it did before the peek existed.
        let sni = conn.server_name().is_some();
        if is_h2 {
            serve_intercepted_h2(state, TokioIo::new(tls_stream), host, port, peer, true, sni).await
        } else {
            serve_intercepted(state, TokioIo::new(tls_stream), host, port, peer, true, sni).await
        }
    } else {
        // No handshake, so no SNI — a plain-HTTP tunnel is `from:tunnel` but
        // never `from:sni`.
        serve_intercepted(state, TokioIo::new(stream), host, port, peer, false, false).await
    }
}

/// A tunnel whose contents are not read, on its way to becoming its one
/// session. An intercepted tunnel has none of its own — each request inside it
/// is one — but a tunnel that is relayed, refused, or turned away at the
/// handshake has nothing else to show for it.
struct Tunnel<'a> {
    state: &'a Arc<AppState>,
    session: Session,
    started: Instant,
}

impl Tunnel<'_> {
    /// Record the tunnel as failed with `err`: at the phase the error was
    /// tagged with where it happened, or at `phase`.
    fn fail(self, target: &str, phase: outcome::Phase, err: &anyhow::Error) {
        let phase = outcome::phase_of(err).unwrap_or(phase);
        self.fail_at(target, outcome::Failure::new(phase, format!("{err:#}")));
    }

    fn fail_at(self, target: &str, failure: outcome::Failure) {
        let url = self.session.url.clone();
        let id = self.state.record(Session {
            target: target.to_string(),
            duration_ms: self.started.elapsed().as_millis(),
            error: outcome::Outcome::failed(failure.clone()),
            ..self.session
        });
        log_failure(id, "CONNECT", &url, &failure);
    }
}

/// The session of a tunnel whose contents are not read: the CONNECT itself,
/// matched exactly as the interception stage matched it.
fn tunnel_session(
    state: &AppState,
    servername: &str,
    port: u16,
    peer: SocketAddr,
    has_sni: bool,
    time_ms: u128,
) -> Session {
    let (info, resolved) = {
        let rules = state.rules.read().unwrap();
        let info = sni::connection_req_info(servername, port, peer, has_sni);
        let resolved = rules.resolve(&info);
        (info, resolved)
    };
    Session {
        time_ms,
        method: "CONNECT".to_string(),
        url: info.full_url,
        // The CONNECT was answered before anything below happened: hyper hands
        // over a tunnel's bytes only after its `200` has gone out — see
        // [`tunnel_aborted`]. A SOCKS client was likewise told "granted".
        status: 200,
        client_ip: Some(peer.ip().to_string()),
        log: log_labels(&resolved),
        rules: matched_ops(&resolved),
        ..Default::default()
    }
}

/// Relay a tunnel nobody reads, and record it: where it went and whether it
/// got there. `tunnel` is `None` for a client that asked for nothing.
///
/// A relayed tunnel used to leave no trace at all, succeeding or failing — so
/// `disable://intercept`, a plugin's `sniCallback` declining, `--no-intercept-https`
/// and every tunnel carrying something that is not HTTP were invisible in the
/// console, and a relay that could not connect was a `warn` in the log. Upstream
/// shows each as a tunnel row. The row appears once the far end is connected,
/// and is complete when the tunnel closes.
async fn relay_recorded<S>(
    client: sni::Prefixed<S>,
    target: &upstream::Target,
    tunnel: Option<Tunnel<'_>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let timings = timing::Timings::new();
    let origin = match upstream::tunnel_stream(target, &timings).await {
        Ok(origin) => origin,
        Err(err) => {
            match tunnel {
                Some(mut t) => {
                    t.session.timings = Some(timings);
                    t.fail(&target_desc(target), outcome::Phase::Internal, &err);
                }
                None => tracing::debug!(
                    "relaying to {}:{} failed: {err:#}",
                    target.connect_host,
                    target.connect_port
                ),
            }
            return Err(err);
        }
    };
    let open = tunnel.and_then(|t| {
        let (_, open) = t.state.record_open(Session {
            target: format!("{} (tunnel)", target_desc(target)),
            duration_ms: t.started.elapsed().as_millis(),
            timings: Some(timings),
            ..t.session
        });
        open.map(|session| (t.state, session))
    });
    let relayed = sni::relay(client, origin).await;
    if let Some((state, session)) = open {
        state.complete(&session);
    }
    relayed
}

/// What a handshake the client broke off most likely means, in words — this is
/// the one failure people meet on the first day, and the raw alert name does
/// not say what to do about it.
fn client_tls_failure(err: &std::io::Error) -> String {
    use rustls::AlertDescription as Alert;
    let refused = match err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::AlertReceived(alert)) => matches!(
            alert,
            Alert::UnknownCA
                | Alert::BadCertificate
                | Alert::CertificateUnknown
                | Alert::UnsupportedCertificate
                | Alert::AccessDenied
        ),
        _ => false,
    };
    let hung_up = matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
    );
    match (refused, hung_up) {
        (true, _) => format!(
            "the client refused this proxy's certificate ({err}): it does not trust the \
             whistle-rs root certificate, or it pins the server's own"
        ),
        (false, true) => format!(
            "the client hung up during the TLS handshake ({err}); a client that does not \
             trust the whistle-rs root certificate often does"
        ),
        (false, false) => format!("the TLS handshake with the client failed: {err}"),
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
        async move { serve_recorded(state, req, origin, peer).await }
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
        async move { serve_recorded(state, req, origin, peer).await }
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
/// nested and each dropped before the `.await` at the end — which is what lets
/// this be called from `serve`'s future. That await is the value loader, and it
/// only ever does work when this pass added an operator whose value names a
/// file or a URL.
async fn resolve_response_phase(
    state: &AppState,
    info: &mut ReqInfo,
    resolved: &mut Resolved,
    res: crate::rules::ResInfo,
    is_internal_req: bool,
    merged: &[crate::rules::RuleManager],
) {
    info.res = Some(res);
    let host = bind_host(state);
    let mut added = false;
    // The same map the request pass used. Reading `state.values` alone here made
    // a response-phase operator the only place a ``` block in the rules text was
    // invisible, so `resBody://{mock} includeFilter://s:404` served the six
    // characters `{mock}` — and the values a produced text carries are part of
    // it, or its response-phase lines would lose them.
    let mut values = effective_values(state);
    for mgr in merged {
        values.extend(mgr.carried_values().clone());
    }
    // Rules merged in mid-request get the same second pass. Upstream re-resolves
    // its `pRules`/`fRules`/`hRules` here too
    // (`_original/lib/plugins/index.js:1326-1335`); each manager answers from
    // its own precomputed flags, so a text with no response-dependent line
    // costs one comparison.
    if let Some(mut extra) = apply::response_phase_of(merged, info, is_internal_req) {
        apply::substitute_values(&mut extra, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
        resolved.merge_response_phase(extra);
        added = true;
    }
    let extra = {
        let rules = state.rules.read().unwrap();
        rules.resolve_response(info, is_internal_req)
    };
    if let Some(mut extra) = extra {
        tracing::debug!(
            "{} {} -> re-resolving rules for status {}",
            info.method,
            info.full_url,
            info.res.as_ref().map(|r| r.status).unwrap_or_default()
        );
        apply::substitute_values(&mut extra, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
        resolved.merge_response_phase(extra);
        added = true;
    }
    // Backtick templates on response-phase operators were left for this moment —
    // they are the only values whose variables need the head that has just
    // arrived (`apply::waits_for_the_response`). Everything else was substituted
    // in the request pass and says so, so this walk touches only what it
    // deferred.
    added |= apply::substitute_values(resolved, &values, tpl_ctx(&host, state.config.port, info));
    // `resRules://` last, because what a rules text produces wins over the file
    // that named it and the merge is an overwrite — upstream's `mergeRules(req,
    // …, true)` at the end of `getResRules`.
    //
    // It substitutes against `values`, the same map every other pass here uses.
    // Reading `state.values` directly is what made a response-phase operator the
    // one place a ``` block in the rules text was invisible.
    if let Some(carried) = apply::merge_res_rules(resolved, info, &values, is_internal_req) {
        values.extend(carried);
        apply::substitute_values(resolved, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(resolved, state.config.port, crate::config::VERSION);
        added = true;
    }
    // Operators this pass added have never been past the value loader — a
    // `resBody:///tmp/mock.json includeFilter://s:404` line withholds its
    // `resBody` from the request pass entirely. Ones that already loaded carry
    // `value_is_content` and are skipped.
    if added {
        apply::load_rule_values(resolved, info).await;
    }
}

/// whistle's own bind address, empty when bound to all interfaces — see
/// [`template::ProxyEnv`]. Owned because `Config` keeps an `IpAddr`.
fn bind_host(state: &AppState) -> String {
    state.config.host.map(|h| h.to_string()).unwrap_or_default()
}

/// The request context a backtick operator value renders against.
fn tpl_ctx<'a>(host: &'a str, port: u16, info: &'a ReqInfo) -> apply::TplCtx<'a> {
    apply::TplCtx {
        info,
        env: template::ProxyEnv {
            host,
            port,
            version: crate::config::VERSION,
        },
    }
}

/// The rules the forwarding family reads, when a URL replacement moved the
/// request off its own URL.
///
/// `None` — the common case — means "use the request's own resolution": nothing
/// moved, so the second pass would match the same URL with the same rules. See
/// [`apply::reresolve_forwarding`] for what the pass covers and why.
///
/// The value store and the config variables are applied to the second pass as
/// they were to the first, so a `host://${addr}` written against the destination
/// resolves rather than reaching the connector as literal text. Nothing is
/// loaded from disk or fetched: no forwarding operator's value is a location
/// (`value_source`'s `LOADABLE_*` lists name none of them), so this stays
/// synchronous.
fn forwarding_resolution(
    state: &AppState,
    info: &ReqInfo,
    dest: &dest::Destination,
    resolved: &Resolved,
    merged_rules: &[crate::rules::RuleManager],
    is_internal_req: bool,
) -> Option<Resolved> {
    if !dest.replaced {
        return None;
    }
    let moved = dest.moved_req_info(info);
    let mut second = {
        let rules = state.rules.read().unwrap();
        apply::reresolve_forwarding(resolved, &moved, &rules, merged_rules, is_internal_req)
    };
    let host = bind_host(state);
    let values = effective_values(state);
    apply::substitute_values(
        &mut second,
        &values,
        tpl_ctx(&host, state.config.port, &moved),
    );
    apply::substitute_config_vars(&mut second, state.config.port, crate::config::VERSION);
    Some(second)
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
#[derive(Default)]
struct ResBodyOps {
    /// `resSpeed://` — throttle, in kilobits/s.
    speed: Option<f64>,
    /// `resScript://` — the loaded source, not the rule value.
    script: Option<String>,
    /// `weinre://` — debug-agent id to inject.
    weinre: Option<String>,
    /// `resWrite://` / `resWriteRaw://` — dump paths, already carrying the
    /// `.<status>` suffix a non-200 gets.
    write: Option<String>,
    write_raw: Option<String>,
    /// `enable://forceReqWrite` — write the dump even over an existing file.
    force_write: bool,
    /// `trailers://` — trailing headers to append after the body. Already empty
    /// when `disable://trailers` cancelled them.
    trailers: hyper::HeaderMap,
    /// `disable://trailers` / `trailer` — drop the origin's trailer section too,
    /// which is the half a rule-side check cannot see.
    no_trailers: bool,
    /// `disable://trailerHeader` clears this: the trailers still go, the
    /// `Trailer:` header announcing them does not.
    announce_trailers: bool,
    /// Any content operator (`resReplace`, `htmlAppend`, `resBody`, …).
    content: bool,
    /// `enable://gzip|br|deflate` — the coding the response must leave under
    /// (`getEnableEncoding`, `_original/lib/util/index.js:1534-1548`).
    ///
    /// Held here rather than read where it is used so that
    /// [`ResBodyOps::needs_body`] can count it. It is the one operator that
    /// needs the whole body without rewriting a byte of it, and leaving it out
    /// of that gate is what made the flag do nothing when it stood alone: the
    /// response took the streaming path, `reencode` was never reached, and
    /// `enable://gzip` was inert unless some *other* operator happened to
    /// buffer the body for it.
    force_encoding: Option<coding::Coding>,
}

/// Is this response an event stream — a body that need never end?
///
/// whistle's `isSSE` (`_original/lib/util/index.js:3917-3921`), whose test is
/// `/^\s*text\/event-stream\s*;?/i` against `content-type`. Deliberately as
/// loose as upstream's: the pattern is not anchored at the end, so anything
/// *starting* with the media type matches, parameters and all.
fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        ct.trim_start()
            .get(.."text/event-stream".len())
            .is_some_and(|head| head.eq_ignore_ascii_case("text/event-stream"))
    })
}

/// Must the response body be collected before anything can go to the client?
///
/// Three doors lead to the buffered path, and gating only one of them is why
/// this is written down in a single place. [`ResBodyOps::of`] already drops the
/// rule operators for an event stream — but a plugin declaring `responseBody`
/// reaches the same `collect_with_trailers` through its own door and hangs the
/// stream exactly as `resReplace://` did, which is not a rule operator and so
/// was not covered. Measured against a live SSE origin: not one byte in six
/// seconds, no response head either, where the unruled host streamed at once.
///
/// An override is the one door an event stream may pass through: the plugin
/// replaced the body outright, so those bytes are already in hand and the
/// origin's body is never awaited. Nothing is withheld, because nothing is
/// waited for.
fn must_collect_body(
    ops: &ResBodyOps,
    plugin_wants_body: bool,
    has_override: bool,
    res_ct: Option<&str>,
) -> bool {
    if has_override {
        return true;
    }
    if is_event_stream(res_ct) {
        return false;
    }
    ops.needs_body() || plugin_wants_body
}

/// The frame splitter a **response** asks for, or `None` for a body the console
/// shows whole.
///
/// whistle's Frames panel gets a body cut into pieces in two cases
/// (`handleResBody`, `_original/lib/inspectors/data.js:323-345`):
///
/// * the response **is** an event stream — `content-type: text/event-stream`,
///   compared whole, which is a narrower test than the one deciding whether the
///   body may be buffered;
/// * a `x-whistle-custom-frame-separator` header names a separator, which works
///   for any content type and is how the FAQ turns a chunked JSON stream into
///   frames.
///
/// `disable://captureStream` turns both off, and a **compressed** body is never
/// framed — upstream checks `getZipType(info)` first, and a separator search in
/// a deflate stream would find nothing anyway.
///
/// The header is removed from the response either way, so the client never sees
/// it (`parseFrameSep` deletes before it decides, `:83`).
fn response_frames(
    resolved: &Resolved,
    headers: &mut hyper::HeaderMap,
    res_enc: Option<&str>,
) -> Option<restream::FrameSplitter> {
    let custom = restream::take_frame_separator(headers);
    if apply::is_disabled(resolved, "captureStream") {
        return None;
    }
    if res_enc.is_some_and(|enc| !enc.trim().eq_ignore_ascii_case("identity")) {
        return None;
    }
    let is_sse = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.trim() == "text/event-stream");
    // **A named separator frames only when `enable://captureStream` says so.**
    // An event stream turns it on by itself — `captureStream = captureStream ||
    // isSse`, and only then does a separator decide anything
    // (`_original/lib/inspectors/data.js:329-340`). Measured through upstream's
    // own frames API: with the header alone and no flag, whistle reports **no
    // frames at all**, on the request side as well as the response side.
    //
    // Worth following rather than simplifying away, and not only for alignment:
    // the header can arrive from the *origin*, or from a whistle further up the
    // chain, and a header somebody else sent should not by itself turn on body
    // capture here. That is the same call this port already made about the
    // rules-carrying headers.
    if custom.is_some() && (is_sse || apply::is_enabled(resolved, "captureStream")) {
        return custom;
    }
    is_sse.then(restream::FrameSplitter::sse)
}

/// The substitution to run on a response body that is **still arriving**, or
/// `None` to stream it through untouched.
///
/// This is the half of the body layer an event stream can have. Collecting one
/// withholds it (see [`must_collect_body`]), so the operators that need the
/// whole body — `resBody://`, the injections, `resMerge://` — stay dropped. But
/// `resReplace://` never needed the whole body: it needs a window, and
/// [`crate::proxy::restream`] holds exactly one.
///
/// Two things disqualify a stream, and both are refusals rather than attempts:
///
/// * **an encoded body**, because searching a deflate stream for a plaintext
///   pattern finds nothing and rewriting it would corrupt what the header
///   promises. The buffered path decompresses first; there is no streaming
///   decoder here, so the honest answer is to leave the bytes alone. In practice
///   an event stream is served uncompressed — `text/event-stream` and
///   `content-encoding` together are rare, and this declines rather than guesses.
/// * **anything that is not an event stream**, because a body with an end
///   belongs to the buffered path, which applies every operator rather than one.
///   Reaching here with substitutions and no event stream would mean
///   [`ResBodyOps::needs_body`] disagreed with this function about `content`.
fn stream_replace(
    resolved: &Resolved,
    res_ct: Option<&str>,
    res_enc: Option<&str>,
) -> Option<restream::TextReplace> {
    if !is_event_stream(res_ct) {
        return None;
    }
    // `identity` is the spelling of "no coding"; anything else is a coding.
    if res_enc.is_some_and(|enc| !enc.trim().eq_ignore_ascii_case("identity")) {
        return None;
    }
    let pairs = apply::res_replace_pairs(resolved, res_ct);
    restream::TextReplace::new(&pairs, true)
}

/// The prepend / append / replace-body injection for a response still arriving,
/// or `None` to leave the stream alone.
///
/// Gated on the response being an event stream for the same reason
/// [`stream_replace`] is: a body with an end belongs to the buffered path, which
/// applies the typed families and the HTML gating too. Unlike the substitution
/// there is no encoding question — nothing here reads the origin's bytes, so a
/// compressed stream can be prepended to as safely as a plain one.
fn stream_injection(resolved: &Resolved, res_ct: Option<&str>) -> Option<apply::StreamInjection> {
    is_event_stream(res_ct)
        .then(|| apply::res_stream_injection(resolved))
        .flatten()
}

impl ResBodyOps {
    /// The body operators in force, given what the response *is*.
    ///
    /// `has_body` is whistle's `util.hasBody` (`_original/lib/util/common.js:370-380`):
    /// false for a `HEAD` request and for a 1xx, 204 or **any 3xx** status. When
    /// it is false upstream drops every body operator on the floor —
    /// `getRuleValue(..., !hasResBody, ...)` returns `undefined` for each inject
    /// value (`res.js:988` → `util/index.js:1394-1396`) and the speed/body/top/
    /// bottom keys are deleted outright (`res.js:1106-1113`).
    ///
    /// This port had no such gate, so `resAppend://X` gave a `302` a body,
    /// stripped its `Content-Length`, and — because the injection also stamps
    /// `Cache-Control: no-store` and strips CSP — rewrote the headers of a
    /// redirect the rule was never meant to touch.
    ///
    /// `streaming_ct` is the content type of a body that is **still arriving**,
    /// and exists for one reason: an event stream must never be collected. A
    /// caller whose body is already wholly in memory passes `None` — there is
    /// nothing left to wait for, so the gate below would only drop operators
    /// that can be applied perfectly well. See [`is_event_stream`].
    fn of(resolved: &Resolved, has_body: bool, status: u16, streaming_ct: Option<&str>) -> Self {
        if is_event_stream(streaming_ct) {
            // Every operator here needs the whole body, and an event stream has
            // no "whole" — it ends when the server decides, which for SSE is
            // typically never. Collecting one does not delay the response, it
            // withholds it: the client receives nothing at all, where without
            // the rule it would have received events for as long as it listened.
            //
            // So the operators that need the whole body are dropped and the
            // stream is passed through. `resReplace://` is *not* among them and
            // is not dropped here — it needs a window rather than the whole
            // body, and it travels with the stream instead. See
            // [`stream_replace`] and [`crate::proxy::restream`], which is
            // upstream's own mechanism: hold back only a chunk tail, and for an
            // event stream flush through the last `\n\n` so a complete event is
            // never held (`_original/lib/util/replace-string-transform.js:27-33`).
            //
            // `disable://trailers` survives because the streaming path reads it
            // — it drops the origin's trailer section, which costs no buffering.
            // The rest of the header operators here (`resWriteRaw://`,
            // `trailers://`) have no reader on that path, so setting them would
            // announce an effect that does not happen.
            return ResBodyOps {
                no_trailers: apply::trailers_disabled(resolved),
                ..ResBodyOps::default()
            };
        }
        if !has_body {
            // The trailers still apply: they are headers, not a body, and
            // upstream folds them in after this gate (`res.js:1250-1290`). So
            // does `resWriteRaw://`, which dumps the head — only the *body*
            // dump is gated on there being one (`res.js:1126-1135`).
            return ResBodyOps {
                write_raw: apply::res_write_raw_path(resolved, status),
                force_write: apply::forces_write(resolved),
                trailers: apply::build_trailers(resolved),
                no_trailers: apply::trailers_disabled(resolved),
                announce_trailers: apply::trailer_header_announced(resolved),
                ..ResBodyOps::default()
            };
        }
        ResBodyOps {
            speed: apply::res_speed_kbps(resolved),
            script: apply::res_script_op(resolved)
                .map(|op| op.value.as_str())
                .and_then(script::load_script),
            weinre: resolved.value("weinre").map(|s| s.to_string()),
            write: apply::res_write_path(resolved, status),
            write_raw: apply::res_write_raw_path(resolved, status),
            force_write: apply::forces_write(resolved),
            trailers: apply::build_trailers(resolved),
            no_trailers: apply::trailers_disabled(resolved),
            announce_trailers: apply::trailer_header_announced(resolved),
            content: apply::wants_res_body(resolved),
            // Only where there is a body to encode. A `HEAD` answer, a 204 or a
            // 3xx takes the branch above, where this stays `None`: compressing
            // nothing produces a header that says "nothing".
            force_encoding: apply::forced_encoding(resolved),
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
            || self.write.is_some()
            || self.write_raw.is_some()
            || !self.trailers.is_empty()
            // A coding cannot be put on a body that is still arriving in
            // frames, so asking for one is asking for the buffered path.
            || self.force_encoding.is_some()
    }
}

/// Put `Content-Encoding` back after a rewrite, and report the coding the
/// capture should be told the body is now under.
///
/// The header is left **exactly as it arrived** when the bytes were never
/// decoded. `reencode` refuses to force a coding onto such a body — see
/// `Restore { plain: false }` — and reports [`coding::Coding::Identity`],
/// because it encoded nothing; but stamping that would *remove* the header, and
/// a `zstd` response would reach the client as zstd bytes labelled as plain.
/// That is worse than the flag doing nothing: the response arrived readable and
/// would leave unreadable.
///
/// `arrived_as` is the response's own `Content-Encoding`, which is what such a
/// body is still under.
fn restore_content_encoding(
    headers: &mut hyper::HeaderMap,
    restore: coding::Restore,
    encoded_as: coding::Coding,
    arrived_as: Option<String>,
) -> Option<String> {
    if !restore.plain {
        return arrived_as;
    }
    // A body that goes back out under the coding it arrived under keeps the
    // origin's spelling of it. `x-gzip` is the pre-RFC name for the same bytes,
    // and rewriting the header to `gzip` announced a change this proxy did not
    // make — the response is the origin's, down to how it named its encoding.
    if let Some(arrived) = arrived_as.filter(|a| coding::Coding::of(Some(a)) == encoded_as) {
        set_header_raw(headers, "content-encoding", &arrived);
        return Some(arrived);
    }
    coding::set_content_encoding(headers, encoded_as);
    encoded_as.header_value().map(str::to_string)
}

/// The values a request resolves against: what the rules files declared in
/// their ``` blocks, each under a key private to the group that declared it
/// ([`crate::rules::inline_key`]), plus the configured values under their plain
/// names. [`apply::value_for`] is what reads the two apart.
///
/// Rebuilt per request rather than cached because either side can change while
/// the proxy runs — the console edits values, and a rules edit can add or
/// remove an inline block. The cost is one map build over a handful of entries;
/// a rules file with no ``` in it contributes an empty map without allocating.
///
/// Which one answers is [`apply::value_for`]'s to say: the operator's own block,
/// then the store — upstream's order — except for a name `--value` gave, whose
/// blocks are left out of the map here so the store's entry is the only one
/// ([`apply::yield_to_overrides`]).
fn effective_values(state: &AppState) -> std::collections::HashMap<String, String> {
    let mut values = state.rules.read().unwrap().inline_values();
    if values.is_empty() {
        return state.values.read().unwrap().clone();
    }
    values.extend(state.values.read().unwrap().clone());
    apply::yield_to_overrides(&mut values, &state.config.value_overrides);
    values
}

/// Does this response carry a body a rule may rewrite? whistle's `hasBody`
/// (`_original/lib/util/common.js:370-380`).
///
/// A `HEAD` answer, a 1xx, a 204 and every 3xx are excluded — a redirect with a
/// body injected into it is not the redirect the origin sent, and the operators
/// that come with an injection (the cache and CSP strips) have no business
/// touching it either.
pub(crate) fn response_has_body(status: u16, method: &str) -> bool {
    if method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    !(status == 204 || (300..400).contains(&status) || (100..200).contains(&status))
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
    if let Some(path) = &ops.write {
        write_body_file(path, &new, ops.force_write);
    }
    if let Some(path) = &ops.write_raw {
        let head = format!(
            "HTTP/1.1 {}\r\n{}",
            parts.status,
            header_dump(&parts.headers)
        );
        write_raw_file(path, &head, &new, ops.force_write);
    }
    new
}

/// Frame a finished in-memory body: drop the now-stale length headers, apply
/// `resSpeed://`, and put the trailer section back on.
///
/// `origin` is the trailer section the upstream response sent, which buffering
/// the body would otherwise have thrown away. whistle keeps it and lays the
/// rule's trailers over the top — `extend(trailers, newTrailers)`
/// (`_original/lib/inspectors/res.js:1264-1273`) — so a `trailers://x-a=1`
/// against an origin that already sends `x-checksum` yields both.
fn finish_res_body(
    parts: &mut hyper::http::response::Parts,
    new: Bytes,
    ops: ResBodyOps,
    origin: Option<hyper::HeaderMap>,
) -> DynBody {
    apply::strip_length_headers(&mut parts.headers);
    // `resSpeed://` applies whether or not there are trailers. Deciding between
    // the two — which is what this did — meant a `trailers://` line silently
    // cancelled the throttle written beside it.
    let body = match ops.speed {
        Some(kbps) => body::throttled(new, kbps),
        None => body::full(new),
    };

    let mut trailers = origin.filter(|_| !ops.no_trailers).unwrap_or_default();
    trailers.extend(ops.trailers);
    // Last, over the merged map, exactly where upstream applies it
    // (`removeIllegalTrailers`, `res.js:1285`): a name banned from a trailer
    // section is banned wherever it came from.
    apply::remove_illegal_trailers(&mut trailers);
    if trailers.is_empty() {
        // Nothing to send — but the origin's may still be on their way, so the
        // `disable://` case has to say so rather than simply not adding any.
        return match ops.no_trailers {
            true => retrailer(body, None),
            false => body,
        };
    }
    // Trailers need chunked transfer; ensure HTTP/1.1 (upstream may be 1.0).
    parts.version = hyper::Version::HTTP_11;
    if ops.announce_trailers {
        let names = trailers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        set_header_raw(&mut parts.headers, "trailer", &names);
    }
    retrailer(body, Some(trailers))
}

/// Replace whatever trailer section `body` would emit with `trailers`, or with
/// none at all.
///
/// Needed on both sides of the buffering decision: a body that was collected has
/// already had its trailers lifted off and merged, and one that is streaming
/// through still carries the origin's — which `disable://trailers` has to be
/// able to drop.
fn retrailer(body: DynBody, trailers: Option<hyper::HeaderMap>) -> DynBody {
    use http_body_util::BodyExt;
    Retrailed {
        inner: Box::pin(body),
        trailers,
    }
    .boxed()
}

/// Body wrapper backing [`retrailer`]: swallows the inner body's trailer frame
/// and emits its own, once, at the end.
struct Retrailed {
    inner: std::pin::Pin<Box<DynBody>>,
    trailers: Option<hyper::HeaderMap>,
}

impl hyper::body::Body for Retrailed {
    type Data = Bytes;
    type Error = body::BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match this.inner.as_mut().poll_frame(cx) {
                // The inner section has already been accounted for — either
                // merged into ours or deliberately dropped.
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(None) => {
                    return Poll::Ready(
                        this.trailers
                            .take()
                            .map(|t| Ok(hyper::body::Frame::trailers(t))),
                    );
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream() && self.trailers.is_none()
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
    let capture = (!bytes.is_empty())
        .then(|| Capture::from_bytes(&bytes, ct, enc.as_deref(), state.config.body_preview_cap));
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
    )
    .await;
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

    let ops = ResBodyOps::of(
        resolved,
        response_has_body(parts.status.as_u16(), &info.method),
        parts.status.as_u16(),
        // `None`: the body is already collected on this path, so even an event
        // stream is a finite `Bytes` here and every operator can be applied.
        None,
    );
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
        let restore = decoded.restore;
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
        let (new, encoded_as) = coding::reencode(new, restore, ops.force_encoding);
        let now = restore_content_encoding(&mut parts.headers, restore, encoded_as, res_enc);
        (new, now)
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
        // A locally produced response has no origin trailer section to keep.
        true => finish_res_body(&mut parts, new, ops, None),
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

/// What an aborted request leaves behind: nothing.
///
/// whistle answers an abort with `res.destroy()`
/// (`_original/lib/inspectors/data.js:536`, `res.js:1178`), which tears the
/// socket down mid-transaction — the client sees a reset, not a status. hyper
/// does the same when the service resolves to an error, so the abort travels
/// out of [`serve`] as one and [`guard`] passes it through instead of dressing
/// it up as a 502. A 502 with a body is a *served* response: it satisfies a
/// fetch, gets cached as a failure page, and cannot be told apart from a real
/// gateway error — which is not what `enable://abort` is for.
#[derive(Debug)]
struct Destroyed;

impl std::fmt::Display for Destroyed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection destroyed by enable://abort")
    }
}

impl std::error::Error for Destroyed {}

/// The header on a response this proxy made up because the request failed,
/// naming the [`outcome::Phase`] it failed in. Its presence is what tells a
/// `502` from here apart from a `502` the origin sent.
pub const ERROR_HEADER: &str = "x-whistle-rs-error";

/// The header carrying the id of the session a failed request was recorded
/// as, so the client that got the error can find it in the console.
pub const SESSION_HEADER: &str = "x-whistle-rs-session";

/// A request on its way to becoming a session.
///
/// Every request [`serve`] takes on becomes **exactly one** session, however it
/// ends. The paths that answer record their own, through [`Ledger::record`]; a
/// failure that escapes [`serve`] as an error is recorded by [`guard`] from the
/// draft; and a request whose future is dropped — which is what hyper does when
/// the client closes the connection or resets the stream while waiting — is
/// recorded when the ledger is dropped with it. Before this, only the first of
/// the three existed, so every request that failed before its response head
/// arrived was in the log and nowhere else.
pub(crate) struct Ledger {
    state: Arc<AppState>,
    /// What is known about the request so far. `None` until [`serve`] knows
    /// this is a request the console records — the console's own traffic is not.
    draft: Option<Session>,
    /// When the request arrived. Every session's `time_ms` and `duration_ms`
    /// count from here.
    started: Instant,
    time_ms: u128,
    /// A session has been recorded; this request owes nothing more.
    settled: bool,
}

impl Ledger {
    pub(crate) fn new(state: &Arc<AppState>) -> Self {
        Ledger {
            state: state.clone(),
            draft: None,
            started: Instant::now(),
            time_ms: now_ms(),
            settled: false,
        }
    }

    /// The request is one the console records: this much is known about it.
    fn open(&mut self, draft: Session) {
        self.draft = Some(Session {
            time_ms: self.time_ms,
            ..draft
        });
    }

    /// Add to what the draft knows. A no-op before [`Ledger::open`].
    fn note(&mut self, f: impl FnOnce(&mut Session)) {
        if let Some(draft) = &mut self.draft {
            f(draft);
        }
    }

    /// Record `session` as this request's one session.
    fn record(&mut self, session: Session) -> u64 {
        self.settled = true;
        self.state.record(session)
    }

    /// Record `session` as this request's one session, its response `body`
    /// still to come: it is completed when the body is over, and fails then
    /// if the body breaks off or the client leaves before the end. `expected`
    /// is the `content-length` the response promises, if any — see
    /// [`outcome::settle`].
    fn record_streaming(
        &mut self,
        session: Session,
        body: DynBody,
        expected: Option<u64>,
    ) -> (u64, DynBody) {
        self.settled = true;
        let (id, open) = self.state.record_open(session);
        let Some(session) = open else {
            return (id, body);
        };
        let state = self.state.clone();
        let body = outcome::settle(body, expected, move |failure| {
            if let Some(failure) = failure {
                log_failure(session.id, &session.method, &session.url, &failure);
                session.error.fail(failure);
            }
            state.complete(&session);
        });
        (id, body)
    }

    /// Record the draft as a request that failed with `failure`, the client
    /// having been answered with `status` (0: nothing at all). `None` when
    /// there is nothing to record — no draft, or a session already recorded.
    fn fail(&mut self, failure: outcome::Failure, status: u16) -> Option<u64> {
        if self.settled {
            return None;
        }
        let draft = self.draft.take()?;
        let (method, url) = (draft.method.clone(), draft.url.clone());
        let id = self.record(Session {
            status,
            duration_ms: self.started.elapsed().as_millis(),
            error: outcome::Outcome::failed(failure.clone()),
            ..draft
        });
        log_failure(id, &method, &url, &failure);
        Some(id)
    }
}

/// The log line for a request that did not complete. It leads with the session
/// id — the one the console lists and a failed request's 502 carries in
/// [`SESSION_HEADER`] — so the three can be matched up.
fn log_failure(id: u64, method: &str, url: &str, failure: &outcome::Failure) {
    tracing::info!(
        "#{id} {method} {url} -> failed at {}: {}",
        failure.phase,
        failure.message
    );
}

impl Drop for Ledger {
    /// The request's future was dropped before it settled. Nothing else drops
    /// it: [`serve`] and [`guard`] settle every way out of it they can see, so
    /// what is left is hyper giving up on a client that has gone.
    fn drop(&mut self) {
        self.fail(
            outcome::Failure::new(
                outcome::Phase::Client,
                "the client closed the connection before the response arrived",
            ),
            0,
        );
    }
}

/// Where a forwarded request went, as its session's `target` says it.
fn target_desc(target: &upstream::Target) -> String {
    let mut desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        desc.push_str(" (via proxy)");
    }
    desc
}

/// The outcome of a request a rule dropped on purpose.
fn aborted(how: &str) -> outcome::Outcome {
    outcome::Outcome::failed(outcome::Failure::new(outcome::Phase::Abort, how))
}

/// [`serve`] a request and settle its session, whatever happens to it.
async fn serve_recorded(
    state: Arc<AppState>,
    req: Request<Incoming>,
    origin: Origin,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    let mut ledger = Ledger::new(&state);
    let result = serve(state, req, origin, peer, &mut ledger).await;
    guard(&mut ledger, result)
}

/// Turn a failure into a 502, except an abort, which gets no answer — and
/// record it either way.
///
/// The 502 is dressed like every other answer this proxy makes itself: it says
/// what it is (`Content-Type`) and who made it (`x-server`). It went out as an
/// undeclared, unattributed body until the forwarding bench asked an unreachable
/// upstream for one — the single most common thing a debugging proxy has to say,
/// and the one response that did not name its author. whistle marks the same
/// answer, from the same place (`wrapGatewayError` → `wrapResponse`,
/// `_original/lib/util/index.js:1080-1109`); its body is HTML, and this one is
/// the error chain as plain text, so it says `text/plain`.
///
/// `x-server` alone cannot tell this 502 from an origin's: a `statusCode://502`
/// rule carries it too. [`ERROR_HEADER`] can, and [`SESSION_HEADER`] says which
/// session in the console is this request.
fn guard(
    ledger: &mut Ledger,
    result: Result<Response<DynBody>>,
) -> Result<Response<DynBody>, Destroyed> {
    match result {
        Ok(resp) => Ok(resp),
        Err(err) if err.is::<Destroyed>() => {
            // Every abort records itself before it leaves `serve`; this is the
            // backstop that keeps a missed one from being called a client that
            // hung up.
            ledger.fail(
                outcome::Failure::new(outcome::Phase::Abort, format!("{err:#}")),
                0,
            );
            Err(Destroyed)
        }
        Err(err) => {
            let phase = outcome::phase_of(&err).unwrap_or(outcome::Phase::Internal);
            // `{err:#}` includes the full anyhow context chain (e.g. the
            // underlying rustls reason behind "upstream TLS handshake").
            let message = format!("{err:#}");
            let id = ledger.fail(outcome::Failure::new(phase, message.clone()), 502);
            if id.is_none() {
                tracing::debug!("request failed at {phase}: {message}");
            }
            let mut resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header(ERROR_HEADER, phase.as_str())
                .body(body::full(Bytes::from(format!("whistle-rs: {message}"))))
                .unwrap();
            if let Some(id) = id {
                resp.headers_mut().insert(SESSION_HEADER, id.into());
            }
            apply::mark_self_generated(resp.headers_mut());
            Ok(resp)
        }
    }
}

/// Core request pipeline: match rules, apply them, forward upstream.
async fn serve(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    origin: Origin,
    peer: SocketAddr,
    ledger: &mut Ledger,
) -> Result<Response<DynBody>> {
    // The handful of hostnames that *are* the console, before anything else
    // looks at this request. `http://local.whistlejs.com/` through the proxy is
    // how whistle's own `w2 status` tells people to open it, and `rootca.pro` is
    // how a phone gets the certificate — set the proxy, open the name, install
    // what it hands you. Both names resolve to `127.0.0.1`, where nothing is
    // listening on port 80, so a proxy that does not know them answers `502`.
    //
    // Here rather than in `top_level` because a tunnel has to answer too:
    // upstream serves both over TLS inside its own MITM, measured. And before
    // the rules, because upstream is before the rules — measured with a
    // matching `host://` line installed, which it serves the console over.
    let console = match &origin {
        Origin::Forward => req.uri().host().map(str::to_string),
        Origin::Mitm { host, .. } => Some(host.clone()),
    }
    .filter(|h| webui::console_host(&state, h));
    if let Some(host) = console {
        return Ok(webui::handle_proxied(&state, req, &host).await);
    }
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
    // The rules-carrying headers, which whistle removes from **every** request
    // whether or not it reads them (`getValue`,
    // `_original/lib/rules/index.js:558-572`: the `delete` is unconditional and
    // only the *reading* is gated on `enableRequestHeaderRules`/`multiEnv`).
    // Leaving them on meant a rules text written by a client reached the origin
    // — and would be honoured by any whistle further up the chain.
    //
    // Under `-M enableRequestHeaderRules` or `-M multiEnv` what they said is
    // also *kept*, and becomes a rules text for this one request — see
    // [`header_rules`]. Off by default in both proxies.
    let carried = take_header_rules(req.headers_mut(), &state.config);
    // What a front proxy claims about this request — the host it was addressed
    // to and the scheme it arrived under. Believed only when a `-M` mode says a
    // front proxy is there; two of the four headers are taken off either way,
    // because this port will not act on them and they may not travel on. See
    // [`forwarded`].
    let claimed = forwarded::take(req.headers_mut(), &state.config);

    // A request that asks to change protocol is matched as a `ws://` one, and
    // that has to be known *before* the rules resolve. whistle stamps
    // `req.isWs = true` on every upgrade it accepts and builds the URL from it —
    // `(req.isWs ? 'ws' : 'http') + (req.isHttps ? 's' : '')`
    // (`_original/lib/upgrade.js:121`, `lib/util/common.js:1267`) — so a
    // `ws://` pattern matches a WebSocket and an `http://` one does not.
    //
    // The rules layer has read this scheme all along; nothing ever set it, so
    // both halves were wrong in production: `ws://example.com` matched nothing a
    // client could send, and `http://example.com` matched the WebSocket it
    // excludes. It also decides whether a `file://` may answer at all
    // (`matcher::serves_no_file`).
    let upgrading = asks_to_upgrade(req.headers());
    // Derive scheme/host/port/path for matching.
    // `port_explicit` says the port came from the request rather than from the
    // scheme's default, which is what decides whether a forwarded-proto claim
    // may move it — see below.
    let (mut scheme, mut host, mut port, path, port_explicit) = match &origin {
        Origin::Forward => {
            let uri = req.uri();
            let host = uri.host().unwrap_or_default().to_string();
            let mut scheme = uri.scheme_str().unwrap_or("http").to_string();
            if was_https && scheme == "http" {
                scheme = "https".to_string();
            }
            if upgrading {
                scheme = match scheme.as_str() {
                    "https" | "wss" => "wss".to_string(),
                    _ => "ws".to_string(),
                };
            }
            // Read after the marker, so a request restored to https and carrying
            // no explicit port lands on 443 rather than 80 — and after the
            // upgrade rename, so a `wss://` one does too.
            let port = uri.port_u16().unwrap_or(match scheme.as_str() {
                "https" | "wss" => 443,
                _ => 80,
            });
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            (scheme, host, port, path, uri.port_u16().is_some())
        }
        Origin::Mitm {
            host, port, tls, ..
        } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let scheme = match (*tls, upgrading) {
                (true, true) => "wss",
                (true, false) => "https",
                (false, true) => "ws",
                (false, false) => "http",
            };
            // The port a CONNECT named is the port, and no claim moves it.
            (scheme.to_string(), host.clone(), *port, path, true)
        }
    };

    // A front proxy's claim, applied to what the rules will match. Upstream
    // does the same two things and no more: `headers.host = host` before the
    // full URL is built (`_original/lib/util/common.js:1259-1265`) and
    // `req.isHttps = proto === 'https'` (`util/index.js:3722-3727`). Measured:
    // the *outgoing* request is unaffected — a request labelled `https` still
    // left over plain HTTP and still reached a plain origin, it simply matched
    // `https://` patterns on the way.
    // What the request actually arrived as, kept because a forwarded-proto claim
    // changes **which pattern matches** and nothing else — see below.
    let wire_scheme = scheme.clone();
    let mut wire_port = port;
    if let Some(https) = claimed.https {
        scheme = match (https, upgrading) {
            (true, true) => "wss",
            (true, false) => "https",
            (false, true) => "ws",
            (false, false) => "http",
        }
        .to_string();
        // The port the request addressed was read against the *old* scheme, so
        // a claim that changes it moves a default port with it — 80 and 443 are
        // the same request to two different servers. An explicit port in the
        // request stands.
        let (from, to) = match https {
            true => (80, 443),
            false => (443, 80),
        };
        if port == from && !port_explicit {
            port = to;
        }
    }
    if let Some(claimed_host) = &claimed.host {
        match forwarded::split_host(claimed_host, port) {
            Some((h, p)) => {
                host = h;
                port = p;
                // A host claim moves the *destination*, so its port is the one
                // to connect to — it replaces whatever a proto claim implied.
                wire_port = p;
                // Upstream assigns `headers.host`, so everything downstream —
                // the rules, the capture, the origin — sees one answer rather
                // than two.
                if let Ok(value) = claimed_host.parse() {
                    req.headers_mut().insert(hyper::header::HOST, value);
                }
            }
            // A claim this proxy cannot address is ignored, and said so: an
            // operator who switched the mode on wants to know their front proxy
            // is sending something unusable.
            None => tracing::warn!("ignoring an unusable forwarded host: {claimed_host:?}"),
        }
    }

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
    // From here on this request becomes a session however it ends. The
    // client's own headers stand in until the outgoing ones exist, for the
    // reason a locally answered request shows them — see
    // `capture_client_request`.
    ledger.open(Session {
        method: info.method.clone(),
        url: info.full_url.clone(),
        client_ip: client_ip.clone(),
        req_headers: header_pairs(req.headers()),
        ..Default::default()
    });
    let (started, time_ms) = (ledger.started, ledger.time_ms);

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
            // Bounded, because this is a client's upload and the only thing
            // asking for it is a `b:` filter that wants to read a prefix.
            // Over the bound the body streams on and the filter answers from
            // what was read — see [`body::collect_capped`]. The limit here is
            // the plain one: `enable://reqMergeBigData` lives on a rule, and
            // which rules apply is the question this buffering exists to
            // answer, so consulting it would be circular.
            match collect_capped_body(body::from_incoming(incoming), apply::REQ_BODY_LIMIT)
                .await
                .map_err(outcome::at(outcome::Phase::Request))?
            {
                body::Capped::Whole { bytes, .. } => (
                    Request::from_parts(parts, body::full(bytes.clone())),
                    Some(bytes),
                ),
                body::Capped::TooBig { prefix, body } => {
                    (Request::from_parts(parts, body), Some(prefix))
                }
            }
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
    // `${host}` is whistle's own bind address, empty when bound to all
    // interfaces — see ProxyEnv.
    let bind_host = bind_host(&state);
    let proxy_env = template::ProxyEnv {
        host: &bind_host,
        port: state.config.port,
        version: crate::config::VERSION,
    };
    // Rules merged in mid-request — a `rule://` value, the `rulesFile://` join,
    // and any a plugin injects below. Their parsed form is kept because the
    // response phase resolves them a second time, exactly as it does the
    // top-level rules (`apply::merge_response_phase_of`).
    let mut merged_rules: Vec<crate::rules::RuleManager> = {
        // A ``` block in a rules file declares a value that travels with it,
        // and it beats the console's store — but not a `--value`.
        let mut values = effective_values(&state);
        // The rules this request brought in its own headers, if the mode reads
        // them at all. Composed and merged **before** anything is substituted,
        // so a `{name}` inside them is expanded in the same pass as every other
        // rule's — and against the private values the request carried, which is
        // what `x-whistle-key-value` is for.
        let from_headers = (!carried.is_empty())
            .then(|| {
                let rules = state.rules.read().unwrap();
                let text = header_rules::compose(
                    &carried,
                    // `values.get(keyHeader)` — the store by its plain name.
                    // Not a private lookup: the request is naming an entry the
                    // *proxy* holds, which is the whole point of the header.
                    |key| values.get(key).cloned(),
                    |name| rules.group_text(name).map(str::to_string),
                )?;
                drop(rules);
                let mgr = header_rules::merge(
                    &mut resolved,
                    &info,
                    &text,
                    state.config.header_rules,
                    is_internal_req,
                );
                // What the request carried is private to its rules, like a
                // block — and so are the text's own blocks, laid over it — and
                // both yield to `--value` like one.
                values.extend(header_rules::private_values(carried.kv.as_deref()));
                values.extend(header_rules::blocks(&mgr));
                apply::yield_to_overrides(&mut values, &state.config.value_overrides);
                Some(mgr)
            })
            .flatten();
        let tpl = tpl_ctx(&bind_host, state.config.port, &info);
        apply::substitute_values(&mut resolved, &values, tpl);
        let mut managers =
            apply::merge_included_rules(&mut resolved, &info, &values, is_internal_req);
        for mgr in &managers {
            values.extend(mgr.carried_values().clone());
        }
        apply::substitute_values(&mut resolved, &values, tpl);
        // Kept for the response phase, exactly as upstream re-resolves `hRules`
        // there (`_original/lib/plugins/index.js:1326-1335`).
        managers.extend(from_headers);
        managers
    };
    apply::substitute_config_vars(&mut resolved, state.config.port, crate::config::VERSION);
    // Operator values that name a file or a URL are read here — the one point
    // where the whole resolved set is in hand and the request has gone nowhere
    // yet. A rule set that names no location walks its own operators and
    // returns; see `apply::load_rule_values`.
    apply::load_rule_values(&mut resolved, &info).await;
    // Which rules applied is most of what a failed request's session has to
    // say. Noted again below whenever a plugin can have added some.
    ledger.note(|s| {
        s.log = log_labels(&resolved);
        s.rules = matched_ops(&resolved);
    });

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
    let (mut req, plugin_req_body): (Request<DynBody>, Option<Bytes>) = {
        let wants_body = !plugin_matches.is_empty()
            && has_request_body(req.headers())
            && state.plugins.any_wants_request_body(&plugin_names).await;
        match (wants_body, prebuffered) {
            (false, _) => (req, None),
            (true, Some(bytes)) => (req, Some(bytes)),
            (true, None) => {
                let (parts, body) = req.into_parts();
                let bytes = collect_body(body)
                    .await
                    .map_err(outcome::at(outcome::Phase::Request))?;
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
                {
                    let values = state.values.read().unwrap();
                    let tpl = tpl_ctx(&bind_host, state.config.port, &info);
                    apply::substitute_values(&mut resolved, &values, tpl);
                }
                // A plugin's rules can name a file or a URL too, and its
                // operators have not been past the loader.
                apply::load_rule_values(&mut resolved, &info).await;
            }
            plugin_set_headers.extend(result.set_headers);
            plugin_remove_headers.extend(result.remove_headers);
            let blocked = result.blocked;
            // A gate that failed rather than refused: the request stops here
            // because a plugin broke, and its session says so.
            let failure = result
                .failure
                .map(|why| outcome::Failure::new(outcome::Phase::Plugin, format!("{name}: {why}")));
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
                let (mut response, res_body) = if blocked {
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
                // What the client sent, which no outgoing request will carry
                // here — see `capture_client_request`.
                let (req_headers, req_body) =
                    capture_client_request(&mut req, state.config.body_preview_cap).await;
                // A broken gate's 502 is made up here like any failed request's,
                // so it says so the same way; without these it reads as an
                // origin's own 502, which is what the header exists to rule out.
                if let Some(failure) = &failure {
                    response
                        .headers_mut()
                        .insert(ERROR_HEADER, failure.phase.as_str().parse().unwrap());
                }
                let id = ledger.record(Session {
                    id: 0,
                    time_ms,
                    method: info.method.clone(),
                    url: info.full_url.clone(),
                    status: response.status().as_u16(),
                    client_ip: client_ip.clone(),
                    target,
                    duration_ms: started.elapsed().as_millis(),
                    log: log_labels(&resolved),
                    rules: matched_ops(&resolved),
                    req_headers,
                    res_headers: header_pairs(response.headers()),
                    req_body,
                    res_body,
                    // Answered here: no connection was opened, so there are no phases.
                    timings: None,
                    error: failure
                        .clone()
                        .map(outcome::Outcome::failed)
                        .unwrap_or_default(),
                });
                if let Some(failure) = &failure {
                    log_failure(id, &info.method, &info.full_url, failure);
                    response.headers_mut().insert(SESSION_HEADER, id.into());
                }
                return Ok(response);
            }
        }
    }

    // `enable://abort` / `abortReq` drop the request without contacting the
    // origin, and without an answer of any kind — upstream's `res.destroy()`
    // (`_original/lib/inspectors/data.js:534-539`). `abortRes` is *not* here:
    // it lets the request go out and destroys the answer instead, further down.
    if apply::aborts_request(&resolved) {
        tracing::info!("{} {} -> aborted", info.method, info.full_url);
        // Recorded, for the same reason an aborted tunnel is (see
        // [`tunnel_aborted`]): upstream emits the session and then marks it
        // aborted (`data.js:534-539` destroys the response, `tunnel.js:31-36`
        // is where the status becomes `'aborted'`), and a request that vanishes
        // from the console is indistinguishable from a rule that never matched
        // — which is the one question the user is asking when they reach for
        // `enable://abort`.
        let (req_headers, req_body) =
            capture_client_request(&mut req, state.config.body_preview_cap).await;
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            // Nothing answered and nothing will. 0 is the console's "no status",
            // matching the tunnel gate rather than inventing a second spelling.
            status: 0,
            client_ip: client_ip.clone(),
            // No address was dialled: the abort sits ahead of the forward.
            target: "aborted".to_string(),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers,
            req_body,
            error: aborted("dropped by a rule before it was sent (enable://abort or abortReq)"),
            ..Default::default()
        });
        return Err(Destroyed.into());
    }

    // Short-circuit rules (redirect, mocked status, file) skip the upstream;
    // `proxy_env` was built with the rest of the template context above.
    // `reqDelay://` waits here, before anything answers. Upstream delays in a
    // pipeline stage of its own (`util.delay(...reqDelay)`,
    // `_original/lib/inspectors/data.js:534`) that runs ahead of the abort gate
    // and ahead of every short-circuit — so `reqDelay://500 file://mock.json`
    // delays there. Waiting further down, next to the forwarding call, meant it
    // was skipped by exactly the rules people pair it with: a delay is how you
    // make a *mock* feel like a slow endpoint.
    if let Some(ms) = apply::req_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // A file rule may name a URL rather than a path, and then its bytes are
    // fetched. Hoisted out of `short_circuit` because everything under there
    // answers without waiting for anything but the filesystem, and one network
    // read is not a reason to make all of it async. Costs nothing unless a file
    // rule won the slot and named a URL.
    let remote = apply::prefetch_remote_file(&resolved).await;
    if let Some(mut resp) = apply::short_circuit(&info, &resolved, proxy_env, remote.as_ref()) {
        tracing::info!("{} {} -> short-circuit", info.method, info.full_url);
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS && asks_to_upgrade(req.headers()) {
            accept_upgrade_locally(&mut req, &mut resp);
        }
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
        // What the client sent, which no outgoing request will carry here — see
        // `capture_client_request`.
        let (req_headers, req_body) =
            capture_client_request(&mut req, state.config.body_preview_cap).await;
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: "short-circuit".to_string(),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers,
            res_headers: header_pairs(resp.headers()),
            req_body,
            res_body,
            // Answered here: no connection was opened, so there are no phases.
            timings: None,
            // A rule's answer, whatever its status — a `file://` whose URL
            // would not load answers 502 on purpose, as upstream's does.
            error: Default::default(),
        });
        return Ok(resp);
    }

    // Where the request is addressed, which is its own URL unless a rule pointed
    // it somewhere else — `www.example.com http://localhost:5173` and friends.
    // Resolved before the target because the target is *how* to reach it, and
    // because the forwarding family is matched against *this* URL rather than
    // the client's — see `forwarding_resolution`.
    // The destination is read against the scheme and port the request **arrived
    // under**, not the one a front proxy claimed.
    //
    // Measured, and the measurement is the whole reason this is here: with
    // `-M x-forwarded-proto` and `x-forwarded-proto: https`, whistle sends
    // **no ClientHello at all** — a plain origin logged zero client errors —
    // while it matched the `https://` rule. The claim describes the hop *before*
    // this proxy; the hop after it is whatever it always was. A rule that writes
    // a destination of its own still governs, scheme and all.
    //
    // This port promoted the transport too, and the difference was invisible to
    // the bench because a failed handshake retries in plain: the answer looked
    // right and every request had paid for a doomed TLS attempt first. An origin
    // that read the ClientHello instead of rejecting it hung forever, which is
    // how it surfaced.
    let dest = match claimed.https.is_some() && (scheme != wire_scheme || port != wire_port) {
        false => dest::Destination::of(&info, &resolved),
        true => {
            let mut wire = info.clone();
            wire.scheme = wire_scheme;
            wire.port = wire_port;
            dest::Destination::of(&wire, &resolved)
        }
    };
    let forwarding = forwarding_resolution(
        &state,
        &info,
        &dest,
        &resolved,
        &merged_rules,
        is_internal_req,
    );
    let forwarding = forwarding.as_ref().unwrap_or(&resolved);
    // A plugin's request hook may have merged rules since they were last noted.
    ledger.note(|s| {
        s.log = log_labels(&resolved);
        s.rules = matched_ops(&resolved);
    });

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(
            &state, req, &info, &resolved, &dest, forwarding, client_ip, ledger,
        )
        .await;
    }

    // A destination whose scheme is neither `http` nor `https` names a transport
    // this request is not — `ws://`, `wss://` and `tunnel://` say so themselves
    // ("普通 HTTP/HTTPS 请求：返回 502"), and upstream refuses every other spelling
    // on the same line of the same function, because node will not hand a
    // protocol to an agent that cannot speak it. Forwarding it as plain HTTP
    // instead sends the traffic somewhere the rule never asked for. See
    // `dest::unroutable_scheme`.
    if let Some(scheme) = dest::unroutable_scheme(&resolved) {
        return Err(outcome::stopped(
            outcome::Phase::Rules,
            anyhow::anyhow!("unsupported protocol {scheme}:"),
        ));
    }

    // Fails the request rather than silently connecting direct when a proxy rule
    // matched but could not be honoured (unusable address, unreachable or
    // throwing PAC file) — see `apply::find_proxy`.
    let target = apply::resolve_target(&info, &dest, forwarding)
        .await
        .map_err(outcome::at(outcome::Phase::Rules))?;
    ledger.note(|s| s.target = target_desc(&target));

    // A proxy rule that names this proxy would send the request back to us, be
    // matched by the same rule, and recurse until the sockets run out. whistle
    // answers the request from its own UI port instead of making the hop
    // (`_original/lib/inspectors/res.js:302-316`); `upstream::forward` refuses
    // the same hop with a "Self loop" error for every path that reaches it.
    // A direct hop to our own port under a name that is not the console's
    // would be forwarded again on arrival (`top_level`); whistle redirects it
    // to its UI by address instead (`_original/lib/inspectors/res.js:409-424`).
    // Under a console name it is simply the console, reached through the proxy.
    let looped = match upstream::self_loop(&target).await {
        Some(addr) => Some(addr),
        None => upstream::direct_self_loop(&target)
            .await
            .filter(|_| !webui::host_names_console(&state, &dest.host)),
    };
    if let Some(addr) = looped {
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
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: format!("self-loop {addr}"),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
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
    upstream::take_client_proxy_auth(&mut parts);
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
    // Buffer + transform the request body only when a body/speed/write operator applies.
    let req_speed = apply::req_speed_kbps(&resolved);
    // The method is read after the request operators, because `method://` may
    // have changed it — a `GET` rewritten to a `POST` does get its body dumped.
    let req_write = apply::req_write_path(&resolved, parts.method.as_str());
    let req_write_raw = apply::req_write_raw_path(&resolved);
    let force_write = apply::forces_write(&resolved);
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
    parts.uri = apply::request_target(&new_path).unwrap_or(parts.uri);
    let req_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    // The id every body frame of this transaction is filed under. Reserved
    // here, because the request body streams long before the session is
    // recorded — a frame cut out of it has to know where it belongs.
    let frame_session = state.reserve_id();
    // `enable://hide` keeps the whole transaction out of the capture, frames
    // included, so the watchers are not installed at all.
    let hidden = apply::hidden_from_capture(&resolved);
    // Frames a **buffered** body produced, each with its direction, held until
    // the session has an id.
    let mut buffered_frames: Vec<(&'static str, Vec<u8>)> = Vec::new();
    // The separator a request asked for, read off the outgoing headers before
    // the body is built — and removed from them either way, so the origin never
    // sees it (`parseFrameSep`, `_original/lib/inspectors/data.js:77-96`).
    let mut req_frames = {
        let asked = restream::take_frame_separator(&mut parts.headers);
        // As on the response side, the separator only frames when
        // `enable://captureStream` asked for it — measured, upstream reports no
        // frames for a request separator without the flag. There is no `isSse`
        // half here: a request body is not an event stream.
        match hidden
            || apply::is_disabled(&resolved, "captureStream")
            || !apply::is_enabled(&resolved, "captureStream")
        {
            true => None,
            false => asked,
        }
    };
    let mut req_body_cap: Option<Capture> = None;
    let req_body: DynBody = if apply::wants_req_body(&resolved, body_ctx)
        || req_speed.is_some()
        || req_write.is_some()
        || req_write_raw.is_some()
    {
        // Bounded: these operators need the body in memory, and the body is
        // whatever the client decided to send. Past the bound whistle stops
        // transforming and lets the rest through — see [`body::collect_capped`].
        match collect_capped_body(incoming, apply::req_body_limit(&resolved))
            .await
            .map_err(outcome::at(outcome::Phase::Request))?
        {
            body::Capped::TooBig { body, .. } => {
                // Said out loud, because every other way for these operators to
                // do nothing has turned out to be a bug worth fixing. This one
                // is a deliberate refusal, and a rule that quietly stopped
                // applying above some size would read exactly like the bugs.
                tracing::warn!(
                    "{} {}: request body is over {} bytes, so it is forwarded \
                     unchanged — reqBody/reqReplace/params/reqWrite and reqSpeed \
                     do not apply. `enable://reqMergeBigData` raises the limit",
                    info.method,
                    info.full_url,
                    apply::req_body_limit(&resolved),
                );
                let cap = Capture::new(
                    req_ct.clone(),
                    req_enc.as_deref(),
                    state.config.body_preview_cap,
                );
                req_body_cap = Some(cap.clone());
                body::tee(body, cap)
            }
            body::Capped::Whole { bytes, .. } => {
                // Decompress before rewriting, exactly as the response path
                // does. Upstream reaches it from the other end: every request
                // body operator goes through `addTextTransform`/`addZipTransform`,
                // both of which set `_needGunzip` (`_original/lib/init.js:90-112`),
                // which puts a decoder in front and an encoder behind
                // (`inspectors/rules.js:64-146`).
                //
                // Without it a `reqReplace://` searched the deflate stream and
                // found nothing, a `reqAppend://` wrote its text *after* the
                // gzip stream, and `reqBody://` sent plain text still labelled
                // `Content-Encoding: gzip` — a request the origin cannot read.
                //
                // No `enable://gzip` here: upstream calls `getEncoder(req)` with
                // one argument (`rules.js:164`), so its `req.enable` lookup is on
                // `undefined` and the flag never reaches the request side. The
                // body goes back under the coding it arrived with, or none.
                let decoded = coding::decode_for_rewrite(bytes, req_enc.as_deref());
                let restore = decoded.restore;
                let new = apply::transform_req_body(decoded.body, &resolved, body_ctx);
                let (new, encoded_as) = coding::reencode(new, restore, None);
                let req_enc = restore_content_encoding(
                    &mut parts.headers,
                    restore,
                    encoded_as,
                    req_enc.clone(),
                );
                if let Some(path) = &req_write {
                    write_body_file(path, &new, force_write);
                }
                if let Some(path) = &req_write_raw {
                    let head = format!(
                        "{} {} HTTP/1.1\r\n{}",
                        parts.method,
                        parts.uri,
                        header_dump(&parts.headers)
                    );
                    write_raw_file(path, &head, &new, force_write);
                }
                if !new.is_empty() {
                    req_body_cap = Some(Capture::from_bytes(
                        &new,
                        req_ct.clone(),
                        req_enc.as_deref(),
                        state.config.body_preview_cap,
                    ));
                }
                // A request body the console shows as frames, cut out of the
                // bytes that go upstream — the response's twin, and gated the
                // same way (`cseSep`, `data.js:63,:249`).
                if let Some(mut splitter) = req_frames.take() {
                    buffered_frames.extend(
                        splitter
                            .push(&new)
                            .into_iter()
                            .chain(splitter.finish())
                            .map(|payload| ("send", payload)),
                    );
                }
                apply::strip_length_headers(&mut parts.headers);
                match req_speed {
                    Some(kbps) => body::throttled(new, kbps),
                    None => body::full(new),
                }
            }
        }
    } else if has_request_body(&parts.headers) {
        // No transform: stream through, copying a bounded preview for inspection.
        let cap = Capture::new(
            req_ct.clone(),
            req_enc.as_deref(),
            state.config.body_preview_cap,
        );
        req_body_cap = Some(cap.clone());
        let teed = body::tee(incoming, cap);
        match req_frames.take() {
            Some(splitter) => body::frames(teed, state.clone(), frame_session, splitter, "send"),
            None => teed,
        }
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

    tracing::info!(
        "{} {} -> {}:{} ({})",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port,
        if target.tls { "https" } else { "http" }
    );

    // Handed in rather than returned: the row is recorded when the response head
    // arrives, and `receive` only lands when the body ends. See `timing`.
    let timings = timing::Timings::new();
    // Everything a failed forward's session can show: what was sent, and how
    // far the connection got — the phases stop where it failed.
    ledger.note(|s| {
        s.id = frame_session;
        s.req_headers = req_header_pairs.clone();
        s.req_body = req_body_cap.clone();
        s.timings = Some(timings.clone());
    });
    let (upstream_resp, server_addr) =
        upstream::forward_with_addr(&target, out_req, &timings).await?;

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
    )
    .await;

    if let Some(ms) = apply::res_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // `enable://abort` / `abortRes`: the request went out, the origin answered,
    // and *now* the connection is destroyed — `res.js:1175-1179`, right after
    // `resDelay://`, which is why this sits below the sleep. The point of
    // aborting here rather than before the request is that the origin still
    // sees the traffic; only the client is cut off.
    if apply::aborts_response(&resolved) {
        tracing::info!("{} {} -> response aborted", info.method, info.full_url);
        // Upstream keeps the head it is about to throw away (`req.__resHeaders`
        // / `req.__statusCode`, `res.js:1176-1177`) so the capture still shows
        // what arrived; without this the session reads as if nothing came back.
        ledger.record(Session {
            id: frame_session,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            client_ip,
            target: format!("{}:{} (aborted)", target.connect_host, target.connect_port),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers: req_header_pairs,
            res_headers: header_pairs(&parts.headers),
            req_body: req_body_cap,
            timings: Some(timings),
            error: aborted(
                "dropped by a rule after the server answered (enable://abort or abortRes)",
            ),
            ..Default::default()
        });
        return Err(Destroyed.into());
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

    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // This is the path where the body is still arriving frame by frame, so the
    // content type is what decides whether it may be collected at all.
    let ops = ResBodyOps::of(
        &resolved,
        response_has_body(parts.status.as_u16(), &info.method),
        parts.status.as_u16(),
        res_ct.as_deref(),
    );
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    // A plugin that asked for the body of an event stream cannot have it, and
    // says so rather than leaving the hook mysteriously un-run: `responseBody`
    // is a declaration this port cannot honour on a body that need never end.
    if plugin_wants_res_body && is_event_stream(res_ct.as_deref()) {
        tracing::warn!(
            "{} is an event stream; a plugin's responseBody hook is skipped rather \
             than holding the stream shut",
            info.full_url
        );
    }
    let mut res_body_cap: Option<Capture> = None;
    // Decide first, then act — because the buffered path may hand the body back.
    // A response too large to hold is not rewritten at all, and then this is the
    // streaming path after all.
    //
    // The origin's trailer section is lifted off with the bytes and handed to
    // `finish_res_body`. Collecting a body discards it otherwise, which is how a
    // response that arrived with trailers reached the client without them the
    // moment *any* body operator matched — including one that had nothing to do
    // with trailers.
    let mut collected: Option<(Bytes, Option<hyper::HeaderMap>)> = None;
    let mut streamed: Option<DynBody> = None;
    if must_collect_body(
        &ops,
        plugin_wants_res_body,
        plugin_res_override.is_some(),
        res_ct.as_deref(),
    ) {
        match &plugin_res_override {
            // A plugin that replaced the body outright makes the upstream bytes
            // irrelevant — don't wait on them, and don't measure them either:
            // they are already in memory and were never read from a socket.
            Some(new) => collected = Some((Bytes::from(new.clone()), None)),
            None => {
                let cap = apply::res_body_limit(&resolved, state.config.body_rewrite_cap);
                match collect_capped_body(body, cap)
                    .await
                    .map_err(outcome::at(outcome::Phase::Response))?
                {
                    body::Capped::Whole { bytes, trailers } => {
                        collected = Some((bytes, trailers));
                    }
                    body::Capped::TooBig { body, .. } => {
                        // whistle never needs this bound: its response rewriting
                        // is a stream transform, so a rule costs it no memory.
                        // This port collects, so it has to stop somewhere — and
                        // it says where, because a rule that quietly stopped
                        // applying above some size reads exactly like a bug.
                        tracing::warn!(
                            "{} {}: response body is over {} bytes, so it is \
                             forwarded unchanged — the body operators, \
                             enable://gzip and any plugin responseBody hook do \
                             not apply. Raise --body-rewrite-limit to allow it",
                            info.method,
                            info.full_url,
                            cap,
                        );
                        streamed = Some(body);
                    }
                }
            }
        }
    } else {
        streamed = Some(body);
    }
    let res_body: DynBody = if let Some((bytes, origin_trailers)) = collected {
        // Decompress before rewriting. Every body operator works on text,
        // and most origins answer compressed — so without this a
        // `resReplace://` against a gzipped page searched the deflate
        // stream for its pattern, found nothing, and silently did nothing.
        // whistle reaches the same place from the other end: any body
        // transform sets `_needGunzip`, which puts a decoder in front of it
        // and a re-encoder behind (`addZipTransform`,
        // `_original/lib/inspectors/data.js:` and `inspectors/rules.js:60-140`).
        let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref());
        let restore = decoded.restore;
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
        let (new, encoded_as) = coding::reencode(new, restore, ops.force_encoding);
        let now =
            restore_content_encoding(&mut parts.headers, restore, encoded_as, res_enc.clone());
        if !new.is_empty() {
            res_body_cap = Some(Capture::from_bytes(
                &new,
                res_ct.clone(),
                // The preview decodes what it is told the body is, so it has
                // to be told what the body *now* is, not what arrived.
                now.as_deref(),
                state.config.body_preview_cap,
            ));
        }
        // A buffered body is framed too, out of the bytes the client will
        // receive — the same rule and the same separator, applied at once
        // rather than as they arrive.
        if let Some(mut splitter) =
            response_frames(&resolved, &mut parts.headers, now.as_deref()).filter(|_| !hidden)
        {
            buffered_frames.extend(
                splitter
                    .push(&new)
                    .into_iter()
                    .chain(splitter.finish())
                    .map(|payload| ("receive", payload)),
            );
        }
        finish_res_body(&mut parts, new, ops, origin_trailers)
    } else {
        let body = streamed.expect("collected or streamed, never neither");
        // Stream through, copying a bounded preview for inspection. The
        // origin's trailers ride along untouched — unless a `disable://`
        // asked for them to go, which this path acts on.
        //
        // One operator can travel with a body that is still arriving:
        // `resReplace://` needs a window, not the whole thing. See
        // [`stream_replace`] for what disqualifies a stream.
        let body = match stream_replace(&resolved, res_ct.as_deref(), res_enc.as_deref()) {
            Some(transform) => {
                // A substitution changes the length, so a promise about it
                // cannot be kept. An event stream does not carry one, but
                // the removal belongs with the rewrite rather than with the
                // assumption.
                parts.headers.remove(hyper::header::CONTENT_LENGTH);
                restream::wrap(body, transform)
            }
            None => body,
        };
        // …and three more that do not need the whole body either:
        // `resPrepend://` goes ahead of the first byte, `resAppend://`
        // after the last, and `resBody://` says there is no origin body to
        // wait for. They sit *after* the substitution because that is the
        // buffered path's order too — upstream's text transforms run ahead
        // of the injection, so a `resReplace://` never sees what a
        // `resPrepend://` put there (`_original/lib/inspectors/res.js`, and
        // see `transform_res_body`).
        let body = match stream_injection(&resolved, res_ct.as_deref()) {
            Some(inject) => {
                parts.headers.remove(hyper::header::CONTENT_LENGTH);
                let origin = match inject.replacement {
                    // `resBody://` replaces the body, so the origin's is
                    // not waited for — dropping it here is what makes this
                    // usable as a mock for a stream that never ends.
                    Some(replacement) => body::full(replacement),
                    None => body,
                };
                body::surround(origin, inject.top, inject.bottom)
            }
            None => body,
        };
        // The capture records what the client receives, so it sits *after*
        // the substitution — as it does on the buffered path, where the
        // preview is built from the rewritten bytes.
        let cap = Capture::new(
            res_ct.clone(),
            res_enc.as_deref(),
            state.config.body_preview_cap,
        );
        res_body_cap = Some(cap.clone());
        let teed = body::tee(body, cap);
        // …and, for a stream the console shows as frames, one more watcher.
        // It sits after the capture for the reason the capture sits after
        // the substitution: a frame is what the client received.
        let framed = match response_frames(&resolved, &mut parts.headers, res_enc.as_deref())
            .filter(|_| !hidden)
        {
            Some(splitter) => body::frames(teed, state.clone(), frame_session, splitter, "receive"),
            None => teed,
        };
        match ops.no_trailers {
            true => retrailer(framed, None),
            false => framed,
        }
    };
    // `receive` runs from the response head to the last byte, so it is stamped
    // by the body itself — on both paths, because a buffered body was received
    // too; it was simply received before the operators ran.
    let res_body = timing::measure_receive(res_body, timings.clone());

    let session = Session {
        id: frame_session,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: parts.status.as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc(&target),
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(&resolved),
        rules: matched_ops(&resolved),
        req_headers: req_header_pairs,
        res_headers: header_pairs(&parts.headers),
        req_body: req_body_cap,
        res_body: res_body_cap,
        timings: Some(timings.clone()),
        error: Default::default(),
    };
    // The row appears now, while the body is still arriving; the transaction
    // is complete — and can still fail — only when the body is over. A
    // response that has no body to send is over already: hyper drops it
    // unread, and that is not a client leaving.
    let (recorded, res_body) = match carries_body(parts.status.as_u16(), &info.method) {
        true => {
            let expected = parts
                .headers
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse().ok());
            ledger.record_streaming(session, res_body, expected)
        }
        false => (ledger.record(session), res_body),
    };
    for (dir, payload) in buffered_frames {
        state.record_frame(WsFrame::body_frame(recorded, dir, &payload));
    }

    Ok(Response::from_parts(parts, res_body))
}

/// Whether a response to `method` with `status` sends a body at all. Stricter
/// than [`response_has_body`], which is about the body *operators* and leaves
/// a redirect's body alone: a 302 still sends one, and it can still break off.
fn carries_body(status: u16, method: &str) -> bool {
    !(method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304)
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

/// Complete the handshake a local `101` answers an upgrade with — what upstream
/// does for `statusCode://101` on a WebSocket (`_original/lib/https/index.js:145-162`):
/// the `Sec-WebSocket-Accept` the key calls for, the first subprotocol asked
/// for, `Upgrade` as the client spelled it (or `websocket`), and
/// `Connection: Upgrade`. Without them a client refuses the switch — the bare
/// `101` this port sent was "unexpected server response (101)" to upstream's
/// `ws.test.js`.
///
/// Then the connection is held, as upstream holds it with nobody behind it:
/// whatever the client sends is read and dropped until it hangs up.
fn accept_upgrade_locally<B>(req: &mut Request<B>, resp: &mut Response<DynBody>) {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let upgrade = header(hyper::header::UPGRADE).unwrap_or_else(|| "websocket".to_string());
    let protocol = header(hyper::header::SEC_WEBSOCKET_PROTOCOL)
        .map(|p| p.split(',').next().unwrap_or_default().trim().to_string());
    let accept = header(hyper::header::SEC_WEBSOCKET_KEY).map(|key| ws::accept_key(&key));
    let headers = resp.headers_mut();
    for (name, value) in [
        (hyper::header::SEC_WEBSOCKET_ACCEPT, accept),
        (hyper::header::SEC_WEBSOCKET_PROTOCOL, protocol),
        (hyper::header::UPGRADE, Some(upgrade)),
        (hyper::header::CONNECTION, Some("Upgrade".to_string())),
    ] {
        if let Some(value) = value.and_then(|v| hyper::header::HeaderValue::from_str(&v).ok()) {
            headers.insert(name, value);
        }
    }
    let upgraded = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(io) = upgraded.await {
            let mut io = TokioIo::new(io);
            let _ = tokio::io::copy(&mut io, &mut tokio::io::sink()).await;
        }
    });
}

/// True if the request asks to upgrade the protocol (e.g. a WebSocket handshake).
fn is_upgrade(req: &Request<DynBody>) -> bool {
    asks_to_upgrade(req.headers())
}

/// The same question of a header map alone, because it has to be answered
/// before the request has been read — the scheme the rules match against
/// depends on it (`ws://` rather than `http://`).
fn asks_to_upgrade(headers: &hyper::HeaderMap) -> bool {
    let conn_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    conn_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// True if the upgrade handshake targets the WebSocket protocol (as opposed to
/// some other `Upgrade:` protocol we should tunnel opaquely).
///
/// `enable://websocket` says yes whatever the header says. Some clients speak
/// WebSocket under a name of their own — `Upgrade: ws`, a vendor string — and
/// upstream's read of the flag is exactly this one:
/// `socket.enable.websocket || util.isWebSocket(headers)`
/// (`_original/lib/https/index.js:81`). Without it such a connection is a byte
/// stream in both proxies, and its frames are never surfaced.
fn is_websocket(req: &Request<DynBody>, resolved: &Resolved) -> bool {
    if apply::is_enabled(resolved, "websocket") {
        return true;
    }
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
///
/// `forwarding` is the forwarding family's own resolution and `resolved` the
/// request's; the two differ only when a rule moved the request — see
/// [`forwarding_resolution`]. Upstream splits them here too: its WebSocket path
/// rewrites `fullUrl` from the `rule` slot and only then calls `getProxy` with
/// it (`_original/lib/https/index.js:228-232,:292`).
#[allow(clippy::too_many_arguments)]
async fn serve_upgrade(
    state: &Arc<AppState>,
    mut req: Request<DynBody>,
    info: &ReqInfo,
    resolved: &Resolved,
    dest: &dest::Destination,
    forwarding: &Resolved,
    client_ip: Option<String>,
    ledger: &mut Ledger,
) -> Result<Response<DynBody>> {
    let (time_ms, started) = (ledger.time_ms, ledger.started);
    let target = apply::resolve_target(info, dest, forwarding)
        .await
        .map_err(outcome::at(outcome::Phase::Rules))?;
    ledger.note(|s| s.target = target_desc(&target));
    let frame_script = resolved.value("frameScript").and_then(script::load_script);
    let websocket = is_websocket(&req, resolved);
    // Which plugins may hook this session's frames. Resolving the plan contacts
    // nothing and allocates nothing unless a rule named a registered plugin;
    // the plugins themselves are dialled later, from inside the tunnel.
    let frame_plan = if websocket {
        ws::FramePlan::new(&state.plugins, resolved, info)
    } else {
        ws::FramePlan::default()
    };
    // What `enable://ignoreSend|ignoreReceive|pauseSend|pauseReceive` asked to
    // happen to each direction. Read here rather than inside the plan: the plan
    // collapses to its default when no plugin is named, and these flags have to
    // survive that.
    let frame_flow = ws::FrameFlow::of(resolved);
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream handshake request (upgrades carry no body, so
    // `params://` can only address the query string here).
    let (mut parts, _body) = req.into_parts();
    let new_path = apply::rewrite_path(&dest.path, resolved, apply::ReqBodyCtx::default());
    parts.uri = apply::request_target(&new_path).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &dest.host, dest.port, &dest.scheme);
    parts.headers.remove("proxy-connection");
    upstream::take_client_proxy_auth(&mut parts);
    mark_stripped_tls(&mut parts.headers, &target);
    apply::apply_request(&mut parts, resolved);
    // Every WebSocket this proxy relays is read frame by frame — captured,
    // offered to `frameScript` and the plugins' hooks — and a compressed frame
    // is unreadable to all of them. Worse, the codec in `ws` does not carry a
    // frame's RSV1 bit across, so once the two ends had agreed on
    // `permessage-deflate` the receiver got compressed bytes marked as plain
    // text: upstream's `connect.test.js` read back binary noise. So nothing is
    // negotiated: the offer does not reach the server, and the frames stay as
    // they were written. Compression is optional to both ends; this costs only
    // bytes on the wire. (Upstream relays the frames compressed and inflates a
    // copy for its display, `lib/socket-mgr.js:699-705`.)
    parts
        .headers
        .remove(hyper::header::SEC_WEBSOCKET_EXTENSIONS);
    let out_req = Request::from_parts(parts, body::empty());

    tracing::info!(
        "{} {} -> upgrade {}:{}",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port
    );

    // Measured for the same reason as a plain request's: a handshake that
    // fails to connect shows how far it got.
    let timings = timing::Timings::new();
    ledger.note(|s| s.timings = Some(timings.clone()));
    let (mut resp, _) = upstream::forward_with_addr(&target, out_req, &timings).await?;
    let target_desc = target_desc(&target);

    // `enable://abort` / `abortRes` on an upgrade: the handshake went out, the
    // server answered it, and the client is cut off instead of being handed the
    // `101` (`_original/lib/https/index.js:783-786`). `abortReq` needs nothing
    // here — an upgrade is an ordinary request until this function is called,
    // and it has already passed the request-side gate in [`serve`], which is
    // where upstream's WebSocket path puts it too (`https/index.js:256-259`).
    //
    // Upstream waits out `resDelay://` before this gate; this port has no
    // response phase on the upgrade path at all, so there is nothing to wait
    // for and nothing to re-resolve — `resolved` is the request pass.
    if apply::aborts_response(resolved) {
        tracing::info!("{} {} -> upgrade aborted", info.method, info.full_url);
        // The head that is being thrown away is still recorded, for the reason
        // the HTTP gate records one: a session that shows nothing coming back
        // reads as if the server never answered, and it did.
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip,
            target: format!("{target_desc} (aborted)"),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(resolved),
            rules: matched_ops(resolved),
            res_headers: header_pairs(resp.headers()),
            timings: Some(timings),
            error: aborted(
                "dropped by a rule after the server answered (enable://abort or abortRes)",
            ),
            ..Default::default()
        });
        return Err(Destroyed.into());
    }

    let session_id = ledger.record(Session {
        id: 0,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: resp.status().as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc,
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(resolved),
        rules: matched_ops(resolved),
        res_headers: header_pairs(resp.headers()),
        timings: Some(timings),
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
                        frame_flow,
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

#[cfg(test)]
mod upgrade_abort_tests {
    use super::tunnel_abort_tests::proxy_with;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An origin that answers anything with a WebSocket `101` and then holds the
    /// connection open, so the proxy sees a live upgrade rather than a hang-up.
    async fn upgrading_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // However much of the handshake arrives, the answer is the
                    // same — this origin agrees to every upgrade.
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    sock.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\
                          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    )
                    .await
                    .ok();
                    // Then hold the socket open until the other end lets go.
                    let _ = sock.read(&mut buf).await;
                });
            }
        });
        addr
    }

    /// Open a WebSocket handshake for `path` through the proxy at `addr` and
    /// return everything the proxy writes back.
    async fn handshake_through(addr: SocketAddr, origin: SocketAddr, path: &str) -> Vec<u8> {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET http://{origin}{path} HTTP/1.1\r\n\
             Host: {origin}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        // One read: it returns as soon as a response head arrives, and returns
        // nothing when the connection is torn down instead — a reset is an error
        // rather than an EOF, and both mean the same thing here. Reading to EOF
        // would mean waiting out the tunnel that a *relayed* upgrade opens.
        let mut got = vec![0u8; 1024];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        got.truncate(read);
        got
    }

    /// `statusCode://101` on a WebSocket completes the handshake itself, as
    /// upstream does (`lib/https/index.js:145-162`): the accept the key calls
    /// for, and the headers a client checks before it believes the switch.
    #[tokio::test]
    async fn a_local_101_completes_the_websocket_handshake() {
        let (_state, addr) = proxy_with("ws.local.test statusCode://101").await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET http://ws.local.test/ HTTP/1.1\r\nHost: ws.local.test\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n",
            )
            .await
            .unwrap();
        let mut got = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .expect("an answer")
            .unwrap();
        let head = String::from_utf8_lossy(&got[..n]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        // RFC 6455's own example key and accept.
        assert!(
            head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
            "{head}"
        );
        assert!(head.contains("sec-websocket-protocol: chat\r\n"), "{head}");
        assert!(head.contains("upgrade: websocket"), "{head}");
        assert!(head.contains("connection: upgrade"), "{head}");
    }

    /// No extension is negotiated through the proxy: the client's
    /// `Sec-WebSocket-Extensions` offer does not reach the server, so a server
    /// that would compress cannot, and the frames the proxy reads and relays
    /// are the ones the ends wrote. With the offer passed on, upstream's
    /// `connect.test.js` got compressed bytes delivered as text.
    #[tokio::test]
    async fn a_compression_offer_does_not_reach_the_server() {
        let offered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let origin = listener.local_addr().unwrap();
        let seen = offered.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            // A server that compresses whenever it is asked to.
            let asked = head.contains("sec-websocket-extensions");
            seen.store(asked, std::sync::atomic::Ordering::SeqCst);
            let ext = if asked {
                "Sec-WebSocket-Extensions: permessage-deflate\r\n"
            } else {
                ""
            };
            let answer = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n{ext}\r\n"
            );
            sock.write_all(answer.as_bytes()).await.ok();
            let _ = sock.read(&mut buf).await;
        });
        let (_state, addr) = proxy_with("").await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET http://{origin}/ws HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut got = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .expect("an answer")
            .unwrap();
        let head = String::from_utf8_lossy(&got[..n]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(
            !offered.load(std::sync::atomic::Ordering::SeqCst),
            "the offer reached the server"
        );
        assert!(!head.contains("sec-websocket-extensions"), "{head}");
    }

    /// `enable://abortRes` on an upgrade lets the handshake reach the server and
    /// then cuts the client off instead of handing it the `101`
    /// (`_original/lib/https/index.js:783-786`). The client must not see the
    /// switch, or it would start speaking WebSocket into a closed socket.
    #[tokio::test]
    async fn an_aborted_upgrade_never_reaches_the_client() {
        let origin = upgrading_origin().await;
        let (state, addr) = proxy_with(&format!("{origin} enable://abortRes")).await;

        let got = handshake_through(addr, origin, "/ws").await;
        assert!(
            !got.starts_with(b"HTTP/1.1 101"),
            "the switch must not be relayed, got {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(
            got.is_empty(),
            "and nothing else is served in its place, got {:?}",
            String::from_utf8_lossy(&got)
        );

        // The head that was thrown away is still on the row, so the session
        // reads as "the server answered and the client was cut off" rather than
        // "nothing came back".
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.front().expect("the abort is recorded");
        assert_eq!(session.status, 101);
        assert!(
            session.target.ends_with("(aborted)"),
            "target was {:?}",
            session.target
        );
    }

    /// `enable://abortReq` on an upgrade needs no gate of its own: an upgrade is
    /// an ordinary request right up to the point the handshake is forwarded, so
    /// it meets the request-side gate first — which is exactly where upstream's
    /// WebSocket path puts it (`_original/lib/https/index.js:256-259`). The
    /// origin is never contacted, and the proof is that an origin which cannot
    /// be reached at all makes no difference to what the client sees.
    #[tokio::test]
    async fn an_upgrade_aborted_before_it_leaves_never_reaches_the_origin() {
        // A port bound only long enough to know nothing else has it.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };

        let (_state, addr) = proxy_with(&format!("{dead} enable://abortReq")).await;
        let got = handshake_through(addr, dead, "/ws").await;
        assert!(
            got.is_empty(),
            "expected silence, got {:?}",
            String::from_utf8_lossy(&got)
        );

        // Without the rule the same unreachable origin produces a `502`, so the
        // silence above is the abort and not the dial failing.
        let (_state, addr) = proxy_with("other.test enable://abortReq").await;
        let got = handshake_through(addr, dead, "/ws").await;
        assert!(
            got.starts_with(b"HTTP/1.1 502"),
            "expected a gateway error, got {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// An upgrade resolves under a `ws://` URL, not an `http://` one.
    ///
    /// whistle stamps `req.isWs` and builds the URL its patterns match from it
    /// (`_original/lib/upgrade.js:121`, `common.js:1267`). The rules layer here
    /// has always read that scheme; nothing ever *set* it, so a `ws://` pattern
    /// matched no request a client could make and an `http://` pattern matched
    /// the WebSocket it is written to exclude. `enable://abortRes` is the probe
    /// — silence means the rule matched, a `101` means it did not.
    #[tokio::test]
    async fn an_upgrade_is_matched_as_a_websocket_url() {
        let origin = upgrading_origin().await;

        let (_state, addr) = proxy_with(&format!("ws://{origin} enable://abortRes")).await;
        assert!(
            handshake_through(addr, origin, "/ws").await.is_empty(),
            "a ws:// pattern must reach a WebSocket"
        );

        let (_state, addr) = proxy_with(&format!("http://{origin} enable://abortRes")).await;
        assert!(
            handshake_through(addr, origin, "/ws")
                .await
                .starts_with(b"HTTP/1.1 101"),
            "an http:// pattern must not reach a WebSocket"
        );

        // And the consequence the scheme decides on its own: a file rule is
        // passed over on an upgrade rather than answering it with a mock
        // (`matcher::serves_no_file`). Measured against whistle 2.10.8, which
        // relays the handshake; this port used to answer `404 Not found file`.
        let (_state, addr) = proxy_with(&format!("{origin} file:///no/such/mock.json")).await;
        assert!(
            handshake_through(addr, origin, "/ws")
                .await
                .starts_with(b"HTTP/1.1 101"),
            "a file rule must not answer an upgrade"
        );
    }

    /// The control: the same proxy relays an upgrade no rule aborts, so the
    /// gate is refusing responses rather than the upgrade path being broken.
    #[tokio::test]
    async fn an_upgrade_no_rule_aborts_is_relayed() {
        let origin = upgrading_origin().await;
        let (_state, addr) = proxy_with("other.test enable://abortRes").await;
        let got = handshake_through(addr, origin, "/ws").await;
        assert!(
            got.starts_with(b"HTTP/1.1 101"),
            "expected the switch, got {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}

/// Append a captured body to a file (`reqWrite`/`resWrite`). Best-effort.
fn write_body_file(path: &str, data: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    if let Err(e) = f.write_all(data) {
        tracing::debug!("write body to {path} failed: {e}");
    }
}

/// Open a dump file for one of the four write operators, or refuse.
///
/// whistle writes a dump file **once**: `getFileWriter` stats the path first and
/// hands back no writer at all when it already exists, so only `ENOENT` produces
/// one (`checkWriterFile`/`getFileWriter`,
/// `_original/lib/util/index.js:502-546`). `enable://forceReqWrite` is the
/// override, and it overwrites rather than appends — the stream is opened with
/// Node's default `w`.
///
/// Appending, which is what this did, is a different tool: point a rule at a
/// path once and every reload of the page grows the file, so what you open is a
/// concatenation of runs with no boundary between them, and the "capture" of the
/// request you meant is somewhere in the middle of it.
///
/// A path ending in a separator names a directory, and the dump goes in it as
/// `index.html` (`END_RE`, `util/index.js:54,:521-523`).
///
/// Upstream's `pendingFiles` guard — which also refuses a file another request
/// is mid-write on — is not reproduced: it exists because its writers are
/// asynchronous streams, and these are one synchronous `write_all`.
fn open_writer(path: &str, force: bool) -> Option<std::fs::File> {
    let path = match path.ends_with('/') || path.ends_with('\\') {
        true => std::path::Path::new(path).join("index.html"),
        false => std::path::PathBuf::from(path),
    };
    if !force && path.exists() {
        tracing::debug!("{} already exists; not written", path.display());
        return None;
    }
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        tracing::debug!("create {} failed: {e}", dir.display());
        return None;
    }
    match std::fs::File::create(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::debug!("open {} for write failed: {e}", path.display());
            None
        }
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

/// Write a raw message — head, blank line, body — to a file.
///
/// Nothing follows the body. Upstream writes `getRawData(…)`, which is the
/// first line, the headers and one blank line, and then pipes the body straight
/// into the same stream (`FileWriterTransform`,
/// `_original/lib/util/file-writer-transform.js:6-13,:53-58`). This port used to
/// add a trailing `\r\n\r\n` on the end, on the theory that a dump might hold
/// several messages — it never does, because `getFileWriter` refuses a path that
/// already exists. What it produced instead was a dump of a bodiless request
/// ending in four CRLFs where whistle's ends in two, which is not a raw record
/// of anything that went over the wire.
fn write_raw_file(path: &str, head: &str, body: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    let _ = f.write_all(head.as_bytes());
    let _ = f.write_all(b"\r\n");
    let _ = f.write_all(body);
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
fn ensure_host_header(headers: &mut hyper::HeaderMap, host: &str, port: u16, scheme: &str) {
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
mod body_gate_tests {
    /// A response with no body is not a response to inject into. whistle's
    /// `hasBody` (`_original/lib/util/common.js:370-380`) excludes a `HEAD`
    /// answer, 1xx, 204 and every 3xx — and a redirect that arrives with an
    /// injected body, a stripped `Content-Length`, `Cache-Control: no-store` and
    /// no CSP is not the redirect the origin sent.
    #[test]
    fn only_a_response_that_carries_a_body_may_be_rewritten() {
        use super::response_has_body;

        for status in [200, 201, 205, 400, 404, 500] {
            assert!(response_has_body(status, "GET"), "{status}");
        }
        for status in [100, 101, 199, 204, 300, 301, 302, 304, 307, 399] {
            assert!(!response_has_body(status, "GET"), "{status}");
        }
        // A HEAD answer never has one, whatever the status says.
        assert!(!response_has_body(200, "HEAD"));
        assert!(!response_has_body(200, "head"));
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "whistle-rs-writer-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join(name)
    }

    /// A dump file is written **once**: whistle stats the path first and hands
    /// back no writer when it already exists (`checkWriterFile`/`getFileWriter`,
    /// `_original/lib/util/index.js:502-546`).
    ///
    /// This appended instead, so a rule left in place over a reload produced a
    /// file that is a concatenation of runs with no boundary between them — and
    /// the request you meant to capture somewhere in the middle of it.
    #[test]
    fn a_dump_file_is_written_once() {
        let path = scratch("body.txt");
        let p = path.to_str().expect("utf-8 path");

        write_body_file(p, &Bytes::from_static(b"first"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // The second request through the same rule leaves it alone.
        write_body_file(p, &Bytes::from_static(b"second"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // `enable://forceReqWrite` overwrites — it does not append, because
        // upstream reopens the stream with Node's default `w`.
        write_body_file(p, &Bytes::from_static(b"second"), true);
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    /// The raw dump takes the same gate, and missing parent directories are
    /// created (`fse.ensureFile`, `util/index.js:536`).
    #[test]
    fn the_raw_dump_takes_the_same_gate_and_makes_its_directory() {
        let path = scratch("nested/deeper/raw.txt");
        let p = path.to_str().expect("utf-8 path");

        write_raw_file(p, "GET / HTTP/1.1", &Bytes::from_static(b"body"), false);
        let written = std::fs::read(&path).expect("read");
        // Head, blank line, body — and nothing after it. The trailing `\r\n\r\n`
        // this used to add made a bodiless dump end in four CRLFs where
        // whistle's ends in two; measured on `tests/differential/write-bench.js`.
        assert_eq!(written, b"GET / HTTP/1.1\r\nbody");

        write_raw_file(p, "GET /other HTTP/1.1", &Bytes::from_static(b"x"), false);
        assert_eq!(std::fs::read(&path).expect("read"), written);
    }

    /// A path ending in a separator names a directory, and the dump goes in it
    /// as `index.html` (`END_RE`, `_original/lib/util/index.js:54,:521-523`).
    #[test]
    fn a_trailing_separator_names_a_directory() {
        let dir = scratch("dumpdir");
        let p = format!("{}/", dir.to_str().expect("utf-8 path"));
        write_body_file(&p, &Bytes::from_static(b"page"), false);
        assert_eq!(
            std::fs::read(dir.join("index.html")).expect("read"),
            b"page"
        );
    }

    /// A non-200 response is dumped beside the good capture, not over it
    /// (`getWriterFile`, `_original/lib/inspectors/res.js:147-153`).
    #[test]
    fn a_failing_response_is_dumped_under_its_status() {
        let mut m = RuleManager::new();
        m.set_text("example.com resWrite:///tmp/dump  resWriteRaw:///tmp/raw\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        assert_eq!(
            apply::res_write_path(&resolved, 200),
            Some("/tmp/dump".to_string())
        );
        assert_eq!(
            apply::res_write_path(&resolved, 502),
            Some("/tmp/dump.502".to_string())
        );
        // The raw dump is named the same way.
        assert_eq!(
            apply::res_write_raw_path(&resolved, 404),
            Some("/tmp/raw.404".to_string())
        );
    }

    /// `reqWrite://` is gated on the request actually having a body
    /// (`util.hasRequestBody(req) ? … : null`,
    /// `_original/lib/inspectors/req.js:582-584`).
    ///
    /// Without the gate a `GET` created an empty file, which reads as "the
    /// capture worked and there was no body" rather than "there was never a
    /// body to capture". `reqWriteRaw://` is *not* gated: the head is worth
    /// dumping either way.
    #[test]
    fn req_write_needs_a_method_that_carries_a_body() {
        let mut m = RuleManager::new();
        m.set_text("example.com reqWrite:///tmp/req  reqWriteRaw:///tmp/rawreq\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        for method in ["GET", "HEAD", "OPTIONS", "CONNECT"] {
            assert_eq!(apply::req_write_path(&resolved, method), None, "{method}");
        }
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                apply::req_write_path(&resolved, method),
                Some("/tmp/req".to_string()),
                "{method}"
            );
        }
        assert_eq!(
            apply::req_write_raw_path(&resolved),
            Some("/tmp/rawreq".to_string())
        );
    }
}

#[cfg(test)]
mod trailer_tests {
    use super::*;
    use hyper::body::Body as _;

    /// Drive a body to its end, returning its data frames and trailer section.
    fn drain(body: DynBody) -> (Vec<Bytes>, Option<hyper::HeaderMap>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut body = std::pin::pin!(body);
            let (mut frames, mut trailers) = (Vec::new(), None);
            while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                let frame = frame.expect("frame");
                match frame.into_data() {
                    Ok(data) => frames.push(data),
                    Err(frame) => trailers = frame.into_trailers().ok(),
                }
            }
            (frames, trailers)
        })
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).expect("name"),
                v.parse().expect("value"),
            );
        }
        h
    }

    /// Everything `finish_res_body` decides about the trailer section, driven
    /// through the same struct `serve` builds.
    fn finish(
        rule_trailers: &[(&str, &str)],
        origin: Option<&[(&str, &str)]>,
        no_trailers: bool,
        speed: Option<f64>,
        body_len: usize,
    ) -> (
        hyper::http::response::Parts,
        Vec<Bytes>,
        Option<hyper::HeaderMap>,
    ) {
        let mut parts = Response::builder()
            .status(200)
            .body(())
            .expect("parts")
            .into_parts()
            .0;
        let ops = ResBodyOps {
            speed,
            trailers: headers(rule_trailers),
            no_trailers,
            announce_trailers: true,
            content: true,
            ..ResBodyOps::default()
        };
        let bytes = Bytes::from(vec![b'x'; body_len]);
        let out = finish_res_body(&mut parts, bytes, ops, origin.map(headers));
        let (frames, trailers) = drain(out);
        (parts, frames, trailers)
    }

    fn names(h: &Option<hyper::HeaderMap>) -> Vec<String> {
        let mut v: Vec<String> = h
            .iter()
            .flat_map(|h| h.iter())
            .map(|(k, val)| format!("{k}={}", val.to_str().unwrap()))
            .collect();
        v.sort();
        v
    }

    /// The origin's own trailer section survives a body rewrite, and the rule's
    /// trailers are laid over it (`extend(trailers, newTrailers)`,
    /// `_original/lib/inspectors/res.js:1264-1273`).
    ///
    /// Buffering the body threw the origin's trailers away, so *any* body
    /// operator — one with nothing to do with trailers — silently deleted them
    /// on the way past.
    #[test]
    fn the_origins_trailers_survive_a_rewrite() {
        let (parts, _, trailers) = finish(
            &[("x-rule", "1")],
            Some(&[("x-origin", "2"), ("x-both", "origin")]),
            false,
            None,
            8,
        );
        assert_eq!(
            names(&trailers),
            ["x-both=origin", "x-origin=2", "x-rule=1"]
        );
        // The `Trailer:` header announces everything that is coming.
        let announced = parts.headers.get("trailer").unwrap().to_str().unwrap();
        for name in ["x-origin", "x-both", "x-rule"] {
            assert!(announced.contains(name), "{announced} must name {name}");
        }

        // A contested name takes the rule's value.
        let (_, _, trailers) = finish(
            &[("x-both", "rule")],
            Some(&[("x-both", "origin")]),
            false,
            None,
            8,
        );
        assert_eq!(names(&trailers), ["x-both=rule"]);

        // With no rule at all the origin's still go out.
        let (_, _, trailers) = finish(&[], Some(&[("x-origin", "2")]), false, None, 8);
        assert_eq!(names(&trailers), ["x-origin=2"]);
    }

    /// `disable://trailers` cancels the whole section, the origin's included —
    /// upstream's guard is on the way out, after the merge (`res.js:1252-1260`).
    #[test]
    fn disabling_trailers_drops_the_origins_too() {
        let (parts, frames, trailers) = finish(&[], Some(&[("x-origin", "2")]), true, None, 8);
        assert!(trailers.is_none(), "no trailer section may be sent");
        assert!(parts.headers.get("trailer").is_none());
        assert_eq!(frames.len(), 1, "the body itself is untouched");
    }

    /// A name an HTTP trailer section may not carry is dropped wherever it came
    /// from (`removeIllegalTrailers`, `_original/lib/util/common.js:410-414`,
    /// applied at `res.js:1285` over the merged map).
    ///
    /// A `Content-Length` arriving *after* the body contradicts the framing that
    /// just delivered it, and a `Set-Cookie` there is a credential a client is
    /// not required to read.
    #[test]
    fn illegal_trailer_names_are_dropped_from_both_sides() {
        let (parts, _, trailers) = finish(
            &[("content-length", "5"), ("x-ok", "1")],
            Some(&[("set-cookie", "sid=1"), ("x-fine", "2")]),
            false,
            None,
            8,
        );
        assert_eq!(names(&trailers), ["x-fine=2", "x-ok=1"]);
        let announced = parts.headers.get("trailer").unwrap().to_str().unwrap();
        assert!(!announced.contains("content-length"));
        assert!(!announced.contains("set-cookie"));

        // Nothing legal left means no trailer section and no announcement.
        let (parts, _, trailers) = finish(&[("trailer", "x")], None, false, None, 8);
        assert!(trailers.is_none());
        assert!(parts.headers.get("trailer").is_none());
    }

    /// `resSpeed://` and `trailers://` are not alternatives.
    ///
    /// The port chose between them, so writing both meant the throttle was
    /// silently dropped — a rule that reproduces a slow connection, cancelled by
    /// an unrelated one on the same line.
    #[test]
    fn a_throttle_survives_the_trailers() {
        // 8 kbit/s is 1000 bytes/s, paced in 50 ms slices of 50 bytes: 100 bytes
        // is two frames rather than the single frame an unpaced body sends.
        let (_, frames, trailers) = finish(&[("x-a", "1")], None, false, Some(8.0), 100);
        assert_eq!(frames.len(), 2, "the body was paced");
        assert_eq!(frames.concat().len(), 100);
        assert_eq!(names(&trailers), ["x-a=1"]);

        // Unpaced, the same body is one frame — so the assertion above is about
        // the throttle and not about chunking in general.
        let (_, frames, _) = finish(&[("x-a", "1")], None, false, None, 100);
        assert_eq!(frames.len(), 1);
    }

    /// `disable://trailerHeader` withholds the announcement, not the trailers
    /// (`_original/lib/inspectors/res.js:1215-1223`).
    #[test]
    fn disabling_the_trailer_header_still_sends_the_trailers() {
        let mut parts = Response::builder()
            .status(200)
            .body(())
            .expect("parts")
            .into_parts()
            .0;
        let ops = ResBodyOps {
            trailers: headers(&[("x-a", "1")]),
            announce_trailers: false,
            content: true,
            ..ResBodyOps::default()
        };
        let (_, trailers) = drain(finish_res_body(
            &mut parts,
            Bytes::from_static(b"x"),
            ops,
            None,
        ));
        assert_eq!(names(&trailers), ["x-a=1"]);
        assert!(parts.headers.get("trailer").is_none());
    }
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

            let out = pipe_body(
                &state,
                &[],
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                source,
            )
            .await;

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
            assert_eq!(
                collect_body(out).await.expect("body"),
                Bytes::from_static(b"as-is")
            );
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
            assert_eq!(
                collect_body(out).await.expect("body"),
                Bytes::from_static(b"SHOUT")
            );
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
            tls_ciphers: None,
            no_proxy_ua: false,
            proxy_connection_close: false,
            connect_host: "example.com".into(),
            connect_port: 80,
            tls,
            origin_tls_stripped: stripped,
            sni: "example.com".into(),
            request_port: 443,
            proxy: None,
            tls_versions: upstream::TlsVersions::Default,
            host_fallback_direct: false,
            auto2http: false,
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
        assert_eq!(
            mgr.resolve_scoped(&info, false).value("host"),
            Some("1.1.1.1")
        );
        assert_eq!(
            mgr.resolve_scoped(&info, true).value("host"),
            Some("2.2.2.2")
        );
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

        fn on_response(&self, res: &crate::plugins::PluginRes) -> crate::plugins::PluginResResult {
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
            parts
                .headers
                .get("x-stamped-by")
                .map(|v| v.to_str().unwrap()),
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

    /// The rules-carrying headers never reach the origin.
    ///
    /// whistle deletes them whether or not it is configured to read them
    /// (`getValue`, `_original/lib/rules/index.js:558-572`), and this port had
    /// been forwarding them — so a client could hand the origin a rules text,
    /// and an upstream whistle would have obeyed it. `x-whistle-rule-name` is
    /// the one that travels on, because upstream only ever looks at it in
    /// `multiEnv` mode and therefore never deletes it. Measured on both.
    #[test]
    fn the_rules_headers_are_consumed() {
        let mut h = hyper::HeaderMap::new();
        for name in HEADER_RULE_HEADERS {
            h.insert(
                hyper::header::HeaderName::from_static(name),
                "a.com file://(x)".parse().unwrap(),
            );
        }
        for name in CONNECTION_MARKER_HEADERS {
            h.insert(
                hyper::header::HeaderName::from_static(name),
                "1234".parse().unwrap(),
            );
        }
        h.insert("x-whistle-rule-name", "n".parse().unwrap());
        h.insert("x-other", "kept".parse().unwrap());
        // The default configuration, which is what a proxy run with no `-M`
        // has: the four are taken, and nothing is read.
        take_header_rules(&mut h, &crate::config::Config::default());
        for name in HEADER_RULE_HEADERS.iter().chain(&CONNECTION_MARKER_HEADERS) {
            assert!(h.get(*name).is_none(), "{name} must not survive");
        }
        assert_eq!(h.get("x-whistle-rule-name").unwrap(), "n");
        assert_eq!(h.get("x-other").unwrap(), "kept");
    }

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
        assert_eq!(
            of(&mitm(true, true)),
            crate::rules::ReqOrigin {
                tunnel: true,
                sni: true,
                composer: false,
            }
        );
        assert_eq!(
            of(&mitm(false, false)),
            crate::rules::ReqOrigin {
                tunnel: true,
                sni: false,
                composer: false,
            }
        );
        assert_eq!(of(&Origin::Forward), crate::rules::ReqOrigin::default());
    }
}
