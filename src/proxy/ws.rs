//! Minimal WebSocket frame codec + a frame-aware capturing tunnel.
//!
//! Every intercepted WebSocket upgrade is tunnelled frame-by-frame so each
//! frame can be captured for the Network view (whistle surfaces every frame).
//! Two hooks may also sit in that path, and they run in this order:
//!
//! 1. **`frameScript`** — the rule operator, on whole text and binary frames.
//!    It is a rule, and rules run before plugins everywhere else in this proxy.
//!    One script per connection, evaluated once: see
//!    [`crate::proxy::script::FrameScript`].
//! 2. **A plugin's frame hook** ([`crate::plugins::wsframe`]) — every data
//!    frame, both directions, may rewrite or drop it. Several plugins chain in
//!    rule order, each seeing the previous one's output.
//!
//! So a plugin sees what the script produced, and what a plugin finally returns
//! is both what goes on the wire and what the capture records. A frame nobody
//! hooks is read, captured and re-encoded exactly as before: the hook path is
//! guarded by an `is_empty()` on a vector that is empty for every session with
//! no frame-hook plugin, which is very nearly all of them.
//!
//! Control frames (close, ping, pong) are **never** offered to a plugin. They
//! are protocol machinery rather than application data: a hook that dropped a
//! ping would break keepalive and one that rewrote a close would break the
//! closing handshake, and no legitimate hook needs either. They are still
//! captured.
//!
//! One direction of a session can also be **held** — see [`DirMode::Pause`] and
//! [`SessionPause`]. That is the one place where a control frame is *not*
//! exempt, because upstream pauses the byte stream rather than the frames in it.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use crate::plugins::wsframe::{Dir, FrameHook, FrameMeta, HookFrame, Verdict};
use crate::plugins::{PluginMatch, Plugins};
use crate::proxy::script::{FrameScript, FrameScriptSpec, FrameScriptStart, ScriptFrame};
use crate::proxy::{AppState, WsFrame};
use crate::rules::{ReqInfo, Resolved};

/// Continuation of a fragmented message.
const OPCODE_CONTINUATION: u8 = 0x0;
/// A text message (UTF-8).
const OPCODE_TEXT: u8 = 0x1;
/// A binary message.
const OPCODE_BINARY: u8 = 0x2;
/// The closing handshake.
const OPCODE_CLOSE: u8 = 0x8;
/// A keep-alive probe.
const OPCODE_PING: u8 = 0x9;
/// The answer to one, or an unsolicited heartbeat.
const OPCODE_PONG: u8 = 0xa;

/// `Sec-WebSocket-Accept` for a client's key (RFC 6455 §4.2.2): SHA-1 of the key
/// and the protocol's fixed GUID, base64.
pub fn accept_key(key: &str) -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

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

/// The frame hooks a WebSocket session *may* run: the plugins its rules named,
/// resolved but not yet contacted.
///
/// Building one is pure and allocation-free when no rule named a registered
/// plugin — the normal case, and the reason a plain WebSocket costs nothing.
/// The plugins are dialled later, from inside the tunnel, so a plugin's
/// handshake never delays the client's.
#[derive(Default, Clone)]
pub struct FramePlan {
    /// Candidate plugins, in rule order, at most one entry per plugin.
    matches: Vec<PluginMatch>,
    method: String,
    url: String,
    client_ip: Option<String>,
    headers: Vec<(String, String)>,
}

impl FramePlan {
    /// Resolve which plugins may hook this session's frames.
    ///
    /// Both `plugin://` and `pipe://` reach the frame hook. Unlike an HTTP body,
    /// a WebSocket offers no buffered-versus-streaming choice for the scheme to
    /// select between, so making one scheme work and the other silently not
    /// would be a trap rather than a distinction. A plugin named by both schemes
    /// still hooks once.
    pub fn new(plugins: &Plugins, resolved: &Resolved, info: &ReqInfo) -> Self {
        let mut matches: Vec<PluginMatch> = Vec::new();
        for m in crate::plugins::matched(resolved) {
            if plugins.reachable(&m.name) && !matches.iter().any(|o| o.name == m.name) {
                matches.push(m);
            }
        }
        if matches.is_empty() {
            return FramePlan::default();
        }
        FramePlan {
            matches,
            method: info.method.clone(),
            url: info.full_url.clone(),
            client_ip: info.client_ip.clone(),
            headers: info.headers.clone(),
        }
    }

    /// Whether any plugin might hook this session.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Open every hook for both directions, concurrently. An empty plan does
    /// nothing whatsoever — no manifest lookup, no connection, no allocation.
    async fn connect(&self, plugins: &Plugins, session: u64) -> (Vec<FrameHook>, Vec<FrameHook>) {
        if self.is_empty() {
            return (Vec::new(), Vec::new());
        }
        tokio::join!(
            self.connect_dir(plugins, Dir::Send, session),
            self.connect_dir(plugins, Dir::Receive, session)
        )
    }

    /// Open the hooks watching one direction, in rule order.
    async fn connect_dir(&self, plugins: &Plugins, dir: Dir, session: u64) -> Vec<FrameHook> {
        let mut hooks = Vec::new();
        for m in &self.matches {
            let meta = FrameMeta {
                id: session,
                method: self.method.clone(),
                url: self.url.clone(),
                param: m.param.clone(),
                pipe_value: m.pipe_value.clone(),
                client_ip: self.client_ip.clone(),
                headers: self.headers.clone(),
                dir,
            };
            if let Some(hook) = plugins.ws_frame_hook(&m.name, &meta).await {
                tracing::debug!(
                    "wsFrame {} hooks session {session} ({})",
                    m.name,
                    dir.label()
                );
                hooks.push(hook);
            }
        }
        hooks
    }
}

/// Frame-aware bidirectional tunnel: captures every frame into `state` under
/// `session`, offers each data frame to `script`, and then to the plugins in
/// `plan`.
pub async fn capturing_tunnel<A, B>(
    client: A,
    upstream: B,
    script: Option<FrameScriptSpec>,
    plan: FramePlan,
    flow: FrameFlow,
    state: Arc<AppState>,
    session: u64,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The `101` has already reached the client by the time we get here, so
    // dialling the plugins now overlaps with the client composing its first
    // frame instead of delaying the handshake.
    let (send_hooks, receive_hooks) = plan.connect(&state.plugins, session).await;
    // A session a rule paused is announced to the console, which is the only
    // thing that can let it go again. Nothing else is registered: a pause is
    // rare, and the registry is meant to answer "which connections is somebody
    // holding", not "which connections exist".
    let pause = flow.holds().then(|| {
        let gate = Arc::new(SessionPause::new(flow));
        state.ws_pause.lock().unwrap().insert(session, gate.clone());
        gate
    });
    // The script is evaluated here, once, for the life of the connection — as
    // upstream evaluates it (`getFrameCtx`). What it sends while it is being
    // evaluated — `ctx.sendToServer` / `ctx.sendToClient` at the top of the
    // file, which is how `frameScript.md`'s example opens — goes out before
    // either side has said anything.
    let started = match script {
        Some(spec) => FrameScript::start(spec).await,
        None => FrameScriptStart::default(),
    };
    let script = started.script;
    let (inject_send, inject_receive): (Vec<ScriptFrame>, Vec<ScriptFrame>) =
        started.sent.into_iter().partition(|frame| frame.to_server);
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    // The two writers, shared with the console so it can send a frame into a
    // live connection — the Frames panel's own Composer (`gui/network.md`).
    // A `Mutex` rather than a channel: a frame is written whole while the lock
    // is held, so an injected one can never interleave with a relayed one, and
    // the ordinary path pays one uncontended lock per frame.
    let writers = Arc::new(SessionWriters::new(uw, cw));
    state
        .ws_write
        .lock()
        .unwrap()
        .insert(session, writers.clone());
    let (uw, cw) = (writers.to_server(), writers.to_client());
    let up = tokio::spawn(pump(
        cr,
        uw,
        Leg {
            dir: Dir::Send,
            script: script.clone(),
            hooks: send_hooks,
            mode: flow.send,
            pause: pause.clone(),
            // This leg writes toward the server, so its keep-alive is the pong.
            keepalive: !flow.no_pong,
            inject: inject_send,
            writers: writers.clone(),
        },
        state.clone(),
        session,
    ));
    let down = tokio::spawn(pump(
        ur,
        cw,
        Leg {
            dir: Dir::Receive,
            script,
            hooks: receive_hooks,
            mode: flow.receive,
            pause: pause.clone(),
            // …and this one writes toward the client, so it is the ping.
            keepalive: !flow.no_ping,
            inject: inject_receive,
            writers: writers.clone(),
        },
        state.clone(),
        session,
    ));
    let _ = tokio::join!(up, down);
    if pause.is_some() {
        state.ws_pause.lock().unwrap().remove(&session);
    }
    // The connection is over; nothing may be written into it any more.
    state.ws_write.lock().unwrap().remove(&session);
}

/// The two write halves of a live WebSocket session, shared with the console.
///
/// whistle's Frames panel can send a frame to either end of a connection that
/// is still open (`gui/network.md`), which is the one thing a capture cannot
/// answer on its own: what the other side *does* with a message. The writers
/// live here for as long as the tunnel does.
///
/// Each half is behind its own mutex, and a frame is written whole while it is
/// held — so an injected frame can never land inside a relayed one, and the
/// ordinary path pays one uncontended lock per frame.
pub struct SessionWriters {
    to_server: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
    to_client: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
}

impl SessionWriters {
    fn new<S, C>(to_server: S, to_client: C) -> Self
    where
        S: AsyncWrite + Unpin + Send + 'static,
        C: AsyncWrite + Unpin + Send + 'static,
    {
        SessionWriters {
            to_server: Arc::new(tokio::sync::Mutex::new(Box::new(to_server))),
            to_client: Arc::new(tokio::sync::Mutex::new(Box::new(to_client))),
        }
    }

    fn to_server(&self) -> SharedWriter {
        SharedWriter {
            inner: self.to_server.clone(),
        }
    }

    fn to_client(&self) -> SharedWriter {
        SharedWriter {
            inner: self.to_client.clone(),
        }
    }

    /// Write one text frame into the live connection, from the console.
    ///
    /// `dir` is the capture's own spelling: `"send"` puts the frame on its way
    /// to the **server** (as if the client had sent it) and `"receive"` on its
    /// way to the client. The frame is masked exactly as a real one from that
    /// side would be, so neither end can tell it apart from traffic.
    pub async fn send(&self, dir: &str, data: &[u8]) -> bool {
        let to_server = match dir {
            "send" => true,
            "receive" => false,
            _ => return false,
        };
        self.send_frame(to_server, OPCODE_TEXT, data).await
    }

    /// Write one whole frame toward either end, holding that end's lock for
    /// all of it. How a `frameScript` handler on one leg sends a frame the
    /// other leg's writer has to carry.
    async fn send_frame(&self, to_server: bool, opcode: u8, data: &[u8]) -> bool {
        let half = if to_server {
            &self.to_server
        } else {
            &self.to_client
        };
        let mut w = half.lock().await;
        write_frame(&mut *w, true, opcode, data, to_server)
            .await
            .is_ok()
    }
}

/// One half of a [`SessionWriters`], as the leg that owns it sees it: an
/// ordinary `AsyncWrite` that happens to be shared.
struct SharedWriter {
    inner: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
}

impl AsyncWrite for SharedWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut guard = match Box::pin(this.inner.lock()).as_mut().poll(cx) {
            std::task::Poll::Ready(g) => g,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };
        std::pin::Pin::new(&mut **guard).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut guard = match Box::pin(this.inner.lock()).as_mut().poll(cx) {
            std::task::Poll::Ready(g) => g,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };
        std::pin::Pin::new(&mut **guard).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut guard = match Box::pin(this.inner.lock()).as_mut().poll(cx) {
            std::task::Poll::Ready(g) => g,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };
        std::pin::Pin::new(&mut **guard).poll_shutdown(cx)
    }
}

/// What `enable://` asked to happen to one direction of a session.
///
/// One value rather than a flag each, because that is what upstream keeps: a
/// single `sendStatus`/`receiveStatus` per direction, `0` normal,
/// `PAUSE_STATUS = 1`, `IGNORE_STATUS = 2` (`_original/lib/socket-mgr.js:13-14`).
/// Modelling it as two booleans would admit a state upstream cannot reach —
/// ignoring and pausing the same direction at once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DirMode {
    /// Deliver every frame, as an unruled session does.
    #[default]
    Pass,
    /// `enable://pauseSend|pauseReceive` — hold the frames, in order, until the
    /// console releases them. Unlike [`DirMode::Ignore`] this holds *control*
    /// frames too: upstream pauses the byte stream, not the frames in it, so a
    /// `close` or `ping` inside a held chunk is held with it
    /// (`handleFrame`, `_original/lib/socket-mgr.js:232-247`). What keeps the
    /// peers from timing out meanwhile is [`KEEPALIVE`], as it does upstream.
    Pause,
    /// `enable://ignoreSend|ignoreReceive` — capture the data frames but never
    /// deliver them.
    Ignore,
}

/// What `enable://` asked for each direction of a session.
///
/// Kept apart from [`FramePlan`] deliberately: the plan collapses to
/// [`FramePlan::default`] when no plugin is named, and folding the flags into it
/// would lose them on exactly the sessions that have no plugin — which is most
/// of the sessions anyone writes these rules for.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameFlow {
    /// Frames travelling client → server.
    pub send: DirMode,
    /// Frames travelling server → client.
    pub receive: DirMode,
    /// `disable://ping` — no keep-alive toward the **client** while the receive
    /// direction is held.
    pub no_ping: bool,
    /// `disable://pong` — no keep-alive toward the **server** while the send
    /// direction is held.
    pub no_pong: bool,
}

impl FrameFlow {
    /// Read both directions off a resolved rule set.
    pub fn of(resolved: &Resolved) -> Self {
        let (pause_send, pause_receive) = crate::proxy::apply::paused_ws_dirs(resolved);
        let (ignore_send, ignore_receive) = crate::proxy::apply::ignored_ws_dirs(resolved);
        let (no_ping, no_pong) = crate::proxy::apply::ws_keepalive_disabled(resolved);
        FrameFlow {
            send: DirMode::of(pause_send, ignore_send),
            receive: DirMode::of(pause_receive, ignore_receive),
            no_ping,
            no_pong,
        }
    }

    /// Whether either direction starts held, and so needs a console control.
    fn holds(&self) -> bool {
        self.send == DirMode::Pause || self.receive == DirMode::Pause
    }
}

impl DirMode {
    /// Pause outranks ignore, as upstream's `else if` chain does
    /// (`initStatus`, `_original/lib/socket-mgr.js:86-97`). `ignored_ws_dirs`
    /// already applies that precedence; this is where it becomes unrepresentable.
    fn of(pause: bool, ignore: bool) -> Self {
        match (pause, ignore) {
            (true, _) => DirMode::Pause,
            (false, true) => DirMode::Ignore,
            (false, false) => DirMode::Pass,
        }
    }
}

/// How often a paused direction sends the peer a keep-alive of the proxy's own.
///
/// A pause stops a direction's control frames along with its data, so a peer
/// that has an idle timeout — most of them do — would close a connection that
/// is merely being held. Upstream answers that by writing its own: an empty
/// `pong` to the server on the client's leg and an empty `ping` to the client on
/// the server's, every 22 seconds (`INTERVAL`, `PING`/`PONG`,
/// `reqReceiver.ping`/`resReceiver.ping`,
/// `_original/lib/socket-mgr.js:8,:11-12,:366-375,:496-505`).
///
/// Upstream also runs this timer while a direction is *ignoring*. This port does
/// not: its ignore path forwards control frames untouched, so the endpoints'
/// own keep-alive is still crossing and there is nothing to stand in for.
const KEEPALIVE: Duration = Duration::from_secs(22);

/// How much one paused direction will hold before it stops reading.
///
/// Upstream needs no such number. It holds the transform callback of the chunk
/// it is on and stops reading the socket entirely (`handleFrame`,
/// `_original/lib/socket-mgr.js:232-247`), so the kernel's receive buffer is the
/// bound and at most one chunk is ever in whistle's own memory — at the price of
/// the console being able to show nothing of what is waiting. This port reads
/// ahead so it can capture and show each held frame, and read-ahead has to be
/// bounded explicitly. On reaching either cap the leg stops taking frames from
/// its reader, which stops reading, which back-pressures the peer exactly as
/// upstream's paused socket does.
///
/// Two caps rather than one because either alone leaves a hole: a count would
/// let 64 frames of 8 MiB through, and a byte budget alone would let four
/// million one-byte frames through.
///
/// A leg that has stopped reading cannot see its peer leave — there is no way to
/// watch a socket for an EOF you are not reading. Below the caps it still can,
/// because it is still reading; at them, what notices is [`KEEPALIVE`] failing
/// against the peer on the other side. A hold nobody ever lifts therefore costs
/// one task and at most these many bytes, which is the same open-ended cost
/// upstream's unread socket has.
const MAX_HELD_FRAMES: usize = 64;
/// The byte half of [`MAX_HELD_FRAMES`].
const MAX_HELD_BYTES: usize = 4 * 1024 * 1024;

/// The pause state of one live WebSocket session: what the console reads, and
/// what it releases.
///
/// Present in [`AppState::ws_pause`](crate::proxy::AppState::ws_pause) for
/// exactly as long as the tunnel runs. A release for a session that has since
/// closed finds nothing, which is the honest answer — its held frames stay
/// flagged in the capture, having never been delivered.
#[derive(Default)]
pub struct SessionPause {
    /// Frames travelling client → server.
    pub send: DirPause,
    /// Frames travelling server → client.
    pub receive: DirPause,
}

impl SessionPause {
    fn new(flow: FrameFlow) -> Self {
        let gate = SessionPause::default();
        gate.send
            .paused
            .store(flow.send == DirMode::Pause, Ordering::Relaxed);
        gate.receive
            .paused
            .store(flow.receive == DirMode::Pause, Ordering::Relaxed);
        gate
    }

    /// One direction by the name the capture and the API use for it.
    pub fn dir(&self, name: &str) -> Option<&DirPause> {
        match name {
            "send" => Some(&self.send),
            "receive" => Some(&self.receive),
            _ => None,
        }
    }

    /// The direction a leg is pumping.
    fn of(&self, dir: Dir) -> &DirPause {
        match dir {
            Dir::Send => &self.send,
            Dir::Receive => &self.receive,
        }
    }
}

/// One direction's half of a [`SessionPause`].
#[derive(Default)]
pub struct DirPause {
    paused: AtomicBool,
    held: AtomicUsize,
    release: Notify,
}

impl DirPause {
    /// Whether this direction is currently holding its frames back.
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// How many frames are waiting to go out.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// Let this direction go, and say how many frames that frees.
    ///
    /// Releasing ends the pause outright rather than letting one frame through,
    /// because that is the only granularity upstream has: its console sets the
    /// direction's status back to `0` and everything held goes out at once
    /// (`setConnStatus`, `_original/lib/socket-mgr.js:63-84`). A direction that
    /// was not paused is untouched, so a second click is harmless.
    pub fn release(&self) -> usize {
        let held = self.held();
        self.paused.store(false, Ordering::Release);
        // `notify_one` and not `notify_waiters`: the leg may be between waits,
        // and only the permit-storing form survives that.
        self.release.notify_one();
        held
    }

    /// Wait for [`DirPause::release`]. Cancel-safe, so it can be a `select!` arm.
    async fn released(&self) {
        self.release.notified().await;
    }
}

/// How one direction of a session is to be treated: which way it flows, what may
/// rewrite its frames, and whether they are delivered at all.
///
/// The two directions differ only in these things, so they travel together
/// rather than as positional arguments that could be crossed over.
struct Leg {
    dir: Dir,
    /// `frameScript://`, running — shared by both legs.
    script: Option<FrameScript>,
    /// The plugin hooks watching this direction, in rule order.
    hooks: Vec<FrameHook>,
    /// What `enable://` asked for this direction.
    mode: DirMode,
    /// The console-visible pause state, when a rule paused either direction.
    pause: Option<Arc<SessionPause>>,
    /// False when `disable://ping` / `disable://pong` asked for no keep-alive on
    /// this leg — see [`crate::proxy::apply::ws_keepalive_disabled`].
    keepalive: bool,
    /// Frames the `frameScript` asked to send on this leg the moment the
    /// connection opened, before anything was read.
    inject: Vec<ScriptFrame>,
    /// Both write halves, for a frame a handler sends the other way.
    writers: Arc<SessionWriters>,
}

async fn pump<R, W>(r: R, w: W, leg: Leg, state: Arc<AppState>, session: u64)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let Leg {
        dir,
        script,
        hooks,
        mode,
        pause,
        keepalive,
        inject,
        writers,
    } = leg;
    let ctx = FrameCtx {
        direction: dir.label(),
        to_server: dir == Dir::Send,
        script,
        hooks,
        mode,
        state,
        session,
        writers,
    };
    match (mode, pause) {
        (DirMode::Pause, Some(gate)) => pump_held(r, w, ctx, gate, dir, keepalive, inject).await,
        // Everything else, which is very nearly every session: read, decide,
        // write, with no companion task and no channel between the two.
        _ => pump_direct(r, w, ctx, inject).await,
    }
}

/// Write the frames a `frameScript` sent on this leg while it was starting,
/// and record them.
///
/// They have already been through the script's own handler for this direction
/// — upstream passes a frame the script sends through `execHandleFrame` like
/// any other, marked `opts.frameScript` (`_original/lib/socket-mgr.js:347-362`).
async fn write_injections<W: AsyncWrite + Unpin>(
    w: &mut W,
    ctx: &FrameCtx,
    inject: &[ScriptFrame],
) {
    for frame in inject {
        let opcode = opcode_of(frame);
        if deliver(w, true, opcode, &frame.data, ctx.to_server).await != Sent::Ok {
            return;
        }
        ctx.state.record_frame(WsFrame::new(
            ctx.session,
            ctx.direction,
            opcode,
            &frame.data,
        ));
    }
}

/// The opcode a script's frame goes out under.
fn opcode_of(frame: &ScriptFrame) -> u8 {
    match frame.binary {
        true => OPCODE_BINARY,
        false => OPCODE_TEXT,
    }
}

/// Everything one leg needs to turn a frame it has read into the frame it
/// delivers, and to record it on the way past.
struct FrameCtx {
    /// `"send"` or `"receive"` — the capture's own spelling of the direction.
    direction: &'static str,
    to_server: bool,
    script: Option<FrameScript>,
    hooks: Vec<FrameHook>,
    mode: DirMode,
    state: Arc<AppState>,
    session: u64,
    writers: Arc<SessionWriters>,
}

impl FrameCtx {
    /// Run the script and the hooks over one frame and record it, returning the
    /// opcode and payload to deliver — or `None` when it is not to be delivered
    /// at all: the script or a hook dropped it, or `enable://ignore…` discarded
    /// it.
    ///
    /// `held` marks the capture as waiting for a release rather than delivered.
    async fn process(&mut self, frame: Frame, held: bool) -> Option<(u8, Bytes)> {
        let mut payload = Bytes::from(frame.payload);
        let mut opcode = frame.opcode;
        // A whole text or binary message: the script may rewrite it, retype it,
        // or refuse it, and may send frames of its own while it decides. A
        // handler that answers with nothing drops the frame, which is what
        // upstream's `cb(null, chunk || null)` does with a falsy return
        // (`_original/lib/socket-mgr.js:198-206`).
        //
        // A *fragment* is not offered. Upstream reassembles a fragmented
        // message before its handler sees it; this port relays frame by frame,
        // and a handler that rewrote one fragment of a message would be
        // rewriting something its author never saw whole.
        if let Some(script) = &self.script
            && frame.fin
            && matches!(opcode, OPCODE_TEXT | OPCODE_BINARY)
            && script.handles(self.to_server)
        {
            let outcome = script
                .relay(ScriptFrame {
                    to_server: self.to_server,
                    data: payload.to_vec(),
                    binary: opcode == OPCODE_BINARY,
                })
                .await;
            // What the handler sent goes first, whichever way it is going —
            // upstream's `sendToClient` writes before the handler has returned.
            for sent in &outcome.sent {
                let code = opcode_of(sent);
                if self
                    .writers
                    .send_frame(sent.to_server, code, &sent.data)
                    .await
                {
                    let direction = if sent.to_server { "send" } else { "receive" };
                    self.state.record_frame(WsFrame::new(
                        self.session,
                        direction,
                        code,
                        &sent.data,
                    ));
                }
            }
            let kept = outcome.frame?;
            opcode = opcode_of(&kept);
            payload = Bytes::from(kept.data);
        }
        if !self.hooks.is_empty() && is_data_frame(opcode) {
            match run_hooks(&mut self.hooks, self.direction, frame.fin, opcode, payload).await {
                Some(kept) => payload = kept,
                // Dropped: it reaches neither the peer nor the capture, because
                // it never happened as far as the other end is concerned.
                None => return None,
            }
        }
        // Capture the (possibly rewritten) frame for the Network view. An
        // ignored frame is recorded too, flagged — upstream does the same
        // (`ignore`, `_original/lib/socket-mgr.js:401,:531`), so the view shows
        // that a frame was dropped instead of just not showing it. A held frame
        // is flagged the same way for the same reason: what is waiting is worth
        // more than a count of it.
        let mut record = WsFrame::new(self.session, self.direction, opcode, &payload);
        record.held = held;

        // `enable://ignoreSend|ignoreReceive` discards this direction's data
        // frames. Control frames are exempt: dropping a `close` would leave the
        // tunnel open with both ends believing otherwise, and dropping a
        // `ping`/`pong` breaks the keep-alive the endpoints agreed on —
        // upstream's ignore path likewise only ever withholds data
        // (`opts.data`, `_original/lib/socket-mgr.js:249-274`).
        if self.mode == DirMode::Ignore && is_data_frame(opcode) {
            record.ignored = true;
            self.state.record_frame(record);
            return None;
        }
        self.state.record_frame(record);
        Some((opcode, payload))
    }
}

/// What became of one frame on its way to the peer.
#[derive(PartialEq, Eq)]
enum Sent {
    /// Written; the leg carries on.
    Ok,
    /// Written, and it was the close that ends the conversation.
    Closed,
    /// The peer is gone.
    Failed,
}

/// Encode one frame onto the wire.
async fn deliver<W: AsyncWrite + Unpin>(
    w: &mut W,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    to_server: bool,
) -> Sent {
    if write_frame(w, fin, opcode, payload, to_server)
        .await
        .is_err()
    {
        return Sent::Failed;
    }
    if opcode == OPCODE_CLOSE {
        return Sent::Closed;
    }
    Sent::Ok
}

/// The ordinary leg: read a frame, decide about it, write it.
async fn pump_direct<R, W>(mut r: R, mut w: W, mut ctx: FrameCtx, inject: Vec<ScriptFrame>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_injections(&mut w, &ctx, &inject).await;
    loop {
        let frame = match read_frame(&mut r).await {
            Ok(Some(f)) => f,
            _ => break,
        };
        let fin = frame.fin;
        let Some((opcode, payload)) = ctx.process(frame, false).await else {
            continue;
        };
        if deliver(&mut w, fin, opcode, &payload, ctx.to_server).await != Sent::Ok {
            break;
        }
    }
}

/// A frame this leg has read, captured and is holding.
type HeldFrame = (bool, u8, Bytes);

/// The leg of a direction `enable://pauseSend|pauseReceive` held.
///
/// The read moves to a companion task so this one can wait on the peer and on
/// the console's release at the same time. It has to: [`read_frame`] takes a
/// frame in several reads, so cancelling it as a losing `select!` arm would
/// discard the bytes it had already taken — and a release with nothing arriving
/// behind it is precisely the case that has to work.
async fn pump_held<R, W>(
    r: R,
    mut w: W,
    mut ctx: FrameCtx,
    pause: Arc<SessionPause>,
    dir: Dir,
    keepalive: bool,
    inject: Vec<ScriptFrame>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // The script's own frames go out before the hold begins: they are not the
    // peer's traffic, and holding them would hold something nobody sent.
    write_injections(&mut w, &ctx, &inject).await;
    let gate = pause.of(dir);
    let (tx, mut rx) = mpsc::channel::<Frame>(1);
    let reader = tokio::spawn(async move {
        let mut r = r;
        while let Ok(Some(frame)) = read_frame(&mut r).await {
            if tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    let mut held: Vec<HeldFrame> = Vec::new();
    let mut held_bytes = 0usize;
    // The probe runs on a fixed period from the moment the hold starts, not from
    // the last thing that happened on this leg. A frame arriving on a held
    // direction is exactly what the peer being written to *cannot* see, so
    // letting one postpone the probe would defeat it. Its first tick is
    // immediate and is taken here, which is where the period begins.
    let mut probe = tokio::time::interval(KEEPALIVE);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    probe.tick().await;

    'leg: loop {
        // The queue empties before anything behind it goes out, wherever the
        // release happened to land — a pause that reordered the conversation it
        // was asked to hold would be worse than no pause at all.
        if !gate.paused()
            && !held.is_empty()
            && !flush(&mut w, &mut held, &mut held_bytes, &ctx, gate).await
        {
            break;
        }
        let frame = loop {
            if !gate.paused() {
                match rx.recv().await {
                    Some(frame) => break frame,
                    None => break 'leg,
                }
            }
            let room = held.len() < MAX_HELD_FRAMES && held_bytes < MAX_HELD_BYTES;
            tokio::select! {
                // A release outranks a frame that arrived with it: the queue
                // goes first either way, and taking it first says so plainly.
                biased;
                () = gate.released() => continue 'leg,
                // Full: stop taking frames, so the reader stops reading and the
                // peer is back-pressured. See `MAX_HELD_FRAMES`.
                frame = rx.recv(), if room => match frame {
                    Some(frame) => break frame,
                    None => break 'leg,
                },
                // `disable://ping` / `disable://pong` suppress the probe
                // rather than the tick: the timer is cheap and the flag is
                // about what goes on the wire.
                _ = probe.tick(), if keepalive => {
                    if !send_keepalive(&mut w, ctx.to_server).await {
                        break 'leg;
                    }
                }
            }
        };
        let fin = frame.fin;
        let holding = gate.paused();
        let Some((opcode, payload)) = ctx.process(frame, holding).await else {
            continue;
        };
        if holding {
            held_bytes += payload.len();
            held.push((fin, opcode, payload));
            gate.held.store(held.len(), Ordering::Release);
            continue;
        }
        if deliver(&mut w, fin, opcode, &payload, ctx.to_server).await != Sent::Ok {
            break;
        }
    }
    // This leg is over however it ended, and the reader may still be parked on a
    // peer that is never going to speak again. Nothing is left to read what it
    // would produce, so let it go and let it drop its half of the socket with it.
    reader.abort();
}

/// Let a released direction's queue go, oldest first. `false` when the leg is
/// over — the peer went away, or the queue held the close that ends it.
///
/// The captures are unmarked here rather than by the endpoint that lifted the
/// pause because this task is the only writer of that mark, so there is no
/// window in which a frame is recorded as held after its release. A frame still
/// marked when the connection ended is one that genuinely never went anywhere.
async fn flush<W: AsyncWrite + Unpin>(
    w: &mut W,
    held: &mut Vec<HeldFrame>,
    held_bytes: &mut usize,
    ctx: &FrameCtx,
    gate: &DirPause,
) -> bool {
    let mut sent = 0usize;
    let mut alive = true;
    for (fin, opcode, payload) in held.drain(..) {
        match deliver(w, fin, opcode, &payload, ctx.to_server).await {
            Sent::Ok => sent += 1,
            Sent::Closed => {
                sent += 1;
                alive = false;
                break;
            }
            Sent::Failed => {
                alive = false;
                break;
            }
        }
    }
    *held_bytes = 0;
    gate.held.store(held.len(), Ordering::Release);
    clear_held_marks(&ctx.state, ctx.session, ctx.direction, sent);
    alive
}

/// Clear the `held` flag on the oldest `count` still-held captures of one
/// direction. They were recorded in arrival order and go out in it, so the
/// oldest `count` of them are exactly the ones just delivered.
fn clear_held_marks(state: &AppState, session: u64, direction: &str, count: usize) {
    if count == 0 {
        return;
    }
    let mut left = count;
    let mut frames = state.ws_frames.lock().unwrap();
    for frame in frames.iter_mut() {
        if left == 0 {
            break;
        }
        if frame.session == session && frame.dir == direction && frame.held {
            frame.held = false;
            left -= 1;
        }
    }
}

/// Keep the peer this direction has gone quiet on from timing out. `false` once
/// it has stopped listening.
///
/// The frames are the proxy's own and are deliberately not captured: upstream
/// writes them straight to the socket, below the layer that reports frames
/// (`res.write(PONG)` / `req.write(PING)`,
/// `_original/lib/socket-mgr.js:370,:500`). An unsolicited pong is a legal
/// unidirectional heartbeat (RFC 6455 §5.5.3); the ping asks the client for one
/// back, which is what keeps *its* idle timer quiet too.
async fn send_keepalive<W: AsyncWrite + Unpin>(w: &mut W, to_server: bool) -> bool {
    let opcode = if to_server { OPCODE_PONG } else { OPCODE_PING };
    write_frame(w, true, opcode, &[], to_server).await.is_ok()
}

/// Whether a frame carries application data, and so may be offered to a plugin.
fn is_data_frame(opcode: u8) -> bool {
    matches!(opcode, OPCODE_CONTINUATION | OPCODE_TEXT | OPCODE_BINARY)
}

/// Offer one frame to each hook in turn, returning the payload to forward or
/// `None` to drop the frame.
///
/// A hook that fails is dropped from the chain and the frame carries on as if
/// it had never been there: a misbehaving plugin costs the session its hook,
/// never its connection. The first hook to drop a frame ends the chain, the way
/// the first plugin to `respond()` ends the request chain.
async fn run_hooks(
    hooks: &mut Vec<FrameHook>,
    direction: &str,
    fin: bool,
    opcode: u8,
    mut payload: Bytes,
) -> Option<Bytes> {
    let mut i = 0;
    while i < hooks.len() {
        let verdict = hooks[i]
            .exchange(&HookFrame {
                fin,
                opcode,
                // A refcount, not a copy: the hook shares the pump's bytes.
                payload: payload.clone(),
            })
            .await;
        match verdict {
            Ok(Verdict::Keep) => i += 1,
            Ok(Verdict::Replace(new)) => {
                payload = new;
                i += 1;
            }
            Ok(Verdict::Drop) => return dropped(fin, opcode),
            Err(e) => {
                tracing::warn!(
                    "wsFrame {} ({direction}): {e:#}; frames now pass through unchanged",
                    hooks[i].name()
                );
                hooks.remove(i);
            }
        }
    }
    Some(payload)
}

/// What "drop" means for one frame.
///
/// A whole message simply vanishes. A *fragment* cannot: removing one frame of
/// a fragmented message would orphan its continuations or leave the message
/// unterminated, which is a protocol error rather than a missing message. A
/// dropped fragment is therefore forwarded empty — the bytes go, the structure
/// stays — so a plugin can censor a fragmented message without corrupting the
/// stream it travels in.
fn dropped(fin: bool, opcode: u8) -> Option<Bytes> {
    let fragment = !fin || opcode == OPCODE_CONTINUATION;
    fragment.then(Bytes::new)
}

// ── a tunnel a rule asked to see ───────────────────────────────────────────

/// How much one read of an inspected tunnel takes at most — and so the most a
/// handler is handed at once. Node's socket reads are 64 KiB.
const CHUNK: usize = 64 * 1024;

/// Relay a tunnel **chunk by chunk**, because a rule said `enable://inspect`.
///
/// A tunnel that is not read — anything that is not HTTP or a TLS handshake
/// this proxy intercepts, or one a rule said to leave alone — is ordinarily a
/// `copy_bidirectional`, and nothing about it is visible. With
/// `enable://inspect` upstream shows each chunk in the Frames panel and hands
/// it to the connection's `frameScript` (`handleConnSend` / `handleConnReceive`,
/// `_original/lib/socket-mgr.js:125-205`): [`frameScript.md`] is for
/// "WebSocket 和普通 TCP 请求数据帧", and until 2026-09-30 only the first half
/// was true here.
///
/// A "frame" on a tunnel is whatever one read returned. TCP has no message
/// boundaries, so a handler that needs a whole message has to reassemble it
/// itself — upstream's does too.
///
/// `enable://pauseSend` and the other three are not honoured on a tunnel; they
/// imply `inspect` upstream and do here, and that is all they do.
///
/// [`frameScript.md`]: https://wproxy.org/docs/rules/frameScript.html
pub async fn inspected_relay<C, O>(
    client: C,
    origin: O,
    script: Option<FrameScriptSpec>,
    state: Arc<AppState>,
    session: Option<u64>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let started = match script {
        Some(spec) => FrameScript::start(spec).await,
        None => FrameScriptStart::default(),
    };
    let (client_read, client_write) = tokio::io::split(client);
    let (origin_read, origin_write) = tokio::io::split(origin);
    // Each write half behind a lock: a handler running for one direction may
    // send bytes the other way, and a chunk must not land inside another.
    let pipe = TunnelPipe {
        to_server: tokio::sync::Mutex::new(origin_write),
        to_client: tokio::sync::Mutex::new(client_write),
        script: started.script,
        state,
        session,
    };
    // What the script sent while it was being evaluated goes first. The CONNECT
    // has been answered by now, so bytes toward the client are tunnel bytes —
    // upstream writes them *before* its `200`, and the client's CONNECT then
    // fails on a status line it cannot read.
    for frame in &started.sent {
        pipe.write(frame.to_server, &frame.data).await?;
    }
    let up = pipe.pump(client_read, true);
    let down = pipe.pump(origin_read, false);
    let (up, down) = tokio::join!(up, down);
    up.and(down)
}

/// The two write halves of an inspected tunnel, and what looks at its chunks.
struct TunnelPipe<S, C> {
    to_server: tokio::sync::Mutex<S>,
    to_client: tokio::sync::Mutex<C>,
    script: Option<FrameScript>,
    state: Arc<AppState>,
    /// The session the chunks are filed under; `None` for a hidden tunnel,
    /// whose script runs and whose chunks are not kept.
    session: Option<u64>,
}

impl<S, C> TunnelPipe<S, C>
where
    S: AsyncWrite + Unpin,
    C: AsyncWrite + Unpin,
{
    /// Write one chunk toward either end, and record it as a frame.
    async fn write(&self, to_server: bool, data: &[u8]) -> io::Result<()> {
        if to_server {
            let mut w = self.to_server.lock().await;
            w.write_all(data).await?;
            w.flush().await?;
        } else {
            let mut w = self.to_client.lock().await;
            w.write_all(data).await?;
            w.flush().await?;
        }
        let Some(session) = self.session else {
            return Ok(());
        };
        // Filed as text when it is text, so the Frames panel shows it as
        // written rather than as hex; a tunnel's bytes have no type of their
        // own.
        let opcode = match std::str::from_utf8(data) {
            Ok(_) => OPCODE_TEXT,
            Err(_) => OPCODE_BINARY,
        };
        let direction = if to_server { "send" } else { "receive" };
        self.state
            .record_frame(WsFrame::new(session, direction, opcode, data));
        Ok(())
    }

    /// No more bytes will come this way: tell the far end, as a plain relay's
    /// half-close does.
    async fn finish(&self, to_server: bool) {
        if to_server {
            let _ = self.to_server.lock().await.shutdown().await;
        } else {
            let _ = self.to_client.lock().await.shutdown().await;
        }
    }

    /// One direction: read a chunk, let the script see it, write what is left.
    async fn pump<R: AsyncRead + Unpin>(&self, mut from: R, to_server: bool) -> io::Result<()> {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) => {
                    self.finish(to_server).await;
                    return Err(err);
                }
            };
            let chunk = &buf[..n];
            let Some(script) = self.script.as_ref().filter(|s| s.handles(to_server)) else {
                self.write(to_server, chunk).await?;
                continue;
            };
            let outcome = script
                .relay(ScriptFrame {
                    to_server,
                    data: chunk.to_vec(),
                    binary: true,
                })
                .await;
            for sent in &outcome.sent {
                self.write(sent.to_server, &sent.data).await?;
            }
            if let Some(kept) = outcome.frame {
                self.write(to_server, &kept.data).await?;
            }
        }
        self.finish(to_server).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;
    use crate::config::Config;
    use crate::plugins::{PluginReq, PluginResult, RustPlugin};
    use crate::proxy::apply;
    use crate::rules::RuleManager;
    use tokio::io::DuplexStream;
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Server state backed by a throwaway storage dir, so the tests never touch
    /// the developer's real `~/.whix`.
    ///
    /// One dir per state, not one per run: these tests execute in parallel and
    /// would otherwise race to write the same root CA, now and then reading a
    /// half-written PEM back.
    fn state_with(plugins: crate::plugins::Plugins) -> Arc<AppState> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir()
                .join(format!("whix-ws-tests-{}-{n}", std::process::id())),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::with_plugins(
            config,
            RuleManager::new(),
            ca,
            plugins,
        ))
    }

    /// A plan built from `rules`, as the proxy would build it for `ws://ws.test/chat`.
    fn plan_for(state: &AppState, rules: &str) -> FramePlan {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let info = apply::build_req_info(
            "GET",
            "ws",
            "ws.test",
            80,
            "/chat",
            &hyper::HeaderMap::new(),
            Some("1.2.3.4".to_string()),
        );
        // Frame rules have no response phase; resolve once, like the tunnel does.
        let resolved = mgr.resolve_once(&info, false);
        FramePlan::new(&state.plugins, &resolved, &info)
    }

    /// The two ends of a tunnel: what the client writes/reads, and what the
    /// origin server writes/reads. Dropping either end closes the tunnel.
    struct Wire {
        client: DuplexStream,
        server: DuplexStream,
        tunnel: tokio::task::JoinHandle<()>,
    }

    fn spawn_tunnel(state: &Arc<AppState>, plan: FramePlan, script: Option<String>) -> Wire {
        spawn_tunnel_with(state, plan, script, FrameFlow::default())
    }

    /// As [`spawn_tunnel`], with the per-direction modes a rule would supply.
    fn spawn_tunnel_with(
        state: &Arc<AppState>,
        plan: FramePlan,
        script: Option<String>,
        flow: FrameFlow,
    ) -> Wire {
        let (client, client_io) = tokio::io::duplex(1 << 16);
        let (server, upstream_io) = tokio::io::duplex(1 << 16);
        // The script as a request for `ws://chat.test/room` would carry it.
        let script = script.and_then(|src| {
            let info = apply::build_req_info(
                "GET",
                "ws",
                "chat.test",
                80,
                "/room",
                &hyper::HeaderMap::new(),
                Some("10.0.0.7".to_string()),
            );
            FrameScriptSpec::for_request(src, &info, "chat.test", &Default::default())
        });
        let tunnel = tokio::spawn(capturing_tunnel(
            client_io,
            upstream_io,
            script,
            plan,
            flow,
            state.clone(),
            7,
        ));
        Wire {
            client,
            server,
            tunnel,
        }
    }

    /// Close both ends and wait for the tunnel's tasks to finish.
    async fn finish(wire: Wire) {
        let Wire {
            client,
            server,
            tunnel,
        } = wire;
        drop(client);
        drop(server);
        tunnel.await.expect("tunnel task");
    }

    /// A native plugin whose frame hook is supplied by the test.
    struct TestPlugin {
        name: &'static str,
        verdict: fn(&HookFrame) -> Verdict,
    }

    impl RustPlugin for TestPlugin {
        fn name(&self) -> &str {
            self.name
        }

        fn on_request(&self, _req: &PluginReq) -> PluginResult {
            PluginResult::default()
        }

        fn manifest(&self) -> crate::plugins::PluginManifest {
            crate::plugins::PluginManifest {
                ws_frame: true,
                ..crate::plugins::PluginManifest::v1_fallback(self.name)
            }
        }

        fn on_ws_frame(&self, _meta: &FrameMeta, frame: &HookFrame) -> Verdict {
            (self.verdict)(frame)
        }
    }

    fn state_hooking(name: &'static str, verdict: fn(&HookFrame) -> Verdict) -> Arc<AppState> {
        let mut plugins = crate::plugins::Plugins::new();
        plugins.register_rust(Box::new(TestPlugin { name, verdict }));
        state_with(plugins)
    }

    /// The non-negotiable: with no frame-hook plugin, every byte the tunnel
    /// emits is the byte it emitted before this feature existed — the codec's
    /// own encoding of the frame it read, masked on the way to the server and
    /// bare on the way back — and every frame is still captured.
    #[test]
    fn a_session_with_no_frame_plugin_is_untouched() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            // A rule naming no plugin at all leaves the plan empty…
            let plan = plan_for(&state, "ws.test resHeaders://x=1\n");
            assert!(plan.is_empty());
            // …and so does one naming a plugin with no frame hook.
            assert!(
                plan_for(&state, "ws.test plugin://stamp\n")
                    .connect(&state.plugins, 7)
                    .await
                    .0
                    .is_empty()
            );

            let mut wire = spawn_tunnel(&state, plan, None);
            let payloads: [&[u8]; 3] = [b"hello", b"\x00\xff\xfe binary", &[0u8; 300]];
            for payload in payloads {
                write_frame(&mut wire.client, true, OPCODE_BINARY, payload, true)
                    .await
                    .expect("client write");
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(got.payload, payload);

                // Byte-for-byte: what reached the origin is exactly what the
                // codec encodes for that frame, nothing added, nothing lost.
                let mut expected = Vec::new();
                write_frame(&mut expected, true, OPCODE_BINARY, payload, true)
                    .await
                    .expect("encode");
                assert_eq!(expected[0], 0x82);

                write_frame(&mut wire.server, true, OPCODE_TEXT, b"pong", false)
                    .await
                    .expect("server write");
                let back = read_frame(&mut wire.client)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(back.payload, b"pong");
            }
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 6, "every frame is still captured");
            assert_eq!(frames[0].dir, "send");
            assert_eq!(frames[0].opcode, "binary");
            assert_eq!(frames[1].dir, "receive");
            assert_eq!(frames[1].preview, "pong");
        });
    }

    /// The built-in native hook rewrites text frames in both directions, and
    /// what the capture shows is what actually went on the wire.
    #[test]
    fn a_frame_hook_rewrites_both_directions() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test pipe://ws-upper\n");
            assert!(!plan.is_empty());
            let mut wire = spawn_tunnel(&state, plan, None);

            write_frame(&mut wire.client, true, OPCODE_TEXT, b"up", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"UP");

            write_frame(&mut wire.server, true, OPCODE_TEXT, b"down", false)
                .await
                .expect("server write");
            let back = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(back.payload, b"DOWN");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames[0].preview, "UP");
            assert_eq!(frames[1].preview, "DOWN");
        });
    }

    /// 8 MiB of every byte value, through a hook that replaces the payload with
    /// itself. The length must come back identical: a hook that round-tripped
    /// binary through UTF-8 would inflate it, which is exactly the failure this
    /// asserts against.
    #[test]
    fn binary_frames_survive_the_hook_byte_for_byte() {
        rt().block_on(async {
            let state = state_hooking("echo-bytes", |f| Verdict::Replace(f.payload.clone()));
            let plan = plan_for(&state, "ws.test pipe://echo-bytes\n");
            let mut wire = spawn_tunnel(&state, plan, None);

            let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
            let sent = payload.clone();
            let mut client = wire.client;
            let writer = tokio::spawn(async move {
                write_frame(&mut client, true, OPCODE_BINARY, &sent, true)
                    .await
                    .expect("client write");
                client
            });
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload.len(), payload.len(), "no inflation");
            assert_eq!(got.payload, payload, "and no substitution");
            wire.client = writer.await.expect("writer");
            finish(wire).await;
        });
    }

    /// A dropped frame reaches neither the peer nor the capture; the next frame
    /// is unaffected.
    #[test]
    fn a_dropped_frame_never_reaches_the_peer() {
        rt().block_on(async {
            let state = state_hooking("censor", |f| {
                if f.payload.as_ref() == b"secret" {
                    Verdict::Drop
                } else {
                    Verdict::Keep
                }
            });
            let plan = plan_for(&state, "ws.test plugin://censor\n");
            let mut wire = spawn_tunnel(&state, plan, None);

            for payload in [&b"secret"[..], &b"public"[..]] {
                write_frame(&mut wire.client, true, OPCODE_TEXT, payload, true)
                    .await
                    .expect("client write");
            }
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(
                got.payload, b"public",
                "the dropped frame is simply not there"
            );
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].preview, "public");
        });
    }

    /// `enable://ignoreSend` discards what the client sends and leaves the
    /// other direction alone. The frame is still *recorded*, flagged — upstream
    /// reports it with `ignore: true` (`_original/lib/socket-mgr.js:401,:531`)
    /// rather than omitting it, so the view shows a dropped frame instead of a
    /// gap. Previously both flags parsed and did nothing.
    #[test]
    fn ignore_send_drops_one_direction_only() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://ignoreSend\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Ignore,
                    receive: DirMode::Pass,
                    ..FrameFlow::default()
                },
            );

            write_frame(&mut wire.client, true, OPCODE_TEXT, b"muted", true)
                .await
                .expect("client write");
            // The origin must never see it, so prove the tunnel is still live by
            // driving the *other* direction and reading that instead.
            write_frame(&mut wire.server, true, OPCODE_TEXT, b"heard", false)
                .await
                .expect("server write");
            let back = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(back.payload, b"heard", "receive is untouched");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 2, "both frames are captured");
            let sent = frames.iter().find(|f| f.dir == "send").expect("send frame");
            assert_eq!(sent.preview, "muted");
            assert!(sent.ignored, "the dropped frame is flagged, not hidden");
            let recv = frames
                .iter()
                .find(|f| f.dir == "receive")
                .expect("receive frame");
            assert!(!recv.ignored);
        });
    }

    /// The mirror image, and the control frames that survive either flag: a
    /// `close` still closes and a `ping` still pings, because withholding those
    /// breaks the connection rather than silencing the payload — upstream only
    /// ever withholds data too (`opts.data`, `socket-mgr.js:249-274`).
    #[test]
    fn ignore_receive_spares_the_control_frames() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://ignoreReceive\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pass,
                    receive: DirMode::Ignore,
                    ..FrameFlow::default()
                },
            );

            // Data from the origin is dropped…
            write_frame(&mut wire.server, true, OPCODE_TEXT, b"dropped", false)
                .await
                .expect("server write");
            // …but a ping is not, so this is what the client actually reads.
            write_frame(&mut wire.server, true, 0x9, b"", false)
                .await
                .expect("server ping");
            let got = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.opcode, 0x9, "the ping got through; the text did not");

            // The client's own direction is unaffected by this flag.
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"sent", true)
                .await
                .expect("client write");
            let up = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(up.payload, b"sent");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            let dropped = frames
                .iter()
                .find(|f| f.preview == "dropped")
                .expect("recorded");
            assert!(dropped.ignored);
            assert!(frames.iter().any(|f| f.opcode == "ping" && !f.ignored));
            assert!(frames.iter().any(|f| f.preview == "sent" && !f.ignored));
        });
    }

    // ── enable://pauseSend | pauseReceive ──

    /// The pause state of session 7, which every test here uses. Waits for it:
    /// the tunnel registers itself from its own task, after dialling whatever
    /// plugins the plan named.
    async fn gate_of(state: &AppState) -> Arc<SessionPause> {
        for _ in 0..10_000 {
            let found = state.ws_pause.lock().unwrap().get(&7).cloned();
            if let Some(gate) = found {
                return gate;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("a paused session is registered for release");
    }

    /// How many of the captures are still waiting to be let go.
    fn still_held(state: &AppState) -> usize {
        state
            .ws_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.held)
            .count()
    }

    /// Wait until `cond` holds. The legs pump on tasks of their own, so a test
    /// that asserted the instant after it wrote would be asserting on a race.
    /// The ten-second ceiling is a stuck-test guard, not a deadline: these
    /// settle in milliseconds on a machine that is not otherwise busy.
    async fn until(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..10_000 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// True when nothing crosses in 50ms — as close to "never" as a test gets.
    async fn stays_silent<R: AsyncRead + Unpin>(r: &mut R) -> bool {
        tokio::time::timeout(Duration::from_millis(50), read_frame(r))
            .await
            .is_err()
    }

    /// The per-direction modes a rule set resolves to, as the proxy reads them.
    fn flow_for(rules: &str) -> FrameFlow {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let info = apply::build_req_info(
            "GET",
            "ws",
            "ws.test",
            80,
            "/chat",
            &hyper::HeaderMap::new(),
            None,
        );
        FrameFlow::of(&mgr.resolve_once(&info, false))
    }

    /// `enable://pauseSend` holds what the client sends until someone releases
    /// it — and then lets all of it out at once, in the order it arrived, which
    /// is the only granularity upstream's console offers either
    /// (`setConnStatus`, `_original/lib/socket-mgr.js:63-84`).
    #[test]
    fn pause_send_holds_every_frame_until_the_console_releases_it() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseSend\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pause,
                    receive: DirMode::Pass,
                    ..FrameFlow::default()
                },
            );

            for payload in [&b"one"[..], b"two"] {
                write_frame(&mut wire.client, true, OPCODE_TEXT, payload, true)
                    .await
                    .expect("client write");
            }
            until("both frames held", || still_held(&state) == 2).await;
            assert!(
                stays_silent(&mut wire.server).await,
                "and none of it crosses"
            );

            let gate = gate_of(&state).await;
            assert!(gate.send.paused());
            assert_eq!(gate.send.held(), 2);
            assert!(
                !gate.receive.paused(),
                "the other direction was not asked for"
            );

            // Which is also how we know the tunnel is alive rather than merely
            // quiet: the unheld direction still carries.
            write_frame(&mut wire.server, true, OPCODE_TEXT, b"down", false)
                .await
                .expect("server write");
            let back = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(back.payload, b"down");

            assert_eq!(gate.send.release(), 2, "the release says what it freed");
            for expected in [&b"one"[..], b"two"] {
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(got.payload, expected, "in the order they were sent");
            }
            // A frame that went out is no longer waiting, so the console stops
            // showing it as such.
            until("the marks cleared", || still_held(&state) == 0).await;
            assert_eq!(gate.send.held(), 0);
            assert!(!gate.send.paused());

            // And the direction is open from here on, not held again.
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"three", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"three");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 4, "every frame is captured as it arrives");
            assert!(frames.iter().all(|f| !f.ignored), "held is not dropped");
        });
    }

    /// The mirror image, and the difference from `ignore`: a pause holds this
    /// direction's **control** frames too. Upstream pauses the byte stream, so a
    /// `ping` sharing a chunk with held data is held with it
    /// (`handleFrame`, `_original/lib/socket-mgr.js:232-247`) — where its ignore
    /// path only ever withholds data.
    #[test]
    fn pause_receive_holds_one_direction_only_control_frames_included() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseReceive\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pass,
                    receive: DirMode::Pause,
                    ..FrameFlow::default()
                },
            );

            write_frame(&mut wire.server, true, OPCODE_TEXT, b"later", false)
                .await
                .expect("server write");
            write_frame(&mut wire.server, true, OPCODE_PING, b"", false)
                .await
                .expect("server ping");
            until("both frames held", || still_held(&state) == 2).await;
            assert!(
                stays_silent(&mut wire.client).await,
                "the ping waits with the text"
            );

            // The client's own direction is untouched by this flag.
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"sent", true)
                .await
                .expect("client write");
            let up = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(up.payload, b"sent");

            let gate = gate_of(&state).await;
            assert_eq!(gate.receive.release(), 2);
            let text = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(text.payload, b"later");
            let ping = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(ping.opcode, OPCODE_PING);
            finish(wire).await;
        });
    }

    /// The hold is bounded by a frame count, because nothing else bounds it: this
    /// port reads ahead so the console can show what is waiting, where upstream
    /// simply stops reading the socket. Past the bound the leg stops taking
    /// frames and the peer is back-pressured instead — nothing is lost, and
    /// nothing beyond the bound is captured until the release.
    #[test]
    fn the_hold_queue_stops_at_its_frame_bound() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseSend\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pause,
                    receive: DirMode::Pass,
                    ..FrameFlow::default()
                },
            );

            let total = MAX_HELD_FRAMES + 16;
            for i in 0..total {
                write_frame(
                    &mut wire.client,
                    true,
                    OPCODE_TEXT,
                    format!("{i}").as_bytes(),
                    true,
                )
                .await
                .expect("client write");
            }
            let gate = gate_of(&state).await;
            until("the queue to fill", || gate.send.held() == MAX_HELD_FRAMES).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(gate.send.held(), MAX_HELD_FRAMES, "and to stay there");
            assert_eq!(
                still_held(&state),
                MAX_HELD_FRAMES,
                "nothing past it is captured"
            );

            // The back-pressured frames were never dropped, only not yet read.
            gate.send.release();
            for i in 0..total {
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(
                    got.payload,
                    format!("{i}").as_bytes(),
                    "all of it, in order"
                );
            }
            finish(wire).await;
        });
    }

    /// And by a byte budget, because 64 frames of 8 MiB is not a bound.
    #[test]
    fn the_hold_queue_stops_at_its_byte_bound_too() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseSend\n");
            let wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pause,
                    receive: DirMode::Pass,
                    ..FrameFlow::default()
                },
            );

            // Five one-mebibyte frames against a four-mebibyte budget. They go
            // out from a task of their own: the fifth cannot be written until
            // the release, which is the whole point.
            let chunk = vec![b'x'; 1024 * 1024];
            let mut wire = wire;
            let mut client = wire.client;
            let writer = tokio::spawn(async move {
                for _ in 0..5 {
                    write_frame(&mut client, true, OPCODE_BINARY, &chunk, true)
                        .await
                        .expect("client write");
                }
                client
            });

            let gate = gate_of(&state).await;
            let cap = MAX_HELD_BYTES / (1024 * 1024);
            until("the budget to fill", || gate.send.held() == cap).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                gate.send.held(),
                cap,
                "the fifth frame is not held, it is unread"
            );

            gate.send.release();
            for _ in 0..5 {
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(got.payload.len(), 1024 * 1024);
            }
            wire.client = writer.await.expect("writer");
            finish(wire).await;
        });
    }

    /// A session nobody paused is not registered at all — the registry answers
    /// "which connections is somebody holding", and an entry per WebSocket would
    /// make it answer something else. A paused one is registered for exactly as
    /// long as it lasts, and frames still held when it ends stay flagged: they
    /// never reached the peer, and the capture should not pretend otherwise.
    #[test]
    fn only_a_paused_session_is_registered_and_only_while_it_lasts() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plain = spawn_tunnel(&state, plan_for(&state, "ws.test resHeaders://x=1\n"), None);
            write_frame(&mut { plain.client }, true, OPCODE_TEXT, b"hi", true)
                .await
                .expect("client write");
            assert!(state.ws_pause.lock().unwrap().is_empty());

            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseSend\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pause,
                    receive: DirMode::Pass,
                    ..FrameFlow::default()
                },
            );
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"stranded", true)
                .await
                .expect("client write");
            until("the frame held", || still_held(&state) == 1).await;

            // A peer that leaves while its frames are held ends the leg even
            // though nothing released it.
            finish(wire).await;
            assert!(
                state.ws_pause.lock().unwrap().is_empty(),
                "a session that ended cannot be released"
            );
            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 1);
            assert!(
                frames[0].held,
                "and what it was holding is still marked as held"
            );
        });
    }

    /// A held direction is a silent one, and a silent connection is one an idle
    /// timeout closes. Upstream answers that with a keep-alive of its own every
    /// 22 seconds while the pause lasts (`INTERVAL`, `PING`,
    /// `_original/lib/socket-mgr.js:8,:11,:496-505`); so does this. It is the
    /// proxy's own traffic, so it is not captured as part of the conversation.
    #[test]
    fn a_held_direction_keeps_its_peer_alive() {
        rt().block_on(async {
            // The clock is the test's, not the wall's: 22 seconds of it pass as
            // soon as everything else has stopped.
            tokio::time::pause();
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseReceive\n");
            let mut wire = spawn_tunnel_with(
                &state,
                plan,
                None,
                FrameFlow {
                    send: DirMode::Pass,
                    receive: DirMode::Pause,
                    ..FrameFlow::default()
                },
            );

            let probe = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(probe.opcode, OPCODE_PING, "with nothing at all flowing");
            assert!(probe.payload.is_empty());
            assert!(
                state.ws_frames.lock().unwrap().is_empty(),
                "the proxy's own keep-alive is not part of the capture"
            );
            finish(wire).await;
        });
    }

    /// `disable://ping` turns the keep-alive off, which is the whole of what
    /// upstream's flag does (`req.disable.ping`,
    /// `_original/lib/socket-mgr.js:496-498`). It had nothing to say here until
    /// there was a keep-alive to suppress.
    #[test]
    fn disable_ping_silences_the_keepalive_the_pause_brought() {
        rt().block_on(async {
            tokio::time::pause();
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://pauseReceive disable://ping\n");
            let flow = flow_for("ws.test enable://pauseReceive disable://ping\n");
            assert!(flow.no_ping, "the flag is read");
            assert!(!flow.no_pong, "and only the leg it names");
            let mut wire = spawn_tunnel_with(&state, plan, None, flow);

            // Nothing arrives where the probe would have: the origin sends a
            // frame after the clock has run past several intervals, and it is
            // the *held* frame's absence that proves the leg is alive but quiet.
            tokio::time::advance(KEEPALIVE * 3).await;
            write_frame(&mut wire.server, true, OPCODE_TEXT, b"held", false)
                .await
                .expect("server write");
            until("the frame held", || still_held(&state) == 1).await;
            assert_eq!(
                state.ws_frames.lock().unwrap().len(),
                1,
                "one captured frame and no probe on the wire"
            );
            finish(wire).await;
        });
    }

    /// The flags name one leg each, so the pong's flag says nothing about the
    /// ping's. Upstream guards `res.write(PONG)` with `disable.pong` and
    /// `req.write(PING)` with `disable.ping` (`socket-mgr.js:366-368,:496-498`).
    #[test]
    fn each_keepalive_flag_names_one_leg() {
        let ping = flow_for("ws.test enable://pauseSend disable://ping\n");
        assert!(ping.no_ping && !ping.no_pong);
        let pong = flow_for("ws.test enable://pauseSend disable://pong\n");
        assert!(pong.no_pong && !pong.no_ping);
        let both = flow_for("ws.test enable://pauseSend disable://ping|pong\n");
        assert!(both.no_ping && both.no_pong);
        let neither = flow_for("ws.test enable://pauseSend\n");
        assert!(!neither.no_ping && !neither.no_pong);
    }

    /// The two flags of one direction are one status upstream, and it tests the
    /// pause first (`initStatus`, `_original/lib/socket-mgr.js:86-97`), so a
    /// direction that names both is paused rather than ignored — and stays open
    /// once released instead of quietly starting to drop.
    #[test]
    fn pause_outranks_ignore_on_the_same_direction() {
        assert_eq!(
            flow_for("ws.test enable://pauseSend\n").send,
            DirMode::Pause
        );
        assert_eq!(
            flow_for("ws.test enable://ignoreSend\n").send,
            DirMode::Ignore
        );
        assert_eq!(flow_for("ws.test resHeaders://x=1\n").send, DirMode::Pass);

        let both = flow_for("ws.test enable://pauseSend|ignoreSend\n");
        assert_eq!(both.send, DirMode::Pause);
        assert_eq!(both.receive, DirMode::Pass);

        let mixed = flow_for("ws.test enable://pauseReceive|ignoreSend\n");
        assert_eq!(
            mixed.send,
            DirMode::Ignore,
            "each direction is judged alone"
        );
        assert_eq!(mixed.receive, DirMode::Pause);
    }

    /// Dropping a *fragment* empties it instead of removing it: the message
    /// keeps its shape, so the peer still sees a well-formed (if empty) message
    /// rather than an unterminated one.
    #[test]
    fn dropping_a_fragment_keeps_the_message_well_formed() {
        rt().block_on(async {
            let state = state_hooking("censor-all", |_| Verdict::Drop);
            let plan = plan_for(&state, "ws.test plugin://censor-all\n");
            let mut wire = spawn_tunnel(&state, plan, None);

            // A two-fragment text message: "part" + "two", neither complete.
            write_frame(&mut wire.client, false, OPCODE_TEXT, b"part", true)
                .await
                .expect("client write");
            write_frame(&mut wire.client, true, OPCODE_CONTINUATION, b"two", true)
                .await
                .expect("client write");

            let first = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert!(!first.fin);
            assert_eq!(first.opcode, OPCODE_TEXT);
            assert!(first.payload.is_empty());
            let second = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert!(second.fin);
            assert_eq!(second.opcode, OPCODE_CONTINUATION);
            assert!(second.payload.is_empty());
            finish(wire).await;
        });
    }

    /// Control frames are never offered to a hook, however greedy it is, and
    /// pass through byte-for-byte. A close still ends the tunnel.
    #[test]
    fn control_frames_bypass_the_hook() {
        rt().block_on(async {
            let state = state_hooking("greedy", |_| Verdict::Replace(Bytes::from_static(b"X")));
            let plan = plan_for(&state, "ws.test pipe://greedy\n");
            let mut wire = spawn_tunnel(&state, plan, None);

            for (opcode, payload) in [(0x9u8, &b"ping-payload"[..]), (0xa, b"pong-payload")] {
                write_frame(&mut wire.client, true, opcode, payload, true)
                    .await
                    .expect("client write");
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(got.opcode, opcode);
                assert_eq!(got.payload, payload);
            }

            // A data frame on the same session still goes through the hook.
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"data", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"X");

            write_frame(&mut wire.client, true, OPCODE_CLOSE, &[0x03, 0xe8], true)
                .await
                .expect("client write");
            let close = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(close.opcode, OPCODE_CLOSE);
            assert_eq!(close.payload, vec![0x03, 0xe8]);
            finish(wire).await;
        });
    }

    /// A remote plugin that accepts the session and then dies. Every frame must
    /// still cross, in both directions: the proxy owns the frame stream, so
    /// losing a hook is never losing a WebSocket.
    #[test]
    fn a_plugin_that_dies_mid_session_is_abandoned_not_the_connection() {
        rt().block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            // Declares the hook, accepts the session, then hangs up at once.
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while tokio::io::AsyncReadExt::read_exact(&mut sock, &mut byte)
                            .await
                            .is_ok()
                        {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let reply: &[u8] = if head.starts_with(b"GET /manifest") {
                            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 36\r\n\r\n{\"name\":\"flaky\",\"hooks\":[\"wsFrame\"]}"
                        } else {
                            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n"
                        };
                        let _ = sock.write_all(reply).await;
                    });
                }
            });

            let mut plugins = crate::plugins::Plugins::new();
            plugins.register_remote("flaky", &addr.to_string());
            let state = state_with(plugins);
            let plan = plan_for(&state, "ws.test pipe://flaky\n");
            assert!(!plan.is_empty());
            let mut wire = spawn_tunnel(&state, plan, None);

            for payload in [&b"one"[..], &b"two"[..]] {
                write_frame(&mut wire.client, true, OPCODE_TEXT, payload, true)
                    .await
                    .expect("client write");
                let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
                assert_eq!(got.payload, payload, "the frame crosses even so");
            }
            write_frame(&mut wire.server, true, OPCODE_TEXT, b"down", false)
                .await
                .expect("server write");
            let back = read_frame(&mut wire.client).await.expect("read").expect("frame");
            assert_eq!(back.payload, b"down", "and the other direction too");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 3, "and every one of them is still captured");
        });
    }

    /// `frameScript` runs first and the plugin sees its output, so the two
    /// compose instead of racing.
    #[test]
    fn the_script_runs_before_the_plugin() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test pipe://ws-upper\n");
            let script = "ctx.frame.data = ctx.frame.data + ' via ' + ctx.direction;".to_string();
            let mut wire = spawn_tunnel(&state, plan, Some(script));

            write_frame(&mut wire.client, true, OPCODE_TEXT, b"hi", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"HI VIA SEND");
            finish(wire).await;
        });
    }

    /// A `frameScript` written the way `frameScript.md` writes one: two
    /// handlers installed on `ctx`, each returning the frame to deliver.
    #[test]
    fn a_frame_script_may_install_handlers() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let script = "ctx.handleSendToServerFrame = function (buf) { \
                              return (buf + '').replace(/1/g, '***'); \
                          };"
            .to_string();
            let mut wire = spawn_tunnel(&state, plan, Some(script));
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"1 and 1", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"*** and ***");
            finish(wire).await;
        });
    }

    /// A handler that answers with nothing delivers nothing —
    /// `cb(null, chunk || null)` (`_original/lib/socket-mgr.js:198-206`).
    #[test]
    fn a_handler_that_returns_nothing_drops_the_frame() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let script = "ctx.handleSendToServerFrame = function (buf) { \
                              return (buf + '') === 'drop' ? '' : buf; \
                          };"
            .to_string();
            let mut wire = spawn_tunnel(&state, plan, Some(script));
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"drop", true)
                .await
                .expect("client write");
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"keep", true)
                .await
                .expect("client write");
            // The dropped frame never arrives, so the next one is what reads.
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"keep");
            finish(wire).await;
        });
    }

    /// `ctx.sendToServer` sends a frame the moment the connection opens.
    #[test]
    fn a_frame_script_may_send_a_frame_of_its_own() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let script = "ctx.sendToServer('hello server');".to_string();
            let mut wire = spawn_tunnel(&state, plan, Some(script));
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"hello server");
            finish(wire).await;
        });
    }

    /// Send `frames` from the client and collect what the server is handed.
    async fn through(wire: &mut Wire, frames: &[(u8, &[u8])]) -> Vec<(u8, Vec<u8>)> {
        let mut seen = Vec::new();
        for (opcode, payload) in frames {
            write_frame(&mut wire.client, true, *opcode, payload, true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server)
                .await
                .expect("read")
                .expect("frame");
            seen.push((got.opcode, got.payload));
        }
        seen
    }

    /// The defect this guards against: the script was evaluated afresh for
    /// every frame, so a counter in it answered 1 for ever. It is one script
    /// per connection — and a second connection starts from its own zero.
    #[test]
    fn a_frame_script_keeps_its_state_for_the_life_of_the_connection() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let script = "var n = 0; ctx.handleSendToServerFrame = function (buf) { \
                          return 'N' + (++n) + ':' + buf; };";
            for _ in 0..2 {
                let plan = plan_for(&state, "ws.test enable://websocket\n");
                let mut wire = spawn_tunnel(&state, plan, Some(script.to_string()));
                let seen = through(
                    &mut wire,
                    &[
                        (OPCODE_TEXT, b"a"),
                        (OPCODE_TEXT, b"b"),
                        (OPCODE_TEXT, b"c"),
                    ],
                )
                .await;
                let texts: Vec<&[u8]> = seen.iter().map(|(_, p)| p.as_slice()).collect();
                assert_eq!(texts, [&b"N1:a"[..], b"N2:b", b"N3:c"]);
                finish(wire).await;
            }
        });
    }

    /// A binary frame reaches the handler, as a `Buffer`, and what comes back
    /// decides the type that goes out: a string is text, a `Buffer` keeps the
    /// frame's own type, and `opts.binary` overrides either.
    #[test]
    fn a_frame_script_sees_binary_frames_and_may_retype_them() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            // The handler's body; the frame sent; the frame that must arrive.
            type Case = (&'static str, u8, &'static [u8], u8, &'static [u8]);
            let cases: [Case; 6] = [
                // A string built from the bytes: text.
                ("return 'X' + buf;", OPCODE_BINARY, b"BIN", OPCODE_TEXT, b"XBIN"),
                // The bytes handed straight back, not text at all: still binary,
                // and still those bytes.
                ("return buf;", OPCODE_BINARY, &[0x00, 0xff, 0x80], OPCODE_BINARY, &[0x00, 0xff, 0x80]),
                // A Buffer in place of a text frame: still text.
                ("return Buffer.from('new');", OPCODE_TEXT, b"old", OPCODE_TEXT, b"new"),
                // The handler says which, either way.
                ("opts.binary = true; return buf;", OPCODE_TEXT, b"t", OPCODE_BINARY, b"t"),
                ("opts.binary = false; return buf;", OPCODE_BINARY, b"b", OPCODE_TEXT, b"b"),
                // What it is handed: a Buffer, and the frame's particulars.
                (
                    "return [Buffer.isBuffer(buf), buf.length, opts.opcode, opts.mask, opts.length].join();",
                    OPCODE_BINARY,
                    b"ab",
                    OPCODE_TEXT,
                    b"true,2,2,true,2",
                ),
            ];
            for (body, opcode, payload, want_opcode, want) in cases {
                let plan = plan_for(&state, "ws.test enable://websocket\n");
                let script = format!("ctx.handleSendToServerFrame = function (buf, opts) {{ {body} }};");
                let mut wire = spawn_tunnel(&state, plan, Some(script));
                let seen = through(&mut wire, &[(opcode, payload)]).await;
                assert_eq!(seen, [(want_opcode, want.to_vec())], "{body}");
                finish(wire).await;
            }
        });
    }

    /// A handler may send frames of its own, either way, while it decides about
    /// the one it was handed. They go out first, and each passes through the
    /// handler for the direction it travels, marked `opts.frameScript`.
    #[test]
    fn a_handler_may_send_frames_of_its_own() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let script = "\
                ctx.handleSendToServerFrame = function (buf, opts) {\
                    if (opts.frameScript) { return 'S!' + buf; }\
                    ctx.sendToClient('ack:' + buf);\
                    ctx.sendToServer('also:' + buf);\
                    return buf;\
                };\
                ctx.handleSendToClientFrame = function (buf, opts) {\
                    return 'C(' + buf + ')' + (opts.frameScript ? '!' : '');\
                };";
            let mut wire = spawn_tunnel(&state, plan, Some(script.to_string()));
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"a", true)
                .await
                .expect("client write");
            // Toward the server: what the handler sent, then the frame itself.
            for want in [&b"S!also:a"[..], b"a"] {
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                assert_eq!(got.payload, want);
            }
            // Toward the client: the acknowledgement, through the other handler.
            let got = read_frame(&mut wire.client)
                .await
                .expect("read")
                .expect("frame");
            assert_eq!(got.payload, b"C(ack:a)!");
            // Both are in the capture, each under the direction it went.
            let kept: Vec<(&str, String)> = state
                .ws_frames
                .lock()
                .unwrap()
                .iter()
                .filter(|f| f.session == 7)
                .map(|f| (f.dir, f.preview.clone()))
                .collect();
            let kept: Vec<(&str, &str)> = kept.iter().map(|(d, p)| (*d, p.as_str())).collect();
            assert_eq!(
                kept,
                [
                    ("receive", "C(ack:a)!"),
                    ("send", "S!also:a"),
                    ("send", "a")
                ]
            );
            finish(wire).await;
        });
    }

    /// What a handler returns, as upstream's `util.toBuffer` reads it: an
    /// object is its JSON, a number its digits, and nothing — `undefined`,
    /// `null`, `0`, `''` — drops the frame. A handler that throws puts its
    /// message where the frame was, which is how its author finds out.
    #[test]
    fn what_a_handler_returns_is_what_is_delivered() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let script = "var n = 0; ctx.handleSendToServerFrame = function (buf) { \
                n++; \
                if (n === 1) return { a: 1 }; \
                if (n === 2) return 7; \
                if (n === 3) return 0; \
                if (n === 4) return ''; \
                if (n === 5) return undefined; \
                if (n === 6) throw new Error('boom'); \
                return 'last'; };";
            let mut wire = spawn_tunnel(&state, plan, Some(script.to_string()));
            for payload in [b"1", b"2", b"3", b"4", b"5", b"6", b"7"] {
                write_frame(&mut wire.client, true, OPCODE_TEXT, payload, true)
                    .await
                    .expect("client write");
            }
            let mut seen = Vec::new();
            for _ in 0..4 {
                let got = read_frame(&mut wire.server)
                    .await
                    .expect("read")
                    .expect("frame");
                seen.push(String::from_utf8(got.payload).unwrap());
            }
            assert_eq!(
                seen,
                ["{\"a\":1}", "7", "boom (handleSendToServerFrame)", "last"]
            );
            finish(wire).await;
        });
    }

    /// A script with nothing to say about a direction is not asked about it,
    /// and a script that throws while it is evaluated is no script at all.
    #[test]
    fn a_script_that_installs_nothing_leaves_the_frames_alone() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            for script in [
                // Only the other direction.
                "ctx.handleSendToClientFrame = function (buf) { return 'C' + buf; };",
                // Threw before it finished: its handler is not kept.
                "ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; }; throw new Error('early');",
                // Does not say `ctx`.
                "var unused = 1;",
                // Never ends: stopped, and then no script.
                "ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; }; while (true) {}",
            ] {
                let plan = plan_for(&state, "ws.test enable://websocket\n");
                let mut wire = spawn_tunnel(&state, plan, Some(script.to_string()));
                let seen = through(&mut wire, &[(OPCODE_TEXT, b"same"), (OPCODE_BINARY, b"\x01")]).await;
                assert_eq!(
                    seen,
                    [(OPCODE_TEXT, b"same".to_vec()), (OPCODE_BINARY, vec![1])],
                    "{script}"
                );
                finish(wire).await;
            }
        });
    }

    /// A handler still running at the time limit ends the script for its
    /// connection: that frame, and every one after it, goes through as it
    /// came. It used to hold the connection — and a thread at full speed —
    /// for as long as the loop lasted, which here is for ever.
    #[test]
    fn a_handler_out_of_time_ends_the_script_and_the_frames_go_through() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let script = "ctx.handleSendToServerFrame = function (buf) {\n\
                              function f() { for (var i = 0; i < 2000000; i++) {} }\n\
                              for (var j = 0; j < 2000000; j++) f();\n\
                              return 'X' + buf;\n\
                          };";
            let plan = plan_for(&state, "ws.test enable://websocket\n");
            let mut wire = spawn_tunnel(&state, plan, Some(script.to_string()));
            let started = std::time::Instant::now();
            let seen = through(&mut wire, &[(OPCODE_TEXT, b"one"), (OPCODE_TEXT, b"two")]).await;
            assert_eq!(
                seen,
                [
                    (OPCODE_TEXT, b"one".to_vec()),
                    (OPCODE_TEXT, b"two".to_vec())
                ]
            );
            assert!(
                started.elapsed()
                    < crate::proxy::script::TIME_LIMIT + std::time::Duration::from_secs(3),
                "{:?}",
                started.elapsed()
            );
            finish(wire).await;
        });
    }

    // ── an inspected tunnel ──

    /// `enable://inspect` on a plain tunnel: each chunk is a frame, offered to
    /// the script, which keeps its state and may send bytes of its own.
    #[test]
    fn an_inspected_tunnel_runs_the_script_over_each_chunk() {
        rt().block_on(async {
            let state = state_with(crate::plugins::Plugins::new());
            let (mut client, client_io) = tokio::io::duplex(1 << 16);
            let (mut origin, origin_io) = tokio::io::duplex(1 << 16);
            let info = apply::build_req_info(
                "",
                "https",
                "db.test",
                5432,
                "/",
                &hyper::HeaderMap::new(),
                None,
            );
            let script = "\
                var n = 0;\
                ctx.sendToClient('greeting');\
                ctx.handleSendToServerFrame = function (buf, opts) {\
                    if (String(buf) === 'secret') { return null; }\
                    return 'N' + (++n) + ':' + buf;\
                };\
                ctx.handleSendToClientFrame = function (buf, opts) {\
                    return opts.frameScript ? buf : Buffer.concat([Buffer.from('<'), buf, Buffer.from('>')]);\
                };";
            let spec = FrameScriptSpec::for_request(script.to_string(), &info, "db.test", &Default::default());
            assert!(spec.is_some());
            let relay = tokio::spawn(inspected_relay(client_io, origin_io, spec, state.clone(), Some(9)));

            async fn read_some(from: &mut DuplexStream) -> Vec<u8> {
                let mut buf = vec![0u8; 256];
                let n = from.read(&mut buf).await.expect("read");
                buf.truncate(n);
                buf
            }
            // What the script sent while starting arrives first.
            assert_eq!(read_some(&mut client).await, b"greeting");
            for (chunk, want) in [(&b"one"[..], &b"N1:one"[..]), (b"two", b"N2:two")] {
                client.write_all(chunk).await.expect("write");
                assert_eq!(read_some(&mut origin).await, want);
            }
            // A chunk the handler refuses does not arrive; the next one does.
            client.write_all(b"secret").await.expect("write");
            // Bytes that are not text come back as the bytes they were.
            origin.write_all(&[0x00, 0xff]).await.expect("write");
            assert_eq!(read_some(&mut client).await, [b'<', 0x00, 0xff, b'>']);
            client.write_all(b"three").await.expect("write");
            assert_eq!(read_some(&mut origin).await, b"N3:three");

            // Closing one side closes the other, as a plain relay's would.
            drop(client);
            assert_eq!(read_some(&mut origin).await, b"");
            drop(origin);
            relay.await.expect("task").expect("relay");

            // Each chunk that was delivered is a frame of the tunnel's session.
            let frames = state.ws_frames.lock().unwrap();
            let kept: Vec<(&str, &str, &str)> = frames
                .iter()
                .filter(|f| f.session == 9)
                .map(|f| (f.dir, f.opcode, f.preview.as_str()))
                .collect();
            assert_eq!(
                kept,
                [
                    ("receive", "text", "greeting"),
                    ("send", "text", "N1:one"),
                    ("send", "text", "N2:two"),
                    ("receive", "binary", "3c00ff3e"),
                    ("send", "text", "N3:three"),
                ]
            );
        });
    }

    /// With no script an inspected tunnel is a relay that shows what it
    /// carried; with no session to show it under, it keeps nothing.
    #[test]
    fn an_inspected_tunnel_with_no_script_only_records() {
        rt().block_on(async {
            for session in [Some(11u64), None] {
                let state = state_with(crate::plugins::Plugins::new());
                let (mut client, client_io) = tokio::io::duplex(1 << 16);
                let (mut origin, origin_io) = tokio::io::duplex(1 << 16);
                let relay = tokio::spawn(inspected_relay(
                    client_io,
                    origin_io,
                    None,
                    state.clone(),
                    session,
                ));
                client.write_all(b"ping").await.expect("write");
                let mut buf = [0u8; 16];
                let n = origin.read(&mut buf).await.expect("read");
                assert_eq!(&buf[..n], b"ping");
                origin.write_all(b"pong").await.expect("write");
                let n = client.read(&mut buf).await.expect("read");
                assert_eq!(&buf[..n], b"pong");
                drop(client);
                drop(origin);
                relay.await.expect("task").expect("relay");
                let kept = state.ws_frames.lock().unwrap().len();
                assert_eq!(kept, if session.is_some() { 2 } else { 0 });
            }
        });
    }

    /// The console's own frame: written into a live connection, masked the way
    /// a real frame from that side would be.
    #[tokio::test]
    async fn the_console_can_write_into_a_live_session() {
        let (to_server, mut server) = tokio::io::duplex(4096);
        let (to_client, mut client) = tokio::io::duplex(4096);
        let writers = SessionWriters::new(to_server, to_client);

        assert!(writers.send("send", b"to the server").await);
        let frame = read_frame(&mut server).await.expect("read").expect("frame");
        assert_eq!(frame.opcode, OPCODE_TEXT);
        assert_eq!(frame.payload, b"to the server");

        assert!(writers.send("receive", b"to the client").await);
        let frame = read_frame(&mut client).await.expect("read").expect("frame");
        assert_eq!(frame.payload, b"to the client");

        // A direction nobody has is not a direction.
        assert!(!writers.send("sideways", b"nowhere").await);
    }

    /// A frame from the client is **masked** and one from the server is not
    /// (RFC 6455 §5.3), and the console's frames have to look the same or the
    /// peer would know where they came from.
    #[tokio::test]
    async fn a_console_frame_is_masked_like_a_real_one() {
        let (to_server, mut server) = tokio::io::duplex(4096);
        let (to_client, mut client) = tokio::io::duplex(4096);
        let writers = SessionWriters::new(to_server, to_client);

        writers.send("send", b"abc").await;
        let mut head = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut head)
            .await
            .expect("head");
        assert_eq!(head[1] & 0x80, 0x80, "a client frame is masked");

        writers.send("receive", b"abc").await;
        let mut head = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut head)
            .await
            .expect("head");
        assert_eq!(head[1] & 0x80, 0, "a server frame is not masked");
    }

    /// Only whole messages can be dropped outright.
    #[test]
    fn drop_policy() {
        // A complete message: gone.
        assert!(dropped(true, OPCODE_TEXT).is_none());
        assert!(dropped(true, OPCODE_BINARY).is_none());
        // The first fragment of one, and the last: emptied, never removed.
        assert_eq!(dropped(false, OPCODE_TEXT), Some(Bytes::new()));
        assert_eq!(dropped(true, OPCODE_CONTINUATION), Some(Bytes::new()));
        assert_eq!(dropped(false, OPCODE_CONTINUATION), Some(Bytes::new()));
    }

    /// Data frames reach hooks; control and reserved opcodes do not.
    #[test]
    fn only_data_frames_are_hooked() {
        for opcode in [OPCODE_CONTINUATION, OPCODE_TEXT, OPCODE_BINARY] {
            assert!(is_data_frame(opcode));
        }
        for opcode in [0x3, 0x7, OPCODE_CLOSE, 0x9, 0xa, 0xf] {
            assert!(!is_data_frame(opcode));
        }
    }
}
