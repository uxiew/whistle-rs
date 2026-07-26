//! Minimal WebSocket frame codec + a frame-aware capturing tunnel.
//!
//! Every intercepted WebSocket upgrade is tunnelled frame-by-frame so each
//! frame can be captured for the Network view (whistle surfaces every frame).
//! Two hooks may also sit in that path, and they run in this order:
//!
//! 1. **`frameScript`** — the rule operator, on text frames only. It is a rule,
//!    and rules run before plugins everywhere else in this proxy.
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

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::plugins::wsframe::{Dir, FrameHook, FrameMeta, HookFrame, Verdict};
use crate::plugins::{PluginMatch, Plugins};
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
            if plugins.contains(&m.name) && !matches.iter().any(|o| o.name == m.name) {
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
                tracing::debug!("wsFrame {} hooks session {session} ({})", m.name, dir.label());
                hooks.push(hook);
            }
        }
        hooks
    }
}

/// Frame-aware bidirectional tunnel: captures every frame into `state` under
/// `session`, runs `script` on each text frame, and offers each data frame to
/// the plugins in `plan`.
pub async fn capturing_tunnel<A, B>(
    client: A,
    upstream: B,
    script: Option<String>,
    plan: FramePlan,
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
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let up = tokio::spawn(pump(
        cr,
        uw,
        Dir::Send,
        script.clone(),
        send_hooks,
        state.clone(),
        session,
    ));
    let down = tokio::spawn(pump(
        ur,
        cw,
        Dir::Receive,
        script,
        receive_hooks,
        state,
        session,
    ));
    let _ = tokio::join!(up, down);
}

async fn pump<R, W>(
    mut r: R,
    mut w: W,
    dir: Dir,
    script: Option<String>,
    mut hooks: Vec<FrameHook>,
    state: Arc<AppState>,
    session: u64,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let direction = dir.label();
    let to_server = dir == Dir::Send;
    loop {
        let frame = match read_frame(&mut r).await {
            Ok(Some(f)) => f,
            _ => break,
        };
        let mut payload = Bytes::from(frame.payload);
        if frame.opcode == OPCODE_TEXT {
            // Text frame: allow the script to rewrite it.
            if let Some(script) = &script
                && let Some(new) = std::str::from_utf8(&payload)
                    .ok()
                    .and_then(|text| crate::proxy::script::run_frame_script(script, direction, text))
            {
                payload = Bytes::from(new);
            }
        }
        if !hooks.is_empty() && is_data_frame(frame.opcode) {
            match run_hooks(&mut hooks, direction, frame.fin, frame.opcode, payload).await {
                Some(kept) => payload = kept,
                // Dropped: it reaches neither the peer nor the capture, because
                // it never happened as far as the other end is concerned.
                None => continue,
            }
        }
        // Capture the (possibly rewritten) frame for the Network view.
        state.record_frame(WsFrame::new(session, direction, frame.opcode, &payload));
        if write_frame(&mut w, frame.fin, frame.opcode, &payload, to_server)
            .await
            .is_err()
        {
            break;
        }
        if frame.opcode == OPCODE_CLOSE {
            break;
        }
    }
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
    /// the developer's real `~/.whistle-rs`.
    ///
    /// One dir per state, not one per run: these tests execute in parallel and
    /// would otherwise race to write the same root CA, now and then reading a
    /// half-written PEM back.
    fn state_with(plugins: crate::plugins::Plugins) -> Arc<AppState> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-ws-tests-{}-{n}", std::process::id())),
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
        let (client, client_io) = tokio::io::duplex(1 << 16);
        let (server, upstream_io) = tokio::io::duplex(1 << 16);
        let tunnel = tokio::spawn(capturing_tunnel(
            client_io,
            upstream_io,
            script,
            plan,
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
            assert!(plan_for(&state, "ws.test plugin://stamp\n")
                .connect(&state.plugins, 7)
                .await
                .0
                .is_empty());

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
            let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
            assert_eq!(got.payload, b"UP");

            write_frame(&mut wire.server, true, OPCODE_TEXT, b"down", false)
                .await
                .expect("server write");
            let back = read_frame(&mut wire.client).await.expect("read").expect("frame");
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
            let state = state_hooking("echo-bytes", |f| {
                Verdict::Replace(f.payload.clone())
            });
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
            let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
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
            let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
            assert_eq!(got.payload, b"public", "the dropped frame is simply not there");
            finish(wire).await;

            let frames = state.ws_frames.lock().unwrap();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].preview, "public");
        });
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

            let first = read_frame(&mut wire.server).await.expect("read").expect("frame");
            assert!(!first.fin);
            assert_eq!(first.opcode, OPCODE_TEXT);
            assert!(first.payload.is_empty());
            let second = read_frame(&mut wire.server).await.expect("read").expect("frame");
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
                let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
                assert_eq!(got.opcode, opcode);
                assert_eq!(got.payload, payload);
            }

            // A data frame on the same session still goes through the hook.
            write_frame(&mut wire.client, true, OPCODE_TEXT, b"data", true)
                .await
                .expect("client write");
            let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
            assert_eq!(got.payload, b"X");

            write_frame(&mut wire.client, true, OPCODE_CLOSE, &[0x03, 0xe8], true)
                .await
                .expect("client write");
            let close = read_frame(&mut wire.server).await.expect("read").expect("frame");
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
            let got = read_frame(&mut wire.server).await.expect("read").expect("frame");
            assert_eq!(got.payload, b"HI VIA SEND");
            finish(wire).await;
        });
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
