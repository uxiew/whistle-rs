//! The state every connection shares: configuration, rules, values, the root
//! CA, plugins, and the in-memory session list with its observers.

use super::*;
use std::sync::atomic::AtomicBool;

/// Maximum number of captured transactions kept in memory, when nothing says
/// otherwise — [`crate::config::Config::req_cache_size`] is what the running
/// proxy reads, and `-R/--req-cache-size` is how a user changes it.
pub const MAX_SESSIONS: usize = crate::config::DEFAULT_REQ_CACHE_SIZE;

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
    /// What the pages a `log://` rule matched have written to their consoles —
    /// see [`pagelog`]. Bounded; the console's Console pane reads it.
    pub page_logs: Mutex<pagelog::PageLogs>,
    /// The console's HTTPS switch, as it stands now: starts at what the command
    /// line said (`config.intercept_https`) and can be flipped while running —
    /// upstream's `interceptHttpsConnects`. Read through
    /// [`AppState::intercepts_https`], which also knows when a mode has taken
    /// the switch away.
    pub(super) intercept_https: AtomicBool,
    pub(super) next_id: AtomicU64,
    /// Optional session persistence (JSONL on disk).
    pub(super) session_store: Option<persist::SessionStore>,
    /// Told about every completed transaction, for a program that has embedded
    /// this proxy and wants the traffic rather than the console. Set once,
    /// before serving; see [`AppState::observe`].
    pub(super) observer: std::sync::OnceLock<SessionObserver>,
    /// The storage directory, held for as long as this state lives — which is
    /// as long as anything can still write history into it. Set by an
    /// embedded proxy that keeps history; the binary holds its own in `main`.
    pub(crate) dir_lock: Option<crate::dir_lock::DirLock>,
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
        // The locks are the command line's, and outrank anything a previous run
        // switched off and saved: they are applied here, last, so the order the
        // caller restored things in cannot get round them.
        let mut rules = rules;
        if config.rules_switch_locked {
            rules.set_all_off(false);
        }
        if config.plugins_switch_locked {
            plugins.lock_switches();
        }
        let intercept_https = AtomicBool::new(config.intercept_https);
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
            page_logs: Mutex::new(pagelog::PageLogs::default()),
            intercept_https,
            next_id: AtomicU64::new(1),
            session_store: None,
            observer: std::sync::OnceLock::new(),
            dir_lock: None,
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

    /// Fetch every remote plugin's manifest in the background, one task each,
    /// so the rules a plugin brings apply from the first request — see
    /// [`crate::plugins::Plugins::static_rules`]. Needs a tokio runtime.
    pub fn warm_up_plugins(self: &Arc<Self>) {
        for name in self.plugins.remote_names() {
            let state = self.clone();
            tokio::spawn(async move { state.plugins.warm_up(&name).await });
        }
    }

    /// Is HTTPS intercepted for connections no rule speaks for? The console's
    /// switch as it stands now, unless `-M multiEnv` or
    /// `-M notAllowedEnableHTTPS` has taken it away — see
    /// [`Config::intercepts_https`], which answers the same question about the
    /// command line alone.
    pub fn intercepts_https(&self) -> bool {
        self.intercept_https.load(Ordering::Relaxed) && !self.config.capture_locked_off
    }

    /// Flip the HTTPS switch. Refused while a mode has taken it away, rather
    /// than recording a setting nothing would read.
    ///
    /// Only for this run: a restart goes back to what the command line says.
    /// Connections already open keep what they were given when they opened —
    /// a tunnel is decided once, at its `CONNECT`.
    pub fn set_intercept_https(&self, on: bool) -> Result<(), &'static str> {
        if self.config.capture_locked_off {
            return Err(
                "a mode has taken the HTTPS switch away (-M multiEnv or -M notAllowedEnableHTTPS)",
            );
        }
        self.intercept_https.store(on, Ordering::Relaxed);
        Ok(())
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
    pub(super) fn reserve_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Record a transaction that is already over — answered here, failed, or
    /// aborted. Returns its id.
    pub(super) fn record(&self, mut session: Session) -> u64 {
        let id = self.assign_id(&mut session);
        if !is_hidden(&session) {
            self.complete(&session);
            self.show(session);
        }
        id
    }

    /// [`Self::record`], saying whether there is now a session to look up:
    /// `None` for a hidden one. Its id names nothing, so a 502 or a log line
    /// that quoted it would send someone looking for a session that was
    /// never kept.
    pub(super) fn record_visible(&self, session: Session) -> Option<u64> {
        let hidden = is_hidden(&session);
        let id = self.record(session);
        (!hidden).then_some(id)
    }

    /// Record a transaction whose response is still arriving: it is in the
    /// console from now on, and [`Self::complete`] is owed the session
    /// returned once it is over — the observer and the history on disk get it
    /// then, with the whole body preview, every phase and, if it came to that,
    /// why it failed. `None` for a hidden one, which is owed nothing.
    pub(super) fn record_open(&self, mut session: Session) -> (u64, Option<Session>) {
        let id = self.assign_id(&mut session);
        if is_hidden(&session) {
            return (id, None);
        }
        // Shared with the copy in the ring, so the list says it is under way
        // until `complete` says otherwise.
        session.error.set_open(true);
        self.show(session.clone());
        (id, Some(session))
    }

    /// The id a session is recorded under: the one reserved for it, or the next.
    pub(super) fn assign_id(&self, session: &mut Session) -> u64 {
        if session.id == 0 {
            session.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        session.id
    }

    /// Put a session in the console's ring, evicting the oldest past the cap.
    pub(super) fn show(&self, session: Session) {
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
    pub(super) fn complete(&self, session: &Session) {
        session.error.set_open(false);
        if let Some(observe) = self.observer.get() {
            observe(session);
        }
        if let Some(store) = &self.session_store {
            store.persist(session);
        }
    }

    /// Wait until every completed session is on disk; see
    /// [`persist::SessionStore::flush`]. Nothing to wait for without history.
    pub async fn flush_history(&self) {
        if let Some(store) = &self.session_store {
            store.flush().await;
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
pub(super) fn is_hidden(session: &Session) -> bool {
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
