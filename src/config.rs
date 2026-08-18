//! Runtime configuration, ported from `_original/lib/config.js` (the subset that
//! the Rust core currently honours). Values mirror whistle's defaults so the CLI
//! behaves the same way from the user's point of view.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Package defaults taken verbatim from `_original/package.json`.
pub const DEFAULT_PORT: u16 = 8899;
pub const DEFAULT_TIMEOUT_MS: u64 = 360_000;
pub const DATA_DIRNAME: &str = ".whistle-rs";
pub const NAME: &str = "whistle-rs";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The whole running configuration. In the original this is a giant mutable
/// singleton; here it is an immutable value built once from CLI args.
#[derive(Debug, Clone)]
pub struct Config {
    /// Main proxy port (HTTP proxy + CONNECT). whistle default: 8899.
    pub port: u16,
    /// Bind address. `None` => all interfaces (INADDR_ANY).
    pub host: Option<IpAddr>,
    /// Socket idle timeout.
    pub timeout_ms: u64,
    /// Storage directory (root CA, rules, etc.). whistle: `~/.whistle`.
    pub storage_dir: PathBuf,
    /// Whether HTTPS interception (MITM) is enabled by default. whistle only
    /// intercepts when told to; we expose a global switch for the core.
    pub intercept_https: bool,
    /// Inline rules text loaded at startup (`-r`/`--rules`), whistle's
    /// `config.rules`.
    pub rules: Option<String>,
    /// Console login — whistle's `-n/--username` and `-w/--password`.
    ///
    /// With neither set the console is open, which is upstream's default and
    /// its own test: `if (!username && !password) return true`
    /// (`_original/biz/webui/lib/index.js:161-163`).
    pub ui_username: Option<String>,
    pub ui_password: Option<String>,
    /// The read-only account — `-N/--guestName` and `-W/--guestPassword`. It
    /// may `GET`; anything that writes needs the full login
    /// (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`).
    pub guest_username: Option<String>,
    pub guest_password: Option<String>,
    /// Optional separate port for the console — whistle's `-P/--uiport`.
    ///
    /// `None` (or the proxy's own port) means the console is served on the
    /// proxy port, which is upstream's default: `config.uiport = config.port`
    /// unless the flag moved it, and only a *different* value starts a second
    /// server (`customUIPort`, `_original/biz/init.js:8-19`).
    pub ui_port: Option<u16>,
    /// Extra hostnames that **are** the console rather than somewhere to
    /// forward to — whistle's `-l/--localUIHost`, which appends to a built-in
    /// list rather than replacing it (`uiHostList`,
    /// `_original/lib/config.js:1040-1054`). Lower-cased on the way in; the
    /// built-in three live in [`crate::proxy::webui::BUILTIN_UI_HOSTS`].
    pub local_ui_hosts: Vec<String>,
    /// Optional inbound SOCKS5 port (whistle's `socksPort`).
    pub socks_port: Option<u16>,
    /// Registered plugin servers: name → `host:port` (whistle plugin servers).
    pub plugins: HashMap<String, String>,
    /// Named values (whistle's Values store): name → content. Referenced by
    /// `{name}` in operator values and by `rule://name`.
    pub values: HashMap<String, String>,
    /// Max bytes of each captured body kept for the inspection preview.
    pub body_preview_cap: usize,
    /// Max bytes of a **response** body this proxy will hold in memory in order
    /// to rewrite it. See [`DEFAULT_BODY_REWRITE_CAP`].
    pub body_rewrite_cap: usize,
    /// Whether to persist captured sessions to disk (JSONL).
    pub persist_sessions: bool,
    /// Number of days of session JSONL files to retain.
    pub persist_days: u32,
    /// How many captured transactions to keep in memory — whistle's
    /// `-R/--reqCacheSize`. Floored at 600 there and here
    /// (`_original/lib/util/data-server.js:10-12`).
    pub req_cache_size: usize,
    /// How many captured WebSocket frames to keep in memory — whistle's
    /// `-F/--frameCacheSize`. Upstream's floor is the odd one: anything under
    /// **720** becomes 600 (`data-server.js:14-16`), so the flag can only ever
    /// raise the number.
    pub frame_cache_size: usize,
}

impl Config {
    pub fn data_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// Path of the persisted root CA certificate (PEM).
    pub fn root_ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join("certs").join("root.crt")
    }

    /// Path of the persisted root CA private key (PEM).
    pub fn root_ca_key_path(&self) -> PathBuf {
        self.storage_dir.join("certs").join("root.key")
    }

    /// Directory for persisted session JSONL files.
    pub fn sessions_dir(&self) -> PathBuf {
        self.storage_dir.join("sessions")
    }
}

impl Default for Config {
    fn default() -> Self {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Config {
            port: DEFAULT_PORT,
            host: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            storage_dir: base.join(DATA_DIRNAME),
            intercept_https: true,
            rules: None,
            ui_username: None,
            ui_password: None,
            guest_username: None,
            guest_password: None,
            ui_port: None,
            local_ui_hosts: Vec::new(),
            socks_port: None,
            plugins: HashMap::new(),
            values: HashMap::new(),
            body_preview_cap: DEFAULT_BODY_PREVIEW_CAP,
            body_rewrite_cap: DEFAULT_BODY_REWRITE_CAP,
            persist_sessions: true,
            persist_days: DEFAULT_PERSIST_DAYS,
            req_cache_size: DEFAULT_REQ_CACHE_SIZE,
            frame_cache_size: DEFAULT_FRAME_CACHE_SIZE,
        }
    }
}

/// Default preview cap: 16 KB of each body kept for inspection.
pub const DEFAULT_BODY_PREVIEW_CAP: usize = 16 * 1024;

/// Default ceiling on a response body held in memory to rewrite it: 16 MiB.
///
/// **This bound exists because this port's body layer is buffered and whistle's
/// is not.** whistle rewrites a response with stream transforms
/// (`addTextTransform` / `addZipTransform`, `_original/lib/inspectors/res.js`),
/// so a rule never costs it the body; the one place it accumulates —
/// `resMerge://` — carries an explicit ceiling of its own (`MAX_RES_SIZE`,
/// `res.js:21-22`). Here any body operator collects the whole response, and
/// measured against an 800 MB download with a single `resReplace://` matching,
/// resident memory went from 9.9 MB to **1.97 GB**.
///
/// 16 MiB is upstream's own "big data" number (`BIG_MAX_RES_SIZE`), which is
/// generous for the pages, bundles and JSON payloads rewriting is actually
/// aimed at, and far below the point where a download costs the proxy its life.
/// Past it the response streams through untouched — see
/// `crate::proxy::body::collect_capped`.
pub const DEFAULT_BODY_REWRITE_CAP: usize = 16 * 1024 * 1024;

/// Default number of days to retain persisted session files.
pub const DEFAULT_PERSIST_DAYS: u32 = 7;

/// Captured transactions kept in memory, and whistle's own default and floor
/// (`-R/--reqCacheSize`, `_original/lib/util/data-server.js:10-12`). This port
/// used to keep 500, so the console showed a shorter history than whistle's for
/// the same traffic.
pub const DEFAULT_REQ_CACHE_SIZE: usize = 600;

/// Captured WebSocket frames kept in memory (`-F/--frameCacheSize`,
/// `data-server.js:14-16`). 600 is upstream's default; its floor is written
/// against **720**, so a smaller flag value lands back on 600 rather than on
/// itself — see [`Config::frame_cache_size`].
pub const DEFAULT_FRAME_CACHE_SIZE: usize = 600;

/// Apply whistle's floor to a `-R` value: under its default, the default wins.
pub fn clamp_req_cache_size(n: usize) -> usize {
    n.max(DEFAULT_REQ_CACHE_SIZE)
}

/// Apply whistle's floor to a `-F` value. The comparison is against 720 and the
/// result is 600 — upstream's own asymmetry, kept because a user who copies a
/// `-F 700` from one proxy to the other should get the same buffer.
pub fn clamp_frame_cache_size(n: usize) -> usize {
    match n >= 720 {
        true => n,
        false => DEFAULT_FRAME_CACHE_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two capture caps, and the floors whistle applies to them
    /// (`_original/lib/util/data-server.js:10-16`). The `-F` floor is written
    /// against 720 and answers 600, which is upstream's own asymmetry rather
    /// than a transcription slip.
    #[test]
    fn a_capture_cap_cannot_be_set_below_its_floor() {
        assert_eq!(clamp_req_cache_size(0), 600);
        assert_eq!(clamp_req_cache_size(1), 600);
        assert_eq!(clamp_req_cache_size(599), 600);
        assert_eq!(clamp_req_cache_size(600), 600);
        assert_eq!(clamp_req_cache_size(5000), 5000);

        assert_eq!(clamp_frame_cache_size(0), 600);
        assert_eq!(clamp_frame_cache_size(600), 600);
        assert_eq!(clamp_frame_cache_size(719), 600);
        assert_eq!(clamp_frame_cache_size(720), 720);
        assert_eq!(clamp_frame_cache_size(5000), 5000);
    }
}
