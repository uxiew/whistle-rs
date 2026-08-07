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
            socks_port: None,
            plugins: HashMap::new(),
            values: HashMap::new(),
            body_preview_cap: DEFAULT_BODY_PREVIEW_CAP,
            body_rewrite_cap: DEFAULT_BODY_REWRITE_CAP,
            persist_sessions: true,
            persist_days: DEFAULT_PERSIST_DAYS,
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
