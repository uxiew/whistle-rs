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
        }
    }
}
