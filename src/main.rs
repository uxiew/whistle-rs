//! CLI entry point, mirroring `_original/bin/whistle.js` for the options the
//! Rust core supports.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use whistle_rs::ca::CertAuthority;
use whistle_rs::config::{Config, DATA_DIRNAME};
use whistle_rs::proxy::{self, AppState};
use whistle_rs::rules::RuleManager;

/// HTTP/HTTPS/WebSocket debugging proxy (Rust port of whistle).
#[derive(Parser, Debug)]
#[command(name = "whistle-rs", version, about)]
struct Cli {
    /// Proxy port (whistle default: 8899).
    #[arg(short = 'p', long, default_value_t = whistle_rs::config::DEFAULT_PORT)]
    port: u16,

    /// Bind address (default: all interfaces).
    #[arg(short = 'H', long)]
    host: Option<IpAddr>,

    /// Also run an inbound SOCKS5 server on this port.
    #[arg(long)]
    socks_port: Option<u16>,

    /// Register a remote plugin as `name=host:port` (repeatable). Routes
    /// `plugin://name` rules to an already-running HTTP plugin (Node or any).
    #[arg(long = "plugin", value_name = "NAME=HOST:PORT")]
    plugins: Vec<String>,

    /// Spawn a Node plugin as `name=path/to/plugin.js` (repeatable). whistle-rs
    /// runs `node <path>`, assigns it a port (via `WHISTLE_RS_PLUGIN_PORT`), and
    /// routes `plugin://name` to it.
    #[arg(long = "node-plugin", value_name = "NAME=PATH")]
    node_plugins: Vec<String>,

    /// Define a named value as `name=content` (repeatable). Referenced by
    /// `{name}` in operator values and by `rule://name`.
    #[arg(long = "value", value_name = "NAME=CONTENT")]
    values: Vec<String>,

    /// Path to a whistle rules file to load at startup.
    #[arg(short = 'r', long)]
    rules: Option<PathBuf>,

    /// Inline rules text (whistle DSL), applied after `--rules`.
    #[arg(long)]
    rule: Option<String>,

    /// Storage directory for the root CA etc. (default: ~/.whistle-rs).
    #[arg(long)]
    dir: Option<PathBuf>,

    /// Max bytes of each captured body kept for the inspection preview.
    #[arg(long, default_value_t = whistle_rs::config::DEFAULT_BODY_PREVIEW_CAP)]
    body_preview_limit: usize,

    /// Disable session persistence to disk.
    #[arg(long)]
    no_persist: bool,

    /// Do not verify the origin server's TLS certificate.
    ///
    /// whistle never verifies unless started with `--safe`; whistle-rs verifies
    /// by default and this opts out. Needed for self-signed or private-CA
    /// origins — and it means this proxy can no longer tell you when the
    /// connection it is inspecting has itself been intercepted.
    #[arg(long)]
    insecure_upstream: bool,

    /// Days of session history to retain on disk.
    #[arg(long, default_value_t = whistle_rs::config::DEFAULT_PERSIST_DAYS)]
    persist_days: u32,

    /// Do not decrypt HTTPS: relay every TLS connection untouched.
    ///
    /// The connection is still *routed* by its rules — `host://` and the proxy
    /// family apply — but nothing inside it is read, so no certificate has to be
    /// trusted and no request/response operator can run. whistle spells this
    /// `-M pureProxy`.
    #[arg(long)]
    no_intercept_https: bool,

    /// Request timeout in milliseconds (whistle's `-t`).
    ///
    /// Caps how long a connection to an origin or an upstream proxy may take to
    /// establish — a destination that drops packets otherwise holds the request
    /// for as long as the operating system's TCP timeout, which is over a
    /// minute. It never cuts short a connection that *did* establish, so a slow
    /// response or a long-lived stream is unaffected.
    #[arg(short = 't', long, default_value_t = whistle_rs::config::DEFAULT_TIMEOUT_MS)]
    timeout: u64,

    /// Verbose (debug) logging.
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_target(false)
        .init();

    // rustls needs a crypto provider installed before any TLS is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let storage_dir = cli.dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DATA_DIRNAME)
    });
    std::fs::create_dir_all(&storage_dir)
        .with_context(|| format!("creating storage dir {}", storage_dir.display()))?;

    let mut plugins = std::collections::HashMap::new();
    for spec in &cli.plugins {
        if let Some((name, addr)) = spec.split_once('=') {
            plugins.insert(name.trim().to_string(), addr.trim().to_string());
        } else {
            anyhow::bail!("invalid --plugin '{spec}', expected name=host:port");
        }
    }

    let mut values = std::collections::HashMap::new();
    for spec in &cli.values {
        if let Some((name, content)) = spec.split_once('=') {
            values.insert(name.trim().to_string(), content.to_string());
        } else {
            anyhow::bail!("invalid --value '{spec}', expected name=content");
        }
    }

    let config = Config {
        port: cli.port,
        host: cli.host,
        storage_dir,
        socks_port: cli.socks_port,
        plugins,
        values,
        body_preview_cap: cli.body_preview_limit,
        persist_sessions: !cli.no_persist,
        persist_days: cli.persist_days,
        timeout_ms: cli.timeout,
        intercept_https: !cli.no_intercept_https,
        ..Config::default()
    };

    // Load rules (resolving `@url` / `@file` includes first).
    let mut rules_text = String::new();
    let mut base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(path) = &cli.rules {
        rules_text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules file {}", path.display()))?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            base_dir = parent.to_path_buf();
        }
    }
    if let Some(inline) = &cli.rule {
        rules_text.push('\n');
        rules_text.push_str(inline);
    }
    let rules_text = expand_at_includes(&rules_text, &base_dir).await;
    let mut manager = RuleManager::new();
    manager.set_text(&rules_text);

    // Load any persisted rule groups from disk (added via the UI).
    let rules_dir = config.data_dir().join("rules");
    whistle_rs::rules::storage::load_groups(&rules_dir, &mut manager);
    tracing::info!("loaded {} rules ({} groups)", manager.len(), manager.groups().len());

    let ca = CertAuthority::load_or_create(&config).context("initialising root CA")?;

    // Build the plugin registry: built-in Rust plugins + `--plugin` remotes +
    // spawned `--node-plugin` subprocesses.
    let mut registry = whistle_rs::plugins::Plugins::new();
    for (name, addr) in &config.plugins {
        registry.register_remote(name, addr);
    }
    let mut children = Vec::new();
    let mut node_ports = Vec::new();
    for spec in &cli.node_plugins {
        let (name, path) = spec
            .split_once('=')
            .with_context(|| format!("invalid --node-plugin '{spec}', expected name=path.js"))?;
        let (name, path) = (name.trim(), path.trim());
        let port = free_port().context("allocating a port for a node plugin")?;
        let child = tokio::process::Command::new("node")
            .arg(path)
            .env("WHISTLE_RS_PLUGIN_PORT", port.to_string())
            .env("WHISTLE_RS_PLUGIN_NAME", name)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawning node plugin '{name}' ({path})"))?;
        children.push(child);
        node_ports.push((name.to_string(), port));
        registry.register_remote(name, &format!("127.0.0.1:{port}"));
        tracing::info!("spawned node plugin '{name}' -> node {path} on 127.0.0.1:{port}");
    }
    // Wait for spawned plugins to start listening so early requests don't miss
    // them (best-effort, ~5s cap per plugin).
    for (name, port) in &node_ports {
        if wait_for_port(*port, std::time::Duration::from_secs(5)).await {
            tracing::info!("node plugin '{name}' ready on 127.0.0.1:{port}");
        } else {
            tracing::warn!("node plugin '{name}' not ready after 5s (continuing)");
        }
    }
    tracing::info!("plugins: {}", registry.names().join(", "));

    whistle_rs::proxy::upstream::set_request_timeout(cli.timeout);
    whistle_rs::proxy::upstream::set_insecure_upstream(cli.insecure_upstream);
    if cli.insecure_upstream {
        tracing::warn!(
            "--insecure-upstream: origin certificates are NOT verified; \
             an intercepted upstream connection will look identical to a genuine one"
        );
    }

    let mut state = AppState::with_plugins(config, manager, ca, registry);

    // Session persistence: load history and enable runtime writes.
    if state.config.persist_sessions {
        let sessions_dir = state.config.sessions_dir();
        let loaded = whistle_rs::proxy::persist::SessionStore::load(
            &sessions_dir,
            whistle_rs::proxy::MAX_SESSIONS,
        );
        if !loaded.is_empty() {
            let max_id = loaded.iter().map(|s| s.id).max().unwrap_or(0);
            let mut q = state.sessions.lock().unwrap();
            for s in loaded {
                q.push_back(s);
            }
            state.set_next_id(max_id + 1);
            tracing::info!("loaded {} sessions from disk", q.len());
        }
        let store = whistle_rs::proxy::persist::SessionStore::new(
            sessions_dir,
            state.config.persist_days,
        );
        state.enable_persistence(store);
    }

    let state = Arc::new(state);

    // Keep the spawned Node plugin processes alive for the server's lifetime.
    let _children = children;
    proxy::run(state).await
}

/// Grab a free TCP port on localhost (for a spawned plugin to bind).
fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Expand whistle `@` includes: a line `@<url|file>` is replaced by the rules
/// fetched from that URL or read from that file (one level, best-effort).
/// Ported from `REMOTE_RULES_RE` in the original util.
async fn expand_at_includes(text: &str, base: &std::path::Path) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let target = trimmed
            .strip_prefix('@')
            .map(|r| r.trim().trim_matches('`').trim());
        match target {
            Some(t) if !t.is_empty() && !t.starts_with('#') => match fetch_include(t, base).await {
                Some(rules) => {
                    tracing::info!("included rules from @{t}");
                    out.push_str(rules.trim_end());
                    out.push('\n');
                }
                None => tracing::warn!("could not resolve @{t}"),
            },
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Fetch the rules text for one `@` include (http(s) URL or local file path).
async fn fetch_include(target: &str, base: &std::path::Path) -> Option<String> {
    if target.starts_with("http://") || target.starts_with("https://") {
        let (status, bytes) = whistle_rs::proxy::upstream::simple_get(target).await.ok()?;
        return (status == 200).then(|| String::from_utf8_lossy(&bytes).into_owned());
    }
    if target.starts_with("whistle.") {
        tracing::warn!("@{target}: plugin-provided rules are not supported yet");
        return None;
    }
    // Local path: absolute, ~-home, or relative to the rules file's directory.
    let path = if let Some(rest) = target.strip_prefix("~/") {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(rest)
    } else {
        let p = PathBuf::from(target);
        if p.is_absolute() {
            p
        } else {
            base.join(p)
        }
    };
    std::fs::read_to_string(path).ok()
}

/// Poll `127.0.0.1:port` until it accepts a connection or `timeout` elapses.
async fn wait_for_port(port: u16, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}
