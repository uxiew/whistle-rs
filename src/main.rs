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
        ..Config::default()
    };

    // Load rules.
    let mut manager = RuleManager::new();
    if let Some(path) = &cli.rules {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules file {}", path.display()))?;
        manager.set_text(&text);
        tracing::info!("loaded {} rules from {}", manager.len(), path.display());
    }
    if let Some(inline) = &cli.rule {
        manager.append_text(inline);
    }

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

    let state = Arc::new(AppState::with_plugins(config, manager, ca, registry));

    // Keep the spawned Node plugin processes alive for the server's lifetime.
    let _children = children;
    proxy::run(state).await
}

/// Grab a free TCP port on localhost (for a spawned plugin to bind).
fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
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
