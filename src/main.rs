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

    /// Bind address (default: 127.0.0.1, this machine only). `-H 0.0.0.0` lets
    /// phones and other machines in — set a console login (-n/-w) first.
    #[arg(short = 'H', long)]
    host: Option<IpAddr>,

    /// Console login name (whistle's `-n/--username`).
    ///
    /// With no name and no password the console is open, as it is there.
    #[arg(short = 'n', long)]
    username: Option<String>,

    /// Console login password (whistle's `-w/--password`).
    #[arg(short = 'w', long)]
    password: Option<String>,

    /// Read-only console account (whistle's `-N/--guestName`): it may look at
    /// the capture and the rules, and may not change them.
    #[arg(short = 'N', long)]
    guest_name: Option<String>,

    /// Password for the read-only account (whistle's `-W/--guestPassword`).
    #[arg(short = 'W', long)]
    guest_password: Option<String>,

    /// Serve the console on its own port (whistle's `-P/--uiport`).
    ///
    /// Without it the console lives on the proxy port, which is where whistle
    /// keeps it too — `config.uiport = config.port`, and only a different value
    /// starts a second server (`_original/biz/init.js:8-19`). A separate port
    /// is what lets a client reach the console without going through the proxy,
    /// and what keeps `http://<proxy>/` free for the rules to answer.
    #[arg(short = 'P', long = "uiport")]
    ui_port: Option<u16>,

    /// Startup modes (whistle's `-M/--mode`), separated by `|`, `,` or `&`.
    ///
    /// whistle's vocabulary is fifty-six tokens, of which fifteen change
    /// anything a proxy client can see — measured, one whistle per token, by
    /// `tests/differential/mode-bench.js`. This honours the ones that mean
    /// something here:
    ///
    /// * `pureProxy` (`proxyOnly`, `httpProxy`) — stop answering for the console
    ///   hostnames and forward them like any other name;
    /// * `headless` (`shadowRulesOnly`) — no console at all, except the root
    ///   certificate and the PAC file;
    /// * `capture` (`intercept`, `enableCapture`, `enableHttps`,
    ///   `persistentCapture`) — intercept HTTPS, which is already the default
    ///   here; `disableCapture` is the off switch and is `--no-intercept-https`
    ///   under whistle's name;
    /// * `keepXFF` (`forwardedFor`) — let a client's own `x-forwarded-for` reach
    ///   the origin, which both proxies otherwise drop;
    /// * `enableRequestHeaderRules` — let a request carry its own rules in
    ///   `x-whistle-rule-value` and friends. The stored rules still win;
    /// * `multiEnv` (`nohost`, `multienv`) — the same, except the request's
    ///   rules win, `x-whistle-rule-name` is read too, only the default rule
    ///   group resolves, and HTTPS is no longer intercepted from the switch.
    ///   **This lets whoever sends a request decide where it goes**: it is for
    ///   one proxy serving many environments, not for a shared network;
    /// * `notAllowedEnableHTTPS` — take the HTTPS switch away on its own;
    /// * `strict` — refuse to read the rules headers after all, which is how
    ///   upstream's `admin` preset composes.
    ///
    /// A token whistle has and this port cannot apply is reported at startup,
    /// and so is one neither program knows. See `docs/ROADMAP.md` for the rest.
    #[arg(short = 'M', long = "mode")]
    mode: Option<String>,

    /// More hostnames that open the console (whistle's `-l/--localUIHost`),
    /// separated by `|`, `,` or `&`.
    ///
    /// It **adds to** the built-in three rather than replacing them, which is
    /// what upstream does with it (`uiHostList`, `_original/lib/config.js:1040-1054`).
    /// `local.whistlejs.com`, `local.wproxy.org` and `rootca.pro` answer without
    /// it.
    #[arg(short = 'l', long = "local-ui-host")]
    local_ui_host: Option<String>,

    /// Origins allowed to call the console's API from a page on another site
    /// (whistle's `--allowOrigin`), separated by `|`, `,` or `&`.
    ///
    /// `*` anywhere in the list means every origin. An entry may carry the same
    /// domain stars a rule pattern may — `*` is one label, `**` any number.
    /// `/api/status` and the root certificate answer any origin regardless,
    /// which is upstream's `CORS_PATHS`.
    #[arg(long = "allow-origin", alias = "allowOrigin")]
    allow_origin: Option<String>,

    /// A directory of certificates to serve instead of forged ones (whistle's
    /// `-z/--certDir`).
    ///
    /// `<name>.key` beside `<name>.crt` (or `.cer`, `.pem`) is served for every
    /// name the certificate carries — its `subjectAltName` entries, not the
    /// filename — so a client that pins its server's certificate can still be
    /// read. `root.key` + `root.crt` replaces the root CA itself.
    #[arg(short = 'z', long = "cert-dir", alias = "certDir")]
    cert_dir: Option<PathBuf>,

    /// Also run an inbound SOCKS5 server on this port.
    #[arg(long, alias = "socksPort")]
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
    ///
    /// **Not quite whistle's `-r`.** There the flag is `--shadowRules`, and what
    /// it loads is a layer *beneath* everything: the rules apply and they do not
    /// appear in the console's list at all — measured, `/cgi-bin/rules/list`
    /// comes back empty while the rule still fires. This loads the file into the
    /// **Default group**, where it is listed, editable, and switchable off. Both
    /// read the file and both apply it; who can see it afterwards differs. See
    /// `docs/ROADMAP.md`.
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

    /// Max bytes of a response body held in memory to rewrite it. Past this a
    /// response streams through untouched and the body operators do not apply.
    #[arg(long, default_value_t = whistle_rs::config::DEFAULT_BODY_REWRITE_CAP)]
    body_rewrite_limit: usize,

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

    /// How many captured requests to keep (whistle's `-R/--reqCacheSize`).
    ///
    /// Values below the default are ignored, as they are upstream — its own
    /// floor is `if (!(size > 0) || size < 600) size = 600`
    /// (`_original/lib/util/data-server.js:10-12`).
    #[arg(short = 'R', long, default_value_t = whistle_rs::config::DEFAULT_REQ_CACHE_SIZE)]
    req_cache_size: usize,

    /// How many captured WebSocket frames to keep (whistle's
    /// `-F/--frameCacheSize`).
    ///
    /// Upstream compares against **720** and falls back to 600, so a value
    /// between 1 and 719 buys nothing there and nothing here
    /// (`data-server.js:14-16`).
    #[arg(short = 'F', long, default_value_t = whistle_rs::config::DEFAULT_FRAME_CACHE_SIZE)]
    frame_cache_size: usize,

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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Say which rules a request would hit, without making one.
    ///
    /// whistle's console has this as *Test Rules*. It answers the question a
    /// rules file poses most often — a line that never matches reports nothing,
    /// so a working rule and a silently inert one look identical from the
    /// client side.
    Explain(ExplainArgs),

    /// Print a QR code for a URL — what the console draws beside each LAN
    /// address so a phone can reach the root certificate without typing.
    ///
    /// Useful on its own for the same reason the console's is: reading an
    /// address off a screen and into a phone is where a setup goes wrong.
    Qr(QrArgs),
}

#[derive(clap::Args, Debug)]
struct QrArgs {
    /// The text to encode. Usually a URL.
    text: String,

    /// Print the module matrix as rows of `0` and `1` instead of drawing it.
    ///
    /// This is the machine-readable form `tests/differential/qr-bench.js`
    /// compares against `qrcode@1.2.0`, module for module.
    #[arg(long)]
    matrix: bool,

    /// Print an SVG instead, at this many pixels per module.
    #[arg(long, value_name = "SCALE")]
    svg: Option<usize>,
}

#[derive(clap::Args, Debug)]
struct ExplainArgs {
    /// The request URL. Without a scheme it is read as `http://`.
    #[arg(required_unless_present = "batch")]
    url: Option<String>,

    /// Rules file to test (defaults to the top-level `--rules`, if given).
    #[arg(short = 'r', long)]
    rules: Option<PathBuf>,

    /// Inline rules text, applied after `--rules`.
    #[arg(long)]
    rule: Option<String>,

    /// Define a named value as `name=content` (repeatable).
    #[arg(long = "value", value_name = "NAME=CONTENT")]
    values: Vec<String>,

    /// Request method.
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Request header as `name: value` (repeatable).
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,

    /// Request body, for the `b:` filter conditions.
    #[arg(long)]
    body: Option<String>,

    /// Client address, for the `clientIp:` / `i:` conditions.
    #[arg(long)]
    client_ip: Option<String>,

    /// Answer the second question too: which rules apply once the origin has
    /// replied with this status. Without it a condition about the response has
    /// no answer and fails closed, which is the state a real request is in
    /// until the head arrives.
    #[arg(long)]
    status: Option<u16>,

    /// Response header as `name: value` (repeatable); needs `--status`.
    #[arg(long = "res-header", value_name = "NAME: VALUE")]
    res_headers: Vec<String>,

    /// Print the answer as JSON.
    #[arg(long)]
    json: bool,

    /// Read one JSON query per line from stdin and answer each on stdout.
    ///
    /// The batch shape is what lets another program ask thousands of these —
    /// `tests/differential/rules-oracle.js` puts the same corpus through
    /// whistle's own parser and compares.
    #[arg(long)]
    batch: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Answered before anything is initialised: explaining a rules file starts no
    // server, writes no storage directory and creates no CA. A tool you reach
    // for while a proxy is already running must not disturb the one running.
    if let Some(Command::Explain(args)) = &cli.command {
        return run_explain(args, cli.rules.as_deref());
    }
    // Same reasoning: encoding a string starts nothing and touches no storage.
    if let Some(Command::Qr(args)) = &cli.command {
        return run_qr(args);
    }

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
    whistle_rs::private_fs::create_dir(&storage_dir)
        .with_context(|| format!("creating storage dir {}", storage_dir.display()))?;

    // `-N/-W` alone looks like a protected console and is an open one: the
    // read-only account only restricts anything beside an admin account, and
    // with no `-n/-w` nobody is asked to log in at all (upstream's
    // `if (!username && !password) return true`, which it shares). Refused
    // rather than started in a state the operator did not mean.
    if (cli.guest_name.is_some() || cli.guest_password.is_some())
        && cli.username.is_none()
        && cli.password.is_none()
    {
        anyhow::bail!(
            "-N/-W set a read-only account, but without an admin account (-n/-w) \
             nobody is asked to log in and the console stays open to everyone, \
             writes included. Add -n and -w."
        );
    }

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

    let mut config = Config {
        port: cli.port,
        host: cli.host,
        storage_dir,
        local_ui_hosts: cli
            .local_ui_host
            .as_deref()
            .map(|list| {
                list.split(['|', ',', '&'])
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        ui_username: cli.username,
        ui_password: cli.password,
        guest_username: cli.guest_name,
        guest_password: cli.guest_password,
        ui_port: cli.ui_port,
        socks_port: cli.socks_port,
        plugins,
        values,
        body_preview_cap: cli.body_preview_limit,
        body_rewrite_cap: cli.body_rewrite_limit,
        persist_sessions: !cli.no_persist,
        persist_days: cli.persist_days,
        req_cache_size: whistle_rs::config::clamp_req_cache_size(cli.req_cache_size),
        frame_cache_size: whistle_rs::config::clamp_frame_cache_size(cli.frame_cache_size),
        timeout_ms: cli.timeout,
        intercept_https: !cli.no_intercept_https,
        cert_dir: cli.cert_dir,
        allow_origins: cli
            .allow_origin
            .as_deref()
            .map(whistle_rs::config::AllowedOrigins::parse)
            .unwrap_or_default(),
        ..Config::default()
    };

    // `-M/--mode`, applied over the flags so that a mode and a flag naming the
    // same thing agree rather than race — `--no-intercept-https -M capture` is a
    // contradiction and the mode, being the more specific instruction, wins.
    //
    // The report is printed rather than swallowed: a whistle command line that
    // names modes this port has nothing to do with should say so, or it looks
    // like it worked.
    if let Some(list) = &cli.mode {
        let report = config.apply_modes(list);
        if !report.honoured.is_empty() {
            tracing::info!("mode: {}", report.honoured.join(", "));
        }
        if !report.inert.is_empty() {
            tracing::info!(
                "mode: {} — whistle has these and this port has nothing to apply \
                 them to; see docs/ROADMAP.md",
                report.inert.join(", ")
            );
        }
        if !report.unknown.is_empty() {
            tracing::warn!(
                "mode: {} — no such mode in whistle either, so probably a typo",
                report.unknown.join(", ")
            );
        }
    }
    whistle_rs::proxy::apply::set_keep_client_xff(config.keep_client_xff);

    // Load rules. An `@` line naming a file or a URL is *registered* here and
    // fetched by `rules::include` before the first connection is accepted — the
    // same path the console's own text takes, so a rules file behaves the same
    // whichever end it arrived from.
    let mut rules_text = String::new();
    if let Some(path) = &cli.rules {
        rules_text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules file {}", path.display()))?;
    }
    if let Some(inline) = &cli.rule {
        rules_text.push('\n');
        rules_text.push_str(inline);
    }
    let mut manager = RuleManager::with_includes();
    manager.set_text(&rules_text);

    // Load any persisted rule groups from disk (added via the UI).
    let rules_dir = config.data_dir().join("rules");
    whistle_rs::rules::storage::load_groups(&rules_dir, &mut manager);

    // Values persisted by the console, with anything named on the command line
    // laid over them: `--value` is an instruction for this run and wins.
    let persisted = whistle_rs::rules::storage::load_values(config.data_dir());
    if !persisted.is_empty() {
        let mut merged = persisted;
        merged.extend(config.values.clone());
        config.values = merged;
    }
    // `-M multiEnv` stops the **named** groups resolving: upstream's
    // `getSelectedRulesList()` returns `[]` there and nothing can select one
    // (`_original/lib/rules/util.js:94,:149,:204`). The default group still
    // applies. Set after the groups are loaded, because loading is what would
    // otherwise switch some of them on.
    if config.multi_env {
        manager.only_default_group();
        let named = manager
            .groups()
            .iter()
            .filter(|g| g.name != "default")
            .count();
        if named > 0 {
            tracing::info!(
                "-M multiEnv: {named} named rule group(s) loaded but not resolved; \
                 the default group and each request's own rules apply"
            );
        }
    }
    tracing::info!(
        "loaded {} rules ({} groups)",
        manager.len(),
        manager.groups().len()
    );

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
            state.config.req_cache_size,
            state.config.persist_days,
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
        let store =
            whistle_rs::proxy::persist::SessionStore::new(sessions_dir, state.config.persist_days);
        state.enable_persistence(store);
    }

    let state = Arc::new(state);

    // Keep the spawned Node plugin processes alive for the server's lifetime.
    let _children = children;
    proxy::run(state).await
}

/// `whistle-rs explain` — see [`whistle_rs::explain`].
///
/// `fallback_rules` is the top-level `--rules`, so that the file a running
/// proxy was started with can be tested by naming it once.
/// Draw a QR code, or print the modules behind it.
///
/// The terminal form uses one half-block per two rows, so a version-3 symbol
/// fits in a normal window — a symbol drawn one character per module is 29
/// lines tall and twice as wide as it is high, and a phone reads a squashed one
/// badly or not at all.
fn run_qr(args: &QrArgs) -> Result<()> {
    let code = whistle_rs::qr::encode(&args.text).with_context(|| {
        format!(
            "{} bytes is more than this encoder takes ({} bytes at version {})",
            args.text.len(),
            213,
            whistle_rs::qr::MAX_VERSION
        )
    })?;
    if args.matrix {
        for y in 0..code.size {
            let row: String = (0..code.size)
                .map(|x| if code.get(x, y) { '1' } else { '0' })
                .collect();
            println!("{row}");
        }
        return Ok(());
    }
    if let Some(scale) = args.svg {
        println!("{}", code.to_svg(scale));
        return Ok(());
    }
    // Four modules of quiet zone, which a camera needs as much as a scanner
    // does — and a terminal's own background is not white enough to count.
    let quiet = 4;
    let side = code.size + quiet * 2;
    let dark = |x: usize, y: usize| {
        x >= quiet
            && y >= quiet
            && x < quiet + code.size
            && y < quiet + code.size
            && code.get(x - quiet, y - quiet)
    };
    for y in (0..side).step_by(2) {
        let row: String = (0..side)
            .map(|x| match (dark(x, y), y + 1 < side && dark(x, y + 1)) {
                (true, true) => ' ',
                (true, false) => '\u{2584}',
                (false, true) => '\u{2580}',
                (false, false) => '\u{2588}',
            })
            .collect();
        println!("{row}");
    }
    Ok(())
}

fn run_explain(args: &ExplainArgs, fallback_rules: Option<&std::path::Path>) -> Result<()> {
    use std::io::{BufRead, Write};
    use whistle_rs::explain::{self, Query};

    let mut rules = String::new();
    if let Some(path) = args.rules.as_deref().or(fallback_rules) {
        rules = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules file {}", path.display()))?;
    }
    if let Some(inline) = &args.rule {
        rules.push('\n');
        rules.push_str(inline);
    }

    let mut values = std::collections::HashMap::new();
    for spec in &args.values {
        let (name, content) = spec
            .split_once('=')
            .with_context(|| format!("invalid --value '{spec}', expected name=content"))?;
        values.insert(name.trim().to_string(), content.to_string());
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if args.batch {
        // One JSON object in, one out, in order — a line that cannot be read
        // answers `{"error": …}` rather than ending the run, because a corpus
        // of thousands is worth more with one case missing than not at all.
        for line in std::io::stdin().lock().lines() {
            let line = line.context("reading a batch query")?;
            if line.trim().is_empty() {
                continue;
            }
            let answer = serde_json::from_str::<Query>(&line)
                .map_err(|e| format!("cannot read query: {e}"))
                .and_then(|query| explain::explain(&query));
            let json = match answer {
                Ok(explanation) => serde_json::to_string(&explanation)?,
                Err(message) => serde_json::json!({ "error": message }).to_string(),
            };
            writeln!(out, "{json}")?;
        }
        return Ok(());
    }

    let split_headers =
        |given: &[String], flag: &str| -> Result<std::collections::BTreeMap<String, String>> {
            let mut out = std::collections::BTreeMap::new();
            for header in given {
                let (name, value) = header.split_once(':').with_context(|| {
                    format!("invalid {flag} '{header}', expected 'name: value'")
                })?;
                out.insert(name.trim().to_string(), value.trim().to_string());
            }
            Ok(out)
        };
    let headers = split_headers(&args.headers, "--header")?;
    let response = match args.status {
        None => None,
        Some(status) => Some(whistle_rs::explain::Response {
            status,
            headers: split_headers(&args.res_headers, "--res-header")?,
            server_ip: None,
            server_port: None,
        }),
    };

    let query = Query {
        rules,
        values,
        url: args.url.clone().unwrap_or_default(),
        method: Some(args.method.clone()),
        headers,
        body: args.body.clone(),
        client_ip: args.client_ip.clone(),
        response,
    };
    let explanation = explain::explain(&query).map_err(|e| anyhow::anyhow!(e))?;
    if args.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&explanation)?)?;
    } else {
        write!(out, "{}", explain::to_text(&explanation))?;
    }
    Ok(())
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
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}
