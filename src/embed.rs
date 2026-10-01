//! Run whistle-rs **inside another program**.
//!
//! The binary is one consumer of this crate; this module is the other. It exists
//! because a proxy embedded in an application needs three things the binary
//! never does:
//!
//! * **the address it actually got** — an embedder asks for port `0` so the
//!   operating system picks a free one, and then has to tell the rest of the
//!   program where to point;
//! * **a way to stop** — a binary runs until the process ends; a library has to
//!   go away without taking its host with it;
//! * **the traffic delivered rather than polled** — an application that has
//!   embedded a proxy wants each transaction handed to it, not scraped back out
//!   of `/sessions.json`.
//!
//! Everything else it needs already exists and is not duplicated here: rules are
//! the same DSL, and interception is the same
//! [`RustPlugin`](crate::plugins::RustPlugin) trait the built-in plugins
//! implement — an in-process hook that can rewrite headers, inject rules, answer
//! the request outright, gate it, or choose its TLS certificate.
//!
//! ```no_run
//! use whistle_rs::embed::Proxy;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let proxy = Proxy::builder()
//!     .port(0)                                   // let the OS choose
//!     .rules("api.example.com http://127.0.0.1:3000")
//!     .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
//!     .start()
//!     .await?;
//!
//! println!("proxy on {}", proxy.addr());        // the port it really got
//! // … the host program runs, pointing its HTTP client at proxy.addr() …
//! proxy.shutdown().await;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::plugins::{Plugins, RustPlugin};
use crate::proxy::{AppState, Session, SessionObserver};
use crate::rules::RuleManager;

/// A running embedded proxy.
///
/// Dropping it does **not** stop the proxy — the accept loop is a spawned task
/// and outlives the handle, which is what you want when the handle is stored in
/// a struct that gets moved around. Call [`shutdown`](Proxy::shutdown) to stop
/// it.
pub struct Proxy {
    addr: SocketAddr,
    state: Arc<AppState>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Proxy {
    /// Start configuring a proxy.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The address the proxy is listening on — with `port(0)`, the one the
    /// operating system chose.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The proxy's shared state: the session ring, the rules manager, the plugin
    /// registry, the CA. For anything this facade does not cover.
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// The root certificate to trust, in PEM, if the embedder needs to install
    /// it into a client it controls.
    pub fn root_ca_pem(&self) -> &str {
        self.state.ca.root_cert_pem()
    }

    /// Replace the rules while running. The next request uses them.
    ///
    /// An `@` include the new text names is fetched in the background, so this
    /// returns at the speed of the parse and the include lands when it lands —
    /// the same contract the console's own save has.
    pub fn set_rules(&self, text: &str) {
        self.state.rules.write().unwrap().set_text(text);
        let state = self.state.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                crate::rules::include::load_pending(&state.rules).await;
            });
        }
    }

    /// Stop accepting, and wait for the accept loop to finish.
    ///
    /// Connections already established are not cut off — they end when their
    /// requests do, which is what a debugging proxy should do to a download in
    /// flight.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.task).await;
    }
}

/// Configuration for an embedded proxy. See [`Proxy::builder`].
#[derive(Default)]
pub struct Builder {
    port: Option<u16>,
    host: Option<IpAddr>,
    socks_port: Option<u16>,
    storage_dir: Option<PathBuf>,
    rules: Option<String>,
    values: Vec<(String, String)>,
    plugins: Vec<Box<dyn RustPlugin>>,
    observer: Option<SessionObserver>,
    intercept_https: Option<bool>,
    persist: bool,
    body_preview_cap: Option<usize>,
    body_rewrite_cap: Option<usize>,
    /// A whistle `-M/--mode` list, applied last — see [`Builder::mode`].
    mode: Option<String>,
}

impl Builder {
    /// Listen on this port. `0` asks the operating system for a free one, which
    /// [`Proxy::addr`] then reports.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Bind to this address. Without it the proxy binds `127.0.0.1`, which
    /// keeps an embedded proxy — and its console, which has no login here —
    /// off the network. `0.0.0.0` exposes both to every device that can reach
    /// the machine.
    pub fn host(mut self, host: IpAddr) -> Self {
        self.host = Some(host);
        self
    }

    /// Also run an inbound SOCKS5 server on this port.
    pub fn socks_port(mut self, port: u16) -> Self {
        self.socks_port = Some(port);
        self
    }

    /// Where the root CA lives. Two embedders sharing a directory share a CA,
    /// which is usually right — a client trusts it once.
    pub fn storage_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.storage_dir = Some(dir.into());
        self
    }

    /// The rules text, in whistle's DSL. See `docs/RULES.md`.
    pub fn rules(mut self, text: impl Into<String>) -> Self {
        self.rules = Some(text.into());
        self
    }

    /// Define a named value, referenced as `{name}` from any operator.
    pub fn value(mut self, name: impl Into<String>, content: impl Into<String>) -> Self {
        self.values.push((name.into(), content.into()));
        self
    }

    /// Register an in-process interceptor, reachable as `plugin://<name>`.
    ///
    /// This is the hook for "intercept the traffic and do something with it in
    /// my own code": a [`RustPlugin`] can rewrite request headers, inject rules,
    /// answer the request itself, gate it, transform the response, or choose the
    /// TLS certificate. See `docs/PLUGINS.md`.
    pub fn plugin(mut self, plugin: impl RustPlugin + 'static) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Be told about every transaction as it completes — once each, when its
    /// response has reached the client, failed, or been abandoned. A failed one
    /// says where it stopped in [`Session::error`].
    ///
    /// Runs on the request's own task, so hand slow work to a channel. For
    /// inspection only — to *change* a request, register a [`plugin`](Self::plugin).
    pub fn on_session(mut self, f: impl Fn(&Session) + Send + Sync + 'static) -> Self {
        self.observer = Some(Box::new(f));
        self
    }

    /// Decrypt HTTPS (the default), or relay it untouched.
    ///
    /// Relaying still routes the connection by its rules — `host://` and the
    /// proxy family apply — it simply does not read it, so no client has to
    /// trust the CA.
    pub fn intercept_https(mut self, on: bool) -> Self {
        self.intercept_https = Some(on);
        self
    }

    /// Write captured sessions to disk. Off by default here, on in the binary:
    /// an embedded proxy should not leave files behind unless asked.
    pub fn persist_sessions(mut self, on: bool) -> Self {
        self.persist = on;
        self
    }

    /// Bytes of each body kept for inspection. `0` captures none, which is the
    /// setting for an embedder that only wants headers.
    pub fn body_preview_cap(mut self, bytes: usize) -> Self {
        self.body_preview_cap = Some(bytes);
        self
    }

    /// The largest response body the body operators may rewrite — the
    /// binary's `--body-rewrite-limit`. A body over it is forwarded as it
    /// arrived, and its session names the operators that did not run.
    pub fn body_rewrite_cap(mut self, bytes: usize) -> Self {
        self.body_rewrite_cap = Some(bytes);
        self
    }

    /// Apply a whistle `-M/--mode` list — the same string the binary's `-M`
    /// takes, `|`, `,` or `&` separated.
    ///
    /// Returns the builder and the report, so an embedder can see which tokens
    /// meant something. Read [`crate::config::HeaderRules`] before reaching for
    /// `multiEnv` here: it lets whoever sends a request choose where it goes.
    pub fn mode(mut self, list: impl AsRef<str>) -> Self {
        self.mode = Some(list.as_ref().to_string());
        self
    }

    /// Bind, start accepting, and return once the address is known.
    ///
    /// The accept loop runs on a spawned task, so this returns immediately and
    /// the caller can point the rest of the program at [`Proxy::addr`] without
    /// racing the first connection.
    pub async fn start(self) -> Result<Proxy> {
        let mut config = Config {
            port: self.port.unwrap_or(0),
            host: self.host,
            ui_username: None,
            ui_password: None,
            guest_username: None,
            guest_password: None,
            ui_port: None,
            socks_port: self.socks_port,
            persist_sessions: self.persist,
            values: self.values.into_iter().collect(),
            ..Config::default()
        };
        if let Some(dir) = self.storage_dir {
            config.storage_dir = dir;
        }
        if let Some(on) = self.intercept_https {
            config.intercept_https = on;
        }
        if let Some(cap) = self.body_preview_cap {
            config.body_preview_cap = cap;
        }
        if let Some(cap) = self.body_rewrite_cap {
            config.body_rewrite_cap = cap;
        }
        // After the explicit setters, because a mode is upstream's way of
        // saying the same things and the later word should win — `-M capture`
        // beside `.intercept_https(false)` is a caller contradicting itself,
        // and the mode is the more specific statement.
        if let Some(list) = &self.mode {
            config.apply_modes(list);
        }
        // Process-wide, as upstream's `dns.setDefaultResultOrder` is: two
        // proxies in one program share the last one's order.
        crate::proxy::upstream::set_dns_order(config.dns_order);

        let ca = CertAuthority::load_or_create(&config)?;
        // `with_includes`: an embedded proxy's rules are as long-lived as the
        // program holding it, so an `@` line names something worth fetching and
        // worth keeping fresh — see [`crate::rules::include`].
        let mut rules = RuleManager::with_includes();
        if let Some(text) = &self.rules {
            rules.set_text(text);
        }
        // `-M multiEnv` resolves the default group alone — see
        // [`RuleManager::only_default_group`].
        if config.multi_env {
            rules.only_default_group();
        }
        let mut registry = Plugins::new();
        for plugin in self.plugins {
            registry.register_rust(plugin);
        }

        let mut state = AppState::with_plugins(config, rules, ca, registry);
        if state.config.persist_sessions {
            state.start_history();
        }
        let state = Arc::new(state);
        state.warm_up_plugins();
        if let Some(observer) = self.observer {
            state.observe(observer);
        }

        let (listener, addr) = crate::proxy::bind(&state).await?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(crate::proxy::accept_loop(
            state.clone(),
            listener,
            Some(stopped),
        ));
        Ok(Proxy {
            addr,
            state,
            stop: Some(stop),
            task,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginReq, PluginResult};

    /// A plugin that answers instead of forwarding — the shape an embedder uses
    /// to mock an endpoint from its own code.
    struct Canned;

    impl RustPlugin for Canned {
        fn name(&self) -> &str {
            "canned"
        }
        fn on_request(&self, _req: &PluginReq) -> PluginResult {
            PluginResult {
                response: Some(crate::plugins::PluginResp {
                    status: 418,
                    headers: vec![("x-from".into(), "embedded".into())],
                    body: b"brewed in-process".to_vec(),
                }),
                ..Default::default()
            }
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("whistle-rs-embed-{tag}-{}", std::process::id()))
    }

    /// The three things a binary never needs and an embedder always does: the
    /// address it really got, the traffic delivered, and a way to stop.
    #[tokio::test]
    async fn an_embedded_proxy_reports_its_port_serves_and_stops() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = seen.clone();

        let proxy = Proxy::builder()
            .port(0)
            .host("127.0.0.1".parse().unwrap())
            .storage_dir(temp_dir("basic"))
            .rules("mock.test plugin://canned")
            .plugin(Canned)
            .on_session(move |s| {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", s.status, s.url));
            })
            .start()
            .await
            .expect("starts");

        // Port 0 was asked for; a real one came back.
        assert_ne!(proxy.addr().port(), 0);

        let (status, body) = get_via(proxy.addr(), "http://mock.test/x").await;
        assert_eq!(status, 418);
        assert_eq!(body, b"brewed in-process");

        // The observer saw it, without anyone polling an endpoint.
        assert_eq!(seen.lock().unwrap().as_slice(), ["418 http://mock.test/x"]);

        // And it stops, releasing the port.
        let addr = proxy.addr();
        proxy.shutdown().await;
        assert!(
            tokio::net::TcpListener::bind(addr).await.is_ok(),
            "the port should be free once the proxy has stopped"
        );
    }

    /// Rules can be swapped while running, which is the point of embedding one:
    /// the host program changes what it wants intercepted as it goes.
    #[tokio::test]
    async fn rules_can_be_replaced_while_running() {
        let proxy = Proxy::builder()
            .port(0)
            .host("127.0.0.1".parse().unwrap())
            .storage_dir(temp_dir("rules"))
            .rules("mock.test statusCode://204")
            .start()
            .await
            .expect("starts");

        assert_eq!(get_via(proxy.addr(), "http://mock.test/x").await.0, 204);
        proxy.set_rules("mock.test statusCode://503");
        assert_eq!(get_via(proxy.addr(), "http://mock.test/x").await.0, 503);

        proxy.shutdown().await;
    }

    /// One request through `addr`, in absolute form as a forward proxy expects.
    async fn get_via(addr: SocketAddr, url: &str) -> (u16, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let host = url.split('/').nth(2).unwrap_or_default();
        let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        sock.write_all(req.as_bytes()).await.expect("write");
        let mut raw = Vec::new();
        sock.read_to_end(&mut raw).await.expect("read");

        let text = String::from_utf8_lossy(&raw);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| raw[i + 4..].to_vec())
            .unwrap_or_default();
        (status, body)
    }
}
