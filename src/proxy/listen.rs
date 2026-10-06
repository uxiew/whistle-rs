//! Listening: binding the proxy port (and a separate console port, if asked),
//! the accept loop and its shutdown, and the LAN addresses a phone can be
//! pointed at.

use super::*;

/// Start the proxy and serve until the process exits.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let (listener, _addr) = bind(&state).await?;
    accept_loop(state, listener, None).await
}

/// Bind the proxy's listening socket and announce it, without accepting yet.
///
/// Split out of [`run`] for the sake of an **embedding** program: with
/// `port: 0` the operating system chooses the port, and the only way to learn
/// which one is to ask the bound socket. Returning it before the accept loop
/// starts means the embedder can hand the address to whatever it is configuring
/// without racing the first connection. See [`crate::embed`].
pub async fn bind(state: &Arc<AppState>) -> Result<(TcpListener, SocketAddr)> {
    let requested = SocketAddr::new(state.config.bind_ip(), state.config.port);
    let listener = TcpListener::bind(requested).await?;
    let addr = listener.local_addr().unwrap_or(requested);
    tracing::info!("whistle-rs listening on http://{addr}");

    // Teach the forwarding layer which addresses are *us*, so a `proxy://` rule
    // naming this proxy is refused instead of recursing into it. Registered
    // before the first connection is accepted; see `upstream::self_loop`.
    // The *bound* port, not the requested one, or port 0 would register nothing.
    let mut own_ports = vec![addr.port()];
    own_ports.extend(state.config.socks_port);
    own_ports.extend(state.config.ui_port);
    upstream::register_listen(Some(state.config.bind_ip()), &own_ports);

    // The same fact the include layer needs for a `${port}` in a backticked
    // `@` source: `--port 0` means the operating system chose, and this is the
    // first moment anyone knows what it chose.
    state.rules.write().unwrap().set_include_port(addr.port());
    tracing::info!(
        "root CA: {} (download at http://{}/rootCA.crt)",
        // The file actually in use, which `--cert-dir` may have replaced.
        state.ca.root_cert_path().display(),
        addr
    );
    // The address to give a phone. `0.0.0.0:8899` is not something anyone can
    // type into a Wi-Fi proxy field, and `mobile.md` is an entire page about
    // typing exactly that in — whistle's own `w2 status` prints the reachable
    // URLs for the same reason. This prints the one a device on the same network
    // should use, when it is not the address that was bound anyway.
    // Who else can reach it, said once, where the operator is looking.
    if addr.ip().is_loopback() {
        tracing::info!(
            "only this machine can use the proxy (bound to {}); to use it from a phone \
             or another machine, restart with -H 0.0.0.0 — and set a console login \
             (-n/-w) first",
            addr.ip()
        );
    } else if state.config.ui_username.is_none() && state.config.ui_password.is_none() {
        tracing::warn!(
            "listening on {addr} with no console login: anyone who can reach this port \
             can use the proxy and rewrite its rules, which read and write files on this \
             machine. Set -n/-w, or bind 127.0.0.1"
        );
    }
    if addr.ip().is_unspecified() {
        let candidates = lan_addresses();
        if !candidates.is_empty() {
            let urls: Vec<String> = candidates
                .iter()
                .map(|ip| format!("http://{ip}:{}", addr.port()))
                .collect();
            tracing::info!(
                "on this network: {} — set one as the proxy on a phone (try each \
                 if unsure), then open http://rootca.pro/ to install the certificate",
                urls.join("  ")
            );
        }
    }
    Ok((listener, addr))
}

/// The addresses a device on the same network might reach this machine at.
///
/// No interface enumeration and no new dependency: a UDP socket *connected* to
/// an address sends nothing, and the kernel fills in the local address it would
/// have used to get there. Asking that once per private range is asking "if
/// something on a 10.x network talked to me, which of my addresses would it be
/// talking to" — and the answers, deduplicated, are the candidates.
///
/// **Several, not one.** A single probe against a public address returns
/// whatever holds the default route, which on a machine running a VPN is the
/// tunnel — an address no phone on the Wi-Fi can reach. Upstream sidesteps the
/// same problem by listing every interface and telling you to try them in turn
/// (`getIpList`, `_original/bin/util.js:33-49`, and the FAQ's "试看看"), and this
/// keeps that shape.
///
/// Only private addresses are offered. A public one is either a server, where
/// this line is not the advice anyone needs, or a VPN's, where it is wrong.
pub(crate) fn lan_addresses() -> Vec<std::net::IpAddr> {
    let probe = |target: &str| -> Option<std::net::IpAddr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect(target).ok()?;
        Some(sock.local_addr().ok()?.ip())
    };
    let private = |ip: &std::net::IpAddr| match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(_) => false,
    };
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    // `224.0.0.1` — the all-hosts multicast group — first, and it is the one
    // that works. Link-local multicast is not carried through a tunnel, so the
    // kernel answers with the physical interface even on a machine whose default
    // route belongs to a VPN. Measured here: with a full-tunnel VPN running,
    // every unicast probe below answers with the tunnel's own address and this
    // one answers `192.168.2.203`, which is what the phone on the same Wi-Fi can
    // actually reach.
    //
    // Then one target per RFC 1918 range, which adds a second interface on a
    // machine that has one and costs nothing on a machine that does not.
    for target in [
        "224.0.0.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80",
        "192.168.0.1:80",
    ] {
        if let Some(ip) = probe(target)
            && private(&ip)
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
pub(super) mod lan_tests {
    /// Whatever this machine's network looks like, the answer has a shape: only
    /// private IPv4 addresses, and no duplicates.
    ///
    /// It cannot assert *which* addresses without asserting a fact about the
    /// machine running the test — a CI container may have none, and this one has
    /// a VPN that hides them from every unicast probe. What it can hold is that
    /// nothing public, loopback or repeated ever reaches the line a person is
    /// about to type into a phone.
    #[test]
    fn the_addresses_offered_are_private_and_distinct() {
        let found = super::super::lan_addresses();
        let mut seen = std::collections::HashSet::new();
        for ip in &found {
            assert!(seen.insert(*ip), "{ip} offered twice");
            match ip {
                std::net::IpAddr::V4(v4) => {
                    assert!(v4.is_private(), "{v4} is not an address on a local network");
                    assert!(!v4.is_loopback(), "{v4} is this machine talking to itself");
                }
                std::net::IpAddr::V6(v6) => panic!("{v6}: only IPv4 is offered"),
            }
        }
    }
}

/// How long a starting proxy waits for the `@` includes in its rules before it
/// answers without the ones still on their way.
const INCLUDE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Accept connections until `shutdown` resolves (or forever, if it is `None`).
///
/// The optional shutdown is what lets an embedded proxy be stopped: a binary
/// runs until the process ends, but a proxy inside another program has to be
/// able to go away without taking its host with it.
pub async fn accept_loop(
    state: Arc<AppState>,
    listener: TcpListener,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<()> {
    // The console on its own port, when `-P/--uiport` named one. Upstream
    // starts a second plain HTTP server for exactly this case and serves the UI
    // and nothing else on it (`customUIPort`, `_original/biz/init.js:8-19`);
    // this is that server. A port equal to the proxy's is not a second server
    // in either program — there the console already answers.
    if let Some(ui_port) = state.config.ui_port.filter(|p| *p != state.config.port) {
        let ui_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_console(ui_state, ui_port).await {
                tracing::error!("console server error: {e}");
            }
        });
    }

    // Optional inbound SOCKS5 server.
    if let Some(socks_port) = state.config.socks_port {
        let socks_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = socks::run(socks_state, socks_port).await {
                tracing::error!("SOCKS server error: {e}");
            }
        });
    }

    // `@` includes, before the first connection is answered — for up to
    // [`INCLUDE_WAIT`], and then without them.
    //
    // The socket is already bound, so a client connecting during a fetch waits
    // in the backlog rather than being refused, and a rules file that says
    // `@https://intra/rules.txt` is in effect for the first request when the
    // server answers. When it does not, the fetches go on in the background
    // and their rules apply when they land. Waiting them out was 16 s per
    // source, one after another, with the console silent too; upstream does
    // not wait at all. A proxy whose rules name no include does nothing here.
    let resolves_includes = state.rules.read().unwrap().resolves_includes();
    if resolves_includes {
        let (loaded, landed) = tokio::sync::oneshot::channel();
        let loader = state.clone();
        tokio::spawn(async move {
            let count = crate::rules::include::load_pending(&loader.rules).await;
            tracing::info!("resolved {count} rules include(s)");
            let _ = loaded.send(());
            crate::rules::include::poll(&loader.rules).await;
        });
        if tokio::time::timeout(INCLUDE_WAIT, landed).await.is_err() {
            let waiting = state.rules.read().unwrap().includes().pending();
            tracing::warn!(
                "rules includes still loading after {} s, answering without them until \
                 they arrive: {}",
                INCLUDE_WAIT.as_secs(),
                waiting
                    .iter()
                    .map(|t| format!("@{t}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    // `Either` rather than a `select!` per iteration: with no shutdown channel
    // there is nothing to poll, and the binary's hot loop should not pay for a
    // feature only the library uses.
    let mut shutdown = shutdown;
    loop {
        let accepted = match &mut shutdown {
            None => listener.accept().await,
            Some(stop) => tokio::select! {
                biased;
                _ = &mut *stop => {
                    tracing::info!("whistle-rs shutting down");
                    return Ok(());
                }
                accepted = listener.accept() => accepted,
            },
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            // Origin connections this client may reuse — its own, and only
            // for as long as it stays connected. See `pool`.
            let pool = pool::ConnPool::new();
            let service = service_fn(move |mut req: Request<Incoming>| {
                let state = state.clone();
                req.extensions_mut().insert(pool.clone());
                async move { top_level(state, req, peer).await }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("connection from {peer} closed: {err}");
            }
        });
    }
}

/// Serve the console, and only the console, on its own port.
///
/// Every request here is the UI's: there is no proxying, no CONNECT and no
/// rules — a client that wants those has the proxy port. That is upstream's
/// arrangement too, whose UI server is a bare `http.createServer()` with the
/// web UI's own handler on it and nothing of the proxy attached
/// (`_original/biz/init.js:8-19`).
pub(super) async fn run_console(state: Arc<AppState>, port: u16) -> Result<()> {
    let addr = SocketAddr::new(state.config.bind_ip(), port);
    serve_console(state, TcpListener::bind(addr).await?).await
}

/// [`run_console`] on a socket that is already bound. Split out so a test can
/// bind port 0 and keep holding it: dropping a probe listener and re-binding
/// its number lost the port to a parallel test about one run in twenty.
pub(super) async fn serve_console(state: Arc<AppState>, listener: TcpListener) -> Result<()> {
    tracing::info!("console listening on http://{}", listener.local_addr()?);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("console accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(webui::handle(&state, req).await) }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!("console connection from {peer} closed: {err}");
            }
        });
    }
}

#[cfg(test)]
pub(super) mod console_port_tests {
    use super::super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A state with its own storage directory, so two tests never race over one
    /// root CA.
    fn state(ui_port: Option<u16>) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-console-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ui_port,
            ..Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, RuleManager::new(), ca))
    }

    /// No `-H`: this machine only. It used to be every interface, which made a
    /// fresh start an open proxy — and an open console — for the whole network.
    #[tokio::test]
    async fn with_no_host_it_listens_on_loopback() {
        let config = Config {
            port: 0,
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-bind-default-{}", std::process::id())),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        let s = Arc::new(AppState::new(config, RuleManager::new(), ca));
        let (_listener, addr) = bind(&s).await.expect("bind");
        assert!(addr.ip().is_loopback(), "bound {addr}");
        assert!(!s.config.listens_beyond_loopback());
    }

    /// `-P/--uiport` serves the console, and only the console: the page and the
    /// capture API answer, and a request that would be a *proxy* request on the
    /// other port is not one here.
    #[tokio::test]
    async fn the_console_answers_on_its_own_port() {
        // Bound here and handed over, never dropped and re-bound: the port is
        // ours from this line on, and connects queue in the backlog until the
        // server task first polls `accept`.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let state = state(Some(port));
        let server = state.clone();
        tokio::spawn(async move { serve_console(server, listener).await });

        let url = format!("http://127.0.0.1:{port}");
        let page = reqwest_get(&format!("{url}/")).await.expect("index");
        assert!(
            page.starts_with("HTTP/1.1 200"),
            "index: {}",
            &page[..40.min(page.len())]
        );
        assert!(page.contains("<!doctype html>") || page.contains("<!DOCTYPE html>"));

        let api = reqwest_get(&format!("{url}/sessions.json"))
            .await
            .expect("sessions");
        assert!(
            api.starts_with("HTTP/1.1 200"),
            "sessions: {}",
            &api[..40.min(api.len())]
        );

        // Nothing here proxies: an unknown path is a 404 from the UI, not a
        // gateway error from a forward that was never attempted.
        let missing = reqwest_get(&format!("{url}/nope")).await.expect("404");
        assert!(
            missing.starts_with("HTTP/1.1 404"),
            "unknown: {}",
            &missing[..40.min(missing.len())]
        );
    }

    /// One raw GET, so the test needs no HTTP client dependency.
    async fn reqwest_get(url: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.strip_prefix("http://").unwrap_or(url);
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let mut stream = tokio::net::TcpStream::connect(authority).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}
