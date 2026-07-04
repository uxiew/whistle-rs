//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
pub mod body;
pub mod script;
pub mod socks;
pub mod upstream;
pub mod webui;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::rules::{ReqInfo, Resolved, RuleManager};
use body::DynBody;

/// Maximum number of captured transactions kept in memory.
const MAX_SESSIONS: usize = 500;

/// Shared server state.
pub struct AppState {
    pub config: Config,
    pub rules: RwLock<RuleManager>,
    pub ca: Arc<CertAuthority>,
    /// Bounded ring buffer of recent transactions (whistle's session capture).
    pub sessions: Mutex<VecDeque<Session>>,
    next_id: AtomicU64,
}

impl AppState {
    /// Construct fresh server state.
    pub fn new(config: Config, rules: RuleManager, ca: Arc<CertAuthority>) -> Self {
        AppState {
            config,
            rules: RwLock::new(rules),
            ca,
            sessions: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn record(&self, mut session: Session) {
        session.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut q = self.sessions.lock().unwrap();
        if q.len() >= MAX_SESSIONS {
            q.pop_front();
        }
        q.push_back(session);
    }
}

/// One captured request/response transaction.
#[derive(Clone, serde::Serialize)]
pub struct Session {
    pub id: u64,
    /// Unix time in milliseconds when the request was received.
    pub time_ms: u128,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub client_ip: Option<String>,
    /// Where the request was sent (or "short-circuit").
    pub target: String,
    pub duration_ms: u128,
}

/// Milliseconds since the Unix epoch (best-effort).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Where a request originated, which decides how we derive its target.
#[derive(Clone)]
enum Origin {
    /// A normal absolute-form forward-proxy request.
    Forward,
    /// A request seen inside an intercepted tunnel (CONNECT or SOCKS). `tls`
    /// indicates the tunnel was TLS-decrypted (scheme https) vs. plain (http).
    Mitm { host: String, port: u16, tls: bool },
}

/// Start the proxy and serve until the process exits.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let addr = SocketAddr::new(
        state
            .config
            .host
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
        state.config.port,
    );
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("whistle-rs listening on http://{addr}");
    tracing::info!(
        "root CA: {} (download at http://{}/rootCA.crt)",
        state.config.root_ca_cert_path().display(),
        addr
    );

    // Optional inbound SOCKS5 server.
    if let Some(socks_port) = state.config.socks_port {
        let socks_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = socks::run(socks_state, socks_port).await {
                tracing::error!("SOCKS server error: {e}");
            }
        });
    }

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let state = state.clone();
        let peer_ip = peer.ip();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { top_level(state, req, peer_ip).await }
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

/// Entry point for every request arriving on the main port.
async fn top_level(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: IpAddr,
) -> Result<Response<DynBody>, Infallible> {
    let client_ip = Some(peer.to_string());
    if req.method() == hyper::Method::CONNECT {
        return Ok(handle_connect(state, req, peer));
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return Ok(guard(serve(state, req, Origin::Forward, client_ip).await));
    }
    Ok(webui::handle(&state, req).await)
}

/// Handle a CONNECT: acknowledge, then intercept the tunnel with MITM.
fn handle_connect(state: Arc<AppState>, req: Request<Incoming>, peer: IpAddr) -> Response<DynBody> {
    let Some((host, port)) = authority_host_port(req.uri()) else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"bad CONNECT target")))
            .unwrap();
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // A CONNECT tunnel is (almost always) TLS; intercept it.
                if let Err(err) =
                    serve_tunnel(state, TokioIo::new(upgraded), host, port, peer, true).await
                {
                    tracing::debug!("mitm error: {err}");
                }
            }
            Err(err) => tracing::debug!("connect upgrade failed: {err}"),
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(body::empty())
        .unwrap()
}

/// Serve HTTP over an intercepted tunnel stream, optionally TLS-decrypting first.
/// Shared by CONNECT interception and the SOCKS server.
pub(crate) async fn serve_tunnel<S>(
    state: Arc<AppState>,
    stream: S,
    host: String,
    port: u16,
    peer: IpAddr,
    tls: bool,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if tls {
        let acceptor = state.ca.acceptor_for(&host)?;
        let tls_stream = acceptor.accept(stream).await?;
        let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
        if is_h2 {
            serve_intercepted_h2(state, TokioIo::new(tls_stream), host, port, peer).await
        } else {
            serve_intercepted(state, TokioIo::new(tls_stream), host, port, peer, true).await
        }
    } else {
        serve_intercepted(state, TokioIo::new(stream), host, port, peer, false).await
    }
}

/// Serve an intercepted HTTP/2 connection (ALPN negotiated `h2`). Upstream
/// forwarding stays HTTP/1.1 — hyper translates request/response between them.
async fn serve_intercepted_h2<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: IpAddr,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls: true,
        };
        let client_ip = Some(peer.to_string());
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, client_ip).await)) }
    });

    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Run the HTTP/1.1 server over an already-prepared tunnel IO.
async fn serve_intercepted<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: IpAddr,
    tls: bool,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls,
        };
        let client_ip = Some(peer.to_string());
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin, client_ip).await)) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

/// Turn an internal error into a 502 so the service signature stays infallible.
fn guard(result: Result<Response<DynBody>>) -> Response<DynBody> {
    match result {
        Ok(resp) => resp,
        Err(err) => {
            tracing::debug!("request failed: {err}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(body::full(Bytes::from(format!("whistle-rs: {err}"))))
                .unwrap()
        }
    }
}

/// Core request pipeline: match rules, apply them, forward upstream.
async fn serve(
    state: Arc<AppState>,
    req: Request<Incoming>,
    origin: Origin,
    client_ip: Option<String>,
) -> Result<Response<DynBody>> {
    // Derive scheme/host/port/path for matching.
    let (scheme, host, port, path) = match &origin {
        Origin::Forward => {
            let uri = req.uri();
            let host = uri.host().unwrap_or_default().to_string();
            let scheme = uri.scheme_str().unwrap_or("http").to_string();
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            (scheme, host, port, path)
        }
        Origin::Mitm { host, port, tls } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let scheme = if *tls { "https" } else { "http" };
            (scheme.to_string(), host.clone(), *port, path)
        }
    };

    let info = apply::build_req_info(
        req.method().as_str(),
        &scheme,
        &host,
        port,
        &path,
        req.headers(),
        client_ip.clone(),
    );
    let resolved = state.rules.read().unwrap().resolve(&info);
    let started = Instant::now();
    let time_ms = now_ms();

    // Short-circuit rules (redirect, mocked status, file) skip the upstream.
    if let Some(resp) = apply::short_circuit(&info, &resolved) {
        tracing::info!("{} {} -> short-circuit", info.method, info.full_url);
        state.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: "short-circuit".to_string(),
            duration_ms: started.elapsed().as_millis(),
        });
        return Ok(resp);
    }

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(req, &info, &resolved, &scheme, &host, port).await;
    }

    let mut target = apply::resolve_target(&info, &resolved);

    // A matched, registered plugin server handles the request instead of the
    // origin: route to the plugin over HTTP with x-whistle-* context headers.
    let plugin = apply::resolve_plugin(&resolved, &state.config.plugins);
    if let Some((_, phost, pport)) = &plugin {
        target.connect_host = phost.clone();
        target.connect_port = *pport;
        target.tls = false;
        target.proxy = None;
    }

    // Rewrite to origin-form + apply request-side rules.
    let (mut parts, incoming) = req.into_parts();
    let new_path = apply::rewrite_path(&info.path, &resolved);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &host, port, &scheme);
    parts.headers.remove("proxy-connection");
    apply::apply_request(&mut parts, &resolved);
    if let Some((name, _, _)) = &plugin {
        set_header_raw(&mut parts.headers, "x-whistle-plugin", name);
        set_header_raw(&mut parts.headers, "x-whistle-req-url", &info.full_url);
        set_header_raw(&mut parts.headers, "x-whistle-req-method", &info.method);
    }

    // Buffer + transform the request body only when a body/speed operator applies.
    let req_speed = apply::req_speed_kbps(&resolved);
    let req_body: DynBody = if apply::wants_req_body(&resolved) || req_speed.is_some() {
        let bytes = incoming.collect().await?.to_bytes();
        let new = apply::transform_req_body(bytes, &resolved);
        apply::strip_length_headers(&mut parts.headers);
        match req_speed {
            Some(kbps) => body::throttled(new, kbps),
            None => body::full(new),
        }
    } else {
        body::from_incoming(incoming)
    };
    let out_req = Request::from_parts(parts, req_body);

    if let Some(ms) = apply::req_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    tracing::info!(
        "{} {} -> {}:{} ({})",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port,
        if target.tls { "https" } else { "http" }
    );

    let upstream_resp = upstream::forward(&target, out_req).await?;

    if let Some(ms) = apply::res_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // Apply response-side rules.
    let (mut parts, body) = upstream_resp.into_parts();
    apply::apply_response(&mut parts, &resolved);

    let res_speed = apply::res_speed_kbps(&resolved);
    let res_script = resolved
        .value("resScript")
        .and_then(script::load_script);
    let res_body: DynBody =
        if apply::wants_res_body(&resolved) || res_speed.is_some() || res_script.is_some() {
            let bytes = body.collect().await?.to_bytes();
            let mut new = apply::transform_res_body(bytes, &resolved);
            if let Some(src) = &res_script {
                let hv: Vec<(String, String)> = parts
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body_str = String::from_utf8_lossy(&new).into_owned();
                if let Some(r) = script::run_res_script(
                    src,
                    &info.method,
                    &info.full_url,
                    parts.status.as_u16(),
                    &hv,
                    &body_str,
                ) {
                    if let Some(st) = r.status {
                        if let Ok(s) = StatusCode::from_u16(st) {
                            parts.status = s;
                        }
                    }
                    for (k, v) in r.headers {
                        set_header_raw(&mut parts.headers, &k, &v);
                    }
                    if let Some(b) = r.body {
                        new = Bytes::from(b);
                    }
                }
            }
            apply::strip_length_headers(&mut parts.headers);
            match res_speed {
                Some(kbps) => body::throttled(new, kbps),
                None => body::full(new),
            }
        } else {
            body::from_incoming(body)
        };

    let mut target_desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        target_desc.push_str(" (via proxy)");
    }
    state.record(Session {
        id: 0,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: parts.status.as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc,
        duration_ms: started.elapsed().as_millis(),
    });

    Ok(Response::from_parts(parts, res_body))
}

/// True if the request asks to upgrade the protocol (e.g. a WebSocket handshake).
fn is_upgrade(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    let conn_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    conn_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// Forward an upgrade handshake and, on `101`, tunnel bytes both ways.
/// This is how WebSocket (`ws://`/`wss://`) traffic is proxied.
async fn serve_upgrade(
    mut req: Request<Incoming>,
    info: &ReqInfo,
    resolved: &Resolved,
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<Response<DynBody>> {
    let target = apply::resolve_target(info, resolved);
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream handshake request (upgrades carry no body).
    let (mut parts, _body) = req.into_parts();
    let new_path = apply::rewrite_path(&info.path, resolved);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, host, port, scheme);
    parts.headers.remove("proxy-connection");
    apply::apply_request(&mut parts, resolved);
    let out_req = Request::from_parts(parts, body::empty());

    tracing::info!(
        "{} {} -> upgrade {}:{}",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port
    );

    let mut resp = upstream::forward(&target, out_req).await?;
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade; relay its response verbatim.
        let (p, b) = resp.into_parts();
        return Ok(Response::from_parts(p, body::from_incoming(b)));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut resp);
    let (p, _b) = resp.into_parts();

    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok((client_io, upstream_io)) => {
                let mut c = TokioIo::new(client_io);
                let mut u = TokioIo::new(upstream_io);
                if let Err(err) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
                    tracing::debug!("ws tunnel closed: {err}");
                }
            }
            Err(err) => tracing::debug!("ws upgrade failed: {err}"),
        }
    });

    // Relay the 101 (with Sec-WebSocket-Accept etc.) so the client handshake completes.
    Ok(Response::from_parts(p, body::empty()))
}

/// Set/replace a header (empty value deletes); used by response scripts.
fn set_header_raw(headers: &mut hyper::HeaderMap, name: &str, value: &str) {
    let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if value.is_empty() {
        headers.remove(&name);
    } else if let Ok(v) = hyper::header::HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Ensure a correct `Host` header for the upstream request.
fn ensure_host_header(
    headers: &mut hyper::HeaderMap,
    host: &str,
    port: u16,
    scheme: &str,
) {
    let default_port = if scheme == "https" { 443 } else { 80 };
    let value = if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    if let Ok(v) = hyper::header::HeaderValue::from_str(&value) {
        headers.insert(hyper::header::HOST, v);
    }
}

/// Parse `host:port` out of a CONNECT authority.
fn authority_host_port(uri: &Uri) -> Option<(String, u16)> {
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(443);
    Some((host, port))
}
