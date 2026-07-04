//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
pub mod body;
pub mod upstream;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

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

/// Shared server state.
pub struct AppState {
    pub config: Config,
    pub rules: RwLock<RuleManager>,
    pub ca: Arc<CertAuthority>,
}

/// Where a request originated, which decides how we derive its target.
#[derive(Clone)]
enum Origin {
    /// A normal absolute-form forward-proxy request.
    Forward,
    /// A request seen inside an intercepted CONNECT tunnel.
    Mitm { host: String, port: u16 },
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
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { top_level(state, req).await }
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
) -> Result<Response<DynBody>, Infallible> {
    if req.method() == hyper::Method::CONNECT {
        return Ok(handle_connect(state, req));
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return Ok(guard(serve(state, req, Origin::Forward).await));
    }
    Ok(local_ui(&state, req))
}

/// Handle a CONNECT: acknowledge, then intercept the tunnel with MITM.
fn handle_connect(state: Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let Some((host, port)) = authority_host_port(req.uri()) else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"bad CONNECT target")))
            .unwrap();
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(err) = mitm_serve(state, upgraded, host, port).await {
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

/// TLS-accept the intercepted tunnel and serve HTTP over it.
async fn mitm_serve(
    state: Arc<AppState>,
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    port: u16,
) -> Result<()> {
    let acceptor = state.ca.acceptor_for(&host)?;
    let tls = acceptor.accept(TokioIo::new(upgraded)).await?;
    let io = TokioIo::new(tls);

    let service = service_fn(move |req| {
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
        };
        async move { Ok::<_, Infallible>(guard(serve(state, req, origin).await)) }
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
        Origin::Mitm { host, port } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            ("https".to_string(), host.clone(), *port, path)
        }
    };

    let info = apply::build_req_info(req.method().as_str(), &scheme, &host, port, &path);
    let resolved = state.rules.read().unwrap().resolve(&info);

    // Short-circuit rules (redirect, mocked status, file) skip the upstream.
    if let Some(resp) = apply::short_circuit(&info, &resolved) {
        tracing::info!("{} {} -> short-circuit", info.method, info.full_url);
        return Ok(resp);
    }

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(req, &info, &resolved, &scheme, &host, port).await;
    }

    let target = apply::resolve_target(&info, &resolved);

    // Rewrite to origin-form + apply request-side rules.
    let (mut parts, incoming) = req.into_parts();
    let new_path = apply::rewrite_path(&info.path, &resolved);
    parts.uri = Uri::try_from(new_path.as_str()).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &host, port, &scheme);
    parts.headers.remove("proxy-connection");
    apply::apply_request(&mut parts, &resolved);

    // Buffer + transform the request body only when a body operator applies.
    let req_body: DynBody = if apply::wants_req_body(&resolved) {
        let bytes = incoming.collect().await?.to_bytes();
        let new = apply::transform_req_body(bytes, &resolved);
        apply::strip_length_headers(&mut parts.headers);
        body::full(new)
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

    let res_body: DynBody = if apply::wants_res_body(&resolved) {
        let bytes = body.collect().await?.to_bytes();
        let new = apply::transform_res_body(bytes, &resolved);
        apply::strip_length_headers(&mut parts.headers);
        body::full(new)
    } else {
        body::from_incoming(body)
    };
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

/// The built-in page served when a browser hits the proxy port directly.
fn local_ui(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let path = req.uri().path();
    if path == "/rootCA.crt" || path == "/rootca.crt" {
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-x509-ca-cert",
            )
            .header(
                hyper::header::CONTENT_DISPOSITION,
                "attachment; filename=\"whistle-rs-rootCA.crt\"",
            )
            .body(body::full(Bytes::from(
                state.ca.root_cert_pem().to_string(),
            )))
            .unwrap();
    }

    let rule_count = state.rules.read().unwrap().len();
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>whistle-rs</title>\
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:680px;margin:40px auto;padding:0 16px;color:#222}}\
code{{background:#f4f4f4;padding:2px 6px;border-radius:4px}}a{{color:#2d7ff9}}</style></head><body>\
<h1>whistle-rs</h1><p>HTTP/HTTPS debugging proxy (Rust port) — v{version}.</p>\
<p><b>{count}</b> rules loaded.</p>\
<h2>Setup</h2><ol>\
<li>Point your client's HTTP &amp; HTTPS proxy at <code>{host}:{port}</code>.</li>\
<li>To intercept HTTPS, install the root CA: <a href=\"/rootCA.crt\">download rootCA.crt</a> and trust it.</li>\
</ol></body></html>",
        version = crate::config::VERSION,
        count = rule_count,
        host = state.config.host.map(|h| h.to_string()).unwrap_or_else(|| "127.0.0.1".to_string()),
        port = state.config.port,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body::full(Bytes::from(html)))
        .unwrap()
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
