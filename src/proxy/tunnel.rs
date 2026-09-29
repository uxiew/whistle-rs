//! Everything that arrives on the proxy port before it is a request: telling a
//! plain request from a `CONNECT`, deciding what a tunnel is — refused, relayed
//! unread, or intercepted — and serving the HTTP/1.1 or h2 inside an
//! intercepted one. SOCKS connections arrive here too.

use super::*;

/// Entry point for every request arriving on the main port.
pub(super) async fn top_level(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    if req.method() == hyper::Method::CONNECT {
        return handle_connect(state, req, peer).await;
    }
    // Absolute-form URI => proxied request. Origin-form => a direct hit on us.
    if req.uri().authority().is_some() {
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    // …unless the path opens with the escape hatch. Everything addressed to the
    // proxy's own port is its console, and `/-/` (or `/_/`) is how upstream lets
    // a client say "this one is an ordinary request, not an instruction to you"
    // — it strips the prefix and lets the request fall through to the rules
    // (`_original/biz/index.js:114-129`, and the FAQ's answer to "how do I reach
    // the proxy port without being taken for an internal request").
    //
    // The request then names *this* proxy, so what happens next is a rule's to
    // decide: `http://127.0.0.1:8899/x https://api.example.com/x` is the FAQ's
    // own example. With no rule it meets the self-loop guard and answers 302,
    // which is what upstream does with it too.
    if let Some(uri) = bypass_console(&req) {
        *req.uri_mut() = uri;
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    // …and unless it names somebody else. "Addressed to the proxy's own port"
    // is what the `Host` says, not where the socket went: an origin-form
    // request for `api.example.com` is a client with no proxy configured — a
    // hosts-file entry, a WebSocket library pointed at the proxy — and whistle
    // forwards it like any other (`_original/biz/index.js:98-106`,
    // `lib/upgrade.js:23-24`: the console only under one of its names, or this
    // machine's address on the proxy port). This port sent every such request
    // to the console, which after the rebinding check answered 403.
    //
    // A name that resolves back to this proxy is not served the console under
    // it — that is the rebinding attack — but redirected to the console's
    // address, in `serve`.
    if let Some(uri) = forwarded_by_name(&state, &req) {
        // This proxy sent the request here itself: `serve` did not know the
        // name for one of its own addresses. Refused rather than sent round
        // again — see `upstream::LOOP_HEADER`.
        if req
            .headers()
            .get(upstream::LOOP_HEADER)
            .is_some_and(|v| v == upstream::loop_nonce())
        {
            return Ok(loop_detected(&uri));
        }
        *req.uri_mut() = uri;
        return serve_recorded(state, req, Origin::Forward, peer).await;
    }
    req.headers_mut().remove(upstream::LOOP_HEADER);
    Ok(webui::handle(&state, req).await)
}

/// The absolute-form URI of an origin-form request whose `Host` is not a name
/// for the console, or `None` when it is one (or says nothing).
pub(super) fn forwarded_by_name<B>(state: &Arc<AppState>, req: &Request<B>) -> Option<hyper::Uri> {
    let host = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
    if host.is_empty() || webui::host_names_console(state, host) {
        return None;
    }
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    format!("http://{host}{path}").parse().ok()
}

/// `508 Loop Detected` for a request this proxy forwarded to itself.
pub(super) fn loop_detected(uri: &hyper::Uri) -> Response<DynBody> {
    tracing::warn!("{uri} came back to this proxy after it forwarded it; refusing");
    Response::builder()
        .status(StatusCode::LOOP_DETECTED)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(format!(
            "whistle-rs: {uri} resolves to this proxy, which forwarded it to itself\n"
        ))))
        .expect("static 508")
}

/// `/-/…` and `/_/…` on the proxy's own port: the absolute-form URI the request
/// would have had if the client had gone through the proxy properly.
///
/// Returns `None` when the path carries neither prefix, or when there is no
/// `Host` header to build an authority from — a request with neither is not one
/// this proxy can forward anywhere.
pub(super) fn bypass_console(req: &Request<Incoming>) -> Option<hyper::Uri> {
    let path_and_query = req.uri().path_and_query()?.as_str();
    let rest = path_and_query
        .strip_prefix("/-/")
        .or_else(|| path_and_query.strip_prefix("/_/"))?;
    let host = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
    format!("http://{host}/{rest}").parse().ok()
}

/// Handle a CONNECT: refuse it, relay it once the far end has answered, or
/// acknowledge it and decide at the ClientHello whether to intercept.
pub(super) async fn handle_connect(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    let Some((host, port)) = authority_host_port(req.uri()) else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"bad CONNECT target")))
            .unwrap());
    };

    // The last moment a tunnel can be refused: everything below this line has
    // already told the client it is open. See [`tunnel_aborted`].
    if tunnel_aborted(&state, &host, port, peer) {
        return Err(Destroyed);
    }

    if let Some(resolution) = relayed_unread(&state, &host, port, peer) {
        return relay_before_reply(state, req, &host, port, peer, resolution).await;
    }

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

    Ok(connect_established())
}

fn connect_established() -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(body::empty())
        .unwrap()
}

/// Is this tunnel already decided against reading, on the CONNECT alone — and
/// if so, the connection's rules, resolved once, to route it by.
///
/// Two things decide it that early, and both are answers `sni::decide` would
/// reach after the ClientHello anyway: interception switched off for every
/// connection (`--no-intercept-https`, and the modes that lock capture off),
/// and `disable://intercept` (or `https`, `capture`) on the address the client
/// asked for. Upstream decides at the same point, on the same address
/// (`isIntercept()`, `_original/lib/tunnel.js:201-215`, against
/// `tunnel://host:port`). Anything else needs the ClientHello, which only
/// arrives once the CONNECT has been answered.
fn relayed_unread(
    state: &Arc<AppState>,
    host: &str,
    port: u16,
    peer: SocketAddr,
) -> Option<(crate::rules::ReqInfo, crate::rules::Resolved)> {
    let everything = !state.config.intercepts_https();
    let rules = state.rules.read().unwrap();
    // One `bool` per group when neither applies, which is the default setup.
    if !everything && !rules.has_no_intercept() {
        return None;
    }
    // No ClientHello yet, so no SNI: the same reading `tunnel_aborted` makes.
    let info = sni::connection_req_info(host, port, peer, false);
    let resolved = rules.resolve(&info);
    (everything || sni::no_intercept(&resolved)).then_some((info, resolved))
}

/// Relay a tunnel nobody is going to read, answering the CONNECT only once the
/// far end has answered.
///
/// Upstream dials first and writes `200 Connection Established` from the
/// connect callback (`handleConnect` → `sendEstablished`,
/// `_original/lib/tunnel.js:637-695`). When the name does not resolve or the
/// dial fails, it destroys the client's socket without a reply (`emitError`,
/// `:833-836`), so the client's CONNECT itself fails — Chrome reports
/// `ERR_TUNNEL_CONNECTION_FAILED`. This port used to answer `200` to every
/// tunnel first, so a relay that could not connect looked to the client like a
/// server that accepted the connection and hung up mid-handshake.
///
/// Only for tunnels [`relayed_unread`] decided on: one that may yet be
/// intercepted has to be acknowledged before its ClientHello can be read, and a
/// relay decided *there* still dials after the `200` — as upstream's does on
/// that path (`rollBackTunnel`, `tunnel.js:270-271`).
async fn relay_before_reply(
    state: Arc<AppState>,
    req: Request<Incoming>,
    host: &str,
    port: u16,
    peer: SocketAddr,
    (info, resolved): (crate::rules::ReqInfo, crate::rules::Resolved),
) -> Result<Response<DynBody>, Destroyed> {
    let started = Instant::now();
    let session = tunnel_session_of(&info, &resolved, peer, now_ms());
    // Not answered, and now never will be.
    let refused = |session: Session| Tunnel {
        state: &state,
        session: Session {
            status: 0,
            ..session
        },
        started,
    };
    let target = match sni::relay_target(&state, &info, &resolved).await {
        Ok(target) => target,
        Err(why) => {
            let err = anyhow::anyhow!("tunnel to {host}:{port} not routable: {why}");
            refused(session).fail("", outcome::Phase::Rules, &err);
            return Err(Destroyed);
        }
    };
    let timings = timing::Timings::new();
    let origin = match upstream::tunnel_stream(&target, &timings).await {
        Ok(origin) => origin,
        Err(err) => {
            let mut tunnel = refused(session);
            tunnel.session.timings = Some(timings);
            tunnel.fail(&target_desc(&target), outcome::Phase::Internal, &err);
            return Err(Destroyed);
        }
    };
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let client = sni::Prefixed::new(Vec::new(), TokioIo::new(upgraded));
                let tunnel = Tunnel {
                    state: &state,
                    session,
                    started,
                };
                if let Err(err) =
                    relay_dialled(client, origin, &target, timings, Some(tunnel)).await
                {
                    tracing::debug!("relay error: {err}");
                }
            }
            Err(err) => tracing::debug!("connect upgrade failed: {err}"),
        }
    });
    Ok(connect_established())
}

/// Does a rule refuse to carry this connection — and, when one does, record the
/// refusal so an aborted tunnel is visible rather than simply absent.
///
/// This is whistle's tunnel-side abort. Upstream tests it twice on a CONNECT it
/// carries: once before the origin is dialled (`needAbortReq`,
/// `_original/lib/tunnel.js:372-374`) and once instead of writing the CONNECT
/// reply (`needAbortRes`, `tunnel.js:748-750`). Both end in the same
/// `reqSocket.destroy()`, so the client observes the same thing either way — a
/// CONNECT that is never answered — and here the two collapse into one gate,
/// because hyper hands over the tunnel's bytes only *after* the answer to the
/// CONNECT has gone out. What that costs is `abortRes`'s one distinguishing
/// effect: upstream has dialled the origin by the time it fires, and this port
/// has not. Buying it back would mean acknowledging the CONNECT first, and then
/// neither gate can produce the silence the abort exists for.
///
/// `disable://tunnel` is the third arm of the same two predicates — on a tunnel
/// it *is* an abort (`_original/lib/util/index.js:3900,:3912`) — and, like the
/// other two, `disable://abort` calls it off, that being the first thing both
/// predicates test (`util/index.js:3893,:3905`).
///
/// Upstream skips this gate entirely on a tunnel it decides to intercept
/// (`tunnel.js:251-277` dispatches to the MITM server and returns, so
/// `handleTunnel` is never reached) and lets the abort bite on each request
/// inside instead. This port cannot follow it there: the interception decision
/// needs the ClientHello, which only arrives once the CONNECT has been
/// acknowledged. So the gate runs for every connection, intercepted or relayed,
/// and an aborted CONNECT is one refused session rather than N refused requests.
/// Requests inside a tunnel that is *not* refused still meet the request-side
/// gate in [`serve`], and a path-scoped `enable://abort` only ever reaches that
/// one — a connection has no path to match.
///
/// The connection is matched on the [`ReqInfo`] the SNI stage already defines
/// ([`sni::connection_req_info`]): the address, the client, `from:tunnel`, and
/// nothing invented. One resolution per connection is what upstream pays too
/// (`rules.initRules(req)` per CONNECT, `tunnel.js:155-160`), and against the
/// TLS handshake that follows it does not show up.
pub(super) fn tunnel_aborted(
    state: &Arc<AppState>,
    host: &str,
    port: u16,
    peer: SocketAddr,
) -> bool {
    let started = Instant::now();
    let time_ms = now_ms();
    // Scoped so the read guard is dropped before anything is recorded.
    let (info, resolved) = {
        let rules = state.rules.read().unwrap();
        // No ClientHello has been read yet, so this connection has named no
        // server: `from:sni` is false, not unknown.
        let info = sni::connection_req_info(host, port, peer, false);
        let resolved = rules.resolve(&info);
        (info, resolved)
    };
    let disabled = apply::disabled_flags(&resolved);
    let refuses_tunnel = disabled.contains("tunnel")
        && !disabled.contains("abort")
        && !(disabled.contains("abortReq") && disabled.contains("abortRes"));
    if !apply::aborts_request(&resolved) && !apply::aborts_response(&resolved) && !refuses_tunnel {
        return false;
    }
    tracing::info!("CONNECT {} -> aborted", info.full_url);
    state.record(Session {
        id: 0,
        time_ms,
        // Upstream records the tunnel under the method the client sent, which
        // for a SOCKS client is the CONNECT its own front end issued against
        // whistle's port (`_original/lib/index.js:166-173`).
        method: "CONNECT".to_string(),
        // The URL the rules matched, so the row and the rule agree.
        url: info.full_url.clone(),
        // Nothing answered and nothing will: upstream writes the string
        // `'aborted'` here (`tunnel.js:31-36`) where this port has a number, and
        // 0 is the console's "no status" (it already paints it as a warning).
        status: 0,
        client_ip: Some(peer.ip().to_string()),
        // Not "somewhere, aborted": no address was dialled at all.
        target: "aborted".to_string(),
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(&resolved),
        rules: matched_ops(&resolved),
        // A connection has no request headers the rules were allowed to see —
        // see [`sni::connection_req_info`] — so showing some here would be
        // showing what did not take part in the decision.
        error: aborted(
            "tunnel refused by a rule (enable://abort, abortReq, abortRes or disable://tunnel)",
        ),
        ..Default::default()
    });
    true
}

/// Serve HTTP over an intercepted tunnel stream, optionally TLS-decrypting first.
/// Shared by CONNECT interception and the SOCKS server.
pub(crate) async fn serve_tunnel<S>(
    state: Arc<AppState>,
    mut stream: S,
    host: String,
    port: u16,
    peer: SocketAddr,
    tls: bool,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if tls {
        let started = Instant::now();
        let time_ms = now_ms();
        // Read the ClientHello before deciding anything, because two decisions
        // depend on it: which name the certificate has to be for, and what an
        // `sniCallback://` plugin is being asked about. The bytes are replayed
        // either way — see [`sni`].
        let hello = sni::peek_client_hello(&mut stream).await;
        let has_sni = hello.server_name.is_some();
        // The name the client will check is the one it asked for; the tunnel's
        // own hostname is only the fallback for a client that asked for nothing
        // (upstream's `useSNI || socket.tunnelHostname`).
        let servername = hello.server_name.unwrap_or_else(|| host.clone());
        // A tunnel is opened to an address, not to a protocol. This port used to
        // assume TLS and hand every one of them to the acceptor, which turns a
        // tunnel carrying anything else into a TLS alert — see [`sni::Carried`].
        let carried = sni::carried_protocol(&hello.prefix);
        // A client that closed the tunnel without sending a byte asked for
        // nothing, and leaves no session: that is a connection opened and
        // abandoned, which clients do all the time.
        let asked = !hello.prefix.is_empty();
        let stream = sni::Prefixed::new(hello.prefix, stream);
        // The session a tunnel leaves when nothing inside it is read — relayed,
        // refused, or turned away at the handshake. Built only then: it costs a
        // second rule resolution, which an intercepted tunnel never pays.
        let session = || Tunnel {
            state: &state,
            session: tunnel_session(&state, &servername, port, peer, has_sni, time_ms),
            started,
        };
        let acceptor =
            match sni::decide(&state, &servername, &host, port, peer, has_sni, carried).await {
                sni::Decision::Generated => match state.ca.acceptor_for(&servername) {
                    Ok(acceptor) => acceptor,
                    Err(err) => {
                        let err = err.context(format!("a certificate for {servername}"));
                        if asked {
                            session().fail("intercept", outcome::Phase::Internal, &err);
                        }
                        return Err(err);
                    }
                },
                sni::Decision::Plugin(acceptor) => acceptor,
                sni::Decision::Bypass(target) => {
                    return relay_recorded(stream, &target, asked.then(session)).await;
                }
                // Cleartext inside the tunnel: no handshake to make, and the
                // same two servers the SOCKS path already reaches for.
                sni::Decision::Cleartext(sni::Carried::H2c) => {
                    // `tls: false`: the connection genuinely is not encrypted, so
                    // an `https://` pattern must not match it. Upstream reaches
                    // its h2 server before it ever sets `socket.curUrl` to an
                    // `https://` URL (`_original/lib/https/index.js:1280-1282`
                    // returns above `:1297`), which is the same reading.
                    return serve_intercepted_h2(
                        state,
                        TokioIo::new(stream),
                        host,
                        port,
                        peer,
                        false,
                        false,
                    )
                    .await;
                }
                sni::Decision::Cleartext(_) => {
                    return serve_intercepted(
                        state,
                        TokioIo::new(stream),
                        host,
                        port,
                        peer,
                        false,
                        false,
                    )
                    .await;
                }
                // A proxy rule that cannot be honoured closes the connection
                // rather than quietly sending the bytes direct — the same call
                // the request path makes, where it answers 502.
                sni::Decision::Unroutable(why) => {
                    let err = anyhow::anyhow!("tunnel to {host}:{port} not routable: {why}");
                    if asked {
                        session().fail("", outcome::Phase::Rules, &err);
                    }
                    return Err(err);
                }
            };
        let tls_stream = match acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(err) => {
                if asked {
                    session().fail_at(
                        "intercept",
                        outcome::Failure::new(outcome::Phase::ClientTls, client_tls_failure(&err)),
                    );
                }
                return Err(err.into());
            }
        };
        let conn = tls_stream.get_ref().1;
        let is_h2 = conn.alpn_protocol() == Some(b"h2");
        // Read once, off the completed handshake: whether the client named a
        // server in its ClientHello. Costs nothing — rustls already parsed it to
        // pick a certificate. Deliberately not taken from `has_sni` above, so
        // `from:sni` keeps answering off the handshake rustls actually
        // completed, exactly as it did before the peek existed.
        let sni = conn.server_name().is_some();
        if is_h2 {
            serve_intercepted_h2(state, TokioIo::new(tls_stream), host, port, peer, true, sni).await
        } else {
            serve_intercepted(state, TokioIo::new(tls_stream), host, port, peer, true, sni).await
        }
    } else {
        // No handshake, so no SNI — a plain-HTTP tunnel is `from:tunnel` but
        // never `from:sni`.
        serve_intercepted(state, TokioIo::new(stream), host, port, peer, false, false).await
    }
}

/// A tunnel whose contents are not read, on its way to becoming its one
/// session. An intercepted tunnel has none of its own — each request inside it
/// is one — but a tunnel that is relayed, refused, or turned away at the
/// handshake has nothing else to show for it.
pub(super) struct Tunnel<'a> {
    pub(super) state: &'a Arc<AppState>,
    pub(super) session: Session,
    pub(super) started: Instant,
}

impl Tunnel<'_> {
    /// Record the tunnel as failed with `err`: at the phase the error was
    /// tagged with where it happened, or at `phase`.
    pub(super) fn fail(self, target: &str, phase: outcome::Phase, err: &anyhow::Error) {
        let phase = outcome::phase_of(err).unwrap_or(phase);
        self.fail_at(target, outcome::Failure::new(phase, format!("{err:#}")));
    }

    pub(super) fn fail_at(self, target: &str, failure: outcome::Failure) {
        let url = self.session.url.clone();
        let id = self.state.record_visible(Session {
            target: target.to_string(),
            duration_ms: self.started.elapsed().as_millis(),
            error: outcome::Outcome::failed(failure.clone()),
            ..self.session
        });
        log_failure(id, "CONNECT", &url, &failure);
    }
}

/// The session of a tunnel whose contents are not read: the CONNECT itself,
/// matched exactly as the interception stage matched it.
pub(super) fn tunnel_session(
    state: &AppState,
    servername: &str,
    port: u16,
    peer: SocketAddr,
    has_sni: bool,
    time_ms: u128,
) -> Session {
    let (info, resolved) = {
        let rules = state.rules.read().unwrap();
        let info = sni::connection_req_info(servername, port, peer, has_sni);
        let resolved = rules.resolve(&info);
        (info, resolved)
    };
    tunnel_session_of(&info, &resolved, peer, time_ms)
}

/// [`tunnel_session`], from a resolution already made.
fn tunnel_session_of(
    info: &crate::rules::ReqInfo,
    resolved: &crate::rules::Resolved,
    peer: SocketAddr,
    time_ms: u128,
) -> Session {
    Session {
        time_ms,
        method: "CONNECT".to_string(),
        url: info.full_url.clone(),
        // The CONNECT was answered before the row appears: hyper hands over a
        // tunnel's bytes only after its `200` has gone out — see
        // [`tunnel_aborted`] — and a relay decided on the CONNECT answers once
        // the far end has ([`relay_before_reply`], which writes 0 when it never
        // does). A SOCKS client was likewise told "granted".
        status: 200,
        client_ip: Some(peer.ip().to_string()),
        log: log_labels(resolved),
        rules: matched_ops(resolved),
        ..Default::default()
    }
}

/// Relay a tunnel nobody reads, and record it: where it went and whether it
/// got there. `tunnel` is `None` for a client that asked for nothing.
///
/// A relayed tunnel used to leave no trace at all, succeeding or failing — so
/// `disable://intercept`, a plugin's `sniCallback` declining, `--no-intercept-https`
/// and every tunnel carrying something that is not HTTP were invisible in the
/// console, and a relay that could not connect was a `warn` in the log. Upstream
/// shows each as a tunnel row. The row appears once the far end is connected,
/// and is complete when the tunnel closes.
pub(super) async fn relay_recorded<S>(
    client: sni::Prefixed<S>,
    target: &upstream::Target,
    tunnel: Option<Tunnel<'_>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let timings = timing::Timings::new();
    let origin = match upstream::tunnel_stream(target, &timings).await {
        Ok(origin) => origin,
        Err(err) => {
            match tunnel {
                Some(mut t) => {
                    t.session.timings = Some(timings);
                    t.fail(&target_desc(target), outcome::Phase::Internal, &err);
                }
                None => tracing::debug!(
                    "relaying to {}:{} failed: {err:#}",
                    target.connect_host,
                    target.connect_port
                ),
            }
            return Err(err);
        }
    };
    relay_dialled(client, origin, target, timings, tunnel).await
}

/// The rest of [`relay_recorded`], once the far end is connected: the row
/// appears now, and is complete when the tunnel closes.
async fn relay_dialled<S>(
    client: sni::Prefixed<S>,
    origin: upstream::BoxedIo,
    target: &upstream::Target,
    timings: timing::Timings,
    tunnel: Option<Tunnel<'_>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let open = tunnel.and_then(|t| {
        let (_, open) = t.state.record_open(Session {
            target: format!("{} (tunnel)", target_desc(target)),
            duration_ms: t.started.elapsed().as_millis(),
            timings: Some(timings),
            ..t.session
        });
        open.map(|session| (t.state, session))
    });
    let relayed = sni::relay(client, origin).await;
    if let Some((state, session)) = open {
        state.complete(&session);
    }
    relayed
}

/// What a handshake the client broke off most likely means, in words — this is
/// the one failure people meet on the first day, and the raw alert name does
/// not say what to do about it.
pub(super) fn client_tls_failure(err: &std::io::Error) -> String {
    use rustls::AlertDescription as Alert;
    let refused = match err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::AlertReceived(alert)) => matches!(
            alert,
            Alert::UnknownCA
                | Alert::BadCertificate
                | Alert::CertificateUnknown
                | Alert::UnsupportedCertificate
                | Alert::AccessDenied
        ),
        _ => false,
    };
    let hung_up = matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
    );
    match (refused, hung_up) {
        (true, _) => format!(
            "the client refused this proxy's certificate ({err}): it does not trust the \
             whistle-rs root certificate, or it pins the server's own"
        ),
        (false, true) => format!(
            "the client hung up during the TLS handshake ({err}); a client that does not \
             trust the whistle-rs root certificate often does"
        ),
        (false, false) => format!("the TLS handshake with the client failed: {err}"),
    }
}

/// Serve an intercepted HTTP/2 connection (ALPN negotiated `h2`). Its requests
/// go on over h2 to an HTTPS origin that offers it and over HTTP/1.1 otherwise
/// (`upstream::offers_h2`); hyper translates between the two.
pub(super) async fn serve_intercepted_h2<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: SocketAddr,
    tls: bool,
    sni: bool,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // Every stream on this connection shares one pool; see `pool`.
    let pool = pool::ConnPool::new();
    let service = service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(pool.clone());
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls,
            sni,
        };
        async move { serve_recorded(state, req, origin, peer).await }
    });

    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Run the HTTP/1.1 server over an already-prepared tunnel IO.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_intercepted<I>(
    state: Arc<AppState>,
    io: I,
    host: String,
    port: u16,
    peer: SocketAddr,
    tls: bool,
    sni: bool,
) -> Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // One pool for the tunnel: a tunnel is one client connection. See `pool`.
    let pool = pool::ConnPool::new();
    let service = service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(pool.clone());
        let state = state.clone();
        let origin = Origin::Mitm {
            host: host.clone(),
            port,
            tls,
            sni,
        };
        async move { serve_recorded(state, req, origin, peer).await }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tunnel_abort_tests {
    use super::super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// State over a storage directory nobody else touches, with `rules` loaded.
    pub(crate) fn state_with(rules: &str) -> Arc<AppState> {
        state_with_plugins(rules, crate::plugins::Plugins::new())
    }

    /// [`state_with`], with `plugins` as the registry.
    pub(crate) fn state_with_plugins(
        rules: &str,
        plugins: crate::plugins::Plugins,
    ) -> Arc<AppState> {
        state_with_config(rules, plugins, |_| {})
    }

    /// [`state_with_plugins`], with the config adjusted by `tweak` first.
    pub(crate) fn state_with_config(
        rules: &str,
        plugins: crate::plugins::Plugins,
        tweak: impl FnOnce(&mut crate::config::Config),
    ) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut config = crate::config::Config {
            port: 0,
            host: Some("127.0.0.1".parse().unwrap()),
            storage_dir: std::env::temp_dir()
                .join(format!("whistle-rs-abort-{}-{n}", std::process::id())),
            persist_sessions: false,
            ..crate::config::Config::default()
        };
        tweak(&mut config);
        let ca = CertAuthority::load_or_create(&config).expect("root CA");
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        Arc::new(AppState::with_plugins(config, mgr, ca, plugins))
    }

    pub(crate) fn peer() -> SocketAddr {
        "127.0.0.1:51234".parse().unwrap()
    }

    /// Would `rules` refuse a tunnel to `example.com:443`?
    fn refuses(rules: &str) -> bool {
        tunnel_aborted(&state_with(rules), "example.com", 443, peer())
    }

    /// The tunnel gate is armed and called off by exactly the flags the request
    /// gate is, because it is the same pair of predicates
    /// (`needAbortReq`/`needAbortRes`, `_original/lib/util/index.js:3891-3913`)
    /// read at a different moment.
    #[test]
    fn a_tunnel_is_refused_by_either_spelling_and_spared_by_either_cancellation() {
        for rules in [
            "example.com enable://abort",
            "example.com enable://abortReq",
            "example.com enable://abortRes",
            // One side cancelled still leaves the other armed, and on a tunnel
            // both end in the same silence.
            "example.com enable://abort disable://abortReq",
            "example.com enable://abort disable://abortRes",
        ] {
            assert!(refuses(rules), "{rules}");
        }
        for rules in [
            "",
            "example.com enable://abort disable://abort",
            "example.com enable://abortReq disable://abortReq",
            // A different host's rule is a different host's rule.
            "other.test enable://abort",
        ] {
            assert!(!refuses(rules), "{rules}");
        }
    }

    /// `disable://tunnel` has no meaning anywhere else — upstream reads it only
    /// as the last arm of these two predicates (`util/index.js:3900,:3912`), so
    /// this is the one path on which it does anything at all.
    #[test]
    fn disable_tunnel_refuses_the_connection_and_disable_abort_calls_it_off() {
        assert!(refuses("example.com disable://tunnel"));
        assert!(!refuses("example.com disable://tunnel disable://abort"));
        // Each predicate tests its own cancellation before it reaches the tunnel
        // arm, so cancelling both named gates cancels that arm with them.
        assert!(!refuses(
            "example.com disable://tunnel disable://abortReq disable://abortRes"
        ));
    }

    /// A connection has no path, so a path-scoped abort cannot match one — and
    /// must not, or `example.com/api enable://abort` would take the whole host
    /// off the air instead of one endpoint. The request inside still meets the
    /// request-side gate.
    #[test]
    fn a_path_scoped_abort_leaves_the_tunnel_alone() {
        assert!(!refuses("example.com/api enable://abort"));
    }

    /// A refused tunnel is a session, not a silence: whistle emits the request
    /// event before the gate and marks the result `aborted`
    /// (`_original/lib/tunnel.js:338,:31-36`), so the console shows what was
    /// refused. Recording nothing would make an abort indistinguishable from a
    /// rule that never fired.
    #[test]
    fn an_aborted_tunnel_is_recorded_rather_than_vanishing() {
        let state = state_with("example.com enable://abort log://blocked");
        assert!(tunnel_aborted(&state, "example.com", 443, peer()));
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.front().expect("the refusal is recorded");
        assert_eq!(session.method, "CONNECT");
        assert_eq!(session.url, "https://example.com/");
        assert_eq!(session.status, 0, "nothing answered");
        assert_eq!(session.target, "aborted", "nothing was dialled");
        assert_eq!(session.client_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(session.log, ["blocked"]);
        assert!(
            session.rules.iter().any(|op| op.protocol == "enable"),
            "the rule that refused it is on the row"
        );
    }

    /// A tunnel nobody refused is not recorded here at all — this gate exists to
    /// stop connections, not to log every CONNECT twice.
    #[test]
    fn a_tunnel_no_rule_refuses_is_left_unrecorded() {
        let state = state_with("example.com enable://abort");
        assert!(!tunnel_aborted(&state, "other.test", 443, peer()));
        assert!(state.sessions.lock().unwrap().is_empty());
    }

    /// Start a proxy on an ephemeral port with `rules` loaded.
    pub(crate) async fn proxy_with(rules: &str) -> (Arc<AppState>, SocketAddr) {
        proxy_with_plugins(rules, crate::plugins::Plugins::new()).await
    }

    /// [`proxy_with`], with `plugins` as the registry.
    pub(crate) async fn proxy_with_plugins(
        rules: &str,
        plugins: crate::plugins::Plugins,
    ) -> (Arc<AppState>, SocketAddr) {
        serve(state_with_plugins(rules, plugins)).await
    }

    /// [`proxy_with`], with the config adjusted by `tweak`.
    pub(crate) async fn proxy_with_config(
        rules: &str,
        tweak: impl FnOnce(&mut crate::config::Config),
    ) -> (Arc<AppState>, SocketAddr) {
        serve(state_with_config(
            rules,
            crate::plugins::Plugins::new(),
            tweak,
        ))
        .await
    }

    /// Serve `state` on an ephemeral port.
    pub(crate) async fn serve(state: Arc<AppState>) -> (Arc<AppState>, SocketAddr) {
        let (listener, addr) = bind(&state).await.expect("bind");
        let serving = state.clone();
        tokio::spawn(async move {
            accept_loop(serving, listener, None).await.ok();
        });
        (state, addr)
    }

    /// `/-/` and `/_/` on the proxy's own port say "this is an ordinary request".
    ///
    /// Everything addressed to that port origin-form is the console, so a client
    /// with no proxy configured cannot otherwise reach a rule at all. Upstream
    /// strips the prefix and lets the request fall through
    /// (`_original/biz/index.js:114-129`); measured against whistle 2.10.8 with
    /// the FAQ's own example, both proxies land the request on the origin the
    /// rule names, and both answer the console's 404 without the prefix.
    #[tokio::test]
    async fn the_console_port_has_an_escape_hatch() {
        // A one-line origin, so the test can see *where* the request landed.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let origin = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("?").to_string();
                    let body = format!("LANDED {path}");
                    let res = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    sock.write_all(res.as_bytes()).await.ok();
                });
            }
        });

        // The pattern names the proxy's own port, which the test does not know
        // yet — so it is written as the regexp that any of them matches.
        let (_state, addr) = proxy_with(&format!(
            r"/^http:\/\/127\.0\.0\.1:\d+\/hop$/ http://{origin}/landed"
        ))
        .await;

        let get = |path: String| async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.ok();
            String::from_utf8_lossy(&got).to_string()
        };

        for prefix in ["/-/", "/_/"] {
            let answer = get(format!("{prefix}hop")).await;
            assert!(answer.starts_with("HTTP/1.1 200"), "{prefix}: {answer}");
            assert!(answer.contains("LANDED /landed"), "{prefix}: {answer}");
        }
        // Without the prefix the same path is the console's to answer.
        let answer = get("/hop".to_string()).await;
        assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    }

    /// End to end: the client's CONNECT is never answered. Upstream destroys the
    /// socket (`_original/lib/tunnel.js:372-374,:748-750`) rather than refusing
    /// with a status, and a status is what the whole feature is trying not to
    /// produce — a `502` to a CONNECT is a *served* answer a client can report,
    /// cache and retry against.
    #[tokio::test]
    async fn a_refused_connect_gets_no_reply_at_all() {
        let (state, addr) = proxy_with("blocked.test enable://abort").await;

        let mut refused = tokio::net::TcpStream::connect(addr).await.unwrap();
        refused
            .write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        // A reset is an error rather than a clean EOF; both mean the same thing
        // here, which is that nothing was written back.
        refused.read_to_end(&mut got).await.ok();
        assert!(
            got.is_empty(),
            "expected silence, got {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(state.sessions.lock().unwrap().len(), 1);

        // And a tunnel no rule refuses is still acknowledged, so the gate is
        // refusing connections rather than the CONNECT handler being broken.
        let mut allowed = tokio::net::TcpStream::connect(addr).await.unwrap();
        allowed
            .write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        allowed
            .read_exact(&mut head)
            .await
            .expect("a CONNECT reply");
        assert_eq!(&head, b"HTTP/1.1 200");
    }

    /// With interception off, every tunnel is answered only once its far end
    /// has been reached, and not at all when it cannot be — upstream's order
    /// (`_original/lib/tunnel.js:637-695`, `:833-836`). Before, the `200` went
    /// out first, and a client whose origin did not resolve saw a server that
    /// accepted the tunnel and then hung up in the middle of its handshake:
    /// measured on Linux, where `probe.test` does not resolve, as
    /// `connect ECONNRESET` from whistle against `tls ECONNRESET` from this port
    /// (`mode-bench.js`). The `disable://intercept` path is
    /// `failure_tests::a_relayed_tunnel_that_cannot_connect_fails_at_connect`.
    #[tokio::test]
    async fn with_interception_off_a_tunnel_is_answered_once_the_far_end_is() {
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        // An origin that echoes one line back, so relaying is seen to work.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    sock.write_all(&buf[..n]).await.ok();
                });
            }
        });
        let connect = |addr: SocketAddr, authority: String| async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();
            client
        };

        let (state, addr) = proxy_with_config("", |c| c.intercept_https = false).await;

        let mut refused = connect(addr, dead.to_string()).await;
        let mut got = Vec::new();
        refused.read_to_end(&mut got).await.ok();
        assert!(
            got.is_empty(),
            "expected silence, got {:?}",
            String::from_utf8_lossy(&got)
        );
        {
            let sessions = state.sessions.lock().unwrap();
            let session = sessions
                .iter()
                .next()
                .expect("the failed tunnel is on the list");
            assert_eq!(session.method, "CONNECT");
            assert_eq!(session.status, 0, "nothing was answered");
            let failure = session.error.get().expect("recorded as failed");
            assert_eq!(failure.phase, outcome::Phase::Connect, "{failure:?}");
        }

        let mut relayed = connect(addr, live.to_string()).await;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            relayed
                .read_exact(&mut byte)
                .await
                .expect("a CONNECT reply");
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        relayed.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        relayed.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping", "relayed, not read");
    }

    /// An aborted *request* is recorded too, for the same reason an aborted
    /// tunnel is: a row that never appears is indistinguishable from a rule
    /// that never matched, and which of those happened is the only thing the
    /// user wants to know when they write `enable://abort`.
    #[tokio::test]
    async fn an_aborted_request_is_recorded_rather_than_vanishing() {
        let (state, addr) = proxy_with("blocked.test enable://abort").await;

        let mut refused = tokio::net::TcpStream::connect(addr).await.unwrap();
        refused
            .write_all(b"GET http://blocked.test/a HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        refused.read_to_end(&mut got).await.ok();
        assert!(
            got.is_empty(),
            "an abort answers nothing, got {:?}",
            String::from_utf8_lossy(&got)
        );

        let sessions = state.sessions.lock().unwrap();
        let session = sessions.iter().next().expect("the abort is on the list");
        assert_eq!(session.method, "GET");
        assert_eq!(session.url, "http://blocked.test/a");
        assert_eq!(session.status, 0, "nothing answered");
        assert_eq!(session.target, "aborted", "and nothing was dialled");
        assert!(
            session.rules.iter().any(|r| r.raw == "enable://abort"),
            "the rule that did it is named: {:?}",
            session.rules
        );
    }

    /// A gateway error is a response this proxy made itself, and says so.
    ///
    /// It is the most common thing a debugging proxy ever has to tell its user —
    /// "I could not reach that" — and it went out as an unattributed body with
    /// no declared type, so it could not be told apart from an origin's own
    /// answer. whistle stamps the identical response through `wrapResponse`
    /// (`_original/lib/util/index.js:1080-1109`).
    #[tokio::test]
    async fn a_gateway_error_names_the_proxy_that_made_it() {
        // A port bound only long enough to know nothing else has it.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (_state, addr) = proxy_with(&format!("{dead} proxy://{dead}")).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // `Connection: close`, or the answer keeps the socket open and reading
        // to the end never ends.
        client
            .write_all(
                format!(
                    "GET http://{dead}/a HTTP/1.1\r\nHost: {dead}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.ok();
        let got = String::from_utf8_lossy(&got).to_lowercase();

        assert!(got.starts_with("http/1.1 502"), "{got}");
        assert!(got.contains("x-server: whistle-rs"), "{got}");
        assert!(
            got.contains("content-type: text/plain; charset=utf-8"),
            "{got}"
        );
    }
}
