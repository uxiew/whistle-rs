//! Upgrades: telling a WebSocket handshake from any other `Upgrade:`, answering
//! one locally, and forwarding one — on `101`, relaying frame by frame so each
//! is captured and offered to `frameScript` and the plugins, or relaying bytes
//! for a protocol that is not WebSocket.

use super::*;

/// Complete the handshake a local `101` answers an upgrade with — what upstream
/// does for `statusCode://101` on a WebSocket (`_original/lib/https/index.js:145-162`):
/// the `Sec-WebSocket-Accept` the key calls for, the first subprotocol asked
/// for, `Upgrade` as the client spelled it (or `websocket`), and
/// `Connection: Upgrade`. Without them a client refuses the switch — the bare
/// `101` this port sent was "unexpected server response (101)" to upstream's
/// `ws.test.js`.
///
/// Then the connection is held, as upstream holds it with nobody behind it:
/// whatever the client sends is read and dropped until it hangs up.
pub(super) fn accept_upgrade_locally<B>(req: &mut Request<B>, resp: &mut Response<DynBody>) {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let upgrade = header(hyper::header::UPGRADE).unwrap_or_else(|| "websocket".to_string());
    let protocol = header(hyper::header::SEC_WEBSOCKET_PROTOCOL)
        .map(|p| p.split(',').next().unwrap_or_default().trim().to_string());
    let accept = header(hyper::header::SEC_WEBSOCKET_KEY).map(|key| ws::accept_key(&key));
    let headers = resp.headers_mut();
    for (name, value) in [
        (hyper::header::SEC_WEBSOCKET_ACCEPT, accept),
        (hyper::header::SEC_WEBSOCKET_PROTOCOL, protocol),
        (hyper::header::UPGRADE, Some(upgrade)),
        (hyper::header::CONNECTION, Some("Upgrade".to_string())),
    ] {
        if let Some(value) = value.and_then(|v| hyper::header::HeaderValue::from_str(&v).ok()) {
            headers.insert(name, value);
        }
    }
    let upgraded = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(io) = upgraded.await {
            let mut io = TokioIo::new(io);
            let _ = tokio::io::copy(&mut io, &mut tokio::io::sink()).await;
        }
    });
}

/// True if the request asks to upgrade the protocol (e.g. a WebSocket handshake).
pub(super) fn is_upgrade(req: &Request<DynBody>) -> bool {
    asks_to_upgrade(req.headers())
}

/// The same question of a header map alone, because it has to be answered
/// before the request has been read — the scheme the rules match against
/// depends on it (`ws://` rather than `http://`).
pub(super) fn asks_to_upgrade(headers: &hyper::HeaderMap) -> bool {
    let conn_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    conn_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// True if the upgrade handshake targets the WebSocket protocol (as opposed to
/// some other `Upgrade:` protocol we should tunnel opaquely).
///
/// `enable://websocket` says yes whatever the header says. Some clients speak
/// WebSocket under a name of their own — `Upgrade: ws`, a vendor string — and
/// upstream's read of the flag is exactly this one:
/// `socket.enable.websocket || util.isWebSocket(headers)`
/// (`_original/lib/https/index.js:81`). Without it such a connection is a byte
/// stream in both proxies, and its frames are never surfaced.
pub(super) fn is_websocket(req: &Request<DynBody>, resolved: &Resolved) -> bool {
    if apply::is_enabled(resolved, "websocket") {
        return true;
    }
    req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Forward an upgrade handshake and, on `101`, tunnel bytes both ways.
/// This is how WebSocket (`ws://`/`wss://`) traffic is proxied. WebSocket
/// upgrades are tunnelled frame-by-frame so each frame is captured; any other
/// `Upgrade:` protocol is tunnelled as an opaque byte stream.
///
/// `forwarding` is the forwarding family's own resolution and `resolved` the
/// request's; the two differ only when a rule moved the request — see
/// [`forwarding_resolution`]. Upstream splits them here too: its WebSocket path
/// rewrites `fullUrl` from the `rule` slot and only then calls `getProxy` with
/// it (`_original/lib/https/index.js:228-232,:292`).
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_upgrade(
    state: &Arc<AppState>,
    mut req: Request<DynBody>,
    info: &ReqInfo,
    resolved: &Resolved,
    dest: &dest::Destination,
    forwarding: &Resolved,
    client_ip: Option<String>,
    ledger: &mut Ledger,
) -> Result<Response<DynBody>> {
    let (time_ms, started) = (ledger.time_ms, ledger.started);
    let target = apply::resolve_target(info, dest, forwarding)
        .await
        .map_err(outcome::at(outcome::Phase::Rules))?;
    ledger.note(|s| s.target = target_desc(&target));
    note_cipher_dropped(ledger, &target, resolved);
    let frame_script = resolved.value("frameScript").and_then(script::load_script);
    let websocket = is_websocket(&req, resolved);
    // Which plugins may hook this session's frames. Resolving the plan contacts
    // nothing and allocates nothing unless a rule named a registered plugin;
    // the plugins themselves are dialled later, from inside the tunnel.
    let frame_plan = if websocket {
        ws::FramePlan::new(&state.plugins, resolved, info)
    } else {
        ws::FramePlan::default()
    };
    // What `enable://ignoreSend|ignoreReceive|pauseSend|pauseReceive` asked to
    // happen to each direction. Read here rather than inside the plan: the plan
    // collapses to its default when no plugin is named, and these flags have to
    // survive that.
    let frame_flow = ws::FrameFlow::of(resolved);
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream handshake request (upgrades carry no body, so
    // `params://` can only address the query string here).
    let (mut parts, _body) = req.into_parts();
    let new_path = apply::rewrite_path(&dest.path, resolved, apply::ReqBodyCtx::default());
    parts.uri = apply::request_target(&new_path).unwrap_or(parts.uri);
    ensure_host_header(&mut parts.headers, &dest.host, dest.port, &dest.scheme);
    parts.headers.remove("proxy-connection");
    upstream::take_client_proxy_auth(&mut parts);
    mark_stripped_tls(&mut parts.headers, &target);
    apply::apply_request(&mut parts, resolved);
    // Every WebSocket this proxy relays is read frame by frame — captured,
    // offered to `frameScript` and the plugins' hooks — and a compressed frame
    // is unreadable to all of them. Worse, the codec in `ws` does not carry a
    // frame's RSV1 bit across, so once the two ends had agreed on
    // `permessage-deflate` the receiver got compressed bytes marked as plain
    // text: upstream's `connect.test.js` read back binary noise. So nothing is
    // negotiated: the offer does not reach the server, and the frames stay as
    // they were written. Compression is optional to both ends; this costs only
    // bytes on the wire. (Upstream relays the frames compressed and inflates a
    // copy for its display, `lib/socket-mgr.js:699-705`.)
    parts
        .headers
        .remove(hyper::header::SEC_WEBSOCKET_EXTENSIONS);
    let out_req = Request::from_parts(parts, body::empty());

    tracing::info!(
        "{} {} -> upgrade {}:{}",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port
    );

    // Measured for the same reason as a plain request's: a handshake that
    // fails to connect shows how far it got.
    let timings = timing::Timings::new();
    ledger.note(|s| s.timings = Some(timings.clone()));
    let (mut resp, _) = upstream::forward_with_addr(&target, out_req, &timings).await?;
    let target_desc = target_desc(&target);

    // `enable://abort` / `abortRes` on an upgrade: the handshake went out, the
    // server answered it, and the client is cut off instead of being handed the
    // `101` (`_original/lib/https/index.js:783-786`). `abortReq` needs nothing
    // here — an upgrade is an ordinary request until this function is called,
    // and it has already passed the request-side gate in [`serve`], which is
    // where upstream's WebSocket path puts it too (`https/index.js:256-259`).
    //
    // Upstream waits out `resDelay://` before this gate; this port has no
    // response phase on the upgrade path at all, so there is nothing to wait
    // for and nothing to re-resolve — `resolved` is the request pass.
    if apply::aborts_response(resolved) {
        tracing::info!("{} {} -> upgrade aborted", info.method, info.full_url);
        // The head that is being thrown away is still recorded, for the reason
        // the HTTP gate records one: a session that shows nothing coming back
        // reads as if the server never answered, and it did.
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip,
            target: format!("{target_desc} (aborted)"),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(resolved),
            rules: matched_ops(resolved),
            res_headers: header_pairs(resp.headers()),
            timings: Some(timings),
            error: aborted(
                "dropped by a rule after the server answered (enable://abort or abortRes)",
            ),
            ..Default::default()
        });
        return Err(Destroyed.into());
    }

    let session_id = ledger.record(Session {
        id: 0,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: resp.status().as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc,
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(resolved),
        rules: matched_ops(resolved),
        res_headers: header_pairs(resp.headers()),
        timings: Some(timings),
        ..Default::default()
    });

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade; relay its response verbatim.
        let (p, b) = resp.into_parts();
        return Ok(Response::from_parts(p, body::from_incoming(b)));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut resp);
    let (p, _b) = resp.into_parts();
    let state = state.clone();

    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok((client_io, upstream_io)) => {
                let c = TokioIo::new(client_io);
                let u = TokioIo::new(upstream_io);
                if websocket {
                    // Frame-aware tunnel: capture every frame, run the script on
                    // text frames when a frameScript rule matched, and offer each
                    // data frame to the plugins the plan named.
                    ws::capturing_tunnel(
                        c,
                        u,
                        frame_script,
                        frame_plan,
                        frame_flow,
                        state,
                        session_id,
                    )
                    .await;
                } else {
                    // Non-WebSocket upgrade: opaque byte passthrough.
                    let mut c = c;
                    let mut u = u;
                    if let Err(err) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
                        tracing::debug!("upgrade tunnel closed: {err}");
                    }
                }
            }
            Err(err) => tracing::debug!("upgrade failed: {err}"),
        }
    });

    // Relay the 101 (with Sec-WebSocket-Accept etc.) so the client handshake completes.
    Ok(Response::from_parts(p, body::empty()))
}

#[cfg(test)]
pub(super) mod websocket_flag_tests {
    use super::super::*;

    fn req(upgrade: Option<&str>) -> Request<DynBody> {
        let mut b = Request::builder().method("GET").uri("http://a.com/ws");
        if let Some(u) = upgrade {
            b = b.header(hyper::header::UPGRADE, u);
        }
        b.body(body::empty()).expect("request")
    }

    fn resolved(rules: &str) -> Resolved {
        let mut m = RuleManager::new();
        m.set_text(rules);
        let info = apply::build_req_info(
            "GET",
            "http",
            "a.com",
            80,
            "/ws",
            &hyper::HeaderMap::new(),
            None,
        );
        m.resolve(&info)
    }

    /// `enable://websocket` is the flag for a client that speaks WebSocket
    /// under a name of its own: upstream reads
    /// `socket.enable.websocket || util.isWebSocket(headers)`
    /// (`_original/lib/https/index.js:81`), so the header decides unless the
    /// flag overrules it.
    #[test]
    fn a_nonstandard_upgrade_is_a_websocket_when_the_flag_says_so() {
        let none = resolved("");
        assert!(is_websocket(&req(Some("websocket")), &none));
        assert!(is_websocket(&req(Some("WebSocket")), &none));
        assert!(!is_websocket(&req(Some("ws-custom")), &none));
        assert!(!is_websocket(&req(None), &none));

        let on = resolved("a.com enable://websocket");
        assert!(is_websocket(&req(Some("ws-custom")), &on));
        assert!(is_websocket(&req(None), &on));
        // `disable://` beats it, as it beats every flag (`isEnable`,
        // `_original/lib/util/index.js:678-680`).
        let off = resolved("a.com enable://websocket\na.com disable://websocket");
        assert!(!is_websocket(&req(Some("ws-custom")), &off));
    }
}

#[cfg(test)]
pub(super) mod upgrade_abort_tests {
    use super::super::tunnel_abort_tests::proxy_with;
    use super::super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An origin that answers anything with a WebSocket `101` and then holds the
    /// connection open, so the proxy sees a live upgrade rather than a hang-up.
    async fn upgrading_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // However much of the handshake arrives, the answer is the
                    // same — this origin agrees to every upgrade.
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    sock.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\
                          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    )
                    .await
                    .ok();
                    // Then hold the socket open until the other end lets go.
                    let _ = sock.read(&mut buf).await;
                });
            }
        });
        addr
    }

    /// Open a WebSocket handshake for `path` through the proxy at `addr` and
    /// return everything the proxy writes back.
    async fn handshake_through(addr: SocketAddr, origin: SocketAddr, path: &str) -> Vec<u8> {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET http://{origin}{path} HTTP/1.1\r\n\
             Host: {origin}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        // One read: it returns as soon as a response head arrives, and returns
        // nothing when the connection is torn down instead — a reset is an error
        // rather than an EOF, and both mean the same thing here. Reading to EOF
        // would mean waiting out the tunnel that a *relayed* upgrade opens.
        let mut got = vec![0u8; 1024];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        got.truncate(read);
        got
    }

    /// `statusCode://101` on a WebSocket completes the handshake itself, as
    /// upstream does (`lib/https/index.js:145-162`): the accept the key calls
    /// for, and the headers a client checks before it believes the switch.
    #[tokio::test]
    async fn a_local_101_completes_the_websocket_handshake() {
        let (_state, addr) = proxy_with("ws.local.test statusCode://101").await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET http://ws.local.test/ HTTP/1.1\r\nHost: ws.local.test\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n",
            )
            .await
            .unwrap();
        let mut got = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .expect("an answer")
            .unwrap();
        let head = String::from_utf8_lossy(&got[..n]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        // RFC 6455's own example key and accept.
        assert!(
            head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
            "{head}"
        );
        assert!(head.contains("sec-websocket-protocol: chat\r\n"), "{head}");
        assert!(head.contains("upgrade: websocket"), "{head}");
        assert!(head.contains("connection: upgrade"), "{head}");
    }

    /// No extension is negotiated through the proxy: the client's
    /// `Sec-WebSocket-Extensions` offer does not reach the server, so a server
    /// that would compress cannot, and the frames the proxy reads and relays
    /// are the ones the ends wrote. With the offer passed on, upstream's
    /// `connect.test.js` got compressed bytes delivered as text.
    #[tokio::test]
    async fn a_compression_offer_does_not_reach_the_server() {
        let offered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let origin = listener.local_addr().unwrap();
        let seen = offered.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            // A server that compresses whenever it is asked to.
            let asked = head.contains("sec-websocket-extensions");
            seen.store(asked, std::sync::atomic::Ordering::SeqCst);
            let ext = if asked {
                "Sec-WebSocket-Extensions: permessage-deflate\r\n"
            } else {
                ""
            };
            let answer = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n{ext}\r\n"
            );
            sock.write_all(answer.as_bytes()).await.ok();
            let _ = sock.read(&mut buf).await;
        });
        let (_state, addr) = proxy_with("").await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET http://{origin}/ws HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut got = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut got))
            .await
            .expect("an answer")
            .unwrap();
        let head = String::from_utf8_lossy(&got[..n]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(
            !offered.load(std::sync::atomic::Ordering::SeqCst),
            "the offer reached the server"
        );
        assert!(!head.contains("sec-websocket-extensions"), "{head}");
    }

    /// `enable://abortRes` on an upgrade lets the handshake reach the server and
    /// then cuts the client off instead of handing it the `101`
    /// (`_original/lib/https/index.js:783-786`). The client must not see the
    /// switch, or it would start speaking WebSocket into a closed socket.
    #[tokio::test]
    async fn an_aborted_upgrade_never_reaches_the_client() {
        let origin = upgrading_origin().await;
        let (state, addr) = proxy_with(&format!("{origin} enable://abortRes")).await;

        let got = handshake_through(addr, origin, "/ws").await;
        assert!(
            !got.starts_with(b"HTTP/1.1 101"),
            "the switch must not be relayed, got {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(
            got.is_empty(),
            "and nothing else is served in its place, got {:?}",
            String::from_utf8_lossy(&got)
        );

        // The head that was thrown away is still on the row, so the session
        // reads as "the server answered and the client was cut off" rather than
        // "nothing came back".
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.front().expect("the abort is recorded");
        assert_eq!(session.status, 101);
        assert!(
            session.target.ends_with("(aborted)"),
            "target was {:?}",
            session.target
        );
    }

    /// `enable://abortReq` on an upgrade needs no gate of its own: an upgrade is
    /// an ordinary request right up to the point the handshake is forwarded, so
    /// it meets the request-side gate first — which is exactly where upstream's
    /// WebSocket path puts it (`_original/lib/https/index.js:256-259`). The
    /// origin is never contacted, and the proof is that an origin which cannot
    /// be reached at all makes no difference to what the client sees.
    #[tokio::test]
    async fn an_upgrade_aborted_before_it_leaves_never_reaches_the_origin() {
        // A port bound only long enough to know nothing else has it.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };

        let (_state, addr) = proxy_with(&format!("{dead} enable://abortReq")).await;
        let got = handshake_through(addr, dead, "/ws").await;
        assert!(
            got.is_empty(),
            "expected silence, got {:?}",
            String::from_utf8_lossy(&got)
        );

        // Without the rule the same unreachable origin produces a `502`, so the
        // silence above is the abort and not the dial failing.
        let (_state, addr) = proxy_with("other.test enable://abortReq").await;
        let got = handshake_through(addr, dead, "/ws").await;
        assert!(
            got.starts_with(b"HTTP/1.1 502"),
            "expected a gateway error, got {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// An upgrade resolves under a `ws://` URL, not an `http://` one.
    ///
    /// whistle stamps `req.isWs` and builds the URL its patterns match from it
    /// (`_original/lib/upgrade.js:121`, `common.js:1267`). The rules layer here
    /// has always read that scheme; nothing ever *set* it, so a `ws://` pattern
    /// matched no request a client could make and an `http://` pattern matched
    /// the WebSocket it is written to exclude. `enable://abortRes` is the probe
    /// — silence means the rule matched, a `101` means it did not.
    #[tokio::test]
    async fn an_upgrade_is_matched_as_a_websocket_url() {
        let origin = upgrading_origin().await;

        let (_state, addr) = proxy_with(&format!("ws://{origin} enable://abortRes")).await;
        assert!(
            handshake_through(addr, origin, "/ws").await.is_empty(),
            "a ws:// pattern must reach a WebSocket"
        );

        let (_state, addr) = proxy_with(&format!("http://{origin} enable://abortRes")).await;
        assert!(
            handshake_through(addr, origin, "/ws")
                .await
                .starts_with(b"HTTP/1.1 101"),
            "an http:// pattern must not reach a WebSocket"
        );

        // And the consequence the scheme decides on its own: a file rule is
        // passed over on an upgrade rather than answering it with a mock
        // (`matcher::serves_no_file`). Measured against whistle 2.10.8, which
        // relays the handshake; this port used to answer `404 Not found file`.
        let (_state, addr) = proxy_with(&format!("{origin} file:///no/such/mock.json")).await;
        assert!(
            handshake_through(addr, origin, "/ws")
                .await
                .starts_with(b"HTTP/1.1 101"),
            "a file rule must not answer an upgrade"
        );
    }

    /// The control: the same proxy relays an upgrade no rule aborts, so the
    /// gate is refusing responses rather than the upgrade path being broken.
    #[tokio::test]
    async fn an_upgrade_no_rule_aborts_is_relayed() {
        let origin = upgrading_origin().await;
        let (_state, addr) = proxy_with("other.test enable://abortRes").await;
        let got = handshake_through(addr, origin, "/ws").await;
        assert!(
            got.starts_with(b"HTTP/1.1 101"),
            "expected the switch, got {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}
