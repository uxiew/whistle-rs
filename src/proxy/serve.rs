//! The request pipeline: [`serve`] takes one request — forward proxy or
//! intercepted — matches the rules, applies the request side, answers locally
//! or forwards it, and hands the response to `response`. `serve_recorded` wraps
//! it so every request ends as exactly one session.
//!
//! `serve` is one long function on purpose for now: it is the order of
//! whistle's request inspectors, step by step, and M1 moved it whole rather
//! than rewrite it.

use super::*;

/// Collect a whole [`DynBody`] into memory. Its boxed error type is unsized, so
/// it needs flattening before `?` can carry it into `anyhow`.
pub(super) async fn collect_body(body: DynBody) -> Result<Bytes> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// As [`collect_body`], but giving up past `limit` bytes rather than reading
/// whatever the client decides to send. See [`body::collect_capped`] for what
/// happens at the limit, and why it is not an error.
pub(super) async fn collect_capped_body(body: DynBody, limit: usize) -> Result<body::Capped> {
    match body::collect_capped(body, limit).await {
        Ok(capped) => Ok(capped),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// Monotonic id handed to plugins so their request and response hooks can be
/// correlated. Distinct from a [`Session`] id, which is only assigned once the
/// transaction is recorded — far too late for the request hook.
pub(super) fn next_plugin_req_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Where a request originated, which decides how we derive its target.
#[derive(Clone)]
pub(super) enum Origin {
    /// A normal absolute-form forward-proxy request.
    Forward,
    /// A request seen inside an intercepted tunnel (CONNECT or SOCKS). `tls`
    /// indicates the tunnel was TLS-decrypted (scheme https) vs. plain (http);
    /// `sni` says the ClientHello named a server, which is what `from:sni`
    /// asks (`checkSNI`, `_original/lib/https/index.js:1281`).
    Mitm {
        host: String,
        port: u16,
        tls: bool,
        sni: bool,
    },
}

/// whistle's own bind address, empty when bound to all interfaces — see
/// [`template::ProxyEnv`]. Owned because `Config` keeps an `IpAddr`.
pub(super) fn bind_host(state: &AppState) -> String {
    state.config.host.map(|h| h.to_string()).unwrap_or_default()
}

/// The request context a backtick operator value renders against.
pub(super) fn tpl_ctx<'a>(host: &'a str, port: u16, info: &'a ReqInfo) -> apply::TplCtx<'a> {
    apply::TplCtx {
        info,
        env: template::ProxyEnv {
            host,
            port,
            version: crate::config::VERSION,
        },
    }
}

/// The rules the forwarding family reads, when a URL replacement moved the
/// request off its own URL.
///
/// `None` — the common case — means "use the request's own resolution": nothing
/// moved, so the second pass would match the same URL with the same rules. See
/// [`apply::reresolve_forwarding`] for what the pass covers and why.
///
/// The value store and the config variables are applied to the second pass as
/// they were to the first, so a `host://${addr}` written against the destination
/// resolves rather than reaching the connector as literal text. Nothing is
/// loaded from disk or fetched: no forwarding operator's value is a location
/// (`value_source`'s `LOADABLE_*` lists name none of them), so this stays
/// synchronous.
pub(super) fn forwarding_resolution(
    state: &AppState,
    info: &ReqInfo,
    dest: &dest::Destination,
    resolved: &Resolved,
    merged_rules: &[crate::rules::RuleManager],
    is_internal_req: bool,
) -> Option<Resolved> {
    if !dest.replaced {
        return None;
    }
    let moved = dest.moved_req_info(info);
    let mut second = {
        let rules = state.rules.read().unwrap();
        apply::reresolve_forwarding(resolved, &moved, &rules, merged_rules, is_internal_req)
    };
    let host = bind_host(state);
    let values = effective_values(state);
    apply::substitute_values(
        &mut second,
        &values,
        tpl_ctx(&host, state.config.port, &moved),
    );
    apply::substitute_config_vars(&mut second, state.config.port, crate::config::VERSION);
    Some(second)
}

/// The address the request actually went to.
///
/// It comes from the socket: `TcpStream::connect` picks among the resolver's
/// answers without saying which, and asking the resolver a second time can
/// answer differently under round-robin DNS, so the connected peer is the only
/// honest source. Through an upstream proxy that peer is the *proxy*, which is
/// what whistle reports too (`req.hostIp` is set from the resolved proxy
/// address when a proxy rule matched, `_original/lib/inspectors/res.js:238,:259`).
///
/// The `connect_host` fallback covers the case where no connection was made at
/// all; `serverIp:` then stays unanswerable and fails closed rather than
/// matching on a guess.
pub(super) fn known_server_ip(
    target: &upstream::Target,
    reached: Option<SocketAddr>,
) -> Option<String> {
    reached.map(|a| a.ip().to_string()).or_else(|| {
        target
            .connect_host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string())
    })
}

/// [`serve`] a request and settle its session, whatever happens to it.
pub(super) async fn serve_recorded(
    state: Arc<AppState>,
    req: Request<Incoming>,
    origin: Origin,
    peer: SocketAddr,
) -> Result<Response<DynBody>, Destroyed> {
    let mut ledger = Ledger::new(&state);
    let result = serve(state, req, origin, peer, &mut ledger).await;
    guard(&mut ledger, result)
}

/// Turn a failure into a 502, except an abort, which gets no answer — and
/// record it either way.
///
/// The 502 is dressed like every other answer this proxy makes itself: it says
/// what it is (`Content-Type`) and who made it (`x-server`). It went out as an
/// undeclared, unattributed body until the forwarding bench asked an unreachable
/// upstream for one — the single most common thing a debugging proxy has to say,
/// and the one response that did not name its author. whistle marks the same
/// answer, from the same place (`wrapGatewayError` → `wrapResponse`,
/// `_original/lib/util/index.js:1080-1109`); its body is HTML, and this one is
/// the error chain as plain text, so it says `text/plain`.
///
/// `x-server` alone cannot tell this 502 from an origin's: a `statusCode://502`
/// rule carries it too. [`ERROR_HEADER`] can, and [`SESSION_HEADER`] says which
/// session in the console is this request.
pub(super) fn guard(
    ledger: &mut Ledger,
    result: Result<Response<DynBody>>,
) -> Result<Response<DynBody>, Destroyed> {
    match result {
        Ok(resp) => Ok(resp),
        Err(err) if err.is::<Destroyed>() => {
            // Every abort records itself before it leaves `serve`; this is the
            // backstop that keeps a missed one from being called a client that
            // hung up.
            ledger.fail(
                outcome::Failure::new(outcome::Phase::Abort, format!("{err:#}")),
                0,
            );
            Err(Destroyed)
        }
        Err(err) => {
            let phase = outcome::phase_of(&err).unwrap_or(outcome::Phase::Internal);
            // `{err:#}` includes the full anyhow context chain (e.g. the
            // underlying rustls reason behind "upstream TLS handshake").
            let message = format!("{err:#}");
            let id = ledger.fail(outcome::Failure::new(phase, message.clone()), 502);
            if id.is_none() {
                tracing::debug!("request failed at {phase}: {message}");
            }
            let mut resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header(ERROR_HEADER, phase.as_str())
                .body(body::full(Bytes::from(format!("whistle-rs: {message}"))))
                .unwrap();
            if let Some(id) = id {
                resp.headers_mut().insert(SESSION_HEADER, id.into());
            }
            apply::mark_self_generated(resp.headers_mut());
            Ok(resp)
        }
    }
}

/// Core request pipeline: match rules, apply them, forward upstream.
pub(super) async fn serve(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    origin: Origin,
    peer: SocketAddr,
    ledger: &mut Ledger,
) -> Result<Response<DynBody>> {
    // The handful of hostnames that *are* the console, before anything else
    // looks at this request. `http://local.whistlejs.com/` through the proxy is
    // how whistle's own `w2 status` tells people to open it, and `rootca.pro` is
    // how a phone gets the certificate — set the proxy, open the name, install
    // what it hands you. Both names resolve to `127.0.0.1`, where nothing is
    // listening on port 80, so a proxy that does not know them answers `502`.
    //
    // Here rather than in `top_level` because a tunnel has to answer too:
    // upstream serves both over TLS inside its own MITM, measured. And before
    // the rules, because upstream is before the rules — measured with a
    // matching `host://` line installed, which it serves the console over.
    let console = match &origin {
        Origin::Forward => req.uri().host().map(str::to_string),
        Origin::Mitm { host, .. } => Some(host.clone()),
    }
    .filter(|h| webui::console_host(&state, h));
    if let Some(host) = console {
        return Ok(webui::handle_proxied(&state, req, &host).await);
    }
    // A page this proxy put the `log://` collector into, reporting what its
    // console said. The path is on the page's own origin and means nothing
    // there: it is answered here, reaches no origin and leaves no session.
    if req.uri().path() == pagelog::PATH {
        return Ok(pagelog::accept(&state, req, peer).await);
    }
    let client_ip = Some(peer.ip().to_string());
    // Consumed before anything else looks at the headers, exactly like whistle
    // deletes its own marker on arrival: rule filters, plugins, the capture and
    // the origin server must never see it.
    let is_internal_req = take_internal_marker(req.headers_mut());
    // Consumed here too: an upstream whistle stripped this request's TLS for the
    // hop, and the scheme it arrived under is not the one the rules should see.
    let was_https = take_https_marker(req.headers_mut());
    // Consumed here too, and for the same reason: it is this proxy's own marker,
    // not the client's, so nothing downstream may see it.
    let from_composer = take_composer_marker(req.headers_mut());
    // The rules-carrying headers, which whistle removes from **every** request
    // whether or not it reads them (`getValue`,
    // `_original/lib/rules/index.js:558-572`: the `delete` is unconditional and
    // only the *reading* is gated on `enableRequestHeaderRules`/`multiEnv`).
    // Leaving them on meant a rules text written by a client reached the origin
    // — and would be honoured by any whistle further up the chain.
    //
    // Under `-M enableRequestHeaderRules` or `-M multiEnv` what they said is
    // also *kept*, and becomes a rules text for this one request — see
    // [`header_rules`]. Off by default in both proxies.
    let carried = take_header_rules(req.headers_mut(), &state.config);
    // What a front proxy claims about this request — the host it was addressed
    // to and the scheme it arrived under. Believed only when a `-M` mode says a
    // front proxy is there; two of the four headers are taken off either way,
    // because this port will not act on them and they may not travel on. See
    // [`forwarded`].
    let claimed = forwarded::take(req.headers_mut(), &state.config);

    // A request that asks to change protocol is matched as a `ws://` one, and
    // that has to be known *before* the rules resolve. whistle stamps
    // `req.isWs = true` on every upgrade it accepts and builds the URL from it —
    // `(req.isWs ? 'ws' : 'http') + (req.isHttps ? 's' : '')`
    // (`_original/lib/upgrade.js:121`, `lib/util/common.js:1267`) — so a
    // `ws://` pattern matches a WebSocket and an `http://` one does not.
    //
    // The rules layer has read this scheme all along; nothing ever set it, so
    // both halves were wrong in production: `ws://example.com` matched nothing a
    // client could send, and `http://example.com` matched the WebSocket it
    // excludes. It also decides whether a `file://` may answer at all
    // (`matcher::serves_no_file`).
    let upgrading = asks_to_upgrade(req.headers());
    // Derive scheme/host/port/path for matching.
    // `port_explicit` says the port came from the request rather than from the
    // scheme's default, which is what decides whether a forwarded-proto claim
    // may move it — see below.
    let (mut scheme, mut host, mut port, path, port_explicit) = match &origin {
        Origin::Forward => {
            let uri = req.uri();
            let host = uri.host().unwrap_or_default().to_string();
            let mut scheme = uri.scheme_str().unwrap_or("http").to_string();
            if was_https && scheme == "http" {
                scheme = "https".to_string();
            }
            if upgrading {
                scheme = match scheme.as_str() {
                    "https" | "wss" => "wss".to_string(),
                    _ => "ws".to_string(),
                };
            }
            // Read after the marker, so a request restored to https and carrying
            // no explicit port lands on 443 rather than 80 — and after the
            // upgrade rename, so a `wss://` one does too.
            let port = uri.port_u16().unwrap_or(match scheme.as_str() {
                "https" | "wss" => 443,
                _ => 80,
            });
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            (scheme, host, port, path, uri.port_u16().is_some())
        }
        Origin::Mitm {
            host, port, tls, ..
        } => {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let scheme = match (*tls, upgrading) {
                (true, true) => "wss",
                (true, false) => "https",
                (false, true) => "ws",
                (false, false) => "http",
            };
            // The port a CONNECT named is the port, and no claim moves it.
            (scheme.to_string(), host.clone(), *port, path, true)
        }
    };

    // A front proxy's claim, applied to what the rules will match. Upstream
    // does the same two things and no more: `headers.host = host` before the
    // full URL is built (`_original/lib/util/common.js:1259-1265`) and
    // `req.isHttps = proto === 'https'` (`util/index.js:3722-3727`). Measured:
    // the *outgoing* request is unaffected — a request labelled `https` still
    // left over plain HTTP and still reached a plain origin, it simply matched
    // `https://` patterns on the way.
    // What the request actually arrived as, kept because a forwarded-proto claim
    // changes **which pattern matches** and nothing else — see below.
    let wire_scheme = scheme.clone();
    let mut wire_port = port;
    if let Some(https) = claimed.https {
        scheme = match (https, upgrading) {
            (true, true) => "wss",
            (true, false) => "https",
            (false, true) => "ws",
            (false, false) => "http",
        }
        .to_string();
        // The port the request addressed was read against the *old* scheme, so
        // a claim that changes it moves a default port with it — 80 and 443 are
        // the same request to two different servers. An explicit port in the
        // request stands.
        let (from, to) = match https {
            true => (80, 443),
            false => (443, 80),
        };
        if port == from && !port_explicit {
            port = to;
        }
    }
    if let Some(claimed_host) = &claimed.host {
        match forwarded::split_host(claimed_host, port) {
            Some((h, p)) => {
                host = h;
                port = p;
                // A host claim moves the *destination*, so its port is the one
                // to connect to — it replaces whatever a proto claim implied.
                wire_port = p;
                // Upstream assigns `headers.host`, so everything downstream —
                // the rules, the capture, the origin — sees one answer rather
                // than two.
                if let Ok(value) = claimed_host.parse() {
                    req.headers_mut().insert(hyper::header::HOST, value);
                }
            }
            // A claim this proxy cannot address is ignored, and said so: an
            // operator who switched the mode on wants to know their front proxy
            // is sending something unusable.
            None => tracing::warn!("ignoring an unusable forwarded host: {claimed_host:?}"),
        }
    }

    let mut info = apply::build_req_info(
        req.method().as_str(),
        &scheme,
        &host,
        port,
        &path,
        req.headers(),
        client_ip.clone(),
    );
    // The accepted socket's port, for `clientPort:` / `remotePort:` filters.
    info.client_port = Some(peer.port());
    ledger.watch(info.noted.clone());
    // What a `reqScript` reads as `port`, `uiPort` and `httpVersion`.
    info.script_env = crate::rules::ScriptEnv {
        proxy_port: state.config.port,
        ui_port: state.config.ui_port.unwrap_or(state.config.port),
        http_version: match req.version() {
            hyper::Version::HTTP_10 => "1.0",
            hyper::Version::HTTP_2 => "2.0",
            hyper::Version::HTTP_3 => "3.0",
            _ => "1.1",
        },
    };
    // Where the request came from, for `from:`. All of it is known before the
    // rules resolve — which is what makes `from:!tunnel` a real answer rather
    // than a filter that fails closed.
    info.from = crate::rules::ReqOrigin {
        tunnel: matches!(origin, Origin::Mitm { .. }),
        sni: matches!(origin, Origin::Mitm { sni: true, .. }),
        composer: from_composer,
    };
    // From here on this request becomes a session however it ends. The
    // client's own headers stand in until the outgoing ones exist, for the
    // reason a locally answered request shows them — see
    // `capture_client_request`.
    ledger.open(Session {
        method: info.method.clone(),
        url: info.full_url.clone(),
        client_ip: client_ip.clone(),
        req_headers: header_pairs(req.headers()),
        composer: from_composer,
        ..Default::default()
    });
    let (started, time_ms) = (ledger.started, ledger.time_ms);

    // A `b:` filter reads the request body, so the body has to be in hand
    // *before* the rules resolve. Whether any line asks is answered from the
    // per-group candidate list each group precomputes; a rules file that never
    // mentions the body costs one `is_empty()` per group and the body keeps
    // streaming untouched.
    //
    // Locking: the read guard is dropped before the `.await` below — no guard
    // may cross one here, which is also why this cannot share the acquisition
    // with the resolution that follows.
    let needs_req_body = {
        let rules = state.rules.read().unwrap();
        rules.needs_request_body(&info, is_internal_req)
    };
    // Normalising to `DynBody` here rather than at the plugin hook lets both
    // reasons to buffer share one decision point.
    let (req, prebuffered): (Request<DynBody>, Option<Bytes>) = {
        let (parts, incoming) = req.into_parts();
        if needs_req_body {
            // Bounded, because this is a client's upload and the only thing
            // asking for it is a `b:` filter that wants to read a prefix.
            // Over the bound the body streams on and the filter answers from
            // what was read — see [`body::collect_capped`]. The limit here is
            // the plain one: `enable://reqMergeBigData` lives on a rule, and
            // which rules apply is the question this buffering exists to
            // answer, so consulting it would be circular.
            match collect_capped_body(body::from_incoming(incoming), apply::REQ_BODY_LIMIT)
                .await
                .map_err(outcome::at(outcome::Phase::Request))?
            {
                body::Capped::Whole { bytes, .. } => (
                    Request::from_parts(parts, body::full(bytes.clone())),
                    Some(bytes),
                ),
                body::Capped::TooBig { prefix, body } => {
                    (Request::from_parts(parts, body), Some(prefix))
                }
            }
        } else {
            (
                Request::from_parts(parts, body::from_incoming(incoming)),
                None,
            )
        }
    };
    if let Some(bytes) = &prebuffered {
        // Set even when empty: upstream's `req._reqBody` is a string either way,
        // so `b:!x` holds for a request with no body rather than failing closed.
        info.req_body = Some(String::from_utf8_lossy(bytes).into_owned());
    }

    let mut resolved = state
        .rules
        .read()
        .unwrap()
        .resolve_scoped(&info, is_internal_req);
    // `${host}` is whistle's own bind address, empty when bound to all
    // interfaces — see ProxyEnv.
    let bind_host = bind_host(&state);
    let proxy_env = template::ProxyEnv {
        host: &bind_host,
        port: state.config.port,
        version: crate::config::VERSION,
    };
    // Rules merged in mid-request — a `rule://` value, the `rulesFile://` join,
    // and any a plugin injects below. Their parsed form is kept because the
    // response phase resolves them a second time, exactly as it does the
    // top-level rules (`apply::merge_response_phase_of`).
    let mut merged_rules: Vec<crate::rules::RuleManager> = {
        // A ``` block in a rules file declares a value that travels with it,
        // and it beats the console's store — but not a `--value`.
        let mut values = effective_values(&state);
        // The rules this request brought in its own headers, if the mode reads
        // them at all. Composed and merged **before** anything is substituted,
        // so a `{name}` inside them is expanded in the same pass as every other
        // rule's — and against the private values the request carried, which is
        // what `x-whistle-key-value` is for.
        let from_headers = (!carried.is_empty())
            .then(|| {
                let rules = state.rules.read().unwrap();
                let text = header_rules::compose(
                    &carried,
                    // `values.get(keyHeader)` — the store by its plain name.
                    // Not a private lookup: the request is naming an entry the
                    // *proxy* holds, which is the whole point of the header.
                    |key| values.get(key).cloned(),
                    |name| rules.group_text(name).map(str::to_string),
                )?;
                drop(rules);
                let mgr = header_rules::merge(
                    &mut resolved,
                    &info,
                    &text,
                    state.config.header_rules,
                    is_internal_req,
                );
                // What the request carried is private to its rules, like a
                // block — and so are the text's own blocks, laid over it — and
                // both yield to `--value` like one.
                values.extend(header_rules::private_values(carried.kv.as_deref()));
                values.extend(header_rules::blocks(&mgr));
                apply::yield_to_overrides(&mut values, &state.config.value_overrides);
                Some(mgr)
            })
            .flatten();
        let tpl = tpl_ctx(&bind_host, state.config.port, &info);
        apply::substitute_values(&mut resolved, &values, tpl);
        let mut managers =
            apply::merge_included_rules(&mut resolved, &info, &values, is_internal_req);
        for mgr in &managers {
            values.extend(mgr.carried_values().clone());
        }
        apply::substitute_values(&mut resolved, &values, tpl);
        // Kept for the response phase, exactly as upstream re-resolves `hRules`
        // there (`_original/lib/plugins/index.js:1326-1335`).
        managers.extend(from_headers);
        managers
    };
    apply::substitute_config_vars(&mut resolved, state.config.port, crate::config::VERSION);
    // The rules plugins bring with them (a plugin's `rules.txt` upstream),
    // ranked below the console's — see `apply::merge_below`. Nothing to do —
    // one check per plugin — unless a plugin declared some.
    let brought = state.plugins.static_rules();
    if !brought.is_empty() {
        for (_, text) in &brought {
            merged_rules.push(apply::merge_brought_rules(
                &mut resolved,
                &info,
                text,
                is_internal_req,
            ));
        }
        let values = state.values.read().unwrap().clone();
        apply::substitute_values(
            &mut resolved,
            &values,
            tpl_ctx(&bind_host, state.config.port, &info),
        );
        apply::substitute_config_vars(&mut resolved, state.config.port, crate::config::VERSION);
    }
    // `abc://value` for a plugin called `abc` — before anything reads the
    // destination slot it was parsed into.
    state.plugins.claim_short_protocol(&mut resolved);
    // Operator values that name a file or a URL are read here — the one point
    // where the whole resolved set is in hand and the request has gone nowhere
    // yet. A rule set that names no location walks its own operators and
    // returns; see `apply::load_rule_values`.
    apply::load_rule_values(&mut resolved, &info).await;
    // Which rules applied is most of what a failed request's session has to
    // say. Noted again below whenever a plugin can have added some.
    ledger.note(|s| {
        s.log = log_labels(&resolved);
        s.rules = matched_ops(&resolved);
    });

    // Plugins matched by `plugin://name` / `pipe://name`, minus any that aren't
    // registered. `pipe://` drives the *streaming* hooks and `plugin://` the
    // buffered ones, so the two are kept apart; a `pipe://` rule naming a plugin
    // with no streaming hook falls back to the buffered path, which is what
    // `pipe://` meant before the streaming hooks existed.
    let mut plugin_matches: Vec<(String, String)> = Vec::new();
    let mut pipe_matches: Vec<crate::plugins::PluginMatch> = Vec::new();
    for m in crate::plugins::matched(&resolved) {
        if !state.plugins.reachable(&m.name) {
            continue;
        }
        let streams = m.via_pipe
            && matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.has_pipe_hook());
        if streams {
            pipe_matches.push(m);
        } else {
            plugin_matches.push((m.name.clone(), m.param.clone()));
        }
    }
    let plugin_names: Vec<String> = plugin_matches.iter().map(|(n, _)| n.clone()).collect();

    // Correlates this request's plugin hooks with each other. Session ids are
    // only assigned once a transaction is recorded, which is too late here.
    let plugin_req_id = next_plugin_req_id();

    // Hand a plugin the request body if its manifest declares `requestBody`.
    // Buffering happens *only* then — otherwise the body stays a lazy stream and
    // the proxy's streaming fast path is untouched. A `b:` filter may already
    // have bought the bytes above, in which case this costs nothing but the
    // manifest lookup.
    let (mut req, plugin_req_body): (Request<DynBody>, Option<Bytes>) = {
        let wants_body = !plugin_matches.is_empty()
            && has_request_body(req.headers())
            && state.plugins.any_wants_request_body(&plugin_names).await;
        match (wants_body, prebuffered) {
            (false, _) => (req, None),
            (true, Some(bytes)) => (req, Some(bytes)),
            (true, None) => {
                let (parts, body) = req.into_parts();
                let bytes = collect_body(body)
                    .await
                    .map_err(outcome::at(outcome::Phase::Request))?;
                (
                    Request::from_parts(parts, body::full(bytes.clone())),
                    Some(bytes),
                )
            }
        }
    };

    // Request hook: a matched plugin may inject rules, rewrite request headers,
    // and/or answer the request directly (Rust in-process or remote).
    let mut plugin_set_headers: Vec<(String, String)> = Vec::new();
    let mut plugin_remove_headers: Vec<String> = Vec::new();
    if !plugin_matches.is_empty() {
        let preq_headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        for (name, param) in plugin_matches.iter() {
            let preq = crate::plugins::PluginReq {
                id: plugin_req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                headers: preq_headers.clone(),
                client_ip: client_ip.clone(),
                param: param.clone(),
                body: plugin_req_body.clone().map(|b| b.to_vec()),
            };
            let Some(result) = state.plugins.on_request(name, &preq).await else {
                continue;
            };
            if let Some(why) = &result.hook_failed {
                ledger.unapplied(plugin_hook_failed(&resolved, name, "request", why));
            }
            if let Some(rules) = result.rules {
                let mgr = apply::merge_plugin_rules(
                    &mut resolved,
                    &info,
                    name,
                    &rules,
                    result.values,
                    is_internal_req,
                );
                {
                    let mut values = state.values.read().unwrap().clone();
                    values.extend(mgr.carried_values().clone());
                    let tpl = tpl_ctx(&bind_host, state.config.port, &info);
                    apply::substitute_values(&mut resolved, &values, tpl);
                }
                merged_rules.push(mgr);
                // A plugin's rules can name a file or a URL too, and its
                // operators have not been past the loader.
                apply::load_rule_values(&mut resolved, &info).await;
            }
            plugin_set_headers.extend(result.set_headers);
            plugin_remove_headers.extend(result.remove_headers);
            let blocked = result.blocked;
            // A gate that failed rather than refused: the request stops here
            // because a plugin broke, and its session says so.
            let failure = result
                .failure
                .map(|why| outcome::Failure::new(outcome::Phase::Plugin, format!("{name}: {why}")));
            if let Some(resp) = result.response {
                tracing::debug!("{} {} -> plugin {name}", info.method, info.full_url);
                let target = format!("plugin:{name}");
                // The plugin answered, but it is not the last word: every
                // response operator still runs, exactly as it does over the
                // origin's answer. Skipping this left `resHeaders://`,
                // `replaceStatus://`, `resType://`, `trailers://` and the whole
                // body family silently inert on a path users reach on purpose.
                // An answer is an ordinary response: every response operator and
                // every response hook runs over it. A *refusal* from the auth
                // gate is served as produced — see [`pin_refusal`].
                let (mut response, res_body) = if blocked {
                    pin_refusal(&state, plugin_response(resp))
                } else {
                    finish_local_response(
                        &state,
                        &mut info,
                        &mut resolved,
                        &merged_rules,
                        is_internal_req,
                        plugin_response(resp),
                        ResHooks {
                            plugins: &plugin_matches,
                            pipes: &pipe_matches,
                            req_id: plugin_req_id,
                            client_ip: client_ip.clone(),
                            notes: Some(&mut ledger.unapplied),
                        },
                    )
                    .await
                };
                // What the client sent, which no outgoing request will carry
                // here — see `capture_client_request`.
                let (req_headers, req_body) =
                    capture_client_request(&mut req, state.config.body_preview_cap).await;
                // A broken gate's 502 is made up here like any failed request's,
                // so it says so the same way; without these it reads as an
                // origin's own 502, which is what the header exists to rule out.
                if let Some(failure) = &failure {
                    response
                        .headers_mut()
                        .insert(ERROR_HEADER, failure.phase.as_str().parse().unwrap());
                }
                let id = ledger.record_visible(Session {
                    id: 0,
                    time_ms,
                    method: info.method.clone(),
                    url: info.full_url.clone(),
                    status: response.status().as_u16(),
                    client_ip: client_ip.clone(),
                    target,
                    duration_ms: started.elapsed().as_millis(),
                    log: log_labels(&resolved),
                    rules: matched_ops(&resolved),
                    req_headers,
                    res_headers: header_pairs(response.headers()),
                    req_body,
                    res_body,
                    // Answered here: no connection was opened, so there are no phases.
                    timings: None,
                    error: failure
                        .clone()
                        .map(outcome::Outcome::failed)
                        .unwrap_or_default(),
                    composer: info.from.composer,
                    unapplied: Vec::new(),
                });
                if let Some(failure) = &failure {
                    log_failure(id, &info.method, &info.full_url, failure);
                    if let Some(id) = id {
                        response.headers_mut().insert(SESSION_HEADER, id.into());
                    }
                }
                return Ok(response);
            }
        }
    }

    // `enable://abort` / `abortReq` drop the request without contacting the
    // origin, and without an answer of any kind — upstream's `res.destroy()`
    // (`_original/lib/inspectors/data.js:534-539`). `abortRes` is *not* here:
    // it lets the request go out and destroys the answer instead, further down.
    if apply::aborts_request(&resolved) {
        tracing::debug!("{} {} -> aborted", info.method, info.full_url);
        // Recorded, for the same reason an aborted tunnel is (see
        // [`tunnel_aborted`]): upstream emits the session and then marks it
        // aborted (`data.js:534-539` destroys the response, `tunnel.js:31-36`
        // is where the status becomes `'aborted'`), and a request that vanishes
        // from the console is indistinguishable from a rule that never matched
        // — which is the one question the user is asking when they reach for
        // `enable://abort`.
        let (req_headers, req_body) =
            capture_client_request(&mut req, state.config.body_preview_cap).await;
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            // Nothing answered and nothing will. 0 is the console's "no status",
            // matching the tunnel gate rather than inventing a second spelling.
            status: 0,
            client_ip: client_ip.clone(),
            // No address was dialled: the abort sits ahead of the forward.
            target: "aborted".to_string(),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers,
            req_body,
            error: aborted("dropped by a rule before it was sent (enable://abort or abortReq)"),
            ..Default::default()
        });
        return Err(Destroyed.into());
    }

    // Short-circuit rules (redirect, mocked status, file) skip the upstream;
    // `proxy_env` was built with the rest of the template context above.
    // `reqDelay://` waits here, before anything answers. Upstream delays in a
    // pipeline stage of its own (`util.delay(...reqDelay)`,
    // `_original/lib/inspectors/data.js:534`) that runs ahead of the abort gate
    // and ahead of every short-circuit — so `reqDelay://500 file://mock.json`
    // delays there. Waiting further down, next to the forwarding call, meant it
    // was skipped by exactly the rules people pair it with: a delay is how you
    // make a *mock* feel like a slow endpoint.
    if let Some(ms) = apply::req_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // A file rule may name a URL rather than a path, and then its bytes are
    // fetched. Hoisted out of `short_circuit` because everything under there
    // answers without waiting for anything but the filesystem, and one network
    // read is not a reason to make all of it async. Costs nothing unless a file
    // rule won the slot and named a URL.
    let remote = apply::prefetch_remote_file(&resolved).await;
    if let Some(mut resp) = apply::short_circuit(&info, &resolved, proxy_env, remote.as_ref()) {
        tracing::debug!("{} {} -> short-circuit", info.method, info.full_url);
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS && asks_to_upgrade(req.headers()) {
            accept_upgrade_locally(&mut req, &mut resp);
        }
        // Response-side operators apply to a mocked response too: upstream runs
        // its response inspectors over `file`/`tpl`/`redirect` responses just as
        // it does over real ones, so `resHeaders://` and friends must land here
        // as well — and so must the response-phase rules, which is why a
        // `statusCode://404` this port answered can be filtered on with `s:404`.
        // Every short-circuit body is already in memory, so collecting it costs
        // nothing but lets the body operators run over it as well.
        let (parts, body) = resp.into_parts();
        let bytes = collect_body(body).await?;
        let (resp, res_body) = finish_local_response(
            &state,
            &mut info,
            &mut resolved,
            &merged_rules,
            is_internal_req,
            Response::from_parts(parts, bytes),
            ResHooks {
                plugins: &plugin_matches,
                pipes: &pipe_matches,
                req_id: plugin_req_id,
                client_ip: client_ip.clone(),
                notes: Some(&mut ledger.unapplied),
            },
        )
        .await;
        // What the client sent, which no outgoing request will carry here — see
        // `capture_client_request`.
        let (req_headers, req_body) =
            capture_client_request(&mut req, state.config.body_preview_cap).await;
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: "short-circuit".to_string(),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers,
            res_headers: header_pairs(resp.headers()),
            req_body,
            res_body,
            // Answered here: no connection was opened, so there are no phases.
            timings: None,
            // A rule's answer, whatever its status — a `file://` whose URL
            // would not load answers 502 on purpose, as upstream's does.
            error: Default::default(),
            composer: info.from.composer,
            unapplied: Vec::new(),
        });
        return Ok(resp);
    }

    // Where the request is addressed, which is its own URL unless a rule pointed
    // it somewhere else — `www.example.com http://localhost:5173` and friends.
    // Resolved before the target because the target is *how* to reach it, and
    // because the forwarding family is matched against *this* URL rather than
    // the client's — see `forwarding_resolution`.
    // The destination is read against the scheme and port the request **arrived
    // under**, not the one a front proxy claimed.
    //
    // Measured, and the measurement is the whole reason this is here: with
    // `-M x-forwarded-proto` and `x-forwarded-proto: https`, whistle sends
    // **no ClientHello at all** — a plain origin logged zero client errors —
    // while it matched the `https://` rule. The claim describes the hop *before*
    // this proxy; the hop after it is whatever it always was. A rule that writes
    // a destination of its own still governs, scheme and all.
    //
    // This port promoted the transport too, and the difference was invisible to
    // the bench because a failed handshake retries in plain: the answer looked
    // right and every request had paid for a doomed TLS attempt first. An origin
    // that read the ClientHello instead of rejecting it hung forever, which is
    // how it surfaced.
    let dest = match claimed.https.is_some() && (scheme != wire_scheme || port != wire_port) {
        false => dest::Destination::of(&info, &resolved),
        true => {
            let mut wire = info.clone();
            wire.scheme = wire_scheme;
            wire.port = wire_port;
            dest::Destination::of(&wire, &resolved)
        }
    };
    let forwarding = forwarding_resolution(
        &state,
        &info,
        &dest,
        &resolved,
        &merged_rules,
        is_internal_req,
    );
    let forwarding = forwarding.as_ref().unwrap_or(&resolved);
    // A plugin's request hook may have merged rules since they were last noted.
    ledger.note(|s| {
        s.log = log_labels(&resolved);
        s.rules = matched_ops(&resolved);
    });

    // WebSocket / other protocol upgrades are tunnelled after a 101.
    if is_upgrade(&req) {
        return serve_upgrade(
            &state, req, &info, &resolved, &dest, forwarding, client_ip, ledger,
        )
        .await;
    }

    // A destination whose scheme is neither `http` nor `https` names a transport
    // this request is not — `ws://`, `wss://` and `tunnel://` say so themselves
    // ("普通 HTTP/HTTPS 请求：返回 502"), and upstream refuses every other spelling
    // on the same line of the same function, because node will not hand a
    // protocol to an agent that cannot speak it. Forwarding it as plain HTTP
    // instead sends the traffic somewhere the rule never asked for. See
    // `dest::unroutable_scheme`.
    if let Some(scheme) = dest::unroutable_scheme(&resolved) {
        return Err(outcome::stopped(
            outcome::Phase::Rules,
            anyhow::anyhow!("unsupported protocol {scheme}:"),
        ));
    }

    // Fails the request rather than silently connecting direct when a proxy rule
    // matched but could not be honoured (unusable address, unreachable or
    // throwing PAC file) — see `apply::find_proxy`.
    let target = apply::resolve_target(&info, &dest, forwarding)
        .await
        .map_err(outcome::at(outcome::Phase::Rules))?;
    ledger.note(|s| s.target = target_desc(&target));
    note_cipher_dropped(ledger, &target, &resolved);

    // A proxy rule that names this proxy would send the request back to us, be
    // matched by the same rule, and recurse until the sockets run out. whistle
    // answers the request from its own UI port instead of making the hop
    // (`_original/lib/inspectors/res.js:302-316`); `upstream::forward` refuses
    // the same hop with a "Self loop" error for every path that reaches it.
    // A direct hop to our own port under a name that is not the console's
    // would be forwarded again on arrival (`top_level`); whistle redirects it
    // to its UI by address instead (`_original/lib/inspectors/res.js:409-424`).
    // Under a console name it is simply the console, reached through the proxy.
    let looped = match upstream::self_loop(&target).await {
        Some(addr) => Some(addr),
        None => upstream::direct_self_loop(&target)
            .await
            .filter(|_| !webui::host_names_console(&state, &dest.host)),
    };
    if let Some(addr) = looped {
        let location = format!(
            "http://{}{}",
            SocketAddr::new(addr.ip(), state.config.port),
            info.path
        );
        tracing::warn!(
            "{} {} -> self loop via {addr}; redirecting to {location}",
            info.method,
            without_query(&info.full_url)
        );
        let resp = Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, &location)
            .body(body::empty())
            .expect("static 302");
        ledger.record(Session {
            id: 0,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: resp.status().as_u16(),
            client_ip: client_ip.clone(),
            target: format!("self-loop {addr}"),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            res_headers: header_pairs(resp.headers()),
            ..Default::default()
        });
        return Ok(resp);
    }

    // Rewrite to origin-form + apply request-side rules. (Plugins that wanted to
    // handle this request already returned above; any rules they injected have
    // been merged into `resolved`.)
    let (mut parts, incoming) = req.into_parts();
    // The origin is asked for the destination's host, not the client's — that
    // is the whole difference between a URL replacement and `host://`.
    ensure_host_header(&mut parts.headers, &dest.host, dest.port, &dest.scheme);
    parts.headers.remove("proxy-connection");
    upstream::take_client_proxy_auth(&mut parts);
    mark_stripped_tls(&mut parts.headers, &target);
    apply::apply_request(&mut parts, &resolved);
    // Plugin header rewrites land after the rule operators, so a plugin can
    // override what the rules set.
    for name in &plugin_remove_headers {
        parts.headers.remove(name.to_ascii_lowercase().as_str());
    }
    for (k, v) in &plugin_set_headers {
        set_header_raw(&mut parts.headers, k, v);
    }
    // Buffer + transform the request body only when a body/speed/write operator applies.
    let req_speed = apply::req_speed_kbps(&resolved);
    // The method is read after the request operators, because `method://` may
    // have changed it — a `GET` rewritten to a `POST` does get its body dumped.
    let req_write = apply::req_write_path(&resolved, parts.method.as_str());
    let req_write_raw = apply::req_write_raw_path(&resolved);
    let force_write = apply::forces_write(&resolved);
    let req_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Read after the request operators, because `method://` and `reqType://`
    // decide whether `params://` addresses the body or the query string — as
    // they do upstream (`_original/lib/inspectors/req.js:536,560-561`). That is
    // also why the path is rewritten here rather than before `apply_request`.
    let req_method = parts.method.to_string();
    let body_ctx = apply::ReqBodyCtx {
        method: &req_method,
        content_type: req_ct.as_deref(),
    };
    // From the destination's path, not the request's: a URL-replacement rule has
    // already decided what is being asked for, and `urlReplace`/`params` then
    // rewrite *that* — the same order as upstream, where `req.options` is built
    // before the request inspectors run.
    let new_path = apply::rewrite_path(&dest.path, &resolved, body_ctx);
    parts.uri = apply::request_target(&new_path).unwrap_or(parts.uri);
    let req_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    // The id every body frame of this transaction is filed under. Reserved
    // here, because the request body streams long before the session is
    // recorded — a frame cut out of it has to know where it belongs.
    let frame_session = state.reserve_id();
    // `enable://hide` keeps the whole transaction out of the capture, frames
    // included, so the watchers are not installed at all.
    let hidden = apply::hidden_from_capture(&resolved);
    // Frames a **buffered** body produced, each with its direction, held until
    // the session has an id.
    let mut buffered_frames: Vec<(&'static str, Vec<u8>)> = Vec::new();
    // The separator a request asked for, read off the outgoing headers before
    // the body is built — and removed from them either way, so the origin never
    // sees it (`parseFrameSep`, `_original/lib/inspectors/data.js:77-96`).
    let mut req_frames = {
        let asked = restream::take_frame_separator(&mut parts.headers);
        // As on the response side, the separator only frames when
        // `enable://captureStream` asked for it — measured, upstream reports no
        // frames for a request separator without the flag. There is no `isSse`
        // half here: a request body is not an event stream.
        match hidden
            || apply::is_disabled(&resolved, "captureStream")
            || !apply::is_enabled(&resolved, "captureStream")
        {
            true => None,
            false => asked,
        }
    };
    let mut req_body_cap: Option<Capture> = None;
    let req_body: DynBody = if apply::wants_req_body(&resolved, body_ctx)
        || req_speed.is_some()
        || req_write.is_some()
        || req_write_raw.is_some()
    {
        // Bounded: these operators need the body in memory, and the body is
        // whatever the client decided to send. Past the bound whistle stops
        // transforming and lets the rest through — see [`body::collect_capped`].
        let limit = apply::req_body_limit(&resolved);
        let params_on_body = apply::params_rewrite_body(&resolved, body_ctx);
        let req_body_op = |op: &MatchedOp| {
            unapplied::req_body_op(op) || (op.protocol == "params" && params_on_body)
        };
        match collect_capped_body(incoming, limit)
            .await
            .map_err(outcome::at(outcome::Phase::Request))?
        {
            body::Capped::TooBig { body, .. } => {
                // Said out loud, because every other way for these operators to
                // do nothing has turned out to be a bug worth fixing. This one
                // is a deliberate refusal, and a rule that quietly stopped
                // applying above some size would read exactly like the bugs.
                tracing::warn!(
                    "{} {}: request body is over {} bytes, so it is forwarded \
                     unchanged — reqBody/reqReplace/params/reqWrite and reqSpeed \
                     do not apply. `enable://reqMergeBigData` raises the limit",
                    info.method,
                    info.full_url,
                    limit,
                );
                ledger.unapplied(unapplied::Unapplied::over(
                    &matched_ops(&resolved),
                    req_body_op,
                    unapplied::Kind::RequestBodyOverLimit,
                    format!(
                        "the request body is over {limit} bytes, the limit for rewriting \
                         one, so it was forwarded as it arrived. `enable://reqMergeBigData` \
                         or `lineProps://enableBigData` on the params line raise it to 16 MiB"
                    ),
                ));
                let cap = Capture::new(
                    req_ct.clone(),
                    req_enc.as_deref(),
                    state.config.body_preview_cap,
                );
                req_body_cap = Some(cap.clone());
                body::tee(body, cap)
            }
            body::Capped::Whole { bytes, .. } => 'rewrite: {
                // Decompress before rewriting, exactly as the response path
                // does. Upstream reaches it from the other end: every request
                // body operator goes through `addTextTransform`/`addZipTransform`,
                // both of which set `_needGunzip` (`_original/lib/init.js:90-112`),
                // which puts a decoder in front and an encoder behind
                // (`inspectors/rules.js:64-146`).
                //
                // Without it a `reqReplace://` searched the deflate stream and
                // found nothing, a `reqAppend://` wrote its text *after* the
                // gzip stream, and `reqBody://` sent plain text still labelled
                // `Content-Encoding: gzip` — a request the origin cannot read.
                //
                // No `enable://gzip` here: upstream calls `getEncoder(req)` with
                // one argument (`rules.js:164`), so its `req.enable` lookup is on
                // `undefined` and the flag never reaches the request side. The
                // body goes back under the coding it arrived with, or none.
                let decoded = coding::decode_for_rewrite(bytes, req_enc.as_deref(), limit);
                // A body that cannot be undone goes to the origin as the client
                // sent it — not rewritten in bytes nobody here can read.
                if let Some(why) = decoded.not_decoded {
                    ledger.unapplied(unapplied::not_decoded(
                        why,
                        "request",
                        req_enc.as_deref().unwrap_or_default(),
                        &matched_ops(&resolved),
                        req_body_op,
                    ));
                    let cap = Capture::new(
                        req_ct.clone(),
                        req_enc.as_deref(),
                        state.config.body_preview_cap,
                    );
                    req_body_cap = Some(cap.clone());
                    break 'rewrite body::tee(body::full(decoded.body), cap);
                }
                let restore = decoded.restore;
                let new = apply::transform_req_body(decoded.body, &resolved, body_ctx);
                let (new, encoded_as) = coding::reencode(new, restore, None);
                let req_enc = restore_content_encoding(
                    &mut parts.headers,
                    restore,
                    encoded_as,
                    req_enc.clone(),
                );
                if let Some(path) = &req_write {
                    write_body_file(path, &new, force_write);
                }
                if let Some(path) = &req_write_raw {
                    let head = format!(
                        "{} {} HTTP/1.1\r\n{}",
                        parts.method,
                        parts.uri,
                        header_dump(&parts.headers)
                    );
                    write_raw_file(path, &head, &new, force_write);
                }
                if !new.is_empty() {
                    req_body_cap = Some(Capture::from_bytes(
                        &new,
                        req_ct.clone(),
                        req_enc.as_deref(),
                        state.config.body_preview_cap,
                    ));
                }
                // A request body the console shows as frames, cut out of the
                // bytes that go upstream — the response's twin, and gated the
                // same way (`cseSep`, `data.js:63,:249`).
                if let Some(mut splitter) = req_frames.take() {
                    buffered_frames.extend(
                        splitter
                            .push(&new)
                            .into_iter()
                            .chain(splitter.finish())
                            .map(|payload| ("send", payload)),
                    );
                }
                apply::strip_length_headers(&mut parts.headers);
                match req_speed {
                    Some(kbps) => body::throttled(new, kbps),
                    None => body::full(new),
                }
            }
        }
    } else if has_request_body(&parts.headers) {
        // No transform: stream through, copying a bounded preview for inspection.
        let cap = Capture::new(
            req_ct.clone(),
            req_enc.as_deref(),
            state.config.body_preview_cap,
        );
        req_body_cap = Some(cap.clone());
        let teed = body::tee(incoming, cap);
        match req_frames.take() {
            Some(splitter) => body::frames(teed, state.clone(), frame_session, splitter, "send"),
            None => teed,
        }
    } else {
        incoming
    };
    // Streaming request hook: a `pipe://` plugin sees the body as the client
    // sends it, and what it emits is what goes upstream. No-op (and no cost)
    // when nothing matched.
    let req_body = pipe_body(
        &state,
        &pipe_matches,
        crate::plugins::pipe::Dir::Request,
        crate::plugins::pipe::PipeMeta {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            client_ip: client_ip.clone(),
            headers: header_pairs(&parts.headers),
            ..Default::default()
        },
        &mut parts.headers,
        req_body,
    )
    .await;

    // Capture the outgoing request headers (as forwarded).
    let req_header_pairs = header_pairs(&parts.headers);
    let out_req = Request::from_parts(parts, req_body);

    // DEBUG, as every line about a request that went through is: upstream logs
    // none, and a URL's query often carries a token. `-v` shows them.
    tracing::debug!(
        "{} {} -> {}:{} ({})",
        info.method,
        info.full_url,
        target.connect_host,
        target.connect_port,
        if target.tls { "https" } else { "http" }
    );

    // Handed in rather than returned: the row is recorded when the response head
    // arrives, and `receive` only lands when the body ends. See `timing`.
    let timings = timing::Timings::new();
    // Everything a failed forward's session can show: what was sent, and how
    // far the connection got — the phases stop where it failed.
    ledger.note(|s| {
        s.id = frame_session;
        s.req_headers = req_header_pairs.clone();
        s.req_body = req_body_cap.clone();
        s.timings = Some(timings.clone());
    });
    let (upstream_resp, server_addr) =
        upstream::forward_with_addr(&target, out_req, &timings).await?;

    let (mut parts, body) = upstream_resp.into_parts();

    // Response phase: rules whose filters ask about the response are resolved
    // here, against the head as the origin sent it — before `resDelay://` (so a
    // delay can be conditioned on the status), before any response operator, and
    // before the plugin response hooks, which is upstream's order too
    // (`_original/lib/inspectors/res.js:823-826`).
    resolve_response_phase(
        &state,
        &mut info,
        &mut resolved,
        apply::build_res_info(
            parts.status.as_u16(),
            &parts.headers,
            known_server_ip(&target, server_addr),
            Some(target.connect_port),
        ),
        is_internal_req,
        &merged_rules,
    )
    .await;

    if let Some(ms) = apply::res_delay_ms(&resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    // `enable://abort` / `abortRes`: the request went out, the origin answered,
    // and *now* the connection is destroyed — `res.js:1175-1179`, right after
    // `resDelay://`, which is why this sits below the sleep. The point of
    // aborting here rather than before the request is that the origin still
    // sees the traffic; only the client is cut off.
    if apply::aborts_response(&resolved) {
        tracing::debug!("{} {} -> response aborted", info.method, info.full_url);
        // Upstream keeps the head it is about to throw away (`req.__resHeaders`
        // / `req.__statusCode`, `res.js:1176-1177`) so the capture still shows
        // what arrived; without this the session reads as if nothing came back.
        ledger.record(Session {
            id: frame_session,
            time_ms,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            client_ip,
            target: format!("{}:{} (aborted)", target.connect_host, target.connect_port),
            duration_ms: started.elapsed().as_millis(),
            log: log_labels(&resolved),
            rules: matched_ops(&resolved),
            req_headers: req_header_pairs,
            res_headers: header_pairs(&parts.headers),
            req_body: req_body_cap,
            timings: Some(timings),
            error: aborted(
                "dropped by a rule after the server answered (enable://abort or abortRes)",
            ),
            ..Default::default()
        });
        return Err(Destroyed.into());
    }

    // Apply response-side rules.
    apply::apply_response_for(&mut parts, &resolved, Some(&info));

    // Response hook, part 1: plugins that did *not* ask for the response body
    // run here, so the response can keep streaming. Such a plugin may still
    // replace the body outright — that needs no knowledge of the original.
    let mut plugin_res_override: Option<Vec<u8>> = None;
    let mut plugin_wants_res_body = false;
    for (name, param) in plugin_matches.iter() {
        let Some(manifest) = state.plugins.manifest(name).await else {
            continue;
        };
        if !manifest.on_response {
            continue;
        }
        if manifest.response_body {
            plugin_wants_res_body = true;
            continue; // handled below, once the body is in hand
        }
        let pres = crate::plugins::PluginRes {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
            param: param.clone(),
            body: None,
        };
        if let Some(result) = state.plugins.on_response(name, &pres).await {
            if let Some(why) = &result.hook_failed {
                ledger.unapplied(plugin_hook_failed(&resolved, name, "response", why));
            }
            if let Some(new) = apply_plugin_res_result(&mut parts, result) {
                plugin_res_override = Some(new);
            }
        }
    }

    // Streaming response hook: a `pipe://` plugin transforms upstream bytes as
    // they arrive. Deliberately *before* the buffering decision below, so a
    // piped response still takes the streaming branch — the whole point of the
    // hook is that it never forces a body into memory.
    let body = pipe_body(
        &state,
        &pipe_matches,
        crate::plugins::pipe::Dir::Response,
        crate::plugins::pipe::PipeMeta {
            id: plugin_req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            client_ip: client_ip.clone(),
            headers: header_pairs(&parts.headers),
            status: Some(parts.status.as_u16()),
            ..Default::default()
        },
        &mut parts.headers,
        body::from_incoming(body),
    )
    .await;

    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // This is the path where the body is still arriving frame by frame, so the
    // content type is what decides whether it may be collected at all.
    let ops = ResBodyOps::of(
        &resolved,
        response_has_body(parts.status.as_u16(), &info.method),
        parts.status.as_u16(),
        res_ct.as_deref(),
    );
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    // A plugin that asked for the body of an event stream cannot have it, and
    // says so rather than leaving the hook mysteriously un-run: `responseBody`
    // is a declaration this port cannot honour on a body that need never end.
    if plugin_wants_res_body && is_event_stream(res_ct.as_deref()) {
        tracing::warn!(
            "{} is an event stream; a plugin's responseBody hook is skipped rather \
             than holding the stream shut",
            without_query(&info.full_url)
        );
    }
    // What [`ResBodyOps::of`] dropped for an event stream, on the session: the
    // stream went through with what can travel with it, and the rest did not
    // run. Only where there was a body for them to run on.
    if is_event_stream(res_ct.as_deref()) && response_has_body(parts.status.as_u16(), &info.method)
    {
        let encoded = res_enc
            .as_deref()
            .is_some_and(|enc| !enc.trim().eq_ignore_ascii_case("identity"));
        let plugins = match plugin_wants_res_body {
            true => "; no plugin's responseBody hook saw it either",
            false => "",
        };
        ledger.unapplied(unapplied::Unapplied::over(
            &matched_ops(&resolved),
            |op| unapplied::needs_whole_res_body(op, encoded),
            unapplied::Kind::EventStream,
            format!(
                "the response is an event stream, which is passed through as it arrives \
                 rather than held until it ends — so the operators that need the whole \
                 body did not run{plugins}. resReplace, resBody, resPrepend and resAppend \
                 still apply{}",
                if encoded {
                    ", except resReplace on a compressed stream"
                } else {
                    ""
                }
            ),
        ));
    }
    let mut res_body_cap: Option<Capture> = None;
    // Decide first, then act — because the buffered path may hand the body back.
    // A response too large to hold is not rewritten at all, and then this is the
    // streaming path after all.
    //
    // The origin's trailer section is lifted off with the bytes and handed to
    // `finish_res_body`. Collecting a body discards it otherwise, which is how a
    // response that arrived with trailers reached the client without them the
    // moment *any* body operator matched — including one that had nothing to do
    // with trailers.
    let mut collected: Option<(coding::Decoded, Option<hyper::HeaderMap>)> = None;
    let mut streamed: Option<DynBody> = None;
    if must_collect_body(
        &ops,
        plugin_wants_res_body,
        plugin_res_override.is_some(),
        res_ct.as_deref(),
    ) {
        match &plugin_res_override {
            // A plugin that replaced the body outright makes the upstream bytes
            // irrelevant — don't wait on them, and don't measure them either:
            // they are already in memory and were never read from a socket.
            // Decoded unbounded and used whatever came of it, as a local
            // response's body is: it was made by the plugin, not received.
            Some(new) => {
                let bytes = Bytes::from(new.clone());
                let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref(), usize::MAX);
                collected = Some((decoded, None));
            }
            None => {
                let cap = apply::res_body_limit(&resolved, state.config.body_rewrite_cap);
                match collect_capped_body(body, cap)
                    .await
                    .map_err(outcome::at(outcome::Phase::Response))?
                {
                    body::Capped::Whole { bytes, trailers } => {
                        // Decompressed before rewriting — see below. A body that
                        // cannot be undone takes the path a body too big to
                        // hold does: through as it arrived, trailers and all.
                        let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref(), cap);
                        match decoded.not_decoded {
                            None => collected = Some((decoded, trailers)),
                            Some(why) => {
                                ledger.unapplied(unapplied::not_decoded(
                                    why,
                                    "response",
                                    res_enc.as_deref().unwrap_or_default(),
                                    &matched_ops(&resolved),
                                    unapplied::res_body_op,
                                ));
                                streamed = Some(retrailer(body::full(decoded.body), trailers));
                            }
                        }
                    }
                    body::Capped::TooBig { body, .. } => {
                        // whistle never needs this bound: its response rewriting
                        // is a stream transform, so a rule costs it no memory.
                        // This port collects, so it has to stop somewhere — and
                        // it says where, because a rule that quietly stopped
                        // applying above some size reads exactly like a bug.
                        tracing::warn!(
                            "{} {}: response body is over {} bytes, so it is \
                             forwarded unchanged — the body operators, \
                             enable://gzip and any plugin responseBody hook do \
                             not apply. Raise --body-rewrite-limit to allow it",
                            info.method,
                            info.full_url,
                            cap,
                        );
                        // …and on the session, which is where someone looking
                        // at a response their rule did not touch will look.
                        let plugins = match plugin_wants_res_body {
                            true => "; no plugin's responseBody hook saw it either",
                            false => "",
                        };
                        ledger.unapplied(unapplied::Unapplied::over(
                            &matched_ops(&resolved),
                            unapplied::res_body_op,
                            unapplied::Kind::BodyOverLimit,
                            format!(
                                "the response body is over {cap} bytes, the rewrite limit, \
                                 so it was forwarded as it arrived{plugins}. \
                                 --body-rewrite-limit raises it"
                            ),
                        ));
                        streamed = Some(body);
                    }
                }
            }
        }
    } else {
        streamed = Some(body);
    }
    let res_body: DynBody = if let Some((decoded, origin_trailers)) = collected {
        // Decompress before rewriting. Every body operator works on text,
        // and most origins answer compressed — so without this a
        // `resReplace://` against a gzipped page searched the deflate
        // stream for its pattern, found nothing, and silently did nothing.
        // whistle reaches the same place from the other end: any body
        // transform sets `_needGunzip`, which puts a decoder in front of it
        // and a re-encoder behind (`addZipTransform`,
        // `_original/lib/inspectors/data.js:` and `inspectors/rules.js:60-140`).
        let restore = decoded.restore;
        let mut new = apply::transform_res_body(decoded.body, &resolved, res_ct.as_deref());

        // Response hook, part 2: plugins that asked for the body. It sits
        // between the content operators and the injections, which is why
        // those two halves are separate functions.
        for (name, param) in plugin_matches.iter() {
            let Some(manifest) = state.plugins.manifest(name).await else {
                continue;
            };
            if !manifest.on_response || !manifest.response_body {
                continue;
            }
            let pres = crate::plugins::PluginRes {
                id: plugin_req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                status: parts.status.as_u16(),
                headers: header_pairs(&parts.headers),
                param: param.clone(),
                body: Some(new.to_vec()),
            };
            if let Some(result) = state.plugins.on_response(name, &pres).await {
                if let Some(why) = &result.hook_failed {
                    ledger.unapplied(plugin_hook_failed(&resolved, name, "response", why));
                }
                if let Some(replaced) = apply_plugin_res_result(&mut parts, result) {
                    new = Bytes::from(replaced);
                }
            }
        }
        let new = inject_res_body(&state, &mut parts, new, &ops, &info);
        // Put the coding back on, so the client gets what the header
        // promises. `enable://gzip|br|deflate` asks for a *different* one
        // than arrived (`getEnableEncoding`,
        // `_original/lib/util/index.js:1534-1548`) — the only case where the
        // body leaves compressed that arrived plain.
        let (new, encoded_as) = coding::reencode(new, restore, ops.force_encoding);
        let now =
            restore_content_encoding(&mut parts.headers, restore, encoded_as, res_enc.clone());
        if !new.is_empty() {
            res_body_cap = Some(Capture::from_bytes(
                &new,
                res_ct.clone(),
                // The preview decodes what it is told the body is, so it has
                // to be told what the body *now* is, not what arrived.
                now.as_deref(),
                state.config.body_preview_cap,
            ));
        }
        // A buffered body is framed too, out of the bytes the client will
        // receive — the same rule and the same separator, applied at once
        // rather than as they arrive.
        if let Some(mut splitter) =
            response_frames(&resolved, &mut parts.headers, now.as_deref()).filter(|_| !hidden)
        {
            buffered_frames.extend(
                splitter
                    .push(&new)
                    .into_iter()
                    .chain(splitter.finish())
                    .map(|payload| ("receive", payload)),
            );
        }
        finish_res_body(&mut parts, new, ops, origin_trailers)
    } else {
        let body = streamed.expect("collected or streamed, never neither");
        // Stream through, copying a bounded preview for inspection. The
        // origin's trailers ride along untouched — unless a `disable://`
        // asked for them to go, which this path acts on.
        //
        // One operator can travel with a body that is still arriving:
        // `resReplace://` needs a window, not the whole thing. See
        // [`stream_replace`] for what disqualifies a stream.
        let body = match stream_replace(&resolved, res_ct.as_deref(), res_enc.as_deref()) {
            Some(transform) => {
                // A substitution changes the length, so a promise about it
                // cannot be kept. An event stream does not carry one, but
                // the removal belongs with the rewrite rather than with the
                // assumption.
                parts.headers.remove(hyper::header::CONTENT_LENGTH);
                restream::wrap(body, transform)
            }
            None => body,
        };
        // …and three more that do not need the whole body either:
        // `resPrepend://` goes ahead of the first byte, `resAppend://`
        // after the last, and `resBody://` says there is no origin body to
        // wait for. They sit *after* the substitution because that is the
        // buffered path's order too — upstream's text transforms run ahead
        // of the injection, so a `resReplace://` never sees what a
        // `resPrepend://` put there (`_original/lib/inspectors/res.js`, and
        // see `transform_res_body`).
        let body = match stream_injection(&resolved, res_ct.as_deref()) {
            Some(inject) => {
                parts.headers.remove(hyper::header::CONTENT_LENGTH);
                let origin = match inject.replacement {
                    // `resBody://` replaces the body, so the origin's is
                    // not waited for — dropping it here is what makes this
                    // usable as a mock for a stream that never ends.
                    Some(replacement) => body::full(replacement),
                    None => body,
                };
                body::surround(origin, inject.top, inject.bottom)
            }
            None => body,
        };
        // The capture records what the client receives, so it sits *after*
        // the substitution — as it does on the buffered path, where the
        // preview is built from the rewritten bytes.
        let cap = Capture::new(
            res_ct.clone(),
            res_enc.as_deref(),
            state.config.body_preview_cap,
        );
        res_body_cap = Some(cap.clone());
        let teed = body::tee(body, cap);
        // …and, for a stream the console shows as frames, one more watcher.
        // It sits after the capture for the reason the capture sits after
        // the substitution: a frame is what the client received.
        let framed = match response_frames(&resolved, &mut parts.headers, res_enc.as_deref())
            .filter(|_| !hidden)
        {
            Some(splitter) => body::frames(teed, state.clone(), frame_session, splitter, "receive"),
            None => teed,
        };
        match ops.no_trailers {
            true => retrailer(framed, None),
            false => framed,
        }
    };
    // `receive` runs from the response head to the last byte, so it is stamped
    // by the body itself — on both paths, because a buffered body was received
    // too; it was simply received before the operators ran.
    let res_body = timing::measure_receive(res_body, timings.clone());

    let session = Session {
        id: frame_session,
        time_ms,
        method: info.method.clone(),
        url: info.full_url.clone(),
        status: parts.status.as_u16(),
        client_ip: client_ip.clone(),
        target: target_desc(&target),
        duration_ms: started.elapsed().as_millis(),
        log: log_labels(&resolved),
        rules: matched_ops(&resolved),
        req_headers: req_header_pairs,
        res_headers: header_pairs(&parts.headers),
        req_body: req_body_cap,
        res_body: res_body_cap,
        timings: Some(timings.clone()),
        error: Default::default(),
        composer: info.from.composer,
        unapplied: Vec::new(),
    };
    // The row appears now, while the body is still arriving; the transaction
    // is complete — and can still fail — only when the body is over. A
    // response that has no body to send is over already: hyper drops it
    // unread, and that is not a client leaving.
    let (recorded, res_body) = match carries_body(parts.status.as_u16(), &info.method) {
        true => {
            let expected = parts
                .headers
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse().ok());
            ledger.record_streaming(session, res_body, expected)
        }
        false => (ledger.record(session), res_body),
    };
    for (dir, payload) in buffered_frames {
        state.record_frame(WsFrame::body_frame(recorded, dir, &payload));
    }

    Ok(Response::from_parts(parts, res_body))
}

/// Whether a response to `method` with `status` sends a body at all. Stricter
/// than [`response_has_body`], which is about the body *operators* and leaves
/// a redirect's body alone: a 302 still sends one, and it can still break off.
pub(super) fn carries_body(status: u16, method: &str) -> bool {
    !(method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304)
}

/// Hand `body` to every matched `pipe://` plugin that serves the streaming hook
/// for `dir`, chaining them in rule order so the second sees the first's output.
///
/// Returns `body` untouched — same allocation, same laziness — when no plugin
/// takes it, which is what keeps a request without streaming plugins on exactly
/// the path it was on before. When one does take it, the length headers go: a
/// transform may change the body's size, and the framing is chunked from here on.
pub(super) async fn pipe_body(
    state: &AppState,
    matches: &[crate::plugins::PluginMatch],
    dir: crate::plugins::pipe::Dir,
    meta: crate::plugins::pipe::PipeMeta,
    headers: &mut hyper::HeaderMap,
    body: DynBody,
) -> DynBody {
    if matches.is_empty() {
        return body;
    }
    let mut active = Vec::new();
    for m in matches {
        if matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.serves_pipe(dir)) {
            active.push(m);
        }
    }
    if active.is_empty() {
        return body;
    }
    apply::strip_length_headers(headers);
    let mut body = body;
    for m in active {
        let meta = crate::plugins::pipe::PipeMeta {
            param: m.param.clone(),
            pipe_value: m.pipe_value.clone(),
            ..meta.clone()
        };
        body = state.plugins.pipe(&m.name, dir, &meta, body).await;
    }
    body
}

/// Apply a plugin response-hook result to the response head. Returns the
/// replacement body, if the plugin supplied one.
pub(super) fn apply_plugin_res_result(
    parts: &mut hyper::http::response::Parts,
    result: crate::plugins::PluginResResult,
) -> Option<Vec<u8>> {
    if let Some(code) = result.status
        && let Ok(s) = StatusCode::from_u16(code)
    {
        parts.status = s;
    }
    for name in &result.remove_headers {
        parts.headers.remove(name.to_ascii_lowercase().as_str());
    }
    for (k, v) in &result.set_headers {
        set_header_raw(&mut parts.headers, k, v);
    }
    result.body
}

/// Set/replace a header (empty value deletes); used by response scripts.
pub(super) fn set_header_raw(headers: &mut hyper::HeaderMap, name: &str, value: &str) {
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
pub(super) fn ensure_host_header(
    headers: &mut hyper::HeaderMap,
    host: &str,
    port: u16,
    scheme: &str,
) {
    let default_port = if dest::is_tls(scheme) { 443 } else { 80 };
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
pub(super) fn authority_host_port(uri: &Uri) -> Option<(String, u16)> {
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(443);
    Some((host, port))
}

#[cfg(test)]
pub(super) mod hide_tests {
    use super::super::*;

    fn session(rules: &[(&str, &str)]) -> Session {
        let mut s = Session {
            id: 0,
            time_ms: 0,
            method: "GET".into(),
            url: "http://a.com/".into(),
            status: 200,
            client_ip: None,
            target: String::new(),
            duration_ms: 0,
            log: Vec::new(),
            rules: Vec::new(),
            req_headers: Vec::new(),
            res_headers: Vec::new(),
            req_body: None,
            res_body: None,
            timings: None,
            error: Default::default(),
            composer: false,
            unapplied: Vec::new(),
        };
        s.rules = rules
            .iter()
            .map(|(protocol, value)| MatchedOp {
                protocol: (*protocol).to_string(),
                value: (*value).to_string(),
                raw: format!("{protocol}://{value}"),
            })
            .collect();
        s
    }

    /// `checkHideProp` (`_original/lib/util/index.js:3982-3987`) is four flags:
    /// two that hide and two that un-hide, with un-hiding winning.
    #[test]
    fn hide_and_the_three_flags_that_argue_with_it() {
        assert!(!is_hidden(&session(&[])));
        assert!(is_hidden(&session(&[("enable", "hide")])));
        assert!(is_hidden(&session(&[("disable", "show")])));
        // Un-hiding wins, from either side.
        assert!(!is_hidden(&session(&[
            ("enable", "hide"),
            ("enable", "show")
        ])));
        assert!(!is_hidden(&session(&[
            ("enable", "hide"),
            ("disable", "hide")
        ])));
        assert!(!is_hidden(&session(&[
            ("disable", "show"),
            ("enable", "show")
        ])));
        // The value is a prop list, so one line may carry several flags.
        assert!(is_hidden(&session(&[("enable", "gzip|hide")])));
        assert!(!is_hidden(&session(&[("enable", "gzip|hide|show")])));
        // A flag that merely contains the word is not the word.
        assert!(!is_hidden(&session(&[("enable", "hideComposer")])));
    }
}

#[cfg(test)]
pub(super) mod pipe_wiring_tests {
    use super::super::*;
    use crate::plugins::pipe::{Dir, PipeMeta};

    /// Server state backed by a throwaway storage dir, so running the tests
    /// never touches the developer's real `~/.whistle-rs`.
    /// A private storage dir per call: these tests run in parallel threads, and
    /// sharing one made them race to write the root CA, which surfaced as an
    /// occasional "PEM error: malformed".
    fn state() -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-pipe-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, RuleManager::new(), ca))
    }

    fn headers_with_length() -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::CONTENT_LENGTH, "9".parse().unwrap());
        h
    }

    /// The non-negotiable: with no streaming plugin matched, the body comes back
    /// still lazy. Proven by sending its frames only *after* `pipe_body` has
    /// returned — a body that had been collected could not carry them.
    #[test]
    fn no_pipe_plugin_leaves_the_body_streaming() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            let (tx, source) = body::channel(4);

            let out = pipe_body(
                &state,
                &[],
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                source,
            )
            .await;

            // Nothing was read, so these frames still reach the client.
            tokio::spawn(async move {
                for part in ["not ", "buffered"] {
                    tx.send(Ok(Bytes::from_static(part.as_bytes()))).await.ok();
                }
            });
            let bytes = collect_body(out).await.expect("body");
            assert_eq!(bytes, Bytes::from_static(b"not buffered"));
            // And the framing headers are untouched — only a plugin that
            // actually takes the stream may change the body's length.
            assert_eq!(headers.get(hyper::header::CONTENT_LENGTH).unwrap(), "9");
        });
    }

    /// A `pipe://` match whose plugin declares no streaming hook is equally
    /// inert — the fallback to the buffered path must not disturb the body.
    #[test]
    fn matched_plugin_without_the_hook_is_inert() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            // `stamp` serves the buffered response hook, never a streaming one.
            let matches = vec![crate::plugins::PluginMatch {
                name: "stamp".to_string(),
                param: String::new(),
                pipe_value: None,
                via_pipe: true,
            }];
            let out = pipe_body(
                &state,
                &matches,
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                body::full("as-is"),
            )
            .await;
            assert_eq!(
                collect_body(out).await.expect("body"),
                Bytes::from_static(b"as-is")
            );
            assert_eq!(headers.get(hyper::header::CONTENT_LENGTH).unwrap(), "9");
        });
    }

    /// A plugin that does take the stream transforms it and drops the length
    /// headers, since the transform may change the body's size.
    #[test]
    fn pipe_plugin_takes_the_stream_and_drops_length() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state();
            let mut headers = headers_with_length();
            let matches = vec![crate::plugins::PluginMatch {
                name: "upper".to_string(),
                param: String::new(),
                pipe_value: Some("v".to_string()),
                via_pipe: true,
            }];
            let out = pipe_body(
                &state,
                &matches,
                Dir::Response,
                PipeMeta::default(),
                &mut headers,
                body::full("shout"),
            )
            .await;
            assert_eq!(
                collect_body(out).await.expect("body"),
                Bytes::from_static(b"SHOUT")
            );
            assert!(headers.get(hyper::header::CONTENT_LENGTH).is_none());
        });
    }
}
