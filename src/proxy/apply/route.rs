//! Where a request goes: the `host://`/`proxy://`/`socks://`/`pac://` family and
//! which of them survives the others, the second resolution after a URL
//! rewrite, and the [`Target`] the connection is made from — address, TLS, the
//! `cipher://` pin and the h2 offer.

use super::*;

/// The protocol an operator was *written* with, before alias folding.
pub(super) fn raw_protocol(op: &RuleOp) -> Option<&str> {
    op.raw.split_once("://").map(|(proto, _)| proto)
}

/// How to reach the proxy each upstream-proxy operator names.
///
/// Only the transport is decided here. The scheme conversions two of the names
/// promise are a separate question, answered by [`origin_tls`]: `internal-*` and
/// `https2http-proxy` speak plain HTTP *to* the proxy either way.
pub(super) fn proxy_kind(proto: &str) -> ProxyKind {
    match proto {
        "socks" => ProxyKind::Socks,
        "https-proxy" | "internal-https-proxy" => ProxyKind::Https,
        _ => ProxyKind::Http,
    }
}

/// The protocol of the matched upstream-proxy rule, if one matched at all.
/// Cheap on purpose: it answers "is there a proxy rule?" without parsing the
/// value or evaluating a PAC script.
pub(super) fn matched_proxy_proto(resolved: &Resolved) -> Option<&'static str> {
    crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .copied()
        .find(|proto| resolved.value(proto).is_some())
}

/// The winning upstream proxy, with the protocol that supplied it so its line
/// properties can be read back. `Ok(None)` means "no proxy rule matched, or the
/// one that did chose a direct connection".
///
/// Every other outcome is an error, and that is the point: a rule that names a
/// proxy has said where the request must go. When the address is unusable, or a
/// PAC file cannot be fetched or throws, the request cannot go there — and
/// sending it straight to the origin instead would quietly do the one thing the
/// rule ruled out.
///
/// Only the **PAC** half of that is stricter than upstream: a PAC failure
/// reaches `logger.error` and nothing else (`_original/lib/rules/index.js:295`),
/// so whistle connects direct. An unusable *address* it refuses as well —
/// measured against 2.10.8, `proxy://`, `socks://`, `http-proxy://@` and
/// `proxy://?proxyHost` all answer 502, because the matcher is still truthy and
/// becomes the address `http://`, which the resolver cannot answer. See
/// `docs/RULES.md`.
pub(super) async fn find_proxy(
    info: &ReqInfo,
    resolved: &Resolved,
) -> Result<Option<(&'static str, super::super::upstream::ProxyConfig)>> {
    // Upstream files every proxy spelling under a single `proxy` key, so the
    // first matching *rule line* wins rather than a protocol priority
    // (`PROXY_RE` → `protocol = 'proxy'`, `_original/lib/rules/rules.js:1286`).
    // This port keeps one key per protocol, so rule order is recovered from the
    // winning operator's resolution order.
    let first_by_rule_order = crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .copied()
        .filter_map(|proto| resolved.get(proto).map(|op| (proto, op)))
        .min_by_key(|(_, op)| op.order);
    if let Some((proto, op)) = first_by_rule_order {
        // `parse_proxy_rule` reads the address and the `?host=` override off the
        // matcher as written; whistle's other query flags (`?proxyHost`) are not
        // part of either.
        let mut cfg = parse_proxy_rule(proxy_kind(proto), &op.value).ok_or_else(|| {
            anyhow!(
                "{proto}://{} is not a usable proxy address",
                super::super::upstream::without_credentials(&op.value)
            )
        })?;
        cfg.tunnel = proxy_tunnel(resolved, proto);
        // The `x`-prefixed spellings ask for a direct connection if the hop
        // fails (`X_RE`, `_original/lib/inspectors/res.js:31`).
        cfg.fallback_direct = op.raw.starts_with('x');
        return Ok(Some((proto, cfg)));
    }
    // `pac://` picks the proxy by evaluating FindProxyForURL, from a local file,
    // an inline script, or a URL that is fetched and cached.
    let Some(pac_val) = resolved.value("pac") else {
        return Ok(None);
    };
    let result = crate::proxy::script::find_proxy_for_url(pac_val, &info.full_url, &info.host)
        .await
        .with_context(|| format!("pac://{pac_val}"))?;
    match parse_pac_result(&result)? {
        Some(cfg) => Ok(Some(("pac", cfg))),
        None => Ok(None),
    }
}

/// `proxyTunnel`: the address the hop connects to is itself a proxy, so CONNECT
/// onward through it. Written on the proxy line, on the `host://` line, or
/// request-wide with `enable://proxyTunnel` (`_original/lib/rules/index.js:85-89`).
pub(super) fn proxy_tunnel(resolved: &Resolved, proxy_proto: &str) -> bool {
    resolved.props(proxy_proto).has("proxyTunnel")
        || resolved.props("host").has("proxyTunnel")
        || is_enabled(resolved, "proxyTunnel")
}

/// `?proxyHost` / `&proxyHosts` written into an upstream proxy's own URL —
/// whistle's URL-borne spelling of the line property
/// (`PROXY_HOSTS_RE`, `_original/lib/rules/index.js:80,:168`).
pub(super) fn proxy_host_flag(value: &str) -> bool {
    let Some((_, query)) = value.split_once('?') else {
        return false;
    };
    query
        .split('&')
        .any(|seg| seg.eq_ignore_ascii_case("proxyHost") || seg.eq_ignore_ascii_case("proxyHosts"))
}

/// Does a matched upstream proxy survive next to a matched `host://` rule?
///
/// whistle's default is that `host` wins outright: with both matched, the proxy
/// is dropped and the request goes straight to the host address
/// (`_original/lib/rules/index.js:220-237`). The line properties invert that:
///
/// * `proxyHost` (on either line) — use both: reach the origin through the
///   proxy, but have the proxy connect to the `host://` address (`_phost`);
/// * `proxyHostOnly` — as `proxyHost`, and additionally drop the proxy when no
///   `host://` rule matched, since there is then no host for it to apply;
/// * `proxyFirst` (on either line) — prefer the proxy over the plain host. The
///   host address is then **not used at all**: see [`host_travels_with_proxy`].
///
/// `enable://proxyHost` / `enable://proxyFirst` say the same request-wide.
pub(super) fn proxy_survives_host(
    resolved: &Resolved,
    proxy_proto: &str,
    host_matched: bool,
) -> bool {
    if !host_matched {
        return !resolved.props(proxy_proto).has("proxyHostOnly");
    }
    host_travels_with_proxy(resolved, proxy_proto) || {
        let host_props = resolved.props("host");
        resolved.props(proxy_proto).has("proxyFirst")
            || host_props.has("proxyFirst")
            || is_enabled(resolved, "proxyFirst")
    }
}

/// Does the `host://` address travel *with* the proxy — as the address the hop
/// is asked to connect to (whistle's `req._phost`) — rather than being dropped?
///
/// Only the `proxyHost` family says so. `proxyFirst` does not, and the
/// difference is visible on the wire: whistle reaches `req._phost = …` only
/// inside `if (proxyHost)`, and the `proxyFirst` test is that branch's `else if`
/// (`_original/lib/rules/index.js:217-236`). So `proxyFirst` decides *which of
/// the two rules wins*, the winner is the proxy, and the host address goes
/// nowhere. This port kept it, which turned an absolute-form request for the
/// requested origin into a CONNECT to an address the rule had just been told to
/// prefer the proxy over.
pub(super) fn host_travels_with_proxy(resolved: &Resolved, proxy_proto: &str) -> bool {
    let proxy_props = resolved.props(proxy_proto);
    let host_props = resolved.props("host");
    // `?proxyHost` written into the proxy's own URL; a PAC rule has no URL of
    // its own to carry it.
    let url_flag = proxy_proto != "pac"
        && resolved
            .value(proxy_proto)
            .map(proxy_host_flag)
            .unwrap_or(false);
    proxy_props.has("proxyHostOnly")
        || url_flag
        || proxy_props.has("proxyHost")
        || host_props.has("proxyHost")
        || is_enabled(resolved, "proxyHost")
}

/// Resolve the forwarding family a **second** time, against the URL a URL
/// replacement produced, and lay the answer over the first pass.
///
/// This is upstream's `getProxy`, which is handed `options.href` rather than the
/// request's own URL and re-matches `host://`, the proxy family and `pac://`
/// against it (`_original/lib/rules/index.js:125-152`,
/// `lib/inspectors/res.js:196,:207-210`). Without it a four-word rules file
/// routes opposite ways in the two proxies: `a.com/ http://b.com/x` followed by
/// `b.com proxy://hop` engages the hop upstream and not here, and the same pair
/// written against `a.com` engages it here and not upstream.
///
/// The result *replaces* the first pass's answer for exactly the protocols
/// [`crate::rules::protocols::forwarding_protocols`] names, including when the
/// second pass matched nothing — upstream deletes `proxy` and `pac` before it
/// starts and drops `host` when the second pass finds none. Everything else is
/// the first pass untouched, which is what keeps `cipher://` and the
/// `disable://proxyUA` family reading the URL the client asked for, as they do
/// upstream.
///
/// `moved` is the second pass's subject; `top` and `merged` are the same rule
/// sets the first pass walked, in the same order, so an included or
/// plugin-injected `proxy://` line is re-matched too — upstream re-resolves all
/// four of its managers (`pRules`, `rules`, `fRules`, `hRules`).
///
/// The caller skips this entirely when nothing moved the request: matching is a
/// function of the rules and the request, so a second walk over an unchanged URL
/// reaches the answer already in hand. (The one thing that would differ is a
/// `chance:` filter, which upstream re-rolls; a rule whose engagement is random
/// is not one this port will pay a resolution pass to re-roll.)
pub fn reresolve_forwarding(
    first: &Resolved,
    moved: &ReqInfo,
    top: &RuleManager,
    merged: &[RuleManager],
    is_internal_req: bool,
) -> Resolved {
    let mut second = top.resolve_scoped(moved, is_internal_req);
    for mgr in merged {
        merge_resolved(&mut second, mgr.resolve_scoped(moved, is_internal_req));
    }
    let mut out = first.clone();
    for proto in crate::rules::protocols::forwarding_protocols() {
        // Every one of them is single-match, so there is one operator to move
        // and `remove` is the whole of "the second pass found nothing".
        match second.single.remove(proto) {
            Some(op) => out.single.insert(proto.to_string(), op),
            None => out.single.remove(proto),
        };
    }
    out
}

/// Compute the upstream target, honouring `host://` (and `:port`) overrides.
///
/// `dest` is where the request is *addressed* — its own URL, unless a
/// URL-replacement rule moved it (see [`super::super::dest::Destination`]). `host://`
/// then overrides the address to connect to without changing that, which is why
/// the two are separate: a request forwarded to `http://localhost:5173` and then
/// pinned with `host://10.0.0.1` connects to `10.0.0.1:5173` and still asks for
/// `localhost`. Upstream stacks them the same way — `req.options` comes from the
/// URL rule and `getServerIp` from the host rule.
///
/// Fails rather than falling back to a direct connection when a proxy rule
/// matched but could not be honoured; see [`find_proxy`].
///
/// `resolved` is the forwarding resolution, not the request's own — see
/// [`reresolve_forwarding`], which the caller applies when a rule moved the
/// request.
pub async fn resolve_target(
    info: &ReqInfo,
    dest: &super::super::dest::Destination,
    resolved: &Resolved,
) -> Result<Target> {
    let mut connect_host = dest.host.clone();
    let mut connect_port = dest.port;

    let host_op = resolved.get("host");
    let host_rule = host_op.map(|op| op.value.as_str());
    if let Some(value) = host_rule {
        let (h, p) = parse_host_value(value, dest.port);
        if let Some(h) = h {
            connect_host = h;
        }
        if let Some(p) = p {
            connect_port = p;
        }
    }
    // `xhost://` is the pass-through spelling: the address is used if it works
    // and ignored if it does not, where plain `host://` fails the request
    // (`retryXHost`, `_original/lib/inspectors/res.js:571-600`). The `x` is only
    // visible on the matcher as written — both spellings resolve to the same
    // `host` operator (`xhost: 'host'`, `_original/lib/rules/protocols.js:145`).
    let host_fallback_direct = host_op.is_some_and(|op| op.raw.starts_with('x'));

    let matched = find_proxy(info, resolved)
        .await?
        .filter(|(proto, _)| proxy_survives_host(resolved, proto, host_rule.is_some()));
    let (proxy_proto, proxy) = match matched {
        Some((proto, cfg)) => (Some(proto), Some(cfg)),
        None => (None, None),
    };
    // A proxy that survived a `host://` rule on `proxyFirst` alone won *instead
    // of* it, so the address that rule named is put back — see
    // [`host_travels_with_proxy`].
    if let Some(proto) = proxy_proto
        && host_rule.is_some()
        && !host_travels_with_proxy(resolved, proto)
    {
        connect_host = dest.host.clone();
        connect_port = dest.port;
    }

    let request_tls = super::super::dest::is_tls(&dest.scheme);
    let tls = origin_tls(request_tls, proxy_proto, resolved);
    let cipher = cipher_options(resolved);
    // A cipher string that names nothing this build has takes the **pin** down,
    // not the request. See `parse_cipher_suites` for why the two are not the
    // same fact here that they are in OpenSSL.
    let tls_versions = parse_cipher_versions(&cipher);
    let mut cipher_dropped = None;
    let tls_ciphers = match parse_cipher_suites(&cipher) {
        Ok(policy) => policy,
        Err(e) => {
            tracing::warn!(
                "{} {}: cipher://: {e} — the connection is made without the pin, \
                 so the suite is not the one the rule asked for",
                info.method,
                info.full_url
            );
            cipher_dropped = Some(format!(
                "{e} — the connection was made with this proxy's default cipher suites, \
                 not the ones the rule asked for"
            ));
            None
        }
    };
    // Suites that no version the same rule allows can use — only TLS 1.3 ones
    // under a `maxVersion` of 1.2 — are dropped the same way: the handshake
    // cannot happen with them, and rustls refuses to even build it.
    let tls_ciphers = tls_ciphers.filter(|policy| {
        let fits = policy.fits(tls_versions);
        if !fits {
            tracing::warn!(
                "{} {}: cipher://: none of {:?} can be used with the TLS versions the rule \
                 allows — the connection is made without the suite pin",
                info.method,
                info.full_url,
                policy.names()
            );
            cipher_dropped = Some(format!(
                "none of the suites it names ({}) can be used with the TLS versions it \
                 allows, so the connection was made with the default suites for those \
                 versions",
                policy.names().join(", ")
            ));
        }
        fits
    });
    // Who this proxy is to the origin, and whom it trusts there — the client
    // certificate `tlsOptions://key=…&cert=…` names. Material that cannot be
    // used stops the request here, with the reason: the alternative is a
    // connection made without the identity the rule asked for.
    let tls_extras = match tls {
        true => super::super::tls_options::extras_of(&cipher)
            .await
            .map_err(|why| anyhow!(why))?,
        false => None,
    };
    // The options Node would hand to OpenSSL and rustls has no place for.
    let ignored = super::super::tls_options::unsupported(&cipher);
    if !ignored.is_empty() {
        let note = format!(
            "this build's TLS library has no equivalent of `{}`; {} ignored",
            ignored.join("`, `"),
            if ignored.len() == 1 {
                "it was"
            } else {
                "they were"
            }
        );
        cipher_dropped = Some(match cipher_dropped {
            Some(why) => format!("{why}; {note}"),
            None => note,
        });
    }
    let disabled = disabled_flags(resolved);
    // `checkAuto2Http` (`_original/lib/util/index.js:3191-3198`): a `host://`
    // rule, a local address, or the flag said so out loud — and `disable://`
    // beats all three. The address is read as written rather than as resolved:
    // whistle asks the question of the IP it has just looked up, so a *name*
    // that happens to resolve to a loopback address is local there and not
    // here. Both agree on the shapes the page is about — an IP written into a
    // `host://` rule, and `127.0.0.1` written as a destination.
    let auto2http = !disabled.contains("auto2http")
        && (enabled_flags(resolved).contains("auto2http")
            || host_rule.is_some()
            || if proxy.is_some() {
                connect_host != dest.host || connect_port != dest.port
            } else {
                connect_host == "localhost"
                    || connect_host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(super::super::upstream::is_local_ip)
            });
    // `checkH2` (`_original/lib/inspectors/res.js:174-195`): any of the three
    // spellings, `disable` first.
    const H2: [&str; 3] = ["h2", "http2", "httpsH2"];
    let h2 = if H2.iter().any(|f| disabled.contains(*f)) {
        Some(false)
    } else if H2.iter().any(|f| enabled_flags(resolved).contains(*f)) {
        Some(true)
    } else {
        None
    };
    Ok(Target {
        auto2http,
        h2,
        tls_ciphers,
        tls_extras,
        // Only where there is a handshake for a pin to be missing from.
        cipher_dropped: cipher_dropped.filter(|_| tls),
        // Read straight off `disable`, as upstream reads them.
        no_proxy_ua: disabled.contains("proxyUA"),
        proxy_connection_close: disabled.contains("proxyConnection"),
        connect_host,
        connect_port,
        tls,
        // Whether the hop stripped the origin's TLS: the request then carries
        // whistle's marker so the whistle on the far side can put it back.
        origin_tls_stripped: request_tls && !tls,
        sni: dest.host.clone(),
        request_port: dest.port,
        proxy,
        tls_versions,
        host_fallback_direct,
    })
}

/// Does the connection to the origin speak TLS?
///
/// Normally the request's own scheme decides. Two families of proxy operator
/// exist to override it, and until now neither did — traffic went out in
/// whatever the scheme said, so `http2https-proxy://` left cleartext on the wire
/// that the rule promised to encrypt:
///
/// * `http2https-proxy://` turns an http origin into an https one
///   (`options.protocol = 'https:'`, `_original/lib/inspectors/res.js:236-237`,
///   and `wss = true` for the WebSocket path, `lib/https/index.js:323-324`);
/// * `https2http-proxy://` and the `internal-*` family are hops to another
///   whistle, which wants the request in plaintext so it can inspect it: the
///   origin's TLS is stripped and a marker header carries the fact across
///   (`headers[config.HTTPS_FIELD] = 1; options.protocol = null;`,
///   `res.js:229-234`). Note that this sends cleartext to the proxy — it is what
///   the operator's name asks for, and the receiving whistle restores the
///   scheme, but it is worth knowing before pointing one at a public proxy.
///
/// A `pac://`-chosen proxy converts nothing of its own: whistle reads the
/// conversion off the rule's own protocol, and PAC results carry no whistle
/// protocol. `lineProps://internalProxy` still reaches it, as it reaches any
/// other hop — see [`internal_proxy`].
pub(super) fn origin_tls(
    request_tls: bool,
    proxy_proto: Option<&str>,
    resolved: &Resolved,
) -> bool {
    let Some(proto) = proxy_proto else {
        return request_tls;
    };
    // Upstream asks `isInternal` before `isHttp2https`, so a hop that is somehow
    // both is internal (`res.js:224-238`).
    if matches!(
        proto,
        "https2http-proxy" | "internal-proxy" | "internal-http-proxy" | "internal-https-proxy"
    ) || internal_proxy(resolved, proto)
    {
        return false;
    }
    proto == "http2https-proxy" || request_tls
}

/// `internalProxy` — an ordinary `proxy://` hop is another whistle, so hand it
/// the request in plaintext with the marker header, exactly as the `internal-*`
/// spellings do (`isInternalProxy`, `_original/lib/util/index.js:3801-3807`).
///
/// `docs/LINE_PROPS.md` had this as exposed-only, on the grounds that this port
/// has no "forward https to an upstream proxy in the clear" mode. It has had one
/// since the `internal-*` protocols were ported — see [`origin_tls`]; what was
/// missing was only the *other* way of asking for it. Upstream reads the
/// property off the proxy line or the `host://` line, and `enable://internalProxy`
/// says it request-wide.
pub(super) fn internal_proxy(resolved: &Resolved, proxy_proto: &str) -> bool {
    resolved.props(proxy_proto).has("internalProxy")
        || resolved.props("host").has("internalProxy")
        || is_enabled(resolved, "internalProxy")
}

/// Every `cipher://` line on the request, merged into one options object.
///
/// `getTlsOptions` walks `cipher.list` and hands the lot to `parseRuleJson`
/// (`_original/lib/rules/index.js:684-691`), so several lines **combine** —
/// which is what `cipher.md` means by "根据从上到下的顺序自动合并" — and the
/// first line to name a key keeps it, as it does for `resHeaders://`.
///
/// A value made only of `[a-z0-9:!-]` is a bare cipher string and becomes
/// `{ciphers: …}` (`SEP_CIPHER_RE`, `rules/index.js:38,:686-688`). Anything else
/// is a data object, so the `minVersion=TLSv1.2&maxVersion=TLSv1.3` form the
/// page leads with parses here as it does there — this port read only JSON and
/// silently ignored the documented spelling.
pub(super) fn cipher_options(resolved: &Resolved) -> serde_json::Map<String, serde_json::Value> {
    let mut merged = serde_json::Map::new();
    for value in collect_values(resolved, "cipher") {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let object = match is_bare_cipher_list(value) {
            true => Some(serde_json::json!({ "ciphers": value })),
            // A bare version token — `cipher://TLSv1.2`, which the dot keeps out
            // of the cipher-string road — is not an object either, and upstream
            // makes nothing of it. Here it pins the version, which is the
            // declared improvement `docs/RULES.md` and `https-bench.js` record:
            // whistle's options never reach a handshake that works, so a pin
            // that means what it says is strictly more useful than one that
            // does nothing.
            false => parse_data_object(value, false, false).or_else(|| {
                (cipher_is_12(value) || cipher_is_13(value))
                    .then(|| serde_json::json!({ "minVersion": value, "maxVersion": value }))
            }),
        };
        let Some(serde_json::Value::Object(map)) = object else {
            continue;
        };
        for (key, val) in map {
            merged.entry(key).or_insert(val);
        }
    }
    merged
}

/// `SEP_CIPHER_RE = /[^a-z\d:!-]/i` (`_original/lib/rules/index.js:38`), read
/// the way it is used: a value with **no** character outside that set is a
/// cipher string rather than an options object. A version token fails it on the
/// dot, which is why `cipher://TLSv1.2` is not a cipher list in either program.
pub(super) fn is_bare_cipher_list(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '!' | '-'))
}

/// Parse a `cipher://` value into an upstream TLS version constraint.
///
/// Whistle's `cipher` operator carries Node TLS options as JSON (`minVersion`,
/// `maxVersion`, `secureProtocol`, `ciphers`, …). rustls exposes TLS 1.2 and 1.3
/// only and cannot take OpenSSL cipher strings, so we honour the portable part:
/// the min/max protocol version. Accepts either a JSON object or a bare version
/// token (`cipher://TLSv1.2`). Older pins clamp to the nearest supported version.
pub(super) fn parse_cipher_versions(
    options: &serde_json::Map<String, serde_json::Value>,
) -> super::super::upstream::TlsVersions {
    use super::super::upstream::TlsVersions;
    let get = |k: &str| options.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let (mut min, mut max) = (get("minVersion"), get("maxVersion"));
    // secureProtocol pins a single version (e.g. "TLSv1_2_method").
    if let Some(sp) = get("secureProtocol") {
        min = Some(sp.clone());
        max = Some(sp);
    }

    let is13 = |s: &Option<String>| s.as_deref().map(cipher_is_13).unwrap_or(false);
    let is12 = |s: &Option<String>| s.as_deref().map(cipher_is_12).unwrap_or(false);
    if is13(&min) {
        TlsVersions::Only13 // min 1.3 ⇒ 1.3 only
    } else if is12(&max) || (max.is_none() && is12(&min)) {
        TlsVersions::Only12 // capped at 1.2 (or the bare `TLSv1.2` token)
    } else if is13(&max) && min.is_none() {
        TlsVersions::Only13
    } else {
        TlsVersions::Default
    }
}

/// Read the `ciphers` half of a `cipher://` value.
///
/// The other half — `minVersion`/`maxVersion` — is [`parse_cipher_versions`],
/// and the two are read independently on purpose: a value whose cipher string
/// is unusable may still carry a version that is not, and there is no reason for
/// one to take the other with it.
///
/// `Err` means the string selected no suite. **The caller drops the pin and
/// makes the connection anyway**, which is a deliberate departure from both
/// OpenSSL and from what this port used to do — see [`super::super::ciphers`]'s
/// "When the answer is nothing".
pub(super) fn parse_cipher_suites(
    options: &serde_json::Map<String, serde_json::Value>,
) -> Result<
    Option<std::sync::Arc<super::super::ciphers::CipherPolicy>>,
    super::super::ciphers::NoCipherMatch,
> {
    let spec = options
        .get("ciphers")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let Some(spec) = spec.filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    super::super::ciphers::evaluate(&spec).map(|p| Some(std::sync::Arc::new(p)))
}

/// True if a version token names TLS 1.3.
pub(super) fn cipher_is_13(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("1.3") || s.contains("1_3")
}

/// True if a version token names TLS 1.2 (or an older version we clamp up to 1.2).
pub(super) fn cipher_is_12(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("1.2") || s.contains("1_2") || s.contains("1.1") || s.contains("1_1")
}

/// Parse a PAC `FindProxyForURL` return value into a proxy.
///
/// The list is read in order, as a PAC list is meant to be: the first entry that
/// names somewhere reachable wins. `DIRECT` reached before any usable proxy
/// yields `Ok(None)` — the script was asked where to send the request and
/// answered "nowhere in particular". A `DIRECT` *after* the chosen proxy is a
/// fallback rather than a choice, and is carried as [`ProxyConfig::fallback_direct`]
/// so a hop that cannot be established goes direct instead of failing. whistle
/// arrives at the same place by rewriting the result into an `x`-prefixed rule
/// when the word `direct` follows the proxy it picked (`prefix = 'x'`,
/// `node-pac/lib/Pac.js:96-103`).
///
/// A result with no usable entry and no `DIRECT` is an error instead, because
/// the script *did* name somewhere and we could not act on it. `SOCKS4` is such
/// a case: this port speaks SOCKS5 only, and quietly going direct would hide
/// that.
pub(super) fn parse_pac_result(
    result: &str,
) -> Result<Option<super::super::upstream::ProxyConfig>> {
    let mut entries = result.split(';');
    while let Some(entry) = entries.next() {
        let mut it = entry.split_whitespace();
        let kind = it.next().unwrap_or("").to_ascii_uppercase();
        let hostport = it.next().unwrap_or("");
        let parsed = match kind.as_str() {
            "" => continue,
            "DIRECT" => return Ok(None),
            "PROXY" | "HTTP" => parse_proxy(ProxyKind::Http, hostport),
            "HTTPS" => parse_proxy(ProxyKind::Https, hostport),
            "SOCKS" | "SOCKS5" => parse_proxy(ProxyKind::Socks, hostport),
            _ => None,
        };
        if let Some(mut p) = parsed {
            p.fallback_direct = entries.any(|rest| {
                rest.split_whitespace()
                    .next()
                    .is_some_and(|k| k.eq_ignore_ascii_case("DIRECT"))
            });
            return Ok(Some(p));
        }
    }
    bail!("FindProxyForURL returned no usable proxy: {result:?}");
}

/// Parse a `host` operator value (`ip`, `ip:port`, `host:port`, `:port`).
pub(super) fn parse_host_value(value: &str, _default_port: u16) -> (Option<String>, Option<u16>) {
    let value = value.trim();
    if let Some(port) = value.strip_prefix(':') {
        return (None, port.parse().ok());
    }
    match value.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (Some(h.to_string()), p.parse().ok())
        }
        _ => (Some(value.to_string()), None),
    }
}
