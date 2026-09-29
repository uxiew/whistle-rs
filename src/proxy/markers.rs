//! The headers whistle uses to talk to itself — an internal request, an https
//! request carried over a stripped hop, a Composer request, rules carried in a
//! request header — and taking them off before anything else sees them.

use super::*;

/// Request header that marks a request as *whistle-internal*: issued by the
/// proxy (or its tooling) rather than by a client being debugged. It is what
/// makes the `lineProps://internal` and `lineProps://internalOnly` rule lines
/// visible — see [`crate::rules::LineProps::allows_scope`].
///
/// whistle marks such requests with a per-process secret header
/// (`config.PROXY_ID_HEADER = 'x-whistle-proxy-id-' + uid`,
/// `_original/lib/config.js:89`), set by the HTTP client it uses for its own
/// calls (`setInternalOptions`, `_original/lib/util/common.js:1268`) and deleted
/// again the moment the proxy sees it (`checkPluginReqOnce`,
/// `_original/lib/util/index.js:3414-3425`). This port uses a fixed, documented
/// name rather than a secret one: it has no privileged internal service to
/// protect, and a stable name is what lets a client — or whistle-rs's own
/// tooling — deliberately exercise an `internal` rule.
///
/// Any non-empty value marks the request. The header is removed before the
/// rules run, so it never reaches a `includeFilter://reqH.` condition, the session
/// capture, or the origin server.
pub const INTERNAL_REQ_HEADER: &str = "x-whistle-internal-req";

/// Strip the internal-request marker, reporting whether it was present.
pub(super) fn take_internal_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(INTERNAL_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Request header saying "this request was https before the hop that carried it
/// here" — whistle's `config.HTTPS_FIELD`
/// (`'x-whistle-https-request'`, `_original/lib/util/common.js:160`).
///
/// An `internal-*` or `https2http-proxy://` hop deliberately hands the next
/// whistle a plaintext request so it can be inspected, and sets this header so
/// the scheme is not lost on the way (`_original/lib/inspectors/res.js:229-234`).
/// We set it when we are the sending side and honour it when we are the
/// receiving one (`lib/init.js:190-193`), which is what makes a chain of two
/// whistles behave like one.
pub const HTTPS_REQ_HEADER: &str = "x-whistle-https-request";

/// Add [`HTTPS_REQ_HEADER`] when the hop we are about to make strips the
/// origin's TLS, so the whistle on the far side knows the request was https.
pub(super) fn mark_stripped_tls(headers: &mut hyper::HeaderMap, target: &upstream::Target) {
    if target.origin_tls_stripped {
        headers.insert(
            hyper::header::HeaderName::from_static(HTTPS_REQ_HEADER),
            hyper::header::HeaderValue::from_static("1"),
        );
    }
}

/// Strip the stripped-TLS marker, reporting whether it was present. Like the
/// internal marker it is consumed on arrival, so it never reaches a rule
/// condition, the capture, or the origin.
pub(super) fn take_https_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(HTTPS_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Request header saying "the Web UI replayed this" — whistle's
/// `config.FROM_COM_HEADER` (`'x-whistle-composer-<uid>'`,
/// `_original/lib/config.js:93`), the marker behind `from:composer`.
///
/// Sent by [`webui::do_replay`] on the loopback hop through our own port and
/// consumed here, so it reaches neither the rules' header conditions nor the
/// origin — whistle deletes its own the same way
/// (`parseClientInfo`, `_original/lib/util/index.js:3391-3396`). The name is
/// fixed rather than per-process for the same reason the internal marker's is:
/// a stable one is what lets a client exercise the condition deliberately.
pub const COMPOSER_REQ_HEADER: &str = "x-whistle-composer";

/// The headers whistle reads rules out of, and removes either way — see
/// [`header_rules`], which is where reading them lives.
pub use header_rules::ALWAYS_TAKEN as HEADER_RULE_HEADERS;

/// Proxy-internal markers a client may not forge.
///
/// `x-whistle-client-port` is deleted the moment a request is read
/// (`_original/lib/init.js:181`, and again on the upgrade and tunnel paths);
/// `x-whistle-alpn-protocol` is deleted where it is consumed (`init.js:224`).
/// Both name facts about the *connection*, which the connection already
/// answers — a client sending them is either an upstream whistle (whose values
/// this port does not read) or someone spoofing them at the origin.
///
/// `x-whistle-client-id` is not here because it survives
/// `enable://keepClientId`, and that is decided from the rules — see
/// [`apply::apply_request`].
pub const CONNECTION_MARKER_HEADERS: [&str; 2] =
    ["x-whistle-client-port", "x-whistle-alpn-protocol"];

/// Take the rules-carrying headers and the connection markers off a request on
/// its way in, returning what the first four said.
///
/// The removal is unconditional in both proxies — see [`header_rules::take`].
/// What the mode decides is whether the contents are *returned* here or
/// dropped on the floor.
pub(super) fn take_header_rules(
    headers: &mut hyper::HeaderMap,
    cfg: &crate::config::Config,
) -> header_rules::Carried {
    let carried = header_rules::take(headers, cfg.header_rules, cfg.multi_env);
    for name in CONNECTION_MARKER_HEADERS {
        headers.remove(name);
    }
    carried
}

/// Strip the composer marker, reporting whether it was present.
pub(super) fn take_composer_marker(headers: &mut hyper::HeaderMap) -> bool {
    match headers.remove(COMPOSER_REQ_HEADER) {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

#[cfg(test)]
pub(super) mod internal_req_tests {
    use super::super::*;

    fn marked(value: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(INTERNAL_REQ_HEADER, value.parse().unwrap());
        h
    }

    /// The marker flags the request *and* is consumed, so nothing downstream —
    /// a `includeFilter://reqH.` condition, a plugin, the capture, the origin server —
    /// ever sees it.
    #[test]
    fn marker_is_consumed() {
        let mut h = marked("1");
        assert!(take_internal_marker(&mut h));
        assert!(h.get(INTERNAL_REQ_HEADER).is_none());
    }

    /// A missing or empty marker is an ordinary client request; an empty one is
    /// still stripped.
    #[test]
    fn unmarked_request_is_client_scoped() {
        assert!(!take_internal_marker(&mut hyper::HeaderMap::new()));
        let mut h = marked("");
        assert!(!take_internal_marker(&mut h));
        assert!(h.get(INTERNAL_REQ_HEADER).is_none());
    }

    /// The stripped-TLS marker travels only on a hop that actually strips TLS,
    /// and is consumed on arrival like the internal one
    /// (`_original/lib/inspectors/res.js:229-234`, `lib/init.js:190-193`).
    #[test]
    fn the_stripped_tls_marker_is_set_by_the_hop_and_consumed_on_arrival() {
        let target = |tls: bool, stripped: bool| upstream::Target {
            tls_ciphers: None,
            cipher_dropped: None,
            no_proxy_ua: false,
            proxy_connection_close: false,
            connect_host: "example.com".into(),
            connect_port: 80,
            tls,
            origin_tls_stripped: stripped,
            sni: "example.com".into(),
            request_port: 443,
            proxy: None,
            tls_versions: upstream::TlsVersions::Default,
            host_fallback_direct: false,
            auto2http: false,
            h2: None,
        };

        let mut h = hyper::HeaderMap::new();
        mark_stripped_tls(&mut h, &target(false, true));
        assert_eq!(h.get(HTTPS_REQ_HEADER).expect("marker"), "1");
        // Consumed on the way in, so it never reaches a rule condition or the
        // origin — and it says the request was https before the hop.
        assert!(take_https_marker(&mut h));
        assert!(h.get(HTTPS_REQ_HEADER).is_none());

        // An ordinary hop marks nothing.
        let mut h = hyper::HeaderMap::new();
        mark_stripped_tls(&mut h, &target(true, false));
        assert!(h.get(HTTPS_REQ_HEADER).is_none());
        assert!(!take_https_marker(&mut h));
    }

    /// The end of the chain: the flag the pipeline derives from the header is
    /// what makes `internalOnly` lines visible and plain lines invisible.
    #[test]
    fn scope_reaches_rule_resolution() {
        let mut mgr = RuleManager::new();
        mgr.set_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2 lineProps://internalOnly\n",
        );
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        assert_eq!(
            mgr.resolve_scoped(&info, false).value("host"),
            Some("1.1.1.1")
        );
        assert_eq!(
            mgr.resolve_scoped(&info, true).value("host"),
            Some("2.2.2.2")
        );
    }
}

#[cfg(test)]
pub(super) mod req_origin_tests {
    use super::super::*;

    /// The rules-carrying headers never reach the origin.
    ///
    /// whistle deletes them whether or not it is configured to read them
    /// (`getValue`, `_original/lib/rules/index.js:558-572`), and this port had
    /// been forwarding them — so a client could hand the origin a rules text,
    /// and an upstream whistle would have obeyed it. `x-whistle-rule-name` is
    /// the one that travels on, because upstream only ever looks at it in
    /// `multiEnv` mode and therefore never deletes it. Measured on both.
    #[test]
    fn the_rules_headers_are_consumed() {
        let mut h = hyper::HeaderMap::new();
        for name in HEADER_RULE_HEADERS {
            h.insert(
                hyper::header::HeaderName::from_static(name),
                "a.com file://(x)".parse().unwrap(),
            );
        }
        for name in CONNECTION_MARKER_HEADERS {
            h.insert(
                hyper::header::HeaderName::from_static(name),
                "1234".parse().unwrap(),
            );
        }
        h.insert("x-whistle-rule-name", "n".parse().unwrap());
        h.insert("x-other", "kept".parse().unwrap());
        // The default configuration, which is what a proxy run with no `-M`
        // has: the four are taken, and nothing is read.
        take_header_rules(&mut h, &crate::config::Config::default());
        for name in HEADER_RULE_HEADERS.iter().chain(&CONNECTION_MARKER_HEADERS) {
            assert!(h.get(*name).is_none(), "{name} must not survive");
        }
        assert_eq!(h.get("x-whistle-rule-name").unwrap(), "n");
        assert_eq!(h.get("x-other").unwrap(), "kept");
    }

    /// The composer marker is consumed exactly like the internal one: the rules'
    /// header conditions, the plugins, the capture and the origin must never see
    /// this proxy's own bookkeeping. whistle deletes its `FROM_COM_HEADER` on
    /// arrival for the same reason (`_original/lib/util/index.js:3391-3396`).
    #[test]
    fn the_composer_marker_is_consumed() {
        let mut h = hyper::HeaderMap::new();
        h.insert(COMPOSER_REQ_HEADER, "1".parse().unwrap());
        assert!(take_composer_marker(&mut h));
        assert!(h.get(COMPOSER_REQ_HEADER).is_none());

        assert!(!take_composer_marker(&mut hyper::HeaderMap::new()));
        let mut h = hyper::HeaderMap::new();
        h.insert(COMPOSER_REQ_HEADER, "".parse().unwrap());
        assert!(!take_composer_marker(&mut h));
        assert!(h.get(COMPOSER_REQ_HEADER).is_none());
    }

    /// `from:tunnel` and `from:sni` are read off the origin, and they are not the
    /// same fact: a tunnel carrying plain HTTP has no ClientHello to have named a
    /// server, and a forward-proxy request has no tunnel.
    #[test]
    fn the_origin_decides_tunnel_and_sni() {
        let of = |origin: &Origin| crate::rules::ReqOrigin {
            tunnel: matches!(origin, Origin::Mitm { .. }),
            sni: matches!(origin, Origin::Mitm { sni: true, .. }),
            composer: false,
        };
        let mitm = |tls, sni| Origin::Mitm {
            host: "example.com".into(),
            port: 443,
            tls,
            sni,
        };
        assert_eq!(
            of(&mitm(true, true)),
            crate::rules::ReqOrigin {
                tunnel: true,
                sni: true,
                composer: false,
            }
        );
        assert_eq!(
            of(&mitm(false, false)),
            crate::rules::ReqOrigin {
                tunnel: true,
                sni: false,
                composer: false,
            }
        );
        assert_eq!(of(&Origin::Forward), crate::rules::ReqOrigin::default());
    }
}
