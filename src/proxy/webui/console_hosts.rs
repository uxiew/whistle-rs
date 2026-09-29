//! The hostnames the console answers to when a request for them comes through
//! the proxy — `local.whistlejs.com`, `local.wproxy.org`, `rootca.pro` — which
//! win over the rules, as they do in whistle.

use super::*;

/// The hostnames that **are** the console rather than somewhere to forward to.
///
/// whistle's `LOCAL_UI_HOST_LIST` (`_original/lib/config.js:38-42`). A browser
/// pointed at the proxy and sent to `http://local.whistlejs.com/` gets the
/// console, which is what `w2 status` tells people to do — and what this port
/// used to answer with a `502`, because the name resolves to `127.0.0.1` and
/// there is nothing on port 80 there.
///
/// **`rootca.pro` is not the console**: it serves the root certificate, at
/// every path. That is the phone workflow — set the proxy, open `rootca.pro`,
/// install what it hands you — and it is why the name exists.
pub(in super::super) const BUILTIN_UI_HOSTS: [&str; 2] =
    ["local.whistlejs.com", "local.wproxy.org"];

/// The one that hands out the certificate instead.
pub(in super::super) const ROOT_CA_HOST: &str = "rootca.pro";

/// Whether a **proxied** request for this host is the console's to answer.
///
/// Measured against whistle 2.10.8 rather than read: this beats the rules. With
/// `local.whistlejs.com http://127.0.0.1:19902` installed and matching, upstream
/// still serves the console — so the question is asked before a rule is
/// resolved, and it is asked here for the same reason.
pub(in super::super) fn console_host(state: &Arc<AppState>, host: &str) -> bool {
    // `-M pureProxy` puts these names back to being ordinary ones to forward,
    // which is upstream's own `if (config.pureProxy) return false` inside
    // `isWebUIHost` (`_original/lib/config.js:1068-1073`).
    //
    // `-M headless` deliberately does **not** stop the routing: upstream still
    // sends the name to the console and lets the console answer `404`, so the
    // name says "there is a console here and it is off" rather than "no such
    // host". Measured — under `headless` upstream's console hostname is a 404
    // and `rootca.pro` still hands out the certificate.
    if !state.config.console_hostnames {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    BUILTIN_UI_HOSTS
        .iter()
        .any(|h| host.eq_ignore_ascii_case(h))
        || host.eq_ignore_ascii_case(ROOT_CA_HOST)
        || state
            .config
            .local_ui_hosts
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
}

/// Answer a proxied request that named one of those hostnames.
///
/// `rootca.pro` answers with the certificate whatever the path is — measured:
/// `/`, `/anything` and `/cgi-bin/rules/list` all return it. Everything else
/// goes to the ordinary console router, so the API, the login and `/-/` behave
/// exactly as they do on the proxy's own port.
pub(in super::super) async fn handle_proxied(
    state: &Arc<AppState>,
    mut req: Request<Incoming>,
    host: &str,
) -> Response<DynBody> {
    if host.eq_ignore_ascii_case(ROOT_CA_HOST) {
        return root_ca(state);
    }
    // Origin-form, so the router sees the path it would have seen anyway.
    let rest = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if let Ok(uri) = rest.parse::<hyper::Uri>() {
        *req.uri_mut() = uri;
    }
    handle(state, req).await
}
