//! Who may use the console: the `Host` and `Origin` checks that stop a
//! cross-site write and DNS rebinding, the `--allow-origin` list and the paths
//! it opens to other pages, and the login — `-n/-w`, and the read-only guest
//! `-N/-W` — with the few paths that stay open without one.

use super::*;

/// The `Origin` to echo back, or `None` when this is not a cross-origin request
/// the console is willing to answer.
///
/// whistle's `checkAllowOrigin` (`_original/biz/webui/lib/index.js:356-378`),
/// measured branch by branch:
///
/// * no `Origin`, or `sec-fetch-site: same-origin` — not cross-origin, and
///   nothing is added;
/// * **`/api/status` and the root certificate answer any origin**, configured or
///   not. Upstream opens the same two (`CORS_PATHS`): whether a proxy is alive
///   and which certificate to trust are the two things a page may legitimately
///   ask of a proxy it does not own;
/// * otherwise the origin's **host**, with its port dropped, has to be on the
///   `--allow-origin` list.
///
/// The header echoes the `Origin` **as it was sent**, port and all, because that
/// is what a browser compares it against.
///
/// Deliberately no `access-control-allow-methods` or `-allow-headers`: upstream
/// sends neither, so a preflighted request (anything with a JSON body or a
/// custom header) is refused by the browser in both. Adding them here would let
/// a named origin drive the whole API — a bigger grant than the flag asks for,
/// on a console whose only other gate may be a password.
pub(super) fn allowed_origin<B>(
    state: &Arc<AppState>,
    req: &Request<B>,
    path: &str,
) -> Option<String> {
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())?
        .to_string();
    if origin.is_empty() {
        return None;
    }
    let same_site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("same-origin"));
    if same_site {
        return None;
    }
    if state.config.allow_origins.all || CORS_PATHS.contains(&path) {
        return Some(origin);
    }
    if state.config.allow_origins.is_empty() {
        return None;
    }
    origin_on_allow_list(state, &origin).then_some(origin)
}

/// `None` when the request may reach the console; the `403` to send when it
/// must not.
///
/// Two attacks a CORS header does nothing about, because the browser has
/// already *sent* the request by the time it reads the response:
///
/// * **Cross-site writes.** A page on any site could `POST` a `text/plain` body
///   to `http://127.0.0.1:8899/api/rules` — a simple request, never preflighted
///   — and the rules changed. Rules read and write files (`file://`,
///   `resWrite://`), so that was a web page writing to the user's disk. A
///   state-changing request that carries an `Origin` must now come from the
///   console's own origin, or from one on `--allow-origin`. One without an
///   `Origin` is not a browser acting for a site (browsers send it on every
///   `POST` and `DELETE`), so curl, scripts and the differential benches are
///   unaffected. `Origin: null` — a sandboxed frame, a `file://` page — is
///   never the console.
/// * **DNS rebinding.** A page on `evil.example` re-resolves its own name to
///   `127.0.0.1` and is then same-origin with the console: it can read and
///   write everything. The request still says `Host: evil.example`, so a
///   request reaching the console directly must name it by an IP literal,
///   `localhost`, or one of its hostnames — the built-in ones and any added
///   with `-l`, which is also how to open it under another name. On the proxy
///   port such a request never gets here: it is forwarded to the name it gave,
///   which redirects to the console's address (`top_level`, `serve`). This
///   check is what answers on the `-P` console port, which forwards nothing.
///
/// Upstream checks neither. The certificate and the PAC file stay open to any
/// host and any origin: they are public by design (see [`open_without_login`]).
pub(super) fn cross_site_refused<B>(
    state: &Arc<AppState>,
    req: &Request<B>,
    path: &str,
) -> Option<Response<DynBody>> {
    if open_without_login(path) {
        return None;
    }
    let host = request_host(req);
    if let Some(host) = &host
        && !host_names_console(state, host)
    {
        return Some(forbidden(&format!(
            "Host {host} is not a name for this console. Open it by IP address or localhost, \
             or add the name with -l."
        )));
    }
    if matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD) {
        return None;
    }
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())?;
    let trusted = origin != "null"
        && (host.as_deref().is_some_and(|h| same_origin(origin, h))
            || state.config.allow_origins.all
            || origin_on_allow_list(state, origin));
    (!trusted).then(|| {
        forbidden(&format!(
            "cross-site request refused: Origin {origin} is not this console. \
             Allow it with --allow-origin if it should be able to change things here."
        ))
    })
}

/// The authority the request was addressed to: `Host`, or the URI's authority
/// for HTTP/2 and absolute-form requests.
pub(super) fn request_host<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
        .filter(|h| !h.is_empty())
}

/// `host[:port]` → (`host`, `port`), brackets off an IPv6 literal.
pub(super) fn split_authority(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        let (ip, tail) = rest.split_once(']').unwrap_or((rest, ""));
        return (ip, tail.strip_prefix(':').and_then(|p| p.parse().ok()));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse().ok()),
        _ => (authority, None),
    }
}

/// Is this a name the console answers to? An IP literal is — rebinding needs a
/// name the attacker controls — and so are `localhost` and the console's own
/// hostnames, whether or not `-M pureProxy` has stopped routing them.
pub(in super::super) fn host_names_console(state: &Arc<AppState>, authority: &str) -> bool {
    let (host, _) = split_authority(authority);
    host.parse::<std::net::IpAddr>().is_ok()
        || host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || BUILTIN_UI_HOSTS
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
        || host.eq_ignore_ascii_case(ROOT_CA_HOST)
        || state
            .config
            .local_ui_hosts
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
}

/// Does `origin` (`scheme://host[:port]`) name the same host and port as the
/// `Host` the request arrived with? A side with no port takes the origin
/// scheme's default, which is how a browser forms both.
pub(super) fn same_origin(origin: &str, host: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let default = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let (oh, op) = split_authority(authority);
    let (hh, hp) = split_authority(host);
    oh.eq_ignore_ascii_case(hh) && op.unwrap_or(default) == hp.unwrap_or(default)
}

pub(super) fn forbidden(message: &str) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(format!("{message}\n"))))
        .unwrap()
}

/// Is `origin`'s host on the `--allow-origin` list — the origin dropped to its
/// host, the way the browser is not asked and upstream's `isAllowHost` is.
pub(super) fn origin_on_allow_list(state: &Arc<AppState>, origin: &str) -> bool {
    // `scheme://host:port` → `host`.
    let host = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let host = host.split('/').next().unwrap_or(host);
    let host = match host.rsplit_once(':') {
        // Not a port if what follows is not a number — an IPv6 literal.
        Some((left, port)) if port.chars().all(|c| c.is_ascii_digit()) => left,
        _ => host,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    state.config.allow_origins.allows(host)
}

/// Whether `/api/status` must answer this caller with **only** its liveness
/// fields, holding back the rest of the pane.
///
/// `/api/status` is one of the [`CORS_PATHS`] that answer any origin, and for
/// upstream that is safe: its `/cgi-bin/status` returns a storage *name*, a
/// couple of labels and a version. This console's status also reports the
/// storage *path* — which carries the account's username — the machine's LAN
/// addresses and the installed plugins. Handed to any origin with
/// `access-control-allow-credentials: true`, that lets a page the operator never
/// allow-listed fingerprint the host: the home directory, the internal network,
/// the tooling. So a caller answered **only** because of the blanket exemption —
/// a cross-origin browser fetch from an unlisted page — gets the liveness subset.
///
/// Everyone the operator did trust sees the whole pane: the console itself
/// (same-origin, so no `Origin` or `sec-fetch-site: same-origin`), a host on the
/// `--allow-origin` list, and a deliberate `--allow-origin '*'`. So does a
/// non-browser client that sends no `Origin` — CORS never gated it and it can
/// read the port directly regardless; the drive-by page is the whole threat.
pub(super) fn status_body_restricted<B>(state: &Arc<AppState>, req: &Request<B>) -> bool {
    let Some(origin) = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| !o.is_empty())
    else {
        return false;
    };
    let same_site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("same-origin"));
    if same_site || state.config.allow_origins.all {
        return false;
    }
    !origin_on_allow_list(state, origin)
}

/// The two paths that answer a cross-origin caller whatever the configuration —
/// upstream's `CORS_PATHS` (`biz/webui/lib/index.js:43`), in this console's
/// spelling.
pub(super) const CORS_PATHS: [&str; 3] = ["/api/status", "/rootCA.crt", "/rootca.crt"];

/// Headers carrying the console's login, withheld from plugin pages.
pub(super) const CONSOLE_CREDENTIALS: [&str; 2] = ["authorization", "proxy-authorization"];

/// Paths that answer before the login does.
///
/// A device that cannot reach the root certificate cannot trust the proxy, and
/// a client that cannot read the PAC file cannot use it — so both stay open,
/// which is upstream's arrangement too (`/cgi-bin/rootca` is in its
/// `DONT_CHECK_PATHS`, `_original/biz/webui/lib/index.js:39-40`).
/// What still answers when `-M headless` has turned the console off.
///
/// The status endpoint, because a console that is off is not a proxy that is
/// gone and something has to be able to say the difference. Upstream keeps
/// `/cgi-bin/status` answering under `headless` for the same reason — measured,
/// along with `/cgi-bin/rootca`, while everything else is a 404.
///
/// Deliberately **not** the same list as [`open_without_login`]: "the console is
/// switched off" and "you have not logged in" are different questions, and the
/// certificate is on both lists for its own reason.
pub(super) const ALIVE_WHEN_HEADLESS: [&str; 1] = ["/api/status"];

pub(super) fn open_without_login(path: &str) -> bool {
    matches!(path, "/rootCA.crt" | "/rootca.crt" | "/proxy.pac" | "/pac")
}

/// `None` when the request may proceed; the 401 to send when it may not.
///
/// whistle's model, minus its cookie. `-n`/`-w` name the account that may do
/// anything; `-N`/`-W` name one that may only **read**, which upstream spells
/// as "the guest login passes, and then the method has to be `GET`"
/// (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`). Credentials come from
/// `Authorization`, from `Proxy-Authorization` — a browser pointed at a proxy
/// port may send either — or from an `authorization` query parameter, all three
/// of which upstream reads (`verifyLogin`, `:171-173`).
///
/// **Narrowed on purpose:** upstream also sets a login cookie keyed on the
/// client's IP so the prompt appears once. Here every request carries its own
/// credentials, which a browser does by itself after the first prompt, and
/// nothing has to be stored.
pub(super) fn login_required<B>(
    state: &Arc<AppState>,
    req: &Request<B>,
    path: &str,
) -> Option<Response<DynBody>> {
    let config = &state.config;
    let account = (config.ui_username.as_deref(), config.ui_password.as_deref());
    if account == (None, None) {
        return None;
    }
    if open_without_login(path) {
        return None;
    }
    let offered = offered_credentials(req);
    let matches = |name: Option<&str>, pass: Option<&str>| {
        offered
            .iter()
            .any(|(u, p)| u.as_str() == name.unwrap_or("") && p.as_str() == pass.unwrap_or(""))
    };
    if matches(account.0, account.1) {
        return None;
    }
    let guest = (
        config.guest_username.as_deref(),
        config.guest_password.as_deref(),
    );
    if guest != (None, None) && matches(guest.0, guest.1) && req.method() == hyper::Method::GET {
        return None;
    }
    let mut resp = Response::builder()
        .status(hyper::StatusCode::UNAUTHORIZED)
        .body(crate::proxy::body::full(bytes::Bytes::from_static(
            b"Access denied",
        )))
        .expect("static response");
    resp.headers_mut().insert(
        hyper::header::WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Basic realm=User Login"),
    );
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Some(resp)
}

/// Every username and password this request offers.
///
/// **Two candidates, not one.** Upstream reads a header *and* a query parameter
/// and lets either satisfy the login — `equalAuth(headerAuth, auth) ||
/// equalAuth(queryAuth, auth)` (`verifyLogin`,
/// `_original/biz/webui/lib/index.js:171-177`). This used to take the first
/// source that carried anything, which meant a browser holding a stale
/// `Authorization` from an earlier password masked the `?authorization=…` the
/// user had just pasted into the address bar, and no reload could get past it.
///
/// The header slot is itself one candidate: `Authorization` when it is there and
/// `Proxy-Authorization` only when it is not, which is upstream's `||` and not a
/// third try.
pub(super) fn offered_credentials<B>(req: &Request<B>) -> Vec<(String, String)> {
    let from_header = |name: hyper::header::HeaderName| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let from_query = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "authorization")
            .map(|(_, v)| percent_decode(v))
    });
    let header = from_header(hyper::header::AUTHORIZATION)
        .or_else(|| from_header(hyper::header::PROXY_AUTHORIZATION));
    [header, from_query]
        .into_iter()
        .flatten()
        .filter_map(|raw| parse_basic(&raw))
        .collect()
}

/// One `Basic` credential, read the way upstream's `parseAuth` reads it.
pub(super) fn parse_basic(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    // `Basic ` comes off when it is there, and **the whole value is decoded when
    // it is not** — `parseAuth` is `AUTH_RE.test(auth) ? auth.substring(6) : auth`
    // (`_original/lib/util/common.js:911-928`). The scheme-less spelling is not
    // idiomatic in a header, but the same function reads the `?authorization=`
    // parameter, where writing `Basic%20…` into a URL is the awkward one.
    // `auth-bench.js` measures all three places.
    let encoded = raw
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map_or(raw, |(_, rest)| rest);
    // Padding optional: `Buffer.from(s, 'base64')` accepts a value whose `=` was
    // trimmed, and a client that trims it is offering the right credentials.
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let decoded = base64::Engine::decode(&engine, encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // The **first** colon splits, so a password may contain one; with no colon
    // the whole value is the name and the password is empty, which is upstream's
    // `indexOf(':') === -1` branch and the only way an empty `-w` is satisfied.
    let (user, pass) = text.split_once(':').unwrap_or((text.as_str(), ""));
    Some((user.to_string(), pass.to_string()))
}

/// `%xx` decoding for the query-parameter spelling.
pub(super) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
pub(super) mod login_tests {
    use super::super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn state(users: (Option<&str>, Option<&str>, Option<&str>, Option<&str>)) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = crate::config::Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-login-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ui_username: users.0.map(str::to_string),
            ui_password: users.1.map(str::to_string),
            guest_username: users.2.map(str::to_string),
            guest_password: users.3.map(str::to_string),
            ..crate::config::Config::default()
        };
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        Arc::new(AppState::new(config, crate::rules::RuleManager::new(), ca))
    }

    fn basic(user: &str, pass: &str) -> String {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    /// Build a request with an optional `Authorization` header.
    fn req(method: &str, path: &str, auth: Option<&str>) -> Request<()> {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(hyper::header::AUTHORIZATION, a);
        }
        b.body(()).expect("request")
    }

    /// Allowed if `login_required` says nothing.
    fn allowed(state: &Arc<AppState>, method: &str, path: &str, auth: Option<&str>) -> bool {
        let r = req(method, path, auth);
        let p = r.uri().path().to_string();
        login_required(state, &r, &p).is_none()
    }

    /// With no account configured the console is open — upstream's own first
    /// test, `if (!username && !password) return true`
    /// (`_original/biz/webui/lib/index.js:161-163`).
    #[test]
    fn no_account_means_no_login() {
        let s = state((None, None, None, None));
        assert!(allowed(&s, "GET", "/", None));
        assert!(allowed(&s, "POST", "/api/rules", None));
    }

    /// The full account may do anything; a wrong password may do nothing.
    #[test]
    fn the_account_opens_everything_and_a_wrong_one_opens_nothing() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(&s, "GET", "/", None));
        assert!(!allowed(&s, "GET", "/", Some(&basic("admin", "wrong"))));
        assert!(!allowed(&s, "GET", "/", Some(&basic("root", "s3cret"))));
        assert!(allowed(&s, "GET", "/", Some(&basic("admin", "s3cret"))));
        assert!(allowed(
            &s,
            "POST",
            "/api/rules",
            Some(&basic("admin", "s3cret"))
        ));
        // A password may contain a colon: only the first one splits.
        let s2 = state((Some("admin"), Some("a:b"), None, None));
        assert!(allowed(&s2, "GET", "/", Some(&basic("admin", "a:b"))));
    }

    /// The guest may read and may not write — upstream gates it on the method
    /// being `GET` (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`).
    #[test]
    fn the_guest_account_may_only_read() {
        let s = state((Some("admin"), Some("s3cret"), Some("guest"), Some("look")));
        let guest = basic("guest", "look");
        assert!(allowed(&s, "GET", "/sessions.json", Some(&guest)));
        assert!(!allowed(&s, "POST", "/api/rules", Some(&guest)));
        assert!(!allowed(&s, "DELETE", "/api/value", Some(&guest)));
        // And a guest that is not configured is nobody.
        let s2 = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(&s2, "GET", "/sessions.json", Some(&guest)));
    }

    /// Which cross-origin callers the console answers, branch by branch —
    /// every row measured against whistle 2.10.8 first.
    ///
    /// The two that answer *any* origin are upstream's `CORS_PATHS`: whether a
    /// proxy is alive, and which certificate to trust. Everything else needs the
    /// origin's host — port dropped — to be on the list, and the header echoes
    /// the `Origin` as it was sent, because that is what a browser compares.
    #[test]
    fn the_console_answers_the_origins_it_was_told_to() {
        let with = |list: &str| {
            let mut c = crate::config::Config {
                storage_dir: std::env::temp_dir().join(format!(
                    "whistle-rs-cors-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                )),
                persist_sessions: false,
                ..crate::config::Config::default()
            };
            c.allow_origins = crate::config::AllowedOrigins::parse(list);
            let ca = crate::ca::CertAuthority::load_or_create(&c).expect("ca");
            Arc::new(AppState::new(c, crate::rules::RuleManager::new(), ca))
        };
        let ask = |state: &Arc<AppState>, path: &str, origin: Option<&str>, hint: bool| {
            let mut b = Request::builder().method("GET").uri(path);
            if let Some(o) = origin {
                b = b.header(hyper::header::ORIGIN, o);
            }
            if hint {
                b = b.header("sec-fetch-site", "same-origin");
            }
            let r = b.body(()).expect("request");
            allowed_origin(state, &r, path)
        };

        let s = with("good.test|*.wild.test");
        assert_eq!(
            ask(&s, "/api/rules", Some("http://good.test"), false).as_deref(),
            Some("http://good.test")
        );
        assert_eq!(
            ask(&s, "/api/rules", Some("http://api.wild.test"), false).as_deref(),
            Some("http://api.wild.test")
        );
        assert_eq!(
            ask(&s, "/api/rules", Some("http://wild.test"), false),
            None,
            "one star is one label"
        );
        assert_eq!(ask(&s, "/api/rules", Some("http://evil.test"), false), None);
        // The port is dropped before matching and kept in the answer.
        assert_eq!(
            ask(&s, "/api/rules", Some("http://good.test:8080"), false).as_deref(),
            Some("http://good.test:8080")
        );
        // Not cross-origin at all.
        assert_eq!(ask(&s, "/api/rules", None, false), None);
        assert_eq!(
            ask(&s, "/api/rules", Some("http://good.test"), true),
            None,
            "same-origin hint"
        );
        // The two that answer anyone, list or no list.
        for path in ["/api/status", "/rootCA.crt"] {
            assert_eq!(
                ask(&s, path, Some("http://evil.test"), false).as_deref(),
                Some("http://evil.test"),
                "{path}"
            );
        }

        // With nothing configured, only those two answer.
        let none = with("");
        assert_eq!(
            ask(&none, "/api/rules", Some("http://good.test"), false),
            None
        );
        assert_eq!(
            ask(&none, "/api/status", Some("http://good.test"), false).as_deref(),
            Some("http://good.test")
        );

        // And `*` answers everyone, everywhere.
        let all = with("*");
        assert_eq!(
            ask(&all, "/api/rules", Some("http://anywhere.test"), false).as_deref(),
            Some("http://anywhere.test")
        );
    }

    /// `/api/status` answers *any* origin (it is a [`CORS_PATHS`]), but a
    /// cross-origin browser reaching it only through that blanket exemption gets
    /// the liveness subset — not the storage path, the LAN addresses or the
    /// plugin list, which a page the operator never allow-listed could otherwise
    /// read with credentials and fingerprint the host by.
    ///
    /// Everyone the operator trusted — the console (same-origin), the
    /// `--allow-origin` list, `--allow-origin '*'`, and a non-browser client
    /// with no `Origin` — still sees the whole pane.
    #[tokio::test]
    async fn cross_origin_status_is_liveness_only() {
        let with = |list: &str| {
            let mut c = crate::config::Config {
                storage_dir: std::env::temp_dir().join(format!(
                    "whistle-rs-status-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                )),
                persist_sessions: false,
                ..crate::config::Config::default()
            };
            c.allow_origins = crate::config::AllowedOrigins::parse(list);
            let ca = crate::ca::CertAuthority::load_or_create(&c).expect("ca");
            Arc::new(AppState::new(c, crate::rules::RuleManager::new(), ca))
        };
        let restricted = |state: &Arc<AppState>, origin: Option<&str>, same_site: bool| {
            let mut b = Request::builder().method("GET").uri("/api/status");
            if let Some(o) = origin {
                b = b.header(hyper::header::ORIGIN, o);
            }
            if same_site {
                b = b.header("sec-fetch-site", "same-origin");
            }
            status_body_restricted(state, &b.body(()).expect("request"))
        };

        let s = with("good.test");
        // The drive-by page: only allowed by the blanket exemption, so held back.
        assert!(restricted(&s, Some("https://evil.example.com"), false));
        // Everyone the operator trusted sees the whole pane.
        assert!(
            !restricted(&s, Some("https://evil.example.com"), true),
            "same-origin"
        );
        assert!(
            !restricted(&s, Some("http://good.test"), false),
            "allow-listed"
        );
        assert!(
            !restricted(&s, Some("http://good.test:8443"), false),
            "allow-listed, port dropped"
        );
        assert!(
            !restricted(&s, None, false),
            "no Origin — not a browser cross-origin read"
        );
        assert!(
            !restricted(&with("*"), Some("https://evil.example.com"), false),
            "--allow-origin '*'"
        );

        // And the bodies match those verdicts: the fingerprinting fields are
        // present for a trusted caller and absent for the drive-by one.
        async fn body(state: &Arc<AppState>, restricted: bool) -> serde_json::Value {
            let resp = status_json(state, restricted).await;
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        }
        let full = body(&s, false).await;
        assert!(
            full.get("storage_dir").is_some(),
            "the console needs the whole pane"
        );
        assert!(full.get("lan_addresses").is_some());
        assert!(full.get("plugins").is_some());

        let lean = body(&s, true).await;
        assert_eq!(
            lean.get("version").and_then(|v| v.as_str()),
            Some(crate::config::VERSION)
        );
        for leaked in [
            "storage_dir",
            "root_ca",
            "lan_addresses",
            "plugins",
            "intercept_https",
        ] {
            assert!(
                lean.get(leaked).is_none(),
                "{leaked} must not cross an untrusted origin"
            );
        }
    }

    /// The three hostnames that open the console through the proxy, and the
    /// one that hands out the certificate instead.
    ///
    /// Measured against whistle 2.10.8: `local.whistlejs.com` and
    /// `local.wproxy.org` serve the console at every path, API included, and
    /// `rootca.pro` serves the root certificate at every path — `/`,
    /// `/anything` and `/cgi-bin/rules/list` all return it.
    #[test]
    fn the_console_hostnames_are_the_console() {
        let s = state((None, None, None, None));
        for host in ["local.whistlejs.com", "local.wproxy.org", "rootca.pro"] {
            assert!(console_host(&s, host), "{host}");
            // Case is not part of a hostname.
            assert!(console_host(&s, &host.to_ascii_uppercase()), "{host} upper");
        }
        assert!(!console_host(&s, "www.example.com"));
        assert!(!console_host(&s, "local.whistlejs.com.evil.test"));
        assert!(!console_host(&s, "notlocal.whistlejs.com"));
    }

    /// `-l/--localUIHost` **adds to** the built-in list rather than replacing
    /// it, which is what upstream does with it.
    #[test]
    fn extra_console_hostnames_are_added_not_substituted() {
        let mut config = crate::config::Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-uihost-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )),
            persist_sessions: false,
            local_ui_hosts: vec!["my.console.test".into(), "other.test".into()],
            ..crate::config::Config::default()
        };
        config.intercept_https = false;
        let ca = crate::ca::CertAuthority::load_or_create(&config).expect("ca");
        let s = Arc::new(AppState::new(config, crate::rules::RuleManager::new(), ca));
        assert!(console_host(&s, "my.console.test"));
        assert!(console_host(&s, "other.test"));
        assert!(
            console_host(&s, "local.whistlejs.com"),
            "the built-ins survive"
        );
        assert!(!console_host(&s, "somewhere.else.test"));
    }

    /// The certificate and the PAC file answer before the login does: a device
    /// that cannot fetch them cannot be configured to use the proxy at all.
    #[test]
    fn the_certificate_and_the_pac_stay_open() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        assert!(allowed(&s, "GET", "/rootCA.crt", None));
        assert!(allowed(&s, "GET", "/proxy.pac", None));
        assert!(!allowed(&s, "GET", "/sessions.json", None));
    }

    /// The three places credentials may travel — `Proxy-Authorization` because
    /// a browser pointed at a proxy port may send that one instead, and the
    /// query parameter because upstream reads it (`verifyLogin`, `:171-173`).
    #[test]
    fn credentials_travel_three_ways() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        let creds = basic("admin", "s3cret");
        let proxy_auth = Request::builder()
            .method("GET")
            .uri("/")
            .header(hyper::header::PROXY_AUTHORIZATION, &creds)
            .body(())
            .expect("request");
        assert!(login_required(&s, &proxy_auth, "/").is_none());
        let query = Request::builder()
            .method("GET")
            .uri(format!(
                "/sessions.json?authorization={}",
                creds.replace(' ', "%20")
            ))
            .body(())
            .expect("request");
        assert!(login_required(&s, &query, "/sessions.json").is_none());
        // A lower-case scheme is still Basic.
        assert!(allowed(
            &s,
            "GET",
            "/",
            Some(&creds.replace("Basic", "basic"))
        ));
    }

    /// A header and a query parameter are **two candidates**, and either one
    /// satisfies the login on its own: upstream's `equalAuth(headerAuth, auth)
    /// || equalAuth(queryAuth, auth)` (`verifyLogin`, `:171-177`).
    ///
    /// Taking the first source that carried anything — which this did — meant a
    /// browser still holding an `Authorization` from an old password masked the
    /// `?authorization=…` in the address bar, and no reload could get past it.
    /// `auth-bench.js` is where the difference was measured.
    #[test]
    fn a_wrong_header_does_not_mask_a_right_query_parameter() {
        let s = state((Some("admin"), Some("s3cret"), None, None));
        let right = basic("admin", "s3cret").replace(' ', "%20");
        let with = |header: &str| {
            let r = Request::builder()
                .method("GET")
                .uri(format!("/sessions.json?authorization={right}"))
                .header(hyper::header::AUTHORIZATION, header)
                .body(())
                .expect("request");
            login_required(&s, &r, "/sessions.json").is_none()
        };
        assert!(with(&basic("admin", "wrong")));
        assert!(with(&basic("root", "s3cret")));
        assert!(with("Bearer nonsense"));
        // And the other way round: a right header beside a wrong parameter.
        let r = Request::builder()
            .method("GET")
            .uri(format!(
                "/sessions.json?authorization={}",
                basic("admin", "wrong").replace(' ', "%20")
            ))
            .header(hyper::header::AUTHORIZATION, basic("admin", "s3cret"))
            .body(())
            .expect("request");
        assert!(login_required(&s, &r, "/sessions.json").is_none());
    }

    /// `parseAuth` strips `Basic ` only when it is there and base64-decodes the
    /// whole value when it is not (`_original/lib/util/common.js:911-928`), and
    /// `Buffer.from(s, 'base64')` does not insist on the padding. The
    /// scheme-less spelling is the natural one in a URL, which is the other
    /// place the same function reads.
    #[test]
    fn a_credential_needs_neither_its_scheme_nor_its_padding() {
        use base64::Engine;
        let s = state((Some("admin"), Some("look"), None, None));
        let raw = base64::engine::general_purpose::STANDARD.encode("admin:look");
        assert!(
            raw.ends_with('='),
            "the fixture has to carry padding to prove anything"
        );
        assert!(allowed(&s, "GET", "/", Some(&raw)));
        assert!(allowed(&s, "GET", "/", Some(raw.trim_end_matches('='))));
        assert!(allowed(
            &s,
            "GET",
            "/",
            Some(&format!("Basic {}", raw.trim_end_matches('=')))
        ));
        // Still no: the wrong credentials are wrong however they are spelled.
        let wrong = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        assert!(!allowed(&s, "GET", "/", Some(&wrong)));
        // A scheme that is not Basic is not stripped, so what is decoded is the
        // whole value — which is not a credential, and does not become one.
        assert!(!allowed(&s, "GET", "/", Some(&format!("Bearer {raw}"))));
    }

    /// No colon at all: the whole value is the name and the password is empty,
    /// upstream's `indexOf(':') === -1` branch. It is the only way an account
    /// configured with an empty password can be satisfied.
    #[test]
    fn a_value_with_no_colon_is_a_name_and_an_empty_password() {
        use base64::Engine;
        let name_only = base64::engine::general_purpose::STANDARD.encode("admin");
        let s = state((Some("admin"), None, None, None));
        assert!(allowed(&s, "GET", "/", Some(&format!("Basic {name_only}"))));
        // And it does not open an account that has a password.
        let s2 = state((Some("admin"), Some("s3cret"), None, None));
        assert!(!allowed(
            &s2,
            "GET",
            "/",
            Some(&format!("Basic {name_only}"))
        ));
    }
}

#[cfg(test)]
pub(super) mod cross_site_tests {
    use super::super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn state(allow: &str, extra_hosts: &[&str]) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut c = crate::config::Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-cross-site-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            local_ui_hosts: extra_hosts.iter().map(|h| h.to_string()).collect(),
            ..crate::config::Config::default()
        };
        c.allow_origins = crate::config::AllowedOrigins::parse(allow);
        let ca = crate::ca::CertAuthority::load_or_create(&c).expect("ca");
        Arc::new(AppState::new(c, crate::rules::RuleManager::new(), ca))
    }

    /// Is the request let through? `origin` is sent only when given.
    fn passes(
        state: &Arc<AppState>,
        method: &str,
        path: &str,
        host: &str,
        origin: Option<&str>,
    ) -> bool {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, host);
        if let Some(o) = origin {
            b = b.header(hyper::header::ORIGIN, o);
        }
        let r = b.body(()).expect("request");
        cross_site_refused(state, &r, path).is_none()
    }

    /// The attack itself: a page elsewhere posting rules as `text/plain`.
    #[test]
    fn a_page_on_another_site_cannot_change_the_rules() {
        let s = state("", &[]);
        let host = "127.0.0.1:8899";
        assert!(!passes(
            &s,
            "POST",
            "/api/rules",
            host,
            Some("http://evil.example")
        ));
        assert!(!passes(
            &s,
            "DELETE",
            "/api/rule-group",
            host,
            Some("https://evil.example")
        ));
        assert!(!passes(
            &s,
            "POST",
            "/plugin/x/save",
            host,
            Some("http://evil.example")
        ));
        // Same host, another port, is another origin — another local app.
        assert!(!passes(
            &s,
            "POST",
            "/api/rules",
            host,
            Some("http://127.0.0.1:3000")
        ));
        // A sandboxed frame or a file:// page says `null`.
        assert!(!passes(&s, "POST", "/api/rules", host, Some("null")));
    }

    /// What must keep working: the console itself, and clients that are not a
    /// browser acting for a site.
    #[test]
    fn the_console_and_non_browser_clients_still_write() {
        let s = state("", &[]);
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "127.0.0.1:8899",
            Some("http://127.0.0.1:8899")
        ));
        assert!(passes(&s, "POST", "/api/rules", "127.0.0.1:8899", None));
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "localhost:8899",
            Some("http://localhost:8899")
        ));
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "[::1]:8899",
            Some("http://[::1]:8899")
        ));
        // Through the proxy, by console hostname, plain and intercepted.
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "local.whistlejs.com",
            Some("http://local.whistlejs.com")
        ));
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "local.whistlejs.com",
            Some("https://local.whistlejs.com")
        ));
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "local.whistlejs.com:80",
            Some("http://local.whistlejs.com")
        ));
    }

    /// Reads stay the browser's CORS business: a foreign page can send a GET
    /// but cannot read the answer, and refusing it would break nothing it could
    /// not already do.
    #[test]
    fn a_read_from_another_site_is_left_to_cors() {
        let s = state("", &[]);
        assert!(passes(
            &s,
            "GET",
            "/sessions.json",
            "127.0.0.1:8899",
            Some("http://evil.example")
        ));
    }

    /// `--allow-origin` still means what it says, for writes too.
    #[test]
    fn an_allowed_origin_may_write() {
        let s = state("tools.example", &[]);
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "127.0.0.1:8899",
            Some("https://tools.example:4443")
        ));
        assert!(!passes(
            &s,
            "POST",
            "/api/rules",
            "127.0.0.1:8899",
            Some("https://evil.example")
        ));
        let all = state("*", &[]);
        assert!(passes(
            &all,
            "POST",
            "/api/rules",
            "127.0.0.1:8899",
            Some("https://evil.example")
        ));
    }

    /// DNS rebinding: the page is same-origin by then, and only `Host` gives it
    /// away — for reads as much as writes.
    #[test]
    fn a_rebound_name_is_refused_for_reads_and_writes() {
        let s = state("", &[]);
        assert!(!passes(
            &s,
            "GET",
            "/sessions.json",
            "evil.example:8899",
            None
        ));
        assert!(!passes(&s, "GET", "/", "evil.example:8899", None));
        assert!(!passes(
            &s,
            "POST",
            "/api/rules",
            "evil.example:8899",
            Some("http://evil.example:8899")
        ));
        // By address, or by the names the console answers to, it opens.
        assert!(passes(&s, "GET", "/", "192.168.1.20:8899", None));
        assert!(passes(&s, "GET", "/", "localhost", None));
        assert!(passes(&s, "GET", "/", "app.localhost:8899", None));
    }

    /// `-l` is how to reach the console under another name.
    #[test]
    fn a_name_added_with_dash_l_is_the_console() {
        let s = state("", &["proxy.lan"]);
        assert!(passes(&s, "GET", "/", "proxy.lan:8899", None));
        assert!(passes(
            &s,
            "POST",
            "/api/rules",
            "proxy.lan:8899",
            Some("http://proxy.lan:8899")
        ));
    }

    /// The certificate and the PAC file are public, from anywhere.
    #[test]
    fn the_certificate_and_pac_answer_any_host() {
        let s = state("", &[]);
        assert!(passes(
            &s,
            "GET",
            "/rootCA.crt",
            "evil.example",
            Some("http://evil.example")
        ));
        assert!(passes(&s, "GET", "/proxy.pac", "evil.example", None));
    }

    #[test]
    fn authorities_split_the_way_browsers_write_them() {
        assert_eq!(split_authority("127.0.0.1:8899"), ("127.0.0.1", Some(8899)));
        assert_eq!(split_authority("[::1]:8899"), ("::1", Some(8899)));
        assert_eq!(split_authority("[::1]"), ("::1", None));
        assert_eq!(split_authority("::1"), ("::1", None));
        assert_eq!(split_authority("example.com"), ("example.com", None));
        assert!(same_origin("http://a.test", "a.test:80"));
        assert!(same_origin("https://a.test", "a.test"));
        assert!(!same_origin("https://a.test", "a.test:80"));
        assert!(!same_origin("not an origin", "a.test"));
    }
}
