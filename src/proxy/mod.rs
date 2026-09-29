//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! and a small built-in page to download the root CA.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers.

pub mod apply;
#[cfg(test)]
mod bench;
pub mod body;
pub mod ciphers;
pub mod coding;
pub mod dest;
#[cfg(test)]
mod failure_tests;
pub mod forwarded;
pub mod header_rules;
pub mod outcome;
pub mod persist;
pub mod pool;
pub mod restream;
pub mod script;
pub mod search;
pub mod sni;
pub mod socks;
pub mod template;
pub mod timing;
pub mod unapplied;
#[cfg(test)]
mod unapplied_tests;
pub mod upstream;
pub mod webui;
pub mod ws;

use std::collections::{HashMap, VecDeque};
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

// One file per kind of work the server does. Each takes what it needs from
// here with `use super::*` and is imported whole, so the rest of the crate
// still names everything `proxy::…`. What was private here is `pub(super)`
// there: the same reach it had before.
mod capture;
mod listen;
mod markers;
mod session;
mod state;
mod tunnel;

pub use capture::*;
pub use listen::*;
pub use markers::*;
pub use session::*;
pub use state::*;
use tunnel::*;

/// Collect a whole [`DynBody`] into memory. Its boxed error type is unsized, so
/// it needs flattening before `?` can carry it into `anyhow`.
async fn collect_body(body: DynBody) -> Result<Bytes> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// As [`collect_body`], but giving up past `limit` bytes rather than reading
/// whatever the client decides to send. See [`body::collect_capped`] for what
/// happens at the limit, and why it is not an error.
async fn collect_capped_body(body: DynBody, limit: usize) -> Result<body::Capped> {
    match body::collect_capped(body, limit).await {
        Ok(capped) => Ok(capped),
        Err(e) => Err(anyhow::anyhow!("reading body: {e}")),
    }
}

/// Monotonic id handed to plugins so their request and response hooks can be
/// correlated. Distinct from a [`Session`] id, which is only assigned once the
/// transaction is recorded — far too late for the request hook.
fn next_plugin_req_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod forced_encoding_tests {
    use super::*;

    fn ops(rule: &str, has_body: bool) -> ResBodyOps {
        ops_ct(rule, has_body, None)
    }

    fn ops_ct(rule: &str, has_body: bool, streaming_ct: Option<&str>) -> ResBodyOps {
        let mut m = RuleManager::new();
        m.set_text(&format!("example.com {rule}\n"));
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        ResBodyOps::of(&m.resolve(&info), has_body, 200, streaming_ct)
    }

    /// An event stream is never collected, whatever the rule asks for.
    ///
    /// Collecting one does not delay the response, it withholds it: the body
    /// ends when the server says so, which for SSE is typically never, so the
    /// client receives nothing at all. Verified against a live SSE origin —
    /// before this gate, `enable://gzip` and `resReplace://` each produced not
    /// one byte in three seconds where the unruled host streamed events.
    #[test]
    fn an_event_stream_is_never_collected() {
        for rule in [
            "enable://gzip",
            "resReplace://tick=TOCK",
            "resBody://(x)",
            "resSpeed://10",
            "resAppend://(x)",
        ] {
            for ct in [
                "text/event-stream",
                "text/event-stream; charset=utf-8",
                "  TEXT/EVENT-STREAM ;charset=utf-8",
            ] {
                let ops = ops_ct(rule, true, Some(ct));
                assert!(
                    !ops.needs_body(),
                    "`{rule}` on `{ct}` would hold the stream shut"
                );
            }
        }
    }

    /// …and the gate is only about event streams. Any other type still gets
    /// every operator, or the fix would have bought the hang with the feature.
    #[test]
    fn an_ordinary_response_is_still_transformed() {
        for ct in [
            "text/html",
            "application/json",
            "text/event",
            "application/event-stream",
        ] {
            assert!(
                ops_ct("resReplace://a=b", true, Some(ct)).needs_body(),
                "{ct}"
            );
        }
        // A response with no content type at all is transformed as before.
        assert!(ops_ct("resReplace://a=b", true, None).needs_body());
        // `text/event-streamlike` *does* count as a stream: upstream's `SSE_RE`
        // is not anchored at the end. Pinned as **documented**, not as desired —
        // it is upstream's answer, and diverging here would be a divergence
        // nobody asked for.
        assert!(is_event_stream(Some("text/event-streamlike")));
    }

    /// The Frames panel cuts an event stream by its **type**: a `charset`
    /// parameter, spacing and case do not hide one (whistle 2.10.9 and later),
    /// and a type that merely starts the same way is not one.
    #[test]
    fn an_event_stream_is_framed_whatever_its_parameters() {
        let framed = |ct: &str| {
            let mut headers = hyper::HeaderMap::new();
            headers.insert(hyper::header::CONTENT_TYPE, ct.parse().unwrap());
            response_frames(&resolved_for("reqHeaders://x-a=1"), &mut headers, None).is_some()
        };
        for ct in [
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "  TEXT/EVENT-STREAM ;charset=utf-8",
        ] {
            assert!(framed(ct), "{ct}");
        }
        for ct in [
            "text/event-streamlike",
            "application/event-stream",
            "text/plain",
        ] {
            assert!(!framed(ct), "{ct}");
        }
    }

    /// A `Resolved` for one rule line, for the gate tests below.
    fn resolved_for(rule: &str) -> Resolved {
        let mut m = RuleManager::new();
        m.set_text(&format!("example.com {rule}\n"));
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        m.resolve(&info)
    }

    /// Not being collected is not the same as not being rewritten.
    /// `resReplace://` travels with the stream, so the operator that the gate
    /// above drops from the buffered path is picked up here instead.
    #[test]
    fn a_substitution_rides_along_with_an_event_stream() {
        let r = resolved_for("resReplace://tick=TOCK");
        let mut t = stream_replace(&r, Some("text/event-stream"), None)
            .expect("a substitution for an event stream");
        assert_eq!(
            String::from_utf8(t.push(b"data: tick\n\n")).unwrap(),
            "data: TOCK\n\n"
        );
    }

    /// The three refusals, each for its own reason — see [`stream_replace`].
    #[test]
    fn a_stream_that_cannot_be_substituted_is_left_alone() {
        let r = resolved_for("resReplace://tick=TOCK");
        assert!(
            stream_replace(&r, Some("text/html"), None).is_none(),
            "a body with an end belongs to the buffered path"
        );
        assert!(
            stream_replace(&r, Some("text/event-stream"), Some("gzip")).is_none(),
            "a compressed stream cannot be searched for a plaintext pattern"
        );
        assert!(
            stream_replace(&resolved_for("log://x"), Some("text/event-stream"), None).is_none(),
            "no substitutions means no transform to install"
        );
        // `identity` is the spelling of "no coding", so it is not a refusal.
        assert!(stream_replace(&r, Some("text/event-stream"), Some("identity")).is_some());
    }

    /// The operator gate and the stream gate must agree about which bodies
    /// `resReplace://` reaches, or a substitution would be applied on one path
    /// and skipped on the other for the same response.
    #[test]
    fn the_content_type_gate_is_the_same_on_both_paths() {
        // Upstream refuses the operator outright for an image, and an event
        // stream can carry one — `text/event-stream` is only the usual case.
        let r = resolved_for("resReplace://a=b");
        assert!(apply::res_replace_pairs(&r, Some("image/png")).is_empty());
        assert!(apply::res_replace_pairs(&r, None).is_empty());
        assert!(!apply::res_replace_pairs(&r, Some("text/event-stream")).is_empty());
    }

    /// `resPrepend://` and `resAppend://` do not need a body either — one goes
    /// before the first byte, the other after the last.
    #[test]
    fn an_event_stream_can_be_prepended_to_and_appended_to() {
        let r = resolved_for("resPrepend://(BEFORE) resAppend://(AFTER)");
        let inject = stream_injection(&r, Some("text/event-stream")).expect("an injection");
        assert_eq!(inject.top, b"BEFORE");
        assert_eq!(inject.bottom, b"AFTER");
        assert!(
            inject.replacement.is_none(),
            "the origin's body still flows"
        );
        // A body with an end belongs to the buffered path, which also applies
        // the typed families and the HTML gating this one cannot.
        assert!(stream_injection(&r, Some("text/html")).is_none());
    }

    /// `resBody://` says there is no origin body to wait for, which is what
    /// makes it usable as a mock for a stream that would never end.
    #[test]
    fn res_body_replaces_a_stream_rather_than_waiting_for_it() {
        // No space inside the parentheses: a rules line is whitespace-separated
        // tokens, so a multi-word body is named with `{a-value}` or a file.
        let r = resolved_for("resBody://(data:mocked)");
        let inject = stream_injection(&r, Some("text/event-stream")).expect("an injection");
        assert_eq!(inject.replacement.as_deref(), Some(&b"data:mocked"[..]));
    }

    /// Nothing here reads the origin's bytes, so unlike the substitution an
    /// encoded stream is no obstacle.
    #[test]
    fn an_injection_does_not_care_what_the_stream_is_encoded_as() {
        let r = resolved_for("resPrepend://(X)");
        assert!(stream_injection(&r, Some("text/event-stream")).is_some());
        assert!(
            stream_replace(
                &resolved_for("resReplace://a=b"),
                Some("text/event-stream"),
                Some("gzip")
            )
            .is_none(),
            "…where the substitution still refuses one"
        );
    }

    /// A line with none of these operators installs nothing.
    #[test]
    fn a_stream_no_operator_touches_gets_no_injection() {
        assert!(stream_injection(&resolved_for("log://x"), Some("text/event-stream")).is_none());
    }

    /// `disable://trailers` costs no buffering, so an event stream keeps it
    /// where it loses the operators that need the whole body.
    #[test]
    fn an_event_stream_still_drops_the_trailers_it_was_told_to() {
        let ops = ops_ct("disable://trailers", true, Some("text/event-stream"));
        assert!(ops.no_trailers);
        assert!(!ops.needs_body(), "and still does not hold the stream shut");
    }

    /// Gating the rule operators was not enough: a plugin declaring
    /// `responseBody` reaches the same collection through its own door, and is
    /// not a rule operator. Measured against a live SSE origin — not one byte
    /// in six seconds, not even a response head.
    #[test]
    fn a_plugin_asking_for_the_body_cannot_hold_an_event_stream_shut_either() {
        let sse = Some("text/event-stream");
        let ops = ops_ct("resReplace://a=b", true, sse);
        assert!(!must_collect_body(&ops, true, false, sse));
        // …and the gate is only about event streams: an ordinary response is
        // still collected for the hook that asked for it.
        let html = Some("text/html");
        let ops = ops_ct("log://x", true, html);
        assert!(must_collect_body(&ops, true, false, html));
    }

    /// The one door an event stream may pass through. A plugin that replaced
    /// the body outright hands over bytes that are already in hand, so the
    /// origin's stream is never awaited and nothing is withheld.
    #[test]
    fn an_overridden_body_is_collected_even_for_an_event_stream() {
        let sse = Some("text/event-stream");
        let ops = ops_ct("log://x", true, sse);
        assert!(must_collect_body(&ops, false, true, sse));
    }

    /// The bug: `enable://gzip` standing alone left `needs_body` false, so the
    /// response took the streaming path, `reencode` was never reached, and the
    /// flag did nothing at all. It only ever appeared to work when some *other*
    /// operator on the line happened to buffer the body for it.
    #[test]
    fn a_forced_encoding_alone_asks_for_the_buffered_path() {
        for flag in ["enable://gzip", "enable://br", "enable://deflate"] {
            let ops = ops(flag, true);
            assert!(ops.force_encoding.is_some(), "{flag}");
            assert!(
                ops.needs_body(),
                "{flag} must buffer, or it cannot be applied"
            );
        }
    }

    /// A response with no body has nothing to encode, so the flag must not drag
    /// it onto the buffered path — gzipping nothing produces a 20-byte header
    /// that says "nothing".
    #[test]
    fn a_response_with_no_body_is_not_buffered_to_encode_it() {
        let ops = ops("enable://gzip", false);
        assert!(ops.force_encoding.is_none());
        assert!(!ops.needs_body());
    }

    /// The streaming fast path is what most traffic takes, and nothing here may
    /// pull it onto the buffered one.
    #[test]
    fn a_response_no_operator_touches_still_streams() {
        assert!(!ops("log://x", true).needs_body());
    }

    /// A body that could not be decoded goes out exactly as it arrived,
    /// **including its header**. `reencode` refuses to force a coding onto such
    /// a body and reports `Identity` — and stamping that removes the header, so
    /// a `zstd` response would reach the client as zstd bytes labelled plain.
    /// That is worse than the flag doing nothing: it arrived readable and would
    /// leave unreadable.
    #[test]
    fn a_body_that_was_never_decoded_keeps_the_coding_it_arrived_under() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-encoding", "zstd".parse().expect("a header value"));
        let restore = coding::Restore {
            coding: coding::Coding::Identity,
            plain: false,
        };
        let now = restore_content_encoding(
            &mut headers,
            restore,
            coding::Coding::Identity,
            Some("zstd".to_string()),
        );
        assert_eq!(headers.get("content-encoding").expect("kept"), "zstd");
        // …and the capture is told what the body is really under, so the
        // preview does not try to read zstd as text.
        assert_eq!(now.as_deref(), Some("zstd"));
    }

    /// The ordinary case still stamps what was actually applied — including
    /// removing the header when a gzipped body was rewritten and goes out plain.
    #[test]
    fn a_decoded_body_is_labelled_with_what_went_back_on() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().expect("a header value"));
        let restore = coding::Restore {
            coding: coding::Coding::Gzip,
            plain: true,
        };
        let now = restore_content_encoding(
            &mut headers,
            restore,
            coding::Coding::Identity,
            Some("gzip".to_string()),
        );
        assert!(headers.get("content-encoding").is_none(), "must be removed");
        assert_eq!(now, None);

        let mut headers = hyper::HeaderMap::new();
        let now = restore_content_encoding(&mut headers, restore, coding::Coding::Brotli, None);
        assert_eq!(headers.get("content-encoding").expect("set"), "br");
        assert_eq!(now.as_deref(), Some("br"));
    }
}

/// Where a request originated, which decides how we derive its target.
#[derive(Clone)]
enum Origin {
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

#[cfg(test)]
mod websocket_flag_tests {
    use super::*;

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
mod hide_tests {
    use super::*;

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

/// Resolve the rules a second time, now that the response head is in, and fold
/// the result into `resolved`.
///
/// This is whistle's response phase (`pluginMgr.getResRules` →
/// `rulesMgr.resolveResRules`, `_original/lib/plugins/index.js:1322-1336`),
/// which runs for **every** response — from the origin or from a rule that
/// answered locally — before any response operator or plugin hook has touched
/// it. Same here: `res` is built from the head exactly as it arrived.
///
/// Costs nothing when no rule mentions the response: the manager answers that
/// from a list of candidate lines its groups precompute, and this returns
/// without walking a single rule.
///
/// Locking: takes the two `std::sync` read locks one after the other, never
/// nested and each dropped before the `.await` at the end — which is what lets
/// this be called from `serve`'s future. That await is the value loader, and it
/// only ever does work when this pass added an operator whose value names a
/// file or a URL.
async fn resolve_response_phase(
    state: &AppState,
    info: &mut ReqInfo,
    resolved: &mut Resolved,
    res: crate::rules::ResInfo,
    is_internal_req: bool,
    merged: &[crate::rules::RuleManager],
) {
    info.res = Some(res);
    let host = bind_host(state);
    let mut added = false;
    // The same map the request pass used. Reading `state.values` alone here made
    // a response-phase operator the only place a ``` block in the rules text was
    // invisible, so `resBody://{mock} includeFilter://s:404` served the six
    // characters `{mock}` — and the values a produced text carries are part of
    // it, or its response-phase lines would lose them.
    let mut values = effective_values(state);
    for mgr in merged {
        values.extend(mgr.carried_values().clone());
    }
    // Rules merged in mid-request get the same second pass. Upstream re-resolves
    // its `pRules`/`fRules`/`hRules` here too
    // (`_original/lib/plugins/index.js:1326-1335`); each manager answers from
    // its own precomputed flags, so a text with no response-dependent line
    // costs one comparison.
    if let Some(mut extra) = apply::response_phase_of(merged, info, is_internal_req) {
        apply::substitute_values(&mut extra, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
        resolved.merge_response_phase(extra);
        added = true;
    }
    let extra = {
        let rules = state.rules.read().unwrap();
        rules.resolve_response(info, is_internal_req)
    };
    if let Some(mut extra) = extra {
        tracing::debug!(
            "{} {} -> re-resolving rules for status {}",
            info.method,
            info.full_url,
            info.res.as_ref().map(|r| r.status).unwrap_or_default()
        );
        apply::substitute_values(&mut extra, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(&mut extra, state.config.port, crate::config::VERSION);
        resolved.merge_response_phase(extra);
        added = true;
    }
    // Backtick templates on response-phase operators were left for this moment —
    // they are the only values whose variables need the head that has just
    // arrived (`apply::waits_for_the_response`). Everything else was substituted
    // in the request pass and says so, so this walk touches only what it
    // deferred.
    added |= apply::substitute_values(resolved, &values, tpl_ctx(&host, state.config.port, info));
    // `resRules://` last, because what a rules text produces wins over the file
    // that named it and the merge is an overwrite — upstream's `mergeRules(req,
    // …, true)` at the end of `getResRules`.
    //
    // It substitutes against `values`, the same map every other pass here uses.
    // Reading `state.values` directly is what made a response-phase operator the
    // one place a ``` block in the rules text was invisible.
    if let Some(carried) = apply::merge_res_rules(resolved, info, &values, is_internal_req) {
        values.extend(carried);
        apply::substitute_values(resolved, &values, tpl_ctx(&host, state.config.port, info));
        apply::substitute_config_vars(resolved, state.config.port, crate::config::VERSION);
        added = true;
    }
    // Operators this pass added have never been past the value loader — a
    // `resBody:///tmp/mock.json includeFilter://s:404` line withholds its
    // `resBody` from the request pass entirely. Ones that already loaded carry
    // `value_is_content` and are skipped.
    if added {
        apply::load_rule_values(resolved, info).await;
    }
}

/// whistle's own bind address, empty when bound to all interfaces — see
/// [`template::ProxyEnv`]. Owned because `Config` keeps an `IpAddr`.
fn bind_host(state: &AppState) -> String {
    state.config.host.map(|h| h.to_string()).unwrap_or_default()
}

/// The request context a backtick operator value renders against.
fn tpl_ctx<'a>(host: &'a str, port: u16, info: &'a ReqInfo) -> apply::TplCtx<'a> {
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
fn forwarding_resolution(
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
fn known_server_ip(target: &upstream::Target, reached: Option<SocketAddr>) -> Option<String> {
    reached.map(|a| a.ip().to_string()).or_else(|| {
        target
            .connect_host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string())
    })
}

/// The response-side operators that act on the body once it is in hand.
///
/// Gathered in one place because more than one exit produces a response: the
/// origin's, a `plugin://` hook's, and a short-circuit rule's. whistle runs the
/// same response inspectors over all three (`_original/lib/inspectors/res.js`
/// is reached whether the bytes came from a server, a plugin, or a local file),
/// so they must run the same set here too.
#[derive(Default)]
struct ResBodyOps {
    /// `resSpeed://` — throttle, in kilobits/s.
    speed: Option<f64>,
    /// `resScript://` — the loaded source, not the rule value.
    script: Option<String>,
    /// `weinre://` — debug-agent id to inject.
    weinre: Option<String>,
    /// `resWrite://` / `resWriteRaw://` — dump paths, already carrying the
    /// `.<status>` suffix a non-200 gets.
    write: Option<String>,
    write_raw: Option<String>,
    /// `enable://forceReqWrite` — write the dump even over an existing file.
    force_write: bool,
    /// `trailers://` — trailing headers to append after the body. Already empty
    /// when `disable://trailers` cancelled them.
    trailers: hyper::HeaderMap,
    /// `disable://trailers` / `trailer` — drop the origin's trailer section too,
    /// which is the half a rule-side check cannot see.
    no_trailers: bool,
    /// `disable://trailerHeader` clears this: the trailers still go, the
    /// `Trailer:` header announcing them does not.
    announce_trailers: bool,
    /// Any content operator (`resReplace`, `htmlAppend`, `resBody`, …).
    content: bool,
    /// `enable://gzip|br|deflate` — the coding the response must leave under
    /// (`getEnableEncoding`, `_original/lib/util/index.js:1534-1548`).
    ///
    /// Held here rather than read where it is used so that
    /// [`ResBodyOps::needs_body`] can count it. It is the one operator that
    /// needs the whole body without rewriting a byte of it, and leaving it out
    /// of that gate is what made the flag do nothing when it stood alone: the
    /// response took the streaming path, `reencode` was never reached, and
    /// `enable://gzip` was inert unless some *other* operator happened to
    /// buffer the body for it.
    force_encoding: Option<coding::Coding>,
}

/// Is this response an event stream — a body that need never end?
///
/// whistle's `isSSE` (`_original/lib/util/index.js:3917-3921`), whose test is
/// `/^\s*text\/event-stream\s*;?/i` against `content-type`. Deliberately as
/// loose as upstream's: the pattern is not anchored at the end, so anything
/// *starting* with the media type matches, parameters and all.
fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        ct.trim_start()
            .get(.."text/event-stream".len())
            .is_some_and(|head| head.eq_ignore_ascii_case("text/event-stream"))
    })
}

/// Must the response body be collected before anything can go to the client?
///
/// Three doors lead to the buffered path, and gating only one of them is why
/// this is written down in a single place. [`ResBodyOps::of`] already drops the
/// rule operators for an event stream — but a plugin declaring `responseBody`
/// reaches the same `collect_with_trailers` through its own door and hangs the
/// stream exactly as `resReplace://` did, which is not a rule operator and so
/// was not covered. Measured against a live SSE origin: not one byte in six
/// seconds, no response head either, where the unruled host streamed at once.
///
/// An override is the one door an event stream may pass through: the plugin
/// replaced the body outright, so those bytes are already in hand and the
/// origin's body is never awaited. Nothing is withheld, because nothing is
/// waited for.
fn must_collect_body(
    ops: &ResBodyOps,
    plugin_wants_body: bool,
    has_override: bool,
    res_ct: Option<&str>,
) -> bool {
    if has_override {
        return true;
    }
    if is_event_stream(res_ct) {
        return false;
    }
    ops.needs_body() || plugin_wants_body
}

/// The frame splitter a **response** asks for, or `None` for a body the console
/// shows whole.
///
/// whistle's Frames panel gets a body cut into pieces in two cases
/// (`handleResBody`, `_original/lib/inspectors/data.js:323-345`):
///
/// * the response **is** an event stream — the type before any `;`, so
///   `text/event-stream; charset=utf-8` counts. whistle compared the header
///   whole up to 2.10.8 and framed that one as a plain body; 2.10.9 fixed it
///   ("support `text/event-stream` responses with a `charset=utf-8` parameter",
///   `trimType`, `data.js:335`), and this follows. Still narrower than the test
///   deciding whether the body may be buffered ([`is_event_stream`]), which
///   also takes `text/event-streamlike`;
/// * a `x-whistle-custom-frame-separator` header names a separator, which works
///   for any content type and is how the FAQ turns a chunked JSON stream into
///   frames.
///
/// `disable://captureStream` turns both off, and a **compressed** body is never
/// framed — upstream checks `getZipType(info)` first, and a separator search in
/// a deflate stream would find nothing anyway.
///
/// The header is removed from the response either way, so the client never sees
/// it (`parseFrameSep` deletes before it decides, `:83`).
fn response_frames(
    resolved: &Resolved,
    headers: &mut hyper::HeaderMap,
    res_enc: Option<&str>,
) -> Option<restream::FrameSplitter> {
    let custom = restream::take_frame_separator(headers);
    if apply::is_disabled(resolved, "captureStream") {
        return None;
    }
    if res_enc.is_some_and(|enc| !enc.trim().eq_ignore_ascii_case("identity")) {
        return None;
    }
    let is_sse = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let essence = ct.split(';').next().unwrap_or("").trim();
            essence.eq_ignore_ascii_case("text/event-stream")
        });
    // **A named separator frames only when `enable://captureStream` says so.**
    // An event stream turns it on by itself — `captureStream = captureStream ||
    // isSse`, and only then does a separator decide anything
    // (`_original/lib/inspectors/data.js:329-340`). Measured through upstream's
    // own frames API: with the header alone and no flag, whistle reports **no
    // frames at all**, on the request side as well as the response side.
    //
    // Worth following rather than simplifying away, and not only for alignment:
    // the header can arrive from the *origin*, or from a whistle further up the
    // chain, and a header somebody else sent should not by itself turn on body
    // capture here. That is the same call this port already made about the
    // rules-carrying headers.
    if custom.is_some() && (is_sse || apply::is_enabled(resolved, "captureStream")) {
        return custom;
    }
    is_sse.then(restream::FrameSplitter::sse)
}

/// The substitution to run on a response body that is **still arriving**, or
/// `None` to stream it through untouched.
///
/// This is the half of the body layer an event stream can have. Collecting one
/// withholds it (see [`must_collect_body`]), so the operators that need the
/// whole body — `resBody://`, the injections, `resMerge://` — stay dropped. But
/// `resReplace://` never needed the whole body: it needs a window, and
/// [`crate::proxy::restream`] holds exactly one.
///
/// Two things disqualify a stream, and both are refusals rather than attempts:
///
/// * **an encoded body**, because searching a deflate stream for a plaintext
///   pattern finds nothing and rewriting it would corrupt what the header
///   promises. The buffered path decompresses first; there is no streaming
///   decoder here, so the honest answer is to leave the bytes alone. In practice
///   an event stream is served uncompressed — `text/event-stream` and
///   `content-encoding` together are rare, and this declines rather than guesses.
/// * **anything that is not an event stream**, because a body with an end
///   belongs to the buffered path, which applies every operator rather than one.
///   Reaching here with substitutions and no event stream would mean
///   [`ResBodyOps::needs_body`] disagreed with this function about `content`.
fn stream_replace(
    resolved: &Resolved,
    res_ct: Option<&str>,
    res_enc: Option<&str>,
) -> Option<restream::TextReplace> {
    if !is_event_stream(res_ct) {
        return None;
    }
    // `identity` is the spelling of "no coding"; anything else is a coding.
    if res_enc.is_some_and(|enc| !enc.trim().eq_ignore_ascii_case("identity")) {
        return None;
    }
    let pairs = apply::res_replace_pairs(resolved, res_ct);
    restream::TextReplace::new(&pairs, true)
}

/// The prepend / append / replace-body injection for a response still arriving,
/// or `None` to leave the stream alone.
///
/// Gated on the response being an event stream for the same reason
/// [`stream_replace`] is: a body with an end belongs to the buffered path, which
/// applies the typed families and the HTML gating too. Unlike the substitution
/// there is no encoding question — nothing here reads the origin's bytes, so a
/// compressed stream can be prepended to as safely as a plain one.
fn stream_injection(resolved: &Resolved, res_ct: Option<&str>) -> Option<apply::StreamInjection> {
    is_event_stream(res_ct)
        .then(|| apply::res_stream_injection(resolved))
        .flatten()
}

impl ResBodyOps {
    /// The body operators in force, given what the response *is*.
    ///
    /// `has_body` is whistle's `util.hasBody` (`_original/lib/util/common.js:370-380`):
    /// false for a `HEAD` request and for a 1xx, 204 or **any 3xx** status. When
    /// it is false upstream drops every body operator on the floor —
    /// `getRuleValue(..., !hasResBody, ...)` returns `undefined` for each inject
    /// value (`res.js:988` → `util/index.js:1394-1396`) and the speed/body/top/
    /// bottom keys are deleted outright (`res.js:1106-1113`).
    ///
    /// This port had no such gate, so `resAppend://X` gave a `302` a body,
    /// stripped its `Content-Length`, and — because the injection also stamps
    /// `Cache-Control: no-store` and strips CSP — rewrote the headers of a
    /// redirect the rule was never meant to touch.
    ///
    /// `streaming_ct` is the content type of a body that is **still arriving**,
    /// and exists for one reason: an event stream must never be collected. A
    /// caller whose body is already wholly in memory passes `None` — there is
    /// nothing left to wait for, so the gate below would only drop operators
    /// that can be applied perfectly well. See [`is_event_stream`].
    fn of(resolved: &Resolved, has_body: bool, status: u16, streaming_ct: Option<&str>) -> Self {
        if is_event_stream(streaming_ct) {
            // Every operator here needs the whole body, and an event stream has
            // no "whole" — it ends when the server decides, which for SSE is
            // typically never. Collecting one does not delay the response, it
            // withholds it: the client receives nothing at all, where without
            // the rule it would have received events for as long as it listened.
            //
            // So the operators that need the whole body are dropped and the
            // stream is passed through. `resReplace://` is *not* among them and
            // is not dropped here — it needs a window rather than the whole
            // body, and it travels with the stream instead. See
            // [`stream_replace`] and [`crate::proxy::restream`], which is
            // upstream's own mechanism: hold back only a chunk tail, and for an
            // event stream flush through the last `\n\n` so a complete event is
            // never held (`_original/lib/util/replace-string-transform.js:27-33`).
            //
            // `disable://trailers` survives because the streaming path reads it
            // — it drops the origin's trailer section, which costs no buffering.
            // The rest of the header operators here (`resWriteRaw://`,
            // `trailers://`) have no reader on that path, so setting them would
            // announce an effect that does not happen.
            return ResBodyOps {
                no_trailers: apply::trailers_disabled(resolved),
                ..ResBodyOps::default()
            };
        }
        if !has_body {
            // The trailers still apply: they are headers, not a body, and
            // upstream folds them in after this gate (`res.js:1250-1290`). So
            // does `resWriteRaw://`, which dumps the head — only the *body*
            // dump is gated on there being one (`res.js:1126-1135`).
            return ResBodyOps {
                write_raw: apply::res_write_raw_path(resolved, status),
                force_write: apply::forces_write(resolved),
                trailers: apply::build_trailers(resolved),
                no_trailers: apply::trailers_disabled(resolved),
                announce_trailers: apply::trailer_header_announced(resolved),
                ..ResBodyOps::default()
            };
        }
        ResBodyOps {
            speed: apply::res_speed_kbps(resolved),
            script: apply::res_script_op(resolved)
                .map(|op| op.value.as_str())
                .and_then(script::load_script),
            weinre: resolved.value("weinre").map(|s| s.to_string()),
            write: apply::res_write_path(resolved, status),
            write_raw: apply::res_write_raw_path(resolved, status),
            force_write: apply::forces_write(resolved),
            trailers: apply::build_trailers(resolved),
            no_trailers: apply::trailers_disabled(resolved),
            announce_trailers: apply::trailer_header_announced(resolved),
            content: apply::wants_res_body(resolved),
            // Only where there is a body to encode. A `HEAD` answer, a 204 or a
            // 3xx takes the branch above, where this stays `None`: compressing
            // nothing produces a header that says "nothing".
            force_encoding: apply::forced_encoding(resolved),
        }
    }

    /// True when at least one of these needs the whole body in memory. A
    /// response no operator touches never gets collected — that is what keeps
    /// the streaming path streaming.
    fn needs_body(&self) -> bool {
        self.content
            || self.speed.is_some()
            || self.script.is_some()
            || self.weinre.is_some()
            || self.write.is_some()
            || self.write_raw.is_some()
            || !self.trailers.is_empty()
            // A coding cannot be put on a body that is still arriving in
            // frames, so asking for one is asking for the buffered path.
            || self.force_encoding.is_some()
    }
}

/// Put `Content-Encoding` back after a rewrite, and report the coding the
/// capture should be told the body is now under.
///
/// The header is left **exactly as it arrived** when the bytes were never
/// decoded. `reencode` refuses to force a coding onto such a body — see
/// `Restore { plain: false }` — and reports [`coding::Coding::Identity`],
/// because it encoded nothing; but stamping that would *remove* the header, and
/// a `zstd` response would reach the client as zstd bytes labelled as plain.
/// That is worse than the flag doing nothing: the response arrived readable and
/// would leave unreadable.
///
/// `arrived_as` is the response's own `Content-Encoding`, which is what such a
/// body is still under.
fn restore_content_encoding(
    headers: &mut hyper::HeaderMap,
    restore: coding::Restore,
    encoded_as: coding::Coding,
    arrived_as: Option<String>,
) -> Option<String> {
    if !restore.plain {
        return arrived_as;
    }
    // A body that goes back out under the coding it arrived under keeps the
    // origin's spelling of it. `x-gzip` is the pre-RFC name for the same bytes,
    // and rewriting the header to `gzip` announced a change this proxy did not
    // make — the response is the origin's, down to how it named its encoding.
    if let Some(arrived) = arrived_as.filter(|a| coding::Coding::of(Some(a)) == encoded_as) {
        set_header_raw(headers, "content-encoding", &arrived);
        return Some(arrived);
    }
    coding::set_content_encoding(headers, encoded_as);
    encoded_as.header_value().map(str::to_string)
}

/// The values a request resolves against: what the rules files declared in
/// their ``` blocks, each under a key private to the group that declared it
/// ([`crate::rules::inline_key`]), plus the configured values under their plain
/// names. [`apply::value_for`] is what reads the two apart.
///
/// Rebuilt per request rather than cached because either side can change while
/// the proxy runs — the console edits values, and a rules edit can add or
/// remove an inline block. The cost is one map build over a handful of entries;
/// a rules file with no ``` in it contributes an empty map without allocating.
///
/// Which one answers is [`apply::value_for`]'s to say: the operator's own block,
/// then the store — upstream's order — except for a name `--value` gave, whose
/// blocks are left out of the map here so the store's entry is the only one
/// ([`apply::yield_to_overrides`]).
fn effective_values(state: &AppState) -> std::collections::HashMap<String, String> {
    let mut values = state.rules.read().unwrap().inline_values();
    if values.is_empty() {
        return state.values.read().unwrap().clone();
    }
    values.extend(state.values.read().unwrap().clone());
    apply::yield_to_overrides(&mut values, &state.config.value_overrides);
    values
}

/// Does this response carry a body a rule may rewrite? whistle's `hasBody`
/// (`_original/lib/util/common.js:370-380`).
///
/// A `HEAD` answer, a 1xx, a 204 and every 3xx are excluded — a redirect with a
/// body injected into it is not the redirect the origin sent, and the operators
/// that come with an injection (the cache and CSP strips) have no business
/// touching it either.
pub(crate) fn response_has_body(status: u16, method: &str) -> bool {
    if method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    !(status == 204 || (300..400).contains(&status) || (100..200).contains(&status))
}

/// The operators that rewrite an already-transformed body: `resScript://`, the
/// two HTML injections, and the two dump paths. Runs after
/// [`apply::transform_res_body`] and after any plugin response-body hook.
fn inject_res_body(
    state: &AppState,
    parts: &mut hyper::http::response::Parts,
    mut new: Bytes,
    ops: &ResBodyOps,
    info: &ReqInfo,
) -> Bytes {
    if let Some(src) = &ops.script {
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
            if let Some(st) = r.status
                && let Ok(s) = StatusCode::from_u16(st)
            {
                parts.status = s;
            }
            for (k, v) in r.headers {
                set_header_raw(&mut parts.headers, &k, &v);
            }
            if let Some(b) = r.body {
                new = Bytes::from(b);
            }
        }
    }
    // weinre: inject a debug <script> into HTML responses.
    if let Some(id) = &ops.weinre
        && is_html(&parts.headers)
    {
        let src = weinre_src(id, &state.config);
        let tag = format!("<script src=\"{src}\"></script>");
        new = inject_into_html(&new, &tag);
    }
    if let Some(path) = &ops.write {
        write_body_file(path, &new, ops.force_write);
    }
    if let Some(path) = &ops.write_raw {
        let head = format!(
            "HTTP/1.1 {}\r\n{}",
            parts.status,
            header_dump(&parts.headers)
        );
        write_raw_file(path, &head, &new, ops.force_write);
    }
    new
}

/// Frame a finished in-memory body: drop the now-stale length headers, apply
/// `resSpeed://`, and put the trailer section back on.
///
/// `origin` is the trailer section the upstream response sent, which buffering
/// the body would otherwise have thrown away. whistle keeps it and lays the
/// rule's trailers over the top — `extend(trailers, newTrailers)`
/// (`_original/lib/inspectors/res.js:1264-1273`) — so a `trailers://x-a=1`
/// against an origin that already sends `x-checksum` yields both.
fn finish_res_body(
    parts: &mut hyper::http::response::Parts,
    new: Bytes,
    ops: ResBodyOps,
    origin: Option<hyper::HeaderMap>,
) -> DynBody {
    apply::strip_length_headers(&mut parts.headers);
    // `resSpeed://` applies whether or not there are trailers. Deciding between
    // the two — which is what this did — meant a `trailers://` line silently
    // cancelled the throttle written beside it.
    let body = match ops.speed {
        Some(kbps) => body::throttled(new, kbps),
        None => body::full(new),
    };

    let mut trailers = origin.filter(|_| !ops.no_trailers).unwrap_or_default();
    trailers.extend(ops.trailers);
    // Last, over the merged map, exactly where upstream applies it
    // (`removeIllegalTrailers`, `res.js:1285`): a name banned from a trailer
    // section is banned wherever it came from.
    apply::remove_illegal_trailers(&mut trailers);
    if trailers.is_empty() {
        // Nothing to send — but the origin's may still be on their way, so the
        // `disable://` case has to say so rather than simply not adding any.
        return match ops.no_trailers {
            true => retrailer(body, None),
            false => body,
        };
    }
    // Trailers need chunked transfer; ensure HTTP/1.1 (upstream may be 1.0).
    parts.version = hyper::Version::HTTP_11;
    if ops.announce_trailers {
        let names = trailers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        set_header_raw(&mut parts.headers, "trailer", &names);
    }
    retrailer(body, Some(trailers))
}

/// Replace whatever trailer section `body` would emit with `trailers`, or with
/// none at all.
///
/// Needed on both sides of the buffering decision: a body that was collected has
/// already had its trailers lifted off and merged, and one that is streaming
/// through still carries the origin's — which `disable://trailers` has to be
/// able to drop.
fn retrailer(body: DynBody, trailers: Option<hyper::HeaderMap>) -> DynBody {
    use http_body_util::BodyExt;
    Retrailed {
        inner: Box::pin(body),
        trailers,
    }
    .boxed()
}

/// Body wrapper backing [`retrailer`]: swallows the inner body's trailer frame
/// and emits its own, once, at the end.
struct Retrailed {
    inner: std::pin::Pin<Box<DynBody>>,
    trailers: Option<hyper::HeaderMap>,
}

impl hyper::body::Body for Retrailed {
    type Data = Bytes;
    type Error = body::BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match this.inner.as_mut().poll_frame(cx) {
                // The inner section has already been accounted for — either
                // merged into ours or deliberately dropped.
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(None) => {
                    return Poll::Ready(
                        this.trailers
                            .take()
                            .map(|t| Ok(hyper::body::Frame::trailers(t))),
                    );
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream() && self.trailers.is_none()
    }
}

/// The plugin audience a locally produced response still owes its hooks to.
///
/// [`Default`] is nobody — two empty slices — which is what a path with no
/// plugin in sight passes, so the hook loops below cost one `is_empty` each.
#[derive(Default)]
struct ResHooks<'a> {
    /// Plugins matched for this request, in rule order: the `POST /response`
    /// audience. Held as `(name, param)` because that is what the request hook
    /// already built.
    plugins: &'a [(String, String)],
    /// `pipe://` plugins matched for this request, in rule order.
    pipes: &'a [crate::plugins::PluginMatch],
    /// Correlation id, shared with the request hook of the same request.
    req_id: u64,
    /// The client address, as the request hook reported it.
    client_ip: Option<String>,
    /// Where a hook that failed is noted — the ledger's list, so it reaches
    /// the session. See [`plugin_hook_failed`].
    notes: Option<&'a mut Vec<unapplied::Unapplied>>,
}

/// A plugin hook that failed, as the session records it: the `plugin://` or
/// `pipe://` operators naming that plugin did not take effect in that hook.
fn plugin_hook_failed(
    resolved: &Resolved,
    name: &str,
    hook: &str,
    why: &str,
) -> Option<unapplied::Unapplied> {
    unapplied::Unapplied::over(
        &matched_ops(resolved),
        |op| {
            matches!(op.protocol.as_str(), "plugin" | "pipe")
                && crate::plugins::match_name(&op.value, op.protocol == "pipe").as_deref()
                    == Some(name)
        },
        unapplied::Kind::PluginFailed,
        format!(
            "plugin {name}'s {hook} hook failed ({why}); the request went on as if it had said nothing"
        ),
    )
}

/// Serve an [`auth`](crate::plugins::auth) gate's refusal exactly as the gate
/// produced it: no response-phase rules, no response operators, no plugin hooks.
///
/// Upstream pins it the same way, and this is what its pinning *means*: the
/// denial comes back as `* ignore://!statusCode|!resBody|!resType|!resCharset …`
/// (`_original/lib/plugins/index.js:936-959`), and `ignore://!x` is an inverted
/// whitelist — `ignoreRules` walks every resolved rule and deletes all but the
/// excluded names, plugin rules included (`lib/util/index.js:2068-2092,:2008`).
/// So on a refusal no user rule applies, which is the property worth keeping: a
/// gate a `resHeaders://` line or another plugin can rewrite is not a gate.
///
/// Returns the response and the body preview to record with it, like
/// [`finish_local_response`] — the transaction is still logged.
fn pin_refusal(state: &AppState, res: Response<Bytes>) -> (Response<DynBody>, Option<Capture>) {
    let (parts, bytes) = res.into_parts();
    let ct = header_str(&parts.headers, hyper::header::CONTENT_TYPE);
    let enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let capture = (!bytes.is_empty())
        .then(|| Capture::from_bytes(&bytes, ct, enc.as_deref(), state.config.body_preview_cap));
    (Response::from_parts(parts, body::full(bytes)), capture)
}

/// Finish a response this proxy produced itself — a `plugin://` hook's answer,
/// or a short-circuit rule's — by resolving the response phase and running every
/// response operator over it.
///
/// whistle reaches its response inspectors on both paths: a `plugin://` rule
/// proxies the request to the plugin's own server, so the plugin's answer comes
/// back as an ordinary response and goes through `handleResponse`
/// (`pluginMgr.getResRules`, `_original/lib/inspectors/res.js:825`), and a
/// locally served `file://` takes the same route. `res` is built from the head
/// as produced, before any operator has touched it — which is what lets `s:`
/// filter on a `statusCode://404` this port answered.
///
/// `hooks` is the plugin audience for the finished response. Upstream reaches its
/// response-side plugin machinery on both these paths as well: a `plugin://`
/// answer travels back as an ordinary response and goes through `handleResponse`
/// (`_original/lib/inspectors/res.js:825`), and a `pipe://` plugin is resolved
/// from its own rule with no regard for who produced the bytes
/// (`resolvePipePlugin`, `_original/lib/plugins/index.js:1173`).
///
/// `res` is the response as produced, body and all — it is wholly in memory on
/// both these paths, which is what lets the body operators and the buffered hooks
/// run over it without waiting on anything.
///
/// Returns the finished response and the body preview to record with it.
async fn finish_local_response(
    state: &Arc<AppState>,
    info: &mut ReqInfo,
    resolved: &mut Resolved,
    merged_rules: &[crate::rules::RuleManager],
    is_internal_req: bool,
    res: Response<Bytes>,
    mut hooks: ResHooks<'_>,
) -> (Response<DynBody>, Option<Capture>) {
    let (mut parts, bytes) = res.into_parts();
    resolve_response_phase(
        state,
        info,
        resolved,
        // No connection was made, so `serverIp:`/`serverPort:` stay unanswerable
        // and fail closed rather than matching on a guess.
        apply::build_res_info(parts.status.as_u16(), &parts.headers, None, None),
        is_internal_req,
        merged_rules,
    )
    .await;
    if let Some(ms) = apply::res_delay_ms(resolved) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    apply::apply_response_for(&mut parts, resolved, Some(info));

    // Response hook, part 1: plugins that did not ask for the body. Such a
    // plugin may still replace it outright — that needs no knowledge of the
    // original. The plugin that produced this response is in the audience too:
    // upstream builds the response pipeline from *every* matched plugin, so one
    // that both answers and hooks the response does see its own answer.
    let mut bytes = bytes;
    let mut hook_replaced = false;
    let mut wants_body = false;
    for (name, param) in hooks.plugins {
        let Some(manifest) = state.plugins.manifest(name).await else {
            continue;
        };
        if !manifest.on_response {
            continue;
        }
        if manifest.response_body {
            wants_body = true;
            continue; // handled below, once the body is in hand
        }
        let pres = crate::plugins::PluginRes {
            id: hooks.req_id,
            method: info.method.clone(),
            url: info.full_url.clone(),
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
            param: param.clone(),
            body: None,
        };
        if let Some(result) = state.plugins.on_response(name, &pres).await {
            if let Some(why) = &result.hook_failed
                && let Some(notes) = hooks.notes.as_deref_mut()
            {
                notes.extend(plugin_hook_failed(resolved, name, "response", why));
            }
            if let Some(new) = apply_plugin_res_result(&mut parts, result) {
                bytes = Bytes::from(new);
                hook_replaced = true;
            }
        }
    }

    // Streaming hook: a `pipe://` plugin transforms the bytes on their way out.
    // The body is wholly in memory on this path — a plugin's answer, or a mocked
    // response — so it is framed, piped and collected straight back. That is the
    // same work the streaming path does, in a different order, and it keeps one
    // implementation of the hook rather than two.
    if !hooks.pipes.is_empty() {
        let piped = pipe_body(
            state,
            hooks.pipes,
            crate::plugins::pipe::Dir::Response,
            crate::plugins::pipe::PipeMeta {
                id: hooks.req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                client_ip: hooks.client_ip.clone(),
                headers: header_pairs(&parts.headers),
                status: Some(parts.status.as_u16()),
                ..Default::default()
            },
            &mut parts.headers,
            body::full(bytes.clone()),
        )
        .await;
        // A plugin that serves no response pipe hands the body back untouched,
        // so this collects the same bytes. One that takes it may change the
        // length — `pipe_body` has already dropped the headers for that.
        match collect_body(piped).await {
            Ok(new) => bytes = new,
            // The transform broke mid-stream. There is nothing left to send but
            // what the pipe managed to produce, which is nothing.
            Err(err) => {
                tracing::debug!("response pipe failed: {err:#}");
                bytes = Bytes::new();
                hook_replaced = true;
            }
        }
    }

    let ops = ResBodyOps::of(
        resolved,
        response_has_body(parts.status.as_u16(), &info.method),
        parts.status.as_u16(),
        // `None`: the body is already collected on this path, so even an event
        // stream is a finite `Bytes` here and every operator can be applied.
        None,
    );
    let res_ct = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let res_enc = header_str(&parts.headers, hyper::header::CONTENT_ENCODING);
    let (new, res_enc) = if ops.needs_body() || wants_body {
        // Decode before rewriting, re-encode after — the same treatment the
        // upstream path gives a compressed body. A plugin answer or a mocked
        // response rarely arrives encoded, but `enable://gzip` can still ask for
        // one on the way out, and a plugin is free to send `Content-Encoding`.
        //
        // Unbounded, and applied whatever came of it: this body was made here,
        // in memory already, by a rule or a plugin — not received from a server
        // that may send anything.
        let decoded = coding::decode_for_rewrite(bytes, res_enc.as_deref(), usize::MAX);
        let restore = decoded.restore;
        let mut new = apply::transform_res_body(decoded.body, resolved, res_ct.as_deref());

        // Response hook, part 2: plugins that asked for the body. It sits
        // between the content operators and the injections — the same slot the
        // streaming path gives it.
        for (name, param) in hooks.plugins {
            let Some(manifest) = state.plugins.manifest(name).await else {
                continue;
            };
            if !manifest.on_response || !manifest.response_body {
                continue;
            }
            let pres = crate::plugins::PluginRes {
                id: hooks.req_id,
                method: info.method.clone(),
                url: info.full_url.clone(),
                status: parts.status.as_u16(),
                headers: header_pairs(&parts.headers),
                param: param.clone(),
                body: Some(new.to_vec()),
            };
            if let Some(result) = state.plugins.on_response(name, &pres).await {
                if let Some(why) = &result.hook_failed
                    && let Some(notes) = hooks.notes.as_deref_mut()
                {
                    notes.extend(plugin_hook_failed(resolved, name, "response", why));
                }
                if let Some(replaced) = apply_plugin_res_result(&mut parts, result) {
                    new = Bytes::from(replaced);
                    hook_replaced = true;
                }
            }
        }
        let new = inject_res_body(state, &mut parts, new, &ops, info);
        let (new, encoded_as) = coding::reencode(new, restore, ops.force_encoding);
        let now = restore_content_encoding(&mut parts.headers, restore, encoded_as, res_enc);
        (new, now)
    } else {
        (bytes, res_enc)
    };
    let capture = (!new.is_empty()).then(|| {
        Capture::from_bytes(
            &new,
            res_ct,
            res_enc.as_deref(),
            state.config.body_preview_cap,
        )
    });
    // `finish_res_body` drops the length headers, which a body nothing rewrote
    // still has correctly set — so only take that route when something did.
    let body = match ops.needs_body() {
        // A locally produced response has no origin trailer section to keep.
        true => finish_res_body(&mut parts, new, ops, None),
        false => {
            // A hook that replaced the body invalidated the length its producer
            // declared; dropping the header lets hyper write the true one.
            if hook_replaced {
                apply::strip_length_headers(&mut parts.headers);
            }
            body::full(new)
        }
    };
    (Response::from_parts(parts, body), capture)
}

/// What an aborted request leaves behind: nothing.
///
/// whistle answers an abort with `res.destroy()`
/// (`_original/lib/inspectors/data.js:536`, `res.js:1178`), which tears the
/// socket down mid-transaction — the client sees a reset, not a status. hyper
/// does the same when the service resolves to an error, so the abort travels
/// out of [`serve`] as one and [`guard`] passes it through instead of dressing
/// it up as a 502. A 502 with a body is a *served* response: it satisfies a
/// fetch, gets cached as a failure page, and cannot be told apart from a real
/// gateway error — which is not what `enable://abort` is for.
#[derive(Debug)]
struct Destroyed;

impl std::fmt::Display for Destroyed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection destroyed by enable://abort")
    }
}

impl std::error::Error for Destroyed {}

/// The header on a response this proxy made up because the request failed,
/// naming the [`outcome::Phase`] it failed in. Its presence is what tells a
/// `502` from here apart from a `502` the origin sent.
pub const ERROR_HEADER: &str = "x-whistle-rs-error";

/// The header carrying the id of the session a failed request was recorded
/// as, so the client that got the error can find it in the console.
pub const SESSION_HEADER: &str = "x-whistle-rs-session";

/// A request on its way to becoming a session.
///
/// Every request [`serve`] takes on becomes **exactly one** session, however it
/// ends. The paths that answer record their own, through [`Ledger::record`]; a
/// failure that escapes [`serve`] as an error is recorded by [`guard`] from the
/// draft; and a request whose future is dropped — which is what hyper does when
/// the client closes the connection or resets the stream while waiting — is
/// recorded when the ledger is dropped with it. Before this, only the first of
/// the three existed, so every request that failed before its response head
/// arrived was in the log and nowhere else.
pub(crate) struct Ledger {
    state: Arc<AppState>,
    /// What is known about the request so far. `None` until [`serve`] knows
    /// this is a request the console records — the console's own traffic is not.
    draft: Option<Session>,
    /// When the request arrived. Every session's `time_ms` and `duration_ms`
    /// count from here.
    started: Instant,
    time_ms: u128,
    /// A session has been recorded; this request owes nothing more.
    settled: bool,
    /// Matched operators that did not take effect, noted as `serve` found
    /// out, for whichever session this request becomes — see [`unapplied`].
    unapplied: Vec<unapplied::Unapplied>,
}

impl Ledger {
    pub(crate) fn new(state: &Arc<AppState>) -> Self {
        Ledger {
            state: state.clone(),
            draft: None,
            started: Instant::now(),
            time_ms: now_ms(),
            settled: false,
            unapplied: Vec::new(),
        }
    }

    /// Note that matched operators did not take effect. `None` notes nothing:
    /// [`unapplied::Unapplied::over`] returns it when no rule was waiting.
    fn unapplied(&mut self, note: Option<unapplied::Unapplied>) {
        self.unapplied.extend(note);
    }

    /// Put what was noted on the session this request is recorded as.
    fn stamp(&mut self, session: &mut Session) {
        session.unapplied.append(&mut self.unapplied);
    }

    /// The request is one the console records: this much is known about it.
    fn open(&mut self, draft: Session) {
        self.draft = Some(Session {
            time_ms: self.time_ms,
            ..draft
        });
    }

    /// Add to what the draft knows. A no-op before [`Ledger::open`].
    fn note(&mut self, f: impl FnOnce(&mut Session)) {
        if let Some(draft) = &mut self.draft {
            f(draft);
        }
    }

    /// Record `session` as this request's one session.
    fn record(&mut self, mut session: Session) -> u64 {
        self.settled = true;
        self.stamp(&mut session);
        self.state.record(session)
    }

    /// Record `session` as this request's one session, its response `body`
    /// still to come: it is completed when the body is over, and fails then
    /// if the body breaks off or the client leaves before the end. `expected`
    /// is the `content-length` the response promises, if any — see
    /// [`outcome::settle`].
    fn record_streaming(
        &mut self,
        mut session: Session,
        body: DynBody,
        expected: Option<u64>,
    ) -> (u64, DynBody) {
        self.settled = true;
        self.stamp(&mut session);
        let (id, open) = self.state.record_open(session);
        let Some(session) = open else {
            return (id, body);
        };
        let state = self.state.clone();
        let body = outcome::settle(body, expected, move |failure| {
            if let Some(failure) = failure {
                log_failure(Some(session.id), &session.method, &session.url, &failure);
                session.error.fail(failure);
            }
            state.complete(&session);
        });
        (id, body)
    }

    /// Record `session` as this request's one session, and say whether there is
    /// one to look up — see [`AppState::record_visible`].
    fn record_visible(&mut self, mut session: Session) -> Option<u64> {
        self.settled = true;
        self.stamp(&mut session);
        self.state.record_visible(session)
    }

    /// Record the draft as a request that failed with `failure`, the client
    /// having been answered with `status` (0: nothing at all), and return the
    /// session id to name. `None` when there is none: no draft, a session
    /// already recorded, or a request a rule hides.
    fn fail(&mut self, failure: outcome::Failure, status: u16) -> Option<u64> {
        if self.settled {
            return None;
        }
        let draft = self.draft.take()?;
        let (method, url) = (draft.method.clone(), draft.url.clone());
        let id = self.record_visible(Session {
            status,
            duration_ms: self.started.elapsed().as_millis(),
            error: outcome::Outcome::failed(failure.clone()),
            ..draft
        });
        log_failure(id, &method, &url, &failure);
        id
    }
}

/// The log line for a request that did not complete. It leads with the session
/// id — the one the console lists and a failed request's 502 carries in
/// [`SESSION_HEADER`] — so the three can be matched up. A hidden request has no
/// session to match, and says so rather than quoting an id that names nothing.
fn log_failure(id: Option<u64>, method: &str, url: &str, failure: &outcome::Failure) {
    let id = id.map_or_else(|| "(hidden)".to_string(), |id| format!("#{id}"));
    tracing::info!(
        "{id} {method} {url} -> failed at {}: {}",
        failure.phase,
        failure.message
    );
}

impl Drop for Ledger {
    /// The request's future was dropped before it settled. Nothing else drops
    /// it: [`serve`] and [`guard`] settle every way out of it they can see, so
    /// what is left is hyper giving up on a client that has gone.
    fn drop(&mut self) {
        self.fail(
            outcome::Failure::new(
                outcome::Phase::Client,
                "the client closed the connection before the response arrived",
            ),
            0,
        );
    }
}

/// A `cipher://` pin that could not be used, on the session: the connection
/// went ahead without it — see [`super::ciphers`] for why — and a pin that
/// silently did not happen is the last thing to find out from a log.
fn note_cipher_dropped(ledger: &mut Ledger, target: &upstream::Target, resolved: &Resolved) {
    if let Some(why) = &target.cipher_dropped {
        ledger.unapplied(unapplied::Unapplied::over(
            &matched_ops(resolved),
            |op| op.protocol == "cipher",
            unapplied::Kind::CipherUnusable,
            why.clone(),
        ));
    }
}

/// Where a forwarded request went, as its session's `target` says it.
fn target_desc(target: &upstream::Target) -> String {
    let mut desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        desc.push_str(" (via proxy)");
    }
    desc
}

/// The outcome of a request a rule dropped on purpose.
fn aborted(how: &str) -> outcome::Outcome {
    outcome::Outcome::failed(outcome::Failure::new(outcome::Phase::Abort, how))
}

/// [`serve`] a request and settle its session, whatever happens to it.
async fn serve_recorded(
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
fn guard(
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
async fn serve(
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
        if !state.plugins.contains(&m.name) {
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
                merged_rules.push(apply::merge_rules_text(
                    &mut resolved,
                    &info,
                    &rules,
                    is_internal_req,
                ));
                {
                    let values = state.values.read().unwrap();
                    let tpl = tpl_ctx(&bind_host, state.config.port, &info);
                    apply::substitute_values(&mut resolved, &values, tpl);
                }
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
                tracing::info!("{} {} -> plugin {name}", info.method, info.full_url);
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
        tracing::info!("{} {} -> aborted", info.method, info.full_url);
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
        tracing::info!("{} {} -> short-circuit", info.method, info.full_url);
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
            info.full_url
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

    tracing::info!(
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
        tracing::info!("{} {} -> response aborted", info.method, info.full_url);
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
            info.full_url
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
fn carries_body(status: u16, method: &str) -> bool {
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
async fn pipe_body(
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
fn apply_plugin_res_result(
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
fn accept_upgrade_locally<B>(req: &mut Request<B>, resp: &mut Response<DynBody>) {
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
fn is_upgrade(req: &Request<DynBody>) -> bool {
    asks_to_upgrade(req.headers())
}

/// The same question of a header map alone, because it has to be answered
/// before the request has been read — the scheme the rules match against
/// depends on it (`ws://` rather than `http://`).
fn asks_to_upgrade(headers: &hyper::HeaderMap) -> bool {
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
fn is_websocket(req: &Request<DynBody>, resolved: &Resolved) -> bool {
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
async fn serve_upgrade(
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
mod upgrade_abort_tests {
    use super::tunnel_abort_tests::proxy_with;
    use super::*;
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

/// Append a captured body to a file (`reqWrite`/`resWrite`). Best-effort.
fn write_body_file(path: &str, data: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    if let Err(e) = f.write_all(data) {
        tracing::debug!("write body to {path} failed: {e}");
    }
}

/// Open a dump file for one of the four write operators, or refuse.
///
/// whistle writes a dump file **once**: `getFileWriter` stats the path first and
/// hands back no writer at all when it already exists, so only `ENOENT` produces
/// one (`checkWriterFile`/`getFileWriter`,
/// `_original/lib/util/index.js:502-546`). `enable://forceReqWrite` is the
/// override, and it overwrites rather than appends — the stream is opened with
/// Node's default `w`.
///
/// Appending, which is what this did, is a different tool: point a rule at a
/// path once and every reload of the page grows the file, so what you open is a
/// concatenation of runs with no boundary between them, and the "capture" of the
/// request you meant is somewhere in the middle of it.
///
/// A path ending in a separator names a directory, and the dump goes in it as
/// `index.html` (`END_RE`, `util/index.js:54,:521-523`).
///
/// Upstream's `pendingFiles` guard — which also refuses a file another request
/// is mid-write on — is not reproduced: it exists because its writers are
/// asynchronous streams, and these are one synchronous `write_all`.
fn open_writer(path: &str, force: bool) -> Option<std::fs::File> {
    let path = match path.ends_with('/') || path.ends_with('\\') {
        true => std::path::Path::new(path).join("index.html"),
        false => std::path::PathBuf::from(path),
    };
    if !force && path.exists() {
        tracing::debug!("{} already exists; not written", path.display());
        return None;
    }
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        tracing::debug!("create {} failed: {e}", dir.display());
        return None;
    }
    match std::fs::File::create(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::debug!("open {} for write failed: {e}", path.display());
            None
        }
    }
}

/// Serialise headers as `name: value\r\n` lines.
fn header_dump(headers: &hyper::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(value.to_str().unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// Write a raw message — head, blank line, body — to a file.
///
/// Nothing follows the body. Upstream writes `getRawData(…)`, which is the
/// first line, the headers and one blank line, and then pipes the body straight
/// into the same stream (`FileWriterTransform`,
/// `_original/lib/util/file-writer-transform.js:6-13,:53-58`). This port used to
/// add a trailing `\r\n\r\n` on the end, on the theory that a dump might hold
/// several messages — it never does, because `getFileWriter` refuses a path that
/// already exists. What it produced instead was a dump of a bodiless request
/// ending in four CRLFs where whistle's ends in two, which is not a raw record
/// of anything that went over the wire.
fn write_raw_file(path: &str, head: &str, body: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    let _ = f.write_all(head.as_bytes());
    let _ = f.write_all(b"\r\n");
    let _ = f.write_all(body);
}

/// True if the response declares an HTML content type.
fn is_html(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// Build the weinre target-script URL. If `id` is already a URL/path use it as-is;
/// otherwise build the conventional weinre target URL served on the proxy host.
fn weinre_src(id: &str, config: &Config) -> String {
    let id = id.trim();
    if id.contains("://") || id.starts_with('/') {
        return id.to_string();
    }
    let host = config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let anchor = if id.is_empty() {
        String::new()
    } else {
        format!("#{id}")
    };
    format!(
        "//{host}:{port}/weinre/target/target-script-min.js{anchor}",
        port = config.port
    )
}

/// Inject `tag` into HTML: before `</head>`, else after `<body>`, else prepend.
fn inject_into_html(body: &Bytes, tag: &str) -> Bytes {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    if let Some(i) = lower.find("</head>") {
        let mut out = String::with_capacity(text.len() + tag.len());
        out.push_str(&text[..i]);
        out.push_str(tag);
        out.push_str(&text[i..]);
        return Bytes::from(out);
    }
    if let Some(i) = lower.find("<body")
        && let Some(close) = text[i..].find('>')
    {
        let pos = i + close + 1;
        let mut out = String::with_capacity(text.len() + tag.len());
        out.push_str(&text[..pos]);
        out.push_str(tag);
        out.push_str(&text[pos..]);
        return Bytes::from(out);
    }
    let mut out = String::with_capacity(text.len() + tag.len());
    out.push_str(tag);
    out.push_str(&text);
    Bytes::from(out)
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
fn ensure_host_header(headers: &mut hyper::HeaderMap, host: &str, port: u16, scheme: &str) {
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
fn authority_host_port(uri: &Uri) -> Option<(String, u16)> {
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(443);
    Some((host, port))
}

#[cfg(test)]
mod body_gate_tests {
    /// A response with no body is not a response to inject into. whistle's
    /// `hasBody` (`_original/lib/util/common.js:370-380`) excludes a `HEAD`
    /// answer, 1xx, 204 and every 3xx — and a redirect that arrives with an
    /// injected body, a stripped `Content-Length`, `Cache-Control: no-store` and
    /// no CSP is not the redirect the origin sent.
    #[test]
    fn only_a_response_that_carries_a_body_may_be_rewritten() {
        use super::response_has_body;

        for status in [200, 201, 205, 400, 404, 500] {
            assert!(response_has_body(status, "GET"), "{status}");
        }
        for status in [100, 101, 199, 204, 300, 301, 302, 304, 307, 399] {
            assert!(!response_has_body(status, "GET"), "{status}");
        }
        // A HEAD answer never has one, whatever the status says.
        assert!(!response_has_body(200, "HEAD"));
        assert!(!response_has_body(200, "head"));
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "whistle-rs-writer-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join(name)
    }

    /// A dump file is written **once**: whistle stats the path first and hands
    /// back no writer when it already exists (`checkWriterFile`/`getFileWriter`,
    /// `_original/lib/util/index.js:502-546`).
    ///
    /// This appended instead, so a rule left in place over a reload produced a
    /// file that is a concatenation of runs with no boundary between them — and
    /// the request you meant to capture somewhere in the middle of it.
    #[test]
    fn a_dump_file_is_written_once() {
        let path = scratch("body.txt");
        let p = path.to_str().expect("utf-8 path");

        write_body_file(p, &Bytes::from_static(b"first"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // The second request through the same rule leaves it alone.
        write_body_file(p, &Bytes::from_static(b"second"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // `enable://forceReqWrite` overwrites — it does not append, because
        // upstream reopens the stream with Node's default `w`.
        write_body_file(p, &Bytes::from_static(b"second"), true);
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    /// The raw dump takes the same gate, and missing parent directories are
    /// created (`fse.ensureFile`, `util/index.js:536`).
    #[test]
    fn the_raw_dump_takes_the_same_gate_and_makes_its_directory() {
        let path = scratch("nested/deeper/raw.txt");
        let p = path.to_str().expect("utf-8 path");

        write_raw_file(p, "GET / HTTP/1.1", &Bytes::from_static(b"body"), false);
        let written = std::fs::read(&path).expect("read");
        // Head, blank line, body — and nothing after it. The trailing `\r\n\r\n`
        // this used to add made a bodiless dump end in four CRLFs where
        // whistle's ends in two; measured on `tests/differential/write-bench.js`.
        assert_eq!(written, b"GET / HTTP/1.1\r\nbody");

        write_raw_file(p, "GET /other HTTP/1.1", &Bytes::from_static(b"x"), false);
        assert_eq!(std::fs::read(&path).expect("read"), written);
    }

    /// A path ending in a separator names a directory, and the dump goes in it
    /// as `index.html` (`END_RE`, `_original/lib/util/index.js:54,:521-523`).
    #[test]
    fn a_trailing_separator_names_a_directory() {
        let dir = scratch("dumpdir");
        let p = format!("{}/", dir.to_str().expect("utf-8 path"));
        write_body_file(&p, &Bytes::from_static(b"page"), false);
        assert_eq!(
            std::fs::read(dir.join("index.html")).expect("read"),
            b"page"
        );
    }

    /// A non-200 response is dumped beside the good capture, not over it
    /// (`getWriterFile`, `_original/lib/inspectors/res.js:147-153`).
    #[test]
    fn a_failing_response_is_dumped_under_its_status() {
        let mut m = RuleManager::new();
        m.set_text("example.com resWrite:///tmp/dump  resWriteRaw:///tmp/raw\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        assert_eq!(
            apply::res_write_path(&resolved, 200),
            Some("/tmp/dump".to_string())
        );
        assert_eq!(
            apply::res_write_path(&resolved, 502),
            Some("/tmp/dump.502".to_string())
        );
        // The raw dump is named the same way.
        assert_eq!(
            apply::res_write_raw_path(&resolved, 404),
            Some("/tmp/raw.404".to_string())
        );
    }

    /// `reqWrite://` is gated on the request actually having a body
    /// (`util.hasRequestBody(req) ? … : null`,
    /// `_original/lib/inspectors/req.js:582-584`).
    ///
    /// Without the gate a `GET` created an empty file, which reads as "the
    /// capture worked and there was no body" rather than "there was never a
    /// body to capture". `reqWriteRaw://` is *not* gated: the head is worth
    /// dumping either way.
    #[test]
    fn req_write_needs_a_method_that_carries_a_body() {
        let mut m = RuleManager::new();
        m.set_text("example.com reqWrite:///tmp/req  reqWriteRaw:///tmp/rawreq\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        for method in ["GET", "HEAD", "OPTIONS", "CONNECT"] {
            assert_eq!(apply::req_write_path(&resolved, method), None, "{method}");
        }
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                apply::req_write_path(&resolved, method),
                Some("/tmp/req".to_string()),
                "{method}"
            );
        }
        assert_eq!(
            apply::req_write_raw_path(&resolved),
            Some("/tmp/rawreq".to_string())
        );
    }
}

#[cfg(test)]
mod trailer_tests {
    use super::*;
    use hyper::body::Body as _;

    /// Drive a body to its end, returning its data frames and trailer section.
    fn drain(body: DynBody) -> (Vec<Bytes>, Option<hyper::HeaderMap>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut body = std::pin::pin!(body);
            let (mut frames, mut trailers) = (Vec::new(), None);
            while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                let frame = frame.expect("frame");
                match frame.into_data() {
                    Ok(data) => frames.push(data),
                    Err(frame) => trailers = frame.into_trailers().ok(),
                }
            }
            (frames, trailers)
        })
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).expect("name"),
                v.parse().expect("value"),
            );
        }
        h
    }

    /// Everything `finish_res_body` decides about the trailer section, driven
    /// through the same struct `serve` builds.
    fn finish(
        rule_trailers: &[(&str, &str)],
        origin: Option<&[(&str, &str)]>,
        no_trailers: bool,
        speed: Option<f64>,
        body_len: usize,
    ) -> (
        hyper::http::response::Parts,
        Vec<Bytes>,
        Option<hyper::HeaderMap>,
    ) {
        let mut parts = Response::builder()
            .status(200)
            .body(())
            .expect("parts")
            .into_parts()
            .0;
        let ops = ResBodyOps {
            speed,
            trailers: headers(rule_trailers),
            no_trailers,
            announce_trailers: true,
            content: true,
            ..ResBodyOps::default()
        };
        let bytes = Bytes::from(vec![b'x'; body_len]);
        let out = finish_res_body(&mut parts, bytes, ops, origin.map(headers));
        let (frames, trailers) = drain(out);
        (parts, frames, trailers)
    }

    fn names(h: &Option<hyper::HeaderMap>) -> Vec<String> {
        let mut v: Vec<String> = h
            .iter()
            .flat_map(|h| h.iter())
            .map(|(k, val)| format!("{k}={}", val.to_str().unwrap()))
            .collect();
        v.sort();
        v
    }

    /// The origin's own trailer section survives a body rewrite, and the rule's
    /// trailers are laid over it (`extend(trailers, newTrailers)`,
    /// `_original/lib/inspectors/res.js:1264-1273`).
    ///
    /// Buffering the body threw the origin's trailers away, so *any* body
    /// operator — one with nothing to do with trailers — silently deleted them
    /// on the way past.
    #[test]
    fn the_origins_trailers_survive_a_rewrite() {
        let (parts, _, trailers) = finish(
            &[("x-rule", "1")],
            Some(&[("x-origin", "2"), ("x-both", "origin")]),
            false,
            None,
            8,
        );
        assert_eq!(
            names(&trailers),
            ["x-both=origin", "x-origin=2", "x-rule=1"]
        );
        // The `Trailer:` header announces everything that is coming.
        let announced = parts.headers.get("trailer").unwrap().to_str().unwrap();
        for name in ["x-origin", "x-both", "x-rule"] {
            assert!(announced.contains(name), "{announced} must name {name}");
        }

        // A contested name takes the rule's value.
        let (_, _, trailers) = finish(
            &[("x-both", "rule")],
            Some(&[("x-both", "origin")]),
            false,
            None,
            8,
        );
        assert_eq!(names(&trailers), ["x-both=rule"]);

        // With no rule at all the origin's still go out.
        let (_, _, trailers) = finish(&[], Some(&[("x-origin", "2")]), false, None, 8);
        assert_eq!(names(&trailers), ["x-origin=2"]);
    }

    /// `disable://trailers` cancels the whole section, the origin's included —
    /// upstream's guard is on the way out, after the merge (`res.js:1252-1260`).
    #[test]
    fn disabling_trailers_drops_the_origins_too() {
        let (parts, frames, trailers) = finish(&[], Some(&[("x-origin", "2")]), true, None, 8);
        assert!(trailers.is_none(), "no trailer section may be sent");
        assert!(parts.headers.get("trailer").is_none());
        assert_eq!(frames.len(), 1, "the body itself is untouched");
    }

    /// A name an HTTP trailer section may not carry is dropped wherever it came
    /// from (`removeIllegalTrailers`, `_original/lib/util/common.js:410-414`,
    /// applied at `res.js:1285` over the merged map).
    ///
    /// A `Content-Length` arriving *after* the body contradicts the framing that
    /// just delivered it, and a `Set-Cookie` there is a credential a client is
    /// not required to read.
    #[test]
    fn illegal_trailer_names_are_dropped_from_both_sides() {
        let (parts, _, trailers) = finish(
            &[("content-length", "5"), ("x-ok", "1")],
            Some(&[("set-cookie", "sid=1"), ("x-fine", "2")]),
            false,
            None,
            8,
        );
        assert_eq!(names(&trailers), ["x-fine=2", "x-ok=1"]);
        let announced = parts.headers.get("trailer").unwrap().to_str().unwrap();
        assert!(!announced.contains("content-length"));
        assert!(!announced.contains("set-cookie"));

        // Nothing legal left means no trailer section and no announcement.
        let (parts, _, trailers) = finish(&[("trailer", "x")], None, false, None, 8);
        assert!(trailers.is_none());
        assert!(parts.headers.get("trailer").is_none());
    }

    /// `resSpeed://` and `trailers://` are not alternatives.
    ///
    /// The port chose between them, so writing both meant the throttle was
    /// silently dropped — a rule that reproduces a slow connection, cancelled by
    /// an unrelated one on the same line.
    #[test]
    fn a_throttle_survives_the_trailers() {
        // 8 kbit/s is 1000 bytes/s, paced in 50 ms slices of 50 bytes: 100 bytes
        // is two frames rather than the single frame an unpaced body sends.
        let (_, frames, trailers) = finish(&[("x-a", "1")], None, false, Some(8.0), 100);
        assert_eq!(frames.len(), 2, "the body was paced");
        assert_eq!(frames.concat().len(), 100);
        assert_eq!(names(&trailers), ["x-a=1"]);

        // Unpaced, the same body is one frame — so the assertion above is about
        // the throttle and not about chunking in general.
        let (_, frames, _) = finish(&[("x-a", "1")], None, false, None, 100);
        assert_eq!(frames.len(), 1);
    }

    /// `disable://trailerHeader` withholds the announcement, not the trailers
    /// (`_original/lib/inspectors/res.js:1215-1223`).
    #[test]
    fn disabling_the_trailer_header_still_sends_the_trailers() {
        let mut parts = Response::builder()
            .status(200)
            .body(())
            .expect("parts")
            .into_parts()
            .0;
        let ops = ResBodyOps {
            trailers: headers(&[("x-a", "1")]),
            announce_trailers: false,
            content: true,
            ..ResBodyOps::default()
        };
        let (_, trailers) = drain(finish_res_body(
            &mut parts,
            Bytes::from_static(b"x"),
            ops,
            None,
        ));
        assert_eq!(names(&trailers), ["x-a=1"]);
        assert!(parts.headers.get("trailer").is_none());
    }
}

#[cfg(test)]
mod pipe_wiring_tests {
    use super::*;
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

#[cfg(test)]
mod local_response_tests {
    use super::*;

    /// State with `rules` loaded, on a storage dir of its own — these tests run
    /// in parallel and sharing one made them race to write the root CA.
    fn state_with(rules: &str) -> Arc<AppState> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let config = Config {
            storage_dir: std::env::temp_dir().join(format!(
                "whistle-rs-local-res-tests-{}-{unique}",
                std::process::id()
            )),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&config).expect("ca");
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        Arc::new(AppState::new(config, mgr, ca))
    }

    /// Run `rules` against a locally produced response, exactly as `serve`'s
    /// plugin and short-circuit exits do.
    fn finish(
        rules: &str,
        status: u16,
        res_headers: &[(&str, &str)],
        body: &str,
    ) -> (hyper::http::response::Parts, Bytes) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = state_with(rules);
            let mut info = apply::build_req_info(
                "GET",
                "http",
                "example.com",
                80,
                "/",
                &hyper::HeaderMap::new(),
                Some("127.0.0.1".to_string()),
            );
            let mut resolved = state.rules.read().unwrap().resolve_scoped(&info, false);
            let resp = crate::plugins::PluginResp {
                status,
                headers: res_headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            };
            let (resp, _) = finish_local_response(
                &state,
                &mut info,
                &mut resolved,
                &[],
                false,
                plugin_response(resp),
                ResHooks::default(),
            )
            .await;
            let (parts, body) = resp.into_parts();
            let bytes = collect_body(body).await.expect("body");
            (parts, bytes)
        })
    }

    /// The fix: a plugin's answer is not the last word. Response-side operators
    /// run over it, as they do over the origin's answer — upstream reaches its
    /// response inspectors on this path too, because a `plugin://` rule is a
    /// proxy hop to the plugin's own server.
    #[test]
    fn a_plugin_answer_takes_the_response_operators() {
        let (parts, body) = finish(
            "example.com plugin://echo resHeaders://x-late=1 replaceStatus://503 \
             resType://json resAppend://!\n",
            200,
            &[("content-type", "text/plain")],
            "answered",
        );
        assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(parts.headers.get("x-late").unwrap(), "1");
        assert!(
            parts
                .headers
                .get(hyper::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("application/json"),
            "resType:// applies to a plugin's answer"
        );
        assert_eq!(body, Bytes::from_static(b"answered!"));
    }

    /// And the *response phase* runs on it: a filter about the response can be
    /// answered, because the plugin's head is in hand before any operator has
    /// touched it. `s:404` here sees the plugin's own 404, not the 200 the
    /// `replaceStatus://` on the same line would later write.
    #[test]
    fn a_plugin_answer_gets_the_response_phase() {
        let rules = "example.com plugin://echo\n\
                     example.com resHeaders://x-notfound=1 includeFilter://s:404\n";
        let (parts, _) = finish(rules, 404, &[], "");
        assert_eq!(parts.headers.get("x-notfound").unwrap(), "1");
        let (parts, _) = finish(rules, 200, &[], "");
        assert!(parts.headers.get("x-notfound").is_none());
    }

    /// A response no operator touches is handed back byte-for-byte, with its
    /// framing headers intact — nothing here may cost a plugin its `content-length`.
    #[test]
    fn an_untouched_answer_keeps_its_framing() {
        let (parts, body) = finish(
            "example.com plugin://echo\n",
            201,
            &[("content-length", "2"), ("x-plugin", "yes")],
            "hi",
        );
        assert_eq!(parts.status, StatusCode::CREATED);
        assert_eq!(parts.headers.get("content-length").unwrap(), "2");
        assert_eq!(parts.headers.get("x-plugin").unwrap(), "yes");
        assert_eq!(body, Bytes::from_static(b"hi"));
    }

    /// The short-circuit exit shares the same finisher, so a mocked response
    /// now takes the body operators too — not just the header ones.
    #[test]
    fn a_short_circuit_answer_takes_the_body_operators() {
        let (parts, body) = finish(
            "example.com statusCode://200 resBody://base\n\
             example.com resAppend://+more\n",
            200,
            &[],
            "",
        );
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(body, Bytes::from_static(b"base+more"));
    }

    /// A refusal from the auth gate is served as produced. The contrast is the
    /// point: the very same rules that rewrite an *answer* must not touch a
    /// refusal — which is what upstream's `ignore://!statusCode|…` pinning says.
    #[test]
    fn a_refusal_is_served_as_produced() {
        let rules = "example.com plugin://gate resHeaders://x-late=1 \
                     replaceStatus://200 resAppend://!\n";

        // The answer path: every operator lands, 403 included.
        let (parts, body) = finish(rules, 403, &[], "denied");
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(parts.headers.get("x-late").unwrap(), "1");
        assert_eq!(body, Bytes::from_static(b"denied!"));

        // The refusal path: nothing lands — not the header, not the append, and
        // above all not the status rewrite that would have made a 403 a 200.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (parts, body) = rt.block_on(async {
            let state = state_with(rules);
            let res = plugin_response(crate::plugins::PluginResp {
                status: 403,
                headers: vec![("content-length".to_string(), "6".to_string())],
                body: b"denied".to_vec(),
            });
            let (resp, capture) = pin_refusal(&state, res);
            assert!(capture.is_some(), "a refusal is still recorded");
            let (parts, body) = resp.into_parts();
            (parts, collect_body(body).await.expect("body"))
        });
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        assert!(parts.headers.get("x-late").is_none());
        assert_eq!(body, Bytes::from_static(b"denied"));
        // And its framing survives: nothing rewrote the body, so the length the
        // gate declared is still the truth.
        assert_eq!(parts.headers.get("content-length").unwrap(), "6");
    }

    // -- the plugin response hooks on a locally produced response -------------

    /// A plugin that hooks the response **with the body**. No built-in does, and
    /// the buffered half of the hook is the half that rewrites bytes.
    struct BodyHookPlugin;

    impl crate::plugins::RustPlugin for BodyHookPlugin {
        fn name(&self) -> &str {
            "bodyhook"
        }

        fn manifest(&self) -> crate::plugins::PluginManifest {
            crate::plugins::PluginManifest {
                on_response: true,
                response_hook: true,
                response_body: true,
                ..crate::plugins::PluginManifest::none(self.name())
            }
        }

        fn on_request(&self, _req: &crate::plugins::PluginReq) -> crate::plugins::PluginResult {
            crate::plugins::PluginResult::default()
        }

        fn on_response(&self, res: &crate::plugins::PluginRes) -> crate::plugins::PluginResResult {
            // The header proves the body arrived; the body proves what comes
            // back replaces it.
            let seen = res.body.clone().unwrap_or_default();
            crate::plugins::PluginResResult {
                set_headers: vec![("x-saw-body".to_string(), seen.len().to_string())],
                body: Some([b"<", seen.as_slice(), b">"].concat()),
                ..Default::default()
            }
        }
    }

    /// As [`finish`], but passing the plugin audience `serve` passes: the matched
    /// `plugin://` and `pipe://` sets, split the same way and resolved from the
    /// same rules.
    fn finish_hooked(
        rules: &str,
        extra: Option<Box<dyn crate::plugins::RustPlugin>>,
        status: u16,
        res_headers: &[(&str, &str)],
        body: &str,
    ) -> (hyper::http::response::Parts, Bytes) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let state = {
                let base = state_with(rules);
                match extra {
                    None => base,
                    // `AppState` owns its registry, so an extra plugin means
                    // building one — same config, same rules, same CA.
                    Some(plugin) => {
                        let mut plugins = crate::plugins::Plugins::new();
                        plugins.register_rust(plugin);
                        let mut mgr = RuleManager::new();
                        mgr.set_text(rules);
                        Arc::new(AppState::with_plugins(
                            base.config.clone(),
                            mgr,
                            base.ca.clone(),
                            plugins,
                        ))
                    }
                }
            };
            let mut info = apply::build_req_info(
                "GET",
                "http",
                "example.com",
                80,
                "/",
                &hyper::HeaderMap::new(),
                Some("127.0.0.1".to_string()),
            );
            let mut resolved = state.rules.read().unwrap().resolve_scoped(&info, false);

            // The same split `serve` does: a `pipe://` naming a plugin with a
            // streaming hook drives the stream, everything else the buffered hook.
            let mut plugins: Vec<(String, String)> = Vec::new();
            let mut pipes: Vec<crate::plugins::PluginMatch> = Vec::new();
            for m in crate::plugins::matched(&resolved) {
                if !state.plugins.contains(&m.name) {
                    continue;
                }
                let streams = m.via_pipe
                    && matches!(state.plugins.manifest(&m.name).await, Some(mf) if mf.has_pipe_hook());
                if streams {
                    pipes.push(m);
                } else {
                    plugins.push((m.name.clone(), m.param.clone()));
                }
            }

            let resp = crate::plugins::PluginResp {
                status,
                headers: res_headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            };
            let (resp, _) = finish_local_response(
                &state,
                &mut info,
                &mut resolved,
                &[],
                false,
                plugin_response(resp),
                ResHooks {
                    plugins: &plugins,
                    pipes: &pipes,
                    req_id: 7,
                    client_ip: Some("127.0.0.1".to_string()),
                    notes: None,
                },
            )
            .await;
            let (parts, body) = resp.into_parts();
            let bytes = collect_body(body).await.expect("body");
            (parts, bytes)
        })
    }

    /// The gap this closes: a plugin's own response hook never ran over a
    /// response the proxy produced itself. Upstream reaches it — a `plugin://`
    /// answer comes back from the plugin's server as an ordinary response, so
    /// the response-side plugin machinery runs over it like any other.
    #[test]
    fn a_local_answer_reaches_the_buffered_response_hook() {
        // `stamp` declares the response hook without the body, so it runs in
        // part 1, before the body is even looked at.
        let (parts, body) = finish_hooked(
            "example.com plugin://echo plugin://stamp\n",
            None,
            200,
            &[],
            "answered",
        );
        assert_eq!(
            parts
                .headers
                .get("x-stamped-by")
                .map(|v| v.to_str().unwrap()),
            Some("whistle-rs"),
            "the response hook of a matched plugin must see a local answer"
        );
        assert_eq!(body, Bytes::from_static(b"answered"));
    }

    /// The same for a short-circuit rule's response: nothing about
    /// `statusCode://` makes it invisible to a matched plugin.
    #[test]
    fn a_short_circuit_answer_reaches_the_buffered_response_hook() {
        let (parts, _) = finish_hooked(
            "example.com statusCode://204 plugin://stamp\n",
            None,
            204,
            &[],
            "",
        );
        assert!(parts.headers.get("x-stamped-by").is_some());
    }

    /// Part 2 of the hook: a plugin that asked for the body gets it, and what it
    /// returns replaces it — with the framing corrected, because the length the
    /// producer declared is no longer the truth.
    #[test]
    fn the_body_half_of_the_hook_rewrites_a_local_answer() {
        let (parts, body) = finish_hooked(
            "example.com plugin://bodyhook\n",
            Some(Box::new(BodyHookPlugin)),
            200,
            &[("content-length", "8")],
            "answered",
        );
        assert_eq!(parts.headers.get("x-saw-body").unwrap(), "8");
        assert_eq!(body, Bytes::from_static(b"<answered>"));
        // The stale `content-length: 8` must not survive a body that is now 10
        // bytes long; hyper writes the true one from a measurable body.
        assert!(
            parts.headers.get(hyper::header::CONTENT_LENGTH).is_none(),
            "a hook that replaced the body invalidated the declared length"
        );
    }

    /// The streaming hook reaches this path too. `pipe://upper` never sees a
    /// whole body — it maps frames — so this also pins that a local answer is
    /// handed to it as a body rather than as bytes.
    #[test]
    fn a_local_answer_reaches_the_streaming_response_hook() {
        let (_, body) = finish_hooked(
            "example.com plugin://echo pipe://upper\n",
            None,
            200,
            &[],
            "answered",
        );
        assert_eq!(body, Bytes::from_static(b"ANSWERED"));
    }

    /// Hooks and operators compose in the documented order: the operators run
    /// first (they are the response's own rules), then the plugin sees what they
    /// produced.
    #[test]
    fn the_operators_run_before_the_hook_sees_the_response() {
        let (parts, body) = finish_hooked(
            "example.com plugin://bodyhook resAppend://!\n",
            Some(Box::new(BodyHookPlugin)),
            200,
            &[],
            "answered",
        );
        assert_eq!(body, Bytes::from_static(b"<answered!>"));
        assert_eq!(parts.headers.get("x-saw-body").unwrap(), "9");
    }

    /// And a response with no plugin in the audience is still handed back
    /// untouched — the hooks cost an `is_empty` check, not a copy.
    #[test]
    fn no_plugin_means_no_change_and_no_lost_framing() {
        let (parts, body) = finish_hooked(
            "example.com statusCode://200\n",
            None,
            200,
            &[("content-length", "2"), ("x-mock", "yes")],
            "hi",
        );
        assert_eq!(parts.headers.get("content-length").unwrap(), "2");
        assert_eq!(parts.headers.get("x-mock").unwrap(), "yes");
        assert_eq!(body, Bytes::from_static(b"hi"));
    }
}
