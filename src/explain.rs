//! Resolve a rules file against a request **without making one**.
//!
//! whistle has this as a console dialog — Network → Actions → *Test Rules*,
//! `docs/docs/gui/test-rules.md`: you type a rules text, a method, a URL, a set
//! of headers and a body, and it tells you which rules that request would hit.
//! The question it answers is the one a rule file poses most often, because a
//! rule that does not match reports nothing at all: a line that is silently
//! inert and a line that is working look identical from the client side.
//!
//! This is the same question asked offline. Nothing here opens a socket, reads
//! a file or starts a proxy — it parses the text, builds the request the caller
//! described, and runs the ordinary [`RuleManager::resolve`] over it. So the
//! answer is the resolver's, not a second implementation that could drift from
//! it.
//!
//! Two deliberate narrowings, both because the request is imaginary:
//!
//! * `@`-includes naming a file or a URL stay literal ([`RuleManager::new`]
//!   rather than [`RuleManager::with_includes`]) — a rule tester that polls a
//!   URL is a proxy with extra steps;
//! * everything resolves in **one** pass unless the caller describes a
//!   response. The proxy splits resolution in two so that an operator guarded
//!   by a response condition (`statusCode:`, `resH.`) can be decided once the
//!   head is in; with no head that operator is still reported and the condition
//!   fails closed, and with a `response` in the query both passes run exactly
//!   as they do on a real response.
//!
//! The batch shape ([`Query`] in, [`Explanation`] out, one JSON object per
//! line) exists so that another program can ask thousands of these; that is
//! what `tests/differential/rules-oracle.js` does with whistle's own parser on
//! the other side.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::proxy::apply::{self, TplCtx};
use crate::proxy::template::ProxyEnv;
use crate::rules::{RuleManager, RuleOp};

/// One question: this rules text, against this request.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// The rules text, exactly as it would be typed into the console.
    #[serde(default)]
    pub rules: String,
    /// The values store — what `{name}` refers to.
    ///
    /// ``` blocks inside `rules` are read too, and they lose to this map for
    /// the same reason `--value` beats a block at runtime (see
    /// `effective_values`).
    #[serde(default)]
    pub values: HashMap<String, String>,
    /// The request URL, with scheme. A bare `host/path` is read as `http://`.
    pub url: String,
    /// The request method; `GET` when absent.
    #[serde(default)]
    pub method: Option<String>,
    /// Request headers, for the header conditions (`reqH.`, `H:`, `ua:` …).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The request body, for the `b:` conditions. Absent means *unknown*, which
    /// is not the same as empty: a `b:` condition over an unread body fails
    /// closed, upstream included.
    #[serde(default)]
    pub body: Option<String>,
    /// The client address, for `clientIp:` / `i:`.
    #[serde(default)]
    pub client_ip: Option<String>,
    /// The response head, when the question is about the **second** phase.
    ///
    /// Without one, a condition that asks about the response has no answer and
    /// fails closed — which is the state a real request is in until the head
    /// arrives. With one, the response-phase operators are resolved again
    /// against it, exactly as [`crate::proxy::resolve_response_phase`] does.
    #[serde(default)]
    pub response: Option<Response>,
}

/// The response head a [`Query`] may carry.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The address the origin answered from, for `serverIp:` / `enable://showHost`.
    #[serde(default)]
    pub server_ip: Option<String>,
    #[serde(default)]
    pub server_port: Option<u16>,
}

/// One operator that matched, and where it came from.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Op {
    /// The canonical protocol name — the alias is resolved (`hosts://` reports
    /// `host`), and the raw token below still says what was written.
    pub protocol: String,
    /// The value after `protocol://`, once `{name}` references, backtick
    /// templates and `$1` captures have been expanded — what the operator will
    /// actually be handed.
    pub value: String,
    /// The token exactly as written on the line.
    pub raw: String,
    /// The pattern of the line the operator was written on.
    pub pattern: String,
    /// Is the value the **content** rather than a place to find it — an
    /// `(inline)` payload, or what a `{name}` reference returned? A reader that
    /// treats it as a path would go looking for a file named after a mock body.
    pub content: bool,
    /// Did this operator win the **shared slot**? At most one can
    /// (`protocols::SLOT_PROTOCOLS`), and the losers are absent from the
    /// answer entirely — which is the point of reporting it.
    pub slot: bool,
    /// Resolution order: important lines first, source order within a pass.
    pub order: u64,
}

/// What the rules text does to the request.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Explanation {
    /// The URL as this port normalised it, which is the string every pattern
    /// was matched against.
    pub url: String,
    /// The matching operators, in resolution order.
    pub ops: Vec<Op>,
}

/// Answer one [`Query`].
///
/// The error is a sentence for a human: the only way to fail here is a URL
/// this port cannot read, and the caller wrote it.
pub fn explain(query: &Query) -> Result<Explanation, String> {
    let (scheme, host, port, path) = split_url(&query.url)?;

    let mut manager = RuleManager::new();
    manager.set_text(&query.rules);

    let mut headers = hyper::HeaderMap::new();
    if !query.headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
        // Every request carries one, and `H:` / `reqH.host` conditions read it.
        let authority = if is_default_port(&scheme, port) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        insert_header(&mut headers, "host", &authority);
    }
    for (name, value) in &query.headers {
        insert_header(&mut headers, name, value);
    }

    let mut info = apply::build_req_info(
        query.method.as_deref().unwrap_or("GET"),
        &scheme,
        &host,
        port,
        &path,
        &headers,
        query.client_ip.clone(),
    );
    info.req_body = query.body.clone();

    // With a response head in hand, the two passes the proxy runs: the request
    // one withholds the operators a response condition guards, and the second
    // decides them against the head (`resolve_response_phase`).
    //
    // Without one, everything resolves in a single pass. The split exists so
    // that a response-phase operator can be decided once the head is in, and
    // here no head will ever arrive; withholding would report nothing about the
    // half of a rules file that is about responses. A condition that needs the
    // response still fails closed — the same answer the request pass gives, and
    // the same one whistle's own single-pass `resolveRules` gives.
    let mut resolved = match &query.response {
        None => manager.resolve_once(&info, false),
        Some(_) => manager.resolve(&info),
    };
    if let Some(response) = &query.response {
        let mut headers = hyper::HeaderMap::new();
        for (name, value) in &response.headers {
            insert_header(&mut headers, name, value);
        }
        info.res = Some(apply::build_res_info(
            response.status,
            &headers,
            response.server_ip.clone(),
            response.server_port,
        ));
        if let Some(extra) = manager.resolve_response(&info, false) {
            resolved.merge_response_phase(extra);
        }
    }

    let mut values = manager.inline_values();
    values.extend(query.values.clone());
    apply::substitute_values(
        &mut resolved,
        &values,
        TplCtx {
            info: &info,
            env: ProxyEnv {
                host: "",
                port: crate::config::DEFAULT_PORT,
                version: env!("CARGO_PKG_VERSION"),
            },
        },
    );

    let slot_order = resolved.slot().map(|op| op.order);
    let mut ops: Vec<Op> = resolved
        .ops()
        .map(|op| to_op(op, slot_order == Some(op.order)))
        .collect();
    // Resolution order is the whole answer for the operators that compete, so
    // report it rather than a hash map's whim. The protocol name breaks the tie
    // between two operators written on the same line.
    ops.sort_by(|a, b| {
        a.order
            .cmp(&b.order)
            .then_with(|| a.protocol.cmp(&b.protocol))
    });

    Ok(Explanation {
        url: info.full_url,
        ops,
    })
}

fn to_op(op: &RuleOp, slot: bool) -> Op {
    Op {
        protocol: op.protocol.clone(),
        value: op.value.clone(),
        raw: op.raw.clone(),
        pattern: op.raw_pattern.clone(),
        content: op.value_is_content,
        slot,
        order: op.order,
    }
}

/// A header the caller typed, dropped if it is not one a request could carry.
///
/// An explanation of a request that cannot exist is worth less than an
/// explanation of the request minus the impossible header, and hyper's own
/// parse is the same gate the real path applies.
fn insert_header(headers: &mut hyper::HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        name.parse::<hyper::header::HeaderName>(),
        value.parse::<hyper::header::HeaderValue>(),
    ) {
        headers.append(name, value);
    }
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!(
        (scheme, port),
        ("http", 80) | ("ws", 80) | ("https", 443) | ("wss", 443)
    )
}

/// Split a URL the way the proxy would have, had the request arrived.
///
/// A missing scheme is `http://` — the console's own Test Rules box accepts
/// `www.example.com/api` and so does this, because that is how the pattern on
/// the line beside it is written.
fn split_url(url: &str) -> Result<(String, String, u16, String), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("no url".into());
    }
    let absolute = if crate::rules::url::has_protocol(url) {
        url.to_string()
    } else {
        format!("http://{url}")
    };
    let uri: hyper::Uri = absolute
        .parse()
        .map_err(|e| format!("cannot read url {url:?}: {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    // Left exactly as written: `build_req_info` folds the case of the *host* and
    // keeps it in the URL, because a regexp pattern is matched against the URL
    // as text. Folding it here would answer a question about a request the
    // caller did not describe.
    let host = uri
        .host()
        .ok_or_else(|| format!("url {url:?} names no host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or(match scheme.as_str() {
        "https" | "wss" => 443,
        _ => 80,
    });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok((scheme, host, port, path))
}

/// Render an [`Explanation`] for a terminal.
///
/// The slot marker is the column that earns its place: a `statusCode://`
/// written under a `file://` is *absent*, and a reader who does not know the
/// two share one slot will look for a typo in the pattern instead.
pub fn to_text(explanation: &Explanation) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", explanation.url));
    if explanation.ops.is_empty() {
        out.push_str("  (no rule matches)\n");
        return out;
    }
    let width = explanation
        .ops
        .iter()
        .map(|op| op.protocol.len())
        .max()
        .unwrap_or(0);
    for op in &explanation.ops {
        out.push_str(&format!(
            "  {:width$}  {}{}\n      on: {} {}\n",
            op.protocol,
            op.value,
            if op.slot { "   [slot]" } else { "" },
            op.pattern,
            op.raw,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(rules: &str, url: &str) -> Explanation {
        explain(&Query {
            rules: rules.to_string(),
            url: url.to_string(),
            ..Default::default()
        })
        .expect("a readable url")
    }

    fn protocols(explanation: &Explanation) -> Vec<&str> {
        explanation
            .ops
            .iter()
            .map(|op| op.protocol.as_str())
            .collect()
    }

    #[test]
    fn a_matching_line_reports_its_operators() {
        let e = ask(
            "example.com reqHeaders://a=1 resHeaders://b=2",
            "http://example.com/x",
        );
        assert_eq!(protocols(&e), ["reqHeaders", "resHeaders"]);
        assert_eq!(e.ops[0].value, "a=1");
        assert_eq!(e.ops[0].pattern, "example.com");
    }

    #[test]
    fn a_line_that_does_not_match_reports_nothing() {
        let e = ask("other.com reqHeaders://a=1", "http://example.com/x");
        assert!(e.ops.is_empty(), "{e:?}");
    }

    /// The reason the tool exists: the loser of the shared slot is not a rule
    /// that ran late, it is a rule that never ran.
    #[test]
    fn only_the_slot_winner_is_reported() {
        let e = ask(
            "example.com file:///srv/x\nexample.com statusCode://503",
            "http://example.com/",
        );
        assert_eq!(protocols(&e), ["file"]);
        assert!(e.ops[0].slot);
    }

    #[test]
    fn a_value_reference_is_expanded() {
        let e = explain(&Query {
            rules: "example.com resBody://{mock}".into(),
            values: HashMap::from([("mock".to_string(), "hello".to_string())]),
            url: "http://example.com/".into(),
            ..Default::default()
        })
        .expect("a readable url");
        assert_eq!(e.ops[0].value, "hello");
    }

    /// A ``` block declares a value for the text that holds it, and the tester
    /// reads the same store the proxy would.
    #[test]
    fn an_inline_block_answers_its_own_text() {
        let e = ask(
            "example.com resBody://{mock}\n```mock\nhi\n```",
            "http://example.com/",
        );
        assert_eq!(e.ops[0].value, "hi");
    }

    #[test]
    fn a_header_condition_is_answered_from_the_headers_given() {
        let q = |headers: BTreeMap<String, String>| {
            explain(&Query {
                rules: "example.com reqHeaders://a=1 includeFilter://reqH.x-env=test".into(),
                url: "http://example.com/".into(),
                headers,
                ..Default::default()
            })
            .unwrap()
        };
        assert!(q(BTreeMap::new()).ops.is_empty());
        assert_eq!(
            protocols(&q(BTreeMap::from([("x-env".into(), "test".into())]))),
            ["reqHeaders"]
        );
    }

    /// An unread body is not an empty body — the condition fails closed, which
    /// is also what the proxy does before it has buffered one.
    #[test]
    fn a_body_condition_is_answered_from_the_body_given() {
        let q = |body: Option<&str>| {
            explain(&Query {
                rules: "example.com reqHeaders://a=1 includeFilter://b:secret".into(),
                url: "http://example.com/".into(),
                method: Some("POST".into()),
                body: body.map(str::to_string),
                ..Default::default()
            })
            .unwrap()
        };
        assert!(q(None).ops.is_empty());
        assert!(q(Some("nothing here")).ops.is_empty());
        assert_eq!(protocols(&q(Some("a secret value"))), ["reqHeaders"]);
    }

    #[test]
    fn the_method_decides_a_method_condition() {
        let q = |method: &str| {
            explain(&Query {
                rules: "example.com reqHeaders://a=1 includeFilter://m:post".into(),
                url: "http://example.com/".into(),
                method: Some(method.into()),
                ..Default::default()
            })
            .unwrap()
        };
        assert!(q("GET").ops.is_empty());
        assert_eq!(protocols(&q("POST")), ["reqHeaders"]);
    }

    /// A URL without a scheme is an `http://` one, and the port comes back in
    /// the reported URL only when it is not the scheme's own.
    #[test]
    fn a_scheme_less_url_is_http() {
        assert_eq!(
            ask("", "www.example.com/api").url,
            "http://www.example.com/api"
        );
        assert_eq!(ask("", "https://example.com/").url, "https://example.com/");
        assert_eq!(
            ask("", "http://example.com:8080/").url,
            "http://example.com:8080/"
        );
    }

    #[test]
    fn a_url_with_no_host_is_an_error() {
        assert!(
            explain(&Query {
                url: "/just/a/path".into(),
                ..Default::default()
            })
            .is_err()
        );
    }

    /// Important lines resolve first, and the report says so by its order.
    #[test]
    fn the_report_is_in_resolution_order() {
        let e = ask(
            "example.com resHeaders://a=1\nexample.com resHeaders://b=2 lineProps://important",
            "http://example.com/",
        );
        assert_eq!(
            e.ops.iter().map(|op| op.value.as_str()).collect::<Vec<_>>(),
            ["b=2", "a=1"]
        );
    }

    #[test]
    fn the_text_rendering_names_the_slot_winner() {
        let text = to_text(&ask("example.com file:///srv/x", "http://example.com/"));
        assert!(text.contains("[slot]"), "{text}");
        assert!(to_text(&ask("", "http://example.com/")).contains("no rule matches"));
    }
}
