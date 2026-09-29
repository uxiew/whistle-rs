//! Operators a rule matched that did not take effect, and why.
//!
//! A session's `rules` are the operators that *resolved* for the request —
//! every line that matched and won its slot. That is not the same as every
//! operator that *did* something. A response body over `--body-rewrite-limit`
//! is forwarded untouched, an event stream cannot be collected for `resMerge://`,
//! a body under a coding this proxy cannot undo is not rewritten, a plugin hook
//! that failed changed nothing, a `cipher://` no handshake could use is dropped.
//! Each of those is a decision, made on purpose, and each used to be said only
//! in a log line, if at all — so the console showed a rule that "matched" and a
//! response it had plainly not touched, which reads exactly like a bug.
//!
//! [`Unapplied`] is that decision on the record: which of the session's matched
//! operators it covers (by the `raw` token, as `rules` lists them), a stable
//! [`Kind`] for a program to branch on, and the reason in words with the numbers
//! that decided it.

use super::MatchedOp;

/// Why a matched operator did not take effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// The response body was over the rewrite limit and was forwarded
    /// unchanged.
    BodyOverLimit,
    /// The request body was over its limit and was forwarded unchanged.
    RequestBodyOverLimit,
    /// The response is an event stream, which is never collected: the
    /// operators that need the whole body cannot have it.
    EventStream,
    /// Undone, the body's `content-encoding` would have been over the rewrite
    /// limit, so it was not undone and the body was forwarded unchanged.
    DecodedOverLimit,
    /// The body's `content-encoding` would not decode — the bytes are not what
    /// the header says — so the body was forwarded unchanged.
    Undecodable,
    /// The body is under a coding this proxy cannot undo (`zstd`, stacked
    /// codings), so it was forwarded unchanged.
    UnsupportedCoding,
    /// A plugin's hook failed — could not be reached, answered an error, or
    /// did not answer in time — and the request went on without it.
    PluginFailed,
    /// The `cipher://` pin could not be used, so the connection was made
    /// without it.
    CipherUnusable,
}

/// Matched operators that did not take effect, for one reason.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Unapplied {
    pub kind: Kind,
    /// The operators it covers, each as its `raw` token — the same string the
    /// session's `rules` entry for it carries.
    pub ops: Vec<String>,
    /// What happened, in words, with the numbers that decided it.
    pub reason: String,
}

impl Unapplied {
    /// `kind` over the matched operators `covers` picks, or `None` when it
    /// picks none: a limit nobody's rule was waiting on is not news.
    pub fn over(
        matched: &[MatchedOp],
        covers: impl Fn(&MatchedOp) -> bool,
        kind: Kind,
        reason: impl Into<String>,
    ) -> Option<Self> {
        let ops: Vec<String> = matched
            .iter()
            .filter(|op| covers(op))
            .map(|op| op.raw.clone())
            .collect();
        (!ops.is_empty()).then(|| Unapplied {
            kind,
            ops,
            reason: reason.into(),
        })
    }
}

/// The entry for a body left under its coding — see
/// [`super::coding::NotDecoded`]. `side` is `request` or `response`.
pub fn not_decoded(
    why: super::coding::NotDecoded,
    side: &str,
    encoding: &str,
    matched: &[MatchedOp],
    covers: impl Fn(&MatchedOp) -> bool,
) -> Option<Unapplied> {
    use super::coding::NotDecoded;
    let (kind, reason) = match why {
        NotDecoded::Unsupported => (
            Kind::UnsupportedCoding,
            format!(
                "the {side} body is under content-encoding `{encoding}`, which this proxy \
                 cannot undo, so it was forwarded as it arrived"
            ),
        ),
        NotDecoded::Corrupt => (
            Kind::Undecodable,
            format!(
                "the {side} body's content-encoding `{encoding}` would not decode — the \
                 bytes are not what the header says — so it was forwarded as it arrived"
            ),
        ),
        NotDecoded::TooBig(limit) => (
            Kind::DecodedOverLimit,
            format!(
                "undone, the {side} body's content-encoding `{encoding}` would come to more \
                 than {limit} bytes, the rewrite limit, so it was forwarded as it arrived"
            ),
        ),
    };
    Unapplied::over(matched, covers, kind, reason)
}

/// The response-body operators: each one needs the body in hand, so each is
/// skipped when the body is forwarded as it arrived.
const RES_BODY: &[&str] = &[
    "resBody",
    "resPrepend",
    "resAppend",
    "resReplace",
    "resMerge",
    "htmlBody",
    "htmlPrepend",
    "htmlAppend",
    "jsBody",
    "jsPrepend",
    "jsAppend",
    "cssBody",
    "cssPrepend",
    "cssAppend",
    "resSpeed",
    "resScript",
    "weinre",
    "resWrite",
    "resWriteRaw",
    "trailers",
];

/// The request-body operators, likewise.
const REQ_BODY: &[&str] = &[
    "reqBody",
    "reqPrepend",
    "reqAppend",
    "reqReplace",
    "reqSpeed",
    "reqWrite",
    "reqWriteRaw",
];

/// Does `op` act on a response body — see [`RES_BODY`]? Also a
/// `delete://resBody.…` and an `enable://gzip|br|deflate`, which re-encodes
/// the body and so needs it whole too.
pub fn res_body_op(op: &MatchedOp) -> bool {
    RES_BODY.contains(&op.protocol.as_str())
        || (op.protocol == "delete" && op.value.contains("resBody"))
        || (op.protocol == "enable"
            && flags(&op.value).any(|f| matches!(f, "gzip" | "br" | "deflate")))
}

/// Does `op` wait for the whole response body, and so not run on an event
/// stream, which is never collected? Every response-body operator but the ones
/// that travel with a stream: `resBody`, `resPrepend` and `resAppend` always,
/// `resReplace` while the stream is not compressed (see `stream_replace`).
pub fn needs_whole_res_body(op: &MatchedOp, encoded: bool) -> bool {
    let travels = match op.protocol.as_str() {
        "resBody" | "resPrepend" | "resAppend" => true,
        "resReplace" => !encoded,
        _ => false,
    };
    res_body_op(op) && !travels
}

/// Does `op` act on a request body? `delete://body` / `delete://reqBody.…` do.
/// `params://` (which `reqMerge://` is an alias of) does only when it rewrites
/// a form or JSON body rather than the query string, which the caller knows —
/// see [`crate::proxy::apply::params_rewrite_body`].
pub fn req_body_op(op: &MatchedOp) -> bool {
    REQ_BODY.contains(&op.protocol.as_str())
        || (op.protocol == "delete"
            && (op.value.contains("reqBody") || flags(&op.value).any(|f| f == "body")))
}

/// The flags in an `enable://`/`delete://` value: `a|b`, `a,b` or `a b`.
fn flags(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(['|', ',', ' '])
        .map(str::trim)
        .filter(|f| !f.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(protocol: &str, value: &str) -> MatchedOp {
        MatchedOp {
            protocol: protocol.into(),
            value: value.into(),
            raw: format!("{protocol}://{value}"),
        }
    }

    #[test]
    fn only_the_operators_a_reason_covers_are_named() {
        let matched = [
            op("host", "1.2.3.4"),
            op("resReplace", "a=b"),
            op("enable", "gzip|abort"),
            op("enable", "hide"),
            op("delete", "resBody.token"),
            op("resHeaders", "x=1"),
        ];
        let u = Unapplied::over(&matched, res_body_op, Kind::BodyOverLimit, "too big")
            .expect("some are covered");
        assert_eq!(
            u.ops,
            [
                "resReplace://a=b",
                "enable://gzip|abort",
                "delete://resBody.token"
            ]
        );
        assert!(
            Unapplied::over(&matched[..1], res_body_op, Kind::BodyOverLimit, "x").is_none(),
            "nothing to say when no rule was waiting on the body"
        );
    }

    #[test]
    fn a_request_body_operator_is_not_a_response_one() {
        assert!(req_body_op(&op("reqReplace", "a=b")));
        assert!(req_body_op(&op("delete", "body")));
        assert!(!req_body_op(&op("delete", "resBody.x")));
        assert!(!res_body_op(&op("reqBody", "x")));
    }

    #[test]
    fn the_kind_is_spelled_for_a_program() {
        let json = serde_json::to_value(Kind::BodyOverLimit).unwrap();
        assert_eq!(json, "body-over-limit");
    }
}
