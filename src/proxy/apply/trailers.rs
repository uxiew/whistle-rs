//! Response trailers: what `trailers://` adds, what `disable://trailers` and
//! `disable://trailerHeader` take away, and the names no trailer section may
//! carry.

use super::*;

/// Build the response trailer headers from `trailers://` operators.
///
/// `trailers` is one of `parseRuleJson`'s arguments (`_original/lib/inspectors/res.js:845-855`),
/// so several lines fold into one map with the first line winning a contested
/// name, exactly as `resHeaders` does.
///
/// `delete://trailer.<name>` then removes one, and it applies *after* the
/// operators — upstream deletes from the merged map on the way out
/// (`delProps.trailers`, `_original/lib/inspectors/res.js:1275-1280`), so a
/// request carrying both spellings of a name ends up without it.
pub fn build_trailers(resolved: &Resolved) -> HeaderMap {
    let mut h = HeaderMap::new();
    // `disable://trailers` / `disable://trailer` cancel the whole trailer
    // section — the rule's *and* the origin's (`_original/lib/inspectors/res.js:
    // 1252-1260`, which returns before `addTrailers` is reached).
    if trailers_disabled(resolved) {
        return h;
    }
    for (name, values) in merge_header_ops(resolved, "trailers") {
        for (i, value) in values.iter().enumerate() {
            match i {
                0 => assign_header(&mut h, &name, value),
                _ => append_header(&mut h, &name, value),
            }
        }
    }
    // `headerReplace://trailer.x:…` rewrites a trailer, then the deletions run,
    // which is upstream's order on the way out (`res.js:1275-1281`).
    apply_header_replace(&mut h, resolved, HeaderScope::Trailer);
    for name in &Deletions::of(resolved, false).trailers {
        remove_header(&mut h, name);
    }
    h
}

/// `disable://trailers` / `disable://trailer` — send no trailer section at all.
///
/// Both spellings, and both cancel the origin's trailers as well as the rule's:
/// upstream's guard is on the way *out*, after the two have been merged
/// (`_original/lib/inspectors/res.js:1252-1260`).
pub fn trailers_disabled(resolved: &Resolved) -> bool {
    let dis = disabled_flags(resolved);
    dis.contains("trailers") || dis.contains("trailer")
}

/// `disable://trailerHeader` — send the trailers without announcing them.
///
/// A separate flag from [`trailers_disabled`], and it does something different:
/// upstream skips only `addTrailerNames`, which is what writes the `Trailer:`
/// header naming what is coming (`_original/lib/inspectors/res.js:1215-1223`).
/// The trailers themselves still go.
pub fn trailer_header_announced(resolved: &Resolved) -> bool {
    !disabled_flags(resolved).contains("trailerHeader")
}

/// Header names an HTTP trailer section may not carry (`ILLEGAL_TRAILERS`,
/// `_original/lib/util/common.js:34-53`).
///
/// The list is upstream's, verbatim and in its order. It is not decoration: a
/// `Content-Length` or `Transfer-Encoding` arriving after the body contradicts
/// the framing that just delivered it, and a `Set-Cookie` or `Authorization`
/// there is a credential a client is not required to look at.
pub(super) const ILLEGAL_TRAILERS: &[&str] = &[
    "host",
    "transfer-encoding",
    "content-length",
    "cache-control",
    "te",
    "max-forwards",
    "authorization",
    "set-cookie",
    "content-encoding",
    "content-type",
    "content-range",
    "trailer",
    "connection",
    "upgrade",
    "http2-settings",
    "proxy-connection",
    "keep-alive",
];

/// `removeIllegalTrailers` (`_original/lib/util/common.js:410-414`), applied to
/// the merged map immediately before it goes on the wire (`res.js:1285`).
pub fn remove_illegal_trailers(trailers: &mut HeaderMap) {
    for name in ILLEGAL_TRAILERS {
        trailers.remove(*name);
    }
}
