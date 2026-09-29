//! `delete://` on headers, cookies and trailers: which keys it names on which
//! side, and removing them.

use super::*;

/// The `delete://` keys that apply to one side, already classified.
///
/// whistle does not take a bare name: every key is matched against a fixed set
/// of anchored patterns (`_original/lib/util/index.js:2661-2669`) and anything
/// unrecognised is silently ignored. `delete://server` therefore deletes
/// nothing at all — the header spellings are `resHeaders.server`,
/// `res.headers.server`, `resH.server` (case-insensitive) or the side-agnostic
/// `headers.server` (case-**sensitive**, and only in the plural).
#[derive(Default)]
pub(super) struct Deletions {
    /// Header names to remove from this side.
    pub(super) headers: Vec<String>,
    /// Cookie names to remove.
    ///
    /// On the request side this drops the cookie from the outgoing `Cookie`
    /// header. On the response side there is nothing to drop — the cookie lives
    /// in the *client*, so it is removed by sending an already-expired
    /// `Set-Cookie` back ([`expiring_cookies`]).
    pub(super) cookies: Vec<String>,
    /// `delete://trailer.x` — trailing header names to drop after the body
    /// (`TRAILER_RE`, `_original/lib/util/index.js:2663,:2812`). Response side
    /// only, and unlike every other key here it is *not* scoped by `req`/`res`
    /// and *not* case-insensitive.
    pub(super) trailers: Vec<String>,
    /// `delete://resType` — drop the media type, keeping any charset.
    pub(super) drop_type: bool,
    /// `delete://resCharset` — drop the charset, keeping the media type.
    pub(super) drop_charset: bool,
    /// `delete://body` / `delete://res.body` — empty the body outright, which
    /// also discards anything an operator meant to inject (`removeBody`,
    /// `_original/lib/util/index.js:3591-3598`).
    ///
    /// Deliberate divergence, and the second half is all upstream achieves.
    /// `removeBody` writes `data.body = EMPTY_BUFFER`, and `EMPTY_BUFFER` is
    /// `toBuffer('')` — whose first act is `if (!buf) return;`
    /// (`_original/lib/util/common.js:1630-1632`), so the constant is
    /// `undefined`. The assignment therefore leaves `data.body` falsy,
    /// `isWhistleTransformData` says no, and no transform is added: upstream
    /// drops the `reqBody`/`reqPrepend`/`reqAppend` injections and forwards the
    /// real body untouched. The key is documented as removing the body
    /// (<https://wproxy.org/docs/rules/delete.html>) and the code plainly means
    /// to; this port does it.
    pub(super) drop_body: bool,
    /// `delete://resBody.a.b` — dotted paths to remove from a JSON body.
    pub(super) body_props: Vec<String>,
}

impl Deletions {
    /// True when a `delete://` key on its own needs the body buffered.
    pub(super) fn touches_body(&self) -> bool {
        self.drop_body || !self.body_props.is_empty()
    }
}

impl Deletions {
    /// Classify every `delete://` key for one side.
    pub(super) fn of(resolved: &Resolved, request_side: bool) -> Deletions {
        let mut del = Deletions::default();
        let side = if request_side { "req" } else { "res" };
        for value in collect_values(resolved, "delete") {
            // `parseProps` — the split honours `\|`, `\&` and the `\s`/`\t`/
            // `\n`/`\r`/`\f`/`\v` escapes, which is how `delete.md`'s own
            // example addresses a body key holding a newline and a pipe.
            for key in parse_props(value) {
                let key = key.trim();
                if key.is_empty() {
                    continue;
                }
                if let Some(name) = strip_del_scope(key, side, "H", "eaders") {
                    del.headers.push(name.to_string());
                } else if let Some(name) = key.strip_prefix("headers.") {
                    del.headers.push(name.to_string());
                } else if let Some(name) = strip_del_scope(key, side, "C", "ookies")
                    .or_else(|| strip_del_scope(key, "", "C", "ookies"))
                {
                    // `cookies.x` with no side is honoured on both
                    // (`COOKIE_RE`, `_original/lib/util/index.js:2669`).
                    del.cookies.push(name.to_string());
                } else if !request_side
                    && let Some(name) = key
                        .find("trailer.")
                        .map(|i| &key[i + "trailer.".len()..])
                        .filter(|n| !n.is_empty())
                {
                    // `TRAILER_RE` is unanchored at the front, so a bare
                    // `trailer.x` matches and so does anything else ending in
                    // `trailer.<name>`. It is also the one key here written
                    // without the `i` flag, so the word must be lower case:
                    // `delete://resTrailer.x` matches nothing and is inert.
                    del.trailers.push(name.to_string());
                } else if let Some(path) = strip_del_scope(key, side, "B", "ody") {
                    del.body_props.push(path.to_string());
                } else if key == format!("{side}Type") || key == format!("{side}.type") {
                    del.drop_type = true;
                } else if key == format!("{side}Charset") || key == format!("{side}.charset") {
                    del.drop_charset = true;
                } else if key == "body" || key == format!("{side}.body") {
                    del.drop_body = true;
                }
            }
        }
        del
    }
}

/// Match one of whistle's `^<side>\.?<initial>(?:<rest>s?)?\.(.+)$` delete keys
/// (case-insensitive), returning the trailing name.
///
/// One regex covers `resHeaders.x`, `res.headers.x`, `resHeader.x`, `resH.x` and
/// `res.h.x`; the same shape with `C`/`ookies` covers the cookie spellings.
pub(super) fn strip_del_scope<'a>(
    key: &'a str,
    side: &str,
    initial: &str,
    rest: &str,
) -> Option<&'a str> {
    let tail = key
        .get(..side.len())
        .filter(|p| p.eq_ignore_ascii_case(side))?;
    let mut tail = &key[tail.len()..];
    tail = tail.strip_prefix('.').unwrap_or(tail);
    let after_initial = tail
        .get(..initial.len())
        .filter(|c| c.eq_ignore_ascii_case(initial))?;
    tail = &tail[after_initial.len()..];
    // The word may be spelled out in full, with an optional plural `s`.
    for word in [rest, &rest[..rest.len() - 1]] {
        if let Some(t) = tail
            .get(..word.len())
            .filter(|w| w.eq_ignore_ascii_case(word))
        {
            tail = &tail[t.len()..];
            break;
        }
    }
    tail.strip_prefix('.').filter(|name| !name.is_empty())
}

/// Apply the header and cookie deletions for one side.
pub(super) fn apply_deletes(headers: &mut HeaderMap, del: &Deletions, request_side: bool) {
    for name in &del.headers {
        remove_header(headers, name);
    }
    // Only the request side has a cookie to strip: on the response side the
    // cookie is already in the client, and the deletion is a `Set-Cookie` that
    // expires it instead — see [`expiring_cookies`].
    if request_side {
        for name in &del.cookies {
            remove_cookie(headers, name);
        }
    }
}

pub(super) fn remove_header(headers: &mut HeaderMap, name: &str) {
    if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
        headers.remove(&n);
    }
}

/// Remove a single cookie from the request `Cookie` header.
///
/// The header is *rebuilt*, not edited: upstream splits it, drops the named
/// pair and renders the survivors as `name=value` joined by `"; "`
/// (`setReqCookies`, `_original/lib/util/index.js:3052-3090`). Three
/// consequences worth the rebuild: a pair that arrived without a `=` leaves
/// with one, a trailing `;` becomes a nameless `=` pair of its own, and when
/// nothing survives the header is set to the **empty string** rather than
/// removed. `setHeader` assigns unconditionally, so the request still carries a
/// `Cookie:` with nothing after it; a server that branches on the header's
/// presence must see what whistle's would.
pub(super) fn remove_cookie(headers: &mut HeaderMap, name: &str) {
    let Some(cur) = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return;
    };
    let kept = cur
        .split(';')
        .map(|s| s.trim())
        .filter(|kv| kv.split_once('=').map_or(*kv, |(k, _)| k) != name)
        .map(|kv| match kv.contains('=') {
            true => kv.to_string(),
            false => format!("{kv}="),
        })
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(v) = HeaderValue::from_str(&kept) {
        headers.insert(hyper::header::COOKIE, v);
    }
}
