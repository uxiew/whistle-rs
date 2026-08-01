//! JavaScript replacement-string expansion, ported from
//! `_original/lib/util/replace-pattern-transform.js`.
//!
//! whistle uses one expander for two jobs, and so does this port: the
//! `*Replace` operators expand it against a regexp match's groups, and every
//! operator on a rule line expands it against what the *pattern* captured
//! (`replaceSubMatcher`, `_original/lib/rules/rules.js:945-953`). That is how
//! `^*.example.com/v0/** file:///mock/$1/$2` reaches a per-request path.

/// Expand a JavaScript replacement string against one regex match
/// (`replacePattern`, `_original/lib/util/replace-pattern-transform.js:64-91`).
///
/// `$&` is the whole match and `$1`…`$9` are groups. The `$$`-prefixed spelling
/// of either — `$$&`, `$$1` — inserts the same text **percent-encoded**, which
/// is why this is expanded here instead of being handed to the `regex` crate as
/// a replacement string: that syntax has no way to transform a group.
///
/// Backslashes in front of a reference are upstream's escape, and it reads at
/// most two: `\$1` is the literal `$1`, `\\$1` is a backslash then the group.
/// A `$b`-prefixed reference (`$b1`) names a *value* list that only whistle's
/// streaming body transform has, so here it is left as written — which is what
/// upstream does too when it calls this with no value list.
pub fn expand(value: &str, groups: &[&str]) -> String {
    let group = |n: usize| groups.get(n).copied().unwrap_or("");
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        // At most two, matching `\\{0,2}` — a third backslash is literal.
        let slashes = bytes[i..].iter().take_while(|b| **b == b'\\').count().min(2);
        let rest = &bytes[i + slashes..];
        // `$`, an optional second `$` (encode), an optional `b`, then `&` or a digit.
        let (encode, after_dollars) = match rest {
            [b'$', b'$', tail @ ..] => (true, tail),
            [b'$', tail @ ..] => (false, tail),
            _ => {
                // Not a reference: emit one byte and re-scan, so the slashes we
                // counted are not consumed by a match that did not happen.
                out.push(bytes[i] as char);
                i += 1;
                continue;
            }
        };
        let (is_vals, after_b) = match after_dollars {
            [b'b', tail @ ..] => (true, tail),
            tail => (false, tail),
        };
        let Some((selector, consumed)) = (match after_b {
            [b'&', ..] => Some((0usize, 1)),
            [d, ..] if d.is_ascii_digit() => Some(((d - b'0') as usize, 1)),
            _ => None,
        }) else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };
        let reference_len = slashes + if encode { 2 } else { 1 } + usize::from(is_vals) + consumed;
        let reference = &value[i + slashes..i + reference_len];
        if is_vals {
            // No value list here, so the whole thing stays as it was written —
            // slashes included (upstream returns `$1 + $2`).
            out.push_str(&value[i..i + reference_len]);
            i += reference_len;
            continue;
        }
        match slashes {
            // `\$1` escapes the reference: the `$1` is literal.
            1 => out.push_str(reference),
            _ => {
                // `\\$1` keeps one backslash and expands.
                if slashes == 2 {
                    out.push('\\');
                }
                let text = group(selector);
                match encode && !text.is_empty() {
                    true => out.push_str(&encode_uri_component(text)),
                    false => out.push_str(text),
                }
            }
        }
        i += reference_len;
    }
    out
}

/// JavaScript's `encodeURIComponent`: everything outside the unreserved set
/// `A-Za-z0-9-_.!~*'()` is percent-encoded.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Does `value` reference a capture group at all?
///
/// Upstream asks the same question before doing any work (`SUB_MATCH_RE`,
/// `_original/lib/rules/rules.js:947-950`), which is what keeps the substitution
/// off the hot path for the overwhelming majority of rules — they contain no
/// `$`.
pub fn has_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().enumerate().any(|(i, b)| {
        *b == b'$'
            && matches!(
                bytes.get(i + 1),
                Some(b'&') | Some(b'$') | Some(b'0'..=b'9')
            )
    })
}
