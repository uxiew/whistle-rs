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
                // Not a reference: emit one character and re-scan, so the
                // slashes we counted are not consumed by a match that did not
                // happen.
                i += emit_char(&mut out, value, i);
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
            i += emit_char(&mut out, value, i);
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

/// Copy one whole character from `value` at byte offset `at`, and report how
/// many bytes it took.
///
/// The scan above walks **bytes**, because every marker it looks for (`$`, `\`,
/// `&`, a digit, `b`) is ASCII and a UTF-8 continuation byte can never be
/// mistaken for one. But emitting has to move a character at a time: pushing
/// `bytes[i] as char` reinterprets each byte as a Latin-1 scalar, so `/搜索`
/// came out as `/æ\u{90}\u{9c}ç´¢` — and that applies to *every* `$`-expanding
/// replacement, not just the header one it was noticed on.
fn emit_char(out: &mut String, value: &str, at: usize) -> usize {
    match value[at..].chars().next() {
        Some(c) => {
            out.push(c);
            c.len_utf8()
        }
        // Unreachable while `at` is on a boundary, but advancing keeps the loop
        // total rather than trusting that.
        None => 1,
    }
}

/// JavaScript's `encodeURIComponent`: everything outside the unreserved set
/// `A-Za-z0-9-_.!~*'()` is percent-encoded.
pub fn encode_uri_component(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The expander scans bytes — every marker it looks for is ASCII — but it
    /// has to *emit* whole characters. Pushing each byte as a `char` reads it as
    /// a Latin-1 scalar, so any non-ASCII text in a replacement was mangled:
    /// `/搜索` came out `/æ\u{90}\u{9c}ç´¢`. Every `$`-expanding operator was
    /// affected, not only the header one where it was first seen.
    #[test]
    fn non_ascii_survives_expansion() {
        let groups = ["whole", "one", "two"];
        // Text with no reference at all passes through unchanged.
        assert_eq!(expand("/搜索/结果", &groups), "/搜索/结果");
        // …and so does the text around a reference.
        assert_eq!(expand("/搜索/$1/尾", &groups), "/搜索/one/尾");
        // A group's own content is inserted verbatim.
        assert_eq!(expand("$1", &["", "中文"]), "中文");
        // The escape forms still work with multi-byte text beside them.
        assert_eq!(expand("中\\$1文", &groups), "中$1文");
        // `$$` percent-encodes, which is byte-oriented by definition.
        assert_eq!(expand("$$1", &["", "中"]), "%E4%B8%AD");
        // `$1` followed by digits is still `$1` plus literal text, as in
        // JavaScript — `"$100"` is group 1 then `00`.
        assert_eq!(expand("价格$100", &groups), "价格one00");
        // A `$` that references nothing is literal, and the character after it
        // must not be swallowed with it.
        assert_eq!(expand("价格$元", &groups), "价格$元");
    }
}
