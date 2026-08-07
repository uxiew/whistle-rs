//! Text substitution applied to a body **as it arrives**, for bodies that need
//! never end.
//!
//! The buffered body layer ([`crate::proxy::apply`]) collects a response and
//! then transforms it. That is correct for a body with an end and impossible for
//! one without: collecting an event stream does not delay it, it withholds it —
//! the stream ends when the server decides, which for SSE is typically never, so
//! the client receives nothing at all. The port's answer until now was to drop
//! the body operators for an event stream and pass the bytes through, which at
//! least kept the events flowing.
//!
//! whistle does not have to choose, because its text transforms are streaming:
//! each one holds back only a **tail** of the bytes it has seen — just enough
//! that a match straddling a chunk boundary cannot be missed — and emits the
//! rest immediately (`_original/lib/util/replace-string-transform.js:16-38`,
//! `_original/lib/util/replace-pattern-transform.js:21-57`). For an event stream
//! it additionally flushes through the last `\n\n`, so a *complete* event is
//! never held back even when the tail rule would have kept it
//! (`replace-string-transform.js:27-32`, `replace-pattern-transform.js:42-47`).
//!
//! This module is that mechanism. It is deliberately a separate layer from the
//! buffered one rather than a replacement for it: the buffered path serves every
//! operator that genuinely needs the whole body (`resBody://`, the injections,
//! `resMerge://`), and only the substitutions can be done a piece at a time.
//!
//! # Where this port differs from upstream, and why
//!
//! * **Indices are bytes, not UTF-16 code units.** JavaScript slices strings by
//!   code unit; this counts bytes and rounds down to a character boundary. The
//!   only thing an index decides here is *how much is held back*, so for
//!   non-ASCII text this port holds back the same text measured differently —
//!   never a different result, only a different amount of latency before the
//!   tail is released.
//! * **A body that is not UTF-8 is passed through untouched.** whistle's text
//!   transforms run over Node strings and would mangle such a body; the port's
//!   buffered path already declines it the same way (`apply_replace` hands back
//!   the bytes when `String::from_utf8` fails). Bytes held back at the moment
//!   the decision is made are flushed first, so nothing is lost.
//! * **A non-global pattern replaces once per chunk, not once per body.** That
//!   is upstream's behaviour, not a simplification: it calls `String.replace`
//!   on each chunk in turn, so a `/x/` without `g` fires once in every chunk
//!   that contains it. It is reproduced rather than corrected because the whole
//!   point of this layer is to be the same transform upstream applies.

use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::{Body, Frame};

use super::body::{BodyError, DynBody};

/// How much of the tail a regexp stage keeps in hand
/// (`LENGTH`, `_original/lib/util/replace-pattern-transform.js:4`). A pattern
/// may match text longer than any one chunk, so unlike a literal needle there is
/// no exact bound to derive — upstream picks this number and so does this port.
const TAIL: usize = 5120;

/// How close to the end of what has been seen a match may end before it is
/// left alone for the next chunk to extend
/// (`MAX_SUB_MATCH_LEN`, `replace-pattern-transform.js:8`).
const NEAR_END: usize = 512;

/// Split `/source/flags` into its two halves, or `None` when the pattern is not
/// that shape. Mirrors `ORIG_REG_EXP = /^\/(.+)\/([igmu]{0,4})$/`: the source is
/// greedy (so `/a\/b/` keeps its inner slash) and every flag character must be
/// one of `igmu`.
pub fn split_regexp(pattern: &str) -> Option<(&str, &str)> {
    let rest = pattern.strip_prefix('/')?;
    let end = rest.rfind('/')?;
    let (source, flags) = (&rest[..end], &rest[end + 1..]);
    let ok = !source.is_empty()
        && flags.len() <= 4
        && flags.chars().all(|c| matches!(c, 'i' | 'g' | 'm' | 'u'));
    ok.then_some((source, flags))
}

/// Compile the `/source/flags` half of a `*Replace` pattern, translating the
/// JavaScript flags this port honours into the `regex` crate's inline form.
///
/// `u` is absent because Rust's `regex` is Unicode-aware already, and `g` is not
/// a compilation flag — it decides how many matches are replaced, which is the
/// caller's business.
pub fn compile(source: &str, flags: &str) -> Option<regex::Regex> {
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    regex::Regex::new(&format!("{prefix}{source}")).ok()
}

/// The largest index `<= at` that falls on a character boundary of `s`.
///
/// `str::floor_char_boundary` is still unstable, and every index this module
/// computes — a held-back tail length, a match offset plus a literal's length —
/// is a byte count that may land inside a multi-byte character.
fn floor_boundary(s: &str, at: usize) -> usize {
    let mut at = at.min(s.len());
    while at > 0 && !s.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// One `pattern` → `replacement` substitution, holding its own tail.
///
/// Upstream adds one `Transform` to the response pipeline per pattern
/// (`handleReplace`, `_original/lib/inspectors/res.js:134-144`), so the stages
/// are chained: what one emits is what the next one sees.
enum Stage {
    /// A literal needle — upstream's `ReplaceStringTransform`, whose `replace`
    /// is `split(str).join(value)` and so always replaces every occurrence.
    Literal {
        needle: String,
        value: String,
        rest: String,
    },
    /// A `/source/flags` pattern — upstream's `ReplacePatternTransform`.
    Pattern {
        re: regex::Regex,
        value: String,
        global: bool,
        rest: String,
    },
    /// `/.*/` and `/.+/`, which mean "the replacement *is* the body".
    ///
    /// Upstream special-cases them (`ALL_RE`, `replace-pattern-transform.js:7`,
    /// `:23-26`) because the pattern also matches the empty string at the end of
    /// every chunk, which would otherwise repeat the replacement for as long as
    /// the stream ran. It emits the value once and nothing afterwards, so on a
    /// stream that never ends the client sees the replacement and then silence —
    /// which is the buffered path's answer too, arriving sooner.
    Whole { value: Option<String> },
}

impl Stage {
    fn new(pattern: &str, value: &str) -> Option<Self> {
        // An empty pattern is dropped rather than matched: upstream reaches the
        // transforms through `else if (pattern)` (`res.js:141`), so a falsy one
        // adds no transform at all. Matching it here would splice the value
        // between every pair of characters.
        if pattern.is_empty() {
            return None;
        }
        let Some((source, flags)) = split_regexp(pattern) else {
            return Some(Stage::Literal {
                needle: pattern.to_string(),
                value: value.to_string(),
                rest: String::new(),
            });
        };
        if matches!(source, ".*" | ".+") {
            return Some(Stage::Whole {
                value: Some(value.to_string()),
            });
        }
        Some(Stage::Pattern {
            re: compile(source, flags)?,
            value: value.to_string(),
            global: flags.contains('g'),
            rest: String::new(),
        })
    }

    /// Take `input`, emit everything that is safe to emit, keep the rest.
    fn push(&mut self, input: &str, sse: bool) -> String {
        match self {
            // The body is the replacement, so nothing that arrives is ever
            // looked at; the value goes out with the first chunk and the stage
            // is silent from then on.
            Stage::Whole { value } => value.take().unwrap_or_default(),
            Stage::Literal { needle, value, rest } => {
                if input.is_empty() {
                    return String::new();
                }
                let mut chunk = std::mem::take(rest);
                chunk.push_str(input);
                // Everything but the last `needle.len() - 1` bytes is safe: a
                // match cannot begin later than that and still be a match. If
                // the needle *does* occur, everything through the end of its
                // last occurrence is safe as well, which is what lets a long
                // needle still stream (`replace-string-transform.js:19-26`).
                let min = (chunk.len() + 1).saturating_sub(needle.len());
                let cut = match chunk.rfind(needle.as_str()) {
                    Some(at) => (at + needle.len()).max(min),
                    None => min,
                };
                // Safe to raise here without a second thought, because the
                // substitution below runs on whatever survives the truncation:
                // every complete occurrence in the emitted prefix is replaced
                // however the cut was arrived at.
                let cut = cut.max(event_cut(&chunk, sse));
                let cut = floor_boundary(&chunk, cut);
                *rest = chunk[cut..].to_string();
                chunk.truncate(cut);
                chunk.replace(needle.as_str(), value)
            }
            Stage::Pattern { re, value, global, rest } => {
                if input.is_empty() {
                    return String::new();
                }
                let mut chunk = std::mem::take(rest);
                chunk.push_str(input);
                // Where a complete event ends, and so where bytes have to go out
                // whether or not the tail guard is satisfied. Computed *before*
                // the substitution rather than after it — see [`event_cut`].
                let event = event_cut(&chunk, sse);
                let (out, replaced_to) = replace_streaming(re, value, *global, &chunk, event);
                // Nothing before `replaced_to` can change again, and neither can
                // anything before the last `TAIL` bytes — a pattern has no
                // length to derive a bound from, so upstream picks one.
                let cut = replaced_to.max(chunk.len().saturating_sub(TAIL)).max(event);
                let cut = floor_boundary(&chunk, cut);
                *rest = chunk[cut..].to_string();
                // `out` ends with exactly the bytes `rest` holds: every match at
                // or after `cut` was left as it was written, so the tail of the
                // result is the tail of the input.
                let keep = out.len() - rest.len();
                out[..keep].to_string()
            }
        }
    }

    /// No more bytes can arrive: substitute in what was held back and emit it.
    ///
    /// There is no event-stream question on this pass — nothing is being held
    /// against a match that might still arrive, because nothing more will.
    fn finish(&mut self) -> String {
        match self {
            Stage::Whole { value } => value.take().unwrap_or_default(),
            Stage::Literal { needle, value, rest } => {
                std::mem::take(rest).replace(needle.as_str(), value)
            }
            Stage::Pattern { re, value, global, rest } => {
                let held = std::mem::take(rest);
                if held.is_empty() {
                    return held;
                }
                // No tail guard on the last pass: there is nothing left to
                // extend a match, so every match is final
                // (`replace-pattern-transform.js:52-56`).
                match global {
                    true => re
                        .replace_all(&held, |caps: &regex::Captures<'_>| expand(value, caps))
                        .into_owned(),
                    false => re
                        .replace(&held, |caps: &regex::Captures<'_>| expand(value, caps))
                        .into_owned(),
                }
            }
        }
    }

    /// Whatever is still held back, as it was written. Used when the body turns
    /// out not to be text after all and the transform has to stand down.
    fn held(&mut self) -> String {
        match self {
            Stage::Whole { .. } => String::new(),
            Stage::Literal { rest, .. } | Stage::Pattern { rest, .. } => std::mem::take(rest),
        }
    }
}

/// How much of `chunk` has to go out now because it is a complete event.
///
/// Two `\n` end an SSE message, so everything up to there is whole and holding
/// it back would be holding back the point of the stream
/// (`replace-string-transform.js:27-32`,
/// `replace-pattern-transform.js:42-47`). Zero when this is not an event stream,
/// or when no event has completed yet.
///
/// **This is computed before the substitution, where upstream computes it
/// after, and the difference is a bug fixed rather than a behaviour changed.**
/// Upstream's pattern transform first decides which matches are settled — every
/// match ending within `NEAR_END` of what it has seen is left for the next chunk
/// — and only then raises the cut to flush a complete event. On a small event
/// those two steps disagree: the match was skipped *because* it was near the
/// end, and then the flush emits it anyway, unreplaced. Since an SSE chunk is
/// usually one short event, that makes a regexp `resReplace://` on an event
/// stream silently do nothing, which is the exact failure mode this port has
/// spent its audits removing. Passing the cut *into* the decision settles the
/// question once: bytes that are about to be flushed are final, so their matches
/// are final too. The literal transform never had the problem, because it
/// substitutes after truncating.
fn event_cut(chunk: &str, sse: bool) -> usize {
    match sse {
        true => chunk.rfind("\n\n").map_or(0, |at| at + 2),
        false => 0,
    }
}

/// Expand a replacement string against one match — the same expander the
/// buffered path uses, so `$1`, `$$1` and the backslash escapes mean one thing
/// in this port. See [`crate::rules::replace::expand`].
fn expand(value: &str, caps: &regex::Captures<'_>) -> String {
    let groups: Vec<&str> = (0..=9).map(|n| caps.get(n).map_or("", |m| m.as_str())).collect();
    crate::rules::replace::expand(value, &groups)
}

/// Replace inside `chunk`, leaving alone any match that ends near enough to the
/// end that more bytes could still extend it.
///
/// Returns the rewritten text and the offset (into `chunk`) past the last match
/// that *was* replaced — everything before it is settled.
///
/// `event` is [`event_cut`]: a match ending at or before it is inside bytes that
/// are going out regardless, so there is no later chunk that could extend it.
fn replace_streaming(
    re: &regex::Regex,
    value: &str,
    global: bool,
    chunk: &str,
    event: usize,
) -> (String, usize) {
    // Upstream's `len = chunk.length - MAX_SUB_MATCH_LEN`, which it lets go
    // negative — on a chunk shorter than `NEAR_END` *every* match is near the
    // end, and saturating at zero here would instead call every match settled.
    let near = chunk.len() as isize - NEAR_END as isize;
    let mut out = String::with_capacity(chunk.len());
    let mut last = 0usize;
    let mut settled = 0usize;
    for caps in re.captures_iter(chunk) {
        let m = caps.get(0).expect("group 0 always matches");
        let (start, end) = (m.start(), m.end());
        // How far past the near-end mark this match reaches — upstream's
        // `subLen`. It leaves a match alone when it ends in that zone *and* is
        // short enough that a longer one could still be found there
        // (`replace-pattern-transform.js:34-38`).
        let over = end as isize - near;
        if end > event && over >= 0 && m.len() as isize <= TAIL as isize - over {
            continue;
        }
        out.push_str(&chunk[last..start]);
        out.push_str(&expand(value, &caps));
        last = end;
        settled = end;
        if !global {
            break;
        }
    }
    out.push_str(&chunk[last..]);
    (out, settled)
}

/// A chain of substitutions applied to a body one chunk at a time.
pub struct TextReplace {
    stages: Vec<Stage>,
    /// Bytes that are a valid UTF-8 prefix of a character that has not finished
    /// arriving. Held rather than decoded, so a character split across a chunk
    /// boundary is never turned into a replacement character.
    partial: Vec<u8>,
    /// The body turned out not to be text; everything from here is passed
    /// through untouched.
    passthrough: bool,
    sse: bool,
}

impl TextReplace {
    /// The transform for `pairs`, or `None` when it would do nothing.
    ///
    /// `sse` decides only whether a complete event may jump the tail guard, so a
    /// caller that is not sure passes `false` and gets upstream's behaviour for
    /// an ordinary body.
    pub fn new(pairs: &[(String, String)], sse: bool) -> Option<Self> {
        let stages: Vec<Stage> = pairs
            .iter()
            .filter_map(|(pattern, value)| Stage::new(pattern, value))
            .collect();
        (!stages.is_empty()).then_some(TextReplace {
            stages,
            partial: Vec::new(),
            passthrough: false,
            sse,
        })
    }

    /// Feed one chunk of the body in; get back what may go to the client now.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        if self.passthrough {
            return bytes.to_vec();
        }
        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(bytes);
        let text = match std::str::from_utf8(&buf) {
            Ok(text) => text,
            // `error_len() == None` means the bytes end mid-character: valid so
            // far, incomplete. Anything else is a body that is not text, and the
            // transform has no business rewriting it.
            Err(e) if e.error_len().is_none() => {
                let (good, tail) = buf.split_at(e.valid_up_to());
                let text = std::str::from_utf8(good).expect("valid up to here");
                let out = self.run(text);
                self.partial = tail.to_vec();
                return out;
            }
            Err(_) => return self.stand_down(buf),
        };
        self.run(text)
    }

    /// The body has ended: flush every stage's held-back tail.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.passthrough {
            return Vec::new();
        }
        // A character that never finished arriving is emitted as it stands. It
        // is not text, so no stage may see it, and dropping it would silently
        // shorten the body.
        let trailing = std::mem::take(&mut self.partial);
        let mut carry = String::new();
        for stage in &mut self.stages {
            let mut out = stage.push(&carry, self.sse);
            out.push_str(&stage.finish());
            carry = out;
        }
        let mut bytes = carry.into_bytes();
        bytes.extend_from_slice(&trailing);
        bytes
    }

    /// Run `text` through every stage in turn.
    fn run(&mut self, text: &str) -> Vec<u8> {
        let mut carry = text.to_string();
        for stage in &mut self.stages {
            carry = stage.push(&carry, self.sse);
        }
        carry.into_bytes()
    }

    /// Give up on transforming: release what every stage was holding, then the
    /// bytes that proved the body was not text, and pass everything through from
    /// now on.
    fn stand_down(&mut self, buf: Vec<u8>) -> Vec<u8> {
        self.passthrough = true;
        let mut out: Vec<u8> = Vec::new();
        // Later stages have to see what earlier ones were holding, or a
        // substitution that was mid-flight would be dropped.
        let mut carry = String::new();
        for stage in &mut self.stages {
            let mut text = stage.push(&carry, self.sse);
            text.push_str(&stage.held());
            carry = text;
        }
        out.extend_from_slice(carry.as_bytes());
        out.extend_from_slice(&buf);
        out
    }
}

/// Box a body, substituting inside it as it streams past.
pub fn wrap(body: DynBody, replace: TextReplace) -> DynBody {
    ReplaceBody {
        inner: Box::pin(body),
        replace: Some(replace),
    }
    .boxed_dyn()
}

/// Body wrapper for [`wrap`].
struct ReplaceBody {
    inner: Pin<Box<DynBody>>,
    /// Taken when the inner body ends, so the flush happens exactly once.
    replace: Option<TextReplace>,
}

impl ReplaceBody {
    fn boxed_dyn(self) -> DynBody {
        use http_body_util::BodyExt;
        self.boxed()
    }
}

impl Body for ReplaceBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            let Some(replace) = this.replace.as_mut() else {
                return Poll::Ready(None);
            };
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let Some(data) = frame.data_ref() else {
                        // A trailer frame carries no body bytes; pass it on.
                        return Poll::Ready(Some(Ok(frame)));
                    };
                    let out = replace.push(data);
                    // A chunk may be wholly held back. Returning an empty frame
                    // would tell hyper the body produced something, so poll the
                    // inner body again instead of ending the stream early.
                    if out.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }
                Poll::Ready(None) => {
                    let tail = this.replace.take().expect("checked above").finish();
                    return match tail.is_empty() {
                        true => Poll::Ready(None),
                        false => Poll::Ready(Some(Ok(Frame::data(Bytes::from(tail))))),
                    };
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed the whole body as one chunk and read the result — the shape every
    /// test uses, so that "same answer as the buffered path" is one line.
    fn whole(pairs: &[(&str, &str)], sse: bool, body: &str) -> String {
        chunks(pairs, sse, &[body])
    }

    /// Feed the body in pieces, exactly as it would arrive off a socket.
    fn chunks(pairs: &[(&str, &str)], sse: bool, parts: &[&str]) -> String {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(p, v)| (p.to_string(), v.to_string()))
            .collect();
        let mut t = TextReplace::new(&owned, sse).expect("a stage");
        let mut out: Vec<u8> = Vec::new();
        for part in parts {
            out.extend_from_slice(&t.push(part.as_bytes()));
        }
        out.extend_from_slice(&t.finish());
        String::from_utf8(out).expect("utf-8 out")
    }

    /// The result must not depend on how the bytes were cut up. This is the
    /// property the tail-holding exists to provide, so it is asserted directly
    /// rather than through a single hand-picked split.
    fn every_split(pairs: &[(&str, &str)], sse: bool, body: &str) -> String {
        let expected = whole(pairs, sse, body);
        for at in 1..body.len() {
            if !body.is_char_boundary(at) {
                continue;
            }
            let got = chunks(pairs, sse, &[&body[..at], &body[at..]]);
            assert_eq!(got, expected, "split at {at} of {body:?}");
        }
        expected
    }

    #[test]
    fn a_literal_is_replaced_wherever_the_chunk_boundary_falls() {
        let out = every_split(&[("ORIGINAL", "REPLACED")], false, "a ORIGINAL b ORIGINAL c");
        assert_eq!(out, "a REPLACED b REPLACED c");
    }

    #[test]
    fn a_literal_split_across_two_chunks_still_matches() {
        // The half-needle at the end of the first chunk is exactly what the tail
        // guard exists for: without it this emits `ORIG` and then `INAL`.
        let out = chunks(&[("ORIGINAL", "X")], false, &["aORIG", "INALb"]);
        assert_eq!(out, "aXb");
    }

    #[test]
    fn a_pattern_is_expanded_with_its_groups() {
        let out = every_split(&[("/(\\w+)@(\\w+)/g", "$2.$1")], false, "x a@b y c@d z");
        assert_eq!(out, "x b.a y d.c z");
    }

    #[test]
    fn dot_star_replaces_the_whole_body_exactly_once() {
        // The empty match at the end of every chunk would otherwise repeat the
        // replacement for as long as the stream ran.
        assert_eq!(chunks(&[("/.*/g", "ONLY")], false, &["a", "b", "c"]), "ONLY");
        assert_eq!(chunks(&[("/.+/", "ONLY")], false, &["a", "b", "c"]), "ONLY");
    }

    #[test]
    fn an_event_stream_releases_each_event_as_it_completes() {
        // The point of the whole module: with a rule attached, the first event
        // must reach the client before the second one is written — a stream that
        // never ends must not be held for a tail that never fills.
        let owned = vec![("ping".to_string(), "pong".to_string())];
        let mut t = TextReplace::new(&owned, true).expect("a stage");
        let first = t.push(b"data: ping\n\n");
        assert_eq!(
            String::from_utf8(first).unwrap(),
            "data: pong\n\n",
            "a complete event is not held back"
        );
        let second = t.push(b"data: ping\n\n");
        assert_eq!(String::from_utf8(second).unwrap(), "data: pong\n\n");
    }

    #[test]
    fn a_flushed_event_is_substituted_rather_than_passed_through_raw() {
        // The upstream defect recorded on [`event_cut`]: the match ends inside
        // the near-end zone, so the tail guard would skip it, and the event
        // flush would then emit it unreplaced. On an event stream — where a
        // chunk is one short event — that is every match there is.
        let owned = vec![("/pi(n)g/g".to_string(), "po$1g".to_string())];
        let mut t = TextReplace::new(&owned, true).expect("a stage");
        assert_eq!(
            String::from_utf8(t.push(b"data: ping\n\n")).unwrap(),
            "data: pong\n\n"
        );
    }

    #[test]
    fn without_the_event_stream_flag_the_same_bytes_are_held() {
        // The contrast that shows `sse` is doing the work: a pattern stage keeps
        // a tail until it has seen enough, which for an endless stream is never.
        let owned = vec![("/pi(n)g/g".to_string(), "po$1g".to_string())];
        let mut held = TextReplace::new(&owned, false).expect("a stage");
        assert!(
            held.push(b"data: ping\n\n").is_empty(),
            "an ordinary body waits for its tail to fill"
        );
        let mut flowing = TextReplace::new(&owned, true).expect("a stage");
        assert_eq!(
            String::from_utf8(flowing.push(b"data: ping\n\n")).unwrap(),
            "data: pong\n\n"
        );
    }

    #[test]
    fn an_incomplete_event_holds_back_only_what_could_still_match() {
        // A literal needle needs `len - 1` bytes of tail and no more, so a
        // half-arrived event is not held whole — the part that cannot be the
        // start of a match goes out at once, and the match still completes.
        let owned = vec![("ping".to_string(), "pong".to_string())];
        let mut t = TextReplace::new(&owned, true).expect("a stage");
        let first = String::from_utf8(t.push(b"data: pi")).unwrap();
        assert_eq!(first, "data:", "only the last three bytes could start `ping`");
        let second = String::from_utf8(t.push(b"ng\n\n")).unwrap();
        assert_eq!(first + &second, "data: pong\n\n");
    }

    #[test]
    fn stages_chain_so_the_second_sees_what_the_first_produced() {
        // Upstream adds one transform per pattern to the same pipeline, so this
        // is a pipeline and not a set of independent rewrites.
        let out = every_split(&[("a", "b"), ("b", "c")], false, "aaa");
        assert_eq!(out, "ccc");
    }

    #[test]
    fn a_character_split_across_chunks_is_never_mangled() {
        // `搜` is three bytes; cutting between them must not produce U+FFFD.
        let body = "找到搜索了".as_bytes();
        for at in 1..body.len() {
            let owned = vec![("找到".to_string(), "X".to_string())];
            let mut t = TextReplace::new(&owned, false).expect("a stage");
            let mut out = t.push(&body[..at]);
            out.extend_from_slice(&t.push(&body[at..]));
            out.extend_from_slice(&t.finish());
            assert_eq!(String::from_utf8(out).unwrap(), "X搜索了", "split at {at}");
        }
    }

    #[test]
    fn a_body_that_is_not_text_is_handed_back_byte_for_byte() {
        // The buffered path declines a non-UTF-8 body; so must this one, and it
        // must not lose the bytes it was holding when it found out.
        let owned = vec![("ping".to_string(), "pong".to_string())];
        let mut t = TextReplace::new(&owned, false).expect("a stage");
        let mut out = t.push(b"pi");
        out.extend_from_slice(&t.push(&[0xff, 0xfe]));
        out.extend_from_slice(&t.push(b"ng"));
        out.extend_from_slice(&t.finish());
        assert_eq!(out, b"pi\xff\xfeng", "every byte survives, none replaced");
    }

    #[test]
    fn a_body_longer_than_the_tail_guard_streams_instead_of_accumulating() {
        // The guard holds `TAIL` bytes, so a body several times that long must
        // come out in pieces rather than all at the end — otherwise "streaming"
        // is just buffering with extra steps.
        let body = format!("{}MARK{}", "x".repeat(TAIL * 2), "y".repeat(TAIL * 2));
        let owned = vec![("/MA(R)K/g".to_string(), "HIT$1".to_string())];
        let mut t = TextReplace::new(&owned, false).expect("a stage");
        let mut early = 0usize;
        let mut out: Vec<u8> = Vec::new();
        for part in body.as_bytes().chunks(1024) {
            let got = t.push(part);
            early += got.len();
            out.extend_from_slice(&got);
        }
        out.extend_from_slice(&t.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{}HITR{}", "x".repeat(TAIL * 2), "y".repeat(TAIL * 2))
        );
        assert!(
            early > TAIL * 3,
            "most of the body should have gone out before the end, got {early}"
        );
    }

    #[test]
    fn a_pattern_matching_across_a_chunk_boundary_deep_in_the_body_still_hits() {
        // Far enough in that the tail guard, not the chunk size, is what decides
        // when the match is settled.
        let body = format!("{}fo", "-".repeat(TAIL + 100));
        let owned = vec![("/foo/g".to_string(), "BAR".to_string())];
        let mut t = TextReplace::new(&owned, false).expect("a stage");
        let mut out = t.push(body.as_bytes());
        out.extend_from_slice(&t.push(b"o!"));
        out.extend_from_slice(&t.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{}BAR!", "-".repeat(TAIL + 100))
        );
    }

    #[test]
    fn an_empty_pattern_adds_no_stage() {
        assert!(TextReplace::new(&[(String::new(), "x".to_string())], false).is_none());
    }

    #[test]
    fn a_truncated_character_at_the_end_of_a_body_is_still_emitted() {
        let owned = vec![("a".to_string(), "b".to_string())];
        let mut t = TextReplace::new(&owned, false).expect("a stage");
        let mut out = t.push(b"a");
        out.extend_from_slice(&t.push(&[0xe6, 0x90])); // the first two bytes of 搜
        out.extend_from_slice(&t.finish());
        assert_eq!(out, b"b\xe6\x90");
    }

    #[test]
    fn the_regexp_split_accepts_only_the_flags_whistle_accepts() {
        assert_eq!(split_regexp("/a\\/b/gi"), Some(("a\\/b", "gi")));
        assert_eq!(split_regexp("/x/"), Some(("x", "")));
        assert_eq!(split_regexp("//"), None, "an empty source is not a pattern");
        assert_eq!(split_regexp("/x/z"), None, "z is not one of igmu");
        assert_eq!(split_regexp("plain"), None);
    }
}
