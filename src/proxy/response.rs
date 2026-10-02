//! The response side of the pipeline: resolving the rules a second time once
//! the response head is in, the body operators applied as the body arrives —
//! collected, streamed, framed, injected into, re-encoded — the plugin response
//! hooks, trailers, and finishing an answer this proxy made itself.

use super::*;

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
pub(super) async fn resolve_response_phase(
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

/// The response-side operators that act on the body once it is in hand.
///
/// Gathered in one place because more than one exit produces a response: the
/// origin's, a `plugin://` hook's, and a short-circuit rule's. whistle runs the
/// same response inspectors over all three (`_original/lib/inspectors/res.js`
/// is reached whether the bytes came from a server, a plugin, or a local file),
/// so they must run the same set here too.
#[derive(Default)]
pub(super) struct ResBodyOps {
    /// `resSpeed://` — throttle, in kilobits/s.
    pub(super) speed: Option<f64>,
    /// `resScript://` — the operator as written, and the loaded source.
    pub(super) script: Option<(String, String)>,
    /// `weinre://` — debug-agent id to inject.
    pub(super) weinre: Option<String>,
    /// `log://` — the rule whose collector goes into a page or a script. Set
    /// only where there is one to put it in: see [`LogRule`].
    pub(super) log: Option<LogRule>,
    /// `resWrite://` / `resWriteRaw://` — dump paths, already carrying the
    /// `.<status>` suffix a non-200 gets.
    pub(super) write: Option<String>,
    pub(super) write_raw: Option<String>,
    /// `enable://forceReqWrite` — write the dump even over an existing file.
    pub(super) force_write: bool,
    /// `trailers://` — trailing headers to append after the body. Already empty
    /// when `disable://trailers` cancelled them.
    pub(super) trailers: hyper::HeaderMap,
    /// `disable://trailers` / `trailer` — drop the origin's trailer section too,
    /// which is the half a rule-side check cannot see.
    pub(super) no_trailers: bool,
    /// `disable://trailerHeader` clears this: the trailers still go, the
    /// `Trailer:` header announcing them does not.
    pub(super) announce_trailers: bool,
    /// Any content operator (`resReplace`, `htmlAppend`, `resBody`, …).
    pub(super) content: bool,
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
    pub(super) force_encoding: Option<coding::Coding>,
}

/// Is this response an event stream — a body that need never end?
///
/// whistle's `isSSE` (`_original/lib/util/index.js:3917-3921`), whose test is
/// `/^\s*text\/event-stream\s*;?/i` against `content-type`. Deliberately as
/// loose as upstream's: the pattern is not anchored at the end, so anything
/// *starting* with the media type matches, parameters and all.
pub(super) fn is_event_stream(content_type: Option<&str>) -> bool {
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
pub(super) fn must_collect_body(
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
pub(super) fn response_frames(
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
pub(super) fn stream_replace(
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
pub(super) fn stream_injection(
    resolved: &Resolved,
    res_ct: Option<&str>,
) -> Option<apply::StreamInjection> {
    is_event_stream(res_ct)
        .then(|| apply::res_stream_injection(resolved))
        .flatten()
}

/// A matched `log://` rule, as far as the response needs it.
pub(super) struct LogRule {
    /// The rule's value: an id or `{name}` as written — or, once the values
    /// pass has been over it, what `name` holds.
    value: String,
    /// `name`, when `value` is already what the store holds for it. The values
    /// pass replaces `{name}` with the content, and `log://{name}` needs both
    /// halves: the name is the group, the content is the user's script.
    key: Option<String>,
    /// The group the rule was written in, for a `{name}` that is a ``` block.
    group: Option<String>,
    /// `!disable://interceptConsole || enable://interceptConsole`.
    intercept_console: bool,
}

impl LogRule {
    /// The first `log://` on the request, when the response is one the
    /// collector can stand in.
    ///
    /// `streaming_ct` is the type of a body still arriving, and decides whether
    /// it is collected at all: a rule over a whole host matches its images and
    /// its downloads too, and none of those should be buffered for a script
    /// that has nowhere to go. A body already in memory (`None`) costs nothing
    /// to look at, and is asked again when it is injected.
    fn of(resolved: &Resolved, streaming_ct: Option<&str>) -> Option<Self> {
        let op = resolved.all("log").first()?;
        if streaming_ct.is_some() && !pagelog::injects_into(streaming_ct) {
            return None;
        }
        Some(LogRule {
            value: op.value.clone(),
            key: op.value_key.clone().filter(|_| op.value_is_content),
            group: op.group.as_deref().map(str::to_string),
            intercept_console: !apply::disabled_flags(resolved).contains("interceptConsole")
                || apply::enabled_flags(resolved).contains("interceptConsole"),
        })
    }
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
    pub(super) fn of(
        resolved: &Resolved,
        has_body: bool,
        status: u16,
        streaming_ct: Option<&str>,
    ) -> Self {
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
                .and_then(|op| script::load_script(&op.value).map(|src| (op.raw.clone(), src))),
            weinre: resolved.value("weinre").map(|s| s.to_string()),
            log: LogRule::of(resolved, streaming_ct),
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

    /// Forget a `weinre://` that has no script to inject — see [`weinre_src`] —
    /// so that a response is not collected for a tag that will not be written.
    pub(super) fn for_config(mut self, config: &Config) -> Self {
        if self
            .weinre
            .as_deref()
            .is_some_and(|id| weinre_src(id, config).is_none())
        {
            self.weinre = None;
        }
        self
    }

    /// True when at least one of these needs the whole body in memory. A
    /// response no operator touches never gets collected — that is what keeps
    /// the streaming path streaming.
    pub(super) fn needs_body(&self) -> bool {
        self.content
            || self.speed.is_some()
            || self.script.is_some()
            || self.weinre.is_some()
            || self.log.is_some()
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
pub(super) fn restore_content_encoding(
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
pub(super) fn effective_values(state: &AppState) -> std::collections::HashMap<String, String> {
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
pub(super) fn inject_res_body(
    state: &AppState,
    parts: &mut hyper::http::response::Parts,
    mut new: Bytes,
    ops: &ResBodyOps,
    info: &ReqInfo,
) -> Bytes {
    if let Some((raw, src)) = &ops.script {
        let hv: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body_str = String::from_utf8_lossy(&new).into_owned();
        let ran = script::run_res_script(
            src,
            &info.method,
            &info.full_url,
            parts.status.as_u16(),
            &hv,
            &body_str,
        );
        // A script that did not finish leaves the response as it was, and
        // says so on the session.
        if let Err(why) = &ran
            && let Ok(mut failures) = info.script_failures.lock()
        {
            failures.push((raw.clone(), why.to_string()));
        }
        if let Ok(r) = ran {
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
        && let Some(src) = weinre_src(id, &state.config)
    {
        let tag = format!("<script src=\"{src}\"></script>");
        new = inject_into_html(&new, &tag);
    }
    // log: put the console collector into a page or a script.
    if let Some(rule) = &ops.log {
        let content_type = parts
            .headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let (id, user_script) = match &rule.key {
            Some(name) => (name.clone(), Some(rule.value.clone())),
            None => {
                pagelog::id_and_script(&rule.value, rule.group.as_deref(), &effective_values(state))
            }
        };
        let injection = pagelog::Injection {
            id,
            user_script,
            intercept_console: rule.intercept_console,
        };
        if let Some(injected) = pagelog::inject(&new, content_type, &injection) {
            new = injected;
        }
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
pub(super) fn finish_res_body(
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
pub(super) fn retrailer(body: DynBody, trailers: Option<hyper::HeaderMap>) -> DynBody {
    use http_body_util::BodyExt;
    Retrailed {
        inner: Box::pin(body),
        trailers,
    }
    .boxed()
}

/// Body wrapper backing [`retrailer`]: swallows the inner body's trailer frame
/// and emits its own, once, at the end.
pub(super) struct Retrailed {
    pub(super) inner: std::pin::Pin<Box<DynBody>>,
    pub(super) trailers: Option<hyper::HeaderMap>,
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
pub(super) struct ResHooks<'a> {
    /// Plugins matched for this request, in rule order: the `POST /response`
    /// audience. Held as `(name, param)` because that is what the request hook
    /// already built.
    pub(super) plugins: &'a [(String, String)],
    /// `pipe://` plugins matched for this request, in rule order.
    pub(super) pipes: &'a [crate::plugins::PluginMatch],
    /// Correlation id, shared with the request hook of the same request.
    pub(super) req_id: u64,
    /// The client address, as the request hook reported it.
    pub(super) client_ip: Option<String>,
    /// Where a hook that failed is noted — the ledger's list, so it reaches
    /// the session. See [`plugin_hook_failed`].
    pub(super) notes: Option<&'a mut Vec<unapplied::Unapplied>>,
}

/// A plugin hook that failed, as the session records it: the `plugin://` or
/// `pipe://` operators naming that plugin did not take effect in that hook.
pub(super) fn plugin_hook_failed(
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
pub(super) fn pin_refusal(
    state: &AppState,
    res: Response<Bytes>,
) -> (Response<DynBody>, Option<Capture>) {
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
pub(super) async fn finish_local_response(
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
    )
    .for_config(&state.config);
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

/// True if the response declares an HTML content type.
pub(super) fn is_html(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// The URL a `weinre://` rule's `<script>` loads, or `None` when there is none
/// to give.
///
/// * a value that is already a URL or a path is the script's own address and
///   is used as written;
/// * a bare id is `<server>/target/target-script-min.js#<id>` on the weinre
///   server `--weinre` named;
/// * a bare id with no server named is **nothing**. whistle bundles weinre and
///   serves it from its own port, so there a bare id always works; this port
///   contains no weinre, and it used to emit the same URL anyway — a script
///   tag pointing at this proxy, which answers it `404`. The page loaded, no
///   debugger ever connected, and nothing said why.
pub(super) fn weinre_src(id: &str, config: &Config) -> Option<String> {
    let id = id.trim();
    if id.contains("://") || id.starts_with('/') {
        return Some(id.to_string());
    }
    let server = config
        .weinre_server
        .as_deref()?
        .trim()
        .trim_end_matches('/');
    let server = match server.contains("://") || server.starts_with("//") {
        true => server.to_string(),
        false => format!("//{server}"),
    };
    let anchor = match id.is_empty() {
        true => String::new(),
        false => format!("#{id}"),
    };
    Some(format!("{server}/target/target-script-min.js{anchor}"))
}

/// Inject `tag` into HTML: before `</head>`, else after `<body>`, else prepend.
pub(super) fn inject_into_html(body: &Bytes, tag: &str) -> Bytes {
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

#[cfg(test)]
pub(super) mod forced_encoding_tests {
    use super::super::*;

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
            stream_replace(
                &resolved_for("reqHeaders://x=1"),
                Some("text/event-stream"),
                None
            )
            .is_none(),
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
        assert!(
            stream_injection(&resolved_for("reqHeaders://x=1"), Some("text/event-stream"))
                .is_none()
        );
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
        let ops = ops_ct("reqHeaders://x=1", true, html);
        assert!(must_collect_body(&ops, true, false, html));
    }

    /// The one door an event stream may pass through. A plugin that replaced
    /// the body outright hands over bytes that are already in hand, so the
    /// origin's stream is never awaited and nothing is withheld.
    #[test]
    fn an_overridden_body_is_collected_even_for_an_event_stream() {
        let sse = Some("text/event-stream");
        let ops = ops_ct("reqHeaders://x=1", true, sse);
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
        assert!(!ops("reqHeaders://x=1", true).needs_body());
    }

    /// `log://` collects a body only where its script has somewhere to go: a
    /// page or a script. A rule over a whole host matches its images and its
    /// downloads too, and those keep streaming.
    #[test]
    fn a_log_rule_collects_pages_and_scripts_and_nothing_else() {
        for (ct, collected) in [
            ("text/html; charset=utf-8", true),
            ("application/javascript", true),
            ("image/png", false),
            ("application/octet-stream", false),
            ("application/json", false),
            ("text/event-stream", false),
        ] {
            assert_eq!(
                ops_ct("log://app", true, Some(ct)).needs_body(),
                collected,
                "{ct}"
            );
        }
        // A body already in hand is looked at when it is injected.
        assert!(ops("log://app", true).log.is_some());
        // Nothing to inject into a response with no body.
        assert!(ops("log://app", false).log.is_none());
        // `disable://interceptConsole` is read off the same request.
        let quiet = ops("log://app disable://interceptConsole", true)
            .log
            .expect("a rule");
        assert!(!quiet.intercept_console);
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

#[cfg(test)]
pub(super) mod body_gate_tests {
    /// A response with no body is not a response to inject into. whistle's
    /// `hasBody` (`_original/lib/util/common.js:370-380`) excludes a `HEAD`
    /// answer, 1xx, 204 and every 3xx — and a redirect that arrives with an
    /// injected body, a stripped `Content-Length`, `Cache-Control: no-store` and
    /// no CSP is not the redirect the origin sent.
    #[test]
    fn only_a_response_that_carries_a_body_may_be_rewritten() {
        use super::super::response_has_body;

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
pub(super) mod trailer_tests {
    use super::super::*;
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
pub(super) mod local_response_tests {
    use super::super::*;

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
                if !state.plugins.reachable(&m.name) {
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
