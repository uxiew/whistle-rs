//! `enable://` and `disable://` read as sets of flags, and the questions other
//! code asks of them: is the request hidden from the capture, aborted on either
//! side, paused or ignored on a WebSocket, forced to an encoding.

use super::*;

/// Collect flag names from `enable`/`disable` operators.
///
/// The separators are `|` and `&` — upstream's `parseProps`
/// (`_original/lib/util/common.js:72,98`) recognises no others, so a
/// comma-separated list is one long flag name in both implementations.
pub(super) fn flag_set(resolved: &Resolved, protocol: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for v in collect_values(resolved, protocol) {
        for f in parse_props(v) {
            let f = f.trim().to_string();
            if !f.is_empty() {
                set.insert(f);
            }
        }
    }
    set
}

/// Split a prop list on `|` and `&`, honouring the escapes upstream honours.
///
/// `parseProps` (`_original/lib/util/common.js:73,:111-127`) is a single
/// regexp — `/(\\*)([|&]|\\[stnrfv])/g` — over the whole value, and it does two
/// things at once:
///
/// * a separator preceded by an **odd** number of backslashes is a literal
///   `|` or `&` rather than a split, and the run is halved;
/// * `\s`, `\t`, `\n`, `\r`, `\f` and `\v` become the characters they name —
///   which is how `delete://reqBody.a\nb` addresses a key with a newline in it.
///
/// `delete://` and the two flag families take this road; `lineProps://` takes
/// the plain `SEP_RE` split with no escapes at all (`index.js:1898`), which is
/// a difference `docs/LINE_PROPS.md` already records.
pub(crate) fn parse_props(value: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            match c {
                '|' | '&' => out.push(String::new()),
                _ => out.last_mut().expect("never empty").push(c),
            }
            continue;
        }
        // The run of backslashes, and then what it applies to.
        let mut run = 1;
        while chars.next_if_eq(&'\\').is_some() {
            run += 1;
        }
        let kept = "\\".repeat(run / 2);
        let tail = out.last_mut().expect("never empty");
        match chars.peek() {
            // `\<sep>`: odd keeps the separator as text, even splits.
            Some('|' | '&') => {
                let sep = chars.next().expect("peeked");
                tail.push_str(&kept);
                match run % 2 {
                    1 => tail.push(sep),
                    _ => out.push(String::new()),
                }
            }
            // `\s` and friends: the run is counted **with** the escape's own
            // backslash, so an even run leaves the letter and an odd one
            // replaces it with the character it names.
            Some(&letter) if matches!(letter, 's' | 't' | 'n' | 'r' | 'f' | 'v') => {
                chars.next();
                let kept = "\\".repeat(run.div_ceil(2) - usize::from(run % 2 == 1));
                tail.push_str(&kept);
                match run % 2 {
                    1 => tail.push(match letter {
                        's' => ' ',
                        't' => '\t',
                        'n' => '\n',
                        'r' => '\r',
                        'f' => '\u{c}',
                        _ => '\u{b}',
                    }),
                    _ => tail.push(letter),
                }
            }
            // Anything else: the backslashes are text, untouched — the regexp
            // did not match, so nothing was halved.
            _ => tail.push_str(&"\\".repeat(run)),
        }
    }
    out
}

/// `enable://` flags for a request.
pub fn enabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "enable")
}

/// `disable://` flags for a request.
pub fn disabled_flags(resolved: &Resolved) -> std::collections::HashSet<String> {
    flag_set(resolved, "disable")
}

/// Is this transaction hidden from the capture?
///
/// `checkHideProp` (`_original/lib/util/index.js:3982-3987`) reads four flags,
/// not one: `enable://hide` and `disable://show` hide, and `enable://show` and
/// `disable://hide` un-hide, with the un-hiding half winning. The pair exists
/// because the flags usually arrive from different lines — a broad
/// `enable://hide` over a domain, an `enable://show` on the one request being
/// looked at.
///
/// Taken as two sets rather than as a `Resolved`, because the same question is
/// asked of a recorded session, whose flags have already been flattened.
pub fn hides_capture(
    enabled: &std::collections::HashSet<String>,
    disabled: &std::collections::HashSet<String>,
) -> bool {
    (enabled.contains("hide") || disabled.contains("show"))
        && !enabled.contains("show")
        && !disabled.contains("hide")
}

/// [`hides_capture`], asked of a request's resolved rules.
pub fn hidden_from_capture(resolved: &Resolved) -> bool {
    hides_capture(&enabled_flags(resolved), &disabled_flags(resolved))
}

/// `enable://<flag>` — cancelled by a `disable://<flag>` on the same request.
///
/// Upstream's `isEnable` is `req.enable[name] && !req.disable[name]`
/// (`_original/lib/util/index.js:678-680`), and its mirror `isDisable` is the
/// same expression the other way round. This port had only the mirror: every
/// flag was read as `enabled_flags(…).contains(…)`, so `enable://keepCSP
/// disable://keepCSP` kept the CSP here and stripped it upstream — and the same
/// omission applied to all sixteen reads, not just that one.
///
/// The two together mean a name written on both sides does **nothing**, which
/// is the only reading under which `enable`/`disable` compose predictably: the
/// answer does not depend on which was written first, or on which of the two
/// the code happens to consult.
/// **Not every flag is read this way**, and the three exceptions are upstream's,
/// found by checking each name's reader rather than assuming they share one:
/// `showHost` is a bare `req._filters.showHost || enable.showHost`
/// (`_original/lib/inspectors/res.js:1193`), `userLogin` goes through a bespoke
/// helper where `enable` wins over `disable` (`util/index.js:3557-3562`), and
/// `cors` has no `enable` reader upstream at all. Those three keep the direct
/// read. A blanket conversion broke the second of them and an existing test
/// caught it — the test had the real semantics pinned.
pub(crate) fn is_enabled(resolved: &Resolved, flag: &str) -> bool {
    enabled_flags(resolved).contains(flag) && !disabled_flags(resolved).contains(flag)
}

/// `disable://<flag>` — with the escape hatch upstream gives it: an
/// `enable://<flag>` on the same request wins (`isDisable`,
/// `_original/lib/util/index.js:681-683`).
pub(crate) fn is_disabled(resolved: &Resolved, flag: &str) -> bool {
    disabled_flags(resolved).contains(flag) && !enabled_flags(resolved).contains(flag)
}

/// `enable://ignoreSend` / `enable://ignoreReceive` — drop every data frame of
/// one direction of a WebSocket session (`initStatus`,
/// `_original/lib/socket-mgr.js:86-97`).
///
/// The frame is still *captured*: upstream records it with `ignore: true` so the
/// Network view shows what was discarded rather than a silent gap
/// (`socket-mgr.js:401,:531`). Discarding a frame without saying so would make a
/// session look like the peer never sent anything.
///
/// A direction `pauseSend`/`pauseReceive` also names is **not** reported as
/// ignored: upstream reads the two flags as one status per direction and takes
/// the pause branch first (`if (enable.pauseSend) … else if (enable.ignoreSend)`,
/// `initStatus`, `_original/lib/socket-mgr.js:86-97`), so the flags cannot both
/// apply. See [`paused_ws_dirs`].
pub fn ignored_ws_dirs(resolved: &Resolved) -> (bool, bool) {
    let e = enabled_flags(resolved);
    let (pause_send, pause_receive) = paused_ws_dirs(resolved);
    (
        e.contains("ignoreSend") && !pause_send,
        e.contains("ignoreReceive") && !pause_receive,
    )
}

/// `enable://pauseSend` / `enable://pauseReceive` — hold one direction of a
/// WebSocket session instead of delivering it, until someone releases it
/// (`PAUSE_STATUS`, `initStatus`, `_original/lib/socket-mgr.js:13,:86-97`).
///
/// A pause is only half a feature without the release: upstream's console sets
/// the direction back to 0 through `/cgi-bin/socket/change-status`
/// (`changeStatus`, `socket-mgr.js:907-918`), and this port answers
/// `POST /api/ws/release` for the same purpose. Held frames are captured and
/// flagged as they arrive, so the console can show what is waiting rather than
/// only that something is.
pub fn paused_ws_dirs(resolved: &Resolved) -> (bool, bool) {
    let e = enabled_flags(resolved);
    (e.contains("pauseSend"), e.contains("pauseReceive"))
}

/// `disable://ping` / `disable://pong` — suppress the keep-alive the proxy
/// writes on a direction it is holding, as `(ping, pong)`.
///
/// Upstream guards each leg with its own flag: the pong that goes to the
/// **server** while the client's send direction is held is `disable.pong`
/// (`res.write(PONG)`, `_original/lib/socket-mgr.js:366-368`), and the ping that
/// goes to the **client** while the receive direction is held is `disable.ping`
/// (`req.write(PING)`, `:496-498`). Read straight off `disable`, without the
/// `enable://` cancellation, which is how upstream reads them.
///
/// These meant nothing here until there was a keep-alive to suppress — the
/// port used to inject none, so `docs/ROADMAP.md` recorded them as having
/// nothing to disable. Holding a direction brought one, and with it these.
pub fn ws_keepalive_disabled(resolved: &Resolved) -> (bool, bool) {
    let d = disabled_flags(resolved);
    (d.contains("ping"), d.contains("pong"))
}

/// True when the request must be destroyed **before** it is sent
/// (`needAbortReq`, `_original/lib/util/index.js:3893-3903`, applied from the
/// `data` inspector at `_original/lib/inspectors/data.js:534-539` — which runs
/// before `res`, so an abort here means the origin is never contacted).
///
/// `abortRes` is deliberately absent: it lets the request go out and destroys
/// the answer instead — see [`aborts_response`].
pub fn aborts_request(resolved: &Resolved) -> bool {
    aborts(resolved, "abortReq")
}

/// True when the response must be destroyed **after** its head has arrived
/// (`needAbortRes`, `_original/lib/util/index.js:3905-3915`, applied at
/// `_original/lib/inspectors/res.js:1175-1179`, after `resDelay://`).
pub fn aborts_response(resolved: &Resolved) -> bool {
    aborts(resolved, "abortRes")
}

/// The shape both abort gates share: a `disable://` of either spelling cancels
/// the abort outright, and only then does an `enable://` arm it.
///
/// The `disable://` arm is the half this port was missing, which made
/// `enable://abort` unconditional — a rule you could arm on a whole domain and
/// then not exempt one path from.
///
/// Upstream also arms on `req._filters.abort`, set by a `filter://abort` line.
/// This port reads `filter://` only as a match condition (`src/rules/mod.rs`),
/// so there is no filter bag to consult; `enable://` is the whole vocabulary
/// here.
pub(super) fn aborts(resolved: &Resolved, side: &str) -> bool {
    let dis = disabled_flags(resolved);
    if dis.contains("abort") || dis.contains(side) {
        return false;
    }
    let en = enabled_flags(resolved);
    en.contains("abort") || en.contains(side)
}

/// The coding an `enable://gzip|br|deflate` flag demands the response leave under,
/// or `None` when no such flag is set (`getEnableEncoding`,
/// `_original/lib/util/index.js:1534-1548`).
///
/// The precedence is upstream's — `br` beats `gzip` beats `deflate` — and it is
/// the one case where a body that arrived uncompressed goes out compressed. The
/// caller hands this to [`coding::reencode`], which lets it win over the body's
/// own coding.
pub fn forced_encoding(resolved: &Resolved) -> Option<super::super::coding::Coding> {
    let e = enabled_flags(resolved);
    if e.contains("br") {
        Some(super::super::coding::Coding::Brotli)
    } else if e.contains("gzip") {
        Some(super::super::coding::Coding::Gzip)
    } else if e.contains("deflate") {
        Some(super::super::coding::Coding::Deflate)
    } else {
        None
    }
}
