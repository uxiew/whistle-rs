//! Pacing: `reqDelay://`, `resDelay://`, `reqSpeed://` and `resSpeed://`, read
//! the way whistle reads a number.

use super::*;

/// Milliseconds to delay before forwarding the request (`reqDelay`).
///
/// The delays and the speeds read their value **differently**, and the
/// difference is not a choice anyone made — it falls out of where each one is
/// used. A speed goes through `parseFloat` (`_original/lib/inspectors/res.js:914`),
/// which takes the longest numeric prefix, so `resSpeed://600kb` is 600. A delay
/// is never parsed at all: `exports.delay` compares the matcher's **string** to
/// zero, `if (time > 0)` (`_original/lib/util/index.js:3686-3691`), and
/// JavaScript's `>` converts that string with `Number`, which demands the whole
/// text be numeric. `'400' > 0` is true; `'400ms' > 0` is `NaN > 0`, which is
/// false, so a delay carrying its unit **does not delay**.
///
/// This port used `parseFloat` for both, so `reqDelay://400ms` waited 400 ms
/// here and nothing upstream. Measured on the timing bench, which is the only
/// place a delay is visible at all.
pub fn req_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved
        .value("reqDelay")
        .and_then(js_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Milliseconds to delay before returning the response (`resDelay`).
pub fn res_delay_ms(resolved: &Resolved) -> Option<u64> {
    resolved
        .value("resDelay")
        .and_then(js_number)
        .filter(|ms| *ms > 0.0)
        .map(|ms| ms as u64)
}

/// Request-body throughput cap in kilobits/s (`reqSpeed`) — see
/// [`super::super::body::throttled`] for why the unit is bits.
///
/// Only a **positive** rate is a cap. Upstream gates both speeds on
/// `if (reqSpeed > 0)` / `if (resSpeed > 0)`
/// (`_original/lib/inspectors/req.js:523-527`, `res.js:913-917`), so `0` and a
/// negative value mean *no throttle*, the same way `reqDelay://0` means no
/// delay. Without this filter `resSpeed://0` reached [`super::super::body::throttled`],
/// whose `.max(1.0)` floor turned it into one byte per 50 ms — 20 B/s, or four
/// hours for a 300 KB body. A value meaning "no limit" became the slowest limit
/// expressible, which reads to a client as a hang.
pub fn req_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved
        .value("reqSpeed")
        .and_then(parse_leading_number)
        .filter(|rate| *rate > 0.0)
}

/// Response-body throughput cap in kilobits/s (`resSpeed`).
pub fn res_speed_kbps(resolved: &Resolved) -> Option<f64> {
    resolved
        .value("resSpeed")
        .and_then(parse_leading_number)
        .filter(|rate| *rate > 0.0)
}

/// JavaScript's `Number(string)`: the whole text, or nothing.
///
/// Returns `None` where JavaScript would give `NaN`, which is what a caller
/// comparing `> 0` needs — every comparison against `NaN` is false.
///
/// The three shapes `Number` accepts that a plain float parse does not, and the
/// two it rejects that Rust's does:
///
/// * an empty or all-whitespace string is **zero**, not an error;
/// * `0x` / `0o` / `0b` are read in their radix, but only unsigned —
///   `Number('-0x10')` is `NaN`;
/// * `Infinity` is spelled exactly that way, capital `I`, optionally signed.
///   Rust also accepts `inf`, `infinity` and `nan`, which JavaScript does not,
///   so anything else carrying a letter besides an exponent's `e` is rejected.
///
/// Only the delays use this; see [`req_delay_ms`] for why they and the speeds
/// read their values differently.
pub(super) fn js_number(value: &str) -> Option<f64> {
    let text = value.trim();
    if text.is_empty() {
        return Some(0.0);
    }
    match text {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok().map(|n| n as f64);
    }
    if let Some(rest) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        return u64::from_str_radix(rest, 8).ok().map(|n| n as f64);
    }
    if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        return u64::from_str_radix(rest, 2).ok().map(|n| n as f64);
    }
    // `inf`, `infinity` and `nan` parse in Rust and are `NaN` in JavaScript.
    if text
        .chars()
        .any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E')
    {
        return None;
    }
    text.parse().ok().filter(|n: &f64| !n.is_nan())
}

/// JavaScript's `parseFloat`: the longest numeric prefix, ignoring whatever
/// follows.
///
/// whistle reads the **speeds** this way — `resSpeed = resSpeed &&
/// parseFloat(resSpeed)` (`_original/lib/inspectors/res.js:914`,
/// `req.js:524`) — so `resSpeed://20kb` is 20 there. Rust's `parse` rejects it
/// outright, which turned a value with a unit suffix — the way anyone would
/// first write one — into no throttle at all.
///
/// The delays do **not** go through here; see [`js_number`].
pub(super) fn parse_leading_number(value: &str) -> Option<f64> {
    let text = value.trim();
    let end = text
        .char_indices()
        .take_while(|(i, c)| {
            c.is_ascii_digit() || *c == '.' || (*i == 0 && (*c == '-' || *c == '+'))
        })
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    text[..end].parse().ok()
}
