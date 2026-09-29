//! Caching: `cache://` on a response, `disable://cache` on either side, and the
//! rule that a response-body operator busts the request cache by itself — a
//! `304` would otherwise hand the browser a body the operator never touched.

use super::*;

/// Make a request unconditional: drop the validators that let an origin answer
/// `304 Not Modified` (`disableReqCache`, `_original/lib/util/index.js:974-982`).
///
/// A `304` has no body, so anything meant to rewrite one has nothing to work on.
/// That is why whistle applies this whenever a **response-body operator**
/// matched, not only for `disable://cache` — see [`res_body_forbids_cache`].
pub(super) fn disable_req_cache(headers: &mut HeaderMap) {
    for name in [
        "if-modified-since",
        "if-none-match",
        "last-modified",
        "etag",
    ] {
        headers.remove(name);
    }
    set_header(headers, "pragma", "no-cache");
    set_header(headers, "cache-control", "no-cache");
}

/// The response-body operators that make a conditional request unanswerable
/// (`BODY_PROTOCOLS` + `notAllowCache`, `_original/lib/inspectors/res.js:33-60`,
/// applied at `res.js:1328`).
///
/// Without this a rule works on the first load and silently stops working on a
/// reload, because the origin answers `304` and there is no body to rewrite —
/// intermittent in exactly the way that reads as a bug in the proxy.
pub(super) const BODY_PROTOCOLS: &[&str] = &[
    "attachment",
    "resReplace",
    "resBody",
    "resPrepend",
    "resAppend",
    "htmlBody",
    "htmlPrepend",
    "htmlAppend",
    "jsBody",
    "jsPrepend",
    "jsAppend",
    "cssBody",
    "cssPrepend",
    "cssAppend",
    "resWrite",
    "resWriteRaw",
    "resMerge",
];

/// The two tool protocols that inject a script into an HTML response, and so
/// need one to inject into.
///
/// Upstream busts the cache for these the moment the rule matches
/// (`util.disableReqCache(req.headers)`, `_original/lib/inspectors/log.js:30`
/// and `weinre.js:26`) — and unlike `notAllowCache`, which reads the response
/// phase's protocols from the request pass and therefore never fires, these two
/// are request-phase and really do run. Measured against whistle 2.10.8: a
/// `log://` rule reaches the origin with `pragma: no-cache`.
pub(super) const SCRIPT_INJECTORS: &[&str] = &["log", "weinre"];

/// True when a rule on this request will want to rewrite or inject into the
/// response body, and therefore cannot tolerate a `304`.
/// See [`BODY_PROTOCOLS`] and [`SCRIPT_INJECTORS`].
pub(super) fn res_body_forbids_cache(resolved: &Resolved) -> bool {
    BODY_PROTOCOLS
        .iter()
        .chain(SCRIPT_INJECTORS)
        .any(|p| resolved.value(p).is_some())
}

/// `cache://` — `Cache-Control` plus the `Expires`/`Pragma` pair whistle always
/// writes with it (`_original/lib/inspectors/res.js:877-897`).
///
/// The accepted spellings are narrow: `no`, `no-cache`, `no-store` (any case) or
/// a leading integer. `cache://reserve`/`keep` mean "leave the upstream headers
/// alone", and anything else — `cache://off`, say — is silently ignored rather
/// than passed through as a header value.
pub(super) fn apply_cache(headers: &mut HeaderMap, resolved: &Resolved) {
    let Some(value) = resolved.value("cache").map(str::trim) else {
        return;
    };
    if value == "reserve" || value == "keep" {
        return;
    }
    // `parseInt` reads a leading integer and ignores the rest, so `cache://60s`
    // is a minute.
    let max_age = parse_leading_int(value);
    let lower = value.to_ascii_lowercase();
    let no_cache =
        matches!(lower.as_str(), "no" | "no-cache" | "no-store") || max_age.is_some_and(|n| n < 0);
    // Neither a no-cache spelling nor a usable max-age: nothing to write.
    if !no_cache && max_age.is_none_or(|n| n < 0) {
        return;
    }
    let cache_control = match (no_cache, lower == "no-store") {
        (true, true) => "no-store".to_string(),
        (true, false) => "no-cache".to_string(),
        (false, _) => format!("max-age={}", max_age.unwrap_or(0)),
    };
    set_header(headers, "cache-control", &cache_control);
    set_header(headers, "pragma", if no_cache { "no-cache" } else { "" });
    let offset = match no_cache {
        true => -60_000_000,
        false => max_age.unwrap_or(0).saturating_mul(1000),
    };
    set_header(headers, "expires", &http_date(offset));
}

/// The leading integer of `value`, as JavaScript's `parseInt` reads it.
pub(super) fn parse_leading_int(value: &str) -> Option<i64> {
    let digits = value
        .strip_prefix(['+', '-'])
        .unwrap_or(value)
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let end = usize::from(value.starts_with(['+', '-'])) + digits;
    value.get(..end.min(value.len()))?.parse().ok()
}

/// `cache://reserve`/`keep` and `enable://keepAllCache` mark the response's
/// caching as deliberate, which stops the injection pass from overriding it
/// (`req._customCache`, `_original/lib/inspectors/res.js:878-881`).
pub(super) fn custom_cache(resolved: &Resolved) -> bool {
    if is_enabled(resolved, "keepAllCache") {
        return true;
    }
    match resolved.value("cache").map(str::trim) {
        Some("reserve") | Some("keep") => true,
        Some(value) => {
            let lower = value.to_ascii_lowercase();
            matches!(lower.as_str(), "no" | "no-cache" | "no-store")
                || parse_leading_int(value).is_some()
        }
        None => false,
    }
}

/// An RFC 1123 date `offset` milliseconds from now, as `Date#toGMTString`
/// renders it.
pub(super) fn http_date(offset: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = now + offset / 1000;
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let (h, m, s) = (time / 3600, (time % 3600) / 60, time % 60);
    let weekday = DAYS[(days + 4).rem_euclid(7) as usize];
    let (year, month, day) = civil_from_days(days);
    format!(
        "{weekday}, {day:02} {} {year} {h:02}:{m:02}:{s:02} GMT",
        MONTHS[(month - 1) as usize]
    )
}

/// Days since the Unix epoch → `(year, month, day)`. Howard Hinnant's
/// `civil_from_days`, which is exact for the whole range we can produce.
pub(super) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}
