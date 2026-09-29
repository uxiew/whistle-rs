//! Where `reqWrite://`, `resWrite://` and their `Raw` forms write a request or
//! response to, and whether `enable://forceReqWrite` lets them overwrite a file
//! that is already there.

use super::*;

/// File to write the request body to (`reqWrite`), or `None` when the method
/// carries no body.
///
/// The gate is upstream's: `util.hasRequestBody(req) ? getWriteFilePath(…) :
/// null` (`_original/lib/inspectors/req.js:582-584`). Without it a `GET` through
/// a `reqWrite://` rule created an empty file, which reads as "the capture
/// worked and the request had no body" rather than "there was never a body to
/// capture".
pub fn req_write_path(resolved: &Resolved, method: &str) -> Option<String> {
    method_allows_body(method)
        .then(|| resolved.value("reqWrite"))?
        .map(dump_path)
}

/// File to write the response body to (`resWrite`), named for the status.
pub fn res_write_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved
        .value("resWrite")
        .map(|f| writer_file(&dump_path(f), status))
}

/// File to write the raw request (head + body) to (`reqWriteRaw`).
///
/// Not gated on the method: the head is worth dumping whether or not a body
/// followed it, and upstream does not gate it either (`req.js:586`).
pub fn req_write_raw_path(resolved: &Resolved) -> Option<String> {
    resolved.value("reqWriteRaw").map(dump_path)
}

/// File to write the raw response (head + body) to (`resWriteRaw`), named for
/// the status.
pub fn res_write_raw_path(resolved: &Resolved, status: u16) -> Option<String> {
    resolved
        .value("resWriteRaw")
        .map(|f| writer_file(&dump_path(f), status))
}

/// A dump operator's value as a filesystem path.
///
/// Two things the matcher's tail-join leaves behind, both removed by upstream's
/// `getPath` before the path is opened (`_original/lib/util/index.js:1461-1464`,
/// via `getPath` at `:1420-1433`):
///
/// * **the query.** `resWrite://…/d` on a request for `/echo?q=1` writes `d/echo`
///   upstream; this port wrote a file literally named `echo?q=1`.
/// * **`<verbatim>` brackets.** They are the documented way to refuse the join,
///   and unwrapping them is what makes the refusal mean a path rather than a
///   filename with angle brackets in it — which is what this port tried to open,
///   so nothing was written at all.
pub(super) fn dump_path(value: &str) -> String {
    let text =
        crate::rules::url::fixed_value(value).map_or_else(|| value.to_string(), |(_, inner)| inner);
    match text.find('?') {
        Some(i) => text[..i].to_string(),
        None => text,
    }
}

/// `getWriterFile` (`_original/lib/inspectors/res.js:147-153`): a response that
/// is not a `200` is written to `<file>.<status>` instead.
///
/// The point is that a rule left running collects its failures separately —
/// a run of 502s lands in `dump.502` rather than overwriting the good capture
/// in `dump`, which is exactly when you want both.
pub(super) fn writer_file(file: &str, status: u16) -> String {
    match status {
        200 => file.to_string(),
        other => format!("{file}.{other}"),
    }
}

/// `enable://forceReqWrite` — write a dump file even though it already exists.
///
/// One flag for all four operators: upstream passes `isEnable(req,
/// 'forceReqWrite')` as the `force` argument on both the request side
/// (`_original/lib/inspectors/req.js:601`) and the response side
/// (`res.js:1304`), despite the name.
pub fn forces_write(resolved: &Resolved) -> bool {
    is_enabled(resolved, "forceReqWrite") && !disabled_flags(resolved).contains("forceReqWrite")
}
