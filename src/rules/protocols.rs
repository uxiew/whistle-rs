//! Protocol registry, ported from `_original/lib/rules/protocols.js`.
//!
//! The full whistle protocol list is preserved so that rule parsing recognises
//! the same set of operators. Not every protocol has runtime behaviour wired up
//! yet in the Rust core (see `crate::proxy::apply`); unknown-but-listed
//! protocols still parse and are exposed on the resolved rule set.

/// Every protocol name whistle understands (order preserved from the original).
pub const PROTOCOLS: &[&str] = &[
    "G",
    "style",
    "host",
    "rule",
    "pipe",
    "weinre",
    "proxy",
    "https2http-proxy",
    "http2https-proxy",
    "internal-proxy",
    "pac",
    "filter",
    "ignore",
    "enable",
    "disable",
    "delete",
    "log",
    "plugin",
    "referer",
    "auth",
    "ua",
    "urlParams",
    "params",
    "resMerge",
    "replaceStatus",
    "method",
    "cache",
    "attachment",
    "forwardedFor",
    "responseFor",
    "rulesFile",
    "resScript",
    "frameScript",
    "reqDelay",
    "resDelay",
    "headerReplace",
    "reqSpeed",
    "resSpeed",
    "reqType",
    "resType",
    "reqCharset",
    "resCharset",
    "reqCookies",
    "resCookies",
    "reqCors",
    "resCors",
    "reqHeaders",
    "resHeaders",
    "trailers",
    "reqPrepend",
    "resPrepend",
    "reqBody",
    "resBody",
    "reqAppend",
    "resAppend",
    "urlReplace",
    "reqReplace",
    "resReplace",
    "reqWrite",
    "resWrite",
    "reqWriteRaw",
    "resWriteRaw",
    "cssAppend",
    "htmlAppend",
    "jsAppend",
    "cssBody",
    "htmlBody",
    "jsBody",
    "cssPrepend",
    "htmlPrepend",
    "jsPrepend",
    "cipher",
    "sniCallback",
    // Common aliases / additional operators handled by the core.
    "redirect",
    "location",
    "statusCode",
    "https",
    "http",
    "socks",
    "http-proxy",
    "https-proxy",
    "file",
    "rawfile",
    "tpl",
    "jsonp",
    "xfile",
    "xrawfile",
];

/// whistle's "tool" protocols (`_original/lib/rules/protocols.js:73`).
pub const TOOL_PROTOCOLS: &[&str] = &["log", "weinre"];

/// Protocols that may legitimately appear multiple times in a resolved set
/// (`multiMatchs` in the original). We keep every matching value for these
/// instead of first-match-wins.
pub const MULTI_MATCH: &[&str] = &[
    "plugin",
    "reqHeaders",
    "resHeaders",
    "reqCookies",
    "resCookies",
    "reqCors",
    "resCors",
    "trailers",
    "log",
    "params",
    "urlParams",
    "ignore",
];

/// Returns true if `name` is a protocol whistle recognises.
pub fn is_protocol(name: &str) -> bool {
    PROTOCOLS.contains(&name)
}

/// Returns true if this protocol keeps every matching value (see [`MULTI_MATCH`]).
pub fn is_multi_match(name: &str) -> bool {
    MULTI_MATCH.contains(&name)
}
