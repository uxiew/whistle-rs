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
    "internal-http-proxy",
    "internal-https-proxy",
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
    "locationHref",
    "statusCode",
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
    "delete",
    "headerReplace",
    "enable",
    "disable",
    "pipe",
];

/// Alias protocol names → their canonical operator (`aliasProtocols` in the
/// original `protocols.js`). Rules may use either the alias or the canonical
/// name; we normalise to the canonical name at parse time so the apply layer
/// only ever deals with one spelling.
pub fn canonical(name: &str) -> Option<&'static str> {
    Some(match name {
        "hosts" | "xhost" => "host",
        "html" => "htmlAppend",
        "js" => "jsAppend",
        "css" => "cssAppend",
        "download" => "attachment",
        "status" => "statusCode",
        "skip" => "ignore",
        "tlsOptions" => "cipher",
        "pathReplace" => "urlReplace",
        "reqMerge" => "params",
        "resRules" => "resScript",
        "ruleFile" | "ruleScript" | "rulesScript" | "reqScript" | "reqRules" => "rulesFile",
        "P" => "G",
        // `x`-prefixed proxy variants (whistle's tunnel proxies) are approximated
        // by their base proxy — the transparent-tunnel nuance is not replicated.
        "xproxy" => "proxy",
        "xhttp-proxy" => "http-proxy",
        "xhttps-proxy" => "https-proxy",
        "xsocks" => "socks",
        "xinternal-proxy" => "internal-proxy",
        _ => return None,
    })
}

/// The local-file / template protocol family, matched dynamically by whistle's
/// `RULE_RE` (`/^(?:|x|xs)(?:file|rawfile|dust|tpl|jsonp):/`) rather than listed
/// in the `protocols` array. Returns true for `file`, `rawfile`, `dust`, `tpl`,
/// `jsonp` and their `x`/`xs` prefixed fallback variants.
pub fn is_file_protocol(name: &str) -> bool {
    let base = name
        .strip_prefix("xs")
        .or_else(|| name.strip_prefix('x'))
        .unwrap_or(name);
    matches!(base, "file" | "rawfile" | "dust" | "tpl" | "jsonp")
}

/// Returns true if `name` is a protocol whistle recognises (canonical, alias, or
/// a member of the local-file/template family).
pub fn is_protocol(name: &str) -> bool {
    PROTOCOLS.contains(&name) || canonical(name).is_some() || is_file_protocol(name)
}

/// Returns true if this protocol keeps every matching value (see [`MULTI_MATCH`]).
pub fn is_multi_match(name: &str) -> bool {
    MULTI_MATCH.contains(&name)
}
