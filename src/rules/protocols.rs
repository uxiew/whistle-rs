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

/// The protocol key a **URL-replacement** rule resolves to.
///
/// whistle has no operator name for this one: you write a destination URL and it
/// lands in the `rule` list because `rules[protocol]` came back undefined
/// (`_original/lib/rules/rules.js:1313-1316`). Its resolved URL then replaces
/// the request's own — scheme, host, port, path and query
/// (`util.rule.getUrl(req.rules.rule)` → `req.options`,
/// `lib/inspectors/rules.js:40-44`). It is how `www.example.com
/// http://localhost:5173` forwards a site to a dev server, and it differs from
/// [`host`](crate::proxy::apply::resolve_target) in exactly that breadth: `host://`
/// moves the socket and keeps the `Host` header, a URL replacement moves both.
///
/// **One spelling is this port's own.** A rule written literally as
/// `rule://<name>` pulls in the named entry of the values store as *more rules*
/// (see [`crate::proxy::apply::merge_included_rules`]) instead of naming a
/// destination. Upstream files that spelling here too, where it can only ever
/// produce the unusable URL `rule://<name>`, so the divergence costs no rule
/// that works upstream — and `ignore://rule` still drops both readings.
pub const URL_REPLACE: &str = "rule";

/// Every upstream-proxy operator, in the order this port prefers them.
///
/// whistle files all of them under one protocol key. A `socks://` line and a
/// `proxy://` line both land in `_rules.proxy`, and the spelling survives only
/// inside the stored matcher (`_original/lib/rules/rules.js:1305-1310`,
/// `:1368-1388`). Two consequences follow from that, and both are behaviour:
///
/// * at most one upstream proxy can be in play, so the order here is a
///   precedence order, not a list of independent operators;
/// * `ignore://proxy` names the *family*, so it drops whichever one matched —
///   `util.isIgnored(filter, 'proxy')` in `resolveProxy`
///   (`_original/lib/rules/rules.js:2419-2443`). Naming one spelling
///   (`ignore://socks`) drops only that one.
///
/// This port keeps a separate key per protocol, which is why the family has to
/// be written down. The `x`/`xs` spellings are absent because [`canonical`] has
/// already folded them into their base protocol by the time a rule resolves.
pub const UPSTREAM_PROXY_PROTOCOLS: &[&str] = &[
    "socks",
    "https-proxy",
    "http-proxy",
    "proxy",
    "internal-https-proxy",
    "internal-proxy",
    "internal-http-proxy",
    "https2http-proxy",
    "http2https-proxy",
];

/// whistle's "tool" protocols (`_original/lib/rules/protocols.js:73`).
pub const TOOL_PROTOCOLS: &[&str] = &["log", "weinre"];

/// The operators whistle decides in the **response** phase — `pureResProtocols`
/// (`_original/lib/rules/protocols.js:82-111`), which is `resProtocols` minus the
/// filtering machinery, plus [`TOOL_PROTOCOLS`].
///
/// Upstream resolves a request's rules twice and splits the protocol set between
/// the passes: `resolveReqRules` skips every name in this list
/// (`reqProtocols`, `protocols.js:156-158`) and `resolveResRules` resolves
/// *only* these (`rules.js:2234-2235`). So a rule's effect on the response is
/// always decided with the response head in hand.
///
/// This port resolves everything in the request pass and then re-resolves just
/// these names once the response head arrives — but only for the rules whose
/// filters actually ask about the response, which is what
/// [`crate::rules::Rule::needs_response_phase`] decides. See
/// [`crate::rules::matcher::resolve_response_refs`].
///
/// Names absent from upstream's list are absent here too, and the omissions are
/// deliberate: `statusCode`, `redirect`, `location` and `resScript` are req-phase
/// operators upstream, because they either answer the request without one being
/// sent or are needed before the response exists.
pub const RES_PHASE_PROTOCOLS: &[&str] = &[
    "replaceStatus",
    "cache",
    "attachment",
    "resMerge",
    "resDelay",
    "resSpeed",
    "resType",
    "resCharset",
    "resCookies",
    "resCors",
    "resHeaders",
    "trailers",
    "resPrepend",
    "resBody",
    "resAppend",
    "resReplace",
    "resWrite",
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
    "responseFor",
    // `.concat(toolProtocols)` — kept in sync with [`TOOL_PROTOCOLS`].
    "log",
    "weinre",
];

/// Is this operator decided in the response phase (see [`RES_PHASE_PROTOCOLS`])?
pub fn is_res_phase(name: &str) -> bool {
    RES_PHASE_PROTOCOLS.contains(&name)
}

/// May a rules text merged into the **response** set this operator?
///
/// `resProtocols` (`_original/lib/rules/protocols.js:112-120`) is
/// [`RES_PHASE_PROTOCOLS`] plus the filtering machinery, and it is what
/// `mergeRules(req, add, isResRules)` restricts itself to
/// (`_original/lib/util/index.js:2198-2203`). So a `host://` written inside a
/// `resRules://` text is parsed and then dropped: by the time the text is read
/// the request has already gone out.
pub fn is_res_protocol(name: &str) -> bool {
    is_res_phase(name)
        || matches!(
            name,
            "filter" | "enable" | "disable" | "ignore" | "style" | "delete" | "headerReplace"
        )
}

/// Protocols that may legitimately appear multiple times in a resolved set
/// (`multiMatchs`, `_original/lib/rules/protocols.js:186-226`). We keep every
/// matching value for these instead of first-match-wins.
///
/// Upstream keeps *both* views of such a protocol: `_rules[name]` is still the
/// first match, and `rule.list` carries every match
/// (`_original/lib/rules/rules.js:2240-2258`). [`crate::rules::Resolved`] does
/// the same — [`crate::rules::Resolved::value`] reads the winner,
/// [`crate::rules::Resolved::all`] the whole list — so listing a protocol here
/// only ever *adds* the accumulated view.
///
/// How several values combine is per family and lives in `crate::proxy::apply`:
/// the body operators CRLF-join, the `*Replace`/`*Merge` operators collapse into
/// one JSON object, and the header-shaped ones apply in turn.
pub const MULTI_MATCH: &[&str] = &[
    // ── upstream's `multiMatchs`, in its order ──
    "G",
    "ignore",
    "enable",
    "filter",
    "disable",
    "plugin",
    "delete",
    "style",
    "cipher",
    "trailers",
    "urlParams",
    "params",
    "headerReplace",
    "reqHeaders",
    "resHeaders",
    "reqCors",
    "resCors",
    "reqCookies",
    "resCookies",
    "reqReplace",
    "urlReplace",
    "resReplace",
    "resMerge",
    "reqBody",
    "reqPrepend",
    "resPrepend",
    "reqAppend",
    "resAppend",
    "resBody",
    "htmlAppend",
    "jsAppend",
    "cssAppend",
    "htmlBody",
    "jsBody",
    "cssBody",
    "htmlPrepend",
    "jsPrepend",
    "cssPrepend",
    "rulesFile",
    "resScript",
    // ── whistle-rs additions ──
    // Upstream resolves both of these to a single rule (`log` is absent from
    // `multiMatchs`; `pipe` is resolved by `resolveSingleRule`,
    // `_original/lib/rules/rules.js:2384`). This port lets them accumulate
    // because its own consumers are list-shaped: `log://` names a debug channel
    // and several may be attached at once, and `pipe://` feeds the plugin
    // matcher alongside `plugin://`.
    "log",
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
        // Every upstream-proxy name may carry an `x` prefix, which upstream
        // strips in one place — `PROXY_RE`'s optional `x?`, whose capture group
        // is the base name (`_original/lib/rules/rules.js:37-38`). Folding the
        // prefix here does not lose it: `RuleOp::raw` keeps the token exactly as
        // written, which is where the apply layer reads the `x` back to decide
        // what the prefix *means* for this proxy.
        //
        // Derived from `UPSTREAM_PROXY_PROTOCOLS` rather than spelled out, so a
        // name added to that list cannot end up recognised in its bare form and
        // unrecognised in its `x` one — which is how four of them
        // (`xinternal-http-proxy`, `xinternal-https-proxy`, `xhttps2http-proxy`,
        // `xhttp2https-proxy`) came to configure nothing at all.
        _ => return name.strip_prefix('x').and_then(x_proxy_base),
    })
}

/// The upstream-proxy protocol `base` names, when it is one — the `x`-stripped
/// half of [`canonical`]. Returns the `'static` spelling from
/// [`UPSTREAM_PROXY_PROTOCOLS`] so the canonical name outlives the input.
fn x_proxy_base(base: &str) -> Option<&'static str> {
    UPSTREAM_PROXY_PROTOCOLS
        .iter()
        .copied()
        .find(|proto| *proto == base)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every response-phase name has to be a protocol the parser recognises, or
    /// a rule writing it would never produce an operator to re-resolve.
    #[test]
    fn res_phase_protocols_are_all_known_protocols() {
        for name in RES_PHASE_PROTOCOLS {
            assert!(is_protocol(name), "{name} is not a known protocol");
            assert!(canonical(name).is_none(), "{name} should be canonical");
        }
    }

    /// **Every** upstream-proxy name has an `x`-prefixed spelling upstream, in
    /// one regexp with an optional `x?` (`PROXY_RE`,
    /// `_original/lib/rules/rules.js:37-38`).
    ///
    /// Four of them used to be missing from the hand-written list this replaced
    /// — `xinternal-http-proxy`, `xinternal-https-proxy`, `xhttps2http-proxy`,
    /// `xhttp2https-proxy` — and a name that does not canonicalise is not a
    /// protocol at all here (`is_protocol` consults `canonical`), so those rules
    /// produced no proxy operator and the request went **direct**.
    #[test]
    fn every_proxy_protocol_has_an_x_spelling() {
        for name in UPSTREAM_PROXY_PROTOCOLS {
            let x = format!("x{name}");
            assert_eq!(canonical(&x), Some(*name), "{x}");
            assert!(is_protocol(&x), "{x} is not a known protocol");
        }
        // The four the list used to miss, spelled out so a regression names
        // itself rather than hiding inside the loop above.
        for (x, base) in [
            ("xinternal-http-proxy", "internal-http-proxy"),
            ("xinternal-https-proxy", "internal-https-proxy"),
            ("xhttps2http-proxy", "https2http-proxy"),
            ("xhttp2https-proxy", "http2https-proxy"),
        ] {
            assert_eq!(canonical(x), Some(base), "{x}");
        }
        // The `x` fold reaches proxies only: it must not invent a protocol out
        // of any other name that happens to start with one.
        for name in ["xyz", "xfile", "x", "xhtml", "xstatus"] {
            assert_ne!(canonical(name), Some("proxy"), "{name}");
        }
        // `xhost` keeps its own explicit arm — `host` is not a proxy.
        assert_eq!(canonical("xhost"), Some("host"));
    }

    /// The tool protocols are part of the response phase upstream
    /// (`pureResProtocols.concat(toolProtocols)`), and both lists are written
    /// out here, so they can drift apart.
    #[test]
    fn tool_protocols_are_response_phase() {
        for name in TOOL_PROTOCOLS {
            assert!(is_res_phase(name), "{name} must be resolved in the res phase");
        }
    }
}
