//! Operator values that name a file or a URL instead of holding the value:
//! which operators may be loaded that way, and loading them all in one pass
//! before any rule is applied — upstream's `readRuleValue`.

use super::*;

/// The operators whose value upstream *reads* rather than uses
/// (`readRuleValue`, `_original/lib/util/index.js:1189-1213`), when that value
/// carries JSON or `k=v` pairs.
///
/// The set is not a property of the protocol table: it is whoever passes a rule
/// to `parseRuleJson`. Every caller in the tree contributes —
/// `_original/lib/inspectors/req.js:463-472` (`reqHeaders`, `reqCookies`,
/// `auth`, `params`, `reqCors`, `reqReplace`, `urlReplace`, `urlParams`),
/// `lib/inspectors/res.js:830-841` (`resHeaders`, `resCookies`, `resCors`,
/// `resReplace`, `resMerge`, `trailers`), `lib/rules/index.js:691` (`cipher`),
/// and the tunnel/HTTPS paths at `lib/tunnel.js:343,:752` and
/// `lib/https/index.js:671-680,:746`, which add no name the first two do not.
pub(super) const LOADABLE_JSON_OPS: &[&str] = &[
    "reqHeaders",
    "reqCookies",
    "auth",
    "params",
    "urlParams",
    "reqCors",
    "reqReplace",
    "urlReplace",
    "resHeaders",
    "resCookies",
    "resCors",
    "resReplace",
    "resMerge",
    "trailers",
    "cipher",
];

/// The operators whose value upstream reads as **content** — `getRuleValue`
/// (`_original/lib/util/index.js:1409-1416`), from
/// `lib/inspectors/req.js:545-548` and `lib/inspectors/res.js:984` — split by
/// whether a URL value means "fetch this" or "this URL".
///
/// `readRuleValue`'s `checkUrl` argument is what splits them: it is
/// `isJsHtml || isCssHtml` (`util/index.js:1339`), so for the `js*`/`css*`
/// families a URL value is handed back **as the URL** when the response is HTML
/// — that is how `jsAppend://https://cdn/a.js` becomes `<script src=…>`. On a
/// non-HTML response the same value is fetched and inlined instead. This port
/// cannot make that choice here: the loader runs in the request phase, before
/// there is a response to classify. So those two families load from a **file**
/// only, and a URL keeps the meaning this port already documents.
pub(super) const LOADABLE_TEXT_OPS: &[&str] = &[
    "reqBody",
    "reqPrepend",
    "reqAppend",
    "resBody",
    "resPrepend",
    "resAppend",
    "htmlBody",
    "htmlPrepend",
    "htmlAppend",
];

/// The operators whose loaded value is sent as bytes, not text — upstream's
/// `binProtocols` (`_original/lib/rules/protocols.js:121-128`), read with
/// `needRawData` (`util/index.js:1273-1274`). See [`RuleOp::value_bytes`].
pub(super) const BINARY_OPS: &[&str] = &[
    "reqBody",
    "reqPrepend",
    "reqAppend",
    "resBody",
    "resPrepend",
    "resAppend",
];

/// The `js*`/`css*` families: a file value loads, a URL value does not — see
/// [`LOADABLE_TEXT_OPS`].
pub(super) const LOADABLE_FILE_ONLY_OPS: &[&str] = &[
    "jsBody",
    "jsPrepend",
    "jsAppend",
    "cssBody",
    "cssPrepend",
    "cssAppend",
];

/// Where an operator's value says its content lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ValueSource {
    /// One or more local paths, `|`-separated as upstream's `readFileText` has
    /// them (`_original/lib/util/file-mgr.js:157-166`).
    File(String),
    /// An `http(s)://` URL, fetched once per matching request.
    Url(String),
}

/// The value of a loadable operator is a **location** only when it looks like
/// one: an `http(s)://` URL, or a path that starts at the root, the home
/// directory, a Windows drive, or an explicit `./` / `../`.
///
/// **Deliberately narrower than upstream, and the narrowing is the interesting
/// part.** whistle has no shape test at all: for the text operators *every*
/// non-inline value is a path, and for the JSON ones every value that is not
/// `{json}` and not `k=v`. A bare `resBody://patched` there is a read of
/// `./patched` relative to the rules file's root — `rule.root`, which only
/// exists for rules a plugin or an `@`-include brought in — or, with no root, to
/// whistle's own working directory. It fails, and the operator quietly sets an
/// empty body.
///
/// This port has no `rule.root` to resolve against, and a path relative to the
/// proxy's working directory is not something a rules file can rely on. So a
/// bare value stays the literal it already is here (`docs/RULES.md` documents
/// `resBody://` as taking replacement text), and every spelling that *works*
/// upstream — an absolute path, `~/…`, a URL — loads. The difference is
/// confined to values that upstream reads from a relative path, which is to say
/// values that upstream almost always fails to read.
///
/// The JSON operators additionally keep any value containing `=`: those pairs
/// are the operator's own syntax, and upstream reaches the same place by a
/// longer road — it reads the path, gets nothing, and then falls back to parsing
/// the matcher as a query string (`tryParseMatcher`,
/// `_original/lib/util/index.js:1165-1171,:1303`). Skipping the read that can
/// only fail is what keeps a `urlReplace:///api/v1=/api/v2` rule from
/// `stat()`-ing a nonexistent file on every request.
pub(super) fn value_source(op: &RuleOp) -> Option<ValueSource> {
    // Already content, not a location: the `(inline)` form and a whole-value
    // `{name}` the values store answered. Upstream's `if (rule.value)` returns
    // before it looks at a disk (`util/index.js:1177-1179`).
    if op.value_is_content {
        return None;
    }
    let value = op.value.trim();
    if value.is_empty() {
        return None;
    }
    // A URL on `re[qs]Cors://` is the **origin**, not a location: upstream tests
    // `isCors` and folds a `GEN_URL_RE` value into `{ origin: value }` before
    // `readRuleValue` is ever reached (`_original/lib/util/index.js:1344,:1361-1370`).
    // `GEN_URL_RE` (`:44`) also admits the scheme-relative `//host`, so both
    // spellings are excluded here.
    if is_cors_origin(op, value) {
        return None;
    }
    // [`is_http_url`] is whistle's `HTTP_RE` (`util/common.js:58`), which is the
    // test `pluginMgr.resolveKey` uses to decide that a value is fetched rather
    // than read (`lib/plugins/index.js:1521-1528`). It wants an explicit scheme,
    // which is what keeps the POSIX path `//srv/x` from being read as a URL.
    if is_http_url(value) {
        let loadable = LOADABLE_JSON_OPS.contains(&op.protocol.as_str())
            || LOADABLE_TEXT_OPS.contains(&op.protocol.as_str());
        return loadable.then(|| ValueSource::Url(value.to_string()));
    }
    if !looks_like_path(value) {
        return None;
    }
    if LOADABLE_JSON_OPS.contains(&op.protocol.as_str()) {
        return (!value.contains('=')).then(|| ValueSource::File(value.to_string()));
    }
    let loadable = LOADABLE_TEXT_OPS.contains(&op.protocol.as_str())
        || LOADABLE_FILE_ONLY_OPS.contains(&op.protocol.as_str());
    loadable.then(|| ValueSource::File(value.to_string()))
}

/// Is this a `re[qs]Cors://` value that whistle reads as an origin URL rather
/// than as somewhere to read from? See [`value_source`].
pub(super) fn is_cors_origin(op: &RuleOp, value: &str) -> bool {
    if op.protocol != "reqCors" && op.protocol != "resCors" {
        return false;
    }
    // `GEN_URL_RE = /^\s*(?:https?:)?\/\/\w[^\s]*\s*$/i` — a word character has
    // to follow the `//`, which is what separates `//cdn.test/x` from a path.
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .or_else(|| value.strip_prefix("//"));
    matches!(rest.and_then(|r| r.chars().next()), Some(c) if c.is_alphanumeric() || c == '_')
}

/// Does this value name a filesystem path outright? See [`value_source`] for why
/// the question is asked at all.
pub(super) fn looks_like_path(value: &str) -> bool {
    let first = value.split('|').next().unwrap_or(value);
    if first.starts_with('/')
        || first.starts_with("~/")
        || first.starts_with("～/")
        || first.starts_with("./")
        || first.starts_with("../")
        || first.starts_with('\\')
    {
        return true;
    }
    // `C:\x` / `C:/x` — upstream's `FILE_RE` (`_original/lib/rules/rules.js:35`)
    // spells the same drive-letter test.
    let bytes = first.as_bytes();
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// How long a URL-valued operator may hold a request up.
///
/// Upstream's own budget for the same fetch — `TIMEOUT = 16000` in
/// `_original/lib/util/http-mgr.js:14`, which `pluginMgr.requestText` reaches
/// through `util.request`. There it is an *idle* timer rearmed on every chunk;
/// here it is a deadline on the whole exchange, which can only be stricter. A
/// value that never arrives must not be able to hold a request open forever,
/// and this is the only place a rule can make an outbound call before the
/// request it belongs to has gone anywhere.
pub(super) const VALUE_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);

/// The most a URL-valued operator may contribute (`MAX_URL_VAL_LEN`,
/// `_original/lib/plugins/index.js:1497`).
///
/// Upstream enforces it *while* reading and aborts the response; this port asks
/// the shared one-shot helper for the whole body and then rejects an oversized
/// one, because [`super::super::upstream::simple_get`] collects before it returns and
/// growing a second, capped variant of it is not this change's business. The
/// deadline above is what bounds the exchange in the meantime.
pub(super) const MAX_URL_VALUE: usize = 256 * 1024;

/// Read the content an operator's value points at.
///
/// `None` is a failure, and every failure is the same one: upstream's file read
/// yields `undefined` and its URL fetch yields `''` for a non-200, a timeout or
/// an oversized body (`requestValue`, `_original/lib/plugins/index.js:1500-1512`).
/// What the caller does with it differs by family — see [`load_rule_values`].
/// What a value source yielded: its text, and — for a file — its bytes.
#[derive(Clone)]
pub(super) struct Loaded {
    pub(super) text: String,
    /// The files' bytes joined with CRLF, untouched: what the binary operators
    /// send (see [`RuleOp::value_bytes`]); a URL's body likewise.
    pub(super) raw: Option<Bytes>,
}

pub(super) async fn read_value_source(source: &ValueSource) -> Option<Loaded> {
    match source {
        // `readFileText` splits on `|` and joins what it read with CRLF, missing
        // files dropping out (`_original/lib/util/file-mgr.js:96-102,:157-166`).
        // That is *not* the first-one-wins of a `file://` rule: several files
        // concatenate into one value.
        //
        // The text is each file decoded on its own, which is `readFileText`'s;
        // the bytes are the files as they are, which is `readFile`'s, and what
        // `joinData` concatenates for a binary operator (`file-mgr.js:93-109`).
        // Upstream's suite splits a Chinese sentence across three files mid-
        // character (`test/units/insertFile.test.js`); only the bytes join back.
        ValueSource::File(spec) => {
            let mut parts: Vec<Vec<u8>> = Vec::new();
            for entry in spec.split('|') {
                let path = convert_slash(&expand_home(&decode_path(entry.trim())));
                if has_parent_ref(&path) {
                    tracing::warn!("rule value {path}: refused, path contains '..'");
                    continue;
                }
                match read_cached(Path::new(&path)) {
                    Some(data) => parts.push(data.to_vec()),
                    // Only `debug`: `a|b` is written precisely so that a missing
                    // alternative is normal. The caller warns once when *nothing*
                    // was read, which is the case worth a line per request.
                    None => tracing::debug!("rule value {path}: not readable"),
                }
            }
            (!parts.is_empty()).then(|| Loaded {
                text: parts
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join("\r\n"),
                raw: Some(Bytes::from(parts.join(CRLF))),
            })
        }
        ValueSource::Url(url) => {
            let fetch = super::super::upstream::simple_get(url);
            match tokio::time::timeout(VALUE_FETCH_TIMEOUT, fetch).await {
                Ok(Ok((200, bytes))) if bytes.len() <= MAX_URL_VALUE => Some(Loaded {
                    text: String::from_utf8_lossy(&bytes).into_owned(),
                    raw: Some(Bytes::copy_from_slice(&bytes)),
                }),
                Ok(Ok((200, bytes))) => {
                    tracing::warn!("rule value {url}: {} bytes exceeds the limit", bytes.len());
                    None
                }
                Ok(Ok((status, _))) => {
                    tracing::warn!("rule value {url}: responded {status}");
                    None
                }
                Ok(Err(err)) => {
                    tracing::warn!("rule value {url}: {err}");
                    None
                }
                Err(_) => {
                    tracing::warn!("rule value {url}: timed out");
                    None
                }
            }
        }
    }
}

/// Load every operator value that names a file or a URL, in place.
///
/// This is upstream's `readRuleValue` (`_original/lib/util/index.js:1189-1213`),
/// moved to one pass over the resolved set instead of one call per consumer.
/// Upstream reads at the moment each inspector wants the value, which lets it
/// pass a `checkUrl`/`needRawData` pair per call site; doing it once here costs
/// a rule set that uses the feature at most one read per *distinct* location,
/// however many operators name it, and costs a rule set that does not use it a
/// walk over the operators it already has — no syscall, no allocation, no await
/// that yields.
///
/// **Failure differs by family, and both halves are upstream's.**
///
/// * A JSON-valued operator keeps its value as written. Upstream reads the path,
///   gets nothing back, and `tryParseMatcher` then parses the *matcher* as a
///   query string (`util/index.js:1165-1171,:1303,:1327`) — so an unreadable
///   `reqHeaders://x=1` still sets the header. Blanking it here would break
///   rules that never asked for this feature.
/// * A text-valued operator becomes **empty**, which is `readFileText`'s `''`
///   and, downstream, `data.body = reqBody || util.EMPTY_BUFFER`
///   (`lib/inspectors/req.js:548`). It deliberately does not fall back to the
///   text as written: that text is a path, and sending a path to an origin as a
///   request body is the fail-open this exists to avoid.
///
/// Loaded values are marked [`RuleOp::value_is_content`], so a second call —
/// the response phase merges operators that were withheld from the request pass
/// — reads nothing twice.
pub async fn load_rule_values(resolved: &mut Resolved, at: &ReqInfo) {
    let mut wanted: HashMap<ValueSource, Option<Loaded>> = HashMap::new();
    for op in resolved.ops_mut() {
        if let Some(source) = value_source(op) {
            wanted.entry(source).or_default();
        }
    }
    if wanted.is_empty() {
        return;
    }
    for (source, slot) in wanted.iter_mut() {
        *slot = read_value_source(source).await;
    }
    for op in resolved.ops_mut() {
        let Some(source) = value_source(op) else {
            continue;
        };
        match wanted.get(&source).and_then(Option::as_ref) {
            Some(loaded) => {
                op.value = loaded.text.clone();
                if BINARY_OPS.contains(&op.protocol.as_str()) {
                    op.value_bytes = loaded.raw.clone();
                }
                op.value_is_content = true;
                op.value_loaded = true;
            }
            // See the failure note above: the JSON operators keep their text so
            // upstream's `tryParseMatcher` fallback still holds, the text ones
            // are emptied so a path can never reach an origin as a body.
            None if LOADABLE_JSON_OPS.contains(&op.protocol.as_str()) => {
                tracing::warn!(
                    "{} {} -> {}://{}: nothing loaded, value kept as written",
                    at.method,
                    at.full_url,
                    op.protocol,
                    op.value
                );
            }
            None => {
                tracing::warn!(
                    "{} {} -> {}://{}: nothing loaded, value emptied",
                    at.method,
                    at.full_url,
                    op.protocol,
                    op.value
                );
                op.value = String::new();
                op.value_is_content = true;
            }
        }
    }
}
