//! The request line: `urlReplace://`, `urlParams://` and `params://` on the
//! query, and `delete://` on path segments and query keys — everything that
//! rewrites the path a request is sent to before its head goes out.

use super::*;

/// The `delete://` keys that address the request's **URL** rather than its
/// headers (`parseDelQuery`, `_original/lib/util/index.js:2674-2699`).
///
/// These live here rather than in [`Deletions`] because upstream applies them
/// from the URL-rewriting pass, not the header pass: the path indices go to
/// `parsePathReplace` alongside `urlReplace://` and the query names to
/// `deleteQuery` after it (`_original/lib/inspectors/req.js:557,562-570`).
#[derive(Default)]
pub(super) struct DelQuery {
    /// `delete://query.<name>` — query-string names to drop. Also spelled
    /// `params.<name>` and `url[.]Param[s].<name>`.
    pub(super) names: Vec<String>,
    /// The same words with nothing after them: drop the query string outright,
    /// `?` and all.
    pub(super) clear: bool,
    /// `delete://pathname…`, absent when no key named a segment.
    pub(super) paths: Option<DelPaths>,
}

/// Which path segments `delete://pathname…` names.
#[derive(Default)]
pub(super) struct DelPaths {
    /// A bare `delete://pathname`: the whole path goes, the query stays.
    pub(super) all: bool,
    /// `delete://pathname.last` — the final segment, and a trailing slash left
    /// where it was.
    pub(super) last: bool,
    /// Segment indices, counted from the end when negative. `first` is `0`.
    pub(super) indices: Vec<i64>,
}

/// What one `pathname…` key names.
pub(super) enum PathKey {
    All,
    Last,
    Index(i64),
}

impl DelQuery {
    /// Classify every `delete://` key that addresses the URL.
    pub(super) fn of(resolved: &Resolved) -> DelQuery {
        let mut del = DelQuery::default();
        for value in collect_values(resolved, "delete") {
            // Same split as [`Deletions::of`] — `parseProps` takes `|` and `&`.
            for key in value.split(['|', '&']) {
                let key = key.trim();
                match strip_query_scope(key) {
                    Some(Some(name)) => del.names.push(name.to_string()),
                    Some(None) => del.clear = true,
                    None => match strip_pathname_scope(key) {
                        Some(PathKey::All) => del.paths.get_or_insert_default().all = true,
                        Some(PathKey::Last) => del.paths.get_or_insert_default().last = true,
                        Some(PathKey::Index(i)) => {
                            del.paths.get_or_insert_default().indices.push(i)
                        }
                        None => {}
                    },
                }
            }
        }
        del
    }
}

/// Strip whistle's query-string prefix — `query`, `params` or `url[.]Param[s]`,
/// all case-insensitive (`QUERY_RE` / `QUERY_STRING_RE`,
/// `_original/lib/util/index.js:2670-2671`).
///
/// `Some(None)` is the bare form (drop the whole query string), `Some(Some(n))`
/// names one parameter.
pub(super) fn strip_query_scope(key: &str) -> Option<Option<&str>> {
    for prefix in [
        "query",
        "params",
        "urlParams",
        "urlParam",
        "url.Params",
        "url.Param",
    ] {
        let Some(head) = key
            .get(..prefix.len())
            .filter(|h| h.eq_ignore_ascii_case(prefix))
        else {
            continue;
        };
        let rest = &key[head.len()..];
        if rest.is_empty() {
            return Some(None);
        }
        if let Some(name) = rest.strip_prefix('.').filter(|n| !n.is_empty()) {
            return Some(Some(name));
        }
    }
    None
}

/// Match `PATH_INDEX_RE` (`_original/lib/util/index.js:2672`).
///
/// The dot before the index is optional in the regex, so `pathname-1` names the
/// same segment as `pathname.-1`, and `pathnamelast` the same as
/// `pathname.last`. A trailing dot with nothing after it matches neither branch
/// and is ignored, exactly as the regex ignores it.
///
/// `first`/`last` are matched **case-sensitively** even though the regex is
/// not. That is upstream's, not an oversight here: the regex accepts
/// `pathname.LAST`, but `parseDelQuery` then keys the map on the *matched
/// spelling* and `parsePathReplace` looks up the literal `last` and coerces
/// every other key with `+key` — `+'LAST'` is `NaN`, so the key is silently
/// dropped (`util/index.js:2688,1037-1047`). Only the word `pathname` itself is
/// case-insensitive all the way through.
pub(super) fn strip_pathname_scope(key: &str) -> Option<PathKey> {
    let head = key
        .get(.."pathname".len())
        .filter(|h| h.eq_ignore_ascii_case("pathname"))?;
    let rest = &key[head.len()..];
    if rest.is_empty() {
        return Some(PathKey::All);
    }
    let idx = rest.strip_prefix('.').unwrap_or(rest);
    if idx == "first" {
        return Some(PathKey::Index(0));
    }
    if idx == "last" {
        return Some(PathKey::Last);
    }
    // `-?\d+`: a leading `+` is not one of the shapes upstream accepts, and
    // Rust's integer parser would take it.
    (!idx.starts_with('+'))
        .then(|| idx.parse::<i64>().ok())
        .flatten()
        .map(PathKey::Index)
}

/// `delete://pathname…` — drop path segments (`parsePathReplace`'s `delPaths`
/// arm, `_original/lib/util/index.js:1023-1058`).
///
/// Segments are counted in the path *without* its leading slash — the same
/// slice `urlReplace://` substitutes into — so `pathname.0` names `a` in
/// `/a/b/c`. The query string is split off first and put back untouched.
pub(super) fn delete_path_segments(path: &str, del: &DelPaths) -> String {
    let (head, rest) = match path.strip_prefix('/') {
        Some(rest) => ("/", rest),
        None => ("", path),
    };
    let (cur, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // `if (curPath)`: a URL that is nothing but a query string has no segment to
    // name, and upstream leaves it alone.
    if cur.is_empty() {
        return path.to_string();
    }
    if del.all {
        // Deliberate divergence: upstream assigns the query to `curPath` and
        // then appends it again two lines later (`util/index.js:1033,1057`), so
        // a bare `delete://pathname` on `/a?x=1` produces `/?x=1?x=1`. That is a
        // malformed request line no origin parses; the query goes on once here.
        return format!("{head}{query}");
    }
    let mut segs: Vec<Option<&str>> = cur.split('/').map(Some).collect();
    let len = segs.len() as i64;
    let mut indices = del.indices.clone();
    if del.last {
        indices.push(len - 1);
    }
    for i in indices {
        let i = if i < 0 { len + i } else { i };
        if (0..len).contains(&i) {
            segs[i as usize] = None;
        }
    }
    let mut kept: Vec<&str> = segs.into_iter().flatten().collect();
    // `pathname.last` leaves a trailing slash where the segment was: upstream
    // pushes an empty segment back when the new last one is non-empty
    // (`util/index.js:1051-1053`). `pathname.-1` does not — the two spellings
    // name the same segment and disagree about the slash.
    if del.last && kept.last().is_some_and(|s| !s.is_empty()) {
        kept.push("");
    }
    format!("{head}{}{query}", kept.join("/"))
}

/// `deleteQuery` (`_original/lib/util/index.js:2701-2721`): drop the named
/// pairs from the query string, or all of it when `clear`.
///
/// Names are compared raw, before any percent-decoding, because that is what
/// upstream compares — `delete://query.a%20b` names the parameter spelled that
/// way on the wire.
pub(super) fn delete_query(path: &str, names: &[String], clear: bool) -> String {
    let Some(i) = path.find('?') else {
        return path.to_string();
    };
    if clear {
        return path[..i].to_string();
    }
    let query = &path[i + 1..];
    if query.is_empty() {
        return path.to_string();
    }
    let kept = query
        .split('&')
        .filter(|item| {
            let name = item.split_once('=').map_or(*item, |(k, _)| k);
            !names.iter().any(|n| n == name)
        })
        .collect::<Vec<_>>()
        .join("&");
    // The `?` goes too when nothing survives.
    match kept.is_empty() {
        true => path[..i].to_string(),
        false => format!("{}?{kept}", &path[..i]),
    }
}

/// `encodeURI`: the characters a URL may not carry raw, percent-encoded as
/// UTF-8, and every other character left exactly as it is.
///
/// The set is the one JavaScript's `encodeURI` escapes — space, `"`, `<`, `>`,
/// `\`, `^`, `` ` ``, `{`, `|`, `}`, `%`, and everything above ASCII — and it
/// was arrived at by measurement rather than by reading: `auth-bench`-style
/// probes put each character through a `params://` value and read what reached
/// the origin. `é`→`%C3%A9`, `中`→`%E4%B8%AD`, `🚀`→`%F0%9F%9A%80`, `{`→`%7B`,
/// `%`→`%25`, and `#`, `&`, `=`, `+`, `/`, `?`, `:` untouched.
///
/// `%`→`%25` means a value that was **already** escaped is escaped again —
/// `%41` becomes `%2541`. That is upstream's answer and it is the consistent
/// one: what a rule writes into a parameter arrives at the origin as those
/// characters, whatever they look like.
pub(super) fn encode_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let raw = byte.is_ascii()
            && !matches!(
                byte,
                b' ' | b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' | b'%'
            )
            && !byte.is_ascii_control();
        match raw {
            true => out.push(byte as char),
            false => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The request target to put on the wire: **every non-ASCII byte percent-encoded
/// as UTF-8**, and every ASCII byte left exactly as it is.
///
/// A request target is ASCII, and a rule may name anything. A destination
/// spelled `http://host/中文` or a `params://` value carrying one is an ordinary
/// thing to write, and forwarding those bytes raw is not a request line: the
/// bench's origin answers `400` and closes the connection, so the rule did not
/// merely fail to apply — it took the request down with it.
///
/// Upstream escapes the same range on the rule's own URL —
/// `ruleUrl = util.encodeNonLatin1Char(ruleUrl)`
/// (`_original/lib/inspectors/rules.js:42`) — and the bench agrees with it
/// character by character.
///
/// **Only non-ASCII.** The wider `encodeURI` set belongs to a `params://`
/// *value* (see [`merge_query`]) and not here: a `%` escaped at this level would
/// re-escape what the client wrote, turning a request for `/a%20b` into
/// `/a%2520b`, and `urlReplace://` — which writes URL syntax on purpose — would
/// have its `{`, `|` and `^` escaped where upstream leaves them alone. All three
/// were measured separately.
///
/// **A target hyper still refuses gets the full [`encode_uri`] as a last
/// resort.** `urlReplace://echo=ec` + a backtick produces a path the URI parser
/// will not take, and the caller's fallback then keeps the *original* URI — so
/// the rule silently does not happen, which is the one outcome worse than
/// applying it differently. whistle puts the backtick on the wire raw; this
/// sends `%60`, which every server decodes back to it. Declared in
/// `cases-paths.js`.
///
/// `None` only when even that is not a URI, and the caller keeps the request's
/// original URI.
///
/// The encoding is for the wire only: what is recorded and shown keeps the path
/// as the rule wrote it, which is the readable form and the one to search a
/// capture for.
pub fn request_target(path: &str) -> Option<hyper::Uri> {
    let ascii = match path.is_ascii() {
        true => path.to_string(),
        false => {
            let mut out = String::with_capacity(path.len());
            for byte in path.bytes() {
                match byte.is_ascii() {
                    true => out.push(byte as char),
                    false => out.push_str(&format!("%{byte:02X}")),
                }
            }
            out
        }
    };
    hyper::Uri::try_from(ascii.as_str())
        .ok()
        .or_else(|| hyper::Uri::try_from(encode_uri(&ascii).as_str()).ok())
}

/// Rewrite the request path+query per `urlReplace`, `params`, `urlParams`, and
/// the `delete://` keys that name a query parameter or a path segment.
pub fn rewrite_path(path: &str, resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> String {
    let mut p = path.to_string();
    let del = DelQuery::of(resolved);
    // Each protocol collapses to one map of its own, then `urlParams` is laid
    // over `params` (`extend(_params, urlParams)`,
    // `_original/lib/inspectors/req.js:425`). `params` is skipped entirely when
    // the body claimed it — `_params = hasBody ? null : params` (`req.js:421`);
    // `urlParams` always addresses the query.
    let mut params: Vec<(String, String)> = Vec::new();
    if params_body_kind(resolved, ctx).is_none() {
        params.extend(merge_params_pairs(resolved, "params"));
    }
    params.extend(merge_params_pairs(resolved, "urlParams"));
    if !params.is_empty() {
        p = merge_query(&p, &params);
    }
    // `urlReplace://` runs **after** the params merge, which is upstream's order:
    // `handleParams` writes the query first (`req.js:561`) and `parsePathReplace`
    // rewrites the URL that results (`:569`). Reversed, a `urlReplace` pattern
    // aimed at what a `params://` on the same line had just written never saw it.
    let replacements = merge_rule_maps(resolved, "urlReplace");
    if !replacements.is_empty() {
        // whistle substitutes into the path *without* its leading slash — it
        // slices the URL from one character past the host's `/`
        // (`parsePathReplace`, `_original/lib/util/index.js:1009-1013`), so a
        // pattern anchored with `^/` matches in neither implementation.
        let rest = p.strip_prefix('/');
        let replaced = apply_str_replace(rest.unwrap_or(&p), &replacements);
        p = match rest.is_some() {
            true => format!("/{replaced}"),
            false => replaced,
        };
    }
    // The path deletions are `parsePathReplace`'s second half, so they run in
    // the same pass as `urlReplace://` and after it
    // (`_original/lib/util/index.js:1023-1058`).
    if let Some(paths) = &del.paths {
        p = delete_path_segments(&p, paths);
    }
    // `deleteQuery` runs last, over whatever the query string has become
    // (`_original/lib/inspectors/req.js:570`) — so a name it drops is dropped
    // even when a `params://` on the same line had just written it.
    if del.clear || !del.names.is_empty() {
        p = delete_query(&p, &del.names, del.clear);
    }
    p
}

/// The `params`/`urlParams` lines of one protocol folded into a flat map, first
/// line winning a contested name.
pub(super) fn merge_params_pairs(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_params_values(resolved, protocol)
        .into_iter()
        .map(|(k, v)| (k, json_to_param_string(v)))
        .collect()
}

/// The same fold, keeping each value as JSON so a nested object survives into a
/// JSON request body.
pub(super) fn merge_params_values(
    resolved: &Resolved,
    protocol: &str,
) -> Vec<(String, serde_json::Value)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_param_values(&op.value, op.value_is_content, resolves_dotted_keys(op))),
    )
}

/// Parse `k=v&k2=v2`, `{json}` or the line format into `name` → value pairs.
///
/// The three roads and their order are [`parse_data_object`]'s — this had its
/// own copy of them, and the copy differed twice: a key written with no `=`
/// was dropped where `parseQuery` keeps it with an empty value (`solo` and
/// `solo:` both merged nothing here and `{"solo":""}` upstream), and the line
/// format never resolved a dotted name.
pub(super) fn parse_param_values(
    value: &str,
    is_content: bool,
    resolve_keys: bool,
) -> Vec<(String, serde_json::Value)> {
    match parse_data_object(value, resolve_keys, is_content) {
        Some(serde_json::Value::Object(map)) => map.into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Does this operator read a dotted name as a **path** into the object?
///
/// `RESOLVE_KEY_RE` is `/^re[qs]Merge:\/\//` (`_original/lib/util/index.js:95`)
/// and it is tested against the matcher **as written**, so the question is about
/// the spelling and not about the protocol it resolves to: measured against
/// whistle 2.10.8, a block holding `a.b: 1` merges as `{"a":{"b":"1"}}` under
/// `reqMerge://{v}` and as `{"a.b":"1"}` under `params://{v}` — the same
/// operator, the same value, two answers.
pub(super) fn resolves_dotted_keys(op: &RuleOp) -> bool {
    let written = op.raw.split_once("://").map(|(proto, _)| proto);
    matches!(written, Some("reqMerge" | "resMerge"))
}

/// A param value as it appears in a query string or a form body: a string
/// unquoted, a number or a boolean written out, **a structure written as
/// nothing**.
///
/// The last one is Node's `querystring.stringify`, which upstream hands the
/// whole patch to before merging it into a form body (`replaceQueryString`,
/// `_original/lib/util/index.js:1753-1756`): it writes primitives and drops
/// anything else, so `{a:{b:'1'}}` becomes `a=`. Measured against whistle
/// 2.10.8; this port used to write the JSON text of the structure, which is a
/// value the form's reader never sees from whistle.
///
/// A nested patch belongs on a JSON body, where both implementations merge the
/// structure itself.
pub(super) fn json_to_param_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => String::new(),
        other => other.to_string(),
    }
}

/// Merge `params` into the query string of `path`, overriding same-named keys.
///
/// **The merged-in values are percent-encoded and the query's existing ones are
/// not**, which is not a symmetry worth fixing: what was already in the URL is
/// whatever the client wrote and re-encoding it would turn its `%20` into
/// `%2520`, while what a rule adds is text somebody typed into a rules file and
/// has to survive the trip. Measured on both sides character by character —
/// `params://q=a{b` reaches the origin as `q=a%7Bb` from whistle and used to
/// reach it as `q=a{b` from here. See [`encode_uri`].
///
/// `urlReplace://` is deliberately *not* encoded, and that asymmetry is
/// upstream's too: it rewrites a URL, so what it writes is URL syntax rather
/// than a value inside one.
pub(super) fn merge_query(path: &str, params: &[(String, String)]) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => (path, ""),
    };
    let params: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (k.clone(), encode_uri(v)))
        .collect();
    let merged = merge_query_string(query, &params, &[]);
    if merged.is_empty() {
        return base.to_string();
    }
    format!("{base}?{merged}")
}

/// `replaceQueryString` (`_original/lib/util/index.js:1738-1800`): overlay
/// `params` on a `k=v&…` string, dropping the names in `del`.
///
/// The surviving original pairs keep their position and order; each replaced or
/// new name is appended in `params` order. Shared by the query string and the
/// urlencoded request body, which upstream runs through the same function.
pub(super) fn merge_query_string(
    query: &str,
    params: &[(String, String)],
    del: &[String],
) -> String {
    let deleted = |name: &str| del.iter().any(|d| d == name);
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .filter(|(k, _)| !deleted(k))
        .collect();
    for (k, v) in params {
        if deleted(k) {
            continue;
        }
        pairs.retain(|(ek, _)| ek != k);
        pairs.push((k.clone(), v.clone()));
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}
