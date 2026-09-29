//! The body operators: what a request or response body is rewritten into.
//! `reqBody`/`resBody` and their `Prepend`/`Append` forms, the `html`/`js`/`css`
//! injections and the gates on them (`safeHtml`, `strictHtml`, the doctype),
//! `reqMerge`/`resMerge` on JSON, `reqReplace`/`resReplace`, `params` into a
//! form or multipart body, `delete://` on JSON keys — and which bodies they
//! may touch at all.

use super::*;

/// Content-type-specific body operator prefixes (`css`/`html`/`js`).
pub(super) const TYPED_BODY_PREFIXES: &[&str] = &["css", "html", "js"];

/// Body operators for a side, keyed by prefix (`req`/`res`): `*Body` (replace),
/// `*Replace` (substring/`/regex/` substitute), `*Prepend`, `*Append`.
pub(super) fn body_ops_present(resolved: &Resolved, prefix: &str) -> bool {
    let generic = ["Body", "Replace", "Prepend", "Append"]
        .iter()
        .any(|s| resolved.value(&format!("{prefix}{s}")).is_some());
    if generic {
        return true;
    }
    // `delete://body` and `delete://resBody.a` rewrite the body on their own.
    if Deletions::of(resolved, prefix == "req").touches_body() {
        return true;
    }
    if prefix == "res" && resolved.value("resMerge").is_some() {
        return true;
    }
    // css/html/js typed ops only exist on the response side.
    prefix == "res"
        && TYPED_BODY_PREFIXES.iter().any(|k| {
            ["Body", "Prepend", "Append"]
                .iter()
                .any(|s| resolved.value(&format!("{k}{s}")).is_some())
        })
}

/// whistle's coarse content classes (`getContentType`,
/// `_original/lib/util/index.js:1475-1510`).
///
/// The order of the tests is upstream's and is load-bearing: `javascript` is
/// looked for before `css`, which is looked for before `html`, so a type that
/// mentions two of them resolves to the first. Only the media type is examined —
/// parameters after the first `;` are dropped before the substring tests, so a
/// `charset=` value cannot smuggle a class in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ResClass {
    Js,
    Css,
    Html,
    Json,
    Xml,
    Text,
    Img,
    /// Not one of `getContentType`'s classes. `handleReplace` substitutes the
    /// string `FORM` for a urlencoded **request** body before its gate
    /// (`_original/lib/inspectors/req.js:435`), which is the only reason
    /// `reqReplace://` reaches a form POST at all — `getContentType` puts
    /// `application/x-www-form-urlencoded` in no class, and the gate refuses
    /// anything unclassified. Never produced for a response.
    Form,
}

/// Classify a `Content-Type` header the way whistle does. `None` covers both a
/// missing header and a type in none of the classes (e.g. `image/…` aside,
/// `application/octet-stream`).
pub(super) fn res_class(content_type: &str) -> Option<ResClass> {
    let raw = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    Some(if raw.contains("javascript") {
        ResClass::Js
    } else if raw.contains("css") {
        ResClass::Css
    } else if raw.contains("html") {
        ResClass::Html
    } else if raw.contains("json") {
        ResClass::Json
    } else if raw.contains("xml") {
        ResClass::Xml
    } else if raw.contains("text/") {
        ResClass::Text
    } else if raw.contains("image/") {
        ResClass::Img
    } else {
        return None;
    })
}

/// Which typed-body families a response accepts.
///
/// The nuance that makes `jsAppend` useful at all: **an HTML response accepts
/// the JS *and* the CSS families too** — `isJs = isHtml || resType === 'JS'`
/// (`_original/lib/inspectors/res.js:952-954`). `jsAppend://alert(1)` on a page
/// is the canonical whistle one-liner; it works because the injected script is
/// wrapped in `<script>` before it reaches the markup (see [`wrap_js`]).
#[derive(Clone, Copy)]
pub(super) struct BodyFamilies {
    pub(super) html: bool,
    pub(super) js: bool,
    pub(super) css: bool,
}

impl BodyFamilies {
    pub(super) fn of(class: Option<ResClass>) -> BodyFamilies {
        let html = class == Some(ResClass::Html);
        BodyFamilies {
            html,
            js: html || class == Some(ResClass::Js),
            css: html || class == Some(ResClass::Css),
        }
    }
}

/// A URL written where whistle expects script or stylesheet source
/// (`GEN_URL_RE`, `_original/lib/util/index.js:44`). Such a value is linked
/// rather than inlined.
pub(super) static GEN_URL_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(?i)^\s*(?:https?:)?//\w\S*\s*$").expect("static regex"));

/// `<script>` attributes contributed by the injecting line's properties
/// (`getScriptProps`, `_original/lib/util/index.js:277-303`). The groups are
/// exclusive in upstream's order: the first `crossorigin` spelling wins, and
/// `module` outranks `importmap` outranks `speculationrules`.
pub(super) fn script_props(props: &LineProps) -> String {
    let mut out = String::new();
    if props.has("use-credentials") || props.has("useCredentials") {
        out.push_str(" crossorigin=\"use-credentials\"");
    } else if props.has("anonymous") {
        out.push_str(" crossorigin=\"anonymous\"");
    } else if props.has("crossorigin") {
        out.push_str(" crossorigin");
    }
    for flag in ["defer", "async", "nomodule"] {
        if props.has(flag) {
            out.push(' ');
            out.push_str(flag);
        }
    }
    if props.has("module") {
        out.push_str(" type=\"module\"");
    } else if props.has("importmap") {
        out.push_str(" type=\"importmap\"");
    } else if props.has("speculationrules") {
        out.push_str(" type=\"speculationrules\"");
    }
    out
}

/// Wrap a `jsXxx` value for injection into markup (`wrapJs`,
/// `_original/lib/util/index.js:305-313`): a bare URL becomes a `src=` script
/// tag, anything else an inline one.
pub(super) fn wrap_js(js: &str, props: &LineProps) -> String {
    let attrs = script_props(props);
    match GEN_URL_RE.is_match(js) {
        true => format!("<script{attrs} src=\"{}\"></script>", js.trim()),
        false => format!("<script{attrs}>{js}</script>"),
    }
}

/// Wrap a `cssXxx` value for injection into markup (`wrapCss`,
/// `_original/lib/util/index.js:315-322`). Line properties do not apply here —
/// upstream passes none.
pub(super) fn wrap_css(css: &str) -> String {
    match GEN_URL_RE.is_match(css) {
        true => format!("<link rel=\"stylesheet\" href=\"{}\" />", css.trim()),
        false => format!("<style>{css}</style>"),
    }
}

/// The separator whistle puts between several values landing in the same slot
/// (`joinData`, `_original/lib/util/file-mgr.js:93-109`).
pub(super) const CRLF: &[u8] = b"\r\n";

/// Prepended to a non-empty `top` on an HTML response unless `disable://doctype`
/// (`_original/lib/util/whistle-transform.js:6,116-118`). Surprising but real:
/// any `resPrepend`/`htmlPrepend` on a page also stamps a doctype in front of it.
pub(super) const DOCTYPE: &[u8] = b"<!DOCTYPE html>\r\n";

/// The three slots whistle's `WhistleTransform` writes around a body: `top`
/// before it, `body` *instead* of it, `bottom` after it
/// (`_original/lib/util/whistle-transform.js:88-127`).
///
/// Each slot is a list because several operators — and, since they are
/// multi-match, several *lines* per operator — feed it. The parts are joined
/// with CRLF, whistle's separator for everything that lands in one slot.
#[derive(Default)]
pub(super) struct Injection {
    pub(super) top: Vec<Piece>,
    pub(super) body: Vec<Piece>,
    pub(super) bottom: Vec<Piece>,
    /// Whether the body slot was claimed at all. Distinct from `body` being
    /// non-empty: a `*Body` operator that matched with a blank value still
    /// replaces the body (upstream substitutes an empty *buffer*, which is
    /// truthy, `_original/lib/inspectors/res.js:1005` +
    /// `whistle-transform.js:110-114`), so `resBody://` empties it.
    pub(super) replaces_body: bool,
}

impl Injection {
    /// Re-encode every injected piece into the response's own charset.
    ///
    /// A rule's value is UTF-8 — it came out of a rules file — and the page it
    /// is pasted into is not. whistle encodes each value as it reads it
    /// (`toBuffer(value, charset)`, `_original/lib/util/index.js:1388`) and once
    /// more in the transform (`WhistleTransform`,
    /// `_original/lib/util/whistle-transform.js:21-45`), so a `htmlAppend://中文`
    /// lands on a `charset=gbk` page as GBK rather than as four bytes the page
    /// renders as mojibake.
    ///
    /// The separators stay as they are: CRLF and the doctype are ASCII, and
    /// every charset with a `charset=` label worth honouring is ASCII-compatible.
    ///
    /// Bytes a binary operator read from a file are not text in anybody's
    /// charset and go as they are — upstream's `toBuffer` returns a `Buffer`
    /// untouched (`_original/lib/util/common.js:1563-1566`).
    pub(super) fn recode(&mut self, encoding: &'static encoding_rs::Encoding) {
        for slot in [&mut self.top, &mut self.body, &mut self.bottom] {
            for piece in slot.iter_mut().filter(|p| !p.raw) {
                piece.bytes = super::super::coding::encode_charset(
                    encoding,
                    &String::from_utf8_lossy(std::mem::take(&mut piece.bytes).as_slice()),
                );
            }
        }
    }

    /// Wrap `data` in whatever the slots hold.
    pub(super) fn apply(self, data: Vec<u8>, doctype: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if !self.top.is_empty() && doctype {
            out.extend_from_slice(DOCTYPE);
        }
        join_into(&mut out, self.top);
        match self.replaces_body {
            true => join_into(&mut out, self.body),
            false => out.extend_from_slice(&data),
        }
        join_into(&mut out, self.bottom);
        out
    }
}

/// One line's contribution to a slot.
pub(super) struct Piece {
    pub(super) bytes: Vec<u8>,
    /// Bytes a binary operator loaded as they are ([`RuleOp::value_bytes`]),
    /// which no charset applies to.
    pub(super) raw: bool,
}

impl Piece {
    /// Text: a rule's value, or markup made from one.
    pub(super) fn text(bytes: Vec<u8>) -> Self {
        Piece { bytes, raw: false }
    }

    /// What an operator line sends: its loaded bytes when it has them.
    pub(super) fn of(op: &RuleOp) -> Self {
        match &op.value_bytes {
            Some(bytes) => Piece {
                bytes: bytes.to_vec(),
                raw: true,
            },
            None => Piece::text(op.value.as_bytes().to_vec()),
        }
    }
}

/// Append `pieces` to `out`, CRLF-separated.
pub(super) fn join_into(out: &mut Vec<u8>, pieces: Vec<Piece>) {
    for (i, piece) in pieces.into_iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(CRLF);
        }
        out.extend(piece.bytes);
    }
}

/// Deep-merge `patch` (a JSON object) into `target`; objects merge recursively,
/// other values are overwritten. Ported from whistle's `resMerge`.
pub(super) fn json_deep_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
            for (k, v) in p {
                json_deep_merge(t.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
        (t, p) => *t = p.clone(),
    }
}

/// Merge `patch` into `target` one key deep — jQuery's `extend` without its
/// leading `true`, which is how upstream combines several lines of the same
/// JSON-shaped operator.
pub(super) fn json_shallow_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
            for (k, v) in p {
                t.insert(k.clone(), v.clone());
            }
        }
        (t, p) => *t = p.clone(),
    }
}

/// Collapse every matching line of a JSON-shaped operator (`resMerge`) into one
/// patch, mirroring `readRuleList`'s JSON branch
/// (`_original/lib/util/index.js:1300-1312`).
///
/// Like [`merge_rule_maps`] the list is reversed and folded onto its own last
/// entry, so the **first** (highest-priority) line wins a contested key. Two
/// details are specific to this branch:
///
/// * the fold is *shallow* unless one of the lines is the literal `true`, which
///   upstream detects with `isDeep` and turns into `extend`'s deep flag. So
///   `resMerge://true` is a marker line that contributes no data of its own and
///   makes the remaining lines merge recursively;
/// * a single line is passed through untouched — the fold only runs for two or
///   more — so a lone non-object `resMerge` keeps whatever meaning it had.
///
/// The combined patch is then always deep-merged *into the body*
/// (`extend(true, obj, params)`, `_original/lib/inspectors/res.js:1046`).
pub(super) fn merge_json_patches(resolved: &Resolved, protocol: &str) -> Option<serde_json::Value> {
    let mut deep = false;
    let mut patches: Vec<serde_json::Value> = Vec::new();
    for op in resolved.all(protocol) {
        // All three spellings, not JSON alone. `resMerge://test=123` is the
        // first example on <https://wproxy.org/docs/rules/resMerge.html> and it
        // did nothing here; so did the line format, which is how a `{value}`
        // reference carries a merge patch. `resMerge`/`reqMerge` are also the
        // only operators whose dotted names are paths (`RESOLVE_KEY_RE`).
        let Some(value) =
            parse_data_object(&op.value, resolves_dotted_keys(op), op.value_is_content)
        else {
            continue;
        };
        match value {
            serde_json::Value::Bool(true) => deep = true,
            serde_json::Value::Null => {}
            value => patches.push(value),
        }
    }
    if patches.len() < 2 {
        return patches.pop();
    }
    // `extend.apply(null, reversed)`: the last line is the target, and each
    // earlier line is laid over it in turn.
    let mut target = patches.pop()?;
    if !(target.is_object() || target.is_array()) {
        // `if (typeof result[0] !== 'object') { result[0] = {}; }`
        target = serde_json::Value::Object(serde_json::Map::new());
    }
    for src in patches.iter().rev() {
        match deep {
            true => json_deep_merge(&mut target, src),
            false => json_shallow_merge(&mut target, src),
        }
    }
    Some(target)
}

/// The request facts `params://` needs to pick its destination.
///
/// Both are read *after* the request operators have run, because `reqType://`
/// and `method://` are applied before `handleParams` decides
/// (`_original/lib/inspectors/req.js:536,560-561`) — a `reqType://json` line
/// therefore sends the params into the body.
#[derive(Clone, Copy, Default)]
pub struct ReqBodyCtx<'a> {
    /// The method as forwarded (after `method://`).
    pub method: &'a str,
    /// The `Content-Type` as forwarded (after `reqType://` and `reqHeaders://`).
    pub content_type: Option<&'a str>,
}

/// Which kind of request body `params://` merges into, if any.
///
/// `None` means the params address the query string instead — upstream's
/// `hasBody` flag (`handleParams`, `_original/lib/inspectors/req.js:157-232`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ParamsBody {
    /// `application/json` (and anything else `getContentType` calls JSON).
    Json,
    /// `application/x-www-form-urlencoded` — **POST only**, as upstream has it.
    Form,
    /// `multipart/…` with a boundary; the boundary is read back from the type.
    Multipart,
}

/// Where `params://` lands for this request, given what the rules resolved.
///
/// Answering `None` when no `params://` (and no `delete://reqBody.…`) matched is
/// what keeps this off the hot path: an unmatched request never looks at its own
/// content type. Both guards are map lookups — `Deletions::of`, which walks and
/// allocates, is reached only once a `delete://` has actually matched.
/// Whether `params://` rewrites this request's **body** — a form or JSON one —
/// rather than only its query string.
pub fn params_rewrite_body(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> bool {
    params_body_kind(resolved, ctx).is_some()
}

pub(super) fn params_body_kind(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> Option<ParamsBody> {
    let asks = !resolved.all("params").is_empty()
        || (!resolved.all("delete").is_empty()
            && !Deletions::of(resolved, true).body_props.is_empty());
    asks.then(|| request_body_kind(ctx)).flatten()
}

/// Classify a request body by method and content type, the way `handleParams`
/// branches on it.
pub(super) fn request_body_kind(ctx: ReqBodyCtx<'_>) -> Option<ParamsBody> {
    let ct = ctx.content_type?;
    // `isMultipart` tests the content type alone — no method, no body check
    // (`_original/lib/util/index.js:1724-1727`) — and the boundary must be
    // spelled out for the parts to be found at all.
    if ct.to_ascii_lowercase().contains("multipart") {
        return multipart_boundary(ct).map(|_| ParamsBody::Multipart);
    }
    // `isUrlEncoded` is POST-only (`_original/lib/util/common.js:692-695`),
    // while `isJSONContent` accepts any method that may carry a body.
    if ct
        .to_ascii_lowercase()
        .contains("application/x-www-form-urlencoded")
    {
        return ctx
            .method
            .eq_ignore_ascii_case("POST")
            .then_some(ParamsBody::Form);
    }
    if method_has_body(ctx.method) && matches!(res_class(ct), Some(ResClass::Json)) {
        return Some(ParamsBody::Json);
    }
    None
}

/// The class `reqReplace://` is gated on (`handleReplace`,
/// `_original/lib/inspectors/req.js:429-438`).
///
/// It is *not* the response gate with the request's content type substituted,
/// which is what this port had — and why `reqReplace://` was a silent no-op on
/// the commonest request body there is. Two things differ:
///
/// * a method that carries no body is refused before the type is looked at
///   (`hasRequestBody`, `common.js:1591-1604`);
/// * a urlencoded body is mapped to a class of its own — `type =
///   isUrlEncoded(req) ? 'FORM' : getContentType(type)` — because
///   `getContentType` puts `application/x-www-form-urlencoded` in no class at
///   all, and the next line refuses everything unclassified.
pub(super) fn req_replace_class(ctx: ReqBodyCtx<'_>) -> Option<ResClass> {
    if !method_has_body(ctx.method) {
        return None;
    }
    let ct = ctx.content_type?;
    // `isUrlEncoded` is POST-only (`_original/lib/util/common.js:692-695`), so a
    // `PUT` carrying a form body takes the ordinary path and is refused.
    if ctx.method.eq_ignore_ascii_case("POST")
        && ct
            .to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    {
        return Some(ResClass::Form);
    }
    res_class(ct)
}

/// `hasRequestBody` (`_original/lib/util/common.js:1591-1604`) — the methods
/// whistle will look for a body on.
pub(super) fn method_has_body(method: &str) -> bool {
    !matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "CONNECT"
    )
}

/// The `boundary=` of a multipart content type (`BUOUNDARY_RE`,
/// `_original/lib/inspectors/req.js:19`), quoted or bare.
pub(super) fn multipart_boundary(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    let at = lower.find("boundary=")? + "boundary=".len();
    let rest = &content_type[at..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return (end > 0).then(|| quoted[..end].to_string());
    }
    let end = rest.find(';').unwrap_or(rest.len());
    let bare = rest[..end].trim();
    (!bare.is_empty()).then(|| bare.to_string())
}

/// True if any request-body operator applies (so the body must be buffered).
pub fn wants_req_body(resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> bool {
    // A method that carries no body has nothing to buffer *for*: its injections
    // are dropped (see [`transform_req_body`]) and its rewrites have nothing to
    // rewrite, so buffering would cost a copy to reach the same empty body.
    if !method_allows_body(ctx.method) {
        return false;
    }
    body_ops_present(resolved, "req") || params_body_kind(resolved, ctx).is_some()
}

/// Whether a request with this method may carry a body at all
/// (`hasRequestBody`, `_original/lib/util/common.js:1591-1605`).
///
/// The list is upstream's, and it is about the *method*, not about whether this
/// particular request happens to have arrived with bytes: `GET`, `HEAD`,
/// `OPTIONS` and `CONNECT` are the four whistle refuses to give a body to.
///
/// The method compared is the one being **forwarded** — after `method://` — so
/// rewriting a `GET` into a `POST` makes the injection apply, which is the order
/// upstream reads it in too (`handleReq` runs after the method is set).
pub fn method_allows_body(method: &str) -> bool {
    !matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "CONNECT"
    )
}

/// True if any response-body operator applies (so the body must be buffered).
pub fn wants_res_body(resolved: &Resolved) -> bool {
    body_ops_present(resolved, "res")
}

/// Transform a buffered request body per the resolved operators.
///
/// The request pipeline runs the injection first and `reqReplace` after it
/// (`handleReq` adds the transform, then `handleReplace`,
/// `_original/lib/inspectors/req.js:129-130,573`), so a substitution *does* see
/// what `reqPrepend`/`reqAppend` put there — the opposite of the response side.
pub fn transform_req_body(body: Bytes, resolved: &Resolved, ctx: ReqBodyCtx<'_>) -> Bytes {
    let del = Deletions::of(resolved, true);
    // `delete://body` wipes the body *and* anything an operator meant to put
    // around it (`removeBody`, `_original/lib/util/index.js:3592-3598`).
    if del.drop_body {
        return Bytes::new();
    }
    // Request bodies are never injection-gated: whistle's request transform
    // leaves `isHtml` unset, so `allowInject` lets every operator through.
    //
    // The method is the one gate. `GET`, `HEAD`, `OPTIONS` and `CONNECT` get no
    // body, so `reqBody`/`reqPrepend`/`reqAppend` are dropped rather than
    // applied (`delete data.top/bottom/body`,
    // `_original/lib/inspectors/req.js:116-120`) — handing a GET eight bytes of
    // payload is the kind of thing a CDN answers with a 400.
    //
    // Only the *injections* go. `reqReplace` and `delete://reqBody.x` rewrite a
    // body that is already there, and on these methods there is nothing there to
    // rewrite, so they are left to be no-ops of their own accord.
    let mut data = if method_allows_body(ctx.method) {
        let gate = InjectionGate::plain(resolved);
        let mut injection = Injection::default();
        collect_generic(&mut injection, &gate, "req");
        injection.apply(body.to_vec(), false)
    } else {
        body.to_vec()
    };
    if let Some(kind) = params_body_kind(resolved, ctx) {
        data = merge_params_into_body(data, resolved, &del, kind, ctx);
    }
    Bytes::from(apply_replace(
        data,
        resolved,
        "reqReplace",
        req_replace_class(ctx),
    ))
}

/// `params://` merged into the request body, and `delete://reqBody.…` applied
/// alongside it (`handleParams`, `_original/lib/inspectors/req.js:157-232`).
///
/// The two ride the same transform upstream, which is why the deletions land
/// here rather than in a pass of their own: they are only ever applied to a body
/// whose shape whistle recognises.
pub(super) fn merge_params_into_body(
    data: Vec<u8>,
    resolved: &Resolved,
    del: &Deletions,
    kind: ParamsBody,
    ctx: ReqBodyCtx<'_>,
) -> Vec<u8> {
    if kind == ParamsBody::Multipart {
        let Some(boundary) = ctx.content_type.and_then(multipart_boundary) else {
            return data;
        };
        return merge_params_into_multipart(data, resolved, del, &boundary);
    }
    // Not UTF-8 means bytes whistle's text transforms never see. (Upstream tries
    // GB18030 first and re-encodes afterwards; this port stays UTF-8, as it does
    // for every other text transform.)
    let mut text = match String::from_utf8(data) {
        Ok(text) => text,
        Err(e) => return e.into_bytes(),
    };
    match kind {
        ParamsBody::Json => {
            let params = merge_params_values(resolved, "params");
            // An empty body becomes the params outright — `JSON.stringify(params)`
            // on the no-buffer branch (`req.js:214-218`).
            if text.trim().is_empty() {
                let mut obj = serde_json::Value::Object(params.into_iter().collect());
                delete_json_props(&mut obj, &del.body_props);
                return serde_json::to_vec(&obj).unwrap_or_default();
            }
            // Only the first JSON-looking span is patched, so a body wrapped in
            // something else keeps its wrapper (`JSON_RE`, `req.js:18,193`).
            let Some((start, end)) = json_span(&text) else {
                return text.into_bytes();
            };
            let Some(mut base) = crate::rules::url::parse_json(&text[start..end]) else {
                return text.into_bytes();
            };
            // `extend(true, obj, params)` — deep, unlike the fold that built it.
            for (key, value) in params {
                json_deep_merge_key(&mut base, &key, value);
            }
            delete_json_props(&mut base, &del.body_props);
            let Ok(merged) = serde_json::to_string(&base) else {
                return text.into_bytes();
            };
            format!("{}{merged}{}", &text[..start], &text[end..]).into_bytes()
        }
        ParamsBody::Form => {
            let params = merge_params_pairs(resolved, "params");
            text = merge_query_string(&text, &params, &del.body_props);
            text.into_bytes()
        }
        ParamsBody::Multipart => unreachable!("handled above"),
    }
}

/// `params://` merged into a `multipart/form-data` body.
///
/// Upstream rewrites this one *streaming*, part by part, so it never holds a
/// file upload in memory (`_original/lib/inspectors/req.js:226-410`). This port
/// has the whole body in hand already — every other request-body operator
/// buffers — so it splits on the boundary instead, which is far less code for
/// the same result on a well-formed body:
///
/// * a part whose `name=` is in `params` has its **whole** part replaced, so an
///   uploaded file named by a param becomes a plain field (upstream's
///   `toMultipart(name, params[name])` does exactly this);
/// * a part named by `delete://reqBody.<name>` is dropped;
/// * params that matched no part are appended as new parts, in fold order.
///
/// A body that does not start with the boundary is left alone — upstream's
/// `badMultipart` path, which passes the bytes through untouched.
pub(super) fn merge_params_into_multipart(
    data: Vec<u8>,
    resolved: &Resolved,
    del: &Deletions,
    boundary: &str,
) -> Vec<u8> {
    let start = format!("--{boundary}\r\n").into_bytes();
    if !data.starts_with(&start) {
        return data;
    }
    let sep = format!("\r\n--{boundary}").into_bytes();
    // Kept as JSON: an object is a file part, not a field (`toMultipart`).
    let mut params = merge_params_values(resolved, "params");

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut rest = &data[start.len()..];
    loop {
        let Some(at) = find_bytes(rest, &sep) else {
            // No closing boundary: not a body this can rewrite safely.
            return data;
        };
        let part = &rest[..at];
        let name = multipart_part_name(part);
        let deleted = name
            .as_deref()
            .is_some_and(|n| del.body_props.iter().any(|d| d == n));
        // `params[name] = undefined` marks the param consumed, so it is not
        // appended again at the end.
        let replacement = name
            .as_deref()
            .and_then(|n| params.iter().position(|(k, _)| k == n))
            .map(|i| params.remove(i));
        if !deleted {
            match replacement {
                Some((k, v)) => push_multipart_raw(&mut out, boundary, &multipart_part(&k, &v)),
                None => push_multipart_raw(&mut out, boundary, part),
            }
        }
        rest = &rest[at + sep.len()..];
        // `--` after the boundary ends the body; `\r\n` starts the next part.
        if rest.starts_with(b"--") {
            break;
        }
        match rest.strip_prefix(b"\r\n".as_slice()) {
            Some(next) => rest = next,
            None => return data,
        }
    }
    for (name, value) in &params {
        push_multipart_raw(&mut out, boundary, &multipart_part(name, value));
    }
    if out.is_empty() {
        // Every part was deleted and nothing replaced them: emit an empty body
        // rather than a lone terminator.
        return Vec::new();
    }
    out.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    out
}

/// Append one already-encoded part, with the separator it needs.
pub(super) fn push_multipart_raw(out: &mut Vec<u8>, boundary: &str, part: &[u8]) {
    match out.is_empty() {
        true => out.extend_from_slice(format!("--{boundary}\r\n").as_bytes()),
        false => out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes()),
    }
    out.extend_from_slice(part);
}

/// One `params://` entry as a multipart part — `toMultipart`
/// (`_original/lib/inspectors/req.js:61-95`).
///
/// A scalar is a plain field. An **object** is a file: `filename` (or `name`,
/// or else the field's own name), content from `content` or `value` — an
/// object there is pretty-printed JSON, and `base64` supplies raw bytes
/// instead — and a `Content-Type` from `type` (a bare extension is looked up)
/// or from the filename. This port wrote an object as an empty plain field;
/// upstream's `params.test.js` uploads through exactly these two shapes.
pub(super) fn multipart_part(name: &str, value: &serde_json::Value) -> Vec<u8> {
    let serde_json::Value::Object(obj) = value else {
        let text = json_to_param_string(value.clone());
        return format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{text}")
            .into_bytes();
    };
    let truthy = |v: &&serde_json::Value| match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        serde_json::Value::String(s) => !s.is_empty(),
        _ => true,
    };
    // `String(v)`, near enough for what a rules file can hold.
    let js_string = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => "[object Object]".to_string(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|i| json_to_param_string(i.clone()))
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    };
    // `value.filename || value.name`, then `filename == null ? name : filename + ''`.
    let filename = match obj
        .get("filename")
        .filter(truthy)
        .or_else(|| obj.get("name"))
    {
        None | Some(serde_json::Value::Null) => name.to_string(),
        Some(v) => js_string(v),
    };
    // `value.content || value.value || ''`.
    let content = obj
        .get("content")
        .filter(truthy)
        .or_else(|| obj.get("value").filter(truthy));
    let mut raw: Vec<u8> = Vec::new();
    let text = match content {
        Some(v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => {
            serde_json::to_string_pretty(v).unwrap_or_default()
        }
        Some(v) => js_string(v),
        None => {
            if let Some(serde_json::Value::String(b64)) = obj.get("base64").filter(truthy) {
                use base64::Engine as _;
                raw = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .unwrap_or_default();
            }
            String::new()
        }
    };
    let content_type = match obj.get("type") {
        Some(serde_json::Value::String(t)) if t.contains('/') => t.clone(),
        Some(serde_json::Value::String(t)) if !t.is_empty() => {
            content_type_of_ext(&format!("x.{t}"))
                .map(media_type)
                .unwrap_or(t)
                .to_string()
        }
        _ => content_type_of_ext(&filename)
            .map(media_type)
            .unwrap_or("application/octet-stream")
            .to_string(),
    };
    let mut part = format!(
        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
         Content-Type: {content_type}\r\n\r\n{text}"
    )
    .into_bytes();
    part.extend(raw);
    part
}

/// The `name=` of a multipart part, read from the headers ahead of its blank
/// line (`getName` over `NAME_RE`, `_original/lib/inspectors/req.js:41-59`).
pub(super) fn multipart_part_name(part: &[u8]) -> Option<String> {
    let at = find_bytes(part, b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&part[..at]).ok()?;
    let start = headers.to_ascii_lowercase().find("name=")? + "name=".len();
    let rest = &headers[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.find('"').map(|end| quoted[..end].to_string());
    }
    let end = rest.find([';', '\r']).unwrap_or(rest.len());
    let bare = rest[..end].trim();
    // A `'`-quoted name is unwrapped too (`getName`'s second branch).
    let bare = bare
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(bare);
    (!bare.is_empty()).then(|| bare.to_string())
}

/// Index of `needle` in `haystack`.
pub(super) fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Deep-merge one `params` entry into a JSON value at the top level.
pub(super) fn json_deep_merge_key(
    base: &mut serde_json::Value,
    key: &str,
    value: serde_json::Value,
) {
    let serde_json::Value::Object(map) = base else {
        return;
    };
    match map.get_mut(key) {
        Some(slot) => json_deep_merge(slot, &value),
        None => {
            map.insert(key.to_string(), value);
        }
    }
}

/// Transform a buffered response body; `content_type` decides which typed-body
/// families apply and whether injected content is wrapped as markup.
///
/// Operators run in whistle's pipeline order, which is *not* the order they are
/// written: the text transforms (`resMerge`, then `resReplace`) sit ahead of the
/// injecting `WhistleTransform` in the response stream
/// (`_original/lib/inspectors/res.js:1041,1114-1120`; `addTextTransform` splices
/// its sub-pipeline in at the head, `_original/lib/init.js:135-141`). So a
/// substitution never sees prepended or appended content, and `resBody`
/// discards whatever `resMerge`/`resReplace` produced.
pub fn transform_res_body(body: Bytes, resolved: &Resolved, content_type: Option<&str>) -> Bytes {
    let del = Deletions::of(resolved, false);
    if del.drop_body {
        return Bytes::new();
    }
    let class = content_type.and_then(res_class);
    let families = BodyFamilies::of(class);
    // The gate is built from the body as it arrived: whistle decides once, from
    // the *original* first non-whitespace byte, whether injection is allowed.
    let gate = InjectionGate::new(resolved, families.html, &body);
    // A declared `charset=` other than UTF-8 puts the text operators inside a
    // decode/encode pair, and encodes the injected values on the way in. Both
    // halves are upstream's — see [`super::super::coding::charset_of`].
    let charset = super::super::coding::charset_of(content_type);

    let mut data = match charset {
        None => body.to_vec(),
        Some(enc) => super::super::coding::decode_charset(enc, &body).into_bytes(),
    };
    data = apply_res_merge(data, resolved, class, &del);
    data = apply_replace(data, resolved, "resReplace", class);
    if let Some(enc) = charset {
        data = super::super::coding::encode_charset(enc, &String::from_utf8_lossy(&data));
    }

    let mut injection = collect_res_injection(&gate, families);
    if let Some(enc) = charset {
        injection.recode(enc);
    }
    // Only an HTML response gets the doctype, and `disable://doctype` opts out.
    let doctype = families.html && !is_disabled(resolved, "doctype");
    Bytes::from(injection.apply(data, doctype))
}

/// Fill the generic (`res*` / `req*`) contribution of each slot, shared by both
/// sides.
///
/// Several lines carrying the same operator are CRLF-joined in resolution order
/// and pushed as one part. That is byte-identical to pushing each line
/// separately, since the typed families that follow use the same separator.
pub(super) fn collect_generic(injection: &mut Injection, gate: &InjectionGate<'_>, prefix: &str) {
    if let Some(joined) = gate
        .joined(&format!("{prefix}Body"))
        .filter(Joined::claims_body)
    {
        injection.replaces_body = true;
        injection.body.extend(joined.pieces);
    }
    // `*Prepend`/`*Append` are tested the same way: upstream assigns the raw
    // value and tests it for truthiness, so an all-blank one contributes nothing
    // (`_original/lib/inspectors/res.js:1008-1009,1082-1092`).
    for (protocol, slot) in [
        (format!("{prefix}Prepend"), &mut injection.top),
        (format!("{prefix}Append"), &mut injection.bottom),
    ] {
        if let Some(joined) = gate.joined(&protocol).filter(|j| !j.pieces.is_empty()) {
            slot.extend(joined.pieces);
        }
    }
}

/// Fill all three slots for a response, in whistle's order: the generic `res*`
/// operators first, then `css*`, `html*` and `js*`
/// (`_original/lib/inspectors/res.js:1063-1072`).
///
/// On an HTML response the `js*`/`css*` values are markup-wrapped, since raw
/// JavaScript pasted into a page would only render as text.
pub(super) fn collect_res_injection(gate: &InjectionGate<'_>, families: BodyFamilies) -> Injection {
    let mut injection = Injection::default();
    collect_generic(&mut injection, gate, "res");

    let html = families.html;
    for (family, enabled) in [
        ("css", families.css),
        ("html", families.html),
        ("js", families.js),
    ] {
        if !enabled {
            continue;
        }
        // whistle orders the families css → html → js in every slot, so the two
        // wrapped families bracket the raw markup one.
        for (suffix, slot) in [
            ("Body", &mut injection.body),
            ("Prepend", &mut injection.top),
            ("Append", &mut injection.bottom),
        ] {
            let protocol = format!("{family}{suffix}");
            let Some(lines) = gate.lines(&protocol) else {
                continue;
            };
            // Unlike the generic operators, each line is wrapped on its own —
            // upstream marks up every entry of the list before joining
            // (`readRuleList`, `_original/lib/util/index.js:955-966`), so two
            // `jsAppend://` lines become two `<script>` tags, not one holding
            // both bodies. Blanks contribute nothing.
            let mut pushed = false;
            for (value, props) in lines.into_iter().filter(|(v, _)| !v.is_empty()) {
                slot.push(Piece::text(match (html, family) {
                    (true, "js") => wrap_js(value, props).into_bytes(),
                    (true, "css") => wrap_css(value).into_bytes(),
                    _ => value.as_bytes().to_vec(),
                }));
                pushed = true;
            }
            // A typed `*Body` only claims the slot when it actually contributed
            // — upstream folds it in with `joinArr`/`if (body)`, both of which
            // are truthiness tests (`res.js:1068,1085`), so a blank or wholly
            // refused one leaves the original body in place.
            if suffix == "Body" && pushed {
                injection.replaces_body = true;
            }
        }
    }
    injection
}

/// Decides, per operator, whether its content may be injected into a response
/// body — the `safeHtml` / `strictHtml` line properties.
///
/// Ported from `WhistleTransform#allowInject` + `filterHtml`
/// (`_original/lib/util/whistle-transform.js:78-100`). Three things matter:
///
/// * the decision looks at the **original** upstream body, before any operator
///   has rewritten it, and at its first non-whitespace byte only;
/// * only HTML responses are gated — `allowInject` returns `true` immediately
///   for anything else (`whistle-transform.js:68`), so `safeHtml` on a `jsAppend`
///   for a JavaScript response does nothing;
/// * the gate is **per line**: whistle marks each injected buffer with the
///   properties of the rule line that produced it (`_original/lib/util/index.js:1375-1381`)
///   and filters them individually, so one line may inject while another on the
///   same request is refused.
pub(super) struct InjectionGate<'a> {
    pub(super) resolved: &'a Resolved,
    /// The unmodified upstream body the decision is made from.
    pub(super) body: &'a [u8],
    /// False when nothing is gated (non-HTML response, or the request side).
    pub(super) html: bool,
    /// `enable://safeHtml` / `enable://strictHtml`, which upstream stamps onto
    /// every injecting rule of the request (`_original/lib/inspectors/res.js:966-982`).
    pub(super) global: LineProps,
}

impl<'a> InjectionGate<'a> {
    pub(super) fn new(resolved: &'a Resolved, html: bool, body: &'a [u8]) -> Self {
        let global = if html {
            let enabled = enabled_flags(resolved);
            LineProps::from_actions(
                ["strictHtml", "safeHtml"]
                    .into_iter()
                    .filter(|a| enabled.contains(*a)),
            )
        } else {
            LineProps::default()
        };
        InjectionGate {
            resolved,
            body,
            html,
            global,
        }
    }

    /// A gate that refuses nothing, for the request side.
    pub(super) fn plain(resolved: &'a Resolved) -> Self {
        InjectionGate::new(resolved, false, &[])
    }

    /// Every line contributing to an injecting operator, in resolution order,
    /// each paired with its own line properties. Lines the gate refuses are
    /// dropped individually, the way `filterHtml` walks the buffer list.
    ///
    /// `None` means the operator contributes nothing here: either it did not
    /// match, or a request-wide `enable://strictHtml`/`safeHtml` shut the whole
    /// injection off — upstream's `allowInject` returns false for that and the
    /// transform then leaves even the body slot alone
    /// (`_original/lib/util/whistle-transform.js:71-83,107-114`). An empty list,
    /// by contrast, is an operator that matched and had every line refused
    /// individually, which the body slot treats differently.
    pub(super) fn lines(&self, protocol: &str) -> Option<Vec<(&'a str, &'a LineProps)>> {
        Some(
            self.kept(protocol)?
                .into_iter()
                .map(|op| (op.value.as_str(), &op.props))
                .collect(),
        )
    }

    /// The operator lines behind [`lines`](Self::lines).
    pub(super) fn kept(&self, protocol: &str) -> Option<Vec<&'a RuleOp>> {
        let ops = self.resolved.all(protocol);
        if ops.is_empty() || (self.html && !self.global.allows_injection(self.body)) {
            return None;
        }
        Some(
            ops.iter()
                .filter(|op| !self.html || op.props.allows_injection(self.body))
                .collect(),
        )
    }

    /// An operator's surviving lines, blanks dropped, or `None` when it
    /// contributes nothing (see [`InjectionGate::lines`]). One piece per line:
    /// a slot CRLF-joins its pieces, so the bytes are those of joining the
    /// lines first (`joinData`, `_original/lib/util/file-mgr.js:93-109`, whose
    /// loop skips falsy entries), and each line keeps whether it is raw.
    pub(super) fn joined(&self, protocol: &str) -> Option<Joined> {
        let pieces = self
            .kept(protocol)?
            .into_iter()
            .map(Piece::of)
            .filter(|p| !p.bytes.is_empty())
            .collect();
        Some(Joined { pieces })
    }
}

/// One operator's contribution to a slot, after gating.
pub(super) struct Joined {
    /// The non-blank lines that survived the gate, in order.
    pub(super) pieces: Vec<Piece>,
}

impl Joined {
    /// Whether a generic `*Body` operator with this contribution replaces the
    /// body.
    ///
    /// Only when it actually carries something. A blank `resBody://` does
    /// **not** empty the response, which is the opposite of what this port used
    /// to do: upstream assigns `resBody || util.EMPTY_BUFFER`
    /// (`_original/lib/inspectors/res.js:1001-1003`) and `EMPTY_BUFFER` is
    /// `toBuffer('')`, which returns `undefined` for a falsy argument
    /// (`_original/lib/util/common.js:1630-1632`) — not an empty buffer. So
    /// `data.body` stays falsy, `isWhistleTransformData` finds nothing to do
    /// (`_original/lib/util/index.js:1615-1620`), and no transform is built at
    /// all. Measured against whistle 2.10.8: `resBody://()` returns the origin's
    /// page untouched there, and returned an empty body here.
    ///
    /// An operator whose every line the HTML gate refused lands in the same
    /// place by a different route — `filterHtml` empties its list and the join
    /// yields the falsy `''` (`_original/lib/util/whistle-transform.js:47-60,110`)
    /// — so the two need not be told apart.
    pub(super) fn claims_body(&self) -> bool {
        !self.pieces.is_empty()
    }
}

/// `resMerge` — deep-merge a JSON patch into a JSON response body
/// (`_original/lib/inspectors/res.js:1022-1069`).
///
/// The gate is narrower than it looks. Upstream only builds the merge transform
/// for a response that is JS, HTML, JSON, or has no `content-type` at all
/// (`res.js:1022`) — so `resMerge` on a `text/plain` body is inert — and it
/// merges into the **first JSON-looking substring** rather than the whole body
/// (`JSON_RE`, `res.js:846`), which is what lets it patch a JSONP payload
/// without disturbing the callback wrapper.
/// `del` carries the `delete://resBody.a.b` paths, which ride the same
/// transform and are therefore gated the same way.
pub(super) fn apply_res_merge(
    data: Vec<u8>,
    resolved: &Resolved,
    class: Option<ResClass>,
    del: &Deletions,
) -> Vec<u8> {
    let patch = merge_json_patches(resolved, "resMerge");
    if patch.is_none() && del.body_props.is_empty() {
        return data;
    }
    let applies = matches!(
        class,
        None | Some(ResClass::Js) | Some(ResClass::Html) | Some(ResClass::Json)
    );
    if !applies {
        return data;
    }
    let text = match String::from_utf8(data) {
        Ok(text) => text,
        // Not text at all; whistle's transforms only ever see decoded strings.
        Err(e) => return e.into_bytes(),
    };
    // An empty body is replaced by the patch outright (`res.js:1049-1054`).
    if text.is_empty() {
        let Some(mut patch) = patch else {
            return Vec::new();
        };
        delete_json_props(&mut patch, &del.body_props);
        return serde_json::to_vec(&patch).unwrap_or_default();
    }
    // For HTML (and for a typeless response) whistle gives up unless the body
    // *starts* like JSON — `LIKE_JSON_RE`, `res.js:1029`.
    let like_json = text.trim_start().starts_with(['{', '[']);
    if matches!(class, None | Some(ResClass::Html)) && !like_json {
        return text.into_bytes();
    }
    let Some((start, end)) = json_span(&text) else {
        return text.into_bytes();
    };
    let Some(mut base) = crate::rules::url::parse_json(&text[start..end]) else {
        return text.into_bytes();
    };
    if let Some(patch) = &patch {
        json_deep_merge(&mut base, patch);
    }
    delete_json_props(&mut base, &del.body_props);
    let Ok(merged) = serde_json::to_string(&base) else {
        return text.into_bytes();
    };
    format!("{}{merged}{}", &text[..start], &text[end..]).into_bytes()
}

/// Remove dotted paths from a JSON value (`deleteProps`,
/// `_original/lib/util/common.js:1105-1128`). A numeric segment addressing an
/// array element splices it out.
pub(super) fn delete_json_props(value: &mut serde_json::Value, paths: &[String]) {
    for path in paths {
        let keys = parse_json_path(path);
        let mut keys = keys.iter().peekable();
        let mut node = &mut *value;
        while let Some(key) = keys.next() {
            if keys.peek().is_none() {
                match node {
                    serde_json::Value::Object(map) => {
                        map.remove(key.name());
                    }
                    serde_json::Value::Array(list) => {
                        if let Some(i) = array_index(key.name()).filter(|i| *i < list.len()) {
                            list.remove(i);
                        }
                    }
                    _ => {}
                }
                break;
            }
            let next = match node {
                serde_json::Value::Object(map) => map.get_mut(key.name()),
                serde_json::Value::Array(list) => {
                    array_index(key.name()).and_then(|i| list.get_mut(i))
                }
                _ => None,
            };
            match next {
                Some(next) => node = next,
                None => break,
            }
        }
    }
}

/// Split a `delete://…Body.<path>` key into the segments the walk above follows
/// (`parseKeys`, `_original/lib/util/common.js:1077-1103`).
///
/// Three spellings beyond the plain dot, all of them upstream's:
///
/// * `a\.b` names **one** key containing a dot. Backslashes are halved before
///   the dot is read, so `a\\.b` is two segments whose first is `a\`, and
///   `a\\\.b` is one segment `a\.b`;
/// * `"k[0]"` — a quoted segment is taken literally, which is how a key that
///   itself ends in brackets is named;
/// * `a[0][1]` — trailing bracket indices become segments of their own, so the
///   bracket form and `a.0.1` address the same element.
pub(super) fn parse_json_path(path: &str) -> Vec<PathSegment> {
    let mut segments: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = path.trim().chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            match c {
                '.' => segments.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
            continue;
        }
        // `DOT_RE` is `/(\\+)\./g`, so the run of backslashes is maximal and
        // only one that ends at a dot is halved at all.
        let mut run = 1;
        while chars.next_if_eq(&'\\').is_some() {
            run += 1;
        }
        if chars.next_if_eq(&'.').is_none() {
            cur.extend(std::iter::repeat_n('\\', run));
            continue;
        }
        cur.extend(std::iter::repeat_n('\\', run / 2));
        match run % 2 {
            1 => cur.push('.'),
            _ => segments.push(std::mem::take(&mut cur)),
        }
    }
    segments.push(cur);
    segments
        .iter()
        .flat_map(|s| parse_json_key(s.trim()))
        .collect()
}

/// One segment of a path, with its quotes stripped and its trailing `[n]`
/// indices split off (`parseKey`, `_original/lib/util/common.js:1051-1075`).
pub(super) fn parse_json_key(key: &str) -> Vec<PathSegment> {
    if key.len() >= 2 && key.starts_with('"') && key.ends_with('"') {
        return vec![PathSegment::key(&key[1..key.len() - 1])];
    }
    let mut head = key;
    let mut indices: Vec<PathSegment> = Vec::new();
    while let Some((rest, index)) = strip_trailing_index(head) {
        indices.insert(0, PathSegment::index(index));
        head = rest;
    }
    if indices.is_empty() {
        return vec![PathSegment::key(key)];
    }
    // `if (key)` — a bare `[0]` has no name in front of it and contributes none.
    if !head.is_empty() {
        indices.insert(0, PathSegment::key(head));
    }
    indices
}

/// Split a trailing `[n]` off a path segment, matching `ARR_RE`
/// (`_original/lib/util/common.js:1003`): decimal, no leading zero beyond `0`
/// itself, and bounded so the index stays a safe integer.
pub(super) fn strip_trailing_index(key: &str) -> Option<(&str, &str)> {
    let inner = key.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let index = &inner[open + 1..];
    let ok = match index.as_bytes() {
        b"0" => true,
        [first @ b'1'..=b'8', rest @ ..] | [first @ b'9', rest @ ..] => {
            let bound = if *first == b'9' { 14 } else { 15 };
            rest.len() <= bound && rest.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    };
    ok.then(|| (&inner[..open], index))
}

/// A path segment as an array index (`NUM_RE`,
/// `_original/lib/util/common.js:1002`): decimal with no leading zero, which is
/// what `deleteProp` requires before it splices rather than deletes
/// (`common.js:1033-1043`).
pub(super) fn array_index(key: &str) -> Option<usize> {
    match key.as_bytes() {
        b"0" => Some(0),
        [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => key.parse().ok(),
        _ => None,
    }
}

/// The span whistle's `JSON_RE` (`/{[\w\W]*}|\[[\w\W]*\]/`, `res.js:846`) picks
/// out of a body: from the first `{` to the last `}`, or — only when there is no
/// `{` at all — from the first `[` to the last `]`. Greedy on purpose, so a
/// JSONP wrapper's parentheses stay outside.
pub(super) fn json_span(text: &str) -> Option<(usize, usize)> {
    if let (Some(s), Some(e)) = (text.find('{'), text.rfind('}'))
        && s < e
    {
        return Some((s, e + 1));
    }
    let (s, e) = (text.find('[')?, text.rfind(']')?);
    (s < e).then_some((s, e + 1))
}

/// `resReplace` / `reqReplace` — substitute inside a body.
///
/// The value is a list of `pattern=replacement` pairs (`a=1&b=2`) or a JSON
/// object, each applied in turn (`parseRuleJson` → `handleReplace`,
/// `_original/lib/inspectors/res.js:124-145`). Upstream skips the whole
/// operator for a response with no `content-type` or an image one, so those
/// bodies are handed back untouched.
pub(super) fn apply_replace(
    data: Vec<u8>,
    resolved: &Resolved,
    protocol: &str,
    class: Option<ResClass>,
) -> Vec<u8> {
    // Upstream refuses the whole operator for a response with no `content-type`
    // or an image one (`handleReplace`, `_original/lib/inspectors/res.js:129-132`).
    if matches!(class, None | Some(ResClass::Img)) {
        return data;
    }
    let pairs = merge_rule_maps(resolved, protocol);
    if pairs.is_empty() {
        return data;
    }
    // Not UTF-8 means a binary body, which whistle's text transforms never see.
    let mut text = match String::from_utf8(data) {
        Ok(text) => text,
        Err(e) => return e.into_bytes(),
    };
    for (pattern, value) in pairs {
        text = replace_once_or_all(&text, &pattern, &value);
    }
    text.into_bytes()
}

/// The `resReplace://` substitutions in force for a response of this content
/// type, in the order they apply.
///
/// The same list [`apply_replace`] walks, exposed for the body layer that runs
/// on a response still arriving ([`crate::proxy::restream`]). It carries the
/// content-type gate with it so the two paths cannot come to different answers
/// about whether the operator reaches this body at all: upstream refuses the
/// whole operator for a response with no `content-type` or an image one
/// (`handleReplace`, `_original/lib/inspectors/res.js:129-132`).
/// What the injecting operators mean for a body that is **still arriving**.
///
/// The buffered path reaches these bytes by concatenation, which needs an
/// ending. These three do not need one: `resPrepend://` goes before the first
/// byte, `resAppend://` after the last, and `resBody://` says there is no origin
/// body at all. See [`crate::proxy::body::surround`].
pub struct StreamInjection {
    /// `resPrepend://`, its lines already CRLF-joined.
    pub top: Vec<u8>,
    /// `resAppend://`, likewise. Never delivered on a stream that does not end,
    /// which is the honest answer rather than a missing feature: there is no
    /// "after" a body that never finishes.
    pub bottom: Vec<u8>,
    /// `resBody://` — the body *is* this, and the origin's is not waited for.
    pub replacement: Option<Vec<u8>>,
}

/// The injection for a response whose body is still arriving, or `None` when no
/// operator asks for one.
///
/// Only the generic `res*` family is collected. The typed families
/// (`htmlPrepend`, `jsAppend`, …) are absent because they are selected by the
/// response being HTML/JS/CSS, and a body that is still arriving here is an
/// event stream — none of those.
///
/// The gate is [`InjectionGate::plain`]: no doctype is stamped and nothing is
/// refused. Both follow from the response not being HTML — upstream stamps a
/// doctype only there, and its `allowInject` returns true whenever `isHtml` is
/// unset (`_original/lib/util/whistle-transform.js:80-83`). `safeHtml` and
/// `strictHtml` gate HTML injection specifically and so have nothing to say.
pub fn res_stream_injection(resolved: &Resolved) -> Option<StreamInjection> {
    let mut injection = Injection::default();
    collect_generic(&mut injection, &InjectionGate::plain(resolved), "res");
    let (mut top, mut bottom) = (Vec::new(), Vec::new());
    join_into(&mut top, std::mem::take(&mut injection.top));
    join_into(&mut bottom, std::mem::take(&mut injection.bottom));
    let replacement = injection.replaces_body.then(|| {
        let mut body = Vec::new();
        join_into(&mut body, std::mem::take(&mut injection.body));
        body
    });
    let empty = top.is_empty() && bottom.is_empty() && replacement.is_none();
    (!empty).then_some(StreamInjection {
        top,
        bottom,
        replacement,
    })
}

pub fn res_replace_pairs(resolved: &Resolved, content_type: Option<&str>) -> Vec<(String, String)> {
    let class = content_type.and_then(res_class);
    if matches!(class, None | Some(ResClass::Img)) {
        return Vec::new();
    }
    merge_rule_maps(resolved, "resReplace")
}

/// Collapse every matching line of a key/value operator into one ordered map,
/// the way `readRuleList`'s JSON branch does
/// (`_original/lib/util/index.js:1300-1312`).
///
/// The mechanism is worth spelling out, because it is not "apply each line in
/// turn": upstream **reverses** the list and `extend`s it onto its own last
/// entry. Two consequences, both reproduced here:
///
/// * a key written on several lines takes the **first** (highest-priority)
///   line's value — consistent with first-match-wins everywhere else;
/// * the resulting key *order* is the last line's keys first, then whatever
///   each earlier line adds. Since `handleReplace` and `parsePathReplace` walk
///   that order, the last line's substitutions are applied first
///   (`_original/lib/inspectors/res.js:134-144`,
///   `_original/lib/util/index.js:1014-1022`).
///
/// Shared by `reqReplace`/`resReplace`/`urlReplace`, which all reach the body
/// and path rewriters through `parseRuleJson`.
pub(super) fn merge_rule_maps(resolved: &Resolved, protocol: &str) -> Vec<(String, String)> {
    merge_line_maps(
        resolved
            .all(protocol)
            .iter()
            .map(|op| parse_replace_pairs(&op.value, op.value_is_content)),
    )
}

/// The `extend`-over-the-reversed-list core of [`merge_rule_maps`], over lines
/// already parsed into pairs.
///
/// Generic in the value so that `params://` can fold as JSON — the flat
/// `String` view cannot carry a nested object into a JSON request body.
pub(super) fn merge_line_maps<V>(
    lines: impl DoubleEndedIterator<Item = Vec<(String, V)>>,
) -> Vec<(String, V)> {
    let mut out: Vec<(String, V)> = Vec::new();
    for pairs in lines.rev() {
        for (key, value) in pairs {
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => out.push((key, value)),
            }
        }
    }
    out
}

/// Split a `*Replace` value into `pattern` → `replacement` pairs.
///
/// `parseQuery` (via `tryParseMatcher`) splits on `&` then on the first `=`, so
/// `resReplace://a=1&b=2` is two substitutions, not one that inserts `1&b=2`.
/// A `{json}` value is an object of the same shape.
pub(super) fn parse_replace_pairs(spec: &str, is_content: bool) -> Vec<(String, String)> {
    // The same three roads every data value takes — JSON, then a query string,
    // then the line format ([`parse_data_object`]). The line format was missing
    // here, and `pathReplace.md` leads with it: a `{value}` holding
    // `test: name` per line is how the page spells "several substitutions", and
    // it did nothing at all in this port.
    let Some(serde_json::Value::Object(map)) = parse_data_object(spec, false, is_content) else {
        return Vec::new();
    };
    map.into_iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            (k, val)
        })
        .collect()
}

/// Apply one `pattern` → `value` substitution the way whistle's transforms do.
///
/// A pattern spelled `/…/[gimu]` is a regular expression (`ORIG_REG_EXP`,
/// `_original/lib/util/index.js:611`), and follows JavaScript's rule that
/// **without the `g` flag only the first match is replaced**. Anything else —
/// including a half-formed `/a/x` — is a literal replace-all
/// (`str.split(key).join(value)`, `_original/lib/util/index.js:2267`).
pub(super) fn replace_once_or_all(text: &str, pattern: &str, value: &str) -> String {
    let Some((source, flags)) = split_regexp(pattern) else {
        return text.replace(pattern, value);
    };
    // `/.*/ ` and `/.+/` mean "replace the whole body", special-cased upstream
    // so the empty trailing match cannot duplicate the replacement
    // (`ALL_RE`, `_original/lib/util/replace-pattern-transform.js:7,24-27`).
    if matches!(source, ".*" | ".+") {
        return value.to_string();
    }
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    let Ok(re) = regex::Regex::new(&format!("{prefix}{source}")) else {
        return text.to_string();
    };
    // Expanded by hand rather than through the `regex` crate's own replacement
    // syntax: `$$1` has to percent-encode the group, and no replacement string
    // can express that. See [`crate::rules::replace::expand`].
    let expand = |caps: &regex::Captures<'_>| {
        let groups: Vec<&str> = (0..=9)
            .map(|n| caps.get(n).map_or("", |m| m.as_str()))
            .collect();
        crate::rules::replace::expand(value, &groups)
    };
    match flags.contains('g') {
        true => re.replace_all(text, expand).into_owned(),
        false => re.replace(text, expand).into_owned(),
    }
}

/// Split `/source/flags` into its two halves, or `None` when the pattern is not
/// that shape. Mirrors `ORIG_REG_EXP = /^\/(.+)\/([igmu]{0,4})$/`: the source is
/// greedy (so `/a\/b/` keeps its inner slash) and every flag character must be
/// one of `igmu`.
pub(super) fn split_regexp(pattern: &str) -> Option<(&str, &str)> {
    let rest = pattern.strip_prefix('/')?;
    let end = rest.rfind('/')?;
    let (source, flags) = (&rest[..end], &rest[end + 1..]);
    let ok = !source.is_empty()
        && flags.len() <= 4
        && flags.chars().all(|c| matches!(c, 'i' | 'g' | 'm' | 'u'));
    ok.then_some((source, flags))
}

/// Substitute a `pattern` → `replacement` list in `text`, in order.
pub(super) fn apply_str_replace(text: &str, pairs: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (pattern, value) in pairs {
        out = replace_once_or_all(&out, pattern, value);
    }
    out
}

/// Remove length/encoding headers so hyper recomputes them for a rewritten body.
pub fn strip_length_headers(headers: &mut HeaderMap) {
    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);
}
