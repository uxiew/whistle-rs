use super::*;
use crate::rules::RuleManager;

/// Proxy facts for tests that reach the template engine.
fn test_env() -> super::super::template::ProxyEnv<'static> {
    super::super::template::ProxyEnv {
        host: "",
        port: 8899,
        version: "9.9.9",
    }
}

/// Tests drive the async parts on a runtime of their own; `resolve_target`
/// is async because a `pac://` rule may have to fetch its script.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

/// The target `resolved` produces for `info`, which must not fail.
fn resolved_target(info: &ReqInfo, resolved: &Resolved) -> Target {
    rt().block_on(resolve_target(
        info,
        &crate::proxy::dest::Destination::of(info, resolved),
        resolved,
    ))
    .expect("resolve_target")
}

fn resolve(rules: &str, url: &str) -> Resolved {
    let mut m = RuleManager::new();
    m.set_text(rules);
    let (scheme, rest) = url.split_once("://").unwrap();
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let info = build_req_info(
        "GET",
        scheme,
        host,
        if scheme == "https" { 443 } else { 80 },
        path,
        &HeaderMap::new(),
        None,
    );
    m.resolve(&info)
}

/// Request facts for the body operators: a POST carrying `content_type`.
fn body_ctx(content_type: Option<&str>) -> ReqBodyCtx<'_> {
    ReqBodyCtx {
        method: "POST",
        content_type,
    }
}

/// A method that carries no body is not given one
/// (`hasRequestBody` → `delete data.top/bottom/body`,
/// `_original/lib/inspectors/req.js:116-120`).
///
/// Measured before the fix: a `GET` through a `reqBody://INJECTED` rule
/// reached the origin as `{"method":"GET","len":"8","body":"INJECTED"}`.
/// A GET with a payload is what a CDN answers with a 400.
#[test]
fn a_bodyless_method_is_not_given_a_body() {
    let resolved = resolve("example.com reqBody://INJECTED\n", "http://example.com/");
    let sent = |method: &str| {
        let ctx = ReqBodyCtx {
            method,
            content_type: None,
        };
        let out = transform_req_body(Bytes::new(), &resolved, ctx);
        String::from_utf8(out.to_vec()).expect("utf-8")
    };

    // The four upstream refuses, in the spellings a client might send.
    for method in ["GET", "HEAD", "OPTIONS", "CONNECT", "get", " Head "] {
        assert_eq!(sent(method), "", "{method} must carry no body");
    }
    // …and the ones that do take one.
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        assert_eq!(sent(method), "INJECTED", "{method} takes the injection");
    }

    // Nothing is buffered for a method that will discard it anyway.
    let get = ReqBodyCtx {
        method: "GET",
        content_type: None,
    };
    let post = ReqBodyCtx {
        method: "POST",
        content_type: None,
    };
    assert!(!wants_req_body(&resolved, get));
    assert!(wants_req_body(&resolved, post));
}

/// The gate reads the method being **forwarded**, so `method://post` on a
/// GET restores the injection — upstream sets the method before
/// `handleReq` runs.
#[test]
fn rewriting_the_method_decides_whether_a_body_applies() {
    let resolved = resolve(
        "example.com reqBody://INJECTED method://post\n",
        "http://example.com/",
    );
    // The caller passes the rewritten method, which is what `serve` does.
    let ctx = ReqBodyCtx {
        method: "POST",
        content_type: None,
    };
    assert!(wants_req_body(&resolved, ctx));
    assert_eq!(
        &transform_req_body(Bytes::new(), &resolved, ctx)[..],
        b"INJECTED"
    );
    assert!(method_allows_body("POST") && !method_allows_body("GET"));
}

/// As [`resolve`], returning the [`ReqInfo`] as well for the callers that
/// need it (the include merge, which resolves the included text in the
/// request's own scope).
fn resolve_with_info(rules: &str, url: &str) -> (ReqInfo, Resolved) {
    let mut m = RuleManager::new();
    m.set_text(rules);
    let (scheme, rest) = url.split_once("://").unwrap();
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let info = build_req_info(
        "GET",
        scheme,
        host,
        if scheme == "https" { 443 } else { 80 },
        path,
        &HeaderMap::new(),
        None,
    );
    let resolved = m.resolve(&info);
    (info, resolved)
}

/// `reqCookies` merges into the existing header: a name already present
/// keeps its position and a new one is appended. Within the query a name
/// with no `=` sets an **empty** value rather than deleting the cookie
/// (that is `delete://reqCookies.<name>`).
#[test]
fn req_cookies_merge_in_place() {
    let resolved = resolve(
        "example.com reqCookies://a=1&b=2\nexample.com reqCookies://old=&c\n",
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    headers.insert(hyper::header::COOKIE, "old=x; keep=y".parse().unwrap());
    apply_req_cookies(&mut headers, &resolved);
    let cookie = headers
        .get(hyper::header::COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    // The merge is `extend` over the *reversed* line list, so the later
    // line's names are laid down first (`readRuleList`,
    // `_original/lib/util/index.js:1325-1331`).
    assert_eq!(cookie, "old=; keep=y; c=; a=1; b=2");
}

/// A whole value with no `=` is a *location*, not a query string: upstream
/// tries to load it as a file and sets no cookie at all
/// (`tryParseMatcher`, `_original/lib/util/index.js:1165-1171`). This port
/// read it as a name with an empty value, so `resCookies://sid` sent a
/// `Set-Cookie: sid=` real whistle never sends.
///
/// Found by putting the same rule through real whistle and through this
/// port — `tests/differential/cases-delete.js`.
#[test]
fn a_cookie_value_with_no_equals_names_a_file_and_sets_nothing() {
    let resolved = resolve("example.com reqCookies://sid\n", "http://example.com/");
    let mut headers = HeaderMap::new();
    headers.insert(hyper::header::COOKIE, "keep=y".parse().unwrap());
    apply_req_cookies(&mut headers, &resolved);
    assert_eq!(headers.get(hyper::header::COOKIE).unwrap(), "keep=y");

    let resolved = resolve("example.com resCookies://sid\n", "http://example.com/");
    let mut headers = HeaderMap::new();
    apply_res_cookies(&mut headers, &resolved, &Deletions::default(), None);
    assert!(headers.get(hyper::header::SET_COOKIE).is_none());
}

#[test]
fn res_body_replaced() {
    let resolved = resolve("example.com/x resBody://NEW\n", "http://example.com/x");
    assert!(wants_res_body(&resolved));
    let out = transform_res_body(Bytes::from_static(b"OLD"), &resolved, None);
    assert_eq!(&out[..], b"NEW");
}

/// `resReplace` runs *before* the injection — its transform sits ahead of
/// the `WhistleTransform` in whistle's response pipeline — so it rewrites
/// the upstream body but never the prepended or appended text.
#[test]
fn res_body_prepend_append_replace() {
    let resolved = resolve(
        "example.com/x resPrepend://<!--foo-->\nexample.com/x resAppend://<!--foo-->\nexample.com/x resReplace://foo=bar\n",
        "http://example.com/x",
    );
    assert!(wants_res_body(&resolved));
    let out = transform_res_body(
        Bytes::from_static(b"a foo b"),
        &resolved,
        Some("text/plain"),
    );
    assert_eq!(
        String::from_utf8_lossy(&out),
        "<!--foo-->a bar b<!--foo-->",
        "the substitution must not reach the injected text"
    );
}

/// A response with no `content-type` (or an image one) is skipped outright
/// by `handleReplace` (`_original/lib/inspectors/res.js:129-132`).
#[test]
fn res_replace_needs_a_replaceable_content_type() {
    let resolved = resolve(
        "example.com/x resReplace://foo=bar\n",
        "http://example.com/x",
    );
    for ct in [None, Some("image/png")] {
        let out = transform_res_body(Bytes::from_static(b"a foo b"), &resolved, ct);
        assert_eq!(&out[..], b"a foo b", "{ct:?} should not be rewritten");
    }
    let out = transform_res_body(
        Bytes::from_static(b"a foo b"),
        &resolved,
        Some("text/plain"),
    );
    assert_eq!(&out[..], b"a bar b");
}

/// The value is a `&`-separated list of `pattern=replacement` pairs, each
/// applied in turn (`parseQuery` via `tryParseMatcher`).
#[test]
fn res_replace_applies_every_pair() {
    let resolved = resolve(
        "example.com/x resReplace://a=1&b=2\n",
        "http://example.com/x",
    );
    let out = transform_res_body(Bytes::from_static(b"a b a"), &resolved, Some("text/plain"));
    assert_eq!(&out[..], b"1 2 1");
}

#[test]
fn res_merge_json_deep() {
    let resolved = resolve(
        "example.com/x resMerge://{\"a\":2,\"c\":{\"d\":1}}\n",
        "http://example.com/x",
    );
    let out = transform_res_body(
        Bytes::from_static(br#"{"a":1,"b":1,"c":{"e":2}}"#),
        &resolved,
        Some("application/json"),
    );
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["a"], 2); // overwritten
    assert_eq!(v["b"], 1); // kept
    assert_eq!(v["c"]["d"], 1); // added
    assert_eq!(v["c"]["e"], 2); // kept (deep merge)
}

/// `delete://` reaches the body too: a bare `body` empties it (discarding
/// any injection with it), and `resBody.<path>` removes a JSON property.
#[test]
fn delete_reaches_the_body() {
    let resolved = resolve(
        "example.com/x delete://body\nexample.com/x resAppend://tail\n",
        "http://example.com/x",
    );
    assert!(wants_res_body(&resolved));
    let out = transform_res_body(Bytes::from_static(b"keep?"), &resolved, Some("text/plain"));
    assert_eq!(&out[..], b"");

    let resolved = resolve(
        "example.com/x delete://resBody.a&resB.c.d\n",
        "http://example.com/x",
    );
    assert!(wants_res_body(&resolved));
    let out = transform_res_body(
        Bytes::from_static(br#"{"a":1,"b":2,"c":{"d":3,"e":4}}"#),
        &resolved,
        Some("application/json"),
    );
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("a").is_none() && v["c"].get("d").is_none());
    assert_eq!((v["b"].as_i64(), v["c"]["e"].as_i64()), (Some(2), Some(4)));

    // `req.body` is the request's alone.
    let resolved = resolve("example.com/x delete://req.body\n", "http://example.com/x");
    assert!(wants_req_body(&resolved, body_ctx(None)) && !wants_res_body(&resolved));
    assert_eq!(
        &transform_req_body(
            Bytes::from_static(b"x"),
            &resolved,
            body_ctx(Some("text/plain"))
        )[..],
        b""
    );
}

/// The `/regexp/flags` form follows JavaScript's `String#replace`: without
/// the `g` flag only the **first** match is substituted.
/// `resMerge` only builds its transform for a JS, HTML, JSON or typeless
/// response (`_original/lib/inspectors/res.js:1022`).
#[test]
fn res_merge_is_gated_on_the_content_type() {
    let resolved = resolve(
        "example.com/x resMerge://{\"a\":2}\n",
        "http://example.com/x",
    );
    let body = br#"{"a":1}"#;
    for ct in ["application/json", "text/html", "application/javascript"] {
        let out = transform_res_body(Bytes::from_static(body), &resolved, Some(ct));
        assert_eq!(&out[..], br#"{"a":2}"#, "{ct} should merge");
    }
    for ct in ["text/plain", "application/xml", "image/png"] {
        let out = transform_res_body(Bytes::from_static(body), &resolved, Some(ct));
        assert_eq!(&out[..], body, "{ct} should be left alone");
    }
}

/// The patch lands in the first JSON-looking *substring*, so a JSONP
/// wrapper survives (`JSON_RE`, `_original/lib/inspectors/res.js:846`).
#[test]
fn res_merge_patches_a_json_substring() {
    let resolved = resolve(
        "example.com/x resMerge://{\"a\":2}\n",
        "http://example.com/x",
    );
    let out = transform_res_body(
        Bytes::from_static(br#"cb({"a":1});"#),
        &resolved,
        Some("application/javascript"),
    );
    assert_eq!(String::from_utf8_lossy(&out), r#"cb({"a":2});"#);
    // An empty body is replaced by the patch outright.
    let out = transform_res_body(Bytes::new(), &resolved, Some("application/json"));
    assert_eq!(&out[..], br#"{"a":2}"#);
    // An HTML body that does not *start* like JSON is left alone.
    let out = transform_res_body(
        Bytes::from_static(br#"<p>{"a":1}</p>"#),
        &resolved,
        Some("text/html"),
    );
    assert_eq!(String::from_utf8_lossy(&out), r#"<p>{"a":1}</p>"#);
}

#[test]
fn res_body_regex_replace_honours_the_g_flag() {
    let once = resolve(
        "example.com/x resReplace:///\\d+/=N\n",
        "http://example.com/x",
    );
    let out = transform_res_body(
        Bytes::from_static(b"id=123 and 45"),
        &once,
        Some("text/plain"),
    );
    assert_eq!(&out[..], b"id=N and 45");

    let all = resolve(
        "example.com/x resReplace:///\\d+/g=N\n",
        "http://example.com/x",
    );
    let out = transform_res_body(
        Bytes::from_static(b"id=123 and 45"),
        &all,
        Some("text/plain"),
    );
    assert_eq!(&out[..], b"id=N and N");
}

/// A pattern that is not exactly `/source/[igmu]` is a literal string, not
/// a regexp — `ORIG_REG_EXP` anchors both ends and admits only those flags.
#[test]
fn a_half_formed_regexp_is_a_literal_pattern() {
    assert_eq!(split_regexp("/\\d+/g"), Some(("\\d+", "g")));
    assert_eq!(split_regexp("/a\\/b/"), Some(("a\\/b", "")));
    assert_eq!(split_regexp("/a/x"), None, "`x` is not a whistle flag");
    assert_eq!(split_regexp("/a/gimux"), None);
    assert_eq!(split_regexp("//"), None, "an empty source is not a regexp");
    assert_eq!(split_regexp("a/b"), None);

    let resolved = resolve("example.com/x resReplace:////=Z\n", "http://example.com/x");
    let out = transform_res_body(
        Bytes::from_static(b"a // b // c"),
        &resolved,
        Some("text/plain"),
    );
    assert_eq!(
        &out[..],
        b"a Z b Z c",
        "a literal pattern replaces them all"
    );
}

/// `$&` and `$1` reach the replacement, and `/.*/ ` swaps the whole body.
#[test]
fn regex_replacement_back_references() {
    let resolved = resolve(
        "example.com/x resReplace:///(\\w+)@(\\w+)/g=$2.$1x\n",
        "http://example.com/x",
    );
    let out = transform_res_body(
        Bytes::from_static(b"a@b c@d"),
        &resolved,
        Some("text/plain"),
    );
    assert_eq!(&out[..], b"b.ax d.cx", "`$1x` is group 1 then a literal x");

    // `\$1` escapes the reference, so the literal `$1` survives.
    let esc = resolve(
        "example.com/x resReplace:///(\\w+)@/g=\\$1-$1\n",
        "http://example.com/x",
    );
    let out = transform_res_body(Bytes::from_static(b"a@"), &esc, Some("text/plain"));
    assert_eq!(&out[..], b"$1-a");

    let all = resolve(
        "example.com/x resReplace:///.*/g=ONLY\n",
        "http://example.com/x",
    );
    let out = transform_res_body(Bytes::from_static(b"whatever"), &all, Some("text/plain"));
    assert_eq!(&out[..], b"ONLY", "`/.*/ ` replaces the body exactly once");
}

/// The `$$`-prefixed spelling of a reference inserts the group
/// **percent-encoded** (`encode = $2[1] === '$'`,
/// `_original/lib/util/replace-pattern-transform.js:78-88`). Previously the
/// whole form was silently literal, so a rule asking for an encoded group
/// got the characters `$$1` in its output.
#[test]
fn an_encoding_back_reference_percent_encodes_the_group() {
    let body = |rule: &str, input: &'static str| {
        let resolved = resolve(
            &format!("example.com/x resReplace://{rule}\n"),
            "http://example.com/x",
        );
        let out = transform_res_body(
            Bytes::from_static(input.as_bytes()),
            &resolved,
            Some("text/plain"),
        );
        String::from_utf8(out.to_vec()).expect("utf-8")
    };

    // A rule value cannot carry a space — the line parser splits on
    // whitespace — so the space under test lives in the *input*.
    //
    // `$$1` encodes; a plain `$1` on the same line does not.
    assert_eq!(body("/(.+)/=[$$1][$1]", "a b"), "[a%20b][a b]");
    // `$$&` (the whole match, encoded) cannot travel through a rule value:
    // `&` separates the pairs of a `resReplace`. Same expansion, called
    // where the rule layer would have called it.
    assert_eq!(replace_once_or_all("a b", "/a.b/", "$$&"), "a%20b");
    // Reserved characters an encoded group is there to protect.
    assert_eq!(body("/(.+)/=$$1", "x/y?z=1&w"), "x%2Fy%3Fz%3D1%26w");
    // Non-ASCII goes out as UTF-8 percent-escapes, as in JavaScript.
    assert_eq!(body("/(.+)/=$$1", "中"), "%E4%B8%AD");
    // An empty group encodes to nothing rather than to a stray `%`.
    assert_eq!(body("/x(z?)/=[$$1]", "x"), "[]");
    // `\$$1` escapes the whole reference, `\\$$1` keeps one backslash
    // and still encodes.
    assert_eq!(body("/(.+)/=\\$$1", "a b"), "$$1");
    assert_eq!(body("/(.+)/=\\\\$$1", "a b"), "\\a%20b");
    // A `$b`-prefixed reference names a value list this port has no
    // counterpart for, so it is left exactly as written.
    assert_eq!(body("/(a)/=[$b1]", "a"), "[$b1]");
}

#[test]
fn req_body_replaced_only_when_present() {
    let none = resolve("example.com host://1.1.1.1\n", "http://example.com/");
    assert!(!wants_req_body(&none, body_ctx(None)));
    let some = resolve("example.com reqBody://HELLO\n", "http://example.com/");
    assert!(wants_req_body(&some, body_ctx(None)));
    let out = transform_req_body(
        Bytes::from_static(b"orig"),
        &some,
        body_ctx(Some("text/plain")),
    );
    assert_eq!(&out[..], b"HELLO");
}

/// A compressed **request** body is decompressed before the operators see it
/// and compressed again on the way out — the same pair the response path
/// uses, and for the same reason.
///
/// Without it `reqReplace://` searched a gzip stream for plaintext and found
/// nothing, `reqAppend://` wrote its text after the end of that stream, and
/// `reqBody://` sent plain bytes still labelled `Content-Encoding: gzip` —
/// a request the origin cannot inflate. Measured against whistle 2.10.8,
/// which delivered `"REWRITTEN body"`, `"ORIGINAL bodyEND"` and `"NEW"`
/// gzipped where this port delivered the original, a truncated stream and
/// unreadable plain text.
#[test]
fn a_compressed_request_body_is_rewritten_inside_its_coding() {
    use crate::proxy::coding;

    let sent = |rule: &str, ct: &str| {
        let wire = coding::encode(coding::Coding::Gzip, b"ORIGINAL body").expect("gzip");
        let decoded = coding::decode_for_rewrite(Bytes::from(wire), Some("gzip"), usize::MAX);
        let restore = decoded.restore;
        let new = transform_req_body(
            decoded.body,
            &resolve(&format!("example.com {rule}\n"), "http://example.com/"),
            body_ctx(Some(ct)),
        );
        let (out, coded) = coding::reencode(new, restore, None);
        assert_eq!(
            coded,
            coding::Coding::Gzip,
            "{rule} must go back out gzipped"
        );
        String::from_utf8(coding::decode(coding::Coding::Gzip, &out).expect("inflates"))
            .expect("utf-8")
    };

    assert_eq!(
        sent("reqReplace://ORIGINAL=REWRITTEN", "text/plain"),
        "REWRITTEN body"
    );
    assert_eq!(sent("reqAppend://END", "text/plain"), "ORIGINAL bodyEND");
    assert_eq!(sent("reqBody://NEW", "text/plain"), "NEW");

    // A coding this proxy cannot undo is not re-encoded over: the operators
    // run on bytes they will not usefully match, and nothing is corrupted.
    let opaque = coding::decode_for_rewrite(
        Bytes::from_static(b"not really zstd"),
        Some("zstd"),
        usize::MAX,
    );
    assert!(!opaque.restore.plain);
    let (out, coded) = coding::reencode(opaque.body, opaque.restore, None);
    assert_eq!(coded, coding::Coding::Identity);
    assert_eq!(&out[..], b"not really zstd");
}

#[test]
fn auth_and_forwarded_for() {
    let resolved = resolve(
        "example.com auth://user:pass\nexample.com forwardedFor://9.9.9.9\n",
        "http://example.com/",
    );
    let mut parts = hyper::Request::builder()
        .uri("http://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    apply_request(&mut parts, &resolved);
    assert_eq!(
        parts.headers.get("authorization").unwrap(),
        "Basic dXNlcjpwYXNz"
    );
    assert_eq!(parts.headers.get("x-forwarded-for").unwrap(), "9.9.9.9");
}

/// `auth://` takes three shapes, not one (`getAuthByRules`,
/// `_original/lib/util/index.js:3645-3662`, `getAuthBasic` at `:3668-3685`,
/// `handleAuth` at `req.js:150-155`).
///
/// This port understood only `user:pass` and base64-encoded everything else
/// whole, so `auth://{"username":"u","password":"p"}` authenticated as the
/// user `{"username"` with the password `"u","password":"p"}` — a 401 that
/// reads as the rule never having run. The `"proxy":true` field, which
/// moves the credentials to `Proxy-Authorization`, had nowhere to land at
/// all.
///
/// The expectations are upstream's own: `getAuthByRules`, `formatAuth`,
/// `getAuthBasic` and `parseQuery` were lifted verbatim and run over these
/// inputs.
#[test]
fn auth_takes_a_json_object_and_a_query_string_too() {
    let sent = |value: &str| {
        let resolved = resolve(
            &format!("example.com auth://{value}\n"),
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &resolved);
        for name in ["authorization", "proxy-authorization"] {
            if let Some(v) = parts.headers.get(name) {
                return Some(format!("{name}: {}", v.to_str().unwrap()));
            }
        }
        None
    };
    let auth = |v: &str| Some(format!("authorization: {v}"));
    let proxy = |v: &str| Some(format!("proxy-authorization: {v}"));

    // ── `user:pass`, which already worked ──
    assert_eq!(sent("user:pass"), auth("Basic dXNlcjpwYXNz"));
    // Only the *first* colon splits.
    assert_eq!(sent("u:p:q"), auth("Basic dTpwOnE="));
    // A username with no password carries no colon either.
    assert_eq!(sent("user"), auth("Basic dXNlcg=="));
    assert_eq!(sent("user:"), auth("Basic dXNlcjo="));
    assert_eq!(sent(":pass"), auth("Basic OnBhc3M="));

    // ── the JSON object ──
    assert_eq!(
        sent(r#"{"username":"u","password":"p"}"#),
        auth("Basic dTpw")
    );
    // `"proxy":true` re-addresses the credentials at the proxy.
    assert_eq!(
        sent(r#"{"username":"u","password":"p","proxy":true}"#),
        proxy("Basic dTpw")
    );
    assert_eq!(sent(r#"{"username":"u"}"#), auth("Basic dQ=="));
    // A password alone still gets its colon, so the server sees two fields.
    assert_eq!(sent(r#"{"password":"p"}"#), auth("Basic OnA="));
    assert_eq!(
        sent(r#"{"username":null,"password":"p"}"#),
        auth("Basic OnA=")
    );
    // Non-strings are stringified (`String(username)`).
    assert_eq!(
        sent(r#"{"username":123,"password":true}"#),
        auth("Basic MTIzOnRydWU=")
    );
    // Naming neither half sends nothing — and so does a JSON object
    // upstream cannot parse, which it turns into an empty one.
    assert_eq!(sent("{}"), None);
    // (A value with a space in it would be two tokens on the line, so the
    // unparseable case is spelled without one.)
    assert_eq!(sent("{not-json}"), None);
    // `!!obj.proxy`, so the JSON `false` really is false.
    assert_eq!(
        sent(r#"{"username":"u","proxy":false}"#),
        auth("Basic dQ==")
    );
    // …but the *string* `"false"` is not.
    assert_eq!(
        sent(r#"{"username":"u","proxy":"false"}"#),
        proxy("Basic dQ==")
    );

    // ── `username=…&password=…` ──
    assert_eq!(sent("username=u&password=p"), auth("Basic dTpw"));
    assert_eq!(sent("username=u"), auth("Basic dQ=="));
    assert_eq!(sent("password=p"), auth("Basic OnA="));
    assert_eq!(sent("username=u&password=p&proxy=1"), proxy("Basic dTpw"));
    // Every query value is a non-empty string, so `proxy=false` is **true**
    // here. Use the JSON spelling when the answer is no.
    assert_eq!(
        sent("username=u&password=p&proxy=false"),
        proxy("Basic dTpw")
    );
    // Values are taken raw: `parseQuery` is given the escaping decoder, so
    // a `%2F` reaches the server as `%2F` and a `+` stays a `+`.
    assert_eq!(
        sent("username=u&password=p%2Fx"),
        auth("Basic dTpwJTJGeA==")
    );
    assert_eq!(sent("username=a+b&password=p"), auth("Basic YStiOnA="));
    // Only the first `=` splits a pair.
    assert_eq!(sent("username=u&password=a=b"), auth("Basic dTphPWI="));
    assert_eq!(sent("username=u&password="), auth("Basic dTo="));
    // `AUTH_RE` is anchored *and* case-sensitive, so this is not the query
    // form at all — it falls through to the colon split and is sent whole.
    assert_eq!(
        sent("Username=u&password=p"),
        auth("Basic VXNlcm5hbWU9dSZwYXNzd29yZD1w")
    );

    // ── a slash makes it a location, not credentials ──
    //
    // `SLASH_RE` (`util/index.js:102,:3653`) tests the whole value, so a
    // password with a slash in it is not one. Measured against whistle
    // 2.10.8: each of these sends **no** `Authorization` header there. This
    // port used to split on the colon anyway, on the reading that a slash in
    // a password should still work — which meant the documented
    // `auth:///Users/john/config/auth.json` reached the origin with the
    // local filesystem path as its credentials whenever the file was
    // missing.
    assert_eq!(sent("u:pa/ss"), None);
    assert_eq!(sent("/no/such/auth.json"), None);
    assert_eq!(sent("temp/blank.json"), None);
    assert_eq!(sent("dom\\user:secret"), None);
    // The JSON and query forms are tested first, so a slash inside either
    // is a password character after all.
    assert_eq!(
        sent(r#"{"username":"u","password":"p/q"}"#),
        auth("Basic dTpwL3E=")
    );
    assert_eq!(sent("username=u&password=p/q"), auth("Basic dTpwL3E="));
}

/// A value read out of the location the rule named takes upstream's *other*
/// road — `parseRuleJson`, not `getAuthByRules` — so the documented file is
/// the line format and never `user:pass`.
///
/// Measured, both halves. `auth://<file holding "username: admin\npassword:
/// my secret password">` sends `admin:my secret password` in whistle; this
/// port sent the file's whole text as the credentials, because it applied
/// the inline reading to content the inline reading was never offered.
#[test]
fn a_loaded_auth_value_is_read_as_pairs() {
    let loaded = |text: &str| {
        let op = RuleOp {
            protocol: "auth".to_string(),
            value: text.to_string(),
            value_is_content: true,
            value_loaded: true,
            ..Default::default()
        };
        auth_of(&op).basic()
    };
    // The docs' own file: `username:` on one line, `password:` on the next.
    assert_eq!(
        loaded("username: admin\npassword: my secret password\n"),
        Some("Basic YWRtaW46bXkgc2VjcmV0IHBhc3N3b3Jk".to_string()),
    );
    // JSON in a file is the same object by the other spelling.
    assert_eq!(
        loaded(r#"{"username":"admin","password":"secret"}"#),
        Some("Basic YWRtaW46c2VjcmV0".to_string()),
    );
    // A file holding `user:pass` names no `username` key, so it is not
    // credentials — the inline spelling is where that form belongs.
    assert_eq!(loaded("admin:secret"), None);
    // `proxy` travels with them.
    let op = RuleOp {
        protocol: "auth".to_string(),
        value: "username: u\npassword: p\nproxy: true\n".to_string(),
        value_is_content: true,
        value_loaded: true,
        ..Default::default()
    };
    assert!(auth_of(&op).proxy);
}

#[test]
fn delay_parsing() {
    let resolved = resolve(
        "example.com reqDelay://250\nexample.com resDelay://40\n",
        "http://example.com/",
    );
    assert_eq!(req_delay_ms(&resolved), Some(250));
    assert_eq!(res_delay_ms(&resolved), Some(40));
}

#[test]
fn speed_parsing() {
    let resolved = resolve(
        "example.com reqSpeed://16\nexample.com resSpeed://20\n",
        "http://example.com/",
    );
    assert_eq!(req_speed_kbps(&resolved), Some(16.0));
    assert_eq!(res_speed_kbps(&resolved), Some(20.0));
}

#[test]
fn url_replace_and_params() {
    let resolved = resolve(
        "example.com/api urlReplace://v1=v2\nexample.com/api params://token=abc\n",
        "http://example.com/api/v1/users?a=1",
    );
    let out = rewrite_path("/api/v1/users?a=1", &resolved, body_ctx(None));
    assert!(out.starts_with("/api/v2/users?"));
    assert!(out.contains("a=1"));
    assert!(out.contains("token=abc"));
}

#[test]
fn params_override_existing_key() {
    let resolved = resolve("example.com params://a=2\n", "http://example.com/p?a=1&b=3");
    let out = rewrite_path("/p?a=1&b=3", &resolved, body_ctx(None));
    assert!(out.contains("b=3"));
    assert!(out.contains("a=2"));
    assert!(!out.contains("a=1"));
}

// ── `params://` merged into the request body ──

/// How much of a request body the merging operators are allowed to hold.
///
/// The response twin: `enable://resMergeBigData` and
/// `lineProps://enableBigData` on the `resMerge://` line raise this
/// request's ceiling to upstream's big one (`res.js:21-22,:1013`), which
/// matters when the configured knob is smaller.
#[test]
fn the_response_merge_flags_raise_this_requests_ceiling() {
    const BIG: usize = 16 * 1024 * 1024;
    let limit = |rules: &str, configured: usize| {
        res_body_limit(&resolve(rules, "http://example.com/"), configured)
    };
    assert_eq!(limit("example.com resMerge://{\"a\":1}\n", 1024), 1024);
    assert_eq!(
        limit(
            "example.com resMerge://{\"a\":1} lineProps://enableBigData\n",
            1024
        ),
        BIG
    );
    assert_eq!(limit("example.com enable://resMergeBigData\n", 1024), BIG);
    assert_eq!(
        limit(
            "example.com enable://resMergeBigData\nexample.com disable://resMergeBigData\n",
            1024
        ),
        1024
    );
    // A ceiling already higher than upstream's stays where it is.
    assert_eq!(
        limit("example.com enable://resMergeBigData\n", BIG * 2),
        BIG * 2
    );
}

/// `lineProps://enableBigData` on the `reqMerge://` line raises it, exactly
/// as `enable://reqMergeBigData` does — upstream passes the one straight
/// into the place it reads the other (`handleParams`,
/// `_original/lib/inspectors/req.js:163,:564`).
///
/// This port read `enableBigData` as a setting of whistle's own rather than
/// a line property, so `docs/LINE_PROPS.md` called it exposed-only. The
/// differential bench disagreed: a 3 MB JSON body with the property written
/// was merged by whistle and forwarded unchanged here.
#[test]
fn enable_big_data_raises_the_request_body_ceiling() {
    const BIG: usize = 16 * 1024 * 1024;
    let limit = |rules: &str| req_body_limit(&resolve(rules, "http://example.com/p"));

    assert_eq!(limit("example.com reqMerge://{\"a\":1}\n"), REQ_BODY_LIMIT);
    assert_eq!(
        limit("example.com reqMerge://{\"a\":1} lineProps://enableBigData\n"),
        BIG
    );
    // `reqMerge` and `params` are one operator here as they are upstream.
    assert_eq!(
        limit("example.com params://a=1 lineProps://enableBigData\n"),
        BIG
    );
    // The request-wide flag still says the same, and still answers to its
    // cancellation — the line property has none to answer to.
    assert_eq!(limit("example.com enable://reqMergeBigData\n"), BIG);
    assert_eq!(
        limit("example.com enable://reqMergeBigData disable://reqMergeBigData\n"),
        REQ_BODY_LIMIT
    );
    assert_eq!(
        limit("example.com params://a=1 lineProps://enableBigData disable://reqMergeBigData\n"),
        BIG
    );
    // Line-scoped: on some other line it raises nothing.
    assert_eq!(
        limit("example.com params://a=1\nexample.com resHeaders://x=1 lineProps://enableBigData\n"),
        REQ_BODY_LIMIT
    );
}

/// `transform_req_body` for a POST carrying `ct`.
fn merged_body(rules: &str, ct: Option<&str>, body: &str) -> String {
    let resolved = resolve(rules, "http://example.com/p");
    let out = transform_req_body(Bytes::from(body.to_string()), &resolved, body_ctx(ct));
    String::from_utf8_lossy(&out).into_owned()
}

/// A form body takes the params, and the query string does **not** — the
/// two are exclusive upstream (`_params = hasBody ? null : params`,
/// `_original/lib/inspectors/req.js:421`). `urlParams` still goes to the
/// query either way.
#[test]
fn params_merge_into_a_form_body() {
    const FORM: &str = "application/x-www-form-urlencoded";
    assert_eq!(
        merged_body("example.com params://b=2\n", Some(FORM), "a=1"),
        "a=1&b=2"
    );
    // A name already in the body is replaced in place.
    assert_eq!(
        merged_body("example.com params://a=9\n", Some(FORM), "a=1&b=2"),
        "b=2&a=9"
    );
    // An empty body becomes the params outright.
    assert_eq!(
        merged_body("example.com params://a=1\n", Some(FORM), ""),
        "a=1"
    );

    let resolved = resolve(
        "example.com params://b=2 urlParams://c=3\n",
        "http://example.com/p?a=1",
    );
    let ctx = body_ctx(Some(FORM));
    assert_eq!(rewrite_path("/p?a=1", &resolved, ctx), "/p?a=1&c=3");
    // Without a body to take them, the params land in the query as before.
    assert_eq!(
        rewrite_path("/p?a=1", &resolved, body_ctx(None)),
        "/p?a=1&b=2&c=3"
    );
}

/// `isUrlEncoded` is POST-only upstream
/// (`_original/lib/util/common.js:692-695`), so the same rule on a PUT sends
/// the params to the query string. Odd, and reproduced.
#[test]
fn a_form_body_takes_params_only_on_post() {
    const FORM: &str = "application/x-www-form-urlencoded";
    let resolved = resolve("example.com params://b=2\n", "http://example.com/p");
    let put = ReqBodyCtx {
        method: "PUT",
        content_type: Some(FORM),
    };
    assert!(!wants_req_body(&resolved, put));
    assert_eq!(rewrite_path("/p", &resolved, put), "/p?b=2");

    let post = ReqBodyCtx {
        method: "POST",
        content_type: Some(FORM),
    };
    assert!(wants_req_body(&resolved, post));
    assert_eq!(rewrite_path("/p", &resolved, post), "/p");
}

/// A JSON body is patched, deeply, and only across its first JSON-looking
/// span so a wrapper survives (`JSON_RE`, `_original/lib/inspectors/req.js:18`).
#[test]
fn params_merge_into_a_json_body() {
    const JSON: &str = "application/json";
    assert_eq!(
        merged_body("example.com params://b=2\n", Some(JSON), "{\"a\":1}"),
        "{\"a\":1,\"b\":\"2\"}"
    );
    // A `{json}` value keeps its structure and merges deeply — the flat
    // `name=value` view could only have inserted a string.
    assert_eq!(
        merged_body(
            "example.com params://{\"a\":{\"y\":2}}\n",
            Some(JSON),
            "{\"a\":{\"x\":1}}"
        ),
        "{\"a\":{\"x\":1,\"y\":2}}"
    );
    // The wrapper around the JSON span is untouched.
    assert_eq!(
        merged_body("example.com params://b=2\n", Some(JSON), "cb({\"a\":1})"),
        "cb({\"a\":1,\"b\":\"2\"})"
    );
    // An empty body becomes the params, serialised as JSON.
    assert_eq!(
        merged_body("example.com params://a=1\n", Some(JSON), ""),
        "{\"a\":\"1\"}"
    );
    // A GET carries no body upstream, so the params address the query.
    let resolved = resolve("example.com params://b=2\n", "http://example.com/p");
    let get = ReqBodyCtx {
        method: "GET",
        content_type: Some(JSON),
    };
    assert_eq!(rewrite_path("/p", &resolved, get), "/p?b=2");
}

/// `delete://reqBody.<path>` rides the same transform upstream, so it only
/// ever reaches a body whose shape whistle recognises.
#[test]
fn delete_req_body_props() {
    assert_eq!(
        merged_body(
            "example.com delete://reqBody.a.x\n",
            Some("application/json"),
            "{\"a\":{\"x\":1,\"y\":2}}"
        ),
        "{\"a\":{\"y\":2}}"
    );
    assert_eq!(
        merged_body(
            "example.com delete://reqBody.a\n",
            Some("application/x-www-form-urlencoded"),
            "a=1&b=2"
        ),
        "b=2"
    );
}

/// The path is `parseKeys`', not a plain split on dots: a backslash escapes
/// a dot into the key, quotes take a segment literally, and a trailing
/// `[n]` is an index of its own. This port split on dots alone, so
/// `delete://reqBody.a[0]` named a key no JSON body has and deleted
/// nothing.
///
/// Found by putting the same rule through real whistle and through this
/// port — `tests/differential/cases-delete.js`.
#[test]
fn a_json_delete_path_reads_upstreams_escapes_and_indices() {
    let json = |rule: &str, body: &str| {
        merged_body(
            &format!("example.com delete://{rule}\n"),
            Some("application/json"),
            body,
        )
    };
    // A backslash escapes the dot, naming one key that contains it.
    assert_eq!(json(r"reqBody.a\.b", r#"{"a.b":1,"c":2}"#), r#"{"c":2}"#);
    // Two backslashes are one backslash and a real separator, so this
    // names the key `b` inside the key `a\`.
    assert_eq!(
        json(r"reqBody.a\\.b", r#"{"a\\":{"b":1,"c":2}}"#),
        r#"{"a\\":{"c":2}}"#
    );
    // Brackets index an array, at the top level and nested.
    assert_eq!(json("reqBody.a[0]", r#"{"a":[1,2,3]}"#), r#"{"a":[2,3]}"#);
    assert_eq!(
        json("reqBody.a.b[1]", r#"{"a":{"b":[1,2,3]}}"#),
        r#"{"a":{"b":[1,3]}}"#
    );
    // …and the dotted spelling names the same element.
    assert_eq!(json("reqBody.a.0", r#"{"a":[1,2,3]}"#), r#"{"a":[2,3]}"#);
    // Quotes take a segment literally, which is how a key ending in
    // brackets is named at all.
    assert_eq!(
        json(r#"reqBody."a[0]""#, r#"{"a[0]":1,"b":2}"#),
        r#"{"b":2}"#
    );
    // An index with a leading zero is not one (`NUM_RE`), so it deletes
    // nothing rather than the wrong element.
    assert_eq!(json("reqBody.a.01", r#"{"a":[1,2,3]}"#), r#"{"a":[1,2,3]}"#);
}

/// The pieces of `parseKeys` on their own, including the shapes a rule can
/// write but a body rarely carries.
#[test]
fn a_json_delete_path_splits_the_way_parse_keys_does() {
    // The names alone; `a_bracket_index_opens_an_array` covers the other
    // half of a segment, which is whether it came from brackets.
    let path = |s: &str| {
        parse_json_path(s)
            .into_iter()
            .map(|seg| seg.name().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(path("a.b.c"), ["a", "b", "c"]);
    assert_eq!(path(" a . b "), ["a", "b"]);
    assert_eq!(path(r"a\.b"), ["a.b"]);
    // Backslashes are halved: two make one, and the dot separates again.
    assert_eq!(path(r"a\\.b"), [r"a\", "b"]);
    assert_eq!(path(r"a\\\.b"), [r"a\.b"]);
    // A run not ending at a dot is left alone.
    assert_eq!(path(r"a\\b"), [r"a\\b"]);
    assert_eq!(path("a[0][12]"), ["a", "0", "12"]);
    // A bare index has no name in front of it.
    assert_eq!(path("[3]"), ["3"]);
    // Not an index: a leading zero, and anything that is not decimal.
    assert_eq!(path("a[01]"), ["a[01]"]);
    assert_eq!(path("a[x]"), ["a[x]"]);
    assert_eq!(path(r#""k[0]""#), ["k[0]"]);
}

/// `parseProps` — the split that honours escapes.
///
/// Upstream runs one regexp over the whole value
/// (`_original/lib/util/common.js:73,:111-127`), so a separator behind an
/// odd number of backslashes is text and `\s`/`\t`/`\n`/`\r`/`\f`/`\v`
/// become the characters they name. Measured against whistle 2.10.8 through
/// `delete://reqBody.…`, which is where `delete.md` documents the table.
#[test]
fn a_prop_list_splits_on_unescaped_separators() {
    let props = |value: &str| parse_props(value);
    assert_eq!(props("a|b"), ["a", "b"]);
    assert_eq!(props("a&b"), ["a", "b"]);
    // An odd run keeps the separator as text and halves the backslashes.
    assert_eq!(props(r"a\|b"), ["a|b"]);
    assert_eq!(props(r"a\&b"), ["a&b"]);
    assert_eq!(props(r"a\\|b"), [r"a\", "b"]);
    assert_eq!(props(r"a\\\|b"), [r"a\|b"]);
    // The named characters.
    assert_eq!(props(r"a\nb"), ["a\nb"]);
    assert_eq!(props(r"a\tb"), ["a\tb"]);
    assert_eq!(props(r"a\sb"), ["a b"]);
    assert_eq!(props(r"a\rb\fc\vd"), ["a\rb\u{c}c\u{b}d"]);
    // An even run leaves the letter alone.
    assert_eq!(props(r"a\\nb"), [r"a\nb"]);
    // A backslash before anything else is text.
    assert_eq!(props(r"a\.b"), [r"a\.b"]);
    assert_eq!(props(r"a\zb"), [r"a\zb"]);
    // `delete.md`'s own example, both keys at once.
    assert_eq!(
        props(r"reqBody.a\nb|reqBody.test\|\&test"),
        ["reqBody.a\nb", "reqBody.test|&test"]
    );
}

/// A bracket index opens an **array**; a dotted number does not.
///
/// Upstream's `parseKey` turns `a[0]` into `['a', 0]` with a number for the
/// index, and `parsePlainText` opens an array exactly when the next key is
/// one (`_original/lib/util/common.js:1064,:1209-1212`). A dotted `a.0`
/// stays two strings and therefore two objects. Measured against whistle
/// 2.10.8 through `reqMerge://{block}`: `a[0]: 1` merges as `{"a":["1"]}`,
/// which this port used to spell `{"a":{"0":"1"}}`.
#[test]
fn a_bracket_index_opens_an_array() {
    let merged = |line: &str| {
        parse_data_object(line, true, true)
            .map(|v| v.to_string())
            .unwrap_or_default()
    };
    assert_eq!(merged("a[0]: 1"), r#"{"a":["1"]}"#);
    assert_eq!(merged("a[1]: x"), r#"{"a":[null,"x"]}"#);
    assert_eq!(merged("a[0][1]: x"), r#"{"a":[[null,"x"]]}"#);
    assert_eq!(merged("a.0: 1"), r#"{"a":{"0":"1"}}"#);
    assert_eq!(merged("a.b[0]: 1"), r#"{"a":{"b":["1"]}}"#);
    // Two lines into the same array, and one that overwrites.
    assert_eq!(merged("a[0]: x\na[1]: y"), r#"{"a":["x","y"]}"#);
    assert_eq!(merged("a[0]: x\na[0]: y"), r#"{"a":["y"]}"#);
}

/// An object-valued param is a **file** part, in the two shapes upstream's
/// `params.test.js` uploads with — `{filename, content}` and a bare
/// `{value}`, whose filename is the field's own name — plus `base64` for
/// raw bytes and `type` for the content type (`toMultipart`,
/// `_original/lib/inspectors/req.js:61-95`).
#[test]
fn an_object_param_is_a_file_part() {
    const CT: &str = "multipart/form-data; boundary=X";
    let body = "--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X--";
    let json = r#"{"file1":{"filename":"text.txt","content":"xxx"},"file2":{"value":"1234567890"},"file3":{"base64":"AAE=","type":"png"}}"#;
    let out = merged_body(&format!("example.com params://{json}\n"), Some(CT), body);
    assert_eq!(
        out,
        "--X\r\n\
             Content-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"file1\"; filename=\"text.txt\"\r\n\
             Content-Type: text/plain\r\n\r\nxxx\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"file2\"; filename=\"file2\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n1234567890\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"file3\"; filename=\"file3\"\r\n\
             Content-Type: image/png\r\n\r\n\u{0}\u{1}\r\n\
             --X--"
    );
}

/// A multipart body: a part named by a param is replaced whole, one named
/// by `delete://reqBody.` is dropped, and an unmatched param is appended.
#[test]
fn params_merge_into_a_multipart_body() {
    const CT: &str = "multipart/form-data; boundary=X";
    let body = "--X\r\n\
                    Content-Disposition: form-data; name=\"keep\"\r\n\r\nkept\r\n\
                    --X\r\n\
                    Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\
                    Content-Type: application/octet-stream\r\n\r\nRAW\r\n\
                    --X\r\n\
                    Content-Disposition: form-data; name=\"gone\"\r\n\r\nbye\r\n\
                    --X--";
    let out = merged_body(
        "example.com params://file=replaced&extra=new delete://reqBody.gone\n",
        Some(CT),
        body,
    );
    assert_eq!(
        out,
        "--X\r\n\
             Content-Disposition: form-data; name=\"keep\"\r\n\r\nkept\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"file\"\r\n\r\nreplaced\r\n\
             --X\r\n\
             Content-Disposition: form-data; name=\"extra\"\r\n\r\nnew\r\n\
             --X--"
    );
    // A body that does not open with the boundary is passed through, which
    // is upstream's `badMultipart` path.
    assert_eq!(
        merged_body("example.com params://a=1\n", Some(CT), "not multipart"),
        "not multipart"
    );
    // No boundary in the content type means no parts to find, so the params
    // fall back to the query string.
    let resolved = resolve("example.com params://a=1\n", "http://example.com/p");
    let no_boundary = ReqBodyCtx {
        method: "POST",
        content_type: Some("multipart/form-data"),
    };
    assert!(!wants_req_body(&resolved, no_boundary));
    assert_eq!(rewrite_path("/p", &resolved, no_boundary), "/p?a=1");
}

/// A request no `params://` line matched never looks at its own body: the
/// buffering decision is answered from the resolved set alone.
#[test]
fn params_cost_nothing_when_no_rule_asks() {
    let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/p");
    for ct in [
        None,
        Some("application/json"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=X"),
    ] {
        assert!(!wants_req_body(&resolved, body_ctx(ct)));
    }
}

#[test]
fn delete_headers_and_cookies() {
    let resolved = resolve(
        "example.com delete://reqHeaders.x-req&reqCookies.sid\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    h.insert("x-req", "1".parse().unwrap());
    h.insert("x-keep", "2".parse().unwrap());
    h.insert(hyper::header::COOKIE, "sid=abc; keep=1".parse().unwrap());
    apply_deletes(&mut h, &Deletions::of(&resolved, true), true);
    assert!(h.get("x-req").is_none());
    assert!(h.get("x-keep").is_some());
    let c = h.get(hyper::header::COOKIE).unwrap().to_str().unwrap();
    assert!(!c.contains("sid="));
    assert!(c.contains("keep=1"));
}

/// Deleting a request cookie **rebuilds** the header rather than editing it,
/// which is what `setReqCookies` does: a pair that arrived without a `=`
/// leaves with one, and when nothing survives the header is set empty
/// rather than removed. This port removed it, so a server that branches on
/// `Cookie` being present saw the opposite of what whistle sends.
///
/// Found by putting the same rule through real whistle and through this
/// port — `tests/differential/cases-delete.js`.
#[test]
fn deleting_every_request_cookie_leaves_an_empty_header() {
    let cookie_after = |rule: &str, sent: &str| {
        let resolved = resolve(
            &format!("example.com delete://{rule}\n"),
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert(hyper::header::COOKIE, sent.parse().unwrap());
        apply_deletes(&mut h, &Deletions::of(&resolved, true), true);
        h.get(hyper::header::COOKIE)
            .map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        cookie_after("reqCookies.sid", "sid=abc"),
        Some(String::new())
    );
    // A valueless pair gains its `=`, and a trailing `;` becomes one.
    assert_eq!(
        cookie_after("reqCookies.sid", "sid=abc; flag; other=1;"),
        Some("flag=; other=1; =".to_string())
    );
    // With no `Cookie` at all there is nothing to rebuild, and none is made.
    let resolved = resolve(
        "example.com delete://reqCookies.sid\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    apply_deletes(&mut h, &Deletions::of(&resolved, true), true);
    assert!(h.get(hyper::header::COOKIE).is_none());
}

/// whistle matches `delete://` keys against a fixed set of anchored
/// patterns (`_original/lib/util/index.js:2661-2669`) and ignores anything
/// else — including a bare header name, and the singular `header.`.
#[test]
fn delete_keys_follow_upstreams_spellings() {
    let names = |rule: &str, request_side: bool| {
        let r = resolve(
            &format!("example.com delete://{rule}\n"),
            "http://example.com/",
        );
        Deletions::of(&r, request_side).headers
    };
    for spelling in [
        "resHeaders.x-a",
        "resHeader.x-a",
        "resH.x-a",
        "res.headers.x-a",
        "res.h.x-a",
        "RESHEADERS.x-a",
        "headers.x-a",
    ] {
        assert_eq!(names(spelling, false), ["x-a"], "{spelling}");
    }
    for ignored in ["x-a", "header.x-a", "reqHeaders.x-a", "Headers.x-a"] {
        assert!(names(ignored, false).is_empty(), "{ignored} must be inert");
    }
    // The type/charset keys are their own thing, not header names.
    let r = resolve(
        "example.com delete://resType&res.charset\n",
        "http://example.com/",
    );
    let del = Deletions::of(&r, false);
    assert!(del.drop_type && del.drop_charset && del.headers.is_empty());
}

/// `headerReplace://` is read as JSON **or** as a query string, and the
/// second is the shorter spelling people actually write. This port took
/// only the first, so `headerReplace://resH.x-a:/yes/=no` parsed, matched
/// and rewrote nothing.
///
/// Found by putting the same rule through real whistle and through this
/// port and comparing the answers — see the differential bench in the
/// commit that added it.
#[test]
fn header_replace_reads_the_query_string_spelling_too() {
    let replaced = |rule: &str| {
        let resolved = resolve(
            &format!("example.com headerReplace://{rule}\n"),
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-a", "yes".parse().unwrap());
        h.insert("x-b", "keep".parse().unwrap());
        apply_header_replace(&mut h, &resolved, HeaderScope::Response);
        h.get("x-a").map(|v| v.to_str().unwrap().to_string())
    };
    // The two spellings mean the same thing.
    assert_eq!(replaced("resH.x-a:/yes/=no"), Some("no".to_string()));
    assert_eq!(
        replaced(r#"{"resH.x-a:/yes/":"no"}"#),
        Some("no".to_string())
    );
    // `&` separates entries and the *first* `=` splits one — a pattern may
    // contain `/` and `:` but the value starts after the first `=`.
    assert_eq!(
        replaced("resH.x-b:/keep/=x&resH.x-a:/yes/=no"),
        Some("no".to_string())
    );
    // A literal pattern, not a regexp, in the same spelling.
    assert_eq!(replaced("resH.x-a:yes=no"), Some("no".to_string()));
    // Scope inheritance still works across the query-string form: the
    // second key names no scope, so it reuses `x-a`.
    assert_eq!(
        replaced("resH.x-a:/nope/=x&:/yes/=no"),
        Some("no".to_string())
    );
}

/// The form the documentation leads with — several `pattern=value` pairs on
/// one header (`res.header-name:p1=v1&p2=v2`,
/// <https://wproxy.org/docs/rules/headerReplace.html>).
///
/// The second pair carries **no colon at all**, and upstream's
/// `key.substring(index + 1)` with `index === -1` makes the whole key the
/// pattern. This port required a colon and dropped the pair — so only the
/// first of the documented pairs applied. The earlier test here happened to
/// write the second pattern as `:/yes/`, with a colon, and walked straight
/// past the bug.
#[test]
fn several_patterns_may_share_one_header() {
    let replaced = |rule: &str| {
        let resolved = resolve(
            &format!("example.com headerReplace://{rule}\n"),
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-mark", "html-and-more".parse().unwrap());
        apply_header_replace(&mut h, &resolved, HeaderScope::Response);
        h.get("x-mark").map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        replaced("res.x-mark:html=X&more=Y"),
        Some("X-and-Y".to_string())
    );
    // Three of them, and a regexp among the bare ones.
    assert_eq!(
        replaced("res.x-mark:html=X&/and/=AND&more=Y"),
        Some("X-AND-Y".to_string())
    );
    // A *scoped* key with no colon has an empty name and is dropped, which
    // is the case the colon check was written for.
    assert_eq!(replaced("res.x-mark"), Some("html-and-more".to_string()));
}

/// A `headerReplace` pattern is a regexp only in the `/…/flags` spelling;
/// anything else is a literal, replaced everywhere it occurs.
#[test]
fn header_replace_patterns() {
    let replaced = |rule: &str, value: &str| {
        let resolved = resolve(
            &format!("example.com headerReplace://{rule}\n"),
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-foo", value.parse().unwrap());
        apply_header_replace(&mut h, &resolved, HeaderScope::Response);
        h.get("x-foo").map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        replaced("{\"resH.x-foo:/ba./g\":\"XX\"}", "bar-baz"),
        Some("XX-XX".to_string())
    );
    assert_eq!(
        replaced("{\"resH.x-foo:ba.\":\"XX\"}", "bar-baz"),
        Some("bar-baz".to_string()),
        "`ba.` is a literal, and `bar-baz` does not contain it"
    );
    assert_eq!(
        replaced("{\"resH.x-foo:ba\":\"XX\"}", "bar-baz"),
        Some("XXr-XXz".to_string())
    );
    // `reqHeaders.`/`resHeaders.` are not among upstream's four prefixes.
    assert_eq!(
        replaced("{\"resHeaders.x-foo:bar\":\"XX\"}", "bar"),
        Some("bar".to_string())
    );
    // A key with no `:` has no pattern at all.
    assert_eq!(
        replaced("{\"res.x-foo\":\"XX\"}", "bar"),
        Some("bar".to_string())
    );
}

/// A repeated `set-cookie` is rewritten entry by entry and every entry
/// stays; any other repeated header is joined and rewritten as one, the
/// shapes Node hands upstream (`handleHeaderReplace`,
/// `_original/lib/util/index.js:2274-2292`).
#[test]
fn header_replace_keeps_every_set_cookie() {
    let resolved = resolve(
        "example.com headerReplace://res.set-cookie:test=abc headerReplace://res.x-dup:b=B\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    for (k, v) in [
        ("set-cookie", "test"),
        ("set-cookie", "test222"),
        ("x-dup", "a"),
        ("x-dup", "b"),
    ] {
        h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
    }
    apply_header_replace(&mut h, &resolved, HeaderScope::Response);
    let all = |name| {
        h.get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(all("set-cookie"), ["abc", "abc222"]);
    assert_eq!(all("x-dup"), ["a, B"]);
}

/// An unscoped key inherits the previous key's scope **and its header
/// name**, keeping only its own pattern — upstream nulls `name` when a key
/// names a scope and otherwise leaves it standing
/// (`parseHeaderReplace`, `_original/lib/util/index.js:2214-2233`). Two
/// substitutions on one header therefore need only name it once.
#[test]
fn an_unscoped_header_replace_key_inherits_the_previous_one() {
    let replaced = |rule: &str, value: &str| {
        let resolved = resolve(
            &format!("example.com headerReplace://{rule}\n"),
            "http://example.com/",
        );
        let mut h = HeaderMap::new();
        h.insert("x-foo", value.parse().unwrap());
        apply_header_replace(&mut h, &resolved, HeaderScope::Response);
        h.get("x-foo").map(|v| v.to_str().unwrap().to_string())
    };

    // Both entries land on `x-foo`: the second names no header at all.
    assert_eq!(
        replaced(r#"{"res.x-foo:a":"1",":b":"2"}"#, "ab"),
        Some("12".to_string())
    );
    // A leading unscoped key has nothing to inherit and is dropped.
    assert_eq!(replaced(r#"{":a":"1"}"#, "ab"), Some("ab".to_string()));
    // The inherited scope is the *previous* one, so a `req.` key in between
    // takes the following unscoped key with it — away from this side.
    assert_eq!(
        replaced(r#"{"res.x-foo:a":"1","req.x-foo:b":"2",":a":"9"}"#, "aa"),
        Some("11".to_string()),
        "the trailing key inherited `req` and must not touch the response"
    );
}

/// `enable://gzip|br|deflate` forces the response's outgoing coding, with
/// upstream's `br` > `gzip` > `deflate` precedence (`getEnableEncoding`,
/// `_original/lib/util/index.js:1534-1548`).
#[test]
fn forced_encoding_follows_upstream_precedence() {
    use super::super::coding::Coding;
    let forced = |rule: &str| {
        forced_encoding(&resolve(
            &format!("example.com {rule}\n"),
            "http://example.com/",
        ))
    };
    assert_eq!(forced("host://1.1.1.1"), None);
    assert_eq!(forced("enable://gzip"), Some(Coding::Gzip));
    assert_eq!(forced("enable://deflate"), Some(Coding::Deflate));
    assert_eq!(forced("enable://br"), Some(Coding::Brotli));
    // br wins over gzip wins over deflate.
    assert_eq!(forced("enable://gzip|deflate"), Some(Coding::Gzip));
    assert_eq!(forced("enable://br|gzip|deflate"), Some(Coding::Brotli));
}

/// `enable://showHost` reports the address the request actually reached
/// (`req.hostIp || LOCALHOST`, `_original/lib/inspectors/res.js:1197-1199`).
/// Previously the flag was inert.
#[test]
fn enable_show_host_reports_the_address_reached() {
    let header = |rules: &str, server_ip: Option<&str>| {
        let resolved = resolve(rules, "http://example.com/");
        let mut info = build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &HeaderMap::new(),
            None,
        );
        info.res = Some(build_res_info(
            200,
            &HeaderMap::new(),
            server_ip.map(str::to_string),
            Some(80),
        ));
        let mut parts = res_parts(&[]);
        apply_response_for(&mut parts, &resolved, Some(&info));
        parts
            .headers
            .get("x-host-ip")
            .map(|v| v.to_str().unwrap().to_string())
    };

    assert_eq!(
        header("example.com enable://showHost\n", Some("93.184.216.34")),
        Some("93.184.216.34".to_string())
    );
    // No address — nothing connected — falls back to whistle's own literal
    // rather than omitting the header the rule asked for.
    assert_eq!(
        header("example.com enable://showHost\n", None),
        Some("127.0.0.1".to_string())
    );
    // Inert without the flag.
    assert_eq!(
        header("example.com host://1.1.1.1\n", Some("1.1.1.1")),
        None
    );
    // It runs after `resHeaders://`, as upstream does, so the flag wins.
    assert_eq!(
        header(
            "example.com enable://showHost resHeaders://x-host-ip=mine\n",
            Some("93.184.216.34")
        ),
        Some("93.184.216.34".to_string())
    );
}

/// `responseFor://` annotates the **response** with who served it. It used
/// to fetch its value as a URL — an unrequested outbound call on every
/// matching request, to whatever a rules file named — and write the result
/// onto the outgoing *request*, where the client never saw it. Nothing
/// upstream makes a network call here.
#[test]
fn response_for_annotates_rather_than_fetches() {
    let annotate = |rules: &str, res_headers: Vec<(&str, &str)>, req_headers: Vec<(&str, &str)>| {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let mut hm = HeaderMap::new();
        for (k, v) in &req_headers {
            hm.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let mut info = build_req_info("GET", "http", "example.com", 80, "/x", &hm, None);
        info.res = Some(crate::rules::ResInfo {
            status: 200,
            headers: Vec::new(),
            server_ip: Some("10.0.0.9".into()),
            server_port: Some(80),
        });
        let resolved = mgr.resolve(&info);
        let mut out = HeaderMap::new();
        for (k, v) in &res_headers {
            out.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        annotate_response_for(&mut out, &resolved, Some(&info));
        out.get("x-whistle-response-for")
            .map(|v| v.to_str().unwrap().to_string())
    };

    // A plain value is emitted as written.
    assert_eq!(
        annotate("example.com responseFor://svc-a\n", vec![], vec![]),
        Some("svc-a".into())
    );
    // `name=` reads headers: response ones in place, `req.` ones appended,
    // with the address actually reached added if it is not already there.
    assert_eq!(
        annotate(
            "example.com responseFor://name=server,req.host\n",
            vec![("server", "nginx")],
            vec![("host", "example.com")],
        ),
        Some("nginx, 10.0.0.9, example.com".into())
    );
    // A named header that is not present contributes nothing.
    assert_eq!(
        annotate("example.com responseFor://name=absent\n", vec![], vec![]),
        Some("10.0.0.9".into())
    );
    // No rule, no header.
    assert_eq!(
        annotate("example.com host://1.1.1.1\n", vec![], vec![]),
        None
    );
}

/// whistle reads a speed or a delay with `parseFloat`/`parseInt`, so a value
/// carrying its unit works. Rust's `parse` rejected it outright, turning
/// `resSpeed://20kb` — the way anyone would first write it — into no
/// throttle at all.
#[test]
fn a_speed_or_delay_may_carry_its_unit() {
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        mgr.resolve(&info)
    };
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://20kb\n")), Some(20.0));
    assert_eq!(req_speed_kbps(&of("a.com reqSpeed://3\n")), Some(3.0));
    // Upstream's `> 0` guard: a zero or negative delay is no delay.
    assert_eq!(res_delay_ms(&of("a.com resDelay://0\n")), None);
    assert_eq!(res_delay_ms(&of("a.com resDelay://-5\n")), None);
    // Nothing numeric at all stays nothing.
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://fast\n")), None);
}

/// A delay carrying its unit does **not** delay, and a speed carrying one
/// does throttle. The asymmetry is upstream's; see [`js_number`].
///
/// This test replaces an assertion that said `resDelay://500ms` was 500 ms.
/// It read plausibly and it was wrong: `exports.delay` never parses, it
/// compares the matcher's string to zero, and `'500ms' > 0` is false. The
/// timing bench measured whistle answering in 3 ms where this port waited
/// 403.
#[test]
fn a_delay_is_read_as_a_whole_number_and_a_speed_is_not() {
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        mgr.resolve(&info)
    };
    assert_eq!(res_delay_ms(&of("a.com resDelay://500ms\n")), None);
    assert_eq!(req_delay_ms(&of("a.com reqDelay://500ms\n")), None);
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://600kb\n")), Some(600.0));
    // The plain spellings still work, exponent and sign included.
    assert_eq!(res_delay_ms(&of("a.com resDelay://500\n")), Some(500));
    assert_eq!(res_delay_ms(&of("a.com resDelay://500.7\n")), Some(500));
    assert_eq!(res_delay_ms(&of("a.com resDelay://1e3\n")), Some(1000));
    assert_eq!(res_delay_ms(&of("a.com resDelay://+400\n")), Some(400));
}

/// `Number(string)` in the corners, because a delay is decided by it.
#[test]
fn js_number_reads_what_javascript_reads() {
    assert_eq!(js_number(""), Some(0.0));
    assert_eq!(js_number("   "), Some(0.0));
    assert_eq!(js_number(" 400 "), Some(400.0));
    assert_eq!(js_number("400ms"), None);
    assert_eq!(js_number(".5"), Some(0.5));
    assert_eq!(js_number("0x10"), Some(16.0));
    assert_eq!(js_number("0b101"), Some(5.0));
    assert_eq!(js_number("0o17"), Some(15.0));
    // A radix prefix takes no sign in JavaScript.
    assert_eq!(js_number("-0x10"), None);
    assert_eq!(js_number("Infinity"), Some(f64::INFINITY));
    // Spellings Rust's float parser accepts and JavaScript's `Number` does not.
    assert_eq!(js_number("inf"), None);
    assert_eq!(js_number("infinity"), None);
    assert_eq!(js_number("nan"), None);
    assert_eq!(js_number("NaN"), None);
}

/// The same `> 0` guard on the speeds, which did not have it.
///
/// `resSpeed://0` used to reach `body::throttled`, whose `.max(1.0)` floor
/// made it one byte per 50 ms. The timing bench found it by hanging: a
/// 300 KB body would have taken over four hours. Upstream gates on
/// `if (resSpeed > 0)` (`_original/lib/inspectors/res.js:913-917`), so the
/// value that means "no limit" must produce no throttle.
#[test]
fn a_zero_or_negative_speed_is_no_throttle_at_all() {
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        mgr.resolve(&info)
    };
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://0\n")), None);
    assert_eq!(req_speed_kbps(&of("a.com reqSpeed://0\n")), None);
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://-600\n")), None);
    assert_eq!(req_speed_kbps(&of("a.com reqSpeed://-600\n")), None);
    // `0kb` parses to zero the same way, and means the same thing.
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://0kb\n")), None);
    // A positive rate is still a rate.
    assert_eq!(res_speed_kbps(&of("a.com resSpeed://0.5\n")), Some(0.5));
}

/// The three spellings a data-valued operator accepts, and the order.
///
/// `_parseJSON` (`_original/lib/util/index.js:1135-1143`) tries JSON, then a
/// query string but **only** on a value with no whitespace, then the line
/// format. This port had the first two and read the third as a one-line
/// special case, so `resMerge://test=123` — the first example on that
/// operator's own documentation page — did nothing, and a `{value}` holding
/// three headers set none of them.
#[test]
fn a_data_value_is_json_then_a_query_then_lines() {
    // `true` = the value is loaded content, which is the road that reaches
    // the three layers; a written matcher containing `=` never gets past
    // `tryParseMatcher`, and `a_written_matcher_with_an_equals_is_a_query`
    // below covers that side.
    let obj = |text: &str, keys: bool| parse_data_object(text, keys, true).unwrap().to_string();
    assert_eq!(obj(r#"{"a":1}"#, false), r#"{"a":1}"#);
    assert_eq!(obj("a=1&b=2", false), r#"{"a":"1","b":"2"}"#);
    assert_eq!(obj("a: 1\nb: two", false), r#"{"a":"1","b":"two"}"#);
    // A quoted value loses its quotes. A safe integer becomes a number —
    // but **only** when its first and last characters differ, because
    // upstream asks that first and the numeric branch is the `else` of it
    // (`parseLine`, `common.js:1145-1157`). Measured against whistle 2.10.8:
    // `1`, `11`, `121` and `0` stay strings; `123` and `-12` are numbers.
    assert_eq!(obj("a: \"1\"", false), r#"{"a":"1"}"#);
    assert_eq!(obj("a: 007", false), r#"{"a":"007"}"#);
    assert_eq!(obj("a: 0", false), r#"{"a":"0"}"#);
    assert_eq!(obj("a: 11", false), r#"{"a":"11"}"#);
    assert_eq!(obj("a: 121", false), r#"{"a":"121"}"#);
    assert_eq!(obj("a: 123", false), r#"{"a":123}"#);
    assert_eq!(obj("a: -12", false), r#"{"a":-12}"#);
    // The separator is `": "`, then `:`, then `=` — so a value may hold both.
    assert_eq!(obj("a: v=1", false), r#"{"a":"v=1"}"#);
    assert_eq!(obj("a=v:1", false), r#"{"a":"v:1"}"#);
    // Whitespace anywhere keeps the value out of the query branch entirely.
    assert_eq!(obj("a=1 &b=2", false), r#"{"a":"1 &b=2"}"#);
    // Only the merge pair reads a dotted name as a path.
    assert_eq!(obj("n.a: x", true), r#"{"n":{"a":"x"}}"#);
    assert_eq!(obj("n.a: x", false), r#"{"n.a":"x"}"#);
    // A line with no separator at all is a name with an empty value.
    assert_eq!(obj("bare", false), r#"{"bare":""}"#);
}

/// A written matcher containing `=` is a query string, whitespace and all.
///
/// `tryParseMatcher` runs ahead of `_parseJSON` and only for the rule's own
/// matcher (`!text`, `_original/lib/util/index.js:1165-1171`). So
/// `reqHeaders://x-a=${v}` with a two-line `v` keeps the newline in the
/// value and `setHeader` throws it away — measured: whistle sends no header
/// at all, and sends the *other* pair when the line has one.
#[test]
fn a_written_matcher_with_an_equals_is_a_query() {
    let written = |t: &str| parse_data_object(t, false, false).unwrap().to_string();
    assert_eq!(written("x-a=1"), r#"{"x-a":"1"}"#);
    assert_eq!(written("x-a=line1\nline2"), "{\"x-a\":\"line1\\nline2\"}");
    assert_eq!(written("x-a=1&x-b=2"), r#"{"x-a":"1","x-b":"2"}"#);
    // No `=` at all is nothing — not the line format, which only loaded
    // content reaches. `reqHeaders://bare` and a lone backtick both set no
    // header in whistle, while the same words inside a `{value}` do.
    assert_eq!(parse_data_object("x-a: 1", false, false), None);
    assert_eq!(parse_data_object("bare", false, false), None);
    // JSON is still read first, with or without an `=` inside it.
    assert_eq!(written(r#"{"x-a":"v=1"}"#), r#"{"x-a":"v=1"}"#);
    assert_eq!(written(r#"{"x-a":"1"}"#), r#"{"x-a":"1"}"#);
    assert_eq!(parse_data_object("   ", false, true), None);
}

/// `enable://x disable://x` is nothing, and the flags that opt out.
///
/// Upstream's `isEnable` is `enable[name] && !disable[name]`
/// (`_original/lib/util/index.js:678-680`); this port read every flag as
/// bare set membership, so a name written on both sides was *enabled* here
/// and inert there. Measured on `cases-flags.js`, where
/// `enable://keepCSP disable://keepCSP` kept the CSP here and stripped it
/// upstream.
#[test]
fn a_flag_written_on_both_sides_does_nothing() {
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        mgr.resolve(&info)
    };
    assert!(is_enabled(&of("a.com enable://keepCSP\n"), "keepCSP"));
    assert!(!is_enabled(
        &of("a.com enable://keepCSP disable://keepCSP\n"),
        "keepCSP"
    ));
    // Order does not decide it, which is the point of reading both sides.
    assert!(!is_enabled(
        &of("a.com disable://keepCSP enable://keepCSP\n"),
        "keepCSP"
    ));
    assert!(!is_disabled(
        &of("a.com enable://keepCSP disable://keepCSP\n"),
        "keepCSP"
    ));
    // `userLogin` is one of the three that keep the direct read, because
    // upstream lets `enable` win there. This guards the revert.
    let both = of("a.com replaceStatus://401 disable://userLogin enable://userLogin\n");
    assert!(user_login_allowed(&both, "replaceStatus"));
}

/// `x-forwarded-for` — the header a client must not be able to dictate.
///
/// whistle strips the client's by default (`res.js:690-710`); this port
/// forwarded it, so any client could claim any address and have the proxy
/// pass it on as if vouched for. It also set a `forwardedFor://` value that
/// was not an address at all.
#[test]
fn forwarded_for_is_an_address_or_nothing() {
    let out = |rules: &str, incoming: Option<&str>| {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let mut hm = HeaderMap::new();
        if let Some(v) = incoming {
            hm.insert("x-forwarded-for", v.parse().unwrap());
        }
        let info = build_req_info("GET", "http", "a.com", 80, "/", &hm, None);
        let resolved = mgr.resolve(&info);
        let mut headers = hm.clone();
        apply_forwarded_for(&mut headers, &resolved);
        headers
            .get("x-forwarded-for")
            .map(|v| v.to_str().unwrap().to_string())
    };

    // The client's claim does not survive by default.
    assert_eq!(out("a.com host://1.1.1.1\n", Some("10.0.0.5")), None);
    // …unless the rules ask for it.
    assert_eq!(
        out("a.com enable://clientIp\n", Some("10.0.0.5")).as_deref(),
        Some("10.0.0.5")
    );
    // A rule may set one, if it is an address.
    assert_eq!(
        out("a.com forwardedFor://203.0.113.7\n", None).as_deref(),
        Some("203.0.113.7")
    );
    assert_eq!(
        out("a.com forwardedFor://2001:db8::1\n", None).as_deref(),
        Some("2001:db8::1")
    );
    // A non-address value sets nothing — and does not rescue the client's.
    assert_eq!(out("a.com forwardedFor://hello\n", Some("10.0.0.5")), None);
    // `disable://clientIp` removes it whatever else said.
    assert_eq!(
        out(
            "a.com forwardedFor://203.0.113.7 disable://clientIp\n",
            None
        ),
        None
    );
}

/// `urlReplace://` rewrites the URL that `params://` produced, not the one
/// before it — `handleParams` writes the query first
/// (`_original/lib/inspectors/req.js:561`) and `parsePathReplace` runs over
/// the result (`:569`). Reversed, a pattern aimed at what `params://` had
/// just written never saw it.
#[test]
fn url_replace_sees_what_params_wrote() {
    let mut mgr = RuleManager::new();
    mgr.set_text("example.com params://token=SECRET urlReplace://SECRET=redacted\n");
    let info = build_req_info(
        "GET",
        "http",
        "example.com",
        80,
        "/api",
        &HeaderMap::new(),
        None,
    );
    let resolved = mgr.resolve(&info);
    let out = rewrite_path("/api", &resolved, ReqBodyCtx::default());
    assert_eq!(out, "/api?token=redacted");
}

/// A rules text merged in mid-request **wins**: upstream's `mergeRule`
/// returns the new rule for a single-value protocol and puts the new list
/// first for a multi-match one, so an included file overrides the file that
/// included it. This port had it reversed, which meant a rule pulled in
/// specifically to override something lost to the thing it was overriding.
#[test]
fn a_merged_rule_wins_the_contest() {
    let dir = std::env::temp_dir().join(format!("whistle-rs-merge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let inc = dir.join("inc.txt");
    std::fs::write(&inc, "example.com resHeaders://x-src=inc host://9.9.9.9\n").expect("write");

    let mut mgr = RuleManager::new();
    mgr.set_text(&format!(
        "example.com resHeaders://x-src=main host://1.1.1.1 rulesFile://{}\n",
        inc.display()
    ));
    let info = build_req_info(
        "GET",
        "http",
        "example.com",
        80,
        "/x",
        &HeaderMap::new(),
        None,
    );
    let mut resolved = mgr.resolve(&info);
    let _keep = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);

    // Single-value: the included one replaces the including one.
    assert_eq!(resolved.value("host"), Some("9.9.9.9"));
    // Multi-match: the included one comes first, and these fold first-wins.
    let mut headers = HeaderMap::new();
    apply_header_ops(&mut headers, &resolved, "resHeaders");
    assert_eq!(
        headers.get("x-src").map(|v| v.to_str().unwrap()),
        Some("inc")
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// …but `important` still outranks it. `mergeRule` keeps an important
/// including rule for a single-value protocol, and its stable partition puts
/// every important operator ahead of every normal one for a multi-match one
/// (`_original/lib/util/index.js:2160-2170`). This port let the merged rule
/// win outright, so `lineProps://important` on the including line meant
/// nothing the moment that line pulled a file in.
#[test]
fn an_important_line_outranks_what_it_pulled_in() {
    let values: HashMap<String, String> = [(
        "extra".to_string(),
        "example.com reqHeaders://x-w=inner host://9.9.9.9\n".to_string(),
    )]
    .into_iter()
    .collect();
    let merged = |rules: &str| {
        let (info, mut resolved) = resolve_with_info(rules, "http://example.com/");
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        let _keep = merge_included_rules(&mut resolved, &info, &values, false);
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "reqHeaders");
        (
            h.get("x-w").map(|v| v.to_str().unwrap().to_string()),
            resolved,
        )
    };

    // Important on the including line: it holds both slots.
    let (header, resolved) = merged(
        "example.com reqHeaders://x-w=outer host://1.1.1.1 lineProps://important\nexample.com reqRules://{extra}\n",
    );
    assert_eq!(header.as_deref(), Some("outer"));
    assert_eq!(resolved.value("host"), Some("1.1.1.1"));

    // Not important: the merged rule wins, as before.
    let (header, resolved) = merged(
        "example.com reqHeaders://x-w=outer host://1.1.1.1\nexample.com reqRules://{extra}\n",
    );
    assert_eq!(header.as_deref(), Some("inner"));
    assert_eq!(resolved.value("host"), Some("9.9.9.9"));
}

/// A produced text answers its `{name}` from values of its own: what the
/// script that produced it set on `values`, with the text's own ``` blocks
/// laid over them — never from the including text's blocks. Each half
/// measured against whistle 2.10.8; upstream's own suite asks the first
/// (`test/units/script.test.js`), where this port served a 404.
#[test]
fn a_produced_text_answers_from_its_own_values() {
    let body_of = |text: &str, status: Option<u16>| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let mut info = build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/x",
            &HeaderMap::new(),
            None,
        );
        let mut resolved = mgr.resolve(&info);
        let mut values = mgr.inline_values();
        fn tpl(info: &ReqInfo) -> TplCtx<'_> {
            TplCtx {
                info,
                env: test_env(),
            }
        }
        substitute_values(&mut resolved, &values, tpl(&info));
        let merged = merge_included_rules(&mut resolved, &info, &values, false);
        for m in &merged {
            values.extend(m.carried_values().clone());
        }
        substitute_values(&mut resolved, &values, tpl(&info));
        if let Some(status) = status {
            info.res = Some(build_res_info(status, &HeaderMap::new(), None, None));
            if let Some(carried) = merge_res_rules(&mut resolved, &info, &values, false) {
                values.extend(carried);
            }
            substitute_values(&mut resolved, &values, tpl(&info));
        }
        resolved.value("resBody").map(str::to_string)
    };
    let f = "```";
    let script =
        |body: &str, how: &str| format!("{f}s.js\n{body}\n{f}\nexample.com {how}://{{s.js}}\n");
    // What the script set…
    let set = "values.v = 'FROM-SCRIPT'; rules.push('example.com resBody://{v}');";
    assert_eq!(
        body_of(&script(set, "reqScript"), None).as_deref(),
        Some("FROM-SCRIPT")
    );
    // …an object as its JSON…
    let object = "values.o = {a: 1}; rules.push('example.com resBody://{o}');";
    assert_eq!(
        body_of(&script(object, "reqScript"), None).as_deref(),
        Some(r#"{"a":1}"#)
    );
    // …and in the response phase too, for a `resScript` that produces rules.
    assert_eq!(
        body_of(&script(set, "resScript"), Some(200)).as_deref(),
        Some("FROM-SCRIPT")
    );
    // The produced text's own block beats what the script set.
    let block = "values.v = 'FROM-SCRIPT'; rules.push('```v'); \
                     rules.push('FROM-BLOCK'); rules.push('```'); \
                     rules.push('example.com resBody://{v}');";
    assert_eq!(
        body_of(&script(block, "reqScript"), None).as_deref(),
        Some("FROM-BLOCK")
    );
    // The including text's block is not the produced text's to read.
    let unseen = format!(
        "{f}v\nFROM-INCLUDING\n{f}\n{}",
        script("rules.push('example.com resBody://{v}');", "reqScript")
    );
    assert_eq!(body_of(&unseen, None).as_deref(), Some("{v}"));
}

/// `reqRules://{name}` names a **value**, not a path, and every other
/// spelling of the family does too. Upstream's `readRuleValue` hands back
/// `rule.value` and never reaches a disk (`_original/lib/util/index.js:
/// 1177-1179`); this port read the filesystem unconditionally, so the
/// contents of the value were opened as a path, nothing was found, and the
/// produced rules vanished without a word.
#[test]
fn a_produced_rules_text_may_come_from_a_value() {
    let values: HashMap<String, String> = [(
        "extra".to_string(),
        "example.com resHeaders://x-src=inc\n".to_string(),
    )]
    .into_iter()
    .collect();
    for spelling in [
        "reqRules",
        "rulesFile",
        "ruleFile",
        "ruleScript",
        "rulesScript",
        "reqScript",
    ] {
        let mut mgr = RuleManager::new();
        mgr.set_text(&format!("example.com {spelling}://{{extra}}\n"));
        let info = build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/x",
            &HeaderMap::new(),
            None,
        );
        let mut resolved = mgr.resolve(&info);
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        let _keep = merge_included_rules(&mut resolved, &info, &values, false);
        let mut headers = HeaderMap::new();
        apply_header_ops(&mut headers, &resolved, "resHeaders");
        assert_eq!(
            headers.get("x-src").map(|v| v.to_str().unwrap()),
            Some("inc"),
            "{spelling}://{{extra}}"
        );
    }
}

/// `${name}` inside an operator's value reads the values store. This port
/// only ever replaced a value that *was* exactly `{name}`, so
/// `resHeaders://x-v=${myval}` reached the origin with the eight literal
/// characters in it — silently, which is the worst way for a value
/// reference to fail.
#[test]
fn a_braced_reference_reads_the_values_store() {
    let values: HashMap<String, String> = [
        ("myval".to_string(), "hello".to_string()),
        ("host".to_string(), "10.0.0.9".to_string()),
    ]
    .into_iter()
    .collect();
    let of = |text: &str, proto: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        resolved.value(proto).map(str::to_string)
    };

    // Inside a value, with text around it.
    assert_eq!(
        of("a.com resHeaders://x-v=${myval}\n", "resHeaders").as_deref(),
        Some("x-v=hello")
    );
    // More than one, and one of them repeated.
    assert_eq!(
        of(
            "a.com resHeaders://a=${myval}&b=${host}&c=${myval}\n",
            "resHeaders"
        )
        .as_deref(),
        Some("a=hello&b=10.0.0.9&c=hello")
    );
    // The whole-value form still replaces with the content itself.
    assert_eq!(
        of("a.com resBody://{myval}\n", "resBody").as_deref(),
        Some("hello")
    );
    // A name with no value is left as written, so a typo shows as itself
    // rather than as an empty string.
    assert_eq!(
        of("a.com resHeaders://x=${nope}\n", "resHeaders").as_deref(),
        Some("x=${nope}")
    );
    // Shapes that are not references are not touched, and do not hang.
    for text in ["x=$notabrace", "x=${", "x=${}", "x=${a${b}}", "x=}{"] {
        let line = format!("a.com resHeaders://{text}\n");
        assert_eq!(of(&line, "resHeaders").as_deref(), Some(text), "{text}");
    }
}

/// A ``` block belongs to the rules text that declared it: another group's
/// reference of the same name is not answered by it, and cannot shadow it.
///
/// Upstream files an inline entry under `key + '\n\r' + file` and looks that
/// key up before falling back to the shared store — never to another file's
/// inline map (`getInlineKey` / `getValueFor`,
/// `_original/lib/util/index.js:205-209`, `lib/rules/rules.js:785-796`).
/// This port merged every enabled group's blocks into one flat map, so the
/// reference below answered whatever group happened to be resolved last.
#[test]
fn a_fenced_block_answers_only_its_own_group() {
    let body_with = |mgr: &RuleManager, overrides: &[&str]| {
        let values = {
            let mut v = mgr.inline_values();
            // What the console and `--value` hold, laid over the top exactly
            // as `crate::proxy::effective_values` does.
            v.extend(HashMap::from([(
                "stored".to_string(),
                "FROM-STORE".to_string(),
            )]));
            let overrides = overrides.iter().map(|n| n.to_string()).collect();
            yield_to_overrides(&mut v, &overrides);
            v
        };
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        resolved.value("resBody").map(str::to_string)
    };
    let body_of = |mgr: &RuleManager| body_with(mgr, &[]);

    // A block and the reference in the same group: the shape that has to
    // keep working.
    let mut own = RuleManager::new();
    own.set_text("```v\nFROM-DEFAULT\n```\na.com resBody://{v}\n");
    assert_eq!(body_of(&own).as_deref(), Some("FROM-DEFAULT"));

    // Declared in one group, referenced from another: not answered, so the
    // reference is left as written — which is what a missed lookup does.
    let mut across = RuleManager::new();
    across.set_text("```v\nFROM-DEFAULT\n```\n");
    across.add_group("A", "a.com resBody://{v}\n", true);
    assert_eq!(body_of(&across).as_deref(), Some("{v}"));

    // And the sharpest form: a group that declares *and* uses `v` keeps its
    // own, whatever another group declares under that name. `A` resolves
    // before `default`, so this is the case the flat map got backwards.
    let mut shadowed = RuleManager::new();
    shadowed.set_text("```v\nFROM-DEFAULT\n```\n");
    shadowed.add_group("A", "```v\nFROM-A\n```\na.com resBody://{v}\n", true);
    assert_eq!(body_of(&shadowed).as_deref(), Some("FROM-A"));

    // The store is shared by all of them and loses to a block of the same
    // name, as upstream's does (`test/units/keys.test.js:91-95`)…
    let mut stored = RuleManager::new();
    stored.set_text("```stored\nFROM-BLOCK\n```\na.com resBody://{stored}\n");
    assert_eq!(body_of(&stored).as_deref(), Some("FROM-BLOCK"));
    // …unless `--value` gave the name, which beats the block…
    assert_eq!(
        body_with(&stored, &["stored"]).as_deref(),
        Some("FROM-STORE")
    );
    // …and a group with no block of its own reads the store either way.
    let mut other = RuleManager::new();
    other.add_group("A", "a.com resBody://{stored}\n", true);
    assert_eq!(body_of(&other).as_deref(), Some("FROM-STORE"));
}

/// An override the console has since deleted gives the blocks back: the
/// name alone is no reason to answer nothing.
#[test]
fn a_deleted_override_does_not_hide_the_block() {
    let key = crate::rules::inline_key("v", "default");
    let mut values = HashMap::from([(key.clone(), "FROM-BLOCK".to_string())]);
    yield_to_overrides(&mut values, &HashSet::from(["v".to_string()]));
    assert_eq!(
        value_for(&values, "v", Some("default")).map(String::as_str),
        Some("FROM-BLOCK")
    );
}

/// Resolve `text` against a GET of `http://a.com/p?q=1`, substitute
/// `values`, and hand back the set — the two passes a request makes before
/// any operator is applied.
fn substituted(text: &str, values: &HashMap<String, String>) -> Resolved {
    let mut mgr = RuleManager::new();
    mgr.set_text(text);
    let info = build_req_info(
        "GET",
        "http",
        "a.com",
        80,
        "/p?q=1",
        &HeaderMap::new(),
        None,
    );
    let mut resolved = mgr.resolve(&info);
    substitute_values(
        &mut resolved,
        values,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );
    resolved
}

/// A value wrapped in backticks is a template rendered against the request
/// (`renderTpl`, `_original/lib/rules/rules.js:762-772`). Without this the
/// backticks reached the origin as two literal characters wrapped around an
/// unexpanded `${…}`.
#[test]
fn a_backtick_value_renders_against_the_request() {
    let none = HashMap::new();
    let of = |text: &str, proto: &str| substituted(text, &none).value(proto).map(str::to_string);

    assert_eq!(
        of("a.com reqHeaders://`x-m=${method}`\n", "reqHeaders").as_deref(),
        Some("x-m=GET")
    );
    // The whole vocabulary is shared with `tpl://`: `.key` subpaths,
    // `${{…}}` encoding and the `.replace(…)` modifier all come along.
    assert_eq!(
        of("a.com reqHeaders://`x-q=${query.q}`\n", "reqHeaders").as_deref(),
        Some("x-q=1")
    );
    assert_eq!(
        of("a.com reqHeaders://`x-u=${{url}}`\n", "reqHeaders").as_deref(),
        Some("x-u=http%3A%2F%2Fa.com%2Fp%3Fq%3D1")
    );
    // Not a template: the backticks have to wrap the *whole* value, and one
    // backtick is not a pair.
    for value in ["x=`${method}`&y=2", "`", "x=${method}"] {
        let line = format!("a.com reqHeaders://{value}\n");
        assert_eq!(of(&line, "reqHeaders").as_deref(), Some(value), "{value}");
    }
    // A name outside the whitelist survives, as it does in a `tpl://` file.
    assert_eq!(
        of("a.com reqHeaders://`x=${nosuchvar}`\n", "reqHeaders").as_deref(),
        Some("x=${nosuchvar}")
    );
}

/// A template is rendered **before** the request's tail is appended, and the
/// scheme in front of it is not part of the template.
///
/// Both halves are `TPL_RE`'s (`rules.js:72,:768`), and both were missing.
/// Joining first left a value that no longer ended with a backtick, so
/// nothing recognised it as a template — measured against whistle 2.10.8,
/// which answers `http://GET.dev/x` where this port sent
/// `` http://`${method}.dev`/x ``.
#[test]
fn a_template_destination_renders_before_it_takes_the_path() {
    let none = HashMap::new();
    let slot = |text: &str| {
        let (info, mut resolved) = resolve_with_info(text, "http://b.com/x");
        substitute_values(
            &mut resolved,
            &none,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        resolved.slot().map(|op| op.value.clone())
    };

    // Backticks around the whole destination, and around the part after the
    // scheme — upstream's regexp accepts either.
    assert_eq!(
        slot("b.com `http://${method}.dev`\n").as_deref(),
        Some("http://GET.dev/x")
    );
    assert_eq!(
        slot("b.com http://`${method}.dev`\n").as_deref(),
        Some("http://GET.dev/x")
    );
    // A scheme this port does not know keeps its place too.
    assert_eq!(
        slot("b.com tunnel://`${method}.dev:443`\n").as_deref(),
        Some("tunnel://GET.dev:443/x")
    );
    // The file family joins the same way.
    assert_eq!(
        slot("b.com file://`/srv/${method}.json`\n").as_deref(),
        Some("/srv/GET.json/x")
    );
    // A pattern that leaves no tail renders just the same.
    let (info, mut resolved) =
        resolve_with_info("b.com/x `http://${method}.dev`\n", "http://b.com/x");
    substitute_values(
        &mut resolved,
        &none,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );
    assert_eq!(
        resolved.slot().map(|op| op.value.as_str()),
        Some("http://GET.dev")
    );
    // Not a template — a `//` that is not a scheme separator leaves the
    // value alone, backtick or no backtick.
    assert_eq!(
        slot("b.com http://a`${method}`\n").as_deref(),
        Some("http://a`${method}`/x")
    );

    // A rendered `(…)` is **content**, unwrapped after the render and never
    // extended by the path — `getValue` runs on what `resolveVar` produced
    // (`rules.js:810-822`). Measured: whistle answers `file://mock-GET`,
    // and this port used to answer `(mock-GET)/x` — parentheses in the
    // mock's own bytes, plus a path appended to a body.
    let (info, mut resolved) =
        resolve_with_info("b.com file://`(mock-${method})`\n", "http://b.com/x");
    substitute_values(
        &mut resolved,
        &none,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );
    let op = resolved.slot().expect("a file rule");
    assert_eq!(op.value, "mock-GET");
    assert!(op.value_is_content);
    // …and the same for an operator that never joins anything.
    let (info, mut resolved) =
        resolve_with_info("b.com reqHeaders://`(x-m=${method})`\n", "http://b.com/x");
    substitute_values(
        &mut resolved,
        &none,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );
    assert_eq!(resolved.value("reqHeaders"), Some("x-m=GET"));
}

/// `resolveVar`'s subtlety (`rules.js:774-783`): when the value *was* a
/// backtick template, what the values store hands back for a `${key}` is
/// rendered too. It is the only way a stored value ever sees the request —
/// it is written once and reused by every rule that names it.
#[test]
fn a_backtick_value_renders_what_the_values_store_returned() {
    let values: HashMap<String, String> = [("hdr".to_string(), "x-m=${method}".to_string())]
        .into_iter()
        .collect();
    let of = |text: &str| {
        substituted(text, &values)
            .value("reqHeaders")
            .map(str::to_string)
    };

    assert_eq!(
        of("a.com reqHeaders://`${hdr}`\n").as_deref(),
        Some("x-m=GET")
    );
    // Without the backticks the stored text is used as written — upstream
    // renders it only when `rule.isTpl`.
    assert_eq!(
        of("a.com reqHeaders://${hdr}\n").as_deref(),
        Some("x-m=${method}")
    );
}

/// A stored value is **content**, and content is not rescanned. Upstream
/// expands a matcher exactly once (`resolveVar`, `rules.js:774-783`); this
/// pass runs several times over one resolved set, once per merge of rules
/// pulled in mid-request, so it has to know what it has already done.
///
/// Every assertion below is a way the second pass corrupted a mock body:
/// a `${x}` in it was expanded, a `{x}` in it was replaced wholesale, and a
/// body that opened and closed with a backtick lost one from each end to the
/// template test.
#[test]
fn a_value_is_substituted_once_however_often_the_pass_runs() {
    let values: HashMap<String, String> = [
        ("inner".to_string(), "INNER".to_string()),
        ("braced".to_string(), "outer-${inner}".to_string()),
        ("whole".to_string(), "{inner}".to_string()),
        ("fenced".to_string(), "```\ncode\n```".to_string()),
    ]
    .into_iter()
    .collect();
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/p", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        let tpl = TplCtx {
            info: &info,
            env: test_env(),
        };
        substitute_values(&mut resolved, &values, tpl);
        // The second call is the one the proxy makes after merging an
        // include, and it must change nothing here.
        substitute_values(&mut resolved, &values, tpl);
        resolved.value("resBody").map(str::to_string)
    };

    assert_eq!(
        of("a.com resBody://{braced}\n").as_deref(),
        Some("outer-${inner}")
    );
    assert_eq!(of("a.com resBody://{whole}\n").as_deref(), Some("{inner}"));
    assert_eq!(
        of("a.com resBody://{fenced}\n").as_deref(),
        Some("```\ncode\n```")
    );
}

/// The whole-value form takes the backticks too: `resolveValue` renders what
/// the store returned when the rule was a template, and substitutes the
/// pattern's captures into it first
/// (`if (rule.isTpl && regExp) … if (rule.isTpl) …`,
/// `_original/lib/rules/rules.js:826-833`).
#[test]
fn a_backticked_value_key_renders_what_the_store_returned() {
    let values: HashMap<String, String> = [(
        "hdr".to_string(),
        "x-m=${method}&x-g=${RegExp.$1}&x-p=$1".to_string(),
    )]
    .into_iter()
    .collect();
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/p", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        resolved.value("reqHeaders").map(str::to_string)
    };

    // `${RegExp.$1}` is the capture; the plain `$1` beside it is left as
    // written, because nothing rescans a store entry for one.
    assert_eq!(
        of("/a\\.(com)/ reqHeaders://`{hdr}`\n").as_deref(),
        Some("x-m=GET&x-g=com&x-p=$1")
    );
    // Without the backticks the content is bytes: a `${method}` in a mock
    // body is text the mock meant to contain.
    assert_eq!(
        of("/a\\.(com)/ reqHeaders://{hdr}\n").as_deref(),
        Some("x-m=${method}&x-g=${RegExp.$1}&x-p=$1")
    );
}

/// Upstream expands the values store **before** it substitutes captures —
/// `resolveVar` then `replaceSubMatcher`, in every branch of
/// `resolveRuleList` (`rules.js:1010-1012`) — so a `$1` written inside a
/// shared value reaches the operator as what the pattern captured. This port
/// expands captures at match time, and the six characters `got-$1` went to
/// the origin as written.
#[test]
fn a_pattern_capture_reaches_the_text_a_value_contributed() {
    let values: HashMap<String, String> = [("tag".to_string(), "got-$1".to_string())]
        .into_iter()
        .collect();
    let of = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/p", &HeaderMap::new(), None);
        let mut resolved = mgr.resolve(&info);
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        resolved.value("reqHeaders").map(str::to_string)
    };

    assert_eq!(
        of("/a\\.(com)/ reqHeaders://x=${tag}\n").as_deref(),
        Some("x=got-com")
    );
    // A wildcard's captures are the same captures.
    assert_eq!(
        of("^http://a.com/* reqHeaders://x=${tag}\n").as_deref(),
        Some("x=got-p")
    );
    // A pattern that captured nothing leaves the `$1` alone, exactly as it
    // does for a `$1` written on the rule line itself.
    assert_eq!(
        of("a.com reqHeaders://x=${tag}\n").as_deref(),
        Some("x=got-$1")
    );
}

/// `${statusCode}` and the rest of the response-side names are what a
/// backtick value on a response operator is *for*, and they are answerable
/// only once the head has arrived. Upstream re-resolves every
/// `pureResProtocols` rule then (`resolveResRules`, `rules.js:2306`); this
/// port re-resolves only the rules whose filters ask about the response, so
/// rendering in the request pass answered every one of them with an empty
/// string — which is not what `docs/TEMPLATES.md` says.
#[test]
fn a_backtick_on_a_response_operator_waits_for_the_response_head() {
    let none = HashMap::new();
    let mut mgr = RuleManager::new();
    mgr.set_text("a.com resHeaders://`x-s=${statusCode}` reqHeaders://`x-m=${method}`\n");
    let mut info = build_req_info("GET", "http", "a.com", 80, "/p", &HeaderMap::new(), None);
    let mut resolved = mgr.resolve(&info);
    substitute_values(
        &mut resolved,
        &none,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );

    // The request-side operator rendered; the response-side one is still a
    // template, waiting.
    assert_eq!(resolved.value("reqHeaders"), Some("x-m=GET"));
    assert_eq!(resolved.value("resHeaders"), Some("`x-s=${statusCode}`"));

    info.res = Some(crate::rules::ResInfo {
        status: 503,
        headers: Vec::new(),
        server_ip: None,
        server_port: None,
    });
    assert!(substitute_values(
        &mut resolved,
        &none,
        TplCtx {
            info: &info,
            env: test_env()
        }
    ));
    assert_eq!(resolved.value("resHeaders"), Some("x-s=503"));
    // And the request-side one was not rendered a second time.
    assert_eq!(resolved.value("reqHeaders"), Some("x-m=GET"));
}

/// `log://` and `weinre://` opt out at parse time upstream
/// (`rule.isTpl = false`, `rules.js:1357-1359`): their values name a
/// channel, and a backtick in one is a backtick.
#[test]
fn the_tool_protocols_opt_out_of_backtick_rendering() {
    let none = HashMap::new();
    let resolved = substituted("a.com log://`${method}`\n", &none);
    assert_eq!(resolved.value("log"), Some("`${method}`"));
}

/// Read `spec` as an operator value would be read, on a runtime of its own.
fn loaded(text: &str) -> Resolved {
    let mut mgr = RuleManager::new();
    mgr.set_text(text);
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    let mut resolved = mgr.resolve(&info);
    rt().block_on(load_rule_values(&mut resolved, &info));
    resolved
}

/// A scratch directory for the value files these tests read.
fn value_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("whistle-rs-values-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The six binary operators send a file's bytes as they are. Upstream's
/// suite splits a Chinese sentence across three files mid-character
/// (`test/units/insertFile.test.js`); decoded one file at a time, the three
/// halves became U+FFFD. And bytes are not re-encoded into a response's
/// `charset=`: a GBK file injected into a GBK page stays GBK.
#[test]
fn a_binary_operator_sends_its_files_bytes() {
    let dir = value_dir("binary");
    let sentence = "我们是社会主义接班人!".as_bytes();
    let (top, rest) = sentence.split_at(10);
    let (mid, bottom) = rest.split_at(10);
    for (name, bytes) in [("top", top), ("mid", mid), ("bottom", bottom)] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    let f = |name: &str| dir.join(name).display().to_string();
    let resolved = loaded(&format!(
        "a.com resPrepend://{} resBody://{} resAppend://{}\n",
        f("top"),
        f("mid"),
        f("bottom")
    ));
    let body = transform_res_body(Bytes::from_static(b"origin"), &resolved, Some("text/plain"));
    assert_eq!(std::str::from_utf8(&body).unwrap(), "我们是社会主义接班人!");

    // "中文" in GBK, into a page that says it is GBK: sent as it is.
    let gbk: &[u8] = &[0xd6, 0xd0, 0xce, 0xc4];
    std::fs::write(dir.join("gbk"), gbk).unwrap();
    let resolved = loaded(&format!("a.com resAppend://{}\n", f("gbk")));
    let body = transform_res_body(
        Bytes::from_static(b"x"),
        &resolved,
        Some("text/plain; charset=gbk"),
    );
    assert_eq!(&body[..], &[b'x', 0xd6, 0xd0, 0xce, 0xc4][..]);
}

/// `reqHeaders:///etc/whistle/headers.json` used to set **nothing**: the
/// path was handed to the header parser, which found no `=` and no `{`, and
/// the rule quietly did nothing at all.
#[test]
fn an_operator_value_can_name_a_file() {
    let dir = value_dir("read");
    let json = dir.join("h.json");
    std::fs::write(&json, r#"{"x-from-file":"1","x-b":"2"}"#).unwrap();
    let body = dir.join("body.txt");
    std::fs::write(&body, "MOCKED").unwrap();

    let resolved = loaded(&format!(
        "a.com reqHeaders://{}\na.com reqBody://{}\n",
        json.display(),
        body.display()
    ));
    let mut headers = HeaderMap::new();
    apply_header_ops(&mut headers, &resolved, "reqHeaders");
    assert_eq!(headers.get("x-from-file").unwrap(), "1");
    assert_eq!(headers.get("x-b").unwrap(), "2");
    assert_eq!(resolved.value("reqBody"), Some("MOCKED"));

    std::fs::remove_dir_all(&dir).ok();
}

/// `readFileText` splits on `|` and **joins** what it read
/// (`_original/lib/util/file-mgr.js:96-102,:157-166`) — which is not the
/// first-one-wins of a `file://` rule. A missing alternative drops out of
/// the join rather than ending it.
#[test]
fn several_paths_in_one_value_join_rather_than_race() {
    let dir = value_dir("join");
    std::fs::write(dir.join("a.txt"), "first").unwrap();
    std::fs::write(dir.join("c.txt"), "third").unwrap();

    let resolved = loaded(&format!(
        "a.com resBody://{}|{}|{}\n",
        dir.join("a.txt").display(),
        dir.join("gone.txt").display(),
        dir.join("c.txt").display()
    ));
    assert_eq!(resolved.value("resBody"), Some("first\r\nthird"));

    std::fs::remove_dir_all(&dir).ok();
}

/// The two failure behaviours, which are not the same one.
///
/// A JSON-valued operator keeps its text, because upstream's
/// `tryParseMatcher` (`_original/lib/util/index.js:1165-1171,:1303`) parses
/// the matcher as a query string once the read comes back empty. A
/// text-valued one is emptied instead: its text is a path, and a path must
/// never reach an origin as a request body.
#[test]
fn a_value_that_cannot_be_read_never_reaches_the_origin_as_a_path() {
    let missing = "/nonexistent-whistle-rs/value.json";
    let resolved = loaded(&format!(
        "a.com reqHeaders://{missing}\na.com reqBody://{missing}\na.com resBody://{missing}\n"
    ));
    assert_eq!(resolved.value("reqHeaders"), Some(missing));
    assert_eq!(resolved.value("reqBody"), Some(""));
    assert_eq!(resolved.value("resBody"), Some(""));

    // A `..` segment is refused before any read, exactly as `joinPath` does.
    let resolved = loaded("a.com resBody:///tmp/../etc/passwd\n");
    assert_eq!(resolved.value("resBody"), Some(""));
}

/// Values that are **not** locations are not read — a rule set that does not
/// use the feature must cost a walk over its own operators and nothing else.
///
/// Asserted on the gate rather than on the outcome: a value the loader
/// wrongly claimed would still *look* untouched afterwards (a failed read
/// leaves a JSON operator's text alone), and a wrongly claimed URL would
/// quietly become an outbound request with a 16-second budget.
#[test]
fn only_a_value_shaped_like_a_location_is_read() {
    let untouched = [
        // Pairs are the JSON operators' own syntax; upstream reaches the
        // same place the long way, by reading the path and falling back.
        ("urlReplace", "/api/v1=/api/v2"),
        ("reqHeaders", "x-a=1"),
        ("resHeaders", "{\"x-a\":\"1\"}"),
        // A bare relative value stays the literal this port documents.
        ("resBody", "console.log('patched')"),
        ("resAppend", "tail"),
        ("reqBody", "INJECTED"),
        // A URL on the js/css families still means `<script src=…>`.
        ("jsAppend", "https://cdn.test/a.js"),
        ("cssAppend", "https://cdn.test/a.css"),
        // …and a URL on `re[qs]Cors://` is the allowed **origin**, which
        // upstream folds into `{origin: …}` before it would read anything.
        ("resCors", "https://app.test"),
        ("reqCors", "//app.test"),
        // Operators outside the loadable set keep their value whatever its
        // shape: `file://` does its own reading, `redirect://` is a target.
        ("resType", "/json"),
        ("redirect", "https://b.com/x"),
        ("file", "/tmp/mock.json"),
        ("rulesFile", "/tmp/extra.rules"),
    ];
    for (proto, value) in untouched {
        let resolved = resolve(&format!("a.com {proto}://{value}\n"), "http://a.com/");
        let op = resolved.get(proto).expect(proto);
        assert_eq!(value_source(op), None, "{proto}://{value}");
    }

    // The mirror image, so the gate cannot be "always no".
    for (proto, value, want) in [
        (
            "reqHeaders",
            "/etc/h.json",
            ValueSource::File("/etc/h.json".into()),
        ),
        (
            "resBody",
            "~/mock.html",
            ValueSource::File("~/mock.html".into()),
        ),
        (
            "jsAppend",
            "/tmp/d.js",
            ValueSource::File("/tmp/d.js".into()),
        ),
        (
            "resBody",
            "https://cdn.test/m.json",
            ValueSource::Url("https://cdn.test/m.json".into()),
        ),
    ] {
        let resolved = resolve(&format!("a.com {proto}://{value}\n"), "http://a.com/");
        let op = resolved.get(proto).expect(proto);
        assert_eq!(value_source(op), Some(want), "{proto}://{value}");
    }
}

/// `readRuleValue` returns before it looks at a disk when `rule.value` is
/// set (`_original/lib/util/index.js:1177-1179`) — the `(inline)` form and a
/// whole-value `{name}` the values store answered.
#[test]
fn content_short_circuits_the_read() {
    let values: HashMap<String, String> = [("mock".to_string(), "/etc/passwd".to_string())]
        .into_iter()
        .collect();
    let mut mgr = RuleManager::new();
    mgr.set_text("a.com reqBody://(/etc/passwd)\na.com resBody://{mock}\n");
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    let mut resolved = mgr.resolve(&info);
    substitute_values(
        &mut resolved,
        &values,
        TplCtx {
            info: &info,
            env: test_env(),
        },
    );
    rt().block_on(load_rule_values(&mut resolved, &info));

    // Both are content: the path text survives instead of being opened.
    assert_eq!(resolved.value("reqBody"), Some("/etc/passwd"));
    assert_eq!(resolved.value("resBody"), Some("/etc/passwd"));
}

/// `file://`, `redirect://`, `statusCode://` and a bare destination URL
/// share **one slot** upstream — none of their names is a protocol, so all
/// of them land in the same list and the first match wins outright.
///
/// This port had a fixed protocol priority instead (redirect, statusCode,
/// file) *and* let a destination rewrite apply alongside a mock, so the two
/// implementations disagreed in whichever direction the file happened to be
/// written.
#[test]
fn the_short_circuit_family_shares_one_slot() {
    let winner = |text: &str, url: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let (scheme, rest) = url.split_once("://").expect("absolute");
        let (host, path) = rest
            .split_once('/')
            .map(|(h, p)| (h, format!("/{p}")))
            .unwrap_or((rest, "/".into()));
        let info = build_req_info("GET", scheme, host, 80, &path, &HeaderMap::new(), None);
        let resolved = mgr.resolve(&info);
        resolved.slot().map(|op| op.protocol.clone())
    };
    let winner = |text: &str, url: &str| winner(text, url);
    let is = |got: Option<String>, want: &str| assert_eq!(got.as_deref(), Some(want));

    // Written first wins, whatever the protocols are.
    let forward_first = "example.com http://127.0.0.1:9000\nexample.com/api file:///mock.json\n";
    is(winner(forward_first, "http://example.com/api"), "rule");
    let mock_first = "example.com/api file:///mock.json\nexample.com http://127.0.0.1:9000\n";
    is(winner(mock_first, "http://example.com/api"), "file");

    // …including against the two that used to be hard-coded ahead of file.
    let file_first = "a.com file:///mock.json\na.com redirect://http://x/\n";
    is(winner(file_first, "http://a.com/"), "file");
    let redirect_first = "a.com redirect://http://x/\na.com file:///mock.json\n";
    is(winner(redirect_first, "http://a.com/"), "redirect");
    let status_first = "a.com statusCode://204\na.com file:///mock.json\n";
    is(winner(status_first, "http://a.com/"), "statusCode");

    // An important line still wins over an earlier normal one — importance
    // is part of the resolution order the slot is decided by.
    let important = "a.com file:///mock.json\na.com statusCode://204 lineProps://important\n";
    is(winner(important, "http://a.com/"), "statusCode");

    // `rule://<name>` is the values-store include, not a destination, so it
    // does not compete.
    assert_eq!(winner("a.com rule://mocks\n", "http://a.com/"), None);

    // Two of them on **one line**: the one written first wins there too.
    // Upstream pushes a line's matchers onto the shared list in the order
    // they are written (`matchers.forEach(parseRule)`,
    // `_original/lib/rules/rules.js:1785-1789`). This port gave every
    // operator on a line the same order key, so the tie fell to whatever
    // order the slot protocols happened to be enumerated in — and
    // `statusCode` came first, so `example.com file:///mock statusCode://204`
    // served the mock upstream and answered 204 here.
    is(
        winner(
            "a.com file:///mock.json statusCode://204\n",
            "http://a.com/",
        ),
        "file",
    );
    is(
        winner(
            "a.com statusCode://204 file:///mock.json\n",
            "http://a.com/",
        ),
        "statusCode",
    );
    is(
        winner(
            "a.com redirect://http://x/ statusCode://204\n",
            "http://a.com/",
        ),
        "redirect",
    );
    is(
        winner(
            "a.com http://127.0.0.1:9000 statusCode://204\n",
            "http://a.com/",
        ),
        "rule",
    );
    // A second bare host on a pattern-first line is an operator, not a
    // pattern, and it takes the slot before anything written after it.
    is(
        winner("a.com b.com statusCode://204\n", "http://a.com/"),
        "rule",
    );
}

/// `statusCode://` only speaks when it won the shared slot.
///
/// Upstream reads it off `rules.rule` (`getStatusCodeFromRule`,
/// `_original/lib/util/index.js:3566-3589`) — the same single winner a
/// `file://` or a destination would have taken — so a `statusCode` written
/// below one of those never reaches the response. Here it was applied
/// unconditionally in the response phase, so it overwrote the status of a
/// file the rules had already chosen to serve, and of a response fetched
/// from a destination the rules had already chosen to forward to.
#[test]
fn a_status_code_that_lost_the_slot_stays_quiet() {
    let status_after = |text: &str| {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let resolved = mgr.resolve(&info);
        let mut parts = Response::new(()).into_parts().0;
        parts.status = StatusCode::OK;
        apply_response(&mut parts, &resolved);
        parts.status
    };
    // Alone, it still answers.
    assert_eq!(
        status_after("a.com statusCode://204\n"),
        StatusCode::NO_CONTENT
    );
    // Behind a destination — on its own line or on the same one — it does not.
    assert_eq!(
        status_after("a.com http://127.0.0.1:9000\na.com statusCode://204\n"),
        StatusCode::OK
    );
    assert_eq!(
        status_after("a.com http://127.0.0.1:9000 statusCode://204\n"),
        StatusCode::OK
    );
    assert_eq!(
        status_after("a.com file:///mock.json statusCode://204\n"),
        StatusCode::OK
    );
    // In front of one, it wins the slot and speaks.
    assert_eq!(
        status_after("a.com statusCode://204\na.com http://127.0.0.1:9000\n"),
        StatusCode::NO_CONTENT
    );
    // `replaceStatus` has a list of its own upstream and needs no slot.
    assert_eq!(
        status_after("a.com http://127.0.0.1:9000 replaceStatus://204\n"),
        StatusCode::NO_CONTENT
    );
}

/// The URL a pattern is matched against carries the host **as the client
/// wrote it**, because upstream's `getFullUrl`
/// (`_original/lib/util/common.js:1231-1267`) lower-cases nothing. Folding
/// it here meant a regexp pattern naming an upper-case host could never
/// match one, and `$0` handed the rule a URL nobody had asked for.
/// [`ReqInfo::host`] is still folded — that one is compared as a host.
#[test]
fn the_matched_url_keeps_the_host_as_written() {
    let info = build_req_info(
        "GET",
        "http",
        "API.Example.COM",
        80,
        "/p",
        &HeaderMap::new(),
        None,
    );
    assert_eq!(info.full_url, "http://API.Example.COM/p");
    assert_eq!(info.host, "api.example.com");
    // The default port is still the one thing the URL drops, as upstream's
    // `removeDefaultPort` does.
    let ported = build_req_info("GET", "http", "a.com", 8080, "/p", &HeaderMap::new(), None);
    assert_eq!(ported.full_url, "http://a.com:8080/p");
}

/// A header name repeated inside one operator value is a **list**, not a
/// contest. Node's `querystring.parse("a=1&a=2")` yields `{a: ["1","2"]}`
/// and writes one header line per element; folding to the last value sent
/// one header where whistle sends two.
#[test]
fn a_repeated_header_name_sends_every_value() {
    let pairs = parse_header_pairs("x-a=1&x-b=2&x-a=3", false);
    assert_eq!(pairs.len(), 2, "two distinct names");
    let x_a = &pairs.iter().find(|(n, _)| n == "x-a").expect("x-a").1;
    assert_eq!(x_a.iter().cloned().collect::<Vec<_>>(), ["1", "3"]);

    // …and it reaches the header map as two lines.
    let mut mgr = RuleManager::new();
    mgr.set_text("a.com resHeaders://x-a=1&x-a=2\n");
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    let resolved = mgr.resolve(&info);
    let mut headers = HeaderMap::new();
    apply_header_ops(&mut headers, &resolved, "resHeaders");
    let sent: Vec<&str> = headers
        .get_all("x-a")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(sent, ["1", "2"]);

    // Names are still trimmed — deliberately unlike upstream, whose
    // `qs.parse` would leave `"x-t "`, a name hyper rejects outright.
    let pairs = parse_header_pairs("x-t = spaced", false);
    assert_eq!(pairs[0].0, "x-t");
    assert_eq!(pairs[0].1.iter().next().map(String::as_str), Some("spaced"));
}

/// A merged-in operator has to win *strictly*, not tie. `MERGED_ORDER` is
/// zero, and an `$`-important rule on a file's first line used to land on
/// zero too — a tie that `min_by_key` breaks by iteration order, which is a
/// map's rather than the file's, so which rule won was not something you
/// could read off the rules.
#[test]
fn a_merged_operator_outranks_even_the_first_important_line() {
    use crate::rules::order_key;

    assert!(
        MERGED_ORDER < order_key(0, true),
        "an important first line must still rank after a merged operator"
    );
    assert!(order_key(0, true) < order_key(1, true));
    // Importance occupies the high half of the key, so any line index that
    // fits the low 32 bits still sorts ahead of the first normal line.
    assert!(order_key(u32::MAX as usize - 1, true) < order_key(0, false));

    // And it decides the shared slot the same way.
    let dir = std::env::temp_dir().join(format!("whistle-rs-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let inc = dir.join("inc.txt");
    std::fs::write(&inc, "a.com statusCode://204\n").expect("write");
    let mut mgr = RuleManager::new();
    mgr.set_text(&format!(
        "$a.com redirect://http://elsewhere/ rulesFile://{}\n",
        inc.display()
    ));
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    let mut resolved = mgr.resolve(&info);
    let _keep = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
    assert_eq!(
        resolved.slot().map(|op| op.protocol.as_str()),
        Some("statusCode"),
        "the merged rule wins the slot outright"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn charset_set_and_strip() {
    let mut h = HeaderMap::new();
    h.insert(hyper::header::CONTENT_TYPE, "text/html".parse().unwrap());
    set_charset(&mut h, Some("utf-8"), false, false);
    assert_eq!(
        h.get(hyper::header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    set_charset(&mut h, None, false, true);
    assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "text/html");

    // `delete://resType` empties the media type but keeps the parameters —
    // upstream blanks slot 0 rather than removing the header.
    set_charset(&mut h, Some("gbk"), true, false);
    assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "; charset=gbk");
    // Nothing left at all removes the header.
    set_charset(&mut h, None, true, true);
    assert!(h.get(hyper::header::CONTENT_TYPE).is_none());
}

/// `resType://json` is a short name to look up, and a value with no
/// parameters inherits the ones already on the header (`getNewType`).
#[test]
fn res_type_looks_up_short_names() {
    let mut h = HeaderMap::new();
    h.insert(
        hyper::header::CONTENT_TYPE,
        "text/html; charset=gbk".parse().unwrap(),
    );
    set_content_type(&mut h, "json", no_type_alias);
    assert_eq!(
        h.get(hyper::header::CONTENT_TYPE).unwrap(),
        "application/json; charset=gbk"
    );
    // An explicit parameter replaces the lot.
    set_content_type(&mut h, "text/plain;charset=utf-8", no_type_alias);
    assert_eq!(
        h.get(hyper::header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    // An unknown short name is whistle's octet-stream default; `sse` is the
    // one name that is not a file extension.
    assert_eq!(
        lookup_type("nosuchtype", no_type_alias),
        "application/octet-stream"
    );
    assert_eq!(lookup_type("sse", no_type_alias), "text/event-stream");
    // The request side has extra aliases of its own.
    assert_eq!(
        lookup_type("form", req_type_alias),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        lookup_type("form", no_type_alias),
        "application/octet-stream"
    );
}

/// A `ReqInfo` for a request a page on `https://app.test` made.
fn cross_origin(method: &str) -> ReqInfo {
    let mut h = HeaderMap::new();
    h.insert("origin", "https://app.test".parse().unwrap());
    build_req_info(method, "http", "a.com", 80, "/api", &h, None)
}

/// Mocking an API with `file://` from a page on another origin is one of
/// the things whistle is for, and the browser rejects the response unless
/// the proxy says who may read it. whistle adds the headers by itself
/// (`isAutoCors`, `_original/lib/handlers/file-proxy.js:178-191`); this port
/// had the writer and not the trigger.
#[test]
fn a_local_file_answer_carries_cors_for_a_cross_origin_page() {
    let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
    let resp = short_circuit(&cross_origin("GET"), &resolved, test_env(), None).expect("file://");
    let h = resp.headers();
    assert_eq!(
        h.get("access-control-allow-origin").unwrap(),
        "https://app.test"
    );
    assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
}

/// …and a same-origin request gets none, because none is needed. The
/// trigger is the `Origin` header, exactly as upstream reads it.
#[test]
fn a_same_origin_request_gets_no_cors_headers() {
    let info = build_req_info("GET", "http", "a.com", 80, "/api", &HeaderMap::new(), None);
    let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
    let resp = short_circuit(&info, &resolved, test_env(), None).expect("file://");
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

/// The half that decides whether the real request ever happens: a preflight
/// is answered 200 with the CORS headers and the file is never opened. Here
/// the file does not exist, so serving it would 404 the preflight and the
/// browser would stop.
#[test]
fn a_preflight_is_answered_without_opening_the_file() {
    let mut h = HeaderMap::new();
    h.insert("origin", "https://app.test".parse().unwrap());
    h.insert("access-control-request-method", "PUT".parse().unwrap());
    h.insert("access-control-request-headers", "x-token".parse().unwrap());
    let info = build_req_info("OPTIONS", "http", "a.com", 80, "/api", &h, None);
    let resolved = resolve("a.com/api file:///no/such/mock.json\n", "http://a.com/api");
    let resp = short_circuit(&info, &resolved, test_env(), None).expect("file://");
    assert_eq!(resp.status(), StatusCode::OK, "not the file's 404");
    let hs = resp.headers();
    assert_eq!(
        hs.get("access-control-allow-origin").unwrap(),
        "https://app.test"
    );
    assert_eq!(hs.get("access-control-allow-methods").unwrap(), "PUT");
    assert_eq!(hs.get("access-control-allow-headers").unwrap(), "x-token");
}

/// Both ways of turning it off, including upstream's own misspelling.
#[test]
fn auto_cors_can_be_turned_off() {
    for rule in [
        "a.com/api file:///no/such/mock.json lineProps://disableAutoCors",
        "a.com/api file:///no/such/mock.json lineProps://disabledAutoCors",
        "a.com/api file:///no/such/mock.json disable://autoCors",
    ] {
        let resolved = resolve(&format!("{rule}\n"), "http://a.com/api");
        let resp =
            short_circuit(&cross_origin("GET"), &resolved, test_env(), None).expect("file://");
        assert!(
            resp.headers().get("access-control-allow-origin").is_none(),
            "{rule} should have silenced it"
        );
        // …and with it off, the preflight is the file's own answer again.
        let resp = short_circuit(&cross_origin("OPTIONS"), &resolved, test_env(), None).expect("f");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{rule}");
    }
}

/// `log://` and `weinre://` inject a script into an HTML response, so they
/// need a response with HTML in it. Upstream busts the cache for both the
/// moment the rule matches (`log.js:30`, `weinre.js:26`); this port did it
/// for the body operators and not for these two.
///
/// Found by the differential bench: whistle reached the origin with
/// `pragma: no-cache` under `log://mytag` and this port did not.
#[test]
fn a_script_injector_busts_the_cache_too() {
    let bust = |rule: &str| {
        let resolved = resolve(&format!("a.com {rule}\n"), "http://a.com/");
        res_body_forbids_cache(&resolved)
    };
    assert!(bust("log://mytag"));
    assert!(bust("weinre://myid"));
    assert!(bust("resBody://(x)"), "the body operators, as before");
    assert!(!bust("reqHeaders://x-a=1"), "and nothing else");
}

/// A status value that is not a status: this port answers, upstream does not.
///
/// `res.writeHead('abc')` throws inside Node and takes the connection with
/// it, so whistle 2.10.8 answers a **reset** — measured for `abc`, `20x`,
/// `099`, `0`, `2000` and a file path. There is nothing there to copy, so
/// the mock keeps the answer an *empty* value gets, which upstream does
/// define: `var code = rule || 200` (`getStatusCodeFromRule`,
/// `_original/lib/util/index.js:3580`). Declared in `harness.js` and
/// measured by four cases in `cases.js`.
#[test]
fn a_status_that_is_not_a_status_still_answers() {
    let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
    for value in ["abc", "20x", "099", "0", "2000", "/tmp/code.txt", ""] {
        let resolved = resolve(&format!("a.com/x statusCode://{value}\n"), "http://a.com/x");
        let resp = short_circuit(&info, &resolved, test_env(), None)
            .unwrap_or_else(|| panic!("statusCode://{value} answers"));
        assert_eq!(resp.status(), StatusCode::OK, "statusCode://{value}");
    }
    // …and the ones that *are* statuses are still themselves, including the
    // two outside the registered range that whistle also accepts.
    for (value, want) in [("204", 204u16), ("999", 999), ("600", 600)] {
        let resolved = resolve(&format!("a.com/x statusCode://{value}\n"), "http://a.com/x");
        let resp = short_circuit(&info, &resolved, test_env(), None).expect("an answer");
        assert_eq!(resp.status().as_u16(), want, "statusCode://{value}");
    }
}

/// Every response the proxy makes itself says so — upstream's `x-server`
/// (`wrapResponse`, `_original/lib/util/index.js:1080-1090`). It answers the
/// question a mock otherwise leaves open: origin, or proxy?
#[test]
fn a_self_made_response_says_who_made_it() {
    let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
    for rule in [
        "statusCode://204",
        "redirect://http://b.com/",
        "file:///nope",
    ] {
        let resolved = resolve(&format!("a.com/x {rule}\n"), "http://a.com/x");
        let resp = short_circuit(&info, &resolved, test_env(), None).expect("an answer");
        assert_eq!(
            resp.headers().get("x-server").map(|v| v.to_str().unwrap()),
            Some("whistle-rs"),
            "{rule}"
        );
    }
}

/// A short-circuit response's body, as text.
fn body_text(resp: Response<DynBody>) -> String {
    let bytes = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
        .expect("collect body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `locationHref://` **answers** the request — it is one of upstream's
/// file-proxy protocols (`isFileProxy`, `protocols.js:282`), not a rewrite
/// of whatever the origin happened to send. This port injected a `<script>`
/// into the origin's HTML instead, so the origin was contacted for a body
/// nobody would read, and a JSON or empty answer got no redirect at all.
#[test]
fn location_href_answers_the_request_itself() {
    let body_of = |rule: &str, info: &ReqInfo| {
        let resolved = resolve(&format!("a.com/x {rule}\n"), "http://a.com/x");
        let resp = short_circuit(info, &resolved, test_env(), None)?;
        let ctype = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        Some((ctype, body_text(resp)))
    };
    let plain = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);

    assert_eq!(
        body_of("locationHref://http://b.com/go", &plain),
        Some((
            Some("text/html; charset=utf-8".to_string()),
            "<script>window.location.href = \"http://b.com/go\";</script>".to_string()
        ))
    );
    // `js:` and a request the browser made for a script both drop the tag.
    let mut script = HeaderMap::new();
    script.insert("sec-fetch-dest", HeaderValue::from_static("script"));
    let as_script = build_req_info("GET", "http", "a.com", 80, "/x", &script, None);
    for (rule, info) in [
        ("locationHref://js:http://b.com/go", &plain),
        ("locationHref://http://b.com/go", &as_script),
    ] {
        assert_eq!(
            body_of(rule, info),
            Some((
                Some("application/javascript; charset=utf-8".to_string()),
                "window.location.href = \"http://b.com/go\";".to_string()
            )),
            "{rule}"
        );
    }
    // `html:` overrides that guess; `replace:` swaps the call.
    assert_eq!(
        body_of("locationHref://html:http://b.com/go", &as_script).map(|(_, b)| b),
        Some("<script>window.location.href = \"http://b.com/go\";</script>".to_string())
    );
    assert_eq!(
        body_of("locationHref://replace:http://b.com/go", &plain).map(|(_, b)| b),
        Some("<script>window.location.replace(\"http://b.com/go\");</script>".to_string())
    );
    // An empty value is still an answer, with an empty body.
    assert_eq!(
        body_of("locationHref://", &plain),
        Some((Some("text/html; charset=utf-8".to_string()), String::new()))
    );
    // Pointing at the request's own URL would loop: the request goes out.
    assert_eq!(body_of("locationHref://http://a.com/x", &plain), None);
    assert_eq!(body_of("locationHref:///x", &plain), None);
    // A relative value resolves against the request, so this one is *not*
    // the request's own URL and does answer.
    assert_eq!(
        body_of("locationHref://y", &plain).map(|(_, b)| b),
        Some("<script>window.location.href = \"y\";</script>".to_string())
    );
}

/// `locationHref://` shares the one destination slot with the file family
/// and a URL replacement, because upstream files all of them under `rule`.
/// Whichever line came first answers; the others do not apply.
#[test]
fn location_href_shares_the_destination_slot() {
    let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
    let first = resolve(
        "a.com/x locationHref://http://b.com/go\na.com/x file://(MOCK)\n",
        "http://a.com/x",
    );
    assert_eq!(
        first.slot().map(|op| op.protocol.as_str()),
        Some("locationHref")
    );
    let second = resolve(
        "a.com/x file://(MOCK)\na.com/x locationHref://http://b.com/go\n",
        "http://a.com/x",
    );
    assert_eq!(second.slot().map(|op| op.protocol.as_str()), Some("file"));
    assert_eq!(
        body_text(short_circuit(&info, &second, test_env(), None).unwrap()),
        "MOCK"
    );
}

/// Only the file family. `redirect://` and `statusCode://` are answered by
/// a different handler upstream and carry no automatic CORS.
#[test]
fn redirect_and_status_code_carry_no_automatic_cors() {
    for rule in ["redirect://http://b.com/", "statusCode://204"] {
        let resolved = resolve(&format!("a.com/api {rule}\n"), "http://a.com/api");
        let resp =
            short_circuit(&cross_origin("GET"), &resolved, test_env(), None).expect("answer");
        assert!(
            resp.headers().get("access-control-allow-origin").is_none(),
            "{rule}"
        );
    }
}

#[test]
fn file_family_cross_falls_through() {
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    // xfile with a missing file → no short-circuit (proxy the real server).
    let x = resolve("a.com xfile:///no/such/file.txt\n", "http://a.com/");
    assert!(short_circuit(&info, &x, test_env(), None).is_none());
    // plain file missing → a 404 short-circuit.
    let f = resolve("a.com file:///no/such/file.txt\n", "http://a.com/");
    let r = short_circuit(&info, &f, test_env(), None).expect("file:// should short-circuit");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// Response-side operators must reach a mocked response too — upstream runs
/// its response inspectors over `file`/`tpl`/`redirect` results as well.
#[test]
fn short_circuit_response_takes_response_operators() {
    let info = build_req_info("GET", "http", "a.com", 80, "/x", &HeaderMap::new(), None);
    let resolved = resolve(
        "a.com file:///definitely/missing/file resHeaders://x-mock=1 resType://json",
        "http://a.com/x",
    );
    let resp = short_circuit(&info, &resolved, test_env(), None).expect("file:// short-circuits");
    let mut parts = resp.into_parts().0;
    apply_response(&mut parts, &resolved);
    assert_eq!(
        parts.headers.get("x-mock").map(|v| v.to_str().unwrap()),
        Some("1")
    );
    assert!(
        parts
            .headers
            .get("content-type")
            .map(|v| v.to_str().unwrap().contains("json"))
            .unwrap_or(false),
        "resType:// should have set a JSON content type"
    );
}

#[test]
fn file_protocol_recognised() {
    use crate::rules::protocols::is_file_protocol;
    for p in [
        "file",
        "rawfile",
        "tpl",
        "jsonp",
        "dust",
        "xfile",
        "xsrawfile",
        "xtpl",
    ] {
        assert!(is_file_protocol(p), "{p} should be a file protocol");
    }
    assert!(!is_file_protocol("host"));
    assert!(!is_file_protocol("xhost"));
}

#[test]
fn config_vars_substituted() {
    let mut r = resolve(
        "a.com ua://agent-${port}\na.com resType://type-${VERSION}\n",
        "http://a.com/",
    );
    substitute_config_vars(&mut r, 8899, "1.2.3");
    assert_eq!(r.value("ua"), Some("agent-8899"));
    assert_eq!(r.value("resType"), Some("type-1.2.3"));
}

/// …but not inside **content**. A mock body that mentions `${port}` means
/// those seven characters; upstream reads a value once and never rescans it.
#[test]
fn config_vars_leave_a_mock_body_alone() {
    let values: HashMap<String, String> =
        [("mock".to_string(), "listening on ${port}".to_string())]
            .into_iter()
            .collect();
    let mut r = substituted("a.com resBody://{mock}\n", &values);
    substitute_config_vars(&mut r, 8899, "1.2.3");
    assert_eq!(r.value("resBody"), Some("listening on ${port}"));
    // The inline form is content too.
    let mut r = substituted("a.com resBody://(port-${port})\n", &HashMap::new());
    substitute_config_vars(&mut r, 8899, "1.2.3");
    assert_eq!(r.value("resBody"), Some("port-${port}"));
}

#[test]
fn proxy_variants_resolve() {
    use super::super::upstream::ProxyKind;
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);

    let r = resolve(
        "a.com internal-https-proxy://1.2.3.4:8080\n",
        "http://a.com/",
    );
    let p = resolved_target(&info, &r)
        .proxy
        .expect("internal-https-proxy");
    assert_eq!(p.kind, ProxyKind::Https);
    assert_eq!(p.port, 8080);

    let r2 = resolve(
        "a.com internal-http-proxy://1.2.3.4:8081\n",
        "http://a.com/",
    );
    let p2 = resolved_target(&info, &r2)
        .proxy
        .expect("internal-http-proxy");
    assert_eq!(p2.kind, ProxyKind::Http);

    // `xproxy` is an alias of `proxy`.
    let r3 = resolve("a.com xproxy://5.6.7.8:3128\n", "http://a.com/");
    let p3 = resolved_target(&info, &r3).proxy.expect("xproxy");
    assert_eq!(p3.kind, ProxyKind::Http);
    assert_eq!(p3.port, 3128);
}

/// The version pin, in every spelling `cipher.md` prints — and across
/// several lines, which is what the page means by "自动合并".
#[test]
fn cipher_maps_to_tls_versions() {
    use super::super::upstream::TlsVersions;
    let versions =
        |rules: &str| parse_cipher_versions(&cipher_options(&resolve(rules, "https://a.com/")));
    let one = |value: &str| versions(&format!("a.com cipher://{value}\n"));
    assert_eq!(one("TLSv1.2"), TlsVersions::Only12);
    assert_eq!(one("TLSv1.3"), TlsVersions::Only13);
    assert_eq!(one(r#"{"maxVersion":"TLSv1.2"}"#), TlsVersions::Only12);
    assert_eq!(one(r#"{"minVersion":"TLSv1.3"}"#), TlsVersions::Only13);
    assert_eq!(
        one(r#"{"secureProtocol":"TLSv1_2_method"}"#),
        TlsVersions::Only12
    );
    // An OpenSSL cipher string carries no version pin → default (1.2+1.3).
    assert_eq!(
        one(r#"{"ciphers":"ECDHE-RSA-AES128-GCM-SHA256"}"#),
        TlsVersions::Default
    );
    // The query spelling the page leads with, which this port used to
    // ignore outright.
    assert_eq!(one("maxVersion=TLSv1.2"), TlsVersions::Only12);
    assert_eq!(
        one("minVersion=TLSv1.3&maxVersion=TLSv1.3"),
        TlsVersions::Only13
    );
    // Several lines merge, and the first to name a key keeps it.
    assert_eq!(
        versions(
            "a.com cipher://minVersion=TLSv1.3\na.com cipher://ciphers=ECDHE-RSA-AES128-GCM-SHA256\n"
        ),
        TlsVersions::Only13
    );
    assert_eq!(
        versions("a.com cipher://maxVersion=TLSv1.2\na.com cipher://maxVersion=TLSv1.3\n"),
        TlsVersions::Only12
    );
}

/// A value made only of `[a-z0-9:!-]` is a cipher string; anything else is
/// an options object (`SEP_CIPHER_RE`, `_original/lib/rules/index.js:38`).
#[test]
fn a_bare_cipher_list_is_told_from_an_options_object() {
    let ciphers = |rules: &str| {
        cipher_options(&resolve(rules, "https://a.com/"))
            .get("ciphers")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    assert_eq!(
        ciphers("a.com cipher://ECDHE-ECDSA-AES256-GCM-SHA384:DH-RSA-AES256-GCM-SHA384\n")
            .as_deref(),
        Some("ECDHE-ECDSA-AES256-GCM-SHA384:DH-RSA-AES256-GCM-SHA384")
    );
    assert_eq!(
        ciphers("a.com cipher://ciphers=ECDHE-RSA-AES128-GCM-SHA256\n").as_deref(),
        Some("ECDHE-RSA-AES128-GCM-SHA256")
    );
    // A version token is not a cipher list — the dot is outside the set.
    assert_eq!(ciphers("a.com cipher://TLSv1.2\n"), None);
}

// -- the file family -----------------------------------------------------

/// A throwaway directory of fixtures, removed when the test ends.
struct Fixtures(PathBuf);

impl Fixtures {
    fn new(tag: &str) -> Fixtures {
        let dir = std::env::temp_dir().join(format!("whistle-rs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        Fixtures(dir)
    }

    /// Write a fixture and return its absolute path.
    fn write(&self, name: &str, body: &[u8]) -> String {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture parent");
        }
        std::fs::write(&path, body).expect("write fixture");
        self.path(name)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every `reqRules://` line contributes to the included rules text, and at
/// most one line spelled any other way — upstream's filter over the
/// accumulated list (`_original/lib/rules/rules.js:2258-2272`). This port
/// used to read only the first line whatever its spelling.
#[test]
fn rules_file_lines_accumulate() {
    let fx = Fixtures::new("rulesfile-accum");
    let a = fx.write("a.txt", b"example.com resHeaders://x-a=1\n");
    let b = fx.write("b.txt", b"example.com resHeaders://x-b=2\n");
    let c = fx.write("c.txt", b"example.com resHeaders://x-c=3\n");

    let merged = |rules: &str| {
        let (info, mut resolved) = resolve_with_info(rules, "http://example.com/");
        let _ = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        h
    };

    // Two `reqRules://` lines: both are rules text, so both apply.
    let h = merged(&format!(
        "example.com reqRules://{a}\nexample.com reqRules://{b}\n"
    ));
    assert_eq!(h.get("x-a").unwrap(), "1");
    assert_eq!(h.get("x-b").unwrap(), "2");

    // Two `rulesFile://` lines: each is a *candidate script*, and upstream
    // keeps only the first. The second is dropped, not merged.
    let h = merged(&format!(
        "example.com rulesFile://{a}\nexample.com rulesFile://{b}\n"
    ));
    assert_eq!(h.get("x-a").unwrap(), "1");
    assert!(h.get("x-b").is_none());

    // Mixed: every `reqRules://` line plus the first other one.
    let h = merged(&format!(
        "example.com reqRules://{a}\n\
             example.com rulesFile://{b}\n\
             example.com rulesFile://{c}\n"
    ));
    assert_eq!(h.get("x-a").unwrap(), "1");
    assert_eq!(h.get("x-b").unwrap(), "2");
    assert!(h.get("x-c").is_none());

    // The pieces are joined into *one* rules text, so a single-value
    // protocol contested across two files is decided by their order.
    let host_a = fx.write("host-a.txt", b"example.com host://1.1.1.1\n");
    let host_b = fx.write("host-b.txt", b"example.com host://2.2.2.2\n");
    let (info, mut resolved) = resolve_with_info(
        &format!("example.com reqRules://{host_a}\nexample.com reqRules://{host_b}\n"),
        "http://example.com/",
    );
    let _ = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
    assert_eq!(resolved.value("host"), Some("1.1.1.1"));
}

/// Rules merged in mid-request take the same two passes the top-level rules
/// do: a response condition inside a `rulesFile://` include (or a plugin's
/// injected rules) is now answered rather than failing closed.
///
/// Upstream re-resolves the same managers in its response phase
/// (`_original/lib/plugins/index.js:1326-1335`).
#[test]
fn merged_rules_get_the_response_phase_too() {
    let fx = Fixtures::new("merged-res-phase");
    let inc = fx.write(
        "inc.txt",
        b"example.com resHeaders://x-late=1 includeFilter://s:404\n\
              example.com resHeaders://x-always=1\n",
    );

    // `merge_included_rules` + `response_phase_of` is exactly what
    // `serve`'s two phases compose; `status` drives the second.
    let resolve_at = |rules: &str, status: Option<u16>| {
        let (mut info, mut resolved) = resolve_with_info(rules, "http://example.com/");
        let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
        if let Some(status) = status {
            info.res = Some(build_res_info(status, &HeaderMap::new(), None, None));
            if let Some(extra) = response_phase_of(&merged, &info, false) {
                resolved.merge_response_phase(extra);
            }
        }
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        h
    };

    let rules = format!("example.com rulesFile://{inc}\n");
    // The unconditional line applies from the request phase on.
    assert_eq!(resolve_at(&rules, None).get("x-always").unwrap(), "1");
    assert!(resolve_at(&rules, None).get("x-late").is_none());
    // The conditional one waits for the status, and then holds — or not.
    let on_404 = resolve_at(&rules, Some(404));
    assert_eq!(on_404.get("x-late").unwrap(), "1");
    assert_eq!(on_404.get("x-always").unwrap(), "1");
    assert!(resolve_at(&rules, Some(200)).get("x-late").is_none());

    // The same for rules a plugin injects.
    let (mut info, mut resolved) = resolve_with_info("example.com/x\n", "http://example.com/x");
    let merged = vec![merge_rules_text(
        &mut resolved,
        &info,
        "example.com resHeaders://x-plugin=1 includeFilter://s:500\n",
        false,
    )];
    info.res = Some(build_res_info(500, &HeaderMap::new(), None, None));
    let extra = response_phase_of(&merged, &info, false).expect("a second pass");
    resolved.merge_response_phase(extra);
    let mut h = HeaderMap::new();
    apply_header_ops(&mut h, &resolved, "resHeaders");
    assert_eq!(h.get("x-plugin").unwrap(), "1");
}

/// Nothing is applied twice: the request pass withholds exactly what the
/// second one resolves, so a line whose *exclude* filter is inert in the
/// request phase does not contribute its operator in both.
#[test]
fn a_merged_rule_is_not_resolved_twice() {
    let fx = Fixtures::new("merged-res-phase-once");
    let inc = fx.write(
        "inc.txt",
        b"example.com resHeaders://x-a=1 excludeFilter://s:404\n",
    );
    let (mut info, mut resolved) = resolve_with_info(
        &format!("example.com rulesFile://{inc}\n"),
        "http://example.com/",
    );
    let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
    assert!(
        resolved.all("resHeaders").is_empty(),
        "withheld until the status is known"
    );
    info.res = Some(build_res_info(200, &HeaderMap::new(), None, None));
    let extra = response_phase_of(&merged, &info, false).expect("a second pass");
    resolved.merge_response_phase(extra);
    assert_eq!(resolved.all("resHeaders").len(), 1);

    // …and the exclude filter still fires when it should.
    let (mut info, mut resolved) = resolve_with_info(
        &format!("example.com rulesFile://{inc}\n"),
        "http://example.com/",
    );
    let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
    info.res = Some(build_res_info(404, &HeaderMap::new(), None, None));
    assert!(
        response_phase_of(&merged, &info, false).is_some_and(|e| e.all("resHeaders").is_empty())
    );
}

/// An included file that says nothing about the response gets no second
/// pass at all — the manager answers from its precomputed flags.
#[test]
fn a_merged_rule_with_no_response_condition_skips_the_second_pass() {
    let fx = Fixtures::new("merged-res-phase-skip");
    let inc = fx.write("inc.txt", b"example.com resHeaders://x-a=1\n");
    let (mut info, mut resolved) = resolve_with_info(
        &format!("example.com rulesFile://{inc}\n"),
        "http://example.com/",
    );
    let merged = merge_included_rules(&mut resolved, &info, &HashMap::new(), false);
    info.res = Some(build_res_info(200, &HeaderMap::new(), None, None));
    assert!(response_phase_of(&merged, &info, false).is_none());
}

/// `resScript` picks the first line **not** spelled `resRules://` — the only
/// one upstream ever executes. Before this, a rules file written above the
/// script was handed to the JS engine in its place.
#[test]
fn res_script_skips_the_rules_spelling() {
    let fx = Fixtures::new("res-script-pick");
    let hook = fx.write("hook.js", b"ctx.res.headers['x-hook'] = '1';\n");
    let other = fx.write("other.js", b"ctx.res.headers['x-other'] = '1';\n");
    let rules = fx.write("rules.txt", b"example.com resHeaders://x-r=1\n");
    let resolved = resolve(
        &format!("example.com resRules://{rules} resScript://{hook}\n"),
        "http://example.com/",
    );
    assert_eq!(
        res_script_op(&resolved).map(|op| op.value.as_str()),
        Some(hook.as_str())
    );
    // With no script at all there is nothing to run, rather than the rules
    // file being evaluated as JavaScript.
    let only_rules = resolve(
        &format!("example.com resRules://{rules}\n"),
        "http://example.com/",
    );
    assert!(res_script_op(&only_rules).is_none());
    // A second script is dropped before the search, so it can never be
    // reached even if the first is a `resRules://` line.
    let two = resolve(
        &format!("example.com resScript://{hook} resScript://{other}\n"),
        "http://example.com/",
    );
    assert_eq!(
        res_script_op(&two).map(|op| op.value.as_str()),
        Some(hook.as_str())
    );
    // A path that names no file runs nothing: its *name* is not a script.
    let missing = resolve(
        "example.com resScript:///no/such.js\n",
        "http://example.com/",
    );
    assert!(res_script_op(&missing).is_none());
}

/// A `resScript://` text that is rules — not a script, and not this port's
/// `ctx` hook — applies to the response as rules, under that spelling as
/// under `resRules://`. Upstream's `tps.test.js` sends `# rules` + a
/// `jsAppend://` line through it; this port ran the text as JavaScript and
/// appended nothing.
#[test]
fn a_rules_text_under_the_res_script_spelling_is_rules() {
    let fx = Fixtures::new("res-script-rules");
    let rules = fx.write("tps.rules", b"# rules\nexample.com resHeaders://x-r=1\n");
    let (mut info, mut resolved) = resolve_with_info(
        &format!("example.com resScript://{rules}\n"),
        "http://example.com/",
    );
    assert!(res_script_op(&resolved).is_none(), "not the hook");
    info.res = Some(build_res_info(200, &HeaderMap::new(), None, None));
    assert!(merge_res_rules(&mut resolved, &info, &HashMap::new(), false).is_some());
    let mut h = HeaderMap::new();
    apply_header_ops(&mut h, &resolved, "resHeaders");
    assert_eq!(h.get("x-r").unwrap(), "1");
}

/// A `resRules://` text is rules, and they apply to the response. Every
/// line contributes, from a file or from a value alike, and what a text
/// produces beats the line that named it. This port parsed `resRules://`,
/// resolved it, and then dropped it on the floor.
#[test]
fn a_res_rules_text_applies_to_the_response() {
    let fx = Fixtures::new("res-rules");
    let file = fx.write("res.txt", b"example.com resHeaders://x-file=1\n");
    let values: HashMap<String, String> = [
        ("r", "example.com resHeaders://x-w=inner\n"),
        ("q", "example.com host://192.0.2.1 reqHeaders://x-late=1\n"),
        (
            "g",
            "example.com resHeaders://x-g=1 includeFilter://s:404\n",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let headers_of = |rules: &str, status: u16| {
        let (mut info, mut resolved) = resolve_with_info(rules, "http://example.com/");
        substitute_values(
            &mut resolved,
            &values,
            TplCtx {
                info: &info,
                env: test_env(),
            },
        );
        info.res = Some(build_res_info(status, &HeaderMap::new(), None, None));
        merge_res_rules(&mut resolved, &info, &HashMap::new(), false);
        let mut h = HeaderMap::new();
        apply_header_ops(&mut h, &resolved, "resHeaders");
        (h, resolved)
    };

    let (h, _) = headers_of(&format!("example.com resRules://{file}\n"), 200);
    assert_eq!(h.get("x-file").unwrap(), "1");

    // The produced text wins over the line that named it.
    let (h, _) = headers_of("example.com resHeaders://x-w=outer resRules://{r}\n", 200);
    assert_eq!(h.get("x-w").unwrap(), "inner");

    // A request-side operator inside the text is dropped: by the time it is
    // read the request has gone out. `mergeRules(…, isResRules)` keeps only
    // `resProtocols`.
    let (_, resolved) = headers_of("example.com resRules://{q}\n", 200);
    assert!(resolved.value("host").is_none());
    assert!(resolved.all("reqHeaders").is_empty());

    // A response filter inside the text is answered with the head in hand.
    let gated = "example.com resRules://{g}\n";
    assert!(headers_of(gated, 200).0.get("x-g").is_none());
    assert_eq!(headers_of(gated, 404).0.get("x-g").unwrap(), "1");
}

/// Serve a file rule for `GET http://x.com/`, returning status, content type
/// and body.
fn serve(proto: &str, value: &str) -> Option<(u16, String, Vec<u8>)> {
    serve_at(proto, value, "http://x.com/")
}

/// As [`serve`], but for an explicit request URL (the content-type fallback
/// and the template variables both read it).
fn serve_at(proto: &str, value: &str, url: &str) -> Option<(u16, String, Vec<u8>)> {
    let (scheme, rest) = url.split_once("://").expect("absolute url");
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let info = build_req_info("GET", scheme, host, 80, path, &HeaderMap::new(), None);
    let op = RuleOp {
        protocol: proto.to_string(),
        value: value.to_string(),
        ..Default::default()
    };
    let resp = serve_file_family(proto, &op, &info, test_env(), None)?;
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
        .expect("collect body")
        .to_bytes()
        .to_vec();
    Some((status, ctype, body))
}

#[test]
fn multi_path_takes_the_first_existing_file() {
    let fx = Fixtures::new("multipath");
    let missing = fx.path("nope.json");
    let present = fx.write("b.json", b"{\"from\":\"b\"}");
    let later = fx.write("c.json", b"{\"from\":\"c\"}");

    let value = format!("{missing}|{present}|{later}");
    let (status, ctype, body) = serve("file", &value).expect("served");
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/json; charset=utf-8");
    assert_eq!(body, b"{\"from\":\"b\"}");
}

/// Mapping a path onto a directory is the whole point of a `file://` rule,
/// and it works because the pattern's leftover URL is appended to the
/// operator's value (`joinUrl`, `_original/lib/rules/rules.js:334-366`).
/// Nothing appended it here: every request under `static.test` served the
/// directory itself, which is not a file, so all of them 404'd.
#[test]
fn a_directory_rule_maps_the_rest_of_the_path_onto_it() {
    let fx = Fixtures::new("dirmap");
    fx.write("js/app.js", b"console.log(1)");
    fx.write("index.html", b"<h1>root</h1>");
    let dir = fx.path("");

    let served = |rules: &str, url: &str| -> Option<(u16, Vec<u8>)> {
        let mut mgr = RuleManager::new();
        mgr.set_text(rules);
        let (scheme, rest) = url.split_once("://").expect("absolute url");
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let info = build_req_info("GET", scheme, host, 80, path, &HeaderMap::new(), None);
        let resp = short_circuit(&info, &mgr.resolve(&info), test_env(), None)?;
        let status = resp.status().as_u16();
        let body = rt()
            .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
            .expect("collect body")
            .to_bytes()
            .to_vec();
        Some((status, body))
    };

    let rules = format!("static.test file://{}\n", dir.trim_end_matches('/'));
    assert_eq!(
        served(&rules, "http://static.test/js/app.js"),
        Some((200, b"console.log(1)".to_vec()))
    );
    // A domain pattern meeting a root request adds **nothing**, so the value
    // stays the bare directory — and a directory is not a file. whistle
    // answers `404 Not found file …/dir` here (measured, 2.10.8), because
    // its `index.html` candidate comes from a *trailing slash* in the text
    // (`getRuleFiles`, `_original/lib/util/index.js:1443-1450`) and the tail
    // that would have supplied one is empty (`rules.js:1100-1101`). Writing
    // the rule with the slash — `file:///srv/static/` — is what asks for the
    // index, and then both proxies serve it.
    assert_eq!(
        served(&rules, "http://static.test/").map(|(s, _)| s),
        Some(404)
    );
    assert_eq!(
        served(&format!("{}/\n", rules.trim_end()), "http://static.test/"),
        Some((200, b"<h1>root</h1>".to_vec()))
    );
    // The query string is not part of a filename.
    assert_eq!(
        served(&rules, "http://static.test/js/app.js?v=2"),
        Some((200, b"console.log(1)".to_vec()))
    );
    // A path pattern contributes only what it did not consume.
    let scoped = format!("static.test/assets file://{}\n", dir.trim_end_matches('/'));
    assert_eq!(
        served(&scoped, "http://static.test/assets/js/app.js"),
        Some((200, b"console.log(1)".to_vec()))
    );
    // …and `<>` pins the value, whatever the request asked for.
    let pinned = format!("static.test file://<{}index.html>\n", dir);
    assert_eq!(
        served(&pinned, "http://static.test/js/app.js"),
        Some((200, b"<h1>root</h1>".to_vec()))
    );
}

/// `file://(text)` answers with the text itself — whistle's inline value
/// (`docs/docs/rules/file.md`, "内联值"). It used to be read as a filename,
/// so every inline mock 404'd.
#[test]
fn a_bracketed_value_is_the_response_body() {
    let (status, ctype, body) =
        serve_at("file", "({\"status\":\"ok\"})", "http://api.test/data.json").expect("served");
    assert_eq!(status, 200);
    assert_eq!(body, b"{\"status\":\"ok\"}");
    // With no file to name the type, the request URL does.
    assert_eq!(ctype, "application/json; charset=utf-8");
    // A template renders the inline text like it renders a file's.
    let (_, _, body) =
        serve_at("tpl", "(hello {name})", "http://api.test/x?name=world").expect("served");
    assert_eq!(body, b"hello world");
}

/// Each `|` alternative takes the request's remaining path, not just the
/// last: joining the value whole would leave the first alternative pointing
/// at the bare directory.
#[test]
fn every_alternative_path_takes_the_rest_of_the_url() {
    let fx = Fixtures::new("altjoin");
    fx.write("second/js/app.js", b"from second");
    let value = format!("{}|{}", fx.path("first"), fx.path("second"));

    let mut mgr = RuleManager::new();
    mgr.set_text(&format!("static.test file://{value}\n"));
    let info = build_req_info(
        "GET",
        "http",
        "static.test",
        80,
        "/js/app.js",
        &HeaderMap::new(),
        None,
    );
    let resp = short_circuit(&info, &mgr.resolve(&info), test_env(), None).expect("served");
    assert_eq!(resp.status().as_u16(), 200);
    let body = rt()
        .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
        .expect("collect body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"from second");
}

#[test]
fn xs_rules_never_split_on_pipe() {
    // whistle's split regex only admits a single `x` (`rules.js:96`), so an
    // `xs` rule treats `|` as part of the filename. Reproduced deliberately.
    let fx = Fixtures::new("xspipe");
    let present = fx.write("only.json", b"ok");
    let value = format!("{}|{present}", fx.path("nope.json"));

    // `xfile` splits and finds the second path…
    assert!(serve("xfile", &value).is_some());
    // …`xsfile` does not, so it falls through to the real server.
    assert!(serve("xsfile", &value).is_none());
}

#[test]
fn parent_directory_paths_are_refused() {
    let fx = Fixtures::new("uppath");
    let target = fx.write("secret.txt", b"nope");
    let escaped = format!("{}/sub/../secret.txt", fx.0.to_string_lossy());
    assert!(std::path::Path::new(&target).exists());

    let (status, _, body) = serve("file", &escaped).expect("served");
    assert_eq!(status, 404);
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("(Path contains parent directory notation &#39;..&#39;)"),
        "{body}"
    );
    // A `..` inside a segment is an ordinary filename, not an escape.
    assert!(!has_parent_ref("/tmp/a..b/c"));
    assert!(has_parent_ref("../a") && has_parent_ref("a/../b") && has_parent_ref("a/.."));
}

#[test]
fn refused_path_still_lets_a_later_alternative_win() {
    let fx = Fixtures::new("uppath2");
    let present = fx.write("ok.txt", b"ok");
    let value = format!("../escape|{present}");
    let (status, _, body) = serve("file", &value).expect("served");
    assert_eq!((status, body.as_slice()), (200, b"ok".as_slice()));
}

#[test]
fn trailing_slash_expands_to_index_html() {
    let fx = Fixtures::new("indexhtml");
    fx.write("site/index.html", b"<h1>home</h1>");
    let value = format!("{}/", fx.path("site"));

    let (status, ctype, body) = serve("file", &value).expect("served");
    assert_eq!(status, 200);
    // The content type comes from the *matched* path, not the rule value.
    assert_eq!(ctype, "text/html; charset=utf-8");
    assert_eq!(body, b"<h1>home</h1>");

    // The directory itself is tried first, and only wins for a real file.
    assert_eq!(
        expand_index("/a/b/"),
        vec!["/a/b".to_string(), "/a/b/index.html".to_string()]
    );
    assert_eq!(expand_index("/a/b"), vec!["/a/b".to_string()]);
}

/// A one-shot HTTP server that answers every request the same way.
///
/// Hand-rolled rather than hyper: what is under test is the fetch, and a
/// fixed status line with a fixed body is the whole of what it needs to
/// answer with. Returns the `http://127.0.0.1:PORT` it is listening on.
async fn one_answer(status: u16, ctype: &str, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let head = head.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Serve a file rule whose source may be a URL, doing the prefetch the
/// request path does.
async fn serve_remote(proto: &str, value: &str, url: &str) -> (u16, String, String) {
    let (scheme, rest) = url.split_once("://").expect("absolute url");
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let info = build_req_info("GET", scheme, host, 80, path, &HeaderMap::new(), None);
    let op = RuleOp {
        protocol: proto.to_string(),
        value: value.to_string(),
        ..Default::default()
    };
    let mut resolved = Resolved::default();
    resolved.insert(op.clone());
    let remote = prefetch_remote_file(&resolved).await;
    let resp = serve_file_family(proto, &op, &info, test_env(), remote.as_ref())
        .expect("the file family answers");
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // Awaited rather than passed to `body_text`, which spins up a runtime
    // of its own and cannot be called from inside one.
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    (status, ctype, String::from_utf8_lossy(&bytes).into_owned())
}

/// A file rule may name a URL, and then its bytes are fetched rather than
/// opened — upstream's `resolveKey`/`requestBin` path
/// (`_original/lib/plugins/index.js:1521-1529`).
///
/// Measured against whistle 2.10.8 before it was written: the content type
/// comes from the **URL**, not from what the source answered with, which is
/// why a JSON body behind an extensionless path is served as `text/html`
/// by both.
#[tokio::test]
async fn a_file_rule_may_name_a_url_instead_of_a_path() {
    let base = one_answer(200, "application/json", r#"{"remote":true}"#).await;

    let (status, ctype, body) =
        serve_remote("file", &format!("{base}/data.json"), "http://x.com/echo").await;
    assert_eq!((status, body.as_str()), (200, r#"{"remote":true}"#));
    assert!(
        ctype.starts_with("application/json"),
        "type from the URL: {ctype}"
    );

    // No extension to guess from, and upstream falls back to the request's
    // own default rather than to what the source said.
    let (_, ctype, _) = serve_remote("file", &format!("{base}/noext"), "http://x.com/echo").await;
    assert!(ctype.starts_with("text/html"), "{ctype}");

    // A final segment that *is* an extension name counts as one, with no
    // dot in sight — `mime.lookup` cuts at the last `.`, `/` or `\`.
    let (_, ctype, _) = serve_remote("file", &format!("{base}/json"), "http://x.com/echo").await;
    assert!(ctype.starts_with("application/json"), "{ctype}");

    // `<…>` is paths only. Measured: whistle opens it as a path and 404s.
    let (status, _, _) =
        serve_remote("file", &format!("<{base}/data.json>"), "http://x.com/echo").await;
    assert_eq!(status, 404, "angle brackets do not name a URL to fetch");
}

/// A source that answers something other than `404` is the file server
/// being broken, and says so with a `502` — `is502` at
/// `_original/lib/handlers/file-proxy.js:301-307`. Measured: whistle answers
/// `502 Error: response 500`, and this port answered `404` until it did.
#[tokio::test]
async fn a_broken_url_source_is_a_502_and_a_missing_one_is_a_404() {
    let broken = one_answer(500, "text/plain", "boom").await;
    let (status, _, body) =
        serve_remote("file", &format!("{broken}/x.json"), "http://x.com/echo").await;
    assert_eq!((status, body.as_str()), (502, "Error: response 500"));

    let missing = one_answer(404, "text/plain", "gone").await;
    let (status, _, body) =
        serve_remote("file", &format!("{missing}/x.json"), "http://x.com/echo").await;
    assert_eq!(status, 404);
    assert!(body.contains("file not found"), "{body}");
}

/// A `|` value mixing a path and a URL tries them in the order written, and
/// only fetches when the local copy is not there.
#[tokio::test]
async fn a_local_path_is_preferred_to_a_url_written_after_it() {
    let base = one_answer(200, "application/json", r#"{"remote":true}"#).await;
    let fx = Fixtures::new("remote-file");
    let local = fx.write("local.json", br#"{"local":true}"#);

    let (_, _, body) = serve_remote(
        "file",
        &format!("{local}|{base}/data.json"),
        "http://x.com/echo",
    )
    .await;
    assert_eq!(body, r#"{"local":true}"#, "the local copy answers first");

    let (_, _, body) = serve_remote(
        "file",
        &format!("/definitely/missing.json|{base}/data.json"),
        "http://x.com/echo",
    )
    .await;
    assert_eq!(
        body, r#"{"remote":true}"#,
        "and the URL when it is not there"
    );
}

#[test]
fn home_prefix_expands_to_the_home_directory() {
    let home = dirs::home_dir().expect("a home directory");
    let home = home.to_string_lossy();
    assert_eq!(expand_home("~/mock.json"), format!("{home}/mock.json"));
    // The full-width tilde is accepted too, a bare `~` is not.
    assert_eq!(expand_home("～/mock.json"), format!("{home}/mock.json"));
    assert_eq!(expand_home("~mock.json"), "~mock.json");
    assert_eq!(expand_home("/tmp/~/x"), "/tmp/~/x");

    assert!(
        FileCandidates::of("file", "~/mock.json", Sources::PathsAndUrls)
            .paths
            .contains(&FileSource::Path(format!("{home}/mock.json")))
    );
}

/// A rules file written on Windows opens on a Mac. `convertSlash` converts
/// on every platform *except* Windows (`util/file-mgr.js:13-16`), which is
/// the opposite of how it reads, and the reason is that the OS being served
/// is not the OS the rule was typed on.
#[cfg(not(windows))]
#[test]
fn a_windows_path_is_read_as_a_path() {
    let home = dirs::home_dir().expect("a home directory");
    let home = home.to_string_lossy();
    assert_eq!(convert_slash("D:\\dir\\mock.json"), "D:/dir/mock.json");
    assert_eq!(convert_slash("/tmp/a\\b.txt"), "/tmp/a/b.txt");
    assert_eq!(convert_slash("/tmp/plain.txt"), "/tmp/plain.txt");
    // Home expansion runs first, so a `~\x` reaches the home directory too.
    assert_eq!(
        convert_slash(&expand_home("~/dir\\mock.json")),
        format!("{home}/dir/mock.json")
    );
    assert!(
        FileCandidates::of("file", "/tmp/wrs\\mock.json", Sources::PathsAndUrls)
            .paths
            .contains(&FileSource::Path("/tmp/wrs/mock.json".to_string()))
    );
}

/// The three encodings a rewritten URL gets, each measured on its own in
/// `cases-paths.js`: the target keeps ASCII exactly and escapes the rest, a
/// `params://` value takes the whole `encodeURI` set, and `urlReplace://`
/// takes neither.
#[test]
fn a_rewritten_target_is_encoded_for_the_wire() {
    let target = |p: &str| request_target(p).map(|u| u.to_string());
    // ASCII is untouched, including what a client already escaped.
    assert_eq!(target("/a%20b%25c"), Some("/a%20b%25c".to_string()));
    assert_eq!(target("/echo?q=a{b|c"), Some("/echo?q=a{b|c".to_string()));
    // Non-ASCII becomes UTF-8 escapes, or the target is not a request line
    // at all and the origin answers 400.
    assert_eq!(target("/echo?q=中"), Some("/echo?q=%E4%B8%AD".to_string()));
    assert_eq!(target("/echo?q=é"), Some("/echo?q=%C3%A9".to_string()));
    assert_eq!(
        target("/echo?q=🚀"),
        Some("/echo?q=%F0%9F%9A%80".to_string())
    );
    // A backtick is not a URI character, so the last resort escapes the
    // rest rather than letting the whole rewrite vanish.
    assert_eq!(target("/ec`ho"), Some("/ec%60ho".to_string()));

    // A `params://` value takes the wider set — and the query it merges
    // into keeps its own escapes as the client wrote them.
    assert_eq!(encode_uri("a{b|c^d"), "a%7Bb%7Cc%5Ed");
    assert_eq!(encode_uri("a%41b"), "a%2541b");
    assert_eq!(encode_uri("a b\"c"), "a%20b%22c");
    assert_eq!(encode_uri("a&b=c/d?e:f"), "a&b=c/d?e:f");
    assert_eq!(
        merge_query("/echo?keep=a%20b", &[("q".into(), "a{b".into())]),
        "/echo?keep=a%20b&q=a%7Bb"
    );
}

#[test]
fn template_rules_render_the_file() {
    let fx = Fixtures::new("tpl");
    let path = fx.write(
        "api.json",
        br#"{"cb":"{callback}","m":"${method.replace(GET,get)}"}"#,
    );
    let (status, ctype, body) =
        serve_at("tpl", &path, "http://x.com/api?callback=cb1").expect("served");
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/json; charset=utf-8");
    assert_eq!(String::from_utf8_lossy(&body), r#"{"cb":"cb1","m":"get"}"#);
}

#[test]
fn raw_file_parses_a_complete_response() {
    let fx = Fixtures::new("rawfile");
    let path = fx.write(
        "res.http",
        b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"nope\"}",
    );
    let (status, ctype, body) = serve("rawfile", &path).expect("served");
    assert_eq!(status, 404);
    assert_eq!(ctype, "application/json");
    assert_eq!(body, b"{\"error\":\"nope\"}");
}

#[test]
fn raw_file_without_a_blank_line_is_served_verbatim() {
    // No separator means it was never a raw response; whistle serves the
    // file rather than eating its first line as a status line.
    let fx = Fixtures::new("rawplain");
    let path = fx.write("plain.txt", b"HTTP/1.1 200 OK\r\nnot really a response");
    let (status, ctype, body) = serve("rawfile", &path).expect("served");
    assert_eq!(status, 200);
    assert_eq!(ctype, "text/plain; charset=utf-8");
    assert_eq!(body, b"HTTP/1.1 200 OK\r\nnot really a response");
}

#[test]
fn raw_file_keeps_a_binary_body() {
    let fx = Fixtures::new("rawbin");
    let mut fixture = b"HTTP/1.1 200 OK\nContent-Type: image/png\n\n".to_vec();
    let payload = [0x89u8, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe];
    fixture.extend_from_slice(&payload);
    let path = fx.write("img.http", &fixture);

    let (status, ctype, body) = serve("rawfile", &path).expect("served");
    assert_eq!((status, ctype.as_str()), (200, "image/png"));
    assert_eq!(body, payload, "lossy UTF-8 would have mangled these bytes");
}

#[test]
fn headers_separator_accepts_every_line_ending() {
    // `HEADERS_SEP_RE`, file-proxy.js:12.
    for sep in [
        "\r\n\r\n", "\r\n\r", "\r\n\n", "\n\r\n", "\n\r", "\n\n", "\r\r\n", "\r\r",
    ] {
        let data = format!("head{sep}body");
        let (head_end, body_start) = find_headers_sep(data.as_bytes()).expect(sep);
        assert_eq!(&data[..head_end], "head", "{sep:?}");
        assert_eq!(&data[body_start..], "body", "{sep:?}");
    }
    assert_eq!(find_headers_sep(b"head\nbody"), None);
}

#[test]
fn a_separator_past_the_header_budget_is_ignored() {
    // whistle stops looking after MAX_HEADERS_SIZE (file-proxy.js:13,151-158).
    let mut data = vec![b'x'; MAX_RAW_HEADERS + 16];
    data.extend_from_slice(b"\r\n\r\nbody");
    assert!(find_headers_sep(&data[..data.len().min(MAX_RAW_HEADERS)]).is_none());
}

/// A raw response's header lines end at any of `\r\n`, `\r` or `\n`
/// (`CRLF_RE`, `file-proxy.js:10`). Splitting on `\n` alone read a
/// CR-terminated fixture as one long status line, so every header in it was
/// dropped — the body and the status arrived, the headers silently did not.
#[test]
fn raw_file_header_lines_end_at_a_bare_cr() {
    let fx = Fixtures::new("rawcr");
    let path = fx.write("cr.http", b"HTTP/1.1 202 Accepted\rX-Sep: cr\r\rcr body");
    let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
    let op = RuleOp {
        protocol: "rawfile".into(),
        value: path,
        ..Default::default()
    };
    let resp = serve_file_family("rawfile", &op, &info, test_env(), None).expect("served");
    assert_eq!(resp.status().as_u16(), 202);
    assert_eq!(
        resp.headers().get("x-sep").and_then(|v| v.to_str().ok()),
        Some("cr")
    );
}

/// A `rawfile://` head with no status line: upstream takes the first line's
/// second word as the status code and throws while writing the response,
/// which the client sees as a reset connection. Serving it as 200 is a
/// deliberate deviation — there is no behaviour there to be faithful to.
#[test]
fn a_raw_response_with_no_status_line_falls_back_to_200() {
    let fx = Fixtures::new("rawnostatus");
    let path = fx.write("h.http", b"X-Only: header\r\n\r\nbody");
    let (status, _, body) = serve("rawfile", &path).expect("served");
    assert_eq!((status, body.as_slice()), (200, b"body".as_slice()));
}

/// Only a file read off disk carries `Server` (`file-proxy.js:315-318`);
/// an inline value, a values-store body and the 404 are all built elsewhere
/// and carry none. The asymmetry is upstream's and is worth keeping: the
/// header says the bytes came from the filesystem.
#[test]
fn only_a_file_read_from_disk_names_the_proxy_in_server() {
    let fx = Fixtures::new("srvhdr");
    let path = fx.write("a.txt", b"body");
    let served = |proto: &str, value: &str| {
        let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
        let op = RuleOp {
            protocol: proto.into(),
            value: value.into(),
            ..Default::default()
        };
        let resp = serve_file_family(proto, &op, &info, test_env(), None).expect("served");
        resp.headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    assert_eq!(served("file", &path).as_deref(), Some("whistle-rs"));
    assert_eq!(served("tpl", &path).as_deref(), Some("whistle-rs"));
    assert_eq!(served("file", "(inline)"), None);
    assert_eq!(served("file", &fx.path("nope.txt")), None);
    // A parsed raw response brings its own headers and replaces the block
    // `Server` lives in; one with no blank line falls back to it.
    let raw = fx.write("r.http", b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nb");
    assert_eq!(served("rawfile", &raw), None);
    assert_eq!(served("rawfile", &path).as_deref(), Some("whistle-rs"));
}

/// The name a body was stored under is the only place its extension is
/// written, so it is what the content type is guessed from
/// (`rule.key`, `file-proxy.js:270-272`). Without this, `file://{mock.json}`
/// served JSON as `text/html` and a browser rendered it as a page.
#[test]
fn a_values_key_names_the_file_its_type_is_guessed_from() {
    let typed = |key: Option<&str>, url: &str| {
        let (host, path) = url.split_once('/').expect("host and path");
        let info = build_req_info("GET", "http", host, 80, path, &HeaderMap::new(), None);
        let op = RuleOp {
            protocol: "file".into(),
            value: "{\"a\":1}".into(),
            value_is_content: true,
            value_key: key.map(str::to_string),
            ..Default::default()
        };
        let resp = serve_file_family("file", &op, &info, test_env(), None).expect("served");
        resp.headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(
        typed(Some("mock.json"), "x.com/echo"),
        "application/json; charset=utf-8"
    );
    // A key with no extension of its own falls back to the request URL's,
    // and then to `text/html` — the same chain a nameless inline value takes.
    assert_eq!(
        typed(Some("mockbody"), "x.com/thing.css"),
        "text/css; charset=utf-8"
    );
    assert_eq!(typed(None, "x.com/thing.css"), "text/css; charset=utf-8");
    assert_eq!(
        typed(Some("mockbody"), "x.com/echo"),
        "text/html; charset=utf-8"
    );
}

/// `util.isText` is a substring test, so a type merely *naming* xml or html
/// is text — which is why an SVG carries a charset and a PNG does not
/// (`_original/lib/util/index.js:1494-1531`).
#[test]
fn a_content_type_carries_a_charset_only_when_it_is_text() {
    for (ext, want) in [
        ("svg", "image/svg+xml; charset=utf-8"),
        ("xhtml", "application/xhtml+xml; charset=utf-8"),
        ("map", "application/json; charset=utf-8"),
        ("md", "text/markdown; charset=utf-8"),
        ("csv", "text/csv; charset=utf-8"),
        ("yml", "text/yaml; charset=utf-8"),
        ("png", "image/png"),
        ("woff2", "font/woff2"),
        ("mp4", "video/mp4"),
        ("zip", "application/zip"),
    ] {
        assert_eq!(
            content_type_of_ext(&format!("a.{ext}")),
            Some(want),
            "{ext}"
        );
    }
}

/// Serve a file rule for a `GET` carrying one request header.
fn serve_with_header(
    proto: &str,
    value: &str,
    name: &str,
    header: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
        header.parse().expect("header value"),
    );
    let info = build_req_info("GET", "http", "x.com", 80, "/", &headers, None);
    let op = RuleOp {
        protocol: proto.into(),
        value: value.into(),
        ..Default::default()
    };
    let resp = serve_file_family(proto, &op, &info, test_env(), None).expect("served");
    let status = resp.status().as_u16();
    let heads = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = rt()
        .block_on(async { http_body_util::BodyExt::collect(resp.into_body()).await })
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, heads, body)
}

#[test]
fn a_range_request_serves_part_of_a_file() {
    let fx = Fixtures::new("range");
    let path = fx.write("r.txt", b"ranged-0123456789-end");
    let (status, heads, body) = serve_with_header("file", &path, "range", "bytes=0-5");
    assert_eq!((status, body.as_slice()), (206, b"ranged".as_slice()));
    assert!(
        heads.contains(&("content-range".into(), "bytes 0-5/21".into())),
        "{heads:?}"
    );
    assert!(
        heads.contains(&("accept-ranges".into(), "bytes".into())),
        "{heads:?}"
    );
    // An inline value is rangeable too — it is the same `if (!isRawFile)`
    // arm upstream (`file-proxy.js:280-289`).
    let (status, _, body) = serve_with_header("file", "(0123456789)", "range", "bytes=2-4");
    assert_eq!((status, body.as_slice()), (206, b"234".as_slice()));
}

/// `rawfile://` asks for no range at all (`file-proxy.js:100-102`) and
/// `tpl://` never reaches the code that would; both answer whole.
#[test]
fn raw_and_template_responses_ignore_a_range_request() {
    let fx = Fixtures::new("rangeskip");
    let raw = fx.write("r.http", b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nabcdefgh");
    let (status, _, body) = serve_with_header("rawfile", &raw, "range", "bytes=0-3");
    assert_eq!((status, body.as_slice()), (200, b"abcdefgh".as_slice()));

    let tpl = fx.write("t.txt", b"abcdefgh${nothing}");
    let (status, _, body) = serve_with_header("tpl", &tpl, "range", "bytes=0-3");
    assert_eq!(status, 200);
    assert_eq!(body.len(), 18);
}

/// whistle's range arithmetic, quirks included: a suffix range compares its
/// computed start against the *suffix length* and loses, and several ranges
/// collapse into the one span that covers them all.
#[test]
fn range_parsing_reproduces_upstreams_arithmetic() {
    let parsed = |spec: &str, size: usize| {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::RANGE, spec.parse().expect("range value"));
        let info = build_req_info("GET", "http", "x.com", 80, "/", &headers, None);
        parse_range(&info, size)
    };
    assert_eq!(parsed("bytes=0-5", 21), Some((0, 5)));
    assert_eq!(parsed("bytes=7-", 21), Some((7, 20)));
    assert_eq!(parsed("bytes=0-20", 21), Some((20 - 20, 20)));
    assert_eq!(parsed("BYTES=0-5", 21), Some((0, 5)));
    assert_eq!(parsed("  bytes=0-5", 21), Some((0, 5)));
    // `bytes=0-1,5-6` is one span, not two parts.
    assert_eq!(parsed("bytes=0-1,5-6", 21), Some((0, 6)));
    // A suffix range: start becomes `21 - 5 = 16`, which is compared against
    // the end `5` and rejected. Upstream sends the whole body.
    assert_eq!(parsed("bytes=-5", 21), None);
    assert_eq!(parsed("bytes=10-99", 21), None);
    assert_eq!(parsed("bytes=9-2", 21), None);
    assert_eq!(parsed("bytes=abc", 21), None);
    assert_eq!(parsed("bytes=", 21), None);
    assert_eq!(parsed("items=0-5", 21), None);
    // `bytes =0-5` — the `=` has to follow the unit immediately.
    assert_eq!(parsed("bytes =0-5", 21), None);
    // Nothing is ranged out of an empty body.
    assert_eq!(parsed("bytes=0-1", 0), None);
}

/// The inline form of `rawfile://` parses what it is given and no more: with
/// no blank line, `parseRes` receives nothing and answers a bare `{200, {}}`,
/// so the body goes out untyped (`getRawResByValue`, `file-proxy.js:84-98`).
/// The path form falls back to the file handler's header block instead.
#[test]
fn an_inline_raw_response_without_a_blank_line_is_untyped() {
    let info = build_req_info(
        "GET",
        "http",
        "x.com",
        80,
        "/a.json",
        &HeaderMap::new(),
        None,
    );
    let op = RuleOp {
        protocol: "rawfile".into(),
        value: "(no-blank-line)".into(),
        ..Default::default()
    };
    let resp = serve_file_family("rawfile", &op, &info, test_env(), None).expect("served");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.headers().get(hyper::header::CONTENT_TYPE).is_none());
}

/// A raw response written as a *value* cannot be the compressed bytes a
/// `content-encoding` claims — it was typed into a rules file — so upstream
/// drops the header (`fromValue`, `file-proxy.js:71-73`). Keeping it made
/// the client try to gunzip plain text and fail on a body it could read.
/// A raw response read from a *file* keeps it: that one can really be gzip.
#[test]
fn a_raw_response_from_a_value_loses_its_content_encoding() {
    let info = build_req_info("GET", "http", "x.com", 80, "/", &HeaderMap::new(), None);
    let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nplain";
    let encoding_of = |op: &RuleOp| {
        serve_file_family("rawfile", op, &info, test_env(), None)
            .expect("served")
            .headers()
            .get(hyper::header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap_or_default().to_string())
    };
    let from_value = RuleOp {
        protocol: "rawfile".into(),
        value: String::from_utf8_lossy(head).into_owned(),
        value_is_content: true,
        ..Default::default()
    };
    assert_eq!(encoding_of(&from_value), None);

    let fx = Fixtures::new("rawenc");
    let from_file = RuleOp {
        protocol: "rawfile".into(),
        value: fx.write("r.http", head),
        ..Default::default()
    };
    assert_eq!(encoding_of(&from_file).as_deref(), Some("gzip"));
}

#[test]
fn missing_file_404s_with_an_escaped_path() {
    let (status, ctype, body) = serve("file", "/nonexistent/<script>").expect("served");
    assert_eq!(status, 404);
    assert_eq!(ctype, "text/html; charset=utf-8");
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("&lt;script&gt;"), "{body}");
    assert!(!body.contains("<script>"), "{body}");
}

#[test]
fn the_file_cache_never_serves_stale_bytes() {
    let fx = Fixtures::new("cache");
    let path = fx.write("mock.json", b"{\"v\":1}");
    assert_eq!(serve("file", &path).expect("served").2, b"{\"v\":1}");

    // A mock edited mid-session must be picked up, even at the same length.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, b"{\"v\":2}").expect("rewrite fixture");
    assert_eq!(serve("file", &path).expect("served").2, b"{\"v\":2}");
}

#[test]
fn cipher_sets_target_tls_versions() {
    use super::super::upstream::TlsVersions;
    let resolved = resolve("example.com cipher://TLSv1.2\n", "https://example.com/");
    let info = build_req_info(
        "GET",
        "https",
        "example.com",
        443,
        "/",
        &HeaderMap::new(),
        None,
    );
    let target = resolved_target(&info, &resolved);
    assert_eq!(target.tls_versions, TlsVersions::Only12);
}

/// **A cipher string that selects nothing takes the pin down, not the
/// request.** It used to `bail!`, which meant one unusable value in a rules
/// file removed every HTTPS site behind that pattern.
///
/// The deciding reason is in [`super::super::ciphers`]: "selects nothing"
/// here is a fact about rustls's nine suites, not about the string —
/// `cipher://3DES` is a good string everywhere OpenSSL was built with 3DES.
/// Failing the request would put a limitation of this build into somebody
/// else's traffic, under a message about their rule. `https-bench.js`
/// measures the family against real whistle, which applies none of it.
#[test]
fn an_unusable_cipher_string_drops_the_pin_and_keeps_the_request() {
    use super::super::upstream::TlsVersions;
    for spec in [
        "example.com cipher://NOTACIPHER\n",
        "example.com tlsOptions://not-a-version\n",
        "example.com cipher://3DES\n",
        "example.com cipher://{\"ciphers\":\"!ALL\"}\n",
    ] {
        let target = try_target(spec, "https://example.com/")
            .unwrap_or_else(|e| panic!("{spec:?} must not fail the request: {e:#}"));
        assert!(
            target.tls_ciphers.is_none(),
            "{spec:?} selected nothing, so nothing is pinned"
        );
    }

    // The two halves of a `cipher://` value are read independently: an
    // unusable cipher string does not take a usable version with it.
    let target = try_target(
        "example.com cipher://{\"ciphers\":\"NOTACIPHER\",\"maxVersion\":\"TLSv1.2\"}\n",
        "https://example.com/",
    )
    .expect("the version half is still usable");
    assert!(target.tls_ciphers.is_none());
    assert_eq!(target.tls_versions, TlsVersions::Only12);

    // Suites that exist but that no allowed version can use — only TLS 1.3
    // ones, capped at 1.2 — go the same way. Building the connection for
    // them panicked the request's task, which then read as the client
    // having left.
    let target = try_target(
            "example.com cipher://{\"ciphers\":\"TLS_AES_128_GCM_SHA256\",\"maxVersion\":\"TLSv1.2\"}\n",
            "https://example.com/",
        )
        .expect("a pin nothing can use does not fail the request");
    assert!(target.tls_ciphers.is_none());
    assert_eq!(target.tls_versions, TlsVersions::Only12);

    // And a string that does select something still pins it, or none of the
    // above would be saying anything.
    let target = try_target(
        "example.com cipher://{\"ciphers\":\"ECDHE-RSA-AES128-GCM-SHA256\"}\n",
        "https://example.com/",
    )
    .expect("a usable cipher string");
    assert!(
        target.tls_ciphers.is_some(),
        "a matchable string still pins"
    );
}

// ── host / proxy precedence (proxyFirst, proxyHost, proxyHostOnly) ──

/// The upstream target `rules` produce for `url`, or the error that stopped
/// the request from being sent anywhere.
fn try_target(rules: &str, url: &str) -> Result<Target> {
    let resolved = resolve(rules, url);
    let (scheme, rest) = url.split_once("://").unwrap();
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let info = build_req_info(
        "GET",
        scheme,
        host,
        if scheme == "https" { 443 } else { 80 },
        path,
        &HeaderMap::new(),
        None,
    );
    rt().block_on(resolve_target(
        &info,
        &crate::proxy::dest::Destination::of(&info, &resolved),
        &resolved,
    ))
}

/// The upstream target `rules` produce for `url`.
fn target(rules: &str, url: &str) -> Target {
    try_target(rules, url).unwrap_or_else(|e| panic!("resolve_target: {e:#}"))
}

/// A client-id a client sent is dropped, unless the request asked to keep
/// it (`removeClientId`, `_original/lib/inspectors/res.js:717-723`).
/// Measured on both proxies, with and without the flag.
#[test]
fn a_client_id_from_the_client_does_not_travel_on() {
    let sent = |rules: &str| {
        let resolved = resolve(rules, "http://example.com/a");
        let req = hyper::Request::builder()
            .method("GET")
            .uri("http://example.com/a")
            .header("x-whistle-client-id", "cid")
            .body(())
            .expect("request");
        let (mut parts, ()) = req.into_parts();
        apply_request(&mut parts, &resolved);
        parts
            .headers
            .get("x-whistle-client-id")
            .map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(sent("example.com reqHeaders://x-a=1"), None);
    assert_eq!(
        sent("example.com enable://keepClientId").as_deref(),
        Some("cid")
    );
    // `disable://` beats it, as it beats every flag.
    assert_eq!(
        sent("example.com enable://keepClientId\nexample.com disable://keepClientId"),
        None
    );
}

/// `auto2http` — `host.md`'s convenience, and the three ways to reach it.
///
/// `checkAuto2Http` (`_original/lib/util/index.js:3191-3198`): a `host://`
/// rule on the request, a local address, or `enable://auto2http`; and
/// `disable://auto2http` over all three.
#[test]
fn an_https_leg_falls_back_to_cleartext_only_when_it_was_asked_to() {
    let https = "https://example.com/";
    // A public address with nothing to say about it: no retry.
    assert!(!target("example.com reqHeaders://x=1", https).auto2http);
    // A `host://` rule is enough on its own, wherever it points.
    assert!(target("example.com host://1.2.3.4", https).auto2http);
    // So is a local destination.
    assert!(target("example.com host://127.0.0.1:5173", https).auto2http);
    assert!(target("example.com https://localhost:5173", https).auto2http);
    // And so is saying it.
    assert!(target("example.com enable://auto2http", https).auto2http);
    // `disable://` beats every one of them.
    assert!(
        !target(
            "example.com host://127.0.0.1:5173\nexample.com disable://auto2http",
            https
        )
        .auto2http
    );
    assert!(
        !target(
            "example.com enable://auto2http\nexample.com disable://auto2http",
            https
        )
        .auto2http
    );
    // An http request has no leg to downgrade — the flag is read, the
    // retry is not reachable.
    let plain = target("example.com host://127.0.0.1:5173", "http://example.com/");
    assert!(plain.auto2http && !plain.tls);
}

/// `checkH2` (`_original/lib/inspectors/res.js:174-195`): three spellings
/// each way, `disable` over `enable`, and no rule leaves it to the client.
#[test]
fn the_h2_flags_turn_origin_h2_either_way() {
    let https = "https://example.com/";
    assert_eq!(target("example.com reqHeaders://x=1", https).h2, None);
    for flag in ["h2", "http2", "httpsH2"] {
        assert_eq!(
            target(&format!("example.com enable://{flag}"), https).h2,
            Some(true)
        );
        assert_eq!(
            target(&format!("example.com disable://{flag}"), https).h2,
            Some(false)
        );
    }
    assert_eq!(
        target(
            "example.com enable://h2\nexample.com disable://http2",
            https
        )
        .h2,
        Some(false)
    );
}

const HOST_AND_PROXY: &str = "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\n";

/// With both a `host://` and a `proxy://` rule matched, whistle uses the
/// host and drops the proxy (`_original/lib/rules/index.js:220-237`).
#[test]
fn host_outranks_proxy_by_default() {
    let t = target(HOST_AND_PROXY, "http://example.com/");
    assert_eq!(t.connect_host, "1.2.3.4");
    assert!(t.proxy.is_none(), "the proxy must lose to the host rule");
}

/// `xhost://` resolves to the same `host` operator as `host://`
/// (`xhost: 'host'`, `_original/lib/rules/protocols.js:145`) — the only
/// thing that tells them apart is the matcher as written, which is what
/// carries the pass-through behaviour to the forwarding layer.
#[test]
fn only_the_x_spelling_of_host_falls_back() {
    let t = target("example.com xhost://10.0.0.9:8443\n", "http://example.com/");
    assert_eq!(
        (t.connect_host.as_str(), t.connect_port),
        ("10.0.0.9", 8443)
    );
    assert!(
        t.host_fallback_direct,
        "xhost:// is the pass-through spelling"
    );

    let t = target("example.com host://10.0.0.9:8443\n", "http://example.com/");
    assert_eq!(
        (t.connect_host.as_str(), t.connect_port),
        ("10.0.0.9", 8443)
    );
    assert!(!t.host_fallback_direct, "host:// fails the request instead");

    // `hosts://` is the third spelling and is *not* the x one.
    let t = target("example.com hosts://10.0.0.9\n", "http://example.com/");
    assert!(!t.host_fallback_direct);
}

/// A proxy rule with no host rule to lose to is used as-is.
#[test]
fn proxy_alone_is_untouched() {
    let t = target(
        "example.com proxy://127.0.0.1:8888\n",
        "http://example.com/",
    );
    assert_eq!(t.proxy.expect("proxy").port, 8888);
}

/// `proxyHost` (on either line, or request-wide) keeps both, so the request
/// goes through the proxy *to the host address*.
#[test]
fn proxy_host_keeps_both_the_proxy_and_the_host_address() {
    for rules in [
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyHost\n",
        "example.com host://1.2.3.4 lineProps://proxyHost\nexample.com proxy://127.0.0.1:8888\n",
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\nexample.com enable://proxyHost\n",
    ] {
        let t = target(rules, "http://example.com/");
        assert!(t.proxy.is_some(), "proxy should survive: {rules}");
        assert_eq!(t.connect_host, "1.2.3.4", "host override still applies");
    }
}

/// `proxyFirst` keeps the proxy and **drops** the host address — it settles
/// which of the two rules wins rather than combining them, and the winner is
/// the proxy. Measured against real whistle 2.10.8, which sends the request
/// to the hop in absolute form naming the *requested* origin, with no
/// CONNECT and no sign of the host rule
/// (`_original/lib/rules/index.js:217-236`; the bench case is
/// `both: proxyFirst prefers the proxy`).
#[test]
fn proxy_first_drops_the_host_address_rather_than_combining_it() {
    for rules in [
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyFirst\n",
        "example.com host://1.2.3.4 lineProps://proxyFirst\nexample.com proxy://127.0.0.1:8888\n",
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888\nexample.com enable://proxyFirst\n",
    ] {
        let t = target(rules, "http://example.com/");
        assert!(t.proxy.is_some(), "proxy should survive: {rules}");
        assert_eq!(
            t.connect_host, "example.com",
            "the host address is dropped: {rules}"
        );
        assert_eq!(t.connect_port, 80);
    }
    // Both properties together: `proxyHost` is the one that speaks, so the
    // address travels after all.
    let t = target(
        "example.com host://1.2.3.4 lineProps://proxyFirst\nexample.com proxy://127.0.0.1:8888 lineProps://proxyHost\n",
        "http://example.com/",
    );
    assert_eq!(t.connect_host, "1.2.3.4");
}

/// `?proxyHost` in the proxy's own URL says the same thing, and is not part
/// of the proxy address.
#[test]
fn proxy_host_flag_in_the_proxy_url() {
    let t = target(
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888?proxyHost\n",
        "http://example.com/",
    );
    let p = t.proxy.expect("?proxyHost should keep the proxy");
    assert_eq!(p.host, "127.0.0.1");
    assert_eq!(
        p.port, 8888,
        "the query flag must not leak into the address"
    );
}

/// `proxyHostOnly` keeps both when a host rule matched, and discards the
/// proxy when none did.
#[test]
fn proxy_host_only_requires_a_host_rule() {
    let with_host = target(
        "example.com host://1.2.3.4\nexample.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
        "http://example.com/",
    );
    assert!(with_host.proxy.is_some());
    assert_eq!(with_host.connect_host, "1.2.3.4");

    let without_host = target(
        "example.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
        "http://example.com/",
    );
    assert!(
        without_host.proxy.is_none(),
        "proxyHostOnly with no host rule drops the proxy"
    );
    assert_eq!(without_host.connect_host, "example.com");
}

// ── ignore://proxy, unusable proxies, scheme-converting proxies ──

/// `ignore://proxy` names the whole upstream-proxy family, because whistle
/// keeps one key for all of them (`resolveProxy`,
/// `_original/lib/rules/rules.js:2419-2443`). Naming one spelling drops only
/// that one. Every one of these used to traverse the hop regardless.
#[test]
fn ignore_proxy_drops_every_proxy_protocol() {
    for proto in crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS {
        let t = target(
            &format!("example.com {proto}://127.0.0.1:8888\nexample.com ignore://proxy\n"),
            "http://example.com/",
        );
        assert!(t.proxy.is_none(), "ignore://proxy must drop {proto}://");
    }

    // The x-spelling of the family says the same thing.
    let t = target(
        "example.com socks://127.0.0.1:1080\nexample.com ignore://xproxy\n",
        "http://example.com/",
    );
    assert!(t.proxy.is_none(), "ignore://xproxy must drop the family");

    // Naming one protocol leaves the others alone.
    let t = target(
        "example.com proxy://127.0.0.1:8888\nexample.com ignore://socks\n",
        "http://example.com/",
    );
    assert_eq!(
        t.proxy
            .expect("ignore://socks must not touch proxy://")
            .port,
        8888
    );
    let t = target(
        "example.com socks://127.0.0.1:1080\nexample.com ignore://socks\n",
        "http://example.com/",
    );
    assert!(t.proxy.is_none(), "ignore://socks drops socks://");
}

/// An ignored proxy does not fall through to a `pac://` rule: whistle
/// returns before it would consult PAC (`_original/lib/rules/index.js:238`).
/// A `pac://` rule with no proxy rule to ignore is still honoured, and
/// `ignore://pac` is what suppresses that one.
#[test]
fn ignoring_the_proxy_does_not_fall_through_to_pac() {
    // A rule token cannot contain whitespace, so a PAC script reaches a rule
    // as a path (or a URL) rather than inline.
    let fx = Fixtures::new("pac-ignore");
    let pac = fx.write(
        "corp.pac",
        b"function FindProxyForURL(u, h) { return 'PROXY 10.0.0.1:3128'; }",
    );

    let t = target(
        &format!(
            "example.com proxy://127.0.0.1:8888\nexample.com pac://{pac}\nexample.com ignore://proxy\n"
        ),
        "http://example.com/",
    );
    assert!(
        t.proxy.is_none(),
        "ignore://proxy must not fall back to PAC"
    );

    let t = target(&format!("example.com pac://{pac}\n"), "http://example.com/");
    assert_eq!(t.proxy.expect("pac chooses the proxy").port, 3128);

    let t = target(
        &format!("example.com pac://{pac}\nexample.com ignore://pac\n"),
        "http://example.com/",
    );
    assert!(t.proxy.is_none(), "ignore://pac drops the PAC rule");
}

/// A proxy rule whose value is empty or unusable fails the request. It used
/// to be skipped, which turned "route this through a proxy" into a direct
/// connection with nothing said about it.
#[test]
fn an_unusable_proxy_value_fails_rather_than_going_direct() {
    for rules in [
        "example.com proxy://\n",
        "example.com proxy:// \n",
        "example.com socks://\n",
        "example.com http-proxy://@\n",
        "example.com proxy://?proxyHost\n",
    ] {
        let err = try_target(rules, "http://example.com/").expect_err(&format!(
            "{rules:?} must not resolve to a direct connection"
        ));
        assert!(
            format!("{err:#}").contains("proxy address"),
            "{rules:?}: {err:#}"
        );
    }
}

/// The error names the value it could not use, but not the password in it:
/// the text goes into the client's 502 and into the session.
#[test]
fn an_unusable_proxy_value_is_reported_without_its_password() {
    let err = try_target(
        "example.com proxy://alice:s3cret@:8080\n",
        "http://example.com/",
    )
    .expect_err("no host, so not usable");
    let message = format!("{err:#}");
    assert!(!message.contains("s3cret"), "{message}");
    assert!(!message.contains("alice"), "{message}");
    assert!(message.contains("proxy://***@:8080"), "{message}");
    assert_eq!(
        super::super::upstream::without_credentials("//u:p@h:1/x?y=@z"),
        "//***@h:1/x?y=@z",
        "only the authority's credentials; an @ in the query is not one"
    );
    assert_eq!(super::super::upstream::without_credentials("h:1"), "h:1");
}

/// A PAC file that answers with something we cannot use is an error too;
/// only `DIRECT` means "no proxy".
#[test]
fn a_pac_result_we_cannot_use_is_not_a_direct_connection() {
    assert!(parse_pac_result("DIRECT").expect("DIRECT parses").is_none());
    assert!(
        parse_pac_result("PROXY 1.2.3.4:8080; DIRECT")
            .expect("parses")
            .is_some()
    );
    // Unknown entry, then DIRECT: the DIRECT still wins.
    assert!(
        parse_pac_result("SOCKS4 1.2.3.4:1080; DIRECT")
            .expect("parses")
            .is_none()
    );
    // …but on its own, an entry we cannot honour is not a direct connection.
    assert!(parse_pac_result("SOCKS4 1.2.3.4:1080").is_err());
    assert!(parse_pac_result("PROXY").is_err());
    assert!(parse_pac_result("").is_err());
}

/// A `DIRECT` *after* the chosen proxy is that proxy's fallback, not a
/// choice: the hop is tried, and a connection that cannot be established
/// goes direct rather than failing the request. This port ignored it, so
/// `PROXY dead; DIRECT` — the shape every corporate PAC file ends with —
/// answered 502 where whistle served the page. whistle turns the same result
/// into an `x`-prefixed rule (`prefix = 'x'`, `node-pac/lib/Pac.js:96-103`).
#[test]
fn a_pac_direct_after_the_proxy_is_that_proxys_fallback() {
    let with = parse_pac_result("PROXY 1.2.3.4:8080; DIRECT")
        .unwrap()
        .unwrap();
    assert!(with.fallback_direct, "the trailing DIRECT is a fallback");

    let without = parse_pac_result("PROXY 1.2.3.4:8080").unwrap().unwrap();
    assert!(!without.fallback_direct, "no DIRECT, no fallback");

    // It may sit past an entry we cannot honour, and it is still a fallback.
    let past = parse_pac_result("PROXY 1.2.3.4:8080; SOCKS4 9.9.9.9:1080; DIRECT")
        .unwrap()
        .unwrap();
    assert!(past.fallback_direct);

    // A `DIRECT` reached *first* is the answer itself, not a fallback.
    assert!(
        parse_pac_result("DIRECT; PROXY 1.2.3.4:8080")
            .unwrap()
            .is_none()
    );
}

/// `http2https-proxy://` upgrades an http origin to TLS
/// (`_original/lib/inspectors/res.js:236-237`), and the `internal-*` /
/// `https2http-proxy://` family strips an https origin's TLS for the hop
/// and marks the request instead (`res.js:229-234`). Neither conversion
/// happened before: the scheme travelled unchanged, so `http2https-proxy`
/// left in cleartext what the rule promised to encrypt.
#[test]
fn scheme_converting_proxies_change_the_origin_connection() {
    let t = target(
        "example.com http2https-proxy://127.0.0.1:8888\n",
        "http://example.com/",
    );
    assert!(t.tls, "http2https-proxy must reach the origin over TLS");
    assert!(!t.origin_tls_stripped);

    // …and an origin that is already https stays https.
    let t = target(
        "example.com http2https-proxy://127.0.0.1:8888\n",
        "https://example.com/",
    );
    assert!(t.tls);

    for proto in [
        "https2http-proxy",
        "internal-proxy",
        "internal-http-proxy",
        "internal-https-proxy",
    ] {
        let t = target(
            &format!("example.com {proto}://127.0.0.1:8888\n"),
            "https://example.com/",
        );
        assert!(!t.tls, "{proto} hands the origin request over in plaintext");
        assert!(t.origin_tls_stripped, "{proto} must mark the stripped TLS");

        // An http origin has no TLS to strip, so nothing is marked.
        let t = target(
            &format!("example.com {proto}://127.0.0.1:8888\n"),
            "http://example.com/",
        );
        assert!(!t.tls);
        assert!(!t.origin_tls_stripped);
    }

    // A plain proxy converts nothing.
    let t = target(
        "example.com proxy://127.0.0.1:8888\n",
        "https://example.com/",
    );
    assert!(t.tls);
    assert!(!t.origin_tls_stripped);

    // The conversion belongs to the proxy, so a proxy that lost to a
    // `host://` rule cannot convert anything on its way out.
    let t = target(
        "example.com http2https-proxy://127.0.0.1:8888\nexample.com host://10.0.0.9\n",
        "http://example.com/",
    );
    assert!(t.proxy.is_none(), "host:// wins by default");
    assert!(!t.tls, "no proxy survived, so no scheme upgrade");
    let t = target(
        "example.com https2http-proxy://127.0.0.1:8888\nexample.com host://10.0.0.9\n",
        "https://example.com/",
    );
    assert!(t.proxy.is_none());
    assert!(t.tls, "…and none to strip either");
    assert!(!t.origin_tls_stripped);
}

/// `lineProps://internalProxy` says of a plain `proxy://` hop what the
/// `internal-*` spellings say of themselves: it is another whistle, so hand
/// it the request in the clear (`isInternalProxy`,
/// `_original/lib/util/index.js:3801-3807`).
///
/// `docs/LINE_PROPS.md` called this exposed-only because the port had no
/// cleartext-through-a-proxy mode. It has had one since the `internal-*`
/// protocols landed; only this way of asking for it was missing.
#[test]
fn internal_proxy_hands_an_https_origin_over_in_the_clear() {
    // On the proxy line, on the `host://` line, and request-wide — the three
    // places upstream reads it from.
    for rules in [
        "example.com proxy://127.0.0.1:8888 lineProps://internalProxy\n",
        "example.com proxy://127.0.0.1:8888 lineProps://proxyHost\n\
             example.com host://10.0.0.9 lineProps://internalProxy\n",
        "example.com proxy://127.0.0.1:8888\nexample.com enable://internalProxy\n",
    ] {
        let t = target(rules, "https://example.com/");
        assert!(!t.tls, "the hop should carry plaintext: {rules}");
        assert!(
            t.origin_tls_stripped,
            "…and say so with the marker: {rules}"
        );
    }

    // An http origin has no TLS to strip, so the property changes nothing.
    let t = target(
        "example.com proxy://127.0.0.1:8888 lineProps://internalProxy\n",
        "http://example.com/",
    );
    assert!(!t.tls);
    assert!(!t.origin_tls_stripped);

    // The property belongs to the hop: with no proxy there is nothing to
    // hand the request to, and an https origin stays https.
    let t = target(
        "example.com host://10.0.0.9 lineProps://internalProxy\n",
        "https://example.com/",
    );
    assert!(t.tls, "no hop, no conversion");
    assert!(!t.origin_tls_stripped);
}

/// Every protocol in the family list is one `find_proxy` actually reads,
/// with the transport its name implies. The list lives in the rules layer
/// (it is what `ignore://proxy` means); this is the check that the two
/// halves cannot drift apart.
#[test]
fn every_family_protocol_resolves_with_its_transport() {
    for proto in crate::rules::protocols::UPSTREAM_PROXY_PROTOCOLS {
        let t = target(
            &format!("example.com {proto}://127.0.0.1:8888\n"),
            "http://example.com/",
        );
        let p = t.proxy.unwrap_or_else(|| panic!("{proto}:// must resolve"));
        assert_eq!(p.kind, proxy_kind(proto), "transport for {proto}");
        assert_eq!(p.port, 8888);
    }
}

// ── weakRule ──

/// `weakRule` on a local-file line makes it yield to a matching proxy or
/// host rule (`filterWeakRule`, `_original/lib/util/index.js:3731`).
#[test]
fn weak_rule_yields_to_proxy_or_host() {
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    for rules in [
        "a.com file:///no/such/file lineProps://weakRule\na.com proxy://127.0.0.1:8888\n",
        "a.com file:///no/such/file lineProps://weakRule\na.com host://1.2.3.4\n",
        "a.com file:///no/such/file\na.com host://1.2.3.4\na.com enable://weakRule\n",
    ] {
        let r = resolve(rules, "http://a.com/");
        assert!(
            short_circuit(&info, &r, test_env(), None).is_none(),
            "the file rule should step aside: {rules}"
        );
    }
}

/// Without something to yield *to*, the file rule still answers — including
/// when the only proxy rule is `proxyHostOnly` with no host rule to apply.
#[test]
fn weak_rule_keeps_the_file_when_nothing_outranks_it() {
    let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
    for rules in [
        "a.com file:///no/such/file lineProps://weakRule\n",
        "a.com file:///no/such/file lineProps://weakRule\na.com proxy://127.0.0.1:8888 lineProps://proxyHostOnly\n",
        // No weakRule: the file rule wins over the proxy as usual.
        "a.com file:///no/such/file\na.com proxy://127.0.0.1:8888\n",
    ] {
        let r = resolve(rules, "http://a.com/");
        assert!(
            short_circuit(&info, &r, test_env(), None).is_some(),
            "the file rule should answer: {rules}"
        );
    }
}

// ── safeHtml / strictHtml injection gating ──

/// Body after applying the response operators of `rules` to `body`, served
/// as `content_type`.
fn inject(rules: &str, body: &'static str, content_type: &str) -> String {
    let resolved = resolve(rules, "http://example.com/x");
    let out = transform_res_body(
        Bytes::from_static(body.as_bytes()),
        &resolved,
        Some(content_type),
    );
    String::from_utf8(out.to_vec()).unwrap()
}

const HTML: &str = "text/html; charset=utf-8";

/// Markup accepts injection whatever the line says — the decision is made
/// from the body's first non-whitespace byte.
#[test]
fn injection_into_markup_always_allowed() {
    for props in ["", " lineProps://safeHtml", " lineProps://strictHtml"] {
        let rules = format!("example.com/x htmlAppend://<!--tail-->{props}\n");
        assert_eq!(
            inject(&rules, "<html></html>", HTML),
            "<html></html><!--tail-->",
            "markup should accept injection with{props:?}"
        );
    }
}

/// `safeHtml` refuses a JSON-looking body; `strictHtml` refuses anything
/// that is not markup (`_original/lib/util/whistle-transform.js:78-100`).
#[test]
fn safe_and_strict_html_refuse_non_markup() {
    let json = "{\"a\":1}";
    assert_eq!(
        inject("example.com/x htmlAppend://<!--t-->\n", json, HTML),
        "{\"a\":1}<!--t-->",
        "an unguarded line still injects into JSON"
    );
    assert_eq!(
        inject(
            "example.com/x htmlAppend://<!--t--> lineProps://safeHtml\n",
            json,
            HTML
        ),
        json
    );
    assert_eq!(
        inject(
            "example.com/x htmlAppend://<!--t--> lineProps://strictHtml\n",
            json,
            HTML
        ),
        json
    );
    // Bare text is "safe" but not markup: only strictHtml refuses it.
    assert_eq!(
        inject(
            "example.com/x htmlAppend://<!--t--> lineProps://safeHtml\n",
            "hello",
            HTML
        ),
        "hello<!--t-->"
    );
    assert_eq!(
        inject(
            "example.com/x htmlAppend://<!--t--> lineProps://strictHtml\n",
            "hello",
            HTML
        ),
        "hello"
    );
}

/// The gate is per line: a guarded line is dropped while an unguarded one
/// on the same request still injects.
#[test]
fn gating_is_per_line() {
    let out = inject(
        "example.com/x htmlAppend://<!--guarded--> lineProps://safeHtml\n\
             example.com/x htmlPrepend://<!--free--> disable://doctype\n",
        "{\"a\":1}",
        HTML,
    );
    assert_eq!(out, "<!--free-->{\"a\":1}");
}

/// Non-HTML responses are not gated at all: upstream's `allowInject`
/// returns before it ever looks at the properties.
#[test]
fn gating_only_applies_to_html_responses() {
    let out = inject(
        "example.com/x resAppend:///*t*/ lineProps://strictHtml\n",
        "{\"a\":1}",
        "application/json",
    );
    assert_eq!(out, "{\"a\":1}/*t*/");
}

/// The generic body operators are gated too — upstream filters
/// `resBody`/`resPrepend`/`resAppend` through the same list.
#[test]
fn generic_body_operators_are_gated() {
    assert_eq!(
        inject(
            "example.com/x resPrepend://<!--p--> lineProps://strictHtml\n",
            "plain text",
            HTML
        ),
        "plain text"
    );
    assert_eq!(
        inject(
            "example.com/x resBody://replaced lineProps://safeHtml\n",
            "[1,2]",
            HTML
        ),
        "[1,2]",
        "safeHtml must keep a JSON body rather than replace it"
    );
}

/// `enable://strictHtml` applies the strict gate to every line of the
/// request (`_original/lib/inspectors/res.js:966-982`).
#[test]
fn enable_strict_html_gates_every_line() {
    let out = inject(
        "example.com/x htmlAppend://<!--t-->\nexample.com/x enable://strictHtml\n",
        "hello",
        HTML,
    );
    assert_eq!(out, "hello");
}

// ── typed body operators (html/js/css) ──

/// `jsXxx`/`cssXxx` reach an **HTML** response too, not just a JS or CSS
/// one: `isJs = isHtml || resType === 'JS'`
/// (`_original/lib/inspectors/res.js:952-954`). Raw JavaScript cannot go
/// into markup as-is, so it arrives wrapped.
#[test]
fn js_and_css_operators_reach_html_responses() {
    let out = inject(
        "example.com/x jsAppend://alert(1) disable://doctype\n",
        "<p>hi</p>",
        HTML,
    );
    assert_eq!(out, "<p>hi</p><script>alert(1)</script>");

    let out = inject(
        "example.com/x cssPrepend://body{color:red} disable://doctype\n",
        "<p>hi</p>",
        HTML,
    );
    assert_eq!(out, "<style>body{color:red}</style><p>hi</p>");
}

/// A bare URL is linked rather than inlined (`GEN_URL_RE` → `wrapJs`/`wrapCss`).
#[test]
fn a_url_value_becomes_a_script_or_link_tag() {
    let out = inject(
        "example.com/x jsAppend://https://cdn.test/a.js disable://doctype\n",
        "<p>hi</p>",
        HTML,
    );
    assert_eq!(
        out,
        "<p>hi</p><script src=\"https://cdn.test/a.js\"></script>"
    );

    let out = inject(
        "example.com/x cssAppend:////cdn.test/a.css disable://doctype\n",
        "<p>hi</p>",
        HTML,
    );
    assert_eq!(
        out,
        "<p>hi</p><link rel=\"stylesheet\" href=\"//cdn.test/a.css\" />"
    );
    // Not a URL: an inline script that merely starts with a comment.
    assert!(!GEN_URL_RE.is_match("// just a comment"));
}

/// Line properties become `<script>` attributes (`getScriptProps`).
#[test]
fn line_props_become_script_attributes() {
    let out = inject(
        "example.com/x jsAppend://https://cdn.test/a.js lineProps://defer|module|anonymous disable://doctype\n",
        "<p>hi</p>",
        HTML,
    );
    assert_eq!(
        out,
        "<p>hi</p><script crossorigin=\"anonymous\" defer type=\"module\" src=\"https://cdn.test/a.js\"></script>"
    );
    assert_eq!(script_props(&LineProps::default()), "");
    // The crossorigin spellings are exclusive, most specific first.
    let props = LineProps::from_actions(["useCredentials", "anonymous", "crossorigin"]);
    assert_eq!(script_props(&props), " crossorigin=\"use-credentials\"");
}

/// On a JS or CSS response the value goes in raw — there is no markup to
/// wrap it into — and the generic `res*` operator comes first, CRLF-joined.
#[test]
fn typed_operators_are_unwrapped_outside_html() {
    let out = inject(
        "example.com/x jsAppend://alert(1)\nexample.com/x resAppend:///*tail*/\n",
        "var a;",
        "application/javascript",
    );
    assert_eq!(out, "var a;/*tail*/\r\nalert(1)");
    // A CSS response ignores the JS family entirely.
    let out = inject(
        "example.com/x jsAppend://alert(1)\nexample.com/x cssAppend://a{}\n",
        "b{}",
        "text/css",
    );
    assert_eq!(out, "b{}a{}");
}

/// Every slot orders its contributors `res*` → `css*` → `html*` → `js*`
/// (`_original/lib/inspectors/res.js:1063-1072`), joined with CRLF.
#[test]
fn html_slots_keep_the_upstream_family_order() {
    let out = inject(
        "example.com/x resAppend://R\nexample.com/x cssAppend://C\n\
             example.com/x htmlAppend://H\nexample.com/x jsAppend://J\n\
             example.com/x disable://doctype\n",
        "<p></p>",
        HTML,
    );
    assert_eq!(
        out,
        "<p></p>R\r\n<style>C</style>\r\nH\r\n<script>J</script>"
    );
}

/// A `*Body` operator replaces the body while `top`/`bottom` still wrap it.
#[test]
fn body_operators_replace_and_stay_wrapped() {
    let out = inject(
        "example.com/x htmlBody://<b>new</b>\nexample.com/x resPrepend://<!--t-->\n\
             example.com/x resAppend://<!--b-->\nexample.com/x disable://doctype\n",
        "<p>old</p>",
        HTML,
    );
    assert_eq!(out, "<!--t--><b>new</b><!--b-->");
    // A blank `resBody` is not an empty body: `util.EMPTY_BUFFER` is
    // `undefined`, so upstream builds no transform. See `Joined::claims_body`.
    assert_eq!(
        inject("example.com/x resBody://\n", "keep?", "text/plain"),
        "keep?"
    );
}

/// An injecting operator written with **no value** does nothing at all —
/// neither to the body nor to the headers that come with an injection.
///
/// Both halves were wrong here. `resBody://()` emptied the response, because
/// this port read `util.EMPTY_BUFFER` as an empty buffer when it is
/// `undefined` (`toBuffer('')`, `_original/lib/util/common.js:1630-1632`);
/// and every blank operator still stripped the page's CSP and marked it
/// `no-store`, because the gate asked whether the operator *matched* rather
/// than whether it produced anything (`res.js:1093`). Measured against
/// whistle 2.10.8: `resBody://()`, `htmlBody://()` and `resPrepend://()` each
/// return the origin's page with its `Cache-Control` and CSP intact.
#[test]
fn an_operator_written_with_no_value_leaves_the_response_alone() {
    for rule in [
        "resBody://()",
        "resBody://",
        "htmlBody://()",
        "resPrepend://()",
    ] {
        assert_eq!(
            inject(&format!("example.com/x {rule}\n"), "<p>keep</p>", HTML),
            "<p>keep</p>",
            "{rule} must not touch the body"
        );

        let (info, resolved) =
            resolve_with_info(&format!("example.com/x {rule}\n"), "http://example.com/x");
        let mut parts = hyper::Response::new(()).into_parts().0;
        parts
            .headers
            .insert(hyper::header::CONTENT_TYPE, HTML.parse().unwrap());
        parts
            .headers
            .insert("cache-control", "max-age=600".parse().unwrap());
        parts.headers.insert(
            "content-security-policy",
            "default-src 'self'".parse().unwrap(),
        );
        apply_response_for(&mut parts, &resolved, Some(&info));
        assert_eq!(
            parts.headers.get("cache-control").unwrap(),
            "max-age=600",
            "{rule} must not bust the cache"
        );
        assert!(
            parts.headers.contains_key("content-security-policy"),
            "{rule} must not strip the CSP"
        );
    }

    // The same operators with a value do all of it, which is the point.
    let (info, resolved) = resolve_with_info(
        "example.com/x resPrepend://(<!--t-->)\n",
        "http://example.com/x",
    );
    let mut parts = hyper::Response::new(()).into_parts().0;
    parts
        .headers
        .insert(hyper::header::CONTENT_TYPE, HTML.parse().unwrap());
    parts.headers.insert(
        "content-security-policy",
        "default-src 'self'".parse().unwrap(),
    );
    apply_response_for(&mut parts, &resolved, Some(&info));
    assert!(!parts.headers.contains_key("content-security-policy"));
    assert_eq!(parts.headers.get("cache-control").unwrap(), "no-store");
}

/// whistle stamps a doctype in front of any `top` it injects into an HTML
/// response (`_original/lib/util/whistle-transform.js:116-118`), and
/// `disable://doctype` is the only way out.
#[test]
fn html_prepends_carry_a_doctype() {
    assert_eq!(
        inject("example.com/x resPrepend://<!--t-->\n", "<p></p>", HTML),
        "<!DOCTYPE html>\r\n<!--t--><p></p>"
    );
    assert_eq!(
        inject(
            "example.com/x resPrepend://<!--t--> disable://doctype\n",
            "<p></p>",
            HTML
        ),
        "<!--t--><p></p>"
    );
    // `enable://` wins over `disable://` for the same flag (`isDisable`).
    assert_eq!(
        inject(
            "example.com/x resPrepend://<!--t--> disable://doctype enable://doctype\n",
            "<p></p>",
            HTML
        ),
        "<!DOCTYPE html>\r\n<!--t--><p></p>"
    );
    // Only HTML, and only when something is actually prepended.
    assert_eq!(
        inject("example.com/x resAppend://<!--t-->\n", "<p></p>", HTML),
        "<p></p><!--t-->"
    );
    assert_eq!(
        inject("example.com/x resPrepend://x\n", "y", "text/plain"),
        "xy"
    );
}

// ── multi-match body operators ──
//
// Every operator below is in upstream's `multiMatchs`
// (`_original/lib/rules/protocols.js:186-226`), so several lines of the same
// one all take effect. How they combine differs per family, and each test
// names the mechanism it covers.

/// The injecting operators CRLF-join their lines in resolution order
/// (`joinData`, `_original/lib/util/file-mgr.js:93-109`).
#[test]
fn several_injection_lines_are_crlf_joined() {
    assert_eq!(
        inject(
            "example.com/x resAppend://one\nexample.com/x resAppend://two\n",
            "body",
            "text/plain",
        ),
        "bodyone\r\ntwo"
    );
    assert_eq!(
        inject(
            "example.com/x resPrepend://one\nexample.com/x resPrepend://two\n\
                 example.com/x disable://doctype\n",
            "body",
            "text/plain",
        ),
        "one\r\ntwobody"
    );
    // `*Body` replaces once, with the join of every line.
    assert_eq!(
        inject(
            "example.com/x resBody://one\nexample.com/x resBody://two\n",
            "gone",
            "text/plain",
        ),
        "one\r\ntwo"
    );
}

/// Each line of a typed family is wrapped on its own before the join, so two
/// `jsAppend://` lines are two `<script>` tags rather than one holding both
/// (`readRuleList` wraps per list entry, `_original/lib/util/index.js:955-966`).
#[test]
fn several_typed_lines_are_wrapped_separately() {
    assert_eq!(
        inject(
            "example.com/x jsAppend://a()\nexample.com/x jsAppend://b()\n",
            "<p></p>",
            HTML,
        ),
        "<p></p><script>a()</script>\r\n<script>b()</script>"
    );
    // …and each keeps the attributes of *its own* line.
    assert_eq!(
        inject(
            "example.com/x jsAppend://https://a.test/a.js lineProps://defer\n\
                 example.com/x jsAppend://https://b.test/b.js lineProps://module\n",
            "<p></p>",
            HTML,
        ),
        "<p></p><script defer src=\"https://a.test/a.js\"></script>\r\n\
             <script type=\"module\" src=\"https://b.test/b.js\"></script>"
    );
}

/// Accumulation follows the matcher's order, so an `important` line leads
/// even when it is written last.
#[test]
fn important_lines_lead_the_accumulation() {
    assert_eq!(
        inject(
            "example.com/x resAppend://normal\n\
                 example.com/x resAppend://important lineProps://important\n",
            "body",
            "text/plain",
        ),
        "bodyimportant\r\nnormal"
    );
    // The same order decides who wins a contested `*Replace` pattern.
    let out = transform_res_body(
        Bytes::from_static(b"x"),
        &resolve(
            "example.com/x resReplace://x=normal\n\
                 example.com/x resReplace://x=important lineProps://important\n",
            "http://example.com/x",
        ),
        Some("text/plain"),
    );
    assert_eq!(out, Bytes::from_static(b"important"));
}

/// `*Replace` lines collapse into one pattern map rather than running as
/// separate passes: every pattern applies, and a pattern written twice takes
/// the first line's replacement (`readRuleList`'s JSON branch reverses the
/// list and `extend`s it, `_original/lib/util/index.js:1300-1312`).
#[test]
fn several_replace_lines_merge_into_one_map() {
    let replace = |rules: &str, body: &'static str| {
        String::from_utf8(
            transform_res_body(
                Bytes::from_static(body.as_bytes()),
                &resolve(rules, "http://example.com/x"),
                Some("text/plain"),
            )
            .to_vec(),
        )
        .unwrap()
    };
    assert_eq!(
        replace(
            "example.com/x resReplace://a=1\nexample.com/x resReplace://b=2\n",
            "a b",
        ),
        "1 2"
    );
    // Contested pattern: the higher-priority line's replacement wins.
    assert_eq!(
        replace(
            "example.com/x resReplace://a=first\nexample.com/x resReplace://a=second\n",
            "a",
        ),
        "first"
    );
    // Substitutions still chain, and the *last* line's patterns run first —
    // upstream's merged key order. Here `x`→`y` (line two) runs before
    // `y`→`z` (line one), so the body ends up fully rewritten.
    assert_eq!(
        replace(
            "example.com/x resReplace://y=z\nexample.com/x resReplace://x=y\n",
            "x",
        ),
        "z"
    );
}

/// `resMerge` lines collapse into one patch the same way — first line wins a
/// contested key — and the fold is shallow unless a `resMerge://true` marker
/// line turns on `extend`'s deep flag (`isDeep`,
/// `_original/lib/util/index.js:1206-1212`).
#[test]
fn several_merge_lines_collapse_into_one_patch() {
    let merge = |rules: &str| {
        String::from_utf8(
            transform_res_body(
                Bytes::from_static(b"{\"keep\":0}"),
                &resolve(rules, "http://example.com/x"),
                Some("application/json"),
            )
            .to_vec(),
        )
        .unwrap()
    };
    // Disjoint keys from both lines land, and the body's own key survives.
    // The order is the body's keys first, then the patch's in fold order —
    // `extend` assigns onto a JavaScript object, which keeps what it was
    // given in the order it was given it. Byte-identical to whistle 2.10.8.
    assert_eq!(
        merge("example.com/x resMerge://{\"a\":1}\nexample.com/x resMerge://{\"b\":2}\n"),
        "{\"keep\":0,\"b\":2,\"a\":1}"
    );
    // Contested key: the first line wins.
    assert_eq!(
        merge("example.com/x resMerge://{\"a\":1}\nexample.com/x resMerge://{\"a\":2}\n"),
        "{\"keep\":0,\"a\":1}"
    );
    // Shallow by default, so the second line's nested object is replaced
    // wholesale rather than merged into.
    assert_eq!(
        merge(
            "example.com/x resMerge://{\"n\":{\"a\":1}}\n\
                 example.com/x resMerge://{\"n\":{\"b\":2}}\n"
        ),
        "{\"keep\":0,\"n\":{\"a\":1}}"
    );
    // …unless a marker line asks for a deep fold. It contributes no data.
    assert_eq!(
        merge(
            "example.com/x resMerge://{\"n\":{\"a\":1}}\n\
                 example.com/x resMerge://{\"n\":{\"b\":2}}\n\
                 example.com/x resMerge://true\n"
        ),
        // The fold's target is the *last* line, so its keys come first.
        "{\"keep\":0,\"n\":{\"b\":2,\"a\":1}}"
    );
}

/// A page that declares a charset reaches the text operators as text, and
/// goes back out in the charset it declared.
///
/// Before this the substitution ran over the raw GBK bytes, `String::from_utf8`
/// refused them, and `resReplace://` on a `charset=gbk` page did nothing at
/// all — silently, on exactly the pages whistle is most used to debug.
/// Byte-identical to whistle 2.10.8 through the differential bench.
#[test]
fn a_declared_charset_is_undone_for_the_text_operators_and_put_back_after() {
    // `<html><body>中文 ORIGINAL</body></html>`, the two CJK glyphs in GBK.
    let page = |tail: &[u8]| {
        let mut v = b"<html><body>\xd6\xd0\xce\xc4 ".to_vec();
        v.extend_from_slice(tail);
        v
    };
    let gbk = "text/html; charset=gbk";
    let run = |rules: &str, ct: &str| {
        transform_res_body(
            Bytes::from(page(b"ORIGINAL</body></html>")),
            &resolve(rules, "http://example.com/x"),
            Some(ct),
        )
    };

    // An ASCII pattern now matches, and the page's own GBK bytes survive.
    assert_eq!(
        &run("example.com/x resReplace://ORIGINAL=REWRITTEN", gbk)[..],
        &page(b"REWRITTEN</body></html>")[..]
    );
    // A replacement written in the rules file — UTF-8 — lands as GBK.
    assert_eq!(
        &run("example.com/x resReplace://ORIGINAL=中文", gbk)[..],
        &page(b"\xd6\xd0\xce\xc4</body></html>")[..]
    );
    // An undeclared charset is left alone: guessing is upstream's answer,
    // not this port's. See `docs/RULES.md`.
    assert_eq!(
        &run("example.com/x resReplace://ORIGINAL=REWRITTEN", "text/html")[..],
        &page(b"ORIGINAL</body></html>")[..]
    );
}

/// An injected value is written in the page's own charset, not pasted in as
/// UTF-8 for the browser to render as mojibake.
#[test]
fn an_injected_value_is_encoded_into_the_pages_charset() {
    let inject = |rules: &str, ct: &str| {
        transform_res_body(
            Bytes::from_static(b"<html><body>x</body></html>"),
            &resolve(rules, "http://example.com/x"),
            Some(ct),
        )
    };
    let gbk = "text/html; charset=gbk";

    assert!(
        inject("example.com/x htmlAppend://<i>中文</i>", gbk).ends_with(b"<i>\xd6\xd0\xce\xc4</i>"),
        "htmlAppend must land as GBK"
    );
    // The `js`/`css` families are wrapped first, then encoded whole.
    assert!(
        inject("example.com/x jsAppend://alert('中文')", gbk)
            .ends_with(b"<script>alert('\xd6\xd0\xce\xc4')</script>"),
        "the wrapper and its content are one piece"
    );
    // `resBody://` replaces the body outright, and in the page's charset.
    assert_eq!(
        &inject("example.com/x resBody://中文", gbk)[..],
        b"\xd6\xd0\xce\xc4"
    );
    // With no charset declared, the value stays UTF-8 — as upstream's does.
    assert!(
        inject("example.com/x htmlAppend://<i>中文</i>", "text/html")
            .ends_with("<i>中文</i>".as_bytes())
    );
}

/// A merged body keeps the order the origin wrote its keys in, with the
/// patch's new ones appended.
///
/// `JSON.stringify` walks a JavaScript object in insertion order, so this is
/// what upstream emits; `serde_json::Map` is a `BTreeMap` unless the
/// `preserve_order` feature is on, and without it every JSON body this proxy
/// touched came back alphabetised. Measured against whistle 2.10.8 through
/// the differential bench: `{"a":1,"keep":"yes","extra":1}` there against
/// `{"a":1,"extra":1,"keep":"yes"}` here.
#[test]
fn a_merged_body_keeps_the_key_order_the_origin_sent() {
    let merged = transform_res_body(
        Bytes::from_static(b"{\"a\":1,\"keep\":\"yes\"}"),
        &resolve(
            "example.com/x resMerge://{\"extra\":1}",
            "http://example.com/x",
        ),
        Some("application/json"),
    );
    assert_eq!(&merged[..], br#"{"a":1,"keep":"yes","extra":1}"#);

    // The same for a property removal, which re-serialises the body too.
    let pruned = transform_res_body(
        Bytes::from_static(b"{\"z\":1,\"m\":2,\"a\":3}"),
        &resolve("example.com/x delete://resBody.m", "http://example.com/x"),
        Some("application/json"),
    );
    assert_eq!(&pruned[..], br#"{"z":1,"a":3}"#);
}

/// `urlReplace` merges its lines into one map like the body `*Replace`
/// operators, then `parsePathReplace` walks it
/// (`_original/lib/util/index.js:1014-1022`).
#[test]
fn several_url_replace_lines_rewrite_one_path() {
    let resolved = resolve(
        "example.com/api urlReplace://v1=v2\nexample.com/api urlReplace://old=new\n",
        "http://example.com/api/v1/old",
    );
    assert_eq!(
        rewrite_path("/api/v1/old", &resolved, body_ctx(None)),
        "/api/v2/new"
    );
}

/// `delete://` also names query parameters and path segments
/// (`parseDelQuery`, `_original/lib/util/index.js:2674-2699`, applied by
/// `deleteQuery` and `parsePathReplace`'s `delPaths` arm at
/// `req.js:557,562-570`).
///
/// None of these keys were parsed anywhere in this port, so every one of
/// them was a rule that resolved, matched, and did nothing — the shape of
/// bug you debug by rereading your own rules file.
///
/// The expectations are upstream's own output: `parseDelQuery`,
/// `parsePathReplace` and `deleteQuery` were lifted verbatim and run over
/// these inputs, which is why the odd ones are here — `pathname.last` leaves
/// a trailing slash where `pathname.-1` does not, and `pathname.LAST`
/// matches the pattern and then does nothing at all.
#[test]
fn delete_names_query_parameters_and_path_segments() {
    let out = |rule: &str, path: &str| {
        let resolved = resolve(
            &format!("example.com {rule}\n"),
            &format!("http://example.com{path}"),
        );
        rewrite_path(path, &resolved, body_ctx(None))
    };

    // ── query parameters ──
    assert_eq!(out("delete://query.a", "/p?a=1&b=2"), "/p?b=2");
    // Every spelling `QUERY_RE` takes, and it is case-insensitive.
    for spelling in [
        "query",
        "params",
        "urlParams",
        "urlParam",
        "url.Param",
        "url.Params",
        "QUERY",
    ] {
        assert_eq!(
            out(&format!("delete://{spelling}.a"), "/p?a=1&b=2"),
            "/p?b=2",
            "{spelling}"
        );
    }
    // Repeats of a named parameter all go.
    assert_eq!(out("delete://query.a", "/p?a=1&a=2&b=3"), "/p?b=3");
    // The `?` goes with the last surviving pair.
    assert_eq!(out("delete://query.a|query.b", "/p?a=1&b=2"), "/p");
    // A valueless pair is named by the bare token.
    assert_eq!(out("delete://query.a", "/p?a"), "/p");
    // Nothing to delete from.
    assert_eq!(out("delete://query.a", "/p"), "/p");
    // An empty query string is left exactly as it is — upstream returns
    // before it can drop the `?`.
    assert_eq!(out("delete://query.a", "/p?"), "/p?");
    // The bare form clears the whole query string, `?` and all…
    assert_eq!(out("delete://query", "/p?a=1&b=2"), "/p");
    assert_eq!(out("delete://urlparams", "/p?a=1&b=2"), "/p");
    // …and that one *does* drop a lone `?`.
    assert_eq!(out("delete://query", "/p?"), "/p");
    // A key with nothing after the dot matches neither pattern.
    assert_eq!(out("delete://query.", "/p?a=1"), "/p?a=1");

    // ── path segments ──
    assert_eq!(out("delete://pathname.0", "/a/b/c"), "/b/c");
    assert_eq!(out("delete://pathname.first", "/a/b/c"), "/b/c");
    // `last` leaves a trailing slash behind; `-1` names the same segment
    // and does not.
    assert_eq!(out("delete://pathname.last", "/a/b/c"), "/a/b/");
    assert_eq!(out("delete://pathname.-1", "/a/b/c"), "/a/b");
    assert_eq!(out("delete://pathname.-2", "/a/b/c"), "/a/c");
    // A path already ending in `/` has an empty last segment, so `last`
    // removes that and the slash is put straight back.
    assert_eq!(out("delete://pathname.last", "/a/b/c/"), "/a/b/c/");
    // Several indices are counted against the *original* path.
    assert_eq!(out("delete://pathname.1|pathname.2", "/a/b/c/d"), "/a/d");
    // Out of range is a no-op, either way round.
    assert_eq!(out("delete://pathname.99", "/a/b"), "/a/b");
    assert_eq!(out("delete://pathname.-9", "/a/b/c"), "/a/b/c");
    // The dot is optional, and `pathname` is case-insensitive.
    assert_eq!(out("delete://pathname-1", "/a/b/c"), "/a/b");
    assert_eq!(out("delete://pathname0", "/a/b/c"), "/b/c");
    assert_eq!(out("delete://pathnamelast", "/a/b/c"), "/a/b/");
    assert_eq!(out("delete://PATHNAME", "/a/b/c"), "/");
    // …but `first`/`last` are not: the key matches and then evaporates.
    assert_eq!(out("delete://pathname.LAST", "/a/b/c"), "/a/b/c");
    assert_eq!(out("delete://pathname.First", "/a/b/c"), "/a/b/c");
    // `all` is not one of the words the pattern accepts.
    assert_eq!(out("delete://pathname.all", "/a/b/c"), "/a/b/c");
    // A `+` is not one of the shapes `-?\d+` accepts.
    assert_eq!(out("delete://pathname.+1", "/a/b/c"), "/a/b/c");
    // The bare form drops the path and keeps the query — and beats an index
    // named on the same line.
    assert_eq!(out("delete://pathname", "/a/b/c"), "/");
    assert_eq!(out("delete://pathname|pathname.0", "/a/b/c"), "/");
    // Deliberate divergence: upstream emits the query twice here
    // (`/?x=1?x=1`), which is a request line no origin parses.
    assert_eq!(out("delete://pathname", "/a/b/c?x=1"), "/?x=1");
    // Nothing but a query string has no segment to name.
    assert_eq!(out("delete://pathname", "/?x=1"), "/?x=1");
    assert_eq!(out("delete://pathname.last", "/a?x=1"), "/?x=1");

    // ── together, and against the operators they run beside ──
    assert_eq!(
        out("delete://pathname.last|query.a", "/a/b?a=1&b=2"),
        "/a/?b=2"
    );
    // `deleteQuery` runs after `params://`, so it wins over a parameter the
    // same line had just written (`req.js:568-570`).
    assert_eq!(out("params://a=9 delete://query.a", "/p?b=2"), "/p?b=2");
    // …and the path deletion runs with `urlReplace://`, over its output.
    assert_eq!(
        out("urlReplace://b=x delete://pathname.-1", "/a/b/c"),
        "/a/x"
    );
}

/// The request side accumulates through the same code path.
#[test]
fn several_request_body_lines_accumulate() {
    let resolved = resolve(
        "example.com reqPrepend://p1\nexample.com reqPrepend://p2\n\
             example.com reqAppend://a1\nexample.com reqAppend://a2\n",
        "http://example.com/",
    );
    let out = transform_req_body(
        Bytes::from_static(b"BODY"),
        &resolved,
        body_ctx(Some("text/plain")),
    );
    assert_eq!(out, Bytes::from_static(b"p1\r\np2BODYa1\r\na2"));
}

/// A blank line inside an accumulating operator is dropped before the join —
/// it must not leave a stray separator behind — and a `*Body` that is blank
/// on *every* line leaves the origin's body where it is.
#[test]
fn blank_lines_drop_out_of_the_join() {
    assert_eq!(
        inject(
            "example.com/x resAppend://one\nexample.com/x resAppend://\n",
            "body",
            "text/plain",
        ),
        "bodyone"
    );
    assert_eq!(
        inject(
            "example.com/x resBody://\nexample.com/x resBody://kept\n",
            "gone",
            "text/plain",
        ),
        "kept"
    );
    assert_eq!(
        inject(
            "example.com/x resBody://\nexample.com/x resBody://\n",
            "gone",
            "text/plain",
        ),
        "gone"
    );
}

/// The injection gate is per line, so one refused line does not take the
/// others down with it (`filterHtml` walks the buffer list,
/// `_original/lib/util/whistle-transform.js:47-60`). The refused line is
/// written first here, where a first-match-wins resolution would have let it
/// silence the whole operator.
#[test]
fn the_gate_refuses_accumulated_lines_one_by_one() {
    assert_eq!(
        inject(
            "example.com/x htmlAppend://<!--refused--> lineProps://strictHtml\n\
                 example.com/x htmlAppend://<!--kept-->\n",
            "{\"json\":1}",
            HTML,
        ),
        "{\"json\":1}<!--kept-->"
    );
    // A `resBody` whose every line the gate refuses leaves the body alone,
    // where a blank one would have emptied it (`filterHtml` reduces the list
    // to the falsy `''`, `whistle-transform.js:110`).
    assert_eq!(
        inject(
            "example.com/x resBody://gone lineProps://strictHtml\n",
            "{\"json\":1}",
            HTML,
        ),
        "{\"json\":1}"
    );
    // A request-wide `enable://strictHtml` shuts the injection off wholesale
    // (`allowInject` returns false).
    assert_eq!(
        inject(
            "example.com/x resBody:// enable://strictHtml\n",
            "{\"json\":1}",
            HTML,
        ),
        "{\"json\":1}"
    );
    // And a blank line is inert with or without the gate: an empty value is
    // not an empty body.
    assert_eq!(
        inject("example.com/x resBody://\n", "{\"json\":1}", HTML),
        "{\"json\":1}"
    );
}

/// The content classes, in upstream's test order.
#[test]
fn content_classes_match_upstream() {
    assert_eq!(res_class("text/html; charset=utf-8"), Some(ResClass::Html));
    assert_eq!(res_class("application/javascript"), Some(ResClass::Js));
    assert_eq!(res_class("text/css"), Some(ResClass::Css));
    assert_eq!(res_class("application/json"), Some(ResClass::Json));
    assert_eq!(res_class("image/png"), Some(ResClass::Img));
    assert_eq!(res_class("text/plain"), Some(ResClass::Text));
    assert_eq!(res_class("application/octet-stream"), None);
    assert_eq!(res_class(""), None);
    // Parameters are stripped before the substring tests, so a filename in
    // the type cannot promote an opaque body to HTML.
    assert_eq!(res_class("application/octet-stream; name=a.html"), None);
    // `application/ecmascript` is not `javascript` to whistle.
    assert_eq!(res_class("application/ecmascript"), None);
}

/// Header operators take a `&`-separated list of pairs, like the other
/// JSON-shaped operators; `enable`/`disable` split on `|` and `&` only.
#[test]
fn header_and_flag_value_lists() {
    let resolved = resolve(
        "example.com resHeaders://x-a=1&x-b=2\nexample.com enable://p|q&r\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    apply_header_ops(&mut h, &resolved, "resHeaders");
    assert_eq!(h.get("x-a").unwrap(), "1");
    assert_eq!(h.get("x-b").unwrap(), "2");

    let flags = enabled_flags(&resolved);
    assert!(flags.contains("p") && flags.contains("q") && flags.contains("r"));
    // A comma is not a separator upstream, so it stays part of the name.
    let commas = resolve("example.com enable://p,q\n", "http://example.com/");
    assert!(enabled_flags(&commas).contains("p,q"));
}

/// Request parts for the operator tests below.
fn req_parts(headers: &[(&str, &str)]) -> request::Parts {
    let mut builder = hyper::Request::builder().uri("http://example.com/");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(()).unwrap().into_parts().0
}

/// Two lines naming the **same** header: the first one wins.
///
/// This is the `parseRuleJson` fold (`_original/lib/util/index.js:1305-1316`),
/// not a top-to-bottom apply — upstream reverses the list and `extend`s it,
/// so the highest-priority line's value survives, consistent with
/// first-match-wins everywhere else. Lines naming *different* headers all
/// contribute.
#[test]
fn contested_header_takes_the_first_line() {
    let resolved = resolve(
        "example.com resHeaders://x-a=first&x-only-1=1\n\
             example.com resHeaders://x-a=second&x-only-2=2\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    apply_header_ops(&mut h, &resolved, "resHeaders");
    assert_eq!(h.get("x-a").unwrap(), "first");
    assert_eq!(h.get("x-only-1").unwrap(), "1");
    assert_eq!(h.get("x-only-2").unwrap(), "2");

    // `important` reorders the lines, and the fold follows the resolution
    // order rather than the source order.
    let important = resolve(
        "example.com resHeaders://x-a=plain\n\
             example.com resHeaders://x-a=important lineProps://important\n",
        "http://example.com/",
    );
    let mut h = HeaderMap::new();
    apply_header_ops(&mut h, &important, "resHeaders");
    assert_eq!(h.get("x-a").unwrap(), "important");
}

/// The same fold reaches `reqHeaders`, `trailers`, and both cookie
/// operators — every protocol upstream hands to `parseRuleJson`
/// (`_original/lib/inspectors/req.js:459-468`, `res.js:845-855`).
#[test]
fn contested_key_takes_the_first_line_everywhere() {
    let resolved = resolve(
        "example.com reqHeaders://x-a=first  reqCookies://sid=first  trailers://x-t=first\n\
             example.com reqHeaders://x-a=second reqCookies://sid=second trailers://x-t=second\n",
        "http://example.com/",
    );
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &resolved);
    assert_eq!(parts.headers.get("x-a").unwrap(), "first");
    assert_eq!(parts.headers.get("cookie").unwrap(), "sid=first");
    assert_eq!(build_trailers(&resolved).get("x-t").unwrap(), "first");

    let res = resolve(
        "example.com resCookies://sid=first\nexample.com resCookies://sid=second\n",
        "http://example.com/",
    );
    let mut parts = res_parts(&[]);
    apply_response(&mut parts, &res);
    assert_eq!(parts.headers.get("set-cookie").unwrap(), "sid=first");
}

/// `resCors` folds too: the first line's `origin` wins, and a key only a
/// later line mentions still lands.
#[test]
fn contested_cors_key_takes_the_first_line() {
    let resolved = resolve(
        "example.com resCors://{\"origin\":\"http://a.test\"}\n\
             example.com resCors://origin=http://b.test&methods=GET\n",
        "http://example.com/",
    );
    let mut parts = res_parts(&[]);
    apply_response(&mut parts, &resolved);
    assert_eq!(
        parts.headers.get("access-control-allow-origin").unwrap(),
        "http://a.test"
    );
    assert_eq!(
        parts.headers.get("access-control-allow-methods").unwrap(),
        "GET"
    );
}

/// `reqCors` is `setReqCors` (`_original/lib/util/index.js:2899-2921`): a
/// URL origin is reduced to its origin, `*` passes through, and `method` /
/// `headers` become the preflight request headers. `enable` sets nothing —
/// there is no origin to echo on the request side.
#[test]
fn req_cors_sets_origin_and_preflight_headers() {
    let resolved = resolve(
        "example.com reqCors://http://a.test/page?q=1\n",
        "http://example.com/",
    );
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &resolved);
    assert_eq!(parts.headers.get("origin").unwrap(), "http://a.test");

    let star = resolve(
        "example.com reqCors://* reqCors://method=PUT&headers=x-a\n",
        "http://example.com/",
    );
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &star);
    assert_eq!(parts.headers.get("origin").unwrap(), "*");
    assert_eq!(
        parts.headers.get("access-control-request-method").unwrap(),
        "PUT"
    );
    assert_eq!(
        parts.headers.get("access-control-request-headers").unwrap(),
        "x-a"
    );

    // `enable` is the response-side spelling; on a request it is inert.
    let enable = resolve("example.com reqCors://enable\n", "http://example.com/");
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &enable);
    assert!(parts.headers.get("origin").is_none());
}

// ── response header operators ──

/// Response parts carrying `headers`, for the operator tests below.
fn res_parts(headers: &[(&str, &str)]) -> response::Parts {
    let mut builder = Response::builder().status(200);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(()).unwrap().into_parts().0
}

/// Header value after applying `rules` to a response carrying `headers`.
fn res_header(rules: &str, headers: &[(&str, &str)], name: &str) -> Option<String> {
    let resolved = resolve(rules, "http://example.com/x");
    let mut parts = res_parts(headers);
    apply_response(&mut parts, &resolved);
    parts
        .headers
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
}

/// `cache://` accepts a leading integer or one of three no-cache spellings,
/// and writes `Expires`/`Pragma` alongside `Cache-Control`. Anything else —
/// `cache://off`, say — is ignored rather than passed through.
#[test]
fn cache_operator_spellings() {
    let cc = |v: &str| res_header(&format!("example.com cache://{v}\n"), &[], "cache-control");
    assert_eq!(cc("600"), Some("max-age=600".to_string()));
    assert_eq!(
        cc("60s"),
        Some("max-age=60".to_string()),
        "parseInt semantics"
    );
    assert_eq!(cc("-1"), Some("no-cache".to_string()));
    assert_eq!(cc("no"), Some("no-cache".to_string()));
    assert_eq!(cc("No-Cache"), Some("no-cache".to_string()));
    assert_eq!(cc("no-store"), Some("no-store".to_string()));
    assert_eq!(cc("off"), None, "not a spelling whistle recognises");
    assert_eq!(cc("keep"), None);
    assert_eq!(cc("reserve"), None);
    // `keep`/`reserve` leave the upstream header where it was.
    assert_eq!(
        res_header(
            "example.com cache://keep\n",
            &[("cache-control", "max-age=5")],
            "cache-control"
        ),
        Some("max-age=5".to_string())
    );
    let resolved = resolve("example.com cache://no\n", "http://example.com/x");
    let mut parts = res_parts(&[]);
    apply_response(&mut parts, &resolved);
    assert_eq!(parts.headers.get("pragma").unwrap(), "no-cache");
    assert!(
        parts
            .headers
            .get("expires")
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(" GMT")
    );
}

/// Injecting into a body costs the response its CSP and its cacheability
/// (`_original/lib/inspectors/res.js:1093-1101`).
#[test]
fn injection_strips_csp_and_caching() {
    let html = [
        ("content-type", "text/html"),
        ("content-security-policy", "default-src 'self'"),
        ("cache-control", "max-age=600"),
    ];
    assert_eq!(
        res_header(
            "example.com jsAppend://alert(1)\n",
            &html,
            "content-security-policy"
        ),
        None,
        "an injected script must not be blocked by the page's own CSP"
    );
    assert_eq!(
        res_header("example.com jsAppend://alert(1)\n", &html, "cache-control"),
        Some("no-store".to_string())
    );
    // `enable://keepCSP` and `enable://keepCache` opt out of each.
    assert!(
        res_header(
            "example.com jsAppend://alert(1) enable://keepCSP|keepCache\n",
            &html,
            "content-security-policy"
        )
        .is_some()
    );
    assert_eq!(
        res_header(
            "example.com jsAppend://alert(1) enable://keepCache\n",
            &html,
            "cache-control"
        ),
        Some("max-age=600".to_string())
    );
    // An explicit `cache://` is the author's decision and survives.
    assert_eq!(
        res_header(
            "example.com jsAppend://alert(1) cache://60\n",
            &html,
            "cache-control"
        ),
        Some("max-age=60".to_string())
    );
    // No injecting operator for *this* content type: nothing is stripped.
    assert!(
        res_header(
            "example.com cssAppend://a{}\n",
            &[
                ("content-type", "application/javascript"),
                ("content-security-policy", "default-src 'self'")
            ],
            "content-security-policy"
        )
        .is_some()
    );
}

/// `weinre://` injects a `<script>` and so pays the same price
/// (`_original/lib/inspectors/weinre.js:37-38`). Before this the agent was
/// pushed into the page and then blocked by the page's own CSP.
#[test]
fn weinre_strips_csp_and_caching_too() {
    let html = [
        ("content-type", "text/html"),
        ("content-security-policy", "default-src 'self'"),
        ("cache-control", "max-age=600"),
    ];
    assert_eq!(
        res_header(
            "example.com weinre://mysession\n",
            &html,
            "content-security-policy"
        ),
        None
    );
    assert_eq!(
        res_header("example.com weinre://mysession\n", &html, "cache-control"),
        Some("no-store".to_string())
    );
    // Nothing is injected into a response that is not markup, so nothing is
    // stripped from one either.
    assert!(
        res_header(
            "example.com weinre://mysession\n",
            &[
                ("content-type", "application/json"),
                ("content-security-policy", "default-src 'self'")
            ],
            "content-security-policy"
        )
        .is_some()
    );
}

/// `attachment://` always names the file; with no value whistle falls back
/// to the request URL's last segment (`getFilename`).
#[test]
fn attachment_names_the_download() {
    assert_eq!(
        res_header(
            "example.com attachment://报告.pdf\n",
            &[],
            "content-disposition"
        ),
        Some("attachment; filename=\"%E6%8A%A5%E5%91%8A.pdf\"".to_string()),
        "a header value cannot carry non-Latin-1 bytes"
    );
    assert_eq!(encode_non_latin1("a b.pdf"), "a%20b.pdf");
    let resolved = resolve(
        "example.com attachment://\n",
        "http://example.com/d/report.csv",
    );
    let info = build_req_info(
        "GET",
        "http",
        "example.com",
        80,
        "/d/report.csv",
        &HeaderMap::new(),
        None,
    );
    let mut parts = res_parts(&[]);
    apply_response_for(&mut parts, &resolved, Some(&info));
    assert_eq!(
        parts.headers.get("content-disposition").unwrap(),
        "attachment; filename=\"report.csv\""
    );
    assert_eq!(url_filename("http://a.com/x/y.pdf?q=1"), "y.pdf");
    assert_eq!(url_filename("http://a.com/"), "index.html");
    assert_eq!(url_filename("http://a.com"), "index.html");
}

/// `replaceStatus://401` also advertises the challenge whistle sends with it.
#[test]
fn replace_status_advertises_authentication() {
    assert_eq!(
        res_header("example.com replaceStatus://401\n", &[], "www-authenticate"),
        Some("Basic realm=User Login".to_string())
    );
    assert_eq!(
        res_header(
            "example.com replaceStatus://407\n",
            &[],
            "proxy-authenticate"
        ),
        Some("Basic realm=User Login".to_string())
    );
}

/// `resCors` negotiates rather than blanket-allowing: an explicit origin or
/// `enable` implies credentials, `*` does not, and a preflight fills the
/// requested methods/headers in from the request.
#[test]
fn res_cors_negotiates() {
    let cors = |rule: &str, method: &str, req_headers: &[(&str, &str)], name: &str| {
        let resolved = resolve(
            &format!("example.com resCors://{rule}\n"),
            "http://example.com/x",
        );
        let mut hm = HeaderMap::new();
        for (k, v) in req_headers {
            hm.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let info = build_req_info(method, "http", "example.com", 80, "/x", &hm, None);
        let mut parts = res_parts(&[]);
        apply_response_for(&mut parts, &resolved, Some(&info));
        parts
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };

    // `*` allows any origin but never credentials.
    assert_eq!(
        cors("*", "GET", &[], "access-control-allow-origin"),
        Some("*".to_string())
    );
    assert_eq!(
        cors("*", "GET", &[], "access-control-allow-credentials"),
        None
    );

    // `enable` echoes the caller's origin, with credentials.
    let origin = [("origin", "https://app.test")];
    assert_eq!(
        cors("enable", "GET", &origin, "access-control-allow-origin"),
        Some("https://app.test".to_string())
    );
    assert_eq!(
        cors("enable", "GET", &origin, "access-control-allow-credentials"),
        Some("true".to_string())
    );
    // …and does nothing at all when the request carries no origin.
    assert_eq!(
        cors("enable", "GET", &[], "access-control-allow-origin"),
        None
    );

    // An explicit URL is trimmed to its origin.
    assert_eq!(
        cors(
            "https://app.test/some/path",
            "GET",
            &[],
            "access-control-allow-origin"
        ),
        Some("https://app.test".to_string())
    );

    // The JSON form spells the rest out; `headers` is *expose* off-preflight.
    let json = r#"{"methods":"GET,POST","headers":"x-a","maxAge":600}"#;
    assert_eq!(
        cors(json, "GET", &[], "access-control-allow-methods"),
        Some("GET,POST".to_string())
    );
    assert_eq!(
        cors(json, "GET", &[], "access-control-expose-headers"),
        Some("x-a".to_string())
    );
    assert_eq!(
        cors(json, "OPTIONS", &[], "access-control-allow-headers"),
        Some("x-a".to_string())
    );
    assert_eq!(
        cors(json, "GET", &[], "access-control-max-age"),
        Some("600".to_string())
    );

    // A preflight completes itself from the request's own asks.
    let preflight = [
        ("access-control-request-headers", "x-token"),
        ("access-control-request-method", "PUT"),
    ];
    assert_eq!(
        cors("*", "OPTIONS", &preflight, "access-control-allow-headers"),
        Some("x-token".to_string())
    );
    assert_eq!(
        cors("*", "OPTIONS", &preflight, "access-control-allow-methods"),
        Some("PUT".to_string()),
        "the header a browser actually reads, and the one upstream writes"
    );

    // The query-string form.
    assert_eq!(
        cors(
            "methods=GET&maxAge=30",
            "GET",
            &[],
            "access-control-max-age"
        ),
        Some("30".to_string())
    );
}

/// `enable://cors` is not an upstream flag; whistle-rs keeps it as an alias
/// for `resCors://enable` rather than as a blanket `*`.
#[test]
fn enable_cors_is_an_alias_for_res_cors_enable() {
    let resolved = resolve("example.com enable://cors\n", "http://example.com/x");
    let mut hm = HeaderMap::new();
    hm.insert("origin", "https://app.test".parse().unwrap());
    let info = build_req_info("GET", "http", "example.com", 80, "/x", &hm, None);
    let mut parts = res_parts(&[]);
    apply_response_for(&mut parts, &resolved, Some(&info));
    assert_eq!(
        parts.headers.get("access-control-allow-origin").unwrap(),
        "https://app.test"
    );
    // An explicit `resCors` wins over the alias.
    let resolved = resolve(
        "example.com enable://cors resCors://*\n",
        "http://example.com/x",
    );
    let mut parts = res_parts(&[]);
    apply_response_for(&mut parts, &resolved, Some(&info));
    assert_eq!(
        parts.headers.get("access-control-allow-origin").unwrap(),
        "*"
    );
}

/// `resCookies` replaces a `Set-Cookie` the response already sent under the
/// same name instead of adding a second one (`setResCookies`).
/// `reqReplace` is gated on the *request's* content type, mirroring the way
/// `resReplace` is gated on the response's (`res.js:129-132`): a request
/// with no `content-type`, or an image one, is left alone.
#[test]
fn req_replace_is_gated_on_the_request_content_type() {
    let resolved = resolve("example.com reqReplace://old=new\n", "http://example.com/");
    let body = || Bytes::from_static(b"old");

    assert_eq!(
        &transform_req_body(body(), &resolved, body_ctx(Some("text/plain")))[..],
        b"new",
        "text is rewritten"
    );
    assert_eq!(
        &transform_req_body(body(), &resolved, body_ctx(None))[..],
        b"old",
        "no content-type: left alone"
    );
    assert_eq!(
        &transform_req_body(body(), &resolved, body_ctx(Some("image/png")))[..],
        b"old",
        "images are left alone"
    );
}

/// …but a **form POST** is not one of the bodies it leaves alone, which is
/// where this port had it wrong (`handleReplace`,
/// `_original/lib/inspectors/req.js:434-438`).
///
/// `getContentType` puts `application/x-www-form-urlencoded` in no class,
/// and the gate refuses everything unclassified — so upstream substitutes
/// the class `FORM` for it first. Without that substitution `reqReplace://`
/// was inert against the single commonest request body there is, and
/// silently so.
#[test]
fn req_replace_reaches_a_form_post() {
    let resolved = resolve("example.com reqReplace://old=new\n", "http://example.com/");
    let sent = |method: &str, ct: Option<&str>| {
        let ctx = ReqBodyCtx {
            method,
            content_type: ct,
        };
        let out = transform_req_body(Bytes::from_static(b"q=old"), &resolved, ctx);
        String::from_utf8(out.to_vec()).expect("utf-8")
    };
    let form = Some("application/x-www-form-urlencoded");

    assert_eq!(sent("POST", form), "q=new");
    // The charset parameter does not change the answer.
    assert_eq!(
        sent(
            "POST",
            Some("application/x-www-form-urlencoded; charset=UTF-8")
        ),
        "q=new"
    );
    // `isUrlEncoded` is POST-only, so a `PUT` carrying the same body takes
    // the ordinary path — and `getContentType` gives it no class.
    assert_eq!(sent("PUT", form), "q=old");
    // A method that carries no body is refused before the type is looked
    // at (`hasRequestBody`, `common.js:1591-1604`).
    assert_eq!(sent("GET", Some("text/plain")), "q=old");
    assert_eq!(sent("OPTIONS", Some("text/plain")), "q=old");
    // The classes that did already work still do.
    assert_eq!(sent("POST", Some("application/json")), "q=new");
    assert_eq!(sent("PUT", Some("text/plain")), "q=new");
}

/// A `set-cookie` written on `resHeaders://` **merges** with the response's
/// own, by cookie name (`setCookies`,
/// `_original/lib/inspectors/res.js:89-122`, run at `:926` just before the
/// `extend` that would otherwise clobber it).
///
/// The port assigned the header instead, so a rule setting `sid` also threw
/// away the `csrf` cookie the origin sent beside it — and the JSON array
/// spelling was worse still: it stringified the array into the header value
/// and sent `Set-Cookie: ["sid=new","theme=dark"]`.
///
/// Expectations are upstream's own output, from a verbatim `setCookies`.
#[test]
fn res_headers_set_cookie_merges_with_the_origins() {
    let sent = |rule: &str, origin: &[&str]| {
        let resolved = resolve(
            &format!("example.com resHeaders://{rule}\n"),
            "http://example.com/",
        );
        let mut parts = res_parts(&[]);
        for c in origin {
            parts
                .headers
                .append(hyper::header::SET_COOKIE, c.parse().unwrap());
        }
        apply_response(&mut parts, &resolved);
        parts
            .headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    // The named cookie is replaced; the others survive, after it.
    assert_eq!(
        sent("set-cookie=sid=new", &["sid=old; Path=/", "csrf=abc"]),
        ["sid=new", "csrf=abc"]
    );
    // The JSON array spelling is a list of cookies, not a header value.
    assert_eq!(
        sent(
            r#"{"set-cookie":["sid=new","theme=dark"]}"#,
            &["sid=old", "csrf=abc"]
        ),
        ["sid=new", "theme=dark", "csrf=abc"]
    );
    // A plain string is split on commas, so this is two cookies…
    assert_eq!(
        sent("set-cookie=a=1,b=2", &["sid=old"]),
        ["a=1", "b=2", "sid=old"]
    );
    // …and an array element is not, which is the only way to write a cookie
    // whose attributes contain a comma (an `Expires=Wed, 21 Oct …`).
    assert_eq!(
        sent(r#"{"set-cookie":["a=1,b=2"]}"#, &["sid=old"]),
        ["a=1,b=2", "sid=old"]
    );
    // Nothing to merge with.
    assert_eq!(sent("set-cookie=sid=new", &[]), ["sid=new"]);
    // A cookie with no `=` is a name of its own, and does not collide.
    assert_eq!(sent("set-cookie=flag", &["sid=old"]), ["flag", "sid=old"]);
    assert_eq!(
        sent("set-cookie=sid=new", &["sid=old", "flag"]),
        ["sid=new", "flag"]
    );
    // An empty value is not a merge: it falls through to the assignment,
    // like any other empty header value.
    assert_eq!(sent("set-cookie=", &["sid=old"]), [""]);
    // The name is matched however it is spelled on the rule.
    assert_eq!(
        sent(r#"{"Set-Cookie":"sid=new"}"#, &["sid=old", "csrf=abc"]),
        ["sid=new", "csrf=abc"]
    );
}

/// The JSON array spelling is several header lines for every header, not
/// only `set-cookie` — Node writes one line per element of
/// `headers[name] = ['a', 'b']`.
#[test]
fn a_json_array_header_value_is_several_headers() {
    let resolved = resolve(
        r#"example.com reqHeaders://{"x-a":["1","2"],"x-b":"3"}"#,
        "http://example.com/",
    );
    let mut parts = req_parts(&[("x-a", "arrived")]);
    apply_request(&mut parts, &resolved);
    let values: Vec<_> = parts
        .headers
        .get_all("x-a")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(
        values,
        ["1", "2"],
        "the arrived value is replaced, not added to"
    );
    assert_eq!(parts.headers.get("x-b").unwrap(), "3");
}

#[test]
fn res_cookies_replace_by_name() {
    let resolved = resolve(
        "example.com resCookies://sid=new&theme=dark\n",
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    headers.append(
        hyper::header::SET_COOKIE,
        "sid=old; Path=/".parse().unwrap(),
    );
    headers.append(hyper::header::SET_COOKIE, "other=1".parse().unwrap());
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    let vals: Vec<_> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(vals, ["sid=new", "other=1", "theme=dark"]);

    // A `;` in the **string** spelling goes out as written, because that is
    // the whole point of writing one: `resCookies://a=x;Secure` is how the
    // operator's documentation sets an attribute. `getCookieItem` returns
    // `name + '=' + cookie` untouched for a non-object
    // (`_original/lib/util/index.js:3093-3096`) — `escapeValue` is reached
    // only down the attribute path. This asserted the opposite, and the
    // encoded form is a cookie with a nonsense value and no attribute at all.
    let resolved = resolve(
        "example.com resCookies://a=x;Secure\n",
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    assert_eq!(
        headers.get(hyper::header::SET_COOKIE).unwrap(),
        "a=x;Secure"
    );
}

/// One `Set-Cookie`, rendered from `resCookies`, for a given JSON spec.
fn set_cookie(rule: &str) -> String {
    let resolved = resolve(
        &format!("example.com resCookies://{rule}\n"),
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    headers
        .get(hyper::header::SET_COOKIE)
        .expect("a cookie")
        .to_str()
        .unwrap()
        .to_string()
}

/// A cookie declared as an object carries attributes, in upstream's order
/// (`getCookieItem`, `_original/lib/util/index.js:3093-3117`). Previously
/// the object was serialised into the value, so
/// `{"sid":{"value":"x","httpOnly":true}}` produced the literal JSON as the
/// cookie's value and set no attributes at all.
#[test]
fn a_cookie_object_becomes_attributes() {
    let out = set_cookie(
        r#"{"sid":{"value":"x","httpOnly":true,"secure":true,"path":"/a","domain":"example.com","sameSite":"Lax","partitioned":true}}"#,
    );
    assert_eq!(
        out,
        "sid=x; Secure; HttpOnly; Partitioned; Path=/a; Domain=example.com; SameSite=Lax"
    );

    // A falsy flag is absent, exactly as in JavaScript — and `Value` /
    // `Path` are read in their capitalised spellings too.
    assert_eq!(
        set_cookie(r#"{"a":{"Value":"1","httpOnly":false,"secure":0,"Path":"/"}}"#),
        "a=1; Path=/"
    );

    // No `value` at all leaves the cookie empty rather than dropping it:
    // upstream's `escapeValue(undefined)` is the empty string.
    assert_eq!(set_cookie(r#"{"a":{"httpOnly":true}}"#), "a=; HttpOnly");

    // The value is escaped inside the attribute form too.
    assert_eq!(set_cookie(r#"{"a":{"value":"x;y"}}"#), "a=x%3By");
}

/// One name may carry an **array**, and then it emits several `Set-Cookie`
/// lines — how upstream expires a cookie under both its plain and its
/// `Secure` spelling in one go (`Array.isArray(cookie)`,
/// `_original/lib/util/index.js:3138-3142`).
#[test]
fn a_cookie_array_becomes_several_headers() {
    let resolved = resolve(
        r#"example.com resCookies://{"sid":[{"value":"a","path":"/"},{"value":"b","secure":true}]}"#,
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    let vals: Vec<_> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(vals, ["sid=a; Path=/", "sid=b; Secure"]);

    // Every line of the array replaces what the response sent under that
    // name — the group is one unit, not an addition to it.
    let mut headers = HeaderMap::new();
    headers.append(hyper::header::SET_COOKIE, "sid=old".parse().unwrap());
    headers.append(hyper::header::SET_COOKIE, "keep=1".parse().unwrap());
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    let vals: Vec<_> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(
        vals,
        ["sid=a; Path=/", "sid=b; Secure", "keep=1"],
        "the replaced name keeps its position, and an untouched one survives"
    );
}

/// `delete://resCookies.x` cannot remove a cookie the client already holds,
/// so it sends one back that has already expired — twice per name, plain and
/// `Secure`, because a `Secure` cookie is not overwritten by a plain one
/// (`parseDelResCookies`, `_original/lib/util/index.js:2776-2795`).
/// Previously the key was parsed and then dropped on the response side, so
/// the rule did nothing at all.
#[test]
fn deleting_a_response_cookie_expires_it() {
    let lines = |rule: &str, info: Option<&ReqInfo>| {
        let resolved = resolve(
            &format!("example.com delete://{rule}\n"),
            "http://example.com/",
        );
        let mut headers = HeaderMap::new();
        apply_res_cookies(
            &mut headers,
            &resolved,
            &Deletions::of(&resolved, false),
            info,
        );
        headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    let out = lines("resCookies.sid", None);
    assert_eq!(out.len(), 2, "one plain and one Secure: {out:?}");
    assert!(out[0].starts_with("sid=; Expires="), "{:?}", out[0]);
    assert!(out[0].ends_with("; Max-Age=0; Path=/"), "{:?}", out[0]);
    assert!(out[1].contains("; Secure; Path=/"), "{:?}", out[1]);
    // The `Expires` is in the past, which together with `Max-Age=0` is what
    // actually drops the cookie. Compared against a date this proxy renders
    // itself rather than a literal, which would rot.
    let expires = out[0]
        .split("; Expires=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("an Expires");
    assert_ne!(expires, http_date(0), "an expiry now is not an expiry");
    assert_eq!(expires, http_date(EXPIRED_MAX_AGE * 1000));

    // A bare `cookies.x` is honoured on this side too (`COOKIE_RE`).
    assert_eq!(lines("cookies.sid", None).len(), 2);
    // …and the request-side spelling is not.
    assert!(lines("reqCookies.sid", None).is_empty());

    // A host with a parent domain adds two more entries scoped to it,
    // because the cookie may have been set there rather than on the host.
    // Every request has the hostname — `req._w2hostname` is the `Host`
    // header's, stamped before any rule runs (`_original/biz/index.js:40`)
    // — so a plain forward-proxy request gets them too. Reading it as a
    // tunnel-only field left `delete://resCookies.x` sending half the
    // `Set-Cookie` lines whistle sends.
    let mut info = build_req_info(
        "GET",
        "https",
        "a.b.example.com",
        443,
        "/",
        &HeaderMap::new(),
        None,
    );
    let out = lines("resCookies.sid", Some(&info));
    assert_eq!(out.len(), 4, "{out:?}");
    assert!(out[2].contains("Domain=b.example.com"), "{:?}", out[2]);
    info.from.tunnel = true;
    assert_eq!(lines("resCookies.sid", Some(&info)).len(), 4);
    // Three labels keep the leading dot; two have no parent at all.
    assert_eq!(
        parent_domain("b.example.com").as_deref(),
        Some(".example.com")
    );
    assert_eq!(parent_domain("example.com"), None);
}

/// The deletion wins over a `resCookies://` for the same name on the same
/// request: upstream folds the deletions in *over* the operators
/// (`extend(cookies, delKeys)`, `_original/lib/util/index.js:3127-3129`).
#[test]
fn deleting_a_cookie_beats_setting_it() {
    let resolved = resolve(
        "example.com resCookies://sid=new delete://resCookies.sid\n",
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    apply_res_cookies(
        &mut headers,
        &resolved,
        &Deletions::of(&resolved, false),
        None,
    );
    let out: Vec<_> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(out.len(), 2, "the expiring pair, not the value: {out:?}");
    assert!(out.iter().all(|c| c.contains("Max-Age=0")), "{out:?}");
}

/// `delete://trailer.x` drops a trailing header, and unlike every other
/// delete key it is not scoped by `req`/`res` (`TRAILER_RE` is unanchored).
#[test]
fn deleting_a_trailer_drops_it() {
    let resolved = resolve(
        "example.com trailers://x-a=1&x-b=2 delete://trailer.x-a\n",
        "http://example.com/",
    );
    let t = build_trailers(&resolved);
    assert!(t.get("x-a").is_none(), "the deleted trailer is gone");
    assert_eq!(t.get("x-b").unwrap(), "2", "the other one stays");

    // `TRAILER_RE` is the one delete key written without the `i` flag, so
    // the word has to be lower case: `resTrailer.x-a` matches nothing.
    let resolved = resolve(
        "example.com trailers://x-a=1 delete://resTrailer.x-a\n",
        "http://example.com/",
    );
    assert_eq!(build_trailers(&resolved).get("x-a").unwrap(), "1");
    // Unanchored at the front, though, so a lower-cased prefix does match.
    let resolved = resolve(
        "example.com trailers://x-a=1 delete://restrailer.x-a\n",
        "http://example.com/",
    );
    assert!(build_trailers(&resolved).get("x-a").is_none());
    // It is not a response *header* deletion.
    let resolved = resolve("example.com delete://trailer.x-a\n", "http://example.com/");
    assert!(Deletions::of(&resolved, false).headers.is_empty());
}

/// `maxAge` emits the `Expires`/`Max-Age` pair, and the sentinel whistle
/// uses for a deletion is written as `Max-Age=0` (`EXPIRED_SEC`).
#[test]
fn a_cookie_max_age_expires_it() {
    let out = set_cookie(r#"{"a":{"value":"1","maxAge":600}}"#);
    assert!(out.starts_with("a=1; Expires="), "got {out}");
    assert!(out.ends_with(" GMT; Max-Age=600"), "got {out}");

    let out = set_cookie(&format!(
        r#"{{"a":{{"value":"1","maxAge":{EXPIRED_MAX_AGE}}}}}"#
    ));
    assert!(out.ends_with("; Max-Age=0"), "got {out}");

    // Every spelling upstream accepts, and only those.
    for key in ["maxAge", "maxage", "MaxAge", "Max-Age", "max-age"] {
        assert!(
            set_cookie(&format!(r#"{{"a":{{"value":"1","{key}":60}}}}"#)).ends_with("; Max-Age=60"),
            "{key} should be read"
        );
    }
    // `parseInt` semantics: a leading integer, or the attribute is skipped.
    assert_eq!(
        set_cookie(r#"{"a":{"value":"1","maxAge":"600s"}}"#)
            .split("; ")
            .last(),
        Some("Max-Age=600")
    );
    assert_eq!(set_cookie(r#"{"a":{"value":"1","maxAge":"soon"}}"#), "a=1");
}

/// The request side has nowhere to put attributes, so it takes the value
/// alone — upstream's `typeof value == 'object' ? value.value : value`.
#[test]
fn a_cookie_object_is_only_a_value_on_the_request() {
    let resolved = resolve(
        r#"example.com reqCookies://{"sid":{"value":"x","httpOnly":true}}"#,
        "http://example.com/",
    );
    let mut headers = HeaderMap::new();
    apply_req_cookies(&mut headers, &resolved);
    assert_eq!(headers.get(hyper::header::COOKIE).unwrap(), "sid=x");
}

/// The request method is uppercased on **every** request, not only one
/// carrying a `method://` (`req.method = util.getMethod(data.method ||
/// req.method)`, `_original/lib/inspectors/req.js:536`, impl
/// `util/common.js:1608-1613`).
///
/// It matters beyond tidiness: the normalised method is what every
/// body gate downstream reads, so a client sending `post` was treated as a
/// method that carries no body and had its `reqBody://` silently dropped.
#[test]
fn the_method_is_uppercased_whether_or_not_a_rule_names_one() {
    let sent = |rule: &str, arrived: &str| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = hyper::Request::builder()
            .method(arrived)
            .uri("http://example.com/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        apply_request(&mut parts, &resolved);
        parts.method.to_string()
    };

    // No `method://` at all: the client's own spelling is normalised.
    assert_eq!(sent("host://1.1.1.1", "post"), "POST");
    assert_eq!(sent("host://1.1.1.1", "GET"), "GET");
    // A rule's value is normalised the same way, and trimmed.
    assert_eq!(sent("method://put", "GET"), "PUT");
    // An unusable value falls back to `GET`, as `getMethod` does.
    assert_eq!(sent("method://", "POST"), "GET");
}

/// `replaceStatus://` only writes the auth challenge when the status
/// actually changed (`replaceStatus != _res.statusCode`,
/// `_original/lib/inspectors/res.js:826-832`).
///
/// Without the guard a rule pinned to `401` wrote a `WWW-Authenticate:
/// Basic` onto a response that was *already* a 401 and had deliberately not
/// asked for one — and a browser answers that header with a login box.
#[test]
fn replace_status_only_challenges_when_the_status_changed() {
    let challenge = |rule: &str, from: u16| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = Response::builder()
            .status(from)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        apply_response(&mut parts, &resolved);
        (
            parts.status.as_u16(),
            parts
                .headers
                .get("www-authenticate")
                .map(|v| v.to_str().unwrap().to_string()),
        )
    };

    // A real change still challenges.
    assert_eq!(
        challenge("replaceStatus://401", 200),
        (401, Some("Basic realm=User Login".to_string()))
    );
    // Replacing a status with itself does not.
    assert_eq!(challenge("replaceStatus://401", 401), (401, None));
    // `disable://userLogin` suppresses the challenge without suppressing
    // the status change (`isDisableUserLogin`, `util/index.js:3557-3562`)…
    assert_eq!(
        challenge("replaceStatus://401 disable://userLogin", 200),
        (401, None)
    );
    // …and `enable://userLogin` wins over it.
    assert_eq!(
        challenge(
            "replaceStatus://401 disable://userLogin enable://userLogin",
            200
        ),
        (401, Some("Basic realm=User Login".to_string()))
    );
    // The line's own properties say the same, and were read as being about
    // whistle's login box rather than about this header — so `lineProps://
    // disableUserLogin` left the challenge standing, which the differential
    // bench caught.
    assert_eq!(
        challenge("replaceStatus://401 lineProps://disableUserLogin", 200),
        (401, None)
    );
    assert_eq!(
        challenge(
            "replaceStatus://401 lineProps://disableUserLogin&enableUserLogin",
            200
        ),
        (401, Some("Basic realm=User Login".to_string()))
    );
    // The property is line-scoped: written on another line it says nothing
    // about this one.
    let two_lines = "example.com replaceStatus://401\n\
                         example.com resHeaders://x-a=1 lineProps://disableUserLogin\n";
    let resolved = resolve(two_lines, "http://example.com/");
    let mut parts = res_parts(&[]);
    apply_response(&mut parts, &resolved);
    assert_eq!(
        parts
            .headers
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap()),
        Some("Basic realm=User Login")
    );
    // 407 takes the proxy spelling.
    let resolved = resolve("example.com replaceStatus://407\n", "http://example.com/");
    let mut parts = res_parts(&[]);
    apply_response(&mut parts, &resolved);
    assert_eq!(
        parts.headers.get("proxy-authenticate").unwrap(),
        "Basic realm=User Login"
    );
}

/// A mocked `statusCode://401` carries the challenge too — upstream answers
/// such a rule through `getStatusCodeFromRule`, which calls `handleStatusCode`
/// unless the line said otherwise (`_original/lib/util/index.js:3566-3588`).
///
/// This port answered with a bare 401, so mocking an unauthenticated
/// response never made a browser ask for credentials. Found with the
/// differential bench, not by reading.
#[test]
fn a_mocked_401_asks_the_browser_for_credentials() {
    let challenge = |rule: &str, header: &str| {
        let info = build_req_info("GET", "http", "a.com", 80, "/", &HeaderMap::new(), None);
        let resolved = resolve(&format!("a.com {rule}\n"), "http://a.com/");
        let resp = short_circuit(&info, &resolved, test_env(), None).expect("a status is answered");
        (
            resp.status().as_u16(),
            resp.headers()
                .get(header)
                .map(|v| v.to_str().unwrap().to_string()),
        )
    };
    let basic = || Some("Basic realm=User Login".to_string());

    assert_eq!(
        challenge("statusCode://401", "www-authenticate"),
        (401, basic())
    );
    assert_eq!(
        challenge("statusCode://407", "proxy-authenticate"),
        (407, basic())
    );
    // Only those two statuses carry one.
    assert_eq!(
        challenge("statusCode://403", "www-authenticate"),
        (403, None)
    );
    // …and the line, or the request, can decline it.
    assert_eq!(
        challenge(
            "statusCode://401 lineProps://disableUserLogin",
            "www-authenticate"
        ),
        (401, None)
    );
    assert_eq!(
        challenge("statusCode://401 disable://userLogin", "www-authenticate"),
        (401, None)
    );
    assert_eq!(
        challenge(
            "statusCode://401 disable://userLogin lineProps://enableUserLogin",
            "www-authenticate"
        ),
        (401, basic())
    );
}

/// `disable://301` hands back a `302` instead
/// (`_original/lib/inspectors/res.js:833-835`).
///
/// This is the flag you reach for once a site has taught the browser a
/// permanent redirect you now need to override, and it did nothing.
#[test]
fn disable_301_downgrades_the_redirect() {
    let status = |rule: &str, from: u16| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = Response::builder()
            .status(from)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        apply_response(&mut parts, &resolved);
        parts.status.as_u16()
    };
    assert_eq!(status("disable://301", 301), 302);
    // Only a 301, and only with the flag.
    assert_eq!(status("disable://301", 302), 302);
    assert_eq!(status("disable://301", 308), 308);
    assert_eq!(status("host://1.1.1.1", 301), 301);
    // It runs after `replaceStatus://`, so a rule that *produces* a 301 is
    // downgraded too.
    assert_eq!(status("replaceStatus://301 disable://301", 200), 302);
}

/// `Location` is percent-encoded on the way out (`encodeNonLatin1Char`,
/// `_original/lib/inspectors/res.js:946-949`).
///
/// Node's URL layer only speaks ASCII, so a redirect to a path with a
/// non-Latin-1 character in it reached the browser as mojibake — or, here,
/// as a header value hyper would not carry at all.
#[test]
fn location_is_re_encoded() {
    let location = |rules: &str, arrived: &str| {
        let resolved = resolve(rules, "http://example.com/");
        let mut parts = res_parts(&[("location", arrived)]);
        apply_response(&mut parts, &resolved);
        parts
            .headers
            .get("location")
            .map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        location("example.com host://1.1.1.1\n", "/搜索"),
        Some("/%E6%90%9C%E7%B4%A2".to_string())
    );
    // ASCII is left exactly as it is.
    assert_eq!(
        location("example.com host://1.1.1.1\n", "https://a.test/x?y=1"),
        Some("https://a.test/x?y=1".to_string())
    );
    // The encode runs *after* the header operators, so a `Location` a rule
    // wrote is encoded too — upstream's order, `extend` at `res.js:927`
    // against the encode at `:946`.
    assert_eq!(
        location("example.com resHeaders://location=/搜\n", "/x/y"),
        Some("/%E6%90%9C".to_string())
    );
}

/// `delete://resHeaders.x` runs **after** the injection's CSP and
/// cache strips (`_original/lib/inspectors/res.js:1160-1165` against
/// `:1097-1104`), so it can take away what they just wrote.
///
/// Deleting first left the `Cache-Control: no-store` standing, which is the
/// one header anyone writes this pair of rules to get rid of.
#[test]
fn a_delete_outlives_the_injections_own_headers() {
    let resolved = resolve(
        "example.com resAppend://x delete://resHeaders.cache-control\n",
        "http://example.com/",
    );
    let mut parts = res_parts(&[
        ("content-type", "text/html"),
        ("cache-control", "max-age=60"),
    ]);
    apply_response(&mut parts, &resolved);
    assert!(
        parts.headers.get("cache-control").is_none(),
        "the injection's own no-store must be deletable"
    );
    // …and the injection still writes it when nothing deleted it.
    let kept = resolve("example.com resAppend://x\n", "http://example.com/");
    let mut parts = res_parts(&[("content-type", "text/html")]);
    apply_response(&mut parts, &kept);
    assert_eq!(parts.headers.get("cache-control").unwrap(), "no-store");
}

/// An empty header value is a value, not a deletion
/// (`extend(req.headers, data.headers)`,
/// `_original/lib/inspectors/req.js:105`; `res.js:927` on the other side).
///
/// The port removed the header instead, which is a different rule with a
/// different spelling (`delete://reqHeaders.x`) and the opposite meaning to
/// any server that branches on a header being *present*. `ua://` and
/// `referer://` ride the same assignment and had the same bug.
#[test]
fn an_empty_header_value_is_sent_not_deleted() {
    let resolved = resolve(
        "example.com reqHeaders://x-a=&x-b=1 ua:// referer://\n",
        "http://example.com/",
    );
    let mut parts = req_parts(&[
        ("x-a", "arrived"),
        ("user-agent", "MyUA"),
        ("referer", "http://ref.test/"),
    ]);
    apply_request(&mut parts, &resolved);
    for name in ["x-a", "user-agent", "referer"] {
        assert_eq!(
            parts.headers.get(name).map(|v| v.to_str().unwrap()),
            Some(""),
            "{name} must be sent empty, not dropped"
        );
    }
    assert_eq!(parts.headers.get("x-b").unwrap(), "1");

    // The response side assigns the same way.
    let res = resolve("example.com resHeaders://x-a=\n", "http://example.com/");
    let mut parts = res_parts(&[("x-a", "arrived")]);
    apply_response(&mut parts, &res);
    assert_eq!(
        parts.headers.get("x-a").map(|v| v.to_str().unwrap()),
        Some("")
    );

    // Removal is still available, under its own name.
    let del = resolve(
        "example.com reqHeaders://x-a=1 delete://reqHeaders.x-a\n",
        "http://example.com/",
    );
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &del);
    assert!(parts.headers.get("x-a").is_none());
}

/// Every `disable://` flag that strips a request header
/// (`disableReqProps`, `_original/lib/util/index.js:2977-3009`). None of
/// these were applied before: the request went out with the cookie, the
/// referer and the user-agent a rule had asked to withhold, which is a
/// privacy promise the proxy was quietly breaking.
#[test]
fn disable_strips_request_headers() {
    let sent = |rule: &str, name: &str| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = req_parts(&[
            ("cookie", "sid=secret"),
            ("user-agent", "MyUA"),
            ("referer", "http://ref.test/"),
            ("accept-encoding", "gzip"),
            ("x-requested-with", "XMLHttpRequest"),
        ]);
        apply_request(&mut parts, &resolved);
        parts
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };

    assert_eq!(sent("disable://ua", "user-agent"), None);
    assert_eq!(sent("disable://gzip", "accept-encoding"), None);
    assert_eq!(sent("disable://referer", "referer"), None);
    // whistle takes the misspelling too, because it matches the header name.
    assert_eq!(sent("disable://referrer", "referer"), None);
    assert_eq!(sent("disable://ajax", "x-requested-with"), None);
    for spelling in ["cookie", "cookies", "reqCookie", "reqCookies"] {
        assert_eq!(
            sent(&format!("disable://{spelling}"), "cookie"),
            None,
            "{spelling}"
        );
    }
    // `enable://captureStream` drops the encoding too: whistle wants the
    // origin's bytes uncompressed (`isEnable`, `util/index.js:675-677`).
    assert_eq!(sent("enable://captureStream", "accept-encoding"), None);
    // …unless the same request also disables it, which is what `isEnable`
    // means — `enable` alone is not enough.
    assert_eq!(
        sent(
            "enable://captureStream disable://captureStream",
            "accept-encoding"
        ),
        Some("gzip".to_string())
    );
    // A flag nobody set leaves everything alone.
    assert_eq!(
        sent("host://1.1.1.1", "cookie"),
        Some("sid=secret".to_string())
    );
}

/// The two abort gates are two different moments, and each has its own
/// `disable://` cancellation (`needAbortReq`/`needAbortRes`,
/// `_original/lib/util/index.js:3893-3915`).
///
/// The port collapsed all three spellings into one before-the-request gate,
/// which got `abortRes` wrong (it must let the request reach the origin) and
/// ignored `disable://` entirely — so `enable://abort` on a domain could not
/// be exempted for a single path, the one thing a `disable://` line is for.
#[test]
fn the_abort_gates_are_two_moments_and_both_can_be_cancelled() {
    let gates = |rules: &str| {
        let r = resolve(&format!("example.com {rules}\n"), "http://example.com/");
        (aborts_request(&r), aborts_response(&r))
    };

    // `abort` arms both, but the request gate fires first, so the origin is
    // never contacted.
    assert_eq!(gates("enable://abort"), (true, true));
    // `abortReq` stops at the request; `abortRes` lets it through and kills
    // the answer.
    assert_eq!(gates("enable://abortReq"), (true, false));
    assert_eq!(gates("enable://abortRes"), (false, true));

    // A `disable://` of the same name cancels its own gate…
    assert_eq!(gates("enable://abort disable://abortReq"), (false, true));
    assert_eq!(gates("enable://abort disable://abortRes"), (true, false));
    // …and `disable://abort` cancels both, whatever armed them.
    assert_eq!(gates("enable://abort disable://abort"), (false, false));
    assert_eq!(
        gates("enable://abortReq|abortRes disable://abort"),
        (false, false)
    );

    // Nothing set: nothing aborts.
    assert_eq!(gates("host://1.1.1.1"), (false, false));
}

/// `disable://keepAlive` closes the hop to the **origin**, not the client's
/// connection (`_original/lib/inspectors/res.js:447-449`).
///
/// The port had it backwards: it wrote `Connection: close` onto the response
/// and left the origin socket pooled, so the one connection the flag exists
/// to un-pool stayed up and the browser's was torn down instead — a rule
/// that made every page slower while doing nothing it promised.
#[test]
fn disable_keep_alive_closes_the_origin_hop() {
    for spelling in ["keepAlive", "keepalive"] {
        let resolved = resolve(
            &format!("example.com disable://{spelling}\n"),
            "http://example.com/",
        );
        let mut parts = req_parts(&[]);
        apply_request(&mut parts, &resolved);
        assert_eq!(
            parts.headers.get("connection").map(|v| v.to_str().unwrap()),
            Some("close"),
            "{spelling} must close the outgoing request"
        );
        // …and the answer to the client is left alone.
        let mut res = res_parts(&[]);
        apply_response(&mut res, &resolved);
        assert!(
            res.headers.get("connection").is_none(),
            "{spelling} must not touch the response"
        );
    }
    // Nothing set: the request keeps whatever framing it arrived with.
    let none = resolve("example.com host://1.1.1.1\n", "http://example.com/");
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &none);
    assert!(parts.headers.get("connection").is_none());
}

/// Every request's `Accept-Encoding` is narrowed to what this proxy can
/// round-trip (`removeUnsupportsHeaders`,
/// `_original/lib/util/index.js:1549-1570`, run at `req.js:579`).
///
/// This was missing entirely, and it is the quiet reason a body operator
/// "stops working" on a modern browser: Chrome asks for
/// `gzip, deflate, br, zstd`, the origin answers zstd, `coding.rs` cannot
/// undo it, and `resReplace://` searches a compressed stream for its
/// pattern, finds nothing, and reports nothing.
#[test]
fn accept_encoding_is_narrowed_to_what_can_be_round_tripped() {
    let sent = |arrived: &str| {
        let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/");
        let mut parts = req_parts(&[("accept-encoding", arrived)]);
        apply_request(&mut parts, &resolved);
        parts
            .headers
            .get("accept-encoding")
            .map(|v| v.to_str().unwrap().to_string())
    };

    // What a browser actually sends.
    assert_eq!(sent("gzip, deflate, br, zstd"), Some("gzip, br".into()));
    // Order is the client's, not a fixed one, and the separator is `, `.
    assert_eq!(sent("br,gzip"), Some("br, gzip".into()));
    assert_eq!(sent("  GZIP , BR  "), Some("gzip, br".into()));
    // `deflate` goes, though this port could decode it — upstream's caller
    // does not pass `supportsDeflate`.
    assert_eq!(
        sent("deflate"),
        Some("deflate".into()),
        "left alone: nothing survived"
    );
    assert_eq!(sent("gzip, deflate"), Some("gzip".into()));
    // A `q` parameter takes the coding with it: the comparison is against
    // the whole token.
    assert_eq!(
        sent("gzip;q=1.0, br;q=0.9"),
        Some("gzip;q=1.0, br;q=0.9".into())
    );
    assert_eq!(sent("gzip;q=1.0, br"), Some("br".into()));
    // Empty tokens are not codings.
    assert_eq!(sent("gzip,,br"), Some("gzip, br".into()));
    // A request that asked for nothing keeps its header, whatever it was.
    assert_eq!(sent("zstd"), Some("zstd".into()));
    assert_eq!(sent("identity"), Some("identity".into()));
    // No header, nothing to narrow.
    let resolved = resolve("example.com host://1.1.1.1\n", "http://example.com/");
    let mut parts = req_parts(&[]);
    apply_request(&mut parts, &resolved);
    assert!(parts.headers.get("accept-encoding").is_none());

    // `disable://gzip` still wins: it runs after this
    // (`req.js:579-580`).
    let off = resolve("example.com disable://gzip\n", "http://example.com/");
    let mut parts = req_parts(&[("accept-encoding", "gzip, deflate, br, zstd")]);
    apply_request(&mut parts, &off);
    assert!(parts.headers.get("accept-encoding").is_none());
}

/// `disable://cache` strips the conditional headers *and* asks for no cache
/// (`disableReqCache`, `_original/lib/util/index.js:974-982`).
#[test]
fn disable_cache_strips_the_conditional_headers() {
    let resolved = resolve("example.com disable://cache\n", "http://example.com/");
    let mut parts = req_parts(&[
        ("if-none-match", "\"v1\""),
        ("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT"),
        ("etag", "\"v1\""),
        ("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
    ]);
    apply_request(&mut parts, &resolved);
    for gone in [
        "if-none-match",
        "if-modified-since",
        "etag",
        "last-modified",
    ] {
        assert!(parts.headers.get(gone).is_none(), "{gone} must be stripped");
    }
    assert_eq!(parts.headers.get("pragma").unwrap(), "no-cache");
    assert_eq!(parts.headers.get("cache-control").unwrap(), "no-cache");
}

/// The half that matters more, because nobody asks for it: **any** response
/// body operator busts the request's cache
/// (`notAllowCache(resRules) && disableReqCache(req.headers)`,
/// `_original/lib/inspectors/res.js:1328`).
///
/// Without it a `resBody://` is silently inert on a reload: the conditional
/// request reaches the origin, the origin answers `304 Not Modified` with no
/// body, and there is nothing for the operator to rewrite. Measured against
/// a running proxy before the fix — the first load said `REWRITTEN`, the
/// reload said `304` — which is the worst shape of bug to be handed, an
/// operator that works until you press reload.
#[test]
fn a_response_body_operator_busts_the_request_cache() {
    let conditional = || {
        req_parts(&[
            ("if-none-match", "\"v1\""),
            ("if-modified-since", "Mon, 01 Jan 2024 00:00:00 GMT"),
        ])
    };
    let survives = |rule: &str| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = conditional();
        apply_request(&mut parts, &resolved);
        parts.headers.contains_key("if-none-match")
    };

    // Every operator on upstream's list, not just the obvious one.
    for rule in [
        "resBody://x",
        "resPrepend://x",
        "resAppend://x",
        "resReplace://a=b",
        "resMerge://{}",
        "htmlAppend://x",
        "jsPrepend://x",
        "cssBody://x",
        "attachment://f.txt",
        "resWrite:///tmp/whistle-rs-test-write",
        "resWriteRaw:///tmp/whistle-rs-test-write-raw",
    ] {
        assert!(!survives(rule), "{rule} must bust the cache");
    }

    // A rule that cannot change the body leaves the conditional request
    // alone — this is not a blanket "disable caching for everything".
    for rule in ["host://1.1.1.1", "resHeaders://x-a=1", "resType://json"] {
        assert!(survives(rule), "{rule} must not touch the cache headers");
    }
}

/// A response-body operator strips them too, without anyone asking
/// (`notAllowCache`, `_original/lib/inspectors/res.js:33-60,:1328`).
///
/// This is the failure that looks like a bug rather than a gap: a rule that
/// rewrites the body works on the first request and silently does nothing on
/// a reload, because the origin answers `304` with no body to rewrite.
#[test]
fn a_body_operator_forbids_a_conditional_request() {
    let conditional_survives = |rule: &str| {
        let resolved = resolve(&format!("example.com {rule}\n"), "http://example.com/");
        let mut parts = req_parts(&[("if-none-match", "\"v1\"")]);
        apply_request(&mut parts, &resolved);
        parts.headers.get("if-none-match").is_some()
    };

    // Every operator on upstream's list, spot-checked across its families.
    for rule in [
        "resBody://x",
        "resReplace://a=b",
        "resPrepend://x",
        "resAppend://x",
        "htmlAppend://x",
        "jsPrepend://x",
        "cssBody://x",
        "resMerge://{}",
        "attachment://f.txt",
        "resWrite:///tmp/x",
        "resWriteRaw:///tmp/x",
    ] {
        assert!(!conditional_survives(rule), "{rule} must forbid a 304");
    }

    // A rule that does not touch the body leaves the request conditional —
    // stripping it unasked would cost every such request its 304.
    for rule in [
        "host://1.1.1.1",
        "resHeaders://x-a=1",
        "replaceStatus://500",
    ] {
        assert!(conditional_survives(rule), "{rule} must keep the 304 path");
    }
}

// ── the forwarding family's second resolution pass ──────────────────────
//
// See `reresolve_forwarding`. Every case here writes a rules file whose two
// halves disagree about *which* URL they are about, which is the only way to
// tell the two passes apart at all.

/// A `ReqInfo` for a URL that carries a port of its own — which every case
/// below needs, because the two origins it plays off differ only by port.
fn req_at(url: &str) -> ReqInfo {
    let (scheme, rest) = url.split_once("://").expect("a scheme");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, p.parse().expect("a port"))
        }
        _ => (authority, if scheme == "https" { 443 } else { 80 }),
    };
    build_req_info("GET", scheme, host, port, path, &HeaderMap::new(), None)
}

/// `rules` resolved for `url`, then the forwarding family resolved again
/// against wherever a replacement moved the request.
///
/// The assertion is the inertness guard: a case whose replacement rule never
/// fires would exercise nothing and pass anyway.
fn second_pass(rules: &str, url: &str) -> Resolved {
    let mut m = RuleManager::new();
    m.set_text(rules);
    let info = req_at(url);
    let resolved = m.resolve(&info);
    let dest = crate::proxy::dest::Destination::of(&info, &resolved);
    assert!(dest.replaced, "the rules must actually move the request");
    reresolve_forwarding(&resolved, &dest.moved_req_info(&info), &m, &[], false)
}

/// The whole arrangement `crate::proxy::forwarding_resolution` sets up, so
/// that one case proves the second pass reaches the connection decision and
/// not merely the resolved set.
fn forwarded_target(rules: &str, url: &str) -> Target {
    let mut m = RuleManager::new();
    m.set_text(rules);
    let info = req_at(url);
    let resolved = m.resolve(&info);
    let dest = crate::proxy::dest::Destination::of(&info, &resolved);
    let forwarding = match dest.replaced {
        true => reresolve_forwarding(&resolved, &dest.moved_req_info(&info), &m, &[], false),
        false => resolved,
    };
    rt().block_on(resolve_target(&info, &dest, &forwarding))
        .expect("resolve_target")
}

const MOVED: &str = "a.com/ http://b.com:9311/echo\n";

#[test]
fn a_proxy_only_the_replacement_matches_is_the_one_used() {
    let r = second_pass(
        &format!("{MOVED}b.com proxy://127.0.0.1:9310\n"),
        "http://a.com/x",
    );
    assert_eq!(r.value("proxy"), Some("127.0.0.1:9310"));
}

#[test]
fn a_proxy_only_the_original_matched_is_dropped() {
    let r = second_pass(
        &format!("{MOVED}a.com proxy://127.0.0.1:9310\n"),
        "http://a.com/x",
    );
    assert_eq!(r.value("proxy"), None);
}

/// The first pass's answer is replaced, not merged: upstream deletes `proxy`
/// and `pac` outright and drops a `host` the second pass did not find again.
#[test]
fn the_host_the_original_matched_is_dropped() {
    let r = second_pass(&format!("{MOVED}a.com host://1.2.3.4\n"), "http://a.com/x");
    assert_eq!(r.value("host"), None);
}

#[test]
fn the_replacements_host_beats_the_originals() {
    let rules = format!("{MOVED}b.com host://1.2.3.4\na.com host://9.9.9.9\n");
    assert_eq!(
        second_pass(&rules, "http://a.com/x").value("host"),
        Some("1.2.3.4")
    );
}

#[test]
fn a_pac_rule_is_matched_against_the_replacement_too() {
    let hit = format!("{MOVED}b.com pac://http://127.0.0.1:9316/p.pac\n");
    let miss = format!("{MOVED}a.com pac://http://127.0.0.1:9316/p.pac\n");
    assert!(second_pass(&hit, "http://a.com/x").value("pac").is_some());
    assert_eq!(second_pass(&miss, "http://a.com/x").value("pac"), None);
}

/// Only the forwarding family moves. Everything else keeps what the
/// request's own URL matched, which is what leaves `cipher://` and the
/// request-header operators reading the URL the client asked for.
#[test]
fn the_rest_of_the_rule_set_is_left_on_the_first_pass() {
    let rules =
        format!("{MOVED}a.com reqHeaders://x-a=1 cipher://TLSv1.2\nb.com reqHeaders://x-b=2\n");
    let r = second_pass(&rules, "http://a.com/x");
    assert_eq!(r.value("reqHeaders"), Some("x-a=1"));
    assert_eq!(r.value("cipher"), Some("TLSv1.2"));
}

/// A line filter is re-read, because the second pass is a whole resolution
/// walk. The pattern matches both URLs so that only the filter decides.
#[test]
fn a_line_filter_is_re_read_against_the_replacement() {
    let tripped = format!("{MOVED}* proxy://127.0.0.1:9310 excludeFilter:///b\\.com/\n");
    let spent = format!("{MOVED}* proxy://127.0.0.1:9310 excludeFilter:///a\\.com/\n");
    assert_eq!(second_pass(&tripped, "http://a.com/x").value("proxy"), None);
    assert_eq!(
        second_pass(&spent, "http://a.com/x").value("proxy"),
        Some("127.0.0.1:9310")
    );
}

/// And so are the capture groups: `$1` is what the *replacement* URL put
/// there, which is the only reason to re-run the match rather than re-use
/// the operator the first pass produced.
#[test]
fn a_capture_group_is_taken_from_the_replacement() {
    let rules = format!("{MOVED}/^http:\\/\\/([a-z]+)\\.com/ host://$1.example\n");
    assert_eq!(
        second_pass(&rules, "http://a.com/x").value("host"),
        Some("b.example")
    );
}

/// End to end: the second pass reaches the connection decision, and the
/// `host://` it found applies to the *destination's* port rather than the
/// client's.
#[test]
fn the_second_pass_reaches_the_connection_decision() {
    let t = forwarded_target(&format!("{MOVED}b.com host://1.2.3.4\n"), "http://a.com/x");
    assert_eq!(t.connect_host, "1.2.3.4");
    assert_eq!(t.connect_port, 9311);
    // And with nothing matching the replacement, the address the request was
    // moved to is the one dialled.
    let t = forwarded_target(&format!("{MOVED}a.com host://1.2.3.4\n"), "http://a.com/x");
    assert_eq!(t.connect_host, "b.com");
    assert_eq!(t.connect_port, 9311);
}
