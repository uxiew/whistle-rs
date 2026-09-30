//! JavaScript scripting for `resScript` (and PAC evaluation).
//!
//! Ported in spirit from whistle's script hooks. A script runs in an embedded
//! JS engine (boa) with a global `ctx` object:
//!
//! ```js
//! // ctx = { req: { method, url }, res: { statusCode, headers, body } }
//! ctx.res.headers['x-scripted'] = '1';
//! ctx.res.body = ctx.res.body.replace(/foo/g, 'bar');
//! if (ctx.req.url.indexOf('/admin') >= 0) ctx.res.statusCode = 403;
//! ```
//!
//! After the script runs, whistle-rs reads `ctx.res` back and applies any
//! changed status / headers / body.
//!
//! # PAC
//!
//! [`find_proxy_for_url`] is the other user of the engine: it resolves a
//! `pac://` value (inline script, local file, or a remote `http(s)://` URL that
//! is fetched and cached) and calls the script's `FindProxyForURL(url, host)`
//! inside the helper environment a PAC file expects — [`PAC_HELPERS`].
//!
//! Both halves used to fail *open*. A remote URL was evaluated as if it were
//! JavaScript and a script calling anything beyond three helpers threw; either
//! way the failure was swallowed and the request went **direct**, past the proxy
//! the rule named, with nothing in the log. So the fallible parts return
//! `Result` here and the caller refuses the request instead of routing it
//! somewhere the rules did not ask for. See `docs/RULES.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use boa_engine::{Context, JsResult, JsString, JsValue, NativeFunction, Source, js_string};
use once_cell::sync::Lazy;
use serde_json::json;

// ── the engine every script runs in ────────────────────────────────────────

/// `Buffer`, `parseUrl`, `parseQuery` and the three `iconv` helpers, written in
/// JavaScript to the behaviour of Node's — see the file's own header.
const NODE_PRELUDE: &str = include_str!("script_prelude.js");

/// How many times one loop may go round before the engine stops the script
/// with an error.
///
/// whistle gives a script 60 ms of wall clock (`VM_OPTIONS.timeout`,
/// `_original/lib/util/index.js:423-426`). This engine cannot be interrupted
/// from outside, so the bound is on what it can count: a `while (true) {}`
/// used to hold its request — and, for a `frameScript`, its connection — for
/// ever. Three million iterations of an empty loop take 21 ms in a release
/// build on an M4 (`tests::cost_of_starting_a_script`), and a loop that does
/// something takes several times that — generous for a script that is building
/// a few rules, and far short of for ever.
///
/// It is per loop, not per script: two nested loops of two thousand each pass.
/// That is a hole a hostile script walks through and an honest one does not
/// find; the rules a script runs under are its author's own.
const LOOP_LIMIT: u64 = 3_000_000;

/// What every engine gets before anything else runs: the `RegExp` statics,
/// and the Node parts as **stubs that load on first use**.
///
/// Evaluating [`NODE_PRELUDE`] takes about 3 ms in a release build — it is
/// twelve hundred lines, and this engine compiles them every time, because a
/// compiled script cannot leave the thread it was compiled on. Most scripts
/// push a rule and never name `Buffer`; charging each of them that is how a
/// `reqScript` would come to cost more than the request it decorates. So each
/// name starts as a small function that, the first time it is called, compiles
/// the real thing and hands over to it.
const BOOTSTRAP: &str = r#"
(function (global) {
  'use strict';

  // ── RegExp.$1 and its relatives ─────────────────────────────────────────
  //
  // The legacy statics V8 keeps and this engine does not. whistle's own source
  // leans on them throughout (`REG_EXP_RE.test(x); … RegExp.$1`), and a script
  // written beside it does the same. Every way of running a regexp — `test`,
  // `match`, `replace`, `split`, `search` — reaches `exec` through the
  // property, so recording there covers them all.
  var exec = RegExp.prototype.exec;
  var R = RegExp;
  var statics = ['input', '$_', 'lastMatch', '$&', 'lastParen', '$+', 'leftContext', '$`', 'rightContext', "$'"];
  var i;
  for (i = 0; i < statics.length; i++) {
    R[statics[i]] = '';
  }
  for (i = 1; i <= 9; i++) {
    R['$' + i] = '';
  }
  RegExp.prototype.exec = function (str) {
    var m = exec.call(this, str);
    if (m) {
      var text = m.input;
      R.input = R.$_ = text;
      R.lastMatch = R['$&'] = m[0];
      for (var n = 1; n <= 9; n++) {
        R['$' + n] = m[n] === undefined ? '' : m[n];
      }
      var last = m.length > 1 ? m[m.length - 1] : '';
      R.lastParen = R['$+'] = last === undefined ? '' : last;
      R.leftContext = R['$`'] = text.slice(0, m.index);
      R.rightContext = R["$'"] = text.slice(m.index + m[0].length);
    }
    return m;
  };

  // ── the Node parts, on demand ───────────────────────────────────────────
  //
  // Every name is an ordinary data property from the start, holding a stub
  // that loads the real thing and calls it; loading then only changes values.
  // (Accessors that replaced themselves were tried first, and tripped the
  // engine's inline caches: the second call from one call site threw.)
  var source = global.__nodePrelude;
  delete global.__nodePrelude;
  // Indirect `eval`, so the source runs at global scope. It is the engine's
  // own way of compiling more code mid-script; evaluating from a native
  // function instead re-enters the VM in a way this engine panics on.
  var indirectEval = eval;
  var stubs = {};
  var loaded = false;
  var host = {
    Buffer: Buffer,
    construct: null,
    define: function (real) {
      Object.keys(real).forEach(function (name) {
        // A name the script took for itself stays the script's.
        if (global[name] === stubs[name]) {
          global[name] = real[name];
        }
      });
    }
  };
  function load() {
    if (!loaded) {
      loaded = true;
      indirectEval(source)(global, host);
    }
  }

  function Buffer(value, encodingOrOffset, length) {
    load();
    return host.construct(value, encodingOrOffset, length);
  }
  Buffer.prototype = Object.create(Uint8Array.prototype, {
    constructor: { value: Buffer, writable: true, configurable: true }
  });
  Object.setPrototypeOf(Buffer, Uint8Array);
  ['from', 'alloc', 'allocUnsafe', 'allocUnsafeSlow', 'isBuffer', 'isEncoding', 'byteLength', 'concat', 'compare'].forEach(
    function (name) {
      var stub = function () {
        load();
        var real = Buffer[name];
        if (real === stub) {
          throw new Error('Buffer.' + name + ' is not available');
        }
        return real.apply(Buffer, arguments);
      };
      Buffer[name] = stub;
    }
  );
  global.Buffer = Buffer;

  ['decodeBuffer', 'encodeString', 'encodingExists', 'parseQuery', 'parseUrl'].forEach(function (name) {
    var stub = function () {
      load();
      var real = global[name];
      if (real === stub) {
        throw new Error(name + ' is not available');
      }
      return real.apply(this, arguments);
    };
    stubs[name] = stub;
    global[name] = stub;
  });
})(this);
"#;

/// A fresh engine with the loop bound set and the Node parts a script is
/// written against — [`BOOTSTRAP`].
///
/// `None` only if the bootstrap itself fails, which is a bug here rather than
/// in anyone's script; it is logged as one.
pub(crate) fn script_engine() -> Option<Context> {
    let mut ctx = Context::default();
    ctx.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_LIMIT);
    type Native = fn(&JsValue, &[JsValue], &mut Context) -> JsResult<JsValue>;
    let natives: [(&str, usize, Native); 5] = [
        ("__utf8Encode", 1, js_utf8_encode),
        ("__utf8Decode", 1, js_utf8_decode),
        ("__iconvEncode", 2, js_iconv_encode),
        ("__iconvDecode", 2, js_iconv_decode),
        ("__encodingExists", 1, js_encoding_exists),
    ];
    for (name, length, function) in natives {
        ctx.register_global_callable(
            JsString::from(name),
            length,
            NativeFunction::from_fn_ptr(function),
        )
        .ok()?;
    }
    ctx.global_object()
        .set(
            js_string!("__nodePrelude"),
            JsString::from(NODE_PRELUDE),
            false,
            &mut ctx,
        )
        .ok()?;
    if let Err(err) = ctx.eval(Source::from_bytes(BOOTSTRAP.as_bytes())) {
        tracing::error!("the script bootstrap does not evaluate: {err}");
        return None;
    }
    Some(ctx)
}

/// Bytes as a JavaScript "binary string": one code unit per byte. The form
/// bytes take between this side and `script_prelude.js`.
fn binary_string(bytes: &[u8]) -> JsString {
    let units: Vec<u16> = bytes.iter().map(|b| u16::from(*b)).collect();
    JsString::from(&units[..])
}

/// The bytes of a binary string. A code unit above 255 cannot come from the
/// prelude; if one arrives it is truncated, as `Buffer.from(s, 'latin1')` does.
fn binary_bytes(text: &JsString) -> Vec<u8> {
    text.to_vec().into_iter().map(|unit| unit as u8).collect()
}

fn arg_string(args: &[JsValue], at: usize, ctx: &mut Context) -> JsResult<JsString> {
    args.get(at).cloned().unwrap_or_default().to_string(ctx)
}

/// `Buffer.from(str, 'utf8')`: a lone surrogate becomes U+FFFD, as in Node.
fn js_utf8_encode(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let text = arg_string(args, 0, ctx)?.to_std_string_lossy();
    Ok(binary_string(text.as_bytes()).into())
}

/// `buf.toString('utf8')`: a byte sequence that is not UTF-8 becomes U+FFFD.
fn js_utf8_decode(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let bytes = binary_bytes(&arg_string(args, 0, ctx)?);
    Ok(JsString::from(String::from_utf8_lossy(&bytes).as_ref()).into())
}

/// An `iconv-lite` encoding, as far as this port can serve one.
#[derive(Clone, Copy)]
enum Codec {
    /// One of the Encoding Standard's, by `encoding_rs`.
    Standard(&'static encoding_rs::Encoding),
    /// ISO-8859-1 proper: a byte is its own code point. Not the Encoding
    /// Standard's `latin1`, which is windows-1252 and puts `€` at 0x80.
    Latin1,
    /// Seven bits. A byte above 0x7F decodes to U+FFFD.
    Ascii,
}

/// The codec for an `iconv-lite` encoding name, where there is one.
///
/// iconv-lite squeezes a name down to its letters and digits before looking it
/// up, so `GB-2312`, `gb_2312` and `gb2312` are one name; the WHATWG labels
/// `encoding_rs` answers to are stricter, and its spellings of the Windows
/// code pages differ. The few aliases here are the ones people type.
fn codec_for(label: &str) -> Option<Codec> {
    let label = label.trim().to_ascii_lowercase();
    let squeezed: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // Before the standard labels, which call all of these windows-1252.
    match squeezed.as_str() {
        "latin1" | "iso88591" | "l1" | "cp819" | "ibm819" => return Some(Codec::Latin1),
        "ascii" | "usascii" | "ascii8bit" | "ansix341968" | "646" => return Some(Codec::Ascii),
        _ => {}
    }
    if let Some(found) = encoding_rs::Encoding::for_label(label.as_bytes()) {
        return Some(Codec::Standard(found));
    }
    let digits = |prefix: &str| {
        squeezed
            .strip_prefix(prefix)
            .filter(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_string)
    };
    let alias = match squeezed.as_str() {
        "cp936" | "ms936" | "windows936" | "gb2312" | "gbk" => "gbk".to_string(),
        "cp950" | "big5" | "big5hkscs" => "big5".to_string(),
        "cp932" | "ms932" | "sjis" | "shiftjis" | "windows31j" => "shift_jis".to_string(),
        "cp949" | "euckr" | "ksc56011987" => "euc-kr".to_string(),
        "eucjp" => "euc-jp".to_string(),
        "gb18030" => "gb18030".to_string(),
        "utf16" | "utf16le" | "ucs2" => "utf-16le".to_string(),
        "utf16be" => "utf-16be".to_string(),
        "utf8" => "utf-8".to_string(),
        "koi8r" => "koi8-r".to_string(),
        "koi8u" => "koi8-u".to_string(),
        "macintosh" | "macroman" => "macintosh".to_string(),
        _ => {
            if let Some(n) = digits("win").or_else(|| digits("windows")) {
                format!("windows-{n}")
            } else if let Some(n) = digits("cp125") {
                format!("windows-125{n}")
            } else {
                format!("iso-8859-{}", digits("iso8859")?)
            }
        }
    };
    encoding_rs::Encoding::for_label(alias.as_bytes()).map(Codec::Standard)
}

/// `iconv.encode(text, encoding)`: a character the encoding cannot hold is a
/// `?`, which is iconv-lite's default (`encoding_rs`'s own is an HTML numeric
/// reference, the right answer for a form submission and the wrong one here).
fn iconv_encode(codec: Codec, text: &str) -> Vec<u8> {
    let encoding = match codec {
        Codec::Standard(encoding) => encoding,
        Codec::Latin1 | Codec::Ascii => {
            let top = if matches!(codec, Codec::Ascii) {
                0x7f
            } else {
                0xff
            };
            return text
                .chars()
                .map(|c| if c as u32 <= top { c as u8 } else { b'?' })
                .collect();
        }
    };
    // `encoding_rs` follows the Encoding Standard, under which nothing is ever
    // *encoded* as UTF-16 — asking gets UTF-8 back. iconv does encode it.
    if encoding == encoding_rs::UTF_16LE {
        return text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    }
    if encoding == encoding_rs::UTF_16BE {
        return text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    }
    let mut encoder = encoding.new_encoder();
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        let need = encoder
            .max_buffer_length_from_utf8_without_replacement(rest.len())
            .unwrap_or(rest.len() * 4 + 16);
        out.reserve(need);
        let (result, read) =
            encoder.encode_from_utf8_to_vec_without_replacement(rest, &mut out, true);
        rest = &rest[read..];
        match result {
            encoding_rs::EncoderResult::InputEmpty => return out,
            encoding_rs::EncoderResult::OutputFull => {}
            encoding_rs::EncoderResult::Unmappable(_) => out.push(b'?'),
        }
    }
}

/// `iconv.decode(bytes, encoding)`. Bytes the encoding cannot explain become
/// U+FFFD.
fn iconv_decode(codec: Codec, bytes: &[u8]) -> String {
    match codec {
        Codec::Standard(encoding) => encoding.decode_without_bom_handling(bytes).0.into_owned(),
        Codec::Latin1 => bytes.iter().map(|b| char::from(*b)).collect(),
        Codec::Ascii => bytes
            .iter()
            .map(|b| {
                if b.is_ascii() {
                    char::from(*b)
                } else {
                    '\u{fffd}'
                }
            })
            .collect(),
    }
}

/// `__iconvEncode(text, encoding)` → a binary string, or `null` for an
/// encoding nobody knows.
fn js_iconv_encode(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let text = arg_string(args, 0, ctx)?.to_std_string_lossy();
    let label = arg_string(args, 1, ctx)?.to_std_string_lossy();
    Ok(match codec_for(&label) {
        Some(codec) => binary_string(&iconv_encode(codec, &text)).into(),
        None => JsValue::null(),
    })
}

/// `__iconvDecode(bytes, encoding)` → the text, or `null` for an encoding
/// nobody knows.
fn js_iconv_decode(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let bytes = binary_bytes(&arg_string(args, 0, ctx)?);
    let label = arg_string(args, 1, ctx)?.to_std_string_lossy();
    Ok(match codec_for(&label) {
        Some(codec) => JsString::from(iconv_decode(codec, &bytes).as_str()).into(),
        None => JsValue::null(),
    })
}

fn js_encoding_exists(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let label = arg_string(args, 0, ctx)?.to_std_string_lossy();
    Ok(codec_for(&label).is_some().into())
}

/// What a response script changed.
pub struct ScriptResult {
    pub status: Option<u16>,
    /// Headers to set/replace (empty value deletes, matching header ops).
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Resolve a script operator value to source: read the file if it exists,
/// otherwise treat the value itself as inline JavaScript.
pub fn load_script(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(src) = std::fs::read_to_string(value) {
        return Some(src);
    }
    Some(value.to_string())
}

/// Run a `resScript` against the current response, returning any changes.
/// Returns `None` if the script errored (the response is then left unchanged).
pub fn run_res_script(
    src: &str,
    method: &str,
    url: &str,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) -> Option<ScriptResult> {
    let mut ctx = script_engine()?;

    let hdr_obj: serde_json::Map<String, serde_json::Value> = headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let ctx_json = json!({
        "req": { "method": method, "url": url },
        "res": { "statusCode": status, "headers": hdr_obj, "body": body }
    });

    let jsval = boa_engine::JsValue::from_json(&ctx_json, &mut ctx).ok()?;
    ctx.global_object()
        .set(js_string!("ctx"), jsval, false, &mut ctx)
        .ok()?;

    if let Err(err) = ctx.eval(Source::from_bytes(src.as_bytes())) {
        tracing::debug!("resScript error: {err}");
        return None;
    }

    let ctx_val = ctx.global_object().get(js_string!("ctx"), &mut ctx).ok()?;
    let out = ctx_val.to_json(&mut ctx).ok()??;
    let res = out.get("res")?;

    let status = res
        .get("statusCode")
        .and_then(|v| v.as_u64())
        .map(|n| n as u16);
    let mut new_headers = Vec::new();
    if let Some(h) = res.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in h {
            let val = v
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| v.to_string());
            new_headers.push((k.clone(), val));
        }
    }
    let body = res
        .get("body")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(ScriptResult {
        status,
        headers: new_headers,
        body,
    })
}

/// Is this text a rules *text*, as opposed to JavaScript that produces one?
///
/// Upstream's `isRulesContent` (`_original/lib/rules/index.js:41-43`), term for
/// term: rules text when it contains no `(` or `[` anywhere, **or** starts with
/// a `#` comment, **or** any line starts with a ``` `` ``` fence, **or** never
/// says the word `rules` or `values`. Only a bracketed, unfenced, uncommented
/// text that names one of the two context arrays is executed.
///
/// The test is deliberately loose in upstream and reproduced loosely here: a
/// rules file that happens to write `values` inside a `(...)` payload would be
/// executed there too, and the honest move is to be wrong in the same place.
pub fn is_rules_content(text: &str) -> bool {
    let bracketed = text.contains('(') || text.contains('[');
    if !bracketed {
        return true;
    }
    if text.trim_start().starts_with('#') {
        return true;
    }
    if text.lines().any(|l| l.trim_start().starts_with("``")) {
        return true;
    }
    !has_script_word(text)
}

/// Is this `resScript` text this port's response hook, rather than rules?
///
/// Upstream has no hook: a `resScript://` text is rules, or a script that
/// produces them ([`is_rules_content`] tells the two apart). This port's hook
/// — JavaScript that edits `ctx.res` — is shaped like rules by that test,
/// because it names neither `rules` nor `values`, so the test alone cannot
/// keep it apart from a real rules text. The word `ctx` does: a hook cannot
/// work without it, and a rules text has no reason to say it. Upstream's own
/// `frameScript` asks the same question the same way (`CTX_RE`,
/// `_original/lib/rules/index.js:449-453`).
///
/// Before this, every rules-shaped `resScript` was run as a hook — upstream's
/// `tps.test.js` hands it `# rules\n… jsAppend://…`, which the JS engine
/// rejected, and nothing was appended.
pub fn is_response_hook(text: &str) -> bool {
    is_rules_content(text) && has_word(text, &["ctx"])
}

/// `/\b(?:rules|values)\b/` without pulling in a regex: the word with no
/// `[A-Za-z0-9_]` on either side.
fn has_script_word(text: &str) -> bool {
    has_word(text, &["rules", "values"])
}

/// Does `text` say any of `words` as a word of its own?
fn has_word(text: &str, words: &[&str]) -> bool {
    let bytes = text.as_bytes();
    let word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for &word in words {
        let mut from = 0;
        while let Some(i) = text[from..].find(word) {
            let at = from + i;
            let before_ok = at == 0 || !word_byte(bytes[at - 1]);
            let end = at + word.len();
            let after_ok = end >= bytes.len() || !word_byte(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            from = at + 1;
        }
    }
    false
}

/// What a rules-producing script gets to look at — upstream's
/// `getScriptContext` (`_original/lib/rules/index.js:349-416`).
pub struct RulesScriptCtx<'a> {
    pub method: &'a str,
    pub full_url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a str,
    pub client_ip: Option<&'a str>,
    pub client_port: Option<u16>,
    /// `None` in the request pass; the response head once there is one.
    pub res: Option<RulesScriptRes<'a>>,
    /// The values store, for `getValue(name)` — inline blocks and the console's
    /// Values pane both, which is the pair upstream's own `getValue` asks
    /// (`_original/lib/rules/index.js:398-401`).
    pub values: &'a std::collections::HashMap<String, String>,
    /// The request's `reqScriptData` — see [`crate::rules::ReqInfo::script_data`].
    pub script_data: &'a Mutex<serde_json::Value>,
    /// The pattern of the rule line the script was written on — upstream's
    /// `script.rawPattern`. `example.com/api` for
    /// `example.com/api reqScript://{x.js}`.
    pub pattern: &'a str,
    /// What the script may know about the proxy it runs in.
    pub env: &'a crate::rules::ScriptEnv,
}

/// The response third of the context, present only in the `resScript` pass.
pub struct RulesScriptRes<'a> {
    pub status: u16,
    pub server_ip: Option<&'a str>,
    pub headers: &'a [(String, String)],
}

/// Run a rules-producing script and return the rules text it pushed.
///
/// Upstream evaluates the source in a vm context holding `rules = []` and reads
/// the array back joined with `\n` (`execRulesScript`,
/// `_original/lib/rules/index.js:434-446`). Two behaviours are load-bearing and
/// were measured before this was written, not assumed:
///
/// * **an error discards everything** — a script that pushes a rule and then
///   throws produces no rules at all, because `execScriptSync` returns
///   `undefined` from its catch and the caller turns that into `''`;
/// * **what the script sets on `values` answers the `{name}` references in the
///   rules it pushed**, and nothing else's — see [`produce_rules`]. (This used to
///   say the opposite, from a probe that wrote `x-v={m}`: a reference only
///   resolves as the *whole* operator value, so that line proved nothing, and
///   upstream's own suite — `test/units/script.test.js` — asks exactly this.)
///
/// The context is upstream's, name for name. `Buffer`, `parseUrl`,
/// `parseQuery`, `decodeBuffer`, `encodeString` and `encodingExists` come from
/// [`script_engine`]; the rest is filled in here. Until 2026-09-30 the first
/// and the last three were missing (a script naming one threw and produced
/// nothing), `parseQuery` kept only the last of a repeated key and left `+`
/// alone, `parseUrl` left `user:pw@` in the host name, and `pattern` and `port`
/// were `''` and `0`.
pub fn run_rules_script(src: &str, input: &RulesScriptCtx<'_>) -> Option<String> {
    produce_rules(src, input).map(|produced| produced.rules)
}

/// What a rules script left behind.
pub struct Produced {
    /// The lines it pushed, joined — upstream's `rules.join('\n').trim()`.
    pub rules: String,
    /// What it set on `values`, private to `rules`: upstream parses the pushed
    /// text into a rule set constructed with them (`resolveRulesFile`,
    /// `_original/lib/rules/index.js:520-529`), and this port gives the text a
    /// scope of its own ([`crate::rules::RuleManager::adopt_scope`]). An object
    /// is its JSON, as `getValueFor` serialises one (`rules.js:785-796`); `null`
    /// and `undefined` are no entry.
    pub values: HashMap<String, String>,
}

/// The values a script's `getValue` reads, as the two maps upstream asks in
/// turn: the ``` blocks of the rules text, then the Values store
/// (`_original/lib/rules/index.js:398-401`). `getValue(key, true)` skips the
/// first.
///
/// An inline block's key carries the group it was declared in
/// (`crate::rules::inline_key`) and a script asks by the plain name, so a
/// block is offered under its plain name. A block `--value` overrides is
/// already gone from the map.
fn value_maps(values: &HashMap<String, String>) -> (serde_json::Value, serde_json::Value) {
    let mut store = serde_json::Map::new();
    for (name, content) in values {
        if crate::rules::inline_key_name(name).is_none() {
            store.insert(name.clone(), serde_json::Value::String(content.clone()));
        }
    }
    // Sorted, so that two groups declaring the same name settle it the same
    // way every time rather than by hash order.
    let mut blocks: Vec<(&str, &String)> = values
        .iter()
        .filter_map(|(key, content)| Some((crate::rules::inline_key_name(key)?, content)))
        .collect();
    blocks.sort();
    blocks.dedup_by_key(|(name, _)| *name);
    let inline: serde_json::Map<String, serde_json::Value> = blocks
        .into_iter()
        .map(|(plain, content)| {
            (
                plain.to_string(),
                serde_json::Value::String(content.clone()),
            )
        })
        .collect();
    (
        serde_json::Value::Object(inline),
        serde_json::Value::Object(store),
    )
}

/// The helpers a script may call that are about *this request* rather than
/// about Node — everything else is [`NODE_PRELUDE`].
const REQUEST_GLUE: &str = r#"
    var console = { log: function(){}, info: function(){}, warn: function(){},
                    error: function(){}, debug: function(){}, fatal: function(){} };
    // `ctx.value = req.globalValue`: there, and `undefined`, unless the request
    // carries one. Reading it must not be a ReferenceError.
    var value;
    function getValue(key, onlyValues) {
        var v = onlyValues ? undefined : __inlineValues[key];
        if (typeof v !== 'string') v = __storeValues[key];
        return typeof v === 'string' ? v : undefined;
    }
    function isLocalAddress(addr) {
        addr = String(addr == null || addr === '' ? ip : addr).toLowerCase();
        if (addr[0] === '[') addr = addr.slice(1, -1);
        return addr === '127.0.0.1' || addr === '0.0.0.0' || addr === 'localhost'
            || addr === '::1' || addr === '0:0:0:0:0:0:0:1' || addr === '::'
            || /^127\./.test(addr) || (!!__localIp && addr === __localIp);
    }
    // whistle's `tpl` (`_original/lib/rules/index.js:304-347`), the same
    // source transformation: `<% … %>` is code, `<%= … %>` interpolates,
    // and a string with no `<%` and `%>` in it is returned as it came. The
    // newline dance is upstream's — lines become tabs so the generated
    // function is one line, and the tabs come back at the end.
    var __tplCache = {};
    function tpl(str, data) {
        if (typeof str !== 'string' || str.indexOf('<%') === -1 || str.indexOf('%>') === -1) {
            return str + '';
        }
        var fn = __tplCache[str];
        if (!fn) {
            var body = str
                .replace(/[\u2028\u2029]/g, '')
                .replace(/\t/g, ' ')
                .replace(/\r?\n|\r/g, '\t')
                .split('<%')
                .join('\u2028')
                .replace(/((^|%>)[^\u2028]*)'/g, '$1\r')
                .replace(/\u2028=(.*?)%>/g, '\',$1,\'')
                .split('\u2028')
                .join('\');')
                .split('%>')
                .join('p.push(\'')
                .split('\r')
                .join('\\\'');
            fn = new Function(
                'obj',
                'var p=[],print=function(){p.push.apply(p,arguments);};'
                    + 'with(obj){p.push(\'' + body + '\');}return p.join(\'\');'
            );
            __tplCache[str] = fn;
        }
        return fn(data || {}).replace(/\t/g, '\n');
    }
    var render = tpl;
"#;

/// Put each property of `globals` on the engine's global object.
fn set_globals(ctx: &mut Context, globals: &serde_json::Value) -> Option<()> {
    let obj = JsValue::from_json(globals, ctx).ok()?;
    let obj = obj.as_object()?.clone();
    for key in obj.own_property_keys(ctx).ok()? {
        let val = obj.get(key.clone(), ctx).ok()?;
        ctx.global_object().set(key, val, false, ctx).ok()?;
    }
    Some(())
}

/// The part of upstream's script context that describes the request — shared
/// by the rules scripts and by `frameScript`, which upstream builds from the
/// same `getScriptContext`.
fn request_globals(input: &RulesScriptCtx<'_>) -> serde_json::Value {
    let headers: serde_json::Map<String, serde_json::Value> = input
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    // Request side gets empty *strings* for the response fields, exactly as
    // upstream writes them (`rules/index.js:406-414`) — a script comparing
    // `statusCode == 200` in the request pass must see `'' == 200`, false.
    let (status, server_ip, res_headers) = match &input.res {
        Some(res) => (
            json!(res.status),
            json!(res.server_ip.unwrap_or("127.0.0.1")),
            json!(
                res.headers
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect::<serde_json::Map<_, _>>()
            ),
        ),
        None => (json!(""), json!(""), json!("")),
    };
    let ip = input.client_ip.unwrap_or("127.0.0.1");
    let script_data = match input.script_data.lock().map(|d| d.clone()) {
        Ok(data @ serde_json::Value::Object(_)) => data,
        _ => json!({}),
    };
    let (inline, store) = value_maps(input.values);
    let env = input.env;
    json!({
        "url": input.full_url,
        "fullUrl": input.full_url,
        "method": if input.method.is_empty() { "GET".to_string() } else { input.method.to_ascii_uppercase() },
        // `req.httpVersion || '1.1'`: what the *client* spoke.
        "httpVersion": if env.http_version.is_empty() { "1.1" } else { env.http_version },
        "headers": headers,
        "reqHeaders": headers,
        "body": input.body,
        "ip": ip,
        "clientIp": ip,
        "clientPort": input.client_port.unwrap_or(0),
        "pattern": input.pattern,
        "version": crate::config::VERSION,
        "port": env.proxy_port,
        "uiPort": env.ui_port,
        "uiHost": "local.wproxy.org",
        "reqScriptData": script_data,
        "res": null,
        "statusCode": status,
        "serverIp": server_ip,
        "resHeaders": res_headers,
        "__inlineValues": inline,
        "__storeValues": store,
        "__localIp": crate::proxy::upstream::primary_local_ip().map(|ip| ip.to_string()),
    })
}

/// [`run_rules_script`], with the values the script set.
pub fn produce_rules(src: &str, input: &RulesScriptCtx<'_>) -> Option<Produced> {
    let mut ctx = script_engine()?;
    let mut globals = request_globals(input);
    globals["rules"] = json!([]);
    globals["values"] = json!({});
    set_globals(&mut ctx, &globals)?;
    ctx.eval(Source::from_bytes(REQUEST_GLUE.as_bytes())).ok()?;

    let ran = ctx.eval(Source::from_bytes(src.as_bytes()));
    // Kept whether or not the script finished: upstream's context is the same
    // object before and after, so a write that happened before a throw stays.
    if let Some(data @ serde_json::Value::Object(_)) = ctx
        .global_object()
        .get(js_string!("reqScriptData"), &mut ctx)
        .ok()
        .and_then(|v| v.to_json(&mut ctx).ok().flatten())
        && let Ok(mut shared) = input.script_data.lock()
    {
        *shared = data;
    }
    if let Err(err) = ran {
        tracing::debug!("rules script error: {err}");
        return None;
    }

    let rules = ctx
        .global_object()
        .get(js_string!("rules"), &mut ctx)
        .ok()?;
    let rules = rules.to_json(&mut ctx).ok()??;
    let lines: Vec<String> = rules
        .as_array()?
        .iter()
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect();
    let values = ctx
        .global_object()
        .get(js_string!("values"), &mut ctx)
        .ok()
        .and_then(|v| v.to_json(&mut ctx).ok().flatten());
    let values = match values {
        Some(serde_json::Value::Object(map)) => map
            .into_iter()
            .filter_map(|(name, value)| match value {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => Some((name, s)),
                other => Some((name, other.to_string())),
            })
            .collect(),
        _ => HashMap::new(),
    };
    Some(Produced {
        rules: lines.join("\n").trim().to_string(),
        values,
    })
}

/// What a `frameScript` decided about one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameAction {
    /// Deliver it as it came — the script said nothing about it.
    Keep,
    /// Deliver this instead.
    Replace(String),
    /// Deliver nothing: upstream's handler returned a falsy value, and
    /// `cb(null, chunk || null)` then writes nothing
    /// (`_original/lib/socket-mgr.js:198-206`).
    Drop,
}

/// The two shapes a `frameScript` may be written in, as JavaScript.
///
/// **Upstream's** is a pair of handlers installed on `ctx`
/// (`frameScript.md`, and `execHandleFrame`,
/// `_original/lib/socket-mgr.js:303-323`): `handleSendToServerFrame` for the
/// client's frames and `handleSendToClientFrame` for the server's, each
/// receiving `(data, opts)` and returning the frame to deliver — or a falsy
/// value to deliver nothing. `ctx.sendToServer` / `ctx.sendToClient` inject a
/// frame of their own; see [`frame_script_injections`].
///
/// **This port's** is `ctx.frame.data`, assigned in place. Both are supported:
/// a script that installs a handler is read as upstream reads it, and one that
/// assigns `ctx.frame.data` is read as this port's own documentation describes.
/// A script doing both gets the handler's answer, because that is the one the
/// other program would honour.
const FRAME_CTX: &str = r#"
    var __injected = [];
    var ctx = {
        direction: __direction,
        frame: { data: __data },
        sendToServer: function (d) { __injected.push(['send', String(d)]); },
        sendToClient: function (d) { __injected.push(['receive', String(d)]); },
        handleSendToServerFrame: null,
        handleSendToClientFrame: null
    };
"#;

/// Run a `frameScript` against one WebSocket text frame.
///
/// `direction` is `"send"` (client → server) or `"receive"`.
pub fn run_frame_script(src: &str, direction: &str, data: &str) -> FrameAction {
    let mut ctx = Context::default();
    let set = |ctx: &mut Context, name: &str, value: &str| {
        let v = boa_engine::JsValue::from_json(&json!(value), ctx).ok()?;
        ctx.global_object()
            .set(js_string!(name), v, false, ctx)
            .ok()
    };
    if set(&mut ctx, "__direction", direction).is_none() || set(&mut ctx, "__data", data).is_none()
    {
        return FrameAction::Keep;
    }
    if ctx.eval(Source::from_bytes(FRAME_CTX.as_bytes())).is_err() {
        return FrameAction::Keep;
    }
    if ctx.eval(Source::from_bytes(src.as_bytes())).is_err() {
        return FrameAction::Keep;
    }
    // The handler shape first: it is the one a script copied from the whistle
    // documentation uses, and the one whose falsy answer means "drop".
    let handler = match direction {
        "send" => "handleSendToServerFrame",
        _ => "handleSendToClientFrame",
    };
    let call = format!(
        "(function () {{
            var f = ctx.{handler};
            if (typeof f !== 'function') return null;
            var out = f(ctx.frame.data, {{}});
            return out ? String(out) : '';
        }})()"
    );
    if let Ok(value) = ctx.eval(Source::from_bytes(call.as_bytes()))
        && !value.is_null()
        && let Ok(text) = value.to_string(&mut ctx)
    {
        let text = text.to_std_string_escaped();
        return match text.is_empty() {
            true => FrameAction::Drop,
            false => FrameAction::Replace(text),
        };
    }
    // …and otherwise this port's own shape. Read by evaluating the path rather
    // than by serialising `ctx`: it now carries functions, and an object with a
    // function in it is not JSON.
    let Ok(value) = ctx.eval(Source::from_bytes(b"ctx.frame.data")) else {
        return FrameAction::Keep;
    };
    let Ok(text) = value.to_string(&mut ctx) else {
        return FrameAction::Keep;
    };
    let text = text.to_std_string_escaped();
    match text != data {
        true => FrameAction::Replace(text),
        false => FrameAction::Keep,
    }
}

/// The frames a `frameScript` injects on its own, evaluated **once** when the
/// connection opens.
///
/// `ctx.sendToServer(data)` / `ctx.sendToClient(data)` at the top of a script
/// send a frame nobody asked for, which is how `frameScript.md`'s own example
/// opens. Returned as `(direction, payload)` pairs in the order they were
/// called, for the leg that writes each one.
pub fn frame_script_injections(src: &str) -> Vec<(String, String)> {
    let mut ctx = Context::default();
    let set = |ctx: &mut Context, name: &str, value: &str| {
        let v = boa_engine::JsValue::from_json(&json!(value), ctx).ok()?;
        ctx.global_object()
            .set(js_string!(name), v, false, ctx)
            .ok()
    };
    // The connection has no frame yet, and a script that reads `ctx.frame.data`
    // here sees an empty one rather than failing.
    if set(&mut ctx, "__direction", "").is_none() || set(&mut ctx, "__data", "").is_none() {
        return Vec::new();
    }
    if ctx.eval(Source::from_bytes(FRAME_CTX.as_bytes())).is_err()
        || ctx.eval(Source::from_bytes(src.as_bytes())).is_err()
    {
        return Vec::new();
    }
    let Ok(value) = ctx.global_object().get(js_string!("__injected"), &mut ctx) else {
        return Vec::new();
    };
    let Ok(Some(json)) = value.to_json(&mut ctx) else {
        return Vec::new();
    };
    json.as_array()
        .map(|pairs| {
            pairs
                .iter()
                .filter_map(|pair| {
                    let dir = pair.get(0)?.as_str()?.to_string();
                    let data = pair.get(1)?.as_str()?.to_string();
                    Some((dir, data))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── PAC ────────────────────────────────────────────────────────────────────

/// The functions a PAC file is entitled to assume, per the original Netscape
/// specification (and the Microsoft `*Ex` extensions, mapped onto the IPv4
/// helpers this port has).
///
/// They are defined *before* the PAC source is evaluated, so a script that
/// ships its own copy of one — some do, defensively — overrides ours rather
/// than being overridden by it.
///
/// `dnsResolve` and `alert` are native (see [`register_pac_natives`]);
/// everything reachable from JavaScript is written here, close to the spec
/// wording, because that is easier to check against the spec than Rust would be.
const PAC_HELPERS: &str = r#"
function isPlainHostName(host) { return String(host).indexOf('.') < 0; }
function dnsDomainIs(host, domain) {
  host = String(host); domain = String(domain);
  return host.length >= domain.length &&
    host.substring(host.length - domain.length) === domain;
}
function localHostOrDomainIs(host, hostdom) {
  host = String(host); hostdom = String(hostdom);
  return host === hostdom || hostdom.indexOf(host + '.') === 0;
}
function isResolvable(host) { return dnsResolve(host) !== null; }
function dnsDomainLevels(host) { return String(host).split('.').length - 1; }
function convert_addr(ipchars) {
  var b = String(ipchars).split('.');
  return ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) |
         ((b[2] & 0xff) << 8) | (b[3] & 0xff);
}
function myIpAddress() { return __whistleMyIpAddress; }
function isInNet(host, pattern, mask) {
  var ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? String(host) : dnsResolve(host);
  if (!ip) { return false; }
  var a = ip.split('.'), p = String(pattern).split('.'), m = String(mask).split('.');
  if (a.length !== 4 || p.length !== 4 || m.length !== 4) { return false; }
  for (var i = 0; i < 4; i++) {
    if ((a[i] & m[i]) !== (p[i] & m[i])) { return false; }
  }
  return true;
}
function shExpMatch(str, shexp) {
  var re = String(shexp)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp('^' + re + '$').test(String(str));
}
function __whistleInRange(now, from, to) {
  return from <= to ? (now >= from && now <= to) : (now >= from || now <= to);
}
function weekdayRange(wd1, wd2, gmt) {
  var days = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 1 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var now = new Date();
  var today = useGmt ? now.getUTCDay() : now.getDay();
  var from = days.indexOf(String(args[0]).toUpperCase());
  if (from < 0) { return false; }
  if (args.length < 2) { return today === from; }
  var to = days.indexOf(String(args[1]).toUpperCase());
  if (to < 0) { return false; }
  return __whistleInRange(today, from, to);
}
function timeRange() {
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 0 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var n = args.map(Number);
  var now = new Date();
  var h = useGmt ? now.getUTCHours() : now.getHours();
  var m = useGmt ? now.getUTCMinutes() : now.getMinutes();
  var s = useGmt ? now.getUTCSeconds() : now.getSeconds();
  var secs = h * 3600 + m * 60 + s;
  if (n.length === 1) { return h === n[0]; }
  // Two hours, two hour:minute pairs, or two hour:minute:second triples. The
  // end of the range is inclusive down to the precision that was given, so
  // timeRange(9, 17) covers all of the 17th hour.
  if (n.length === 2) {
    return __whistleInRange(secs, n[0] * 3600, n[1] * 3600 + 3599);
  }
  if (n.length === 4) {
    return __whistleInRange(secs, n[0] * 3600 + n[1] * 60, n[2] * 3600 + n[3] * 60 + 59);
  }
  if (n.length === 6) {
    return __whistleInRange(secs, n[0] * 3600 + n[1] * 60 + n[2],
                            n[3] * 3600 + n[4] * 60 + n[5]);
  }
  return false;
}
function dateRange() {
  var months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
                'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  var args = Array.prototype.slice.call(arguments);
  var useGmt = args.length > 0 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  if (useGmt) { args.pop(); }
  var now = new Date();
  var day = useGmt ? now.getUTCDate() : now.getDate();
  var mon = useGmt ? now.getUTCMonth() : now.getMonth();
  var year = useGmt ? now.getUTCFullYear() : now.getFullYear();
  // Each argument is a day (1-31), a month name, or a four-digit year.
  var kind = function (v) {
    if (months.indexOf(String(v).toUpperCase()) >= 0) { return 'mon'; }
    return Number(v) >= 1000 ? 'year' : 'day';
  };
  var value = function (v) {
    return kind(v) === 'mon' ? months.indexOf(String(v).toUpperCase()) : Number(v);
  };
  if (args.length === 1) {
    var k = kind(args[0]), v = value(args[0]);
    return k === 'day' ? day === v : k === 'mon' ? mon === v : year === v;
  }
  var half = args.length / 2;
  if (args.length % 2 !== 0 || half > 3) { return false; }
  // A stamp orders (year, month, day) so a range comparison is one number.
  // Components the arguments left out are taken from today, which is what
  // makes dateRange('JAN', 'MAR') mean "January to March of any year".
  var stamp = function (list, y, mo, d) {
    for (var i = 0; i < list.length; i++) {
      var k = kind(list[i]), v = value(list[i]);
      if (k === 'day') { d = v; } else if (k === 'mon') { mo = v; } else { y = v; }
    }
    return y * 10000 + mo * 100 + d;
  };
  var from = args.slice(0, half), to = args.slice(half);
  var today = year * 10000 + mon * 100 + day;
  return __whistleInRange(today, stamp(from, year, mon, day), stamp(to, year, mon, day));
}
// Microsoft's IPv6-aware extensions. This port resolves IPv4 only, so they
// answer from the same data rather than pretending to know more.
function dnsResolveEx(host) { var ip = dnsResolve(host); return ip === null ? '' : ip; }
function myIpAddressEx() { return myIpAddress(); }
function isResolvableEx(host) { return isResolvable(host); }
function isInNetEx(host, prefix) {
  var parts = String(prefix).split('/');
  var len = parts.length > 1 ? Number(parts[1]) : 32;
  if (!(len >= 0 && len <= 32)) { return false; }
  var mask = [0, 0, 0, 0];
  for (var i = 0; i < 4; i++) {
    var bits = Math.min(8, Math.max(0, len - i * 8));
    mask[i] = (0xff << (8 - bits)) & 0xff;
  }
  return isInNet(host, parts[0], mask.join('.'));
}
function sortIpAddressList(list) { return String(list); }
function getClientVersion() { return '1.0'; }
"#;

/// PAC's `dnsResolve(host)`: the first IPv4 address `host` resolves to, or
/// `null`. A dotted quad resolves to itself.
///
/// This blocks on the system resolver, which is why [`find_proxy_for_url`]
/// evaluates PAC scripts on the blocking pool.
fn resolve_ipv4(host: &str) -> Option<String> {
    use std::net::{IpAddr, ToSocketAddrs};
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    // Answered here, not by the resolver: Linux and macOS reject an empty
    // name, but Windows' getaddrinfo answers it with this machine's own
    // addresses, so `isResolvable('')` was true there alone. whistle's Node
    // `dns.lookup('')` answers null without asking anyone.
    if host.is_empty() {
        return None;
    }
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4.to_string()),
            IpAddr::V6(_) => None,
        })
}

/// `dnsResolve` as the engine sees it.
fn js_dns_resolve(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let Some(arg) = args.first() else {
        return Ok(JsValue::null());
    };
    let host = arg.to_string(ctx)?.to_std_string_escaped();
    Ok(match resolve_ipv4(&host) {
        Some(ip) => JsString::from(ip.as_str()).into(),
        None => JsValue::null(),
    })
}

/// `alert` — PAC's only debugging tool. whistle logs it; so do we, at debug
/// level, since a chatty PAC file would otherwise log once per request.
fn js_alert(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    if let Some(arg) = args.first() {
        let msg = arg.to_string(ctx)?.to_std_string_escaped();
        tracing::debug!("pac alert: {msg}");
    }
    Ok(JsValue::undefined())
}

/// Install the parts of the PAC environment that JavaScript cannot provide:
/// the resolver, `alert`, and this machine's address for `myIpAddress`.
fn register_pac_natives(ctx: &mut Context) -> Result<()> {
    ctx.register_global_callable(
        js_string!("dnsResolve"),
        1,
        NativeFunction::from_fn_ptr(js_dns_resolve),
    )
    .map_err(|e| anyhow!("registering dnsResolve: {e}"))?;
    ctx.register_global_callable(
        js_string!("alert"),
        1,
        NativeFunction::from_fn_ptr(js_alert),
    )
    .map_err(|e| anyhow!("registering alert: {e}"))?;
    // `myIpAddress` cannot fail and takes no arguments, so it is a value rather
    // than a call. whistle-rs falls back to the loopback address when the
    // routing table cannot say, which is what a PAC file expects to see when a
    // machine has no route out.
    let ip = super::upstream::primary_local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    ctx.register_global_property(
        js_string!("__whistleMyIpAddress"),
        JsString::from(ip.as_str()),
        boa_engine::property::Attribute::READONLY,
    )
    .map_err(|e| anyhow!("registering myIpAddress: {e}"))?;
    Ok(())
}

/// Evaluate a PAC script's `FindProxyForURL(url, host)` and return its result
/// string (e.g. `"PROXY 127.0.0.1:8888"`, `"SOCKS ..."`, or `"DIRECT"`).
///
/// Every way this can fail is an error, never an empty answer: a PAC file that
/// throws has not said "connect directly", it has said nothing, and treating
/// the two alike is how a request slips past the proxy it was pinned to.
pub fn eval_pac(pac_src: &str, url: &str, host: &str) -> Result<String> {
    let mut ctx = Context::default();
    // A PAC file that loops for ever is an error like any other, rather than a
    // thread of the blocking pool gone for good.
    ctx.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_LIMIT);
    register_pac_natives(&mut ctx)?;
    ctx.eval(Source::from_bytes(PAC_HELPERS.as_bytes()))
        .map_err(|e| anyhow!("PAC helper environment: {e}"))?;
    ctx.eval(Source::from_bytes(pac_src.as_bytes()))
        .map_err(|e| anyhow!("PAC script: {e}"))?;

    let call = format!("FindProxyForURL({}, {})", js_str(url), js_str(host));
    let result = ctx
        .eval(Source::from_bytes(call.as_bytes()))
        .map_err(|e| anyhow!("FindProxyForURL({url}): {e}"))?;
    if result.is_null_or_undefined() {
        bail!("FindProxyForURL({url}) returned no proxy string");
    }
    let out = result
        .to_string(&mut ctx)
        .map_err(|e| anyhow!("FindProxyForURL({url}) returned an unreadable value: {e}"))?
        .to_std_string_escaped();
    Ok(out)
}

/// A remote PAC file, with the moment it was fetched.
struct CachedPac {
    body: Arc<str>,
    at: Instant,
}

/// Remote PAC files, keyed by their URL.
///
/// whistle keeps at most ten and never re-reads one
/// (`cachedPacs`, `_original/lib/rules/index.js:264-274`); we keep the same
/// bound but let an entry expire, because a debugging proxy that pins a routing
/// decision to whatever the PAC file said the first time is hard to explain. A
/// refresh that fails keeps serving the stale copy rather than failing the
/// request — the stale answer is still the answer the rule asked for.
static PAC_CACHE: Lazy<Mutex<HashMap<String, CachedPac>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// How long a fetched PAC file is reused before being fetched again.
const PAC_TTL: Duration = Duration::from_secs(300);
/// How many remote PAC files are remembered (whistle's limit).
const PAC_CACHE_MAX: usize = 10;

/// The cached copy of `url`, and whether it is still fresh.
fn cached_pac(url: &str) -> Option<(Arc<str>, bool)> {
    let cache = PAC_CACHE.lock().ok()?;
    let hit = cache.get(url)?;
    Some((hit.body.clone(), hit.at.elapsed() < PAC_TTL))
}

/// Remember `body` as the current content of `url`, evicting the oldest entry
/// once the cache is full.
fn store_pac(url: &str, body: Arc<str>) {
    let Ok(mut cache) = PAC_CACHE.lock() else {
        return;
    };
    if !cache.contains_key(url)
        && cache.len() >= PAC_CACHE_MAX
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, v)| v.at)
            .map(|(k, _)| k.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(
        url.to_string(),
        CachedPac {
            body,
            at: Instant::now(),
        },
    );
}

/// Fetch a remote PAC file, serving a cached copy while it is fresh.
///
/// whistle fetches `pac://http://…/proxy.pac` through `node-pac`
/// (`_original/lib/rules/index.js:257-275`). This port used to hand the URL
/// straight to the JS engine, where it threw and left the request going direct.
async fn fetch_pac(url: &str) -> Result<Arc<str>> {
    if let Some((body, fresh)) = cached_pac(url)
        && fresh
    {
        return Ok(body);
    }
    let fetched = super::upstream::simple_get(url).await;
    let stale = || cached_pac(url).map(|(body, _)| body);
    match fetched {
        Ok((status, body)) if (200..300).contains(&status) => {
            let text: Arc<str> = String::from_utf8_lossy(&body).into_owned().into();
            store_pac(url, text.clone());
            Ok(text)
        }
        Ok((status, _)) => match stale() {
            Some(body) => {
                tracing::warn!("pac://{url} returned {status}; using the cached copy");
                Ok(body)
            }
            None => bail!("fetching {url}: HTTP {status}"),
        },
        Err(err) => match stale() {
            Some(body) => {
                tracing::warn!("pac://{url} unreachable ({err:#}); using the cached copy");
                Ok(body)
            }
            None => Err(err).with_context(|| format!("fetching {url}")),
        },
    }
}

/// Is this `pac://` value a URL to fetch rather than a path or a script?
fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Resolve a `pac://` value to the script text.
///
/// Three shapes, in the order they are recognised: a remote `http(s)://` URL
/// (fetched and cached), a readable local file, or the script itself written
/// inline. The inline form is this port's own — upstream requires a URL or a
/// path (`index.js:255-258`) — so it is only assumed when the value actually
/// looks like a PAC script; otherwise an unreadable path is reported as one,
/// instead of being evaluated as JavaScript and blamed on the script.
pub async fn load_pac(value: &str) -> Result<Arc<str>> {
    let value = value.trim();
    if value.is_empty() {
        bail!("pac:// with no script, file or URL");
    }
    if is_http_url(value) {
        return fetch_pac(value).await;
    }
    match std::fs::read_to_string(value) {
        Ok(src) => Ok(src.into()),
        Err(err) => {
            if value.contains("FindProxyForURL") {
                Ok(Arc::from(value))
            } else {
                Err(err).with_context(|| format!("reading PAC file {value}"))
            }
        }
    }
}

/// Resolve a `pac://` value for one request: load the script and evaluate
/// `FindProxyForURL(url, host)`.
///
/// The evaluation runs on the blocking pool: it is CPU work, and a PAC file
/// calling `dnsResolve` blocks on the system resolver.
pub async fn find_proxy_for_url(value: &str, url: &str, host: &str) -> Result<String> {
    let src = load_pac(value).await?;
    let (url, host) = (url.to_string(), host.to_string());
    tokio::task::spawn_blocking(move || eval_pac(&src, &url, &host))
        .await
        .context("PAC evaluation")?
}

/// JSON-encode a string for safe embedding in a JS expression.
fn js_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `isRulesContent`: rules text unless bracketed, unfenced, uncommented,
    /// and naming `rules` or `values`.
    #[test]
    fn is_rules_content_matches_upstream() {
        // Plain rules text — no bracket at all.
        assert!(is_rules_content("a.com reqHeaders://x-a=1"));
        // Bracketed but a comment, or a fence, or neither word: still rules.
        assert!(is_rules_content("# a.com file://(mock)"));
        assert!(is_rules_content(
            "```v\nfoo\n```\na.com reqHeaders://x-a={v}"
        ));
        assert!(is_rules_content("a.com file://(a subshell of nothing)"));
        // Bracketed, unfenced, uncommented, and names one of the two words:
        // this is a script.
        assert!(!is_rules_content("rules.push('a.com reqHeaders://x=1')"));
        assert!(!is_rules_content("values['k'] = (1)"));
        // The word has to stand alone, `\b(?:rules|values)\b`.
        assert!(is_rules_content("myrules.push('a.com x://y')"));
        assert!(is_rules_content("rulesfoo = (1)"));
    }

    /// No values store, for the cases that are not about one.
    static NO_VALUES: std::sync::LazyLock<std::collections::HashMap<String, String>> =
        std::sync::LazyLock::new(std::collections::HashMap::new);
    /// No script has run yet.
    static NO_DATA: Mutex<serde_json::Value> = Mutex::new(serde_json::Value::Null);
    /// No proxy around the script: what a unit test and `explain` have.
    static NO_ENV: crate::rules::ScriptEnv = crate::rules::ScriptEnv {
        proxy_port: 0,
        ui_port: 0,
        http_version: "",
    };

    /// A rules script pushes lines; an error discards them; `values` set by the
    /// script does not resolve a `{name}` reference. All measured against
    /// whistle 2.10.8 first.
    #[test]
    fn a_rules_script_pushes_lines_and_an_error_discards_them() {
        fn ctx(body: &str) -> RulesScriptCtx<'_> {
            RulesScriptCtx {
                method: "GET",
                full_url: "http://a.com/p?q=1",
                headers: &[],
                body,
                client_ip: None,
                client_port: None,
                res: None,
                values: &NO_VALUES,
                script_data: &NO_DATA,
                pattern: "",
                env: &NO_ENV,
            }
        }
        assert_eq!(
            run_rules_script("rules.push('a.com reqHeaders://x-a=1')", &ctx("")).as_deref(),
            Some("a.com reqHeaders://x-a=1"),
        );
        // The url is readable.
        assert_eq!(
            run_rules_script(
                "if (url.indexOf('q=1') !== -1) rules.push('a.com reqHeaders://x-u=1')",
                &ctx(""),
            )
            .as_deref(),
            Some("a.com reqHeaders://x-u=1"),
        );
        // An error after a push yields nothing at all.
        assert_eq!(
            run_rules_script(
                "rules.push('a.com x://y'); throw new Error('boom')",
                &ctx("")
            ),
            None,
        );
        // A `values` write does not resolve `{name}` — the literal survives.
        assert_eq!(
            run_rules_script(
                "values['m']='x'; rules.push('a.com reqHeaders://x-v={m}')",
                &ctx(""),
            )
            .as_deref(),
            Some("a.com reqHeaders://x-v={m}"),
        );
        // An empty push list is an empty string, not a rule.
        assert_eq!(
            run_rules_script("var unused = 1;", &ctx("")).as_deref(),
            Some("")
        );
    }

    /// `reqScriptData` outlives the script that wrote it: the `resScript` of a
    /// request reads what its `reqScript` left, as upstream's suite asks
    /// (`test/units/script.test.js`, the `x-test` header). Another request
    /// starts empty.
    #[test]
    fn script_data_carries_from_one_script_to_the_next() {
        let ctx = |data| RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &NO_VALUES,
            script_data: data,
            pattern: "",
            env: &NO_ENV,
        };
        let this_request = Mutex::new(serde_json::Value::Null);
        run_rules_script(
            "reqScriptData.test = 123; rules.push('a')",
            &ctx(&this_request),
        );
        let read = "rules.push('a.com reqHeaders://x=' + reqScriptData.test)";
        assert_eq!(
            run_rules_script(read, &ctx(&this_request)).as_deref(),
            Some("a.com reqHeaders://x=123")
        );
        let next_request = Mutex::new(serde_json::Value::Null);
        assert_eq!(
            run_rules_script(read, &ctx(&next_request)).as_deref(),
            Some("a.com reqHeaders://x=undefined")
        );
    }

    /// The context `reqScript.md` prints, in the three pieces this port had to
    /// build: `render`/`tpl`, `getValue`, and `isLocalAddress`.
    #[test]
    fn a_script_renders_a_template_and_reads_a_value() {
        let mut store = std::collections::HashMap::new();
        store.insert("mock".to_string(), "from-store".to_string());
        store.insert(
            crate::rules::inline_key("block.txt", "Default"),
            "from-fence".to_string(),
        );
        let ctx = RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &store,
            script_data: &NO_DATA,
            pattern: "",
            env: &NO_ENV,
        };
        let push = |expr: &str| {
            run_rules_script(
                &format!("rules.push('a.com reqHeaders://x=' + ({expr}))"),
                &ctx,
            )
        };
        // `tpl` is whistle's own micro-template: `<%= … %>` interpolates and
        // `<% … %>` is code, and a string carrying neither comes back as it was.
        assert_eq!(
            push("render('<%=a%>-<%=b%>', {a:1,b:2})").as_deref(),
            Some("a.com reqHeaders://x=1-2")
        );
        assert_eq!(
            push("render('<% if (a) { %>yes<% } else { %>no<% } %>', {a:0})").as_deref(),
            Some("a.com reqHeaders://x=no")
        );
        assert_eq!(
            push("render('plain')").as_deref(),
            Some("a.com reqHeaders://x=plain")
        );
        assert_eq!(
            push("tpl === render").as_deref(),
            Some("a.com reqHeaders://x=true")
        );
        // `getValue` answers from the store, by the plain name for an inline
        // block as well as for a Values entry.
        assert_eq!(
            push("getValue('mock')").as_deref(),
            Some("a.com reqHeaders://x=from-store")
        );
        assert_eq!(
            push("getValue('block.txt')").as_deref(),
            Some("a.com reqHeaders://x=from-fence")
        );
        assert_eq!(
            push("getValue('nope')").as_deref(),
            Some("a.com reqHeaders://x=undefined")
        );
        // `isLocalAddress` knows the loopback range and the two spellings of
        // the unspecified address; a public address is not local.
        assert_eq!(
            push("isLocalAddress('127.0.0.1')").as_deref(),
            Some("a.com reqHeaders://x=true")
        );
        assert_eq!(
            push("isLocalAddress('[::1]')").as_deref(),
            Some("a.com reqHeaders://x=true")
        );
        assert_eq!(
            push("isLocalAddress('8.8.8.8')").as_deref(),
            Some("a.com reqHeaders://x=false")
        );
    }

    /// A `resScript` sees the response head; a request script sees empty strings
    /// there, so `statusCode == 200` is false in the request pass.
    #[test]
    fn a_response_script_sees_the_status() {
        let res = RulesScriptRes {
            status: 200,
            server_ip: None,
            headers: &[],
        };
        let with_res = RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: Some(res),
            values: &NO_VALUES,
            script_data: &NO_DATA,
            pattern: "",
            env: &NO_ENV,
        };
        assert_eq!(
            run_rules_script(
                "if (statusCode == 200) rules.push('a.com resHeaders://x-r=1')",
                &with_res,
            )
            .as_deref(),
            Some("a.com resHeaders://x-r=1"),
        );
        let no_res = RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &NO_VALUES,
            script_data: &NO_DATA,
            pattern: "",
            env: &NO_ENV,
        };
        assert_eq!(
            run_rules_script(
                "if (statusCode == 200) rules.push('a.com resHeaders://x-r=1')",
                &no_res,
            )
            .as_deref(),
            Some(""),
        );
    }

    /// Evaluate `expr` in a fresh script engine and hand back its value as JSON.
    fn node(expr: &str) -> serde_json::Value {
        let mut ctx = script_engine().expect("engine");
        let src = format!("JSON.stringify((function () {{ return {expr}; }})())");
        let out = ctx
            .eval(Source::from_bytes(src.as_bytes()))
            .unwrap_or_else(|e| panic!("{expr}: {e}"));
        let text = out.to_string(&mut ctx).unwrap().to_std_string_escaped();
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{expr} gave {text}: {e}"))
    }

    /// `querystring.parse`, by the answers Node gives. The first three are the
    /// ones `tests/differential/core-bench.js` asks whistle itself.
    #[test]
    fn parse_query_is_nodes_querystring_parse() {
        for (input, want) in [
            // A repeated key is an array; `+` is a space; a bare key is ''.
            (
                "a=1&a=2&q=a+b&e=%E4%B8%AD&bare",
                json!({"a": ["1", "2"], "q": "a b", "e": "中", "bare": ""}),
            ),
            ("", json!({})),
            // A broken escape is left as written, not thrown on.
            ("a=%zz&b=%41", json!({"a": "%zz", "b": "A"})),
            // An empty pair is skipped; a third value joins the array.
            ("a=1&&a=2&a=3", json!({"a": ["1", "2", "3"]})),
            // Only the first `=` splits; an empty key is a key.
            ("a=b=c&=x", json!({"a": "b=c", "": "x"})),
            // `%2B` is a plus, which `+` is not; a leading `?` is part of the key.
            ("?a%20b=c+d%2B", json!({"?a b": "c d+"})),
        ] {
            assert_eq!(node(&format!("parseQuery({input:?})")), want, "{input}");
        }
        // Not a string: an empty object, as Node answers.
        assert_eq!(node("parseQuery(null)"), json!({}));
    }

    /// `url.parse`, by the answers Node gives — the quirks included.
    #[test]
    fn parse_url_is_nodes_legacy_url_parse() {
        let fields = "[u.protocol, u.slashes, u.auth, u.host, u.port, u.hostname, u.hash, u.search, u.query, u.pathname, u.path, u.href]";
        let parse = |url: &str| {
            node(&format!(
                "(function (u) {{ return {fields}; }})(parseUrl({url:?}))"
            ))
        };
        // Userinfo is `auth`, not part of the host; an IPv6 literal keeps its
        // brackets in `host` and loses them in `hostname`; the hash is kept.
        assert_eq!(
            parse("http://user:pw@[::1]:8080/p/a?x=1#frag"),
            json!([
                "http:",
                true,
                "user:pw",
                "[::1]:8080",
                "8080",
                "::1",
                "#frag",
                "?x=1",
                "x=1",
                "/p/a",
                "/p/a?x=1",
                "http://user:pw@[::1]:8080/p/a?x=1#frag"
            ])
        );
        // The host is lower-cased and the path is not; a space is escaped; no
        // query is `null`, not ''.
        assert_eq!(
            parse("https://Example.COM/a b"),
            json!([
                "https:",
                true,
                null,
                "example.com",
                null,
                "example.com",
                null,
                null,
                null,
                "/a%20b",
                "/a%20b",
                "https://example.com/a%20b"
            ])
        );
        // No scheme, no host.
        assert_eq!(
            parse("/p/a?x=1#h"),
            json!([
                null,
                null,
                null,
                null,
                null,
                null,
                "#h",
                "?x=1",
                "x=1",
                "/p/a",
                "/p/a?x=1",
                "/p/a?x=1#h"
            ])
        );
        // A host with no path gets `/`; a default port is still a port.
        assert_eq!(
            parse("http://a.com:80"),
            json!([
                "http:",
                true,
                null,
                "a.com:80",
                "80",
                "a.com",
                null,
                null,
                null,
                "/",
                "/",
                "http://a.com:80/"
            ])
        );
        // A scheme the parser does not know is opaque after the colon.
        assert_eq!(
            parse("mailto:a@b.c"),
            json!([
                "mailto:",
                null,
                "a",
                "b.c",
                null,
                "b.c",
                null,
                null,
                null,
                null,
                null,
                "mailto:a@b.c"
            ])
        );
        // A name that is not ASCII is punycoded, as `url.parse` does.
        assert_eq!(
            node("parseUrl('http://中文.com/').hostname"),
            json!("xn--fiq228c.com")
        );
        // Not a string: whistle's own lenient parser answers instead of a throw.
        assert_eq!(node("parseUrl(undefined).pathname"), json!("/"));
    }

    /// `Buffer`, in the uses a rule script has for one.
    #[test]
    fn buffer_is_nodes_buffer() {
        assert_eq!(
            node("Buffer.from('A中').toString('hex')"),
            json!("41e4b8ad")
        );
        assert_eq!(
            node("Buffer.from('e4b8ad41', 'hex').toString()"),
            json!("中A")
        );
        assert_eq!(
            node(
                "[Buffer.from('hello').toString('base64'), Buffer.from('aGVsbG8=', 'base64').toString('utf8')]"
            ),
            json!(["aGVsbG8=", "hello"])
        );
        // URL-safe input is read by the same decoder; padding is optional.
        assert_eq!(
            node("Buffer.from('_-8', 'base64').toString('hex')"),
            json!("ffef")
        );
        assert_eq!(
            node("Buffer.from([255, 239]).toString('base64url')"),
            json!("_-8")
        );
        assert_eq!(
            node(
                "(function (b) { return [b.length, Buffer.isBuffer(b), Buffer.isBuffer('x'), Buffer.byteLength('中'), b[0], b.toString()]; })(Buffer.concat([Buffer.from('ab'), Buffer.from('c')]))"
            ),
            json!([3, true, false, 3, 97, "abc"])
        );
        // It is a Uint8Array, and it serialises as Node's does.
        assert_eq!(node("Buffer.from('a') instanceof Uint8Array"), json!(true));
        assert_eq!(
            node("Buffer.from('ab')"),
            json!({"type": "Buffer", "data": [97, 98]})
        );
        // Concatenation with a string is `toString()`, which is what makes
        // `'x' + buf` work in a frame handler.
        assert_eq!(node("'x' + Buffer.from('yz')"), json!("xyz"));
        // Bytes that are not UTF-8 become U+FFFD rather than an error.
        assert_eq!(
            node("Buffer.from([0x61, 0xff]).toString()"),
            json!("a\u{fffd}")
        );
        assert_eq!(
            node("Buffer.from([0x61, 0xff]).toString('latin1')"),
            json!("a\u{ff}")
        );
        // Slices share memory; searching and the fixed-width readers work.
        assert_eq!(
            node(
                "(function (b) { var s = b.slice(1, 3); s[0] = 0x58; return [b.toString(), s.toString(), b.indexOf('c'), b.includes('zz'), b.readUInt16BE(0), b.equals(Buffer.from('aXcd'))]; })(Buffer.from('abcd'))"
            ),
            json!(["aXcd", "Xc", 2, false, 0x6158, true])
        );
        assert_eq!(
            node(
                "(function (b) { b.writeUInt32LE(0x01020304, 0); b.write('hi', 4); return b.toString('hex'); })(Buffer.alloc(6))"
            ),
            json!("040302016869")
        );
        assert_eq!(node("Buffer.alloc(3, 'ab').toString()"), json!("aba"));
        assert_eq!(
            node(
                "(function () { try { Buffer.from('x', 'nope'); } catch (e) { return e.name; } })()"
            ),
            json!("TypeError")
        );
    }

    /// The three `iconv` helpers whistle hands a script.
    #[test]
    fn the_iconv_helpers_move_text_between_encodings() {
        assert_eq!(
            node(
                "[encodeString('中', 'gbk').toString('hex'), decodeBuffer(Buffer.from('d6d0', 'hex'), 'gbk'), encodingExists('gbk'), encodingExists('no-such')]"
            ),
            json!(["d6d0", "中", true, false])
        );
        // The default is UTF-8, in both directions.
        assert_eq!(
            node(
                "[encodeString('中').toString('hex'), decodeBuffer(Buffer.from('e4b8ad', 'hex'))]"
            ),
            json!(["e4b8ad", "中"])
        );
        // Names as iconv-lite accepts them, which is looser than the WHATWG labels.
        assert_eq!(
            node(
                "['GB2312', 'win1252', 'cp936', 'Shift_JIS', 'utf16le', 'latin1', 'big5', 'EUC-KR'].map(encodingExists)"
            ),
            json!([true, true, true, true, true, true, true, true])
        );
        // A character the encoding cannot hold is `?`, iconv-lite's default.
        assert_eq!(
            node("encodeString('a中', 'windows-1252').toString()"),
            json!("a?")
        );
        assert_eq!(
            node("encodeString('ab', 'utf-16be').toString('hex')"),
            json!("00610062")
        );
        // `latin1` is ISO-8859-1 to iconv, a table like any other — not
        // `Buffer`'s latin1, which would have kept the low byte (0x2d) — and
        // not the Encoding Standard's either, which is windows-1252.
        assert_eq!(
            node(
                "[encodeString('a中é', 'latin1').toString('hex'), encodeString('€', 'latin1').toString('hex'), decodeBuffer(Buffer.from([0x80, 0xe9]), 'latin1').length]"
            ),
            json!(["613fe9", "3f", 2])
        );
        assert_eq!(
            node(
                "[encodeString('aé', 'ascii').toString('hex'), encodeString('a中', 'binary').toString('hex')]"
            ),
            json!(["613f", "612d"])
        );
        // An encoding nobody knows is an error the script can catch.
        assert_eq!(
            node(
                "(function () { try { decodeBuffer(Buffer.from('a'), 'nope'); } catch (e) { return 'threw'; } })()"
            ),
            json!("threw")
        );
    }

    /// The legacy corners of the language a whistle script takes for granted:
    /// `substr`, `escape`/`unescape`, and the `RegExp.$1` statics whistle's own
    /// source is written with. The first three were a `TypeError` here.
    #[test]
    fn the_legacy_corners_of_the_language_are_there() {
        assert_eq!(
            node("['abcdef'.substr(1, 3), escape('a b+c'), unescape('%41')]"),
            json!(["bcd", "a%20b+c", "A"])
        );
        assert_eq!(
            node(
                "(/(b)(c)/.test('abcd'), [RegExp.$1, RegExp.$2, RegExp.$3, RegExp.lastMatch, RegExp.leftContext, RegExp.rightContext])"
            ),
            json!(["b", "c", "", "bc", "a", "d"])
        );
        // Through `replace` and `match` too, and a failed match leaves the
        // statics as they were.
        assert_eq!(
            node("('x-1'.replace(/(\\d)/, 'n'), 'zz'.match(/(q)/), RegExp.$1)"),
            json!("1")
        );
    }

    /// The Node parts load the first time one is used, and nothing a script
    /// can do around that moment shows. The first case is the one that broke
    /// an earlier design: the *second* call from one call site.
    #[test]
    fn the_node_parts_load_on_first_use_without_showing() {
        // Called twice from one call site, the first of which triggers the load.
        assert_eq!(
            node("['a=1', 'b=2'].map(function (q) { return parseQuery(q); })"),
            json!([{"a": "1"}, {"b": "2"}])
        );
        assert_eq!(
            node("['gbk', 'nope', 'big5'].map(function (e) { return encodingExists(e); })"),
            json!([true, false, true])
        );
        // A reference taken before the load still works after it, and is the
        // same `Buffer` as the one instances are made by.
        assert_eq!(
            node(
                "(function () { var B = Buffer, pq = parseQuery; var b = B.from('ab'); return [b instanceof B, b instanceof Buffer, B === Buffer, Buffer.isBuffer(b), pq('x=1').x, typeof B.from]; })()"
            ),
            json!([true, true, true, true, "1", "function"])
        );
        // The constructor forms, which are also what the inherited typed-array
        // methods call.
        assert_eq!(
            node(
                "[new Buffer(2).length, Buffer('hi').toString('hex'), Buffer.from('abc').map(function (x) { return x + 1; }).toString()]"
            ),
            json!([2, "6869", "bcd"])
        );
        // A script's own function by one of these names stays the script's,
        // whether it was there before the load or not.
        let mut ctx = script_engine().expect("engine");
        let out = ctx
            .eval(Source::from_bytes(
                b"function parseQuery() { return 'mine'; } Buffer.from('a'); parseQuery('a=1') + '|' + typeof parseUrl('http://a/').host",
            ))
            .expect("runs");
        assert_eq!(
            out.to_string(&mut ctx).unwrap().to_std_string_escaped(),
            "mine|string"
        );
    }

    /// What it costs to start a script: an engine, the prelude, nothing else.
    /// `cargo test --release --lib script::tests::cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn cost_of_starting_a_script() {
        let n = 200u32;
        let started = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(script_engine().expect("engine"));
        }
        let each = started.elapsed() / n;
        println!("script_engine(): {each:?} each");
        let started = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(Context::default());
        }
        println!("Context::default(): {:?} each", started.elapsed() / n);
        let started = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(JsString::from(NODE_PRELUDE));
        }
        println!("the prelude as a string: {:?} each", started.elapsed() / n);
        let started = std::time::Instant::now();
        for _ in 0..n {
            let mut ctx = script_engine().expect("engine");
            ctx.eval(Source::from_bytes(b"Buffer.alloc(1)"))
                .expect("loads");
        }
        println!(
            "script_engine() and the Node parts: {:?} each",
            started.elapsed() / n
        );
        let mut ctx = script_engine().expect("engine");
        let started = std::time::Instant::now();
        let _ = ctx.eval(Source::from_bytes(b"while (true) {}"));
        println!(
            "a loop cut at {LOOP_LIMIT} iterations: {:?}",
            started.elapsed()
        );
    }

    /// `pattern`, `port`, `uiPort` and `httpVersion` say what they say in
    /// whistle; they were `''`, `0`, `0` and always `1.1`.
    #[test]
    fn a_script_knows_its_pattern_and_the_proxy() {
        let env = crate::rules::ScriptEnv {
            proxy_port: 8899,
            ui_port: 8900,
            http_version: "2.0",
        };
        let ctx = RulesScriptCtx {
            method: "post",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &NO_VALUES,
            script_data: &NO_DATA,
            pattern: "a.com/api",
            env: &env,
        };
        assert_eq!(
            run_rules_script(
                "rules.push([pattern, port, uiPort, httpVersion, method, typeof value, res].join('|'))",
                &ctx
            )
            .as_deref(),
            Some("a.com/api|8899|8900|2.0|POST|undefined|")
        );
    }

    /// `getValue(key, true)` skips the ``` blocks and asks the Values store.
    #[test]
    fn get_value_can_ask_the_store_alone() {
        let mut store = std::collections::HashMap::new();
        store.insert("k".to_string(), "from-store".to_string());
        store.insert(
            crate::rules::inline_key("k", "Default"),
            "from-fence".to_string(),
        );
        let ctx = RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &store,
            script_data: &NO_DATA,
            pattern: "",
            env: &NO_ENV,
        };
        assert_eq!(
            run_rules_script(
                "rules.push(getValue('k') + '|' + getValue('k', true))",
                &ctx
            )
            .as_deref(),
            Some("from-fence|from-store")
        );
    }

    /// A loop that never ends is stopped, and its script produces nothing —
    /// it used to hold the request for ever.
    #[test]
    fn a_script_that_never_ends_is_stopped() {
        let ctx = RulesScriptCtx {
            method: "GET",
            full_url: "http://a.com/",
            headers: &[],
            body: "",
            client_ip: None,
            client_port: None,
            res: None,
            values: &NO_VALUES,
            script_data: &NO_DATA,
            pattern: "",
            env: &NO_ENV,
        };
        assert_eq!(
            run_rules_script("rules.push('a'); while (true) {}", &ctx),
            None
        );
        assert_eq!(
            run_rules_script("rules.push('a'); (function f() { f(); })()", &ctx),
            None
        );
        // …and an honest loop is not.
        assert_eq!(
            run_rules_script(
                "var n = 0; for (var i = 0; i < 100000; i++) n++; rules.push('n=' + n)",
                &ctx
            )
            .as_deref(),
            Some("n=100000")
        );
    }

    #[test]
    fn res_script_mutates_status_and_body() {
        let src = "ctx.res.statusCode = 418; ctx.res.body = ctx.res.body + '!'; ctx.res.headers['x-s']='y';";
        let r = run_res_script(src, "GET", "http://x/", 200, &[], "hi").unwrap();
        assert_eq!(r.status, Some(418));
        assert_eq!(r.body.as_deref(), Some("hi!"));
        assert!(r.headers.iter().any(|(k, v)| k == "x-s" && v == "y"));
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    /// Evaluate `pac` and unwrap, so a failing helper shows up as the JS error.
    fn pac(src: &str, url: &str, host: &str) -> String {
        eval_pac(src, url, host).unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// A PAC file that returns `FindProxyForURL(url, host)` from `body`.
    fn wrap(body: &str) -> String {
        format!("function FindProxyForURL(url, host) {{ {body} }}")
    }

    #[test]
    fn pac_returns_proxy() {
        let src = wrap("return host === 'blocked.com' ? 'PROXY 10.0.0.1:8080' : 'DIRECT';");
        assert_eq!(
            pac(&src, "http://blocked.com/", "blocked.com"),
            "PROXY 10.0.0.1:8080"
        );
        assert_eq!(pac(&src, "http://ok.com/", "ok.com"), "DIRECT");
    }

    /// The helper environment a real PAC file assumes. Three of these existed;
    /// the rest threw, and the throw was swallowed into a direct connection.
    #[test]
    fn the_pac_helpers_a_corporate_file_uses_all_exist() {
        for (expr, want) in [
            ("isPlainHostName('intranet')", "true"),
            ("isPlainHostName('a.example.com')", "false"),
            ("dnsDomainIs('www.example.com', '.example.com')", "true"),
            ("dnsDomainIs('www.example.org', '.example.com')", "false"),
            ("localHostOrDomainIs('www', 'www.example.com')", "true"),
            (
                "localHostOrDomainIs('www.example.com', 'www.example.com')",
                "true",
            ),
            ("localHostOrDomainIs('web', 'www.example.com')", "false"),
            ("dnsDomainLevels('www.example.com')", "2"),
            ("dnsDomainLevels('intranet')", "0"),
            (
                "shExpMatch('http://a.example.com/x', '*.example.com/*')",
                "true",
            ),
            (
                "shExpMatch('http://a.example.org/x', '*.example.com/*')",
                "true==false",
            ),
            ("shExpMatch('abc', 'a?c')", "true"),
            // `.` is a literal, not "any character".
            ("shExpMatch('axc', 'a.c')", "false"),
            ("isInNet('10.1.2.3', '10.0.0.0', '255.0.0.0')", "true"),
            ("isInNet('11.1.2.3', '10.0.0.0', '255.0.0.0')", "false"),
            ("isInNetEx('192.168.4.9', '192.168.0.0/16')", "true"),
            ("isInNetEx('192.169.4.9', '192.168.0.0/16')", "false"),
            ("convert_addr('127.0.0.1')", "2130706433"),
            // Resolution of a literal is the literal; localhost is resolvable.
            ("dnsResolve('10.9.8.7')", "'10.9.8.7'"),
            ("isResolvable('localhost')", "true"),
            // A name that cannot resolve answers `null` rather than throwing.
            // The obvious probe — a name under the reserved `.invalid` TLD —
            // cannot be used: a resolver that answers NXDOMAIN with an address
            // of its own (a captive portal, or the fake-IP mode every desktop
            // VPN client ships) resolves it, and the test would then fail on the
            // network rather than on the code. An empty host never reaches a
            // resolver at all (`resolve_ipv4` answers it; Windows' resolver
            // would have said "this machine").
            ("dnsResolve('') === null", "true"),
            ("isResolvable('')", "false"),
            ("typeof myIpAddress()", "'string'"),
            ("typeof myIpAddressEx()", "'string'"),
            ("typeof getClientVersion()", "'string'"),
            // A whole week, all day, every day — true whenever it is evaluated.
            ("weekdayRange('SUN', 'SAT')", "true"),
            ("weekdayRange('SUN', 'SAT', 'GMT')", "true"),
            ("timeRange(0, 23)", "true"),
            ("timeRange(0, 0, 0, 23, 59, 59)", "true"),
            ("dateRange('JAN', 'DEC')", "true"),
            ("dateRange(1, 31)", "true"),
            // …and one that cannot be true: a nonexistent weekday.
            ("weekdayRange('XYZ')", "false"),
        ] {
            let src = wrap(&format!("return String(({expr}) === ({want}));"));
            assert_eq!(
                pac(&src, "http://a.example.com/x", "a.example.com"),
                "true",
                "PAC helper check failed: ({expr}) === ({want})"
            );
        }
    }

    /// A script that throws has not said "go direct" — it has said nothing. It
    /// used to mean a direct connection, silently.
    #[test]
    fn a_broken_pac_is_an_error_rather_than_a_direct_connection() {
        // Throws inside FindProxyForURL.
        let err = eval_pac(&wrap("return nope.nope;"), "http://a.com/", "a.com").unwrap_err();
        assert!(format!("{err:#}").contains("FindProxyForURL"), "{err:#}");
        // Does not parse.
        assert!(eval_pac("function {", "http://a.com/", "a.com").is_err());
        // Defines nothing to call.
        assert!(eval_pac("var x = 1;", "http://a.com/", "a.com").is_err());
        // Returns nothing at all.
        assert!(eval_pac(&wrap("return;"), "http://a.com/", "a.com").is_err());
    }

    /// A PAC file may ship its own copy of a helper — ours must not shadow it.
    #[test]
    fn a_pac_may_override_a_helper() {
        let src = format!(
            "function isPlainHostName(h) {{ return true; }}\n{}",
            wrap("return String(isPlainHostName('a.b.c'));")
        );
        assert_eq!(pac(&src, "http://a.b.c/", "a.b.c"), "true");
    }

    /// Serve `body` as a PAC file, and report how many requests arrived.
    /// Answers `count` requests and then stops listening.
    async fn pac_server(
        body: &'static str,
        count: usize,
    ) -> (String, tokio::task::JoinHandle<usize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}/proxy.pac", listener.local_addr().expect("addr"));
        let handle = tokio::spawn(async move {
            let mut served = 0;
            for _ in 0..count {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                if sock.write_all(resp.as_bytes()).await.is_ok() {
                    served += 1;
                }
            }
            served
        });
        (url, handle)
    }

    /// `pac://http://…/proxy.pac` is fetched over the network and cached, where
    /// it used to be evaluated as if the URL itself were JavaScript.
    #[test]
    fn a_remote_pac_is_fetched_once_and_then_cached() {
        rt().block_on(async {
            let (url, server) = pac_server(
                "function FindProxyForURL(u, h) { return 'PROXY 10.1.1.1:3128'; }",
                2,
            )
            .await;

            let first = find_proxy_for_url(&url, "http://a.com/", "a.com")
                .await
                .expect("remote pac");
            assert_eq!(first, "PROXY 10.1.1.1:3128");
            // Second request is answered from the cache, so the server sees one
            // request even though we asked twice.
            let second = find_proxy_for_url(&url, "http://b.com/", "b.com")
                .await
                .expect("cached pac");
            assert_eq!(second, "PROXY 10.1.1.1:3128");

            // Nothing more will arrive; stop the listener by dropping the task.
            server.abort();
            assert!(cached_pac(&url).is_some(), "the fetched script is cached");
        });
    }

    /// An unreachable PAC URL fails the request rather than quietly routing it
    /// direct — and a value that is neither a URL nor a readable file is
    /// reported as the path it is, not evaluated as JavaScript.
    #[test]
    fn an_unusable_pac_location_is_reported() {
        rt().block_on(async {
            // Port 1 on loopback: nothing is listening.
            let err = load_pac("http://127.0.0.1:1/proxy.pac").await.unwrap_err();
            assert!(format!("{err:#}").contains("127.0.0.1:1"), "{err:#}");

            let err = load_pac("/no/such/dir/corp.pac").await.unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("/no/such/dir/corp.pac"), "{msg}");

            assert!(
                load_pac("   ").await.is_err(),
                "an empty value is not a script"
            );

            // A script written inline is still accepted.
            let inline = wrap("return 'DIRECT';");
            assert_eq!(
                &*load_pac(&inline).await.expect("inline pac"),
                inline.as_str()
            );
        });
    }

    /// A local PAC file is read from disk (the documented form).
    #[test]
    fn a_local_pac_file_is_read() {
        rt().block_on(async {
            let dir = std::env::temp_dir().join("whistle-rs-pac-test");
            std::fs::create_dir_all(&dir).expect("mkdir");
            let path = dir.join("corp.pac");
            let src = wrap("return 'SOCKS5 127.0.0.1:1080';");
            std::fs::write(&path, &src).expect("write pac");
            let out = find_proxy_for_url(path.to_str().expect("path"), "http://a.com/", "a.com")
                .await
                .expect("file pac");
            assert_eq!(out, "SOCKS5 127.0.0.1:1080");
        });
    }
}
