// Values, templates, and the inline payload syntax — everything that decides
// what text an operator's value finally resolves to.
//
// Four spellings meet here, and they are *not* the same mechanism:
//
//   ``` name ␤ … ␤ ```      declares a value inside the rules text itself
//   proto://{name}          the **whole** value is that content
//   proto://x=${name}       the content goes *inside* a value
//   proto://`x=${method}`   a template rendered against the request
//
// Upstream answers the first two from `getValueFor` (`_original/lib/rules/rules.js:785-796`)
// and the last two from `resolveVar` / `renderTpl` (`:762-783`). The order they
// run in is what most of this file pins: values expand **before** the pattern's
// captures do (`resolveVar` then `replaceSubMatcher`, `:1010-1012`), and a
// backtick on the rule line is what says "render whatever the store hands back".
//
// `P` is the origin's authority. `A` pins the pattern to the request's whole
// path, so a value is used as written rather than having the unmatched path
// concatenated onto it — the trap `cases-file.js` documents.
//
// Two things this file does **not** exercise, having established they do not
// exist: there is no `resTpl://` or `reqTpl://` in either proxy (the template
// family is `tpl` / `dust` / `jsonp`, byte-identical, plus the backtick form on
// any operator), and an inline payload cannot have whitespace trimmed out of it
// because it cannot contain any — the line is split on whitespace before `(` is
// looked at, so `resBody://(a b)` is two tokens and neither is a payload.
//
// 90 of the 109 cases change something on the real-whistle side. Of the 19 that
// do not, 13 are the point: "upstream does nothing here" is the fact, and
// whistle-rs doing something is the difference.
//
// ── Cases expected to differ ───────────────────────────────────────────────
//
// A clean run of this file is **`differing: 11`**. They are not in `harness.js`'s
// `EXPECTED` because a matcher wide enough to catch them would hide real news in
// another corpus; what makes them expected is the rule, which a matcher on the
// output cannot see. Two deliberate divergences, already declared in the code:
//
//   * **A value a text operator cannot read is used as written here.**
//     (`a value that names nothing …` ×3, `an unterminated fence …`,
//     `an unbalanced open bracket`, `an unbalanced close bracket`,
//     `a payload whose hash is eaten by the comment stripper`,
//     `angle brackets on a body operator`, `angle brackets around a payload
//     containing parens`, `a script tag in angle brackets`.)
//     Upstream has no shape test: for a text operator *every* non-inline value
//     is a path (`readRuleValue`, `_original/lib/util/index.js:1189-1213`), so
//     `resBody://{typo}` opens a file called `{typo}`, fails, and the operator
//     does nothing. whistle-rs keeps a bare value as the literal it already is —
//     declared in `value_source` (`src/proxy/apply.rs`). The `<…>` half is the
//     same decision from the other end: upstream's `getValue(matcher,'<','>')`
//     strips the brackets off **every** operator's value, so
//     `htmlAppend://<script>x</script>` loses its final `>` and injects nothing;
//     `fixed_value` (`src/rules/url.rs`) asks the question only where the form is
//     documented, and leaves injected markup intact.
//
//   * **`{name}` must end the value here.** (`trailing text after a reference`.)
//     `getKey` takes everything up to the **last** `}` and discards the rest
//     (`rules.js:817-824`), so upstream reads `file://{mock}/x` as `{mock}` and
//     silently drops the `/x`. This port requires the reference to be the whole
//     value, so the text stays a literal — which is wrong in a different
//     direction, and louder.
//
// Five cases that used to be on this list have closed. Three were an operator
// written with **no value**, which now does nothing here either, as the bodies
// audit established; two were the `@` includes below, which now work for a
// rules text set at runtime. The include family has grown its own corpus —
// `cases-includes.js` — and the five cases here are what is left of it: enough
// that this file notices if the feature regresses, not enough to be the place
// it is tested.
//
// One divergence in this area cannot be written as a case at all, because
// `harness.js` sets rules and not values: when a ``` block and a **values-store**
// entry carry the same name, upstream uses the block (`getValueFor` asks the
// inline map first) and whistle-rs uses the store, so that `--value` can override
// what a rules file brought. Measured through each proxy's own values API; see
// `effective_values` in `src/proxy/mod.rs`.

const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT_BASE || 18700) + 2;
const P = `127.0.0.1:${PORT}`;
const A = `${P}/echo`;

/** A fence, spelled once so the cases below stay readable. */
const B = '```';
/** A pattern that captures the last octet of the origin's address. */
const RE = '/127\\.0\\.0\\.(\\d+):' + PORT + '/';

/** Rules files for the `@` include cases, rewritten on every run. */
const DIR = '/tmp/wrs-values-fixtures';
const F = (name) => path.join(DIR, name);
const INCLUDES = {
  'inc.rules': `${A} reqHeaders://x-included=yes\n`,
  'inc-values.rules': `${B}incval\nFROM-AN-INCLUDED-VALUE\n${B}\n${A} resBody://{incval}\n`,
};
fs.mkdirSync(DIR, { recursive: true });
for (const [name, text] of Object.entries(INCLUDES)) fs.writeFileSync(F(name), text);

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Nothing below means anything until a plain request and a plain value
  // reference are known to work through both proxies.
  { name: 'baseline: no rule at all', rules: '' },
  { name: 'baseline: a rule that does nothing to the response', rules: `${A} reqHeaders://x-a=1` },
  { name: 'baseline: a fenced value reaches an operator', rules: `${B}v\nfrom-a-value\n${B}\n${A} resBody://{v}` },
  { name: 'baseline: a fenced value reaches a request header', rules: `${B}v\nfrom-a-value\n${B}\n${A} reqHeaders://x-v=\${v}` },

  // ── declaring a value ──────────────────────────────────────────────────
  { name: 'a value spanning several lines', rules: `${B}v\nline1\nline2\nline3\n${B}\n${A} resBody://{v}` },
  { name: 'a value whose text looks like a rule', rules: `${B}v\n${A} resBody://(FROM-INSIDE)\n${B}\n${A} resBody://{v}` },
  { name: 'the same name declared twice keeps the first', rules: `${B}v\nFIRST\n${B}\n${B}v\nSECOND\n${B}\n${A} resBody://{v}` },
  { name: 'a value declared after the rule that uses it', rules: `${A} resBody://{v}\n${B}v\nAFTER\n${B}` },
  { name: 'a four-backtick fence', rules: `${'````'}v\nQUAD\n${'````'}\n${A} resBody://{v}` },
  { name: 'a three-backtick fence inside a four-backtick block', rules: `${'````'}v\n${B}\ninner\n${B}\n${'````'}\n${A} resBody://{v}` },
  { name: 'a fence name with whitespace around it', rules: `${B}  v  \nSPACED\n${B}\n${A} resBody://{v}` },
  // The name is `\S+`, so this fence declares nothing — and the reference has
  // to be asked for in one token, since the line is split on whitespace first.
  { name: 'a fence name with a space in it declares nothing', rules: `${B}a b\nTWO\n${B}\n${A} reqHeaders://x-a=[\${a}]` },
  { name: 'a fence with no name declares nothing', rules: `${B}\nX\n${B}\n${A} reqHeaders://x-a=1` },
  { name: 'an unterminated fence declares nothing', rules: `${B}v\nNEVER CLOSED\n${A} resBody://{v}` },
  { name: 'a value used by two operators on one line', rules: `${B}v\nAAA\n${B}\n${A} resBody://{v} reqHeaders://x-a=\${v}` },
  { name: 'a value used by two rule lines', rules: `${B}v\nAAA\n${B}\n${A} reqHeaders://x-a=\${v}\n${A} reqHeaders://x-b=\${v}` },

  // ── names ──────────────────────────────────────────────────────────────
  { name: 'a name containing a dot', rules: `${B}mock.json\n{"a":1}\n${B}\n${A} resBody://{mock.json}` },
  { name: 'a name containing a dash and an underscore', rules: `${B}a-b_c\nDASHED\n${B}\n${A} resBody://{a-b_c}` },
  { name: 'a name containing a colon', rules: `${B}a:b\nCOLON\n${B}\n${A} resBody://{a:b}` },
  { name: 'a name containing a slash', rules: `${B}a/b\nSLASH\n${B}\n${A} resBody://{a/b}` },
  // `getKey` takes everything up to the **last** `}`, so this name is `a}b`.
  { name: 'a name containing a closing brace', rules: `${B}a}b\nBRACE\n${B}\n${A} resBody://{a}b}` },
  { name: 'a name that is a bare number', rules: `${B}1\nONE\n${B}\n${A} resBody://{1}` },
  { name: 'a name containing a percent escape', rules: `${B}a%20b\nESCAPED\n${B}\n${A} resBody://{a%20b}` },

  // ── referring to a value ───────────────────────────────────────────────
  { name: 'a bare {name} with no protocol is a file rule', rules: `${B}v.json\n{"k":1}\n${B}\n${A} {v.json}` },
  { name: 'a reference used as the whole value of reqHeaders', rules: `${B}v\nx-a=1\n${B}\n${A} reqHeaders://{v}` },
  { name: 'a reference whose content is a json object', rules: `${B}h\n{"x-a":"1","x-b":"2"}\n${B}\n${A} reqHeaders://{h}` },
  { name: 'a reference inside a value, with text around it', rules: `${B}v\nVALUE\n${B}\n${A} reqHeaders://x-a=[\${v}]` },
  { name: 'two references in one value, one of them twice', rules: `${B}a\nAA\n${B}\n${B}b\nBB\n${B}\n${A} reqHeaders://x-a=\${a}&x-b=\${b}&x-c=\${a}` },
  { name: 'a reference carrying the whole header pair list', rules: `${B}v\nx-a=1&x-b=2\n${B}\n${A} reqHeaders://\${v}` },
  { name: 'a value that names nothing, whole-value form', rules: `${A} resBody://{nope}` },
  { name: 'a value that names nothing, inside a value', rules: `${A} reqHeaders://x-a=\${nope}` },
  { name: 'a value that names nothing on a request body', rules: `${A} reqBody://{nope}`, request: { method: 'POST', body: 'original' } },
  { name: 'a value that names nothing on a prepend', rules: `${A} resPrepend://{nope}` },
  { name: 'a value that names nothing on a file rule', rules: `${A} file://{nope}` },
  { name: 'empty braces are not a reference', rules: `${B}\nX\n${B}\n${A} resBody://{}` },
  { name: 'trailing text after a reference', rules: `${B}v\nVAL\n${B}\n${A} resBody://{v}tail` },
  { name: 'an empty value on a body operator', rules: `${B}e\n${B}\n${A} resBody://{e}` },
  { name: 'an empty value inside a value', rules: `${B}e\n${B}\n${A} reqHeaders://x-a=[\${e}]` },
  { name: 'a value with newlines cannot become a header', rules: `${B}v\nline1\nline2\n${B}\n${A} reqHeaders://x-a=\${v}` },
  { name: 'a reference is not extended by the unmatched path', rules: `${B}v.json\n{"declared":true}\n${B}\n${P} file://{v.json}`, request: { path: '/js/app.js' } },

  // ── a value's content is not rules text ────────────────────────────────
  // The content is bytes. Upstream expands a matcher exactly once
  // (`resolveVar`, `rules.js:774-783`), so nothing in it is looked at again —
  // which is what a mock body containing `${…}`, `{…}` or a fence depends on.
  { name: 'a ${reference} inside a value is not expanded', rules: `${B}inner\nINNER\n${B}\n${B}outer\nouter-\${inner}\n${B}\n${A} resBody://{outer}` },
  { name: 'a {reference} inside a value is not expanded', rules: `${B}inner\nINNER\n${B}\n${B}outer\n{inner}\n${B}\n${A} resBody://{outer}` },
  { name: 'a value that opens and closes with a backtick', rules: `${'````'}v\n${B}\ncode\n${B}\n${'````'}\n${A} resBody://{v}` },
  { name: 'a ${port} inside a value is not a config variable', rules: `${B}v\nport=\${port}\n${B}\n${A} resBody://{v}` },

  // ── captures and values ────────────────────────────────────────────────
  // Upstream expands values first and substitutes captures second, so a `$1`
  // written inside a shared value arrives expanded.
  { name: 'a capture reaches a value used inside a value', rules: `${B}cap\ngot-$1\n${B}\n${RE} reqHeaders://x-c=\${cap}` },
  { name: 'a capture reaches a value on a wildcard pattern', rules: `${B}cap\ngot-$1\n${B}\n^http://${P}/e** reqHeaders://x-c=\${cap}` },
  { name: 'a capture written on the rule line still expands', rules: `${RE} reqHeaders://x-c=got-$1` },
  { name: 'a pattern that captures nothing leaves the $1 alone', rules: `${B}cap\ngot-$1\n${B}\n${A} reqHeaders://x-c=\${cap}` },
  // The whole-value form is the other way round: `replaceSubMatcher` ran on the
  // six characters `{cap}`, so only `${RegExp.$n}` reaches the content, and only
  // when the rule is a template (`SUB_VAR_RE`, `rules.js:99,:826-830`).
  { name: 'a plain capture inside a whole-value reference is literal', rules: `${B}cap\nx-c=got-$1\n${B}\n${RE} reqHeaders://\`{cap}\`` },
  { name: 'RegExp.$1 inside a backticked whole-value reference', rules: `${B}cap\nx-c=\${RegExp.$1}\n${B}\n${RE} reqHeaders://\`{cap}\`` },
  { name: 'RegExp.$& inside a backticked whole-value reference', rules: `${B}cap\nx-c=\${RegExp.$&}\n${B}\n${RE} reqHeaders://\`{cap}\`` },
  { name: 'RegExp.$1 with a caret wildcard pattern', rules: `${B}cap\nx-c=\${RegExp.$1}\n${B}\n^http://${P}/e** reqHeaders://\`{cap}\`` },
  { name: 'RegExp.$1 without the backticks stays as written', rules: `${B}cap\nx-c=\${RegExp.$1}\n${B}\n${RE} reqHeaders://{cap}` },
  { name: 'RegExp.$1 written on the rule line is not that syntax', rules: `${RE} reqHeaders://\`x-c=\${RegExp.$1}\`` },

  // ── backtick templates ─────────────────────────────────────────────────
  { name: 'a backtick value renders the request variables', rules: `${A} reqHeaders://\`x-m=\${method}&x-p=\${pathname}\`` },
  { name: 'a backtick value with an unknown variable', rules: `${A} reqHeaders://\`x-u=\${nosuchvar}\`` },
  { name: 'a backtick value with an encoded variable', rules: `${A} reqHeaders://\`x-e=\${{url}}\`` },
  { name: 'a backtick value reading the query string', rules: `${A} reqHeaders://\`x-q=\${query.a}\``, request: { path: '/echo?a=hello' } },
  { name: 'a backtick value reading a request header', rules: `${A} reqHeaders://\`x-h=\${reqHeaders.x-tag}\``, request: { headers: { 'x-tag': 'tagged' } } },
  { name: 'a backtick value with a replace modifier', rules: `${A} reqHeaders://\`x-r=\${query.a.replace(o,0)}\``, request: { path: '/echo?a=foo' } },
  { name: 'a backtick value with an empty-pattern default', rules: `${A} reqHeaders://\`x-d=\${query.zz.replace(,fallback)}\`` },
  { name: 'a backtick that does not wrap the whole value', rules: `${A} reqHeaders://\`x-n=\${method}` },
  { name: 'a lone backtick is not a pair', rules: `${A} reqHeaders://\`` },
  { name: 'a backtick on log names a channel', rules: `${A} log://\`\${method}\`` },
  { name: 'a backtick renders what a ${reference} returned', rules: `${B}g\nx-g=\${method}\n${B}\n${A} reqHeaders://\`\${g}\`` },
  { name: 'without backticks the same reference is not rendered', rules: `${B}g\nx-g=\${method}\n${B}\n${A} reqHeaders://\${g}` },
  { name: 'a backtick renders what a whole-value reference returned', rules: `${B}g\nx-g=\${method}-\${pathname}\n${B}\n${A} reqHeaders://\`{g}\`` },

  // The response-side names are the point of a backtick on a response operator,
  // and they are answerable only once the head has arrived.
  { name: 'a backtick reading the status code', rules: `${A} resHeaders://\`x-s=\${statusCode}\`` },
  { name: 'a backtick reading the server port', rules: `${A} resHeaders://\`x-p=\${serverPort}\`` },
  { name: 'a backtick reading a response header', rules: `${A} resHeaders://\`x-o=\${resHeaders.x-origin}\`` },
  { name: 'a backtick reading the status of a mocked response', rules: `${A} file://(mock) resHeaders://\`x-s=\${statusCode}\`` },
  { name: 'a backtick reading a status a rule replaced', rules: `${A} replaceStatus://404 resHeaders://\`x-s=\${statusCode}\`` },
  { name: 'a response-phase operator referencing a fenced value', rules: `${B}v\nFENCED-BODY\n${B}\n${A} resBody://{v} includeFilter://s:200` },
  { name: 'a response-phase header referencing a fenced value', rules: `${B}v\nx-v=fenced\n${B}\n${A} resHeaders://\${v} includeFilter://s:200` },

  // ── inline payloads ────────────────────────────────────────────────────
  // A rule line is split on whitespace before `(` is looked at, so an inline
  // payload is one whitespace-free token. Anything with a space in it belongs in
  // a fenced block.
  { name: 'an inline payload on a body operator', rules: `${A} resBody://(REPLACED)` },
  { name: 'an inline payload on a request header', rules: `${A} reqHeaders://(x-a=1)` },
  { name: 'an inline payload on a single-value operator', rules: `${A} ua://(Mozilla/9)` },
  { name: 'an inline payload on a redirect', rules: `${A} redirect://(http://other.test/x)` },
  { name: 'nested parentheses in a payload', rules: `${A} resBody://((inner))` },
  { name: 'an unbalanced open bracket', rules: `${A} resBody://(oops` },
  { name: 'an unbalanced close bracket', rules: `${A} resBody://oops)` },
  { name: 'an empty inline payload', rules: `${A} resBody://()` },
  { name: 'an empty inline payload on a request body', rules: `${A} reqBody://()`, request: { method: 'POST', body: 'original' } },
  { name: 'angle brackets inside a payload', rules: `${A} resBody://(<b>hi</b>)` },
  { name: 'a percent escape inside a payload', rules: `${A} resBody://(a%20b)` },
  { name: 'a payload whose hash is eaten by the comment stripper', rules: `${A} resBody://(a#b)` },
  { name: 'angle brackets on a body operator', rules: `${A} resBody://<hello>` },
  { name: 'angle brackets around a payload containing parens', rules: `${A} resBody://<a(b)c>` },
  { name: 'a script tag in angle brackets', rules: `${P}/html htmlAppend://<script>x</script>`, request: { path: '/html' } },
  { name: 'a script tag in parentheses', rules: `${P}/html htmlAppend://(<script>x</script>)`, request: { path: '/html' } },
  { name: 'a json object is a value, not a location', rules: `${A} resBody://{"a":1}` },
  { name: 'a json array is a value too', rules: `${A} resBody://[1,2]` },

  // ── templates over a value ─────────────────────────────────────────────
  // The two passes a `tpl://` body takes are the query-string `{name}` one and
  // the runtime `${var}` one; a value's *name* is what its content type is
  // guessed from.
  { name: 'tpl renders a fenced value', rules: `${B}t.json\n{"q":"{name}","m":"\${method}"}\n${B}\n${A} tpl://{t.json}`, request: { path: '/echo?name=world' } },
  { name: 'tpl of a fenced value with no query string', rules: `${B}t.json\n{"q":"{name}","m":"\${method}"}\n${B}\n${A} tpl://{t.json}` },
  { name: 'tpl of a fenced value with a repeated query key', rules: `${B}t.json\n{"q":"{name}"}\n${B}\n${A} tpl://{t.json}`, request: { path: '/echo?name=a&name=b' } },
  { name: 'tpl of a fenced value with an escaped variable', rules: `${B}t.json\n{"q":"\${name}"}\n${B}\n${A} tpl://{t.json}`, request: { path: '/echo?name=world' } },
  { name: 'tpl of a fenced value with an unknown query name', rules: `${B}t.json\n{"z":"{zzz}"}\n${B}\n${A} tpl://{t.json}` },
  { name: 'tpl of a fenced value with no braces at all', rules: `${B}t.txt\nno braces, bare $method\n${B}\n${A} tpl://{t.txt}` },
  { name: 'tpl of a fenced value with a runtime variable only', rules: `${B}t.txt\nonly \${method}\n${B}\n${A} tpl://{t.txt}` },
  { name: 'tpl of a fenced value with a spaced brace', rules: `${B}t.txt\n\${ method }\n${B}\n${A} tpl://{t.txt}` },
  { name: 'tpl of an inline payload', rules: `${A} tpl://(q={name}-m=\${method})`, request: { path: '/echo?name=world' } },
  { name: 'a content type guessed from the value name', rules: `${B}t.json\n{"a":1}\n${B}\n${A} file://{t.json}` },
  { name: 'a content type with no extension in the value name', rules: `${B}tbody\nplain\n${B}\n${A} file://{tbody}` },
  { name: 'rawfile parses a fenced value', rules: `${B}r.http\nHTTP/1.1 418 Teapot\r\nX-F: yes\r\n\r\nteapot body\n${B}\n${A} rawfile://{r.http}` },

  // ── @ includes ─────────────────────────────────────────────────────────
  // A line that is only `@` and an absolute path or a URL is spliced in where
  // it stands (`REMOTE_RULES_RE`, `_original/lib/util/index.js:3295`), values
  // and all. A relative path is not — the regexp requires `/`, `~/`, a drive
  // letter or `http(s)://` — and a line with a pattern in front of it is the
  // `G://` operator, not an include. The rest of the family, including the
  // `@<url>` half and where the spliced lines land in precedence, is in
  // `cases-includes.js`.
  { name: 'an @ include of a rules file', rules: `@${F('inc.rules')}` },
  { name: 'an @ include declaring its own value', rules: `@${F('inc-values.rules')}` },
  { name: 'an @ include of a relative path is not an include', rules: '@inc.rules' },
  { name: 'an @ include of a file that does not exist', rules: `@${F('nope.rules')}` },
  { name: 'an @ line with a pattern in front is not an include', rules: `${A} @${F('inc.rules')}` },
];
