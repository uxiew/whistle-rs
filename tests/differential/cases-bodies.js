// Body rewriting across content types and encodings.
//
// This is the area where the two implementations differ *architecturally*:
// whistle rewrites a response with stream transforms, this port buffers. Almost
// everything here exists to find out what that difference means at the edges —
// a gzipped page under `resReplace://`, a GBK page under an injection, an image
// under a body operator, a JSON body under `resMerge://`.
//
// Every family opens with a **baseline**: the same request with no rule at all.
// If the two proxies already disagree about what the origin sent, nothing said
// about the rule that follows means anything.
const zlib = require('zlib');

const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

/** A POST of `body`, for the request-side cases. */
const post = (body, headers) => ({ method: 'POST', path: '/echo', body, headers });

/** The same, with the body actually compressed rather than merely labelled. */
const gzPost = (text, headers) => post(zlib.gzipSync(text), { 'content-encoding': 'gzip', ...headers });

module.exports = [
  // ── baselines: no rule, every origin answer this corpus uses ───────────
  ...['/gz', '/deflate', '/rawdeflate', '/br', '/xgzip', '/zstd', '/liar',
    '/gbk', '/js', '/css', '/json', '/plain', '/xml', '/png', '/octet',
    '/notutf8', '/notype', '/chunked', '/trailers', '/gzjson', '/html',
  ].map((path) => ({ name: `baseline ${path}`, rules: '', request: { path } })),
  { name: 'baseline /big 64k', rules: '', request: { path: '/big?n=65536' } },

  // ── compressed responses under a substitution ──────────────────────────
  // The pattern is in the *decompressed* text, so finding it at all is the
  // whole test; the client must then get a body its Content-Encoding describes.
  { name: 'resReplace on a gzip page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/gz' } },
  { name: 'resReplace on a deflate page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/deflate' } },
  { name: 'resReplace on a br page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/br' } },
  { name: 'resReplace regexp on a gzip page', rules: `${P} resReplace:///ORIG(INAL)/=X$1`, request: { path: '/gz' } },
  // Encodings that cannot be round-tripped: the operator must not corrupt them.
  { name: 'resReplace on a raw-deflate page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/rawdeflate' } },
  { name: 'resReplace on an x-gzip page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/xgzip' } },
  { name: 'resReplace on a zstd page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/zstd' } },
  { name: 'resReplace on a body that lies about gzip', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/liar' } },

  // ── compressed responses under an injection ────────────────────────────
  { name: 'htmlAppend on a gzip page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/gz' } },
  { name: 'htmlAppend on a br page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/br' } },
  { name: 'htmlAppend on a deflate page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/deflate' } },
  { name: 'jsAppend on a gzip page', rules: `${P} jsAppend://(alert(1))`, request: { path: '/gz' } },
  { name: 'resBody on a gzip page', rules: `${P} resBody://(NEW BODY)`, request: { path: '/gz' } },
  { name: 'resPrepend and resAppend on a br page', rules: `${P} resPrepend://(TOP) resAppend://(END)`, request: { path: '/br' } },
  { name: 'resMerge into a gzip json body', rules: `${P} resMerge://{"extra":1}`, request: { path: '/gzjson' } },

  // ── enable://gzip | br | deflate ───────────────────────────────────────
  { name: 'enable gzip on a plaintext page', rules: `${P} enable://gzip`, request: { path: '/html' } },
  { name: 'enable br on a plaintext page', rules: `${P} enable://br`, request: { path: '/html' } },
  { name: 'enable deflate on a plaintext page', rules: `${P} enable://deflate`, request: { path: '/html' } },
  { name: 'enable gzip with a substitution', rules: `${P} enable://gzip resReplace://ORIGINAL=REWRITTEN`, request: { path: '/html' } },
  { name: 'enable br over an arriving gzip', rules: `${P} enable://br`, request: { path: '/gz' } },
  { name: 'enable gzip over an arriving gzip', rules: `${P} enable://gzip`, request: { path: '/gz' } },
  { name: 'enable gzip over an arriving br, rewritten', rules: `${P} enable://gzip resReplace://ORIGINAL=REWRITTEN`, request: { path: '/br' } },
  // The origin's encoding cannot be undone: compressing again would hand the
  // client a body wrapped twice and labelled once.
  { name: 'enable gzip over an arriving zstd', rules: `${P} enable://zstd`, request: { path: '/zstd' } },
  { name: 'enable gzip on an undecodable body', rules: `${P} enable://gzip`, request: { path: '/zstd' } },
  { name: 'enable gzip on a body that lies about gzip', rules: `${P} enable://gzip`, request: { path: '/liar' } },
  { name: 'enable gzip on an image', rules: `${P} enable://gzip`, request: { path: '/png' } },
  { name: 'enable gzip on an empty answer', rules: `${P} enable://gzip statusCode://204` },

  // ── request bodies under an encoding ───────────────────────────────────
  { name: 'baseline gzip request body', rules: '', request: post('', { 'content-encoding': 'gzip', 'content-type': 'text/plain' }) },
  { name: 'reqReplace on a plain request body', rules: `${P} reqReplace://ORIGINAL=REWRITTEN`, request: post('ORIGINAL body', { 'content-type': 'text/plain' }) },
  { name: 'params into a json request body', rules: `${P} params://x=1`, request: post('{"a":1}', { 'content-type': 'application/json' }) },
  { name: 'reqBody replaces a request body', rules: `${P} reqBody://(NEW)`, request: post('OLD', { 'content-type': 'text/plain' }) },
  // A body that really is gzipped: the operator has to find its pattern in the
  // decompressed text, and the origin has to receive something it can inflate.
  { name: 'baseline a gzipped request body', rules: '', request: gzPost('ORIGINAL body', { 'content-type': 'text/plain' }) },
  { name: 'reqReplace on a gzipped request body', rules: `${P} reqReplace://ORIGINAL=REWRITTEN`, request: gzPost('ORIGINAL body', { 'content-type': 'text/plain' }) },
  { name: 'reqAppend onto a gzipped request body', rules: `${P} reqAppend://(END)`, request: gzPost('ORIGINAL body', { 'content-type': 'text/plain' }) },
  { name: 'reqBody over a gzipped request body', rules: `${P} reqBody://(NEW)`, request: gzPost('ORIGINAL body', { 'content-type': 'text/plain' }) },
  { name: 'params into a gzipped json request body', rules: `${P} params://x=1`, request: gzPost('{"a":1}', { 'content-type': 'application/json' }) },

  // ── charsets ───────────────────────────────────────────────────────────
  // The page is GBK; the pattern and the injected text are ASCII. What the
  // origin's own non-ASCII bytes look like afterwards is the question.
  { name: 'resReplace on a gbk page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/gbk' } },
  { name: 'htmlAppend on a gbk page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/gbk' } },
  { name: 'resAppend on a gbk page', rules: `${P} resAppend://(END)`, request: { path: '/gbk' } },
  { name: 'resBody on a gbk page', rules: `${P} resBody://(NEW BODY)`, request: { path: '/gbk' } },
  { name: 'resCharset over a gbk page', rules: `${P} resCharset://utf-8`, request: { path: '/gbk' } },
  // The cases that discriminate: a value the two charsets spell differently.
  { name: 'resReplace writes cjk into a gbk page', rules: `${P} resReplace://ORIGINAL=中文`, request: { path: '/gbk' } },
  { name: 'htmlAppend writes cjk into a gbk page', rules: `${P} htmlAppend://(<i>中文</i>)`, request: { path: '/gbk' } },
  { name: 'jsAppend writes cjk into a gbk page', rules: `${P} jsAppend://(alert('中文'))`, request: { path: '/gbk' } },
  { name: 'resBody writes cjk into a gbk page', rules: `${P} resBody://(中文)`, request: { path: '/gbk' } },
  { name: 'resAppend writes cjk into a utf-8 page', rules: `${P} resAppend://(中文)`, request: { path: '/html' } },

  // ── an operator written with no value ──────────────────────────────────
  // `util.EMPTY_BUFFER` is `undefined`, so upstream builds no transform at all:
  // the body is untouched and the CSP/cache strip that comes with an injection
  // never runs either.
  { name: 'baseline /cached', rules: '', request: { path: '/cached' } },
  ...['resBody://()', 'resBody://', 'htmlBody://()', 'jsBody://()', 'resPrepend://()',
    'resAppend://()', 'htmlAppend://()', 'cssAppend://()',
  ].map((rule) => (
    { name: `${rule} is inert`, rules: `${P} ${rule}`, request: { path: '/cached' } })),
  // …and the same operator with a value does take the CSP and the cache.
  { name: 'resPrepend with a value takes the csp and cache', rules: `${P} resPrepend://(<!--t-->)`, request: { path: '/cached' } },

  // ── bodies that are not text ───────────────────────────────────────────
  { name: 'resReplace on an image', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/png' } },
  { name: 'resReplace on octet-stream', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/octet' } },
  { name: 'resReplace on a body that is not utf-8', rules: `${P} resReplace://ORIG=X`, request: { path: '/notutf8' } },
  { name: 'resReplace on a typeless body', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/notype' } },
  { name: 'htmlAppend on an image', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/png' } },
  { name: 'resAppend on an image', rules: `${P} resAppend://(END)`, request: { path: '/png' } },
  { name: 'resBody on an image', rules: `${P} resBody://(NEW)`, request: { path: '/png' } },
  { name: 'resAppend on octet-stream', rules: `${P} resAppend://(END)`, request: { path: '/octet' } },
  { name: 'htmlAppend on octet-stream', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/octet' } },

  // ── the typed families against each type ───────────────────────────────
  // Which family a response accepts is not obvious: HTML takes all three,
  // JS takes only `js*`, CSS only `css*`, and JSON none of them.
  ...[['html', '/html'], ['html', '/js'], ['html', '/css'], ['html', '/json'], ['html', '/plain'],
    ['js', '/html'], ['js', '/js'], ['js', '/css'], ['js', '/json'], ['js', '/plain'],
    ['css', '/html'], ['css', '/js'], ['css', '/css'], ['css', '/json'], ['css', '/plain'],
  ].flatMap(([family, path]) => [
    { name: `${family}Append on ${path}`, rules: `${P} ${family}Append://(/*A*/)`, request: { path } },
    { name: `${family}Prepend on ${path}`, rules: `${P} ${family}Prepend://(/*P*/)`, request: { path } },
    { name: `${family}Body on ${path}`, rules: `${P} ${family}Body://(/*B*/)`, request: { path } },
  ]),
  // A bare URL in a typed value is linked rather than inlined.
  { name: 'jsAppend with a url value on html', rules: `${P} jsAppend://(//cdn.test/a.js)`, request: { path: '/html' } },
  { name: 'cssAppend with a url value on html', rules: `${P} cssAppend://(//cdn.test/a.css)`, request: { path: '/html' } },
  { name: 'jsAppend with a url value on js', rules: `${P} jsAppend://(//cdn.test/a.js)`, request: { path: '/js' } },
  // Two lines of one typed operator: one wrapper each, not one holding both.
  { name: 'two jsAppend lines on html', rules: `${P} jsAppend://(a())\n${P} jsAppend://(b())`, request: { path: '/html' } },
  // The generic family reaches every type, wrapped in nothing.
  ...['/html', '/js', '/css', '/json', '/plain', '/xml'].map((path) => (
    { name: `resAppend on ${path}`, rules: `${P} resAppend://(END)`, request: { path } })),

  // ── resMerge and JSON ──────────────────────────────────────────────────
  { name: 'resMerge into json', rules: `${P} resMerge://{"extra":1}`, request: { path: '/json' } },
  { name: 'resMerge overwrites a key', rules: `${P} resMerge://{"a":9}`, request: { path: '/json' } },
  { name: 'resMerge into js', rules: `${P} resMerge://{"extra":1}`, request: { path: '/js' } },
  { name: 'resMerge into html', rules: `${P} resMerge://{"extra":1}`, request: { path: '/html' } },
  { name: 'resMerge into text/plain', rules: `${P} resMerge://{"extra":1}`, request: { path: '/plain' } },
  { name: 'resMerge into xml', rules: `${P} resMerge://{"extra":1}`, request: { path: '/xml' } },
  { name: 'resMerge into a typeless body', rules: `${P} resMerge://{"extra":1}`, request: { path: '/notype' } },
  { name: 'resMerge into an image', rules: `${P} resMerge://{"extra":1}`, request: { path: '/png' } },
  { name: 'resMerge two lines', rules: `${P} resMerge://{"a":2}\n${P} resMerge://{"b":3}`, request: { path: '/json' } },
  { name: 'resMerge deep with a true marker', rules: `${P} resMerge://true\n${P} resMerge://{"n":{"x":1}}\n${P} resMerge://{"n":{"y":2}}`, request: { path: '/json' } },
  { name: 'delete a json body property', rules: `${P} delete://resBody.keep`, request: { path: '/json' } },
  { name: 'resMerge then resReplace', rules: `${P} resMerge://{"extra":1} resReplace://yes=no`, request: { path: '/json' } },

  // ── framing: chunked, content-length, trailers ─────────────────────────
  { name: 'resReplace on a chunked page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/chunked' } },
  { name: 'htmlAppend on a chunked page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/chunked' } },
  { name: 'resReplace on a page with trailers', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/trailers' } },
  { name: 'htmlAppend on a page with trailers', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/trailers' } },
  { name: 'resBody on a page with trailers', rules: `${P} resBody://(NEW)`, request: { path: '/trailers' } },
  { name: 'trailers added to a rewritten page', rules: `${P} htmlAppend://(<i>hi</i>) trailers://{"x-added":"1"}`, request: { path: '/html' } },

  // ── size ───────────────────────────────────────────────────────────────
  // Under the port's rewrite ceiling, so both sides must agree exactly.
  { name: 'resReplace on a 64k page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/big?n=65536' } },
  { name: 'resReplace on a 1M page', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/big?n=1048576' } },
  { name: 'htmlAppend on a 1M page', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/big?n=1048576' } },
  // Either side of the port's 16 MiB rewrite ceiling. Under it the two agree
  // byte for byte; over it this port forwards the response untouched, which is
  // the declared cost of buffering where whistle streams — see `src/config.rs`.
  { name: 'resReplace just under the rewrite ceiling', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/big?n=16777100' } },
  { name: 'resReplace just over the rewrite ceiling', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/big?n=16777300' } },
  { name: 'resAppend just over the rewrite ceiling', rules: `${P} resAppend://(TAIL)`, request: { path: '/big?n=16777300' } },

  // ── the injection family's remaining spellings ──────────────────────────
  //
  // `cssBody`, `cssPrepend` and `jsPrepend` were the three names in the family
  // that no corpus mentioned.
  //
  // Their selection is **not** one type each. `isJs = isHtml || resType ===
  // 'JS'` and `isCss = isHtml || resType === 'CSS'`
  // (`_original/lib/inspectors/res.js:947-949`), so the js and css families
  // both reach an HTML page as well — wrapped in `<script>` / `<style>` there,
  // bare on their own type. Only the `html*` three are HTML-only. Each is
  // therefore asked on its own type, on HTML, and on the *other* family's type,
  // which is the one place it must stay out.
  //
  // No payload here contains a space: a rules line is split on whitespace
  // before an operator's brackets are read, so `jsAppend://(var TOP=1;)` is two
  // tokens and does nothing. That is pinned as its own case below rather than
  // left to silently hollow out the others — it hollowed out three of these
  // while they were being written, and they still passed.
  { name: 'cssBody on a css response', rules: `${P} cssBody://(.b{color:green})`, request: { path: '/style.css' } },
  { name: 'cssBody on an html page wraps in style', rules: `${P} cssBody://(.b{color:green})`, request: { path: '/html' } },
  { name: 'cssBody stays out of a js response', rules: `${P} cssBody://(.b{color:green})`, request: { path: '/script.js' } },
  { name: 'cssPrepend on a css response', rules: `${P} cssPrepend://(/*TOP*/)`, request: { path: '/style.css' } },
  { name: 'cssPrepend on an html page', rules: `${P} cssPrepend://(/*TOP*/)`, request: { path: '/html' } },
  { name: 'cssPrepend stays out of a js response', rules: `${P} cssPrepend://(/*TOP*/)`, request: { path: '/script.js' } },
  { name: 'jsPrepend on a js response', rules: `${P} jsPrepend://(TOP=1)`, request: { path: '/script.js' } },
  { name: 'jsPrepend on an html page wraps in script', rules: `${P} jsPrepend://(TOP=1)`, request: { path: '/html' } },
  { name: 'jsPrepend stays out of a css response', rules: `${P} jsPrepend://(TOP=1)`, request: { path: '/style.css' } },
  // The pair on one type, so a shared slot between them would show as one
  // winning over the other.
  { name: 'cssPrepend and cssBody on one line', rules: `${P} cssPrepend://(/*TOP*/) cssBody://(.b{color:green})`, request: { path: '/style.css' } },
  { name: 'jsPrepend beside jsAppend', rules: `${P} jsPrepend://(TOP=1) jsAppend://(END=1)`, request: { path: '/script.js' } },
  // On a compressed body, where the injection has to decode and re-encode.
  { name: 'jsPrepend on a gzip page', rules: `${P} jsPrepend://(TOP=1)`, request: { path: '/gz' } },
  // The space. Both proxies read two tokens and inject nothing — the second
  // token is not an operator, so it is a pattern nothing matches.
  { name: 'an inline payload cannot contain a space', rules: `${P} jsAppend://(var TOP=1;)`, request: { path: '/html' } },
  { name: 'the same payload without the space does inject', rules: `${P} jsAppend://(var_TOP=1;)`, request: { path: '/html' } },
];
