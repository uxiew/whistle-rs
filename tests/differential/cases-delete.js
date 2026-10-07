// `delete://` and the operators that shape typing, cookies and CORS.
//
// `delete://` takes no bare name: every key is matched against a fixed set of
// anchored patterns (`_original/lib/util/index.js:2659-2672`) and anything
// unrecognised is silently dropped. The spellings below are that vocabulary,
// each written the several ways the regexes accept, plus the operators the
// deletions interact with — `reqType`, `resType`, `reqCharset`, `resCharset`,
// `reqCookies`, `resCookies`, `reqCors`, `resCors`.
//
// `P` is the origin's authority; rules are written against it so the same text
// can go to both proxies unchanged.
//
// Eight cases here are **expected** to differ, on two deliberate divergences.
// They are not in `harness.js`'s `EXPECTED` because a matcher wide enough to
// catch them would also hide real news in another corpus — what makes them
// expected is the rule, which the matcher cannot see. A clean run of this file
// has these eight as `declared` (in `declared.js`) and `differing: 0`:
//
//   * `delete bare body on a post`, `delete req.body …` (×3),
//     `delete res.body …` (×3) — all one defect. `EMPTY_BUFFER` is
//     `toBuffer('')`, and `toBuffer` returns `undefined` on a falsy argument
//     (`_original/lib/util/common.js:1630-1632`), so the constant every
//     "empty the body" path assigns is `undefined`. `removeBody` therefore
//     discards the body *injections* and forwards the real body untouched
//     (`util/index.js:3591-3598`). That is neither what upstream's own code
//     means nor what <https://wproxy.org/docs/rules/delete.html> promises, and
//     `delete://body` is an explicit request for an empty body, so whix
//     empties it.
//
//     `reqBody with an empty value` and `resBody with an empty value` were on
//     this list and are not any more. They are the same root cause but not the
//     same question: an operator written with *no value* is not a request for
//     an empty body, it is an operator nobody filled in, and blanking the page
//     for it — plus stripping the CSP and stamping `no-store`, which the port
//     also did — is a footgun rather than an improvement. The bodies audit
//     matched upstream there; the two cases now agree.
//   * `delete bare pathname keeps the query` — upstream appends the query
//     twice (`/a?x=1` → `/?x=1?x=1`, `util/index.js:1033,1057`), which is a
//     request line no origin parses.
//
// One caveat on reading a run: the cases that expire a cookie render an
// `Expires` from the clock, and the two proxies are asked one after the other.
// A `set-cookie` difference of exactly one second is the bench straddling a
// second boundary, not a divergence — re-run it.
const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

/** A request carrying a cookie, a header and a query — most keys have a target. */
const rich = {
  path: '/echo?a=1&b=2',
  headers: { cookie: 'sid=secret; other=keep', 'x-a': 'header-a' },
};

const json = (body) => ({
  method: 'POST',
  body,
  headers: { 'content-type': 'application/json' },
});

const form = (body) => ({
  method: 'POST',
  body,
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
});

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Nothing is asked of either proxy. A difference here is the bench's, not
  // the port's, and every case below is read against it.
  { name: 'baseline: no rule at all', rules: '# nothing' },
  { name: 'baseline: no rule, rich request', rules: '# nothing', request: rich },
  { name: 'baseline: no rule, json post', rules: '# nothing', request: json('{"a":1,"b":{"c":2}}') },

  // ── delete: request headers, every spelling ────────────────────────────
  { name: 'delete reqHeaders.x', rules: `${P} delete://reqHeaders.x-a`, request: rich },
  { name: 'delete req.headers.x', rules: `${P} delete://req.headers.x-a`, request: rich },
  { name: 'delete reqHeader.x singular', rules: `${P} delete://reqHeader.x-a`, request: rich },
  { name: 'delete reqH.x', rules: `${P} delete://reqH.x-a`, request: rich },
  { name: 'delete req.h.x', rules: `${P} delete://req.h.x-a`, request: rich },
  { name: 'delete REQHEADERS.X uppercase', rules: `${P} delete://REQHEADERS.X-A`, request: rich },
  // `HEADER_RE` carries no side, so it applies to request and response alike.
  { name: 'delete headers.x hits the request', rules: `${P} delete://headers.x-a`, request: rich },
  { name: 'delete headers.x hits the response', rules: `${P} delete://headers.x-origin` },
  // …and it is anchored, case-sensitive and plural-only, so these are inert.
  { name: 'delete header.x singular is inert', rules: `${P} delete://header.x-a`, request: rich },
  { name: 'delete Headers.x capitalised is inert', rules: `${P} delete://Headers.x-a`, request: rich },
  { name: 'delete bare name is inert', rules: `${P} delete://x-a`, request: rich },
  // There is no bare form for the header sections: unlike `query`, a section
  // name with nothing after it matches no pattern at all.
  { name: 'delete bare reqHeaders is inert', rules: `${P} delete://reqHeaders`, request: rich },
  { name: 'delete bare resHeaders is inert', rules: `${P} delete://resHeaders` },
  { name: 'delete bare headers is inert', rules: `${P} delete://headers`, request: rich },
  { name: 'delete bare reqCookies is inert', rules: `${P} delete://reqCookies`, request: rich },
  { name: 'delete bare trailer is inert', rules: `${P} trailers://{"x-t":"1"} delete://trailer` },

  // ── delete: response headers ───────────────────────────────────────────
  { name: 'delete resHeaders.x', rules: `${P} delete://resHeaders.x-origin` },
  { name: 'delete res.headers.x', rules: `${P} delete://res.headers.x-origin` },
  { name: 'delete resHeader.x singular', rules: `${P} delete://resHeader.x-origin` },
  { name: 'delete resH.x', rules: `${P} delete://resH.x-origin` },
  { name: 'delete res.h.x', rules: `${P} delete://res.h.x-origin` },
  { name: 'delete resHeaders.content-type', rules: `${P} delete://resHeaders.content-type` },
  { name: 'delete resHeaders on a name that is not there', rules: `${P} delete://resHeaders.x-absent` },
  // The two sides do not leak into each other.
  { name: 'delete resHeaders.x-a leaves the request header', rules: `${P} delete://resHeaders.x-a`, request: rich },
  { name: 'delete reqHeaders.x-origin leaves the response header', rules: `${P} delete://reqHeaders.x-origin` },

  // ── delete: request cookies ────────────────────────────────────────────
  { name: 'delete reqCookies.x', rules: `${P} delete://reqCookies.sid`, request: rich },
  { name: 'delete req.cookies.x', rules: `${P} delete://req.cookies.sid`, request: rich },
  { name: 'delete reqCookie.x singular', rules: `${P} delete://reqCookie.sid`, request: rich },
  { name: 'delete reqC.x', rules: `${P} delete://reqC.sid`, request: rich },
  { name: 'delete req.c.x', rules: `${P} delete://req.c.sid`, request: rich },
  // `COOKIE_RE` carries no side either.
  { name: 'delete cookies.x hits the request', rules: `${P} delete://cookies.sid`, request: rich },
  { name: 'delete cookie.x singular hits the request', rules: `${P} delete://cookie.sid`, request: rich },
  { name: 'delete every request cookie empties the header', rules: `${P} delete://reqCookies.sid|reqCookies.other`, request: rich },
  { name: 'delete reqCookies on a name that is not there', rules: `${P} delete://reqCookies.absent`, request: rich },

  // ── delete: response cookies ───────────────────────────────────────────
  // Nothing to remove from the response: the cookie is already in the client,
  // so the deletion is served as an already-expired `Set-Cookie`.
  { name: 'delete resCookies.x expires it', rules: `${P} delete://resCookies.sid` },
  { name: 'delete res.cookies.x expires it', rules: `${P} delete://res.cookies.sid` },
  { name: 'delete resC.x expires it', rules: `${P} delete://resC.sid` },
  { name: 'delete resCookies.x beats resCookies setting it', rules: `${P} resCookies://sid=abc delete://resCookies.sid` },
  { name: 'delete cookies.x expires it on the response too', rules: `${P} delete://cookies.sid`, request: rich },

  // ── delete: query string ───────────────────────────────────────────────
  { name: 'delete query.x', rules: `${P} delete://query.b`, request: rich },
  { name: 'delete params.x', rules: `${P} delete://params.b`, request: rich },
  { name: 'delete urlParams.x', rules: `${P} delete://urlParams.b`, request: rich },
  { name: 'delete urlParam.x singular', rules: `${P} delete://urlParam.b`, request: rich },
  { name: 'delete url.params.x', rules: `${P} delete://url.params.b`, request: rich },
  { name: 'delete QUERY.x uppercase', rules: `${P} delete://QUERY.b`, request: rich },
  { name: 'delete bare query drops the whole string', rules: `${P} delete://query`, request: rich },
  { name: 'delete bare params drops the whole string', rules: `${P} delete://params`, request: rich },
  { name: 'delete bare urlParams drops the whole string', rules: `${P} delete://urlParams`, request: rich },
  { name: 'delete the only query key drops the question mark', rules: `${P} delete://query.a`, request: { path: '/echo?a=1' } },
  { name: 'delete query with no query at all', rules: `${P} delete://query.a` },
  { name: 'delete a valueless query key', rules: `${P} delete://query.flag`, request: { path: '/echo?flag&a=1' } },
  { name: 'delete a repeated query key takes both', rules: `${P} delete://query.a`, request: { path: '/echo?a=1&a=2&b=3' } },
  { name: 'delete query runs after urlParams wrote it', rules: `${P} urlParams://z=9 delete://query.z` },
  { name: 'delete query.a with params adding it back', rules: `${P} delete://query.a urlParams://a=new`, request: rich },

  // ── delete: the escape table `delete.md` prints ────────────────────────
  //
  // `parseProps` is one regexp over the whole value
  // (`_original/lib/util/common.js:73,:111-127`): a separator behind an odd
  // number of backslashes is text rather than a split, and `\s`/`\t`/`\n`/
  // `\r`/`\f`/`\v` become the characters they name. This port split on `|`
  // and `&` and stopped, so `delete.md`'s own example — a body key holding a
  // newline and a pipe — deleted nothing.
  { name: 'delete an escaped pipe and amp in a key', rules: `${P} delete://reqBody.test\\|\\&test`, request: { method: 'POST', body: '{"test|&test":1,"keep":2}', headers: { 'content-type': 'application/json' } } },
  { name: 'delete an escaped newline in a key', rules: `${P} delete://reqBody.a\\nb`, request: { method: 'POST', body: '{"a\\nb":1,"keep":2}', headers: { 'content-type': 'application/json' } } },
  { name: 'delete an escaped tab in a key', rules: `${P} delete://reqBody.a\\tb`, request: { method: 'POST', body: '{"a\\tb":1,"keep":2}', headers: { 'content-type': 'application/json' } } },
  { name: 'delete an escaped space in a key', rules: `${P} delete://reqBody.a\\sb`, request: { method: 'POST', body: '{"a b":1,"keep":2}', headers: { 'content-type': 'application/json' } } },
  { name: 'delete two keys separated by an unescaped pipe', rules: `${P} delete://reqBody.a|reqBody.b`, request: { method: 'POST', body: '{"a":1,"b":2,"keep":3}', headers: { 'content-type': 'application/json' } } },

  // ── delete: pathname ───────────────────────────────────────────────────
  { name: 'delete bare pathname', rules: `${P} delete://pathname`, request: { path: '/one/two/three' } },
  { name: 'delete bare pathname keeps the query', rules: `${P} delete://pathname`, request: { path: '/one/two?a=1' } },
  { name: 'delete pathname.0', rules: `${P} delete://pathname.0`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.1', rules: `${P} delete://pathname.1`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.first', rules: `${P} delete://pathname.first`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.last', rules: `${P} delete://pathname.last`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.-1', rules: `${P} delete://pathname.-1`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.-2', rules: `${P} delete://pathname.-2`, request: { path: '/one/two/three' } },
  { name: 'delete pathname0 with no dot', rules: `${P} delete://pathname0`, request: { path: '/one/two/three' } },
  { name: 'delete pathname-1 with no dot', rules: `${P} delete://pathname-1`, request: { path: '/one/two/three' } },
  { name: 'delete pathname.9 out of range', rules: `${P} delete://pathname.9`, request: { path: '/one/two/three' } },
  { name: 'delete two path segments at once', rules: `${P} delete://pathname.0|pathname.2`, request: { path: '/one/two/three' } },
  { name: 'delete pathname and a query key together', rules: `${P} delete://pathname.0|query.b`, request: { path: '/one/two?a=1&b=2' } },
  { name: 'delete pathname on a single-segment path', rules: `${P} delete://pathname.0`, request: { path: '/only' } },

  // ── delete: request body ───────────────────────────────────────────────
  { name: 'delete reqBody.x on json', rules: `${P} delete://reqBody.a`, request: json('{"a":1,"b":2}') },
  { name: 'delete req.body.x on json', rules: `${P} delete://req.body.a`, request: json('{"a":1,"b":2}') },
  { name: 'delete reqB.x on json', rules: `${P} delete://reqB.a`, request: json('{"a":1,"b":2}') },
  { name: 'delete req.b.x on json', rules: `${P} delete://req.b.a`, request: json('{"a":1,"b":2}') },
  { name: 'delete a nested json path', rules: `${P} delete://reqBody.a.b`, request: json('{"a":{"b":1,"c":2},"d":3}') },
  { name: 'delete a two-level nested json path', rules: `${P} delete://reqBody.a.b.c`, request: json('{"a":{"b":{"c":1,"d":2}}}') },
  { name: 'delete a json array element', rules: `${P} delete://reqBody.a.1`, request: json('{"a":[1,2,3]}') },
  { name: 'delete a json path that is not there', rules: `${P} delete://reqBody.zz`, request: json('{"a":1}') },
  { name: 'delete through a json path whose parent is missing', rules: `${P} delete://reqBody.zz.yy`, request: json('{"a":1}') },
  { name: 'delete reqBody.x on urlencoded', rules: `${P} delete://reqBody.a`, request: form('a=1&b=2') },
  { name: 'delete every urlencoded key', rules: `${P} delete://reqBody.a|reqBody.b`, request: form('a=1&b=2') },
  { name: 'delete reqBody.x alongside params', rules: `${P} params://c=3 delete://reqBody.a`, request: form('a=1&b=2') },
  { name: 'delete reqBody.x and params writing it back', rules: `${P} params://a=new delete://reqBody.a`, request: json('{"a":1,"b":2}') },
  { name: 'delete reqBody.x on a body that is not json', rules: `${P} delete://reqBody.a`, request: { method: 'POST', body: 'plain text', headers: { 'content-type': 'text/plain' } } },
  // The two path spellings `parseKeys` accepts beyond a plain dot
  // (`_original/lib/util/common.js:1051-1103`): a `\.`-escaped dot names a key
  // that contains one, and `a[0]` indexes an array.
  { name: 'delete a json key whose name contains a dot', rules: `${P} delete://reqBody.a\\.b`, request: json('{"a.b":1,"c":2}') },
  { name: 'delete a json array element in bracket form', rules: `${P} delete://reqBody.a[0]`, request: json('{"a":[1,2,3]}') },
  { name: 'delete a nested json array element in bracket form', rules: `${P} delete://reqBody.a.b[1]`, request: json('{"a":{"b":[1,2,3]}}') },

  // ── delete: whole body ─────────────────────────────────────────────────
  { name: 'delete bare body on a post', rules: `${P} delete://body`, request: json('{"a":1}') },
  { name: 'delete req.body on a post', rules: `${P} delete://req.body`, request: json('{"a":1}') },
  { name: 'delete bare reqBody on a post', rules: `${P} delete://reqBody`, request: json('{"a":1}') },
  { name: 'delete req.body discards reqBody the operator', rules: `${P} reqBody://(INJECTED) delete://req.body`, request: json('{"a":1}') },
  { name: 'delete req.body discards reqPrepend and reqAppend', rules: `${P} reqPrepend://(A) reqAppend://(Z) delete://req.body`, request: { method: 'POST', body: 'M' } },
  { name: 'delete res.body empties the response', rules: `${P} delete://res.body` },
  { name: 'delete bare resBody', rules: `${P} delete://resBody` },
  { name: 'delete res.body discards resBody the operator', rules: `${P} resBody://(REPLACED) delete://res.body` },
  { name: 'delete res.body discards resPrepend and resAppend', rules: `${P} resPrepend://(TOP) resAppend://(END) delete://res.body`, request: { path: '/html' } },
  // The same `EMPTY_BUFFER` reaches `reqBody`/`resBody` with an empty value
  // (`_original/lib/inspectors/req.js:549`, `res.js:1002`), where it is the
  // *documented* meaning: an empty operator is a no-op, not an empty body.
  { name: 'reqBody with an empty value', rules: `${P} reqBody://()`, request: json('{"a":1}') },
  { name: 'resBody with an empty value', rules: `${P} resBody://()`, request: { path: '/html' } },

  // ── delete: response body ──────────────────────────────────────────────
  // The origin's echo is JSON, so a `resBody.` key rewrites it — the bench then
  // compares the two bodies as text, which is what these are for.
  { name: 'delete resBody.x on the echo', rules: `${P} delete://resBody.method` },
  { name: 'delete res.body.x on the echo', rules: `${P} delete://res.body.method` },
  { name: 'delete resB.x on the echo', rules: `${P} delete://resB.method` },
  { name: 'delete a nested resBody path', rules: `${P} delete://resBody.headers.x-a`, request: rich },
  { name: 'delete resBody.x on a body that is not json', rules: `${P} delete://resBody.a`, request: { path: '/html' } },
  { name: 'delete resBody.x alongside resMerge', rules: `${P} resMerge://{"extra":1} delete://resBody.method` },

  // ── delete: trailers ───────────────────────────────────────────────────
  // `TRAILER_RE` is the one delete key written without the `i` flag, and it is
  // unanchored at the front: the word has to be lower case, and anything may
  // precede it.
  { name: 'delete trailer.x', rules: `${P} trailers://{"x-t":"1","x-u":"2"} delete://trailer.x-t` },
  { name: 'delete resTrailer.x is inert', rules: `${P} trailers://{"x-t":"1","x-u":"2"} delete://resTrailer.x-t` },
  { name: 'delete restrailer.x lower case does match', rules: `${P} trailers://{"x-t":"1","x-u":"2"} delete://restrailer.x-t` },
  { name: 'delete Trailer.x capitalised is inert', rules: `${P} trailers://{"x-t":"1","x-u":"2"} delete://Trailer.x-t` },
  { name: 'delete trailer.x on a name that is not there', rules: `${P} trailers://{"x-t":"1"} delete://trailer.x-absent` },

  // ── delete: type and charset ───────────────────────────────────────────
  { name: 'delete reqType', rules: `${P} delete://reqType`, request: json('{"a":1}') },
  { name: 'delete req.type', rules: `${P} delete://req.type`, request: json('{"a":1}') },
  { name: 'delete reqCharset', rules: `${P} delete://reqCharset`, request: { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain; charset=utf-8' } } },
  { name: 'delete req.charset', rules: `${P} delete://req.charset`, request: { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain; charset=utf-8' } } },
  { name: 'delete reqType with a charset on the header', rules: `${P} delete://reqType`, request: { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain; charset=utf-8' } } },
  { name: 'delete reqType and reqCharset together', rules: `${P} delete://reqType|reqCharset`, request: { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain; charset=utf-8' } } },
  { name: 'delete resType', rules: `${P} delete://resType` },
  { name: 'delete res.type', rules: `${P} delete://res.type` },
  { name: 'delete resCharset on a type that has none', rules: `${P} delete://resCharset` },
  { name: 'delete resCharset after resCharset set one', rules: `${P} resCharset://gbk delete://resCharset` },
  { name: 'delete resType after resType set one', rules: `${P} resType://html delete://resType` },

  // ── delete: several keys on one line ───────────────────────────────────
  { name: 'delete two keys split by a pipe', rules: `${P} delete://reqHeaders.x-a|resHeaders.x-origin`, request: rich },
  { name: 'delete two keys split by an ampersand', rules: `${P} delete://reqHeaders.x-a&resHeaders.x-origin`, request: rich },
  { name: 'delete four keys at once', rules: `${P} delete://reqHeaders.x-a|reqCookies.sid|query.b|resHeaders.x-origin`, request: rich },
  { name: 'delete json object form', rules: `${P} delete://{"reqHeaders.x-a":1,"resHeaders.x-origin":1}`, request: rich },
  { name: 'delete two lines merge', rules: `${P} delete://reqHeaders.x-a\n${P} delete://resHeaders.x-origin`, request: rich },
  { name: 'delete an unknown key alongside a known one', rules: `${P} delete://nonsense|reqHeaders.x-a`, request: rich },
  { name: 'delete with an empty value', rules: `${P} delete://`, request: rich },
  { name: 'delete a scope with no name is inert', rules: `${P} delete://reqHeaders.`, request: rich },
  { name: 'delete keys separated by a pipe and an ampersand', rules: `${P} delete://query.a&query.b|reqHeaders.x-a`, request: rich },
  { name: 'delete a percent-encoded query name', rules: `${P} delete://query.a%20b`, request: { path: '/echo?a%20b=1&c=2' } },
  { name: 'delete headers.content-type reaches both sides', rules: `${P} delete://headers.content-type`, request: json('{"a":1}') },
  { name: 'delete resHeaders.set-cookie', rules: `${P} resCookies://sid=abc delete://resHeaders.set-cookie` },

  // ── reqType ────────────────────────────────────────────────────────────
  { name: 'reqType json', rules: `${P} reqType://json`, request: { method: 'POST', body: '{}' } },
  { name: 'reqType form', rules: `${P} reqType://form`, request: { method: 'POST', body: 'a=1' } },
  { name: 'reqType urlencoded', rules: `${P} reqType://urlencoded`, request: { method: 'POST', body: 'a=1' } },
  { name: 'reqType xml', rules: `${P} reqType://xml`, request: { method: 'POST', body: '<a/>' } },
  { name: 'reqType text', rules: `${P} reqType://text`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType upload', rules: `${P} reqType://upload`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType multipart', rules: `${P} reqType://multipart`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType defaultType', rules: `${P} reqType://defaultType`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType html from the extension table', rules: `${P} reqType://html`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType sse', rules: `${P} reqType://sse`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType an explicit media type', rules: `${P} reqType://application/vnd.api+json`, request: { method: 'POST', body: '{}' } },
  { name: 'reqType with parameters', rules: `${P} reqType://text/plain;charset=gbk`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType keeps the parameters already there', rules: `${P} reqType://json`, request: { method: 'POST', body: '{}', headers: { 'content-type': 'text/html; charset=gbk' } } },
  { name: 'reqType an unknown short name', rules: `${P} reqType://nosuchtype`, request: { method: 'POST', body: 'x' } },
  { name: 'reqType on a GET with no body', rules: `${P} reqType://json` },

  // ── resType ────────────────────────────────────────────────────────────
  { name: 'resType json', rules: `${P} resType://json` },
  { name: 'resType html', rules: `${P} resType://html` },
  { name: 'resType css', rules: `${P} resType://css` },
  { name: 'resType js', rules: `${P} resType://js` },
  { name: 'resType text', rules: `${P} resType://text` },
  { name: 'resType sse', rules: `${P} resType://sse` },
  { name: 'resType form has no alias on this side', rules: `${P} resType://form` },
  { name: 'resType an explicit media type', rules: `${P} resType://application/vnd.api+json` },
  { name: 'resType with parameters', rules: `${P} resType://text/plain;charset=gbk` },
  { name: 'resType onto a type that carries a charset', rules: `${P} resType://json`, request: { path: '/htmlx' } },
  { name: 'resType an unknown short name', rules: `${P} resType://nosuchtype` },
  { name: 'resType on the html origin', rules: `${P} resType://json`, request: { path: '/html' } },

  // ── charsets ───────────────────────────────────────────────────────────
  { name: 'reqCharset onto an existing type', rules: `${P} reqCharset://gbk`, request: json('{"a":1}') },
  { name: 'reqCharset replaces an existing charset', rules: `${P} reqCharset://gbk`, request: { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain; charset=utf-8' } } },
  { name: 'reqCharset with no content-type at all', rules: `${P} reqCharset://gbk` },
  { name: 'reqType and reqCharset on one line', rules: `${P} reqType://json reqCharset://gbk`, request: { method: 'POST', body: '{}' } },
  { name: 'resCharset onto an existing type', rules: `${P} resCharset://gbk` },
  { name: 'resType and resCharset on one line', rules: `${P} resType://html resCharset://gbk` },
  { name: 'resCharset then delete resType', rules: `${P} resCharset://gbk delete://resType` },

  // ── reqCookies ─────────────────────────────────────────────────────────
  { name: 'reqCookies adds one', rules: `${P} reqCookies://a=1` },
  { name: 'reqCookies onto an existing cookie header', rules: `${P} reqCookies://a=1`, request: rich },
  { name: 'reqCookies two pairs', rules: `${P} reqCookies://a=1&b=2` },
  { name: 'reqCookies json', rules: `${P} reqCookies://{"a":"1","b":"2"}` },
  { name: 'reqCookies replaces a name already there', rules: `${P} reqCookies://sid=new`, request: rich },
  { name: 'reqCookies with an attribute object', rules: `${P} reqCookies://{"sid":{"value":"x","httpOnly":true,"maxAge":600}}` },
  // A whole value with no `=` is a *location* upstream tries to load, not a
  // query string, so it sets nothing. A valueless pair *inside* a query does
  // set an empty value.
  { name: 'reqCookies a whole value with no equals', rules: `${P} reqCookies://a`, request: rich },
  { name: 'reqCookies a valueless pair inside a query', rules: `${P} reqCookies://a=1&b`, request: rich },
  { name: 'reqCookies an explicitly empty value', rules: `${P} reqCookies://a=`, request: rich },
  { name: 'reqCookies then delete the same name', rules: `${P} reqCookies://a=1 delete://reqCookies.a` },
  { name: 'reqCookies two lines merge', rules: `${P} reqCookies://a=1\n${P} reqCookies://b=2` },
  { name: 'reqCookies two lines contest a name', rules: `${P} reqCookies://a=first\n${P} reqCookies://a=second` },
  { name: 'delete a cookie from a header with a trailing semicolon', rules: `${P} delete://reqCookies.sid`, request: { headers: { cookie: 'sid=secret; other=keep;' } } },
  { name: 'delete a cookie from a header with a valueless pair', rules: `${P} delete://reqCookies.sid`, request: { headers: { cookie: 'sid=secret; flag' } } },

  // ── resCookies ─────────────────────────────────────────────────────────
  { name: 'resCookies adds one', rules: `${P} resCookies://sid=abc` },
  // The string spelling is not escaped: `getCookieItem` returns
  // `name + '=' + cookie` untouched for anything that is not an object
  // (`_original/lib/util/index.js:3093-3096`), so a `;` really does set an
  // attribute — which is how the operator's own documentation writes one. This
  // port escaped it, turning `k=v;path=/` into a value of `v%3Bpath=/` with no
  // attribute at all. Only the *object* spelling's `value` runs `escapeValue`.
  { name: 'resCookies with an attribute after a semicolon', rules: `${P} resCookies://k=v;path=/` },
  { name: 'resCookies with two attributes', rules: `${P} resCookies://k=v;path=/;httponly` },
  { name: 'resCookies with a semicolon inside a json string value', rules: `${P} resCookies://{"k":"v;path=/"}` },
  { name: 'resCookies object spelling still renders its attributes', rules: `${P} resCookies://{"k":{"value":"v","path":"/"}}` },
  // A space ends the token, so this sets nothing in either proxy — the pair
  // that keeps the three above from being read as "a semicolon always works".
  // The space is the subject, and a token cannot contain one — so the value
  // arrives the way a rules file has to write it, through a fenced block.
  { name: 'resCookies with a space after the semicolon', rules: `\`\`\`ck\nk=v; path=/\n\`\`\`\n${P} resCookies://{ck}` },
  { name: 'resCookies two pairs', rules: `${P} resCookies://sid=abc&t=2` },
  { name: 'resCookies json', rules: `${P} resCookies://{"sid":"abc"}` },
  { name: 'resCookies with an attribute object', rules: `${P} resCookies://{"sid":{"value":"x","httpOnly":true,"maxAge":600}}` },
  { name: 'resCookies with path domain and secure', rules: `${P} resCookies://{"sid":{"value":"x","path":"/p","domain":"a.test","secure":true,"sameSite":"Lax"}}` },
  { name: 'resCookies one name carrying several values', rules: `${P} resCookies://{"sid":[{"value":"a","path":"/x"},{"value":"b","path":"/y"}]}` },
  { name: 'resCookies a whole value with no equals', rules: `${P} resCookies://sid` },
  { name: 'resCookies a valueless pair inside a query', rules: `${P} resCookies://sid=abc&t` },
  { name: 'resCookies with expires', rules: `\`\`\`ck\n{"sid":{"value":"x","expires":"Wed, 21 Oct 2099 07:28:00 GMT"}}\n\`\`\`\n${P} resCookies://{ck}` },
  // The line format, which `resCookies.md` prints as the way to write several
  // cookies at once — it set none here until the campaign that read the page.
  { name: 'resCookies from a fenced block', rules: `\`\`\`ck\nkey1: value1\nkey2: value2\n\`\`\`\n${P} resCookies://{ck}` },
  { name: 'resCookies from a fenced block with attributes', rules: `\`\`\`ck\n{"key1":"value1","key2":{"value":"value2","path":"/","secure":true,"domain":"example.com"}}\n\`\`\`\n${P} resCookies://{ck}` },
  { name: 'resCookies two lines merge', rules: `${P} resCookies://a=1\n${P} resCookies://b=2` },
  { name: 'resCookies two lines contest a name', rules: `${P} resCookies://a=first\n${P} resCookies://a=second` },
  { name: 'resCookies a Max-Age spelled Max-Age', rules: `${P} resCookies://{"sid":{"value":"x","Max-Age":60}}` },
  { name: 'resCookies a numeric value', rules: `${P} resCookies://{"sid":1}` },
  { name: 'resCookies a null value', rules: `${P} resCookies://{"sid":null}` },

  // ── CORS ───────────────────────────────────────────────────────────────
  // The detailed spelling `resCors.md` prints: one field per line, in a block.
  { name: 'resCors from a fenced block', rules: `\`\`\`c\norigin: *\nmethods: POST\nheaders: x-test\ncredentials: true\nmaxAge: 300000\n\`\`\`\n${P} resCors://{c}`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors from a fenced block on a preflight', rules: `\`\`\`c\norigin: *\nheaders: x-test\n\`\`\`\n${P} resCors://{c}`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-headers': 'x-a' } } },
  { name: 'resCors star', rules: `${P} resCors://*` },
  { name: 'resCors enable echoes the origin', rules: `${P} resCors://enable`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors enable with no origin header', rules: `${P} resCors://enable` },
  { name: 'resCors a literal origin', rules: `${P} resCors://https://app.test`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors json options', rules: `${P} resCors://{"origin":"https://app.test","methods":"GET,POST","maxAge":600,"credentials":true}`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors preflight', rules: `${P} resCors://enable`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT', 'access-control-request-headers': 'x-token' } } },
  { name: 'resCors star preflight', rules: `${P} resCors://*`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT', 'access-control-request-headers': 'x-token' } } },
  { name: 'reqCors star', rules: `${P} reqCors://*` },
  { name: 'reqCors enable', rules: `${P} reqCors://enable`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'reqCors a literal origin', rules: `${P} reqCors://https://app.test` },
  { name: 'reqCors and resCors on one line', rules: `${P} reqCors://* resCors://*`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors then delete the header it wrote', rules: `${P} resCors://* delete://resHeaders.access-control-allow-origin` },
  { name: 'resCors json options on a preflight', rules: `${P} resCors://{"methods":"GET,PUT","headers":"x-token","maxAge":600}`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT', 'access-control-request-headers': 'x-token' } } },
  { name: 'resCors query-string options', rules: `${P} resCors://methods=GET,POST&maxAge=60`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors credentials', rules: `${P} resCors://credentials`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors use-credentials', rules: `${P} resCors://use-credentials`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors an unknown word', rules: `${P} resCors://maybe`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'reqCors on a preflight', rules: `${P} reqCors://enable`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT' } } },
  { name: 'resCors enable on an OPTIONS that is not a preflight', rules: `${P} resCors://enable`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test' } } },
  { name: 'resCors two lines contest', rules: `${P} resCors://*\n${P} resCors://enable`, request: { headers: { origin: 'https://app.test' } } },
];
