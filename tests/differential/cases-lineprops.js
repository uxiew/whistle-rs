// `lineProps://` — one entry per property in `docs/LINE_PROPS.md` that this
// bench can reach, plus the parsing semantics around them.
//
//   PORT_BASE=19400 CASES=./cases-lineprops.js npm run bench
//
// A `lineProps://` token on a line **by itself** configures nothing and the line
// is dropped — by this port and by upstream alike — so every property is probed
// next to a real operator, which is the only way one is ever written.
//
// Three properties have no case here, and the reason is the bench rather than
// the port:
//
//   * `internalProxy` only converts an **https** origin, and this bench speaks
//     cleartext to a cleartext origin;
//   * `proxyTunnel` needs a hop that is itself a proxy, i.e. a second upstream
//     proxy this bench does not run;
//   * `originUrl` needs a bare-domain pattern whose matcher carries a path, and
//     neither proxy rewrites the destination for that shape against this origin
//     — the case would pin agreement on doing nothing.
//
// All three are covered by unit tests in `src/`.
const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

// The origin doubles as a stand-in upstream proxy: it echoes `q.url`, so a
// request that went **through** a proxy shows the absolute form and one that
// went direct shows the path. Nothing here asks it to CONNECT.
const AS_PROXY = P;

// Over `MAX_REQ_SIZE` (2 MB) and under `BIG_MAX_REQ_SIZE` (16 MB), so the
// merging operators reach it only when something raised the ceiling.
const BIG_BODY = JSON.stringify({ a: 1, pad: 'x'.repeat(3 * 1024 * 1024) });

module.exports = [
  // ── important ──────────────────────────────────────────────────────────
  { name: 'important outranks an earlier line', rules: `${P} method://PUT\n${P} method://DELETE lineProps://important` },
  { name: 'important on the earlier line changes nothing', rules: `${P} method://PUT lineProps://important\n${P} method://DELETE` },
  { name: 'important loses to an earlier important', rules: `${P} method://PUT lineProps://important\n${P} method://DELETE lineProps://important` },

  // ── internal / internalOnly ────────────────────────────────────────────
  // A client request is not internal in either proxy, so an `internalOnly` line
  // is invisible and an `internal` one is not.
  { name: 'internalOnly hides the line from a client request', rules: `${P} method://PUT lineProps://internalOnly` },
  { name: 'internal keeps the line visible', rules: `${P} method://PUT lineProps://internal` },
  { name: 'internalOnly hides only its own line', rules: `${P} method://PUT lineProps://internalOnly\n${P} reqHeaders://x-a=1` },

  // ── safeHtml / strictHtml ──────────────────────────────────────────────
  // The gate reads the response body's first byte, and only for HTML. The echo
  // is JSON, so `resType://html` makes it an HTML response whose body starts
  // with `{` — the case both gates refuse.
  { name: 'safeHtml refuses to inject into a json-shaped body', rules: `${P} resType://html htmlAppend://(INJECTED) lineProps://safeHtml` },
  { name: 'strictHtml refuses it too', rules: `${P} resType://html htmlAppend://(INJECTED) lineProps://strictHtml` },
  { name: 'neither gate stops real markup', rules: `${P} htmlAppend://(<i>hi</i>) lineProps://safeHtml`, request: { path: '/html' } },
  { name: 'strictHtml allows real markup as well', rules: `${P} htmlAppend://(<i>hi</i>) lineProps://strictHtml`, request: { path: '/html' } },
  // The free injection makes the echo unparseable, which sends the harness to
  // comparing bodies — and the echo then carries this port's deliberate
  // request-cache busting, which whistle does not do. Writing the two headers
  // explicitly puts both proxies on the same footing so the case is about the
  // gate and nothing else.
  { name: 'the gate is per line, not per request', rules: `${P} resType://html htmlAppend://(GATED) lineProps://safeHtml\n${P} resType://html htmlPrepend://(FREE) reqHeaders://pragma=no-cache&cache-control=no-cache` },
  { name: 'includeFilter://safeHtml is the same thing', rules: `${P} resType://html htmlAppend://(INJECTED) includeFilter://safeHtml` },
  { name: 'includeFilter://strictHtml is the same thing', rules: `${P} resType://html htmlAppend://(INJECTED) includeFilter://strictHtml` },
  { name: 'enable://safeHtml gates every line', rules: `${P} resType://html htmlAppend://(INJECTED)\n${P} enable://safeHtml` },

  // ── host / proxy precedence ────────────────────────────────────────────
  { name: 'a proxy on its own is used', rules: `${P} proxy://${AS_PROXY}` },
  { name: 'host beats proxy by default', rules: `${P} host://127.0.0.1\n${P} proxy://${AS_PROXY}` },
  { name: 'proxyFirst keeps the proxy', rules: `${P} host://127.0.0.1\n${P} proxy://${AS_PROXY} lineProps://proxyFirst` },
  { name: 'proxyFirst on the host line says the same', rules: `${P} host://127.0.0.1 lineProps://proxyFirst\n${P} proxy://${AS_PROXY}` },
  { name: 'enable://proxyFirst says it request-wide', rules: `${P} host://127.0.0.1\n${P} proxy://${AS_PROXY}\n${P} enable://proxyFirst` },
  { name: 'proxyHostOnly with no host rule drops the proxy', rules: `${P} proxy://${AS_PROXY} lineProps://proxyHostOnly` },
  { name: 'proxyHostOnly alone is still not a host rule', rules: `${P} proxy://${AS_PROXY} lineProps://proxyHostOnly\n${P} reqHeaders://x-a=1` },

  // ── weakRule ───────────────────────────────────────────────────────────
  { name: 'a local file answers by default', rules: `${P} file:///no/such/mock.json\n${P} host://127.0.0.1` },
  { name: 'weakRule hands the request to a host rule', rules: `${P} file:///no/such/mock.json lineProps://weakRule\n${P} host://127.0.0.1` },
  { name: 'weakRule hands it to a proxy too', rules: `${P} file:///no/such/mock.json lineProps://weakRule\n${P} proxy://${AS_PROXY}` },
  { name: 'weakRule with nothing to yield to still answers', rules: `${P} file://(MOCKED) lineProps://weakRule` },
  { name: 'proxyHostOnly is not enough for weakRule to yield', rules: `${P} file://(MOCKED) lineProps://weakRule\n${P} proxy://${AS_PROXY} lineProps://proxyHostOnly` },
  { name: 'enable://weakRule says it request-wide', rules: `${P} file:///no/such/mock.json\n${P} host://127.0.0.1\n${P} enable://weakRule` },

  // ── disableAutoCors / disabledAutoCors ─────────────────────────────────
  // A `file://` mock answering a page on another origin carries CORS headers it
  // was never asked for; these turn that off.
  { name: 'a cross-origin file mock gets automatic CORS', rules: `${P} file://(MOCKED)`, request: { headers: { origin: 'http://other.test' } } },
  { name: 'disableAutoCors turns it off', rules: `${P} file://(MOCKED) lineProps://disableAutoCors`, request: { headers: { origin: 'http://other.test' } } },
  { name: 'disabledAutoCors, upstream own typo, does too', rules: `${P} file://(MOCKED) lineProps://disabledAutoCors`, request: { headers: { origin: 'http://other.test' } } },
  { name: 'disable://autoCors says it request-wide', rules: `${P} file://(MOCKED)\n${P} disable://autoCors`, request: { headers: { origin: 'http://other.test' } } },
  { name: 'no Origin header, no automatic CORS', rules: `${P} file://(MOCKED)` },
  { name: 'the preflight is answered by the mock as well', rules: `${P} file://(MOCKED)`, request: { method: 'OPTIONS', headers: { origin: 'http://other.test', 'access-control-request-method': 'PUT' } } },
  { name: 'disableAutoCors leaves the preflight to the file', rules: `${P} file://(MOCKED) lineProps://disableAutoCors`, request: { method: 'OPTIONS', headers: { origin: 'http://other.test', 'access-control-request-method': 'PUT' } } },
  { name: 'a tpl mock is in the same family', rules: `${P} tpl://({"m":1}) lineProps://disableAutoCors`, request: { headers: { origin: 'http://other.test' } } },

  // ── enableBigData ──────────────────────────────────────────────────────
  // 3 MB is over `MAX_REQ_SIZE` (2 MB) and under `BIG_MAX_REQ_SIZE` (16 MB), so
  // the merge applies only when something raised the ceiling. This port read
  // `enableBigData` as a setting of whistle's own rather than a line property,
  // and forwarded the body unmerged where whistle merged it.
  //
  // The merged key is named to sort last: whistle keeps a JSON object's keys in
  // the order they arrived and this port re-serialises them sorted, so a patch
  // key that is alphabetically last is the one place the two agree. That
  // difference is real and is about `reqMerge`, not about this property.
  { name: 'a small body merges without any flag', rules: `${P} reqMerge://{"zz":1}`, request: { method: 'POST', body: '{"a":1}', headers: { 'content-type': 'application/json' } } },
  { name: 'a 3MB body is over the ceiling', rules: `${P} reqMerge://{"zz":1}`, request: { method: 'POST', body: BIG_BODY, headers: { 'content-type': 'application/json' } } },
  { name: 'enableBigData raises it', rules: `${P} reqMerge://{"zz":1} lineProps://enableBigData`, request: { method: 'POST', body: BIG_BODY, headers: { 'content-type': 'application/json' } } },
  { name: 'enable://reqMergeBigData raises it too', rules: `${P} reqMerge://{"zz":1} enable://reqMergeBigData`, request: { method: 'POST', body: BIG_BODY, headers: { 'content-type': 'application/json' } } },
  { name: 'enableBigData on another line raises nothing', rules: `${P} reqMerge://{"zz":1}\n${P} reqHeaders://x-a=1 lineProps://enableBigData`, request: { method: 'POST', body: BIG_BODY, headers: { 'content-type': 'application/json' } } },

  // ── enableUserLogin / disableUserLogin ─────────────────────────────────
  // Not about whistle's own login box: about the `WWW-Authenticate: Basic realm=
  // User Login` header a mocked 401 carries, which is what makes a browser ask.
  { name: 'a mocked 401 asks for credentials', rules: `${P} statusCode://401` },
  { name: 'a mocked 407 asks the proxy way', rules: `${P} statusCode://407` },
  { name: 'a mocked 403 asks for nothing', rules: `${P} statusCode://403` },
  { name: 'disableUserLogin drops the challenge', rules: `${P} statusCode://401 lineProps://disableUserLogin` },
  { name: 'enableUserLogin wins over it', rules: `${P} statusCode://401 lineProps://disableUserLogin&enableUserLogin` },
  { name: 'disable://userLogin says it request-wide', rules: `${P} statusCode://401 disable://userLogin` },
  { name: 'replaceStatus challenges as well', rules: `${P} replaceStatus://401` },
  { name: 'disableUserLogin on the replaceStatus line', rules: `${P} replaceStatus://401 lineProps://disableUserLogin` },
  { name: 'the property is line-scoped', rules: `${P} statusCode://401\n${P} reqHeaders://x-a=1 lineProps://disableUserLogin` },

  // ── parsing ────────────────────────────────────────────────────────────
  { name: 'both separators, mixed and repeated', rules: `${P} method://PUT lineProps://safeHtml|internalOnly&important` },
  { name: 'several lineProps tokens merge', rules: `${P} method://PUT lineProps://internalOnly lineProps://important` },
  { name: 'an empty payload is a no-op', rules: `${P} method://PUT lineProps://` },
  { name: 'an unknown action is kept and ignored', rules: `${P} method://PUT lineProps://totallyMadeUp` },
  { name: 'lineProps alone is not a rule', rules: `${P} lineProps://important` },
  { name: 'the properties land on every operator of the line', rules: `${P} file://(MOCKED) resHeaders://x-a=1 lineProps://disableAutoCors`, request: { headers: { origin: 'http://other.test' } } },
];
