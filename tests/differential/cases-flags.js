// The `enable://` and `disable://` matrix.
//
// These two operators take a *vocabulary*, not a value, and the vocabulary is
// large: upstream reads 20 names through `isEnable`, another 11 straight off
// `req.enable`, and 24 off `req.disable`. Before this file, **23 of the enable
// names and 20 of the disable names appeared in no case anywhere** — the flag
// family had been aligned by reading `_original` and never measured.
//
// A flag is only observable when something it modifies is also happening, so
// almost every case here pairs the flag with the rule it changes: `keepCSP`
// needs an injection to have stripped a CSP, `keepCache` needs a cached
// response, `trailers` needs trailers. A flag on its own is the control.
//
// **Not covered here, and why.** The plain bench speaks HTTP end to end, so
// nothing that only exists on a tunnel or a socket can be asked: `proxyTunnel`,
// `keepH2Session`, `rejectUnauthorized`, `secureOptions`, `servername`,
// `ping`/`pong`, `websocket`, `socket`, `keepalive`, `auto2http`. The proxy
// family's flags (`proxyHost`, `proxyFirst`, `internalProxy`, `proxyUA`,
// `proxyConnection`) belong to `cases-proxy.js`, which has its own hop servers
// and already carries them. `multiClient`/`singleClient`/`clientId` need two
// clients whistle can tell apart.
//
// **Divergences this file declares rather than pins**, named here instead of in
// `harness.js`'s `EXPECTED` so a wide matcher there cannot swallow news in
// another corpus. A clean run of this file is `differing: 4`.
//
//   1. **`enable://responseWithMatchedRules` is not implemented** (3 cases).
//      whistle writes the matched rules into `x-whistle-matched-rules` on the
//      response (`addMatchedRules`, `_original/lib/util/index.js:3879-3888`);
//      this port writes nothing. Implementing it needs each resolved operator
//      to carry the pattern it came from, which `RuleOp` does not keep — a
//      change in the resolver, deliberately deferred while that machinery is
//      being restructured elsewhere. Recorded in `docs/RULES.md`.
//
//      Its request-side twin `requestWithMatchedRules` **agrees**, and agrees
//      by both proxies doing nothing: upstream calls `addMatchedRules(req)` from
//      the response inspector (`res.js:770`), long after the request head went
//      out, so the origin never sees the header. Measured, not assumed.
//
//   2. **`disable://trailers` still announces the trailer upstream** (1 case).
//      Measured with `TE: trailers` so both proxies would send a section if
//      they meant to: whistle emits `Trailer: x-t` and then sends **no
//      trailer section at all**, while this port drops the announcement with
//      the section. Announcing a field that never arrives is a protocol lie,
//      and not one worth reproducing.
//
// `P` is the origin's authority; rules are written against it so the same text
// goes to both proxies unchanged.
const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

/** An injection, which is what strips the CSP and the cache headers. */
const INJECT = 'htmlAppend://(<i>x</i>)';

module.exports = [
  // ── the controls ─────────────────────────────────────────────────────────
  // A flag with nothing to modify, and the modification with no flag. Both
  // sides of every pair below are only readable against these.
  { name: 'control: the cached page, no rule at all', rules: '', request: { path: '/cached' } },
  { name: 'control: an injection strips the cache and the CSP', rules: `${P} ${INJECT}`, request: { path: '/cached' } },
  { name: 'control: a flag nobody reads', rules: `${P} enable://notAFlagAtAll`, request: { path: '/cached' } },
  { name: 'control: disable a flag nobody reads', rules: `${P} disable://notAFlagAtAll`, request: { path: '/cached' } },

  // ── CSP and cache: what an injection takes away, and what keeps it ───────
  { name: 'keepCSP keeps the header an injection would strip', rules: `${P} ${INJECT} enable://keepCSP`, request: { path: '/cached' } },
  { name: 'keepAllCSP is the log inspector\'s spelling', rules: `${P} ${INJECT} enable://keepAllCSP`, request: { path: '/cached' } },
  { name: 'both CSP flags together', rules: `${P} ${INJECT} enable://keepCSP|keepAllCSP`, request: { path: '/cached' } },
  { name: 'keepCache keeps the cache headers', rules: `${P} ${INJECT} enable://keepCache`, request: { path: '/cached' } },
  { name: 'keepAllCache is the other one', rules: `${P} ${INJECT} enable://keepAllCache`, request: { path: '/cached' } },
  { name: 'keepCache without an injection', rules: `${P} enable://keepCache`, request: { path: '/cached' } },
  { name: 'keepCSP on a response with no CSP', rules: `${P} ${INJECT} enable://keepCSP`, request: { path: '/html' } },
  // `cache://` says the same thing a different way; the two must not fight.
  { name: 'keepAllCache beside cache reserve', rules: `${P} ${INJECT} cache://reserve`, request: { path: '/cached' } },
  { name: 'keepAllCache beside cache keep', rules: `${P} ${INJECT} cache://keep`, request: { path: '/cached' } },
  { name: 'keepAllCache beside a numeric cache', rules: `${P} ${INJECT} cache://600`, request: { path: '/cached' } },

  // ── where an injection lands: strictHtml / safeHtml ──────────────────────
  { name: 'strictHtml moves the injection', rules: `${P} ${INJECT} enable://strictHtml`, request: { path: '/html' } },
  { name: 'safeHtml moves it differently', rules: `${P} ${INJECT} enable://safeHtml`, request: { path: '/html' } },
  { name: 'strictHtml and safeHtml together, strict first', rules: `${P} ${INJECT} enable://strictHtml|safeHtml`, request: { path: '/html' } },
  { name: 'strictHtml on a prepend', rules: `${P} htmlPrepend://(<i>x</i>) enable://strictHtml`, request: { path: '/html' } },
  { name: 'strictHtml on a page that is not html', rules: `${P} ${INJECT} enable://strictHtml`, request: { path: '/plain.txt' } },
  { name: 'strictHtml on an empty page', rules: `${P} ${INJECT} enable://strictHtml`, request: { path: '/empty.html' } },
  { name: 'safeHtml with a css injection', rules: `${P} cssAppend://(a{color:red}) enable://safeHtml`, request: { path: '/html' } },

  // ── the matched-rules headers ────────────────────────────────────────────
  // `addMatchedRules` writes `x-whistle-matched-rules`
  // (`_original/lib/util/index.js:3879-3888`). The harness used to drop every
  // `x-whistle*` header by prefix, which made these two cases unable to fail;
  // it now names the four it drops instead.
  { name: 'requestWithMatchedRules names the rules to the origin', rules: `${P} reqHeaders://x-a=1 enable://requestWithMatchedRules` },
  { name: 'responseWithMatchedRules names them to the client', rules: `${P} resHeaders://x-r=1 enable://responseWithMatchedRules` },
  { name: 'both at once', rules: `${P} reqHeaders://x-a=1 enable://requestWithMatchedRules|responseWithMatchedRules` },
  { name: 'requestWithMatchedRules with several lines matching', rules: `${P} reqHeaders://x-a=1 enable://requestWithMatchedRules\n${P} resHeaders://x-r=2` },
  { name: 'requestWithMatchedRules with no other rule on the line', rules: `${P} enable://requestWithMatchedRules` },
  { name: 'responseWithMatchedRules on a mock', rules: `${P} file://(mocked) enable://responseWithMatchedRules` },

  // ── trailers ─────────────────────────────────────────────────────────────
  // The request carries `TE: trailers` because hyper writes a trailer section
  // only to a client that asked; see `harness.js`'s `EXPECTED`.
  { name: 'the origin trailers, no flag', rules: '', request: { path: '/trailers', headers: { te: 'trailers' } } },
  { name: 'disable trailers drops them', rules: `${P} disable://trailers`, request: { path: '/trailers', headers: { te: 'trailers' } } },
  { name: 'disable trailer, singular', rules: `${P} disable://trailer`, request: { path: '/trailers', headers: { te: 'trailers' } } },
  { name: 'disable trailerHeader', rules: `${P} disable://trailerHeader`, request: { path: '/trailers', headers: { te: 'trailers' } } },
  { name: 'disable trailers against a trailers rule', rules: `${P} trailers://{"x-t":"1"} disable://trailers`, request: { headers: { te: 'trailers' } } },
  { name: 'a trailers rule with no flag', rules: `${P} trailers://{"x-t":"1"}`, request: { headers: { te: 'trailers' } } },

  // ── the abort family ─────────────────────────────────────────────────────
  { name: 'enable abort kills the request', rules: `${P} enable://abort` },
  { name: 'enable abortReq', rules: `${P} enable://abortReq` },
  { name: 'enable abortRes', rules: `${P} enable://abortRes` },
  // `needAbortReq` returns false the moment either disable name is present,
  // whichever order they were written (`util/index.js:3890-3900`).
  { name: 'disable abort cancels enable abort', rules: `${P} enable://abort disable://abort` },
  { name: 'disable abortReq cancels enable abort', rules: `${P} enable://abort disable://abortReq` },
  { name: 'disable abort written first', rules: `${P} disable://abort enable://abort` },
  { name: 'abort beside a mock', rules: `${P} file://(mocked) enable://abort` },

  // ── the rest, one case each, mostly asking "is this inert here too" ──────
  { name: 'useLocalHost rewrites the internal host', rules: `${P} enable://useLocalHost` },
  { name: 'useSafePort', rules: `${P} enable://useSafePort` },
  { name: 'captureStream', rules: `${P} enable://captureStream` },
  { name: 'weakRule', rules: `${P} reqHeaders://x-a=1 enable://weakRule\n${P} reqHeaders://x-a=2` },
  { name: 'reqMergeBigData', rules: `${P} enable://reqMergeBigData`, request: { method: 'POST', body: 'x'.repeat(2000) } },
  { name: 'resMergeBigData', rules: `${P} enable://resMergeBigData` },
  { name: 'disable userLogin against a 401', rules: `${P} statusCode://401 disable://userLogin` },
  { name: 'a 401 with no flag', rules: `${P} statusCode://401` },
  { name: 'disable additionalHeaders', rules: `${P} reqHeaders://x-a=1 disable://additionalHeaders` },
  { name: 'disable flushHeaders', rules: `${P} disable://flushHeaders` },
  { name: 'disable interceptConsole', rules: `${P} disable://interceptConsole` },
  // Upstream's own typo, kept because upstream reads exactly this spelling
  // (`req.disable.lacalhostCompatible`). The correct spelling is not a flag.
  { name: 'disable lacalhostCompatible, upstream\'s spelling', rules: `${P} disable://lacalhostCompatible` },
  { name: 'disable localhostCompatible, the spelling that is not a flag', rules: `${P} disable://localhostCompatible` },

  // ── the shape of the value ───────────────────────────────────────────────
  { name: 'several flags separated by |', rules: `${P} ${INJECT} enable://keepCSP|keepCache`, request: { path: '/cached' } },
  { name: 'several flags on separate lines merge', rules: `${P} ${INJECT} enable://keepCSP\n${P} enable://keepCache`, request: { path: '/cached' } },
  { name: 'a flag repeated', rules: `${P} ${INJECT} enable://keepCSP|keepCSP`, request: { path: '/cached' } },
  { name: 'an empty enable value', rules: `${P} ${INJECT} enable://`, request: { path: '/cached' } },
  { name: 'enable with a trailing pipe', rules: `${P} ${INJECT} enable://keepCSP|`, request: { path: '/cached' } },
  { name: 'enable with a leading pipe', rules: `${P} ${INJECT} enable://|keepCSP`, request: { path: '/cached' } },
  { name: 'a flag name in the wrong case', rules: `${P} ${INJECT} enable://keepcsp`, request: { path: '/cached' } },
  { name: 'enable and disable of the same name', rules: `${P} ${INJECT} enable://keepCSP disable://keepCSP`, request: { path: '/cached' } },
  { name: 'the JSON value form', rules: `${P} ${INJECT} enable://{"keepCSP":true}`, request: { path: '/cached' } },
  // `filter://` is documented as the same vocabulary reaching the same place.
  { name: 'a flag written as filter', rules: `${P} ${INJECT} filter://keepCSP`, request: { path: '/cached' } },
  { name: 'a flag under a filter condition that holds', rules: `${P} ${INJECT} enable://keepCSP includeFilter://m:GET`, request: { path: '/cached' } },
  { name: 'a flag under a filter condition that misses', rules: `${P} ${INJECT} enable://keepCSP includeFilter://m:POST`, request: { path: '/cached' } },
];
