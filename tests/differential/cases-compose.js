// Rule **composition** and **script injection** — the rules that produce other
// rules, and the rules that put something into a response body.
//
//   PORT_BASE=19900 CASES=./cases-compose.js npm run bench
//
// Thirteen rule names had never been measured against real whistle. Several
// turned out not to be rules at all, and saying so is the result:
//
//   * `style://` is parsed and then read by **nothing** in `lib/` — its only
//     mentions are the three registration lists in `rules/protocols.js`. It
//     colours a row in whistle's own console and has no traffic effect at all,
//     here or there. The cases below check that it does not disturb the line it
//     shares.
//   * `pipe://` names a **plugin** (`PIPE_PLUGIN_RE`,
//     `_original/lib/plugins/index.js:1184`). With no such plugin installed it
//     is inert in both. It is exercised here only in that shape: whistle-rs
//     ships demonstration plugins (`upper`, `echo`, `gate`, …) that upstream
//     does not have, so `pipe://upper` compares a plugin set rather than a rule.
//   * `intercept://` is **not a protocol**. `enable://intercept` and
//     `disable://intercept` are flags, and `intercept` is a tunnel policy
//     (`tunnel.js:168,:182`); written as `intercept://x` it is an unknown
//     protocol, and both proxies answer 502 — see the note below.
//   * `sniCallback://` and `tlsOptions://` only mean anything on a TLS
//     connection, so they live in `https-bench.js`, which now reports the TLS
//     version the origin negotiated. `tlsOptions` is an alias of `cipher`.
//   * `frameScript://` runs on **WebSocket text frames**; nothing this bench
//     sends is a WebSocket. It is covered by unit tests in `src/proxy/ws.rs`.
//   * `responseFor://` writes `x-whistle-response-for` on the **response**, and
//     the harness strips every `x-whistle*` header from both sides as whistle's
//     own bookkeeping. The cases here are therefore blind to their own effect;
//     the header itself is pinned by a unit test in `src/proxy/apply.rs`
//     (`response_for_annotates_rather_than_fetches`) and was verified by hand
//     against the oracle — `responseFor://svc-a` comes back as
//     `x-whistle-response-for: svc-a` from both. The cases stay because they
//     still prove `responseFor://` does not disturb the request.
//
// **This corpus ends at `differing: 7`** — six `weinre://` and one
// `intercept://`, each named below.
//
// It said eight until the eighth stopped differing on its own. That one was
// `the response is re-encoded after injection`: both proxies inject into the
// compressed body and recompress, the deflate stream was byte-identical, and
// what differed was byte 9 of the gzip header — the OS field, `0x13` from the
// Node zlib of the day against `0xff`, RFC 1952's "unknown", from `flate2`.
// Node v26.4.0 emits `0xff` too, so the two now agree.
//
// The case is kept rather than deleted, and this paragraph with it, because the
// agreement is the toolchain's rather than either proxy's: whistle's byte is its
// build's, so a different Node will part them again. If this corpus ever reports
// eight, look at byte 9 before looking at the port.
//
// `weinre://` (`_original/lib/inspectors/weinre.js`) appends whistle's **own
// bundled debug agent** — the whole of `assets/js/weinre.js`, inline, at the end
// of the body — and points it at a weinre server whistle serves itself. This
// port does not bundle that agent and does not run that server, so it injects a
// `<script src>` naming the conventional target URL instead. Everything
// downstream of that choice differs and is meant to:
//
//   * the script text, and its placement (`<head>` here, end of body there);
//   * whistle reaches **JavaScript** responses too, appending the agent bare
//     (`weinre.js:33-35`); a `<script src>` tag means nothing in a `.js` file,
//     so this port leaves them alone;
//   * whistle rewrites a **gzipped** body through `addZipTransform`; this port
//     does not re-encode for `weinre://`.
//
// What is *not* a deliberate difference, and was fixed: whistle strips the
// response's CSP and makes it uncacheable whenever it injects (`weinre.js:37-38`),
// and this port did neither — so the agent it pushed into the page was blocked
// by the page's own `Content-Security-Policy` and then cached.
//
// `intercept://on` is an unknown protocol in both. whistle answers 502 with
// `Unsupported protocol intercept:` and dials nothing; this port reads it as a
// destination rewrite, tries to reach a host called `on`, and answers 502 when
// that fails. Same status, different words — and one outbound connection more
// than upstream makes. Left as found: it is the port's general policy for an
// unknown `foo://` and not something `intercept://` can decide on its own.
const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

/** A ``` block: the rules text form that names its content inline. */
const V = (name, body) => '\n\n```' + name + '\n' + body + '\n```';

// `reqRules://` takes a path as readily as a value, and the two forms travel
// different code here — one is substituted before the include is read, the
// other is opened from disk. Written under the bench's own directory so a run
// leaves nothing behind that another run could read.
const fs = require('fs');
const os = require('os');
const path = require('path');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-diff-compose-'));
const file = (name, body) => {
  const p = path.join(DIR, name);
  fs.writeFileSync(p, body);
  return p;
};
const REQ_FILE = file('req.rules', `${P} reqHeaders://x-from-file=1\n`);
const RES_FILE = file('res.rules', `${P} resHeaders://x-from-file=1\n`);
const REQ_FILE_B = file('req-b.rules', `${P} reqHeaders://x-from-file-b=1\n`);

module.exports = [
  // ── reqRules:// — rules that produce more rules ─────────────────────────
  { name: 'a produced rule applies', rules: `${P} reqRules://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  { name: 'the produced text may live on disk', rules: `${P} reqRules://${REQ_FILE}` },
  { name: 'reqScript is the same operator', rules: `${P} reqScript://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  { name: 'rulesFile is the same operator', rules: `${P} rulesFile://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  { name: 'ruleFile is the same operator', rules: `${P} ruleFile://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  { name: 'ruleScript is the same operator', rules: `${P} ruleScript://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  { name: 'rulesScript is the same operator', rules: `${P} rulesScript://{a}` + V('a', `${P} reqHeaders://x-a=1`) },
  // Every `reqRules://` line is rules text and every one is read; any other
  // spelling is a *candidate script* and only the first survives the filter
  // (`_original/lib/rules/rules.js:2258-2272`).
  { name: 'two reqRules lines both contribute', rules: `${P} reqRules://{a}\n${P} reqRules://{b}` + V('a', `${P} reqHeaders://x-a=1`) + V('b', `${P} reqHeaders://x-b=1`) },
  { name: 'the second rulesFile line is dropped', rules: `${P} rulesFile://${REQ_FILE}\n${P} rulesFile://${REQ_FILE_B}` },
  { name: 'a reqRules line survives next to a rulesFile one', rules: `${P} rulesFile://${REQ_FILE}\n${P} reqRules://${REQ_FILE_B}` },

  // ── reqScript/resScript that hold JavaScript, not rules ─────────────────
  //
  // `isRulesContent` (`_original/lib/rules/index.js:41-43`) splits the family:
  // a bracketed, unfenced, uncommented text that names `rules` or `values` is
  // executed, and the array it pushes becomes the rules. This port used to run
  // none of them.
  { name: 'a reqScript pushes a rule', rules: `${P} reqScript://{s}` + V('s', `rules.push('${P} reqHeaders://x-s=1')`) },
  { name: 'a resScript reads the status', rules: `${P} resScript://{s}` + V('s', `if (statusCode == 200) rules.push('${P} resHeaders://x-rs=ok')`) },
  { name: 'a script that throws contributes nothing', rules: `${P} reqScript://{s}` + V('s', `rules.push('${P} reqHeaders://x-t=1'); throw new Error('x')`) },
  { name: 'a script reading the request url', rules: `${P} reqScript://{s}` + V('s', `if (url.indexOf('q=1') !== -1) rules.push('${P} reqHeaders://x-u=1')`), request: { path: '/echo?q=1' } },

  // Depth: what a produced text produces is **not** followed. `resolveRulesFile`
  // parses the included text once and merges it; the merged set is never asked
  // for a `rulesFile` of its own.
  { name: 'composition is one level deep', rules: `${P} reqRules://{a}` + V('a', `${P} reqRules://{b}\n${P} reqHeaders://x-a=1`) + V('b', `${P} reqHeaders://x-b=1`) },
  { name: 'a self-reference terminates', rules: `${P} reqRules://{a}` + V('a', `${P} reqRules://{a}\n${P} reqHeaders://x-a=1`) },
  { name: 'a two-step cycle terminates', rules: `${P} reqRules://{a}` + V('a', `${P} reqRules://{b}\n${P} reqHeaders://x-a=1`) + V('b', `${P} reqRules://{a}\n${P} reqHeaders://x-b=1`) },

  // Precedence: what is merged wins, on the naming line and on any other.
  { name: 'a produced rule beats the line that named it', rules: `${P} reqHeaders://x-w=outer reqRules://{a}` + V('a', `${P} reqHeaders://x-w=inner`) },
  { name: 'a produced rule beats a separate outer line', rules: `${P} reqHeaders://x-w=outer\n${P} reqRules://{a}` + V('a', `${P} reqHeaders://x-w=inner`) },
  { name: 'an important outer line holds its ground', rules: `${P} reqHeaders://x-w=outer lineProps://important\n${P} reqRules://{a}` + V('a', `${P} reqHeaders://x-w=inner`) },
  // A produced rule may answer the request outright, not only decorate it.
  { name: 'a produced mock answers the request', rules: `${P} reqRules://{a}` + V('a', `${P} file://(PRODUCED-MOCK)`) },

  // What the produced rules are matched against.
  { name: 'a produced rule sees the request the line above rewrote', rules: `${P}/echo ${P}/rewritten\n${P} reqRules://{a}` + V('a', `${P}/rewritten reqHeaders://x-saw=rewritten\n${P}/echo reqHeaders://x-saw=original`) },
  { name: 'a produced condition reads a header an outer line set', rules: `${P} reqHeaders://x-set=1\n${P} reqRules://{a}` + V('a', `${P} reqHeaders://x-saw=yes includeFilter://reqH.x-set=1`) },

  // …and what they are **not** given: the ``` blocks of the text that produced
  // them. Upstream parses the produced text into a `Rules` of its own, seeded
  // only with the values that text itself returned, re-keyed under the naming
  // rule's file (`toPrivateValues`, `_original/lib/rules/index.js:520-530`) —
  // the naming file's own inline map lives in a different instance and is never
  // consulted. So `{mock}` inside a produced text is answered by nothing, even
  // though the block sits three lines above the rule that named it.
  //
  // Measured rather than read: `toPrivateValues(vals, rule.file)` says the
  // opposite at a glance, and this port used to serve the block.
  //
  // Written on `reqHeaders://` rather than on a body operator so that the two
  // answers are *both* visible. An unanswered `{name}` on a body operator makes
  // this port write the six characters `{mock}` — the declared "a bare value
  // stays the literal" divergence in `docs/RULES.md` — which would hide this
  // question behind that one. On a header operator an unanswered reference sets
  // nothing in either proxy, so "did the block reach it" is the only thing left
  // to see. The middle case is therefore inert on purpose, and the two around it
  // are what give it meaning: the first proves a produced rule fires at all, the
  // last proves the same block reaches the same operator when it is not produced.
  { name: 'a produced rule needing no value fires', rules: `${P} reqRules://{a}` + V('a', `${P} reqHeaders://x-produced=1`) },
  { name: 'a produced rule cannot see the block beside the line that named it', rules: `${P} reqRules://{a}` + V('mock', 'x-mock=1') + V('a', `${P} reqHeaders://{mock}`) },
  { name: 'the same block on the same operator, not produced', rules: `${P} reqHeaders://{mock}` + V('mock', 'x-mock=1') },

  // Malformed and missing.
  { name: 'a produced text that is not rules', rules: `${P} reqRules://{a}` + V('a', 'this is not a rule at all !!!') },
  { name: 'a produced text that is empty', rules: `${P} reqRules://{a}` + V('a', '') },
  { name: 'reqRules naming a value that does not exist', rules: `${P} reqRules://{nope} reqHeaders://x-a=1` },
  { name: 'reqRules naming a file that does not exist', rules: `${P} reqRules:///no/such/rules.txt reqHeaders://x-a=1` },

  // ── resRules:// — rules that produce **response** rules ─────────────────
  { name: 'a produced response rule applies', rules: `${P} resRules://{r}` + V('r', `${P} resHeaders://x-r=1`) },
  { name: 'the produced response text may live on disk', rules: `${P} resRules://${RES_FILE}` },
  { name: 'a produced response rule beats the line that named it', rules: `${P} resHeaders://x-w=outer resRules://{r}` + V('r', `${P} resHeaders://x-w=inner`) },
  { name: 'resRules can replace the status', rules: `${P} resRules://{r}` + V('r', `${P} replaceStatus://503`) },
  { name: 'resRules can rewrite the body', rules: `${P} resRules://{r}` + V('r', `${P} resBody://(REPLACED)`) },
  { name: 'resRules can retype the response', rules: `${P} resRules://{r}` + V('r', `${P} resType://html`) },
  { name: 'two resRules lines both contribute', rules: `${P} resRules://{a}\n${P} resRules://{b}` + V('a', `${P} resHeaders://x-a=1`) + V('b', `${P} resHeaders://x-b=1`) },
  // Only `resProtocols` are merged: by the time the text is read the request
  // has gone out, so a request-side operator inside it is parsed and dropped.
  { name: 'a request rule inside resRules is too late', rules: `${P} resRules://{r}` + V('r', `${P} reqHeaders://x-too-late=1`) },
  { name: 'a host rule inside resRules is too late', rules: `${P} resRules://{r}` + V('r', `${P} host://192.0.2.1`) },
  // The text is resolved with the response head in hand, so a status condition
  // inside it is answerable.
  { name: 'a status condition inside resRules that matches', rules: `${P} resRules://{r}` + V('r', `${P} resHeaders://x-r=1 includeFilter://s:200`) },
  { name: 'a status condition inside resRules that misses', rules: `${P} resRules://{r}` + V('r', `${P} resHeaders://x-r=1 includeFilter://s:404`) },
  { name: 'a resRules pattern that does not match', rules: `${P} resRules://{r}` + V('r', 'other.test resHeaders://x-r=1') },
  { name: 'resRules is one level deep too', rules: `${P} resRules://{a}` + V('a', `${P} resRules://{b}\n${P} resHeaders://x-a=1`) + V('b', `${P} resHeaders://x-b=1`) },
  { name: 'resRules naming a file that does not exist', rules: `${P} resRules:///no/such/res.txt resHeaders://x-a=1` },
  { name: 'a resRules line next to a resScript one', rules: `${P} resRules://{r} resScript:///no/such/script.js` + V('r', `${P} resHeaders://x-r=1`) },

  // ── locationHref:// — a page that redirects itself ──────────────────────
  // Not an injection: `isFileProxy` admits it (`protocols.js:282`), so it shares
  // the one destination slot with `file://` and answers without contacting the
  // origin at all — whatever the origin would have replied with.
  { name: 'locationHref answers an html request', rules: `${P} locationHref://http://other.test/go`, request: { path: '/html' } },
  { name: 'locationHref answers a json request too', rules: `${P} locationHref://http://other.test/go` },
  { name: 'locationHref answers a relative target', rules: `${P} locationHref:///elsewhere` },
  { name: 'locationHref js: drops the script tag', rules: `${P} locationHref://js:http://other.test/go` },
  { name: 'locationHref html: forces markup', rules: `${P} locationHref://html:http://other.test/go` },
  { name: 'locationHref replace: swaps the call', rules: `${P} locationHref://replace:http://other.test/go` },
  { name: 'a request for a script gets bare javascript', rules: `${P} locationHref://http://other.test/go`, request: { headers: { 'sec-fetch-dest': 'script' } } },
  { name: 'html: overrides the script guess', rules: `${P} locationHref://html:http://other.test/go`, request: { headers: { 'sec-fetch-dest': 'script' } } },
  { name: 'an empty locationHref is still an answer', rules: `${P} locationHref://` },
  { name: 'locationHref at the request own url does not answer', rules: `${P} locationHref://http://${P}/echo` },
  { name: 'an earlier file rule takes the slot', rules: `${P} file://(MOCK)\n${P} locationHref://http://other.test/go` },
  { name: 'locationHref takes the slot when written first', rules: `${P} locationHref://http://other.test/go\n${P} file://(MOCK)` },
  { name: 'response operators reach a locationHref answer', rules: `${P} locationHref://http://other.test/go resHeaders://x-a=1` },

  // ── the injection family ────────────────────────────────────────────────
  { name: 'htmlAppend goes after the markup', rules: `${P} htmlAppend://{v}` + V('v', '<i>ADDED</i>'), request: { path: '/html' } },
  { name: 'htmlPrepend goes before it, with a doctype', rules: `${P} htmlPrepend://{v}` + V('v', '<i>PRE</i>'), request: { path: '/html' } },
  { name: 'htmlBody replaces the whole body', rules: `${P} htmlBody://{v}` + V('v', '<b>WHOLE</b>'), request: { path: '/html' } },
  { name: 'jsAppend on javascript is appended bare', rules: `${P} jsAppend://{v}` + V('v', 'var added=1;'), request: { path: '/script.js' } },
  { name: 'jsAppend on html is wrapped in a script tag', rules: `${P} jsAppend://{v}` + V('v', 'var added=1;'), request: { path: '/html' } },
  { name: 'cssAppend on css is appended bare', rules: `${P} cssAppend://{v}` + V('v', 'p{color:blue}'), request: { path: '/style.css' } },
  { name: 'cssAppend on html is wrapped in a style tag', rules: `${P} cssAppend://{v}` + V('v', 'p{color:blue}'), request: { path: '/html' } },
  { name: 'a url-valued jsAppend becomes a src attribute', rules: `${P} jsAppend://http://cdn.test/a.js`, request: { path: '/html' } },
  { name: 'a url-valued cssAppend becomes a link element', rules: `${P} cssAppend://http://cdn.test/a.css`, request: { path: '/html' } },
  { name: 'the html alias', rules: `${P} html://{v}` + V('v', '<i>ALIAS</i>'), request: { path: '/html' } },
  { name: 'the js alias', rules: `${P} js://{v}` + V('v', 'var alias=1;'), request: { path: '/html' } },
  { name: 'the css alias', rules: `${P} css://{v}` + V('v', 'p{color:green}'), request: { path: '/html' } },
  { name: 'injecting into an empty body', rules: `${P} htmlAppend://{v}` + V('v', '<i>ADDED</i>'), request: { path: '/empty.html' } },
  { name: 'htmlAppend leaves a non-html body alone', rules: `${P} htmlAppend://{v}` + V('v', '<i>ADDED</i>'), request: { path: '/plain.txt' } },
  { name: 'the response is re-encoded after injection', rules: `${P} htmlAppend://{v}` + V('v', '<i>ADDED</i>'), request: { path: '/gzipped.html' } },
  // Injection and `resReplace://` in the same request: the replacement runs over
  // the origin's own bytes, not over what was injected into them.
  { name: 'resReplace rewrites the origin body next to an injection', rules: `${P} htmlAppend://{v} resReplace://ORIGINAL=CHANGED` + V('v', '<i>ADDED</i>'), request: { path: '/html' } },
  { name: 'resReplace does not see the injected text', rules: `${P} htmlAppend://{v} resReplace://ADDED=REPLACED` + V('v', '<i>ADDED</i>'), request: { path: '/html' } },
  // Injecting costs the response its CSP and its cacheability
  // (`_original/lib/inspectors/res.js:1093-1101`).
  { name: 'an injection clears the cache headers', rules: `${P} htmlAppend://{v}` + V('v', '<i>ADDED</i>'), request: { path: '/html' } },

  // ── weinre:// — see the note at the top of this file ────────────────────
  { name: 'weinre injects into html', rules: `${P} weinre://mysession`, request: { path: '/html' } },
  { name: 'weinre reaches javascript upstream', rules: `${P} weinre://mysession`, request: { path: '/script.js' } },
  { name: 'weinre leaves css alone', rules: `${P} weinre://mysession`, request: { path: '/style.css' } },
  { name: 'weinre leaves json alone', rules: `${P} weinre://mysession` },
  { name: 'weinre on an empty html body', rules: `${P} weinre://mysession`, request: { path: '/empty.html' } },
  { name: 'weinre on a gzipped html body', rules: `${P} weinre://mysession`, request: { path: '/gzipped.html' } },
  { name: 'weinre with a url value', rules: `${P} weinre://https://dbg.test/t.js#s1`, request: { path: '/html' } },
  { name: 'weinre with no value at all', rules: `${P} weinre://`, request: { path: '/html' } },

  // ── responseFor:// — blind here, see the note at the top ────────────────
  { name: 'responseFor does not disturb the request', rules: `${P} responseFor://svc-a` },
  { name: 'responseFor in its name= form', rules: `${P} responseFor://name=x-origin,req.host` },
  { name: 'responseFor naming headers that are absent', rules: `${P} responseFor://name=x-nothing` },
  { name: 'responseFor next to a rule that fires', rules: `${P} responseFor://svc-a reqHeaders://x-a=1` },

  // ── style:// — console only ─────────────────────────────────────────────
  { name: 'style on its own is not a rule', rules: `${P} style://color=red` },
  { name: 'style does not disturb the line it shares', rules: `${P} style://bold reqHeaders://x-a=1` },
  { name: 'style with a full payload', rules: `${P} style://fontStyle=italic&color=red resHeaders://x-a=1` },

  // ── pipe:// — a plugin name ─────────────────────────────────────────────
  { name: 'pipe naming a plugin neither proxy has', rules: `${P} pipe://nosuchplugin` },
  { name: 'pipe does not disturb the line it shares', rules: `${P} pipe://nosuchplugin reqHeaders://x-a=1` },

  // ── intercept:// — not a protocol; see the note at the top ──────────────
  { name: 'intercept written as a protocol', rules: `${P} intercept://on` },
  { name: 'enable intercept is the real spelling', rules: `${P} enable://intercept reqHeaders://x-a=1` },
  { name: 'disable intercept on a plain request', rules: `${P} disable://intercept reqHeaders://x-a=1` },

  // ── tlsOptions / sniCallback on cleartext — inert, and must stay so ─────
  { name: 'tlsOptions on a cleartext request', rules: `${P} tlsOptions://TLSv1.2 reqHeaders://x-a=1` },
  { name: 'sniCallback on a cleartext request', rules: `${P} sniCallback://certs reqHeaders://x-a=1` },
];
