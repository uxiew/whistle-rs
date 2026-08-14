// Every rule line the **official documentation** shows as an example, put in
// front of both proxies exactly as it is written there.
//
//   PORT_BASE=19400 CASES=./cases-docs.js npm run bench
//
// The other corpora are hand-written: somebody decided what to ask. This one is
// not — it is generated from `docs/docs/rules/*.md` in the whistle repository,
// which is what wproxy.org renders, so what it asks is whatever the site tells
// a user to type. That is a different question from "does the operator work",
// and it is the question a new user's first rules file actually poses.
//
// **One substitution, and it is the pattern.** Each line keeps its operators
// verbatim and has its pattern repointed at this bench's echo origin. Without
// that every case names `www.example.com`, which neither proxy can reach, and
// the two would agree by failing together. Where a request *goes* is
// `cases-proxy.js`'s subject and it answers it against servers this bench runs.
//
// **What is left out, and why.** Four kinds of documented line are not here:
//
//   * the grammar blocks (`pattern host://ipOrDomain[:port]`) and the tables of
//     template-variable values (`avenwu`, `GET`, `8899`) — not rules;
//   * the pattern, filter and `@`-include pages, whose subject is the thing
//     this corpus rewrites or which have corpora of their own;
//   * lines whose only operator is a bare destination to one of the docs'
//     placeholder hosts — running them sends a request to whoever owns
//     `www.test.com` and tells us nothing about either proxy;
//   * lines that would make a proxy fetch or connect to a third party: an
//     `http(s)://` operator value is loaded per request, `responseFor://` dials
//     the addresses it names, and one `pac://` example routes through
//     `1.1.1.1:8080`.
//
// **Where it came from, and how to take it again.** The pages are
// `docs/docs/rules/*.md` in <https://github.com/avwo/whistle> — 100 files,
// fetched raw. Every fenced block was read, the concrete lines kept by the four
// rules above, deduplicated, and each one's pattern replaced. Nothing was
// written by hand, which is the point: a corpus somebody composed asks what its
// author thought to ask.
//
// ── What it found ──────────────────────────────────────────────────────────
//
// **`auth://` treated a path as credentials.** `auth:///Users/john/config/auth.json`
// — the spelling `auth.md` prints — reached the origin as `Authorization: Basic
// base64("/Users/john/config/auth.json")` when the file could not be read, and
// `auth://<a file in the documented line format>` sent the file's whole text
// the same way. whistle sends nothing for the first and `admin:my secret
// password` for the second: `SLASH_RE` (`_original/lib/util/index.js:102,:3653`)
// makes any value with a slash in it a *location*, never `user:pass`, and the
// other road reads what the location held as `username`/`password` pairs. Both
// halves are fixed and pinned in `crate::proxy::apply`'s `auth_by_rules` and
// `a_loaded_auth_value_is_read_as_pairs`.
//
// ── Cases expected to differ ───────────────────────────────────────────────
//
// A clean run of this file is **`differing: 5`**, from three causes:
//
//   1. **The gateway error's prose and type** (3 cases: `proxy://`,
//      `https-proxy://` and `socks://` at a dead local port). The same
//      divergence `cases-proxy.js` declares first, for the same reason:
//      matching another program's error page is not worth pinning.
//   2. **`resPrepend://(…)` shows the cache-busting headers.** A response-body
//      operator makes this port strip the request's conditional headers so the
//      origin cannot answer `304` — a *deliberate improvement* on whistle, which
//      has the code and never reaches it (`docs/RULES.md`, "A response-body
//      operator busts the request cache on its own"). It is visible here and
//      nowhere else because `resPrepend` keeps the origin's echo of the request
//      it was given, whereas every other body operator overwrites it.
//   3. **`resBody://temp/blank.json` writes the six words rather than nothing.**
//      `temp/<64 hex>|blank[.ext]` is whistle's *temp file* spelling
//      (`TEMP_PATH_RE`, `_original/lib/util/common.js:167`), resolved under its
//      own `temp_files` directory and edited by Cmd-clicking the rule in its
//      console. This port has no such directory and no such editor, so the value
//      is a bare literal and a text operator writes it. Recorded in
//      `docs/RULES.md`, not fixed: the path is only half the feature.
//
// ── The inert ones, and why each is inert ──────────────────────────────────
//
// **34 of 111**, counted by hand off one run, and every one has a reason:
//
//   * **16 cannot be seen on this bench at all.** Eight `tlsOptions://`, which
//     needs a TLS hop to observe (`https-bench.js`); five `reqWrite`/
//     `reqWriteRaw`, which go to disk (`write-bench.js`); two `sniCallback://`,
//     which needs a handshake; and `style://`, which has no traffic effect in
//     either program.
//   * **6 are correctly not applying.** `includeFilter://m:POST` on a `GET`,
//     three `pathReplace://` whose pattern is not in `/echo`, a
//     `delete://resBody.name` where the body has no `name`, and a `skip://`
//     naming a rule that is not there.
//   * **4 name a plugin** (`pipe://test-pipe-http`) that neither proxy has.
//   * **4 are the position-swapped spelling** — `<origin> www.example.com
//     proxy://…` reads as *pattern `www.example.com`*, since a bare `ip:port`
//     is an operator to `indexOfPattern` and a hostname is not. The line then
//     matches nothing, in both. That is the trap `docs/RULES.md` records under
//     the `ws://` row, arrived at here by repointing rather than by writing.
//   * **4 name a file, a values key or a temp file that does not exist** —
//     `/Users/john/config/auth.json` is a 404 on any machine but its author's,
//     and `{static-cache}` is a key the docs assume you created. Both proxies
//     do nothing, which is the agreement worth having, and one of the four is
//     the case that used to send the path as credentials.

const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

module.exports = [
  // ── attachment ──────────────────────────────────────────────────
  { name: 'attachment: https://example.com/report attachment://年度报告.pdf', rules: `${P} attachment://年度报告.pdf` },
  { name: 'attachment: https://www.example.com/ attachment://example.html', rules: `${P} attachment://example.html` },
  // ── auth ────────────────────────────────────────────────────────
  { name: 'auth: https://api.example.com/ auth://admin:secret', rules: `${P} auth://admin:secret` },
  { name: 'auth: https://example.com/api/ auth:///Users/john/config/auth.json', rules: `${P} auth:///Users/john/config/auth.json` },
  { name: 'auth: https://example.com/api/ auth://admin:secret includeFilter://m:POST', rules: `${P} auth://admin:secret includeFilter://m:POST` },
  { name: 'auth: https://example.com/api/ auth://{api-auth}', rules: `${P} auth://{api-auth}` },
  { name: 'auth: https://example.com/report auth://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.json', rules: `${P} auth://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.json` },
  // ── cache ───────────────────────────────────────────────────────
  { name: 'cache: https://example.com/api  cache://300 includeFilter://s:200', rules: `${P} cache://300 includeFilter://s:200` },
  { name: 'cache: https://example.com/assets cache://{static-cache}', rules: `${P} cache://{static-cache}` },
  // ── cipher ──────────────────────────────────────────────────────
  { name: 'cipher: https://example.com/report tlsOptions://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.json', rules: `${P} tlsOptions://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.json` },
  { name: 'cipher: www.example.com/path tlsOptions://ECDHE-ECDSA-AES256-GCM-SHA384:DH-RSA-AES256-GCM-SHA384', rules: `${P} tlsOptions://ECDHE-ECDSA-AES256-GCM-SHA384:DH-RSA-AES256-GCM-SHA384` },
  { name: 'cipher: www.example.com/path1 tlsOptions:///User/xxx/test.json', rules: `${P} tlsOptions:///User/xxx/test.json` },
  { name: 'cipher: www.example.com/path3 tlsOptions://temp/blank.json', rules: `${P} tlsOptions://temp/blank.json` },
  { name: 'cipher: www.exaple.com/path tlsOptions://key=/User/xxx/test.key&cert=/User/xxx/test.crt', rules: `${P} tlsOptions://key=/User/xxx/test.key&cert=/User/xxx/test.crt` },
  { name: 'cipher: www.exaple.com/path tlsOptions://key=E:\\test.key&cert=E:\\test.pem', rules: `${P} tlsOptions://key=E:\\test.key&cert=E:\\test.pem` },
  { name: 'cipher: www.exaple.com/path tlsOptions://passphrase=123456&pfx=/User/xxx/test.pfx', rules: `${P} tlsOptions://passphrase=123456&pfx=/User/xxx/test.pfx` },
  { name: 'cipher: www.exaple.com/path tlsOptions://passphrase=123456&pfx=E:/test.p12', rules: `${P} tlsOptions://passphrase=123456&pfx=E:/test.p12` },
  // ── cssAppend ───────────────────────────────────────────────────
  { name: 'cssAppend: https://example.com/test.css cssAppend://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.css', rules: `${P} cssAppend://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.css` },
  // ── cssBody ─────────────────────────────────────────────────────
  { name: 'cssBody: www.example.com/path1 cssBody://(Hello) file://(-test-)', rules: `${P} cssBody://(Hello) file://(-test-)` },
  { name: 'cssBody: www.example.com/path2 cssBody://(Hello) file://(-test-) resType://js', rules: `${P} cssBody://(Hello) file://(-test-) resType://js` },
  { name: 'cssBody: www.example.com/path3 cssBody://(Hello) file://(-test-) resType://css', rules: `${P} cssBody://(Hello) file://(-test-) resType://css` },
  // ── cssPrepend ──────────────────────────────────────────────────
  { name: 'cssPrepend: www.example.com/path1 cssPrepend://(Hello) file://(-test-)', rules: `${P} cssPrepend://(Hello) file://(-test-)` },
  { name: 'cssPrepend: www.example.com/path2 cssPrepend://(Hello) file://(-test-) resType://js', rules: `${P} cssPrepend://(Hello) file://(-test-) resType://js` },
  { name: 'cssPrepend: www.example.com/path3 cssPrepend://(Hello) file://(-test-) resType://css', rules: `${P} cssPrepend://(Hello) file://(-test-) resType://css` },
  // ── delete ──────────────────────────────────────────────────────
  { name: 'delete: https://raw.githubusercontent.com/avwo/whistle/refs/heads/master/package.json delete://resBody.name resType://json', rules: `${P} delete://resBody.name resType://json` },
  { name: 'delete: https://www.example.com/path delete://reqCookies.token|resCookies.token', rules: `${P} delete://reqCookies.token|resCookies.token` },
  // ── file ────────────────────────────────────────────────────────
  { name: 'file: https://example.com/report file://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.html', rules: `${P} file://temp/11adb9c9e1142df67b30d7646ec59bcd34c855d9011d1a2405c7fc2dfc94568d.html` },
  { name: 'file: www.example.com/api/data file://({"status":"ok"})', rules: `${P} file://({"status":"ok"})` },
  // ── htmlAppend ──────────────────────────────────────────────────
  { name: 'htmlAppend: www.example.com/path htmlAppend://(Hello) file://(-test-)', rules: `${P} htmlAppend://(Hello) file://(-test-)` },
  { name: 'htmlAppend: www.example.com/path1 htmlAppend://(test) file://(-test-) enable://strictHtml', rules: `${P} htmlAppend://(test) file://(-test-) enable://strictHtml` },
  { name: 'htmlAppend: www.example.com/path2 htmlAppend://(Hello) file://(-test-) resType://js', rules: `${P} htmlAppend://(Hello) file://(-test-) resType://js` },
  { name: 'htmlAppend: www.example.com/path2 htmlAppend://(test) file://([-test-])  enable://strictHtml', rules: `${P} htmlAppend://(test) file://([-test-]) enable://strictHtml` },
  { name: 'htmlAppend: www.example.com/path3 htmlAppend://(test) file://([-test-])  enable://safeHtml', rules: `${P} htmlAppend://(test) file://([-test-]) enable://safeHtml` },
  // ── htmlBody ────────────────────────────────────────────────────
  { name: 'htmlBody: www.example.com/path htmlBody://(Hello) file://(-test-)', rules: `${P} htmlBody://(Hello) file://(-test-)` },
  { name: 'htmlBody: www.example.com/path1 htmlBody://(test) file://(-test-) enable://strictHtml', rules: `${P} htmlBody://(test) file://(-test-) enable://strictHtml` },
  { name: 'htmlBody: www.example.com/path2 htmlBody://(Hello) file://(-test-) resType://js', rules: `${P} htmlBody://(Hello) file://(-test-) resType://js` },
  { name: 'htmlBody: www.example.com/path2 htmlBody://(test) file://([-test-])  enable://strictHtml', rules: `${P} htmlBody://(test) file://([-test-]) enable://strictHtml` },
  { name: 'htmlBody: www.example.com/path3 htmlBody://(test) file://([-test-])  enable://safeHtml', rules: `${P} htmlBody://(test) file://([-test-]) enable://safeHtml` },
  // ── htmlPrepend ─────────────────────────────────────────────────
  { name: 'htmlPrepend: www.example.com/path htmlPrepend://(Hello) file://(-test-)', rules: `${P} htmlPrepend://(Hello) file://(-test-)` },
  { name: 'htmlPrepend: www.example.com/path1 htmlPrepend://(test) file://(-test-) enable://strictHtml', rules: `${P} htmlPrepend://(test) file://(-test-) enable://strictHtml` },
  { name: 'htmlPrepend: www.example.com/path2 htmlPrepend://(Hello) file://(-test-) resType://js', rules: `${P} htmlPrepend://(Hello) file://(-test-) resType://js` },
  { name: 'htmlPrepend: www.example.com/path2 htmlPrepend://(test) file://([-test-])  enable://strictHtml', rules: `${P} htmlPrepend://(test) file://([-test-]) enable://strictHtml` },
  { name: 'htmlPrepend: www.example.com/path3 htmlPrepend://(test) file://([-test-])  enable://safeHtml', rules: `${P} htmlPrepend://(test) file://([-test-]) enable://safeHtml` },
  // ── https-proxy ─────────────────────────────────────────────────
  { name: 'https-proxy: www.example.com https-proxy://127.0.0.1:1234', rules: `${P} https-proxy://127.0.0.1:1234` },
  // Inert by construction, and kept for it: the documented line carries **two**
  // patterns sharing one operator, and this corpus repoints the first at the
  // bench's `ip:port` origin — which is the `host://` shorthand, not a pattern.
  // What is left is `www.example.com`, which no request here matches. Both
  // proxies read the line that way, which is what the case now proves.
  { name: 'https-proxy: two patterns, the first repointed into a host override', inert: true, rules: `${P} www.example.com https-proxy://127.0.0.1:1234` },
  // ── jsAppend ────────────────────────────────────────────────────
  { name: 'jsAppend: www.example.com/path1 jsAppend://(Hello) file://(-test-)', rules: `${P} jsAppend://(Hello) file://(-test-)` },
  { name: 'jsAppend: www.example.com/path2 jsAppend://(Hello) file://(-test-) resType://js', rules: `${P} jsAppend://(Hello) file://(-test-) resType://js` },
  { name: 'jsAppend: www.example.com/path3 jsAppend://(Hello) file://(-test-) resType://css', rules: `${P} jsAppend://(Hello) file://(-test-) resType://css` },
  // ── jsBody ──────────────────────────────────────────────────────
  { name: 'jsBody: www.example.com/path1 jsBody://(Hello) file://(-test-)', rules: `${P} jsBody://(Hello) file://(-test-)` },
  { name: 'jsBody: www.example.com/path2 jsBody://(Hello) file://(-test-) resType://js', rules: `${P} jsBody://(Hello) file://(-test-) resType://js` },
  { name: 'jsBody: www.example.com/path3 jsBody://(Hello) file://(-test-) resType://css', rules: `${P} jsBody://(Hello) file://(-test-) resType://css` },
  // ── jsPrepend ───────────────────────────────────────────────────
  { name: 'jsPrepend: www.example.com/path1 jsPrepend://(Hello) file://(-test-)', rules: `${P} jsPrepend://(Hello) file://(-test-)` },
  { name: 'jsPrepend: www.example.com/path2 jsPrepend://(Hello) file://(-test-) resType://js', rules: `${P} jsPrepend://(Hello) file://(-test-) resType://js` },
  { name: 'jsPrepend: www.example.com/path3 jsPrepend://(Hello) file://(-test-) resType://css', rules: `${P} jsPrepend://(Hello) file://(-test-) resType://css` },
  // ── lineProps ───────────────────────────────────────────────────
  { name: 'lineProps: www.example.com/path cssPrepend://(alert(1))', rules: `${P} cssPrepend://(alert(1))` },
  { name: 'lineProps: www.example.com/path file://(test) resType://html', rules: `${P} file://(test) resType://html` },
  { name: 'lineProps: www.example.com/path file:///User/xxx/important1.html', rules: `${P} file:///User/xxx/important1.html` },
  { name: 'lineProps: www.example.com/path file:///User/xxx/important2.html', rules: `${P} file:///User/xxx/important2.html` },
  { name: 'lineProps: www.example.com/path file:///User/xxx/important2.html lineProps://important', rules: `${P} file:///User/xxx/important2.html lineProps://important` },
  { name: 'lineProps: www.example.com/path htmlPrepend://(alert(1))', rules: `${P} htmlPrepend://(alert(1))` },
  { name: 'lineProps: www.example.com/path jsPrepend://(alert(1))', rules: `${P} jsPrepend://(alert(1))` },
  { name: 'lineProps: www.example.com/path jsPrepend://(alert(1)) enable://strictHtml', rules: `${P} jsPrepend://(alert(1)) enable://strictHtml` },
  { name: 'lineProps: www.example.com/path jsPrepend://(alert(1)) lineProps://strictHtml', rules: `${P} jsPrepend://(alert(1)) lineProps://strictHtml` },
  // ── locationHref ────────────────────────────────────────────────
  { name: 'locationHref: www.example.com/path locationHref://replace:https://www.qq.com', rules: `${P} locationHref://replace:https://www.qq.com` },
  { name: 'locationHref: www.example.com/path2 locationHref://../abc/123', rules: `${P} locationHref://../abc/123` },
  // ── pathReplace ─────────────────────────────────────────────────
  { name: 'pathReplace: www.example.com pathReplace://(/^api//=)', rules: `${P} pathReplace://(/^api//=)` },
  { name: 'pathReplace: www.example.com/api/ pathReplace://(/api/=/)', rules: `${P} pathReplace://(/api/=/)` },
  { name: 'pathReplace: www.example.com/path pathReplace://123=abc', rules: `${P} pathReplace://123=abc` },
  // ── pipe ────────────────────────────────────────────────────────
  { name: 'pipe: https://www.example.com/path pipe://test-pipe-http(123)', rules: `${P} pipe://test-pipe-http(123)` },
  { name: 'pipe: tunnel://test-tunnel.example.com pipe://test-pipe-tunnel(abc)', rules: `${P} pipe://test-pipe-tunnel(abc)` },
  { name: 'pipe: tunnel://wwww.example.com pipe://test', rules: `${P} pipe://test` },
  { name: 'pipe: wss://test-ws.example.com/path pipe://test-pipe-ws', rules: `${P} pipe://test-pipe-ws` },
  // ── proxy ───────────────────────────────────────────────────────
  { name: 'proxy: www.example.com proxy://127.0.0.1:1234', rules: `${P} proxy://127.0.0.1:1234` },
  // Inert by construction, and kept for it: the documented line carries **two**
  // patterns sharing one operator, and this corpus repoints the first at the
  // bench's `ip:port` origin — which is the `host://` shorthand, not a pattern.
  // What is left is `www.example.com`, which no request here matches. Both
  // proxies read the line that way, which is what the case now proves.
  { name: 'proxy: two patterns, the first repointed into a host override', inert: true, rules: `${P} www.example.com proxy://127.0.0.1:1234` },
  // ── redirect ────────────────────────────────────────────────────
  { name: 'redirect: www.example.com/path2 redirect://../abc/123', rules: `${P} redirect://../abc/123` },
  // ── replaceStatus ───────────────────────────────────────────────
  { name: 'replaceStatus: www.example.com/api/old replaceStatus://301', rules: `${P} replaceStatus://301` },
  // ── reqAppend ───────────────────────────────────────────────────
  { name: 'reqAppend: www.example.com/path reqAppend://(Hello) reqBody://(-test-) method://post', rules: `${P} reqAppend://(Hello) reqBody://(-test-) method://post` },
  // ── reqBody ─────────────────────────────────────────────────────
  { name: 'reqBody: www.example.com/path reqBody://(Hello) method://post', rules: `${P} reqBody://(Hello) method://post` },
  // ── reqCors ─────────────────────────────────────────────────────
  { name: 'reqCors: www.example.com/path reqCors://*', rules: `${P} reqCors://*` },
  // ── reqHeaders ──────────────────────────────────────────────────
  { name: 'reqHeaders: www.example.com/path reqHeaders://x-proxy=Whistle', rules: `${P} reqHeaders://x-proxy=Whistle` },
  // ── reqMerge ────────────────────────────────────────────────────
  { name: 'reqMerge: www.example.com/path reqMerge://test=123 reqBody://(name=avenwu) reqType://form method://post', rules: `${P} reqMerge://test=123 reqBody://(name=avenwu) reqType://form method://post` },
  // ── reqPrepend ──────────────────────────────────────────────────
  { name: 'reqPrepend: www.example.com/path reqPrepend://(Hello) reqBody://(-test-) method://post', rules: `${P} reqPrepend://(Hello) reqBody://(-test-) method://post` },
  // ── reqWrite ────────────────────────────────────────────────────
  { name: 'reqWrite: /^https://wproxy\\.org/docs/(\\?.*)?$ reqWrite:///User/xxx/test/index.html', rules: `${P} reqWrite:///User/xxx/test/index.html` },
  { name: 'reqWrite: wproxy.org/docs reqWrite:///User/xxx/test/', rules: `${P} reqWrite:///User/xxx/test/` },
  // ── reqWriteRaw ─────────────────────────────────────────────────
  { name: 'reqWriteRaw: /^https://wproxy\\.org/docs/(\\?.*)?$ reqWriteRaw:///User/xxx/test/index.html', rules: `${P} reqWriteRaw:///User/xxx/test/index.html` },
  { name: 'reqWriteRaw: wproxy.org/docs reqWriteRaw:///User/xxx/test/', rules: `${P} reqWriteRaw:///User/xxx/test/` },
  { name: 'reqWriteRaw: wproxy.org/docs/ reqWriteRaw:///User/xxx/test', rules: `${P} reqWriteRaw:///User/xxx/test` },
  // ── resAppend ───────────────────────────────────────────────────
  { name: 'resAppend: www.example.com/path resAppend://(Hello) file://(-test-)', rules: `${P} resAppend://(Hello) file://(-test-)` },
  // ── resBody ─────────────────────────────────────────────────────
  { name: 'resBody: www.example.com/api/data resBody://({"status":"modified"})', rules: `${P} resBody://({"status":"modified"})` },
  { name: 'resBody: www.example.com/api/user resBody://temp/blank.json', rules: `${P} resBody://temp/blank.json` },
  // ── resHeaders ──────────────────────────────────────────────────
  { name: 'resHeaders: www.example.com/path resHeaders://x-proxy=Whistle', rules: `${P} resHeaders://x-proxy=Whistle` },
  // ── resMerge ────────────────────────────────────────────────────
  { name: 'resMerge: www.example.com/path resMerge://test=123 file://({"name":"avenwu"})', rules: `${P} resMerge://test=123 file://({"name":"avenwu"})` },
  // ── resPrepend ──────────────────────────────────────────────────
  { name: 'resPrepend: www.example.com/page resPrepend://(<!--页面开始-->)', rules: `${P} resPrepend://(<!--页面开始-->)` },
  // ── resWrite ────────────────────────────────────────────────────
  { name: 'resWrite: /^https://wproxy\\.org/docs/(\\?.*)?$ resWrite:///User/xxx/test/index.html', rules: `${P} resWrite:///User/xxx/test/index.html` },
  { name: 'resWrite: wproxy.org/docs resWrite:///User/xxx/test/', rules: `${P} resWrite:///User/xxx/test/` },
  // ── resWriteRaw ─────────────────────────────────────────────────
  { name: 'resWriteRaw: /^https://wproxy\\.org/docs/(\\?.*)?$ resWriteRaw:///User/xxx/test/index.html', rules: `${P} resWriteRaw:///User/xxx/test/index.html` },
  { name: 'resWriteRaw: wproxy.org/docs resWriteRaw:///User/xxx/test/', rules: `${P} resWriteRaw:///User/xxx/test/` },
  // ── rule ────────────────────────────────────────────────────────
  { name: 'rule: proxy://127.0.0.1:8080 www.example.com api.example.com static.example.com includeFilter://m:GET excludeFilter:///admin/', rules: `${P} proxy://127.0.0.1:8080 www.example.com api.example.com static.example.com includeFilter://m:GET excludeFilter:///admin/` },
  { name: 'rule: www.example.com/* file:///static-files cache://3600 resCors://*', rules: `${P} file:///static-files cache://3600 resCors://*` },
  // ── skip ────────────────────────────────────────────────────────
  { name: 'skip: www.example.com/path file:///User/xxx/index1.html', rules: `${P} file:///User/xxx/index1.html` },
  { name: 'skip: www.example.com/path file:///User/xxx/index2.html', rules: `${P} file:///User/xxx/index2.html` },
  { name: 'skip: www.example.com/path skip://operation=file:///User/xxx/index1.html', rules: `${P} skip://operation=file:///User/xxx/index1.html` },
  { name: 'skip: www.example.com/path2 file://</User/xxx/test2.html>', rules: `${P} file://</User/xxx/test2.html>` },
  { name: 'skip: www.example.com/path2/test file:///User/xxx/test1.html', rules: `${P} file:///User/xxx/test1.html` },
  // ── sniCallback ─────────────────────────────────────────────────
  { name: 'sniCallback: wwww.example.com sniCallback://test', rules: `${P} sniCallback://test` },
  { name: 'sniCallback: wwww.example.com sniCallback://test-sni(abc)', rules: `${P} sniCallback://test-sni(abc)` },
  // ── socks ───────────────────────────────────────────────────────
  { name: 'socks: www.example.com socks://127.0.0.1:1234', rules: `${P} socks://127.0.0.1:1234` },
  // Inert by construction, and kept for it: the documented line carries **two**
  // patterns sharing one operator, and this corpus repoints the first at the
  // bench's `ip:port` origin — which is the `host://` shorthand, not a pattern.
  // What is left is `www.example.com`, which no request here matches. Both
  // proxies read the line that way, which is what the case now proves.
  { name: 'socks: two patterns, the first repointed into a host override', inert: true, rules: `${P} www.example.com socks://127.0.0.1:1234` },
  // ── statusCode ──────────────────────────────────────────────────
  { name: 'statusCode: www.example.com/api/old-endpoint statusCode://410', rules: `${P} statusCode://410` },
  // ── style ───────────────────────────────────────────────────────
  { name: 'style: www.test.com style://color=@fff&fontStyle=italic&bgColor=red', rules: `${P} style://color=@fff&fontStyle=italic&bgColor=red` },
  // ── urlParams ───────────────────────────────────────────────────
  { name: 'urlParams: www.example.com/path urlParams://test=123', rules: `${P} urlParams://test=123` },
];
