// The corpus. One entry per behaviour worth pinning against upstream.
//
// `P` is the origin's authority; rules are written against it so the same text
// can go to both proxies unchanged.
const PORT = Number(process.env.PORT_BASE || 18700) + 2;
const P = `127.0.0.1:${PORT}`;

module.exports = [
  // ── request headers ────────────────────────────────────────────────────
  { name: 'reqHeaders adds one', rules: `${P} reqHeaders://x-a=1` },
  { name: 'reqHeaders two lines merge', rules: `${P} reqHeaders://x-a=1\n${P} reqHeaders://x-b=2` },
  { name: 'reqHeaders contested name takes the first line', rules: `${P} reqHeaders://x-a=first\n${P} reqHeaders://x-a=second` },
  { name: 'reqHeaders empty value', rules: `${P} reqHeaders://x-a=` },
  { name: 'reqHeaders json', rules: `${P} reqHeaders://{"x-a":"1","x-b":"2"}` },
  { name: 'reqHeaders repeated name', rules: `${P} reqHeaders://x-a=1&x-a=2` },
  { name: 'delete reqHeaders', rules: `${P} reqHeaders://x-a=1 delete://reqHeaders.x-a` },
  { name: 'ua rewrites user-agent', rules: `${P} ua://MyAgent/9` },
  { name: 'referer', rules: `${P} referer://http://ref.test/p` },
  { name: 'auth basic', rules: `${P} auth://user:pass` },
  { name: 'method rewrite', rules: `${P} method://PUT` },
  { name: 'disable cookie', rules: `${P} disable://cookie`, request: { headers: { cookie: 'sid=secret' } } },
  { name: 'disable ua', rules: `${P} disable://ua` },
  { name: 'disable referer', rules: `${P} disable://referer`, request: { headers: { referer: 'http://r.test/' } } },
  { name: 'forwardedFor', rules: `${P} forwardedFor://9.9.9.9` },
  { name: 'reqCookies', rules: `${P} reqCookies://a=1` },
  { name: 'reqType', rules: `${P} reqType://json`, request: { method: 'POST', body: '{}' } },

  // ── url and query ──────────────────────────────────────────────────────
  { name: 'urlParams adds query', rules: `${P} urlParams://a=1` },
  { name: 'urlParams onto existing query', rules: `${P} urlParams://a=1`, request: { path: '/echo?b=2' } },
  { name: 'urlReplace', rules: `${P} urlReplace://echo=replaced` },
  { name: 'pathReplace alias', rules: `${P} pathReplace://echo=replaced` },
  { name: 'delete query key', rules: `${P} delete://query.b`, request: { path: '/echo?a=1&b=2' } },
  { name: 'delete whole query', rules: `${P} delete://query`, request: { path: '/echo?a=1&b=2' } },

  // ── request body ───────────────────────────────────────────────────────
  { name: 'reqBody replaces', rules: `${P} reqBody://(INJECTED)`, request: { method: 'POST', body: 'original' } },
  { name: 'reqBody on GET is dropped', rules: `${P} reqBody://(INJECTED)` },
  { name: 'reqPrepend/reqAppend', rules: `${P} reqPrepend://(A) reqAppend://(Z)`, request: { method: 'POST', body: 'M' } },
  { name: 'reqReplace', rules: `${P} reqReplace://old=new`, request: { method: 'POST', body: 'an old thing', headers: { 'content-type': 'text/plain' } } },
  // The same line without a type, which neither proxy rewrites: the text
  // transforms run inside a charset decode keyed on the content type, and a
  // body with no type is not text as far as either of them is concerned. The
  // case above carried no type either, and so measured nothing for a year.
  { name: 'reqReplace needs a content type', rules: `${P} reqReplace://old=new`, request: { method: 'POST', body: 'an old thing' } },
  { name: 'params into urlencoded body', rules: `${P} params://c=3`, request: { method: 'POST', body: 'a=1&b=2', headers: { 'content-type': 'application/x-www-form-urlencoded' } } },
  { name: 'params with no body goes to query', rules: `${P} params://c=3` },
  { name: 'delete reqBody key on json', rules: `${P} delete://reqBody.a`, request: { method: 'POST', body: '{"a":1,"b":2}', headers: { 'content-type': 'application/json' } } },

  // ── response headers ───────────────────────────────────────────────────
  { name: 'resHeaders adds', rules: `${P} resHeaders://x-r=1` },
  { name: 'resHeaders contested takes first', rules: `${P} resHeaders://x-r=first\n${P} resHeaders://x-r=second` },
  { name: 'delete resHeaders', rules: `${P} delete://resHeaders.x-origin` },
  { name: 'replaceStatus', rules: `${P} replaceStatus://404` },
  { name: 'resType', rules: `${P} resType://html` },
  { name: 'resCookies', rules: `${P} resCookies://sid=abc` },
  { name: 'resCors star', rules: `${P} resCors://*` },
  { name: 'resCors enable echoes origin', rules: `${P} resCors://enable`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'resCors preflight', rules: `${P} resCors://enable`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT', 'access-control-request-headers': 'x-token' } } },
  // The forms the documentation leads with —
  // https://wproxy.org/docs/rules/headerReplace.html
  { name: 'headerReplace on a response header', rules: `${P} headerReplace://resH.x-origin:/yes/=no` },
  { name: 'headerReplace doc form: req, literal', rules: `${P} headerReplace://req.accept:html=abc`, request: { headers: { accept: 'text/html,application/xhtml+xml' } } },
  { name: 'headerReplace doc form: req, regexp global', rules: `${P} headerReplace://req.accept:/ml/g=abc`, request: { headers: { accept: 'text/html,application/xhtml+xml' } } },
  { name: 'headerReplace doc form: res', rules: `${P} headerReplace://res.Content-Type:json=plain` },
  // `p1=v1&p2=v2` on one header: the second pair carries no colon, so the whole
  // key is its pattern. This port dropped it and applied only the first.
  { name: 'headerReplace doc form: several patterns, one header', rules: `${P} headerReplace://res.x-origin:y=Y&es=ES` },
  { name: 'headerReplace JSON form still works', rules: `${P} headerReplace://{"resH.x-origin:/yes/":"no"}` },
  { name: 'attachment', rules: `${P} attachment://out.json` },
  { name: 'cache', rules: `${P} cache://600` },

  // ── response body ──────────────────────────────────────────────────────
  { name: 'resBody replaces', rules: `${P} resBody://(REPLACED)` },
  { name: 'resReplace on html', rules: `${P} resReplace://ORIGINAL=REWRITTEN`, request: { path: '/html' } },
  { name: 'resReplace regexp', rules: `${P} resReplace:///ORIG(INAL)/=X$1`, request: { path: '/html' } },
  { name: 'resPrepend/resAppend on html', rules: `${P} resPrepend://(TOP) resAppend://(END)`, request: { path: '/html' } },
  { name: 'htmlAppend', rules: `${P} htmlAppend://(<i>hi</i>)`, request: { path: '/html' } },
  { name: 'jsAppend on html', rules: `${P} jsAppend://(alert(1))`, request: { path: '/html' } },
  { name: 'cssAppend on html', rules: `${P} cssAppend://(body{color:red})`, request: { path: '/html' } },
  { name: 'resMerge', rules: `${P} resMerge://{"extra":1}` },

  // ── short circuits ─────────────────────────────────────────────────────
  { name: 'statusCode', rules: `${P} statusCode://204` },
  { name: 'statusCode 500', rules: `${P} statusCode://500` },
  { name: 'redirect', rules: `${P} redirect://http://other.test/x` },
  { name: 'file inline', rules: `${P} file://({"mock":true})` },
  { name: 'tpl inline', rules: `${P} tpl://({"m":1})` },

  // ── filters ────────────────────────────────────────────────────────────
  { name: 'includeFilter method match', rules: `${P} resHeaders://x-m=1 includeFilter://m:GET` },
  { name: 'includeFilter method miss', rules: `${P} resHeaders://x-m=1 includeFilter://m:POST` },
  { name: 'excludeFilter method', rules: `${P} resHeaders://x-m=1 excludeFilter://m:GET` },
  { name: 'includeFilter on a request header', rules: `${P} resHeaders://x-h=1 includeFilter://reqH.x-tag:yes`, request: { headers: { 'x-tag': 'yes' } } },
  { name: 'includeFilter on status', rules: `${P} resHeaders://x-s=1 includeFilter://s:200` },
  { name: 'includeFilter on status miss', rules: `${P} resHeaders://x-s=1 includeFilter://s:404` },

  // ── precedence and shape ───────────────────────────────────────────────
  { name: 'first matching line wins a single-value operator', rules: `${P} ua://first\n${P} ua://second` },
  { name: 'important reverses that', rules: `${P} ua://first\n${P} ua://second lineProps://important` },
  { name: 'a pattern that does not match', inert: true, rules: `other.test reqHeaders://x-a=1` },
  { name: 'wildcard pattern', rules: `*.0.0.1:${PORT} reqHeaders://x-w=1` },
  { name: 'regexp pattern with a group', rules: `/127\\.0\\.0\\.(\\d+):${PORT}/ reqHeaders://x-g=$1` },
  { name: 'inline comment is not a rule', rules: `${P} reqHeaders://x-a=1 # a comment` },
  // ── forms taken from the documentation at wproxy.org ───────────────────
  // The three below all pin the **swap** described in the note under them, not
  // what their names used to claim. `127.0.0.1:<port> http://…` reads as
  // *pattern = the URL, operator = the host*, so a request for `/echo` matches
  // nothing and the line does nothing — on both sides. Renamed rather than
  // deleted, because "this documented-looking line is inert" is worth a case;
  // the live pair after them asks the questions the old names promised, with a
  // pattern that cannot be swapped away.
  { name: 'doc: a bare host with an http:// URL swaps into pattern and host', inert: true, rules: `${P} http://${P}/moved` },
  { name: 'doc: a bare host with an <http://> URL swaps and turns into a file', rules: `${P} <http://${P}/fixed>`, request: { path: '/echo/deep/path' } },
  { name: 'doc: the swap leaves a plain request unmatched', inert: true, rules: `${P} http://${P}/base`, request: { path: '/echo/deep' } },
  { name: 'doc: path is concatenated by default', rules: `^http://${P}/echo** http://${P}/base`, request: { path: '/echo/deep' } },
  // The brackets go **inside** the scheme. `<http://…>` is not a destination
  // that refuses the join — the whole token is wrapped, and `formatShorthand`
  // reads a wrapped token as `file://`, so it names a file whose path happens to
  // look like a URL. `http://<…>` is the form the documentation means.
  { name: 'doc: <> disables path concatenation', rules: `^http://${P}/echo** http://<${P}/base>`, request: { path: '/echo/deep' } },
  // These two are inert on **both** sides, and not for the reason their names
  // used to suggest. `127.0.0.1:<port>` is a bare host, which `indexOfPattern`
  // does not accept as a pattern (`isPattern` has no host branch — it only
  // records the index and keeps looking, `_original/lib/rules/rules.js:1449-1467`),
  // while `ws://…` *is* one. So the line is read the other way round: the ws URL
  // is the pattern and the host is a `host://` operator, and a plain HTTP request
  // matches no such pattern. What they pin is the swap, not the ws rule — the
  // pair below asks the ws question with a pattern that cannot be swapped away.
  { name: 'doc: a bare host with a ws:// URL swaps into pattern and host', inert: true, rules: `${P} ws://${P}/other` },
  { name: 'doc: a bare host with a tunnel:// URL swaps the same way', inert: true, rules: `${P} tunnel://${P}` },
  { name: 'doc: submatch $1 from a wildcard', rules: `^http://${P}/**  reqHeaders://x-sub=$1`, request: { path: '/echo/abc' } },
  { name: 'doc: submatch $1 from a regexp', rules: `/127\\.0\\.0\\.1:${PORT}\\/(\\w+)/ reqHeaders://x-sub=$1` },
  { name: 'doc: urlParams with an existing query', rules: `${P} urlParams://a=1&b=2`, request: { path: '/echo?c=3' } },
  { name: 'doc: method lowercase is upcased', rules: `${P} method://put` },
  { name: 'doc: reqCookies json', rules: `${P} reqCookies://{"a":"1","b":"2"}` },
  { name: 'doc: resCookies with attributes', rules: `${P} resCookies://{"sid":{"value":"x","httpOnly":true,"maxAge":600}}` },
  { name: 'doc: log tag', rules: `${P} log://mytag` },
  { name: 'doc: two operators on one line', rules: `${P} reqHeaders://x-a=1 resHeaders://x-b=2` },
  { name: 'doc: pattern with a path prefix', rules: `${P}/echo reqHeaders://x-p=1` },
  { name: 'doc: pattern with a path that should not match', inert: true, rules: `${P}/nope reqHeaders://x-p=1` },
  { name: 'doc: ignore silences an operator', rules: `${P} reqHeaders://x-a=1 ignore://reqHeaders` },
  { name: 'doc: skip is the same as ignore', rules: `${P} reqHeaders://x-a=1 skip://reqHeaders` },
  { name: 'doc: enable and disable on one line', rules: `${P} disable://cookie enable://abort`, request: { headers: { cookie: 'a=1' } } },

  // ── pattern forms, from the docs' Pattern Matching page ────────────────
  // `$` is exact matching: the path must equal the pattern, not begin with it.
  // This port read `$` as an "important" marker and prefix-matched, so
  // `$example.test` applied to every URL on the host instead of its root.
  { name: 'doc pattern: $ exact matches its own path', rules: `$http://${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: $ ignores the query when it has none', rules: `$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo?a=1' } },
  { name: 'doc pattern: $ does not match a sub-path', inert: true, rules: `$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo/sub' } },
  { name: 'doc pattern: $ with a query is exact in both', rules: `$http://${P}/echo?a=1 reqHeaders://x-hit=1`, request: { path: '/echo?a=1' } },
  { name: 'doc pattern: $ with a query rejects another', inert: true, rules: `$http://${P}/echo?a=1 reqHeaders://x-hit=1`, request: { path: '/echo?b=2' } },
  { name: 'doc pattern: $ carries no precedence', rules: `${P}/echo reqHeaders://x-who=normal\n$http://${P}/echo reqHeaders://x-who=exact` },
  { name: 'doc pattern: !$ is a negated exact', rules: `!$http://${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: !$ matches everything else', rules: `!$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo/sub' } },
  { name: 'doc pattern: scheme-relative //host/path', rules: `//${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: ^ wildcard in a path', rules: `^http://${P}/ec*o reqHeaders://x-hit=1` },
  { name: 'doc pattern: ^ with a trailing $ boundary', inert: true, rules: `^http://${P}/ec*o$ reqHeaders://x-hit=1`, request: { path: '/echo/deep' } },
  { name: 'doc pattern: port-only', rules: `:${PORT} reqHeaders://x-hit=1` },
  { name: 'doc pattern: port-only that misses', inert: true, rules: `:9999 reqHeaders://x-hit=1` },

  // A pattern that carries a query changes how its *path* is matched: prefix
  // everywhere else, exact here ("路径必须完全相同，且查询字符串以 xxx 为前缀",
  // https://wproxy.org/docs/rules/pattern.html §3.2). Asked three ways, because
  // "the rule missed" and "the rule does not exist" look the same from one case.
  { name: 'doc pattern: a query pattern matches its own path', rules: `${P}/echo?q= reqHeaders://x-hit=1`, request: { path: '/echo?q=1' } },
  { name: 'doc pattern: a query pattern will not prefix-match the path', inert: true, rules: `${P}/ec?q= reqHeaders://x-hit=1`, request: { path: '/echo?q=1' } },
  { name: 'doc pattern: a query pattern rejects a longer path', inert: true, rules: `${P}/echo?q= reqHeaders://x-hit=1`, request: { path: '/echo/sub?q=1' } },
  // Query wildcards under `^`: `*` is `[^&]*` and stops at the separator, `**`
  // is `.*` and eats the rest of the query string (same page, "查询参数通配符").
  { name: 'doc pattern: ^ query * stops at the separator', inert: true, rules: `^http://${P}/echo?q=a*b reqHeaders://x-hit=1`, request: { path: '/echo?q=a&r=b' } },
  { name: 'doc pattern: ^ query ** crosses it', rules: `^http://${P}/echo?q=a**b reqHeaders://x-hit=1`, request: { path: '/echo?q=a&r=b' } },
  { name: 'doc pattern: ^ query * within one value', rules: `^http://${P}/echo?q=a*b reqHeaders://x-hit=1`, request: { path: '/echo?q=axxb&r=1' } },

  // ── more forms from the documentation ──────────────────────────────────
  // A scheme-relative destination takes the same two bracket forms as a
  // spelled-out one (https://wproxy.org/docs/rules/inherit.html, "禁用路径拼接").
  // Read only for a `://` scheme, the brackets stayed in the value and the host
  // became `<127.0.0.1` — a 502 on the page's own example.
  { name: 'doc: //<> pins a scheme-relative destination', rules: `${P}/echo //<${P}/other>`, request: { path: '/echo/deep' } },
  { name: 'doc: //() pins it too', rules: `${P}/echo //(${P}/other)`, request: { path: '/echo/deep' } },
  { name: 'doc: //<> keeps its own query', rules: `${P}/echo //<${P}/other?k=1>`, request: { path: '/echo/deep' } },
  // "普通 HTTP/HTTPS 请求：返回 502" (ws.html, wss.html, tunnel.html). Upstream
  // hands node a `protocol: 'ws:'` its agent will not speak; this port used to
  // forward the request as plain HTTP to wherever the rule pointed. Both answer
  // 502 now, and `harness.js` excuses the two error pages by these case names.
  { name: 'doc: ws:// is not a transport for a plain request', rules: `${P}/echo ws://${P}/other` },
  { name: 'doc: wss:// is not a transport for a plain request', rules: `${P}/echo wss://${P}/other` },
  { name: 'doc: tunnel:// is not a transport for a plain request', rules: `${P}/echo tunnel://${P}` },
  // A status value that is not a status. Upstream hands it to Node's
  // `res.writeHead`, which throws, and the client gets a **connection reset** —
  // measured for `abc`, `20x`, `099`, `0`, `2000` and a file path. This port
  // keeps the answer an empty value gets (`200`, which is upstream's own
  // `rule || 200`) and leaves a replaced status alone. Declared in `harness.js`.
  { name: 'unusable status value: statusCode text', rules: `${P} statusCode://abc` },
  { name: 'unusable status value: statusCode out of range', rules: `${P} statusCode://2000` },
  { name: 'unusable status value: replaceStatus text', rules: `${P} replaceStatus://abc` },
  { name: 'unusable status value: replaceStatus below 100', rules: `${P} replaceStatus://1` },
  // The two either side of it, which do agree.
  { name: 'statusCode with an empty value is 200', rules: `${P} statusCode://` },
  { name: 'replaceStatus with an empty value changes nothing', rules: `${P} replaceStatus://` },
  { name: 'statusCode 999 is passed through', rules: `${P} statusCode://999` },
  // A method value that is not an HTTP token. Node refuses to build the
  // request and whistle answers its `502` page; this port leaves the method
  // alone, for the same reason it keeps answering an unusable status — an
  // operator that cannot be honoured is not a reason to fail a request that
  // otherwise works. Measured for `GET;`, a JSON object and a block of lines.
  { name: 'unusable method value: a separator', rules: `${P} method://GET;` },
  { name: 'unusable method value: a json object', rules: `${P} method://{"method":"PUT"}` },
  // …and the ones that are tokens, which agree: an unknown verb is sent as
  // written, and digits are a token too.
  { name: 'method: an unknown verb is sent as written', rules: `${P} method://FROBNICATE` },
  { name: 'method: digits are a token', rules: `${P} method://42` },
  // …and neither is `location://`, which is not a protocol at all: it is in
  // neither upstream's registry nor its alias table, so the token is a
  // destination whose scheme nothing can speak. This port answered a `302` for
  // it until the operator-coverage sweep found that no case had ever asked.
  { name: 'doc: location:// is not a transport for a plain request', rules: `${P}/echo location://http://d.test/x` },

  // `no` is the documented short spelling of `no-cache`, and a negative age is
  // the same thing (https://wproxy.org/docs/rules/cache.html).
  { name: 'doc: cache://no is short for no-cache', rules: `${P} cache://no` },
  { name: 'doc: cache with a negative age is no-cache', rules: `${P} cache://-5` },
  // The object form of `auth://` has a `proxy` flag that moves the credentials
  // to `Proxy-Authorization` (https://wproxy.org/docs/rules/auth.html).
  { name: 'doc: auth with proxy true', rules: `${P} auth://{"proxy":true,"username":"admin","password":"secret"}` },
  { name: 'doc: attachment names the download', rules: `${P} attachment://example.html` },
  // `use-credentials` cannot answer `*`, so it echoes the request's own origin
  // (https://wproxy.org/docs/rules/resCors.html, 方法二).
  { name: 'doc: resCors use-credentials echoes the origin', rules: `${P} resCors://use-credentials`, request: { headers: { origin: 'http://foo.test' } } },
  { name: 'doc: reqCharset with no content-type', rules: `${P} reqCharset://utf8`, request: { method: 'POST', body: 'x' } },
  // `<script>` attributes for an injected script
  // (https://wproxy.org/docs/rules/jsAppend.html, "为注入的脚本设置 <script> 标签属性").
  { name: 'doc: jsAppend lineProps nomodule', rules: `${P} jsAppend://(Hello) file://(-test-) lineProps://nomodule` },
  { name: 'doc: jsAppend lineProps async', rules: `${P} jsAppend://(Hello) file://(-test-) lineProps://async` },
  { name: 'doc: jsAppend lineProps crossorigin', rules: `${P} jsAppend://(Hello) file://(-test-) lineProps://crossorigin` },
  // The worked example on the lineProps page: three prepends onto one HTML
  // body, which come out in the order css, html, js behind a `<!DOCTYPE html>`.
  {
    name: 'doc: three prepends onto one html body',
    rules: `${P} file://(test) resType://html\n${P} htmlPrepend://(alert(1))\n${P} jsPrepend://(alert(1))\n${P} cssPrepend://(alert(1))`,
  },
  {
    name: 'doc: lineProps strictHtml gates only its own line',
    rules: `${P} file://(test) resType://html\n${P} htmlPrepend://(alert(1))\n${P} jsPrepend://(alert(1)) lineProps://strictHtml\n${P} cssPrepend://(alert(1))`,
  },
  {
    name: 'doc: enable strictHtml gates every line',
    rules: `${P} file://(test) resType://html\n${P} htmlPrepend://(alert(1))\n${P} jsPrepend://(alert(1)) enable://strictHtml\n${P} cssPrepend://(alert(1))`,
  },
  // The `line` block joins its own newlines into spaces
  // (https://wproxy.org/docs/rules/rule.html, "换行配置").
  { name: 'doc: a line block joins its lines', rules: `line\`\nreqHeaders://x-hit=1\n${P}\n\`` },

  { name: 'values reference', rules: '```v\nfrom-a-value\n```\n' + `${P} reqHeaders://x-v={v}` },

  // ── the three spellings of a data value ────────────────────────────────
  //
  // `_parseJSON` tries JSON, then a query string on a value with no whitespace,
  // then the line format (`_original/lib/util/index.js:1135-1143`). The third
  // was missing here — including for `resMerge://test=123`, the first example
  // on that operator's own documentation page.
  { name: 'resMerge in its query spelling', rules: `${P} resMerge://test=123` },
  { name: 'resMerge in its json spelling', rules: `${P} resMerge://{"test":123}` },
  { name: 'resMerge in its line spelling', rules: '```m\ntest: 123\n```\n' + `${P} resMerge://{m}` },
  { name: 'resMerge line spelling with a dotted path', rules: '```m\nnest.a: x\nnest.b: y\n```\n' + `${P} resMerge://{m}` },
  { name: 'reqHeaders in its line spelling', rules: '```h\nx-a: 1\nx-b: two\n```\n' + `${P} reqHeaders://{h}` },
  { name: 'resHeaders in its line spelling', rules: '```h\nx-r: 1\nx-s: two\n```\n' + `${P} resHeaders://{h}` },
  { name: 'urlParams in its line spelling', rules: '```u\ntest1: 1\ntest2: 2\n```\n' + `${P} urlParams://{u}` },
  // A value carrying both separators, which used to reach the query branch and
  // split at the `=`, giving a header named `x-a: v`.
  { name: 'a line value that contains an equals sign', rules: '```h\nx-a: v=1\n```\n' + `${P} reqHeaders://{h}` },
  { name: 'a query value that contains a colon', rules: `${P} reqHeaders://x-a=v:1` },
  // Quoting, and the number coercion the line format applies and the query
  // spelling does not.
  { name: 'a quoted line value stays text', rules: '```h\nx-a: "1"\n```\n' + `${P} reqHeaders://{h}` },
  { name: 'a line value with a leading zero stays text', rules: '```h\nx-a: 007\n```\n' + `${P} reqHeaders://{h}` },
];
