// The corpus. One entry per behaviour worth pinning against upstream.
//
// `P` is the origin's authority; rules are written against it so the same text
// can go to both proxies unchanged.
const P = '127.0.0.1:18800';

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
  { name: 'reqReplace', rules: `${P} reqReplace://old=new`, request: { method: 'POST', body: 'an old thing' } },
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
  { name: 'a pattern that does not match', rules: `other.test reqHeaders://x-a=1` },
  { name: 'wildcard pattern', rules: `*.0.0.1:18800 reqHeaders://x-w=1` },
  { name: 'regexp pattern with a group', rules: `/127\\.0\\.0\\.(\\d+):18800/ reqHeaders://x-g=$1` },
  { name: 'inline comment is not a rule', rules: `${P} reqHeaders://x-a=1 # a comment` },
  // ── forms taken from the documentation at wproxy.org ───────────────────
  { name: 'doc: protocol inheritance, http:// destination', rules: `${P} http://${P}/moved` },
  { name: 'doc: <> disables path concatenation', rules: `${P} <http://${P}/fixed>`, request: { path: '/echo/deep/path' } },
  { name: 'doc: path is concatenated by default', rules: `${P} http://${P}/base`, request: { path: '/echo/deep' } },
  { name: 'doc: ws:// against a plain HTTP request', rules: `${P} ws://${P}/other` },
  { name: 'doc: tunnel:// against a plain HTTP request', rules: `${P} tunnel://${P}` },
  { name: 'doc: submatch $1 from a wildcard', rules: `^http://127.0.0.1:18800/**  reqHeaders://x-sub=$1`, request: { path: '/echo/abc' } },
  { name: 'doc: submatch $1 from a regexp', rules: `/127\\.0\\.0\\.1:18800\\/(\\w+)/ reqHeaders://x-sub=$1` },
  { name: 'doc: urlParams with an existing query', rules: `${P} urlParams://a=1&b=2`, request: { path: '/echo?c=3' } },
  { name: 'doc: method lowercase is upcased', rules: `${P} method://put` },
  { name: 'doc: reqCookies json', rules: `${P} reqCookies://{"a":"1","b":"2"}` },
  { name: 'doc: resCookies with attributes', rules: `${P} resCookies://{"sid":{"value":"x","httpOnly":true,"maxAge":600}}` },
  { name: 'doc: log tag', rules: `${P} log://mytag` },
  { name: 'doc: two operators on one line', rules: `${P} reqHeaders://x-a=1 resHeaders://x-b=2` },
  { name: 'doc: pattern with a path prefix', rules: `127.0.0.1:18800/echo reqHeaders://x-p=1` },
  { name: 'doc: pattern with a path that should not match', rules: `127.0.0.1:18800/nope reqHeaders://x-p=1` },
  { name: 'doc: ignore silences an operator', rules: `${P} reqHeaders://x-a=1 ignore://reqHeaders` },
  { name: 'doc: skip is the same as ignore', rules: `${P} reqHeaders://x-a=1 skip://reqHeaders` },
  { name: 'doc: enable and disable on one line', rules: `${P} disable://cookie enable://abort`, request: { headers: { cookie: 'a=1' } } },

  // ── pattern forms, from the docs' Pattern Matching page ────────────────
  // `$` is exact matching: the path must equal the pattern, not begin with it.
  // This port read `$` as an "important" marker and prefix-matched, so
  // `$example.test` applied to every URL on the host instead of its root.
  { name: 'doc pattern: $ exact matches its own path', rules: `$http://${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: $ ignores the query when it has none', rules: `$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo?a=1' } },
  { name: 'doc pattern: $ does not match a sub-path', rules: `$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo/sub' } },
  { name: 'doc pattern: $ with a query is exact in both', rules: `$http://${P}/echo?a=1 reqHeaders://x-hit=1`, request: { path: '/echo?a=1' } },
  { name: 'doc pattern: $ with a query rejects another', rules: `$http://${P}/echo?a=1 reqHeaders://x-hit=1`, request: { path: '/echo?b=2' } },
  { name: 'doc pattern: $ carries no precedence', rules: `${P}/echo reqHeaders://x-who=normal\n$http://${P}/echo reqHeaders://x-who=exact` },
  { name: 'doc pattern: !$ is a negated exact', rules: `!$http://${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: !$ matches everything else', rules: `!$http://${P}/echo reqHeaders://x-hit=1`, request: { path: '/echo/sub' } },
  { name: 'doc pattern: scheme-relative //host/path', rules: `//${P}/echo reqHeaders://x-hit=1` },
  { name: 'doc pattern: ^ wildcard in a path', rules: `^http://${P}/ec*o reqHeaders://x-hit=1` },
  { name: 'doc pattern: ^ with a trailing $ boundary', rules: `^http://${P}/ec*o$ reqHeaders://x-hit=1`, request: { path: '/echo/deep' } },
  { name: 'doc pattern: port-only', rules: `:18800 reqHeaders://x-hit=1` },
  { name: 'doc pattern: port-only that misses', rules: `:9999 reqHeaders://x-hit=1` },

  { name: 'values reference', rules: '```v\nfrom-a-value\n```\n' + `${P} reqHeaders://x-v={v}` },
];
