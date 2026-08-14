// One operator of every spelling this port parses, each with a value shaped
// like the one its documentation page prints.
//
// Shared by two readers, which is why it is its own file: `cases-generated.js`
// asks the resolvers about each of them, and `coverage-ops.js` uses the list as
// the set of names the bench is expected to prove something about — so a
// spelling nobody wrote a case for cannot hide by being forgotten in both
// places at once.

'use strict';

module.exports = [
  'host://1.1.1.1', 'host://1.1.1.1:8080', 'hosts://1.1.1.1', 'xhost://1.1.1.1',
  'proxy://127.0.0.1:8888', 'http-proxy://127.0.0.1:8888', 'https-proxy://127.0.0.1:8888',
  'socks://127.0.0.1:1080', 'xproxy://127.0.0.1:8888', 'xsocks://127.0.0.1:1080',
  'xhttp-proxy://127.0.0.1:8888', 'xhttps-proxy://127.0.0.1:8888',
  'internal-proxy://127.0.0.1:8888', 'internal-http-proxy://127.0.0.1:8888',
  'internal-https-proxy://127.0.0.1:8888', 'https2http-proxy://127.0.0.1:8888',
  'http2https-proxy://127.0.0.1:8888', 'xinternal-proxy://127.0.0.1:8888',
  'xhttps2http-proxy://127.0.0.1:8888', 'xhttp2https-proxy://127.0.0.1:8888',
  'pac://http://pac.test/p.pac',
  'file:///srv/mock.json', 'xfile:///srv/mock.json', 'xsfile:///srv/mock.json',
  'rawfile:///srv/raw.http', 'xrawfile:///srv/raw.http', 'tpl:///srv/t.json',
  'xtpl:///srv/t.json', 'jsonp:///srv/j.json', 'dust:///srv/d.json',
  'redirect://http://b.test/x', 'location://http://b.test/x',
  'locationHref://http://b.test/x', 'statusCode://204', 'status://204',
  'reqHeaders://x-a=1', 'resHeaders://x-a=1', 'headerReplace://reqH.x-a=/1/=2',
  'reqCookies://a=1', 'resCookies://a=1', 'reqCors://*', 'resCors://*',
  'reqType://json', 'resType://html', 'reqCharset://gbk', 'resCharset://gbk',
  'reqBody://(a)', 'resBody://(a)', 'reqPrepend://(a)', 'resPrepend://(a)',
  'reqAppend://(a)', 'resAppend://(a)', 'reqReplace://a=b', 'resReplace://a=b',
  'urlReplace://a=b', 'pathReplace://a=b', 'urlParams://a=1', 'params://a=1',
  'reqMerge://{"a":1}', 'resMerge://{"a":1}',
  'reqDelay://100', 'resDelay://100', 'reqSpeed://100', 'resSpeed://100',
  'reqWrite:///tmp/d', 'resWrite:///tmp/d', 'reqWriteRaw:///tmp/d', 'resWriteRaw:///tmp/d',
  'cssAppend://(a)', 'cssBody://(a)', 'cssPrepend://(a)', 'css://(a)',
  'htmlAppend://(a)', 'htmlBody://(a)', 'htmlPrepend://(a)', 'html://(a)',
  'jsAppend://(a)', 'jsBody://(a)', 'jsPrepend://(a)', 'js://(a)',
  'trailers://x-a=1', 'delete://reqHeaders.x-a', 'delete://query.a',
  'replaceStatus://500', 'cache://3600', 'attachment://f.txt', 'download://f.txt',
  'forwardedFor://9.9.9.9', 'method://PUT', 'ua://Agent/1', 'referer://http://r.test/',
  'auth://user:pass', 'log://ch', 'style://red', 'weinre://ch',
  'enable://abort', 'disable://cookie', 'ignore://host', 'skip://host',
  'filter://ua', 'includeFilter://m:GET', 'excludeFilter://m:POST',
  'lineProps://important', 'cipher://TLSv1.2', 'tlsOptions://minVersion=TLSv1.2',
  'sniCallback://no-mitm', 'plugin://name', 'whistle.name://x', 'plugin.name://x',
  'pipe://name', 'rulesFile:///tmp/r.rules', 'reqScript:///tmp/r.js',
  'reqRules:///tmp/r.rules', 'resRules:///tmp/r.rules', 'resScript:///tmp/r.js',
  'ruleFile:///tmp/r.rules', 'ruleScript:///tmp/r.js', 'rulesScript:///tmp/r.js',
  'frameScript:///tmp/f.js', 'responseFor://x-a', 'G://name', 'P://name',
  'inherit://name', 'rule://name', 'http://b.test/x', 'https://b.test/x',
  'ws://b.test/x', 'wss://b.test/x', 'tunnel://b.test:443', '//b.test/x',
  'b.test:8080', '/srv/mock.json', '(inline)', '{named}', '<verbatim>',
  'unknown-proto://x', 'UPPER://x',
];
