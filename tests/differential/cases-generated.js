// Rule lines nobody wrote down: every pattern shape against every URL shape,
// every protocol spelling, every filter condition, and the `ignore://` matrix.
//
// The two hand-made corpora ask what somebody thought to ask — one an author,
// one a documentation site. This one asks the **cross product**, which is only
// affordable because `rules-oracle.js` resolves rather than runs: 40 patterns ×
// 22 URLs costs the same as one HTTP request would.
//
// Every case names its own URL, and every rule line carries **one** operator
// whose presence is the whole answer. `host://1.1.1.1` is that operator for the
// pattern cases: it resolves for any request, has no shape of its own to get
// wrong, and cannot short-circuit — so a difference is a difference about the
// *pattern* and nothing else.
//
// Not generated here: anything whose answer is not a property of the rules —
// `chance:` (a die per resolution), `${now}` (the clock), `${version}` (which
// proxy answered).

'use strict';

const cases = [];
const add = (rules, url, extra) =>
  cases.push(Object.assign({ rules, url, src: 'generated' }, extra));

// ── patterns ───────────────────────────────────────────────────────────────

const PATTERNS = [
  // host forms
  'example.com',
  'EXAMPLE.com',
  '.example.com',
  'example.com.',
  'sub.example.com',
  // wildcards
  '*.example.com',
  '**.example.com',
  '*example.com',
  'ex*.com',
  '*.example.com/a',
  // `^` — wildcards everywhere
  '^example.com/a/*',
  '^http://example.com/a/**',
  '^http://*.example.com/a/***',
  '^http://example.com/a/*$',
  '^https://example.com/a?b=*',
  // paths and queries
  'example.com/a',
  'example.com/a/',
  'example.com/a?b=1',
  'example.com?b=1',
  'example.com/a.js',
  'example.com/A',
  // schemes
  'http://example.com',
  'https://example.com',
  'ws://example.com',
  'wss://example.com',
  'tunnel://example.com',
  '//example.com/a',
  // ports
  'example.com:8080',
  'example.com:80',
  ':8080',
  ':80',
  // regexps
  '/example\\.com/',
  '/example\\.com/i',
  '/^http:\\/\\/example\\.com\\/a$/',
  '/^https?:\\/\\/[^/]+\\/a\\/(\\d+)$/',
  // negation and exactness
  '!example.com',
  '!/example\\.com/',
  '!:8080',
  '$example.com',
  '$http://example.com/a',
  '$http://example.com/a?b=1',
  // addresses
  '127.0.0.1',
  '127.0.0.1:8080',
  '[::1]',
  '[::1]:8080',
  'localhost',
  'localhost:8080',
  // degenerate
  '*',
  '**',
  '$',
  '!',
  '/',
  '#example.com',
];

const URLS = [
  'http://example.com/',
  'http://example.com/a',
  'http://example.com/a/',
  'http://example.com/a/b',
  'http://example.com/a/12',
  'http://example.com/a?b=1',
  'http://example.com/a?b=2',
  'http://example.com/ab',
  'http://example.com/A',
  'http://example.com:8080/a',
  'http://example.com:80/a',
  'http://EXAMPLE.COM/a',
  'https://example.com/a',
  'https://example.com:8080/a',
  'ws://example.com/a',
  'wss://example.com/a',
  'tunnel://example.com:443',
  'http://sub.example.com/a',
  'http://deep.sub.example.com/a',
  'http://example.com.evil.test/a',
  'http://evil.test/?next=http://example.com/a',
  'http://127.0.0.1/a',
  'http://127.0.0.1:8080/a',
  'http://[::1]/a',
  'http://[::1]:8080/a',
  'http://localhost:8080/a',
];

for (const pattern of PATTERNS) {
  for (const url of URLS) {
    add(`${pattern} host://1.1.1.1`, url);
  }
}

// The swapped form: one operator, several patterns. Upstream decides which form
// a line is by scanning for the first token that can only be a pattern
// (`indexOfPattern`), and a bare IP is never it.
for (const line of [
  'host://1.1.1.1 example.com other.test',
  'host://1.1.1.1 example.com',
  '127.0.0.1:8080 example.com',
  'example.com 127.0.0.1:8080 other.test',
  'reqHeaders://x-a=1 example.com other.test',
]) {
  for (const url of ['http://example.com/a', 'http://other.test/a', 'http://127.0.0.1:8080/a']) {
    add(line, url);
  }
}

// ── protocol spellings ─────────────────────────────────────────────────────
//
// Every name in upstream's registry, its aliases, the `x`/`xs` fallbacks and
// the file family — each with a value shaped like the one its page prints. What
// is being compared is which key the operator lands under and what it holds,
// which is the whole of "does this port know this spelling".

const OPERATORS = require('./operators.js');

for (const op of OPERATORS) {
  add(`example.com ${op}`, 'http://example.com/a/b?q=1');
  // …and at the root, where the tail is empty and a value that names a
  // location is the value itself.
  add(`example.com ${op}`, 'http://example.com/');
}

// ── filter conditions ──────────────────────────────────────────────────────
//
// A condition guards the whole line, and a condition that cannot be answered
// fails closed on one side and open on the other depending on which — so each
// is asked twice, of a request that satisfies it and one that does not.

const REQ_MATCH = {
  method: 'POST',
  headers: { 'x-env': 'staging', 'user-agent': 'MyAgent/9', referer: 'http://ref.test/p' },
  body: 'a secret value',
  clientIp: '127.0.0.1',
};
const REQ_MISS = { method: 'GET', headers: {}, body: 'nothing here' };

const CONDITIONS = [
  'm:POST', 'm:/^po/i', 'm:!GET',
  'H:example.com', 'H:/EXAMPLE/i', 'H:other.test',
  'reqH.x-env=staging', 'reqH.x-env:stag', 'reqH.x-env=/^STAG/i', 'reqH.absent=1',
  'reqH.user-agent=/agent/i', 'ua:MyAgent', 'ua:/myagent/i',
  'referer:http://ref.test/p', 'referer:/ref\\.test/',
  'b:secret', 'b:/SECRET/i', 'b:absent',
  'i:127.0.0.1', 'i:/^127\\./', 'clientIp:127.0.0.1', 'clientIp:10.0.0.1',
  'url:/example/', 'url:example.com/a',
  '*/a*', '/example\\.com\\/a/', 'example.com/a',
  'from:composer', 'from:!composer', 'from:tunnel',
  's:200', 'statusCode:200', 'resH.x-a:1',
  'env:Alpha', 'env:!Alpha',
  'clientPort:1', 'serverIp:1.2.3.4',
  'host:example.com', 'host=example.com',
  'pattern=example.com', 'matcher=host://1.1.1.1',
];

for (const cond of CONDITIONS) {
  for (const [kind, req] of [['match', REQ_MATCH], ['miss', REQ_MISS]]) {
    void kind;
    for (const filter of ['includeFilter', 'excludeFilter']) {
      add(`example.com host://1.1.1.1 ${filter}://${cond}`, 'http://example.com/a', req);
    }
  }
}

// Combinations: two includes are or-ed, an include and an exclude are and-ed.
for (const line of [
  'example.com host://1.1.1.1 includeFilter://m:POST includeFilter://m:PUT',
  'example.com host://1.1.1.1 includeFilter://m:POST excludeFilter://reqH.x-env=staging',
  'example.com host://1.1.1.1 excludeFilter://m:POST excludeFilter://m:GET',
  'example.com host://1.1.1.1 includeFilter://m:POST includeFilter://reqH.absent=1',
]) {
  add(line, 'http://example.com/a', REQ_MATCH);
  add(line, 'http://example.com/a', REQ_MISS);
}

// ── ignore / skip ──────────────────────────────────────────────────────────
//
// The one family where naming a *spelling* and naming the *winner* part
// company, and where an exclusion may arrive after the `*` it exempts from.

const IGNORE_LINES = [
  'example.com host://1.1.1.1 ignore://host',
  'example.com host://1.1.1.1 ignore://hosts',
  'example.com host://1.1.1.1 skip://host',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://*|-host',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://*|-reqHeaders',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://* ignore://-*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://* ignore://-host',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://-host ignore://*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://-*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://!*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 skip://*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 skip://* skip://-*',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 skip://*|-host',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 skip://-*',
  'example.com statusCode://204 redirect://http://b.test/ skip://*|-statusCode',
  'example.com statusCode://204 redirect://http://b.test/ ignore://*|-statusCode',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://host&reqHeaders',
  'example.com host://1.1.1.1 reqHeaders://x-a=1 ignore://host|reqHeaders',
  'example.com socks://127.0.0.1:1080 proxy://127.0.0.1:8888 ignore://socks',
  'example.com socks://127.0.0.1:1080 proxy://127.0.0.1:8888 ignore://proxy',
  'example.com proxy://127.0.0.1:8888 ignore://socks',
  'example.com statusCode://204 redirect://http://b.test/ ignore://statusCode',
  'example.com statusCode://204 redirect://http://b.test/ ignore://status',
  'example.com statusCode://204 redirect://http://b.test/ ignore://rule',
  'example.com statusCode://204 redirect://http://b.test/ skip://statusCode',
  'example.com statusCode://204 redirect://http://b.test/ skip://rule',
  'example.com file:///srv/x http://b.test/ ignore://file',
  'example.com file:///srv/x http://b.test/ ignore://rule',
  'example.com host://1.1.1.1 ignore://pattern=example.com',
  'example.com host://1.1.1.1 ignore://matcher=host://1.1.1.1',
  'example.com host://1.1.1.1 skip://pattern=example.com',
  'example.com host://1.1.1.1 ignore://allRules',
  'example.com host://1.1.1.1 ignore://All',
  'example.com host://1.1.1.1 filter://host',
  'example.com host://1.1.1.1\nexample.com ignore://host',
  'example.com ignore://host\nexample.com host://1.1.1.1',
];
for (const line of IGNORE_LINES) add(line, 'http://example.com/a');

// ── order, importance and the shared slot ──────────────────────────────────

const ORDER_LINES = [
  'example.com reqHeaders://x-a=1\nexample.com reqHeaders://x-a=2',
  'example.com reqHeaders://x-a=1\nexample.com reqHeaders://x-a=2 lineProps://important',
  'example.com host://1.1.1.1\nexample.com host://2.2.2.2',
  'example.com host://1.1.1.1\nexample.com host://2.2.2.2 lineProps://important',
  'example.com file:///srv/x\nexample.com statusCode://204',
  'example.com statusCode://204\nexample.com file:///srv/x',
  'example.com file:///srv/x statusCode://204',
  'example.com statusCode://204 file:///srv/x',
  'example.com http://b.test/\nexample.com file:///srv/x',
  'example.com redirect://http://b.test/\nexample.com http://c.test/',
  'example.com file:///srv/x lineProps://important\nexample.com statusCode://204',
  'example.com/a host://1.1.1.1\nexample.com host://2.2.2.2',
  'example.com host://2.2.2.2\nexample.com/a host://1.1.1.1',
];
for (const line of ORDER_LINES) add(line, 'http://example.com/a');

// ── line properties ────────────────────────────────────────────────────────

for (const prop of [
  'important', 'internal', 'internalOnly', 'safeHtml', 'strictHtml', 'proxyFirst',
  'proxyHost', 'proxyHostOnly', 'weakRule', 'originUrl', 'disableAutoCors',
  'enableBigData', 'internalProxy', 'proxyTunnel', 'enableUserLogin',
  'disableUserLogin', 'unknownProp',
]) {
  add(`example.com host://1.1.1.1 lineProps://${prop}`, 'http://example.com/a/b');
  add(`example.com file:///srv/x lineProps://${prop}`, 'http://example.com/a/b');
}

// ── values and the bracket forms ───────────────────────────────────────────

const VALUE_LINES = [
  ['example.com resBody://{v}', { v: 'VAL' }],
  ['example.com resBody://{absent}', {}],
  ['example.com resBody://(inline)', {}],
  ['example.com resBody://<verbatim>', {}],
  ['example.com file://{v}', { v: '/srv/from-value' }],
  ['example.com file://(inline)', {}],
  ['example.com file://<verbatim>', {}],
  ['example.com file://{}', {}],
  ['example.com reqHeaders://x-a=${v}', { v: '1' }],
  ['example.com reqHeaders://x-a=${absent}', {}],
  ['example.com reqHeaders://`x-m=${method}`', {}],
  ['example.com host://`${method}.test`', {}],
  ['example.com http://`${method}.test`', {}],
  ['example.com `http://${method}.test`', {}],
  ['example.com file://`/srv/${method}.json`', {}],
  ['example.com resBody://`(${method})`', {}],
  ['```v\nVAL\n```\nexample.com resBody://{v}', {}],
  ['```v\nVAL\n```\nexample.com resBody://${v}', {}],
  ['example.com resBody://{v}tail', { v: 'VAL' }],
];
for (const [rules, values] of VALUE_LINES) {
  add(rules, 'http://example.com/a', { values });
}

// ── the response phase ─────────────────────────────────────────────────────
//
// The half a request cannot answer on its own. Each line carries one operator
// of each phase, so the split itself is visible: the request-phase one must
// resolve whatever the response says, and the response-phase one only when the
// condition holds.

const RESPONSES = [
  { status: 200, headers: { 'content-type': 'text/html', 'x-a': '1' }, server_ip: '9.9.9.9', server_port: 8080 },
  { status: 404, headers: { 'content-type': 'application/json' } },
  { status: 500, headers: {} },
];

const RES_CONDITIONS = [
  's:200', 's:404', 's:/^2/', 's:!200',
  'statusCode:200', 'statusCode=404',
  'resH.x-a=1', 'resH.x-a:1', 'resH.content-type:html', 'resH.absent=1',
  'resType:html', 'resType:json',
  'serverIp:9.9.9.9', 'serverIp:1.1.1.1', 'serverPort:8080',
  'm:GET', 'reqH.x-env=staging',
];

for (const cond of RES_CONDITIONS) {
  for (const response of RESPONSES) {
    for (const filter of ['includeFilter', 'excludeFilter']) {
      add(
        `example.com resHeaders://x-r=1 reqHeaders://x-q=1 ${filter}://${cond}`,
        'http://example.com/a',
        { response, headers: { 'x-env': 'staging' } }
      );
    }
  }
}

// …and the same question with no head at all, which is where a condition that
// asks about the response fails closed on both sides.
for (const cond of ['s:200', 'resH.x-a=1']) {
  for (const filter of ['includeFilter', 'excludeFilter']) {
    add(
      `example.com resHeaders://x-r=1 reqHeaders://x-q=1 ${filter}://${cond}`,
      'http://example.com/a'
    );
  }
}

// Every response-phase operator, resolved against a head.
for (const op of [
  'resHeaders://x-a=1', 'resBody://(a)', 'resPrepend://(a)', 'resAppend://(a)',
  'resReplace://a=b', 'resMerge://{"a":1}', 'resType://json', 'resCharset://gbk',
  'resCookies://a=1', 'resCors://*', 'resSpeed://100', 'resDelay://100',
  'resWrite:///tmp/d', 'resWriteRaw:///tmp/d', 'trailers://x-a=1',
  'replaceStatus://500', 'cache://3600', 'attachment://f.txt',
  'htmlAppend://(a)', 'jsAppend://(a)', 'cssAppend://(a)', 'responseFor://x-a',
  'log://ch', 'style://red', 'delete://resHeaders.x-a', 'headerReplace://resH.x-a=/1/=2',
  'enable://gzip', 'disable://trailers', 'statusCode://204', 'redirect://http://b.test/',
  'reqHeaders://x-a=1', 'host://1.1.1.1', 'file:///srv/x',
]) {
  add(`example.com ${op}`, 'http://example.com/a', { response: RESPONSES[0] });
}

// ── captures ───────────────────────────────────────────────────────────────

for (const line of [
  '/^https?:\\/\\/example\\.com\\/a\\/(\\d+)$/ reqHeaders://x-id=$1',
  '/^https?:\\/\\/example\\.com\\/a\\/(\\d+)$/ file:///srv/$1.json',
  '/^https?:\\/\\/example\\.com\\/(a)\\/(\\d+)$/ reqHeaders://x=$1-$2',
  '/^https?:\\/\\/example\\.com\\/a\\/(\\d+)$/ reqHeaders://x=$0',
  '^http://*.example.com/a/** reqHeaders://x=$1-$2',
  '^http://example.com/a/* file:///srv/$1',
  'example.com/a reqHeaders://x=$1',
]) {
  for (const url of ['http://example.com/a/12', 'http://sub.example.com/a/b/c']) {
    add(line, url);
  }
}

module.exports = cases;
