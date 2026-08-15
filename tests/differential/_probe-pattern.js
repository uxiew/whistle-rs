// pattern.md's own ✅/❌ table, asked of both parsers.
//
//   node probes/pattern-md.js        (run from tests/differential)
//
// Three columns: what the page claims, what whistle answers, what we answer.
'use strict';

const { upstreamResolve, makeReq, portResolve } = require('./rules-oracle.js');

// [pattern, url, the page's claim]
const CLAIMS = [
  // 1. domain
  ['example.com', 'https://example.com/path/to?query', true],
  ['example.com', 'https://example.com:9090/path/to?query', true],
  ['example.com:8080', 'https://example.com:8080/path/to?query', true],
  ['example.com:8080', 'https://example.com:9090/path/to?query', false],
  ['example.com:8080', 'https://example.com/path/to?query', false],
  // 2. scheme
  ['https://example.com/path/to', 'https://example.com/path/to', true],
  ['https://example.com/path/to', 'http://example.com/path/to', false],
  ['//example.com/path/to', 'http://example.com/path/to', true],
  ['//example.com/path/to', 'https://example.com/path/to', true],
  // 3.1 path prefix on a `/` boundary
  ['https://example.com/path/to', 'https://example.com/path/to/xxx?query', true],
  ['https://example.com/path/to', 'https://example.com/path/toxxx', false],
  // 3.2 with a query: path exact, query a prefix
  ['https://example.com/path/to?xxx', 'https://example.com/path/to?xxx', true],
  ['https://example.com/path/to?xxx', 'https://example.com/path/to?xxxyyy&zzzzz', true],
  ['https://example.com/path/to?xxx', 'https://example.com/path/to/yyy?xxx', false],
  // 4. `$` — path exact, query free
  ['$https://example.com/path/to', 'https://example.com/path/to', true],
  ['$https://example.com/path/to', 'https://example.com/path/to?query', true],
  ['$https://example.com/path/to', 'https://example.com/path/to/xxx', false],
  ['$https://example.com/path/to?query', 'https://example.com/path/to?query', true],
  ['$https://example.com/path/to?query', 'https://example.com/path/to?query=1', false],
  ['$https://example.com/path/to?query', 'https://example.com/path/to', false],
  ['$example.com/path/to', 'http://example.com/path/to', true],
  ['$example.com/path/to', 'https://example.com/path/to/xxx', false],
  // 5. domain wildcards
  ['https://*.example.com/path/to', 'https://www.example.com/path/to', true],
  ['https://*.example.com/path/to', 'https://abc.example.com/path/to/xxx?query', true],
  ['https://*.example.com/path/to', 'https://a.b.example.com/path/to', false],
  ['https://**.example.com:8*/path/to', 'https://foo-bar.example.com:8080/path/to', true],
  ['https://**.example.com:8*/path/to', 'https://a.b.example.com:8888/path/to', true],
  // wildcard § 1 — the same in a `^` pattern
  ['^wss://*.example.com/path/to', 'wss://a.example.com/path/to', true],
  ['^wss://*.example.com/path/to', 'wss://b.example.com/path/to/xxx?query', true],
  ['^wss://*.example.com/path/to', 'wss://a.example.com/path/toxxx', false],
  ['^wss://*.example.com/path/to', 'wss://a.b.example.com/path/to', false],
  // wildcard § 2 — path
  ['^https://example.com/path/to/a*b', 'https://example.com/path/to/axxxb/y?query', true],
  ['^https://example.com/path/to/a*b', 'https://example.com/path/to/a/b', false],
  ['^https://example.com/path/to/a**b', 'https://example.com/path/to/axxxb/y?query', true],
  ['^https://example.com/path/to/a**b', 'https://example.com/path/to/a/b', true],
  ['^https://example.com/path/to/a**b', 'https://example.com/path/to/a/xxxx?query=b', false],
  ['^https://example.com/path/to/a***b', 'https://example.com/path/to/axxxb/y?query', true],
  ['^https://example.com/path/to/a***b', 'https://example.com/path/to/a/b', true],
  ['^https://example.com/path/to/a***b', 'https://example.com/path/to/a/xxxx?query=b', true],
  // wildcard § 3 — query
  ['^https://example.com/path/to?query=a*b', 'https://example.com/path/to?query=ab&q2=xxx', true],
  ['^https://example.com/path/to?query=a*b', 'https://example.com/path/to?query=a&q2=b', false],
  ['^https://example.com/path/to?query=a**b', 'https://example.com/path/to?query=axxxb&q2=xxx', true],
  ['^https://example.com/path/to?query=a**b', 'https://example.com/path/to?query=a&q2=b', true],
  // wildcard § 4 — no scheme
  ['^example*.com/path*/to', 'http://examplex.com/pathy/to', true],
  ['^example*.com/path*/to', 'wss://examplex.com/pathy/to', true],
  // wildcard § 5 — the trailing `$`
  ['^https://*.example.com/path/*/to$', 'https://a.example.com/path/xxx/to', true],
  ['^https://*.example.com/path/*/to$', 'https://b.example.com/path/xxx/to?query', false],
  // regexp
  ['/\\.test\\./', 'http://www.test.example.com/a', true],
  ['/key=value/i', 'http://example.com/a?KEY=VALUE', true],
  ['/key=value/', 'http://example.com/a?KEY=VALUE', false],
];

// The submatch table, asked as a value rather than a match.
const CAPTURES = [
  ['^http://*.example.com/v0/users/**', 'http://www.example.com/v0/users/alice/test.html?q=1', 'file:///User/xxx/$1/$2'],
  ['/regexp\\/(user|admin)\\/(\\d+)/', 'http://a.example.com/regexp/admin/123', 'reqHeaders://X-Type=$1&X-ID=$2'],
  ['^https://**.example.com/api/*/v*/users', 'https://a.b.example.com/api/x/v2/users', 'reqHeaders://x-api-version=$3'],
  ['/^http:\\/\\/(\\w+)\\.example\\.com\\//', 'http://www.example.com/a', 'reqHeaders://x-zero=$0&x-one=$1'],
];

function main() {
  const rows = [];
  const queries = [];
  for (const [pattern, url, claim] of CLAIMS) {
    const rules = `${pattern} reqHeaders://x-hit=1`;
    rows.push({ pattern, url, claim, rules });
    queries.push({ rules, url, method: 'GET', headers: {}, values: {} });
  }
  for (const [pattern, url, op] of CAPTURES) {
    const rules = `${pattern} ${op}`;
    rows.push({ pattern, url, claim: null, rules, capture: true });
    queries.push({ rules, url, method: 'GET', headers: {}, values: {} });
  }

  const ours = portResolve(queries);
  rows.forEach((row, i) => {
    const req = makeReq(row.url, 'GET', {}, undefined, undefined);
    const up = upstreamResolve(row.rules, {}, req, undefined);
    const upOp = up.find((op) => op.bucket === 'reqHeaders' || op.bucket === 'rule');
    const ourOp = (ours[i].ops || [])[0];
    const upValue = upOp ? (upOp.value || upOp.url || upOp.matcher || '') : null;
    const ourValue = ourOp ? (ourOp.value || ourOp.raw || '') : null;
    row.up = upValue;
    row.ours = ourValue;
  });

  let bad = 0;
  for (const row of rows) {
    const upHit = row.up != null;
    const ourHit = row.ours != null;
    const disagree = row.capture ? row.up !== row.ours : upHit !== ourHit;
    const docWrong = !row.capture && row.claim !== upHit;
    if (!disagree && !docWrong) continue;
    bad++;
    const what = disagree ? (docWrong ? 'BOTH' : 'PORT') : 'DOC ';
    console.log(`${what}  ${row.pattern}\n        url:      ${row.url}`);
    if (!row.capture) console.log(`        page:     ${row.claim ? 'match' : 'no match'}`);
    console.log(`        whistle:  ${row.up == null ? '(no match)' : JSON.stringify(row.up)}`);
    console.log(`        rs:       ${row.ours == null ? '(no match)' : JSON.stringify(row.ours)}`);
  }
  console.log(`\n${rows.length} claims, ${bad} to look at`);
  process.exit(0);
}

main();
