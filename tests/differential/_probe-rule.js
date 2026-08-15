// rule.md's syntax claims, asked of both parsers.
'use strict';
const { upstreamResolve, makeReq, portResolve } = require('./rules-oracle.js');

const CASES = [
  // 1. several operations on one line
  ['www.example.com/* cache://3600 resCors://* reqHeaders://x-a=1', 'http://www.example.com/p'],
  // 2. position swap, several patterns
  ['proxy://127.0.0.1:8080 www.example.com api.example.com', 'http://api.example.com/p'],
  ['proxy://127.0.0.1:8080 www.example.com api.example.com', 'http://www.example.com/p'],
  ['reqHeaders://x-a=1 www.example.com api.example.com', 'http://api.example.com/p'],
  // the restriction: both sides URL/domain-shaped, so no swap
  ['https://test.com/path www.example.com', 'http://www.example.com/p'],
  ['//test.com/path www.example.com', 'http://www.example.com/p'],
  ['test.com/path www.example.com', 'http://www.example.com/p'],
  ['test.com www.example.com', 'http://www.example.com/p'],
  // 3. the line` block
  ['line`\nproxy://127.0.0.1:8080\nwww.example.com\napi.example.com\nincludeFilter://m:GET\n`', 'http://api.example.com/p'],
  ['line`\nproxy://127.0.0.1:8080\nwww.example.com\napi.example.com\nincludeFilter://m:POST\n`', 'http://api.example.com/p'],
  ['line`\nreqHeaders://x-a=1\nwww.example.com\n`\nwww.example.com reqHeaders://x-b=2', 'http://www.example.com/p'],
  // a line` block that is never closed
  ['line`\nreqHeaders://x-a=1\nwww.example.com', 'http://www.example.com/p'],
  // 4. comments
  ['# www.example.com reqHeaders://x-a=1', 'http://www.example.com/p'],
  ['www.example.com reqHeaders://x-a=1 # trailing', 'http://www.example.com/p'],
  // 5. important
  ['www.example.com reqHeaders://x-a=first\nwww.example.com reqHeaders://x-a=second lineProps://important', 'http://www.example.com/p'],
  // @: a home-relative include (neither side has the file — both should report nothing)
  ['@~/no-such-whistle-rules.txt', 'http://www.example.com/p'],
];

const queries = CASES.map(([rules, url]) => ({ rules, url, method: 'GET', headers: {}, values: {} }));
const ours = portResolve(queries);
let bad = 0;
CASES.forEach(([rules, url], i) => {
  const up = upstreamResolve(rules, {}, makeReq(url, 'GET', {}, undefined, undefined), undefined);
  const left = up
    .map((op) => `${op.bucket}=${op.value || op.url || op.matcher || ''}`)
    .sort()
    .join(' ');
  const right = (ours[i].ops || [])
    .map((op) => `${op.protocol}=${op.value}`)
    .sort()
    .join(' ');
  // The two spell a matcher differently (whistle keeps the scheme on it), so
  // compare on what each *holds*, not on how it prints.
  const norm = (s) => s.replace(/=(?:[a-z0-9]+:\/\/)?/g, '=').replace(/\s+/g, ' ');
  if (norm(left) === norm(right)) return;
  bad++;
  console.log(`— ${JSON.stringify(rules)}\n  url:     ${url}\n  whistle: ${left || '(nothing)'}\n  rs:      ${right || '(nothing)'}`);
});
console.log(`\n${CASES.length} lines, ${bad} to look at`);
process.exit(0);
