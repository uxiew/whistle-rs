// http.md / https.md / ws.md / wss.md / tunnel.md — what the destination
// becomes, asked of both parsers.
'use strict';
const { upstreamResolve, makeReq, portResolve } = require('./rules-oracle.js');

const CASES = [
  // http:// on each request kind
  ['http://www.example.com/path1 http://www.test.com/path/xxx', 'http://www.example.com/path1'],
  ['http://www.example.com/path1 http://www.test.com/path/xxx', 'http://www.example.com/path1/a/b/c?query'],
  ['https://www.example.com/path2 http://www.abc.com/path3/yyy', 'https://www.example.com/path2/a/b/c?query'],
  ['ws://www.example.com/path1 http://www.test.com/path/xxx', 'ws://www.example.com/path1'],
  ['wss://www.example.com/path2 http://www.abc.com/path3/yyy', 'wss://www.example.com/path2/a/b/c?query'],
  ['tunnel://www.example.com:443 http://www.test.com:123', 'tunnel://www.example.com:443'],
  ['tunnel://www.example2.com:443 http://www.test2.com/path', 'tunnel://www.example2.com:443'],
  // https:// on each request kind
  ['http://www.example.com/path1 https://www.test.com/path/xxx', 'http://www.example.com/path1/a/b/c?query'],
  ['ws://www.example.com/path1 https://www.test.com/path/xxx', 'ws://www.example.com/path1'],
  ['wss://www.example.com/path2 https://www.abc.com/path3/yyy', 'wss://www.example.com/path2/a/b/c?query'],
  ['tunnel://www.example.com:443 https://www.test.com:123', 'tunnel://www.example.com:443'],
  ['tunnel://www.example2.com:443 https://www.test2.com/path', 'tunnel://www.example2.com:443'],
  // ws:// and wss:// as destinations
  ['ws://www.example.com/path1 ws://www.test.com/path', 'ws://www.example.com/path1/a?q=1'],
  ['http://www.example.com/p ws://www.test.com/path', 'http://www.example.com/p'],
  ['http://www.example.com/p wss://www.test.com/path', 'http://www.example.com/p'],
  ['tunnel://www.example.com:443 tunnel://www.test.com:8443', 'tunnel://www.example.com:443'],
  ['http://www.example.com/p tunnel://www.test.com:8443', 'http://www.example.com/p'],
  // path joining disabled, both spellings
  ['www.example.com/path1 http://<www.test.com/path/xxx>', 'http://www.example.com/path1/x/y/z'],
  ['www.example.com/path1 http://(www.test.com/path/xxx)', 'http://www.example.com/path1/x/y/z'],
  ['www.example.com/path1 https://<www.test.com/path/xxx>', 'wss://www.example.com/path1/x/y/z'],
  // a destination with no path at all
  ['www.example.com/path1 http://www.test.com', 'http://www.example.com/path1/x/y?q=1'],
  ['www.example.com http://www.test.com:8080', 'http://www.example.com/a/b?q=1'],
];

const queries = CASES.map(([rules, url]) => ({ rules, url, method: 'GET', headers: {}, values: {} }));
const ours = portResolve(queries);
let bad = 0;
CASES.forEach(([rules, url], i) => {
  const up = upstreamResolve(rules, {}, makeReq(url, 'GET', {}, undefined, undefined), undefined);
  const slot = up.find((op) => op.bucket === 'rule');
  const left = slot ? slot.url || slot.matcher : null;
  const ourOp = (ours[i].ops || []).find((op) => op.slot);
  const right = ourOp ? ourOp.value : null;
  const norm = (s) => (s == null ? '(nothing)' : s.replace(/^[a-z]+:\/\//, ''));
  if (norm(left) === norm(right)) return;
  bad++;
  console.log(`— ${rules}\n  url:     ${url}\n  whistle: ${left ?? '(nothing)'}\n  rs:      ${right ?? '(nothing)'}`);
});
console.log(`\n${CASES.length} destinations, ${bad} to look at`);
process.exit(0);
