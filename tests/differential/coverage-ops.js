// Which operators does the bench actually prove anything about?
//
//   PORT_BASE=19500 node coverage-ops.js
//
// `every_documented_rule_has_a_differential_case` (a Rust test) says every
// documented rule name appears in a corpus. That is a weak claim and says so:
// a case exists, not that the case has any force. This asks the stronger
// question, and it is the same one `triage-inert.js` asks per case, turned
// around:
//
//   for each operator, is there at least one case that **resolves it** and
//   whose answer would change if the rule were removed?
//
// The set of operators comes from this port's own registry, so a protocol
// nobody wrote a case for cannot hide by being forgotten here too.
//
// It runs each corpus's bench, so it needs what the bench needs — two proxies
// and an origin — and takes a few minutes.

'use strict';

const path = require('path');
const { execFileSync } = require('child_process');
const { portResolve } = require('./rules-oracle.js');

const CORPORA = [
  'cases.js', 'cases-lineprops.js', 'cases-file.js', 'cases-filters.js',
  'cases-patterns.js', 'cases-bodies.js', 'cases-delete.js', 'cases-compose.js',
  'cases-values.js', 'cases-includes.js', 'cases-flags.js', 'cases-groups.js',
  'cases-docs.js', 'cases-proxy.js',
];

// Operators these corpora cannot prove anything about, each with where it is
// proved instead. A dump goes to disk, a cipher needs a TLS hop, a frame needs
// a WebSocket, a plugin needs a plugin.
const ELSEWHERE = {
  reqWrite: 'write-bench.js', resWrite: 'write-bench.js',
  reqWriteRaw: 'write-bench.js', resWriteRaw: 'write-bench.js',
  cipher: 'https-bench.js', sniCallback: 'https-bench.js',
  reqDelay: 'timing-bench.js', resDelay: 'timing-bench.js',
  reqSpeed: 'timing-bench.js', resSpeed: 'timing-bench.js',
  // The harness speaks HTTP only, and installs no plugins into either proxy.
  frameScript: 'proxy::ws tests, over real frames',
  plugin: 'plugins tests and examples/plugins; whistle has none of this port\'s',
  pipe: 'plugins tests — it selects a plugin\'s streaming hook',
};

// Operators with no traffic effect by design — this port's Non-goals.
const NO_EFFECT = new Set(['G', 'style', 'weinre', 'log', 'lineProps']);

// A synchronous pause, for the one thing that needs it: the port a bench binds
// is the port the previous bench has just let go of.
function pause(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function benchInert(corpus, attempt = 0) {
  let out;
  try {
    out = execFileSync('node', ['harness.js'], {
      cwd: __dirname,
      env: Object.assign({}, process.env, { CASES: './' + corpus }),
      maxBuffer: 1 << 28,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
  } catch (e) {
    const stderr = (e.stderr || '').toString();
    if (attempt < 2 && /EADDRINUSE/.test(stderr)) {
      pause(1500);
      return benchInert(corpus, attempt + 1);
    }
    const why = stderr.split('\n').find((l) => /Error|error/.test(l));
    throw new Error(`${corpus}: the bench did not finish — ${why || e.message}`);
  }
  // The bench prints its progress to stderr and its report to stdout, so the
  // report may be the whole of it — `indexOf('\n{')` misses a report that
  // starts at the first byte.
  const start = out.search(/^\{/m);
  if (start === -1) throw new Error(`${corpus}: no bench JSON`);
  const report = JSON.parse(out.slice(start));
  return new Set(report.inertCases || []);
}

// A corpus is read in a **child**, never here: two of them stand up servers at
// require time (`cases-includes.js` serves rules at `PORT_BASE+10`, and
// `forward-servers.js` — which `cases-proxy.js` pulls in — records proxied
// requests on the same port). Requiring them in this process would take the
// port the next bench needs, and the bench would fail with `EADDRINUSE` for a
// reason nothing in it could explain.
function readCases(corpus) {
  const json = execFileSync(
    'node',
    ['-e', `process.stdout.write(JSON.stringify(require('./${corpus}')))`],
    { cwd: __dirname, env: process.env, maxBuffer: 1 << 28 }
  ).toString();
  return JSON.parse(json);
}

function main() {
  const base = Number(process.env.PORT_BASE || 18700);
  const origin = base + 2;
  const proves = new Map();   // protocol -> cases that resolve it and are not inert
  const mentions = new Map(); // protocol -> cases that resolve it at all

  for (const corpus of CORPORA) {
    const inert = benchInert(corpus);
    const cases = readCases(corpus);
    const text = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
    const queries = cases.map((c) => {
      const request = c.request || {};
      const groups = (c.groups || [])
        .filter((g) => g.selected !== false)
        .map((g) => g.value || '');
      const headers = {};
      for (const [k, v] of Object.entries(request.headers || {})) headers[k] = text(v);
      const values = {};
      for (const [k, v] of Object.entries(c.values || {})) values[k] = text(v);
      return {
        rules: [c.rules || '', ...groups].filter(Boolean).join('\n'),
        url: request.url || `http://127.0.0.1:${origin}${request.path || '/echo'}`,
        method: request.method || 'GET',
        headers,
        body: request.body == null ? undefined : text(request.body),
        values,
      };
    });
    const answers = portResolve(queries);
    answers.forEach((answer, i) => {
      const name = `${corpus}: ${cases[i].name}`;
      for (const op of answer.ops || []) {
        const bucket = mentions.get(op.protocol) || [];
        bucket.push(name);
        mentions.set(op.protocol, bucket);
        if (!inert.has(cases[i].name)) {
          const strong = proves.get(op.protocol) || [];
          strong.push(name);
          proves.set(op.protocol, strong);
        }
      }
    });
    process.stderr.write(`  ${corpus}: ${cases.length} cases, ${inert.size} inert\n`);
  }

  // The universe is not "what the corpora happened to resolve" — that would let
  // an operator nobody wrote a case for pass by being absent twice. It is every
  // spelling in `operators.js`, resolved once through this port to learn which
  // key each lands under, plus whatever the corpora resolved and the names the
  // other benches carry.
  const registry = portResolve(
    require('./operators.js').map((op) => ({
      rules: `example.com ${op}`,
      url: 'http://example.com/a',
    }))
  ).flatMap((answer) => (answer.ops || []).map((op) => op.protocol));
  const names = [
    ...new Set([...registry, ...mentions.keys(), ...Object.keys(ELSEWHERE)]),
  ].sort();
  const unproved = [];
  for (const name of names) {
    if (NO_EFFECT.has(name)) continue;
    const strong = (proves.get(name) || []).length;
    if (strong) continue;
    unproved.push({
      name,
      mentions: (mentions.get(name) || []).length,
      elsewhere: ELSEWHERE[name],
      unseen: !mentions.has(name),
    });
  }

  console.log(`\noperators resolved by some case: ${names.length}`);
  console.log(`  proved by at least one case that is not inert: ${names.length - unproved.length}`);
  console.log(`  resolved but never proved: ${unproved.length}`);
  for (const op of unproved) {
    const where = op.elsewhere ? ` (its own bench: ${op.elsewhere})` : '';
    const what = op.unseen ? 'no case resolves it' : `${op.mentions} inert case(s)`;
    console.log(`      ${op.name}: ${what}${where}`);
  }
  return unproved.filter((op) => !op.elsewhere).length ? 1 : 0;
}

process.exit(main());
