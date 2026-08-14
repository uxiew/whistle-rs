// Why does this case prove nothing?
//
//   PORT_BASE=19500 CASES=./cases-bodies.js npm run bench \
//     | node triage-inert.js ./cases-bodies.js
//
// `harness.js` reports `inert` — the cases whose answer is the same with no
// rules loaded at all. The number says how much of a corpus is not testing
// anything; it does not say *why*, and the two reasons are opposite:
//
//   * **the rule matched and did nothing.** `jsAppend://` on a CSS response is
//     supposed to do nothing, and a case that checks it says so by being inert.
//     A reason like that is the case working;
//   * **the rule never matched.** Then the case is broken, and it has been
//     passing in the shape of a rule that fires and does nothing — which is the
//     shape a *missing feature* has too. Four classes of these were found by
//     hand last round; this asks the question mechanically.
//
// It answers it by resolving each inert case's rules against its own request —
// through `rules-oracle.js`'s machinery, so the answer is the resolver's — and
// reporting which of the two it is.

'use strict';

const path = require('path');
const { portResolve } = require('./rules-oracle.js');

function readBenchJson(text) {
  // The bench prints progress lines and then one JSON object.
  const start = text.indexOf('\n{');
  if (start === -1) throw new Error('no bench JSON on stdin');
  return JSON.parse(text.slice(start + 1));
}

function main(text) {
  const corpusPath = process.argv[2];
  if (!corpusPath) {
    console.error('usage: … | node triage-inert.js ./cases-x.js');
    return 2;
  }
  const report = readBenchJson(text);
  const inert = new Set(report.inertCases || []);
  if (!inert.size) {
    console.log(`${path.basename(corpusPath)}: nothing inert`);
    return 0;
  }

  const base = Number(process.env.PORT_BASE || 18700);
  const origin = base + 2;
  const cases = require(corpusPath).filter((c) => inert.has(c.name));
  const queries = cases.map((c) => {
    const request = c.request || {};
    const groups = (c.groups || [])
      .filter((g) => g.selected !== false)
      .map((g) => g.value || '');
    const text = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
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

  // A case with no rules at all is a **baseline** — it asks what the origin
  // does, and being inert is the whole of what it claims. A text that is only
  // comments is the same thing said out loud.
  const noRules = (text) =>
    !text
      .split('\n')
      .map((line) => line.replace(/#.*/, '').trim())
      .filter(Boolean).length;
  const baselines = queries.filter((q) => noRules(q.rules)).length;

  const answers = portResolve(queries);
  const dead = [];
  const alive = new Map();
  answers.forEach((answer, i) => {
    if (noRules(queries[i].rules)) return;
    const ops = (answer.ops || []).filter((op) => op.protocol !== 'lineProps');
    if (!ops.length) {
      dead.push({
        name: cases[i].name,
        rules: queries[i].rules,
        url: queries[i].url,
        declared: cases[i].inert === true,
      });
    } else {
      const key = ops.map((op) => op.protocol).sort().join('+');
      alive.set(key, (alive.get(key) || 0) + 1);
    }
  });

  // The other direction: a case that declares itself inert and turns out to
  // discriminate is a marker that has gone stale, and the corpus is claiming
  // less than it proves.
  const stale = require(corpusPath)
    .filter((c) => c.inert === true && !inert.has(c.name))
    .map((c) => c.name);

  console.log(`\n${path.basename(corpusPath)}: ${inert.size} inert`);
  if (stale.length) {
    console.log(`  declared inert but discriminating (stale marker): ${stale.length}`);
    for (const name of stale) console.log(`      ${name}`);
  }
  console.log(`  baselines, which carry no rules: ${baselines}`);
  console.log(`  matched and did nothing: ${inert.size - dead.length - baselines}`);
  for (const [key, n] of [...alive.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`      ${String(n).padStart(3)}  ${key}`);
  }
  // "Never matched" splits again, and only one half is a problem. A line
  // carrying a filter, an `ignore://`, a `skip://`, an `internalOnly` or a
  // negated pattern is often *about* not matching — that case is working. A
  // line carrying none of those meant to fire and did not, which is the shape
  // the four broken classes found by hand last round had.
  const SUPPRESSES =
    /(?:include|exclude)?[Ff]ilter:\/\/|\bignore:\/\/|\bskip:\/\/|internalOnly|^\s*!/m;
  // An `@` line is a source of rules, not a rule: a case made only of them is
  // asking whether the source is read at all, and "no rule resolved" is one of
  // the two answers it is written to tell apart.
  const onlyIncludes = (text) =>
    text
      .split('\n')
      .map((line) => line.replace(/#.*/, '').trim())
      .filter(Boolean)
      .every((line) => line.startsWith('@'));
  const byLine = dead.filter((c) => SUPPRESSES.test(c.rules) || onlyIncludes(c.rules));
  // A case can also be *about* not matching without the line saying so — a
  // pattern that should miss, a spelling that is not an include. Those say it
  // by carrying `inert: true`, which is a claim the corpus makes rather than a
  // guess this tool makes from a name.
  const declared = dead.filter((c) => !byLine.includes(c) && c.declared);
  const unexplained = dead.filter((c) => !byLine.includes(c) && !c.declared);

  console.log(`  never matched, and the line says why: ${byLine.length}`);
  console.log(`  never matched, and the case says so (inert: true): ${declared.length}`);
  for (const c of declared) console.log(`      ${c.name}`);
  console.log(`  never matched, with nothing to explain it: ${unexplained.length}`);
  for (const c of unexplained) {
    console.log(`      ${c.name}`);
    console.log(`         rules: ${c.rules.replace(/\n/g, ' | ')}`);
    console.log(`         url:   ${c.url}`);
  }
  return unexplained.length || stale.length ? 1 : 0;
}

let input = '';
process.stdin.on('data', (chunk) => (input += chunk));
process.stdin.on('end', () => process.exit(main(input)));
