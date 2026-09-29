#!/usr/bin/env node
// Two runs of the bench against two whistle releases, compared case by case.
//
//   node run.js all                       # the baseline, 2.10.8
//   node run.js all --whistle 2.10.10     # the same, against 2.10.10
//   node matrix.js target/differential/<a> target/differential/<b> [--json FILE]
//
// What it answers: **which of whistle's answers moved between the two
// releases**, and whether each move brought upstream closer to whistle-rs or
// further from it. It is the question a single run cannot ask — every number
// in this directory is agreement with one release — and it is asked by case
// and field, not by count: two runs that both report three differences are not
// thereby the same three.
//
// It compares every difference **before** any declaration excused it (the
// `raw` each bench prints next to its verdict). Declarations are a verdict
// about this port and are scoped to a version (`whistle-pkg.js`); what moved
// between releases is the measurement those verdicts are made on.
//
// Both runs have to be of the same whistle-rs binary, or a move could be this
// port's and not upstream's. It says so, and exits 2, when the manifests'
// SHA-256 disagree. Same for the port block: several answers carry a port.
//
// Each (step, case, field) lands in one of:
//   same        differs in both runs, with the same text
//   closer      differed against A, agrees against B — upstream moved to this port
//   away        agreed against A, differs against B — upstream moved away, or
//               B has something new
//   changed     differs in both, but upstream's answer is not the same one
// and the steps whose output cannot be broken down by case are compared on
// their summary line.

'use strict';

const fs = require('fs');
const path = require('path');
const { fieldOf } = require('./declared.js');

const argv = process.argv.slice(2);
const jsonAt = argv.indexOf('--json');
const JSON_OUT = jsonAt === -1 ? null : argv[jsonAt + 1];
const dirs = argv.filter((a, i) => !a.startsWith('--') && (jsonAt === -1 || i !== jsonAt + 1));
if (dirs.length !== 2) {
  console.error('usage: node matrix.js <archive-a> <archive-b> [--json FILE]');
  process.exit(2);
}

/** Read one archive: its manifest and, per step, what each case differed in. */
function load(dir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const steps = new Map();
  for (const step of manifest.steps) steps.set(step.name, { ...observe(dir, step.name), passed: step.passed });
  return { dir, manifest, steps };
}

/**
 * One step's differences as `Map<case, Map<field, text>>`, or `{ summary }`
 * for a step whose output says no more than a line.
 */
function observe(dir, name) {
  const out = readMaybe(path.join(dir, 'steps', `${name}.out`)) || '';
  const suiteJson = readMaybe(path.join(dir, 'steps', `${name}.json`));
  if (suiteJson) return fromSuite(JSON.parse(suiteJson));
  let json = null;
  try { json = JSON.parse(out); } catch {}
  if (json) return fromJson(json);
  if (/^\s*(ok|DIFF|DECL)\s{2,}/m.test(out)) return fromProse(out);
  const line = out.trim().split('\n').reverse().find((l) => /questions:|probes|differing/.test(l));
  return { summary: line ? line.trim() : '(no output)' };
}

function readMaybe(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

function add(cases, name, problem) {
  if (!cases.has(name)) cases.set(name, new Map());
  const fields = cases.get(name);
  const field = fieldOf(problem);
  // A field that differs twice in one case (a header sent twice) keeps both.
  fields.set(field, fields.has(field) && fields.get(field) !== problem ? `${fields.get(field)} | ${problem}` : problem);
}

/** A JSON bench: its `raw` when it prints one, and whatever else it reported. */
function fromJson(j) {
  const cases = new Map();
  const items = [...(j.raw || []), ...(j.report || []), ...(j.excused || [])];
  for (const it of items) {
    const name = it.name || it.mode || (it.group !== undefined ? `${it.group} ${it.text}` : '?');
    const problems = it.problems
      || (it.why ? [`qr: whistle=- rs=${it.why}`] : [`answer: whistle=${JSON.stringify(it.whistle)} rs=${JSON.stringify(it.rs)}`]);
    for (const p of problems) add(cases, name, p);
  }
  return { cases };
}

/**
 * `upstream-suite.js`'s verdict: which calls were judged (upstream passes them
 * with and without the network) and which of those whistle-rs does not pass. A
 * call judged in one release and not the other is upstream's own answer moving.
 */
function fromSuite(v) {
  const cases = new Map();
  for (const key of v.judgedKeys || []) add(cases, key, 'judged: whistle=pass rs=?');
  for (const row of [...(v.failed || []), ...(v.declared || [])]) add(cases, row.key, `rs: whistle=pass rs=${row.state}`);
  return { cases, judged: (v.judgedKeys || []).length };
}

/** A prose bench (`forwarded`, `header-rules`): every probe, agreed or not. */
function fromProse(out) {
  const cases = new Map();
  let section = '';
  const lines = out.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const head = /^## (.*)$/.exec(lines[i]);
    if (head) { section = head[1]; continue; }
    const m = /^\s*(ok|DIFF|DECL)\s{2,}(.*)$/.exec(lines[i]);
    if (!m) continue;
    const name = section ? `${section} / ${m[2]}` : m[2];
    if (m[1] === 'ok') {
      // Agreement is recorded as well: a probe both proxies answered the same
      // way in one release and not in the other is exactly a move.
      add(cases, name, `agreed: whistle=${(lines[i + 1] || '').trim()} rs=same`);
    } else {
      const w = (/whistle: (.*)$/.exec(lines[i + 1] || '') || [])[1];
      const r = (/rs: (.*)$/.exec(lines[i + 2] || '') || [])[1];
      add(cases, name, `answer: whistle=${w} rs=${r}`);
    }
  }
  return { cases, prose: true };
}

/** The whistle half of a problem's text, for telling which side moved. */
function sides(problem) {
  const m = /: whistle=([\s\S]*?) rs=([\s\S]*)$/.exec(problem);
  return m ? { w: m[1], rs: m[2] } : { w: problem, rs: '' };
}

function compare(a, b) {
  const out = { steps: [] };
  const names = [...new Set([...a.steps.keys(), ...b.steps.keys()])];
  for (const name of names) {
    const x = a.steps.get(name);
    const y = b.steps.get(name);
    if (!x || !y) {
      out.steps.push({ name, note: `run only against ${x ? a.version : b.version}` });
      continue;
    }
    if (x.summary !== undefined || y.summary !== undefined) {
      out.steps.push({ name, summary: [x.summary, y.summary], same: x.summary === y.summary });
      continue;
    }
    const row = { name, same: 0, closer: [], away: [], changed: [], rsMoved: [] };
    const caseNames = new Set([...x.cases.keys(), ...y.cases.keys()]);
    for (const c of caseNames) {
      const fx = x.cases.get(c) || new Map();
      const fy = y.cases.get(c) || new Map();
      for (const f of new Set([...fx.keys(), ...fy.keys()])) {
        const [p, q] = [fx.get(f), fy.get(f)];
        if (p === q) { row.same++; continue; }
        const item = { case: c, field: f, [a.version]: p || null, [b.version]: q || null };
        if (p && !q) row.closer.push(item);
        else if (!p && q) row.away.push(item);
        else if (sides(p).w === sides(q).w) row.rsMoved.push(item);
        else row.changed.push(item);
      }
    }
    out.steps.push(row);
  }
  return out;
}

function main() {
  const [a, b] = dirs.map((d) => load(path.resolve(d)));
  for (const r of [a, b]) r.version = r.manifest.whistle.version;
  const problems = [];
  if (a.manifest.whistleRs.sha256 !== b.manifest.whistleRs.sha256) {
    problems.push(`whistle-rs differs: ${a.manifest.whistleRs.sha256.slice(0, 12)} vs ${b.manifest.whistleRs.sha256.slice(0, 12)}`);
  }
  if (a.manifest.portBase !== b.manifest.portBase) {
    problems.push(`port block differs: ${a.manifest.portBase} vs ${b.manifest.portBase}`);
  }
  if (a.version === b.version) problems.push(`both runs are of whistle ${a.version}`);

  const result = compare(a, b);
  result.a = { dir: a.dir, whistle: a.version, commit: a.manifest.git.commit, node: a.manifest.host.node };
  result.b = { dir: b.dir, whistle: b.version, commit: b.manifest.git.commit, node: b.manifest.host.node };
  result.whistleRs = a.manifest.whistleRs.sha256;

  console.log(`whistle ${a.version} → ${b.version}, whistle-rs ${String(result.whistleRs).slice(0, 12)}`);
  for (const p of problems) console.log(`  NOT COMPARABLE: ${p}`);
  const show = (label, items) => {
    for (const it of items) {
      console.log(`    ${label.padEnd(8)} ${it.case} — ${it.field}`);
      console.log(`             ${a.version}: ${it[a.version] ?? '(agreed)'}`);
      console.log(`             ${b.version}: ${it[b.version] ?? '(agreed)'}`);
    }
  };
  for (const s of result.steps) {
    if (s.note) { console.log(`  ${s.name}: ${s.note}`); continue; }
    if (s.summary) {
      console.log(`  ${s.name}: ${s.same ? 'same summary' : 'SUMMARY MOVED'}${s.same ? '' : `\n    ${a.version}: ${s.summary[0]}\n    ${b.version}: ${s.summary[1]}`}`);
      continue;
    }
    const moved = s.closer.length + s.away.length + s.changed.length + s.rsMoved.length;
    console.log(`  ${s.name}: ${s.same} same, ${s.closer.length} closer, ${s.away.length} away, ${s.changed.length} changed${s.rsMoved.length ? `, ${s.rsMoved.length} where whistle-rs's side moved` : ''}`);
    if (moved) {
      show('closer', s.closer);
      show('away', s.away);
      show('changed', s.changed);
      show('rs-side', s.rsMoved);
    }
  }
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(result, null, 2) + '\n');
  process.exit(problems.length ? 2 : 0);
}

main();
