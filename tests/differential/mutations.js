#!/usr/bin/env node
// Does the gate catch a regression? Put one in and find out.
//
//   node mutations.js              every preset mutation
//   node mutations.js --only a,b   some of them
//   node mutations.js --list
//
// Each mutation below is a small, plausible semantic regression — the kind a
// refactor makes by accident — written as one exact text replacement in one
// source file, together with the gate that is supposed to catch it. For each,
// this builds whistle-rs with the mutation in and runs that gate (`run.js`,
// restricted to the named steps). The gate must **fail**. A mutation it passes
// has *survived*: the gate is blind to that regression, and that is a finding
// about the gate.
//
// Before any mutation, the same gates are run on the unmutated build and must
// pass — otherwise a gate that fails on everything would "catch" every one.
//
// Nothing here touches your working tree. The mutations go into a scratch git
// worktree of HEAD (so uncommitted changes are not measured — commit first),
// built into target/mutations so incremental builds are reused between runs.
// The worktree is removed at the end, or when interrupted.
//
// Exit 0: baseline passed and every mutation was caught. 1: something survived
// or the baseline failed. 2: a mutation no longer applies — the text it replaces
// has changed, and the mutation has to be rewritten to still mean something.

const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..', '..');
const TARGET = path.join(REPO, 'target', 'mutations');

const MUTATIONS = [
  {
    name: 'important-loses-priority',
    file: 'src/rules/matcher.rs',
    from: 'for pass_important in [true, false] {',
    to: 'for pass_important in [false, true] {',
    why: '`$`/lineProps://important lines no longer win over normal ones',
    suite: 'fast',
    only: ['oracle-docs', 'oracle-cases'],
  },
  {
    name: 'value-gains-a-space',
    file: 'src/proxy/apply/substitute.rs',
    from: '(false, _) => content.clone(),',
    to: '(false, _) => format!("{content} "),',
    why: 'every {name} a values entry answers comes back with a trailing space',
    suite: 'fast',
    only: ['oracle-cases'],
  },
  {
    name: 'capture-off-by-one',
    file: 'src/rules/replace.rs',
    from: 'let group = |n: usize| groups.get(n).copied().unwrap_or("");',
    to: 'let group = |n: usize| groups.get(n + 1).copied().unwrap_or("");',
    why: '$1 in a value expands to the second capture group, $0 to the first',
    suite: 'network',
    only: ['cases', 'cases-patterns'],
  },
  {
    // In `apply_response_for`, which sets the status the client finally sees.
    // The first version of this mutated the same parse in `short_circuit` and
    // survived — correctly: `apply_response_for` re-reads the operator and
    // overwrites that status, so the change was invisible. An equivalent
    // mutant, not a blind gate.
    name: 'mocked-status-off-by-one',
    file: 'src/proxy/apply/res_ops.rs',
    from: '.and_then(|c| StatusCode::from_u16(c).ok())\n        // `replaceStatus != _res.statusCode`',
    to: '.and_then(|c| StatusCode::from_u16(c + 1).ok())\n        // `replaceStatus != _res.statusCode`',
    why: 'statusCode://404 answers 405 — resolution is unchanged, only the effect',
    suite: 'network',
    only: ['cases'],
  },
  {
    name: 'qr-mask-6-inverted',
    file: 'src/qr.rs',
    from: '6 => ((i * j) % 2 + (i * j) % 3) % 2 == 0,',
    to: '6 => ((i * j) % 2 + (i * j) % 3) % 2 == 1,',
    why: 'mask pattern 6 inverts the wrong modules; symbols using it no longer match',
    suite: 'fast',
    only: ['qr'],
  },
];

const argv = process.argv.slice(2);
const optOnly = (() => {
  const i = argv.indexOf('--only');
  return i === -1 ? null : new Set(argv[i + 1].split(','));
})();
let chosen = optOnly ? MUTATIONS.filter((m) => optOnly.has(m.name)) : MUTATIONS;
if (argv.includes('--list')) {
  for (const m of MUTATIONS) console.log(`${m.name.padEnd(28)} ${m.suite}:${m.only.join(',').padEnd(26)} ${m.why}`);
  process.exit(0);
}
if (optOnly && chosen.length !== optOnly.size) {
  console.error(`unknown mutation(s): ${[...optOnly].filter((n) => !MUTATIONS.some((m) => m.name === n)).join(', ')}`);
  process.exit(2);
}

const git = (...args) => execFileSync('git', args, { cwd: REPO, encoding: 'utf8' }).trim();

if (git('status', '--porcelain', '--', 'src', 'Cargo.toml', 'Cargo.lock', 'tests/differential')) {
  console.error('note: uncommitted changes under src/ or tests/differential/ are not measured — this runs on HEAD.');
}

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-rs-mutations-'));
let added = false;
function cleanup() {
  if (added) {
    try { git('worktree', 'remove', '--force', WORK); } catch {}
    added = false;
  }
  fs.rmSync(WORK, { recursive: true, force: true });
}

// Children are started asynchronously on purpose. This used spawnSync, and a
// signal handler cannot run while spawnSync holds the event loop: Ctrl-C
// waited for the current gate, and the loop then went straight into the next
// one, so the handler never ran and the worktree stayed behind. Now a signal
// is passed to the running child — run.js cleans up its own proxies — and the
// loop stops as soon as that child has gone.
let current = null;
let interrupted = false;
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    interrupted = true;
    if (current) current.kill('SIGTERM');
  });
}

/** Run a command to completion; resolves to its exit status and the tail of stderr. */
function run(command, args, opts) {
  if (interrupted) return Promise.reject(new Error('interrupted'));
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...opts, stdio: ['ignore', 'ignore', 'pipe'] });
    current = child;
    let err = '';
    child.stderr.on('data', (d) => { err = (err + d).slice(-8000); });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      current = null;
      if (interrupted) reject(new Error('interrupted'));
      else resolve({ code: code ?? (signal ? 128 : 1), log: err });
    });
  });
}

async function build() {
  const r = await run('cargo', ['build', '--locked'], {
    cwd: WORK,
    env: { ...process.env, CARGO_TARGET_DIR: TARGET },
  });
  if (r.code !== 0) throw new Error(`cargo build failed:\n${r.log.split('\n').slice(-20).join('\n')}`);
}

/** Run a gate against the build in TARGET; resolves to run.js's exit status. */
function gate(suite, only, label) {
  return run(process.execPath, [
    path.join(WORK, 'tests', 'differential', 'run.js'), suite, '--only', only.join(','),
    '--out', path.join(TARGET, 'runs', label),
  ], {
    cwd: path.join(WORK, 'tests', 'differential'),
    env: { ...process.env, RS_BIN: path.join(TARGET, 'debug', 'whistle-rs') },
  });
}

async function main() {
  git('worktree', 'add', '--detach', WORK, 'HEAD');
  added = true;
  // The oracle's dependencies, exactly as installed here; same lockfile.
  fs.symlinkSync(path.join(HERE, 'node_modules'), path.join(WORK, 'tests', 'differential', 'node_modules'));

  const rows = [];
  console.log(`HEAD ${git('rev-parse', '--short', 'HEAD')}; building the unmutated baseline…`);
  await build();
  const gates = new Map();
  for (const m of chosen) gates.set(`${m.suite}:${m.only.join(',')}`, m);
  for (const [key, m] of gates) {
    const r = await gate(m.suite, m.only, `baseline-${m.suite}-${m.only.join('+')}`);
    rows.push({ name: `(baseline) ${key}`, expect: 'pass', got: r.code === 0 ? 'pass' : `exit ${r.code}`, ok: r.code === 0 });
    if (r.code !== 0) console.error(r.log.split('\n').slice(-15).join('\n'));
  }
  // A gate that already fails would "catch" every mutation; say so and stop.
  if (rows.some((r) => !r.ok)) {
    for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}  ${r.got}`);
    console.log('\nthe unmutated build fails its own gates; nothing a mutation does can be measured');
    return 1;
  }

  let stale = false;
  for (const m of chosen) {
    const file = path.join(WORK, m.file);
    const original = fs.readFileSync(file, 'utf8');
    const count = original.split(m.from).length - 1;
    if (count !== 1) {
      rows.push({ name: m.name, expect: 'caught', got: `does not apply (${count} matches)`, ok: false });
      stale = true;
      continue;
    }
    fs.writeFileSync(file, original.replace(m.from, m.to));
    try {
      await build();
      const r = await gate(m.suite, m.only, m.name);
      const caught = r.code === 1;
      rows.push({
        name: m.name,
        expect: `caught by ${m.suite}:${m.only.join(',')}`,
        got: caught ? 'caught' : r.code === 0 ? 'SURVIVED' : `exit ${r.code}`,
        ok: caught,
      });
    } finally {
      fs.writeFileSync(file, original);
    }
  }
  await build(); // leave TARGET holding the unmutated build, not the last mutation

  console.log('');
  for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.name.padEnd(34)} ${r.got.padEnd(12)} (${r.expect})`);
  console.log(`\narchives: ${path.relative(process.cwd(), path.join(TARGET, 'runs'))}`);
  return stale ? 2 : rows.every((r) => r.ok) ? 0 : 1;
}

main()
  .then((code) => { cleanup(); process.exit(code); })
  .catch((e) => {
    console.error(e.message || e);
    cleanup();
    process.exit(interrupted ? 130 : 1);
  });
