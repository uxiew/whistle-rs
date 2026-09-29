#!/usr/bin/env node
// One command for the differential benches. It starts the proxies they need,
// runs them, decides pass or fail, archives what it saw, and cleans up after
// itself — also when it is interrupted.
//
//   node run.js fast       the rules oracle over both corpora and the QR encoder;
//                          no proxy, about ten seconds. What a pull request runs.
//   node run.js network    both proxies, every corpus and every bench; minutes.
//   node run.js all        both of the above.
//
// Options:
//   --only a,b        run only the named steps (see `--list`)
//   --list            print the steps of the suite and exit
//   --port-base N     first port of the block it claims (default 18700)
//   --out DIR         where the archive goes (default target/differential/<stamp>-<suite>)
//   --keep            keep the scratch directory (proxy state, CAs) for debugging
//   --allow-stale     run even if the whistle-rs binary is older than its source
//   --whistle V       measure against whistle V instead of the baseline in
//                     package.json; V needs a lockfile of its own under
//                     versions/V (see the README, "Which whistle, though")
//   --assume-baseline with --whistle: hold V to the baseline's declarations,
//                     so what fails is what moved between the two releases
//
// Exit status: 0 every step passed; 1 a step failed; 2 it could not start —
// a port was taken, the binary is missing or stale, `npm ci` was not run.
//
// What "isolated" means here, because each of these was a real way for one run
// to measure another:
//   * every proxy's data directory, root CA and session store is created in a
//     fresh scratch directory under the OS temp dir and deleted afterwards, so
//     no run inherits another's rules, CA or state, and nothing lands in the
//     repository;
//   * every proxy it starts listens on 127.0.0.1 only;
//   * every port the suite needs is checked before anything starts, and a port
//     that something already answers on stops the run with its number, rather
//     than letting a bench compare somebody else's server;
//   * every child runs in its own process group, and the whole group is killed
//     afterwards — the benches that start their own proxies leave nothing
//     listening even when they crash, time out or the run is interrupted.

const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..', '..');
// Absolute, because the proxies are started in directories of their own: a
// relative `RS_BIN` passed the existence check here and then failed to spawn
// with an unhandled ENOENT.
const RS_BIN = path.resolve(process.env.RS_BIN || path.join(REPO, 'target', 'debug', 'whistle-rs'));
const HOST = '127.0.0.1';

// ── arguments ─────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const option = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
};
const suite = argv.find((a) => ['fast', 'network', 'all'].includes(a));
if (!suite) {
  console.error('usage: node run.js fast|network|all [--only a,b] [--list] [--port-base N] [--out DIR] [--keep] [--whistle V]');
  process.exit(2);
}
const PB = Number(option('--port-base') || process.env.PORT_BASE || 18700);

// Which whistle. The baseline is the one package.json locks, installed beside
// this file; any other version has a directory of its own under versions/, with
// its own lockfile, so measuring a second release never disturbs the first.
const BASELINE = require('./package.json').dependencies.whistle;
const WHISTLE_VERSION = option('--whistle') || BASELINE;
const WHISTLE_HOME = WHISTLE_VERSION === BASELINE ? HERE : path.join(HERE, 'versions', WHISTLE_VERSION);
if (!fs.existsSync(path.join(WHISTLE_HOME, 'package-lock.json'))) {
  const known = fs.existsSync(path.join(HERE, 'versions')) ? fs.readdirSync(path.join(HERE, 'versions')) : [];
  console.error(`no lockfile for whistle ${WHISTLE_VERSION}: expected versions/${WHISTLE_VERSION}/package-lock.json`
    + ` (have: ${[BASELINE, ...known].join(', ')})`);
  process.exit(2);
}
const WHISTLE_PKG = path.join(WHISTLE_HOME, 'node_modules', 'whistle');
const ASSUME_BASELINE = flag('--assume-baseline');
const only = option('--only') ? new Set(option('--only').split(',')) : null;

// ── the steps ─────────────────────────────────────────────────────────────

// The hand-written corpora `harness.js` runs. Not `cases-generated.js` or
// `cases-rulelines.js`: those are the rules oracle's, and put through a live
// proxy they would send thousands of requests to hosts like example.com.
const CORPORA = [
  'cases.js', 'cases-bodies.js', 'cases-compose.js', 'cases-delete.js', 'cases-docs.js',
  'cases-file.js', 'cases-filters.js', 'cases-flags.js', 'cases-frames.js', 'cases-groups.js',
  'cases-includes.js', 'cases-lineprops.js', 'cases-paths.js', 'cases-patterns.js',
  'cases-proxy.js', 'cases-values.js',
];

// Ports beyond the pair (PB whistle, PB+1 whistle-rs) and the origin (PB+2):
// https-bench and forwarded-bench want a second origin at PB+3, cases-includes
// a rules server at PB+10, and cases-proxy (and so `--from-cases`, which
// requires every corpus) its eight servers at PB+10…PB+17.
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => PB + a + i);
const EXTRA = range(10, 17);

const MINUTE = 60 * 1000;
const FAST = [
  { name: 'oracle-docs', args: ['rules-oracle.js', '--values', '--quiet'], timeout: 5 * MINUTE },
  { name: 'oracle-cases', args: ['rules-oracle.js', '--from-cases', '--values', '--quiet'], ports: EXTRA, timeout: 5 * MINUTE },
  { name: 'qr', args: ['qr-bench.js'], timeout: 5 * MINUTE },
];

// `standard` is one pair shared by every corpus, the way they have always
// been run: `WHISTLE_DIFF_ENV=Alpha` on both (cases-filters asks
// `env:`), `--insecure-upstream` on whistle-rs (cases-proxy's TLS hop and the
// HTTPS bench's self-signed origin). https-bench goes last, because it turns on
// whistle's persisted `Enable HTTPS` switch for everything after it.
const NETWORK = [
  ...CORPORA.map((file) => ({
    name: file.replace(/\.js$/, ''),
    pair: 'standard',
    args: ['harness.js'],
    env: { CASES: `./${file}` },
    ports: [PB + 2, ...EXTRA],
    triage: file,
    timeout: 10 * MINUTE,
  })),
  { name: 'frames', pair: 'standard', args: ['frames-bench.js'], ports: [PB + 2], timeout: 10 * MINUTE },
  { name: 'timing', pair: 'standard', args: ['timing-bench.js'], ports: [PB + 2], timeout: 10 * MINUTE },
  { name: 'ws', pair: 'standard', args: ['ws-bench.js'], ports: [PB + 2], timeout: 5 * MINUTE },
  { name: 'dns', pair: 'standard', args: ['dns-bench.js'], ports: [PB + 2, PB + 3, PB + 4], timeout: 5 * MINUTE },
  // Run in the proxies' own working directory: whistle writes an empty
  // `resWrite://` path relative to its cwd, and this bench finds it — and then
  // deletes it — by watching its own. Anywhere else it would miss the file, or
  // delete something that was not its to delete.
  { name: 'write', pair: 'standard', args: ['write-bench.js'], ports: [PB + 2], cwd: 'cwd', timeout: 10 * MINUTE },
  { name: 'https', pair: 'standard', args: ['https-bench.js'], ports: [PB + 2, PB + 3], timeout: 10 * MINUTE },
  // After https-bench, whose `Enable HTTPS` switch it needs too (and sets
  // itself, for running by hand).
  { name: 'h2', pair: 'standard', args: ['h2-bench.js'], ports: [PB + 2], timeout: 5 * MINUTE },
  // Its own pair: every other bench installs rules through the console this
  // one locks.
  { name: 'auth', pair: 'auth', args: ['auth-bench.js'], ports: [PB + 2], timeout: 10 * MINUTE },
  // These start and stop their own proxies, one per mode, on PB itself.
  { name: 'modes', args: ['mode-bench.js'], ports: range(0, 3), timeout: 20 * MINUTE },
  { name: 'forwarded', args: ['forwarded-bench.js'], ports: range(0, 3), timeout: 15 * MINUTE },
  { name: 'header-rules', args: ['header-rules-bench.js'], ports: range(0, 3), timeout: 15 * MINUTE },
  // Upstream's own test suite. Its ports are its own and fixed — the units
  // spell them out in their URLs — so this step does not move with --port-base.
  // It fetches upstream's `test/` into `target/` on first use.
  {
    name: 'upstream-suite',
    args: ['upstream-suite.js'],
    ports: [6666, 18080, 18081, 5566, 1080, 1118, 7788, 2080, 2081, 19999, 37621],
    timeout: 20 * MINUTE,
    // Its verdict with every judged call's key, for comparing versions call by call.
    json: true,
  },
];

const PAIRS = {
  standard: {
    env: { WHISTLE_DIFF_ENV: 'Alpha' },
    rsArgs: ['--insecure-upstream'],
  },
  // The credentials auth-bench.js is written against.
  auth: {
    env: { W2_USER: 'admin', W2_PASS: 's3cret', W2_GUEST: 'guest', W2_GUEST_PASS: 'look' },
    rsArgs: ['-n', 'admin', '-w', 's3cret', '-N', 'guest', '-W', 'look'],
  },
};

let steps = { fast: FAST, network: NETWORK, all: [...FAST, ...NETWORK] }[suite];
if (only) {
  const unknown = [...only].filter((n) => !steps.some((s) => s.name === n));
  if (unknown.length) {
    console.error(`no such step in ${suite}: ${unknown.join(', ')} (see --list)`);
    process.exit(2);
  }
  steps = steps.filter((s) => only.has(s.name));
}
if (flag('--list')) {
  for (const s of steps) console.log(`${s.name.padEnd(16)} ${s.pair ? `[${s.pair} pair] ` : ''}node ${s.args.join(' ')}`);
  process.exit(0);
}

// ── process groups ────────────────────────────────────────────────────────

/** Every group this run started and has not yet reaped, by leader pid. */
const groups = new Map();

function startGroup(label, command, args, { cwd, env, out, err, stdin = 'ignore' }) {
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, ...env },
    // Its own process group, so a bench that starts proxies of its own takes
    // them with it when the group is killed.
    detached: true,
    stdio: [stdin, out, err],
  });
  // The child has its own copies of these descriptors now.
  for (const fd of new Set([stdin, out, err])) if (typeof fd === 'number') fs.closeSync(fd);
  groups.set(child.pid, label);
  return child;
}

function killGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch (e) {
    if (e.code !== 'ESRCH') throw e;
  }
}

/** Kill a group and wait until its leader is gone; SIGKILL after a grace period. */
async function stopGroup(child) {
  if (!groups.has(child.pid)) return;
  killGroup(child.pid, 'SIGTERM');
  const gone = child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve()
    : new Promise((r) => child.once('exit', r));
  const late = setTimeout(() => killGroup(child.pid, 'SIGKILL'), 3000);
  await gone;
  clearTimeout(late);
  // The leader has gone; anything it started and left behind goes too.
  killGroup(child.pid, 'SIGKILL');
  groups.delete(child.pid);
}

function killEverything() {
  for (const pid of groups.keys()) killGroup(pid, 'SIGKILL');
  groups.clear();
}

// ── ports ─────────────────────────────────────────────────────────────────

/** Does anything answer a connection on this port? */
function answers(port) {
  return new Promise((resolve) => {
    const s = net.connect({ port, host: HOST });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
  });
}

/** Can this run bind the port? A listener on another address can hold it without answering on loopback. */
function bindable(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen({ port, host: HOST, exclusive: true }, () => srv.close(() => resolve(true)));
  });
}

function holderOf(port) {
  try {
    return execFileSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN'], { encoding: 'utf8' }).trim().split('\n').slice(1).join('; ');
  } catch {
    return '';
  }
}

async function requireFree(ports, why) {
  const taken = [];
  for (const port of [...new Set(ports)].sort((a, b) => a - b)) {
    if ((await answers(port)) || !(await bindable(port))) taken.push(port);
  }
  if (taken.length) {
    const who = taken.map((p) => `  ${p}: ${holderOf(p) || 'held (lsof could not say by whom)'}`).join('\n');
    throw new SetupError(`port(s) in use before ${why}:\n${who}\nStop what holds them, or pick another block with --port-base.`);
  }
}

async function waitForPort(port, child, label, timeoutMs) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new SetupError(`${label} exited (${child.exitCode ?? child.signalCode}) before it listened on ${port}; see its log`);
    }
    if (await answers(port)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new SetupError(`${label} did not listen on ${port} within ${timeoutMs / 1000}s; see its log`);
}

class SetupError extends Error {}

// ── the run ───────────────────────────────────────────────────────────────

const started = new Date();
const stamp = started.toISOString().replace(/[:.]/g, '-');
const versionTag = (WHISTLE_VERSION === BASELINE ? '' : `-whistle-${WHISTLE_VERSION}`)
  + (ASSUME_BASELINE ? '-assume-baseline' : '');
const OUT = path.resolve(option('--out') || path.join(REPO, 'target', 'differential', `${stamp}-${suite}${versionTag}`));
const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-rs-diff-'));
const dirs = {
  state: path.join(SCRATCH, 'state'),
  tmp: path.join(SCRATCH, 'tmp'),
  cwd: path.join(SCRATCH, 'cwd'),
};
for (const d of [OUT, path.join(OUT, 'steps'), path.join(OUT, 'logs'), ...Object.values(dirs)]) {
  fs.mkdirSync(d, { recursive: true });
}

// Everything a child sees. `DIFF_STATE`/`DIFF_HOST` are read by the benches
// that start their own proxies; `TMPDIR` puts every `os.tmpdir()` fixture a
// corpus writes inside the scratch directory, so it goes when the run does.
const baseEnv = {
  PORT_BASE: String(PB),
  RS_BIN,
  // Read by whistle-pkg.js in every script: which whistle to load, and so which
  // declarations are in force.
  WHISTLE_PKG,
  ...(ASSUME_BASELINE ? { DIFF_ASSUME_BASELINE: '1' } : {}),
  DIFF_STATE: dirs.state,
  DIFF_HOST: HOST,
  TMPDIR: dirs.tmp,
};

const results = [];
let interrupted = null;

async function startPair(name) {
  const pair = PAIRS[name];
  await requireFree([PB, PB + 1], `starting the ${name} pair`);
  const open = (file) => fs.openSync(path.join(OUT, 'logs', file), 'a');
  const whistle = startGroup(`${name}:whistle`, process.execPath, [path.join(HERE, 'oracle.js')], {
    cwd: dirs.cwd,
    env: {
      ...baseEnv,
      ...pair.env,
      WHISTLE_DIFF_DATA: path.join(dirs.state, `whistle-${name}`),
      WHISTLE_DIFF_HOST: HOST,
    },
    out: open(`${name}-whistle.log`),
    err: open(`${name}-whistle.log`),
  });
  const rs = startGroup(`${name}:whistle-rs`, RS_BIN, [
    '--port', String(PB + 1), '--host', HOST, '--no-persist',
    '--dir', path.join(dirs.state, `rs-${name}`), ...pair.rsArgs,
  ], {
    cwd: dirs.cwd,
    env: { ...baseEnv, ...pair.env },
    out: open(`${name}-rs.log`),
    err: open(`${name}-rs.log`),
  });
  await waitForPort(PB, whistle, `whistle (${name} pair)`, 60 * 1000);
  await waitForPort(PB + 1, rs, `whistle-rs (${name} pair)`, 30 * 1000);
  return { name, whistle, rs };
}

async function stopPair(p) {
  if (!p) return;
  await stopGroup(p.rs);
  await stopGroup(p.whistle);
}

function summarise(stdout) {
  try {
    const j = JSON.parse(stdout);
    const keep = ['ran', 'differing', 'declared', 'inert', 'probes', 'wroteNothing'];
    // mode-bench's `inert` is the list of modes; the count is what a summary wants.
    const out = Object.fromEntries(keep.filter((k) => k in j)
      .map((k) => [k, Array.isArray(j[k]) ? j[k].length : j[k]]));
    if (Array.isArray(j.stale) && j.stale.length) out.stale = j.stale.length;
    return out;
  } catch {
    // rules-oracle and header-rules-bench print prose; their last summary line says it all.
    const line = stdout.trim().split('\n').reverse().find((l) => /questions:|probes|differing/.test(l));
    return line ? { line: line.trim() } : {};
  }
}

async function runStep(step) {
  const t0 = Date.now();
  const outFile = path.join(OUT, 'steps', `${step.name}.out`);
  const errFile = path.join(OUT, 'steps', `${step.name}.err`);
  if (step.ports) await requireFree(step.ports, `step ${step.name}`);
  const args = step.args.map((a, i) => (i === 0 ? path.join(HERE, a) : a));
  if (step.json) args.push('--json', path.join(OUT, 'steps', `${step.name}.json`));
  const child = startGroup(step.name, process.execPath, args, {
    cwd: step.cwd ? dirs[step.cwd] : HERE,
    env: { ...baseEnv, ...(step.env || {}) },
    out: fs.openSync(outFile, 'w'),
    err: fs.openSync(errFile, 'w'),
  });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; killGroup(child.pid, 'SIGKILL'); }, step.timeout);
  const code = await new Promise((r) => child.once('exit', (c, s) => r(c ?? (s ? 128 : 1))));
  clearTimeout(timer);
  await stopGroup(child);
  const stdout = fs.readFileSync(outFile, 'utf8');
  const result = {
    name: step.name,
    command: `node ${step.args.join(' ')}`,
    env: step.env || {},
    pair: step.pair || null,
    exit: code,
    timedOut,
    ms: Date.now() - t0,
    summary: summarise(stdout),
    passed: code === 0 && !timedOut,
  };
  // An inert case must be explained: triage-inert resolves each one's rules and
  // fails on any that matched nothing for no stated reason, and on a stale
  // `inert: true` marker.
  if (step.triage && !timedOut) {
    const triageFile = path.join(OUT, 'steps', `${step.name}.triage`);
    // triage-inert reads the harness's JSON on stdin, which is the file it wrote.
    const triage = startGroup(`${step.name}:triage`, process.execPath, [path.join(HERE, 'triage-inert.js'), `./${step.triage}`], {
      cwd: HERE,
      env: baseEnv,
      stdin: fs.openSync(outFile, 'r'),
      out: fs.openSync(triageFile, 'w'),
      err: fs.openSync(triageFile, 'a'),
    });
    const tcode = await new Promise((r) => triage.once('exit', (c) => r(c ?? 1)));
    await stopGroup(triage);
    // The counts that fail it, rather than whatever line happened to be last.
    const verdict = fs.readFileSync(triageFile, 'utf8').split('\n')
      .filter((l) => /nothing to explain it: [1-9]|stale/i.test(l)).map((l) => l.trim());
    result.triage = { exit: tcode, last: verdict.join('; ') || `exit ${tcode}` };
    if (tcode !== 0) result.passed = false;
  }
  return result;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function git(...args) {
  try {
    // trimEnd: `status --porcelain` starts a line with a space for an unstaged change.
    return execFileSync('git', args, { cwd: REPO, encoding: 'utf8' }).trimEnd();
  } catch {
    return null;
  }
}

/** Newest file under the Rust sources, to catch a binary built from something else. */
function newestSource() {
  let newest = { file: null, mtime: 0 };
  const visit = (p) => {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      for (const e of fs.readdirSync(p)) visit(path.join(p, e));
    } else if (st.mtimeMs > newest.mtime) {
      newest = { file: path.relative(REPO, p), mtime: st.mtimeMs };
    }
  };
  for (const p of ['src', 'build.rs', 'Cargo.toml', 'Cargo.lock']) visit(path.join(REPO, p));
  return newest;
}

function preflight() {
  if (!fs.existsSync(RS_BIN)) {
    throw new SetupError(`no whistle-rs binary at ${RS_BIN}. Build it first: cargo build --locked`);
  }
  const src = newestSource();
  if (!flag('--allow-stale') && !process.env.RS_BIN && src.mtime > fs.statSync(RS_BIN).mtimeMs) {
    throw new SetupError(`${path.relative(REPO, RS_BIN)} is older than ${src.file}: it would measure code that is not in the tree.\nRun cargo build --locked (or pass --allow-stale).`);
  }
  const lock = path.join(WHISTLE_HOME, 'package-lock.json');
  const installed = path.join(WHISTLE_PKG, 'package.json');
  const where = path.relative(REPO, WHISTLE_HOME);
  if (!fs.existsSync(installed)) {
    throw new SetupError(`whistle ${WHISTLE_VERSION} is not installed. Run: npm ci (in ${where})`);
  }
  const locked = JSON.parse(fs.readFileSync(lock, 'utf8')).packages['node_modules/whistle'].version;
  const actual = JSON.parse(fs.readFileSync(installed, 'utf8')).version;
  if (locked !== actual || actual !== WHISTLE_VERSION) {
    throw new SetupError(`${where}/node_modules has whistle ${actual}, the lockfile says ${locked}. Run: npm ci (in ${where})`);
  }
  // The baseline's node_modules also holds what the benches themselves use
  // (upstream's test libraries, qrcode), whichever whistle is measured.
  if (WHISTLE_HOME !== HERE && !fs.existsSync(path.join(HERE, 'node_modules', 'should'))) {
    throw new SetupError('the bench\'s own dependencies are not installed. Run: npm ci (in tests/differential)');
  }
}

function manifest(exitCode) {
  // Untracked files count: a new corpus that is not committed yet is exactly
  // the kind of difference between this run and the commit it names.
  const dirty = git('status', '--porcelain');
  const corpus = {};
  for (const f of fs.readdirSync(HERE).filter((f) => f.endsWith('.js')).sort()) corpus[f] = sha256(path.join(HERE, f));
  let rsVersion = null;
  try {
    rsVersion = execFileSync(RS_BIN, ['--version'], { encoding: 'utf8' }).trim();
  } catch {}
  return {
    suite,
    started: started.toISOString(),
    finished: new Date().toISOString(),
    exitCode,
    interrupted,
    git: { commit: git('rev-parse', 'HEAD'), dirty: dirty ? dirty.split('\n') : [] },
    host: { platform: process.platform, arch: process.arch, release: os.release(), node: process.version },
    whistleRs: {
      binary: path.relative(REPO, RS_BIN),
      version: rsVersion,
      sha256: fs.existsSync(RS_BIN) ? sha256(RS_BIN) : null,
    },
    whistle: {
      version: fs.existsSync(path.join(WHISTLE_PKG, 'package.json'))
        ? JSON.parse(fs.readFileSync(path.join(WHISTLE_PKG, 'package.json'), 'utf8')).version
        : null,
      baseline: WHISTLE_VERSION === BASELINE,
      assumeBaselineDeclarations: ASSUME_BASELINE,
      lockfile: path.relative(REPO, path.join(WHISTLE_HOME, 'package-lock.json')),
      lockfileSha256: sha256(path.join(WHISTLE_HOME, 'package-lock.json')),
    },
    portBase: PB,
    listen: HOST,
    corpusSha256: corpus,
    steps: results,
  };
}

async function main() {
  preflight();
  // Every port any step of this suite will touch, checked before anything starts.
  const all = new Set();
  for (const s of steps) {
    for (const p of s.ports || []) all.add(p);
    if (s.pair) { all.add(PB); all.add(PB + 1); }
  }
  await requireFree([...all], 'the run');

  let pair = null;
  for (const step of steps) {
    if (interrupted) break;
    if ((pair && pair.name) !== (step.pair || null)) {
      await stopPair(pair);
      pair = null;
      if (step.pair) pair = await startPair(step.pair);
    }
    process.stderr.write(`▶ ${step.name}\n`);
    const r = await runStep(step);
    results.push(r);
    const s = r.summary;
    const numbers = s.line || Object.entries(s).map(([k, v]) => `${k} ${v}`).join(', ');
    process.stderr.write(`  ${r.passed ? 'pass' : 'FAIL'}  ${(r.ms / 1000).toFixed(1)}s  ${numbers}${r.timedOut ? '  (timed out)' : ''}${r.triage && r.triage.exit ? `  inert unexplained: ${r.triage.last}` : ''}\n`);
  }
  await stopPair(pair);
}

let finishing = false;
async function finish(code) {
  // A signal can arrive while `main` is still unwinding; the first caller wins.
  if (finishing) return;
  finishing = true;
  killEverything();
  const m = manifest(code);
  fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(m, null, 2) + '\n');
  if (!flag('--keep')) fs.rmSync(SCRATCH, { recursive: true, force: true });
  const failed = results.filter((r) => !r.passed).map((r) => r.name);
  // An interrupted run must not end on "all passed": the steps it never got
  // to are exactly the ones nobody knows about. It said so, once, after being
  // stopped two steps short.
  // Nor may one that never started: "0 of 28 step(s) run, all passed" is what a
  // stale binary used to end on, with exit status 2 underneath it.
  const verdict = interrupted
    ? `INTERRUPTED by ${interrupted}; not completed: ${steps.slice(results.length).map((s) => s.name).join(', ') || 'none'}`
      + (failed.length ? `; FAILED: ${failed.join(', ')}` : '')
    : code === 2 ? 'COULD NOT START (see setup: above)'
      : failed.length ? `FAILED: ${failed.join(', ')}` : 'all passed';
  console.log(`\n${suite} against whistle ${WHISTLE_VERSION}: ${results.length} of ${steps.length} step(s) run, ${verdict}`);
  console.log(`archive: ${path.relative(process.cwd(), OUT) || OUT}${flag('--keep') ? `\nscratch kept: ${SCRATCH}` : ''}`);
  process.exit(code);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    interrupted = sig;
    killEverything();
    finish(sig === 'SIGINT' ? 130 : 143);
  });
}
// Last resort: whatever path out of here, no proxy outlives the run.
process.on('exit', killEverything);

main()
  .then(() => finish(results.every((r) => r.passed) ? 0 : 1))
  .catch((e) => {
    console.error(e instanceof SetupError ? `\nsetup: ${e.message}` : e);
    finish(e instanceof SetupError ? 2 : 1);
  });
