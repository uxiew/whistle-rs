// Every corpus, against **one** whistle — and then the same against another.
//
// Everything in this directory is measured against whistle 2.10.8, and a number
// that agrees with one release is not the same claim as a number that agrees
// with whistle. Some of these alignments will be with behaviour a single
// release happened to have; this is how to find out which, and it is the
// question a corpus cannot ask itself.
//
// Two runs and a diff:
//
//   # whistle-rs, once — it does not change between the two runs
//   WHISTLE_DIFF_ENV=Alpha cargo run -- --port 19401 --no-persist \
//     --insecure-upstream --dir /tmp/rs-versions &
//
//   # the release npm install put here
//   WHISTLE_DIFF_ENV=Alpha PORT_BASE=19400 node oracle.js &
//   PORT_BASE=19400 node bench-versions.js > /tmp/v2.10.8.json
//   kill %2
//
//   # and another, from a directory of its own
//   mkdir -p /tmp/w29 && cd /tmp/w29 && npm i whistle@2.9.109 && cd -
//   WHISTLE_PKG=/tmp/w29/node_modules/whistle \
//     WHISTLE_DIFF_ENV=Alpha PORT_BASE=19400 node oracle.js &
//   PORT_BASE=19400 node bench-versions.js > /tmp/v2.9.109.json
//
//   node bench-versions.js --diff /tmp/v2.10.8.json /tmp/v2.9.109.json
//
// The diff is by **case name**, not by count: two runs that both report three
// differences are not thereby the same three, and a corpus that gains one and
// loses one would show as unchanged under a count.
//
// `--insecure-upstream` is for `cases-proxy.js`'s TLS hop and
// `WHISTLE_DIFF_ENV` for `cases-filters.js`'s `env:` conditions; both are inert
// everywhere else, so one launch serves every corpus.

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');

// Every corpus the plain harness can run. The specialty benches
// (`https-bench.js`, `timing-bench.js`, `write-bench.js`, `auth-bench.js`) each
// want their own launch and are not run from here — named so their absence is a
// decision rather than an oversight.
const CORPORA = [
  'cases.js', 'cases-lineprops.js', 'cases-file.js', 'cases-filters.js',
  'cases-patterns.js', 'cases-bodies.js', 'cases-delete.js', 'cases-compose.js',
  'cases-values.js', 'cases-includes.js', 'cases-flags.js', 'cases-groups.js',
  'cases-docs.js', 'cases-proxy.js', 'cases-frames.js', 'cases-paths.js',
];

/** A synchronous pause: the port a bench binds is the one the last let go of. */
function pause(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function runCorpus(corpus, attempt = 0) {
  let out;
  try {
    out = execFileSync('node', ['harness.js'], {
      cwd: __dirname,
      env: { ...process.env, CASES: './' + corpus },
      maxBuffer: 1 << 28,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
  } catch (e) {
    const stderr = (e.stderr || '').toString();
    if (attempt < 2 && /EADDRINUSE/.test(stderr)) {
      pause(1500);
      return runCorpus(corpus, attempt + 1);
    }
    return { error: stderr.split('\n').slice(0, 3).join(' ') || String(e.message) };
  }
  const json = JSON.parse(out.slice(out.indexOf('{')));
  return {
    ran: json.ran,
    differing: json.differing,
    inert: json.inert,
    // The names, sorted, because the set is the thing that has to be compared.
    differingCases: (json.report || []).map((r) => r.name).sort(),
  };
}

/**
 * Which whistle this run is measuring against — read from the same package the
 * oracle was told to load, so the label on the output cannot drift from what
 * actually answered. `WHISTLE_PKG` has to be set for *both* processes.
 */
function packageVersion() {
  try {
    return require(`${process.env.WHISTLE_PKG || 'whistle'}/package.json`).version;
  } catch (e) {
    return 'unknown';
  }
}

/** That an oracle is answering at all, before spending minutes finding out. */
function oracleIsUp(port) {
  const http = require('http');
  return new Promise((resolve) => {
    // `/cgi-bin/rules/list`, not `/cgi-bin/status`: the console answers this one
    // to the plain `http.request` every bench here uses.
    const req = http.get({ port, path: '/cgi-bin/rules/list' }, (r) => {
      r.resume();
      resolve(r.statusCode === 200);
    });
    req.on('error', () => resolve(false));
  });
}

function diff(aPath, bPath) {
  const a = JSON.parse(fs.readFileSync(aPath, 'utf8'));
  const b = JSON.parse(fs.readFileSync(bPath, 'utf8'));
  const out = { a: a.version, b: b.version, changed: [], unchanged: [] };
  for (const corpus of Object.keys(a.corpora)) {
    const x = a.corpora[corpus];
    const y = b.corpora[corpus];
    if (!y) {
      out.changed.push({ corpus, note: 'not run in the second' });
      continue;
    }
    if (x.error || y.error) {
      out.changed.push({ corpus, note: `error: a=${x.error || '-'} b=${y.error || '-'}` });
      continue;
    }
    const only = (p, q) => p.differingCases.filter((n) => !q.differingCases.includes(n));
    const onlyA = only(x, y);
    const onlyB = only(y, x);
    if (!onlyA.length && !onlyB.length && x.ran === y.ran) {
      out.unchanged.push({ corpus, ran: x.ran, differing: x.differing });
      continue;
    }
    out.changed.push({
      corpus,
      ran: [x.ran, y.ran],
      differing: [x.differing, y.differing],
      // A case differing only against the newer release is behaviour that
      // *changed* between them, and an alignment held against the newer one
      // alone was an alignment with that release.
      [`only against ${a.version}`]: onlyA,
      [`only against ${b.version}`]: onlyB,
    });
  }
  console.log(JSON.stringify(out, null, 2));
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--diff') {
    if (args.length !== 3) {
      console.error('usage: node bench-versions.js --diff <a.json> <b.json>');
      process.exit(2);
    }
    return diff(args[1], args[2]);
  }
  const base = Number(process.env.PORT_BASE || 19400);
  if (!(await oracleIsUp(base))) {
    console.error(`no oracle answering on ${base}; start one first`);
    process.exit(1);
  }
  const version = packageVersion();
  const corpora = {};
  for (const corpus of CORPORA) {
    process.stderr.write(`  ${corpus} … `);
    corpora[corpus] = runCorpus(corpus);
    const r = corpora[corpus];
    process.stderr.write(r.error ? `error\n` : `ran ${r.ran}, differing ${r.differing}\n`);
    // The next corpus binds the port this one has just released.
    pause(600);
  }
  console.log(JSON.stringify({ version, corpora }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
