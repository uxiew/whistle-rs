// What a front proxy claims about a request, asked of both proxies.
//
// A proxy behind another one sees the wrong client address, the wrong scheme
// and sometimes the wrong host. The convention is headers, and whistle reads
// four (`handleForwardedProps`, `_original/lib/util/index.js:3697-3728`, and
// `getFullUrl`, `lib/util/common.js:1231-1266`).
//
//   PORT_BASE=20900 node forwarded-bench.js
//     20900 whichever proxy is being started · 20902 origin A · 20903 origin B
//
// **Two origins, because the interesting claim is a destination.** A request
// addressed to A that arrives at B is a redirect a header performed, and it is
// readable directly rather than inferred. Alongside it each row reports which
// `x-forwarded-*` / `x-whistle-*` headers reached the origin — a claim this
// proxy decided not to trust must not be handed on as if it had.
//
// A rule pair (`https://…` and `http://…`, each setting a marker) makes the
// scheme claim visible too: `x-forwarded-proto` does not change the connection
// this proxy makes, it changes **which pattern matches**. Each row also reports
// how many connections spoke something other than HTTP at the origin — a
// ClientHello, in other words — because that distinction is invisible in the
// answer alone. See `handshakes` below for the bug that taught it.
//
// **A clean run is `differing: 0`, with declared rows**, all of them one
// divergence: upstream lets a *request* open the gates that a mode is otherwise
// required to open.
//
//   * `x-whistle-real-host` redirects the request with **no mode at all** —
//     `getFullUrl` reads it before anything else and there is no flag on the
//     path (`common.js:1233,:1252-1266`);
//   * `x-whistle-forwarded-props: host` / `: proto` turn the corresponding
//     gate on **for that one request** (`util/index.js:3703-3706`).
//
// This port removes both headers from every request and reads neither, except
// that `x-whistle-real-host` is honoured under `-M x-forwarded-host` — the mode
// whose whole subject is "a front proxy is telling me the host". The reasoning
// is in `src/proxy/forwarded.rs`: when the gate is a header, the sender decides,
// and a proxy cannot tell an operator's front proxy from any client, because
// the header is the only evidence and the sender wrote it.
'use strict';
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 20900);
const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');
/** The whistle this run measures — `WHISTLE_PKG`, or the baseline. */
const WHISTLE = require('./whistle-pkg');
const { forVersion } = WHISTLE;
// Set by `run.js`; see mode-bench.js.
const STATE = process.env.DIFF_STATE || __dirname;
const HOST = process.env.DIFF_HOST;
const W = BASE, A = BASE + 2, B = BASE + 3;

const MODES = process.env.FMODES ? process.env.FMODES.split(',') : [
  '',                                    // believe nothing — the default in both
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-host|x-forwarded-proto',
];

const req = (opts, body) => new Promise((res) => {
  const r = http.request(opts, (x) => {
    let s = '';
    x.on('data', (c) => (s += c));
    x.on('end', () => res({ status: x.statusCode, body: s }));
  });
  r.on('error', (e) => res({ status: 0, body: 'ERR ' + e.code }));
  r.setTimeout(6000, () => { r.destroy(); res({ status: 0, body: 'timeout' }); });
  r.end(body);
});

/**
 * Connections that spoke something other than HTTP at an origin, since the last
 * reset — which is how a **TLS handshake** shows up at a plain server.
 *
 * This exists because of a bug it would have caught and did not. A claimed
 * `x-forwarded-proto: https` is supposed to change **which pattern matches**,
 * and this port promoted the outbound connection to TLS as well. The answer
 * still looked right, because a handshake that fails retries in plain — so
 * every probe here passed while every request paid for a doomed ClientHello
 * first. It surfaced only against an origin that *read* the handshake instead
 * of rejecting it, and then hung forever. Measured on upstream afterwards:
 * whistle sends no ClientHello at all for this.
 *
 * A differential bench compares answers. When two proxies can reach the same
 * answer by different routes, the route has to become an observable of its own.
 */
let handshakes = 0;

function origin(port, name) {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      r.writeHead(200, { 'content-type': 'application/json' });
      r.end(JSON.stringify({ who: name, url: q.url, headers: q.headers }));
    });
    // Node reports a ClientHello arriving at a plain server as
    // `HPE_INVALID_METHOD` here.
    srv.on('clientError', (e, sock) => { handshakes++; sock.destroy(); });
    srv.on('error', (e) => { console.error(`origin ${port}: ${e.code}`); process.exit(1); });
    srv.listen(port, () => res(srv));
  });
}

function start(which, mode) {
  return new Promise((resolve, reject) => {
    const dir = path.join(STATE, `.fwd-${which}-${(mode || 'none').replace(/\W/g, '_')}`);
    const child = which === 'whistle'
      ? spawn('node', ['-e', `
          const whistle = require(${JSON.stringify(WHISTLE.dir)});
          whistle({ port: ${W}, baseDir: ${JSON.stringify(dir)}${HOST ? `, host: ${JSON.stringify(HOST)}` : ''}${mode ? `, mode: ${JSON.stringify(mode)}` : ''} },
            () => console.log('READY'));
        `], { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn(RS_BIN, ['--port', String(W), '--no-persist', '--dir', dir,
        ...(HOST ? ['-H', HOST] : []), ...(mode ? ['-M', mode] : [])],
        { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; child.kill('SIGKILL'); reject(new Error('start timeout')); } }, 25000);
    const watch = (d) => { if (!done && /READY|listening on/.test(String(d))) { done = true; clearTimeout(t); resolve(child); } };
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', () => { if (!done) { done = true; clearTimeout(t); reject(new Error('exited early')); } });
  });
}

/** Two rules that differ only in scheme, so the match is readable at the origin. */
const RULES = `https://127.0.0.1:${A}/echo reqHeaders://x-scheme=https\nhttp://127.0.0.1:${A}/echo reqHeaders://x-scheme=http`;

async function seed(which) {
  const post = (p, b, json = true) => req({
    port: W, host: '127.0.0.1', path: p, method: 'POST',
    headers: { host: `127.0.0.1:${W}`, 'content-type': json ? 'application/json' : 'text/plain' },
  }, b);
  if (which === 'whistle') {
    await post('/cgi-bin/rules/add', JSON.stringify({ name: 'Default', value: RULES }));
  } else {
    await post('/api/rules', RULES, false);
  }
}

async function probe(headers) {
  handshakes = 0;
  const a = await req({
    port: W, host: '127.0.0.1', method: 'GET', path: `http://127.0.0.1:${A}/echo`,
    headers: Object.assign({ host: `127.0.0.1:${A}` }, headers),
  });
  // The retry that hid the bug is asynchronous, so let the second connection
  // land before the counter is read.
  await new Promise((r) => setTimeout(r, 250));
  const spoke = handshakes ? ` | TLS attempts: ${handshakes}` : '';
  if (a.status !== 200) return `status ${a.status}${spoke}`;
  let j;
  try { j = JSON.parse(a.body); } catch (e) { return `unparseable: ${a.body.slice(0, 60)}`; }
  const left = Object.keys(j.headers).filter((k) => /^x-(forwarded|whistle)/.test(k)).sort().join(',') || '(none)';
  // The Host is reported as A/B rather than as a port, so a run at another
  // PORT_BASE compares to the same strings.
  const host = j.headers.host === `127.0.0.1:${A}` ? 'A' : j.headers.host === `127.0.0.1:${B}` ? 'B' : j.headers.host;
  return `-> ${j.who} host=${host} scheme=${j.headers['x-scheme'] || '(none)'} | reached origin: ${left}${spoke}`;
}

const PROBES = {
  // The gated pair, which is what the modes are named after.
  'x-forwarded-host names B': { 'x-forwarded-host': `127.0.0.1:${B}` },
  'x-forwarded-proto: https': { 'x-forwarded-proto': 'https' },
  'x-forwarded-proto: http': { 'x-forwarded-proto': 'http' },
  'both at once': { 'x-forwarded-host': `127.0.0.1:${B}`, 'x-forwarded-proto': 'https' },
  // whistle's own spelling of the host claim, which upstream reads with no gate.
  'x-whistle-real-host names B': { 'x-whistle-real-host': `127.0.0.1:${B}` },
  'both host spellings disagree': { 'x-whistle-real-host': `127.0.0.1:${B}`, 'x-forwarded-host': `127.0.0.1:${A}` },
  // The request asking for the gates to be opened for itself.
  'props:host opens the host gate': { 'x-whistle-forwarded-props': 'host', 'x-forwarded-host': `127.0.0.1:${B}` },
  'props:proto opens the proto gate': { 'x-whistle-forwarded-props': 'proto', 'x-forwarded-proto': 'https' },
  'props names all three': {
    'x-whistle-forwarded-props': 'host,proto,ip',
    'x-forwarded-host': `127.0.0.1:${B}`, 'x-forwarded-proto': 'https', 'x-forwarded-for': '9.9.9.9',
  },
  // A claim that is not a destination: neither proxy may act on it, and neither
  // may fail the request over it.
  'an unusable forwarded host': { 'x-forwarded-host': ':::not-a-host' },
  // The baseline. A bench whose no-header row diverged would be measuring the
  // seeding rather than the headers.
  'no claim at all': {},
};

/**
 * The one divergence, named with the reason — same shape as every other corpus
 * here. `probes` lists which rows it excuses.
 */
const WHY = 'a request opening its own gate. Upstream reads `x-whistle-real-host` with '
  + 'no gate at all (`common.js:1233`) and lets `x-whistle-forwarded-props` turn the '
  + 'three gates on for one request (`util/index.js:3703-3706`). This port removes both '
  + 'headers from every request and reads neither — except `x-whistle-real-host` under '
  + '`-M x-forwarded-host`, whose subject is exactly that claim. A mode is an operator '
  + 'deciding once that a front proxy is there; a header is the sender deciding, and the '
  + 'proxy cannot tell the two apart. See src/proxy/forwarded.rs.';

const hasHost = (mode) => /x-forwarded-host/.test(mode);
const hasProto = (mode) => /x-forwarded-proto/.test(mode);

const DECLARED = forVersion([
  // The whistle spelling of the host claim: honoured here **only** once the
  // host gate is open, and honoured upstream always.
  { probes: ['x-whistle-real-host names B', 'both host spellings disagree'],
    modes: (mode) => !hasHost(mode), why: WHY },
  // `props` opening a gate that the mode has not opened.
  { probes: ['props:host opens the host gate'], modes: (mode) => !hasHost(mode), why: WHY },
  { probes: ['props:proto opens the proto gate'], modes: (mode) => !hasProto(mode), why: WHY },
  // This one names all three, and the third is `ip` — for which there is no
  // mode in this bench's list at all, so it differs under every one of them.
  // (`-M keepXFF` is measured by `mode-bench.js`, which is where that gate
  // lives.)
  { probes: ['props names all three'], modes: () => true, why: WHY },
]);

async function answersFor(which, mode) {
  let child;
  try { child = await start(which, mode); } catch (e) { return { error: e.message }; }
  await new Promise((r) => setTimeout(r, 900));
  const out = {};
  try {
    await seed(which);
    await new Promise((r) => setTimeout(r, 300));
    for (const [name, headers] of Object.entries(PROBES)) out[name] = await probe(headers);
  } catch (e) { out.error = String(e.message); }
  child.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 900));
  return out;
}

async function main() {
  const sa = await origin(A, 'A');
  const sb = await origin(B, 'B');
  let total = 0, differing = 0, declared = 0;
  const report = [];
  for (const mode of MODES) {
    const label = mode || '(believe nothing — the default)';
    const w = await answersFor('whistle', mode);
    const rs = await answersFor('rs', mode);
    console.log(`\n## ${label}`);
    for (const name of Object.keys(PROBES)) {
      total++;
      const a = w[name] ?? `(missing: ${w.error || 'no answer'})`;
      const b = rs[name] ?? `(missing: ${rs.error || 'no answer'})`;
      if (a === b) { console.log(`  ok    ${name}\n           ${a}`); continue; }
      const excuse = DECLARED.find((d) => d.probes.includes(name) && d.modes(mode));
      if (excuse) {
        declared++;
        console.log(`  DECL  ${name}\n        whistle: ${a}\n             rs: ${b}`);
      } else {
        differing++;
        report.push({ mode: label, probe: name, whistle: a, rs: b });
        console.log(`  DIFF  ${name}\n        whistle: ${a}\n             rs: ${b}`);
      }
    }
  }
  sa.close();
  sb.close();
  console.log(`\nprobes: ${total}  differing: ${differing}  declared: ${declared}`);
  if (report.length) console.log(JSON.stringify(report, null, 2));
  process.exit(differing ? 1 : 0);
}

main();
