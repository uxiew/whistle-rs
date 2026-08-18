// Rules a request brings **in its own headers**, asked of both proxies.
//
// whistle reads five headers off an arriving request and parses their contents
// as a rules text for that one request (`initHeaderRules`,
// `_original/lib/rules/index.js:576-638`). It is how `nohost`/`multiEnv`
// deployments serve many environments from one proxy: nothing is stored, and
// each request names its own.
//
// This is a **mode**, and one whose default matters: a proxy that honoured these
// headers out of the box is one any client on the network could redirect. Both
// proxies are off by default, and this bench measures all three settings.
//
//   PORT_BASE=20500 node header-rules-bench.js
//     20500 whichever proxy is being started · 20502 the echo origin
//
// **What is compared.** Each mode gets a seeded proxy — one Default rules text,
// one named group, one values entry — and then nine probes, each a request
// carrying some combination of the five headers. What is read off the origin is
// the marker headers the rules set, plus which `x-whistle-*` headers survived
// the proxy. Both are the point:
//
//   * the markers say **which rules applied and which won**;
//   * the survivors say **what a client can hand the origin**. The delete in
//     `getValue` is unconditional — only the reading is gated — so four of the
//     five must never arrive whatever the mode. The fifth,
//     `x-whistle-rule-name`, is the exception upstream forwards outside
//     `multiEnv`, because the function that deletes is the one it never calls.
//
// The seeding APIs differ (the two consoles are different programs), so each
// proxy is seeded through its own and the *probes* are identical. A row that
// differs is a difference in what the proxy did with the request.
//
// **A clean run is `differing: 0`.** Everything here was measured against real
// whistle first and the port written to it; if that stops being true this file
// is how you find out.
'use strict';
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 20500);
const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');
const W = BASE, ORIGIN = BASE + 2;
const O = `127.0.0.1:${ORIGIN}`;
const enc = encodeURIComponent;

/** The modes, and what each is expected to change. */
const MODES = process.env.HMODES ? process.env.HMODES.split(',') : [
  '',                              // off — the default in both
  'enableRequestHeaderRules',      // read, but the stored rules win
  'multiEnv',                      // read, and they win
  'nohost',                        // the same thing by its other name
  'strict|multiEnv',               // strict takes it back away
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

function origin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      r.writeHead(200, { 'content-type': 'application/json' });
      r.end(JSON.stringify({ url: q.url, headers: q.headers }));
    });
    srv.on('error', (e) => { console.error(`origin ${ORIGIN}: ${e.code}`); process.exit(1); });
    srv.listen(ORIGIN, () => res(srv));
  });
}

function start(which, mode) {
  return new Promise((resolve, reject) => {
    const dir = path.join(__dirname, `.hdr-${which}-${(mode || 'none').replace(/\W/g, '_')}`);
    const child = which === 'whistle'
      ? spawn('node', ['-e', `
          const whistle = require('whistle');
          whistle({ port: ${W}, baseDir: ${JSON.stringify(dir)}${mode ? `, mode: ${JSON.stringify(mode)}` : ''} },
            () => console.log('READY'));
        `], { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn(RS_BIN, ['--port', String(W), '--no-persist', '--dir', dir, ...(mode ? ['-M', mode] : [])],
        { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; child.kill('SIGKILL'); reject(new Error('start timeout')); } }, 25000);
    const watch = (d) => { if (!done && /READY|listening on/.test(String(d))) { done = true; clearTimeout(t); resolve(child); } };
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', () => { if (!done) { done = true; clearTimeout(t); reject(new Error('exited early')); } });
  });
}

/** The Default rules text, the named group and the values entry, per console. */
const SEED = {
  default: `${O} reqHeaders://x-who=stored`,
  group: { name: 'Named', text: `${O} reqHeaders://x-mark-name=1` },
  value: { name: 'envA', text: `${O} reqHeaders://x-mark-key=1` },
};

async function seed(which) {
  const post = (p, b, json = true) => req({
    port: W, host: '127.0.0.1', path: p, method: 'POST',
    headers: { host: `127.0.0.1:${W}`, 'content-type': json ? 'application/json' : 'text/plain' },
  }, b);
  if (which === 'whistle') {
    // `rules/add` writes the Default rules when the name is `Default`
    // (`_original/biz/webui/cgi-bin/rules/add.js` -> `setDefaultRules`).
    await post('/cgi-bin/rules/add', JSON.stringify({ name: 'Default', value: SEED.default }));
    await post('/cgi-bin/rules/add', JSON.stringify({ name: SEED.group.name, value: SEED.group.text, selected: false }));
    await post('/cgi-bin/values/add', JSON.stringify({ name: SEED.value.name, value: SEED.value.text }));
  } else {
    await post('/api/rules', SEED.default, false);
    await post('/api/rule-groups', JSON.stringify({ name: SEED.group.name, text: SEED.group.text, enabled: false }));
    await post('/api/values', JSON.stringify({ [SEED.value.name]: SEED.value.text }));
  }
}

/** One request through the proxy, reduced to what the origin saw. */
async function probe(headers) {
  const a = await req({
    port: W, host: '127.0.0.1', method: 'GET', path: `http://${O}/echo`,
    headers: Object.assign({ host: O }, headers),
  });
  if (a.status !== 200) return `status ${a.status}`;
  let h;
  try { h = JSON.parse(a.body).headers; } catch (e) { return `unparseable: ${a.body.slice(0, 60)}`; }
  const marks = Object.keys(h).filter((k) => k.startsWith('x-mark-') || k === 'x-who')
    .sort().map((k) => `${k}=${h[k]}`).join(' ') || '(no marks)';
  const leaked = Object.keys(h).filter((k) => k.startsWith('x-whistle-')).sort().join(',') || '(none)';
  return `${marks} | reached origin: ${leaked}`;
}

/** The nine probes, identical for both proxies. */
const PROBES = {
  // The rules text itself, in both the spellings a client may send it.
  'rule-value, percent-encoded': { 'x-whistle-rule-value': enc(`${O} reqHeaders://x-mark-hdr=1`) },
  'rule-value, raw': { 'x-whistle-rule-value': `${O} reqHeaders://x-mark-raw=1` },
  // Both sides set the same single-value operator. Which one the origin sees
  // *is* the precedence rule, and it is the only thing that separates the two
  // reading modes.
  'precedence against the stored rules': { 'x-whistle-rule-value': enc(`${O} reqHeaders://x-who=header`) },
  // One more line, appended.
  'rule-host': { 'x-whistle-rule-host': enc(`${O} reqHeaders://x-mark-host=1`) },
  // A values entry named by the request, whose content is prepended.
  'rule-key names a values entry': { 'x-whistle-rule-key': SEED.value.name },
  // A name the store does not know contributes nothing — not an empty line, and
  // not an error.
  'rule-key names nothing': { 'x-whistle-rule-key': 'no-such-value' },
  // A `{name}` in the header rules, answered by JSON the same request carried.
  'key-value supplies a private value': {
    'x-whistle-rule-value': enc(`${O} reqHeaders://x-mark-kv=\${pv}`),
    'x-whistle-key-value': JSON.stringify({ pv: 'FROMKV' }),
  },
  // A named rule group, pulled in by name. `multiEnv` only — and the header
  // reaches the origin everywhere else.
  'rule-name names a group': { 'x-whistle-rule-name': SEED.group.name },
  // Everything at once, which is also the only probe that shows the composition
  // order mattering.
  'all five together': {
    'x-whistle-rule-value': enc(`${O} reqHeaders://x-mark-all=1`),
    'x-whistle-rule-host': enc(`${O} reqHeaders://x-mark-host2=1`),
    'x-whistle-rule-key': SEED.value.name,
    'x-whistle-rule-name': SEED.group.name,
    'x-whistle-key-value': JSON.stringify({ pv: 'x' }),
  },
  // The baseline: with none of them sent, both proxies must answer with the
  // stored rules alone. A bench whose no-header row diverged would be measuring
  // the seeding rather than the headers.
  'no headers at all': {},
};

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
  const srv = await origin();
  let differing = 0, total = 0;
  for (const mode of MODES) {
    const label = mode || '(off — the default)';
    const w = await answersFor('whistle', mode);
    const rs = await answersFor('rs', mode);
    console.log(`\n## ${label}`);
    for (const name of Object.keys(PROBES)) {
      total++;
      const a = w[name] ?? `(missing: ${w.error || 'no answer'})`;
      const b = rs[name] ?? `(missing: ${rs.error || 'no answer'})`;
      if (a === b) {
        console.log(`  ok    ${name}\n           ${a}`);
      } else {
        differing++;
        console.log(`  DIFF  ${name}\n        whistle: ${a}\n             rs: ${b}`);
      }
    }
  }
  srv.close();
  console.log(`\nprobes: ${total}  differing: ${differing}`);
  process.exit(differing ? 1 : 0);
}

main();
