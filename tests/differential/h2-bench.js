// Which HTTP version reaches an HTTPS origin, and over how many connections.
//
//   PORT_BASE=18700 node h2-bench.js     # the pair on PORT_BASE and +1 (run.js starts it)
//     +2 the origin: one TLS server that speaks h2 and HTTP/1.1, as most do
//
// whistle forwards a request that arrived over h2 to the origin over h2 when
// the origin offers it, and keeps one session per client connection for every
// request that follows (`_original/lib/https/h2.js:384-460`). A request that
// arrived over HTTP/1.1 goes out over HTTP/1.1. Rules turn it either way:
// `enable://h2` and `disable://h2` (also spelled `http2`, `httpsH2`,
// `_original/lib/inspectors/res.js:174-195`). This port spoke HTTP/1.1 to every
// origin until PERF1, which a client could not see — but the origin could, and
// fifty concurrent h2 requests arrived as fifty connections.
//
// Each case opens one connection to each proxy — h2 or HTTP/1.1, as the case
// says — sends its requests, and compares what the origin reports: the
// version, the headers, and how many connections it took.
//
// Prints `{ ran, differing, declared, stale, report, raw }` like the other JSON
// benches, and exits 1 on a difference `declared.js` does not name.

'use strict';

const fs = require('fs');
const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const { execFileSync } = require('child_process');
const { judge } = require('./declared.js');

const BASE = Number(process.env.PORT_BASE || 18700);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const HOST = process.env.DIFF_HOST || '127.0.0.1';
const STATE = process.env.DIFF_STATE || '/tmp';
const O = `localhost:${ORIGIN}`;

const CASES = [
  { name: 'an h2 client', client: 'h2', rules: '' },
  { name: 'an HTTP/1.1 client', client: 'h1', rules: '' },
  { name: 'an HTTP/1.1 client with enable://h2', client: 'h1', rules: `${O} enable://h2` },
  { name: 'an h2 client with disable://h2', client: 'h2', rules: `${O} disable://h2` },
  { name: 'an h2 client with disable://httpsH2', client: 'h2', rules: `${O} disable://httpsH2` },
  { name: 'an h2 client with disable://http2', client: 'h2', rules: `${O} disable://http2` },
  { name: 'a header rule over h2', client: 'h2', rules: `${O} reqHeaders://x-a=1` },
  { name: 'ten concurrent h2 requests', client: 'h2', rules: '', requests: 10 },
];

// ── the origin ────────────────────────────────────────────────────────────

/** Connections the origin has accepted, for counting per case. */
let accepted = 0;

function certificate() {
  const key = `${STATE}/diff-h2-key.pem`;
  const crt = `${STATE}/diff-h2-crt.pem`;
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', crt, '-days', '2', '-nodes',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

function startOrigin() {
  const server = http2.createSecureServer({ ...certificate(), allowHTTP1: true }, (q, r) => {
    const headers = {};
    for (const [k, v] of Object.entries(q.headers)) if (!k.startsWith(':')) headers[k] = v;
    r.writeHead(200, { 'content-type': 'application/json' });
    r.end(JSON.stringify({
      version: q.httpVersion,
      authority: q.headers[':authority'] || null,
      path: q.url,
      headers,
    }));
  });
  server.on('connection', () => (accepted += 1));
  return new Promise((resolve) => server.listen(ORIGIN, HOST, () => resolve(server)));
}

// ── the clients ───────────────────────────────────────────────────────────

/** A TLS connection to the origin through `port`'s CONNECT, offering `alpn`. */
function tunnel(port, alpn) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: HOST, port, method: 'CONNECT', path: O, headers: { host: O } });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) return reject(new Error(`CONNECT ${res.statusCode}`));
      const s = tls.connect({ socket, servername: 'localhost', ALPNProtocols: alpn, rejectUnauthorized: false },
        () => resolve(s));
      s.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(8000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

/** `n` GETs of `/echo` over one connection to `port`; the origin's answers, and the protocol the proxy spoke to the client. */
async function fetch(port, client, n) {
  const sock = await tunnel(port, client === 'h2' ? ['h2', 'http/1.1'] : ['http/1.1']);
  const spoken = sock.alpnProtocol || 'http/1.1';
  if (spoken === 'h2') {
    const session = http2.connect(`https://${O}`, { createConnection: () => sock });
    session.on('error', () => {});
    const one = () => new Promise((resolve) => {
      const st = session.request({ ':path': '/echo' });
      let body = '';
      st.on('data', (d) => (body += d));
      st.on('end', () => resolve(body));
      st.on('error', (e) => resolve(`stream ${e.code}`));
      st.end();
    });
    const bodies = await Promise.all(Array.from({ length: n }, one));
    session.close();
    return { spoken, bodies };
  }
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  agent.createConnection = () => sock;
  const one = () => new Promise((resolve) => {
    const r = http.request({ agent, host: 'localhost', port: ORIGIN, path: '/echo' }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve(body));
    });
    r.on('error', (e) => resolve(`request ${e.code}`));
    r.end();
  });
  const bodies = [];
  for (let i = 0; i < n; i += 1) bodies.push(await one());
  agent.destroy();
  return { spoken, bodies };
}

// ── the comparison ────────────────────────────────────────────────────────

/** Headers neither proxy is being judged on here: framing, and the proxies' own stamps. */
const IGNORE = /^(date|connection|keep-alive|proxy-connection|transfer-encoding|content-length|user-agent|accept|accept-encoding|x-whistle.*|x-forwarded-for)$/;

/** What one proxy's case comes down to, as a flat map of field → answer. */
function answer({ spoken, bodies }, connections) {
  const seen = bodies.map((b) => {
    try {
      return JSON.parse(b);
    } catch {
      return { version: `unreadable: ${String(b).slice(0, 60)}` };
    }
  });
  const first = seen[0] || {};
  const headers = Object.entries(first.headers || {})
    .filter(([k]) => !IGNORE.test(k))
    .map(([k, v]) => `${k}=${v}`)
    .sort()
    .join('; ');
  return {
    'client protocol': spoken,
    'origin version': [...new Set(seen.map((s) => s.version))].join(','),
    'origin :authority / host': `${first.authority} / ${(first.headers || {}).host}`,
    'origin headers': headers,
    'origin connections': connections,
  };
}

function post(port, path, contentType, body) {
  return new Promise((resolve) => {
    const r = http.request({ host: HOST, port, path, method: 'POST',
      headers: { 'content-type': contentType, 'content-length': Buffer.byteLength(body) } }, (res) => {
      res.resume();
      res.on('end', resolve);
    });
    r.on('error', resolve);
    r.end(body);
  });
}

async function setRules(text) {
  await post(W, '/cgi-bin/rules/add', 'application/x-www-form-urlencoded',
    'name=Default&selected=1&value=' + encodeURIComponent(text));
  await post(RS, '/api/rules', 'text/plain', text);
  await new Promise((r) => setTimeout(r, 200));
}

async function main() {
  const origin = await startOrigin();
  // whistle reads no HTTPS until its console switch is on — see https-bench.js.
  await post(W, '/cgi-bin/intercept-https-connects', 'application/x-www-form-urlencoded',
    'interceptHttpsConnects=1');
  const report = [];
  let ran = 0;
  for (const c of CASES) {
    await setRules(c.rules);
    const answers = {};
    for (const [who, port] of [['whistle', W], ['rs', RS]]) {
      const before = accepted;
      let got;
      try {
        got = await fetch(port, c.client, c.requests || 1);
      } catch (e) {
        got = { spoken: `failed: ${e.message}`, bodies: [] };
      }
      answers[who] = answer(got, accepted - before);
    }
    ran++;
    const problems = Object.keys(answers.whistle)
      .filter((k) => answers.whistle[k] !== answers.rs[k])
      .map((k) => `${k}: whistle=${JSON.stringify(answers.whistle[k])} rs=${JSON.stringify(answers.rs[k])}`);
    if (problems.length) report.push({ name: c.name, rules: c.rules, problems });
  }
  await setRules('');
  origin.close();
  const verdict = judge('h2-bench.js', report, CASES.map((c) => c.name));
  console.log(JSON.stringify({
    ran,
    differing: verdict.news.length,
    declared: verdict.declared,
    stale: verdict.stale,
    report: verdict.news,
    raw: report.map(({ name, problems }) => ({ name, problems })),
  }, null, 2));
  process.exitCode = verdict.news.length || verdict.stale.length ? 1 : 0;
  // Sessions the proxies keep open to the origin would hold the process.
  setTimeout(() => process.exit(), 100).unref();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
