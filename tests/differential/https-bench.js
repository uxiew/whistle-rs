// The same rules over an **HTTPS** origin, through both proxies' MITM.
//
// The plain bench speaks HTTP end to end, so nothing it runs exercises CONNECT,
// certificate forging, SNI, or the `https://` half of pattern matching. This
// does: it opens a real tunnel through each proxy, trusting that proxy's own
// root CA, and compares the decrypted exchange.
//
// Each proxy gets its own CA, so the two clients trust different roots — that is
// the one asymmetry here and it is unavoidable. Everything else is identical.
//
//   PORT_BASE=19600 node https-bench.js
//     19600 whistle · 19601 whistle-rs · 19602 the TLS origin

const https = require('https');
const http = require('http');
const tls = require('tls');
const fs = require('fs');
const { execSync } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 19600);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const KEY = '/tmp/diff-https-key.pem';
const CRT = '/tmp/diff-https-crt.pem';

/** A self-signed certificate for `localhost`, made once. */
function ensureCert() {
  if (fs.existsSync(KEY) && fs.existsSync(CRT)) return;
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${KEY} -out ${CRT} -days 2 -nodes ` +
      `-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null`,
  );
}

/** The TLS origin: echoes what reached it, and what the connection looked like. */
function startOrigin() {
  return new Promise((res) => {
    const srv = https.createServer(
      { key: fs.readFileSync(KEY), cert: fs.readFileSync(CRT) },
      (q, r) => {
        let body = '';
        q.on('data', (c) => (body += c));
        q.on('end', () => {
          r.writeHead(200, { 'content-type': 'application/json', 'x-origin': 'tls' });
          r.end(JSON.stringify({ method: q.method, url: q.url, headers: q.headers, body }));
        });
      },
    );
    srv.listen(ORIGIN, () => res(srv));
  });
}

const post = (port, path, body, type) =>
  new Promise((res, rej) => {
    const req = http.request(
      { port, path, method: 'POST', headers: { 'content-type': type, 'content-length': Buffer.byteLength(body) } },
      (r) => { let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => res(b)); },
    );
    req.on('error', rej);
    req.end(body);
  });

const get = (port, path) =>
  new Promise((res, rej) => {
    const req = http.get({ port, path }, (r) => {
      const c = []; r.on('data', (x) => c.push(x)); r.on('end', () => res(Buffer.concat(c)));
    });
    req.on('error', rej);
  });

async function setRules(text) {
  await post(W, '/cgi-bin/rules/add',
    'name=Default&selected=1&value=' + encodeURIComponent(text),
    'application/x-www-form-urlencoded');
  await post(RS, '/api/rules', text, 'text/plain');
  await new Promise((r) => setTimeout(r, 150));
}

/**
 * One HTTPS request through one proxy: CONNECT, then TLS inside the tunnel,
 * then an ordinary request. `ca` is the proxy's root, so a forged certificate
 * verifies and an un-intercepted one does not — which is itself a signal.
 */
function throughTunnel(port, ca, { method = 'GET', path = '/echo', headers = {} } = {}) {
  return new Promise((resolve) => {
    const done = (v) => resolve(v);
    const req = http.request({
      port, host: '127.0.0.1', method: 'CONNECT', path: `localhost:${ORIGIN}`,
    });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return done({ status: 0, note: `CONNECT ${res.statusCode}` }); }
      const secure = tls.connect({ socket, servername: 'localhost', ca }, () => {
        // The tunnel's socket is already decrypted, so what travels inside it
        // is plain HTTP. `https.request` would negotiate TLS a second time on
        // top of it — which fails as `EPROTO`, identically in both proxies, and
        // therefore looks like agreement.
        const inner = http.request({
          createConnection: () => secure, method, path,
          headers: { host: `localhost:${ORIGIN}`, ...headers },
        }, (r) => {
          const c = [];
          r.on('data', (x) => c.push(x));
          r.on('end', () => {
            secure.destroy();
            done({ status: r.statusCode, headers: r.headers, body: Buffer.concat(c).toString() });
          });
        });
        inner.on('error', (e) => { secure.destroy(); done({ status: 0, note: 'inner ' + e.code }); });
        inner.end();
      });
      secure.on('error', (e) => done({ status: 0, note: 'tls ' + e.code }));
    });
    req.on('error', (e) => done({ status: 0, note: 'connect ' + e.code }));
    req.setTimeout(8000, () => { req.destroy(); done({ status: 0, note: 'timeout' }); });
    req.end();
  });
}

const IGNORE = new Set([
  'date', 'connection', 'keep-alive', 'proxy-connection',
  'transfer-encoding', 'content-length', 'host', 'user-agent', 'accept',
  'accept-encoding', 'x-server',
]);
const norm = (h) => Object.fromEntries(
  Object.entries(h || {})
    .filter(([k]) => !IGNORE.has(k.toLowerCase()) && !k.toLowerCase().startsWith('x-whistle'))
    .map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v)]),
);

/**
 * The one deliberate difference, same as the plain bench's: whistle has
 * `notAllowCache` and never reaches it, so its own body rewrite vanishes on a
 * browser reload. This port busts the cache and is better for it.
 */
const EXPECTED = (p) =>
  /req\.header\.(pragma|cache-control): whistle=undefined rs="no-cache"/.test(p);

const show = (v) => JSON.stringify(v);

function compare(w, rs) {
  const out = [];
  if (w.status !== rs.status) out.push(`status: whistle=${w.status}${w.note ? ` (${w.note})` : ''} rs=${rs.status}${rs.note ? ` (${rs.note})` : ''}`);
  const [wh, rh] = [norm(w.headers), norm(rs.headers)];
  for (const k of new Set([...Object.keys(wh), ...Object.keys(rh)])) {
    if (show(wh[k]) !== show(rh[k])) out.push(`res.header.${k}: whistle=${show(wh[k])} rs=${show(rh[k])}`);
  }
  const [wb, rb] = [w.body, rs.body].map((b) => { try { return JSON.parse(b); } catch { return null; } });
  if (wb && rb) {
    if (wb.method !== rb.method) out.push(`req.method: whistle=${wb.method} rs=${rb.method}`);
    if (wb.url !== rb.url) out.push(`req.url: whistle=${wb.url} rs=${rb.url}`);
    if (wb.body !== rb.body) out.push(`req.body: whistle=${show(wb.body)} rs=${show(rb.body)}`);
    const [whh, rhh] = [norm(wb.headers), norm(rb.headers)];
    for (const k of new Set([...Object.keys(whh), ...Object.keys(rhh)])) {
      if (show(whh[k]) !== show(rhh[k])) out.push(`req.header.${k}: whistle=${show(whh[k])} rs=${show(rhh[k])}`);
    }
  } else if (w.body !== rs.body) {
    out.push(`res.body: whistle=${show((w.body || '').slice(0, 120))} rs=${show((rs.body || '').slice(0, 120))}`);
  }
  return out;
}

async function main() {
  ensureCert();
  const origin = await startOrigin();
  const O = `localhost:${ORIGIN}`;
  const wCa = await get(W, '/cgi-bin/rootca');
  const rsCa = await get(RS, '/rootCA.crt');

  const CASES = [
    { name: 'baseline: no rule', rules: '' },
    { name: 'reqHeaders over TLS', rules: `${O} reqHeaders://x-a=1` },
    { name: 'resHeaders over TLS', rules: `${O} resHeaders://x-r=1` },
    { name: 'resReplace over TLS', rules: `${O} resReplace://tls=TLS` },
    { name: 'ua over TLS', rules: `${O} ua://Probe/1` },
    { name: 'method over TLS', rules: `${O} method://PUT` },
    { name: 'urlParams over TLS', rules: `${O} urlParams://a=1` },
    { name: 'statusCode short-circuits a tunnel', rules: `${O} statusCode://204` },
    { name: 'file mock inside a tunnel', rules: `${O} file://({"mock":true})` },
    // Pattern forms that only mean something once a scheme exists.
    { name: 'https:// pattern matches', rules: `https://${O} reqHeaders://x-s=1` },
    { name: 'http:// pattern must not match', rules: `http://${O} reqHeaders://x-s=1` },
    { name: 'scheme-less pattern matches https', rules: `${O}/echo reqHeaders://x-s=1` },
    { name: '$ exact over TLS', rules: `$https://${O}/echo reqHeaders://x-e=1` },
    { name: '$ exact rejects a sub-path over TLS', rules: `$https://${O}/echo reqHeaders://x-e=1`, request: { path: '/echo/sub' } },
    // Conditions that read connection facts only a tunnel has.
    { name: 'includeFilter from:tunnel', rules: `${O} reqHeaders://x-f=1 includeFilter://from:tunnel` },
    { name: 'includeFilter on a request header over TLS', rules: `${O} reqHeaders://x-f=1 includeFilter://reqH.x-tag:yes`, request: { headers: { 'x-tag': 'yes' } } },
    { name: 'disable://cookie over TLS', rules: `${O} disable://cookie`, request: { headers: { cookie: 'sid=secret' } } },
    { name: 'delete reqHeaders over TLS', rules: `${O} reqHeaders://x-a=1 delete://reqHeaders.x-a` },
  ];

  // A hard baseline. Two proxies that both fail identically compare *equal*,
  // and that is how this bench first reported "18 cases, 0 differences" while
  // every tunnel was dying of `EPROTO`. Nothing below runs until a plain
  // request really works through both.
  {
    await setRules('');
    const [w, rs] = [await throughTunnel(W, wCa), await throughTunnel(RS, rsCa)];
    for (const [who, r] of [['whistle', w], ['whistle-rs', rs]]) {
      if (r.status !== 200 || !r.body || !r.body.includes('"url"')) {
        console.error(`baseline failed for ${who}: ${JSON.stringify(r).slice(0, 200)}`);
        process.exit(1);
      }
    }
  }

  let ran = 0, differing = 0;
  const report = [];
  for (const c of CASES) {
    await setRules(c.rules);
    const [w, rs] = [
      await throughTunnel(W, wCa, c.request),
      await throughTunnel(RS, rsCa, c.request),
    ];
    ran++;
    const problems = compare(w, rs).filter((p) => !EXPECTED(p));
    if (problems.length) { differing++; report.push({ name: c.name, rules: c.rules, problems }); }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
