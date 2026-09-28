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
const http2 = require('http2');
const fs = require('fs');
const { execSync } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 19600);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
// In `run.js`'s scratch directory when it sets one, so the key goes with the run.
const CERT_DIR = process.env.DIFF_STATE || '/tmp';
const KEY = `${CERT_DIR}/diff-https-key.pem`;
const CRT = `${CERT_DIR}/diff-https-crt.pem`;

/**
 * A self-signed certificate for `localhost`, reused while it is under a day old.
 *
 * It is valid for two days, and this used to check only that the files existed,
 * so a `/tmp` left from last week served an expired one. Neither proxy verifies
 * this origin today (whistle by default, whistle-rs under `--insecure-upstream`),
 * so nothing failed — but that is a launch flag away from every case failing on
 * the handshake for a reason that has nothing to do with the case.
 */
function ensureCert() {
  const fresh = (file) => fs.existsSync(file) && Date.now() - fs.statSync(file).mtimeMs < 24 * 3600 * 1000;
  if (fresh(KEY) && fresh(CRT)) return;
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
          // `tls` is the version the *proxy* negotiated with this origin, which
          // is the only place `cipher://` / `tlsOptions://` is observable at
          // all: nothing about a version pin reaches the client. Without it a
          // case that pins a version and a case that pins nothing look the same.
          r.end(JSON.stringify({
            method: q.method, url: q.url, headers: q.headers, body,
            tls: q.socket.getProtocol(),
            // And the **suite**, without which the `ciphers` half of
            // `cipher://` is not observable at all: a version pin shows in
            // `tls`, but a rule that names one suite and a rule that names
            // another negotiate the same version and compared equal. Every
            // `ciphers` case here was inert until this line existed.
            suite: q.socket.getCipher && q.socket.getCipher().name,
          }));
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
function throughTunnel(port, ca, { method = 'GET', path = '/echo', headers = {}, authority } = {}) {
  return new Promise((resolve) => {
    const done = (v) => resolve(v);
    // `authority` names somewhere other than the origin — which the console
    // hostnames need, because nothing is listening where they point and the
    // proxy is supposed to answer for them itself.
    const target = authority || `localhost:${ORIGIN}`;
    const req = http.request({
      port, host: '127.0.0.1', method: 'CONNECT', path: target,
    });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return done({ status: 0, note: `CONNECT ${res.statusCode}` }); }
      const secure = tls.connect({ socket, servername: target.split(':')[0], ca }, () => {
        // The tunnel's socket is already decrypted, so what travels inside it
        // is plain HTTP. `https.request` would negotiate TLS a second time on
        // top of it — which fails as `EPROTO`, identically in both proxies, and
        // therefore looks like agreement.
        const inner = http.request({
          createConnection: () => secure, method, path,
          headers: { host: target, ...headers },
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

/**
 * **Who signed the certificate?** — the only way to see whether a proxy read a
 * connection or passed it through.
 *
 * `throughTunnel` cannot answer it: it verifies against the proxy's own root, so
 * an un-intercepted connection is a TLS error and every un-intercepted
 * connection looks like every other failure. This one accepts any certificate
 * and reports the issuer, so "forged" and "the origin's own" are two readable
 * answers rather than one error.
 */
function issuerThroughTunnel(port, authority, servername) {
  return new Promise((resolve) => {
    const req = http.request({ port, host: '127.0.0.1', method: 'CONNECT', path: authority });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return resolve(`CONNECT ${res.statusCode}`); }
      const opts = { socket, rejectUnauthorized: false };
      if (servername) opts.servername = servername;
      const s = tls.connect(opts, () => {
        const cert = s.getPeerCertificate();
        const cn = (cert && cert.issuer && cert.issuer.CN) || '?';
        s.destroy();
        // Each proxy's root has its own name, so the answer is normalised to
        // the only distinction that matters: did *this* proxy sign it.
        resolve(cn === 'ipcap-origin' || cn === 'localhost' ? 'the origin\'s own' : 'forged by the proxy');
      });
      s.on('error', (e) => resolve('tls ' + e.code));
    });
    req.on('error', (e) => resolve('connect ' + e.code));
    req.setTimeout(8000, () => { req.destroy(); resolve('timeout'); });
    req.end();
  });
}

/**
 * A tunnel that is **not** TLS. Opens `CONNECT`, writes `payload` in the clear,
 * and reports the first line and body of whatever comes back.
 *
 * A tunnel is opened to an address, not to a protocol: a client may put
 * cleartext HTTP, an HTTP/2 preface, or somebody else's protocol entirely
 * through it. Upstream sniffs the first chunk and branches three ways
 * (`_original/lib/https/index.js:1176-1221`), and nothing else in this bench
 * looks at the other two branches.
 */
function plainThroughTunnel(port, authority, payload) {
  return new Promise((resolve) => {
    const req = http.request({ port, host: '127.0.0.1', method: 'CONNECT', path: authority });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return resolve(`CONNECT ${res.statusCode}`); }
      let out = '';
      socket.setTimeout(5000, () => { socket.destroy(); resolve(out ? 'partial: ' + out.slice(0, 80) : 'nothing came back'); });
      socket.on('data', (d) => { out += d.toString(); });
      socket.on('close', () => resolve(
        out ? out.split('\r\n')[0] + ' | ' + (out.split('\r\n\r\n')[1] || '').slice(0, 120) : 'closed with nothing'));
      socket.on('error', (e) => resolve('socket ' + e.code));
      socket.write(payload);
    });
    req.on('error', (e) => resolve('connect ' + e.code));
    req.setTimeout(8000, () => { req.destroy(); resolve('timeout'); });
    req.end();
  });
}

/**
 * Cleartext **HTTP/2** inside a tunnel: the `PRI * HTTP/2.0` preface, which
 * upstream hands to an h2 server of its own (`getHttp2Server`,
 * `_original/lib/https/index.js:1274-1276`). Nothing else here reaches that
 * branch, and this port used to answer it with a TLS alert.
 */
function h2ThroughTunnel(port, authority) {
  return new Promise((resolve) => {
    const req = http.request({ port, host: '127.0.0.1', method: 'CONNECT', path: authority });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return resolve(`CONNECT ${res.statusCode}`); }
      let done = false;
      const fin = (v) => {
        if (done) return;
        done = true;
        try { client.close(); } catch { /* already gone */ }
        try { socket.destroy(); } catch { /* already gone */ }
        resolve(v);
      };
      const client = http2.connect('http://probe.test', { createConnection: () => socket });
      client.on('error', (e) => fin('h2 ' + e.code));
      const st = client.request({ ':method': 'GET', ':path': '/echo' });
      let body = '';
      st.on('response', (h) => {
        st.on('data', (d) => { body += d; });
        st.on('end', () => fin(`${h[':status']} | ${body.slice(0, 120)}`));
      });
      st.on('error', (e) => fin('stream ' + e.code));
      setTimeout(() => fin('timeout'), 6000);
      st.end();
    });
    req.on('error', (e) => resolve('connect ' + e.code));
    req.setTimeout(8000, () => { req.destroy(); resolve('timeout'); });
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
 * The deliberate differences.
 *
 * 1. whistle has `notAllowCache` and never reaches it, so its own body rewrite
 *    vanishes on a browser reload. This port busts the cache and is better for
 *    it.
 * 2. A `cipher://` / `tlsOptions://` version pin is **inert upstream on a
 *    connection that works**. whistle builds the options in `getTlsOptions`
 *    (`_original/lib/rules/index.js:680-733`) but only ever extends the socket
 *    options with them while *retrying a ciphers error*
 *    (`lib/inspectors/res.js:495-497`, `lib/util/common.js:1769-1771`); the
 *    first, successful handshake never sees them. A bare `tlsOptions://TLSv1.2`
 *    does not even get that far — `SEP_CIPHER_RE = /[^a-z\d:!-]/i` rejects the
 *    dot, so it is not read as a cipher string, and it is not JSON either.
 *    whistle-rs applies the pin on the first attempt, which is what the rule
 *    says it does. Declared in `docs/RULES.md`.
 * 3. The **suite** half is inert upstream for the same reason, and it only
 *    became visible when the origin started echoing `getCipher().name` — before
 *    that, a rule naming one suite and a rule naming another negotiated the same
 *    version and compared equal, so every `ciphers` case here was proving
 *    nothing. Measured across the family: whistle stays on the origin's default
 *    `TLS_AES_256_GCM_SHA384` whatever the rule says, and whistle-rs negotiates
 *    the suite that was asked for.
 *
 *    Narrow on purpose — it excuses a difference only where whistle sat on the
 *    default. Two proxies that both pin, and pin differently, is news.
 */
const EXPECTED = (p) =>
  /req\.header\.(pragma|cache-control): whistle=undefined rs="no-cache"/.test(p)
  || /req\.tls: whistle="TLSv1\.3" rs="TLSv1\.2"/.test(p)
  || /req\.suite: whistle="TLS_AES_256_GCM_SHA384" rs="[\w-]+"/.test(p);

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
    if (wb.tls !== rb.tls) out.push(`req.tls: whistle=${show(wb.tls)} rs=${show(rb.tls)}`);
    if (wb.suite !== rb.suite) out.push(`req.suite: whistle=${show(wb.suite)} rs=${show(rb.suite)}`);
    const [whh, rhh] = [norm(wb.headers), norm(rb.headers)];
    for (const k of new Set([...Object.keys(whh), ...Object.keys(rhh)])) {
      if (show(whh[k]) !== show(rhh[k])) out.push(`req.header.${k}: whistle=${show(whh[k])} rs=${show(rhh[k])}`);
    }
  } else if (w.body !== rs.body) {
    out.push(`res.body: whistle=${show((w.body || '').slice(0, 120))} rs=${show((rs.body || '').slice(0, 120))}`);
  }
  return out;
}

/**
 * Compare two tunnel answers the way `compare` does for the ordinary cases:
 * status and body, with the hop-by-hop and framing headers dropped.
 *
 * The echo the origin returns contains the request headers it was given, so a
 * raw string compare would fail on exactly the names `IGNORE` exists to
 * excuse — `connection`, which whistle stamps on the forwarded request and
 * hyper does not, and `host`, which whistle rewrites to the tunnel's authority
 * while this port forwards the `:authority` the client sent.
 */
function sameTunnelAnswer(a, b) {
  const strip = (s) => {
    const cut = s.indexOf('{');
    if (cut === -1) return s;
    try {
      const o = JSON.parse(s.slice(cut));
      if (o && o.headers) {
        o.headers = Object.fromEntries(
          Object.entries(o.headers).filter(([k]) => !IGNORE.has(k.toLowerCase())),
        );
      }
      return s.slice(0, cut) + JSON.stringify(o);
    } catch {
      return s;
    }
  };
  return strip(a) === strip(b);
}

async function main() {
  ensureCert();
  const origin = await startOrigin();
  const O = `localhost:${ORIGIN}`;
  const wCa = await get(W, '/cgi-bin/rootca');
  const rsCa = await get(RS, '/rootCA.crt');

  // **whistle does not decrypt HTTPS until it is told to.** `Enable HTTPS` in
  // its console is off in a fresh data directory, and with it off
  // `isEnableIntercept` only intercepts hosts that already have a custom
  // certificate (`_original/lib/tunnel.js:187-199`). whistle-rs intercepts by
  // default — a deliberate difference of posture, and `--no-intercept-https` is
  // its opt-out — so without this line every case below would be comparing
  // "whistle passed the connection through" against "this port read it".
  //
  // It went unnoticed because the origin here is `localhost`, which whistle
  // intercepts anyway. Any other name and this whole file would have been
  // measuring the switch rather than the rules. Measured, with a
  // `probe.test host://127.0.0.1` origin: with the switch off whistle forges
  // nothing at all; with it on, all ten certificate shapes below agree.
  await post(W, '/cgi-bin/intercept-https-connects', 'interceptHttpsConnects=1',
    'application/x-www-form-urlencoded');

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
    // The TLS knobs. `tlsOptions://` is an alias of `cipher://`
    // (`aliasProtocols`, `_original/lib/rules/protocols.js:149`), and the only
    // thing either of them changes is the handshake the proxy makes with the
    // **origin** — which is why the origin now echoes the version it got.
    { name: 'tlsOptions pins TLS 1.2', rules: `${O} tlsOptions://TLSv1.2` },
    { name: 'tlsOptions pins TLS 1.3', rules: `${O} tlsOptions://TLSv1.3` },
    { name: 'cipher is the same operator', rules: `${O} cipher://TLSv1.2` },
    { name: 'tlsOptions in its JSON form', rules: `${O} tlsOptions://{"maxVersion":"TLSv1.2"}` },
    { name: 'tlsOptions minVersion', rules: `${O} tlsOptions://{"minVersion":"TLSv1.3"}` },
    { name: 'a cipher list pins no version', rules: `${O} tlsOptions://{"ciphers":"ECDHE-RSA-AES128-GCM-SHA256"}` },
    // The query spelling `cipher.md` leads with, and the merge it documents:
    // `getTlsOptions` walks `cipher.list` and hands the lot to `parseRuleJson`
    // (`_original/lib/rules/index.js:684-691`), so several lines combine.
    { name: 'tlsOptions in its query form', rules: `${O} tlsOptions://maxVersion=TLSv1.2` },
    { name: 'tlsOptions query form, two keys', rules: `${O} tlsOptions://minVersion=TLSv1.3&maxVersion=TLSv1.3` },
    { name: 'two tlsOptions lines merge', rules: `${O} tlsOptions://maxVersion=TLSv1.2\n${O} tlsOptions://ciphers=ECDHE-RSA-AES128-GCM-SHA256` },
    { name: 'a bare cipher string on its own line', rules: `${O} tlsOptions://ECDHE-RSA-AES128-GCM-SHA256` },
    // Two suites, asked for one at a time. This is the pair that says the
    // `ciphers` half does anything at all: same version, different suite, and
    // before the origin echoed `suite` they were the same case twice.
    { name: 'a cipher list picks the suite it names', rules: `${O} tlsOptions://{"ciphers":"ECDHE-RSA-AES128-GCM-SHA256","maxVersion":"TLSv1.2"}` },
    { name: 'and a different one names a different suite', rules: `${O} tlsOptions://{"ciphers":"ECDHE-RSA-AES256-GCM-SHA384","maxVersion":"TLSv1.2"}` },
    // ── a value that selects no suite ──────────────────────────────────
    //
    // These used to **502** here while whistle answered: the pin failing took
    // the request with it. It takes only the pin now — see the note in
    // `src/proxy/ciphers.rs`, which is where the reasoning lives. `3DES` is the
    // case that decides it: a perfectly good OpenSSL string that this build
    // cannot honour because rustls has no 3DES, so failing the request would be
    // putting a limitation of the build into somebody's traffic.
    { name: 'tlsOptions with nonsense in it', rules: `${O} tlsOptions://not-a-version` },
    { name: 'a cipher string this build cannot honour', rules: `${O} tlsOptions://{"ciphers":"3DES"}` },
    { name: 'a cipher string that selects nothing', rules: `${O} tlsOptions://{"ciphers":"NOTACIPHER"}` },
    { name: 'a cipher string that excludes everything', rules: `${O} tlsOptions://{"ciphers":"!ALL"}` },
    // The two halves are read independently, so an unusable cipher string does
    // not take a usable version with it. Upstream applies neither.
    { name: 'an unusable cipher string beside a usable version', rules: `${O} tlsOptions://{"ciphers":"NOTACIPHER","maxVersion":"TLSv1.2"}` },
    // `sniCallback://` asks a *plugin* which certificate to present, or whether
    // to intercept at all (`_original/lib/https/load-cert.js:8-17`). Naming a
    // plugin that is not installed leaves the connection exactly as it was.
    { name: 'sniCallback naming no plugin', rules: `${O} sniCallback://nosuchplugin` },
    { name: 'sniCallback with the whistle. prefix', rules: `${O} sniCallback://whistle.nosuchplugin` },
    { name: 'sniCallback with a value', rules: `${O} sniCallback://nosuchplugin(staging)` },
    { name: 'sniCallback next to a rule that fires', rules: `${O} sniCallback://nosuchplugin reqHeaders://x-a=1` },
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

  // ── which connections get read at all ──────────────────────────────────
  //
  // Everything above asks what a rule did to a request *inside* a tunnel, which
  // presupposes the tunnel was opened. Whether it is opened is a decision of its
  // own, and upstream makes it from what the ClientHello named: a CONNECT to a
  // **bare IP** whose ClientHello carried no server name is not decrypted
  // (`net.isIP(servername) && !isCaptureIp()`,
  // `_original/lib/https/index.js:1287`). TLS forbids an IP in SNI, so a client
  // asking for `https://127.0.0.1/` produces exactly that shape — and this port
  // used to read it.
  //
  // `localhost` and `127.0.0.1` are the same origin here, reached two ways, so
  // the pair isolates the one variable.
  // `probe.test`, not `localhost`. **whistle intercepts a local host whatever
  // the rules say** — `disable://intercept` on `localhost` is ignored there, and
  // measured to be: with the authority `probe.test` and a
  // `host://127.0.0.1:<origin>` line to reach the same server, the same flag
  // relays. Every named case below therefore travels under a name whistle has no
  // opinion about, and reaches the origin by a rule rather than by DNS.
  const N = 'probe.test';
  const H = `${N} host://127.0.0.1:${ORIGIN}\n`;
  const CERT_CASES = [
    { name: 'cert: a name, with SNI, is read', rules: H, authority: `${N}:443`, servername: N },
    { name: 'cert: a name, no SNI, is read too', rules: H, authority: `${N}:443` },
    { name: 'cert: a bare IP with no SNI is not', rules: '', authority: `127.0.0.1:${ORIGIN}` },
    { name: 'cert: enable://capture reads the bare IP', rules: `127.0.0.1:${ORIGIN} enable://capture`, authority: `127.0.0.1:${ORIGIN}` },
    { name: 'cert: enable://captureIp reads it', rules: `127.0.0.1:${ORIGIN} enable://captureIp`, authority: `127.0.0.1:${ORIGIN}` },
    { name: 'cert: enable://captureIP is the same flag', rules: `127.0.0.1:${ORIGIN} enable://captureIP`, authority: `127.0.0.1:${ORIGIN}` },
    { name: 'cert: disable://captureIp refuses even then', rules: `127.0.0.1:${ORIGIN} enable://capture disable://captureIp`, authority: `127.0.0.1:${ORIGIN}` },
    { name: 'cert: disable://captureSNI drops the named half', rules: `${H}${N} disable://captureSNI`, authority: `${N}:443`, servername: N },
    { name: 'cert: disable://captureSNI spares the other half', rules: `${H}${N} disable://captureSNI`, authority: `${N}:443` },
    { name: 'cert: disable://captureNoSNI drops the unnamed half', rules: `${H}${N} disable://captureNoSNI`, authority: `${N}:443` },
    { name: 'cert: disable://captureNoSNI spares the named half', rules: `${H}${N} disable://captureNoSNI`, authority: `${N}:443`, servername: N },
    { name: 'cert: disable://intercept relays whatever was named', rules: `${H}${N} disable://intercept`, authority: `${N}:443`, servername: N },
  ];
  for (const c of CERT_CASES) {
    await setRules(c.rules);
    const [w, rs] = [
      await issuerThroughTunnel(W, c.authority, c.servername),
      await issuerThroughTunnel(RS, c.authority, c.servername),
    ];
    ran++;
    if (w !== rs) {
      differing++;
      report.push({ name: c.name, rules: c.rules, problems: [`certificate: whistle=${w} rs=${rs}`] });
    }
  }

  // ── what the tunnel is carrying ────────────────────────────────────────
  //
  // A plain HTTP origin, reached through a `CONNECT` that never speaks TLS.
  // This port used to hand every tunnel to its TLS acceptor, so a client that
  // tunnelled anything else got a TLS alert where whistle gave it an answer.
  const plain = http.createServer((q, r) => {
    r.setHeader('content-type', 'application/json');
    r.end(JSON.stringify({ url: q.url, headers: q.headers }));
  });
  await new Promise((r) => plain.listen(ORIGIN + 1, r));
  const PH = `${N} host://127.0.0.1:${ORIGIN + 1}\n`;
  const GET = 'GET /echo HTTP/1.1\r\nHost: probe.test\r\nConnection: close\r\n\r\n';
  const PLAIN_CASES = [
    { name: 'tunnel: cleartext HTTP is read', rules: PH, payload: GET },
    { name: 'tunnel: cleartext HTTP takes its rules', rules: `${PH}${N} reqHeaders://x-a=1`, payload: GET },
    { name: 'tunnel: enable://forHttps passes cleartext through', rules: `${PH}${N} enable://forHttps reqHeaders://x-a=1`, payload: GET },
    { name: 'tunnel: disable://captureHttp passes it through too', rules: `${PH}${N} disable://captureHttp reqHeaders://x-a=1`, payload: GET },
    { name: 'tunnel: neither HTTP nor TLS is relayed', rules: PH, payload: Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]) },
    // `\w+`, not a list of methods — the classifier accepts one nobody has
    // registered. The explicit `Content-Length: 0` is not part of the question:
    // without it the two proxies frame the body-less request differently (Node's
    // client stamps `content-length: 0`, hyper omits it, and both mean "no
    // body"), which would hide the classification behind a framing detail.
    { name: 'tunnel: an unknown method is still HTTP', rules: `${PH}${N} reqHeaders://x-a=1`,
      payload: 'PROPFIND /echo HTTP/1.1\r\nHost: probe.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' },
  ];
  for (const c of PLAIN_CASES) {
    await setRules(c.rules);
    const [w, rs] = [
      await plainThroughTunnel(W, `${N}:80`, c.payload),
      await plainThroughTunnel(RS, `${N}:80`, c.payload),
    ];
    ran++;
    if (!sameTunnelAnswer(w, rs)) {
      differing++;
      report.push({ name: c.name, rules: c.rules, problems: [`answer: whistle=${w} rs=${rs}`] });
    }
  }
  for (const c of [
    { name: 'tunnel: cleartext HTTP/2 is read', rules: PH },
    { name: 'tunnel: cleartext HTTP/2 takes its rules', rules: `${PH}${N} reqHeaders://x-a=1` },
  ]) {
    await setRules(c.rules);
    const [w, rs] = [
      await h2ThroughTunnel(W, `${N}:80`),
      await h2ThroughTunnel(RS, `${N}:80`),
    ];
    ran++;
    if (!sameTunnelAnswer(w, rs)) {
      differing++;
      report.push({ name: c.name, rules: c.rules, problems: [`answer: whistle=${w} rs=${rs}`] });
    }
  }
  plain.close();

  // ── the console's own hostnames, inside a tunnel ──────────────────────
  //
  // `local.whistlejs.com` and `rootca.pro` are the console and the certificate
  // over **plain HTTP** — `auth-bench.js` measures that half. They are also
  // both over TLS, inside the proxy's own MITM: upstream forges a certificate
  // for the name and then answers from the console behind it, which is what a
  // phone does when it opens `https://rootca.pro/` with the proxy set and no
  // certificate installed yet.
  //
  // Compared on status and content type. The two consoles serve two different
  // pages and the two proxies have two different roots, so the bytes were never
  // going to match; whether the tunnel opened and what kind of thing came out
  // of it is the question.
  //
  // The `Host` header is spelled the way a browser spells it — **without the
  // default port** — and for `rootca.pro` that is not a detail. Upstream reads
  // the header and does not strip `:443` from it, so `Host: rootca.pro` gets the
  // certificate at any path while `Host: rootca.pro:443` gets the console at `/`
  // and a 404 anywhere else. Measured all four ways. The last case below pins
  // that, and `EXPECTED` excuses it: a `Host` carrying the scheme's default port
  // is the same host (RFC 7230 §5.4), this port keys off the authority the
  // `CONNECT` named, and answering two different things to two spellings of one
  // name is not a behaviour to reproduce.
  let declaredHostPort = null;
  for (const [name, authority, path, host] of [
    ['tunnel: the console hostname', 'local.whistlejs.com:443', '/'],
    ['tunnel: the console hostname, a sub-path', 'local.whistlejs.com:443', '/index.html'],
    ['tunnel: the other console hostname', 'local.wproxy.org:443', '/'],
    ['tunnel: the certificate hostname', 'rootca.pro:443', '/', 'rootca.pro'],
    ['tunnel: the certificate hostname, any path', 'rootca.pro:443', '/whatever', 'rootca.pro'],
    ['tunnel: the certificate hostname, Host with :443', 'rootca.pro:443', '/whatever'],
  ]) {
    const opts = { authority, path };
    if (host) opts.headers = { host };
    const [w, rs] = [
      await throughTunnel(W, wCa, opts),
      await throughTunnel(RS, rsCa, opts),
    ];
    ran++;
    const type = (r) => (r.headers && r.headers['content-type'] || '').split(';')[0];
    const problems = [];
    if (w.status !== rs.status) {
      problems.push(`status: whistle=${w.status}${w.note ? ` (${w.note})` : ''} `
        + `rs=${rs.status}${rs.note ? ` (${rs.note})` : ''}`);
    }
    if (type(w) !== type(rs)) problems.push(`content-type: whistle=${type(w)} rs=${type(rs)}`);
    // Declared here rather than in `EXPECTED`, which is given a problem string
    // and not a case: `status: whistle=404 rs=200` written there would excuse
    // that shape everywhere, and it earns an excuse in exactly one case.
    if (problems.length && /Host with :443/.test(name)) {
      declaredHostPort = problems;
    } else if (problems.length) {
      differing++;
      report.push({ name, rules: authority + path, problems });
    }
  }
  if (!declaredHostPort) {
    // The quirk is declared, so its *absence* is news too — upstream may have
    // fixed it, and this port would then be excusing nothing.
    differing++;
    report.push({
      name: 'tunnel: the certificate hostname, Host with :443',
      problems: ['the declared `Host: rootca.pro:443` divergence did not happen'],
    });
  }

  // ── which suite a pin actually produces ────────────────────────────────
  //
  // **One-sided, and it has to be.** Everything above compares two proxies, and
  // upstream applies none of this — so a `ciphers` case can only ever report
  // "whistle-rs pinned something and whistle did not", which is excused and
  // says nothing about whether the suite was the *right* one. These ask that
  // directly: name a suite, read back what the origin negotiated.
  //
  // It is the only claim in this file that would survive whistle disappearing,
  // and it is the one the `ciphers` evaluator is actually for.
  for (const suite of ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305']) {
    await setRules(`${O} tlsOptions://{"ciphers":"${suite}","maxVersion":"TLSv1.2"}`);
    const got = await throughTunnel(RS, rsCa);
    ran++;
    let negotiated;
    try { negotiated = JSON.parse(got.body).suite; } catch (e) { negotiated = got.note || 'unparseable'; }
    if (negotiated !== suite) {
      differing++;
      report.push({
        name: `whistle-rs negotiates the suite it was told to`,
        rules: `${O} tlsOptions://{"ciphers":"${suite}",…}`,
        problems: [`suite: asked for ${suite}, got ${negotiated}`],
      });
    }
  }
  // And the other half of the claim: a string that selects nothing leaves the
  // connection **unpinned and alive**, rather than failing it. This is the case
  // that used to 502.
  for (const spec of ['NOTACIPHER', '3DES', '!ALL', 'not-a-version']) {
    await setRules(`${O} tlsOptions://{"ciphers":"${spec}"}`);
    const got = await throughTunnel(RS, rsCa);
    ran++;
    if (got.status !== 200) {
      differing++;
      report.push({
        name: 'a cipher string that selects nothing keeps the request',
        rules: `${O} tlsOptions://{"ciphers":"${spec}"}`,
        problems: [`status: ${got.status} ${got.note || ''} — the pin should fall, not the request`],
      });
    }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
  process.exitCode = differing ? 1 : 0;
}

main().catch((e) => { console.error(e); process.exit(1); });
