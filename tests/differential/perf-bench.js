// What a request through each proxy costs the network: how many connections
// and TLS handshakes the origin sees, how long requests take, how much memory
// the proxy holds, and whether a request the client gives up on lets go of its
// origin connection.
//
// A measurement, not a gate: nothing here passes or fails, and run.js does not
// run it. Numbers on loopback are noisy, so each figure is the median of
// several rounds, and the proxies take turns within every round so a slow
// moment on the machine lands on both.
//
//   cargo build --release
//   node perf-bench.js                   # loopback
//   RTT_MS=20 node perf-bench.js         # 20 ms round trip between proxy and origin
//   ONLY=h2,cancel-h2 node perf-bench.js # some scenarios; --json FILE writes the raw figures
//
//   PORT_BASE (20400) whistle · +1 whistle-rs · +2 http origin · +3 https origin
//   · +4/+5 the delay relays in front of them when RTT_MS is set
//
// **Why a relay.** On loopback a TCP or TLS handshake costs well under a
// millisecond, so a proxy that opens a connection per request looks as fast as
// one that reuses them — and on any real network it is not. `RTT_MS` puts a
// relay between proxy and origin that holds every chunk for half the round
// trip each way, and holds the first bytes of a new connection for one more
// round trip, which is what the TCP handshake costs before anything can be
// sent. It does not model loss, bandwidth or slow start.

'use strict';

const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const WHISTLE = require('./whistle-pkg');

const BASE = Number(process.env.PORT_BASE || 20400);
const PORTS = { whistle: BASE, rs: BASE + 1 };
const [ORIGIN_HTTP, ORIGIN_TLS, RELAY_HTTP, RELAY_TLS] = [BASE + 2, BASE + 3, BASE + 4, BASE + 5];
const RTT = Number(process.env.RTT_MS || 0);
const ROUNDS = Number(process.env.ROUNDS || 3);
const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'release', 'whistle-rs');
const ONLY = process.env.ONLY ? new Set(process.env.ONLY.split(',')) : null;
const PROXIES = (process.env.PROXIES || 'whistle,rs').split(',');
const JSON_OUT = (() => {
  const i = process.argv.indexOf('--json');
  return i > 0 ? process.argv[i + 1] : null;
})();
const HOST = '127.0.0.1';
const STATE = fs.mkdtempSync(path.join(process.env.DIFF_STATE || os.tmpdir(), 'perf-bench-'));

// Where the proxies are pointed: straight at the origins, or at the relays.
const HTTP_AT = RTT ? RELAY_HTTP : ORIGIN_HTTP;
const TLS_AT = RTT ? RELAY_TLS : ORIGIN_TLS;

const KIB = 1024;
const SMALL = Buffer.alloc(KIB, 'x');
const BIG = Buffer.alloc(32 * 1024 * KIB, 'y');

// ── the origins ───────────────────────────────────────────────────────────

/**
 * What the origins saw since the last `reset()`: connections opened, TLS
 * handshakes completed, h2 sessions, requests by protocol, and the moment each
 * streamed response was torn down (for the cancel scenarios).
 */
const seen = {
  reset() {
    Object.assign(this, { tcp: 0, tls: 0, h2sessions: 0, h1: 0, h2: 0, closed: new Map(), sockets: new Set() });
  },
};
seen.reset();
/** Origin sockets open right now, whoever opened them — for closing them at the end. */
const open = new Set();

function handler(q, r) {
  if (q.httpVersion === '2.0') seen.h2 += 1;
  else seen.h1 += 1;
  const url = new URL(q.url, 'http://x');
  if (url.pathname === '/big') {
    r.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': BIG.length });
    r.end(BIG);
  } else if (url.pathname === '/stream') {
    // Never ends by itself: the only way this response stops is the proxy
    // closing it, which is what the cancel scenarios time.
    const id = url.searchParams.get('id');
    r.writeHead(200, { 'content-type': 'application/octet-stream' });
    const tick = setInterval(() => r.write(SMALL), 20);
    r.write(SMALL);
    r.on('close', () => {
      clearInterval(tick);
      seen.closed.set(id, performance.now());
    });
  } else {
    r.writeHead(200, { 'content-type': 'text/plain', 'content-length': SMALL.length });
    r.end(SMALL);
  }
}

function track(server) {
  server.on('connection', (s) => {
    seen.tcp += 1;
    open.add(s);
    // The ones this scenario opened, so what is still open afterwards is this
    // proxy's and not left over from the other one's turn.
    const mine = seen.sockets;
    mine.add(s);
    s.on('close', () => {
      open.delete(s);
      mine.delete(s);
    });
  });
  return server;
}

function certificate() {
  const key = path.join(STATE, 'origin-key.pem');
  const crt = path.join(STATE, 'origin-crt.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', crt, '-days', '2', '-nodes',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

async function startOrigins() {
  const plain = track(http.createServer({ keepAliveTimeout: 30000 }, handler));
  // One server for both protocols, as most real HTTPS origins are: whichever
  // the proxy offers in its ALPN is the one it gets.
  const secure = track(http2.createSecureServer({ ...certificate(), allowHTTP1: true }, handler));
  secure.on('secureConnection', () => (seen.tls += 1));
  secure.on('session', () => (seen.h2sessions += 1));
  await Promise.all([
    new Promise((r) => plain.listen(ORIGIN_HTTP, HOST, r)),
    new Promise((r) => secure.listen(ORIGIN_TLS, HOST, r)),
  ]);
  const servers = [plain, secure];
  if (RTT) servers.push(await relay(RELAY_HTTP, ORIGIN_HTTP), await relay(RELAY_TLS, ORIGIN_TLS));
  return servers;
}

// ── the delay relay ───────────────────────────────────────────────────────

/** Forward `from` to `to`, each chunk arriving `oneWay` ms after it was sent, and none before `notBefore`. */
function delayed(from, to, oneWay, notBefore) {
  const queue = [];
  let last = 0;
  let timer = null;
  let ended = false;
  const flush = () => {
    timer = null;
    const now = performance.now();
    while (queue.length && queue[0].at <= now) {
      const { chunk } = queue.shift();
      if (chunk) to.write(chunk);
      else to.end();
    }
    if (queue.length) timer = setTimeout(flush, queue[0].at - now);
  };
  const push = (chunk) => {
    // Never earlier than the chunk before it: TCP delivers in order.
    last = Math.max(last, Math.max(performance.now(), notBefore) + oneWay);
    queue.push({ at: last, chunk });
    if (!timer) timer = setTimeout(flush, last - performance.now());
  };
  from.on('data', push);
  from.on('end', () => {
    if (!ended) push(null);
    ended = true;
  });
  from.on('close', () => setTimeout(() => to.destroy(), Math.max(0, last - performance.now()) + oneWay));
  from.on('error', () => {});
}

function relay(listen, target) {
  const oneWay = RTT / 2;
  const server = net.createServer((a) => {
    // The client's connect() has already returned — loopback — but on a real
    // network its first byte could not leave until SYN and SYN-ACK had crossed.
    const notBefore = performance.now() + RTT;
    const b = net.connect(target, HOST);
    delayed(a, b, oneWay, notBefore);
    delayed(b, a, oneWay, 0);
    b.on('error', () => a.destroy());
  });
  return new Promise((r) => server.listen(listen, HOST, () => r(server)));
}

// ── the proxies ───────────────────────────────────────────────────────────

function startProxy(which) {
  const port = PORTS[which];
  const dir = path.join(STATE, which);
  // whistle with `capture`, because it does not decrypt HTTPS by default and
  // this port does: without it the https scenarios would measure a tunnel on
  // one side and an interception on the other. Its origin certificate check is
  // off by default; whistle-rs's is on, hence `--insecure-upstream`.
  const child = which === 'whistle'
    ? spawn(process.execPath, ['-e', `
        require(${JSON.stringify(WHISTLE.dir)})(
          { port: ${port}, baseDir: ${JSON.stringify(dir)}, host: ${JSON.stringify(HOST)}, mode: 'capture' },
          () => console.log('READY'));
      `], { stdio: ['ignore', 'pipe', 'pipe'] })
    : spawn(RS_BIN, ['--port', String(port), '-H', HOST, '--dir', dir, '--no-persist', '--insecure-upstream'],
      { stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let done = false;
    const watch = (d) => {
      if (!done && /READY|listening on/.test(String(d))) {
        done = true;
        resolve(child);
      }
    };
    // Keep reading after it is up, or a chatty proxy blocks on a full pipe.
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', (code) => {
      if (!done) reject(new Error(`${which} exited (${code}) before listening`));
    });
    setTimeout(() => !done && reject(new Error(`${which} did not start in 30s`)), 30000);
  });
}

/** Resident memory of `pid`, in MiB. */
function rss(pid) {
  try {
    return Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8' }).trim()) / 1024;
  } catch {
    return NaN;
  }
}

/** TCP sockets `pid` holds open, listeners included. */
function sockets(pid) {
  try {
    const out = execFileSync('lsof', ['-nP', '-a', '-p', String(pid), '-iTCP'], { encoding: 'utf8' });
    return out.trim().split('\n').length - 1;
  } catch {
    return 0; // lsof exits 1 when nothing matches
  }
}

// ── the clients ───────────────────────────────────────────────────────────

/** A TLS connection to `host:port` through `proxy`'s CONNECT, offering `alpn`. */
function tunnel(proxy, host, port, alpn) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: HOST, port: proxy, method: 'CONNECT', path: `${host}:${port}`, headers: { host: `${host}:${port}` } });
    r.on('connect', (resp, sock) => {
      if (resp.statusCode !== 200) {
        sock.destroy();
        reject(new Error(`CONNECT answered ${resp.statusCode}`));
        return;
      }
      const s = tls.connect({ socket: sock, servername: host, ALPNProtocols: alpn, rejectUnauthorized: false }, () => resolve(s));
      s.on('error', reject);
    });
    r.on('error', reject);
    r.end();
  });
}

/**
 * An HTTP/1.1 client that keeps one connection to the proxy — plain, or a
 * CONNECT tunnel with TLS inside — and sends every request down it, as a
 * browser tab does to one host.
 */
function h1Client(proxy, secure) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  if (secure) {
    agent.createConnection = (_opts, done) => {
      tunnel(proxy, 'localhost', TLS_AT, ['http/1.1']).then((s) => done(null, s), done);
    };
  }
  const get = (p, { onFirstByte } = {}) => new Promise((resolve, reject) => {
    const started = performance.now();
    const opts = secure
      ? { agent, host: 'localhost', port: TLS_AT, path: p }
      : { agent, host: HOST, port: proxy, path: `http://127.0.0.1:${HTTP_AT}${p}`, headers: { host: `127.0.0.1:${HTTP_AT}` } };
    const req = http.request(opts, (res) => {
      let bytes = 0;
      res.on('data', (c) => {
        if (!bytes && onFirstByte) onFirstByte(req);
        bytes += c.length;
      });
      res.on('end', () => resolve({ ms: performance.now() - started, bytes, status: res.statusCode }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
  return { get, close: () => agent.destroy() };
}

/** An HTTP/2 client over one intercepted TLS connection, as a browser opens to an HTTPS host. */
async function h2Client(proxy) {
  const sock = await tunnel(proxy, 'localhost', TLS_AT, ['h2', 'http/1.1']);
  if (sock.alpnProtocol !== 'h2') throw new Error(`the proxy answered ${sock.alpnProtocol} to an h2 offer`);
  const session = http2.connect(`https://localhost:${TLS_AT}`, { createConnection: () => sock });
  session.on('error', () => {});
  const get = (p, { onFirstByte } = {}) => new Promise((resolve, reject) => {
    const started = performance.now();
    const stream = session.request({ ':path': p });
    let bytes = 0;
    let status = 0;
    stream.on('response', (h) => (status = h[':status']));
    stream.on('data', (c) => {
      if (!bytes && onFirstByte) onFirstByte(stream);
      bytes += c.length;
    });
    stream.on('end', () => resolve({ ms: performance.now() - started, bytes, status }));
    stream.on('error', reject);
    stream.end();
  });
  return { get, close: () => session.close() };
}

// ── the scenarios ─────────────────────────────────────────────────────────

const sum = (xs) => xs.reduce((a, b) => a + b, 0);
const quantile = (xs, q) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(s.length * q))];
};
const median = (xs) => quantile(xs, 0.5);

/** N small GETs, one after another, down one kept-alive client connection. */
function sequential(secure, n) {
  return async (proxy) => {
    const c = h1Client(proxy, secure);
    const times = [];
    for (let i = 0; i < n; i += 1) times.push((await c.get('/small')).ms);
    c.close();
    return { requests: n, p50: median(times), p95: quantile(times, 0.95), totalMs: sum(times) };
  };
}

/** A page load: `streams` concurrent GETs on one h2 client connection, `rounds` times. */
function pageLoads(streams, rounds) {
  return async (proxy) => {
    const c = await h2Client(proxy);
    const loads = [];
    const times = [];
    for (let i = 0; i < rounds; i += 1) {
      const started = performance.now();
      const all = await Promise.all(Array.from({ length: streams }, () => c.get('/small')));
      loads.push(performance.now() - started);
      times.push(...all.map((r) => r.ms));
    }
    c.close();
    return { requests: streams * rounds, p50: median(times), p95: quantile(times, 0.95), loadP50: median(loads), totalMs: sum(loads) };
  };
}

/** Big bodies, one after another, to see what the copy loop sustains. */
function download(secure, n) {
  return async (proxy) => {
    const c = h1Client(proxy, secure);
    const times = [];
    let bytes = 0;
    for (let i = 0; i < n; i += 1) {
      const r = await c.get('/big');
      times.push(r.ms);
      bytes += r.bytes;
    }
    c.close();
    return { requests: n, p50: median(times), MiBps: bytes / KIB / KIB / (sum(times) / 1000), totalMs: sum(times) };
  };
}

/**
 * A response the client abandons after its first bytes. What is timed is how
 * long the origin's response stays open afterwards — the connection, buffers
 * and task the proxy keeps for a client that has gone.
 */
function cancel(kind, n) {
  return async (proxy) => {
    const after = [];
    let unreleased = 0;
    for (let i = 0; i < n; i += 1) {
      const id = `${proxy}-${kind}-${i}-${Math.random()}`;
      const c = kind === 'h2' ? await h2Client(proxy) : h1Client(proxy, kind === 'h1-tls');
      let abandoned = 0;
      await new Promise((resolve) => {
        c.get(`/stream?id=${encodeURIComponent(id)}`, {
          onFirstByte: (r) => {
            abandoned = performance.now();
            // h2 cancels the one stream (RST_STREAM) and keeps the connection,
            // which is what a browser does when a tab navigates away from one
            // resource; h1 has no way to cancel but to close.
            if (kind === 'h2') r.close(http2.constants.NGHTTP2_CANCEL);
            else r.destroy();
            resolve();
          },
        }).catch(() => resolve());
      });
      const deadline = performance.now() + 5000;
      while (!seen.closed.has(id) && performance.now() < deadline) await new Promise((r) => setTimeout(r, 5));
      if (seen.closed.has(id)) after.push(seen.closed.get(id) - abandoned);
      else unreleased += 1;
      c.close();
    }
    return { requests: n, releasedP50: after.length ? median(after) : null, releasedMax: after.length ? Math.max(...after) : null, unreleased };
  };
}

const SCENARIOS = [
  { name: 'h1', what: '200 small GETs, one keep-alive connection, http origin', run: sequential(false, 200) },
  { name: 'h1-tls', what: '200 small GETs, one intercepted h1 connection, https origin', run: sequential(true, 200) },
  { name: 'h2', what: '10 page loads of 50 concurrent GETs, one intercepted h2 connection', run: pageLoads(50, 10) },
  { name: 'big', what: '5 × 32 MiB, http origin', run: download(false, 5), noRelay: true },
  { name: 'big-tls', what: '5 × 32 MiB, intercepted, https origin', run: download(true, 5), noRelay: true },
  { name: 'cancel-h1', what: 'abandon a streaming response after its first bytes (h1, 20 times)', run: cancel('h1', 20) },
  { name: 'cancel-h2', what: 'reset one h2 stream after its first bytes (20 times)', run: cancel('h2', 20) },
].filter((s) => (!ONLY || ONLY.has(s.name)) && !(RTT && s.noRelay));

// ── the run ───────────────────────────────────────────────────────────────

async function main() {
  const servers = await startOrigins();
  const children = {};
  for (const p of PROXIES) children[p] = await startProxy(p);
  await new Promise((r) => setTimeout(r, 1500));

  const results = {};
  for (const p of PROXIES) results[p] = { idleMiB: rss(children[p].pid), scenarios: {} };

  for (const s of SCENARIOS) {
    const rounds = {};
    for (const p of PROXIES) rounds[p] = [];
    for (let round = 0; round < ROUNDS; round += 1) {
      // Alternate who goes first, so neither always runs on a warmer machine.
      const order = round % 2 ? [...PROXIES].reverse() : PROXIES;
      for (const p of order) {
        const pid = children[p].pid;
        seen.reset();
        let peak = rss(pid);
        const sampler = setInterval(() => (peak = Math.max(peak, rss(pid))), 100);
        let out;
        try {
          out = await s.run(PORTS[p]);
        } catch (e) {
          out = { error: e.message };
        }
        clearInterval(sampler);
        // Give the proxy a moment to close what it is going to close, then ask
        // what it still holds.
        await new Promise((r) => setTimeout(r, 1000));
        rounds[p].push({
          ...out,
          originTcp: seen.tcp,
          originTls: seen.tls,
          originH2Sessions: seen.h2sessions,
          originH1: seen.h1,
          originH2: seen.h2,
          originStillOpen: seen.sockets.size,
          proxySockets: sockets(pid),
          peakMiB: Math.max(peak, rss(pid)),
        });
      }
    }
    for (const p of PROXIES) results[p].scenarios[s.name] = summarise(rounds[p]);
    print(s, results);
  }
  for (const p of PROXIES) results[p].endMiB = rss(children[p].pid);
  console.log(`\nresident memory (MiB): ${PROXIES.map((p) => `${p} idle ${results[p].idleMiB.toFixed(1)} → end ${results[p].endMiB.toFixed(1)}`).join(' · ')}`);

  if (JSON_OUT) {
    fs.writeFileSync(JSON_OUT, JSON.stringify({
      rttMs: RTT, rounds: ROUNDS, whistle: WHISTLE.version, rsBin: RS_BIN, node: process.version, platform: `${os.platform()} ${os.arch()}`, results,
    }, null, 2));
  }
  for (const p of PROXIES) children[p].kill('SIGKILL');
  for (const s of servers) s.close();
  for (const sock of open) sock.destroy();
  fs.rmSync(STATE, { recursive: true, force: true });
}

/** The median of each figure over the rounds; an error in any round wins. */
function summarise(rounds) {
  const failed = rounds.find((r) => r.error);
  if (failed) return { error: failed.error };
  const out = {};
  for (const key of Object.keys(rounds[0])) {
    const xs = rounds.map((r) => r[key]).filter((x) => typeof x === 'number');
    out[key] = xs.length ? median(xs) : rounds[0][key];
  }
  return out;
}

const COLUMNS = [
  ['originTcp', 'origin conns', 0],
  ['originTls', 'TLS handshakes', 0],
  ['originH2', 'h2 reqs at origin', 0],
  ['p50', 'p50 ms', 2],
  ['p95', 'p95 ms', 2],
  ['loadP50', 'load p50 ms', 1],
  ['totalMs', 'total ms', 0],
  ['MiBps', 'MiB/s', 0],
  ['releasedP50', 'released p50 ms', 1],
  ['releasedMax', 'released max ms', 1],
  ['unreleased', 'never released', 0],
  ['originStillOpen', 'origin conns open after', 0],
  ['proxySockets', 'proxy TCP sockets after', 0],
  ['peakMiB', 'peak RSS MiB', 1],
];

function print(s, results) {
  console.log(`\n${s.name}: ${s.what}${RTT ? ` — ${RTT} ms RTT to the origin` : ''} (median of ${ROUNDS})`);
  const rows = PROXIES.map((p) => [p, results[p].scenarios[s.name]]);
  const err = rows.find(([, r]) => r.error);
  if (err) {
    for (const [p, r] of rows) console.log(`  ${p.padEnd(8)} ${r.error ? `ERROR ${r.error}` : 'ok'}`);
    return;
  }
  for (const [key, label, digits] of COLUMNS) {
    if (rows.every(([, r]) => r[key] == null)) continue;
    const cells = rows.map(([, r]) => (r[key] == null ? '-' : Number(r[key]).toFixed(digits)).padStart(10));
    console.log(`  ${label.padEnd(24)} ${cells.join(' ')}`);
  }
  console.log(`  ${''.padEnd(24)} ${PROXIES.map((p) => p.padStart(10)).join(' ')}`);
}

main().catch((e) => {
  console.error(e);
  fs.rmSync(STATE, { recursive: true, force: true });
  process.exit(1);
});
