// The servers `cases-proxy.js` needs, beyond the harness's own echo origin.
//
// The one that matters is the **recording proxy**. Both whistle and whistle-rs
// are pointed at the same one, and what each of them *says* to it — absolute
// form or CONNECT, which hop headers, which credential — is the finding. A
// response alone cannot show any of that: two proxies that reach the same origin
// by opposite routes return the same bytes.
//
// The recording travels onward to the origin as `x-hop-*` request headers, so it
// lands inside the origin's echo and the harness compares it field by field like
// any other header. Nothing new is needed in `harness.js`.
//
// Ports, all offset from `PORT_BASE` (see `cases-proxy.js` for the map).

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 18700);

/** Every port this file claims, and what answers there. */
const PORTS = {
  origin: BASE + 2, // the harness's echo origin (not started here)
  proxy: BASE + 10, // recording HTTP proxy
  originB: BASE + 11, // a second echo origin: shows *where* a request landed
  auth: BASE + 12, // a proxy that always answers 407
  hang: BASE + 13, // a proxy that accepts the socket and never answers
  closed: BASE + 14, // nothing ever listens here: connection refused
  socks: BASE + 15, // recording SOCKS5 proxy
  pac: BASE + 16, // serves PAC files over HTTP
  tlsProxy: BASE + 17, // recording HTTPS proxy (TLS on the hop itself)
};

/**
 * Header names dropped from a hop record. Everything else is recorded, including
 * whistle's other `x-whistle-*` markers — those *are* decisions and are exactly
 * what this file exists to see.
 *
 *   * the first two carry a per-request identity rather than a decision, so
 *     keeping them would make every case differ from itself;
 *   * `connection` is hop-by-hop, which is the same reason `harness.js` drops it
 *     from every other comparison. whistle's CONNECT always carries
 *     `Connection: close` and this port's never does, and neither is a routing
 *     decision: upstream's comes from Node, which stamps it on any request made
 *     with `agent: false` (`hagent/lib/agent.js:113`), and it contradicts the
 *     `Proxy-Connection: keep-alive` whistle sets on the same request. It is
 *     named in the corpus header rather than pinned.
 */
const VOLATILE = new Set(['x-whistle-request-id', 'x-whistle-client-id', 'connection']);

/**
 * The `x-hop-*` headers describing one hop.
 *
 * `form` is `absolute` (the request line named a full URL), `connect` (a CONNECT
 * came first) or `socks`. `target` is what that request line addressed. Header
 * names are sorted: wire order differs between two HTTP stacks for reasons that
 * are not rules, and a false difference in every case would hide the real ones.
 */
function record(form, target, headers) {
  const out = {};
  for (const k of Object.keys(headers || {}).sort()) {
    if (VOLATILE.has(k)) continue;
    out[k] = String(headers[k]);
  }
  return {
    'x-hop-form': form,
    'x-hop-target': target,
    'x-hop-headers': JSON.stringify(out),
  };
}

/** Split `host:port`, defaulting the port. Brackets an IPv6 literal keeps. */
function authority(value, defaultPort) {
  const m = /^\[(.+)\](?::(\d+))?$/.exec(value);
  if (m) return { host: m[1], port: Number(m[2] || defaultPort) };
  const i = value.lastIndexOf(':');
  if (i > 0 && /^\d+$/.test(value.slice(i + 1))) {
    return { host: value.slice(0, i), port: Number(value.slice(i + 1)) };
  }
  return { host: value, port: defaultPort };
}

/**
 * Pass one request on to `dest`, with the hop record stapled to it.
 *
 * The hop-by-hop headers are stripped exactly as a proxy strips them, so what
 * the origin echoes is the request minus the hop — and the hop itself arrives
 * separately, in `x-hop-headers`.
 */
function relay(q, res, dest, hop) {
  const headers = { ...q.headers, ...hop };
  delete headers['proxy-connection'];
  delete headers['proxy-authorization'];
  const up = http.request(
    { host: dest.host, port: dest.port, path: dest.path, method: q.method, headers },
    (r) => {
      const out = { ...r.headers };
      delete out['transfer-encoding'];
      delete out.connection;
      res.writeHead(r.statusCode, out);
      r.pipe(res);
    },
  );
  up.on('error', (e) => {
    if (res.headersSent) return res.destroy();
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('hop could not reach the origin: ' + e.code);
  });
  q.pipe(up);
}

/**
 * The plain HTTP that travels *inside* a tunnel, whichever kind opened it.
 *
 * A CONNECT (or a SOCKS CONNECT) leaves a raw socket carrying an ordinary
 * origin-form request, so the socket is handed to a server that has never
 * listened on a port. `socket._hop` is what the outer layer recorded.
 */
const inner = http.createServer((q, res) => {
  const hop = q.socket._hop;
  const dest = authority(hop.target, 80);
  relay(q, res, { ...dest, path: q.url }, record(hop.form, hop.target, hop.headers));
});
// A tunnel may itself carry a CONNECT: that is what `proxyTunnel` asks for — the
// address the first hop reaches is a second proxy, asked through the first
// tunnel for the real origin. Only the innermost record reaches the origin, and
// that is the useful one: it names the final target and carries whatever the
// second CONNECT was given.
inner.on('connect', onConnect);

/**
 * Hand a socket to [`inner`], replaying anything already read off it.
 *
 * The `resume()` at the end is load-bearing, and its absence is why this file's
 * first run reported no differences at all: an explicitly paused stream is not
 * restarted by attaching a `data` listener, so every tunnelled case hung, both
 * proxies timed out, and two identical failures compared equal.
 */
function tunnelTo(socket, hop, leftover) {
  socket._hop = hop;
  socket.removeAllListeners('data');
  socket.pause();
  if (leftover && leftover.length) socket.unshift(leftover);
  inner.emit('connection', socket);
  socket.resume();
}

/**
 * Keep a server from holding the bench's event loop open — the harness exits
 * when its own work is done, and these are scenery. Accepted sockets are
 * unref'd too: the hanging proxy never closes one.
 */
function background(server) {
  server.unref();
  server.on('connection', (s) => s.unref());
  return server;
}

/** Answer a CONNECT, record it, and hand the tunnel to [`inner`]. */
function onConnect(q, socket, head) {
  socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
  tunnelTo(socket, { form: 'connect', target: q.url, headers: q.headers }, head);
}

/** A proxy that records what it was told and forwards to the real address. */
function recordingProxy(server) {
  server.on('request', (q, res) => {
    // Absolute form: the request line named the whole URL.
    const url = /^https?:\/\//.test(q.url) ? new URL(q.url) : null;
    if (!url) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      return res.end('the hop expected an absolute-form request line');
    }
    const dest = {
      host: url.hostname,
      port: Number(url.port || 80),
      path: url.pathname + url.search,
    };
    relay(q, res, dest, record('absolute', q.url, q.headers));
  });
  server.on('connect', onConnect);
  return background(server);
}

// ── the echo origin's twin ─────────────────────────────────────────────────
//
// Identical to the harness's origin except for two markers, which is the whole
// point: `x-origin: b` says in the *response* which server answered, and
// `x-seen-host` re-echoes the request's `Host` under a name the harness compares
// (it drops `host` itself, as two proxies disagree about it for reasons that are
// not rules). Together they answer the question `host://` exists to raise: did
// the connection move, and did the `Host` header stay put?
const originB = background(
  http.createServer((q, r) => {
    let body = '';
    q.on('data', (c) => (body += c));
    q.on('end', () => {
      r.writeHead(200, { 'content-type': 'application/json', 'x-origin': 'b' });
      r.end(
        JSON.stringify({
          method: q.method,
          url: q.url,
          headers: { ...q.headers, 'x-seen-host': q.headers.host || '' },
          body,
        }),
      );
    });
  }),
);

// ── the failure paths ──────────────────────────────────────────────────────

/** Answers 407 to everything, with or without a credential. */
const authProxy = background(
  http.createServer((q, res) => {
    res.writeHead(407, {
      'proxy-authenticate': 'Basic realm="hop"',
      'content-type': 'text/plain',
    });
    res.end('hop demands a credential');
  }),
);
authProxy.on('connect', (q, socket) => {
  socket.end(
    'HTTP/1.1 407 Proxy Authentication Required\r\n' +
      'Proxy-Authenticate: Basic realm="hop"\r\n' +
      'Content-Length: 0\r\n\r\n',
  );
});

/** Accepts the connection and then says nothing, ever. */
const hangProxy = background(net.createServer((socket) => socket.on('error', () => {})));

// ── SOCKS5 ─────────────────────────────────────────────────────────────────

/** Buffered exact-length reads over a socket, for a binary handshake. */
function reader(socket) {
  let buf = Buffer.alloc(0);
  const waiting = [];
  const pump = () => {
    while (waiting.length && buf.length >= waiting[0].n) {
      const w = waiting.shift();
      w.resolve(buf.subarray(0, w.n));
      buf = buf.subarray(w.n);
    }
  };
  socket.on('data', (c) => {
    buf = Buffer.concat([buf, c]);
    pump();
  });
  return {
    read: (n) => new Promise((resolve) => (waiting.push({ n, resolve }), pump())),
    rest: () => buf,
  };
}

/**
 * A SOCKS5 proxy that records the handshake it was given.
 *
 * The credential and the auth methods offered are the finding here — a SOCKS
 * hop has no headers to inspect — so they are recorded in place of them and
 * reach the origin under the same `x-hop-headers` name.
 */
const socksProxy = background(
  net.createServer(async (socket) => {
    socket.on('error', () => {});
    const io = reader(socket);
    try {
      const greeting = await io.read(2);
      // Anything that is not a SOCKS5 greeting is hung up on rather than waited
      // out: a case that points an HTTP client at this port is asking what the
      // *client* does, and a server that blocks forever would answer for it.
      if (greeting[0] !== 0x05) return socket.destroy();
      const methods = [...(await io.read(greeting[1]))];
      const note = { methods: methods.join(','), user: '', pass: '' };
      // Prefer user/password when it is on offer, so a credential shows up.
      const chosen = methods.includes(0x02) ? 0x02 : 0x00;
      note.chosen = String(chosen);
      socket.write(Buffer.from([0x05, chosen]));
      if (chosen === 0x02) {
        await io.read(1);
        note.user = (await io.read((await io.read(1))[0])).toString();
        note.pass = (await io.read((await io.read(1))[0])).toString();
        socket.write(Buffer.from([0x01, 0x00]));
      }
      const head = await io.read(4);
      let host;
      if (head[3] === 0x01) host = [...(await io.read(4))].join('.');
      else if (head[3] === 0x03) host = (await io.read((await io.read(1))[0])).toString();
      else host = '[' + (await io.read(16)).toString('hex') + ']';
      const port = (await io.read(2)).readUInt16BE(0);
      socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      const target = host.includes(':') && !host.startsWith('[') ? `[${host}]:${port}` : `${host}:${port}`;
      tunnelTo(socket, { form: 'socks', target, headers: note }, io.rest());
    } catch {
      socket.destroy();
    }
  }),
);

// ── PAC ────────────────────────────────────────────────────────────────────

/** The PAC files the corpus asks for, by path. */
const PACS = {
  '/proxy.pac': `PROXY 127.0.0.1:${PORTS.proxy}`,
  '/socks.pac': `SOCKS 127.0.0.1:${PORTS.socks}`,
  '/socks5.pac': `SOCKS5 127.0.0.1:${PORTS.socks}`,
  '/direct.pac': 'DIRECT',
  // The two orderings, which upstream reads very differently — see the corpus.
  '/proxy-then-direct.pac': `PROXY 127.0.0.1:${PORTS.proxy}; DIRECT`,
  '/direct-then-proxy.pac': `DIRECT; PROXY 127.0.0.1:${PORTS.proxy}`,
  // Names a proxy that is not there, so the fallback (or its absence) shows.
  '/dead.pac': `PROXY 127.0.0.1:${PORTS.closed}`,
  '/dead-then-direct.pac': `PROXY 127.0.0.1:${PORTS.closed}; DIRECT`,
};

const pacServer = background(
  http.createServer((q, res) => {
    const body = PACS[q.url.split('?')[0]];
    if (body === undefined) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('no such pac');
    }
    res.writeHead(200, { 'content-type': 'application/x-ns-proxy-autoconfig' });
    res.end(`function FindProxyForURL(url, host) { return ${JSON.stringify(body)}; }\n`);
  }),
);

// ── a TLS hop ──────────────────────────────────────────────────────────────
//
// `https-proxy://` puts TLS on the hop itself, which needs a certificate. It is
// self-signed and both proxies have to be told to accept it: whistle does by
// default (`rejectUnauthorized` is off unless `--safe`), whistle-rs needs
// `--insecure-upstream`. The corpus header says so.
function selfSigned() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-rs-hop-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '2',
    '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

let tlsProxy = null;
try {
  tlsProxy = recordingProxy(https.createServer(selfSigned()));
} catch (e) {
  // No openssl: the https-proxy cases would then compare two identical
  // failures, which proves nothing. Say so rather than reporting a clean run.
  console.error('no TLS hop (' + e.message + '); https-proxy cases are meaningless');
}

// ── bring them up ──────────────────────────────────────────────────────────

const httpProxy = recordingProxy(http.createServer());

httpProxy.listen(PORTS.proxy);
originB.listen(PORTS.originB);
authProxy.listen(PORTS.auth);
hangProxy.listen(PORTS.hang);
socksProxy.listen(PORTS.socks);
pacServer.listen(PORTS.pac);
if (tlsProxy) tlsProxy.listen(PORTS.tlsProxy);

module.exports = { PORTS };
