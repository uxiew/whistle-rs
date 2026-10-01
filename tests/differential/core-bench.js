// Rules whose **effect** the other corpora could not see, asked of both proxies.
//
//   PORT_BASE=21900 node core-bench.js            # starts both proxies itself
//   PORT_BASE=21900 CASES=regexp,script node core-bench.js
//     21900 whistle · 21901 whistle-rs · 21902 http+ws origin · 21903 raw TCP
//     echo · 21904 an origin that demands a client certificate · 21905 a plugin
//
// The parse oracle asks "which rule matched", and the network harness asks
// "what reached the origin" for one request at a time. Neither can see:
//
//   * a pattern or filter written with a JavaScript-only regular expression
//     (a lookahead compiles in V8 and did not in the `regex` crate, so the rule
//     silently never matched);
//   * what a `reqScript` helper *returns* (`parseQuery`, `parseUrl`, `Buffer`);
//   * state a `frameScript` keeps between the frames of one connection, a
//     binary frame, or a plain TCP tunnel;
//   * the page script `log://` injects;
//   * a client certificate `tlsOptions://` hands to the origin.
//
// Every case here has a **positive** and a **negative** control, and both ends
// are asked: a case only counts when the origin saw the effect, not when the
// proxy answered 200.
//
// The plugin cases are one-sided: upstream has no `--plugin name=host:port`, so
// there is nothing to compare, and they assert what whistle-rs must do on its
// own (see `ONE_SIDED`).
//
// A difference is excused only when `declared.js` names the case (under
// `core-bench.js`) for the whistle being measured; anything else exits 1, and
// so does a declaration whose difference no longer happens. With `--json FILE`
// it also writes `{ ran, differing, declared, stale, report, raw, oneSided }`.
// A `CASES=` run is for working on one group: it does not report stale
// declarations, because the cases they name were not run.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');
const WebSocket = require('ws');

const BASE = Number(process.env.PORT_BASE || 21900);
const [W, RS, ORIGIN, TCP, MTLS, PLUGIN] = [BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5];
const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');
const WHISTLE = require('./whistle-pkg');
const { judge } = require('./declared');
const STATE = process.env.DIFF_STATE || fs.mkdtempSync(path.join(os.tmpdir(), 'wrs-core-'));
const ONLY = process.env.CASES ? new Set(process.env.CASES.split(',')) : null;
const JSON_OUT = (() => { const i = process.argv.indexOf('--json'); return i > 0 ? process.argv[i + 1] : null; })();
const O = `127.0.0.1:${ORIGIN}`;

// ── fixtures ────────────────────────────────────────────────────────────

/** What the WebSocket origin received, by the tag in the connection's query. */
const wsReceived = new Map();
/** What the raw TCP origin received, in arrival order. */
let tcpReceived = [];
/** How many requests the HTTP origin's echo has answered. */
let originHits = 0;

const HTML = '<html><head></head><body>hi</body></html>';

function startOrigin() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((q, r) => {
      const p = q.url.split('?')[0];
      if (p === '/html') {
        r.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return r.end(HTML);
      }
      if (p === '/text') {
        r.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        return r.end('a1b2 foo.bar foobar 2024-09-30');
      }
      originHits++;
      let body = '';
      q.on('data', (c) => (body += c));
      q.on('end', () => {
        r.writeHead(200, { 'content-type': 'application/json' });
        r.end(JSON.stringify({ url: q.url, method: q.method, headers: q.headers, body }));
      });
    });
    const wss = new WebSocket.Server({ server });
    wss.on('connection', (ws) => {
      const tag = ((ws.upgradeReq && ws.upgradeReq.url) || '').split('?')[1] || '';
      ws.on('message', (msg, flags) => {
        const binary = !!(flags && flags.binary);
        const text = Buffer.isBuffer(msg) ? msg.toString('latin1') : String(msg);
        wsReceived.set(tag, [...(wsReceived.get(tag) || []), (binary ? 'bin:' : 'txt:') + text]);
        ws.send(msg, { binary });
      });
    });
    server.on('error', reject);
    server.listen(ORIGIN, '127.0.0.1', () => resolve(server));
  });
}

function startTcp() {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      sock.on('data', (d) => { tcpReceived.push(d.toString('latin1')); sock.write(d); });
      sock.on('error', () => {});
    });
    server.on('error', reject);
    server.listen(TCP, '127.0.0.1', () => resolve(server));
  });
}

/**
 * A throwaway CA, a server certificate and two client certificates — one the
 * origin trusts, one signed by somebody else. Made with the `openssl` on the
 * path, in the run's scratch directory; nothing is installed anywhere.
 */
function makeCerts(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] });
  const ca = (name) => run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', `/CN=${name}`,
    '-keyout', `${name}.key`, '-out', `${name}.crt`);
  const leaf = (name, signer, ext) => {
    run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=${name}`, '-keyout', `${name}.key`, '-out', `${name}.csr`);
    fs.writeFileSync(path.join(dir, `${name}.ext`), ext);
    run('x509', '-req', '-in', `${name}.csr`, '-CA', `${signer}.crt`, '-CAkey', `${signer}.key`, '-CAcreateserial',
      '-days', '2', '-extfile', `${name}.ext`, '-out', `${name}.crt`);
  };
  ca('core-ca');
  ca('other-ca');
  leaf('server', 'core-ca', 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  leaf('client', 'core-ca', 'extendedKeyUsage=clientAuth\n');
  leaf('stranger', 'other-ca', 'extendedKeyUsage=clientAuth\n');
  // The same identity as `client`, as a PKCS#12 bundle with a passphrase.
  run('pkcs12', '-export', '-inkey', 'client.key', '-in', 'client.crt', '-passout', 'pass:123456', '-out', 'client.p12');
  const f = (n) => path.join(dir, n);
  return { dir, f, read: (n) => fs.readFileSync(f(n)) };
}

function startMtls(certs) {
  return new Promise((resolve, reject) => {
    const server = https.createServer({
      key: certs.read('server.key'),
      cert: certs.read('server.crt'),
      ca: certs.read('core-ca.crt'),
      requestCert: true,
      rejectUnauthorized: true,
    }, (q, r) => {
      const peer = q.socket.getPeerCertificate();
      r.writeHead(200, { 'content-type': 'application/json' });
      r.end(JSON.stringify({ authorized: q.socket.authorized, cn: (peer && peer.subject && peer.subject.CN) || '' }));
    });
    server.on('tlsClientError', () => {});
    server.on('error', reject);
    server.listen(MTLS, '127.0.0.1', () => resolve(server));
  });
}

/**
 * A plugin whose answers the case decides: `manifest` and `auth` are each a
 * `[status, body]` the next call gets, and `calls` counts what was asked.
 */
const plugin = { manifest: [503, ''], auth: [200, '{"allow":true}'], calls: { manifest: 0, auth: 0, request: 0 } };
function startPlugin() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((q, r) => {
      const p = q.url.split('?')[0];
      let body = '';
      q.on('data', (c) => (body += c));
      q.on('end', () => {
        const answer = (status, text) => { r.writeHead(status, { 'content-type': 'application/json' }); r.end(text); };
        if (p === '/manifest') { plugin.calls.manifest++; return answer(...plugin.manifest); }
        if (p === '/auth') { plugin.calls.auth++; return answer(...plugin.auth); }
        plugin.calls.request++;
        answer(200, '{}');
      });
    });
    server.on('error', reject);
    server.listen(PLUGIN, '127.0.0.1', () => resolve(server));
  });
}

// ── the two proxies ─────────────────────────────────────────────────────

function start(which, port, extra = []) {
  return new Promise((resolve, reject) => {
    const dir = path.join(STATE, `core-${which}-${port}`);
    const child = which === 'whistle'
      ? spawn('node', ['-e', `
          const whistle = require(${JSON.stringify(WHISTLE.dir)});
          whistle({ port: ${port}, baseDir: ${JSON.stringify(dir)}, host: '127.0.0.1' }, () => console.log('READY'));
        `], { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn(RS_BIN, ['--port', String(port), '--no-persist', '--dir', dir, '--insecure-upstream', ...extra],
        { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false;
    let log = '';
    const t = setTimeout(() => {
      if (!done) { done = true; child.kill('SIGKILL'); reject(new Error(`${which} did not start:\n${log}`)); }
    }, 30000);
    const watch = (d) => {
      log += d;
      if (!done && /READY|listening on/.test(String(d))) { done = true; clearTimeout(t); resolve(child); }
    };
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', (code) => {
      if (!done) { done = true; clearTimeout(t); reject(new Error(`${which} exited ${code}:\n${log}`)); }
    });
  });
}

const send = (port, method, p, body, type) => new Promise((resolve) => {
  const r = http.request({ host: '127.0.0.1', port, method, path: p,
    headers: { ...(type ? { 'content-type': type } : {}), 'content-length': Buffer.byteLength(body || '') } }, (x) => {
    let s = '';
    x.on('data', (c) => (s += c));
    x.on('end', () => resolve({ status: x.statusCode, body: s }));
  });
  r.on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.code }));
  r.end(body || '');
});

const FORM = 'application/x-www-form-urlencoded';
async function setRules(text) {
  await send(W, 'POST', '/cgi-bin/rules/add', 'name=Default&selected=1&value=' + encodeURIComponent(text), FORM);
  await send(RS, 'POST', '/api/rules', text, 'text/plain');
  await new Promise((r) => setTimeout(r, 150));
}

/** One request through a proxy; the answer's status, headers and body. */
const via = (port, url, opts = {}) => new Promise((resolve) => {
  const u = new URL(url);
  const r = http.request({ host: '127.0.0.1', port, method: opts.method || 'GET', path: url,
    headers: { host: u.host, ...(opts.headers || {}) } }, (x) => {
    const chunks = [];
    x.on('data', (c) => chunks.push(c));
    x.on('end', () => resolve({ status: x.statusCode, headers: x.headers, body: Buffer.concat(chunks).toString('utf8') }));
  });
  r.on('error', (e) => resolve({ status: 0, headers: {}, body: 'ERR ' + e.code }));
  r.setTimeout(8000, () => { r.destroy(); resolve({ status: 0, headers: {}, body: 'timeout' }); });
  r.end(opts.body || '');
});

const json = (text) => { try { return JSON.parse(text); } catch (e) { return null; } };

/** The header the origin saw, or `(none)`; `(status N)` when it never got there. */
async function originHeader(port, url, name, opts) {
  const a = await via(port, url, opts);
  const seen = json(a.body);
  if (a.status !== 200 || !seen) return `(status ${a.status})`;
  return seen.headers[name] || '(none)';
}

/**
 * A WebSocket through a proxy, spoken by hand: the client library here cannot
 * be pointed at a proxy, and a bench that reaches the origin directly measures
 * nothing. Text and binary frames, masked, unfragmented — all a case needs.
 */
function wsVia(port, tag, frames) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1');
    const key = crypto.randomBytes(16).toString('base64');
    const out = { client: [], origin: [], handshake: 0 };
    let buf = Buffer.alloc(0);
    let upgraded = false;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      sock.destroy();
      out.origin = wsReceived.get(tag) || [];
      resolve(out);
    };
    const timer = setTimeout(finish, 2500);
    const frame = (f) => {
      const payload = Buffer.from(f.data, 'latin1');
      const mask = crypto.randomBytes(4);
      const head = Buffer.from([0x80 | (f.binary ? 2 : 1), 0x80 | payload.length]);
      const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]));
      return Buffer.concat([head, mask, masked]);
    };
    sock.on('connect', () => {
      sock.write(`GET http://${O}/ws?${tag} HTTP/1.1\r\nHost: ${O}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n`
        + `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (!upgraded) {
        const end = buf.indexOf('\r\n\r\n');
        if (end < 0) return;
        out.handshake = Number(String(buf.slice(0, 12)).split(' ')[1]);
        buf = buf.slice(end + 4);
        upgraded = true;
        if (out.handshake !== 101) { clearTimeout(timer); return finish(); }
        // One at a time, so the order the origin sees is the order sent.
        frames.forEach((f, i) => setTimeout(() => sock.write(frame(f)), 120 * (i + 1)));
      }
      while (buf.length >= 2) {
        const len = buf[1] & 0x7f;
        if (len > 125 || buf.length < 2 + len) break;
        const opcode = buf[0] & 0x0f;
        const data = buf.slice(2, 2 + len).toString('latin1');
        buf = buf.slice(2 + len);
        if (opcode === 1 || opcode === 2) out.client.push((opcode === 2 ? 'bin:' : 'txt:') + data);
      }
      // Not "one reply per frame sent": a script may inject frames of its own,
      // so the exchange is over when the timer says so.
    });
    sock.on('error', () => { clearTimeout(timer); finish(); });
  });
}

/** Bytes through a CONNECT tunnel to the raw TCP origin. */
function tcpVia(port, chunks) {
  return new Promise((resolve) => {
    tcpReceived = [];
    const out = { connect: 0, client: [], origin: [] };
    const r = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: `127.0.0.1:${TCP}`,
      headers: { host: `127.0.0.1:${TCP}` } });
    const done = (sock) => { if (sock) sock.destroy(); out.origin = tcpReceived.slice(); resolve(out); };
    r.on('connect', (resp, sock) => {
      out.connect = resp.statusCode;
      if (resp.statusCode !== 200) return done(sock);
      sock.on('data', (d) => out.client.push(d.toString('latin1')));
      sock.on('error', () => {});
      // As bytes: a string would go out as UTF-8, and a chunk here may not be text.
      chunks.forEach((c, i) => setTimeout(() => sock.write(Buffer.from(c, 'latin1')), 150 * (i + 1)));
      setTimeout(() => done(sock), 150 * (chunks.length + 1) + 1200);
    });
    r.on('error', () => done());
    r.end();
  });
}

// ── the cases ───────────────────────────────────────────────────────────

/** A rules text carrying a named inline value. */
const block = (name, body) => `\`\`\` ${name}\n${body}\n\`\`\`\n`;
const ROUTE = `probe.test host://${O}\n`;

/**
 * Each case: `group` (for `CASES=`), `name`, `rules`, and `ask(port)` — the
 * observation, which must be JSON and must mean the same thing on both sides.
 */
function cases(certs) {
  const list = [];
  const add = (group, name, rules, ask) => list.push({ group, name, rules, ask });

  // ── JavaScript regular expressions ──
  // Each pair is a pattern that must match and a twin that must not, so "the
  // rule never fired" and "the rule always fires" both show.
  const header = (rule) => (port) => originHeader(port, 'http://probe.test/echo/a1?x=1', 'x-probe');
  const REGEXP = [
    ['a lookahead in a pattern', String.raw`/probe(?=\.test)/ reqHeaders://x-probe=hit`],
    ['a lookahead that fails', String.raw`/probe(?=\.nope)/ reqHeaders://x-probe=hit`],
    ['a negative lookahead', String.raw`/probe\.test\/(?!admin)/ reqHeaders://x-probe=hit`],
    ['a negative lookahead that fails', String.raw`/probe\.test\/(?!echo)/ reqHeaders://x-probe=hit`],
    ['a lookbehind', String.raw`/(?<=echo\/)a1/ reqHeaders://x-probe=hit`],
    ['a lookbehind that fails', String.raw`/(?<=nope\/)a1/ reqHeaders://x-probe=hit`],
    ['a backreference', String.raw`/(e)cho\/a1\?x=1(?:\1)?$/ reqHeaders://x-probe=hit`],
    ['a named group, by number', String.raw`/\/(?<first>echo)\/(a\d)/ reqHeaders://x-probe=$1-$2`],
    ['case-insensitive', String.raw`/PROBE\.TEST/i reqHeaders://x-probe=hit`],
    ['case-sensitive by default', String.raw`/PROBE\.TEST/ reqHeaders://x-probe=hit`],
    ['a lookahead in an includeFilter', String.raw`probe.test reqHeaders://x-probe=hit includeFilter://m:/^GET(?=$)/`],
    ['a lookahead in an includeFilter that fails', String.raw`probe.test reqHeaders://x-probe=hit includeFilter://m:/^GET(?=X)/`],
    ['a lookahead in an excludeFilter', String.raw`probe.test reqHeaders://x-probe=hit excludeFilter:///echo(?=\/a1)/`],
    ['a lookahead in a header filter', String.raw`probe.test reqHeaders://x-probe=hit includeFilter://reqH.host=/^probe(?=\.test)/`],
  ];
  for (const [name, rule] of REGEXP) add('regexp', name, ROUTE + rule, header(rule));

  // The replace family compiles its own expressions.
  const bodyOf = (p) => async (port) => { const a = await via(port, `http://probe.test${p}`); return `${a.status} ${a.body}`; };
  add('regexp', 'a lookahead in resReplace', ROUTE + block('rr.txt', String.raw`/foo(?=bar)/g: X`)
    + 'probe.test resReplace://{rr.txt}', bodyOf('/text'));
  add('regexp', 'a lookbehind in resReplace', ROUTE + block('rr.txt', String.raw`/(?<=a)\d/g: N`)
    + 'probe.test resReplace://{rr.txt}', bodyOf('/text'));
  add('regexp', 'a backreference in resReplace', ROUTE + block('rr.txt', String.raw`/(o)\1/g: 00`)
    + 'probe.test resReplace://{rr.txt}', bodyOf('/text'));
  add('regexp', 'a lookahead in urlReplace', ROUTE + block('ur.txt', String.raw`/a(?=1)/: b`)
    + 'probe.test pathReplace://{ur.txt}',
  async (port) => { const a = await via(port, 'http://probe.test/echo/a1?x=1'); const s = json(a.body); return s ? s.url : `(status ${a.status})`; });
  add('regexp', 'a lookahead in a template replace', ROUTE
    + 'probe.test reqHeaders://`x-probe=${url.replace(/a(?=1)/,b)}`', header());

  // ── reqScript helpers ──
  const SCRIPT = (expr) => block('s.js', `
var out;
try { out = (function () { return ${expr}; })(); } catch (e) { out = 'threw ' + (e && e.name); }
values['out.json'] = JSON.stringify(out === undefined ? '(undefined)' : out);
rules.push('* file://{out.json}');`) + ROUTE + 'probe.test reqScript://{s.js}';
  const scriptOut = async (port) => {
    const a = await via(port, 'http://probe.test/echo/a1?x=1&x=2', { headers: { 'x-h': 'v' } });
    return a.status === 200 ? a.body : `(status ${a.status})`;
  };
  const SCRIPTS = [
    ['parseQuery: a repeated key and a plus', `parseQuery('a=1&a=2&q=a+b&e=%E4%B8%AD&bare')`],
    ['parseQuery: an empty string', `parseQuery('')`],
    ['parseQuery: a broken escape', `parseQuery('a=%zz&b=%41')`],
    ['parseUrl: userinfo, IPv6, a hash', `(function (u) { return [u.protocol, u.auth, u.host, u.hostname, u.port, u.pathname, u.search, u.query, u.path, u.hash, u.href, u.slashes]; })(parseUrl('http://user:pw@[::1]:8080/p/a?x=1#frag'))`],
    ['parseUrl: no port, no query', `(function (u) { return [u.protocol, u.auth, u.host, u.hostname, u.port, u.pathname, u.search, u.query, u.path, u.hash, u.href]; })(parseUrl('https://Example.COM/a b'))`],
    ['parseUrl: a bare path', `(function (u) { return [u.protocol, u.host, u.hostname, u.port, u.pathname, u.search, u.query, u.path, u.hash]; })(parseUrl('/p/a?x=1#h'))`],
    ['Buffer.from(...).toString(hex)', `Buffer.from('A\\u4e2d').toString('hex')`],
    ['Buffer.from(hex).toString()', `Buffer.from('e4b8ad41', 'hex').toString()`],
    ['Buffer base64 both ways', `[Buffer.from('hello').toString('base64'), Buffer.from('aGVsbG8=', 'base64').toString('utf8')]`],
    ['Buffer.concat, length, isBuffer, byteLength', `(function (b) { return [b.length, Buffer.isBuffer(b), Buffer.isBuffer('x'), Buffer.byteLength('\\u4e2d'), b[0], b.toString()]; })(Buffer.concat([Buffer.from('ab'), Buffer.from('c')]))`],
    ['decodeBuffer / encodeString (gbk)', `[encodeString('\\u4e2d', 'gbk').toString('hex'), decodeBuffer(Buffer.from('d6d0', 'hex'), 'gbk'), encodingExists('gbk'), encodingExists('no-such')]`],
    ['pattern', `pattern`],
    ['port is the proxy port', `port === ${'__PORT__'}`],
    ['httpVersion', `httpVersion`],
    ['headers and method', `[method, headers['x-h'], typeof reqHeaders, typeof body]`],
    ['the type of every documented global', `[typeof url, typeof fullUrl, typeof ip, typeof clientIp, typeof clientPort, typeof version, typeof uiHost, typeof uiPort, typeof value, typeof getValue, typeof render, typeof tpl, typeof isLocalAddress, typeof reqScriptData, typeof statusCode, typeof serverIp, typeof resHeaders]`],
    // A vm context is JavaScript and nothing else: none of Node's own globals.
    ['what a vm context does not have', `[typeof require, typeof process, typeof setTimeout, typeof module, typeof global, typeof globalThis]`],
    ['parseQuery: the corners', `['a=1&&b=2', '=x', 'a=b=c', '?a=1', 'a[]=1&a[]=2', 'a%zz=1', 'a=%E4%B8', 'a=1;b=2', '&', 'a'].map(function (q) { return parseQuery(q); })`],
    ['parseQuery: not a string', `[parseQuery(), parseQuery(null), parseQuery(12), parseQuery({})]`],
    ...[
      'HTTP://A.com:8080/p?q#h', 'http://a.com', '//a.com/x', 'a.com/x', 'http://a.com/p?q=1?r=2#h#i',
      'file:///tmp/x', 'http://[::1]/', 'http://a_b.com:/x', 'mailto:a@b.c', `http://x.com/a'b"c`,
      'http://user@a.com', 'http://a.com?x=1', 'javascript:alert(1)', ' http://a.com/ ', 'http://a.com\\\\b\\\\c?d\\\\e',
      'http://a.com/p#', 'http://a.com/?', 'ws://h:81/s', 'http://a.com:0080/x', 'http://a b.com/x', 'x:y', '',
      'http://us%20er:p%40w@a.com/', 'HTTP://USER:PW@HOST.COM/PATH',
    ].map((u) => [`parseUrl: ${u || '(empty)'}`,
      `(function (u) { return [u.protocol, u.slashes, u.auth, u.host, u.port, u.hostname, u.hash, u.search, u.query, u.pathname, u.path, u.href]; })(parseUrl(${JSON.stringify(u)}))`]),
    ['parseUrl: not a string', `[typeof parseUrl(), typeof parseUrl(null), parseUrl(12).pathname]`],
    ['Buffer: slices, searches and integers', `(function (b) { var s = b.slice(1, 3); s[0] = 0x58; return [b.toString(), s.toString(), b.indexOf('c'), b.includes('zz'), b.readUInt16BE(0), b.equals(Buffer.from('aXcd')), JSON.stringify(s), b.toString('latin1', 1), Buffer.compare(b, s)]; })(Buffer.from('abcd'))`],
    ['Buffer: bytes that are not text', `(function (b) { return [b.toString(), b.toString('latin1'), b.toString('base64'), b.toString('hex'), b.length]; })(Buffer.from([0x61, 0xff, 0xfe, 0x00]))`],
    ['Buffer: alloc and write', `(function (b) { b.writeUInt32LE(0x01020304, 0); b.write('hi', 4); return [b.toString('hex'), Buffer.alloc(3, 'ab').toString(), Buffer.byteLength('aGk=', 'base64')]; })(Buffer.alloc(6))`],
    ['Buffer: an unknown encoding', `Buffer.from('x', 'nope')`],
    ['Buffer in a string', `'x' + Buffer.from('yz') + String(Buffer.from('!'))`],
    ['decodeBuffer / encodeString: more names', `['GB2312', 'win1252', 'Shift_JIS', 'utf16le', 'latin1', 'big5', 'EUC-KR', 'nope', ''].map(function (e) { return encodingExists(e); })`],
    ['encodeString: a character the encoding cannot hold', `[encodeString('a中', 'latin1').toString('hex'), encodeString('ab', 'utf16le').toString('hex')]`],
    ['render with data', `render('<% for (var i = 0; i < n; i++) { %>[<%= i %>]<% } %>', { n: 3 })`],
    ['isLocalAddress', `[isLocalAddress(), isLocalAddress('8.8.8.8'), isLocalAddress('127.0.0.1'), isLocalAddress('::1')]`],
    ['the older string methods', `['abcdef'.substr(1, 3), escape('a b+c'), unescape('%41%u4E2D'), 'x'.padStart(3, '-'), [1, [2, [3]]].flat(2).join()]`],
    ['RegExp statics', `(/(b)(c)/.test('abcd'), [RegExp.$1, RegExp.$2, RegExp.lastMatch])`],
  ];
  for (const [name, expr] of SCRIPTS) {
    list.push({ group: 'script', name, rulesFor: (port) => SCRIPT(expr.replace('__PORT__', String(port))), ask: scriptOut });
  }

  // ── frameScript ──
  const FRAME = (body) => block('f.js', body) + `${O} frameScript://{f.js}`;
  const ws = (tag, frames) => async (port) => {
    const x = await wsVia(port, `${tag}-${port}-${Date.now()}`, frames);
    return { handshake: x.handshake, origin: x.origin, client: x.client };
  };
  add('frame', 'state kept between the frames of one connection',
    FRAME(`var n = 0;\nctx.handleSendToServerFrame = function (buf) { return 'N' + (++n) + ':' + buf; };`),
    ws('state', [{ data: 'a' }, { data: 'b' }, { data: 'c' }]));
  add('frame', 'state is per connection, not shared',
    FRAME(`var n = 0;\nctx.handleSendToServerFrame = function (buf) { return 'N' + (++n) + ':' + buf; };`),
    async (port) => [await ws('iso1', [{ data: 'a' }])(port), await ws('iso2', [{ data: 'a' }])(port)]);
  add('frame', 'a binary frame reaches the handler',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; };`),
    ws('bin', [{ data: 'BINARY', binary: true }]));
  add('frame', 'a binary frame the handler leaves alone',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { return buf; };`),
    ws('binkeep', [{ data: '\x00\xff\x80raw', binary: true }]));
  add('frame', 'the handler is handed a Buffer',
    FRAME(`ctx.handleSendToServerFrame = function (buf, opts) { return [typeof buf, Buffer.isBuffer(buf), buf.length, typeof opts].join(','); };`),
    ws('type', [{ data: 'abc' }]));
  add('frame', 'a handler that returns nothing drops the frame',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { return String(buf) === 'drop' ? null : buf; };`),
    ws('drop', [{ data: 'keep1' }, { data: 'drop' }, { data: 'keep2' }]));
  add('frame', 'a handler that throws',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { throw new Error('boom'); };`),
    ws('throw', [{ data: 'a' }]));
  add('frame', 'sendToClient from inside a handler',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { ctx.sendToClient('ack:' + buf); return buf; };`),
    ws('inject', [{ data: 'a' }, { data: 'b' }]));
  add('frame', 'sendToServer at the top of the script',
    FRAME(`ctx.sendToServer('hello');`),
    ws('top', [{ data: 'a' }]));
  add('frame', 'the client-bound handler',
    FRAME(`var n = 0;\nctx.handleSendToClientFrame = function (buf) { return 'C' + (++n) + ':' + buf; };`),
    ws('down', [{ data: 'a' }, { data: 'b' }]));
  // Upstream empties the script's globals once it has run, so a handler that
  // names `ctx` or `Buffer` throws there; one that kept a reference does not.
  // These keep one, so both proxies are asked the same thing.
  add('frame', 'what a handler is handed',
    FRAME(`var c = ctx;\nc.handleSendToServerFrame = function (buf, opts) { return [typeof buf, buf && buf.constructor && buf.constructor.name, buf.length, typeof opts, Object.keys(opts).sort().join('+')].join(','); };`),
    ws('type2', [{ data: 'abc' }, { data: 'xy', binary: true }]));
  add('frame', 'a frame the script sends is passed to its own handler',
    FRAME(`var c = ctx;\nc.sendToServer('hello');\nc.handleSendToServerFrame = function (buf, opts) { return 'S(' + buf + ')' + (opts && opts.frameScript ? '!' : ''); };`),
    ws('topwrap', [{ data: 'a' }]));
  add('frame', 'sendToClient from a handler, through the other handler',
    FRAME(`var c = ctx;\nc.handleSendToServerFrame = function (buf) { c.sendToClient('ack:' + buf); return buf; };\nc.handleSendToClientFrame = function (buf, opts) { return 'C(' + buf + ')' + (opts && opts.frameScript ? '!' : ''); };`),
    ws('inject2', [{ data: 'a' }, { data: 'b' }]));
  add('frame', 'sendToServer from the handler for that direction',
    FRAME(`var c = ctx;\nc.handleSendToServerFrame = function (buf, opts) { if (!opts.frameScript && String(buf) === 'a') { c.sendToServer('extra'); } return buf; };`),
    ws('inject3', [{ data: 'a' }, { data: 'b' }]));
  add('frame', 'a handler that asks for a binary frame',
    FRAME(`var c = ctx;\nc.handleSendToServerFrame = function (buf, opts) { opts.binary = true; return buf; };`),
    ws('tobin', [{ data: 'text' }, { data: '\x00\xffraw', binary: true }]));
  add('frame', 'a handler that asks for a text frame',
    FRAME(`var c = ctx;\nc.handleSendToServerFrame = function (buf, opts) { opts.binary = false; return buf; };`),
    ws('totext', [{ data: 'plain', binary: true }]));
  add('frame', 'what a handler may return',
    FRAME(`var c = ctx;\nvar n = 0;\nc.handleSendToServerFrame = function (buf) { n++; return n === 1 ? { a: 1 } : n === 2 ? 7 : n === 3 ? 0 : n === 4 ? '' : n === 5 ? [1, 2] : undefined; };`),
    ws('returns', [{ data: '1' }, { data: '2' }, { data: '3' }, { data: '4' }, { data: '5' }, { data: '6' }]));
  add('frame', 'frames the script sends: a Buffer, an object, options',
    FRAME(`ctx.sendToServer(Buffer.from([0x41, 0x42]), { binary: true });\nctx.sendToServer({ k: 'v' });\nctx.sendToClient('to-client');\nctx.sendToServer('');`),
    ws('topkinds', [{ data: 'a' }]));
  add('frame', 'what the script sees while it runs',
    FRAME(`ctx.sendToServer([typeof url, typeof method, typeof headers, typeof rules, typeof values, typeof Buffer, typeof parseUrl, typeof parseQuery, typeof getValue, typeof render, typeof ctx.sendToClient, typeof ctx.frame, typeof ctx.direction].join(','));`),
    ws('topsees', []));
  add('frame', 'a script that does not say ctx',
    FRAME(`var unused = 1;`),
    ws('noctx', [{ data: 'a' }]));
  add('frame', 'a script that throws while it runs',
    FRAME(`ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; };\nthrow new Error('early');`),
    ws('throwtop', [{ data: 'a' }]));

  // ── frameScript over a plain TCP tunnel ──
  const T = `127.0.0.1:${TCP}`;
  const tcp = (chunks) => (port) => tcpVia(port, chunks);
  add('tcp', 'a tunnel with no script', '', tcp(['RAW_AUDIT']));
  add('tcp', 'frameScript on an inspected tunnel',
    block('t.js', `ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; };`)
    + `${T} enable://inspect frameScript://{t.js}`, tcp(['RAW_AUDIT']));
  add('tcp', 'frameScript state on an inspected tunnel',
    block('t.js', `var n = 0;\nctx.handleSendToServerFrame = function (buf) { return 'N' + (++n) + ':' + buf; };\nctx.handleSendToClientFrame = function (buf) { return '<' + buf + '>'; };`)
    + `${T} enable://inspect frameScript://{t.js}`, tcp(['one', 'two']));
  add('tcp', 'frameScript without enable://inspect',
    block('t.js', `ctx.handleSendToServerFrame = function (buf) { return 'X' + buf; };`)
    + `${T} frameScript://{t.js}`, tcp(['RAW_AUDIT']));
  add('tcp', 'a tunnel script that sends data of its own',
    block('t.js', `var c = ctx;\nc.sendToServer('hello-server');\nc.sendToClient('hello-client');\nc.handleSendToServerFrame = function (buf, opts) { return opts.frameScript ? buf : null; };`)
    + `${T} enable://inspect frameScript://{t.js}`, tcp(['dropped']));
  add('tcp', 'bytes that are not text, through a handler that returns them',
    block('t.js', `var c = ctx;\nc.handleSendToServerFrame = function (buf) { return buf; };`)
    + `${T} enable://inspect frameScript://{t.js}`, tcp(['\x00\xff\x80\xfe']));
  add('tcp', 'an inspected tunnel with no script', `${T} enable://inspect`, tcp(['RAW_AUDIT']));

  // ── log:// ──
  const page = async (port) => {
    const a = await via(port, 'http://probe.test/html');
    return {
      status: a.status,
      injected: a.body.length > HTML.length,
      keepsPage: a.body.includes('<body>hi</body>'),
      hooksConsole: /console/.test(a.body) && /onerror|addEventListener\(['"]error/.test(a.body),
    };
  };
  add('log', 'log:// injects a page script', ROUTE + 'probe.test log://audit', page);
  add('log', 'no log:// rule, no script', ROUTE, page);
  add('log', 'log:// leaves a non-HTML body alone', ROUTE + 'probe.test log://audit',
    async (port) => { const a = await via(port, 'http://probe.test/text'); return `${a.status} ${a.body}`; });

  // ── tlsOptions:// client certificates ──
  // `localhost`, not `127.0.0.1`: upstream sends the rule's host as the TLS
  // server name, and Node refuses an IP address there — the handshake then
  // fails on the client's side, before any certificate is asked for, and every
  // case below reads 502 for a reason that has nothing to do with it.
  const M = `probe.test https://localhost:${MTLS}\n`;
  const mtls = async (port) => {
    const a = await via(port, 'http://probe.test/who');
    const seen = json(a.body);
    return a.status === 200 && seen ? `200 authorized=${seen.authorized} cn=${seen.cn}` : `(status ${a.status})`;
  };
  add('mtls', 'no client certificate', M, mtls);
  add('mtls', 'key and cert by path', M + `probe.test tlsOptions://key=${certs.f('client.key')}&cert=${certs.f('client.crt')}`, mtls);
  add('mtls', 'key and cert inline, from a value',
    M + block('id.json', JSON.stringify({ key: String(certs.read('client.key')), cert: String(certs.read('client.crt')) }))
    + 'probe.test tlsOptions://{id.json}', mtls);
  add('mtls', 'a certificate the origin does not trust',
    M + `probe.test tlsOptions://key=${certs.f('stranger.key')}&cert=${certs.f('stranger.crt')}`, mtls);
  add('mtls', 'a key that does not belong to the certificate',
    M + `probe.test tlsOptions://key=${certs.f('stranger.key')}&cert=${certs.f('client.crt')}`, mtls);
  add('mtls', 'a pfx bundle with its passphrase',
    M + `probe.test tlsOptions://passphrase=123456&pfx=${certs.f('client.p12')}`, mtls);
  add('mtls', 'a pfx bundle with the wrong passphrase',
    M + `probe.test tlsOptions://passphrase=nope&pfx=${certs.f('client.p12')}`, mtls);
  add('mtls', 'the certificate on one line, the version on another',
    M + `probe.test tlsOptions://minVersion=TLSv1.2\nprobe.test tlsOptions://key=${certs.f('client.key')}&cert=${certs.f('client.crt')}`, mtls);
  add('mtls', 'a missing key file',
    M + `probe.test tlsOptions://key=${certs.f('nope.key')}&cert=${certs.f('client.crt')}`, mtls);
  return list;
}

// ── one-sided: what whistle-rs must do with a plugin it cannot describe ──

/**
 * Upstream has no remote plugins, so these are assertions rather than
 * comparisons. Each starts a whistle-rs of its own: what is under test is what
 * the **first** manifest fetch leaves behind.
 */
async function oneSided() {
  const results = [];
  const MANIFEST = JSON.stringify({ name: 'gate', version: '1', hooks: ['auth'] });
  const rules = `${O} plugin://gate`;
  const ask = (port) => via(port, `http://${O}/echo`);
  const scenario = async (name, first, then, expect) => {
    // A refusal is a `200` that says so; any other status is the gate failing.
    Object.assign(plugin, { manifest: first, auth: [200, '{"allow":false}'] });
    plugin.calls = { manifest: 0, auth: 0, request: 0 };
    const port = RS + 10 + results.length;
    const child = await start('rs', port, ['--plugin', `gate=127.0.0.1:${PLUGIN}`]);
    try {
      await send(port, 'POST', '/api/rules', rules, 'text/plain');
      await new Promise((r) => setTimeout(r, 150));
      // Asked of the origin itself, not read off the status: a 200 from the
      // proxy says nothing about who produced it.
      const before = originHits;
      const a = await ask(port);
      const afterFirst = originHits;
      plugin.manifest = then;
      // A failed manifest fetch is remembered for a second before the plugin
      // is asked again; the recovery is only visible after that.
      await new Promise((r) => setTimeout(r, 1300));
      const b = await ask(port);
      const got = {
        first: a.status, firstReachedOrigin: afterFirst > before,
        second: b.status, secondReachedOrigin: originHits > afterFirst,
        authCalls: plugin.calls.auth,
      };
      results.push({ name, got, expect, ok: JSON.stringify(got) === JSON.stringify(expect) });
    } finally {
      child.kill('SIGKILL');
    }
  };
  // The gate denies everything. A request that reaches the origin got past it.
  await scenario('a manifest that answers 503, then recovers',
    [503, ''], [200, MANIFEST],
    { first: 502, firstReachedOrigin: false, second: 403, secondReachedOrigin: false, authCalls: 1 });
  await scenario('a manifest that is not JSON, then recovers',
    [200, '<html>'], [200, MANIFEST],
    { first: 502, firstReachedOrigin: false, second: 403, secondReachedOrigin: false, authCalls: 1 });
  await scenario('a manifest that is there from the start',
    [200, MANIFEST], [200, MANIFEST],
    { first: 403, firstReachedOrigin: false, second: 403, secondReachedOrigin: false, authCalls: 2 });
  // A plugin with no `/manifest` at all is the first protocol: a request hook,
  // no gate. That is still served — 404 says "no such route", which a plugin
  // that is merely starting or broken does not.
  await scenario('no manifest route at all (404) is the first protocol',
    [404, ''], [404, ''],
    { first: 200, firstReachedOrigin: true, second: 200, secondReachedOrigin: true, authCalls: 0 });
  return results;
}

// ── main ────────────────────────────────────────────────────────────────

async function main() {
  const certs = makeCerts(path.join(STATE, 'core-certs'));
  const servers = [await startOrigin(), await startTcp(), await startMtls(certs), await startPlugin()];
  const children = [];
  const report = [];
  const raw = [];
  let oneSidedResults = [];
  try {
    children.push(await start('whistle', W), await start('rs', RS));
    for (const c of cases(certs)) {
      if (ONLY && !ONLY.has(c.group)) continue;
      const answers = {};
      for (const [which, port] of [['whistle', W], ['rs', RS]]) {
        // A script case names the proxy's own port, so its rules differ by side.
        if (c.rulesFor) {
          const text = c.rulesFor(port);
          if (which === 'whistle') await send(W, 'POST', '/cgi-bin/rules/add', 'name=Default&selected=1&value=' + encodeURIComponent(text), FORM);
          else await send(RS, 'POST', '/api/rules', text, 'text/plain');
          await new Promise((r) => setTimeout(r, 150));
        } else if (which === 'whistle') {
          await setRules(c.rules);
        }
        answers[which] = JSON.stringify(await c.ask(port));
      }
      const same = answers.whistle === answers.rs;
      raw.push({ case: `${c.group}: ${c.name}`, whistle: answers.whistle, rs: answers.rs, same });
      if (!same) report.push({ name: `${c.group}: ${c.name}`, problems: [`answer: whistle=${answers.whistle} rs=${answers.rs}`] });
    }
    if (!ONLY || ONLY.has('plugin')) oneSidedResults = await oneSided();
  } finally {
    for (const c of children) c.kill('SIGKILL');
    for (const s of servers) s.close();
  }
  const failed = oneSidedResults.filter((r) => !r.ok);
  const verdict = judge('core-bench.js', report, raw.map((r) => r.case));
  const news = new Set(verdict.news.map((n) => n.name));
  const stale = ONLY ? [] : verdict.stale;
  const out = {
    ran: raw.length, differing: verdict.news.length, declared: verdict.declared, stale,
    report: verdict.news, raw, oneSided: oneSidedResults,
  };
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(out, null, 2));
  const mark = (r) => (r.same ? 'same' : news.has(r.case) ? 'DIFF' : 'decl');
  for (const r of raw) console.log(`${mark(r)}  ${r.case}${r.same ? `\n        ${r.rs}` : `\n        whistle ${r.whistle}\n        rs      ${r.rs}`}`);
  for (const e of stale) console.log(`STALE ${e.case}: ${e.why}`);
  for (const r of oneSidedResults) console.log(`${r.ok ? 'ok  ' : 'FAIL'}  plugin: ${r.name}${r.ok ? '' : `\n        got    ${JSON.stringify(r.got)}\n        expect ${JSON.stringify(r.expect)}`}`);
  console.log(`\nwhistle ${WHISTLE.version} — ran: ${raw.length}  differing: ${verdict.news.length}  declared: ${verdict.declared}  stale: ${stale.length}  one-sided: ${oneSidedResults.length} (${failed.length} failed)`);
  process.exit(verdict.news.length || stale.length || failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
