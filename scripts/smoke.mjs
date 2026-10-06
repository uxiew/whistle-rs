#!/usr/bin/env node
// Use a whistle-rs binary the way a person does, on whatever machine this runs
// on, and say what worked.
//
//   node scripts/smoke.mjs target/release/whistle-rs
//   node scripts/smoke.mjs target\release\whistle-rs.exe --console built --json smoke.json
//
// One run starts the binary on a fresh storage directory with a Node plugin
// (sdk/whistle-rs-plugin.js), edits its rules and values over the API, sends
// HTTP, HTTPS (intercepted, checked against the CA the binary just generated),
// WebSocket, WebSocket-over-TLS and a plugin request through it, kills the
// plugin and checks the next request starts it again, stops it,
// checks the port is free and the plugin gone, starts it a second time on the
// same directory and checks that the CA, rules, values and history came back
// and still work, then stops it again. On Unix a third start ends in SIGKILL,
// which runs none of whistle-rs's shutdown, to check the plugin still goes.
// Everything it talks to is a server this script runs on 127.0.0.1, so no step
// needs the internet or a DNS answer; `node` has to be on PATH for the plugin.
//
// --console built|placeholder|any  what the console page must be (default any).
//                                  `built` compares it with ui-src/dist/index.html
//                                  byte for byte, as scripts/check-console.sh does.
// --json FILE                      also write the report, with the machine, the
//                                  binary's SHA-256 and every step, as JSON.
// --keep                           leave the storage directory for a look.
//
// Exit 0 when every step passed, 1 when one failed, 2 on a usage error. Plain
// Node (20.19 or later), no packages: it has to run on a machine that has
// nothing but the binary and Node.
//
// It does not touch the system proxy settings or any trust store; the CA is
// passed to the TLS client directly.

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createWriteStream, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HOST = 'smoke.test';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const TIMEOUT_MS = 10_000;

// ---- arguments ----------------------------------------------------------

const args = process.argv.slice(2);
let binary = null;
let consoleWant = 'any';
let jsonOut = null;
let keep = false;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--console') consoleWant = args[++i];
  else if (a === '--json') jsonOut = args[++i];
  else if (a === '--keep') keep = true;
  else if (!binary && !a.startsWith('-')) binary = a;
  else usage(`unknown argument ${a}`);
}
if (!binary || !['built', 'placeholder', 'any'].includes(consoleWant)) usage();
binary = path.resolve(binary);
if (!existsSync(binary)) usage(`no binary at ${binary}`);

function usage(why) {
  if (why) console.error(why);
  console.error('usage: node scripts/smoke.mjs <whistle-rs binary> [--console built|placeholder|any] [--json FILE] [--keep]');
  process.exit(2);
}

// ---- the report ---------------------------------------------------------

const steps = [];
async function step(name, fn) {
  const started = Date.now();
  try {
    const detail = (await fn()) ?? '';
    steps.push({ name, ok: true, detail, ms: Date.now() - started });
    console.log(`ok    ${name}${detail ? `  — ${detail}` : ''}`);
    return true;
  } catch (e) {
    const detail = e?.message ?? String(e);
    steps.push({ name, ok: false, detail, ms: Date.now() - started });
    console.log(`FAIL  ${name}  — ${detail}`);
    return false;
  }
}
function skip(name, why) {
  steps.push({ name, ok: true, skipped: true, detail: why, ms: 0 });
  console.log(`skip  ${name}  — ${why}`);
}
function check(cond, message) {
  if (!cond) throw new Error(message);
}
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const withTimeout = (promise, what, ms = TIMEOUT_MS) =>
  Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${what}: no answer in ${ms} ms`)), ms).unref()),
  ]);

// ---- WebSocket frames, both ends ------------------------------------------

/** One unfragmented frame; `mask` for a client, which RFC 6455 requires. */
function frame(opcode, payload, mask) {
  const body = Buffer.from(payload);
  check(body.length < 126, 'this script only writes short frames');
  const head = Buffer.from([0x80 | opcode, (mask ? 0x80 : 0) | body.length]);
  if (!mask) return Buffer.concat([head, body]);
  const key = randomBytes(4);
  const masked = Buffer.from(body.map((b, i) => b ^ key[i % 4]));
  return Buffer.concat([head, key, masked]);
}

/** Pull whole frames off the front of `buf`; returns [frames, rest]. */
function parseFrames(buf) {
  const frames = [];
  for (;;) {
    if (buf.length < 2) break;
    const opcode = buf[0] & 0x0f;
    const masked = (buf[1] & 0x80) !== 0;
    let len = buf[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (buf.length < 4) break;
      len = buf.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (buf.length < 10) break;
      len = Number(buf.readBigUInt64BE(2));
      off = 10;
    }
    const keyLen = masked ? 4 : 0;
    if (buf.length < off + keyLen + len) break;
    let payload = buf.subarray(off + keyLen, off + keyLen + len);
    if (masked) {
      const key = buf.subarray(off, off + 4);
      payload = Buffer.from(payload.map((b, i) => b ^ key[i % 4]));
    }
    frames.push({ opcode, payload });
    buf = buf.subarray(off + keyLen + len);
  }
  return [frames, buf];
}

// ---- the origin: one server for plain HTTP and WebSocket ----------------------

const origin = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'text/plain', 'x-origin': 'smoke' });
    res.end(`origin saw ${req.method} ${req.url} host=${req.headers.host}${body ? ` body=${body}` : ''}`);
  });
});
origin.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  const accept = createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  let pending = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    let frames;
    [frames, pending] = parseFrames(Buffer.concat([pending, chunk]));
    for (const f of frames) {
      if (f.opcode === 1) socket.write(frame(1, `echo: ${f.payload}`, false));
      if (f.opcode === 8) socket.end(frame(8, '', false));
    }
  });
  socket.on('error', () => {});
});

// ---- talking to the proxy ------------------------------------------------------

let proxyPort = 0;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function portIsFree(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
  });
}

/** A request, answered with {status, headers, body}. `options` go to http.request. */
function request(options, payload) {
  return withTimeout(
    new Promise((resolve, reject) => {
      const req = http.request({ agent: false, ...options }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.end(payload);
    }),
    `${options.method ?? 'GET'} ${options.path}`,
  );
}

/** The console's API, straight to the proxy's port (not proxied). */
async function api(method, pathname, payload) {
  const res = await request({ host: '127.0.0.1', port: proxyPort, method, path: pathname }, payload);
  check(res.status === 200, `${method} ${pathname} answered ${res.status}: ${res.body.toString().slice(0, 200)}`);
  return res.body.toString();
}

/** A request for http://smoke.test/… sent through the proxy. */
const viaProxy = (pathname) =>
  request({ host: '127.0.0.1', port: proxyPort, path: `http://${HOST}${pathname}`, headers: { host: HOST } });

/** CONNECT smoke.test:443, then TLS inside it, trusting only `ca`. */
function tunnel(ca) {
  return withTimeout(
    new Promise((resolve, reject) => {
      const req = http.request({
        agent: false,
        host: '127.0.0.1',
        port: proxyPort,
        method: 'CONNECT',
        path: `${HOST}:443`,
        headers: { host: `${HOST}:443` },
      });
      req.on('connect', (res, socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          reject(new Error(`CONNECT answered ${res.statusCode}`));
          return;
        }
        const secure = tls.connect({ socket, servername: HOST, ca, ALPNProtocols: ['http/1.1'] });
        secure.once('secureConnect', () => resolve(secure));
        secure.once('error', reject);
      });
      req.on('error', reject);
      req.end();
    }),
    'CONNECT and TLS handshake',
  );
}

/** GET https://smoke.test/… through the proxy, with its interception CA. */
async function viaTls(pathname, ca) {
  const secure = await tunnel(ca);
  const cert = secure.getPeerCertificate();
  // `agent: undefined`, not false: with an agent, Node ignores createConnection
  // and dials smoke.test itself.
  const res = await request({ agent: undefined, host: HOST, path: pathname, createConnection: () => secure });
  return { ...res, issuer: cert?.issuer?.CN, subjectaltname: cert?.subjectaltname };
}

/**
 * Open a WebSocket over `socket`, send one text message and read the echo.
 * `target` is the request line's target: absolute to a proxy, a path inside TLS.
 */
function wsRoundTrip(socket, target, message) {
  return withTimeout(
    new Promise((resolve, reject) => {
      const key = randomBytes(16).toString('base64');
      const expected = createHash('sha1').update(key + WS_GUID).digest('base64');
      let buf = Buffer.alloc(0);
      let upgraded = false;
      socket.on('error', reject);
      socket.on('close', () => reject(new Error(upgraded ? 'closed before the echo' : 'closed before the 101')));
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (!upgraded) {
          const end = buf.indexOf('\r\n\r\n');
          if (end < 0) return;
          const head = buf.subarray(0, end).toString();
          buf = buf.subarray(end + 4);
          const status = head.split('\r\n')[0];
          if (!/^HTTP\/1\.1 101/.test(status)) return reject(new Error(`upgrade answered "${status}"`));
          const accept = /\r\nsec-websocket-accept:\s*(\S+)/i.exec(head)?.[1];
          if (accept !== expected) return reject(new Error(`Sec-WebSocket-Accept ${accept}, expected ${expected}`));
          upgraded = true;
          socket.write(frame(1, message, true));
        }
        const [frames] = parseFrames(buf);
        const text = frames.find((f) => f.opcode === 1);
        if (text) {
          socket.write(frame(8, '', true));
          socket.end();
          resolve(text.payload.toString());
        }
      });
      socket.write(
        `GET ${target} HTTP/1.1\r\nHost: ${HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
    }),
    `WebSocket ${target}`,
  );
}

const connectToProxy = () =>
  new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, '127.0.0.1', () => resolve(s));
    s.once('error', reject);
  });

// ---- the binary ------------------------------------------------------------------

const work = mkdtempSync(path.join(os.tmpdir(), 'whistle-rs-smoke-'));
const dataDir = path.join(work, 'data');
let child = null;
let childExit = null;
let logFile = null;

// The plugin answers with its pid, so the script can tell whether that
// process outlives the proxy.
const pluginFile = path.join(work, 'smoke-plugin.cjs');
writeFileSync(
  pluginFile,
  `const { start } = require(${JSON.stringify(path.join(root, 'sdk', 'whistle-rs-plugin.js'))});
start({
  name: 'smoke',
  onRequest(ctx) {
    ctx.respond({ statusCode: 200, body: 'plugin pid=' + process.pid });
  },
});
`,
);

/** Start the binary on `dataDir` and wait until its API answers. */
async function start(run) {
  logFile = path.join(work, `run${run}.log`);
  const log = createWriteStream(logFile);
  // The proxy variables this shell may carry mean nothing to the binary, but a
  // run should not depend on what happened to be exported where it was started.
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(https?|all|no)_proxy$/i.test(k)));
  child = spawn(binary, ['-p', String(proxyPort), '--dir', dataDir, '--node-plugin', `smoke=${pluginFile}`], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.pipe(log);
  child.stderr.pipe(log);
  childExit = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`exited during startup (${child.exitCode ?? child.signalCode}); log: ${tail()}`);
    }
    try {
      const res = await request({ host: '127.0.0.1', port: proxyPort, path: '/api/status' });
      if (res.status === 200) return JSON.parse(res.body.toString());
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) throw new Error(`no answer on 127.0.0.1:${proxyPort} after 30 s; log: ${tail()}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

function tail() {
  try {
    return readFileSync(logFile, 'utf8').split('\n').slice(-15).join('\n');
  } catch {
    return '(no log)';
  }
}

/**
 * Stop it the way a person would: Ctrl+C (SIGINT) or a service manager's
 * SIGTERM on Unix. Windows has no signals to send another process from here;
 * `kill()` there is TerminateProcess, what closing the console window or
 * `taskkill /F` amounts to.
 */
async function stop(signal) {
  const sent = process.platform === 'win32' ? 'TerminateProcess' : signal;
  child.kill(signal);
  const exit = await withTimeout(childExit, `exit after ${sent}`, 10_000);
  child = null;
  return `${sent} → exited (${exit.code ?? exit.signal})`;
}

/** Every plugin pid seen, so a failed run does not leave them behind. */
const pluginPids = new Set();

/** The pid the plugin reports, from a request routed to it by the rules. */
async function pluginPid() {
  const res = await viaProxy('/plugin');
  const pid = Number(/^plugin pid=(\d+)$/.exec(res.body.toString())?.[1]);
  check(res.status === 200 && pid > 0, `plugin://smoke answered ${res.status} ${JSON.stringify(res.body.toString())}`);
  pluginPids.add(pid);
  return pid;
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/** The plugin process is gone within a few seconds of the proxy. */
async function pluginGone(pid) {
  for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
  check(!alive(pid), `plugin process ${pid} is still running after 5 s`);
  return `pid ${pid} gone`;
}

// ---- the run ------------------------------------------------------------------------

const RULES = [
  `${HOST}/plugin plugin://smoke`,
  `${HOST} http://127.0.0.1:{origin}`,
  `${HOST} resHeaders://x-smoke=rules-applied`,
  `${HOST}/value resBody://{smoke-value}`,
].join('\n');
const VALUE = 'value-applied';

let version = '';
let sessionUrls = [];
let maxIdBefore = 0;
let caHash = '';

async function run() {
  await new Promise((r) => origin.listen(0, '127.0.0.1', r));
  const originPort = origin.address().port;
  const rules = RULES.replace('{origin}', originPort);
  proxyPort = await freePort();

  version = await new Promise((resolve) => {
    const p = spawn(binary, ['--version'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    p.stdout.on('data', (c) => (out += c));
    p.on('close', () => resolve(out.trim()));
    p.on('error', () => resolve(''));
  });
  console.log(`${version || 'whistle-rs (no --version)'} on ${os.platform()} ${os.release()} ${os.arch()}, Node ${process.version}`);
  console.log(`storage ${dataDir}, proxy port ${proxyPort}, origin port ${originPort}\n`);

  // -- first run: a fresh directory --
  if (!(await step('starts on a fresh directory', async () => {
    const status = await start(1);
    return `listening on ${status.host}:${status.port}`;
  }))) return;

  await step('generates a root CA on first start', () => {
    const crt = path.join(dataDir, 'certs', 'root.crt');
    check(existsSync(crt), `no ${crt}`);
    check(existsSync(path.join(dataDir, 'certs', 'root.key')), 'no certs/root.key');
    caHash = sha256(readFileSync(crt));
    return `certs/root.crt sha256 ${caHash.slice(0, 12)}…`;
  });

  await step('serves the console', async () => {
    const res = await request({ host: '127.0.0.1', port: proxyPort, path: '/' });
    check(res.status === 200, `GET / answered ${res.status}`);
    const page = res.body.toString();
    const placeholder = page.includes('console not built');
    if (consoleWant === 'placeholder') check(placeholder, 'expected the placeholder page');
    if (consoleWant === 'built') {
      check(!placeholder, 'the binary serves the placeholder: ui-src/dist was missing when it was compiled');
      const dist = path.join(root, 'ui-src', 'dist', 'index.html');
      check(existsSync(dist), `no ${dist} to compare with`);
      const v = version.split(' ')[1] ?? '';
      const expected = readFileSync(dist, 'utf8')
        .replaceAll('__VERSION__', v)
        .replaceAll('__HOST__', '127.0.0.1')
        .replaceAll('__PORT__', String(proxyPort));
      check(page === expected, 'the page differs from ui-src/dist/index.html: the binary embeds another build');
    }
    return placeholder ? 'placeholder page' : `console page, ${res.body.length} bytes`;
  });

  await step('rules edited over the API', async () => {
    await api('POST', '/api/rules', rules);
    const back = await api('GET', '/api/rules');
    check(back.trim() === rules.trim(), `GET /api/rules gave back ${JSON.stringify(back)}`);
    return '3 lines in the Default group';
  });

  await step('a value set over the API', async () => {
    await api('POST', '/api/value', JSON.stringify({ name: 'smoke-value', value: VALUE }));
    const values = JSON.parse(await api('GET', '/api/values'));
    check(values['smoke-value'] === VALUE, `GET /api/values: ${JSON.stringify(values)}`);
  });

  await step('HTTP through the proxy, rules applied', async () => {
    const res = await viaProxy('/plain?x=1');
    check(res.status === 200, `status ${res.status}`);
    check(res.headers['x-origin'] === 'smoke', 'did not reach the origin the rule forwards to');
    check(res.headers['x-smoke'] === 'rules-applied', `x-smoke is ${res.headers['x-smoke']}`);
    const valued = await viaProxy('/value');
    check(valued.body.toString() === VALUE, `resBody://{smoke-value} gave ${JSON.stringify(valued.body.toString())}`);
    return res.body.toString();
  });

  const ca = () => readFileSync(path.join(dataDir, 'certs', 'root.crt'));
  await step('HTTPS intercepted, certificate chains to the generated CA', async () => {
    const res = await viaTls('/secure', ca());
    check(res.status === 200, `status ${res.status}`);
    check(res.headers['x-smoke'] === 'rules-applied', `x-smoke is ${res.headers['x-smoke']}`);
    check(res.body.toString().includes('GET /secure'), `body ${res.body}`);
    return `leaf for ${res.subjectaltname}, issued by "${res.issuer}"`;
  });

  await step('WebSocket through the proxy', async () => {
    const echo = await wsRoundTrip(await connectToProxy(), `http://${HOST}/ws`, 'hello ws');
    check(echo === 'echo: hello ws', `got ${JSON.stringify(echo)}`);
    return echo;
  });

  await step('WebSocket inside intercepted TLS', async () => {
    const echo = await wsRoundTrip(await tunnel(ca()), '/wss', 'hello wss');
    check(echo === 'echo: hello wss', `got ${JSON.stringify(echo)}`);
    return echo;
  });

  let plugin = 0;
  await step('a Node plugin started by the proxy answers', async () => {
    plugin = await pluginPid();
    return `pid ${plugin}`;
  });

  // Killed from outside, as a crash would end it. The next request that needs
  // it starts it again and waits for it, as upstream does; it used to go
  // straight to the origin from then on.
  if (plugin) {
    await step('a plugin that dies is started again for the next request', async () => {
      const was = plugin;
      process.kill(was, 'SIGKILL');
      for (let i = 0; i < 50 && alive(was); i++) await new Promise((r) => setTimeout(r, 100));
      check(!alive(was), `plugin process ${was} survived SIGKILL`);
      plugin = await pluginPid();
      check(plugin !== was, `the killed process ${was} answered`);
      return `pid ${was} killed, pid ${plugin} answered`;
    });
  }

  await step('the console lists those requests', async () => {
    const want = [`http://${HOST}/plain?x=1`, `https://${HOST}/secure`, `ws://${HOST}/ws`, `wss://${HOST}/wss`];
    // A WebSocket session completes when it closes, a moment after the echo.
    let list = [];
    for (let i = 0; i < 50; i++) {
      list = JSON.parse(await api('GET', '/sessions.json'));
      if (want.every((u) => list.some((s) => s.url === u && !s.open))) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const missing = want.filter((u) => !list.some((s) => s.url === u));
    check(missing.length === 0, `missing ${missing.join(', ')}; has ${list.map((s) => s.url).join(', ')}`);
    sessionUrls = want;
    maxIdBefore = Math.max(...list.map((s) => s.id));
    return `${list.length} sessions`;
  });

  if (process.platform === 'win32') {
    skip('the key, history and rules are the owner\'s alone', 'Windows: no Unix modes; the profile directory\'s ACL decides');
  } else {
    await step('the key, history and rules are the owner\'s alone', () => {
      const mode = (p) => (statSync(path.join(dataDir, p)).mode & 0o777).toString(8);
      const want = { 'certs/root.key': '600', certs: '700', rules: '700', sessions: '700' };
      const wrong = Object.entries(want).filter(([p, m]) => mode(p) !== m);
      check(wrong.length === 0, wrong.map(([p, m]) => `${p} is ${mode(p)}, want ${m}`).join('; '));
      return Object.entries(want).map(([p, m]) => `${p} ${m}`).join(', ');
    });
  }

  if (!(await step('stops on Ctrl+C', () => stop('SIGINT')))) return;
  await step('the port is free again', async () => {
    check(await portIsFree(proxyPort), `127.0.0.1:${proxyPort} is still taken`);
  });
  if (plugin) await step('the plugin stopped with it', () => pluginGone(plugin));

  // -- second run: the same directory --
  if (!(await step('starts again on the same directory and port', async () => {
    const status = await start(2);
    return `${status.sessions} sessions loaded`;
  }))) return;

  await step('the same root CA', () => {
    const now = sha256(readFileSync(path.join(dataDir, 'certs', 'root.crt')));
    check(now === caHash, `certs/root.crt changed: ${now.slice(0, 12)}… was ${caHash.slice(0, 12)}…`);
  });

  await step('rules and values came back', async () => {
    const back = await api('GET', '/api/rules');
    check(back.trim() === rules.trim(), `GET /api/rules: ${JSON.stringify(back)}`);
    const values = JSON.parse(await api('GET', '/api/values'));
    check(values['smoke-value'] === VALUE, `GET /api/values: ${JSON.stringify(values)}`);
  });

  await step('history came back', async () => {
    const list = JSON.parse(await api('GET', '/sessions.json'));
    const missing = sessionUrls.filter((u) => !list.some((s) => s.url === u));
    check(missing.length === 0, `missing ${missing.join(', ')}`);
    return `${list.length} sessions`;
  });

  await step('HTTP and HTTPS still work, with the reloaded rules, value and CA', async () => {
    const plain = await viaProxy('/value');
    check(plain.body.toString() === VALUE, `resBody://{smoke-value} gave ${JSON.stringify(plain.body.toString())}`);
    const secure = await viaTls('/again', ca());
    check(secure.headers['x-smoke'] === 'rules-applied', `x-smoke is ${secure.headers['x-smoke']}`);
    const list = JSON.parse(await api('GET', '/sessions.json'));
    const fresh = list.filter((s) => s.url === `https://${HOST}/again`);
    check(fresh.length === 1 && fresh[0].id > maxIdBefore, `new session ids must continue past ${maxIdBefore}`);
    return `new session #${fresh[0].id}`;
  });

  plugin = 0;
  await step('the plugin is started again', async () => {
    plugin = await pluginPid();
    return `pid ${plugin}`;
  });

  if (!(await step('stops on SIGTERM', () => stop('SIGTERM')))) return;
  await step('the port is free again', async () => {
    check(await portIsFree(proxyPort), `127.0.0.1:${proxyPort} is still taken`);
  });
  if (plugin) await step('the plugin stopped with it', () => pluginGone(plugin));

  // -- third run, Unix only: a kill nothing can handle. On Windows every stop
  // above already was one (TerminateProcess). --
  if (process.platform !== 'win32') {
    if (await step('starts a third time', async () => void (await start(3)))) {
      plugin = 0;
      await step('the plugin is started again', async () => {
        plugin = await pluginPid();
        return `pid ${plugin}`;
      });
      await step('killed with SIGKILL', () => stop('SIGKILL'));
      await step('the port is free again', async () => {
        check(await portIsFree(proxyPort), `127.0.0.1:${proxyPort} is still taken`);
      });
      if (plugin) await step('the plugin still stopped, on its closed stdin', () => pluginGone(plugin));
    }
  }

  // What the directory holds, for the install notes: the same on every OS?
  const files = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else files.push(path.relative(dataDir, p).split(path.sep).join('/'));
    }
  };
  walk(dataDir);
  console.log(`\nstorage directory holds: ${files.sort().join(', ')}`);
  return files;
}

let files = [];
try {
  files = (await run()) ?? [];
} catch (e) {
  steps.push({ name: 'the script itself', ok: false, detail: e.stack ?? String(e), ms: 0 });
  console.log(`FAIL  the script itself  — ${e.stack ?? e}`);
} finally {
  if (child) child.kill('SIGKILL');
  for (const pid of pluginPids) {
    if (alive(pid)) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // gone in between
      }
    }
  }
  origin.close();
  origin.closeAllConnections?.();
}

const failed = steps.filter((s) => !s.ok);
if (failed.length && logFile) console.log(`\nthe binary's log (last run):\n${tail()}`);
if (jsonOut) {
  writeFileSync(
    jsonOut,
    `${JSON.stringify(
      {
        passed: failed.length === 0,
        version,
        binary: { path: binary, sha256: sha256(readFileSync(binary)) },
        machine: { platform: os.platform(), release: os.release(), arch: os.arch(), node: process.version },
        when: new Date().toISOString(),
        steps,
        storageFiles: files,
      },
      null,
      2,
    )}\n`,
  );
}
if (!keep) {
  // Windows can hold a just-closed file for a moment after its process exits.
  for (let i = 0; i < 20; i++) {
    try {
      rmSync(work, { recursive: true, force: true });
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
} else {
  console.log(`kept ${work}`);
}
console.log(`\n${steps.length - failed.length}/${steps.length} passed${failed.length ? `; failed: ${failed.map((s) => s.name).join('; ')}` : ''}`);
process.exit(failed.length ? 1 : 0);
