// `frameScript://` on a real WebSocket, through both proxies.
//
//   PORT_BASE=18700 node ws-bench.js     # the pair on PORT_BASE and +1 (run.js starts it)
//
// A frame script installs two handlers on `ctx`: `handleSendToServerFrame` for
// what the client sends, `handleSendToClientFrame` for what the server sends
// back. Each case sends one text frame from a client, lets an echo origin
// answer it, and compares two things between the proxies: what the **origin**
// received, and what the **client** got back. Either can only be seen from its
// own end, so both ends are asked.
//
// Why it exists: whistle up to 2.10.9 handed a client's frames on a plain
// WebSocket to `handleSendToClientFrame` — the other direction's handler — and
// 2.10.10 fixed it (avwo/whistle#1358; `execHandleFrame(…, true)` in
// `handleWsSend`). This port always routed them by direction. Until this bench,
// frame scripts were measured only by `src/proxy/ws.rs`'s own tests, which
// cannot say what upstream does.
//
// Prints `{ ran, differing, declared, stale, report, raw }` like the other JSON
// benches, and exits 1 on a difference `declared.js` does not name.

'use strict';

const crypto = require('crypto');
const http = require('http');
const net = require('net');
const WebSocket = require('ws');
const { judge } = require('./declared.js');

const BASE = Number(process.env.PORT_BASE || 18700);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const HOST = process.env.DIFF_HOST || '127.0.0.1';
const P = `${HOST}:${ORIGIN}`;

/** A rules text carrying its frame script as an inline value. */
const script = (name, body) => `\`\`\` ${name}\n${body}\n\`\`\`\n${P} frameScript://{${name}}`;
const TO_SERVER = 'ctx.handleSendToServerFrame = function (data) { return "S(" + data + ")"; };';
const TO_CLIENT = 'ctx.handleSendToClientFrame = function (data) { return "C(" + data + ")"; };';

const CASES = [
  { name: 'no frame script', rules: '' },
  { name: 'a frame script with both handlers', rules: script('both.js', `${TO_SERVER}\n${TO_CLIENT}`) },
  { name: 'a frame script for the client\'s frames only', rules: script('up.js', TO_SERVER) },
  { name: 'a frame script for the server\'s frames only', rules: script('down.js', TO_CLIENT) },
];

// ── the origin: an echo that remembers what it was sent ──────────────────

/** What the origin received, by the tag in the connection's path. */
const received = new Map();

function startOrigin() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((q, r) => r.end('not a websocket'));
    const wss = new WebSocket.Server({ server });
    wss.on('connection', (ws) => {
      const tag = (ws.upgradeReq && ws.upgradeReq.url || '').split('?')[1] || '';
      ws.on('message', (msg) => {
        const text = String(msg);
        received.set(tag, [...(received.get(tag) || []), text]);
        ws.send(`echo:${text}`);
      });
    });
    server.on('error', (e) => reject(new Error(`origin cannot listen on ${ORIGIN}: ${e.code}`)));
    // Closing the server alone leaves the proxies' upgraded connections open,
    // and the process with them: the connections go first.
    server.listen(ORIGIN, HOST, () => resolve({
      close: () => { for (const ws of wss.clients) ws.terminate(); server.close(); },
    }));
  });
}

// ── the client: one text frame out, one back, over a raw socket ──────────

/** A masked client text frame — the framing a client must use (RFC 6455 §5.3). */
function textFrame(text) {
  const payload = Buffer.from(text);
  if (payload.length >= 126) throw new Error('keep test frames short');
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]));
  return Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]);
}

/** The first complete server frame in `buf`, or null. Servers do not mask. */
function readFrame(buf) {
  if (buf.length < 2) return null;
  let len = buf[1] & 0x7f;
  let at = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    at = 4;
  }
  if (buf.length < at + len) return null;
  return { opcode: buf[0] & 0x0f, text: buf.slice(at, at + len).toString() };
}

/**
 * Through the proxy on `port`: upgrade, send `text`, return the first text
 * frame the client gets back (or what went wrong).
 */
function exchange(port, tag, text) {
  return new Promise((resolve) => {
    const socket = net.connect(port, HOST);
    let buf = Buffer.alloc(0);
    let upgraded = false;
    const done = (answer) => { socket.destroy(); resolve(answer); };
    const timer = setTimeout(() => done(upgraded ? '(no frame back)' : '(no upgrade)'), 5000);
    socket.on('error', (e) => { clearTimeout(timer); done(`(error ${e.code})`); });
    socket.on('connect', () => {
      socket.write([
        `GET http://${P}/ws?${tag} HTTP/1.1`,
        `Host: ${P}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
        'Sec-WebSocket-Version: 13',
        '', '',
      ].join('\r\n'));
    });
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!upgraded) {
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = buf.slice(0, end).toString();
        if (!/^HTTP\/1\.1 101/.test(head)) {
          clearTimeout(timer);
          return done(`(${head.split('\r\n')[0]})`);
        }
        upgraded = true;
        buf = buf.slice(end + 4);
        socket.write(textFrame(text));
      }
      const frame = readFrame(buf);
      if (frame && frame.opcode === 1) {
        clearTimeout(timer);
        done(frame.text);
      }
    });
  });
}

// ── the rules ────────────────────────────────────────────────────────────

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
  const run = Date.now().toString(36);
  const report = [];
  let ran = 0;
  for (const [i, c] of CASES.entries()) {
    await setRules(c.rules);
    const answers = {};
    for (const [who, port] of [['whistle', W], ['rs', RS]]) {
      const tag = `${run}-${i}-${who}`;
      const back = await exchange(port, tag, 'hello');
      // The origin's side lands after its echo went out; give it a beat.
      await new Promise((r) => setTimeout(r, 50));
      answers[who] = { back, origin: (received.get(tag) || []).join(' | ') || '(nothing)' };
    }
    ran++;
    const problems = [];
    for (const field of ['origin', 'back']) {
      if (answers.whistle[field] !== answers.rs[field]) {
        problems.push(`${field}: whistle=${JSON.stringify(answers.whistle[field])} rs=${JSON.stringify(answers.rs[field])}`);
      }
    }
    if (problems.length) report.push({ name: c.name, rules: c.rules, problems });
  }
  await setRules('');
  origin.close();
  const verdict = judge('ws-bench.js', report, CASES.map((c) => c.name));
  console.log(JSON.stringify({
    ran,
    differing: verdict.news.length,
    declared: verdict.declared,
    stale: verdict.stale,
    report: verdict.news,
    raw: report.map(({ name, problems }) => ({ name, problems })),
  }, null, 2));
  process.exitCode = verdict.news.length || verdict.stale.length ? 1 : 0;
}

main().catch((e) => { console.error(e); process.exit(1); });
