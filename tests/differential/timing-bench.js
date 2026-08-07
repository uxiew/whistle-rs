// The rules that are only visible on a clock: `reqDelay`, `resDelay`,
// `reqSpeed`, `resSpeed`.
//
// The main bench compares status, headers and bodies, so a delay rule that does
// nothing at all passes it — the response is byte-identical, just sooner. These
// four were the largest group of documented rules with no differential coverage
// of any kind. This measures them instead: time to first byte for the delays,
// time to drain a body of known size for the speeds, both proxies over the same
// rule.
//
//   PORT_BASE=19600 node timing-bench.js
//     19600 whistle · 19601 whistle-rs · 19602 the origin
//
// Timing is noisy, so every case is run REPEATS times and the **minimum** is
// kept: a delay is a floor, and the fastest of several runs is the closest look
// at that floor with the least scheduler noise on top. A case is reported when
// the two proxies' minima differ by more than the tolerance, which is generous
// on purpose — this is looking for "does nothing" and "wrong by an order of
// magnitude", not for millisecond parity.

const http = require('http');

const BASE = Number(process.env.PORT_BASE || 18700);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const P = `127.0.0.1:${ORIGIN}`;
const REPEATS = Number(process.env.REPEATS || 3);

/** Absolute slack, and relative slack, either of which excuses a difference. */
const SLACK_MS = 120;
const SLACK_REL = 0.35;

/** The origin: an echo, and a body of any size on demand. */
function startOrigin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      const big = /^\/big\/(\d+)/.exec(q.url);
      if (big) {
        r.writeHead(200, { 'content-type': 'application/octet-stream' });
        return r.end(Buffer.alloc(Number(big[1]), 0x61));
      }
      let body = '';
      q.on('data', (c) => (body += c));
      q.on('end', () => {
        r.writeHead(200, { 'content-type': 'application/json' });
        r.end(JSON.stringify({ method: q.method, url: q.url, len: body.length }));
      });
    });
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

async function setRules(text) {
  await post(W, '/cgi-bin/rules/add',
    'name=Default&selected=1&value=' + encodeURIComponent(text),
    'application/x-www-form-urlencoded');
  await post(RS, '/api/rules', text, 'text/plain');
  await new Promise((r) => setTimeout(r, 120));
}

/**
 * One request through one proxy, timed at both interesting moments.
 *
 * `ttfb` is when the response head arrived — where a delay shows up. `drain`
 * is how long the body took after that — where a speed cap shows up. Keeping
 * them apart matters: `resSpeed` on a large body would otherwise be
 * indistinguishable from `resDelay`.
 */
function timed(port, { method = 'GET', path = '/echo', body = '', headers = {} } = {}) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    let tHead = null;
    const req = http.request({
      host: '127.0.0.1', port, method,
      path: `http://${P}${path}`,
      headers: { host: P, ...headers },
    }, (r) => {
      tHead = process.hrtime.bigint();
      let bytes = 0;
      r.on('data', (c) => (bytes += c.length));
      r.on('end', () => {
        const tEnd = process.hrtime.bigint();
        resolve({
          status: r.statusCode,
          bytes,
          ttfb: Number(tHead - t0) / 1e6,
          drain: Number(tEnd - tHead) / 1e6,
        });
      });
    });
    req.on('error', (e) => resolve({ status: 0, bytes: 0, ttfb: -1, drain: -1, note: e.code }));
    req.setTimeout(20000, () => { req.destroy(); resolve({ status: 0, bytes: 0, ttfb: -1, drain: -1, note: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

/** REPEATS runs, keeping the minimum of each phase and the last status. */
async function best(port, request) {
  let out = null;
  for (let i = 0; i < REPEATS; i++) {
    const r = await timed(port, request);
    if (r.status === 0) return r;
    out = out === null ? r : {
      ...r, ttfb: Math.min(out.ttfb, r.ttfb), drain: Math.min(out.drain, r.drain),
    };
  }
  return out;
}

const close = (a, b) => Math.abs(a - b) <= SLACK_MS || Math.abs(a - b) <= SLACK_REL * Math.max(a, b);

const BIG = '/big/300000'; // 300 KB — 2400 kb, so resSpeed://600 is ~4s

const CASES = [
  // ── the shape of the value ───────────────────────────────────────────────
  { name: 'baseline: no rule', rules: '', phase: 'ttfb' },
  { name: 'reqDelay 400', rules: `${P} reqDelay://400`, phase: 'ttfb' },
  { name: 'resDelay 400', rules: `${P} resDelay://400`, phase: 'ttfb' },
  { name: 'both delays add up', rules: `${P} reqDelay://300 resDelay://300`, phase: 'ttfb' },
  { name: 'reqDelay 0 is no delay', rules: `${P} reqDelay://0`, phase: 'ttfb' },
  { name: 'reqDelay negative', rules: `${P} reqDelay://-400`, phase: 'ttfb' },
  { name: 'reqDelay with a unit suffix', rules: `${P} reqDelay://400ms`, phase: 'ttfb' },
  { name: 'reqDelay not a number', rules: `${P} reqDelay://soon`, phase: 'ttfb' },
  { name: 'reqDelay fractional', rules: `${P} reqDelay://400.6`, phase: 'ttfb' },
  { name: 'reqDelay empty value', rules: `${P} reqDelay://`, phase: 'ttfb' },
  { name: 'resDelay with a unit suffix', rules: `${P} resDelay://400ms`, phase: 'ttfb' },
  { name: 'delay is per line, first wins', rules: `${P} reqDelay://400\n${P} reqDelay://40`, phase: 'ttfb' },
  { name: 'important reverses that', rules: `${P} reqDelay://400\n${P} reqDelay://40 lineProps://important`, phase: 'ttfb' },

  // ── delay against the things that answer early ───────────────────────────
  { name: 'reqDelay in front of a mock', rules: `${P} reqDelay://400 file://({"m":1})`, phase: 'ttfb' },
  { name: 'reqDelay in front of statusCode', rules: `${P} reqDelay://400 statusCode://204`, phase: 'ttfb' },
  { name: 'resDelay behind statusCode', rules: `${P} resDelay://400 statusCode://204`, phase: 'ttfb' },
  { name: 'reqDelay in front of a redirect', rules: `${P} reqDelay://400 redirect://http://other.test/`, phase: 'ttfb' },
  { name: 'reqDelay with a filter that misses', rules: `${P} reqDelay://400 includeFilter://m:POST`, phase: 'ttfb' },

  // ── the speeds, measured on a body big enough to see ─────────────────────
  { name: 'baseline: the big body unthrottled', rules: '', request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed 600', rules: `${P} resSpeed://600`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed 1200 is twice as fast', rules: `${P} resSpeed://1200`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed 0 is no cap', rules: `${P} resSpeed://0`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed negative', rules: `${P} resSpeed://-600`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed with a unit suffix', rules: `${P} resSpeed://600kb`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed not a number', rules: `${P} resSpeed://slow`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed fractional', rules: `${P} resSpeed://600.5`, request: { path: BIG }, phase: 'drain' },
  { name: 'resSpeed on a tiny body', rules: `${P} resSpeed://600`, phase: 'drain' },
  { name: 'resSpeed on a mock', rules: `${P} resSpeed://600 file://({"m":1})`, phase: 'drain' },
  { name: 'resSpeed under resReplace', rules: `${P} resSpeed://600 resReplace://a=b`, request: { path: BIG }, phase: 'drain' },

  // `reqSpeed` throttles the body going *up*, which the client cannot see in
  // its own timings — the proxy reads slowly and the origin answers late, so it
  // lands in ttfb, not drain.
  { name: 'reqSpeed 600 on a 150KB post', rules: `${P} reqSpeed://600`, request: { method: 'POST', path: '/echo', body: 'x'.repeat(150000) }, phase: 'ttfb' },
  { name: 'reqSpeed 0 is no cap', rules: `${P} reqSpeed://0`, request: { method: 'POST', path: '/echo', body: 'x'.repeat(150000) }, phase: 'ttfb' },
  { name: 'reqSpeed on a GET', rules: `${P} reqSpeed://600`, phase: 'ttfb' },
  { name: 'both speeds at once', rules: `${P} reqSpeed://1200 resSpeed://1200`, request: { method: 'POST', path: BIG, body: 'x'.repeat(150000) }, phase: 'drain' },
];

async function main() {
  const origin = await startOrigin();

  // A hard baseline. Two proxies that are both dead agree perfectly, and this
  // bench would report it as a clean run.
  await setRules('');
  for (const [who, port] of [['whistle', W], ['whistle-rs', RS]]) {
    const r = await timed(port, {});
    if (r.status !== 200) {
      console.error(`baseline failed for ${who}: ${JSON.stringify(r)}`);
      process.exit(1);
    }
    const b = await timed(port, { path: BIG });
    if (b.status !== 200 || b.bytes !== 300000) {
      console.error(`big-body baseline failed for ${who}: ${JSON.stringify(b)}`);
      process.exit(1);
    }
  }

  let ran = 0, differing = 0;
  const report = [], table = [];
  for (const c of CASES) {
    await setRules(c.rules);
    const [w, rs] = [await best(W, c.request), await best(RS, c.request)];
    ran++;
    const problems = [];
    if (w.status !== rs.status) problems.push(`status: whistle=${w.status}${w.note ? ` (${w.note})` : ''} rs=${rs.status}${rs.note ? ` (${rs.note})` : ''}`);
    if (w.bytes !== rs.bytes) problems.push(`bytes: whistle=${w.bytes} rs=${rs.bytes}`);
    const [a, b] = [w[c.phase], rs[c.phase]];
    if (!close(a, b)) problems.push(`${c.phase}: whistle=${a.toFixed(0)}ms rs=${b.toFixed(0)}ms`);
    table.push(`${differing || problems.length ? ' ' : ' '}${c.name.padEnd(38)} ${c.phase.padEnd(5)} w=${a.toFixed(0).padStart(5)}ms rs=${b.toFixed(0).padStart(5)}ms${problems.length ? '   <<<' : ''}`);
    if (problems.length) { differing++; report.push({ name: c.name, rules: c.rules, problems }); }
  }

  origin.close();
  if (process.env.TABLE) console.error(table.join('\n'));
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
