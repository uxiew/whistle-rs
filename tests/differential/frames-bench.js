// The **frames** each console reports, compared.
//
// `cases-frames.js` compares what the framing does to the wire, and for a long
// time that was said to be all a bench could reach: the two consoles are
// different programs with different data models. That was wrong, and believing
// it cost a real divergence — this port framed a body on a separator header
// alone, where upstream wants `enable://captureStream` as well, and nothing on
// the wire could tell.
//
// The models differ; the *question* does not. "How many frames did this request
// produce, carrying what, in which direction" is one question, and both consoles
// answer it over HTTP:
//
//   whistle     POST /cgi-bin/sessions {latest:true}   → the capture
//               POST /cgi-bin/frames   {reqId}         → its frames (base64)
//   whistle-rs  GET  /sessions.json                    → the capture
//               GET  /frames.json?id=                  → its frames (previews)
//
//   PORT_BASE=19300 node oracle.js &
//   cargo run -- --port 19301 --no-persist --dir /tmp/rs-frames &
//   PORT_BASE=19300 node frames-bench.js
//     19300 whistle · 19301 whistle-rs · 19302 the origin
//
// **Two things this bench had to learn the hard way**, both about state it did
// not own. An oracle is meant to be left running between runs, so its capture
// holds every earlier run's sessions too — a per-case tag that repeated across
// runs made the session lookup land on an answer from hours before, and a
// passing case read as a failing one for most of an afternoon. Tags now carry
// the run, and the lookup takes the newest match rather than the first. And an
// origin left listening on this bench's port from an earlier experiment made it
// measure somebody else's server while reporting numbers; it now refuses to
// start in that case, and checks that what answers is really its own origin.
//
// **What is compared.** The payloads, in order, each tagged with its direction.
// Not the ids, the timestamps or the lengths: those are each console's own
// bookkeeping. A frame's *content* is the thing a person opens the panel to see.
//
// The origin here serves bodies whose shape is the subject — a chunked JSON
// stream, an event stream, a body with no separator in it at all — so a case is
// a rule plus a path, and the answer is a list of strings.

'use strict';

const http = require('http');

const BASE = Number(process.env.PORT_BASE || 19300);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const P = `127.0.0.1:${ORIGIN}`;

/** Bodies the framing has something to say about. */
const BODIES = {
  // Three JSON objects, newline separated, written as three chunks — the FAQ's
  // own scenario for a custom separator.
  '/chunked': ['application/json', ['{"a":1}\n', '{"b":2}\n', '{"c":3}\n']],
  // An event stream: framed by content type alone, with no flag and no header.
  '/sse': ['text/event-stream', ['data: one\n\n', 'data: two\n\n', 'data: three\n\n']],
  // The same three objects with nothing to split on.
  '/nosep': ['application/json', ['{"a":1}', '{"b":2}', '{"c":3}']],
};

function startOrigin() {
  return new Promise((res, rej) => {
    const srv = http.createServer((q, r) => {
      const path = q.url.split('?')[0];
      const body = BODIES[path] || BODIES['/nosep'];
      r.writeHead(200, { 'content-type': body[0], 'x-frames-origin': 'yes' });
      for (const chunk of body[1]) r.write(chunk);
      r.end();
    });
    // A port held by somebody else is the worst thing that can happen to a
    // bench: it reports numbers, and they are about a server nobody meant to
    // measure. It has happened three times in one afternoon here, always with a
    // leftover from an earlier experiment, and always looking like a finding.
    srv.on('error', (e) => rej(new Error(
      `origin cannot listen on ${ORIGIN}: ${e.code}. Something else is holding `
      + 'that port — a leftover origin from an earlier run is the usual answer.',
    )));
    srv.listen(ORIGIN, () => res(srv));
  });
}

/**
 * Refuse to run until the origin answering on that port is **this** one.
 *
 * Binding proves the port was free at that instant; it does not prove that what
 * answers a request is the server just started, and a bench that measures the
 * wrong server is worse than one that does not run.
 */
async function checkOrigin() {
  const a = await req(ORIGIN, { path: '/sse' });
  if (!/data: one/.test(a.body)) {
    throw new Error(`the server on ${ORIGIN} is not this bench's origin: ${a.status} ${a.body.slice(0, 60)}`);
  }
}

const req = (port, { method = 'GET', path, headers = {}, body }) =>
  new Promise((resolve) => {
    const opts = { port, path, method, headers: { ...headers } };
    if (body != null) opts.headers['content-length'] = Buffer.byteLength(body);
    const r = http.request(opts, (x) => {
      let s = '';
      x.on('data', (c) => (s += c));
      x.on('end', () => resolve({ status: x.statusCode, body: s }));
    });
    r.on('error', (e) => resolve({ status: 0, body: 'ERR ' + e.code }));
    r.setTimeout(8000, () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
    r.end(body);
  });

const json = (text, fallback) => { try { return JSON.parse(text); } catch (e) { return fallback; } };

async function setRules(text) {
  await req(W, { method: 'POST', path: '/cgi-bin/rules/add',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=Default&selected=1&value=' + encodeURIComponent(text) });
  await req(RS, { method: 'POST', path: '/api/rules',
    headers: { 'content-type': 'text/plain' }, body: text });
  await new Promise((r) => setTimeout(r, 200));
}

/** The frames whistle recorded for the session whose URL carries `tag`. */
async function whistleFrames(tag) {
  const sessions = json((await req(W, { method: 'POST', path: '/cgi-bin/sessions',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ latest: true }) })).body, []);
  const list = Array.isArray(sessions) ? sessions : (sessions.data || []);
  // The **newest** match, not the first. Upstream's list is oldest first, and
  // an oracle left running between runs keeps every session it has ever seen —
  // so a tag that is not unique per run reads somebody's older answer. That is
  // exactly what happened: a tag repeated across eight runs, `find` returned the
  // one from hours earlier, and a passing case looked like a failing one.
  const hits = list.filter((x) => (x.url || '').includes(tag));
  const s = hits[hits.length - 1];
  if (!s) return ['(no session)'];
  const frames = json((await req(W, { method: 'POST', path: '/cgi-bin/frames',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reqId: s.id, latest: true }) })).body, []);
  const arr = Array.isArray(frames) ? frames : (frames.data || []);
  // Oldest first already. This port's list is newest first and is reversed
  // below, so both end up in the order a person reads them in.
  return arr.map((f) => (f.isClient ? '>' : '<') + Buffer.from(f.base64 || '', 'base64').toString());
}

/** The same, from this port. */
async function rsFrames(tag) {
  // Newest first here, so the first match is the newest — the same care as
  // above, from the other end of the list.
  const sessions = json((await req(RS, { path: '/sessions.json' })).body, []);
  const s = sessions.find((x) => (x.url || '').includes(tag));
  if (!s) return ['(no session)'];
  const frames = json((await req(RS, { path: `/frames.json?id=${s.id}` })).body, []);
  return frames.map((f) => (f.dir === 'send' ? '>' : '<') + f.preview).reverse();
}

const SEP = 'x-whistle-custom-frame-separator';

/**
 * Each case is a rule, a request, and the frames it should produce. `name` says
 * what is being asked; what upstream answers is the answer.
 */
const CASES = [
  // ── the event stream, which needs no flag and no header ────────────────
  { name: 'an event stream is framed by its content type', rules: '', path: '/sse' },
  { name: 'an event stream under enable://captureStream',
    rules: `${P} enable://captureStream`, path: '/sse' },
  { name: 'an event stream under disable://captureStream',
    rules: `${P} disable://captureStream`, path: '/sse' },

  // ── a named separator, which needs the flag ────────────────────────────
  //
  // The FAQ prints `enable://captureStream` alongside the header and it is not
  // decoration: without it upstream frames nothing at all. Measured on both
  // sides of the exchange.
  { name: 'a response separator with the flag',
    rules: `${P} enable://captureStream resHeaders://(${SEP}=%0A)`, path: '/chunked' },
  { name: 'a response separator without the flag',
    rules: `${P} resHeaders://(${SEP}=%0A)`, path: '/chunked' },
  { name: 'a request separator with the flag',
    rules: `${P} enable://captureStream`, path: '/chunked',
    request: { method: 'POST', headers: { [SEP]: '%0A', 'content-type': 'text/plain' }, body: 'one\ntwo\nthree' } },
  { name: 'a request separator without the flag',
    rules: '', path: '/chunked',
    request: { method: 'POST', headers: { [SEP]: '%0A', 'content-type': 'text/plain' }, body: 'one\ntwo\nthree' } },

  // ── what the separator does to the frame it ends ───────────────────────
  { name: 'a leading slash keeps the separator on the frame',
    rules: `${P} enable://captureStream resHeaders://(${SEP}=/%0A)`, path: '/chunked' },
  { name: 'a separator that appears nowhere in the body',
    rules: `${P} enable://captureStream resHeaders://(${SEP}=ZZZ)`, path: '/chunked' },
  { name: 'a separator that is not the newline',
    rules: `${P} enable://captureStream resHeaders://(${SEP}=%7D)`, path: '/nosep' },
  // The FAQ prints `%A0` where it means `%0A`. Kept as a case rather than as a
  // note: what the typo *does* is a fact about the parser, and both proxies
  // should do the same thing with it.
  { name: "the FAQ's own example, typo and all",
    rules: `${P} disable://gzip enable://captureStream reqHeaders://(${SEP}=%A0) resHeaders://(${SEP}=%A0)`,
    path: '/chunked' },
  { name: 'the same example with the newline it meant',
    rules: `${P} disable://gzip enable://captureStream reqHeaders://(${SEP}=%0A) resHeaders://(${SEP}=%0A)`,
    path: '/chunked' },

  // ── and the ones that should produce nothing ───────────────────────────
  { name: 'no rule and no separator', rules: '', path: '/chunked' },
  { name: 'the flag alone frames nothing', rules: `${P} enable://captureStream`, path: '/chunked' },
];

async function main() {
  const origin = await startOrigin();
  await checkOrigin();
  // Unique to this run. An oracle is meant to be left running between runs — it
  // takes seconds to start — so its capture holds every earlier run's sessions
  // too, and a tag reused across runs is a lookup that can land on any of them.
  const run = Date.now().toString(36);
  let ran = 0;
  let differing = 0;
  const report = [];
  for (const [i, c] of CASES.entries()) {
    const tag = `/f${run}x${i}`;
    await setRules(c.rules);
    const r = c.request || {};
    const shape = {
      method: r.method || 'GET',
      // The tag rides in the query so the path still selects a body.
      path: `http://${P}${c.path}?tag=${tag.slice(1)}`,
      headers: { host: P, ...(r.headers || {}) },
      body: r.body,
    };
    await req(W, shape);
    await req(RS, shape);
    // **Poll, do not sleep.** Upstream emits the tail of a body only when the
    // body ends (`if (end) emitFrame(buf)`, `data.js:126-129`), so a case whose
    // separator never matches has *nothing* to show until then — it is the most
    // timing-sensitive case in the file, and a fixed wait made it pass on a
    // quiet machine and fail on a busy one. A real difference survives the
    // waiting; a race does not.
    let w = [];
    let rs = [];
    for (let attempt = 0; attempt < 20; attempt++) {
      await new Promise((x) => setTimeout(x, 120));
      [w, rs] = [await whistleFrames(tag.slice(1)), await rsFrames(tag.slice(1))];
      if (JSON.stringify(w) === JSON.stringify(rs)) break;
    }
    ran++;
    if (JSON.stringify(w) !== JSON.stringify(rs)) {
      differing++;
      report.push({ name: c.name, rules: c.rules, whistle: w, rs });
    }
  }
  origin.close();
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
