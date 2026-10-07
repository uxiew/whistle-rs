// The rules that leave their answer on **disk**: `reqWrite`, `reqWriteRaw`,
// `resWrite`, `resWriteRaw`.
//
// Nothing the client receives changes when these fire, so the main bench passes
// them byte for byte whether they work or not — they were four of the eight
// documented rules with no differential coverage of any kind. This runs the two
// proxies **one at a time** against the same path, reading and removing the file
// between, and compares what each wrote.
//
//   PORT_BASE=19600 node write-bench.js
//     19600 whistle · 19601 whix · 19602 the origin
//
// Sequential rather than side by side on purpose: the rules text has to be
// identical for both, so both name the same file, and a parallel run would have
// them appending into each other's dump.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { judge } = require('./declared.js');

const BASE = Number(process.env.PORT_BASE || 18700);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];
const P = `127.0.0.1:${ORIGIN}`;
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-writes-'));

/** The origin: a fixed answer per path, so the dumps are comparable. */
function startOrigin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      const inbound = [];
      q.on('data', (c) => inbound.push(c));
      q.on('end', () => {
        if (q.url.startsWith('/404')) {
          r.writeHead(404, { 'content-type': 'text/plain' });
          return r.end('MISSING');
        }
        if (q.url.startsWith('/204')) {
          r.writeHead(204, { 'x-origin': 'yes' });
          return r.end();
        }
        r.writeHead(200, { 'content-type': 'text/plain', 'x-origin': 'yes' });
        r.end('ORIGINAL BODY');
      });
    });
    srv.listen(ORIGIN, () => res(srv));
  });
}

const post = (port, p, body, type) =>
  new Promise((res, rej) => {
    const req = http.request(
      { port, path: p, method: 'POST', headers: { 'content-type': type, 'content-length': Buffer.byteLength(body) } },
      (r) => { let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => res(b)); },
    );
    req.on('error', rej);
    req.setTimeout(10000, () => { req.destroy(); rej(new Error(`rules POST to :${port} timed out`)); });
    req.end(body);
  });

async function setRules(port, text) {
  if (port === W) {
    await post(W, '/cgi-bin/rules/add',
      'name=Default&selected=1&value=' + encodeURIComponent(text),
      'application/x-www-form-urlencoded');
  } else {
    await post(RS, '/api/rules', text, 'text/plain');
  }
  await new Promise((r) => setTimeout(r, 150));
}

const through = (port, { method = 'GET', path: p = '/echo', headers = {}, body = '' } = {}) =>
  new Promise((res) => {
    const req = http.request({
      host: '127.0.0.1', port, method,
      path: `http://${P}${p}`,
      headers: { host: P, ...headers },
    }, (r) => {
      const c = [];
      r.on('data', (x) => c.push(x));
      r.on('end', () => res({ status: r.statusCode, body: Buffer.concat(c).toString() }));
    });
    req.on('error', (e) => res({ status: 0, body: 'ERR ' + e.code }));
    req.setTimeout(8000, () => { req.destroy(); res({ status: 0, body: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });

/**
 * Everything under `DIR`, as `relative path -> contents`, then removed.
 *
 * Recursive, and that is the whole point. The first version stopped at the top
 * level and reported a directory as `<directory>`, which turned the actual
 * finding — that one proxy writes `dump/echo` where the other writes `dump` —
 * into twenty-one identical "present/absent" lines with the contents nowhere in
 * sight.
 */
/**
 * What was in the working directory before the run.
 *
 * A dump does not have to land where the rule pointed. `resWrite://` with an
 * **empty value** makes whistle write to a path relative to its own cwd, and
 * this bench reported that case as "neither proxy wrote anything" for as long
 * as it only looked inside `DIR` — agreement produced by not looking. Anything
 * new here is reported as `cwd:<name>` and compared like any other file.
 */
const CWD_BEFORE = new Set(fs.readdirSync(process.cwd()));

/** Files a case left in the working directory, then removed. */
function harvestCwd() {
  const out = {};
  for (const name of fs.readdirSync(process.cwd()).sort()) {
    if (CWD_BEFORE.has(name)) continue;
    const full = path.join(process.cwd(), name);
    out['cwd:' + name] = fs.statSync(full).isDirectory() ? '<directory>' : fs.readFileSync(full).toString();
    fs.rmSync(full, { recursive: true, force: true });
  }
  return out;
}

function harvest(dir = DIR, prefix = '') {
  const out = {};
  for (const name of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) {
      Object.assign(out, harvest(full, prefix + name + '/'));
      continue;
    }
    out[prefix + name] = fs.readFileSync(full).toString();
  }
  if (dir === DIR) for (const name of fs.readdirSync(dir)) fs.rmSync(path.join(dir, name), { recursive: true, force: true });
  return out;
}

/**
 * What in a dump is bookkeeping rather than behaviour.
 *
 * Three classes come out before the comparison, and they are the same three the
 * main harness drops from every header comparison it makes:
 *
 * * **the clock and the framing** — `Date`, `Connection`, `Keep-Alive`,
 *   `Transfer-Encoding`, `Content-Length`. whistle re-chunks what it rewrites
 *   and this port buffers it, so the framing headers describe two different
 *   ways of sending the same bytes. The bytes are what is compared.
 * * **each proxy's own bookkeeping** — `x-whistle-*`, the forwarding uid, and
 *   the client's `User-Agent`/`Accept`, which differ because the two runs are
 *   two different node clients.
 * * **header-name case.** whistle keeps the names as they arrived, from
 *   `rawHeaderNames` (`_original/lib/util/file-writer-transform.js:33`); hyper
 *   normalises every name to lower case before this port can see it, and
 *   recovering the original spelling would mean carrying a second copy of every
 *   header through the proxy. A real divergence, recorded in `docs/RULES.md`,
 *   and not one any dump's *content* depends on.
 *
 * The status line's HTTP version and reason phrase go the same way.
 */
const normalise = (text) => text
  .replace(/^HTTP\/1\.[01] (\d{3}) [^\r\n]*/m, 'HTTP/1.1 $1')
  .replace(/^(x-whistle[^\r\n]*\r?\n)/gim, '')
  .replace(/^(date|proxy-connection|connection|keep-alive|transfer-encoding|content-length|user-agent|accept|accept-encoding|x-forwarded-from-whistle-uid): [^\r\n]*\r?\n/gim, '')
  .replace(/^([A-Za-z0-9-]+):/gm, (_, name) => name.toLowerCase() + ':')
  // The request cache-bust this port adds ahead of a body operator, which
  // `harness.js`'s `EXPECTED` already declares: whistle has `notAllowCache` and
  // never reaches it, so its own rewrite vanishes on a browser reload. A raw
  // request dump records it faithfully, which is why it shows up here and only
  // on a case that also carries a body operator. Matched on the exact value so
  // a genuine `cache-control` difference still shows.
  .replace(/^(pragma|cache-control): no-cache\r?\n/gim, '');

const F = (name) => path.join(DIR, name);

const CASES = [
  // ── the four operators, one at a time ────────────────────────────────────
  { name: 'reqWrite dumps the request body', rules: `${P} reqWrite://${F('rq')}`, request: { method: 'POST', body: 'SENT BODY' } },
  { name: 'reqWrite on a GET writes nothing', rules: `${P} reqWrite://${F('rq')}` },
  { name: 'reqWriteRaw dumps head and body', rules: `${P} reqWriteRaw://${F('rqraw')}`, request: { method: 'POST', body: 'SENT BODY' } },
  { name: 'reqWriteRaw on a GET still writes the head', rules: `${P} reqWriteRaw://${F('rqraw')}` },
  { name: 'resWrite dumps the response body', rules: `${P} resWrite://${F('rs')}` },
  { name: 'resWriteRaw dumps the response head and body', rules: `${P} resWriteRaw://${F('rsraw')}` },
  { name: 'all four at once', rules: `${P} reqWrite://${F('a')} reqWriteRaw://${F('b')} resWrite://${F('c')} resWriteRaw://${F('d')}`, request: { method: 'POST', body: 'SENT BODY' } },

  // ── the status suffix, upstream's most distinctive detail here ───────────
  // `getWriterFile` appends `.<status>` to the path for anything but a 200
  // (`_original/lib/inspectors/res.js:143-149`), so a 404 lands beside the file
  // the rule named rather than in it.
  { name: 'resWrite on a 404 lands at path.404', rules: `${P} resWrite://${F('rs')}`, request: { path: '/404' } },
  { name: 'resWriteRaw on a 404 lands at path.404', rules: `${P} resWriteRaw://${F('rsraw')}`, request: { path: '/404' } },
  { name: 'resWrite on a 204 has no body to write', rules: `${P} resWrite://${F('rs')}`, request: { path: '/204' } },
  { name: 'resWriteRaw on a 204 writes the head', rules: `${P} resWriteRaw://${F('rsraw')}`, request: { path: '/204' } },
  { name: 'resWrite under a replaced status', rules: `${P} resWrite://${F('rs')} replaceStatus://503` },
  { name: 'resWrite under a mocked status', rules: `${P} resWrite://${F('rs')} statusCode://418` },

  // ── what the dump contains once a rule has rewritten the exchange ────────
  { name: 'reqWriteRaw sees the rewritten request headers', rules: `${P} reqHeaders://x-added=1 reqWriteRaw://${F('rqraw')}`, request: { method: 'POST', body: 'SENT BODY' } },
  { name: 'reqWrite sees the rewritten request body', rules: `${P} reqBody://(REWRITTEN) reqWrite://${F('rq')}`, request: { method: 'POST', body: 'SENT BODY' } },
  { name: 'resWrite sees the rewritten response body', rules: `${P} resReplace://ORIGINAL=REWRITTEN resWrite://${F('rs')}` },
  { name: 'resWriteRaw sees the added response headers', rules: `${P} resHeaders://x-added=1 resWriteRaw://${F('rsraw')}` },
  { name: 'resWrite of a mocked file', rules: `${P} file://(MOCKED) resWrite://${F('rs')}` },

  // ── the unmatched path is joined onto the write path ─────────────────────
  //
  // `getWriteFilePath` reads the tail-joined `rule.url`
  // (`_original/lib/util/index.js:1461-1464`, `rules.js:936-941`), so one rule
  // gives one dump file **per URL** rather than appending the whole run into
  // one file. A pattern that consumes the path leaves nothing to join.
  { name: 'the unmatched path joins onto the dump', rules: `${P} resWrite://${F('d')}`, request: { path: '/echo' } },
  { name: 'a deeper unmatched path joins whole', rules: `${P} resWrite://${F('d')}`, request: { path: '/a/b/c' } },
  { name: 'a pattern that consumes the path joins nothing', rules: `${P}/echo resWrite://${F('d')}`, request: { path: '/echo' } },
  { name: 'a pattern that consumes part of it joins the rest', rules: `${P}/a resWrite://${F('d')}`, request: { path: '/a/b' } },
  { name: 'the root path', rules: `${P} resWrite://${F('d')}`, request: { path: '/' } },
  { name: 'a trailing slash', rules: `${P} resWrite://${F('d')}`, request: { path: '/a/' } },
  { name: 'the query is not joined', rules: `${P} resWrite://${F('d')}`, request: { path: '/echo?q=1' } },
  { name: 'the same join on reqWriteRaw', rules: `${P} reqWriteRaw://${F('d')}`, request: { method: 'POST', path: '/a/b', body: 'SENT BODY' } },
  // `<verbatim>` is the documented way to refuse the join, and an inline value
  // is content rather than a location — both opt out upstream via
  // `getRuleValue` (`lib/util/common.js:911-919`).
  { name: 'a verbatim path refuses the join', rules: `${P} resWrite://<${F('d')}>`, request: { path: '/echo' } },

  // ── a target that ends in a separator ────────────────────────────────────
  //
  // `reqWrite.md` says a directory target takes `index.html` when the request
  // asks for a directory: "目标路径为 `/User/xxx/test/`，结尾为 `/` 或 `\` 自动
  // 追加 `index.html`". `joinPath` is where that happens
  // (`_original/lib/util/index.js:1855-1871`) — it puts the slash back when the
  // *root* had one and the joined path does not.
  { name: 'a directory target and a file request', rules: `${P} resWrite://${F('dir1')}/`, request: { path: '/a/b.html' } },
  { name: 'a directory target and a directory request', rules: `${P} resWrite://${F('dir2')}/`, request: { path: '/a/' } },
  { name: 'a directory target and the root', rules: `${P} resWrite://${F('dir3')}/`, request: { path: '/' } },
  { name: 'a directory target the pattern consumes', rules: `${P}/a/ resWrite://${F('dir4')}/`, request: { path: '/a/' } },
  { name: 'a file target and a directory request', rules: `${P} resWrite://${F('file1')}`, request: { path: '/a/' } },

  // ── shape of the value ───────────────────────────────────────────────────
  { name: 'a write path that is a directory', rules: `${P} resWrite://${DIR}` },
  { name: 'a write path under a directory that does not exist', rules: `${P} resWrite://${F('no/such/dir/rs')}` },
  // **A declared divergence, and the one case here that differs.** An empty
  // value leaves the tail as the whole path, so upstream's write path is
  // relative — `echo` — and whistle dumps into whatever directory it happens to
  // have been started in. A rule with no path in it writing a file somewhere in
  // the user's tree is not a behaviour worth reproducing; this port writes
  // nothing. Reported as `cwd:echo`, which this bench could not see at all until
  // it started watching its own working directory.
  { name: 'an empty write path', rules: `${P} resWrite://` },
  { name: 'two write rules naming the same file', rules: `${P} resWrite://${F('rs')} resWriteRaw://${F('rs')}` },
  // Both operators on one line, contested across two lines: first wins.
  { name: 'contested resWrite takes the first line', rules: `${P} resWrite://${F('first')}\n${P} resWrite://${F('second')}` },

  // ── repeats: append, truncate, or refuse ─────────────────────────────────
  { name: 'a second request appends to the same dump', rules: `${P} resWrite://${F('rs')}`, repeat: 2 },
  { name: 'enable forceReqWrite on a second request', rules: `${P} resWrite://${F('rs')} enable://forceReqWrite`, repeat: 2 },
];

async function run(port, c) {
  await setRules(port, c.rules);
  const answers = [];
  for (let i = 0; i < (c.repeat || 1); i++) answers.push(await through(port, c.request));
  // A dump is written as the body streams, which finishes after the client's
  // `end` on the response — give it a moment before reading, or a passing case
  // becomes an empty file.
  await new Promise((r) => setTimeout(r, 250));
  return { answers, files: { ...harvest(), ...harvestCwd() } };
}

async function main() {
  const origin = await startOrigin();

  // A hard baseline: prove both proxies work, and prove the harvest sees a file
  // at all. "No file on either side" is what a broken bench and a broken rule
  // look like, identically.
  {
    for (const [who, port] of [['whistle', W], ['whix', RS]]) {
      const r = await run(port, { rules: `${P} resWrite://${F('probe')}` });
      if (r.answers[0].status !== 200 || !Object.keys(r.files).length) {
        console.error(`baseline failed for ${who}: ${JSON.stringify(r).slice(0, 300)}`);
        process.exit(1);
      }
    }
  }

  let ran = 0, differing = 0, wroteNothing = 0;
  const report = [];
  for (const c of CASES) {
    const w = await run(W, c);
    const rs = await run(RS, c);
    ran++;
    // A case where neither proxy wrote anything proves nothing about writing.
    // Counted and reported rather than passed over in silence.
    if (!Object.keys(w.files).length && !Object.keys(rs.files).length) wroteNothing++;

    const problems = [];
    for (let i = 0; i < w.answers.length; i++) {
      if (w.answers[i].status !== rs.answers[i].status) {
        problems.push(`status[${i}]: whistle=${w.answers[i].status} rs=${rs.answers[i].status}`);
      }
    }
    for (const name of new Set([...Object.keys(w.files), ...Object.keys(rs.files)])) {
      const [a, b] = [w.files[name], rs.files[name]];
      if (a === undefined || b === undefined) {
        problems.push(`file ${name}: whistle=${a === undefined ? 'absent' : 'present'} rs=${b === undefined ? 'absent' : 'present'}`);
      } else if (normalise(a) !== normalise(b)) {
        problems.push(`file ${name}: whistle=${JSON.stringify(a.slice(0, 200))} rs=${JSON.stringify(b.slice(0, 200))}`);
      }
    }
    if (problems.length) { differing++; report.push({ name: c.name, rules: c.rules, problems }); }
  }

  origin.close();
  fs.rmSync(DIR, { recursive: true, force: true });
  // The empty write path differs on purpose; `declared.js` names it, and
  // anything else — or that one no longer differing — fails the run.
  const verdict = judge('write-bench.js', report, CASES.map((c) => c.name));
  differing = verdict.news.length;
  console.log(JSON.stringify({
    ran, differing, declared: verdict.declared, stale: verdict.stale, wroteNothing, report: verdict.news,
    // Every difference before `declared.js` excuses any, for `matrix.js`.
    raw: report.map(({ name, problems }) => ({ name, problems })),
  }, null, 2));
  process.exitCode = differing || verdict.stale.length ? 1 : 0;
}

main().catch((e) => { console.error(e); fs.rmSync(DIR, { recursive: true, force: true }); process.exit(1); });
