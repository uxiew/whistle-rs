// A differential test bench: the same rule and the same request, put through
// real whistle and through whistle-rs, with both answers compared.
//
// Reading upstream's source finds what it *says*. This finds what it *does* —
// including the places our reading of it was wrong, which has already happened
// twice today (the TLS 1.3 half of `ciphers`, and `RSA` meaning kRSA).
//
// Two things are compared, and the second matters as much as the first:
//   * what the client got back  (status + headers + body)
//   * what the origin was sent  (method + path + headers + body)
// A rule that rewrites a request is invisible in the response alone.

const http = require('http');

const ORIGIN = 18800;
const W = 18700;   // upstream whistle
const RS = 18999;  // whistle-rs

/** Headers neither proxy is expected to agree on, and why. */
const IGNORE = new Set([
  'date',                       // wall clock
  'connection', 'keep-alive', 'proxy-connection', // hop-by-hop
  'transfer-encoding', 'content-length',          // framing, compared via body
  'host',                       // compared explicitly where it matters
  'x-whistle-request-id', 'x-whistle-client-id', 'x-whistle-real-host',
  'x-forwarded-from-whistle-uid',                 // whistle's own bookkeeping
  'accept-encoding',            // each proxy narrows this its own way
  'user-agent',                 // curl vs node client
  'accept',
]);

/**
 * Divergences that are deliberate, each with the reason. A run is clean when
 * every difference it finds is one of these — anything else is news.
 */
const EXPECTED = [
  {
    // whistle has `notAllowCache` and never reaches it: it reads `req.rules`,
    // and all seventeen body operators are in `pureResProtocols`, which the
    // request pass skips. So its own rewrite vanishes on a browser reload.
    match: (p) => /req\.header\.(pragma|cache-control): whistle=undefined rs="no-cache"/.test(p)
      || /req\.header\.if-none-match: whistle="/.test(p),
    why: 'busting the request cache: deliberate, and better than upstream',
  },
  {
    // whistle stamps `x-server: Whistle`; this is not whistle.
    match: (p) => /res\.header\.x-server: whistle="Whistle" rs="whistle-rs"/.test(p),
    why: 'x-server names the proxy that actually answered',
  },
  {
    // Both fail to find the file and say so; only the wording differs, and
    // matching another program's error prose is not worth pinning.
    match: (p) => /res\.body: whistle="Not found file /.test(p),
    why: 'the same 404, phrased in each proxy\'s own words',
  },
];

const norm = (headers) => {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = k.toLowerCase();
    if (IGNORE.has(key)) continue;
    if (key.startsWith('x-whistle')) continue;
    out[key] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
};

/** The origin: echoes exactly what reached it. */
function startOrigin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      let body = '';
      q.on('data', (c) => (body += c));
      q.on('end', () => {
        if (q.url.startsWith('/html')) {
          r.writeHead(200, { 'content-type': 'text/html' });
          return r.end('<html><body>ORIGINAL<span>x</span></body></html>');
        }
        r.writeHead(200, { 'content-type': 'application/json', 'x-origin': 'yes' });
        r.end(JSON.stringify({
          method: q.method, url: q.url, headers: q.headers, body,
        }));
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

/** Load one rules text into both proxies. */
async function setRules(text) {
  await post(W, '/cgi-bin/rules/add',
    'name=Default&selected=1&value=' + encodeURIComponent(text),
    'application/x-www-form-urlencoded');
  await post(RS, '/api/rules', text, 'text/plain');
  await new Promise((r) => setTimeout(r, 120));
}

/** One request through one proxy; resolves to what the client saw. */
function through(port, { method = 'GET', path = '/echo', headers = {}, body = '' }) {
  return new Promise((res) => {
    const req = http.request({
      host: '127.0.0.1', port, method,
      path: `http://127.0.0.1:${ORIGIN}${path}`,
      headers: { host: `127.0.0.1:${ORIGIN}`, ...headers },
    }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => res({
        status: r.statusCode,
        headers: norm(r.headers),
        body: Buffer.concat(chunks).toString(),
      }));
    });
    req.on('error', (e) => res({ status: 0, headers: {}, body: 'ERR ' + e.code }));
    req.setTimeout(6000, () => { req.destroy(); });
    if (body) req.write(body);
    req.end();
  });
}

/** What the origin saw, dug out of its echo — or null when it never arrived. */
function seenByOrigin(answer) {
  try {
    const j = JSON.parse(answer.body);
    if (!j.headers) return null;
    return { method: j.method, url: j.url, headers: norm(j.headers), body: j.body };
  } catch { return null; }
}

const show = (v) => JSON.stringify(v);

/** Compare two objects field by field, returning readable differences. */
function diff(a, b, label) {
  const out = [];
  if (a === null || b === null) {
    if (a !== b) out.push(`${label}: reached the origin? whistle=${a !== null} rs=${b !== null}`);
    return out;
  }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    if (show(a[k]) !== show(b[k])) out.push(`${label}.${k}: whistle=${show(a[k])} rs=${show(b[k])}`);
  }
  return out;
}

async function main() {
  const origin = await startOrigin();
  const CASES = require('./cases.js');
  let ran = 0, differing = 0;
  const report = [];

  for (const c of CASES) {
    await setRules(c.rules);
    const req = c.request || {};
    const [w, rs] = [await through(W, req), await through(RS, req)];
    ran++;

    const problems = [];
    if (w.status !== rs.status) problems.push(`status: whistle=${w.status} rs=${rs.status}`);
    problems.push(...diff(w.headers, rs.headers, 'res.header'));
    // Bodies are compared as text unless they are the origin's echo, which
    // carries the request and is compared field by field instead.
    const [ws, rss] = [seenByOrigin(w), seenByOrigin(rs)];
    if (ws && rss) {
      if (ws.method !== rss.method) problems.push(`req.method: whistle=${ws.method} rs=${rss.method}`);
      if (ws.url !== rss.url) problems.push(`req.url: whistle=${ws.url} rs=${rss.url}`);
      if (ws.body !== rss.body) problems.push(`req.body: whistle=${show(ws.body)} rs=${show(rss.body)}`);
      problems.push(...diff(ws.headers, rss.headers, 'req.header'));
    } else if (w.body !== rs.body) {
      problems.push(`res.body: whistle=${show(w.body.slice(0, 120))} rs=${show(rs.body.slice(0, 120))}`);
    }

    const news = problems.filter((p) => !EXPECTED.some((e) => e.match(p)));
    if (news.length) {
      differing++;
      report.push({ name: c.name, rules: c.rules, problems: news });
    }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
