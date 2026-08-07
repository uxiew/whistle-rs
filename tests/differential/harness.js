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
const zlib = require('zlib');

// Ports and corpus come from the environment so several benches can run at
// once — one per area under audit — without colliding on a port or on a file.
//   PORT_BASE=19100 CASES=./cases-filters.js node harness.js
const BASE = Number(process.env.PORT_BASE || 18700);
const W = BASE;          // upstream whistle
const RS = BASE + 1;     // whistle-rs
const ORIGIN = BASE + 2; // the echo origin
const CASES_FILE = process.env.CASES || './cases.js';

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
 *
 * `match` is given the difference and the case that produced it. The second
 * argument matters where a single answer shows up as several differences at
 * once: a proxy that never replied differs in its status, its body and every
 * header it did not send, and pinning those one by one would excuse them
 * everywhere rather than in the one case that earns it.
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
    // whistle stamps `x-server: Whistle`; this is not whistle. It also only
    // stamps the responses it built in memory — `wrapResponse` is where the
    // header is set, and a file streamed off disk never goes through it, so
    // upstream's most common mock is the one response it leaves unmarked.
    // whistle-rs marks every response it made itself, which is the whole point
    // of the header.
    match: (p) => /res\.header\.x-server: whistle=("Whistle"|undefined) rs="whistle-rs"/.test(p),
    why: 'x-server names the proxy that actually answered, on every answer',
  },
  {
    // The `Server` header a served local file carries (`file-proxy.js:315-318`).
    // Same header, same reason as above: naming whistle would be a lie.
    match: (p) => /res\.header\.server: whistle="Whistle" rs="whistle-rs"/.test(p),
    why: 'a mocked file names the proxy that served it',
  },
  {
    // Both fail to find the file and say so; only the wording differs, and
    // matching another program's error prose is not worth pinning.
    match: (p) => /res\.body: whistle="Not found (file|key) /.test(p),
    why: 'the same 404, phrased in each proxy\'s own words',
  },
  {
    // hyper's HTTP/1 server writes a trailer section only when the request
    // carried `TE: trailers` (`Conn::write_trailers`, hyper 1.10.1
    // `src/proto/h1/conn.rs:729-733`, from the `TE` read at `conn.rs:328-332`).
    // Node sends them regardless. With `TE: trailers` the two agree exactly —
    // origin trailers forwarded, `trailers://` merged over the top.
    match: (p) => /^res\.trailer\./.test(p),
    why: 'hyper sends trailers only to a client that asked for them; see docs/RULES.md',
  },
  {
    // `zlib.createInflate` is zlib-wrapped only, so a raw-deflate body makes
    // whistle's decoder error out and the response never arrives — no status,
    // no headers, no body. This port tries zlib first and raw second, and
    // answers.
    match: (p, c) => /raw-deflate/.test(c.name) && /whistle=(0|undefined|"ERR HUNG")/.test(p),
    why: 'a raw-deflate body: whistle never answers, this port decodes it',
  },
  {
    // `getEnableEncoding` sets `content-encoding` unconditionally
    // (`_original/lib/inspectors/res.js:1179-1185`) but `getEncoder` refuses to
    // build the compressor when the body arrived under a coding that was never
    // gunzipped (`inspectors/rules.js:117-121`). The client is handed bytes the
    // header misdescribes. This port refuses the force instead — see
    // `coding::reencode`.
    match: (p) => /res\.body: whistle="<undecodable (gzip|br|deflate)>"/.test(p)
      || /res\.header\.content-encoding: whistle="gzip" rs="zstd"/.test(p),
    why: 'enable:// on a body that cannot be decoded: whistle labels it without encoding it',
  },
  {
    // Same line, the bodiless case: whistle stamps `content-encoding` on a 204,
    // which has no body to encode. This port sets the header from the bytes
    // that actually went out.
    match: (p) => /res\.header\.content-encoding: whistle="(gzip|br|deflate)" rs=undefined/.test(p),
    why: 'enable:// on an answer with no body: a coding describing nothing',
  },
  {
    // whistle sniffs an undeclared charset over the first 25 KB and falls back
    // to GB18030 (`getPipeIconvStream`, `_original/lib/util/index.js:1630-1656`),
    // which rewrites bytes it guessed at. This port honours a *declared*
    // `charset=` and leaves an undeclared non-UTF-8 body alone. Documented in
    // docs/RULES.md.
    match: (p) => /res\.body: whistle="X.*INAL"/.test(p),
    why: 'an undeclared charset is guessed by whistle and not by this port',
  },
  {
    // `x-gzip` is not in `getContentEncoding`'s list
    // (`_original/lib/util/common.js:1548-1554`), so whistle never decodes it —
    // and its text transform then runs a lossy UTF-8 round trip over the gzip
    // bytes, corrupting a body it could not read. This port decodes it, rewrites
    // it, and puts the origin's own spelling of the header back.
    match: (p) => /res\.body: whistle="<undecodable x-gzip>"/.test(p),
    why: 'x-gzip is gzip: whistle corrupts such a body, this port rewrites it',
  },
  {
    // whistle rewrites a response with stream transforms and so has no bound;
    // this port buffers and stops at `--body-rewrite-limit` (16 MiB), past which
    // the response is forwarded byte-complete but unrewritten. Measured at the
    // boundary: identical at 16,777,199 bytes, diverging at 16,777,299.
    match: (p, c) => /over the rewrite ceiling/.test(c.name) && /^res\.body:/.test(p),
    why: 'past --body-rewrite-limit the body streams through untouched; see src/config.rs',
  },
  {
    // `rawfile://` whose head has no status line: upstream assigns the second
    // word of the first line as the status code and throws while writing it,
    // which reaches the client as a reset connection. whistle-rs falls back to
    // 200 and serves the body.
    match: (p) => /status: whistle=0 rs=200/.test(p)
      || /res\.body: whistle="ERR ECONNRESET"/.test(p),
    why: 'a rawfile with no status line: upstream crashes, this serves it',
  },
  {
    // whistle files a `host` filter condition under `hostFilter`, which only
    // `util.checkProxyHost` reads: it decides which hosts a `proxy://` engages
    // for, never whether a rule applies. whistle-rs matches the request's host
    // with it. Declared in `docs/RULES.md`; the cases that exercise it carry
    // this header and no other case uses it.
    match: (p) => /req\.header\.x-host-filter:/.test(p),
    why: 'host: and host= match the request host here, by design',
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

const HTML = '<html><body>ORIGINAL<span>x</span></body></html>';

/**
 * Fixed answers for the body-rewriting corpus, keyed by path prefix. Each is
 * `[content-type, body, extra headers]`, and the origin serves them verbatim —
 * ignoring `accept-encoding`, so a compressed case is compressed on both sides
 * whatever each proxy decided to ask for.
 *
 * Everything here is additive: `/echo` and `/html` are untouched, and no path
 * below is requested by `cases.js`.
 */
const FIXED = {
  // ── compressed, all three codings, plus the two that cannot round-trip ──
  '/gz': ['text/html', zlib.gzipSync(HTML), { 'content-encoding': 'gzip' }],
  '/deflate': ['text/html', zlib.deflateSync(HTML), { 'content-encoding': 'deflate' }],
  '/rawdeflate': ['text/html', zlib.deflateRawSync(HTML), { 'content-encoding': 'deflate' }],
  '/br': ['text/html', zlib.brotliCompressSync(HTML), { 'content-encoding': 'br' }],
  '/xgzip': ['text/html', zlib.gzipSync(HTML), { 'content-encoding': 'x-gzip' }],
  '/zstd': ['text/html', HTML, { 'content-encoding': 'zstd' }],
  '/liar': ['text/html', HTML, { 'content-encoding': 'gzip' }],
  '/gzjson': ['application/json', zlib.gzipSync('{"a":1,"keep":"yes"}'), { 'content-encoding': 'gzip' }],

  // ── charsets ───────────────────────────────────────────────────────────
  // GBK for 中文首页: the bytes are written out so the origin needs no iconv.
  '/gbk': ['text/html; charset=gbk',
    Buffer.concat([Buffer.from('<html><body>ORIGINAL '), Buffer.from([0xd6, 0xd0, 0xce, 0xc4]),
      Buffer.from('</body></html>')]), {}],

  // ── types the operators are gated on ───────────────────────────────────
  '/js': ['application/javascript', 'var ORIGINAL = 1;', {}],
  '/css': ['text/css', '.ORIGINAL { color: blue }', {}],
  '/json': ['application/json', '{"a":1,"keep":"yes"}', {}],
  '/plain': ['text/plain', 'ORIGINAL text', {}],
  '/xml': ['application/xml', '<r>ORIGINAL</r>', {}],
  '/png': ['image/png', Buffer.from('89504e470d0a1a0a4f524947494e414c', 'hex'), {}],
  '/octet': ['application/octet-stream', 'ORIGINAL bytes', {}],
  // Latin-1 bytes under an HTML type: a body no UTF-8 decoder accepts.
  '/notutf8': ['text/html', Buffer.from([0x4f, 0x52, 0x49, 0x47, 0xff, 0xfe, 0x49, 0x4e, 0x41, 0x4c]), {}],
  '/notype': [null, 'ORIGINAL untyped', {}],
  // Carries the two headers an injection is supposed to take away, so a case
  // can tell "injected nothing" from "injected an empty string".
  '/cached': ['text/html', HTML,
    { 'cache-control': 'max-age=600', 'content-security-policy': "default-src 'self'" }],
};

/** The origin: echoes exactly what reached it. */
function startOrigin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      // Kept as buffers, not appended to a string: a request body under a
      // `Content-Encoding` is not text, and `+= chunk` would have destroyed it
      // before the echo could report it.
      const inbound = [];
      q.on('data', (c) => inbound.push(c));
      q.on('end', () => {
        const raw = Buffer.concat(inbound);
        const body = raw.toString();
        const path = q.url.split('?')[0];
        const fixed = FIXED[path];
        if (fixed) {
          const [type, payload, extra] = fixed;
          r.writeHead(200, { ...(type ? { 'content-type': type } : {}), ...extra });
          return r.end(payload);
        }
        // A body of `n` bytes, for the rewrite ceiling. `PAD` keeps it text
        // without making it compressible to nothing.
        if (path === '/big') {
          const n = Number(new URL(q.url, 'http://x').searchParams.get('n') || 1024);
          r.writeHead(200, { 'content-type': 'text/html' });
          return r.end('ORIGINAL' + 'PAD_'.repeat(Math.max(0, (n - 8) >> 2)));
        }
        // Chunked with no content-length, and the same again with trailers.
        if (path === '/chunked' || path === '/trailers') {
          const heads = { 'content-type': 'text/html' };
          if (path === '/trailers') heads.trailer = 'x-origin-trailer';
          r.writeHead(200, heads);
          r.write('<html><body>ORIG');
          r.write('INAL</body></html>');
          if (path === '/trailers') r.addTrailers({ 'x-origin-trailer': 'yes' });
          return r.end();
        }
        if (q.url.startsWith('/html')) {
          r.writeHead(200, { 'content-type': 'text/html' });
          return r.end(HTML);
        }
        r.writeHead(200, { 'content-type': 'application/json', 'x-origin': 'yes' });
        r.end(JSON.stringify({
          method: q.method, url: q.url, headers: q.headers, body,
          // Base64 so a request body that is compressed or not UTF-8 survives
          // the echo — `body` above has already been through a UTF-8 decode.
          bodyB64: raw.toString('base64'),
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

/**
 * Undo a `Content-Encoding` before the bodies are compared.
 *
 * Two compressors never agree byte for byte — node's zlib and Rust's flate2
 * pick different levels and headers — so comparing the wire bytes of a
 * recompressed body says nothing. What is worth comparing is the *content*,
 * and separately whether `Content-Encoding` honestly describes it. That header
 * is compared as a header like any other; this only reads it.
 *
 * A body the header cannot explain comes back as `<undecodable gzip>`, which is
 * itself a finding worth seeing side by side.
 */
function decodeBody(headers, buf) {
  const enc = String(headers['content-encoding'] || '').trim().toLowerCase();
  if (!enc || enc === 'identity' || buf.length === 0) return buf.toString();
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf).toString();
    if (enc === 'br') return zlib.brotliDecompressSync(buf).toString();
    if (enc === 'deflate') {
      try { return zlib.inflateSync(buf).toString(); } catch { return zlib.inflateRawSync(buf).toString(); }
    }
  } catch { return `<undecodable ${enc}>`; }
  return buf.toString();
}

/** One request through one proxy; resolves to what the client saw. */
function through(port, { method = 'GET', path = '/echo', headers = {}, body = '' }) {
  return new Promise((resolve) => {
    // A response whose head arrived and whose body never ends leaves `end`
    // unfired, and one such case used to stall the whole run with nothing
    // printed at all. Every path out of here goes through `res`, which cancels
    // the deadline, so a hang becomes an answer the comparison can see.
    let hung;
    const res = (answer) => { clearTimeout(hung); resolve(answer); };
    hung = setTimeout(
      () => res({ status: 0, headers: {}, trailers: {}, body: 'ERR HUNG' }),
      15000,
    );
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
        body: decodeBody(r.headers, Buffer.concat(chunks)),
        // Trailers arrive after the body, so they are only readable here.
        trailers: norm(r.trailers),
      }));
    });
    req.on('error', (e) => res({ status: 0, headers: {}, trailers: {}, body: 'ERR ' + e.code }));
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
    // From `bodyB64`, not `body`: a request body under a `Content-Encoding` is
    // not text, and a UTF-8 decode would destroy it before the comparison. It
    // then goes through the same decoder the response side uses — node's gzip
    // and flate2's differ in one header byte (the OS field) over byte-identical
    // deflate output, which is compressor identity, not behaviour.
    const raw = Buffer.from(j.bodyB64 || '', 'base64');
    return {
      method: j.method,
      url: j.url,
      headers: norm(j.headers),
      body: decodeBody(j.headers, raw),
    };
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
  const CASES = require(CASES_FILE);
  let ran = 0, differing = 0;
  const report = [];

  for (const c of CASES) {
    // Progress on stderr, so a long corpus says where it is without touching
    // the JSON report on stdout.
    process.stderr.write(`… ${c.name}\n`);
    await setRules(c.rules);
    const req = c.request || {};
    const [w, rs] = [await through(W, req), await through(RS, req)];
    ran++;

    const problems = [];
    if (w.status !== rs.status) problems.push(`status: whistle=${w.status} rs=${rs.status}`);
    problems.push(...diff(w.headers, rs.headers, 'res.header'));
    problems.push(...diff(w.trailers, rs.trailers, 'res.trailer'));
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

    const news = problems.filter((p) => !EXPECTED.some((e) => e.match(p, c)));
    if (news.length) {
      differing++;
      report.push({ name: c.name, rules: c.rules, problems: news });
    }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, report }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
