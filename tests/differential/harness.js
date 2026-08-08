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
  // whistle's own bookkeeping, named one at a time rather than by prefix. A
  // blanket `x-whistle*` also hid `x-whistle-matched-rules`, which is the whole
  // observable effect of `enable://requestWithMatchedRules` — a case about that
  // header could not fail. Removing the blanket was measured across six corpora
  // and introduced no difference anywhere, so it was suppressing nothing these
  // four do not already cover.
  'x-whistle-request-id', 'x-whistle-client-id', 'x-whistle-real-host',
  'x-forwarded-from-whistle-uid',
  'accept-encoding',            // each proxy narrows this its own way
  // `user-agent` and `accept` used to be here, from when this bench drove one
  // side with curl and the other with node. It drives both with node now, which
  // sends neither header unless a case asks for it — and the exemption was
  // doing real damage, because these are headers *rules are written about*.
  // Six cases could not fail while it stood: `ua://`, `disable://ua`, the two
  // that pin which of two `ua://` lines wins (the whole of `lineProps://important`
  // in this corpus), and both `headerReplace://` doc forms, which rewrite
  // `accept`. Removing them was measured across all thirteen corpora and
  // introduced no difference anywhere.
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
    // Three pattern deviations, each declared in `docs/RULES.md` and each
    // better than what it replaces: a host is matched case-insensitively, an
    // explicit `:80` on an http pattern is a port rather than dead text, and an
    // IPv6 literal survives the port-stripped comparison upstream's `removePort`
    // mangles. The cases that exercise them carry this header and no other case
    // uses it; `cases-patterns.js` names all three at the top.
    match: (p) => /req\.header\.x-pattern-dev:/.test(p),
    why: 'declared pattern deviations: host case, :80, and IPv6 literals',
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
  {
    // `ws://`, `wss://` and `tunnel://` name transports a plain HTTP request is
    // not, and all three pages say so: "普通 HTTP/HTTPS 请求：返回 502". Both
    // proxies answer 502; only the page differs — whistle's is HTML holding a
    // Node stack trace (`wrapGatewayError`, `_original/lib/util/index.js:1096-1109`)
    // and this port's is the error chain as plain text, the same pair
    // `cases-proxy.js` declares for every other gateway error.
    //
    // Scoped by **case name**, so this cannot excuse a 502 anywhere else.
    match: (p, c) => /^doc: (ws|wss|tunnel):\/\/ is not a transport/.test(c.name)
      && /^(res\.body|res\.header\.content-type):/.test(p),
    why: 'a 502 on both sides; only each proxy\'s error page differs',
  },
  {
    // Not a divergence at all: the bench straddling a second.
    //
    // Several rules render an HTTP date from the clock — an injection strips
    // the cache and stamps `Expires`, `resCookies` with an `expires` renders
    // one — and the two proxies are asked one after the other, so a run that
    // crosses a second boundary reports a difference of exactly one second.
    // It appeared about one run in six of `cases-bodies.js` and was an
    // unidentified flake until a fourth round caught it by name.
    //
    // Scoped to **one second**: a real difference in either header, of any
    // other size, still reports. Nothing here excuses a header that one proxy
    // sent and the other did not — `oneSecondApart` needs two parseable dates.
    match: (p) => oneSecondApart(p),
    why: 'an HTTP date rendered from the clock, one second apart: the bench, not the port',
  },
];

/**
 * True when a difference is two HTTP dates at most a second apart.
 *
 * Deliberately strict about what it will look at: only `expires` and
 * `set-cookie`, only when **both** sides parse as dates, and only up to 1000 ms.
 * Anything it cannot read, it declines.
 */
function oneSecondApart(problem) {
  const m = /^res\.header\.(expires|set-cookie): whistle=(".*") rs=(".*")$/.exec(problem);
  if (!m) return false;
  const at = (quoted) => {
    const text = JSON.parse(quoted);
    const date = /(?:^|expires=)([A-Za-z]{3},[^;"]+GMT)/i.exec(text);
    const t = date && Date.parse(date[1]);
    return Number.isFinite(t) ? t : null;
  };
  const [a, b] = [at(m[2]), at(m[3])];
  if (a === null || b === null) return false;
  // The rest of the two values has to match, or a real change is hiding behind
  // a date that happens to be close. Global, because the harness joins several
  // `set-cookie` values into one string and each carries its own `Expires` —
  // stripping only the first left the second in and the comparison failed, which
  // is a difference of one second reported as news.
  const strip = (quoted) => quoted.replace(/[A-Za-z]{3},[^;"]+GMT/gi, '<date>');
  return strip(m[2]) === strip(m[3]) && Math.abs(a - b) <= 1000;
}

const norm = (headers) => {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = k.toLowerCase();
    if (IGNORE.has(key)) continue;
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
  // A whole HTTP response as a *body*, so a `rawfile://` rule can name a URL
  // and get something it can parse.
  '/rawres': ['text/plain', 'HTTP/1.1 201 Created\r\nx-raw: yes\r\n\r\nRAW BODY', {}],
  // Carries the two headers an injection is supposed to take away, so a case
  // can tell "injected nothing" from "injected an empty string".
  '/cached': ['text/html', HTML,
    { 'cache-control': 'max-age=600', 'content-security-policy': "default-src 'self'" }],
};

/**
 * The same idea for the injection operators, which key off a content type.
 * `[content-type, body, content-encoding?]`. Separate from `FIXED` because it
 * is matched **exactly** rather than by path, so a corpus asking the origin for
 * `/js/app.js` still gets the echo.
 */
const SHAPES = {
  '/script.js': ['application/javascript', 'var origin = 1;'],
  '/style.css': ['text/css', 'body{color:red}'],
  '/plain.txt': ['text/plain', 'PLAIN'],
  '/empty.html': ['text/html', ''],
  '/gzipped.html': [
    'text/html',
    zlib.gzipSync('<html><body>ZIPPED</body></html>'),
    'gzip',
  ],
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
        // Any status on demand — a file rule may name a URL, and what such a
        // source answers with decides between a 404, a 502 and the bytes.
        if (path === '/status') {
          const code = Number(new URL(q.url, 'http://x').searchParams.get('code') || 200);
          r.writeHead(code, { 'content-type': 'text/plain' });
          return r.end('STATUS ' + code);
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
        // One body per content type the injection operators single out, plus an
        // empty one and a compressed one. Matched **exactly**, not by prefix, so
        // that a corpus asking the origin for `/js/app.js` still gets the echo.
        if (SHAPES[q.url]) {
          const [type, body, encoding] = SHAPES[q.url];
          const headers = { 'content-type': type };
          if (encoding) headers['content-encoding'] = encoding;
          r.writeHead(200, headers);
          return r.end(body);
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

/** One request with a body to a proxy's own API; resolves to the answer text. */
const send = (port, method, path, body, type) =>
  new Promise((res, rej) => {
    const req = http.request(
      { port, path, method, headers: { 'content-type': type, 'content-length': Buffer.byteLength(body) } },
      (r) => { let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => res(b)); },
    );
    req.on('error', rej);
    req.end(body);
  });

const post = (port, path, body, type) => send(port, 'POST', path, body, type);

const getText = (port, path) =>
  new Promise((res, rej) => {
    http.get({ port, path, headers: { 'accept-encoding': 'identity' } }, (r) => {
      let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => res(b));
    }).on('error', rej);
  });

const FORM = 'application/x-www-form-urlencoded';

/**
 * Named rule groups the previous case installed, so the next one starts clean.
 *
 * Kept rather than re-read because a corpus that never says `groups` must not
 * pay two round trips a case for a list that is always empty. It starts full,
 * in effect: [`wipeNamedGroups`] runs once before the corpus and clears
 * whatever an earlier run — or an earlier corpus against the same oracle — left
 * behind. Both proxies persist their rule groups, so this is not theoretical.
 */
let installed = [];

/** Did the previous case switch the Default group off? Then switch it back on. */
let defaultOff = false;

/** The Default group's name on each side: upstream spells it with a capital. */
const rsName = (name) => (name === 'Default' ? 'default' : name);

/**
 * Remove every named rule group from both proxies, whoever put it there, and
 * put the Default group's switch back on.
 *
 * Upstream's `remove` unselects the file as it deletes it
 * (`removeRulesFile`, `_original/lib/rules/util.js:213-222`), so nothing has to
 * be unselected first. The **Default** group is not a file and cannot be
 * removed on either side; it is overwritten by every case instead.
 */
async function wipeNamedGroups() {
  const list = JSON.parse(await getText(W, '/cgi-bin/rules/list')).list || [];
  for (const file of list) {
    await post(W, '/cgi-bin/rules/remove', 'name=' + encodeURIComponent(file.name), FORM);
  }
  const rsGroups = JSON.parse(await getText(RS, '/api/rule-groups'));
  for (const g of rsGroups) {
    if (g.name === 'default') continue;
    await send(RS, 'DELETE', '/api/rule-group', JSON.stringify({ name: g.name }), 'application/json');
  }
  installed = [];
  await setDefaultEnabled(true);
}

/**
 * Switch the Default group on or off on both sides.
 *
 * Upstream **sets** the flag — `enable-default` and `disable-default` are two
 * endpoints — while this port **toggles**, so the toggle is aimed at the state
 * the group is actually in rather than at the state it is assumed to be in.
 * Costs a read, and only a case that says `selected` on `Default` pays it.
 */
async function setDefaultEnabled(on) {
  await post(W, on ? '/cgi-bin/rules/enable-default' : '/cgi-bin/rules/disable-default', '', FORM);
  const now = JSON.parse(await getText(RS, '/api/rule-groups')).find((g) => g.name === 'default');
  if (now && now.enabled !== on) {
    await send(RS, 'POST', '/api/rule-group/toggle', '{"name":"default"}', 'application/json');
  }
  defaultOff = !on;
}

/**
 * Load one case's rules into both proxies.
 *
 * A case says `rules` — one text, which is the **Default** group, and the two
 * calls that form issues are the two it has always issued — and/or `groups`,
 * a list of `{ name, value, selected? }` naming rule groups in console order.
 * Both may appear: Default is a group like any other, except that it is the
 * one both proxies resolve **last** (`_original/lib/rules/util.js:94-101`).
 *
 * `remove` deletes named groups again after they were installed, which is the
 * only way to ask what a deletion mid-session does as opposed to what never
 * adding the group does.
 */
async function setRules(c) {
  if (installed.length || defaultOff) await wipeNamedGroups();
  const text = c.rules || '';
  await post(W, '/cgi-bin/rules/add',
    'name=Default&selected=1&value=' + encodeURIComponent(text), FORM);
  await post(RS, '/api/rules', text, 'text/plain');
  for (const g of c.groups || []) {
    // Upstream keys the Default group off the literal name, and so does this:
    // a case may name it in `groups` to put its text beside the others.
    if (g.name === 'Default') {
      await post(W, '/cgi-bin/rules/add',
        'name=Default&selected=1&value=' + encodeURIComponent(g.value || ''), FORM);
      await post(RS, '/api/rules', g.value || '', 'text/plain');
      if (g.selected === false) await setDefaultEnabled(false);
      continue;
    }
    const selected = g.selected !== false;
    await post(W, '/cgi-bin/rules/add',
      'name=' + encodeURIComponent(g.name) + (selected ? '&selected=1' : '')
      + '&value=' + encodeURIComponent(g.value || ''), FORM);
    await send(RS, 'POST', '/api/rule-groups',
      JSON.stringify({ name: g.name, text: g.value || '', enabled: selected }),
      'application/json');
    installed.push(g.name);
  }
  for (const name of c.remove || []) {
    await post(W, '/cgi-bin/rules/remove', 'name=' + encodeURIComponent(name), FORM);
    await send(RS, 'DELETE', '/api/rule-group',
      JSON.stringify({ name: rsName(name) }), 'application/json');
    installed = installed.filter((n) => n !== name);
  }
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

/**
 * One request through one proxy; resolves to what the client saw.
 *
 * `url` names the whole absolute URL instead of a path under the echo origin,
 * which is how a case reaches a host the origin does not have — the pattern
 * corpus points `example.test` at the origin with a `host://` line and then
 * asks which patterns match it. The `Host` header follows the URL's authority.
 */
function through(port, { method = 'GET', path = '/echo', url, headers = {}, body = '' }) {
  const target = url || `http://127.0.0.1:${ORIGIN}${path}`;
  const authority = target.slice(target.indexOf('://') + 3).split('/')[0];
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
      path: target,
      headers: { host: authority, ...headers },
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

/**
 * Everything two answers to the same request disagree about.
 *
 * Pulled out of the run loop because it is asked twice, about two different
 * pairs: whistle against this port, which is what the bench is for, and this
 * port against **itself with the rules taken away**, which is
 * [`unruled`](#discrimination).
 */
function problemsBetween(a, b) {
  const problems = [];
  if (a.status !== b.status) problems.push(`status: whistle=${a.status} rs=${b.status}`);
  problems.push(...diff(a.headers, b.headers, 'res.header'));
  problems.push(...diff(a.trailers, b.trailers, 'res.trailer'));
  // Bodies are compared as text unless they are the origin's echo, which
  // carries the request and is compared field by field instead.
  const [as, bs] = [seenByOrigin(a), seenByOrigin(b)];
  if (as && bs) {
    if (as.method !== bs.method) problems.push(`req.method: whistle=${as.method} rs=${bs.method}`);
    if (as.url !== bs.url) problems.push(`req.url: whistle=${as.url} rs=${bs.url}`);
    if (as.body !== bs.body) problems.push(`req.body: whistle=${show(as.body)} rs=${show(bs.body)}`);
    problems.push(...diff(as.headers, bs.headers, 'req.header'));
  } else if (a.body !== b.body) {
    problems.push(`res.body: whistle=${show(a.body.slice(0, 120))} rs=${show(b.body.slice(0, 120))}`);
  }
  return problems;
}

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

/**
 * <a name="discrimination"></a>
 * What each request answers with **no rules loaded at all**, one entry per
 * distinct request shape.
 *
 * `differing: 0` says the two proxies agree. It does not say the case was
 * *about* anything: a case whose rule never matched, or whose operator does
 * nothing observable here, agrees with upstream perfectly and would go on
 * agreeing if the operator were deleted from the source. Those two outcomes
 * look identical in the output, which is this bench's oldest blind spot — the
 * README already names eleven cases in `cases-file.js` that 404 on both sides
 * and five in `cases-patterns.js` that are really about the layer above.
 *
 * So each answer is compared against this port answering the same request with
 * its rules taken away. Identical means the case cannot tell an implementation
 * that applies its rules from one that ignores them; `inert` counts those.
 *
 * It costs one wipe and one request per distinct request shape — not per case,
 * because most corpora ask about a rule while sending the same plain `/echo`
 * over and over.
 *
 * **Inert is not the same as wrong.** A case pinning that a filter correctly
 * excludes a line, or that a malformed rule is ignored, *should* be inert, and
 * so should one about an effect this bench cannot see (`resWrite://` goes to
 * disk; `write-bench.js` is where that is measured). What the number is for is
 * that each of them needs a reason, and until now none of them were even
 * listed.
 */
async function collectUnruled(cases) {
  await post(RS, '/api/rules', '', 'text/plain');
  await new Promise((r) => setTimeout(r, 120));
  const unruled = new Map();
  for (const c of cases) {
    const key = JSON.stringify(c.request || {});
    if (unruled.has(key)) continue;
    unruled.set(key, await through(RS, c.request || {}));
  }
  return unruled;
}

async function main() {
  const origin = await startOrigin();
  const CASES = require(CASES_FILE);
  let ran = 0, differing = 0;
  const report = [];
  const inert = [];

  // Upstream selects **one** rule file at a time unless `allowMultipleChoice`
  // is on: `selectRulesFile` starts from an empty list when it is off
  // (`_original/lib/rules/util.js:148-161`), so selecting the second group
  // silently unselects the first. Pinned rather than assumed, because it is a
  // persisted property and an earlier run may have left it either way. Inert
  // for a corpus that only ever sets Default: nothing reads it but `select`.
  await post(W, '/cgi-bin/rules/allow-multiple-choice', 'allowMultipleChoice=1', FORM);
  // Both proxies persist their rule groups, so a corpus starts by clearing
  // whatever the last one left in the same data directory.
  await wipeNamedGroups();
  // Before any rules exist — the one moment the unruled answers are cheap to
  // take, and the reason this runs here rather than per case.
  const unruled = await collectUnruled(CASES);

  for (const c of CASES) {
    // Progress on stderr, so a long corpus says where it is without touching
    // the JSON report on stdout.
    process.stderr.write(`… ${c.name}\n`);
    await setRules(c);
    const req = c.request || {};
    const [w, rs] = [await through(W, req), await through(RS, req)];
    ran++;

    const problems = problemsBetween(w, rs);

    // Did the case's own rules change anything this bench can see? Asked of
    // the raw differences, not the filtered ones: `EXPECTED` excuses places
    // where the two proxies disagree on purpose, which has nothing to do with
    // whether the rule did something.
    const bare = unruled.get(JSON.stringify(c.request || {}));
    if (bare && problemsBetween(bare, rs).length === 0) inert.push(c.name);

    const news = problems.filter((p) => !EXPECTED.some((e) => e.match(p, c)));
    if (news.length) {
      differing++;
      report.push({ name: c.name, rules: c.rules, groups: c.groups, problems: news });
    }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, report, inert: inert.length, inertCases: inert }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
