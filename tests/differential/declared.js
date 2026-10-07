// Differences between whistle and whix that were measured, understood and
// accepted — one entry per **case** and **field**, with the upstream version it
// was measured against and the reason.
//
// This replaces "cases-delete.js ends at differing: 8", which lived in corpus
// headers and in the README and was checked by a person reading two numbers.
// A count cannot tell you *which* eight: a run that fixed one difference and
// grew a new one reported 8 and passed. Here every difference has a name, so:
//
//   * a difference no entry names is **news**, and the bench exits 1;
//   * an entry whose difference no longer happens is **stale**, and the bench
//     exits 1 too — delete it, or find out why the behaviour moved. A stale
//     entry left in place would excuse that field in that case forever.
//
// The global patterns that apply across corpora (a proxy naming itself in
// `x-server`, a gateway error's prose) stay in `harness.js`'s `EXPECTED`; this
// file is for differences that belong to one case.
//
// Entry shape:
//   case:     the case's `name`, exactly
//   fields:   the differing fields — the text before `: whistle=` in the
//             bench's report, e.g. `status`, `res.body`, `req.header.x-a`
//   upstream: the whistle version the difference was measured against, or a
//             list of them; an entry is in force only in a run against one of
//             them (`whistle-pkg.js`, `forVersion`)
//   why:      the reason, or where the reason is written down

/** The field a reported problem is about: `req.header.x-a: whistle=…` → `req.header.x-a`. */
function fieldOf(problem) {
  const m = /^(.*?): whistle=/.exec(problem);
  return m ? m[1] : problem.split(': ')[0];
}

const { forVersion, MEASURED } = require('./whistle-pkg');

/**
 * One declared difference, measured against every release in `MEASURED`. The
 * full reasoning lives in the corpus header `why` points at.
 */
const d = (name, fields, why) => ({ case: name, fields, upstream: MEASURED, why });

/** One that only some releases have: upstream changed its answer between them. */
const only = (versions, name, fields, why) => ({ case: name, fields, upstream: versions, why });

// Shared reasons, each written once.
const GATEWAY = 'a 502 on both sides; only the page differs — whistle\'s is HTML holding a Node stack '
  + 'trace (wrapGatewayError), this port\'s is the error chain as plain text. cases-proxy.js, divergence 1';
const PROSE = ['res.header.content-type', 'res.body'];
const BUST = ['res.header.pragma', 'res.header.cache-control', 'res.header.expires', 'res.body'];

const DECLARED = {
  'cases-compose.js': [
    d('script ctx: getValue reads a fenced block', ['req.header.x-v'],
      'upstream\'s getValue misses a ``` block declared in the same text; this port serves it. Header, divergence 8'),
    d('script ctx: a body over whistle\'s chunk cap', ['req.header.x-b'],
      'whistle\'s script sees the body only up to the first chunk past 16 KB. Header, divergence 9'),
    // A bare id, and no --weinre in this run: nothing is injected here, so the
    // cache headers an injection needs are not written either (R4-03).
    ...['weinre injects into html', 'weinre on an empty html body', 'weinre on a gzipped html body',
      'weinre with no value at all'].map((n) => d(n,
      ['res.body', 'res.header.cache-control', 'res.header.expires', 'res.header.pragma'],
      'whistle inlines its own bundled weinre agent and so makes the page uncacheable; this port contains no weinre, names no server here, injects nothing, and leaves the headers as the origin sent them. Header, weinre://')),
    d('weinre with a url value', ['res.body'],
      'whistle inlines its own bundled weinre agent; this port injects a <script src> for the URL the rule names. Header, weinre://'),
    d('weinre reaches javascript upstream', ['res.header.cache-control', 'res.header.expires', 'res.header.pragma', 'res.body'],
      'whistle appends its agent to JavaScript responses too; this port leaves a .js body alone. Header, weinre://'),
    d('intercept written as a protocol', PROSE,
      'intercept:// is a protocol in neither; both answer 502 in their own words. Header, intercept://'),
  ],

  'cases-bodies.js': [
    // The fixture is plain HTML labelled `zstd`. whistle does not know zstd and
    // treats the body as uncompressed, so the substitution finds its pattern.
    // A real zstd body — which Chrome asks for and CDNs send — would get the
    // operators run over compressed bytes: resReplace matching nothing,
    // resAppend writing text after the frame. This port forwards a body under
    // a coding it cannot undo as it arrived and records `unsupported-coding`
    // on the session (docs/API.md, 没生效的规则; docs/RULES.md).
    d('resReplace on a zstd page', ['res.body'],
      'a coding this port cannot undo is forwarded untouched and the session says so; upstream rewrites it as if uncompressed'),
    // 2.10.8 classifies by substring with `xml` ahead of `image/`, so an SVG
    // is text and the substitution runs, here and there. 2.10.10 checks
    // `image/` first (avwo/whistle@ca15b3f) and leaves it alone. Kept at
    // 2.10.8's answer: recolouring an icon is a real use, and following would
    // make a matching rule do nothing without a word.
    only(['2.10.10'], 'resReplace on an svg image', ['res.body'],
      'an SVG is text here, as in 2.10.8; 2.10.10 counts it as an image and skips text operators. STATUS, U1'),
  ],

  'cases-delete.js': [
    d('delete bare pathname keeps the query', ['req.url'],
      'upstream appends the query twice (/?a=1?a=1), a request line no origin parses. Header'),
    ...['delete bare body on a post', 'delete res.body empties the response',
      'delete res.body discards resBody the operator', 'delete res.body discards resPrepend and resAppend']
      .map((n) => d(n, ['res.body'], 'EMPTY_BUFFER is undefined in 2.10.8 and 2.10.10, so upstream forwards the real body; '
        + 'delete://body asks for an empty one and gets it here. Header')),
    ...['delete req.body on a post', 'delete req.body discards reqBody the operator',
      'delete req.body discards reqPrepend and reqAppend']
      .map((n) => d(n, ['req.body'], 'EMPTY_BUFFER is undefined in 2.10.8 and 2.10.10, so upstream forwards the real body; '
        + 'delete://body asks for an empty one and gets it here. Header')),
  ],

  'cases-docs.js': [
    d('https-proxy: www.example.com https-proxy://127.0.0.1:1234', PROSE, GATEWAY),
    d('proxy: www.example.com proxy://127.0.0.1:1234', PROSE, GATEWAY),
    d('socks: www.example.com socks://127.0.0.1:1234', PROSE, GATEWAY),
    d('resPrepend: www.example.com/page resPrepend://(<!--页面开始-->)', ['res.body'],
      'the one body operator that keeps the origin\'s echo shows this port busting the request cache. Header, cause 2'),
    d('resBody: www.example.com/api/user resBody://temp/blank.json', BUST,
      'temp/… is whistle\'s console-edited temp file; this port has no such directory, so it is a literal. Header, cause 3'),
  ],

  'cases-file.js': [
    d('a url file source, https spelling', ['status', 'res.header.server', 'res.header.content-type', 'res.body'],
      'an https:// file source against a plaintext origin: whistle fetches it anyway, this port refuses. Header'),
    d('angle brackets name a path, not a url', ['status', 'res.header.server', 'res.header.content-type', 'res.body'],
      '<…> names a path here and is fetched by upstream when the pattern leaves nothing to append. Header'),
    // The same reclassification as cases-bodies' SVG case: `isText` is false
    // for an image, so 2.10.10 serves the file without a charset.
    only(['2.10.10'], 'file svg content type', ['res.header.content-type'],
      'an SVG is text here, as in 2.10.8, and carries charset=utf-8; 2.10.10 counts it as an image. STATUS, U1'),
  ],

  'cases-flags.js': [
    d('disable trailers against a trailers rule', ['res.header.trailer'],
      'whistle announces Trailer: x-t and then sends no trailer section; this port drops the announcement too. Header, 1'),
  ],

  'cases-frames.js': [
    ...[['an empty response separator', 'res'], ['a response separator on a gzipped body', 'res'],
      ['a response separator under disable://captureStream', 'res'], ['a response separator under enable://hide', 'res'],
      ['an empty request separator', 'req'], ['a request separator under enable://hide', 'req']]
      .map(([n, side]) => d(n, [`${side}.header.x-whistle-custom-frame-separator`],
        'parseFrameSep deletes the control header from inside itself, so every branch that skips it leaks the '
        + 'header; this port removes it first. Header')),
  ],

  'cases-groups.js': [
    d('two groups with the same name', ['req.method'],
      'upstream\'s add overwrites a group of the same name; this port refuses it and keeps the first. Header, 1'),
  ],

  'cases-paths.js': [
    d('paths: a UNC path as the value', PROSE, `a destination both fail to reach. ${GATEWAY}`),
    d('paths: a forward-slash UNC path', PROSE, `a destination both fail to reach. ${GATEWAY}`),
    d('paths: a real file with a percent in its name', ['status', 'res.header.content-type', 'res.header.server'],
      'upstream percent-decodes the path and cannot find per%cent.txt; this port opens the file named. Header, 2'),
    d('paths: a cjk header value', ['req.header.x-cjk'],
      'Node cannot write a header above U+00FF and drops it; this port sends UTF-8. Header, 3–6'),
    d('paths: an emoji header value', ['req.header.x-emoji'],
      'Node cannot write a header above U+00FF and drops it; this port sends UTF-8. Header, 3–6'),
    d('paths: a latin-1 header value', ['req.header.x-latin'],
      'Node writes a header as latin-1, this port as UTF-8. Header, 3–6'),
    d('paths: a cjk response header value', ['status', 'res.header.content-type', 'res.header.x-origin', 'res.header.x-cjk', 'res.body'],
      'the same header on a response: whistle loses the whole response. Header, 3–6'),
    d('paths: a cjk path segment', ['req.url'],
      'pathReplace://echo=中文: whistle drops the segment and asks for /; this port percent-encodes it. Header, 7'),
    d('paths: a cjk replacement into a body that is not utf-8', ['res.body'],
      'both mangle a non-UTF-8 body, each in its own encoding. Header, 8'),
  ],

  'cases-proxy.js': [
    ...['host: a name that does not resolve', 'host: an address that refuses the connection',
      'proxy: http2https-proxy on a plain origin', 'proxy: socks5 is not a protocol name',
      'proxy: https-proxy at a hop that speaks no TLS', 'proxy: a scheme written into the proxy URL',
      'proxy: no address at all', 'fail: a hop that refuses the connection', 'fail: a 407 on the CONNECT path',
      'fail: a socks hop that refuses', 'fail: a socks hop that is not a socks proxy',
      'pac: a proxy that is not there', 'rule: rules:// is not the include, in either',
      'auto2http: disabled, the handshake is the answer', 'auto2http: no host rule and a non-local address',
    ].map((n) => d(n, PROSE, GATEWAY)),
    ...['fail: xproxy falls back to a direct connection', 'pac: a proxy that is not there, then DIRECT']
      .map((n) => d(n, ['req.url'], 'after falling back to a direct connection whistle still sends absolute-form; '
        + 'this port sends origin-form. Header, divergence 2')),
    d('pac: SOCKS5 is not a word upstream reads', ['req.header.x-hop-form', 'req.header.x-hop-target', 'req.header.x-hop-headers'],
      'upstream\'s PAC reader does not know SOCKS5 and goes direct; this port reads the list as PAC defines it. Header, divergence 3'),
    d('pac: DIRECT then PROXY', ['req.header.x-hop-form', 'req.header.x-hop-target', 'req.header.x-hop-headers'],
      'upstream lets a PROXY anywhere in the list win over an earlier DIRECT; this port reads it in order. Header, divergence 3'),
    d('pac: a file that is not served', ['status', 'res.header.content-type', 'res.header.x-origin', 'res.body'],
      'whistle connects direct when the PAC file cannot be fetched; this port refuses. Header, divergence 4'),
    ...['rule: names a values entry holding more rules', 'rule: a values entry that does not exist']
      .map((n) => d(n, ['status', 'res.header.content-type', 'res.header.x-server', 'res.header.x-origin', 'res.body'],
        'rule://<name> is this port\'s values-store include; upstream reads it as an unusable URL. Header, divergence 5')),
    d('residue: urlReplace\'s rewrite is not in the second-pass URL', ['req.header.x-hop-form', 'req.header.x-hop-target', 'req.header.x-hop-headers'],
      'the second resolution pass sees the destination before urlReplace here. Header, divergence 6a'),
    d('residue: enable://proxyHost written against the replacement', ['req.header.x-hop-form', 'req.header.x-hop-target', 'req.header.x-hop-headers'],
      'upstream unions the two passes for three enable:// flags only. Header, divergence 6b'),
    d('fail: xhttps-proxy falls back to a direct connection', ['status', 'res.header.content-type', 'res.header.x-origin', 'res.body'],
      'xhttps-proxy:// at a dead hop hangs upstream; this port falls back as the x prefix documents. Header, divergence 7'),
    d('direct: the client\'s Proxy-Authorization stops at this proxy', ['req.header.proxy-authorization'],
      'the client\'s credential for this proxy; whistle forwards it to the origin, this port only to an upstream proxy. Header, divergence 8'),
  ],

  'cases-values.js': [
    ...['an unbalanced open bracket', 'an unbalanced close bracket',
      'a payload whose hash is eaten by the comment stripper', 'angle brackets on a body operator',
      'angle brackets around a payload containing parens', 'a script tag in angle brackets',
    ].map((n) => d(n, BUST, 'a value a text operator cannot read is used as written here; upstream opens it as '
      + 'a path, fails, and does nothing. Header, first divergence')),
    d('a value that names nothing on statusCode', ['status', 'res.body'],
      'upstream hands {nope} to Node as a status code and the connection is reset; this port answers its own '
      + 'empty 200, as it does for any statusCode it cannot read. See the case\'s comment'),
    d('a value that names nothing on replaceStatus', ['status', 'res.header.content-type', 'res.header.x-origin', 'res.body'],
      'upstream sets {nope} as the status code and the connection is reset; this port leaves the origin\'s '
      + 'answer alone. See the case\'s comment'),
    d('a value that names nothing on method',
      ['status', 'res.header.content-type', 'res.header.x-server', 'res.header.x-origin', 'res.body'],
      'upstream sends {nope} as the method, Node refuses the token, and the answer is a 502; this port '
      + 'sends the request\'s own method. See the case\'s comment'),
    d('trailing text after a reference', ['res.body'],
      'upstream reads {v}tail as {v} and drops the tail; a reference must end the value here. Header, second divergence'),
    d('json5: an unquoted dashed key on resHeaders', ['status', 'res.header.content-type', 'res.header.x-origin', 'res.body'],
      '{x-a: …} is not JSON5 in either; both build a header named {x-a — Node writes it and loses the response, '
      + 'hyper refuses it. See the case\'s comment'),
    d('json5: an unquoted dashed key on trailers', ['res.header.trailer'],
      'the same {x-t header name on the trailer road. See the case\'s comment'),
  ],

  'frames-bench.js': [
    // With a separator header and no enable://captureStream, 2.10.10 frames a
    // GET's response anyway: it no longer records that a bodiless request was
    // sent before the response arrives, and its capture code reads "request
    // still streaming" into that (data.js, `requestTime == null`). Measured
    // with the capture code instrumented. Its changelog and FAQ still ask for
    // the flag, and so does this port.
    only(['2.10.10'], 'a response separator without the flag', ['frames'],
      'a side effect in 2.10.10, not a change it announced; the flag is still required here. STATUS, U1'),
    // 2.10.9 frames an event stream whose type carries a parameter; 2.10.8
    // compared the header whole. This port follows the newer answer.
    only(['2.10.8'], 'an event stream with a charset parameter', ['frames'],
      'fixed upstream in 2.10.9 (text/event-stream; charset=utf-8); followed here. STATUS, U1'),
  ],

  'ws-bench.js': [
    // Up to 2.10.9, a client's frame on a plain WebSocket went to
    // handleSendToClientFrame — the other direction's handler — so a script
    // for the client's frames did nothing and one with both handlers applied
    // the wrong one. 2.10.10 fixed it (avwo/whistle#1358); this port always
    // routed frames by direction.
    ...['a frame script with both handlers', 'a frame script for the client\'s frames only']
      .map((n) => only(['2.10.8'], n, ['origin', 'back'],
        '2.10.8 hands a client frame to the handler for server frames; fixed in 2.10.10, and right here. ws-bench.js header')),
  ],

  'h2-bench.js': [
    // whistle's `disable://http2` turns h2 off on both legs: its forged server
    // stops offering h2 to the client (`getSNIServer(…, disableH2)`,
    // `_original/lib/https/index.js:1263-1270`) as well as to the origin. This
    // port turns off the origin leg only; the client half would need the rules
    // resolved before the TLS handshake picks an ALPN. RULES.md, `h2`.
    d('an h2 client with disable://http2', ['client protocol'],
      'the client half of disable://http2 is not implemented; the origin half is. h2-bench.js, declared.js'),
  ],

  'write-bench.js': [
    d('an empty write path', ['file cwd:echo'],
      'upstream writes the dump to a path relative to its cwd; this port writes nothing. See the case\'s comment'),
  ],

  // `frameScript://` — RULES.md, "frameScript", says each of these in full.
  'core-bench.js': [
    // Where upstream's answer is an accident of its implementation rather than
    // something a script could want, this port does the thing the documentation
    // describes. Each is a place a working upstream script keeps working here;
    // none is a place a script that works here was written against upstream.
    d('frame: a binary frame the handler leaves alone', ['answer'],
      'upstream re-sends every frame a handler saw as text (no opts.binary), so a binary frame arrives as mangled text; '
      + 'this port keeps the opcode the frame came with'),
    d('frame: the handler is handed a Buffer', ['answer'],
      'upstream clears the vm context\'s globals once the script has run, so `Buffer` is undefined inside a handler '
      + '(2.10.10 delivers the ReferenceError as the frame; 2.10.8 never runs the handler); here the globals stay'),
    d('frame: sendToClient from inside a handler', ['answer'],
      'the same cleared context: `ctx` is undefined inside an upstream handler unless the script captured it first. '
      + 'Here `ctx.sendToClient` works from a handler, which is what frameScript.md\'s own example does'),
    d('frame: a frame the script sends is passed to its own handler', ['answer'],
      'upstream replaces the top-level sendToServer when that direction\'s handler is installed, and the frame sent '
      + 'before it is lost; here it is delivered, through the handler like any other'),
    d('frame: what the script sees while it runs', ['answer'],
      'this port also offers `ctx.frame` and `ctx.direction` (its older one-shot form, kept for scripts written for it); '
      + 'everything upstream defines has the same type on both sides'),
    d('tcp: a tunnel script that sends data of its own', ['answer'],
      'upstream writes the script\'s sendToClient into the tunnel before its own `200 Connection Established`, so the '
      + 'client sees bytes where the CONNECT answer should be and the tunnel never opens; here they follow the 200'),
    // 2.10.8 hands a client's frame to the handler for *server* frames
    // (ws-bench.js header), so `handleSendToServerFrame` never sees one. Fixed
    // in 2.10.10, which is what this port follows.
    ...['frame: state kept between the frames of one connection',
      'frame: state is per connection, not shared',
      'frame: a binary frame reaches the handler',
      'frame: a handler that returns nothing drops the frame',
      'frame: a handler that throws',
      'frame: what a handler is handed',
      'frame: sendToClient from a handler, through the other handler',
      'frame: sendToServer from the handler for that direction',
      'frame: a handler that asks for a binary frame',
      'frame: what a handler may return',
    ].map((n) => only(['2.10.8'], n, ['answer'],
      '2.10.8 hands a client frame to the handler for server frames, so handleSendToServerFrame never runs on one; '
      + 'fixed in 2.10.10, and right here. ws-bench.js header')),
  ],
};

/**
 * Sort a bench's report into what its declarations excuse and what is news.
 *
 * `report` is the bench's own list of `{ name, problems: [string] }`; `ran` is
 * every case name that was run, so an entry for a case that no longer exists
 * — renamed or deleted — is reported as stale rather than silently ignored.
 */
function judge(bench, report, ran) {
  // Only the entries measured against the whistle this run is asking.
  const entries = forVersion(DECLARED[bench] || []).map((e) => ({ ...e, used: false }));
  const news = [];
  let declared = 0;
  for (const item of report) {
    const left = [];
    for (const problem of item.problems || []) {
      const field = fieldOf(problem);
      const hit = entries.find((e) => e.case === item.name && e.fields.includes(field));
      if (hit) {
        hit.used = true;
        declared++;
      } else {
        left.push(problem);
      }
    }
    if (left.length) news.push({ ...item, problems: left });
  }
  const names = new Set(ran);
  const stale = entries
    .filter((e) => !e.used)
    .map((e) => ({
      case: e.case,
      fields: e.fields,
      why: names.has(e.case)
        ? 'declared, and did not differ'
        : 'declared for a case that was not run — renamed or removed?',
    }));
  return { news, declared, stale };
}

module.exports = { DECLARED, judge, fieldOf };
