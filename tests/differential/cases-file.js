// The local-file family — `file` `tpl` `rawfile` and their `x`/`xs` variants —
// put through both proxies.
//
// These rules answer from disk, so the corpus owns a fixture tree and writes it
// on load. Both proxies run as the same user and are given the same rules text,
// so the paths below are absolute and shared.
//
// It ends at `differing: 2`, both named where they are written: a URL source
// spelled `https://` against a plaintext origin, and `<…>`, which names a path
// here and is fetched by upstream against a pattern that leaves nothing to
// append.
//
// Note the two pattern shapes. `A` pins the pattern to the request's whole path
// so the rule's value is used as written; `P` leaves the path unmatched so it is
// concatenated onto the value. Getting this wrong is silent: the first draft of
// this corpus wrote `P` everywhere, so `file:///tmp/x/plain.txt` was asked for
// `/tmp/x/plain.txt/echo` and *both* proxies 404'd — eleven cases agreeing on
// nothing.

const fs = require('fs');
const path = require('path');

const ORIGIN = Number(process.env.PORT_BASE || 18700) + 2;
const P = `127.0.0.1:${ORIGIN}`;
const A = `${P}/echo`;

/** The fixture tree, rebuilt on every run so a stale file cannot pass a case. */
const DIR = '/tmp/wrs-file-fixtures';
const F = (name) => path.join(DIR, name);

const FIXTURES = {
  'plain.txt': 'plain text body\n',
  'mock.json': '{"from":"mock"}\n',
  'noext': 'no extension body\n',
  'a b.json': '{"spaced":true}\n',
  'page.html': '<html>a page</html>\n',
  'vector.svg': '<svg xmlns="http://www.w3.org/2000/svg"/>\n',
  'notes.md': '# notes\n',
  'data.csv': 'a,b\n1,2\n',
  'conf.yaml': 'a: 1\n',
  'bundle.js.map': '{"version":3}\n',
  'page.xhtml': '<html/>\n',
  'font.woff2': 'not really a font\n',
  'clip.mp4': 'not really a video\n',
  'bundle.zip': 'not really an archive\n',
  'site/index.html': '<html>index</html>\n',
  'site/js/app.js': 'console.log("app");\n',
  'site/sub/index.html': '<html>sub index</html>\n',
  'a..b': 'a filename that merely contains dots\n',
  // A whole HTTP response, in each of the blank-line spellings whistle accepts.
  'raw.http': 'HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nX-Raw: yes\r\n\r\n{"error":"nope"}',
  'raw-lf.http': 'HTTP/1.1 201 Created\nX-Sep: lf\n\nlf separated body',
  'raw-cr.http': 'HTTP/1.1 202 Accepted\rX-Sep: cr\r\rcr separated body',
  'raw-crlf-lf.http': 'HTTP/1.1 203 Non-Authoritative Information\r\nX-Sep: crlf-lf\r\n\nmixed separated body',
  'raw-noseparator.http': 'HTTP/1.1 500 Oops\r\nX-Raw: never-parsed',
  'raw-nostatus.http': 'X-Only: header\r\n\r\nbody after a headerless head',
  'raw-nobody.http': 'HTTP/1.1 204 No Content\r\nX-Empty: yes\r\n\r\n',
  'raw-encoded.http': 'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\n\r\nnot actually gzipped',
  // Templates. The two passes are query-string `{name}` then runtime `${var}`.
  'tpl.json': '{"q":"{name}","qq":"{{name}}","m":"${method}","esc":"${name}","unknown":"{zzz}"}',
  'tpl-spaced.json': '{"spaced":"${ method }"}',
  'tpl-nobrace.txt': 'no braces at all, and a bare $method',
  'tpl-dollar-only.txt': 'a runtime var and nothing else: ${method}',
  'jsonp.js': '{callback}({"ok":1})',
  'range.txt': 'ranged-0123456789-end',
  // The content-type table, which is `mime@1.6.0`'s and not a guess. These are
  // the entries a subset table gets wrong by reasoning about the name: a `.ts`
  // is a transport stream, a `.rs` is an XML service description, and the
  // office formats carry a charset because `isText` looks for `xml` as a
  // substring and finds it inside `openxmlformats`.
  'types/a.ts': 'not typescript\n',
  'types/a.rs': 'fn main() {}\n',
  'types/a.scss': '$c: red;\n',
  'types/a.jsx': '<div/>\n',
  'types/a.less': '@c: red;\n',
  'types/a.md': '# title\n',
  'types/a.csv': 'a,b\n',
  'types/a.php': '<?php ?>\n',
  'types/a.sh': 'echo hi\n',
  'types/a.pem': '-----BEGIN-----\n',
  'types/a.m3u8': '#EXTM3U\n',
  'types/a.docx': 'not really a document\n',
  'types/a.webmanifest': '{"name":"x"}\n',
  'types/a.ics': 'BEGIN:VCALENDAR\n',
  'types/a.zzz': 'an extension nobody knows\n',
};

for (const [name, content] of Object.entries(FIXTURES)) {
  const target = F(name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}
// A binary fixture, so `file` is shown not to mangle bytes.
fs.writeFileSync(F('pixel.png'), Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'));
fs.mkdirSync(F('emptydir'), { recursive: true });

/** One fixture under `types/`, served by its own path. */
const typed = (name) => ({
  name: `content type: ${name}`,
  rules: `${A} file://${F('types/' + name)}`,
});

module.exports = [
  // ── the content-type table ─────────────────────────────────────────────
  typed('a.ts'), typed('a.rs'), typed('a.scss'), typed('a.jsx'), typed('a.less'),
  typed('a.md'), typed('a.csv'), typed('a.php'), typed('a.sh'), typed('a.pem'),
  typed('a.m3u8'), typed('a.docx'), typed('a.webmanifest'), typed('a.ics'),
  // An extension neither table knows falls back to the request URL's, and the
  // request here asks for `/echo` — so both answer `text/html`.
  typed('a.zzz'),

  // ── serving one file ───────────────────────────────────────────────────
  { name: 'baseline: no rule at all', rules: '' },
  { name: 'baseline: a rule that does nothing to the response', rules: `${A} reqHeaders://x-a=1` },
  { name: 'file serves the named file', rules: `${A} file://${F('plain.txt')}` },
  { name: 'file json content type', rules: `${A} file://${F('mock.json')}` },
  { name: 'file html content type', rules: `${A} file://${F('page.html')}` },
  { name: 'file svg content type', rules: `${A} file://${F('vector.svg')}` },
  { name: 'file markdown content type', rules: `${A} file://${F('notes.md')}` },
  { name: 'file csv content type', rules: `${A} file://${F('data.csv')}` },
  { name: 'file yaml content type', rules: `${A} file://${F('conf.yaml')}` },
  { name: 'file source map content type', rules: `${A} file://${F('bundle.js.map')}` },
  { name: 'file xhtml content type', rules: `${A} file://${F('page.xhtml')}` },
  { name: 'file font content type', rules: `${A} file://${F('font.woff2')}` },
  { name: 'file video content type', rules: `${A} file://${F('clip.mp4')}` },
  { name: 'file archive content type', rules: `${A} file://${F('bundle.zip')}` },
  { name: 'file binary stays bytes', rules: `${A} file://${F('pixel.png')}` },
  { name: 'a bare absolute path is a file rule', rules: `${A} ${F('plain.txt')}` },
  { name: 'a file rule answers a POST', rules: `${A} file://${F('plain.txt')}`, request: { method: 'POST', body: 'ignored' } },

  // ── path concatenation ─────────────────────────────────────────────────
  { name: 'file appends the unmatched path', rules: `${P} file://${F('site')}`, request: { path: '/js/app.js' } },
  { name: 'file appends under a path pattern', rules: `${P}/static file://${F('site')}`, request: { path: '/static/js/app.js' } },
  { name: 'file concatenation reaching a directory index', rules: `${P} file://${F('site')}`, request: { path: '/sub/' } },
  { name: 'file concatenation keeps the query off the path', rules: `${P} file://${F('site')}`, request: { path: '/js/app.js?v=2' } },
  { name: 'file concatenation percent-decodes', rules: `${P} file://${DIR}`, request: { path: '/a%20b.json' } },
  { name: 'file concatenation onto a trailing slash', rules: `${P} file://${F('site')}/`, request: { path: '/js/app.js' } },
  { name: 'angle brackets pin the path', rules: `${P} file://<${F('plain.txt')}>`, request: { path: '/js/app.js' } },
  { name: 'angle brackets pin a directory too', rules: `${P} file://<${F('site')}/>`, request: { path: '/js/app.js' } },
  { name: 'tpl concatenates too', rules: `${P} tpl://${DIR}`, request: { path: '/tpl.json?name=world' } },

  // ── several candidates ─────────────────────────────────────────────────
  { name: 'pipe falls through to the second path', rules: `${A} file://${F('nope.txt')}|${F('plain.txt')}` },
  { name: 'pipe takes the first that exists', rules: `${A} file://${F('mock.json')}|${F('plain.txt')}` },
  { name: 'pipe concatenates onto every candidate', rules: `${P} file://${F('nowhere')}|${F('site')}`, request: { path: '/js/app.js' } },
  { name: 'pipe with every candidate missing', rules: `${A} file://${F('nope1')}|${F('nope2')}` },
  { name: 'a rejected .. candidate does not stop the rest', rules: `${A} file://${DIR}/../../escape|${F('plain.txt')}` },
  { name: 'xsfile does not split on pipe', rules: `${A} xsfile://${F('nope.txt')}|${F('plain.txt')}` },
  // The other half of that pair, and the only case in the corpora that proves
  // `xsfile://` does anything at all: the one above is inert by design, since an
  // unsplit path that does not exist falls through to the origin.
  { name: 'xsfile serves the file when present', rules: `${A} xsfile://${F('plain.txt')}` },

  // ── directories and index files ────────────────────────────────────────
  { name: 'trailing slash serves index.html', rules: `${A} file://${F('site')}/` },
  { name: 'no trailing slash on a directory is not found', rules: `${A} file://${F('site')}` },
  { name: 'a directory with no index.html', rules: `${A} file://${F('emptydir')}/` },

  // ── not found ──────────────────────────────────────────────────────────
  { name: 'a missing file is a 404', rules: `${A} file://${F('nope.txt')}` },
  { name: 'a .. path is refused', rules: `${A} file://${DIR}/../../etc/hosts` },
  { name: 'a lone .. segment mid-path is refused', rules: `${A} file://${DIR}/site/../plain.txt` },
  { name: 'a filename containing .. is fine', rules: `${A} file://${F('a..b')}` },

  // ── the x / xs fallback ────────────────────────────────────────────────
  { name: 'xfile falls through when missing', rules: `${A} xfile://${F('nope.txt')}` },
  { name: 'xfile serves the file when present', rules: `${A} xfile://${F('plain.txt')}` },
  { name: 'xfile falls through on a refused path', rules: `${A} xfile://${DIR}/../../escape` },
  { name: 'xfile falls through on a directory', rules: `${A} xfile://${F('site')}` },
  { name: 'xfile falls through when the concatenated path is missing', rules: `${P} xfile://${F('site')}`, request: { path: '/js/nothing.js' } },
  { name: 'xtpl falls through when missing', rules: `${A} xtpl://${F('nope.json')}` },
  { name: 'xtpl renders when present', rules: `${A} xtpl://${F('tpl.json')}`, request: { path: '/echo?name=world' } },
  { name: 'xrawfile falls through when missing', rules: `${A} xrawfile://${F('nope.http')}` },
  { name: 'xrawfile serves the file when present', rules: `${A} xrawfile://${F('raw.http')}` },

  // ── rawfile ────────────────────────────────────────────────────────────
  { name: 'rawfile parses status line and headers', rules: `${A} rawfile://${F('raw.http')}` },
  { name: 'rawfile with lf separators', rules: `${A} rawfile://${F('raw-lf.http')}` },
  { name: 'rawfile with cr separators', rules: `${A} rawfile://${F('raw-cr.http')}` },
  { name: 'rawfile with a crlf-lf separator', rules: `${A} rawfile://${F('raw-crlf-lf.http')}` },
  { name: 'rawfile with no blank line is served whole', rules: `${A} rawfile://${F('raw-noseparator.http')}` },
  { name: 'rawfile whose first line is a header', rules: `${A} rawfile://${F('raw-nostatus.http')}` },
  { name: 'rawfile with an empty body', rules: `${A} rawfile://${F('raw-nobody.http')}` },
  { name: 'rawfile on a file that is not a response at all', rules: `${A} rawfile://${F('plain.txt')}` },
  { name: 'rawfile of a missing file', rules: `${A} rawfile://${F('nope.http')}` },

  // ── templates ──────────────────────────────────────────────────────────
  { name: 'tpl substitutes from the query string', rules: `${A} tpl://${F('tpl.json')}`, request: { path: '/echo?name=world' } },
  { name: 'tpl with no query string still runs the second pass', rules: `${A} tpl://${F('tpl.json')}` },
  { name: 'tpl repeated query key becomes a json array', rules: `${A} tpl://${F('tpl.json')}`, request: { path: '/echo?name=a&name=b' } },
  { name: 'tpl plus-encoded query value', rules: `${A} tpl://${F('tpl.json')}`, request: { path: '/echo?name=a+b' } },
  { name: 'tpl percent-encoded query value', rules: `${A} tpl://${F('tpl.json')}`, request: { path: '/echo?name=a%2Fb' } },
  { name: 'tpl empty query value', rules: `${A} tpl://${F('tpl.json')}`, request: { path: '/echo?name=' } },
  { name: 'a file with no braces is never rendered', rules: `${A} tpl://${F('tpl-nobrace.txt')}`, request: { path: '/echo?name=world' } },
  { name: 'a brace with whitespace inside does not arm the renderer', rules: `${A} tpl://${F('tpl-spaced.json')}`, request: { path: '/echo?name=world' } },
  { name: 'a runtime var alone does arm the renderer', rules: `${A} tpl://${F('tpl-dollar-only.txt')}` },
  { name: 'dust is tpl', rules: `${A} dust://${F('tpl.json')}`, request: { path: '/echo?name=world' } },
  { name: 'jsonp is tpl', rules: `${A} jsonp://${F('tpl.json')}`, request: { path: '/echo?name=world' } },
  { name: 'jsonp writes its own callback wrapper', rules: `${A} jsonp://${F('jsonp.js')}`, request: { path: '/echo?callback=cb123' } },
  { name: 'jsonp with no callback leaves the placeholder', rules: `${A} jsonp://${F('jsonp.js')}` },
  { name: 'tpl of a missing file', rules: `${A} tpl://${F('nope.json')}` },
  { name: 'tpl content type comes from the file extension', rules: `${A} tpl://${F('jsonp.js')}`, request: { path: '/echo?callback=cb' } },
  { name: 'tpl of a directory index', rules: `${A} tpl://${F('site')}/` },

  // ── content type ───────────────────────────────────────────────────────
  { name: 'content type falls back to the request url extension', rules: `${P}/thing.json file://${F('noext')}`, request: { path: '/thing.json' } },
  { name: 'content type falls back to text html', rules: `${A} file://${F('noext')}` },
  { name: 'content type ignores the request when the file has one', rules: `${P}/thing.css file://${F('mock.json')}`, request: { path: '/thing.css' } },
  { name: 'content type of a concatenated candidate', rules: `${P} file://${F('site')}`, request: { path: '/js/app.js' } },
  { name: 'content type ignores the query when guessing from the url', rules: `${P}/thing.json file://${F('noext')}`, request: { path: '/thing.json?v=1' } },

  // ── inline content ─────────────────────────────────────────────────────
  // An inline value is one whitespace-free token — the rule line is split
  // before `(` is ever looked at, so `file://(a b)` is two tokens and neither is
  // a value. Anything with a space in it belongs in a fenced block instead.
  { name: 'file of an inline value', rules: `${A} file://(inline-body)` },
  { name: 'file of an inline value takes its type from the url', rules: `${P}/thing.json file://(inline-body)`, request: { path: '/thing.json' } },
  { name: 'an inline value containing a space is not a value', rules: `${A} file://(inline body)` },
  { name: 'tpl of an inline value', rules: `${A} tpl://(hello-{name}-and-${'${method}'})`, request: { path: '/echo?name=world' } },
  { name: 'rawfile of an inline value with no blank line', rules: `${A} rawfile://(no-blank-line-anywhere)` },
  { name: 'an empty inline value', rules: `${A} file://()` },
  { name: 'an inline value that looks like a path', rules: `${A} file://(${F('plain.txt')})` },

  // ── values declared in the rules text ──────────────────────────────────
  {
    name: 'a fenced block is the file body',
    rules: '``` mock.json\n{"declared":true}\n```\n' + `${A} file://{mock.json}`,
  },
  {
    name: 'a fenced block with no extension in its name',
    rules: '``` mockbody\nplain declared body\n```\n' + `${A} file://{mockbody}`,
  },
  {
    name: 'a fenced block is rendered by tpl',
    rules: '``` t.json\n{"q":"{name}","m":"${method}"}\n```\n' + `${A} tpl://{t.json}`,
    request: { path: '/echo?name=world' },
  },
  {
    name: 'a fenced block is parsed by rawfile',
    rules: '``` r.http\nHTTP/1.1 418 Teapot\r\nX-Fenced: yes\r\n\r\nfenced raw body\n```\n' + `${A} rawfile://{r.http}`,
  },
  {
    name: 'a fenced raw response loses its content-encoding',
    rules: '``` enc.http\nHTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\n\r\nnot actually gzipped\n```\n' + `${A} rawfile://{enc.http}`,
  },
  {
    name: 'a raw response from a file keeps its content-encoding',
    rules: `${A} rawfile://${F('raw-encoded.http')}`,
  },
  {
    name: 'a fenced block is not extended by the request path',
    rules: '``` mock.json\n{"declared":true}\n```\n' + `${P} file://{mock.json}`,
    request: { path: '/js/app.js' },
  },
  { name: 'a values key that names nothing', rules: `${A} file://{no-such-value}` },

  // ── other operators over a file response ───────────────────────────────
  { name: 'resHeaders applies to a file response', rules: `${A} file://${F('plain.txt')} resHeaders://x-mock=1` },
  { name: 'resType overrides a file content type', rules: `${A} file://${F('plain.txt')} resType://json` },
  { name: 'replaceStatus over a file response', rules: `${A} file://${F('plain.txt')} replaceStatus://503` },
  { name: 'resCors over a file response', rules: `${A} file://${F('plain.txt')} resCors://*`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'a file rule answers an OPTIONS preflight', rules: `${A} file://${F('plain.txt')}`, request: { method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'PUT' } } },
  { name: 'a file rule with no origin header is not corsed', rules: `${A} file://${F('plain.txt')}`, request: { method: 'OPTIONS' } },
  { name: 'a file response carries auto cors when an origin is sent', rules: `${A} file://${F('plain.txt')}`, request: { headers: { origin: 'https://app.test' } } },
  { name: 'a file rule beats a host rule', rules: `${A} file://${F('plain.txt')} host://192.0.2.1` },
  { name: 'a 404 from a file rule still takes response operators', rules: `${A} file://${F('nope.txt')} resHeaders://x-mock=1` },

  // ── the shared slot ────────────────────────────────────────────────────
  // `file://` has no protocol key of its own upstream: it lands in `rules.rule`
  // alongside `statusCode://`, `redirect://` and a bare destination, and
  // `getRule` returns the **first** of them (`_original/lib/rules/rules.js:1310-1316`).
  // So these do not combine — one answers and the others are not in the
  // resolved set at all. Which is also what decides whether an `ignore://` can
  // reach the file: it names the winner or it names nothing.
  { name: 'a file then statusCode on one line', rules: `${A} file://${F('mock.json')} statusCode://204` },
  { name: 'statusCode then a file on one line', rules: `${A} statusCode://204 file://${F('mock.json')}` },
  { name: 'a file then a redirect', rules: `${A} file://${F('mock.json')} redirect://http://d.test/` },
  { name: 'a redirect then a file', rules: `${A} redirect://http://d.test/ file://${F('mock.json')}` },
  { name: 'a file then a destination', rules: `${A} file://${F('mock.json')} http://127.0.0.1:${ORIGIN}/x` },
  { name: 'a destination then a file', rules: `${A} http://127.0.0.1:${ORIGIN}/x file://${F('mock.json')}` },
  { name: 'a file line above a statusCode line', rules: `${A} file://${F('mock.json')}\n${A} statusCode://204` },
  { name: 'a statusCode line above a file line', rules: `${A} statusCode://204\n${A} file://${F('mock.json')}` },
  { name: 'ignore file when the file won the slot', rules: `${A} file://${F('mock.json')} statusCode://204 ignore://file` },
  { name: 'ignore file when the file lost the slot', rules: `${A} statusCode://204 file://${F('mock.json')} ignore://file` },
  { name: 'ignore rule when the file won the slot', rules: `${A} file://${F('mock.json')} statusCode://204 ignore://rule` },
  // `skip://` is the spelling that falls through to the next member.
  { name: 'skip file hands the slot to statusCode', rules: `${A} file://${F('mock.json')} statusCode://204 skip://file` },
  { name: 'skip rule takes the whole family', rules: `${A} file://${F('mock.json')} statusCode://204 skip://rule` },
  { name: 'ignore xfile does not name a file', rules: `${A} file://${F('mock.json')} statusCode://204 ignore://xfile` },
  { name: 'ignore file does not name an xfile', rules: `${A} xfile://${F('nope.txt')} statusCode://204 ignore://file` },

  // ── range requests ─────────────────────────────────────────────────────
  { name: 'range over a file', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=0-5' } } },
  { name: 'range over an inline value', rules: `${A} file://(0123456789)`, request: { headers: { range: 'bytes=2-4' } } },
  { name: 'range over a rawfile is ignored', rules: `${A} rawfile://${F('raw.http')}`, request: { headers: { range: 'bytes=0-3' } } },
  { name: 'range over a tpl is ignored', rules: `${A} tpl://${F('tpl.json')}`, request: { headers: { range: 'bytes=0-3' } } },
  { name: 'an unsatisfiable range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=999-1000' } } },
  { name: 'a suffix range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=-5' } } },
  { name: 'an open-ended range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=7-' } } },
  { name: 'a whole-file range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=0-20' } } },
  { name: 'a range past the end', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=10-99' } } },
  { name: 'two ranges at once', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=0-1,5-6' } } },
  { name: 'a range in a unit that is not bytes', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'items=0-5' } } },
  { name: 'a malformed range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=abc' } } },
  { name: 'a range on an empty file body', rules: `${A} file://()`, request: { headers: { range: 'bytes=0-1' } } },
  { name: 'an uppercase range unit', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'BYTES=0-5' } } },
  { name: 'a range with leading whitespace', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: '  bytes=0-5' } } },
  { name: 'a range with a space before the equals', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes =0-5' } } },
  { name: 'a reversed range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=9-2' } } },
  { name: 'a negative range', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=-3-5' } } },
  { name: 'a range with a doubled dash', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=0--5' } } },
  { name: 'a range with a signed start', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=+2-6' } } },
  { name: 'an empty range value', rules: `${A} file://${F('range.txt')}`, request: { headers: { range: 'bytes=' } } },
  { name: 'a range over a concatenated file', rules: `${P} file://${F('site')}`, request: { path: '/js/app.js', headers: { range: 'bytes=0-6' } } },

  // ── a file source that is a URL ────────────────────────────────────────
  // The file family does not only read the disk: an entry `util.isUrl` accepts
  // is fetched over HTTP and its bytes are served as the mock
  // (`pluginMgr.resolveKey`, `_original/lib/plugins/index.js:1521-1529`, reached
  // from `readFiles`, `lib/handlers/file-proxy.js:39-59`). This port answered
  // 404 to every line below until it was measured.
  //
  // The origin doubles as the source, so `/json` and friends are the fixtures.
  // It is a *fetch*, not a forward: the client's own headers do not travel, and
  // the answer carries the file family's `Server` header — which is how these
  // were told apart from a destination rewrite in the first place.
  { name: 'a url file source is fetched', rules: `${A} file://http://${P}/json` },
  { name: 'a url file source keeps its own path', rules: `${P} file://http://${P}/json`, request: { path: '/echo/deep' } },
  // Two deliberate deviations, both about `https://` and `<…>`:
  //
  // * the **https spelling** points TLS at a plaintext origin. whistle answers
  //   `200` anyway; this port speaks the scheme it was given, fails the
  //   handshake and 404s. Matching upstream here would mean ignoring the `s`.
  // * `<…>` names a **path**, never a URL to fetch — measured, and reproduced.
  //   Against a pattern that leaves nothing to append, upstream fetches it after
  //   all (`^http://P/echo <http://P/x>` serves the URL's bytes). No reading of
  //   `file-proxy.js` explains why the pattern's leftover should decide whether
  //   a value is a URL, so the shape is recorded and not copied.
  { name: 'a url file source, https spelling', rules: `${A} file://https://${P}/json` },
  { name: 'angle brackets name a path, not a url', rules: `${A} file://<http://${P}/json>` },
  { name: 'a url source for tpl', rules: `${A} tpl://http://${P}/json` },
  { name: 'a url source for rawfile', rules: `${A} rawfile://http://${P}/rawres` },
  { name: 'a url source that 404s', rules: `${A} file://http://${P}/status?code=404` },
  { name: 'a url source that 500s is a 502', rules: `${A} file://http://${P}/status?code=500` },
  { name: 'an x variant falls through when the url 404s', rules: `${A} xfile://http://${P}/status?code=404` },
  { name: 'the type comes from the url, not the answer', rules: `${A} file://http://${P}/json?x=1` },
  { name: 'a url source with no extension', rules: `${A} file://http://${P}/plain` },
  { name: 'a local path is preferred to a url after it', rules: `${A} file://${F('mock.json')}|http://${P}/json` },
  { name: 'a missing local path falls through to the url', rules: `${A} file://${F('nope.json')}|http://${P}/json` },
];
