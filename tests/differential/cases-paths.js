// Paths and text that are not what this machine is: **Windows spellings**, and
// **bytes outside ASCII**.
//
// Everything else in this directory was measured on macOS with UTF-8
// throughout, and a rule parser is exactly the sort of thing that agrees on one
// platform's spelling and disagrees on another's. Two Windows path lines exist
// anywhere here, both from the documentation and both only ever *resolved*
// (`cases-rulelines.js`). Nothing has ever run one.
//
// **The point is not that these paths work.** `D:\mock.json` does not exist on
// this machine and is not supposed to: what is under test is that both proxies
// decide the same *kind of thing* about it. A value that one reads as a file and
// the other reads as a **host** is the failure this corpus is looking for —
// whistle's shorthand layer rewrites some bare tokens into `file://` and others
// into a forwarding destination, and a drive letter with a colon in it is
// exactly the shape that could fall either way. One proxy 404ing while the
// other opens a socket to a host named `D` is a difference the bench sees, and
// nothing else here would.
//
// So most of these are inert on purpose. The discriminating ones are marked, and
// they are the cases with a **real file** behind them:
//
//   * a file whose name genuinely contains a backslash — legal on this platform,
//     and a proxy that "helpfully" turns `\` into `/` will 404 where the other
//     serves;
//   * a file whose name is CJK, asked for both literally and percent-encoded;
//   * a mixed-separator path at a real directory.
//
// **What it found on its first run, and what was fixed.** Fourteen differences,
// of which five were this port's bugs and are now closed:
//
//   * **a backslash is a path separator everywhere but Windows.** whistle runs
//     every local path through `convertSlash` (`util/file-mgr.js:13-16`), so
//     `file://D:\mock.json` — a path typed on Windows, in a rules file that
//     travelled — opens `D:/mock.json` here. This port took the backslash
//     literally and 404'd on three of these; `@`-includes had the same gap.
//   * **a rewritten URL has to be a request line.** `params://q=中文` put raw
//     UTF-8 in the target, and the origin answered `400` and closed: the rule
//     did not fail to apply, it took the request down. Three encodings, each
//     measured separately — see `request_target` and `merge_query`.
//
// The nine that remain are declared, and every one of them is upstream doing
// less than this port rather than differently:
//
//   1. **two UNC paths** — `\\server\share\x` is a *destination* in both, both
//      fail to reach it, and only the wording of the failure differs. The same
//      licence `harness.js` gives the 404s.
//   2. **a file whose name contains a `%`** — upstream percent-decodes the path,
//      so `per%cent.txt` becomes an invalid escape and is not found. This port
//      opens the file the rule named.
//   3–5. **a header value above ASCII** — `reqHeaders://x-cjk=中文` reaches the
//      origin from here as UTF-8 and does not reach it at all from whistle: a
//      JavaScript string of code points above `U+00FF` cannot be written into a
//      Node header, and the throw takes the header with it. `resHeaders://` is
//      worse — the **whole response** is lost, which is a crash and not a
//      behaviour to copy. `café` differs more quietly: Node writes a header as
//      latin-1, so whistle sends one byte where this sends the two of UTF-8, and
//      UTF-8 is what an origin reading a header today expects.
//   6. **`pathReplace://echo=中文`** — whistle drops the segment and asks for
//      `/`; this port asks for `/%E4%B8%AD%E6%96%87`, which is the rule applied.
//   7. **`urlReplace://` with a backtick** — whistle puts it on the wire raw.
//      hyper will not, so this sends `%60`; the alternative was the rewrite
//      silently not happening, which is what it used to do.
//   8. **`urlReplace://` with cjk** — whistle declines to apply the rule at all.
//   9. **a cjk replacement into a body that is not UTF-8** — both mangle it,
//      each in its own encoding.
//
// Run it like any other corpus, and through the resolver too, where the
// question costs nothing:
//   PORT_BASE=19300 CASES=./cases-paths.js npm run bench
//   PORT_BASE=19300 node rules-oracle.js --from-cases --grep paths

const fs = require('fs');
const path = require('path');

const ORIGIN = Number(process.env.PORT_BASE || 18700) + 2;
const P = `127.0.0.1:${ORIGIN}`;
/** Pins the whole request path, so the value is used exactly as written. */
const A = `${P}/echo`;

const DIR = '/tmp/wrs-path-fixtures';

/**
 * Names that are legal here and would not be on Windows — which is the whole
 * reason to write them down. A backslash is an ordinary character in a POSIX
 * filename, so `back\slash.txt` is one file and not a directory called `back`.
 */
const FIXTURES = {
  'plain.txt': 'plain text body\n',
  'back\\slash.txt': 'a backslash is part of this name\n',
  '中文.txt': 'cjk filename\n',
  'per%cent.txt': 'a percent sign in the name\n',
  'sub/inner.txt': 'inside a directory\n',
};

fs.rmSync(DIR, { recursive: true, force: true });
for (const [name, body] of Object.entries(FIXTURES)) {
  const full = path.join(DIR, name);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, body);
}

module.exports = [
  // ── a drive letter, in every spelling ──────────────────────────────────
  //
  // None of these can open anything here. What matters is that neither proxy
  // decides the token is a *destination*: `D:` has the shape of `host:port`
  // with a non-numeric port, and a proxy that read it that way would dial.
  { name: 'paths: file:// with a backslash drive path', rules: `${A} file://D:\\mock.json` },
  { name: 'paths: file:// with a forward-slash drive path', rules: `${A} file://D:/mock.json` },
  { name: 'paths: file:/// with a drive path', rules: `${A} file:///D:/mock.json` },
  { name: 'paths: a lower-case drive letter', rules: `${A} file://d:/mock.json` },
  { name: 'paths: a bare drive letter and colon', rules: `${A} file://D:` },
  { name: 'paths: a drive path with mixed separators', rules: `${A} file://C:/Users\\john/mock.json` },
  { name: 'paths: a deep windows path', rules: `${A} file://C:\\Users\\john\\Desktop\\mock.json` },
  // The bare-value shorthand is the one that decides file-or-destination, and
  // it is a different code path from the explicit `file://`.
  { name: 'paths: a bare drive path as the value', rules: `${A} D:\\mock.json` },
  { name: 'paths: a bare drive path with forward slashes', rules: `${A} D:/mock.json` },
  { name: 'paths: a bare deep windows path', rules: `${A} C:\\Users\\john\\mock.json` },
  // UNC. Two leading slashes are how a protocol-relative URL starts, so this is
  // the other shape that could be read as a host.
  { name: 'paths: a UNC path as the value', rules: `${A} \\\\server\\share\\mock.json` },
  { name: 'paths: file:// with a UNC path', rules: `${A} file://\\\\server\\share\\mock.json` },
  { name: 'paths: a forward-slash UNC path', rules: `${A} //server/share/mock.json` },
  // The other members of the family, so the answer is not a fact about `file://`.
  { name: 'paths: tpl:// with a drive path', rules: `${A} tpl://D:\\mock.json` },
  { name: 'paths: rawfile:// with a drive path', rules: `${A} rawfile://D:\\mock.json` },
  { name: 'paths: xfile:// with a drive path', rules: `${A} xfile://D:\\mock.json` },
  { name: 'paths: reqBody:// with a drive path', rules: `${A} reqBody://D:\\body.txt` },
  { name: 'paths: resBody:// with a drive path', rules: `${A} resBody://D:\\body.txt` },
  // A pattern that leaves a path to append: what does concatenation do to a
  // value that is not POSIX-shaped?
  { name: 'paths: a drive path with the request path appended', rules: `${P} file://D:\\dir` },
  { name: 'paths: a drive path ending in a separator', rules: `${P} file://D:\\dir\\` },
  // The home shorthand, in both spellings.
  { name: 'paths: ~/ home', rules: `${A} file://~/wrs-nonexistent.json` },
  { name: 'paths: ~\\ home, windows-style', rules: `${A} file://~\\wrs-nonexistent.json` },
  // And on the pattern side, where a drive letter is simply not a URL.
  { name: 'paths: a drive path as the pattern', rules: `C:\\Users\\john reqHeaders://x-hit=1` },
  { name: 'paths: a UNC path as the pattern', rules: `\\\\server\\share reqHeaders://x-hit=1` },

  // ── real files, spelled awkwardly ──────────────────────────────────────
  //
  // These discriminate: the file exists, so "served" and "404" are different
  // answers rather than two ways of failing.
  { name: 'paths: a real file, plainly', rules: `${A} file://${DIR}/plain.txt` },
  // A backslash *in the name*. A proxy that normalises separators looks for
  // `${DIR}/back/slash.txt` and finds nothing; one that does not, serves.
  { name: 'paths: a real file whose name contains a backslash',
    rules: `${A} file://${DIR}/back\\slash.txt` },
  // The same directory reached with a backslash separator: here the normalising
  // proxy is the one that succeeds, so the two cases cannot both be excused by
  // one rule.
  { name: 'paths: a real file behind a backslash separator',
    rules: `${A} file://${DIR}\\plain.txt` },
  { name: 'paths: a real file behind mixed separators',
    rules: `${A} file://${DIR}/sub\\inner.txt` },
  { name: 'paths: a real file with a cjk name', rules: `${A} file://${DIR}/中文.txt` },
  { name: 'paths: a real file with a cjk name, percent-encoded',
    rules: `${A} file://${DIR}/%E4%B8%AD%E6%96%87.txt` },
  { name: 'paths: a real file with a percent in its name',
    rules: `${A} file://${DIR}/per%cent.txt` },
  { name: 'paths: a real file with its percent escaped',
    rules: `${A} file://${DIR}/per%25cent.txt` },
  // `%5C` is a backslash. Whether a value is percent-decoded before it is used
  // as a path decides which of the two files above this finds.
  { name: 'paths: a percent-encoded backslash in a real path',
    rules: `${A} file://${DIR}/back%5Cslash.txt` },
  { name: 'paths: a file: URL with three slashes and a real path',
    rules: `${A} file://${DIR}/plain.txt` },

  // ── bytes outside ASCII ───────────────────────────────────────────────
  //
  // `cases-bodies.js` already covers a GBK *page* and a body that is not UTF-8.
  // What is not covered anywhere is non-ASCII in the **rule** — in a pattern, in
  // a header value, in a path — which is where an encoding assumption lives.
  { name: 'paths: a cjk header value', rules: `${A} reqHeaders://x-cjk=中文` },
  { name: 'paths: a cjk response header value', rules: `${A} resHeaders://x-cjk=中文` },
  { name: 'paths: a latin-1 header value', rules: `${A} reqHeaders://x-latin=café` },
  { name: 'paths: an emoji header value', rules: `${A} reqHeaders://x-emoji=🚀` },
  { name: 'paths: a cjk query parameter', rules: `${A} params://q=中文` },
  { name: 'paths: a cjk path segment', rules: `${A} pathReplace://echo=中文` },
  // The three encodings are separate, and each was measured on its own — see
  // `request_target` and `merge_query` in `src/proxy/apply.rs`. These pin the
  // boundaries between them.
  { name: 'paths: a params value with url punctuation', rules: `${A} params://q=a{b|c^d` },
  { name: 'paths: a params value that is already escaped', rules: `${A} params://q=a%41b` },
  { name: 'paths: a params value with a bare percent', rules: `${A} params://q=a%b` },
  { name: 'paths: urlReplace with url punctuation', rules: `${A} urlReplace://echo=ec{ho` },
  { name: 'paths: urlReplace with an escape in it', rules: `${A} urlReplace://echo=ec%41ho` },
  { name: 'paths: a destination carrying cjk', rules: `${A} http://${P}/echo?q=中文` },
  { name: 'paths: an untouched query keeps its escapes',
    rules: '', request: { path: '/echo?q=a%20b%25c' } },
  { name: 'paths: a rule beside an untouched escaped query',
    rules: `${P} reqHeaders://x-hit=1`, request: { path: '/echo?q=a%20b%25c' } },
  { name: 'paths: a cjk pattern that matches nothing', rules: `http://例子.测试/ reqHeaders://x-hit=1` },
  { name: 'paths: a cjk value in a body', rules: `${A} resBody://(中文)` },
  { name: 'paths: a cjk replacement into a body that is not utf-8',
    rules: `${P} resReplace://ORIG=中文`, request: { path: '/notutf8' } },
  // A percent escape that decodes to a byte no UTF-8 decoder accepts. Whatever
  // each proxy does with it, they have to do the same thing.
  { name: 'paths: a value with an invalid utf-8 escape', rules: `${A} file://${DIR}/%FF.txt` },
  { name: 'paths: a header value with an invalid utf-8 escape',
    rules: `${A} reqHeaders://x-raw=%FF` },
  { name: 'paths: a lone percent at the end of a value',
    rules: `${A} reqHeaders://x-raw=abc%` },
  { name: 'paths: a percent that is not an escape',
    rules: `${A} reqHeaders://x-raw=100%zz` },
  // The request side, so the origin's echo shows what actually left.
  //
  // Percent-encoded and not raw, and that is a limit of the bench rather than a
  // choice: Node's client throws `ERR_UNESCAPED_CHARACTERS` on a path carrying
  // a raw `中文` or a raw backslash, so neither proxy can be asked about one
  // from here. No browser sends either — both are encoded before the request
  // line is built — so what is unaskable is also what nobody sends.
  { name: 'paths: a percent-encoded cjk request path',
    rules: `${P} reqHeaders://x-hit=1`, request: { path: '/echo/%E4%B8%AD%E6%96%87' } },
  { name: 'paths: a percent-encoded backslash in the request path',
    rules: `${P} reqHeaders://x-hit=1`, request: { path: '/echo/%5Cx' } },
  { name: 'paths: a pattern matching a percent-encoded cjk path',
    rules: `${P}/echo/%E4%B8%AD%E6%96%87 reqHeaders://x-hit=1`,
    request: { path: '/echo/%E4%B8%AD%E6%96%87' } },
];
