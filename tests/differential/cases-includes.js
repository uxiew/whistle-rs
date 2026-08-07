// `@` includes: a rules line that is only `@` and a source pulls that source's
// rules text in where the line stands.
//
//   PORT_BASE=19100 node oracle.js &
//   cargo run -- --port 19101 --no-persist --dir /tmp/rs-includes &
//   PORT_BASE=19100 CASES=./cases-includes.js npm run bench
//
// One extra port beyond the harness's three: **`PORT_BASE+10` serves rules
// texts over HTTP**, for the `@<url>` half. A file on disk and a URL are
// different loaders with different caches in upstream (`readFile` vs `request`,
// `_original/lib/util/http-mgr.js:268-330` and `:353-415`) and have to be asked
// separately. The server is started by this file, the way `cases-proxy.js`
// starts its own.
//
// **Why this corpus exists at all.** `@` includes were resolved here only for
// the startup `-r`/`--rule` text: a rules text typed into the console or posted
// to `/api/rules` kept the line as written and configured nothing. That is
// exactly what this bench sets — `setRules` posts to each proxy's own API — so
// every case below went through the path that did not work.
//
// **What makes a case here honest.** An include that never happened and an
// include of an empty file look identical: nothing changes. So every case that
// is *supposed* to include something asserts a header or a body that only the
// included text can produce, and the file opens with two baselines that pin
// "the bench can see a rule at all" before any of it means anything.
//
// **24 of the 35 cases change something on the real-whistle side — and the same
// 24 change something here.** Measured the only way that means anything: each
// case run twice per proxy, once with no rules and once with its own, and the
// two answers compared. A corpus where both proxies agree by doing nothing
// proves nothing, and this area is the worst offender for it.
//
// The 11 that change nothing anywhere are the ones where *nothing happening* is
// the fact: the empty baseline, the five shapes that are not includes, a source
// no plugin serves, and the four sources with nothing in them (a missing file,
// an empty file, a 404 and a 204). Those four say only that neither proxy
// invents rules out of an empty answer — which is worth pinning and is not the
// same as saying the include ran.
//
// ── Cases expected to differ ───────────────────────────────────────────────
//
// A clean run of this file is **`differing: 0`**.
//
// One divergence is deliberate and is *not* reachable from here, so it is
// declared rather than pinned: **a fetch that fails keeps the last good text**.
// Upstream keeps it for three consecutive failures and then applies `''`,
// deleting the rules that source carried (`updateBody`,
// `_original/lib/util/http-mgr.js:377-401`); a redirect blanks it at once, and
// a file that has *vanished* blanks it at once too (`readFile`, `:280-294`).
// This port keeps the text until a fetch replaces it and logs every failure —
// see `src/rules/include.rs`. Reaching that difference needs a source to load
// and then break *within one case*, which this harness has no way to express:
// it sets one rules text and makes one request. The unit test
// `an_include_that_fails_to_fetch_keeps_the_last_good_text` covers it instead.
//
// ── Two properties this file cannot pin, and where they are pinned ─────────
//
// `setRules` posts to `Default` on one side and `/api/rules` on the other, so
// nothing here can say anything about a **named group** — that its includes are
// registered, that switching it off stops them being fetched, and that
// switching it back on starts them again. `src/rules/include.rs` has all three.
//
// Nor can it say anything about the **poll timer**: upstream re-reads a local
// source every 5 s and a remote one on a 10–30 s round robin
// (`getInterval`, `http-mgr.js:38-45`), and a bench that waits 30 s per case to
// watch a file change would take a quarter of an hour to say so. Measured by
// hand instead — a file edited under a running proxy took effect 5 s later, in
// both proxies — and pinned by `the_poll_interval_spends_upstreams_budget`.

const fs = require('fs');
const http = require('http');
const path = require('path');

const BASE = Number(process.env.PORT_BASE || 18700);
const PORT = BASE + 2; // the harness's echo origin
const RULES_PORT = BASE + 10; // this file's rules server
const P = `127.0.0.1:${PORT}`;
/** `A` pins the pattern to the request's whole path — the trap `cases-file.js` documents. */
const A = `${P}/echo`;

/** A fence, spelled once so the cases below stay readable. */
const B = '```';

// ── the sources ────────────────────────────────────────────────────────────
// One file per case that needs its own content. Distinct names on purpose:
// both proxies cache an include by its source string and upstream's file
// loader skips a re-read when the mtime has not moved, so two cases sharing a
// path and disagreeing about its content would be a race, not a test.

const DIR = '/tmp/wrs-includes-fixtures';
const F = (name) => path.join(DIR, name);

/** Rules texts served from disk. */
const FILES = {
  'inc.rules': `${A} reqHeaders://x-included=from-a-file\n`,
  'inc-body.rules': `${A} resBody://(FROM-AN-INCLUDED-FILE)\n`,
  'inc-first.rules': `${A} resBody://(FROM-THE-INCLUDE)\n`,
  'inc-important.rules': `${A} resBody://(FROM-THE-INCLUDE) lineProps://important\n`,
  'inc-order.rules': `${A} resBody://(SECOND)\n`,
  'inc-value.rules': `${B}v\nFROM-AN-INCLUDED-VALUE\n${B}\n${A} resBody://{v}\n`,
  'inc-value-only.rules': `${B}w\nDECLARED-BY-THE-INCLUDE\n${B}\n`,
  'inc-shadow.rules': `${B}v\nFROM-THE-INCLUDE\n${B}\n`,
  'inc-nested.rules': `${A} reqHeaders://x-outer=yes\n@${F('inc-inner.rules')}\n`,
  'inc-inner.rules': `${A} reqHeaders://x-inner=yes\n`,
  'inc-two-a.rules': `${A} reqHeaders://x-a=yes\n`,
  'inc-two-b.rules': `${A} reqHeaders://x-b=yes\n`,
  'inc-comment.rules': `${A} reqHeaders://x-commented=yes\n`,
  'inc-backtick.rules': `${A} reqHeaders://x-backticked=yes\n`,
  'inc-trailing.rules': `${A} reqHeaders://x-trailing=yes\n`,
  'inc-spaced.rules': `${A} reqHeaders://x-spaced=yes\n`,
  'inc-pattern.rules': `${A} reqHeaders://x-patterned=yes\n`,
  'inc-relative.rules': `${A} reqHeaders://x-relative=yes\n`,
  'inc-empty.rules': '',
};
fs.mkdirSync(DIR, { recursive: true });
for (const [name, text] of Object.entries(FILES)) fs.writeFileSync(F(name), text);

/** Rules texts served over HTTP, and the status each is served with. */
const URLS = {
  '/inc.rules': [200, `${A} reqHeaders://x-included=from-a-url\n`],
  '/inc-body.rules': [200, `${A} resBody://(FROM-AN-INCLUDED-URL)\n`],
  '/inc-value.rules': [200, `${B}u\nFROM-A-URL-VALUE\n${B}\n${A} resBody://{u}\n`],
  // Not a rules text at all: 404 with a body, and 204 with nothing. Upstream
  // reads 200 and 204 as answers and everything else as a failure
  // (`http-mgr.js:379-381`), so these are two different questions.
  '/missing.rules': [404, 'no such rules'],
  '/empty.rules': [204, ''],
};
const U = (p) => `http://127.0.0.1:${RULES_PORT}${p}`;

const rulesServer = http.createServer((q, r) => {
  const entry = URLS[q.url.split('?')[0]];
  if (!entry) {
    r.writeHead(404, { 'content-type': 'text/plain' });
    return r.end('unknown fixture');
  }
  const [status, text] = entry;
  r.writeHead(status, status === 204 ? {} : { 'content-type': 'text/plain' });
  r.end(status === 204 ? undefined : text);
});
rulesServer.listen(RULES_PORT);
// Scenery, like `forward-servers.js`'s: unref'd so it cannot hold the bench's
// event loop open after the last case. Without this the run prints its report
// and then never exits, which reads exactly like a case that hung.
rulesServer.unref();
rulesServer.on('connection', (s) => s.unref());

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Nothing below means anything until a rules text set through each proxy's
  // own API is known to reach a request at all.
  { name: 'baseline: no rule at all', rules: '' },
  { name: 'baseline: a rule set at runtime reaches the request', rules: `${A} reqHeaders://x-a=1` },

  // ── the gap: an include in a rules text set at runtime ──────────────────
  { name: 'an @ include of a rules file', rules: `@${F('inc.rules')}` },
  { name: 'an @ include of a URL', rules: `@${U('/inc.rules')}` },
  { name: 'an @ include of a rules file, rewriting the response', rules: `@${F('inc-body.rules')}` },
  { name: 'an @ include of a URL, rewriting the response', rules: `@${U('/inc-body.rules')}` },
  {
    name: 'an @ include beside a hand-written rule',
    rules: `${A} reqHeaders://x-hand=yes\n@${F('inc.rules')}`,
  },
  {
    name: 'two @ includes in one text',
    rules: `@${F('inc-two-a.rules')}\n@${F('inc-two-b.rules')}`,
  },
  {
    name: 'a file include and a URL include in one text',
    rules: `@${F('inc-two-a.rules')}\n@${U('/inc.rules')}`,
  },

  // ── where the included lines land ───────────────────────────────────────
  // Spliced where the line stands, so the ordering that decides which rule
  // wins is the ordering of the text it went into. `resBody://` is
  // single-valued, so the first line to match is the one that answers.
  {
    name: 'a hand-written line above the include wins',
    rules: `${A} resBody://(FROM-THE-TEXT)\n@${F('inc-first.rules')}`,
  },
  {
    name: 'the include wins over a hand-written line below it',
    rules: `@${F('inc-first.rules')}\n${A} resBody://(FROM-THE-TEXT)`,
  },
  {
    name: 'the include splices in place, not at the end',
    rules: `${A} resBody://(FIRST)\n@${F('inc-order.rules')}\n${A} resBody://(THIRD)`,
  },
  {
    name: 'an important line inside an include outranks a line above it',
    rules: `${A} resBody://(FROM-THE-TEXT)\n@${F('inc-important.rules')}`,
  },

  // ── values an included text declares ────────────────────────────────────
  { name: 'an @ include declaring its own value', rules: `@${F('inc-value.rules')}` },
  { name: 'an @ include of a URL declaring its own value', rules: `@${U('/inc-value.rules')}` },
  {
    name: 'a value declared by an include reaches the including text',
    rules: `@${F('inc-value-only.rules')}\n${A} resBody://{w}`,
  },
  {
    name: 'the including text keeps its own value when the include declares the same name',
    rules: `${B}v\nFROM-THE-TEXT\n${B}\n@${F('inc-shadow.rules')}\n${A} resBody://{v}`,
  },
  {
    name: 'the including text keeps its own value even when the include comes first',
    rules: `@${F('inc-shadow.rules')}\n${B}v\nFROM-THE-TEXT\n${B}\n${A} resBody://{v}`,
  },
  {
    name: 'an @ line inside a fenced value is not an include',
    rules: `${B}v\n@${F('inc-body.rules')}\n${B}\n${A} resBody://{v}`,
  },

  // ── how far it goes ────────────────────────────────────────────────────
  // One level: what an include brings in is text, and an `@` line in it is not
  // followed. `String.replace` never rescans what it substituted, which is why
  // upstream cannot cycle either.
  { name: 'an @ line inside an included text is not followed', rules: `@${F('inc-nested.rules')}` },

  // ── the shapes ─────────────────────────────────────────────────────────
  { name: 'a backticked source', rules: '@`' + F('inc-backtick.rules') + '`' },
  { name: 'a source with a trailing comment', rules: `@${F('inc-comment.rules')} # the team's` },
  { name: 'a source with a comment and no space', rules: `@${F('inc-comment.rules')}#the-team's` },
  { name: 'an indented @ line is still an include', rules: `   @${F('inc.rules')}` },
  { name: 'an @ include after a comment line', rules: `# rules\n@${F('inc.rules')}` },

  // ── the shapes that are not includes ────────────────────────────────────
  // Each of these is a line someone will write. What matters is that neither
  // proxy fetches anything for it — and, for the first two, that whatever the
  // line already meant it goes on meaning.
  { name: 'a relative path is not an include', rules: '@inc-relative.rules' },
  { name: 'a dot-relative path is not an include', rules: '@./inc-relative.rules' },
  {
    name: 'an @ line with a pattern in front is not an include',
    rules: `${A} @${F('inc-pattern.rules')}`,
  },
  { name: 'a space after the @ is not an include', rules: `@ ${F('inc-spaced.rules')}` },
  {
    name: 'trailing text after the source is not an include',
    rules: `@${F('inc-trailing.rules')} extra`,
  },
  { name: 'a plugin source serves no rules here', rules: '@whistle.no-such-plugin' },

  // ── nothing to include ─────────────────────────────────────────────────
  { name: 'an @ include of a file that is not there', rules: `@${F('nope.rules')}` },
  { name: 'an @ include of an empty file', rules: `@${F('inc-empty.rules')}` },
  { name: 'an @ include of a URL that answers 404', rules: `@${U('/missing.rules')}` },
  { name: 'an @ include of a URL that answers 204', rules: `@${U('/empty.rules')}` },
];
