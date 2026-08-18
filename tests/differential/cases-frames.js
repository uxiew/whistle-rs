// A body cut into **frames**: the event stream, and the separator a header names.
//
// whistle's Frames panel is not only for WebSockets. An ordinary body is cut
// into frames when the response is an event stream, and when
// `x-whistle-custom-frame-separator` names a separator — for any content type,
// on the request as well as the response (`parseFrameSep` / `handleResBody`,
// `_original/lib/inspectors/data.js:67-96,:323-345`).
//
// **What this corpus can see, and what it cannot.** This one is about the
// **wire**; `frames-bench.js` is about the frames, which turned out to be
// comparable after all — the two consoles have different data models but both
// answer "how many frames, carrying what" over HTTP, and the note that used to
// be here saying otherwise is how a real divergence went unmeasured for a while.
//
// What is on the wire is still where a particular kind of risk lives:
//
//   * **the separator header must not reach the other end.** Upstream deletes
//     it inside `parseFrameSep`, which is called from a branch — so *when* it
//     deletes is a fact about the flags, not about the header;
//   * **the body must arrive byte for byte.** Cutting a stream into frames means
//     putting a splitter in the streaming path, and a splitter that swallows a
//     boundary, or holds the tail waiting for one more separator, would be
//     invisible to every other corpus here. Most of these cases exist to say
//     that nothing changed, which is the whole claim.
//
// So most of this corpus is `inert` by the bench's own measure, and that is
// correct rather than a gap: a case pinning "the framing did not disturb the
// bytes" *should* answer the same with the rules taken away. The discriminating
// ones are the header cases — a header the origin sent and the client must not
// see is a difference the unruled baseline shows too.
//
// **A clean run of this file is `differing: 6`, and all six are one fact:
// upstream leaks its own control header whenever it does not get as far as
// deleting it.** `parseFrameSep` deletes from inside itself, so every branch
// that skips the call also skips the delete:
//
//   * `handleResBody` wraps the whole block in
//     `if (!disable.captureStream && !getZipType(info))` (`data.js:329`), so a
//     **gzipped** response and one under **`disable://captureStream`** both
//     forward the header to the client — two cases;
//   * `emitDataEvents` returns at `if (!util.showPluginReq(req) || util.isHide(req))`
//     (`:58-60`) before either side is read, so **`enable://hide`** leaks it in
//     both directions — two more;
//   * `isString` is `str && typeof str === 'string'` (`util/common.js:1006`), so
//     an **empty** value is not a string, `parseFrameSep` returns early, and the
//     header survives on both sides — the last two.
//
// This port removes the header first and decides afterwards, in both
// directions. A header whose only reader is the proxy has no business reaching
// the origin or the client, and this repository has already fixed the same
// class of leak once by hand — the rules-carrying headers that were reaching
// origins. Following upstream here would mean reintroducing it under a
// different name.
//
// Note the one that does *not* differ: a **request** separator under
// `disable://captureStream`. The request side reads the header before that flag
// is consulted at all, so both proxies strip it, and the case is here to hold
// the asymmetry down rather than to report it.
//
// Run it like any other corpus:
//   PORT_BASE=19300 CASES=./cases-frames.js npm run bench

const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;
const SEP = 'x-whistle-custom-frame-separator';

/** A request that names a separator for its own body. */
const withSep = (sep, body = 'one\ntwo\nthree') => ({
  method: 'POST',
  headers: { 'content-type': 'text/plain', [SEP]: sep },
  body,
});

module.exports = [
  // ── the response is an event stream ────────────────────────────────────
  //
  // Nothing about framing reaches the client, so every one of these says the
  // stream came through untouched. The splitter runs on a copy or it is a bug.
  { name: 'an event stream arrives unchanged', rules: '', request: { path: '/sse' } },
  { name: 'an event stream with a rule on the line',
    rules: `${P} resHeaders://x-hit=1`, request: { path: '/sse' } },
  { name: 'an event stream with a charset parameter',
    rules: '', request: { path: '/sse-charset' } },
  { name: 'a gzipped event stream arrives unchanged',
    rules: '', request: { path: '/sse-gz' } },
  { name: 'disable://captureStream on an event stream',
    rules: `${P} disable://captureStream`, request: { path: '/sse' } },
  { name: 'enable://captureStream on an event stream',
    rules: `${P} enable://captureStream`, request: { path: '/sse' } },
  { name: 'enable://hide on an event stream',
    rules: `${P} enable://hide`, request: { path: '/sse' } },
  // The one operator that reaches a stream still arriving. If the splitter and
  // the substitution fight over the same window, this is where it shows.
  { name: 'resReplace:// on an event stream',
    rules: `${P} resReplace://one=ONE`, request: { path: '/sse' } },
  { name: 'resReplace:// on an event stream, across a frame boundary',
    rules: `${P} resReplace://data=DATA`, request: { path: '/sse' } },

  // ── the response names a separator ─────────────────────────────────────
  //
  // Here the header itself is the observable: the origin sent one and the
  // client must not see it.
  { name: 'a response separator does not reach the client',
    rules: '', request: { path: '/sep' } },
  { name: 'a response separator that keeps itself (leading /)',
    rules: '', request: { path: '/sep-slash' } },
  { name: 'a response separator written percent-encoded',
    rules: '', request: { path: '/sep-encoded' } },
  { name: 'an empty response separator',
    rules: '', request: { path: '/sep-empty' } },
  // Upstream never calls `parseFrameSep` for a compressed body or under
  // `disable://captureStream` — the whole block is behind
  // `if (!disable.captureStream && !getZipType(info))` (`data.js:329`). So the
  // header it would have deleted goes out to the client. Measured, not assumed.
  { name: 'a response separator on a gzipped body',
    rules: '', request: { path: '/sep-gz' } },
  { name: 'a response separator under disable://captureStream',
    rules: `${P} disable://captureStream`, request: { path: '/sep' } },
  { name: 'a response separator under enable://hide',
    rules: `${P} enable://hide`, request: { path: '/sep' } },
  { name: 'a response separator beside a resHeaders rule',
    rules: `${P} resHeaders://x-hit=1`, request: { path: '/sep' } },

  // ── the request names a separator ──────────────────────────────────────
  //
  // The origin echoes the headers it was given, so this half is visible
  // directly: a separator the client sent must not arrive there.
  { name: 'a request separator does not reach the origin',
    rules: '', request: withSep('\\n') },
  { name: 'a request separator, percent-encoded', rules: '', request: withSep('%0A') },
  { name: 'a request separator that keeps itself', rules: '', request: withSep('/%0A') },
  { name: 'an empty request separator', rules: '', request: withSep('') },
  { name: 'a request separator on a GET with no body',
    rules: '', request: { headers: { [SEP]: '%0A' } } },
  { name: 'a request separator under disable://captureStream',
    rules: `${P} disable://captureStream`, request: withSep('%0A') },
  { name: 'a request separator under enable://hide',
    rules: `${P} enable://hide`, request: withSep('%0A') },
  { name: 'a request separator beside a body rewrite',
    rules: `${P} reqBody://(rewritten)`, request: withSep('%0A') },
  { name: 'a request separator beside a reqReplace',
    rules: `${P} reqReplace://one=ONE`, request: withSep('%0A') },
  { name: 'a request separator on a compressed body',
    rules: '',
    request: {
      method: 'POST',
      headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip', [SEP]: '%0A' },
      body: 'not really gzip',
    } },
  // A separator naming a string that is not in the body at all: the splitter
  // holds everything and must still hand it all over at the end.
  { name: 'a request separator that never matches', rules: '', request: withSep('ZZZ') },
  // Both directions at once.
  { name: 'a separator on the request and one on the response',
    rules: '', request: { ...withSep('%0A'), path: '/sep' } },
];
