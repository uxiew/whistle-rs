// The pattern corpus: which rules apply to a request at all, and which of
// several applying rules wins. Everything else rides on this gate, so a silent
// bug here is the most expensive kind.
//
// Two probes and one trick:
//
//   * `HIT` — a request header the origin echoes back. A rule that applied
//     added it, so `x-hit` present means "this pattern matched".
//   * `statusCode://` — a single-value operator, for the cases about *which* of
//     several matching lines won. 204 is always the line that should win and
//     205 the line that should not, so a case's answer names the winner.
//   * `MAP` — `* host://127.0.0.1:<origin>` points every hostname at the echo
//     origin, so a case can ask about `a.example.test` and about the **default
//     port**, which the origin's own `127.0.0.1:<port>` address cannot reach.
//     Every case carries it; it is a different protocol from either probe and
//     never competes with them.
//
// The pairing matters as much as in the filter corpus: "the rule did not apply"
// and "the rule does not exist" look identical from one case, so nearly every
// pattern form is asked twice — once where it should match and once where it
// should not.
//
// ── three declared deviations ──────────────────────────────────────────────
// These cases carry `reqHeaders://x-pattern-dev=1` instead of the usual probe,
// and `harness.js` lets that one header's differences through. Each is a place
// where upstream's answer is an accident of how it compares text, and this port
// answers the question the user was asking (`docs/RULES.md`, deliberate
// deviations):
//
//   1. **Host case.** whistle compares the pattern against the request URL as
//      text, so `EXAMPLE.com` and `example.com` are different hosts. Hostnames
//      are not case-sensitive, and this port folds them. Only the plain
//      host-prefix form folds — a regexp or a wildcard pattern is matched
//      against the URL as written, exactly as upstream matches it.
//   2. **`example.com:80` on an http request.** `getFullUrl` strips the default
//      port (`_original/lib/util/common.js:1266`), so the URL never contains
//      `:80` and a pattern that spells it can never match anything. Here it
//      means the port it says.
//   3. **An IPv6 literal with no port.** A host-only pattern is also compared
//      against the port-stripped URL, and upstream's `removePort`
//      (`_original/lib/rules/rules.js:885-908`) cuts at the first `:` after the
//      scheme — which is inside `[::1]`, leaving `http://[`. Here `[::1]`
//      matches `[::1]:8080`.
const ORIGIN = Number(process.env.PORT_BASE || 18700) + 2;

/** Points every hostname at the echo origin. */
const MAP = `* host://127.0.0.1:${ORIGIN}`;
/** Visible in the origin's echo: a rule that applied added this header. */
const HIT = 'reqHeaders://x-hit=1';
/** The probe for the three declared deviations — see the header above. */
const DEV = 'reqHeaders://x-pattern-dev=1';

/** The URL nearly every case is asked about. */
const A = 'http://a.example.test/echo';

/** One pattern under test, against `url`. */
const p = (name, pattern, url = A, probe = HIT) =>
  ({ name: `${name}: ${pattern}`, rules: `${MAP}\n${pattern} ${probe}`, request: { url } });
/** A whole rules text, with the mapper prepended. */
const raw = (name, rules, url = A) =>
  ({ name, rules: `${MAP}\n${rules}`, request: { url } });

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Before any pattern is trusted, the mapper and the probe have to agree.
  { name: 'baseline: the mapper alone', rules: MAP, request: { url: A } },
  p('baseline: a bare host that matches', 'a.example.test'),
  p('baseline: a bare host that misses', 'b.example.test'),
  { name: 'baseline: no mapper, the origin by address', rules: `127.0.0.1:${ORIGIN} ${HIT}` },

  // ── domain forms ───────────────────────────────────────────────────────
  p('a host with another port', 'a.example.test:8080'),
  p('a host with no port against a ported origin', '127.0.0.1', `http://127.0.0.1:${ORIGIN}/echo`),
  p('host:port against that port', `127.0.0.1:${ORIGIN}`, `http://127.0.0.1:${ORIGIN}/echo`),
  p('host:port against another port', '127.0.0.1:1', `http://127.0.0.1:${ORIGIN}/echo`),
  p('*.host', '*.example.test'),
  p('*.host does not cross a dot', '*.example.test', 'http://x.y.example.test/echo'),
  p('**.host does', '**.example.test', 'http://x.y.example.test/echo'),
  p('***.host also matches the bare domain', '***.example.test', 'http://example.test/echo'),
  p('*host with no dot after the star', '*example.test'),
  p('a star inside a label', 'a.exam*le.test'),
  p('a star alone', '*'),
  p('two stars alone', '**'),
  p('three stars alone', '***'),
  p('a tilde is a star too', '~.example.test'),
  p('a leading dot matches a subdomain', '.example.test'),
  p('a leading dot matches the domain itself', '.example.test', 'http://example.test/echo'),
  p('a leading dot on the full host', '.a.example.test'),
  p('www.*.tld', 'www.*.test', 'http://www.foo.test/echo'),
  p('a trailing dot in the pattern', 'a.example.test.'),
  p('a trailing dot in the request', 'a.example.test', 'http://a.example.test./echo'),
  p('localhost is not 127.0.0.1', 'localhost', `http://127.0.0.1:${ORIGIN}/echo`),
  p('127.0.0.1 is not localhost', '127.0.0.1', `http://localhost:${ORIGIN}/echo`),
  p('an IPv6 literal with its port', `[::1]:${ORIGIN}`, `http://[::1]:${ORIGIN}/echo`),
  p('a host ending in a colon', 'a.example.test:'),
  p('a host with a port that is not a number', 'a.example.test:x'),
  p('a wildcard host against a ported URL', '*.example.test', 'http://a.example.test:8080/echo'),
  p('a wildcard host with a star in the port', '**.example.test:8*', 'http://a.example.test:8080/echo'),

  // the domain fallback: only a host-and-nothing-else pattern ignores the port
  p('a bare host against a ported URL', 'a.example.test', 'http://a.example.test:8080/echo'),
  p('a host with a trailing slash against a ported URL', 'a.example.test/', 'http://a.example.test:8080/echo'),
  p('a host and path against a ported URL', 'a.example.test/echo', 'http://a.example.test:8080/echo'),
  p('a host and query against a ported URL', 'a.example.test?q=1', 'http://a.example.test:8080/?q=1'),
  p('a scheme and host against a ported URL', 'http://a.example.test', 'http://a.example.test:8080/echo'),

  // ── scheme and authority ───────────────────────────────────────────────
  p('http:// on a plain request', 'http://a.example.test'),
  p('https:// on a plain request', 'https://a.example.test'),
  p('ws:// on a plain request', 'ws://a.example.test'),
  p('wss:// on a plain request', 'wss://a.example.test'),
  p('tunnel:// on a plain request', 'tunnel://a.example.test'),
  p('an unknown scheme', 'ftp://a.example.test'),
  p('an upper-case scheme', 'HTTP://a.example.test'),
  p('//host takes any scheme', '//a.example.test'),
  p('a scheme with no host matches nothing', 'http://'),
  p('a scheme, no host, with a path', 'http:///echo'),
  p('three slashes', '///a.example.test'),
  p('a path with no host', '/echo'),
  p('a port and a path with no host', ':80/echo'),
  p('a star for the whole scheme', '*://a.example.test'),
  p('a star inside the scheme', 'htt*://a.example.test'),

  // ── path forms ─────────────────────────────────────────────────────────
  p('host/path', 'a.example.test/api', 'http://a.example.test/api/users?q=1'),
  p('host/path/', 'a.example.test/api/', 'http://a.example.test/api/users?q=1'),
  p('a prefix that stops mid-segment', 'a.example.test/ap', 'http://a.example.test/api/users'),
  p('the whole path', 'a.example.test/api/users', 'http://a.example.test/api/users'),
  p('the whole path plus a slash', 'a.example.test/api/users/', 'http://a.example.test/api/users'),
  p('a path of only /', 'a.example.test/', 'http://a.example.test/api'),
  p('an upper-case path in the pattern', 'a.example.test/ECHO'),
  p('an upper-case path in the request', 'a.example.test/echo', 'http://a.example.test/ECHO'),
  p('a percent escape on both sides', 'a.example.test/a%20b', 'http://a.example.test/a%20b'),
  p('a backslash ends a segment', 'a.example.test/api', 'http://a.example.test/api\\x'),
  p('a double slash in the path', 'a.example.test//echo', 'http://a.example.test//echo'),
  p('a star in the path is a literal', 'a.example.test/ec*'),
  p('a star in the path, matched literally', 'a.example.test/ec*', 'http://a.example.test/ec*'),
  p('a request with a fragment', 'a.example.test/echo', 'http://a.example.test/echo#frag'),

  // patterns carrying a query
  p('a query and no path', 'a.example.test?q=1', 'http://a.example.test/?q=1'),
  p('a query prefix of a longer one', 'a.example.test?q=1', 'http://a.example.test/?q=1&r=2'),
  p('a query that differs', 'a.example.test?q=2', 'http://a.example.test/?q=1'),
  p('a query against a request with none', 'a.example.test?q=1', 'http://a.example.test/'),
  p('a scheme, host and query', 'http://a.example.test?q=1', 'http://a.example.test/?q=1'),
  p('a bare question mark', 'a.example.test?', 'http://a.example.test/?q=1'),
  p('a path and a query', 'a.example.test/echo?q=1', 'http://a.example.test/echo?q=1'),
  p('a path and a query, request has none', 'a.example.test/echo?q=1'),
  p('a wildcard host and a query', '*.example.test?q=1', 'http://a.example.test/?q=1'),
  p('a leading-dot host and a query', '.example.test?q=1', 'http://a.example.test/?q=1'),

  // what the match leaves behind, seen through the destination
  raw('a host pattern hands the whole path over', `a.example.test http://127.0.0.1:${ORIGIN}`, 'http://a.example.test/echo?q=1'),
  raw('a path pattern hands the rest over', `a.example.test/ec http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),
  raw('a query pattern hands the rest over', `a.example.test/echo?q= http://127.0.0.1:${ORIGIN}/x?k=`, 'http://a.example.test/echo?q=1'),
  raw('a wildcard hands the rest over', `*.example.test/ec http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),
  raw('an exact pattern hands over the query', `$a.example.test/echo http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),
  raw('an exact pattern, destination has a query', `$a.example.test/echo http://127.0.0.1:${ORIGIN}/x?k=1`, 'http://a.example.test/echo?q=1'),
  raw('an exact pattern with a query of its own', `$a.example.test/echo?q=1 http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),
  raw('an exact pattern, no query to hand over', `$a.example.test/echo http://127.0.0.1:${ORIGIN}/x`),
  raw('an exact wildcard hands over the query', `$*.example.test/echo http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),
  raw('an exact wildcard with a query of its own', `$*.example.test/echo?q=1 http://127.0.0.1:${ORIGIN}/x`, 'http://a.example.test/echo?q=1'),

  // ── regexps ────────────────────────────────────────────────────────────
  p('a plain regexp', '/echo/'),
  p('a regexp that misses', '/nope/'),
  p('the i flag', '/ECHO/i'),
  p('no flag is case-sensitive', '/ECHO/'),
  p('the u flag', '/echo/u'),
  p('the iu flags', '/ECHO/iu'),
  p('the ui flags', '/ECHO/ui'),
  // The next five are inert on **both** sides, and not for the reason their
  // names suggest: a token of `/` followed by a non-`/` that is not a valid
  // regexp is a *file path*, and `formatShorthand` claims it before the line is
  // even split (`FILE_RE.test(url) && !util.isRegExp(url)`,
  // `_original/lib/rules/rules.js:1195`). The line then has no pattern at all.
  // So they pin the shorthand's flag test, not the pattern parser's.
  p('the g flag is not a flag', '/echo/g'),
  p('the m flag is not a flag', '/echo/m'),
  p('the s flag is not a flag', '/echo/s'),
  p('the gi flags are not flags', '/ECHO/gi'),
  p('flags that are a word', '/echo/xyz'),
  p('an invalid regexp', '/[/'),
  p('an unterminated regexp', '/echo'),
  p('a regexp with an empty body', '//i'),
  p('two slashes', '//'),
  // These two are the pair that *does* discriminate the pattern parser's flag
  // set, because a `//`-led token escapes the file shorthand and reaches it.
  // `////` has empty flags and is the regexp `//`, which fires; `///host` has
  // flags of `a.example.test`, which is not a flag set, so it is no regexp and
  // ends up a pattern with no host. Reading the flags loosely turned the second
  // into the regexp `/` — matching every URL there is — and it is the case that
  // caught it.
  p('four slashes', '////'),
  p('a regexp with two bodies', '/a/b/'),
  p('an anchored regexp', '/^http:\\/\\/a\\.example\\.test\\/echo$/'),
  p('a regexp anchored at the end only', '/echo$/'),
  p('a regexp against an upper-case host', '/A\\.EXAMPLE\\.TEST/', 'http://A.EXAMPLE.TEST/echo'),
  p('a wildcard against an upper-case host', '*.EXAMPLE.TEST', 'http://A.EXAMPLE.TEST/echo'),
  p('a negated regexp that would match', '!/echo/'),
  p('a negated regexp that misses', '!/nope/'),
  p('a negated plain pattern', '!a.example.test'),
  p('a negated wildcard', '!*.example.test'),
  p('a negated scheme-relative pattern', '!//a.example.test'),

  // capture references
  raw('two captures reach the value', '/\\/(ec)(ho)/ reqHeaders://x-hit=$1-$2'),
  raw('$0 is the request URL', '/echo/ reqHeaders://x-hit=$0'),
  raw('$0 keeps the host as written', '/echo/ reqHeaders://x-hit=$0', 'http://A.EXAMPLE.TEST/echo'),
  raw('$& is the request URL too', '/echo/ reqHeaders://x-hit=$&'),
  raw('$$1 percent-encodes the group', '/\\/(echo)/ reqHeaders://x-hit=$$1'),
  raw('a reference with no group', '/echo/ reqHeaders://x-hit=[$7]'),
  raw('$9 with four groups', '/(e)(c)(h)(o)/ reqHeaders://x-hit=[$9]'),
  raw('a named group is still $1', '/(?<n>echo)/ reqHeaders://x-hit=$1'),
  raw('a wildcard host captures', '*.example.test reqHeaders://x-hit=$1'),
  raw('a caret pattern captures host and path', '^http://*.example.test/ec* reqHeaders://x-hit=$1-$2'),
  raw('a plain pattern captures nothing', 'a.example.test reqHeaders://x-hit=[$1]'),

  // ── exact and anchored ─────────────────────────────────────────────────
  p('$ with a scheme and a path', '$http://a.example.test/echo'),
  p('$ with no scheme', '$a.example.test/echo'),
  p('$ on a bare host is the site root', '$a.example.test'),
  p('$ on a bare host, root requested', '$a.example.test', 'http://a.example.test/'),
  p('$ ignores the request query', '$a.example.test/echo', 'http://a.example.test/echo?q=1'),
  p('$ with a query of its own', '$a.example.test/echo?q=1', 'http://a.example.test/echo?q=1'),
  p('$ with a query and no path', '$a.example.test?q=1', 'http://a.example.test/?q=1'),
  p('$ does not match a sub-path', '$a.example.test/ec'),
  p('$ on a wildcard', '$*.example.test/echo'),
  p('$ on a wildcard, sub-path', '$*.example.test/ec'),
  p('$ on a wildcard with a query', '$*.example.test/echo?q=1', 'http://a.example.test/echo?q=1'),
  p('$ on a leading-dot host', '$.example.test/echo'),
  p('$ on a two-star host', '$**.example.test/echo'),
  p('$ negated on a pattern that matches', '!$a.example.test/echo'),
  p('$ negated on a pattern that misses', '!$b.example.test/echo'),
  p('a bare $ names nothing', '$'),

  p('a caret makes a path star a wildcard', '^http://a.example.test/ec*'),
  p('a caret anchored at the end', '^http://a.example.test/echo$'),
  p('a caret anchored at the end, query present', '^http://a.example.test/echo$', 'http://a.example.test/echo?q=1'),
  p('two carets are case-sensitive', '^^http://A.EXAMPLE.TEST/echo'),
  p('one caret is case-insensitive', '^http://A.EXAMPLE.TEST/echo'),
  p('a caret with no scheme', '^a.example.test/echo'),
  p('a caret with ** in the path', '^http://a.example.test/**', 'http://a.example.test/a/b'),
  p('a caret with * in the path stops at a slash', '^http://a.example.test/*', 'http://a.example.test/a/b'),
  p('a caret with *** crosses the query', '^http://a.example.test/***', 'http://a.example.test/a?b=c'),
  p('a caret with a query star', '^http://a.example.test/echo?q=*', 'http://a.example.test/echo?q=1&r=2'),
  p('a caret with a query star that misses', '^http://a.example.test/echo?q=*b', 'http://a.example.test/echo?q=1&r=2'),
  p('*/path is a host wildcard', '*/echo'),
  p('**/path is one too', '**/echo'),
  p('*/pa*th is read as a caret pattern', '*/ec*'),
  p('a bare suffix pattern', '.echo', 'http://a.example.test/app.echo'),
  p('a bare suffix that misses', '.echo'),
  p('a bare suffix with a query', '.echo', 'http://a.example.test/app.echo?q=1'),
  p('a bare suffix anchored', '.echo$', 'http://a.example.test/app.echo'),
  p('a port pattern for the origin port', `:${ORIGIN}`, `http://127.0.0.1:${ORIGIN}/echo`),
  p('a port pattern for another port', ':8080', `http://127.0.0.1:${ORIGIN}/echo`),
  p('a port pattern negated', `!:${ORIGIN}`, `http://127.0.0.1:${ORIGIN}/echo`),
  p('a port pattern for the default port', ':80'),

  // ── precedence ─────────────────────────────────────────────────────────
  raw('two matching lines, the first wins', 'a.example.test statusCode://204\na.example.test statusCode://205'),
  raw('the second line is important', 'a.example.test statusCode://205\na.example.test statusCode://204 lineProps://important'),
  raw('the first line is important', 'a.example.test statusCode://204 lineProps://important\na.example.test statusCode://205'),
  raw('two important lines keep source order', 'a.example.test statusCode://204 lineProps://important\na.example.test statusCode://205 lineProps://important'),
  raw('important on a line that does not match', 'b.example.test statusCode://205 lineProps://important\na.example.test statusCode://204'),
  raw('a more specific pattern below', 'a.example.test statusCode://204\na.example.test/echo statusCode://205'),
  raw('a more specific pattern above', 'a.example.test/echo statusCode://204\na.example.test statusCode://205'),
  raw('a wildcard above a plain pattern', '*.example.test statusCode://204\na.example.test statusCode://205'),
  raw('a plain pattern above a wildcard', 'a.example.test statusCode://204\n*.example.test statusCode://205'),
  raw('an exact line above a prefix line', '$a.example.test/echo statusCode://204\na.example.test statusCode://205'),
  raw('a prefix line above an exact line', 'a.example.test statusCode://204\n$a.example.test/echo statusCode://205'),
  raw('a regexp line above a plain line', '/echo/ statusCode://204\na.example.test statusCode://205'),
  raw('a negated pattern above a plain one', '!b.example.test statusCode://204\na.example.test statusCode://205'),
  raw('only the second line matches', 'b.example.test statusCode://205\na.example.test statusCode://204'),
  raw('the same operator twice on one line', 'a.example.test statusCode://204 statusCode://205'),
  raw('three lines, the middle one important', 'a.example.test statusCode://205\na.example.test statusCode://204 lineProps://important\na.example.test statusCode://206'),
  raw('two multi-match lines accumulate in order', 'a.example.test reqHeaders://x-hit=first\na.example.test reqHeaders://x-hit=second'),
  raw('an important multi-match line goes first', 'a.example.test reqHeaders://x-hit=plain\na.example.test reqHeaders://x-hit=strong lineProps://important'),

  // the shared slot: `file://`, `statusCode://`, `redirect://` and a bare
  // destination all compete for one winner, decided by which was written first
  raw('a destination then statusCode on one line', `a.example.test http://127.0.0.1:${ORIGIN}/x statusCode://204`),
  raw('statusCode then a destination on one line', `a.example.test statusCode://204 http://127.0.0.1:${ORIGIN}/x`),
  raw('redirect then statusCode on one line', 'a.example.test redirect://http://d.test/ statusCode://204'),
  raw('statusCode then redirect on one line', 'a.example.test statusCode://204 redirect://http://d.test/'),
  raw('a destination line above a statusCode line', `a.example.test http://127.0.0.1:${ORIGIN}/x\na.example.test statusCode://204`),
  raw('a statusCode line above a destination line', `a.example.test statusCode://204\na.example.test http://127.0.0.1:${ORIGIN}/x`),
  raw('a second bare host is an operator, not a pattern', 'a.example.test b.example.test statusCode://204'),
  raw('the same pattern written twice on one line', 'a.example.test a.example.test statusCode://204'),
  raw('a bare host after the operator', 'a.example.test statusCode://204 b.example.test'),

  // operator-first lines
  raw('operator first, one pattern', 'statusCode://204 a.example.test'),
  raw('operator first, a pattern that misses', 'statusCode://204 b.example.test'),
  raw('operator first, two patterns', 'statusCode://204 a.example.test b.example.test'),
  raw('two operators first, one pattern', 'statusCode://204 resHeaders://x-r=1 a.example.test'),
  raw('operator, pattern, operator', 'statusCode://204 a.example.test resHeaders://x-r=1'),
  raw('operator first with an IP pattern', `${HIT} 127.0.0.1`, `http://127.0.0.1:${ORIGIN}/echo`),
  raw('operator first, important on the second line', 'statusCode://205 a.example.test\nstatusCode://204 a.example.test lineProps://important'),
  raw('a line property between two patterns', 'statusCode://204 a.example.test lineProps://important b.example.test'),

  // ── shape ──────────────────────────────────────────────────────────────
  raw('blank lines around a rule', `\n\na.example.test ${HIT}\n\n`),
  raw('a line of only whitespace', `a.example.test ${HIT}\n   \n`),
  raw('a comment line', `# a comment\na.example.test ${HIT}`),
  raw('an inline comment', `a.example.test ${HIT} # trailing`),
  raw('a comment glued to the value', 'a.example.test reqHeaders://x-hit=1#trailing'),
  raw('a comment glued to the pattern', 'a.example#.test reqHeaders://x-hit=1'),
  raw('a whole line commented out', `#a.example.test ${HIT}`),
  { name: 'CRLF line endings', rules: `${MAP}\r\na.example.test ${HIT}\r\n`, request: { url: A } },
  { name: 'CR-only line endings', rules: `${MAP}\ra.example.test ${HIT}\r`, request: { url: A } },
  { name: 'a tab as the separator', rules: `${MAP}\na.example.test\t${HIT}`, request: { url: A } },
  { name: 'several spaces as the separator', rules: `${MAP}\na.example.test    ${HIT}`, request: { url: A } },
  { name: 'leading whitespace on the line', rules: `${MAP}\n   a.example.test ${HIT}`, request: { url: A } },
  { name: 'a line indented with a tab', rules: `${MAP}\n\ta.example.test ${HIT}`, request: { url: A } },
  { name: 'a trailing tab', rules: `${MAP}\na.example.test ${HIT}\t`, request: { url: A } },
  raw('a trailing backslash', `a.example.test ${HIT}\\`),
  raw('a line with only a pattern', 'a.example.test'),
  raw('a line with only an operator', HIT),
  raw('a line of two operators', `${HIT} resHeaders://x-r=1`),
  raw('a pattern with a trailing comma', `a.example.test, ${HIT}`),
  raw('a value containing a space is two tokens', 'a.example.test reqHeaders://x-hit=a b'),
  raw('a very long value', `a.example.test reqHeaders://x-hit=1&x-pad=${'p'.repeat(4000)}`),
  { name: 'a very long pattern', rules: `${MAP}\na.example.test/${'z'.repeat(3000)} ${HIT}`, request: { url: A } },
  raw('a line with three operators', `a.example.test ${HIT} resHeaders://x-r=1 statusCode://204`),

  // ── the three declared deviations ──────────────────────────────────────
  // See the header. These carry `x-pattern-dev` and are the only cases in this
  // corpus the harness expects to differ.
  p('an upper-case pattern against a lower-case host', 'A.EXAMPLE.TEST', A, DEV),
  p('a lower-case pattern against an upper-case host', 'a.example.test', 'http://A.EXAMPLE.TEST/echo', DEV),
  p('the default port spelled out in the pattern', 'a.example.test:80', A, DEV),
  p('the default port spelled out on both sides', 'a.example.test:80', 'http://a.example.test:80/echo', DEV),
  p('an IPv6 literal with no port', '[::1]', `http://[::1]:${ORIGIN}/echo`, DEV),
];
