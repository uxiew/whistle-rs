// The filter-condition corpus: `includeFilter://`, `excludeFilter://`,
// `filter://` and `ignore://`, one entry per condition spelling and per shape
// rule, each with a case that should hold and one that should not.
//
// A filter is only visible through the rule it gates, so every case carries one
// of two probes and nothing else:
//
//   * `REQ` — a request header the origin echoes back, for conditions that are
//     answerable before the request goes out;
//   * `RES` — a response header the client sees, for `s:`, `resH.`, `serverIp:`
//     and `serverPort:`, which are not answerable until the response head is in.
//
// The pair matters. "The rule did not apply" and "the rule does not exist" look
// identical from one case, so each condition is asked twice — once where it
// should hold and once where it should not — and a divergence in only one of
// the two is a divergence in the *filter*, not in the probe.
//
// `env:` is asked about `WHISTLE_DIFF_ENV`, which both proxies must be started
// with for those cases to mean anything:
//
//   WHISTLE_DIFF_ENV=Alpha PORT_BASE=19100 node oracle.js &
//   WHISTLE_DIFF_ENV=Alpha cargo run -- --port 19101 --no-persist --dir /tmp/rs-filters
const P = `127.0.0.1:${Number(process.env.PORT_BASE || 18700) + 2}`;

/** Visible in the origin's echo: a rule that applied added this header. */
const REQ = 'reqHeaders://x-hit=1';
/** Visible in the client's response: for conditions the response settles. */
const RES = 'resHeaders://x-hit=1';

/** A request carrying `x-tag: yes`, for the header conditions. */
const TAGGED = { headers: { 'x-tag': 'yes' } };
/** A POST with a body, for `b:` and for `m:POST`. */
const BODY = { method: 'POST', body: 'hello world', headers: { 'content-type': 'text/plain' } };

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Before any filter is trusted, both probes have to agree unfiltered.
  { name: 'baseline: no rule at all', rules: '' },
  { name: 'baseline: the request probe, unfiltered', rules: `${P} ${REQ}` },
  { name: 'baseline: the response probe, unfiltered', rules: `${P} ${RES}` },
  { name: 'baseline: the request probe on a POST', rules: `${P} ${REQ}`, request: BODY },
  { name: 'baseline: the request probe with x-tag', rules: `${P} ${REQ}`, request: TAGGED },

  // ── m: / method: ───────────────────────────────────────────────────────
  { name: 'm: matches the method', rules: `${P} ${REQ} includeFilter://m:GET` },
  { name: 'm: misses another method', rules: `${P} ${REQ} includeFilter://m:POST` },
  { name: 'm: on a POST', rules: `${P} ${REQ} includeFilter://m:POST`, request: BODY },
  { name: 'm: value is upper-cased', rules: `${P} ${REQ} includeFilter://m:get` },
  { name: 'method: is the long spelling', rules: `${P} ${REQ} includeFilter://method:GET` },
  { name: 'method: misses', rules: `${P} ${REQ} includeFilter://method:POST` },
  { name: 'm: regexp', rules: `${P} ${REQ} includeFilter://m:/^G/` },
  { name: 'm: regexp is always case-insensitive', rules: `${P} ${REQ} includeFilter://m:/^g/` },
  { name: 'm: regexp that misses', rules: `${P} ${REQ} includeFilter://m:/^P/` },
  { name: 'm: negated on the matching method', rules: `${P} ${REQ} includeFilter://m:!GET` },
  { name: 'm: negated on another method', rules: `${P} ${REQ} includeFilter://m:!POST` },
  { name: 'M: is not a condition name', rules: `${P} ${REQ} includeFilter://M:GET` },
  { name: 'm: with no value is not a condition', rules: `${P} ${REQ} includeFilter://m:` },

  // ── s: / statusCode: ───────────────────────────────────────────────────
  { name: 's: matches the status', rules: `${P} ${RES} includeFilter://s:200` },
  { name: 's: misses another status', rules: `${P} ${RES} includeFilter://s:404` },
  { name: 's: regexp', rules: `${P} ${RES} includeFilter://s:/^2/` },
  { name: 's: regexp that misses', rules: `${P} ${RES} includeFilter://s:/^4/` },
  { name: 's: negated', rules: `${P} ${RES} includeFilter://s:!200` },
  { name: 'statusCode: is the long spelling', rules: `${P} ${RES} includeFilter://statusCode:200` },
  { name: 'statusCode. pure form', rules: `${P} ${RES} includeFilter://statusCode.200` },
  { name: 'statusCode= pure form', rules: `${P} ${RES} includeFilter://statusCode=200` },
  { name: 'status: is not a condition name', rules: `${P} ${RES} includeFilter://status:200` },
  { name: 's: against the request probe never settles', rules: `${P} ${REQ} includeFilter://s:200` },
  { name: 'excludeFilter on a status that holds', rules: `${P} ${RES} excludeFilter://s:200` },
  { name: 'excludeFilter on a status that misses', rules: `${P} ${RES} excludeFilter://s:404` },

  // ── i: / ip: / clientIp: / serverIp: ───────────────────────────────────
  { name: 'i: regexp on the client address', rules: `${P} ${REQ} includeFilter://i:/127\\.0\\.0\\.1/` },
  { name: 'i: another address', rules: `${P} ${REQ} includeFilter://i:10.0.0.5` },
  { name: 'ip: is the long spelling', rules: `${P} ${REQ} includeFilter://ip:/127\\.0\\.0\\.1/` },
  { name: 'i: literal 127.0.0.1', rules: `${P} ${REQ} includeFilter://i:127.0.0.1` },
  // Upstream drops an ip condition whose value is neither an IP nor a regexp
  // (`net.isIP` in `resolveMatchFilter`), so the rule keeps no filter at all.
  { name: 'i: a value that is not an IP drops the filter', rules: `${P} ${REQ} includeFilter://i:localhost` },
  { name: 'clientIp: a value that is not an IP drops the filter', rules: `${P} ${REQ} includeFilter://clientIp:nothing` },
  { name: 'clientIp:', rules: `${P} ${REQ} includeFilter://clientIp:/127\\./` },
  { name: 'clientIP: capitalised', rules: `${P} ${REQ} includeFilter://clientIP:/127\\./` },
  { name: 'clientIp. pure form', rules: `${P} ${REQ} includeFilter://clientIp./127\\./` },
  { name: 'clientIp= pure form', rules: `${P} ${REQ} includeFilter://clientIp=/127\\./` },
  { name: 'clientIp: another address', rules: `${P} ${REQ} includeFilter://clientIp:10.0.0.5` },
  { name: 'serverIp: the origin address', rules: `${P} ${RES} includeFilter://serverIp:/127\\.0\\.0\\.1/` },
  { name: 'serverIp: another address', rules: `${P} ${RES} includeFilter://serverIp:10.0.0.5` },
  { name: 'serverIP. pure form', rules: `${P} ${RES} includeFilter://serverIP./127\\./` },
  { name: 'remoteAddress:', rules: `${P} ${REQ} includeFilter://remoteAddress:/127\\./` },
  { name: 'remoteAddress: that misses', rules: `${P} ${REQ} includeFilter://remoteAddress:10.0.0.5` },

  // ── clientPort: / serverPort: / remotePort: ────────────────────────────
  { name: 'clientPort: any port', rules: `${P} ${REQ} includeFilter://clientPort:/^\\d+$/` },
  { name: 'clientPort: an impossible port', rules: `${P} ${REQ} includeFilter://clientPort:1` },
  { name: 'clientPort= pure form', rules: `${P} ${REQ} includeFilter://clientPort=/^\\d+$/` },
  { name: 'remotePort: any port', rules: `${P} ${REQ} includeFilter://remotePort:/^\\d+$/` },
  { name: 'remotePort: an impossible port', rules: `${P} ${REQ} includeFilter://remotePort:1` },
  { name: 'serverPort: the origin port', rules: `${P} ${RES} includeFilter://serverPort:${Number(process.env.PORT_BASE || 18700) + 2}` },
  { name: 'serverPort: another port', rules: `${P} ${RES} includeFilter://serverPort:1` },
  { name: 'serverPort: regexp', rules: `${P} ${RES} includeFilter://serverPort:/^\\d+$/` },

  // ── h: / header: (request, falling back to the response) ───────────────
  { name: 'h: on a request header', rules: `${P} ${REQ} includeFilter://h:x-tag=yes`, request: TAGGED },
  { name: 'h: on a request header that misses', rules: `${P} ${REQ} includeFilter://h:x-tag=no`, request: TAGGED },
  { name: 'h: colon separates too', rules: `${P} ${REQ} includeFilter://h:x-tag:yes`, request: TAGGED },
  { name: 'header: is the long spelling', rules: `${P} ${REQ} includeFilter://header:x-tag=yes`, request: TAGGED },
  { name: 'h: on an absent header', rules: `${P} ${REQ} includeFilter://h:x-nope=yes`, request: TAGGED },
  { name: 'h: reads the response head as a fallback', rules: `${P} ${RES} includeFilter://h:x-origin=yes` },
  { name: 'h: fallback that misses', rules: `${P} ${RES} includeFilter://h:x-origin=no` },

  // ── reqH. and its spellings ────────────────────────────────────────────
  { name: 'reqH. on a request header', rules: `${P} ${REQ} includeFilter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'reqH. that misses', rules: `${P} ${REQ} includeFilter://reqH.x-tag:no`, request: TAGGED },
  { name: 'req. short spelling', rules: `${P} ${REQ} includeFilter://req.x-tag:yes`, request: TAGGED },
  { name: 'reqHeader. spelling', rules: `${P} ${REQ} includeFilter://reqHeader.x-tag:yes`, request: TAGGED },
  { name: 'reqHeaders. spelling', rules: `${P} ${REQ} includeFilter://reqHeaders.x-tag:yes`, request: TAGGED },
  { name: 'reqH= separator', rules: `${P} ${REQ} includeFilter://reqH=x-tag=yes`, request: TAGGED },
  { name: 'reqH: props separator', rules: `${P} ${REQ} includeFilter://reqH:x-tag:yes`, request: TAGGED },
  { name: 'req: props separator', rules: `${P} ${REQ} includeFilter://req:x-tag=yes`, request: TAGGED },
  { name: 'reqH. presence only', rules: `${P} ${REQ} includeFilter://reqH.x-tag`, request: TAGGED },
  { name: 'reqH. presence of an absent header', rules: `${P} ${REQ} includeFilter://reqH.x-nope`, request: TAGGED },
  { name: 'reqH. substring of the value', rules: `${P} ${REQ} includeFilter://reqH.x-tag:e`, request: TAGGED },
  { name: 'reqH. regexp value', rules: `${P} ${REQ} includeFilter://reqH.x-tag:/^yes$/`, request: TAGGED },
  { name: 'reqH. regexp with the i flag', rules: `${P} ${REQ} includeFilter://reqH.x-tag:/^YES$/i`, request: TAGGED },
  { name: 'reqH. regexp that misses', rules: `${P} ${REQ} includeFilter://reqH.x-tag:/^no$/`, request: TAGGED },
  { name: 'reqH. header name is case-insensitive', rules: `${P} ${REQ} includeFilter://reqH.X-Tag:yes`, request: TAGGED },
  { name: 'reqH. value negated', rules: `${P} ${REQ} includeFilter://reqH.x-tag:!yes`, request: TAGGED },
  { name: 'reqH. value negated against another value', rules: `${P} ${REQ} includeFilter://reqH.x-tag:!no`, request: TAGGED },
  { name: 'reqH. key negated', rules: `${P} ${REQ} includeFilter://reqH.x-tag!:yes`, request: TAGGED },
  { name: 'reqH. key negated on an absent header', rules: `${P} ${REQ} includeFilter://reqH.x-nope!:v`, request: TAGGED },
  { name: 'reqH. negated twice cancels', rules: `${P} ${REQ} includeFilter://reqH.x-tag!:!yes`, request: TAGGED },
  // The first colon splits, so the rest of a value keeps its own colons.
  { name: 'reqH. value containing a colon', rules: `${P} ${REQ} includeFilter://reqH.referer:http://ref.test/p`, request: { headers: { referer: 'http://ref.test/p' } } },
  // An empty key is not the same as a key of `!`: upstream drops only the
  // second, and answers the first with the header it never finds.
  { name: 'reqH. with an empty key', rules: `${P} ${REQ} includeFilter://reqH.=yes`, request: TAGGED },
  { name: 'reqH. with a key of only !', rules: `${P} ${REQ} includeFilter://reqH.!=yes`, request: TAGGED },
  { name: 'ReqH. is not a condition name', rules: `${P} ${REQ} includeFilter://ReqH.x-tag:yes`, request: TAGGED },

  // ── resH. and its spellings ────────────────────────────────────────────
  { name: 'resH. on a response header', rules: `${P} ${RES} includeFilter://resH.x-origin:yes` },
  { name: 'resH. that misses', rules: `${P} ${RES} includeFilter://resH.x-origin:no` },
  { name: 'res. short spelling', rules: `${P} ${RES} includeFilter://res.x-origin:yes` },
  { name: 'resHeader. spelling', rules: `${P} ${RES} includeFilter://resHeader.x-origin:yes` },
  { name: 'resHeaders. spelling', rules: `${P} ${RES} includeFilter://resHeaders.x-origin:yes` },
  { name: 'resH: props separator', rules: `${P} ${RES} includeFilter://resH:x-origin:yes` },
  { name: 'resH. on content-type', rules: `${P} ${RES} includeFilter://resH.content-type:json` },
  { name: 'resH. regexp', rules: `${P} ${RES} includeFilter://resH.content-type:/^application/` },
  { name: 'resH. on an absent header', rules: `${P} ${RES} includeFilter://resH.x-nope:v` },
  { name: 'resH. absent header negated', rules: `${P} ${RES} includeFilter://resH.x-nope!:v` },
  { name: 'resH. against the request probe never settles', rules: `${P} ${REQ} includeFilter://resH.x-origin:yes` },
  { name: 'excludeFilter on a response header that holds', rules: `${P} ${RES} excludeFilter://resH.x-origin:yes` },
  { name: 'excludeFilter on a response header that misses', rules: `${P} ${RES} excludeFilter://resH.x-origin:no` },

  // ── b: / body: ─────────────────────────────────────────────────────────
  { name: 'b: a substring of the body', rules: `${P} ${REQ} includeFilter://b:hello`, request: BODY },
  { name: 'b: a string the body lacks', rules: `${P} ${REQ} includeFilter://b:goodbye`, request: BODY },
  { name: 'body: is the long spelling', rules: `${P} ${REQ} includeFilter://body:hello`, request: BODY },
  { name: 'b: regexp', rules: `${P} ${REQ} includeFilter://b:/^hello/`, request: BODY },
  { name: 'b: regexp that misses', rules: `${P} ${REQ} includeFilter://b:/^world/`, request: BODY },
  { name: 'b: is case-insensitive', rules: `${P} ${REQ} includeFilter://b:HELLO`, request: BODY },
  { name: 'b: negated', rules: `${P} ${REQ} includeFilter://b:!hello`, request: BODY },
  { name: 'b: on a GET with no body', rules: `${P} ${REQ} includeFilter://b:hello` },
  { name: 'excludeFilter on a body that matches', rules: `${P} ${REQ} excludeFilter://b:hello`, request: BODY },
  { name: 'excludeFilter on a body that does not', rules: `${P} ${REQ} excludeFilter://b:goodbye`, request: BODY },
  // A `b:` regexp's groups are offered to the line's operators as `$1`
  // (upstream's `_bodySubVals`, `rules.js:1908-1913`).
  { name: 'b: regexp groups reach the operator', rules: `${P} reqHeaders://x-hit=$1 includeFilter://b:/hello (\\w+)/`, request: BODY },
  { name: 'b: on a body sent as urlencoded', rules: `${P} ${REQ} includeFilter://b:name`, request: { method: 'POST', body: 'name=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } } },

  // ── chance: / probability: ─────────────────────────────────────────────
  { name: 'chance:1 always holds', rules: `${P} ${REQ} includeFilter://chance:1` },
  { name: 'chance:0 never holds', rules: `${P} ${REQ} includeFilter://chance:0` },
  { name: 'chance:100% always holds', rules: `${P} ${REQ} includeFilter://chance:100%` },
  { name: 'chance:0% never holds', rules: `${P} ${REQ} includeFilter://chance:0%` },
  { name: 'probability: is the long spelling', rules: `${P} ${REQ} includeFilter://probability:1` },
  { name: 'probability:0', rules: `${P} ${REQ} includeFilter://probability:0` },
  { name: 'chance negated', rules: `${P} ${REQ} includeFilter://chance:!0` },
  { name: 'chance that is not a number never holds', rules: `${P} ${REQ} includeFilter://chance:abc` },
  { name: 'excludeFilter chance:1 excludes everything', rules: `${P} ${REQ} excludeFilter://chance:1` },
  { name: 'excludeFilter chance:0 excludes nothing', rules: `${P} ${REQ} excludeFilter://chance:0` },
  { name: 'chance= pure form', rules: `${P} ${REQ} includeFilter://chance=1` },

  // ── env: ───────────────────────────────────────────────────────────────
  { name: 'env: a variable that is set', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV` },
  { name: 'env: a variable that is not set', rules: `${P} ${REQ} includeFilter://env:WHISTLE_NO_SUCH_VAR` },
  { name: 'env: with its value', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV=alpha` },
  { name: 'env: value comparison ignores case', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV=Alpha` },
  { name: 'env: with another value', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV=beta` },
  { name: 'env: name keeps its case', rules: `${P} ${REQ} includeFilter://env:whistle_diff_env` },
  { name: 'env: only = separates, never :', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV:alpha` },
  { name: 'env: an unset variable negated', rules: `${P} ${REQ} includeFilter://env:WHISTLE_NO_SUCH_VAR!=x` },
  { name: 'env. pure form', rules: `${P} ${REQ} includeFilter://env.WHISTLE_DIFF_ENV=alpha` },
  { name: 'env= pure form', rules: `${P} ${REQ} includeFilter://env=WHISTLE_DIFF_ENV=alpha` },
  { name: 'env: regexp value', rules: `${P} ${REQ} includeFilter://env:WHISTLE_DIFF_ENV=/^alpha$/` },

  // ── from: ──────────────────────────────────────────────────────────────
  { name: 'from:tunnel on a plain request', rules: `${P} ${REQ} includeFilter://from:tunnel` },
  { name: 'from:!tunnel on a plain request', rules: `${P} ${REQ} includeFilter://from:!tunnel` },
  { name: 'from:composer', rules: `${P} ${REQ} includeFilter://from:composer` },
  { name: 'from:!composer', rules: `${P} ${REQ} includeFilter://from:!composer` },
  { name: 'from:sni', rules: `${P} ${REQ} includeFilter://from:sni` },
  { name: 'from:test', rules: `${P} ${REQ} includeFilter://from:test` },
  { name: 'from:internalPath', rules: `${P} ${REQ} includeFilter://from:internalPath` },
  { name: 'from:httpserver', rules: `${P} ${REQ} includeFilter://from:httpserver` },
  { name: 'from:httpsserver', rules: `${P} ${REQ} includeFilter://from:httpsserver` },
  { name: 'from:httpsport', rules: `${P} ${REQ} includeFilter://from:httpsport` },
  { name: 'from: an unknown marker', rules: `${P} ${REQ} includeFilter://from:nowhere` },
  { name: 'from: an unknown marker negated', rules: `${P} ${REQ} includeFilter://from:!nowhere` },
  { name: 'excludeFilter from: an unknown marker', rules: `${P} ${REQ} excludeFilter://from:nowhere` },
  { name: 'excludeFilter from:!tunnel', rules: `${P} ${REQ} excludeFilter://from:!tunnel` },
  { name: 'from. pure form', rules: `${P} ${REQ} includeFilter://from.tunnel` },
  { name: 'from: marker case is folded', rules: `${P} ${REQ} includeFilter://from:!TUNNEL` },

  // ── host: ──────────────────────────────────────────────────────────────
  // A **declared deviation**, and the only one this corpus expects to differ.
  // Upstream files a `host` condition under `hostFilter`, which only
  // `util.checkProxyHost` reads — deciding which hosts a `proxy://` engages
  // for, never whether a rule applies. whistle-rs matches the request's host
  // with it (`docs/RULES.md`, deliberate deviations). These cases carry their
  // own probe header so the harness can name the difference and let it pass;
  // see `EXPECTED` in `harness.js`.
  { name: 'host= the request host', rules: `${P} reqHeaders://x-host-filter=1 includeFilter://host=127.0.0.1` },
  { name: 'host= another host', rules: `${P} reqHeaders://x-host-filter=1 includeFilter://host=other.test` },
  { name: 'host: the request host', rules: `${P} reqHeaders://x-host-filter=1 includeFilter://host:127.0.0.1` },
  { name: 'host: another host', rules: `${P} reqHeaders://x-host-filter=1 includeFilter://host:other.test` },
  { name: 'excludeFilter host= the request host', rules: `${P} reqHeaders://x-host-filter=1 excludeFilter://host=127.0.0.1` },

  // ── the URL-pattern form ───────────────────────────────────────────────
  { name: 'a wildcard URL filter that matches', rules: `${P} ${REQ} includeFilter://*/echo` },
  { name: 'a wildcard URL filter that misses', rules: `${P} ${REQ} includeFilter://*/nope` },
  { name: 'a wildcard URL filter negated', rules: `${P} ${REQ} includeFilter://!*/echo` },
  { name: 'a regexp URL filter', rules: `${P} ${REQ} includeFilter:///echo$/` },
  { name: 'a regexp URL filter that misses', rules: `${P} ${REQ} includeFilter:///nope$/` },
  { name: 'a regexp URL filter with the i flag', rules: `${P} ${REQ} includeFilter:///ECHO$/i` },
  { name: 'a regexp URL filter without the i flag is case-sensitive', rules: `${P} ${REQ} includeFilter:///ECHO$/` },
  { name: 'a regexp URL filter with the u flag', rules: `${P} ${REQ} includeFilter:///ECHO$/u` },
  { name: 'a regexp URL filter negated', rules: `${P} ${REQ} includeFilter://!/echo$/` },
  { name: 'a regexp URL filter negated, missing', rules: `${P} ${REQ} includeFilter://!/nope$/` },
  { name: 'excludeFilter with a regexp URL', rules: `${P} ${REQ} excludeFilter:///echo$/` },
  { name: 'excludeFilter with a wildcard URL', rules: `${P} ${REQ} excludeFilter://*/echo` },
  { name: 'excludeFilter with a wildcard URL that misses', rules: `${P} ${REQ} excludeFilter://*/nope` },
  // With a condition name present the `!` belongs to the value, so a leading
  // `!` makes the whole payload a negated URL pattern instead.
  { name: 'a leading ! makes m:GET a URL pattern', rules: `${P} ${REQ} includeFilter://!m:GET` },
  { name: 'a leading ! makes m:POST a URL pattern too', rules: `${P} ${REQ} includeFilter://!m:POST` },

  // ── which spellings include and which exclude ──────────────────────────
  { name: 'filter:// excludes when its condition holds', rules: `${P} ${REQ} filter://m:GET` },
  { name: 'filter:// leaves the rule alone when it does not', rules: `${P} ${REQ} filter://m:POST` },
  { name: 'filter:// with a regexp URL excludes', rules: `${P} ${REQ} filter:///echo$/` },
  { name: 'filter:// with a regexp URL that misses', rules: `${P} ${REQ} filter:///nope$/` },
  // `filter://` takes no delimiting slash of its own: the trailing one is the
  // marker, and everything before it is the expression.
  { name: 'filter:// regexp with no leading slash', rules: `${P} ${REQ} filter://echo$/` },
  { name: 'filter:// regexp with no leading slash, missing', rules: `${P} ${REQ} filter://nope$/` },
  { name: 'filter:// regexp with the i flag', rules: `${P} ${REQ} filter://ECHO$/i` },
  { name: 'filter:// regexp negated', rules: `${P} ${REQ} filter://!echo$/` },
  { name: 'filter:// with a wildcard URL excludes', rules: `${P} ${REQ} filter://*/echo` },
  { name: 'filter:// with a wildcard URL that misses', rules: `${P} ${REQ} filter://*/nope` },
  { name: 'filter:// with a negated wildcard URL', rules: `${P} ${REQ} filter://!*/echo` },
  { name: 'filter:// wildcard needs no trailing slash', rules: `${P} ${REQ} filter://*/echo-no-slash` },
  // The spelling the deviations table used to claim differed: a payload with a
  // trailing `/` and no `*` is a regexp for both.
  { name: 'filter:// host-shaped regexp that misses', rules: `${P} ${REQ} filter://example.com/` },
  { name: 'filter:// host-shaped regexp that matches', rules: `${P} ${REQ} filter://127.0.0.1/` },
  { name: 'excludeFilter host-shaped regexp that matches', rules: `${P} ${REQ} excludeFilter:///127.0.0.1/` },
  { name: 'ignore:// with a condition excludes', rules: `${P} ${REQ} ignore://m:GET` },
  { name: 'ignore:// with a condition that misses', rules: `${P} ${REQ} ignore://m:POST` },
  { name: 'ignore:// with a wildcard URL excludes', rules: `${P} ${REQ} ignore://*/echo` },
  { name: 'ignore:// with a wildcard URL that misses', rules: `${P} ${REQ} ignore://*/nope` },
  { name: 'ignore:// with a regexp URL excludes', rules: `${P} ${REQ} ignore:///echo$/` },
  { name: 'ignore:// with a bracketed condition', rules: `${P} ${REQ} ignore://(m:GET)` },
  { name: 'ignore:// still suppresses a protocol', rules: `${P} ${REQ} ignore://reqHeaders` },
  { name: 'excludeFilter:// on the matching method', rules: `${P} ${REQ} excludeFilter://m:GET` },
  { name: 'excludeFilter:// on another method', rules: `${P} ${REQ} excludeFilter://m:POST` },

  // ── several conditions on one line ─────────────────────────────────────
  { name: 'two includes are or-ed, the second holding', rules: `${P} ${REQ} includeFilter://m:POST includeFilter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'two includes are or-ed, neither holding', rules: `${P} ${REQ} includeFilter://m:POST includeFilter://reqH.x-tag:no`, request: TAGGED },
  { name: 'two includes are or-ed, both holding', rules: `${P} ${REQ} includeFilter://m:GET includeFilter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'an exclude vetoes a satisfied include', rules: `${P} ${REQ} includeFilter://m:GET excludeFilter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'an exclude that misses leaves the include', rules: `${P} ${REQ} includeFilter://m:GET excludeFilter://reqH.x-tag:no`, request: TAGGED },
  { name: 'two excludes, the second holding', rules: `${P} ${REQ} excludeFilter://m:POST excludeFilter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'two excludes, neither holding', rules: `${P} ${REQ} excludeFilter://m:POST excludeFilter://reqH.x-tag:no`, request: TAGGED },
  { name: 'filter:// and includeFilter:// on one line', rules: `${P} ${REQ} includeFilter://m:GET filter://reqH.x-tag:yes`, request: TAGGED },
  { name: 'a request-phase and a response-phase include', rules: `${P} ${RES} includeFilter://m:POST includeFilter://s:200` },
  { name: 'a request-phase and a response-phase exclude', rules: `${P} ${RES} excludeFilter://m:GET excludeFilter://s:404` },

  // ── a condition on a line that carries other operators ─────────────────
  { name: 'a filter alongside two operators', rules: `${P} ${REQ} resHeaders://x-r=1 includeFilter://m:GET` },
  { name: 'a filter alongside two operators, missing', rules: `${P} ${REQ} resHeaders://x-r=1 includeFilter://m:POST` },
  { name: 'a filter written before the operator', rules: `${P} includeFilter://m:GET ${REQ}` },
  { name: 'a filter written before the operator, missing', rules: `${P} includeFilter://m:POST ${REQ}` },
  { name: 'a filter between two operators', rules: `${P} ${REQ} includeFilter://m:GET resHeaders://x-r=1` },
  { name: 'a filtered line and an unfiltered one', rules: `${P} reqHeaders://x-hit=filtered includeFilter://m:POST\n${P} reqHeaders://x-hit=plain` },
  { name: 'a filter on a line whose operator is a short circuit', rules: `${P} statusCode://204 includeFilter://m:GET` },
  { name: 'a filter on a short circuit that misses', rules: `${P} statusCode://204 includeFilter://m:POST` },
  // Operator-first lines: the filter has to reach every pattern the line names.
  { name: 'operator-first line with a filter that holds', rules: `${REQ} includeFilter://m:GET ${P} other.test` },
  { name: 'operator-first line with a filter that misses', rules: `${REQ} includeFilter://m:POST ${P} other.test` },
  { name: 'operator-first line, filter last', rules: `${REQ} ${P} other.test includeFilter://m:GET` },
  { name: 'a filter next to a line property', rules: `${P} ${REQ} includeFilter://m:GET lineProps://important` },
  { name: 'a filter next to a line property, missing', rules: `${P} ${REQ} includeFilter://m:POST lineProps://important` },
  // `filter://` whose payload is neither a condition nor a URL shape: the
  // *other* `filter://`, an operator naming protocols to suppress.
  { name: 'filter:// naming a protocol', rules: `${P} ${REQ} filter://reqHeaders` },
  { name: 'filter:// naming a host', rules: `${P} ${REQ} filter://example.com` },

  // ── conditions that do not parse ───────────────────────────────────────
  { name: 'an empty includeFilter is dropped', rules: `${P} ${REQ} includeFilter://` },
  { name: 'an includeFilter of only ! is dropped', rules: `${P} ${REQ} includeFilter://!` },
  { name: 'an empty excludeFilter is dropped', rules: `${P} ${REQ} excludeFilter://` },
  { name: 'an empty filter:// is dropped', rules: `${P} ${REQ} filter://` },
  { name: 'a condition name with no value', rules: `${P} ${REQ} includeFilter://reqH.` },
  { name: 'a condition name with no value, = form', rules: `${P} ${REQ} includeFilter://reqH=` },
  { name: 'a status condition with no value', rules: `${P} ${RES} includeFilter://s:` },
  { name: 'an unknown condition name', rules: `${P} ${REQ} includeFilter://nosuch:value` },
  { name: 'a bare word filter', rules: `${P} ${REQ} includeFilter://word` },
  { name: 'a bare word excludeFilter', rules: `${P} ${REQ} excludeFilter://word` },
  { name: 'a dotted name after filter:// is not a condition', rules: `${P} ${REQ} filter://reqH.x-tag:yes`, request: TAGGED },
  // An empty header key is kept and never matches; only a key of `!` — which
  // takes two, the first being the value's negation — drops the filter.
  { name: 'a header key emptied by its own !', rules: `${P} ${REQ} includeFilter://reqH.!!=yes`, request: TAGGED },
  { name: 'a header key emptied by its own !, colon form', rules: `${P} ${REQ} includeFilter://reqH.!!:yes`, request: TAGGED },
  { name: 'one ! leaves the key empty but present', rules: `${P} ${REQ} includeFilter://reqH.!:yes`, request: TAGGED },
  { name: 'an env key emptied by its own !', rules: `${P} ${REQ} includeFilter://env.!!=v` },

  // ── the bracketed inline form ──────────────────────────────────────────
  { name: 'a condition in round brackets', rules: `${P} ${REQ} includeFilter://(m:GET)` },
  { name: 'a condition in round brackets that misses', rules: `${P} ${REQ} includeFilter://(m:POST)` },
  { name: 'a condition in angle brackets', rules: `${P} ${REQ} includeFilter://<m:GET>` },
  // The brackets do not protect a space: the line is split on whitespace before
  // any token is looked at, so this is two tokens and neither is a filter.
  { name: 'brackets do not let a condition hold a space', rules: `${P} ${REQ} includeFilter://(reqH.x-tag:y es)`, request: { headers: { 'x-tag': 'y es' } } },
  { name: 'a bracketed excludeFilter', rules: `${P} ${REQ} excludeFilter://(m:GET)` },
  { name: 'a bracketed filter:// condition', rules: `${P} ${REQ} filter://(m:GET)` },
  { name: 'a bracketed filter:// wildcard URL', rules: `${P} ${REQ} filter://(*/echo)` },
  { name: 'a bracketed ignore:// regexp URL', rules: `${P} ${REQ} ignore://(/echo$/)` },
  { name: 'a bracketed URL filter', rules: `${P} ${REQ} includeFilter://(*/echo)` },
  { name: 'a bracketed URL filter that misses', rules: `${P} ${REQ} includeFilter://(*/nope)` },
];
