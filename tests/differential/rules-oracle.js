// The same rules text and the same request URL, resolved by **whistle's own
// parser** and by this port's, with the two answers compared.
//
//   node rules-oracle.js                 # the whole corpus
//   node rules-oracle.js --values        # also compare the resolved values
//   node rules-oracle.js --limit 5       # at most 5 examples per class
//   node rules-oracle.js --grep host     # only cases whose rule line matches
//
// ── Why a second bench ─────────────────────────────────────────────────────
//
// `harness.js` compares what a client got and what an origin got. That is the
// truth, and it is also expensive: two live proxies, an origin, a port range,
// and one request per case. It can only ask what a request can show, and it can
// only ask it about rules that are safe to run — a corpus generated from the
// documentation had to drop every line naming `www.example.com` as a
// destination, because running it sends a stranger a request.
//
// This bench asks a narrower question and pays almost nothing for it: **which
// rules match, and what does each operator end up holding**. No socket is
// opened on either side. whistle's `Rules` is driven in-process (its
// `lib/rules/rules.js`, the same code the real proxy runs), and this port
// answers through `whistle-rs explain --batch`, which runs the ordinary
// resolver. So the corpus can be anything at all: `/Users/john/mock.json`,
// `www.test.com`, a line that is not a rule. Nothing is sent anywhere.
//
// It is the layer where most of this port's bugs have lived. Every finding in
// the roadmap's "pattern and destination" round — the wildcard that matched any
// URL that *mentioned* a host, the shared slot, `formatShorthand` — is a
// question this bench asks directly, and a live request could only ask through
// its consequences.
//
// ── What it cannot see ─────────────────────────────────────────────────────
//
// Resolution is not application. A rule that resolves identically on both sides
// can still be applied differently, and that is `harness.js`'s subject, not
// this one's. Neither does this bench see the response phase, plugins, or
// anything an `@`-include or a `rulesFile://` pulls in mid-request.
//
// ── Reading the output ─────────────────────────────────────────────────────
//
// `differing` counts (case, URL) pairs whose **operator sets** differ.
// `values` counts pairs that agree on the set but disagree on what an operator
// holds; those are only compared under `--values`, because the two programs
// spell a resolved value differently often enough that the noise would bury the
// signal — see `KNOWN` below for the vocabulary this bench translates and
// `docs/RULES.md` for the divergences this port has declared.

'use strict';

const path = require('path');
const Module = require('module');
const { execFileSync } = require('child_process');

// The real path, not the spelled one (`whistle-pkg.js` resolves it):
// `loadUpstreamRules` plants a stub in `require.cache`, and Node keys that cache
// by real path. Through a symlinked `node_modules` (mutations.js's scratch
// worktree) the stub landed under a key nothing looked up, upstream's circular
// require ran for real, and every run died on "Rules is not a constructor".
const WHISTLE = require('./whistle-pkg');
const { forVersion } = WHISTLE;
const WHISTLE_RULES = path.join(WHISTLE.dir, 'lib', 'rules');
// `RS_BIN` as in the benches that start a proxy, so every tool here can be
// pointed at the same binary — a release build, or one under test elsewhere.
const BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');

// `rules.js` requires `util.js`, which requires `index.js`, which requires
// `rules.js` back — and `index.js` also builds the singletons a running proxy
// needs. Standing a stub in its place is what makes the parser drivable on its
// own: the cycle resolves, and nothing that listens on a port is constructed.
function loadUpstreamRules() {
  const idxPath = path.join(WHISTLE_RULES, 'index.js');
  const stub = new Module(idxPath, null);
  stub.filename = idxPath;
  stub.loaded = true;
  stub.exports = {};
  require.cache[idxPath] = stub;
  return require(path.join(WHISTLE_RULES, 'rules.js'));
}

const Rules = loadUpstreamRules();
const protoMgr = require(path.join(WHISTLE_RULES, 'protocols.js'));

// ── The two vocabularies ───────────────────────────────────────────────────
//
// whistle files a rule under a protocol *key*; this port keeps a key per
// protocol name and settles the shared slot during resolution. Where the two
// spell the same fact differently, the difference is translated here rather
// than counted, and each translation is a claim about upstream that the
// comment beside it names.
const KNOWN = {
  // Every upstream-proxy spelling lands in `_rules.proxy` (`PROXY_RE`,
  // `lib/rules/rules.js:1286`); this port keeps the spelling.
  proxy: 'proxy',
  socks: 'proxy',
  'http-proxy': 'proxy',
  'https-proxy': 'proxy',
  'internal-proxy': 'proxy',
  'internal-http-proxy': 'proxy',
  'internal-https-proxy': 'proxy',
  'https2http-proxy': 'proxy',
  'http2https-proxy': 'proxy',
};

// Buckets neither side reports in a comparable way, so a difference in them is
// not a difference in the answer:
//
//   * `pipe` is skipped by upstream's `resolveRules` outright
//     (`rules.js:2244`) and resolved by `resolveSingleRule` elsewhere;
//   * `sniCallback` lives in its own list (`rulesMgr._sniCallback`), read
//     during the TLS handshake;
//   * `lineProps` is not an operator on either side — it is a property of the
//     line, and this port carries it on each operator;
//   * a per-line `includeFilter://` / `excludeFilter://` is not an operator on
//     either side — upstream attaches it to the rule it guards and files
//     nothing (checked by `assertVocabulary`), and this port keeps it as a
//     condition on the line;
//   * `ignore` and `filter` are **consumed** here: this port applies what they
//     silence during resolution and the operator itself does not survive into
//     the answer, where upstream keeps it in `_rules.ignore` for later phases
//     to read. What either of them actually silenced still shows up, in the
//     buckets that are missing an operator because of it — which is the thing
//     worth comparing.
const IGNORED_BUCKETS = new Set([
  'pipe',
  'sniCallback',
  'lineProps',
  'ignore',
  'filter',
]);

function bucketOf(protocol) {
  return KNOWN[protocol] || protocol;
}

// ── The translation table, checked against upstream ────────────────────────
//
// Every entry above is a claim about where whistle files a rule, and a *wrong*
// claim hides exactly what this bench exists to find: `location://` was
// translated as a slot member of its own, so both sides "agreed" while whistle
// answered `502` and this port answered `302`. The claims are cheap to check —
// the parser is right here — so they are checked before anything is compared,
// and a false one stops the run rather than quietly excusing a difference.

/** Which `_rules[…]` lists does whistle file this line under? */
function upstreamKeysOf(line) {
  const rules = new Rules({});
  rules.parse(`a.com ${line}`);
  return Object.keys(rules._rules).filter(
    (key) => rules._rules[key] && rules._rules[key].length
  );
}

function assertVocabulary() {
  const wrong = [];
  const claim = (line, key) => {
    const got = upstreamKeysOf(line);
    if (!got.includes(key)) {
      wrong.push(`${line} lands in _rules.${got.join('/') || '(nothing)'}, not ${key}`);
    }
  };

  // Every slot member shares the one `rule` list — that is what makes it a
  // member. A name with a key of its own would be reduced to a single winner
  // by this bench and by nothing else.
  for (const member of SLOT_MEMBERS) {
    if (member === 'rule') continue;
    claim(`${member}:///srv/x`, 'rule');
  }
  // …and the names that are *not* members, for the same reason in reverse.
  for (const [matcher, key] of [
    ['urlReplace://a=b', 'urlReplace'],
    ['host://1.1.1.1', 'host'],
    ['replaceStatus://500', 'replaceStatus'],
    ['resBody://(a)', 'resBody'],
  ]) {
    claim(matcher, key);
  }
  // The upstream-proxy family is one key, whatever the spelling.
  for (const name of Object.keys(KNOWN)) {
    if (KNOWN[name] !== 'proxy') continue;
    claim(`${name}://127.0.0.1:8888`, 'proxy');
  }
  // …and both filter spellings are one protocol.
  // `filter://` the *protocol* — the spelling that suppresses other operators —
  // is a rule with a list of its own. The per-line `includeFilter://` /
  // `excludeFilter://` conditions are not: they are attached to the rule they
  // guard (`rule.filters`) and file nothing, which is why neither side reports
  // them as operators.
  claim('filter://ua', 'filter');
  claim('host://1.1.1.1 includeFilter://m:GET', 'host');

  // The two buckets this bench ignores because upstream resolves them
  // elsewhere — checked by asking, not by trusting the comment: `pipe` is
  // parsed into a list of its own and then skipped by `resolveRules`
  // (`rules.js:2244`), and `sniCallback` never reaches `_rules` at all.
  const req = makeReq('http://a.com/x');
  const resolvedPipe = (() => {
    const rules = new Rules({});
    rules.parse('a.com pipe://name sniCallback://cert');
    return rules.resolveRules(req);
  })();
  if (resolvedPipe.pipe) wrong.push('pipe is resolved by resolveRules after all');
  if (resolvedPipe.sniCallback) {
    wrong.push('sniCallback is resolved by resolveRules after all');
  }

  if (wrong.length) {
    console.error('the bench\'s vocabulary disagrees with whistle:');
    for (const line of wrong) console.error(`  ${line}`);
    process.exit(2);
  }
}

// ── Upstream ───────────────────────────────────────────────────────────────

// One question with no response head, or **two** with one — which is what a
// real request asks. whistle resolves the request-phase protocols before it has
// a head (`resolveReqRules`) and the `pureResProtocols` once it does
// (`resolveResRules`, `_original/lib/rules/rules.js:2302-2308`), against a
// request `lib/inspectors/res.js` has just stamped the status and headers onto.
// Asking for everything in one call with the head already in hand would decide
// the *request* half with an answer no request has yet, which is the one thing
// this port is careful not to do.
function upstreamResolve(rulesText, values, req, response) {
  const rules = new Rules(values || {});
  rules.parse(rulesText);
  let resolved;
  if (response) {
    resolved = rules.resolveReqRules(req);
    req.statusCode = String(response.status);
    req.resHeaders = response.headers || {};
    req.hostIp = response.server_ip;
    req.serverPort = response.server_port;
    Object.assign(resolved, rules.resolveResRules(req));
  } else {
    resolved = rules.resolveRules(req);
  }
  const ops = [];
  for (const key of Object.keys(resolved)) {
    const rule = resolved[key];
    if (!rule) continue;
    const list = rule.list && rule.list.length ? rule.list : [rule];
    for (const item of list) {
      ops.push({
        bucket: key,
        matcher: item.matcher,
        // `parseRule` splits a `host://` value in two, keeping the address in
        // the matcher and the port beside it (`rules.js:1319-1327`).
        port: item.port,
        // `rule.url` is the matcher with the request's unmatched tail joined on;
        // it exists only for the shared slot and the file family.
        url: item.url,
        value: typeof item.value === 'string' ? item.value : undefined,
        // `getRuleFiles` reads these, not `url`: `files` is the `|`-separated
        // list with the tail joined onto each, and `rawFiles` the same list
        // before the join, which is what a URL entry is fetched from
        // (`_original/lib/util/index.js:1435-1457`).
        files: item.files,
        rawFiles: item.rawFiles,
        // `getRuleValue` prefers `rule.path` — what a `<verbatim>` value
        // resolved to, brackets off and no tail joined
        // (`_original/lib/util/common.js:951-953`, `rules.js:840-843`).
        path: item.path,
        // A `{name}` reference upstream recognised. When the store had no
        // answer, upstream leaves the literal in the matcher and this port
        // keeps it too — see `docs/RULES.md`, "a bare value stays literal".
        key: item.key,
        pattern: item.rawPattern,
      });
    }
  }
  return ops;
}

function makeReq(url, method, headers, body, clientIp) {
  const parsed = new URL(url);
  const head = Object.assign(
    { host: parsed.host },
    headers || {}
  );
  // The URL a pattern is matched against is the one `getFullUrl` builds, and it
  // drops the port when the scheme implies it (`removeDefaultPort`,
  // `_original/lib/util/common.js:1266`). Both proxies do; only this bench,
  // which hands the resolver a URL rather than a socket, has to be told.
  url = url.replace(
    /^(https?|wss?|tunnel):\/\/([^/?#]+)/,
    (all, scheme, authority) => {
      const port = /^(wss|https)$/.test(scheme) ? ':443' : ':80';
      return authority.endsWith(port)
        ? `${scheme}://${authority.slice(0, -port.length)}`
        : all;
    }
  );
  return {
    fullUrl: url,
    curUrl: url,
    method: (method || 'GET').toUpperCase(),
    headers: head,
    isHttps: parsed.protocol === 'https:',
    _reqBody: typeof body === 'string' ? body : undefined,
    // `matchFilter` reads it straight off the request (`rules.js:1876,:1882`);
    // the socket it normally comes from does not exist here.
    clientIp,
  };
}

// ── This port ──────────────────────────────────────────────────────────────

function portResolve(queries) {
  const input = queries.map((q) => JSON.stringify(q)).join('\n') + '\n';
  const out = execFileSync(BIN, ['explain', '--batch'], {
    input,
    maxBuffer: 1 << 28,
  }).toString();
  const lines = out.split('\n').filter((line) => line.trim());
  if (lines.length !== queries.length) {
    throw new Error(
      `explain answered ${lines.length} of ${queries.length} queries`
    );
  }
  return lines.map((line) => JSON.parse(line));
}

// ── Comparison ─────────────────────────────────────────────────────────────

// The scheme of a matcher, which is the *member* of the shared slot upstream
// chose — `getProtocolName` (`lib/util/index.js:2043-2045`) asks the same
// question of `rules.rule.url`.
//
// Anything else is a destination: a scheme whistle does not know is exactly how
// a rule reaches the shared list in the first place (`rules.js:1313-1316`), so
// `myplugin://value` and `enale://https` — a typo for `enable` — are both URL
// replacements, and this port calls them that.
function slotMember(matcher) {
  const m = /^([\w.-]+):\/\//.exec(matcher || '');
  if (!m) return 'rule';
  // `status://` is `statusCode`, `download://` is `attachment`, … — the alias
  // table is upstream's own (`protocols.js:1151-1173`), and this port stores the
  // canonical name.
  const name = protoMgr.aliasProtocols[m[1]] || m[1];
  return SLOT_MEMBERS.has(name) ? name : 'rule';
}

const SLOT_MEMBERS = new Set([
  'rule',
  'file',
  'rawfile',
  'tpl',
  'jsonp',
  'dust',
  'xfile',
  'xrawfile',
  'xtpl',
  'xjsonp',
  'xdust',
  'xsfile',
  'xsrawfile',
  'xstpl',
  'statusCode',
  'redirect',
  'locationHref',
  // `location` is **not** here: it is in neither upstream's registry nor its
  // alias table, so `location://x` is a destination whose scheme happens to be
  // spelled `location` — the same fall-through any unknown protocol takes.
]);

function upstreamKey(op) {
  if (op.bucket === 'rule') {
    return 'rule:' + slotMember(op.matcher);
  }
  return bucketOf(op.bucket);
}

function portKey(op) {
  // This port names the slot's member outright; upstream's is the scheme of the
  // matcher its one list holds.
  if (op.slot) return 'rule:' + op.protocol;
  // `rule://<name>` is this port's include spelling and takes no slot, which is
  // a declared divergence (`protocols::RULE_INCLUDE`): upstream files it in the
  // shared list, where it can only ever produce the unusable URL
  // `rule://<name>`. Translated by name so that the *consequence* — a slot this
  // port leaves free for the next candidate — is still counted.
  if (op.protocol === 'ruleInclude') return 'rule:rule';
  return bucketOf(op.protocol);
}

// Two places where this port's resolved set holds more than upstream's, in both
// cases because upstream reduced the list *earlier* and this port reduces it at
// the reader. The bench compares what each proxy will act on, so the same
// reduction is applied here — and each is the rule the reader implements.
//
//   * the upstream-proxy family shares one key upstream, so at most one operator
//     can be in it; here every spelling has a key and the smallest resolution
//     order wins (`apply::find_proxy`, `protocols::UPSTREAM_PROXY_PROTOCOLS`);
//   * `rulesFile` / `resScript` keep every line written with the rules-text
//     spelling (`reqRules://`, `resRules://`) and **one** script
//     (`resolveRules`'s filter, `rules.js:2260-2273`; here
//     `apply::accumulated_script_ops`).
const PROXY_FAMILY = new Set(
  Object.keys(KNOWN).filter((name) => KNOWN[name] === 'proxy')
);
const SCRIPT_PROTOCOLS = { rulesFile: 'reqRules', resScript: 'resRules' };

function collapse(ops) {
  const out = [];
  let proxy = null;
  const seenScript = {};
  for (const op of ops) {
    if (PROXY_FAMILY.has(op.protocol)) {
      if (!proxy || op.order < proxy.order) proxy = op;
      continue;
    }
    const pure = SCRIPT_PROTOCOLS[op.protocol];
    if (pure) {
      const written = /^([\w.-]+):\/\//.exec(op.raw);
      if (!written || written[1] !== pure) {
        if (seenScript[op.protocol]) continue;
        seenScript[op.protocol] = true;
      }
    }
    out.push(op);
  }
  if (proxy) out.push(proxy);
  return out;
}

function tally(keys) {
  const counts = new Map();
  for (const key of keys) counts.set(key, (counts.get(key) || 0) + 1);
  return counts;
}

function diffTallies(a, b) {
  const out = [];
  for (const key of new Set([...a.keys(), ...b.keys()])) {
    const left = a.get(key) || 0;
    const right = b.get(key) || 0;
    if (left !== right) out.push(`${key}: whistle ${left} vs rs ${right}`);
  }
  return out.sort();
}

// The value comparison, which only `--values` turns on.
//
// The two programs spell a resolved value differently and the translation is
// three claims about upstream, each of them checkable:
//
//  1. whistle keeps the operator's protocol **on the front** of the value it
//     stores (`rule.matcher` is the whole token); this port splits the two at
//     parse time. So one leading `scheme://` comes off the upstream string —
//     but only when the scheme is not a web one, because there the scheme is
//     part of the value: a destination *is* `http://localhost:5173`.
//  2. `rule.url` is the matcher with the request's unmatched tail joined on,
//     and `getExactRule` sets it for **every** rule (`rules.js:957-966`), not
//     only the ones that use it. Upstream joins for the shared slot and the
//     file family and nothing else (`util.rule.getUrl`), so that is where the
//     joined form is the value, and elsewhere the matcher is.
//  3. `rule.value` exists only when the value **is content** — an `(inline)`
//     payload or a values-store hit — and then it is what the operator gets,
//     whatever the matcher says.
// The scheme comes off only when it is the operator's **own name** — its alias
// included, since `tlsOptions://x` is filed under `cipher`. A destination keeps
// its scheme, and so does an unknown one: `protocol://temp/blank.js` is a URL
// whose scheme happens to be spelled `protocol`, which is precisely how it
// reached the shared list.
function stripOperatorScheme(text, bucket) {
  const m = /^([\w.-]+):\/\//.exec(text);
  if (!m) return text;
  const scheme = m[1];
  // `PROXY_RE`'s `x?` (`rules.js:37-38`): every upstream-proxy name may carry
  // the fallback prefix, and the family is one bucket either way.
  const base = /^x./.test(scheme) && KNOWN[scheme.slice(1)] ? scheme.slice(1) : scheme;
  const canonical = bucketOf(protoMgr.aliasProtocols[base] || base);
  return canonical === bucketOf(bucket) || scheme === bucket
    ? text.slice(m[0].length)
    : text;
}

// Who reads the **joined** value, `rule.url`, rather than the matcher as
// written: the URL-replacement rule (`util.rule.getUrl`), the local-file family
// (`util.getRuleFiles`) and the four dump operators (`getWriteFilePath`,
// `_original/lib/util/index.js:1461-1464`). `getExactRule` fills `url` in for
// every rule, so reading it for the others would compare a field upstream never
// looks at: `statusCode://404` on `/a` has `rule.url` of `statusCode://404/a`.
const WRITE_PROTOCOLS = new Set([
  'reqWrite',
  'resWrite',
  'reqWriteRaw',
  'resWriteRaw',
]);

const FILE_PROTOCOL_RE = /^(?:|x|xs)(?:file|rawfile|dust|tpl|jsonp)$/;

function joinsTail(op, member) {
  if (op.bucket === 'rule') return member === 'rule' || FILE_PROTOCOL_RE.test(member);
  return WRITE_PROTOCOLS.has(op.bucket);
}

function upstreamValue(op) {
  const bucket = op.bucket === 'rule' ? slotMember(op.matcher) : op.bucket;
  if (typeof op.value === 'string') return stripOperatorScheme(op.value, bucket);
  // The file family is read from its own list, where a URL entry keeps the path
  // it was written with and only a local path takes the request's tail.
  if (op.bucket === 'rule' && FILE_PROTOCOL_RE.test(bucket) && op.files) {
    const raw = op.rawFiles || op.files;
    return op.files
      .map((file, i) => (/^https?:\/\//.test(stripOperatorScheme(raw[i], bucket)) ? raw[i] : file))
      .map((file) => stripOperatorScheme(file, bucket))
      .join('|');
  }
  // `whistle.<name>://value` carries the plugin's name in the *protocol*; this
  // port carries it in the value (`plugin://name` / `name/rest`).
  if (op.bucket === 'plugin') {
    const m = /^(?:whistle|plugin)\.([\w-]+):\/\/(.*)$/.exec(op.matcher || '');
    if (m) return m[2] ? `${m[1]}/${m[2]}` : m[1];
  }
  if (typeof op.path === 'string') return stripOperatorScheme(op.path, bucket);
  const joins = joinsTail(op, bucket);
  let value = stripOperatorScheme(joins && op.url ? op.url : op.matcher, bucket);
  // The port a `host://` value named is stored beside the matcher, not in it.
  if (op.bucket === 'host' && op.port) value += ':' + op.port;
  return value;
}

function valuesOf(ops, isUpstream, scheme) {
  const out = new Map();
  for (const op of ops) {
    const key = isUpstream ? upstreamKey(op) : portKey(op);
    const list = out.get(key) || [];
    list.push(isUpstream ? upstreamValue(op) : portValue(op, key, scheme));
    out.set(key, list);
  }
  for (const [key, list] of out) out.set(key, list.slice().sort());
  return out;
}

// A destination written without a scheme inherits the request's, which upstream
// does while resolving (`setProtocol(matcher, curUrl)`, `rules.js:1085-1087`)
// and this port does when it builds the request (`dest.rs`). Same answer, later
// — so the scheme is put back here rather than counted as a difference.
function portValue(op, key, scheme) {
  let value = op.value;
  // `<path>` says "this exact value, whatever the request asked for". Upstream
  // takes the brackets off while resolving (`getValue(matcher, '<', '>')`,
  // `rules.js:840-843`); this port keeps them until the layer that reads the
  // value does, which is the same answer one step later. Only where this port
  // asks the question at all — the shared slot and the file family
  // (`url::fixed_value`'s narrowing, `docs/RULES.md`); an
  // `htmlPrepend://(<!--x-->)` is content that merely looks bracketed.
  const brackets =
    key.startsWith('rule:') &&
    !op.content &&
    /^([\w.-]+:\/\/|\/\/)?<(.*)>$/.exec(value);
  if (brackets) value = (brackets[1] || '') + brackets[2];
  // A destination written without a scheme inherits the request's, which
  // upstream does while resolving (`setProtocol`, `rules.js:1085-1087`) and
  // this port does when it builds the request.
  if (key === 'rule:rule' && !/^[\w.-]+:\/\//.test(value)) {
    return value.startsWith('//') ? scheme + ':' + value : scheme + '://' + value;
  }
  return value;
}

// A backtick template is rendered when its operator runs, and a response-phase
// operator does not run here: this bench has no response, so `${statusCode}`
// has no answer and the value is still the template. Upstream renders it during
// the pass it resolves the operator in, which for those is the response pass —
// so the two disagree about *when*, not about *what*, and comparing them here
// would only ever measure this bench's own missing half. `${now}` would differ
// on every run besides.
function isDeferredTemplate(ops) {
  return ops.some((op) => op.value.startsWith('`') && op.value.endsWith('`'));
}

// whistle asks its `<…>` question of **every** operator's value, so an
// operator whose value merely opens with `<` and ends with `>` loses both:
// `resBody://<h1>x</h1>` mocks `h1>x</h1`. This port asks it where the two
// bracket forms are documented — the shared slot and the file family — and
// leaves injected markup alone (`url::fixed_value`, and `docs/RULES.md` under
// the bracket forms). A declared divergence, and the only one this bench's
// value comparison still meets.
function isBracketQuirk(theirs, ours) {
  return (
    theirs.length === ours.length &&
    ours.every((value, i) => {
      const m = /^<(.*)>$/.exec(value);
      return m && m[1] === theirs[i];
    })
  );
}

// A local path the request's tail is joined onto, where the only difference is
// which separator did the joining: `file://D:\dir\` asked for `/echo` resolves
// to `D:\dir\echo` upstream and `D:\dir/echo` here. Neither is what gets opened.
// Upstream runs every local path through `convertSlash` first
// (`lib/util/file-mgr.js:13-16`, `formatPathSep` off Windows), and so does this
// port's file layer, so both open `D:/dir/echo`; on Windows both separators are
// separators. Scoped to the file family — a `\` anywhere else is text.
function isSeparatorOnly(key, theirs, ours) {
  const slashes = (list) => JSON.stringify(list.map((v) => v.replace(/\\/g, '/')));
  return (
    /^rule:(?:|x|xs)(?:file|rawfile|tpl|dust|jsonp)$/.test(key) &&
    theirs.length === ours.length &&
    slashes(theirs) === slashes(ours)
  );
}

// A `{name}` the values store did not answer. Upstream extends the literal with
// the request's tail, having no reason to treat it differently from a path;
// this port leaves it alone, which is the declared choice `docs/RULES.md`
// records for a bare value that names nothing — telling `{typo}` from
// `{"a":1}` needs a grammar for names that neither program has. Not a
// difference in what either resolves, so not counted as one.
function isUnansweredKey(ops) {
  return ops.some((op) => /^\{\S+\}$/.test(op.value));
}

// Two more value-level divergences this port has declared, both about what a
// value *is* rather than about which rule matched — so the operator sets agree
// and only the text differs.
//
//   * `rule://<name>` is this port's include spelling. Upstream files it as a
//     destination and joins the request's tail onto the unusable URL
//     `rule://<name>`; there is no text to compare.
//   * a `{name}` reference must **end** the value here. `getKey` takes
//     everything up to the last `}` and discards the rest (`rules.js:817-824`),
//     so upstream reads `resBody://{v}tail` as `{v}` and silently drops `tail`;
//     this port keeps the literal. Declared at the top of `cases-values.js`.
function isDeclaredValue(ops) {
  return ops.some(
    (op) =>
      op.protocol === 'ruleInclude' || /^\{[^{}\s]+\}.+$/.test(op.value)
  );
}

// ── The corpus ─────────────────────────────────────────────────────────────

const CORPUS = require('./cases-rulelines.js');

// The hand-written corpora, read as *rules* rather than run as requests.
//
// Each of those files already carries the request its case is about — a method,
// a path, headers, sometimes a body — so a case becomes a question this bench
// can ask exactly: put this rules text and this request through both resolvers.
// They are the tricky lines somebody sat down and thought of, which is a
// different set from the ones the documentation prints, and here they cost no
// proxy and no origin.
//
// `PORT_BASE` matters only in that the corpora bake it into their patterns; the
// same value is used to build the URL, so pattern and request agree.
const CASE_FILES = [
  'cases.js',
  'cases-lineprops.js',
  'cases-file.js',
  'cases-filters.js',
  'cases-patterns.js',
  'cases-bodies.js',
  'cases-delete.js',
  'cases-compose.js',
  'cases-values.js',
  'cases-includes.js',
  'cases-proxy.js',
  'cases-flags.js',
  'cases-groups.js',
  'cases-docs.js',
  // The resolver is the right instrument for these two, and for opposite
  // reasons. `cases-paths.js` is mostly about lines nothing on this machine can
  // open — a drive letter, a UNC share — and resolving one costs no filesystem
  // at all, so the question "which operator did this token land in" can be asked
  // of every spelling. `cases-frames.js` is the other way round: its subject is
  // invisible to a resolver, and it is here so that its rules are at least
  // parsed the same on both sides.
  'cases-paths.js',
  'cases-frames.js',
];

function casesCorpus() {
  const base = Number(process.env.PORT_BASE || 18700);
  const origin = base + 2;
  const out = [];
  for (const file of CASE_FILES) {
    let cases;
    try {
      cases = require('./' + file);
    } catch (e) {
      console.log(`  (skipped ${file}: ${e.message})`);
      continue;
    }
    for (const c of cases) {
      const request = c.request || {};
      const url = request.url || `http://127.0.0.1:${origin}${request.path || '/echo'}`;
      // A case may install several named groups; the resolver here reads one
      // text, so they are concatenated in the order the harness enables them.
      const groups = (c.groups || [])
        .filter((g) => g.selected !== false)
        .map((g) => g.value || '');
      // A corpus may carry a JSON body as an object and a value as one too;
      // both sides want the text a request would actually contain.
      const text = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
      const headers = {};
      for (const [k, v] of Object.entries(request.headers || {})) headers[k] = text(v);
      const values = {};
      for (const [k, v] of Object.entries(c.values || {})) values[k] = text(v);
      out.push({
        rules: [c.rules || '', ...groups].filter(Boolean).join('\n'),
        src: `${file}: ${c.name}`,
        url,
        method: request.method,
        headers,
        body: request.body == null ? undefined : text(request.body),
        values,
      });
    }
  }
  return out;
}

// Where a rule line is asked about. Every case gets the fixed set — so that a
// pattern which matches nothing is *seen* to match nothing on both sides — plus
// URLs derived from its own pattern, without which most lines would never match
// at all.
const FIXED_URLS = [
  'http://www.example.com/',
  'http://www.example.com/index.html?a=1',
  'https://www.example.com/api/list?id=2',
  'http://test.example.com:8080/path/app.js',
  'http://127.0.0.1:8080/cgi-bin/x',
  'ws://www.example.com/socket',
  'wss://www.example.com/socket',
  'tunnel://www.example.com:443',
  // Shapes a pattern can get wrong on its own: a port where the scheme's own
  // was implied, a deeper path, an upper-case host, a path that is a prefix of
  // another, and a query where the pattern may have one too.
  'http://www.example.com:8080/api',
  'https://www.example.com:8443/api/list',
  'http://www.example.com/api/v2/users/42?q=x&r=y',
  'http://WWW.EXAMPLE.COM/API',
  'http://www.example.com/apixel',
  'http://www.example.com/api/',
  'http://sub.www.example.com/a',
  'http://example.com/a',
];

function derivedUrls(line) {
  const token = line.trim().split(/\s+/)[0] || '';
  const urls = [];
  const add = (url) => {
    if (!url || urls.includes(url)) return;
    // A shape derived from a pattern is not always a URL — `tunnel://h:443`
    // with a suffix stuck on it is not one, and asking either side about a
    // string neither can parse measures the derivation, not the proxies.
    try {
      new URL(url);
    } catch {
      return;
    }
    urls.push(url);
  };
  // A regular-expression or a filter-looking first token names no host.
  if (/^[/^$!]/.test(token) || token.includes('://') === false) {
    if (/^[a-z0-9*.-]+(:\d+)?(\/|$)/i.test(token)) {
      const [hostAndPath] = [token];
      const base = hostAndPath.replace(/^\*+\./, 'sub.').replace(/\*+/g, 'x');
      const bare = base.replace(/\/$/, '');
      add('http://' + bare);
      add('http://' + bare + '/');
      add('http://' + bare + '/page.html?q=1');
      add('http://' + bare + '/deep/er/page.html');
      add('http://' + bare + 'suffix');
      add('https://' + bare);
      add('ws://' + bare + '/socket');
    }
  }
  if (/^(https?|wss?|tunnel):\/\//.test(token)) {
    const base = token.replace(/\*+\./, 'sub.').replace(/\*+/g, 'x');
    add(base);
    add(base.replace(/\/$/, '') + '/page.html?q=1');
    add(base.replace(/\/$/, '') + '/deep/er/page.html');
    add(base.replace(/\/$/, '') + 'suffix');
  }
  return urls;
}

// ── Run ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {
    limit: 3, values: false, grep: null, quiet: false,
    fromCases: false, generated: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--values') args.values = true;
    else if (arg === '--from-cases') args.fromCases = true;
    else if (arg === '--generated') args.generated = true;
    else if (arg === '--quiet') args.quiet = true;
    else if (arg === '--limit') args.limit = parseInt(argv[++i], 10);
    else if (arg === '--grep') args.grep = new RegExp(argv[++i], 'i');
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  assertVocabulary();
  const corpus = args.generated
    ? require('./cases-generated.js')
    : args.fromCases
      ? casesCorpus()
      : CORPUS;
  const cases = corpus.filter(
    (c) =>
      (!args.grep || args.grep.test(c.rules)) &&
      // Lines whose answer is not a property of the rules: `chance:` throws a
      // die per resolution, `${now}` is the clock, and `${version}` is whichever
      // proxy answered — 2.10.8 there, this crate's version here.
      !/\bchance:/.test(c.rules) &&
      !/\$\{(?:now|version)\}/.test(c.rules)
  );

  const queries = [];
  for (const testCase of cases) {
    // A case that names its own request is asked about that one — the
    // hand-written corpora do — and one that is only a rule line is asked about
    // every URL that could plausibly meet it.
    const urls = testCase.url
      ? [testCase.url]
      : [...FIXED_URLS, ...derivedUrls(testCase.rules)];
    for (const url of urls) {
      queries.push({
        rules: testCase.rules,
        url,
        method: testCase.method || 'GET',
        headers: testCase.headers || {},
        body: testCase.body,
        values: testCase.values || {},
        client_ip: testCase.clientIp,
        response: testCase.response,
      });
    }
  }

  console.log(
    `rules-oracle: ${cases.length} ` +
      `${args.fromCases ? 'bench cases' : args.generated ? 'generated cases' : 'rule lines'}` +
      ` × urls = ${queries.length} questions`
  );

  const answers = portResolve(queries);

  const classes = new Map();
  let differing = 0;
  let valueDiffs = 0;
  let matched = 0;
  let folded = 0;
  let declaredCount = 0;
  let declaredValues = 0;

  for (let i = 0; i < queries.length; i++) {
    const query = queries[i];
    const answer = answers[i];
    if (answer.error) {
      record(classes, 'explain error: ' + answer.error, query, '', '');
      differing++;
      continue;
    }
    let upstream;
    try {
      upstream = upstreamResolve(
        query.rules,
        query.values,
        makeReq(query.url, query.method, query.headers, query.body, query.client_ip),
        query.response
      );
    } catch (e) {
      record(classes, 'whistle threw: ' + e.message, query, '', '');
      differing++;
      continue;
    }

    const ours = collapse(answer.ops.filter((op) => !IGNORED_BUCKETS.has(op.protocol)));
    const theirs = upstream.filter((op) => !IGNORED_BUCKETS.has(op.bucket));
    if (ours.length || theirs.length) matched++;

    const left = tally(theirs.map(upstreamKey));
    const right = tally(ours.map(portKey));
    let delta = diffTallies(left, right);
    if (delta.length && isHostCaseFolding(query, right)) {
      folded++;
      delta = [];
    }
    const declared = delta.length && DECLARED.find((d) => d.match(delta, query));
    if (declared) {
      declaredCount++;
      // The values are not compared either: a difference in *which* operators
      // matched carries its own difference in what they hold.
      continue;
    }
    if (delta.length) {
      differing++;
      record(
        classes,
        delta.join(', '),
        query,
        theirs.map((op) => op.matcher).join(' '),
        ours.map((op) => `${op.protocol}://${op.value}`).join(' ')
      );
      continue;
    }

    if (
      args.values &&
      !isDeferredTemplate(ours) &&
      !isUnansweredKey(ours) &&
      !isDeclaredValue(ours)
    ) {
      const scheme = new URL(query.url).protocol.replace(':', '');
      const leftValues = valuesOf(theirs, true, scheme);
      const rightValues = valuesOf(ours, false, scheme);
      const bad = [];
      let excused = false;
      for (const [key, list] of leftValues) {
        const other = rightValues.get(key) || [];
        if (JSON.stringify(list) === JSON.stringify(other) || isBracketQuirk(list, other)) continue;
        if (isSeparatorOnly(key, list, other)) {
          excused = true;
          continue;
        }
        bad.push(`${key}: ${JSON.stringify(list)} vs ${JSON.stringify(other)}`);
      }
      if (excused && !bad.length) declaredValues++;
      if (bad.length) {
        valueDiffs++;
        record(classes, 'value ' + bad[0].split(':')[0], query, bad.join('; '), '');
      }
    }
  }

  const classList = [...classes.entries()].sort(
    (a, b) => b[1].count - a[1].count
  );
  if (!args.quiet) {
    for (const [label, entry] of classList) {
      console.log(`\n[${entry.count}] ${label}`);
      for (const example of entry.examples.slice(0, args.limit)) {
        console.log(`    rule: ${example.rules}`);
        console.log(`    url:  ${example.url}`);
        if (example.left) console.log(`    whistle: ${example.left}`);
        if (example.right) console.log(`    rs:      ${example.right}`);
      }
    }
  }

  console.log(
    `\nquestions: ${queries.length}, answered by a rule: ${matched}, ` +
      `differing: ${differing}, value differences: ${valueDiffs}, ` +
      `host-case folds: ${folded}, declared: ${declaredCount}, ` +
      `declared values: ${declaredValues}, classes: ${classList.length}`
  );
  // A value difference is as much a failure as a matcher difference. This used
  // to return `differing` alone, so `--values` printed a wrong value and still
  // exited 0 — one sat in `--from-cases` unnoticed until the gate read the code.
  return differing + valueDiffs;
}

// Divergences this port has **declared**, each with the reason and each scoped
// so it cannot excuse anything else. The same discipline `harness.js` keeps:
// a matcher wide enough to swallow a real difference is worse than no matcher.
const DECLARED = forVersion([
  {
    // `host:` / `host=` is a *filter condition*, and upstream answers it from
    // the address it will dial rather than from the request's host — so it says
    // nothing about which rule applies. This port answers it from the request's
    // host. Declared in `docs/RULES.md`, and `harness.js` declares the same one
    // for the live bench.
    match: (delta, query) =>
      /(?:include|exclude)?Filter:\/\/[^\s]*\bhost[:=]/.test(query.rules),
    why: 'host: / host= matches the request host here, by design',
  },
  {
    // Two pattern shapes upstream can only get wrong, because it compares the
    // pattern with the URL **as text** — both are in `docs/RULES.md` under
    // "Where patterns differ from upstream", and each turns a rule somebody
    // wrote into one that fires never, so no rules file can be relying on the
    // upstream answer.
    //
    //   * `example.com:80` on an http request: `getFullUrl` strips the default
    //     port before anything is compared, so the URL never contains `:80`;
    //   * `[::1]` with no port: `removePort` cuts at the first `:` after the
    //     scheme, which is inside the brackets.
    match: (delta, query) =>
      query.rules
        .split('\n')
        .some((line) => /^\s*(?:\[[0-9a-fA-F:]+\]|\S+:(?:80|443))(?:\s|$)/.test(line)),
    why: 'a default port and a bracketed IPv6 host match here; upstream compares text',
  },
  {
    // `ignore://socks` drops the proxy that matched, and upstream's `getProxy`
    // then returns before it would consult the PAC rule at all
    // (`ignoreProxy`, `_original/lib/rules/index.js:160-171,:238-241`). The
    // effect is the same — the request goes direct — but upstream reaches it
    // *after* resolution, so `_rules.pac` still holds the operator while this
    // port has already dropped it (`matcher::ignore_upstream_proxies`).
    match: (delta, query) =>
      delta.length === 1 &&
      /^pac: whistle \d+ vs rs 0$/.test(delta[0]) &&
      /\b(ignore|skip):\/\//.test(query.rules),
    why: 'an ignored proxy takes the PAC fallback with it, one step earlier',
  },
]);

// The one **declared** divergence this bench meets: a domain pattern is matched
// against the request's host with the case folded here, and as written
// upstream. whistle's `indexOf` is over the URL text
// (`rules.js:1078-1083`), so a client that sends `Host: EXAMPLE.COM` gets none
// of the rules written for `example.com` — measured, and it is the direction
// that fails *open*: a rule meant to intercept a host stops applying because
// somebody shifted a key. Recorded in `docs/RULES.md` rather than copied.
//
// Proved rather than assumed: the same question is asked again with the host
// lower-cased, and only an upstream answer that then matches this port's counts
// as the case folding. Anything else is a real difference.
function isHostCaseFolding(query, right) {
  // Either side of the comparison may carry the capitals: the request's host,
  // or the pattern that names it. Both are lowered before upstream is asked
  // again — the pattern only in the tokens that *are* patterns, since an
  // operator's value has a case of its own.
  const at = query.url.indexOf('://') + 3;
  const host = query.url.slice(at).split(/[/?#]/)[0];
  const lowered =
    query.url.slice(0, at) + host.toLowerCase() + query.url.slice(at + host.length);
  const rules = query.rules
    .split('\n')
    .map((line) =>
      line.replace(/^(\s*)(\S+)/, (all, space, token) =>
        token.includes('://') ? all : space + token.toLowerCase()
      )
    )
    .join('\n');
  if (lowered === query.url && rules === query.rules) return false;
  let ops;
  try {
    ops = upstreamResolve(
      rules,
      query.values,
      makeReq(lowered, query.method, query.headers, query.body, query.client_ip),
      query.response
    );
  } catch {
    return false;
  }
  const left = tally(
    ops.filter((op) => !IGNORED_BUCKETS.has(op.bucket)).map(upstreamKey)
  );
  return diffTallies(left, right).length === 0;
}

function record(classes, label, query, left, right) {
  const entry = classes.get(label) || { count: 0, examples: [] };
  entry.count++;
  if (entry.examples.length < 20) {
    entry.examples.push({ rules: query.rules, url: query.url, left, right });
  }
  classes.set(label, entry);
}

if (require.main === module) {
  const differing = main();
  // whistle's modules leave timers behind, and a bench that hangs after it has
  // printed its answer reads as a bench that never finished.
  process.exit(differing ? 1 : 0);
}

module.exports = { upstreamResolve, makeReq, portResolve, loadUpstreamRules };
