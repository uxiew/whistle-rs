#!/usr/bin/env node
// Upstream's own test suite — whistle v2.10.8's `test/` directory, 82 unit
// files, 280 calls that assert something — run against whistle-rs.
//
//   node upstream-suite.js                          # the gate: three runs, one verdict
//   node upstream-suite.js --target rs --only file,reqHeaders --verbose
//   node upstream-suite.js --target whistle         # upstream, as it tests itself
//
// **What the gate asks.** Two thirds of the calls lean on the suite's eight
// Node plugins, which this port does not run (a stated non-goal). The gate
// hands both proxies the rules those plugins ship as ordinary rules
// (`--fixture flat`, see `flattenPlugins`), asks whistle first — twice, once
// with the network and once with every name it looks up failing — and keeps
// the calls that pass both times: the ones the suite's own rules and servers
// decide, whatever the network does today. whistle-rs must pass each of those,
// or the call is declared in `DECLARED` below with its reason; a declared call
// that passes is stale and fails the gate as well.
//
// Options:
//   --target rs|whistle   one run against one proxy instead of the gate
//   --fixture plugins|flat|bare   what stands in for the plugins, for one run:
//                         `plugins` installs them (whistle only), `flat` their
//                         rules, `bare` nothing (default: plugins for whistle,
//                         flat for rs)
//   --no-network          whistle only: every DNS lookup fails
//   --control             the gate also runs whistle with its plugins and says
//                         whether upstream still passes its own suite
//   --only a,b            run only these units (file names without .test.js)
//   --suite DIR           an upstream checkout to take `test/` from, instead of
//                         fetching the pinned commit
//   --json FILE           write the results there
//   --verbose             print every call, not only the ones that failed
//   --print-fixture       print the flattened plugin rules and stop
//
// Exit status: 0 passed; 1 an undeclared failure or a stale declaration (for
// one run: any failure); 2 it could not start — a port taken, the binary
// missing, the suite not fetched.
//
// **How it runs the units.** Upstream's `index.test.js` starts whistle
// in-process, then runs the units thirty at a time, and an assertion that
// fails throws out of a response callback and ends the process: the whole
// report is "exit 0" or a stack trace. That is fine for a suite that always
// passes, and useless for one that is expected to fail in places. So this
// keeps every file of `test/` as it is and replaces only the driver:
//   * the same fixture servers on the same fixed ports, the same rules, values,
//     certificates and startup options (transcribed from `index.test.js`,
//     line numbers below);
//   * the units one at a time, in upstream's order;
//   * `util.request`, `util.proxy` and `util.requestWS` wrapped, so each call
//     is one row of the report: its assertions ran and held, one of them threw
//     (with the message and the line of the unit), or no answer came within
//     the unit's time. An assertion that throws asynchronously is attributed
//     through `AsyncLocalStorage`, which Node keeps available in the
//     `uncaughtException` handler.
//
// The ports are upstream's and cannot move: the units and `rules.txt` spell
// out 6666, 18080, 5566 and the rest in their URLs. They are checked before
// anything starts.

'use strict';

// `request` sends the suite's tunnel calls without a proxy option, and then
// takes one from the environment — a developer's shell proxy would carry them
// somewhere else entirely. Gone before anything is loaded.
for (const k of ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']) {
  delete process.env[k];
}

const { AsyncLocalStorage } = require('async_hooks');
const { spawn, execFileSync } = require('child_process');
const dgram = require('dgram');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const { createRequire } = require('module');
const { StringDecoder } = require('string_decoder');
const { parse: parseUrl } = require('url');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..', '..');
const RS_BIN = process.env.RS_BIN || path.join(REPO, 'target', 'debug', 'whistle-rs');

/** whistle v2.10.8, the version `package.json` installs; `git rev-parse v2.10.8`. */
const UPSTREAM_REPO = 'https://github.com/avwo/whistle';
const UPSTREAM_COMMIT = '1df0805f09fd979e0e31fd6eab99ca97239ac1ec';

// ── arguments ─────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const option = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
};
/** `undefined` is the gate. */
const TARGET = option('--target');
if (TARGET !== undefined && !['rs', 'whistle'].includes(TARGET)) {
  console.error('usage: node upstream-suite.js [--target rs|whistle] [--fixture …] [--only a,b] [--suite DIR] [--json FILE] [--verbose]');
  process.exit(2);
}
const ONLY = option('--only') ? new Set(option('--only').split(',')) : null;
const VERBOSE = argv.includes('--verbose');
/** What stands in for the suite's plugins — see the options above. */
const FIXTURE = option('--fixture') || (TARGET === 'whistle' ? 'plugins' : 'flat');
if (!['plugins', 'flat', 'bare'].includes(FIXTURE) || (FIXTURE === 'plugins' && TARGET !== 'whistle')) {
  console.error('--fixture is plugins (whistle only), flat or bare');
  process.exit(2);
}
const FLAT_GROUP = 'plugins-private-rules';
const JSON_OUT = option('--json');
/** Per unit. The slowest upstream unit (`reqSpeed`) takes about four seconds. */
const UNIT_TIMEOUT = Number(process.env.UNIT_TIMEOUT || 20000);

// ── the suite ─────────────────────────────────────────────────────────────

/**
 * `test/` of the pinned commit, fetched once into `target/` and reused.
 *
 * The npm package does not ship `test/`, so it comes from git. Fetching the
 * commit by its id is what makes it the commit: git checks every object
 * against its hash, which a tarball download would not.
 */
function suiteDir() {
  if (option('--suite')) return path.resolve(option('--suite'), 'test');
  const cache = path.join(REPO, 'target', 'upstream-suite', UPSTREAM_COMMIT);
  const dir = path.join(cache, 'test');
  if (fs.existsSync(path.join(dir, 'index.test.js'))) return dir;
  const git = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-upstream-git-'));
  try {
    const run = (...args) => execFileSync('git', ['-C', git, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
    run('init', '-q');
    console.log(`fetching test/ of ${UPSTREAM_REPO} at ${UPSTREAM_COMMIT.slice(0, 7)}…`);
    run('fetch', '-q', '--depth', '1', UPSTREAM_REPO, UPSTREAM_COMMIT);
    const tar = path.join(git, 'test.tar');
    run('archive', '--format=tar', '-o', tar, UPSTREAM_COMMIT, 'test');
    fs.mkdirSync(cache, { recursive: true });
    execFileSync('tar', ['-xf', tar, '-C', cache]);
  } finally {
    fs.rmSync(git, { recursive: true, force: true });
  }
  return dir;
}

/**
 * A scratch copy of the suite, laid out the way its relative requires expect.
 *
 *   W/test/          the suite, copied (it writes `.whistle/` into itself)
 *   W/index.js       `require('../index')` — whistle
 *   W/lib → whistle/lib    `require('../lib/config')`, and the four units that
 *                          test upstream's own modules
 *   W/biz → whistle/biz    `others` calls one function from it
 *   W/node_modules → ./node_modules    should, request, ws@1, sockx…
 */
function workDir(src) {
  const whistle = path.dirname(require.resolve('whistle/package.json'));
  const w = fs.mkdtempSync(path.join(process.env.DIFF_STATE || os.tmpdir(), 'whistle-upstream-suite-'));
  // Not a `node_modules` or `.whistle` an existing checkout may carry: the
  // dependencies are ours, and `.whistle` is state from someone's last run.
  fs.cpSync(src, path.join(w, 'test'), {
    recursive: true,
    filter: (p) => !/[\\/](node_modules|\.whistle)$/.test(p),
  });
  fs.writeFileSync(path.join(w, 'index.js'), `module.exports = require(${JSON.stringify(whistle)});\n`);
  fs.symlinkSync(path.join(whistle, 'lib'), path.join(w, 'lib'));
  fs.symlinkSync(path.join(whistle, 'biz'), path.join(w, 'biz'));
  fs.symlinkSync(path.join(HERE, 'node_modules'), path.join(w, 'node_modules'));
  return w;
}

// ── results ───────────────────────────────────────────────────────────────

const als = new AsyncLocalStorage();
/** The unit running now; everything else is attributed through `als`. */
let current = null;
const units = [];

function describe(kind, options) {
  if (kind === 'requestWS') return 'WS ' + options;
  if (kind === 'proxy') return 'CONNECT+GET ' + options;
  if (typeof options === 'string') return 'GET ' + options;
  const method = (options.method || 'GET').toUpperCase();
  return method + ' ' + options.url + (options.isTunnel ? ' (tunnel)' : '');
}

/** The first frame inside a unit file: which assertion it was. */
function where(err) {
  const m = /units[\\/]([^\\/]+)\.test\.js:(\d+)/.exec((err && err.stack) || '');
  return m ? `${m[1]}.test.js:${m[2]}` : '';
}

/**
 * Who wrote the body a call got back, read off its shape: the echo servers of
 * `index.test.js` say `type: 'server'`; the `whistle.test` plugin's server
 * (`plugins/whistle.test/lib/server.js`) adds the `ruleValue` upstream hands
 * a plugin; anything else is a rule's own body or an error page.
 */
function answeredBy(kind, args) {
  const data = kind === 'request' ? args[1] : kind === 'requestWS' ? args[0] : undefined;
  if (!data || typeof data !== 'object') return typeof data === 'string' ? 'text' : 'none';
  if ('ruleValue' in data) return 'plugin';
  if (data.type === 'server') return 'fixture';
  return 'other';
}

function settle(call, state, err) {
  if (call.state !== 'pending') {
    // An answer after the unit gave up on it, or a second assertion failing
    // after the first already did: noted, not counted twice.
    if (state === 'fail' && call.state !== 'fail') call.late = String(err && err.message);
    return;
  }
  call.state = state;
  if (err) {
    call.error = String(err.message || err).slice(0, 600);
    call.at = where(err);
  }
  const unit = call.unit;
  unit.outstanding.delete(call);
  if (unit.outstanding.size === 0 && unit.graceOver && unit.finish) unit.finish();
}

function instrument(util) {
  for (const kind of ['request', 'proxy', 'requestWS']) {
    const orig = util[kind];
    util[kind] = function (options, callback) {
      const store = als.getStore();
      const unit = (store && store.unit) || current;
      const call = { unit, kind, desc: describe(kind, options), state: 'pending', error: null, at: '' };
      unit.calls.push(call);
      // A call without a callback asserts nothing, so it cannot fail, and it
      // is left exactly as it was: handing upstream's helper a callback would
      // make it JSON-parse a body it otherwise never looks at.
      if (typeof callback !== 'function') {
        call.state = 'sent';
        return orig.call(this, options, callback);
      }
      unit.outstanding.add(call);
      const wrapped = function (...args) {
        call.answeredBy = answeredBy(kind, args);
        if (kind === 'proxy' && args[0]) call.transport = String(args[0].code || args[0].message);
        try {
          callback.apply(this, args);
          settle(call, 'pass');
        } catch (e) {
          settle(call, 'fail', e);
        }
      };
      return als.run({ unit, call }, () => orig.call(this, options, wrapped));
    };
  }
}

/**
 * Put a tap on the `request` module before `util.test.js` loads it, so a call
 * records its status and transport error even when upstream's helper throws
 * on the body before the unit's callback ever sees them — a 502 page is not
 * JSON, and "not valid JSON" alone says nothing about why.
 */
function tapRequest(wreq) {
  const id = wreq.resolve('request');
  const request = wreq('request');
  const tap = (fn) => function (options, cb) {
    const store = als.getStore();
    const call = store && store.call;
    if (call && typeof cb === 'function') {
      const inner = cb;
      cb = function (err, res, body, ...rest) {
        if (err) call.transport = String(err.code || err.message || err);
        if (res) call.status = res.statusCode;
        if (res && res.statusCode >= 400 && typeof body === 'string') call.body = body.slice(0, 240);
        return inner.call(this, err, res, body, ...rest);
      };
    }
    return fn.call(this, options, cb);
  };
  const tapped = Object.assign(tap(request), request);
  tapped.defaults = (...args) => tap(request.defaults(...args));
  require.cache[id].exports = tapped;
}

function onUncaught(err) {
  const store = als.getStore();
  const call = store && store.call;
  if (call) return settle(call, 'fail', err);
  const unit = (store && store.unit) || current;
  if (unit) {
    unit.errors.push({ error: String((err && err.message) || err).slice(0, 600), at: where(err) });
  } else {
    console.error('uncaught outside any unit:', err);
  }
}

/**
 * Only this handler, for both events. whistle, loaded in-process as the
 * control, installs its own that prints a report and exits
 * (`lib/index.js:277-278`) — which is upstream's harness's pass/fail signal,
 * and would end this one at the first failed assertion.
 */
function ownExceptions() {
  for (const event of ['uncaughtException', 'unhandledRejection']) {
    process.removeAllListeners(event);
    process.on(event, onUncaught);
  }
}
ownExceptions();

// ── fixtures (index.test.js) ──────────────────────────────────────────────

// Loopback only, where `index.test.js` takes every interface: nothing here is
// for another machine, and `run.js` promises as much for all it starts.
const listen = (server, port) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, '127.0.0.1', () => resolve(server));
});

/**
 * The servers `index.test.js:40-203` starts beside the proxy, one for one:
 * an echo origin, an HTTPS origin, a WebSocket echo, two SOCKS5 servers and a
 * forwarding HTTP proxy. The bodies they answer with are what the units parse.
 */
async function startFixtures(wreq, W, config) {
  const WebSocketServer = wreq('ws').Server;
  const socks = wreq('sockx');
  const noop = () => {};

  const wss = new WebSocketServer({ port: config.wsPort, host: '127.0.0.1' });
  wss.on('connection', (ws) => {
    const req = ws.upgradeReq;
    ws.on('message', (msg) => {
      ws.send(JSON.stringify({ type: 'server', method: req.method, headers: req.headers, body: msg }, null, '\t'));
    });
  });

  const origin = http.createServer((req, res) => {
    req.on('error', noop);
    res.on('error', noop);
    let body = '';
    const decoder = new StringDecoder('utf8');
    req.on('data', (d) => { body += decoder.write(d); });
    req.on('end', () => {
      body += decoder.end();
      res.end(JSON.stringify({ type: 'server', url: req.url, method: req.method, headers: req.headers, body }, null, '\t'));
    });
  });

  const tlsOrigin = https.createServer({
    key: fs.readFileSync(path.join(W, 'test/assets/certs/root.key')),
    cert: fs.readFileSync(path.join(W, 'test/assets/certs/_root.crt')),
  }, (req, res) => {
    if (req.url.indexOf('test-remote.rules') !== -1) {
      return res.end('str2.w2.org/index.html file://`(${search.replace(a,b)})`\nstr2.w2.org/index2.html file://`(${query.replace(/a/g,b)})`');
    }
    res.end(JSON.stringify({ headers: req.headers, body: 'test' }));
  });

  // SOCKS: 443 goes to the HTTPS origin, 18081 to the WebSocket echo, and
  // anything else is answered with the server's own port.
  //
  // **The one place this departs from `index.test.js`**, and only in when
  // things happen. As written there, both servers race their client:
  //   * sockx's `accept(true)` reports success and sets the socket flowing on
  //     the next tick (`sockx/lib/server.js:109-120`), while the pipe to the
  //     origin is attached only once that connection is up — whatever the
  //     client sends in between, a TLS ClientHello, is emitted to nobody and
  //     lost, and the call hangs;
  //   * the canned answer is written the moment the tunnel opens, before the
  //     client has sent its request, which an HTTP client may refuse as a
  //     response to nothing ("received unexpected message from connection").
  // whistle's client happens to lose both races; this port's does not, and
  // failed about half of the SOCKS calls at random. Here the socket is paused
  // until the pipe takes it, and the answer waits for the request. What the
  // servers answer, and every assertion, is unchanged.
  const pipeTo = (socket, port) => {
    process.nextTick(() => socket.pause()); // after sockx's own resume
    const client = net.connect({ host: '127.0.0.1', port }, () => socket.pipe(client).pipe(socket));
  };
  const answerPort = (socket, port) => {
    const body = JSON.stringify({ port });
    socket.once('data', () => socket.end(['HTTP/1.1 200 OK', 'Connection: close', 'Content-Type: text/plain;charset=utf8',
      'Content-Length: ' + Buffer.byteLength(body), '', body].join('\r\n')));
  };
  const socksServer = socks.createServer((info, accept) => {
    const socket = accept(true);
    if (!socket) return;
    if (info.dstPort === 443) return pipeTo(socket, config.httpsPort);
    if (info.dstPort === 18081) return pipeTo(socket, 18081);
    answerPort(socket, config.socksPort);
  });
  const authSocksServer = socks.createServer((info, accept) => {
    const socket = accept(true);
    if (!socket) return;
    if (info.dstPort === 443) return pipeTo(socket, config.httpsPort);
    answerPort(socket, config.authSocksPort);
  });
  socksServer.useAuth(socks.auth.None());
  authSocksServer.useAuth(socks.auth.UserPassword((user, password, cb) => cb(user == 'test' && password == 'hello1234')));

  // A plain forwarding proxy: every request goes to 127.0.0.1 on its own port.
  const upstreamProxy = http.createServer((req, res) => {
    const fullUrl = /^http:/.test(req.url) ? req.url : 'http://' + req.headers.host + req.url;
    const options = parseUrl(fullUrl);
    delete options.hostname;
    options.host = '127.0.0.1';
    options.method = req.method;
    options.headers = req.headers;
    const client = http.request(options, (r) => r.pipe(res));
    req.pipe(client);
  });
  upstreamProxy.on('connect', (req, socket) => {
    const tunnelUrl = 'tunnel://' + (/^[^:/]+:\d+$/.test(req.url) ? req.url : req.headers.host);
    const options = parseUrl(tunnelUrl);
    const client = net.connect({ host: '127.0.0.1', port: options.port || 443 }, () => {
      socket.pipe(client).pipe(socket);
      socket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: whistle/test\r\n\r\n');
    });
  });

  await Promise.all([
    new Promise((r) => wss._server ? wss._server.once('listening', r) : r()),
    listen(origin, config.serverPort),
    listen(tlsOrigin, config.httpsPort),
    listen(socksServer, config.socksPort),
    listen(authSocksServer, config.authSocksPort),
    listen(upstreamProxy, config.proxyPort),
  ]);
}

// ── the plugins' rules, flattened ─────────────────────────────────────────

/** The suite's plugins by the short names their protocols go by. */
const PLUGIN_NAMES = ['test', 'test1', 'test2', 'test3', 'test-values', 'pass', 'pipe-http', 'pipe-ws', 'pipe-tunnel'];

/**
 * The rules the suite's plugins carry as files, turned into ordinary rules
 * both proxies can take.
 *
 * Two thirds of the suite's calls lean on its eight Node plugins
 * (`test/plugins/`), mostly not for their code but for the rules they ship:
 * `rules.txt` applies to every request while the plugin is installed, and
 * `_rules.txt` to the requests the plugin takes on. Running upstream's plugin
 * API is not a goal of this port; running the rules is. So `--fixture flat`
 * gives both proxies the same translation of those files:
 *   * a token that hands the request to a plugin — `whistle.x://`,
 *     `plugin://`, `pipe://` and its `@name`, the bare `test://` short form,
 *     a `%x=` plugin variable — is dropped, and a line with nothing left but
 *     its pattern goes with it;
 *   * a relative path that exists under the plugin's own directory, which is
 *     what upstream resolves it against, becomes absolute;
 *   * `_rules.txt` goes in first, in a group of its own, because upstream
 *     merges a plugin's private rules over the ones that matched; `rules.txt`
 *     goes in last, after Default.
 * Which calls this can decide is then measured, not assumed: only a call that
 * passes against whistle under the same translation counts (see `main`).
 */
function flattenPlugins(W) {
  const root = path.join(W, 'test', 'plugins');
  // `@name` beside a `pipe://` is the pipe plugins' own argument, not an
  // include: it goes with the token it qualifies.
  const pluginToken = new RegExp(`^(?:(?:whistle|plugin)\\.[\\w-]+:\\/\\/|plugin:\\/\\/|pipe:\\/\\/|%|@|(?:${PLUGIN_NAMES.join('|')}):\\/\\/)`);
  const translate = (text, dir) => text.split('\n').map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('```')) return line;
    const tokens = trimmed.split(/\s+/);
    const kept = tokens.filter((t) => !pluginToken.test(t)).map((t) => absolutize(t, dir));
    // Every token but one was a plugin's: the line said nothing else.
    if (kept.length < 2 && kept.length !== tokens.length) return '';
    return kept.join(' ');
  }).join('\n');
  const absolutize = (token, dir) => {
    const m = /^([\w.-]+:\/\/)(<?)([^{(<`$/][^>]*?)(>?)$/.exec(token);
    if (!m) return token;
    const file = path.join(dir, m[3]);
    return fs.existsSync(file) ? m[1] + m[2] + file + m[4] : token;
  };
  const read = (name, file) => {
    const p = path.join(root, name, file);
    return fs.existsSync(p) ? `# ${name}/${file}\n` + translate(fs.readFileSync(p, 'utf8'), path.join(root, name)) : '';
  };
  const names = fs.readdirSync(root).filter((n) => n.startsWith('whistle.')).sort();
  return {
    private: names.map((n) => read(n, '_rules.txt')).filter(Boolean).join('\n\n'),
    global: names.map((n) => read(n, 'rules.txt')).filter(Boolean).join('\n\n'),
  };
}

// ── the proxy under test ──────────────────────────────────────────────────

/**
 * `index.test.js:85-112`: what whistle is started with — plus, under
 * `--fixture flat`, the plugins' rules (see `flattenPlugins`). The group of
 * private rules is the first key so that it is the first group upstream adds,
 * and resolves before `test`, as it is created first here too.
 */
function upstreamOptions(W, config, util) {
  const values = util.getValues();
  values['options.html'] = { method: 'options' };
  const flat = FIXTURE === 'flat' ? flattenPlugins(W) : null;
  const rules = {};
  if (flat) rules[FLAT_GROUP] = { rules: flat.private, enable: true };
  rules.Default = util.readText('rules.txt') + (flat ? '\n\n' + flat.global : '');
  rules.test = {
    rules: 'test.options.com file://{options.html}\n@'
      + path.join(W, 'test', 'assets/files/rules.txt')
      + '\n@https://127.0.0.1:' + config.httpsPort + '/test-remote.rules'
      + '\ntest.key.test.w2.org/test file://{test.txt}\n``` test.txt\ntest\n```',
    enable: true,
  };
  rules.abc = '123';
  return {
    port: config.port,
    host: '127.0.0.1', // as the fixtures, see `listen`
    storage: 'test_',
    httpPort: config.httpServerPort,
    httpsPort: config.httpsServerPort,
    certDir: path.join(W, 'test/assets/certs'),
    debugMode: true,
    localUIHost: 'local.whistle.com|local2.whistle.com&localn.whistle.com',
    pluginHost: 'test=test.local.whistle.com|b.test.local.whistle.com&test3.local.whistle.com,',
    mode: 'enableRequestHeaderRules',
    rules,
    values,
    copy: true,
  };
}

/**
 * A DNS server that knows no names: every query gets NXDOMAIN at once.
 *
 * The suite's hostnames are real — `*.test.whistlejs.com`, `filter.com` — and
 * a call no rule answers goes out to wherever they resolve today. With
 * `--no-network` whistle asks this instead (its `dnsServer` option does not
 * fall back to the system resolver, `lib/rules/dns.js:80-85`), so a call can
 * only pass on what the suite itself serves.
 */
function startSinkhole() {
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, peer) => {
    if (msg.length < 12) return;
    // Header, then the question as asked: the name's labels up to the zero
    // byte, then type and class. Anything after it (an EDNS record) is dropped
    // along with the counts that announced it.
    let end = 12;
    while (end < msg.length && msg[end] !== 0) end += msg[end] + 1;
    end += 5;
    if (end > msg.length) return;
    const res = Buffer.from(msg.subarray(0, end));
    res[2] = 0x80 | (msg[2] & 0x01); // a response; recursion-desired echoed
    res[3] = 0x80 | 3; // recursion available; NXDOMAIN
    res.fill(0, 6, 12); // no answers, authorities or additionals
    sock.send(res, peer.port, peer.address);
  });
  return new Promise((resolve) => sock.bind(0, '127.0.0.1', () => {
    sock.unref();
    resolve(sock.address().port);
  }));
}

async function startWhistle(W, config, util) {
  const fse = require('fs-extra2');
  const whistlePath = path.join(W, 'test');
  fse.removeSync(path.join(whistlePath, '.whistle'));
  if (FIXTURE === 'plugins') {
    fse.copySync(path.join(whistlePath, 'plugins'), path.join(whistlePath, '.whistle/node_modules'));
  }
  const start = require(path.join(W, 'index.js'));
  const options = upstreamOptions(W, config, util);
  if (argv.includes('--no-network')) options.dnsServer = '127.0.0.1:' + await startSinkhole();
  // Upstream selects one rule group at a time unless told otherwise, and
  // selecting `test` would switch the plugins' group off again
  // (`selectRulesFile`, `lib/rules/util.js:148-161`). This port has no
  // single-select mode, so the comparison is made with it on — as
  // `cases-groups.js` makes it. Set before the groups load (`lib/index.js:74-80`).
  if (FIXTURE === 'flat') options.allowMultipleChoice = true;
  const proxy = await new Promise((resolve) => {
    const p = start(options, () => resolve(p));
  });
  ownExceptions();
  // index.test.js:114-120 and 206-208, in that order.
  proxy.on('tunnelRequest', util.noop);
  proxy.on('wsRequest', util.noop);
  proxy.on('_request', util.noop);
  proxy.setUIHost('_');
  proxy.setUIHost();
  proxy.setPluginUIHost('test', '_');
  proxy.setPluginUIHost('whistle.test', '');
  proxy.rulesUtil.setMockRules(util.setPath(util.readText('assets/rules/mock.txt')));
  proxy.rulesUtil.setServiceRules(util.setPath(util.readText('assets/rules/service.txt')));
  proxy.setShadowRules(util.setPath(util.readText('assets/rules/shadow.txt')));
  // index.test.js:232-248 asks the console for its data once before the
  // units, and every ten seconds after. Here once, and the rest unref'd.
  const getData = () => new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: config.port, path: 'http://local.whistlejs.com/cgi-bin/get-data' }, (res) => {
      res.resume();
      res.on('end', resolve);
    }).on('error', resolve);
  });
  await getData();
  setInterval(getData, 10000).unref();
}

/**
 * whistle-rs with the nearest equivalent of those options:
 *   port, certDir, localUIHost, mode, rules and values have one each;
 *   `--insecure-upstream` because whistle does not verify an origin's
 *   certificate unless told to, and the HTTPS origin here is self-signed;
 *   httpPort/httpsPort, pluginHost, storage, debugMode and copy have none,
 *   and no unit reaches them except through the plugins and the console API,
 *   which are declared.
 * Mock, service and shadow rules are an embedding API with no counterpart.
 */
async function startRs(W, config, util) {
  if (!fs.existsSync(RS_BIN)) {
    console.error(`no binary at ${RS_BIN} — cargo build first`);
    process.exit(2);
  }
  // whistle, loaded in-process, turns certificate checks off for the whole
  // process (`lib/util/patch.js:20`), and the suite's own client runs in that
  // process — it has never verified the proxy's certificates, and most of its
  // HTTPS calls do not ask it not to. Kept that way against this proxy too.
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const args = [
    '-p', String(config.port), '-H', '127.0.0.1',
    '--dir', path.join(W, 'rs-home'), '--no-persist', '--insecure-upstream',
    '-z', path.join(W, 'test/assets/certs'),
    '-M', 'enableRequestHeaderRules',
    '-l', 'local.whistle.com|local2.whistle.com&localn.whistle.com',
  ];
  const child = spawn(RS_BIN, args, { stdio: ['ignore', 'ignore', 'pipe'], env: process.env });
  let stderr = '';
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-4000); });
  child.on('exit', (code, signal) => {
    if (!stopping) {
      console.error(`whistle-rs exited (${code ?? signal}) during the run:\n${stderr}`);
      process.exit(1);
    }
  });
  process.on('exit', () => { stopping = true; child.kill('SIGKILL'); });
  await waitForPort(config.port, 15000);

  const opts = upstreamOptions(W, config, util);
  // Upstream's `values` option writes the values store (`addValues`,
  // `lib/rules/util.js:671-700`, an object as two-space JSON), which is the
  // console's store here — not `--value`, which is a run-scoped override.
  for (const [name, value] of Object.entries(opts.values)) {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, '  ');
    await api(config.port, 'POST', '/api/value', JSON.stringify({ name, value: text }), 'application/json');
  }
  await api(config.port, 'POST', '/api/rules', opts.rules.Default, 'text/plain');
  // Named groups in the order upstream adds them; a bare string is a group
  // that is added and not switched on (`addRules`, `lib/rules/util.js:622-660`).
  for (const [name, item] of Object.entries(opts.rules)) {
    if (name === 'Default') continue;
    const text = typeof item === 'string' ? item : item.rules;
    const enabled = typeof item === 'object' && !!item.enable;
    await api(config.port, 'POST', '/api/rule-groups', JSON.stringify({ name, text, enabled }), 'application/json');
  }
}
let stopping = false;

function api(port, method, pathname, body, type) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: pathname,
      headers: { 'content-type': type, 'content-length': Buffer.byteLength(body) } }, (res) => {
      let text = '';
      res.on('data', (d) => { text += d; });
      res.on('end', () => (res.statusCode < 300 ? resolve(text) : reject(new Error(`${method} ${pathname}: ${res.statusCode} ${text}`))));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function waitForPort(port, ms) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await answers(port)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`nothing listening on ${port} after ${ms} ms`);
}

function answers(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
  });
}

// ── running ───────────────────────────────────────────────────────────────

/** The four units that test upstream's own JS modules, not a proxy. */
const INTERNAL = new Set(['_normalizeConnectArgs', 'common', 'fm', 'utils']);

function runUnit(unit) {
  // Upstream's helper prints the whole request (a 250 KB body, once) before
  // rethrowing a parse error. Kept with the unit, shown with --verbose.
  const print = console.log;
  console.log = (...args) => unit.log.push(require('util').format(...args).slice(0, 300));
  return new Promise((resolve) => {
    let over = false;
    unit.finish = () => {
      if (over) return;
      over = true;
      console.log = print;
      clearTimeout(timer);
      for (const call of unit.outstanding) call.state = 'timeout';
      unit.outstanding.clear();
      unit.ms = Date.now() - started;
      resolve();
    };
    const started = Date.now();
    const timer = setTimeout(unit.finish, UNIT_TIMEOUT);
    current = unit;
    als.run({ unit, call: null }, () => {
      try {
        unit.fn();
      } catch (e) {
        unit.errors.push({ error: String(e.message || e).slice(0, 600), at: where(e) });
      }
    });
    // A unit may make no call at all (the internal ones) or its callbacks may
    // start the next call; give it a moment before an empty list means done.
    setTimeout(() => {
      unit.graceOver = true;
      if (unit.outstanding.size === 0) unit.finish();
    }, 300);
  });
}

async function main() {
  const src = suiteDir();
  const W = workDir(src);
  // Whatever ends the run — the report, a port check, the proxy dying — the
  // scratch copy goes with it. `rmSync` unlinks the symlinks, not what they
  // point at.
  process.on('exit', () => fs.rmSync(W, { recursive: true, force: true }));
  process.on('SIGINT', () => process.exit(130));
  process.on('SIGTERM', () => process.exit(143));
  process.env.WHISTLE_PATH = path.join(W, 'test');
  if (argv.includes('--print-fixture')) {
    const flat = flattenPlugins(W);
    console.log(`── ${FLAT_GROUP} ──\n${flat.private}\n\n── appended to Default ──\n${flat.global}`);
    process.exit(0);
  }
  const wreq = createRequire(path.join(W, 'test', 'index.test.js'));
  const config = wreq('./config.test');
  const ports = [...Object.values(config), 19999, 37621];
  const taken = [];
  for (const p of ports) if (await answers(p)) taken.push(p);
  if (taken.length) {
    console.error(`port(s) ${taken.join(', ')} already answer; the suite needs ${ports.join(', ')} free`);
    process.exit(2);
  }

  wreq('should');
  wreq('should-http');
  tapRequest(wreq);
  const util = wreq('./util.test');
  await startFixtures(wreq, W, config);
  if (TARGET === 'whistle') await startWhistle(W, config, util);
  else await startRs(W, config, util);
  instrument(util);

  // index.test.js:217-223: directory order, `tplStr` second to last and `ui`
  // last. Sorted first, because readdir order is the file system's.
  let names = fs.readdirSync(path.join(W, 'test/units')).filter((n) => n.endsWith('.test.js')).sort();
  for (const last of ['tplStr.test.js', 'ui.test.js']) {
    names = names.filter((n) => n !== last).concat(last);
  }
  for (const file of names) {
    const name = file.replace(/\.test\.js$/, '');
    if (ONLY && !ONLY.has(name)) continue;
    const unit = { name, calls: [], errors: [], log: [], outstanding: new Set(), graceOver: false, ms: 0 };
    units.push(unit);
    if (TARGET === 'rs' && INTERNAL.has(name)) {
      unit.skipped = 'tests one of upstream\'s own JS modules, not the proxy';
      continue;
    }
    unit.fn = wreq('./units/' + file);
    await runUnit(unit);
  }
  current = null;
  report(W);
}

function report(W) {
  let checked = 0, passed = 0, failed = 0, timedOut = 0, sent = 0;
  for (const unit of units) {
    if (unit.skipped) {
      console.log(`  -    ${unit.name}: not run (${unit.skipped})`);
      continue;
    }
    const count = (state) => unit.calls.filter((c) => c.state === state).length;
    const p = count('pass'), f = count('fail'), t = count('timeout'), s = count('sent');
    const n = unit.calls.length - s;
    checked += n; passed += p; failed += f; timedOut += t; sent += s;
    const ok = f === 0 && t === 0 && unit.errors.length === 0;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${unit.name}: ${p}/${n}${f ? `, ${f} failed` : ''}${t ? `, ${t} no answer` : ''}`
      + `${s ? `, ${s} sent unchecked` : ''}${unit.errors.length ? `, ${unit.errors.length} other error(s)` : ''} (${unit.ms} ms)`);
    for (const c of unit.calls) {
      if ((c.state === 'pass' || c.state === 'sent') && !VERBOSE) continue;
      const got = c.transport ? ` (${c.transport})` : c.status ? ` (${c.status})` : '';
      console.log(`         ${c.state.padEnd(7)} ${c.desc}${got}${c.at ? `  [${c.at}]` : ''}${c.error ? `\n                 ${c.error.split('\n')[0]}` : ''}`
        + `${c.body ? `\n                 body: ${c.body.replace(/\s+/g, ' ').slice(0, 160)}` : ''}`);
    }
    for (const e of unit.errors) console.log(`         error   ${e.at} ${e.error.split('\n')[0]}`);
  }
  console.log(`\n${TARGET}: ${passed}/${checked} checked calls passed, ${failed} failed, ${timedOut} without an answer; ${sent} sent without a check`);
  if (JSON_OUT) {
    fs.writeFileSync(JSON_OUT, JSON.stringify({
      target: TARGET, commit: UPSTREAM_COMMIT,
      units: units.map((u) => ({
        name: u.name, skipped: u.skipped, ms: u.ms, errors: u.errors,
        calls: u.calls.map(({ desc, kind, state, error, at, late, answeredBy, transport, status, body }) =>
          ({ desc, kind, state, error, at, late, answeredBy, transport, status, body })),
      })),
    }, null, 2));
  }
  stopping = true;
  process.exit(failed || timedOut || units.some((u) => u.errors.length) ? 1 : 0);
}

// ── the gate ──────────────────────────────────────────────────────────────

/**
 * Calls the gate judges and whistle-rs fails, each for a stated reason — named
 * one by one, as `indexCalls` keys them, because a category is too wide: some
 * calls in these same families pass here on assertions loose enough not to
 * need the feature. Every one must still fail (or, made from a failed call's
 * callback, still not be made), or the declaration is stale.
 */
const DECLARED = [
  {
    why: 'rules set through upstream\'s embedding API — `rulesUtil.setMockRules`, '
      + '`setServiceRules`, `setShadowRules` (index.test.js:206-208) — which has no '
      + 'counterpart here',
    calls: [
      'keys GET http://mock.test.w2.org/path/to?doNotParseJson #1',
      'keys GET http://mock.script-key.test.w2.org/test/script/api #1',
      'keys GET http://mock.script-key.test.w2.org/test/script/path/to?doNotParseJson #1',
      'keys GET http://service.test.w2.org/path/to/index2.html?doNotParseJson #1',
      'keys GET http://service.script-key.test.w2.org/test/script/api #1',
      'keys GET http://service.script-key.test.w2.org/test/script/path/to?doNotParseJson #1',
      'keys GET http://shadow.test.w2.org/path/to/index.html?doNotParseJson #1',
      'keys GET http://shadow.script-key.test.w2.org/test/script/path/to?doNotParseJson #1',
      'keys GET http://shadow.script-key.test.w2.org/test/script/api #1',
      'ui GET http://mock.remote-key.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://service.remote-key.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://shadow.remote-key.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://mock.remote-key2.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://service.remote-key2.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://shadow.remote-key2.test.w2.org/test/path?doNotParseJson #1',
      'ui GET http://shadow.remote-key3.test.w2.org/test/script/api #1',
      'ui GET http://service.remote-key3.test.w2.org/test/script/api #1',
      'ui GET http://mock.remote-key3.test.w2.org/test/script/api #1',
    ],
  },
  {
    why: 'upstream\'s console API, `/cgi-bin/*`: a stated non-goal — this port has '
      + 'its own (docs/API.md). The three `rename` calls are made from the `add` '
      + 'calls\' callbacks, and so are never made here',
    calls: [
      'ui POST http://local.whistlejs.com/cgi-bin/values/add #1',
      'ui POST http://local.wproxy.org:1234/cgi-bin/values/add #1',
      'ui POST http://local.whistle.com/cgi-bin/values/add #1',
      'ui POST http://local.whistlejs.com/cgi-bin/values/rename #1',
      'ui POST http://local.wproxy.org:1234/cgi-bin/values/rename #1',
      'ui POST http://local.whistle.com/cgi-bin/values/rename #1',
    ],
  },
  {
    why: 'an interim (`100`) or out-of-range (`1000`) status: upstream breaks the '
      + 'connection, this port answers — docs/RULES.md, "A status value that is '
      + 'not a status"',
    calls: [
      'statusCode POST http://statuscode4.test.whistlejs.com/index.html?resBody= #1',
      'statusCode GET https://statuscode5.test.whistlejs.com/index.html?resBody= #1',
    ],
  },
];

/** One call per key: unit, description, and which occurrence of it. */
function indexCalls(result) {
  const out = new Map();
  for (const unit of result.units) {
    const seen = new Map();
    for (const call of unit.calls) {
      const n = (seen.get(call.desc) || 0) + 1;
      seen.set(call.desc, n);
      out.set(`${unit.name} ${call.desc} #${n}`, { unit: unit.name, skipped: unit.skipped, ...call });
    }
  }
  return out;
}

/** One run of this file as a child, its summary line echoed. */
function runChild(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [__filename, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    child.on('exit', (code, signal) => resolve({ code: code ?? 1, signal, out }));
    process.on('exit', () => child.kill('SIGKILL'));
  });
}

async function gate() {
  // Fetched once here, not by three children racing to the same directory.
  const root = path.dirname(suiteDir());
  const scratch = fs.mkdtempSync(path.join(process.env.DIFF_STATE || os.tmpdir(), 'whistle-upstream-gate-'));
  process.on('exit', () => fs.rmSync(scratch, { recursive: true, force: true }));
  process.on('SIGINT', () => process.exit(130));
  process.on('SIGTERM', () => process.exit(143));
  const shared = ['--suite', root, ...(ONLY ? ['--only', [...ONLY].join(',')] : [])];
  const runs = [
    { name: 'whistle, no network', args: ['--target', 'whistle', '--fixture', 'flat', '--no-network'] },
    { name: 'whistle', args: ['--target', 'whistle', '--fixture', 'flat'] },
    { name: 'whistle-rs', args: ['--target', 'rs', '--fixture', 'flat'] },
  ];
  if (argv.includes('--control')) {
    runs.unshift({ name: 'whistle with its plugins', args: ['--target', 'whistle', '--fixture', 'plugins'], control: true });
  }
  for (const run of runs) {
    const file = path.join(scratch, run.name.replace(/\W+/g, '-') + '.json');
    const { code, out } = await runChild([...run.args, ...shared, '--json', file]);
    const summary = out.trim().split('\n').pop();
    console.log(`${run.name.padEnd(26)} ${summary.replace(/^\w[\w-]*: /, '')}`);
    if (code === 2 || !fs.existsSync(file)) {
      console.error(out);
      process.exit(2);
    }
    run.result = JSON.parse(fs.readFileSync(file, 'utf8'));
  }

  const [noNetwork, network, rs] = runs.filter((r) => !r.control).map((r) => indexCalls(r.result));
  const verdict = { commit: UPSTREAM_COMMIT, judged: 0, passed: 0, notRun: 0, declared: [], failed: [], stale: [] };
  for (const [key, control] of noNetwork) {
    if (control.state !== 'pass' || network.get(key)?.state !== 'pass') continue;
    verdict.judged++;
    const got = rs.get(key) || { state: 'never made' };
    if (got.skipped) {
      verdict.notRun++;
      continue;
    }
    const why = DECLARED.find((d) => d.calls.includes(key))?.why;
    const row = { key, state: got.state, at: got.at, error: got.error, why };
    if (got.state === 'pass') {
      verdict.passed++;
      if (why) verdict.stale.push(row);
    } else if (why) {
      verdict.declared.push(row);
    } else {
      verdict.failed.push(row);
    }
  }

  const control = runs.find((r) => r.control);
  console.log(`\njudged ${verdict.judged} calls — the ones whistle passes under the flattened rules, with and without the network`);
  console.log(`  ${verdict.passed} pass on whistle-rs`);
  const byReason = new Map();
  for (const row of verdict.declared) byReason.set(row.why, (byReason.get(row.why) || 0) + 1);
  for (const [why, n] of byReason) console.log(`  ${n} declared: ${why}`);
  if (verdict.notRun) console.log(`  ${verdict.notRun} not run: they test upstream's own JS modules, not a proxy`);
  for (const row of verdict.failed) {
    console.log(`  FAIL ${row.key}  [${row.at || ''}]\n       ${String(row.error || row.state).split('\n')[0]}`);
  }
  for (const row of verdict.stale) console.log(`  STALE ${row.key} passes, but is declared: ${row.why}`);
  if (control) {
    const all = [...indexCalls(control.result).values()].filter((c) => c.state !== 'sent');
    const bad = all.filter((c) => c.state !== 'pass');
    console.log(`\ncontrol: whistle passes ${all.length - bad.length}/${all.length} of its own suite with its plugins`
      + (bad.length ? ` — not: ${bad.map((c) => `${c.unit} ${c.desc}`).join('; ')}` : ''));
  }
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(verdict, null, 2));
  const ok = !verdict.failed.length && !verdict.stale.length;
  // One line `run.js` can lift into its summary (it looks for `differing`).
  console.log(`\nupstream suite: judged ${verdict.judged}, passed ${verdict.passed}, `
    + `declared ${verdict.declared.length}, differing ${verdict.failed.length}, `
    + `stale ${verdict.stale.length} — ${ok ? 'passed' : 'FAILED'}`);
  process.exit(ok ? 0 : 1);
}

(TARGET ? main : gate)().catch((e) => {
  console.error(e);
  process.exit(2);
});
