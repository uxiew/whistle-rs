// `-M/--mode`, asked of both proxies one token at a time.
//
// `cli.md` prints nine modes; upstream's parser knows fifty-six. Rather than
// pick which to port by reading, this starts **one proxy per token** and runs
// the same battery of nine probes through it, twice — real whistle and this
// port — and compares. A mode that neither proxy's answers move is a mode with
// no effect a client can see, and saying so is as useful as the ones that do.
//
// It is the cross-multiply the corpora already use, applied to a vocabulary
// instead of to rules. It is slow — two process starts per token — so it is not
// part of a normal bench run; reach for it when the vocabulary changes.
//
//   PORT_BASE=20100 node mode-bench.js              # every token
//   PORT_BASE=20100 MODES=pureProxy,headless node mode-bench.js
//     20100 whichever proxy is being started · 20102 the echo origin
//
// **What it found.** Fifteen of the fifty-six move anything, and they collapse
// into six behaviours: turn the console hostnames off (`pureProxy`), turn the
// console off (`headless`), intercept HTTPS from startup (`capture`), keep the
// client's `x-forwarded-for` (`keepXFF`), read rules out of request headers
// (`multiEnv`, `enableRequestHeaderRules`), and trust a front proxy's forwarded
// headers (`x-forwarded-proto`, `x-forwarded-host`). **All six are honoured.**
//
// Two of them wanted more than one probe can hold, so each has a bench of its
// own: `header-rules-bench.js` walks the five rules-carrying headers under every
// setting, and `forwarded-bench.js` walks the four forwarding ones against two
// origins.
'use strict';
const http = require('http');
const tls = require('tls');
const path = require('path');
const { spawn } = require('child_process');

const BASE = Number(process.env.PORT_BASE || 20100);
/** The binary under test; built by `cargo build` from the repo root. */
const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');
// `run.js` sets both: a scratch directory for every proxy's state, and a
// loopback listener. Unset, the state lands beside this file and the proxies
// listen on every interface, as they always did.
const STATE = process.env.DIFF_STATE || __dirname;
const HOST = process.env.DIFF_HOST;
const W = BASE, ORIGIN = BASE + 2;

const MODES = process.env.MODES ? process.env.MODES.split(',') : [
  '', // baseline
  'pureProxy', 'proxyOnly', 'httpProxy', 'debug', 'strict', 'noGzip',
  'multiEnv', 'nohost', 'network', 'rules', 'rulesOnly', 'plugins', 'pluginsOnly',
  'shadowRules', 'shadowRulesOnly', 'capture', 'intercept', 'enableCapture',
  'disableCapture', 'persistentCapture', 'http2', 'disableH2', 'enableH2',
  'keepXFF', 'forwardedFor', 'x-forwarded-proto', 'x-forwarded-host',
  'safe', 'rejectUnauthorized', 'enableRequestHeaderRules', 'socks',
  'captureData', 'headless', 'encrypted', 'master', 'client', 'diagnose',
  'ipv6Only', 'disableAuthUI', 'showPluginReq', 'disableCustomCerts',
  'allowMultipleChoice', 'disableMultipleRules', 'notAllowedDisableRules',
  'disabledBackOption', 'disabledRulesOptions', 'notAllowedEnableHTTPS',
  'notAllowedDisablePlugins', 'hideLeftMenu', 'keepProxyUI', 'proxifier',
  'admin', 'multiple', 'agent', 'INADDR_ANY', 'disableUpdateTips',
];

function origin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      r.writeHead(200, { 'content-type': 'application/json' });
      r.end(JSON.stringify({ url: q.url, headers: q.headers }));
    });
    srv.listen(ORIGIN, () => res(srv));
  });
}

const req = (opts, body) => new Promise((res) => {
  const r = http.request(opts, (x) => {
    let s = '';
    x.on('data', (c) => (s += c));
    x.on('end', () => res({ status: x.statusCode, type: (x.headers['content-type'] || '').split(';')[0], body: s }));
  });
  r.on('error', (e) => res({ status: 0, type: '', body: 'ERR ' + e.code }));
  r.setTimeout(6000, () => { r.destroy(); res({ status: 0, type: '', body: 'timeout' }); });
  r.end(body);
});

function issuer(port, authority) {
  return new Promise((res) => {
    const r = http.request({ port, host: '127.0.0.1', method: 'CONNECT', path: authority });
    r.on('connect', (resp, sock) => {
      if (resp.statusCode !== 200) { sock.destroy(); return res('CONNECT ' + resp.statusCode); }
      const name = authority.split(':')[0];
      const opts = { socket: sock, rejectUnauthorized: false };
      // A ServerName may not be an IP, so a bare-address CONNECT sends none —
      // which is also the case the bare-IP default is about.
      if (!/^[\d.]+$/.test(name) && !name.includes(':')) opts.servername = name;
      const s = tls.connect(opts, () => {
        const c = s.getPeerCertificate();
        s.destroy();
        res((c && c.issuer && c.issuer.CN || '?').startsWith('whistle') ? 'intercepted' : 'passed-through');
      });
      s.on('error', (e) => res('tls ' + e.code));
    });
    r.on('error', (e) => res('connect ' + e.code));
    r.setTimeout(6000, () => { r.destroy(); res('timeout'); });
    r.end();
  });
}

/**
 * The console paths, one spelling per proxy.
 *
 * The two consoles are different programs with different route tables, so
 * asking both for `/cgi-bin/rules/list` would be asking one of them for a page
 * it has never had. Each is asked for its own equivalent, and what is compared
 * is the answer to the same *question*.
 */
const CONSOLE_PATHS = {
  rules: { whistle: '/cgi-bin/rules/list', rs: '/api/rules' },
  status: { whistle: '/cgi-bin/status', rs: '/api/status' },
  rootca: { whistle: '/cgi-bin/rootca', rs: '/rootCA.crt' },
};

/**
 * A console answer, reduced to its **status**.
 *
 * Not the content type: the two consoles have different route tables, so
 * `/cgi-bin/rules/list` answers JSON and `/api/rules` answers the rules text,
 * and comparing those would be comparing the tables. Whether the door opened is
 * the question a mode moves.
 */
const shape = (a) => String(a.status);

/** Everything one proxy answers, as a flat map of probe → answer. */
async function battery(port, which) {
  const out = {};
  const echo = `http://127.0.0.1:${ORIGIN}/echo`;
  // 1. an ordinary proxied request, and which headers reached the origin
  let a = await req({ port, path: echo, method: 'GET', headers: { host: `127.0.0.1:${ORIGIN}` } });
  out['proxy.status'] = a.status;
  try {
    const h = JSON.parse(a.body).headers;
    out['proxy.headers'] = Object.keys(h).filter((k) => !/^(host|connection|keep-alive)$/.test(k)).sort().join(',');
  } catch (e) { out['proxy.headers'] = '(unparseable)'; }
  // 2. a client-supplied x-forwarded-for: does it survive to the origin
  a = await req({ port, path: echo, method: 'GET', headers: { host: `127.0.0.1:${ORIGIN}`, 'x-forwarded-for': '9.9.9.9' } });
  try { out['proxy.xff'] = JSON.parse(a.body).headers['x-forwarded-for'] || '(gone)'; }
  catch (e) { out['proxy.xff'] = '(unparseable)'; }
  // 3. a rules text carried in a request header
  a = await req({ port, path: echo, method: 'GET',
    headers: { host: `127.0.0.1:${ORIGIN}`, 'x-whistle-rule-value': encodeURIComponent(`127.0.0.1:${ORIGIN} reqHeaders://x-hdr-rule=1`) } });
  try { out['proxy.headerRules'] = JSON.parse(a.body).headers['x-hdr-rule'] ? 'honoured' : 'ignored'; }
  catch (e) { out['proxy.headerRules'] = '(unparseable)'; }
  // 4. CONNECT: is the tunnel read or relayed
  out['tunnel'] = await issuer(port, `probe.test:${ORIGIN}`);
  // 5. the console, each at its own address
  for (const [name, paths] of Object.entries(CONSOLE_PATHS)) {
    out[`console.${name}`] = shape(await req({ port, path: paths[which], method: 'GET' }));
  }
  // 6. the console reached by hostname, through the proxy
  out['console.byHost'] = shape(await req({ port, path: 'http://local.whistlejs.com/', method: 'GET', headers: { host: 'local.whistlejs.com' } }));
  out['console.rootcaHost'] = shape(await req({ port, path: 'http://rootca.pro/', method: 'GET', headers: { host: 'rootca.pro' } }));
  return out;
}

/**
 * Start one proxy with one mode, and resolve when it is listening.
 *
 * Both are started the same way and killed the same way, so the comparison is
 * of the two programs rather than of two launch procedures.
 */
function start(which, mode, port) {
  return new Promise((resolve, reject) => {
    const dir = path.join(STATE, `.mode-${which}-${mode || 'none'}`);
    // **whistle is started with `capture` in front of every list.** The two
    // proxies' defaults differ on purpose — whistle does not decrypt HTTPS in a
    // fresh data directory (`_original/lib/tunnel.js:187-199`) and this port
    // does — and comparing what a *mode* did needs the same starting state on
    // both sides, or most rows differ on the default rather than on the mode.
    // `https-bench.js` turns the same switch on for the same reason.
    // `disableCapture` stays measurable: it comes later in the list, and the
    // last word wins.
    const wMode = mode ? `capture|${mode}` : 'capture';
    const child = which === 'whistle'
      ? spawn('node', ['-e', `
          const whistle = require('whistle');
          whistle({ port: ${port}, baseDir: ${JSON.stringify(dir)},${HOST ? ` host: ${JSON.stringify(HOST)},` : ''}
            mode: ${JSON.stringify(wMode)} }, () => console.log('READY'));
        `], { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn(RS_BIN, [
          '--port', String(port), '--no-persist', '--dir', dir,
          ...(HOST ? ['-H', HOST] : []),
          ...(mode ? ['-M', mode] : []),
        ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false;
    const ready = /READY|listening on/;
    const t = setTimeout(() => {
      if (!done) { done = true; child.kill('SIGKILL'); reject(new Error('start timeout')); }
    }, 25000);
    const watch = (d) => {
      if (!done && ready.test(String(d))) { done = true; clearTimeout(t); resolve(child); }
    };
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', () => { if (!done) { done = true; clearTimeout(t); reject(new Error('exited')); } });
  });
}

/** Everything one proxy answers for one mode, or the reason it could not say. */
async function answersFor(which, mode, port) {
  let child;
  try { child = await start(which, mode, port); }
  catch (e) { return { error: e.message }; }
  await new Promise((r) => setTimeout(r, 700));
  let out;
  try { out = await battery(port, which); } catch (e) { out = { error: String(e.message) }; }
  child.kill('SIGKILL');
  await new Promise((r) => setTimeout(r, 900));
  return out;
}

async function main() {
  const srv = await origin();
  const rows = {};
  for (const mode of MODES) {
    const label = mode || '(baseline)';
    rows[label] = {
      whistle: await answersFor('whistle', mode, W),
      rs: await answersFor('rs', mode, W),
    };
    process.stderr.write(`  ${label}\n`);
  }
  srv.close();

  // Compared on the **answers**, not on the change from each proxy's own
  // baseline. The two baselines differ on purpose — whistle does not decrypt
  // HTTPS in a fresh data directory and this port does — so a delta compare
  // would report `disableCapture` as a difference when both proxies end up in
  // the same state, which is the thing that actually matters.
  //
  // The baseline row is compared too: a mode bench whose no-mode row diverged
  // would be measuring the launch rather than the mode.
  const DECLARED = [
    // `multiEnv` / `nohost` / `enableRequestHeaderRules` / `multiple` and
    // `notAllowedEnableHTTPS` used to be declared here. They are implemented —
    // see `header-rules-bench.js`, which measures the five headers probe by
    // probe, and `src/proxy/header_rules.rs`. The `tunnel` probe moves with
    // them because `isEnableCapture()` opens with
    // `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`
    // (`_original/lib/rules/util.js:547-550`), which this port spells
    // `Config::intercepts_https`.
    // `x-forwarded-proto` / `x-forwarded-host` were declared here. They are
    // implemented — see `forwarded-bench.js`, which sends the headers this
    // battery does not and compares where the request ended up.
  ];

  /**
   * How each probe is compared, and why it is not one rule for all of them.
   *
   * * **absolute** — the two proxies agree on the vocabulary *and* on the
   *   default, so the answers themselves are comparable.
   * * **delta** — for a probe whose two defaults differ on purpose, what a
   *   *mode* did is the change from each proxy's own baseline. Nothing uses it:
   *   `tunnel` was the one candidate, and the better answer was to start both
   *   proxies from the same state instead — see `start()`.
   */
  const COMPARE = {
    'proxy.status': 'absolute',
    'proxy.headers': 'absolute',
    'proxy.xff': 'absolute',
    'proxy.headerRules': 'absolute',
    // Absolute, with the two defaults declared below rather than compared
    // away: what a capture mode leaves behind is the same on both sides, and
    // that is the claim worth checking.
    tunnel: 'absolute',
  };
  const how = (k) => COMPARE[k] || 'absolute';

  let ran = 0;
  const differing = [];
  const declared = [];
  const agreed = { moves: [], inert: [] };
  const baseW = (rows['(baseline)'] || {}).whistle || {};
  const baseRs = (rows['(baseline)'] || {}).rs || {};
  const delta = (base, now, k) => (String(base[k]) === String(now[k]) ? '(no change)' : `${base[k]} -> ${now[k]}`);
  for (const [label, r] of Object.entries(rows)) {
    ran++;
    if (r.whistle.error || r.rs.error) {
      differing.push({ mode: label, problems: [`start: whistle=${r.whistle.error || 'ok'} rs=${r.rs.error || 'ok'}`] });
      continue;
    }
    const keys = [...new Set([...Object.keys(r.whistle), ...Object.keys(r.rs)])].sort();
    const problems = [];
    const excused = [];
    for (const k of keys) {
      const [w, rs] = how(k) === 'delta'
        ? [delta(baseW, r.whistle, k), delta(baseRs, r.rs, k)]
        : [String(r.whistle[k]), String(r.rs[k])];
      if (w === rs) continue;
      const reason = DECLARED.find((d) => d.match(label) && d.probes.includes(k));
      (reason ? excused : problems).push(`${k}: whistle=${w} rs=${rs}`);
    }
    if (excused.length) declared.push({ mode: label, problems: excused, why: DECLARED.find((d) => d.match(label)).why });
    if (problems.length) { differing.push({ mode: label, problems }); continue; }
    if (label === '(baseline)') continue;
    // `moves` is what a mode did where **both** proxies did the same thing, so a
    // mode whose effect had to be excused belongs in `excused` and not here.
    if (excused.length) continue;
    const moved = keys.filter((k) => String(baseW[k]) !== String(r.whistle[k]));
    if (moved.length) agreed.moves.push({ mode: label, effect: Object.fromEntries(moved.map((k) => [k, `${baseW[k]} -> ${r.whistle[k]}`])) });
    else agreed.inert.push(label);
  }
  console.log(JSON.stringify({
    ran,
    differing: differing.length,
    declared: declared.length,
    report: differing,
    excused: declared,
    // The two lists that make this readable: what a mode does when both agree
    // it does something, and the modes that do nothing on either side.
    moves: agreed.moves,
    inert: agreed.inert,
  }, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
