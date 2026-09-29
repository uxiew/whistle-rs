// Which address each proxy dials for `localhost`, when one family, the other,
// or both are listening.
//
//   PORT_BASE=18700 node dns-bench.js     # the pair on PORT_BASE and +1 (run.js starts it)
//
// A name with an IPv4 and an IPv6 address is dialled at one of them first, and
// which one decides what answers when two servers share a port number across
// the families — or whether anything answers at all, on a network whose IPv6
// route drops packets. Both whistle 2.10.8 and 2.10.10 ask IPv4 first for
// `localhost` (`IPV4_FIRST`, lib/rules/dns.js), and 2.10.10 does for every name
// by default. This port used to take the resolver's order, which puts `::1`
// first on macOS: a dual-stack origin saw it arrive over IPv6 and through
// whistle over IPv4.
//
// Three origins on PORT_BASE+2…+4 — IPv4 only, IPv6 only, one socket for both —
// each answering with the address it was reached at. Where `::1` cannot be
// bound (some containers have no IPv6 at all) the bench says so and compares
// nothing, rather than reporting a difference that is the machine's.

'use strict';

const http = require('http');
const { judge } = require('./declared.js');

const BASE = Number(process.env.PORT_BASE || 18700);
const [W, RS] = [BASE, BASE + 1];
const [V4, V6, DUAL] = [BASE + 2, BASE + 3, BASE + 4];
const HOST = process.env.DIFF_HOST || '127.0.0.1';

const CASES = [
  { name: 'localhost with an IPv4 listener only', port: V4 },
  { name: 'localhost with an IPv6 listener only', port: V6 },
  { name: 'localhost with one listener for both families', port: DUAL },
];

function listen(port, options) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((q, r) => r.end(`reached at ${q.socket.localAddress}`));
    server.once('error', reject);
    server.listen({ port, ...options }, () => resolve(server));
  });
}

/** A request for `http://localhost:port/` through the proxy on `proxy`. */
function via(proxy, port) {
  return new Promise((resolve) => {
    const url = `http://localhost:${port}/`;
    const req = http.request({ host: HOST, port: proxy, path: url, headers: { host: `localhost:${port}` } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve(`${res.statusCode} ${body.slice(0, 80)}`));
    });
    req.on('error', (e) => resolve(`error ${e.code}`));
    req.setTimeout(20000, () => { req.destroy(); resolve('timeout'); });
    req.end();
  });
}

async function main() {
  let servers;
  try {
    servers = [
      await listen(V4, { host: '127.0.0.1' }),
      await listen(V6, { host: '::1' }),
      await listen(DUAL, { host: '::', ipv6Only: false }),
    ];
  } catch (e) {
    console.log(JSON.stringify({ ran: 0, differing: 0, skipped: `cannot listen on both families here: ${e.code || e.message}`, report: [] }, null, 2));
    return;
  }
  const report = [];
  for (const c of CASES) {
    const [w, rs] = [await via(W, c.port), await via(RS, c.port)];
    if (w !== rs) report.push({ name: c.name, problems: [`answer: whistle=${JSON.stringify(w)} rs=${JSON.stringify(rs)}`] });
  }
  for (const s of servers) s.close();
  const verdict = judge('dns-bench.js', report, CASES.map((c) => c.name));
  console.log(JSON.stringify({
    ran: CASES.length,
    differing: verdict.news.length,
    declared: verdict.declared,
    stale: verdict.stale,
    report: verdict.news,
    raw: report,
  }, null, 2));
  process.exitCode = verdict.news.length || verdict.stale.length ? 1 : 0;
}

main().catch((e) => { console.error(e); process.exit(1); });
