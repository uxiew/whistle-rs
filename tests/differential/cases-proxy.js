// The forwarding corpus: where a request is actually sent, and through what.
//
//   PORT_BASE=19300 node oracle.js &
//   cargo run -- --port 19301 --no-persist --insecure-upstream --dir /tmp/rs-fwd &
//   PORT_BASE=19300 CASES=./cases-proxy.js npm run bench
//
// `--insecure-upstream` is only for the three `https-proxy://` cases, whose hop
// carries a self-signed certificate. Nothing else here speaks TLS, so the flag
// changes nothing else: every origin in this file is plain HTTP.
//
// Ports, all offset from `PORT_BASE` (the servers themselves are in
// `forward-servers.js`):
//
//   +0  real whistle          +10  the recording proxy
//   +1  whistle-rs            +11  a second echo origin
//   +2  the echo origin       +12  a proxy that always answers 407
//                             +13  a proxy that accepts and never answers
//                             +14  nothing, ever: connection refused
//                             +15  the recording SOCKS5 proxy
//                             +16  PAC files over HTTP
//                             +17  the recording proxy, behind TLS
//
// **How a forwarding case is made observable.** A response cannot show a route:
// two proxies that reach the same origin by opposite paths return the same
// bytes. So two instruments stand in for the missing evidence, and every case
// here leans on one of them:
//
//   * the recording proxy staples what it was told — `x-hop-form` (absolute
//     form, CONNECT or SOCKS), `x-hop-target` (what the request line addressed)
//     and `x-hop-headers` — onto the request, where it reaches the origin's echo
//     and the harness compares it like any other header;
//   * the second origin answers with `x-origin: b` and re-echoes the request's
//     `Host` as `x-seen-host`, so "did the connection move" and "did the `Host`
//     header stay put" are two separate, visible answers. `host://` exists for
//     that gap between them, and the harness drops plain `host` from its
//     comparison, so nothing else in this bench could see it.
//
// **Divergences this file declares rather than pins.** Each is named here
// instead of in `harness.js`'s `EXPECTED`, so that a wide matcher there cannot
// swallow news in another area's corpus. They show as differences in a run; that
// is the honest report. In the order they appear:
//
//   1. **The gateway error's prose and type** (12 cases). whistle answers an
//      unreachable upstream with a 502 whose body is an HTML `<pre>` holding a
//      Node stack trace (`wrapGatewayError`,
//      `_original/lib/util/index.js:1096-1109`); this port answers 502 with the
//      error chain as plain text and says `text/plain`. Both now name themselves
//      in `x-server`. Matching another program's error prose is not worth
//      pinning.
//   2. **`socks5://` is nobody's protocol**, and the two disagree about what to
//      do with a scheme neither understands. whistle refuses it —
//      `Unsupported protocol socks5:` (`lib/handlers/http-proxy.js:5-11`, gated
//      on `protoMgr.isWebProtocol`) — while this port reads the line as a URL
//      replacement and sends the request to that address **in cleartext HTTP**.
//      Not fixed: refusing it means `Destination::parse` has to be able to fail,
//      which reaches past the forwarding family into the plugin dispatch.
//   3. **Falling back to a direct connection leaves whistle in absolute form.**
//      `xproxy://` at a dead hop, and a PAC answering `PROXY <dead>; DIRECT`,
//      both retry direct — and whistle sends the origin
//      `GET http://host/path` rather than `GET /path`, because `options.path`
//      was rewritten for the proxy and `send()` only rewrites it once
//      (`origPath = null`, `_original/lib/inspectors/res.js:604-612`). Servers
//      must accept absolute-form, so it works; this port sends origin-form.
//   4. **A PAC file's `SOCKS5`**, and the order of its entries. Upstream reads
//      the result with `/(PROXY|SOCKS)\s+([^;\s]+)/i` (`node-pac/lib/Pac.js:7`),
//      so `SOCKS5 host` matches nothing and the request goes direct, and a
//      `PROXY` anywhere in the list wins even when `DIRECT` came first. This
//      port reads the list in order, as PAC defines it: `DIRECT; PROXY x` is
//      direct, `SOCKS5 x` is a SOCKS hop. (A `DIRECT` *after* the chosen proxy
//      is its fallback in both, which is what `dead-then-direct.pac` checks.)
//   5. **A PAC file that cannot be fetched.** whistle logs and connects direct
//      (`logger.error`, `_original/lib/rules/index.js:295`); this port refuses
//      the request, because a rule that named a proxy ruled a direct connection
//      out. Declared in `docs/RULES.md`.
//   6. **`rule://` and `rules://`.** This port reads `rule://<name>` as a
//      values-store include of more rules; upstream has no such spelling and
//      reads it as the unusable URL `rule://<name>`, answering 502. Declared in
//      `crate::rules::protocols::URL_REPLACE`.
//   7. **Which URL the forwarding family is matched against**, once a URL
//      replacement has moved the destination. whistle resolves `host://`, the
//      proxy family and `pac://` a *second* time, against the URL the
//      replacement produced: `getProxy` is handed `options.href` and assigns
//      `req.curUrl = url` before resolving any of them
//      (`_original/lib/rules/index.js:124-152`, `lib/rules/rules.js:2419-2420`,
//      `lib/inspectors/res.js:208-212`). This port resolves every rule once,
//      against the request's own URL. So a proxy or host line whose pattern
//      matches only the *replacement* engages upstream and not here, and one
//      that matches only the *original* engages here and not upstream — opposite
//      routes for the same four-word rules file. **Found, not fixed**: matching
//      it means a second resolution pass over exactly those four protocols and
//      no others, which reaches well past the forwarding family.
//   8. **`xhttps-proxy://` at an unreachable hop hangs upstream** (1 case).
//      Measured against the same dead hop, written by name so no SNI objection
//      is in play: `xproxy://` and `xsocks://` fall back and answer 200, plain
//      `https-proxy://` answers 502 promptly, and `xhttps-proxy://` returns
//      nothing at all until the client gives up. This port falls back, which is
//      what the `x` prefix documents and what its three siblings do.
//
// **How much of this corpus does anything.** 83 of the 94 cases change what
// real whistle answers, measured against the same request with no rule at all.
// The other eleven are the negative controls, and each is inert on purpose: the
// empty baseline, the two `host://` spellings that must *keep* the request's own
// address or port, the `xhost://` fallback whose whole point is landing back
// where it started, a pattern written to miss, the two `ignore://` cases,
// `proxyHostOnly` with no `host://` to attach to, PAC `DIRECT`, and the two PAC
// cases where upstream's silence is itself the finding.
//
// One more difference is real but not shown, because it is hop-by-hop and
// `harness.js` drops that class everywhere else: whistle's CONNECT always
// carries `Connection: close`, stamped by Node on any request made with
// `agent: false` (`hagent/lib/agent.js:113`), contradicting the
// `Proxy-Connection: keep-alive` whistle sets on the same request. See
// `forward-servers.js`.

const { PORTS } = require('./forward-servers');

/** The harness's own echo origin — every pattern is written against it. */
const P = `127.0.0.1:${PORTS.origin}`;
const HOP = `127.0.0.1:${PORTS.proxy}`;
const OTHER = `127.0.0.1:${PORTS.originB}`;
const AUTH407 = `127.0.0.1:${PORTS.auth}`;
const HANG = `127.0.0.1:${PORTS.hang}`;
const CLOSED = `127.0.0.1:${PORTS.closed}`;
const SOCKS = `127.0.0.1:${PORTS.socks}`;
const PAC = `http://127.0.0.1:${PORTS.pac}`;
// By name, because a TLS hop needs a server name — see the case below that asks
// for it by address instead.
const TLSHOP = `localhost:${PORTS.tlsProxy}`;
const TLSHOP_IP = `127.0.0.1:${PORTS.tlsProxy}`;

/**
 * A name that really does not resolve. `.invalid` does not work: this machine's
 * VPN answers every unknown name with a fake 198.18.0.0/15 address, so a rule
 * pointed there would sit in a connect timeout instead of failing to resolve.
 * A label over 63 octets is refused by the resolver itself, before any server.
 */
const NOWHERE = 'x'.repeat(70) + '.test';

module.exports = [
  // ── baseline ───────────────────────────────────────────────────────────
  // Nothing below means anything until a plain request works through both, and
  // until the recording proxy is shown to record. A bench where both sides are
  // broken reports no differences at all.
  { name: 'baseline: no rule at all', rules: '' },
  { name: 'baseline: the recording proxy is reached', rules: `${P} proxy://${HOP}` },
  // The pattern carries a `/` on purpose. A bare `host:port` pattern fires
  // `host://`, `redirect://` and `statusCode://` but **not** a URL replacement —
  // both proxies agree on that, so it is not news, but three cases here were
  // silently doing nothing until the "does whistle answer differently with this
  // rule than without it" count found them.
  { name: 'baseline: the second origin is reachable', rules: `${P}/ http://${OTHER}/echo` },

  // ── host:// — the address moves, the Host header does not ──────────────
  { name: 'host: bare IP with a port', rules: `${P} host://${OTHER}` },
  { name: 'host: bare IP, no port keeps the request port', rules: `${P} host://127.0.0.1` },
  { name: 'host: port only', rules: `${P} host://:${PORTS.originB}` },
  { name: 'host: hostname with a port', rules: `${P} host://localhost:${PORTS.originB}` },
  { name: 'host: hostname, no port', rules: `${P} host://localhost` },
  { name: 'host: a name that does not resolve', rules: `${P} host://${NOWHERE}` },
  { name: 'host: an address that refuses the connection', rules: `${P} host://${CLOSED}` },
  { name: 'host: xhost falls back to the requested address', rules: `${P} xhost://${CLOSED}` },
  { name: 'host: xhost that works is still used', rules: `${P} xhost://${OTHER}` },
  // The port question, asked from the other side: a URL replacement moves the
  // destination *and* its port, and `host://` with no port of its own must keep
  // the port the replacement chose, not the one the client asked for.
  {
    name: 'host: no port, after a URL replacement moved the port',
    rules: `${P}/ http://${OTHER}/echo host://127.0.0.1`,
  },
  { name: 'host: two lines, the first wins', rules: `${P} host://${OTHER}\n${P} host://${CLOSED}` },
  { name: 'host: on a pattern that carries its own port', rules: `127.0.0.1:${PORTS.origin}/echo host://${OTHER}` },
  { name: 'host: a pattern whose port does not match', rules: `127.0.0.1:${PORTS.originB}/echo host://${OTHER}` },

  // ── host:// meeting other rules ────────────────────────────────────────
  { name: 'host: with a request header rule', rules: `${P} host://${OTHER} reqHeaders://x-a=1` },
  { name: 'host: with a response header rule', rules: `${P} host://${OTHER} resHeaders://x-r=1` },
  // A short circuit answers without a connection, so the address is never used.
  { name: 'host: with statusCode, which answers first', rules: `${P} host://${OTHER} statusCode://204` },
  { name: 'host: with file, which answers first', rules: `${P} host://${OTHER} file://({"mock":1})` },
  { name: 'host: with a redirect, which answers first', rules: `${P} host://${OTHER} redirect://http://elsewhere.test/x` },

  // ── the proxy family: what the hop is actually told ────────────────────
  { name: 'proxy: absolute form to a plain hop', rules: `${P} proxy://${HOP}` },
  { name: 'proxy: http-proxy is the same operator', rules: `${P} http-proxy://${HOP}` },
  { name: 'proxy: internal-proxy on a plain origin', rules: `${P} internal-proxy://${HOP}` },
  { name: 'proxy: internal-http-proxy on a plain origin', rules: `${P} internal-http-proxy://${HOP}` },
  { name: 'proxy: https2http-proxy on a plain origin', rules: `${P} https2http-proxy://${HOP}` },
  { name: 'proxy: http2https-proxy on a plain origin', rules: `${P} http2https-proxy://${HOP}` },
  { name: 'proxy: socks CONNECTs rather than asking', rules: `${P} socks://${SOCKS}` },
  // `socks5://` is a spelling nobody implements: upstream's proxy regex knows
  // `socks` only (`_original/lib/rules/protocols.js:81`), so the line falls
  // through to the URL-replacement slot. It is pointed at the *echo origin's
  // twin* on purpose — whistle refuses the scheme outright, and this port sends
  // the request there in cleartext HTTP, which the answer makes visible.
  { name: 'proxy: socks5 is not a protocol name', rules: `${P} socks5://${OTHER}` },
  { name: 'proxy: https-proxy puts TLS on the hop', rules: `${P} https-proxy://${TLSHOP}` },
  { name: 'proxy: internal-https-proxy puts TLS on the hop', rules: `${P} internal-https-proxy://${TLSHOP}` },
  // The same hop named by its IP. Node refuses to set an SNI server name to an
  // IP address, and whistle passes `proxyServername: proxyOptions.hostname`
  // unconditionally (`_original/lib/inspectors/res.js:362-364`), so upstream
  // cannot reach an `https-proxy://` written as an address at all.
  { name: 'proxy: https-proxy named by IP rather than name', rules: `${P} https-proxy://${TLSHOP_IP}` },
  { name: 'proxy: https-proxy at a hop that speaks no TLS', rules: `${P} https-proxy://${HOP}` },

  // ── credentials on the hop ─────────────────────────────────────────────
  { name: 'proxy: credentials in the URL', rules: `${P} proxy://user:pass@${HOP}` },
  // The password-less form: whistle base64s the credential verbatim, so this is
  // `Basic dXNlcg==` and not `Basic dXNlcjo=` (`res.js:291`).
  { name: 'proxy: a credential with no password', rules: `${P} proxy://user@${HOP}` },
  {
    name: 'proxy: the client\'s own Proxy-Authorization is forwarded',
    rules: `${P} proxy://${HOP}`,
    request: { headers: { 'proxy-authorization': 'Basic Y2xpZW50OnNlY3JldA==' } },
  },
  {
    name: 'proxy: the rule\'s credential beats the client\'s',
    rules: `${P} proxy://user:pass@${HOP}`,
    request: { headers: { 'proxy-authorization': 'Basic Y2xpZW50OnNlY3JldA==' } },
  },
  { name: 'proxy: credentials on a socks hop', rules: `${P} socks://user:pass@${SOCKS}` },
  { name: 'proxy: a socks credential with no password', rules: `${P} socks://user@${SOCKS}` },
  { name: 'proxy: credentials on a tunnelled hop', rules: `${P} proxy://user:pass@${HOP} host://${OTHER} lineProps://proxyHost` },

  // ── the shape of the proxy value ───────────────────────────────────────
  { name: 'proxy: a path written into the proxy URL', rules: `${P} proxy://${HOP}/some/path` },
  { name: 'proxy: a path and a query written into the proxy URL', rules: `${P} proxy://${HOP}/p?a=1` },
  { name: 'proxy: a scheme written into the proxy URL', rules: `${P} proxy://http://${HOP}` },
  { name: 'proxy: no address at all', rules: `${P} proxy://` },
  { name: 'proxy: ?host= redirects the hop\'s own connection', rules: `${P} proxy://${HOP}?host=${OTHER}` },
  { name: 'proxy: ignore drops the whole family', rules: `${P} proxy://${HOP} ignore://proxy` },
  { name: 'proxy: ignore by its own spelling', rules: `${P} socks://${SOCKS} ignore://socks` },

  // ── host:// and proxy:// together ──────────────────────────────────────
  // By default `host` wins outright and the proxy is dropped
  // (`_original/lib/rules/index.js:220-237`).
  { name: 'both: host wins and the proxy is dropped', rules: `${P} host://${OTHER} proxy://${HOP}` },
  { name: 'both: proxyHost uses the proxy and the host address', rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyHost` },
  { name: 'both: enable://proxyHost says the same', rules: `${P} host://${OTHER} proxy://${HOP} enable://proxyHost` },
  { name: 'both: proxyFirst prefers the proxy', rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyFirst` },
  { name: 'both: proxyHostOnly with a host rule', rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyHostOnly` },
  { name: 'both: proxyHostOnly with no host rule drops the proxy', rules: `${P} proxy://${HOP} lineProps://proxyHostOnly` },
  { name: 'both: ?proxyHost in the proxy URL', rules: `${P} host://${OTHER} proxy://${HOP}?proxyHost` },
  { name: 'both: host with a socks hop', rules: `${P} host://${OTHER} socks://${SOCKS} lineProps://proxyHost` },
  // `proxyTunnel`: the address the hop reaches is *itself* a proxy, so a second
  // CONNECT travels inside the first tunnel and asks it for the real origin.
  // Both halves are required — whistle guards it with `req._phost &&
  // req._proxyTunnel` (`_original/lib/util/index.js:889`), so the second case
  // has nothing to tunnel through and the flag does nothing.
  { name: 'both: proxyTunnel CONNECTs twice', rules: `${P} host://${HOP} proxy://${HOP} lineProps://proxyHost&proxyTunnel` },
  { name: 'both: proxyTunnel with no host override does nothing', rules: `${P} proxy://${HOP} lineProps://proxyTunnel` },
  { name: 'both: proxyTunnel via the proxy URL\'s own ?host=', rules: `${P} proxy://${HOP}?host=${HOP} enable://proxyTunnel` },

  // ── the connection-shaping flags ───────────────────────────────────────
  { name: 'hop: disable proxyConnection', rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyHost disable://proxyConnection` },
  {
    name: 'hop: disable proxyUA drops the echoed User-Agent',
    rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyHost disable://proxyUA`,
    request: { headers: { 'user-agent': 'Prober/1' } },
  },
  {
    name: 'hop: the client User-Agent is echoed onto a CONNECT',
    rules: `${P} host://${OTHER} proxy://${HOP} lineProps://proxyHost`,
    request: { headers: { 'user-agent': 'Prober/1' } },
  },

  // ── failure paths ──────────────────────────────────────────────────────
  { name: 'fail: a hop that refuses the connection', rules: `${P} proxy://${CLOSED}` },
  { name: 'fail: xproxy falls back to a direct connection', rules: `${P} xproxy://${CLOSED}` },
  { name: 'fail: a hop that answers 407', rules: `${P} proxy://${AUTH407}` },
  { name: 'fail: xproxy at a hop that answers 407', rules: `${P} xproxy://${AUTH407}` },
  { name: 'fail: a 407 on the CONNECT path', rules: `${P} host://${OTHER} proxy://${AUTH407} lineProps://proxyHost` },
  { name: 'fail: a socks hop that refuses', rules: `${P} socks://${CLOSED}` },
  { name: 'fail: a socks hop that is not a socks proxy', rules: `${P} socks://${HOP}` },
  { name: 'fail: a hop that accepts and never answers', rules: `${P} proxy://${HANG}` },

  // ── pac:// ─────────────────────────────────────────────────────────────
  { name: 'pac: PROXY names the hop', rules: `${P} pac://${PAC}/proxy.pac` },
  { name: 'pac: DIRECT goes straight out', rules: `${P} pac://${PAC}/direct.pac` },
  { name: 'pac: SOCKS names the socks hop', rules: `${P} pac://${PAC}/socks.pac` },
  { name: 'pac: SOCKS5 is not a word upstream reads', rules: `${P} pac://${PAC}/socks5.pac` },
  { name: 'pac: PROXY then DIRECT', rules: `${P} pac://${PAC}/proxy-then-direct.pac` },
  { name: 'pac: DIRECT then PROXY', rules: `${P} pac://${PAC}/direct-then-proxy.pac` },
  { name: 'pac: a proxy that is not there', rules: `${P} pac://${PAC}/dead.pac` },
  { name: 'pac: a proxy that is not there, then DIRECT', rules: `${P} pac://${PAC}/dead-then-direct.pac` },
  { name: 'pac: a file that is not served', rules: `${P} pac://${PAC}/missing.pac` },
  { name: 'pac: a proxy rule on the same line wins', rules: `${P} proxy://${HOP} pac://${PAC}/direct.pac` },

  // ── rule:// and rules:// ───────────────────────────────────────────────
  { name: 'rule: names a values entry holding more rules', rules: '```more\n' + `${P} proxy://${HOP}\n` + '```\n' + `${P} rule://more` },
  { name: 'rule: a values entry that does not exist', rules: `${P} rule://absent` },
  { name: 'rule: rules:// is the same include', rules: '```more\n' + `${P} proxy://${HOP}\n` + '```\n' + `${P} rules://more` },

  // ── forwarding meeting the rest of the rule set ────────────────────────
  { name: 'proxy: with a request header rule', rules: `${P} proxy://${HOP} reqHeaders://x-a=1` },
  { name: 'proxy: with statusCode, which answers first', rules: `${P} proxy://${HOP} statusCode://204` },
  { name: 'proxy: with a redirect, which answers first', rules: `${P} proxy://${HOP} redirect://http://elsewhere.test/x` },
  { name: 'proxy: with a URL replacement that moves the origin', rules: `${P}/ proxy://${HOP} http://${OTHER}/echo` },
  // The four cases below isolate divergence 7 — which URL the forwarding family
  // is matched against once a URL replacement has moved the destination. Each
  // pair asks the same question from both sides: a pattern that matches only the
  // *original* URL, and one that matches only the *replacement*.
  {
    name: 'reresolve: a proxy pattern matching only the original URL',
    rules: `${P}/ http://${OTHER}/echo\n${P} proxy://${HOP}`,
  },
  {
    name: 'reresolve: a proxy pattern matching only the replacement',
    rules: `${P}/ http://${OTHER}/echo\n${OTHER} proxy://${HOP}`,
  },
  {
    name: 'reresolve: a host pattern matching only the original URL',
    rules: `${P}/ http://${OTHER}/echo\n${P} host://127.0.0.1`,
  },
  {
    name: 'reresolve: a host pattern matching only the replacement',
    rules: `${P}/ http://${OTHER}/echo\n${OTHER} host://${P}`,
  },
  { name: 'proxy: on a pattern that carries its own port', rules: `127.0.0.1:${PORTS.origin}/echo proxy://${HOP}` },
  { name: 'proxy: on a POST with a body', rules: `${P} proxy://${HOP}`, request: { method: 'POST', body: 'payload', headers: { 'content-type': 'text/plain' } } },
  { name: 'proxy: two lines, the first wins', rules: `${P} proxy://${HOP}\n${P} proxy://${CLOSED}` },
  { name: 'proxy: a socks line and a proxy line share one slot', rules: `${P} socks://${SOCKS}\n${P} proxy://${HOP}` },

  // ── the two `x` spellings nothing had asked about ────────────────────────
  //
  // `xsocks://` and `xhttps-proxy://` were the last two names in this family
  // with no case anywhere. Each is asked twice, because one answer alone cannot
  // tell the fallback from a proxy that was never engaged: at a dead hop, where
  // the `x` prefix has to fall back to a direct connection, and at a live one,
  // where it must not.
  { name: 'fail: xsocks falls back to a direct connection', rules: `${P} xsocks://${CLOSED}` },
  { name: 'proxy: xsocks at a hop that works is still used', rules: `${P} xsocks://${SOCKS}` },
  // **This one differs, and the difference is upstream's.** Measured side by
  // side at the same dead hop, written by name so no SNI objection is in play:
  // `xproxy://` and `xsocks://` fall back and answer 200, plain
  // `https-proxy://` answers 502 promptly — and `xhttps-proxy://` **hangs**.
  // No fallback, no error, no response at all; the client times out. This port
  // falls back, which is what the `x` prefix is documented to mean and what its
  // three siblings do.
  { name: 'fail: xhttps-proxy falls back to a direct connection', rules: `${P} xhttps-proxy://localhost:${PORTS.closed}` },
  { name: 'proxy: xhttps-proxy at a hop that works is still used', rules: `${P} xhttps-proxy://${TLSHOP}` },
];
