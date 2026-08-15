// The console **login**, asked of both proxies with the same credentials.
//
// `-n`/`-w` name the account that may do anything and `-N`/`-W` one that may
// only read. Nothing else in this directory can ask about them: every other
// bench installs its rules through the console it is measuring, so a corpus
// that locked itself out would have nothing left to say. This one never
// installs a rule — its whole subject is which requests get past the gate.
//
// **What is compared, and what is not.** The two consoles are different
// programs with different route tables, so comparing what a path *answers*
// would be comparing the tables. What is comparable is the gate in front of
// them: the status, and whether a `WWW-Authenticate` came back. A path that
// exists in neither (`/no-such-route`) isolates it exactly — 401 when the
// credentials are wrong, 404 when they are right, in both, and the difference
// between those two is the gate and nothing else.
//
// The prose and the content type of the 401 body are each proxy's own words and
// are not compared, the same licence `harness.js` gives the 404s.
//
//   W2_USER=admin W2_PASS=s3cret W2_GUEST=guest W2_GUEST_PASS=look \
//     PORT_BASE=19800 node oracle.js &
//   cargo run -- --port 19801 --no-persist --dir /tmp/rs-auth \
//     -n admin -w s3cret -N guest -W look &
//   PORT_BASE=19800 node auth-bench.js
//     19800 whistle · 19801 whistle-rs · 19802 the echo origin

const http = require('http');

const BASE = Number(process.env.PORT_BASE || 19800);
const [W, RS, ORIGIN] = [BASE, BASE + 1, BASE + 2];

const USER = 'admin';
const PASS = 's3cret';
const GUEST = 'guest';
const GUEST_PASS = 'look';

const b64 = (text) => Buffer.from(text).toString('base64');
const ADMIN = b64(`${USER}:${PASS}`);
const GUEST_B64 = b64(`${GUEST}:${GUEST_PASS}`);

/**
 * Divergences that are deliberate, each with the reason. Kept here rather than
 * left out of the corpus: a case that is not written proves nothing, and one
 * that is written and excused says what this port decided and why.
 */
const EXPECTED = [
  {
    match: (name) => /^static suffix/.test(name),
    why: "upstream exempts every path ending .ico/.js/.css/.png from the login "
      + '(`STATIC_SRC_RE`, `biz/webui/lib/index.js:44`) so its login page can load '
      + 'its own assets. This console is one self-contained page with no assets to '
      + 'fetch, so the exemption would only be a hole.',
  },
];

/** One request, reduced to the two things the gate decides. */
function probe(port, { method = 'GET', path = '/no-such-route', headers = {} }) {
  return new Promise((resolve) => {
    const req = http.request({ port, path, method, headers }, (r) => {
      r.resume();
      r.on('end', () =>
        resolve({
          status: r.statusCode,
          // Presence, not the value: upstream's carries a leading space
          // (`' Basic realm=User Login'`) which no client sees, since a header
          // value's leading whitespace is not part of it.
          challenged: r.headers['www-authenticate'] != null,
        }),
      );
    });
    req.on('error', (e) => resolve({ status: 0, challenged: false, error: e.code }));
    req.end();
  });
}

/** A proxied request, to ask whether the login gates traffic as well as the UI. */
function throughProxy(port, headers = {}) {
  return new Promise((resolve) => {
    const req = http.request(
      { port, path: `http://127.0.0.1:${ORIGIN}/echo`, method: 'GET', headers },
      (r) => {
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () =>
          resolve({ status: r.statusCode, body: Buffer.concat(chunks).toString().slice(0, 40) }),
        );
      },
    );
    req.on('error', (e) => resolve({ status: 0, body: e.code }));
    req.end();
  });
}

/** The origin: says only that it was reached. */
function startOrigin() {
  return new Promise((res) => {
    const srv = http.createServer((q, r) => {
      r.writeHead(200, { 'content-type': 'text/plain' });
      r.end('ORIGIN');
    });
    srv.listen(ORIGIN, () => res(srv));
  });
}

/**
 * The matrix. Every case is one request shape put to both consoles; `name` is
 * what it is asking, not what it expects, because what upstream does is the
 * answer and not the question.
 */
const CASES = [
  // ── the gate, on a path neither console has ────────────────────────────
  { name: 'no credentials at all' },
  { name: 'the right credentials, Authorization',
    headers: { authorization: `Basic ${ADMIN}` } },
  { name: 'the scheme in lower case',
    headers: { authorization: `basic ${ADMIN}` } },
  { name: 'the scheme in upper case',
    headers: { authorization: `BASIC ${ADMIN}` } },
  // `parseAuth` takes six characters off only when the value matches `/^Basic /i`
  // and otherwise base64-decodes the whole string (`lib/util/common.js:911-928`),
  // so upstream accepts credentials with no scheme at all.
  { name: 'no scheme, just the base64',
    headers: { authorization: ADMIN } },
  { name: 'two spaces after the scheme',
    headers: { authorization: `Basic  ${ADMIN}` } },
  { name: 'a trailing space',
    headers: { authorization: `Basic ${ADMIN} ` } },
  { name: 'the wrong password',
    headers: { authorization: `Basic ${b64(`${USER}:wrong`)}` } },
  { name: 'the wrong username',
    headers: { authorization: `Basic ${b64(`root:${PASS}`)}` } },
  { name: 'the username alone, no colon',
    headers: { authorization: `Basic ${b64(USER)}` } },
  { name: 'a colon and nothing else',
    headers: { authorization: `Basic ${b64(':')}` } },
  { name: 'an empty Authorization header',
    headers: { authorization: '' } },
  { name: 'base64 of nothing',
    headers: { authorization: 'Basic ' } },
  { name: 'not base64 at all',
    headers: { authorization: 'Basic @@@@@@' } },
  { name: 'a Bearer token',
    headers: { authorization: `Bearer ${ADMIN}` } },
  // The password keeps every colon after the first: `split_once(':')`, and
  // upstream's `auth.indexOf(':')` with `substring(index + 1)`.
  { name: 'a password that itself contains a colon',
    headers: { authorization: `Basic ${b64(`${USER}:s3:cret`)}` } },
  // `Buffer.from(s, 'base64')` does not insist on the padding. Both the guest
  // and the admin are asked, because only one of the two encodes to a length
  // that needs any: `admin:s3cret` is a clean 16 characters and would prove
  // nothing on its own.
  { name: 'base64 with the padding trimmed',
    headers: { authorization: `Basic ${GUEST_B64.replace(/=+$/, '')}` } },
  { name: 'base64 with the padding trimmed, wrong password',
    headers: { authorization: `Basic ${b64(`${GUEST}:wrongish`).replace(/=+$/, '')}` } },

  // ── the same credentials, in the other two places upstream reads ───────
  { name: 'Proxy-Authorization instead',
    headers: { 'proxy-authorization': `Basic ${ADMIN}` } },
  { name: 'Proxy-Authorization with the wrong password',
    headers: { 'proxy-authorization': `Basic ${b64(`${USER}:wrong`)}` } },
  // `Authorization` is read first and is not fallen back on when it is wrong:
  // upstream `req.headers.authorization || req.headers['proxy-authorization']`.
  { name: 'a wrong Authorization beside a right Proxy-Authorization',
    headers: { authorization: `Basic ${b64(`${USER}:wrong`)}`,
      'proxy-authorization': `Basic ${ADMIN}` } },
  { name: 'the query parameter',
    path: `/no-such-route?authorization=${encodeURIComponent(`Basic ${ADMIN}`)}` },
  { name: 'the query parameter with no scheme',
    path: `/no-such-route?authorization=${encodeURIComponent(ADMIN)}` },
  { name: 'the query parameter, wrong password',
    path: `/no-such-route?authorization=${encodeURIComponent(`Basic ${b64(`${USER}:wrong`)}`)}` },
  { name: 'the query parameter beside another parameter',
    path: `/no-such-route?a=1&authorization=${encodeURIComponent(`Basic ${ADMIN}`)}&b=2` },
  { name: 'a wrong header beside a right query parameter',
    headers: { authorization: `Basic ${b64(`${USER}:wrong`)}` },
    path: `/no-such-route?authorization=${encodeURIComponent(`Basic ${ADMIN}`)}` },

  // ── the read-only account ─────────────────────────────────────────────
  { name: 'the guest reading',
    headers: { authorization: `Basic ${GUEST_B64}` } },
  { name: 'the guest writing (POST)',
    method: 'POST', headers: { authorization: `Basic ${GUEST_B64}` } },
  { name: 'the guest writing (PUT)',
    method: 'PUT', headers: { authorization: `Basic ${GUEST_B64}` } },
  { name: 'the guest writing (DELETE)',
    method: 'DELETE', headers: { authorization: `Basic ${GUEST_B64}` } },
  { name: 'the guest with a HEAD',
    method: 'HEAD', headers: { authorization: `Basic ${GUEST_B64}` } },
  { name: 'the guest with the wrong password',
    headers: { authorization: `Basic ${b64(`${GUEST}:wrong`)}` } },
  { name: 'the admin writing (POST)',
    method: 'POST', headers: { authorization: `Basic ${ADMIN}` } },
  { name: 'the admin writing (DELETE)',
    method: 'DELETE', headers: { authorization: `Basic ${ADMIN}` } },
  { name: 'a POST with no credentials',
    method: 'POST' },

  // ── the suffix exemption ──────────────────────────────────────────────
  { name: 'static suffix .js, no credentials', path: '/no-such-route.js' },
  { name: 'static suffix .css, no credentials', path: '/no-such-route.css' },
  { name: 'static suffix .png, no credentials', path: '/no-such-route.png' },
  { name: 'static suffix .ico, no credentials', path: '/no-such-route.ico' },
  { name: 'static suffix .JS in capitals, no credentials', path: '/no-such-route.JS' },
  { name: 'static suffix .html is not one of them', path: '/no-such-route.html' },
  // Express's `req.path` has the query cut off it already, so this is a suffix
  // like any other — measured, not assumed.
  { name: 'static suffix .js ahead of a query', path: '/no-such-route.js?a=1' },
];

async function main() {
  const origin = await startOrigin();
  let ran = 0;
  let differing = 0;
  let declared = 0;
  const report = [];
  const excused = [];

  for (const c of CASES) {
    const [w, rs] = [await probe(W, c), await probe(RS, c)];
    ran++;
    const problems = [];
    if (w.status !== rs.status) problems.push(`status: whistle=${w.status} rs=${rs.status}`);
    if (w.challenged !== rs.challenged) {
      problems.push(`www-authenticate: whistle=${w.challenged} rs=${rs.challenged}`);
    }
    if (!problems.length) continue;
    const reason = EXPECTED.find((e) => e.match(c.name));
    if (reason) {
      declared++;
      excused.push({ name: c.name, problems, why: reason.why });
    } else {
      differing++;
      report.push({ name: c.name, problems });
    }
  }

  // ── the root certificate answers before the login does ────────────────
  //
  // Each console spells it its own way, so this is the one place the two are
  // asked different paths: the question is whether a device that cannot log in
  // can still fetch the certificate, and both have to be asked in their own
  // words for it to be a question at all.
  for (const [name, wPath, rsPath] of [
    ['the root certificate, no credentials', '/cgi-bin/rootca', '/rootCA.crt'],
  ]) {
    const [w, rs] = [await probe(W, { path: wPath }), await probe(RS, { path: rsPath })];
    ran++;
    if (w.status !== rs.status) {
      differing++;
      report.push({ name, problems: [`status: whistle=${w.status} rs=${rs.status}`] });
    }
  }

  // ── the login gates the console, not the traffic ──────────────────────
  //
  // whistle reads `config.username`/`config.password` in `biz/webui` and
  // nowhere else, so a proxy with a login still proxies for anyone. A port that
  // got this wrong would break every client the moment a login was set, and
  // nothing above would notice: all of it speaks to the console.
  for (const [name, headers] of [
    ['proxied traffic with no credentials', {}],
    ['proxied traffic with wrong credentials',
      { 'proxy-authorization': `Basic ${b64(`${USER}:wrong`)}` }],
    ['proxied traffic with the right credentials',
      { 'proxy-authorization': `Basic ${ADMIN}` }],
  ]) {
    const [w, rs] = [await throughProxy(W, headers), await throughProxy(RS, headers)];
    ran++;
    if (w.status !== rs.status || w.body !== rs.body) {
      differing++;
      report.push({
        name,
        problems: [`answer: whistle=${w.status} ${JSON.stringify(w.body)} `
          + `rs=${rs.status} ${JSON.stringify(rs.body)}`],
      });
    }
  }

  origin.close();
  console.log(JSON.stringify({ ran, differing, declared, report, excused }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
