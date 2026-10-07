// A whix *certificate chooser*: it runs during the TLS handshake of an
// intercepted connection and decides which certificate that connection gets —
// or that it should not be intercepted at all.
//
//   whix --node-plugin certs=examples/plugins/sni-certs.js
//   # rules:
//   #   pinned.example.com   sniCallback://certs           <- not intercepted
//   #   api.example.com      sniCallback://certs(mine)     <- our own certificate
//   #   other.example.com    sniCallback://certs(default)  <- whix's own
//
// One hook, and it is unlike every other hook in this SDK: there is no request.
// The handshake has not finished, so there is no method, no URL, no headers and
// no body — only what the client put in its ClientHello. `ctx` reflects that.
//
// What the hook may return:
//
//   false            do not intercept. The connection is relayed to the origin
//                    still encrypted; whix never sees inside it. Nothing
//                    else in this plugin system can turn interception off.
//   true             intercept, with the certificate whix would have
//                    generated for this name anyway.
//   {key, cert}      intercept, presenting this certificate (PEM, both halves).
//   ctx.reuse()      intercept, with the certificate we supplied last time.
//   nothing          no opinion, which means the generated certificate.
//
// Two things to keep in mind, both consequences of *when* this runs:
//
//  * A client is blocked on the answer, so do not issue a certificate per
//    connection. This example signs one per name, keeps it, and answers
//    `ctx.reuse()` when whix already has it — that is what
//    `ctx.certCacheName` / `ctx.certCacheTime` are for.
//  * Failure is forgiven. If this process throws, hangs or is not running,
//    whix intercepts with its own generated certificate and logs a
//    warning. That is a fallback, not an admission — unlike `onAuth`, this hook
//    is not a gate.
//
// The certificate below is minted by Node's own `crypto` at startup, so the
// example runs with no files and no openssl. A real chooser would read a key
// pair off disk, or fetch one from a CA it controls.

const { start } = require('../../sdk/whix-plugin');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const os = require('os');
const path = require('path');
const fs = require('fs');

/** Certificates we have issued, by server name. */
const issued = new Map();

/** When this process started, used as the `mtime` of everything it issues. */
const startedAt = Math.floor(Date.now() / 1000);

start({
  name: 'certs',

  sniCallback(ctx) {
    // `sniCallback://certs(<value>)` — the argument routes inside the plugin,
    // the same way `plugin://name/param` does for the request hooks.
    if (ctx.value === 'default') return true;

    // No argument at all: this host is not to be intercepted. The client and
    // the origin negotiate TLS with each other and whix relays bytes.
    if (!ctx.value) {
      log(`${ctx.servername}: declining interception`);
      return false;
    }

    // whix is telling us it still holds a certificate of ours for this
    // name, and when we issued it. If it is the one we would send anyway, say
    // so instead of shipping it again.
    const held = issued.get(ctx.servername);
    if (held && ctx.hasCachedCert && ctx.certCacheTime === held.mtime) {
      log(`${ctx.servername}: reusing the certificate from ${held.mtime}`);
      return ctx.reuse();
    }

    const cert = held || issue(ctx.servername);
    issued.set(ctx.servername, cert);
    log(`${ctx.servername}: supplying our own certificate`);
    return cert;
  },
});

/**
 * Mint a self-signed certificate for `servername`.
 *
 * Self-signed on purpose: a browser will refuse it, which is exactly how you
 * can tell from the outside that *this plugin's* certificate was served and not
 * whix's. Point a client that trusts nothing at it and read the subject.
 */
function issue(servername) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'whix-sni-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  try {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    fs.writeFileSync(
      keyPath,
      privateKey.export({ type: 'pkcs8', format: 'pem' })
    );
    // Node has no certificate *signing* API, so this shells out. A real plugin
    // would already have a key pair and would not need any of this.
    execFileSync('openssl', [
      'req', '-new', '-x509', '-key', keyPath, '-out', certPath,
      '-days', '30', '-subj', `/CN=${servername}/O=whix sniCallback example`,
      '-addext', `subjectAltName=DNS:${servername}`,
    ]);
    return {
      key: fs.readFileSync(keyPath, 'utf8'),
      cert: fs.readFileSync(certPath, 'utf8'),
      mtime: startedAt,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function log(message) {
  console.log(`[certs] ${message}`);
}
