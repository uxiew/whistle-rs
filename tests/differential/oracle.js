// Real whistle, on a fixed port, with a storage directory of its own.
//
// Kept apart from the bench so the oracle can be left running between runs —
// whistle takes a few seconds to come up and there is no reason to pay it
// twice.
//
// Which whistle comes from `whistle-pkg.js`: `WHISTLE_PKG`, or the baseline
// `npm ci` put here. `run.js --whistle 2.10.10` is how a second version runs.
const WHISTLE = require('./whistle-pkg');
const whistle = require(WHISTLE.dir);
const path = require('path');

// The storage directory is keyed on the **version** as well as the port. Two
// releases sharing one directory would each read the other's state, and the
// answer to "did this behaviour change between versions" would be partly an
// answer about a data file written by the other one. (`run.js` gives every run
// a scratch directory anyway; this is for an oracle started by hand.)
const tag = WHISTLE.version === WHISTLE.BASELINE ? '' : `-${WHISTLE.version}`;

// A console login, for `auth-bench.js` and for nothing else: every other bench
// installs its rules through the same console, and would be locked out. Named
// one at a time rather than spread, so an empty variable cannot become an empty
// username — which is how upstream spells "no login at all".
const auth = {};
if (process.env.W2_USER) auth.username = process.env.W2_USER;
if (process.env.W2_PASS) auth.password = process.env.W2_PASS;
if (process.env.W2_GUEST) auth.guestName = process.env.W2_GUEST;
if (process.env.W2_GUEST_PASS) auth.guestPassword = process.env.W2_GUEST_PASS;

// `run.js` points both of these somewhere of its own: the data directory at a
// scratch directory it deletes afterwards, so no run inherits another's rules
// or root CA, and the listener at loopback. Unset, they are what they always
// were — a directory beside this file, and every interface.
const baseDir = process.env.WHISTLE_DIFF_DATA
  || path.join(__dirname, `.data-${process.env.PORT_BASE || 18700}${tag}`);
const host = process.env.WHISTLE_DIFF_HOST ? { host: process.env.WHISTLE_DIFF_HOST } : {};

whistle(
  {
    port: Number(process.env.PORT_BASE || 18700),
    // A directory per port, so several oracles can run side by side.
    baseDir,
    ...host,
    ...auth,
  },
  () => console.log(`whistle ${WHISTLE.version} listening on`, process.env.PORT_BASE || 18700),
);
