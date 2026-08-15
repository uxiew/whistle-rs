// Real whistle, on a fixed port, with a storage directory of its own.
//
// Kept apart from the bench so the oracle can be left running between runs —
// whistle takes a few seconds to come up and there is no reason to pay it
// twice.
//
// `WHISTLE_PKG` names the package to load, so a second version can be pointed
// at from a directory of its own without disturbing the one `npm install` put
// here. It is how `bench-versions.js` asks whether an alignment was with
// whistle or only with 2.10.8.
const whistle = require(process.env.WHISTLE_PKG || 'whistle');
const path = require('path');

// The storage directory is keyed on the **version** as well as the port. Two
// releases sharing one directory would each read the other's state, and the
// answer to "did this behaviour change between versions" would be partly an
// answer about a data file written by the other one.
const tag = (() => {
  if (!process.env.WHISTLE_PKG) return '';
  try {
    return '-' + require(`${process.env.WHISTLE_PKG}/package.json`).version;
  } catch (e) {
    return '-alt';
  }
})();

// A console login, for `auth-bench.js` and for nothing else: every other bench
// installs its rules through the same console, and would be locked out. Named
// one at a time rather than spread, so an empty variable cannot become an empty
// username — which is how upstream spells "no login at all".
const auth = {};
if (process.env.W2_USER) auth.username = process.env.W2_USER;
if (process.env.W2_PASS) auth.password = process.env.W2_PASS;
if (process.env.W2_GUEST) auth.guestName = process.env.W2_GUEST;
if (process.env.W2_GUEST_PASS) auth.guestPassword = process.env.W2_GUEST_PASS;

whistle(
  {
    port: Number(process.env.PORT_BASE || 18700),
    // A directory per port, so several oracles can run side by side.
    baseDir: path.join(__dirname, `.data-${process.env.PORT_BASE || 18700}${tag}`),
    ...auth,
  },
  () => console.log('whistle listening on', process.env.PORT_BASE || 18700),
);
