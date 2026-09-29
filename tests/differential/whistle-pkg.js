// Which whistle this run measures against — one answer for every script here.
//
// `WHISTLE_PKG` names the package directory; `run.js --whistle 2.10.10` sets it
// to `versions/2.10.10/node_modules/whistle`. Unset, it is the baseline `npm ci`
// put in `node_modules/` beside this file.
//
// Everything that loads or starts whistle goes through here. Before this file,
// `oracle.js` honoured `WHISTLE_PKG` and the benches that start their own
// whistle (`mode-bench.js` and two more) did `require('whistle')`: a run "against
// 2.10.10" measured its pair against 2.10.10 and its modes against 2.10.8, and
// said nothing about it.
//
// Declarations are measured against a version too, so this also decides which
// of them are in force: see `forVersion`.

'use strict';

const fs = require('fs');
const path = require('path');

/** The version `package.json` locks — the one every declaration was first measured on. */
const BASELINE = require('./package.json').dependencies.whistle;

const dir = (() => {
  const asked = process.env.WHISTLE_PKG
    ? path.resolve(process.env.WHISTLE_PKG)
    : path.join(__dirname, 'node_modules', 'whistle');
  try {
    // The real path: `rules-oracle.js` plants a stub in `require.cache`, which
    // Node keys by real path.
    return fs.realpathSync(asked);
  } catch (e) {
    throw new Error(`no whistle at ${asked}${process.env.WHISTLE_PKG ? ' (WHISTLE_PKG)' : '; run npm ci here'}`);
  }
})();

const version = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;

/**
 * The entries of a declaration list that hold for the whistle being measured.
 *
 * An entry's `upstream` is the version, or the list of versions, whose answer it
 * was measured against; `'any'` is for a divergence that is about this port
 * alone (a proxy naming itself, a clock read twice). An entry without one was
 * written before there were two versions, and means `BASELINE`.
 *
 * An entry for another version is left out entirely — it neither excuses a
 * difference nor counts as stale. So a run against a version no one has
 * measured yet reports every difference it finds, which is the measurement.
 */
function forVersion(entries) {
  return entries.filter((e) => {
    const u = e.upstream === undefined ? BASELINE : e.upstream;
    if (u === 'any') return true;
    return Array.isArray(u) ? u.includes(version) : u === version;
  });
}

module.exports = { dir, version, BASELINE, forVersion };
