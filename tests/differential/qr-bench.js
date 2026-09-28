// The QR encoder, module by module, against the package whistle uses.
//
// `gui/mobile.md` is a page about typing a proxy address into a phone, and
// upstream's console shortens it by drawing a QR code per LAN address:
// point the camera at the screen and the phone opens the page that hands it the
// root certificate. whistle gets that from `qrcode@1.2.0`; this port has its
// own encoder (`src/qr.rs`) rather than a dependency for one dialog.
//
// **A QR code is either right or unreadable, and the difference is not
// visible.** So this compares the whole matrix — every module of every symbol —
// against `qrcode@1.2.0` at the same error-correction level, over the payloads
// the console actually draws and a few hundred it never will.
//
//   npm ci                                 # brings in qrcode@1.2.0, whistle's own version
//   npm run qr
//
// Nothing is started and no port is claimed: `whistle-rs qr` prints the matrix
// as rows of `0`/`1`, and the reference runs in this process.
//
// **A clean run is `differing: 0`.** A single wrong module is a symbol a phone
// may or may not read depending on the camera, which is the worst kind of
// wrong — so the comparison is exact and there is nothing to declare.
'use strict';
const path = require('path');
const { execFileSync } = require('child_process');

const RS_BIN = process.env.RS_BIN || path.join(__dirname, '..', '..', 'target', 'debug', 'whistle-rs');

let QRCode;
try {
  QRCode = require('qrcode');
} catch (e) {
  console.error('qr-bench needs the reference encoder, qrcode@1.2.0 from the lockfile:\n  npm ci');
  process.exit(2);
}

/**
 * The reference matrix, as an array of rows of 0/1.
 *
 * **The reference is held to byte mode.** Left to itself `qrcode` splits a URL
 * into numeric and alphanumeric segments, which is a smaller symbol for the
 * same string and a different matrix — a difference in *what was encoded*, not
 * in the encoder. This port is byte-mode only and says so; `versions()` below
 * measures what that costs, which is the claim worth checking.
 */
function reference(text) {
  // `create` is synchronous and returns the raw module data, which is what a
  // comparison wants — not a PNG, and not the SVG either proxy renders.
  const qr = QRCode.create([{ data: text, mode: 'byte' }], { errorCorrectionLevel: 'M' });
  const { size, data } = qr.modules;
  const rows = [];
  for (let y = 0; y < size; y++) {
    let row = '';
    for (let x = 0; x < size; x++) row += data[y * size + x] ? '1' : '0';
    rows.push(row);
  }
  return { version: qr.version, rows };
}

/** This port's matrix, printed by `whistle-rs qr --matrix`. */
function ours(text) {
  const out = execFileSync(RS_BIN, ['qr', '--matrix', text], { encoding: 'utf8' });
  const rows = out.trim().split('\n').filter((l) => /^[01]+$/.test(l));
  return { rows };
}

/**
 * The payloads.
 *
 * The first group is what the console draws — a root-certificate URL for each
 * shape of LAN address a machine can have. The rest push the encoder across
 * every version it claims: the version boundary is where a capacity table is
 * wrong, the character-count width changes at version 10, and the mask is
 * chosen per symbol, so a run that never changes length never changes mask.
 */
function payloads() {
  const out = [];
  const push = (group, text) => out.push({ group, text });

  for (const host of [
    '192.168.1.5', '10.0.0.2', '172.16.31.100', '127.0.0.1',
    '192.168.100.200', '10.1.1.1',
  ]) {
    push('what the console draws', `http://${host}:8899/rootCA.crt`);
    push('what the console draws', `http://${host}:8899/`);
  }
  // Every version boundary this encoder claims, from both sides.
  const CAPACITY = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213];
  for (const cap of CAPACITY) {
    push('at a version boundary', 'a'.repeat(cap));
    push('one inside a boundary', 'a'.repeat(cap - 1));
  }
  // Lengths in between, which is also how a variety of masks gets chosen.
  for (let n = 1; n <= 120; n++) {
    push('every length', 'x'.repeat(n));
  }
  // Content that is not one repeated byte: the mask penalty scores it
  // differently, and a wrong penalty picks a wrong mask.
  for (let i = 0; i < 40; i++) {
    push('varied content', `http://192.168.${i}.${(i * 7) % 250}:8899/rootCA.crt#${i}`);
  }
  // Bytes above ASCII, which is the mode this encoder uses and the one a URL
  // with a percent escape avoids — but not one a hostname always does.
  push('non-ascii', 'http://例え.テスト:8899/rootCA.crt');
  push('non-ascii', '主机名-with-ümlaut');
  // Not the empty payload: `qrcode@1.2.0` refuses it ("No input text"), so
  // there is nothing to compare against. This encoder accepts it and says so in
  // its own unit test — the console never draws one.
  return out;
}

/**
 * The SVG, read back into modules.
 *
 * The matrix being right and the *image* being right are two claims, and the
 * console shows the image. The renderer emits one `M<x> <y>h<s>v<s>h-<s>z` per
 * dark module over a four-module quiet zone, so parsing it back is exact —
 * a renderer that dropped, doubled or shifted a module would pass every matrix
 * comparison here and still be unreadable on screen.
 */
function svgModules(text, scale = 3) {
  const svg = execFileSync(RS_BIN, ['qr', '--svg', String(scale), text], { encoding: 'utf8' });
  const side = Number(/width="(\d+)"/.exec(svg)[1]) / scale;
  const size = side - 8; // the quiet zone, four modules either side
  const rows = Array.from({ length: size }, () => new Array(size).fill('0'));
  const re = /M(\d+) (\d+)h/g;
  let m;
  let count = 0;
  while ((m = re.exec(svg))) {
    const x = Number(m[1]) / scale - 4;
    const y = Number(m[2]) / scale - 4;
    if (x < 0 || y < 0 || x >= size || y >= size) return { error: `module outside the symbol at ${x},${y}` };
    rows[y][x] = '1';
    count++;
  }
  return { rows: rows.map((r) => r.join('')), count };
}

function main() {
  const cases = payloads();
  let differing = 0;
  const report = [];
  for (const { group, text } of cases) {
    let want, got;
    try { want = reference(text); } catch (e) {
      console.error(`reference refused ${JSON.stringify(text.slice(0, 30))}: ${e.message}`);
      process.exit(2);
    }
    try { got = ours(text); } catch (e) {
      differing++;
      report.push({ group, text: text.slice(0, 40), why: `whistle-rs qr failed: ${e.message}` });
      continue;
    }
    if (got.rows.length !== want.rows.length) {
      differing++;
      report.push({
        group, text: text.slice(0, 40),
        why: `size ${got.rows.length} vs ${want.rows.length} (version ${want.version})`,
      });
      continue;
    }
    const bad = [];
    for (let y = 0; y < want.rows.length; y++) {
      for (let x = 0; x < want.rows.length; x++) {
        if (want.rows[y][x] !== got.rows[y][x]) bad.push(`${x},${y}`);
      }
    }
    if (bad.length) {
      differing++;
      report.push({
        group, text: text.slice(0, 40), version: want.version,
        why: `${bad.length} module(s) differ, first at ${bad[0]}`,
      });
      continue;
    }
    // And the image drawn from that matrix is the same matrix.
    const drawn = svgModules(text);
    if (drawn.error || drawn.rows.join('\n') !== got.rows.join('\n')) {
      differing++;
      report.push({
        group, text: text.slice(0, 40), version: want.version,
        why: drawn.error || 'the SVG does not draw the matrix it encoded',
      });
    }
  }
  const byGroup = {};
  for (const c of cases) byGroup[c.group] = (byGroup[c.group] || 0) + 1;

  // What byte mode costs, over the payloads the console actually draws. The
  // module note in `src/qr.rs` claims "no human would ever notice"; this is the
  // claim, measured. A bigger symbol is not a failure — it is reported so that
  // "we skipped numeric and alphanumeric modes" stays an informed choice.
  const bigger = [];
  for (const { group, text } of cases) {
    if (group !== 'what the console draws') continue;
    const optimised = QRCode.create(text, { errorCorrectionLevel: 'M' }).version;
    const plain = reference(text).version;
    if (plain !== optimised) bigger.push({ text, byteMode: plain, optimised });
  }

  console.log(JSON.stringify({
    symbols: cases.length, groups: byGroup, differing, report,
    byteModeCosts: { largerSymbols: bigger.length, of: byGroup['what the console draws'], detail: bigger },
  }, null, 2));
  process.exit(differing ? 1 : 0);
}

main();
