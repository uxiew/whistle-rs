#!/usr/bin/env node
// Writes the license texts of everything a release binary carries that this
// repository did not write.
//
//   node scripts/third-party-licenses.mjs [--target <triple>] [--out FILE]
//
// Two sources, both read from lockfiles, never from the network:
//   * the Rust crates compiled into whistle-rs for <target> (default: the
//     host), from `cargo metadata` — each crate's LICENSE/COPYING/NOTICE files
//     as they sit in the Cargo registry;
//   * the npm packages the console bundle is built from, from ui-src's
//     package-lock.json — their files in ui-src/node_modules.
//
// Why a release needs this and not only our LICENSE: most of these licenses
// (MIT, BSD, ISC, Apache-2.0, Unicode-3.0, CDLA-Permissive-2.0, MPL-2.0) ask
// that their text or notice travels with any binary built from the code.
// Identical texts are printed once, followed by the packages they cover.
//
// It fails (exit 1) when a package declares no license at all. A package that
// declares one but ships no license file is listed by name and SPDX id, and
// named on stderr; that is the crate's own omission and is reported, not fixed.
//
// Needs `cargo fetch` (or any build) done, so the registry sources are on disk,
// and `npm ci` in ui-src.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
};
const host = /host: (\S+)/.exec(execFileSync('rustc', ['-vV'], { cwd: root, encoding: 'utf8' }))[1];
const target = arg('--target') || host;
const out = arg('--out') || path.join(root, 'THIRD-PARTY-LICENSES.md');

const LICENSE_FILE = /^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)([-._].*)?$/i;
const licenseFiles = (dir) => readdirSync(dir)
  .filter((f) => LICENSE_FILE.test(f))
  .sort()
  .map((f) => ({ name: f, text: readFileSync(path.join(dir, f), 'utf8').replace(/\r\n/g, '\n').trim() }));

// ── Rust ──────────────────────────────────────────────────────────────────
const meta = JSON.parse(execFileSync('cargo', [
  'metadata', '--locked', '--format-version', '1', '--filter-platform', target,
], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 }));
const byId = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const rootId = meta.resolve.root;
const crates = new Set();
const stack = [rootId];
while (stack.length) {
  const id = stack.pop();
  if (crates.has(id)) continue;
  crates.add(id);
  for (const d of nodes.get(id).deps) {
    // Normal edges only: build scripts and dev-dependencies do not end up in the binary.
    if (d.dep_kinds.some((k) => k.kind === null)) stack.push(d.pkg);
  }
}
crates.delete(rootId);
const rust = [...crates].map((id) => byId.get(id)).map((p) => ({
  name: p.name,
  version: p.version,
  license: p.license || (p.license_file ? `see ${p.license_file}` : null),
  files: licenseFiles(path.dirname(p.manifest_path)),
}));

// ── the console's npm packages ────────────────────────────────────────────
const uiLock = JSON.parse(readFileSync(path.join(root, 'ui-src', 'package-lock.json'), 'utf8')).packages;
const uiDeps = Object.keys(JSON.parse(readFileSync(path.join(root, 'ui-src', 'package.json'), 'utf8')).dependencies || {});
const npmSeen = new Set();
const queue = [...uiDeps];
while (queue.length) {
  const name = queue.pop();
  if (npmSeen.has(name)) continue;
  npmSeen.add(name);
  queue.push(...Object.keys(uiLock[`node_modules/${name}`]?.dependencies || {}));
}
const npm = [...npmSeen].map((name) => {
  const entry = uiLock[`node_modules/${name}`];
  const dir = path.join(root, 'ui-src', 'node_modules', name);
  if (!entry || !existsSync(dir)) throw new Error(`ui-src/node_modules/${name} is missing; run npm ci --prefix ui-src`);
  return { name, version: entry.version, license: entry.license || null, files: licenseFiles(dir) };
});

// ── write ─────────────────────────────────────────────────────────────────
const undeclared = [...rust, ...npm].filter((p) => !p.license);
const noFile = [...rust, ...npm].filter((p) => p.license && !p.files.length);

function section(title, pkgs) {
  const byText = new Map();
  for (const p of pkgs.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))) {
    for (const f of p.files) {
      const key = createHash('sha256').update(f.text).digest('hex');
      const entry = byText.get(key) || { text: f.text, who: [] };
      entry.who.push(`${p.name} ${p.version} (${f.name})`);
      byText.set(key, entry);
    }
  }
  const lines = [`## ${title} (${pkgs.length})`, ''];
  lines.push('| Package | Version | License |', '| --- | --- | --- |');
  for (const p of pkgs) lines.push(`| ${p.name} | ${p.version} | ${p.license || '**none declared**'}${p.files.length ? '' : ' (no license file shipped)'} |`);
  lines.push('');
  for (const { text, who } of byText.values()) {
    lines.push(`### ${who.length === 1 ? who[0] : `${who.length} packages`}`, '');
    if (who.length > 1) lines.push(who.map((w) => `- ${w}`).join('\n'), '');
    lines.push('```text', text, '```', '');
  }
  return lines.join('\n');
}

const version = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version', '1'], { cwd: root, encoding: 'utf8' }))
  .packages.find((p) => p.id === rootId)?.version;
writeFileSync(out, [
  `# Third-party licenses — whistle-rs ${version} for ${target}`,
  '',
  'Generated by `scripts/third-party-licenses.mjs` from `Cargo.lock` and `ui-src/package-lock.json`.',
  'whistle-rs itself is under the MIT license in `LICENSE`; where it comes from is in `NOTICE.md`.',
  '',
  section('Rust crates compiled into the binary', rust),
  section('npm packages the console is built from', npm),
].join('\n'));

console.log(`${path.relative(process.cwd(), out)}: ${rust.length} crates, ${npm.length} npm packages for ${target}`);
if (noFile.length) {
  console.error(`declared a license but ship no license file (listed by SPDX id only): ${noFile.map((p) => `${p.name} ${p.version}`).join(', ')}`);
}
if (undeclared.length) {
  console.error(`declare no license at all: ${undeclared.map((p) => `${p.name} ${p.version}`).join(', ')}`);
  process.exit(1);
}
