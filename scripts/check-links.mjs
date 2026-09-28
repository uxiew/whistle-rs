#!/usr/bin/env node
// Checks every relative link and #anchor in the tracked Markdown files.
//
//   node scripts/check-links.mjs
//
// Exit 1 with one line per broken link, 0 when there are none. External links
// (http:, https:, mailto:) are not fetched: a gate that fails because someone
// else's site is down is a gate people learn to ignore.
//
// "Exists" means tracked by git, not merely present on this disk. A link to
// `_original/…` (the untracked upstream checkout) resolves here and 404s on
// GitHub, which is where these files are read.
//
// Anchors follow GitHub's rules: the heading text lower-cased, punctuation
// dropped, spaces turned into hyphens, and `-1`, `-2`… on repeats. Explicit
// `<a name="…">` and `id="…"` count too.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const tracked = new Set(
  execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean),
);
const trackedDirs = new Set();
for (const file of tracked) {
  for (let dir = path.posix.dirname(file); dir !== '.'; dir = path.posix.dirname(dir)) trackedDirs.add(dir);
}
const markdown = [...tracked].filter((f) => f.endsWith('.md'));

/** Heading text as GitHub renders it, before slugging: markup gone, words kept. */
function headingText(raw) {
  return raw
    .replace(/<[^>]+>/g, '')                  // inline HTML, e.g. <a name="x"></a>
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1') // links and images keep their text
    .replace(/`([^`]*)`/g, '$1')               // code spans keep their content
    .replace(/(\*\*|__|\*|~~)/g, '')          // emphasis markers
    .trim();
}

/** github-slugger: lower-case, drop everything but letters/marks/numbers/_/-/space. */
const slug = (text) => text.toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replace(/ /g, '-');

/** Lines outside fenced code blocks, with inline code blanked so its text is not read as a link. */
function proseLines(text) {
  const out = [];
  let fence = null;
  text.split('\n').forEach((line, i) => {
    const m = /^\s*(`{3,}|~{3,})/.exec(line);
    if (m) {
      if (!fence) fence = m[1][0];
      else if (m[1][0] === fence) fence = null;
      return;
    }
    if (!fence) out.push({ n: i + 1, line: line.replace(/(`+)[^`]*?\1/g, (s) => ' '.repeat(s.length)) });
  });
  return out;
}

/**
 * Every anchor a file offers. Headings are slugged from their real text — code
 * spans included, which is why this does not reuse `proseLines`' blanked lines.
 */
function anchorsOf(file) {
  const text = readFileSync(path.join(root, file), 'utf8');
  const anchors = new Set();
  const seen = new Map();
  let fence = null;
  for (const line of text.split('\n')) {
    const m = /^\s*(`{3,}|~{3,})/.exec(line);
    if (m) {
      if (!fence) fence = m[1][0];
      else if (m[1][0] === fence) fence = null;
      continue;
    }
    if (fence) continue;
    const h = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!h) continue;
    const base = slug(headingText(h[1]));
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    anchors.add(count ? `${base}-${count}` : base);
  }
  // Explicit anchors, anywhere, including inside headings.
  for (const m of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) anchors.add(m[1]);
  for (const m of text.matchAll(/\sid="([^"]+)"/g)) anchors.add(m[1]);
  return anchors;
}
const anchorCache = new Map(markdown.map((file) => [file, anchorsOf(file)]));

const LINK = /!?\[(?:[^\]\\]|\\.)*\]\(\s*<?([^)\s>]*)>?(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)/g;
const REF_DEF = /^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/;
const HREF = /\shref="([^"]+)"/g;

const broken = [];
for (const file of markdown) {
  const text = readFileSync(path.join(root, file), 'utf8');
  for (const { n, line } of proseLines(text)) {
    const targets = [...line.matchAll(LINK)].map((m) => m[1]);
    const def = REF_DEF.exec(line);
    if (def) targets.push(def[1]);
    for (const m of line.matchAll(HREF)) targets.push(m[1]);
    for (const target of targets) {
      const why = check(file, target);
      if (why) broken.push(`${file}:${n}: ${target} — ${why}`);
    }
  }
}

function check(file, target) {
  if (!target) return 'empty link';
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return null; // http:, https:, mailto:, …
  const hash = target.indexOf('#');
  const rawPath = hash === -1 ? target : target.slice(0, hash);
  const anchor = hash === -1 ? null : decodeURIComponent(target.slice(hash + 1));
  let resolved;
  if (!rawPath) resolved = file;
  else {
    const decoded = decodeURIComponent(rawPath.split('?')[0]);
    resolved = decoded.startsWith('/')
      ? path.posix.normalize(decoded.slice(1))
      : path.posix.normalize(path.posix.join(path.posix.dirname(file), decoded));
    resolved = resolved.replace(/\/$/, '');
    if (resolved.startsWith('..')) return 'points outside the repository';
    if (!tracked.has(resolved) && !trackedDirs.has(resolved)) {
      return anchorCache.has(resolved) ? null : 'no such tracked file';
    }
  }
  if (anchor === null) return null;
  if (!resolved.endsWith('.md')) {
    // GitHub's line anchors on source files: #L10, #L10-L20.
    return /^L\d+(-L\d+)?$/.test(anchor) ? null : `anchor #${anchor} on a non-Markdown file`;
  }
  const anchors = anchorCache.get(resolved);
  if (!anchors) return 'no such tracked file';
  return anchors.has(anchor) ? null : `no heading or anchor #${anchor} in ${resolved}`;
}

if (broken.length) {
  console.log(broken.join('\n'));
  console.log(`\n${broken.length} broken link(s) in ${markdown.length} Markdown files.`);
  process.exit(1);
}
console.log(`links: ${markdown.length} Markdown files, no broken relative links or anchors.`);
