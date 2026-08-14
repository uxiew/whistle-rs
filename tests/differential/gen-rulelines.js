// Regenerate `cases-rulelines.js` from a checkout of the whistle documentation.
//
//   git clone --depth 1 https://github.com/avwo/whistle /tmp/whistle
//   node gen-rulelines.js /tmp/whistle/docs/docs
//
// The corpus is every concrete rule line the documentation prints, kept
// verbatim. It exists as a generated file rather than as a fetch at run time so
// that a bench run needs no network and so that a change in the corpus shows up
// as a diff — the same reason `cases-docs.js` is written down.
//
// What is kept: a line inside a fenced block, in a block that is not tagged as
// another language, that parses as `pattern operator…` — either some token
// carries a `proto://`, or the line is exactly two host-or-path-shaped tokens.
// Prose, `Key: value` dumps and JavaScript fragments are dropped. Nothing else
// is filtered, and nothing is rewritten: `rules-oracle.js` only ever *resolves*
// these lines, so a line naming `www.test.com` or `/Users/john/mock.json` is
// safe to keep as written, which is precisely the half `cases-docs.js` has to
// drop.

'use strict';

const fs = require('fs');
const path = require('path');

const HEADER = `// Every concrete rule line the whistle documentation prints, kept **verbatim**.
//
// Generated from \`docs/docs/**/*.md\` in <https://github.com/avwo/whistle> — the
// 100 rule pages that wproxy.org renders, and also the pages beside them:
// getting-started, the FAQ, the console guides and the plugin docs. Every
// fenced block was read and every line that parses as \`pattern operator…\` kept,
// deduplicated, and left exactly as the site prints it.
//
// **Nothing is rewritten here, and that is the point.** \`cases-docs.js\` had to
// repoint each pattern at a live echo origin and drop every line that would
// make a proxy dial a stranger — it runs real requests. This corpus is only
// ever *resolved*, by \`rules-oracle.js\`, so \`/Users/john/mock.json\`,
// \`www.test.com\` and \`10.1.0.1:8080\` can all stay as written. The lines that
// bench had to leave out are exactly the ones a first rules file is most likely
// to copy.
//
// Regenerate with \`node gen-rulelines.js <path-to-whistle>/docs/docs\`; do not
// hand-edit. A corpus somebody composed asks what its author thought to ask.
`;

const OPERATOR = /^[\w.-]+:\/\//;
const HOSTISH = /^[\w*.$^!/-]+(:\d+)?(\/[^\s]*)?$/;
const CODE_LANGS = ['js', 'sh', 'bash', 'json', 'html', 'ts', 'javascript'];

function walk(dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

function isRuleLine(line) {
  if (line.length > 300) return false;
  // A JavaScript fragment or a `Key: value` dump — unless the line is plainly
  // `pattern proto://…`, which several plugin pages print inside prose blocks.
  if (
    /console\.|function\s*\(|=>|require\(|module\.exports|^\s*[\w'"-]+\s*:/.test(line) &&
    !/^\S+\s+\S*:\/\//.test(line)
  ) {
    return false;
  }
  const tokens = line.split(/\s+/);
  if (tokens.some((t) => OPERATOR.test(t))) return true;
  return tokens.length === 2 && HOSTISH.test(tokens[0]) && HOSTISH.test(tokens[1]);
}

function main() {
  const root = process.argv[2];
  if (!root) {
    console.error('usage: node gen-rulelines.js <path-to-whistle>/docs/docs');
    process.exit(2);
  }
  const seen = new Map();
  for (const file of walk(root)) {
    const rel = path.relative(root, file);
    const text = fs.readFileSync(file, 'utf8');
    for (const block of text.match(/```[\s\S]*?```/g) || []) {
      const lang = (/^```\s*(\w+)/.exec(block) || [])[1] || '';
      if (CODE_LANGS.includes(lang)) continue;
      for (const raw of block.split('\n').slice(1, -1)) {
        const line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) continue;
        if (!isRuleLine(line)) continue;
        if (!seen.has(line)) seen.set(line, new Set());
        seen.get(line).add(rel);
      }
    }
  }

  const entries = [...seen.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const body = entries
    .map(([line, srcs]) => {
      const src = [...srcs].sort().join(', ');
      return `  { rules: ${JSON.stringify(line)}, src: ${JSON.stringify(src)} },`;
    })
    .join('\n');
  const out = path.join(__dirname, 'cases-rulelines.js');
  fs.writeFileSync(out, `${HEADER}\nmodule.exports = [\n${body}\n];\n`);
  console.log(`wrote ${entries.length} lines to ${out}`);
}

main();
