// The whistle rules classifier — the part of the editor that decides what each
// token on a line *is*.
//
// The point of highlighting here is not colour for its own sake — it is that
// whistle's line grammar is *positional*, and the position is not obvious from
// reading a line. `example.com http://localhost:5173` is a pattern and a
// destination; `http://a.com/x host://1.2.3.4` is also a pattern and an
// operator, but the pattern is the token that *looks* like an operator's value.
// Getting that wrong is the single most common way to write a rule that
// silently does nothing, so the editor answers it: whatever is highlighted as a
// pattern is what the proxy will match on.
//
// The split below is the same algorithm the proxy runs (`index_of_pattern`,
// `src/rules/mod.rs`, ported from `_original/lib/rules/rules.js:1449`). Keep the
// two in step: a highlighter that disagrees with the parser is worse than none.
//
// ── why this file is plain script-shaped JavaScript ────────────────────────
// It is deliberately written with no `import`/`export` and no dependency on the
// editor, because it is evaluated in two very different places: bundled into
// the console by Vite (see `whistle-language.ts`), and evaluated *as a script*
// by a Rust test in `src/proxy/webui.rs`, which runs it in the JS engine the
// proxy already carries and holds its answers against the parser's own
// `split_line`. Keeping one copy is the whole point — two would drift, and the
// drift is exactly the bug this file exists to prevent. So: no module syntax,
// and the entry points are hung on `globalThis` at the bottom.

'use strict';

const WEB_SCHEMES = ['http', 'https', 'ws', 'wss', 'tunnel'];
const FILTER_PROTOS = ['includeFilter', 'excludeFilter', 'filter', 'ignore'];

const hasProtocol = (tok) => {
  const i = tok.indexOf('://');
  return i > 0 && /^[a-zA-Z0-9.-]+$/.test(tok.slice(0, i));
};

const protoOf = (tok) => {
  const i = tok.indexOf('://');
  return i > 0 ? tok.slice(0, i) : null;
};

/** whistle's `parseHost`: the bare-address shorthand is an IP literal only. */
function isAddress(tok) {
  const bracketed = /^\[([\da-fA-F:.]+)\](?::\d{1,5})?$/.exec(tok);
  if (bracketed) return true;
  const v4 = /^(?:::(?:ffff:)?)?(\d+\.\d+\.\d+\.\d+)(?::\d{1,5})?$/.exec(tok);
  if (v4) return v4[1].split('.').every((o) => Number(o) <= 255);
  // A bare v6 literal. Two colons at least, so `8080:80` — which `IpAddr`
  // rejects on the Rust side — is not mistaken for one here either.
  return /^[\da-fA-F:]+$/.test(tok) && (tok.match(/:/g) || []).length >= 2;
}

/** whistle's `isPattern`: can this token only ever be a pattern? */
function isPatternToken(tok) {
  if (/^[!$^]/.test(tok)) return true;
  if (/^!?:\d{1,5}$/.test(tok)) return true;                 // port pattern
  if (/^\/\/[^/]/.test(tok)) return true;                    // scheme-relative
  if (/^\/.+\/i?$/.test(tok)) return true;                   // /regexp/
  const proto = protoOf(tok);
  return proto !== null && WEB_SCHEMES.includes(proto);
}

/** whistle's `indexOfPattern`, over the tokens of one line. */
function indexOfPattern(tokens) {
  let ipIndex = -1;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i].text;
    if (isPatternToken(tok)) return i;
    if (!hasProtocol(tok)) {
      if (!isAddress(tok)) return i;
      if (ipIndex === -1) ipIndex = i;
    }
  }
  return ipIndex;
}

/** Split a line into `{ text, start }` tokens, stopping at a `#` comment. */
function lineTokens(line) {
  const hash = line.indexOf('#');
  const body = hash === -1 ? line : line.slice(0, hash);
  const out = [];
  const re = /\S+/g;
  let m;
  while ((m = re.exec(body))) out.push({ text: m[0], start: m.index });
  return out;
}

const isFilter = (tok) => FILTER_PROTOS.includes(protoOf(tok));
const isLineProps = (tok) => protoOf(tok) === 'lineProps';

/**
 * Decide the role of every token on a line: 'pattern', 'operator', 'filter'
 * or 'props'. Mirrors the two branches of the proxy's `parse_line`.
 */
function classify(line) {
  const tokens = lineTokens(line);
  const at = indexOfPattern(tokens);
  for (const t of tokens) {
    if (isLineProps(t.text)) t.role = 'props';
    else if (isFilter(t.text)) t.role = 'filter';
    else t.role = null;
  }
  if (at === -1) {
    // No pattern: the line configures nothing, and saying so is the point.
    for (const t of tokens) if (!t.role) t.role = 'dead';
    return tokens;
  }
  if (at === 0) {
    // pattern, then operators — whatever they look like.
    tokens.forEach((t, i) => { if (!t.role) t.role = i === 0 ? 'pattern' : 'operator'; });
    return tokens;
  }
  // An operator leads, and the rest split by shape.
  tokens.forEach((t, i) => {
    if (t.role) return;
    if (i === 0) { t.role = 'operator'; return; }
    t.role = (isPatternToken(t.text) || isAddress(t.text) || !hasProtocol(t.text))
      ? 'pattern' : 'operator';
  });
  return tokens;
}

/**
 * The style each role paints with.
 *
 * Named after the roles rather than in CodeMirror 5's vocabulary (`def`,
 * `keyword`, `variable-2`, …), which is what this mode used to emit: version 6
 * keeps a table of those legacy names and quietly resolves them to its own
 * standard tags before a stream parser's own table is consulted, so a mode that
 * still spells them that way cannot colour them. These names are ours, and are
 * carried into CodeMirror by `whistle-language.ts`.
 */
const ROLE_STYLE = {
  pattern: 'pattern',
  operator: 'protocol',
  filter: 'filter',
  props: 'props',
  dead: 'dead',
};

/**
 * Cut one token into the coloured runs it is made of, so an operator's
 * protocol reads differently from its value and a `$1` inside that value
 * stands out from the text around it.
 */
function pieces(tok, role) {
  // A pattern is one run, but its `*` wildcards and its `^`/`$`/`!` markers
  // are what decide how much it matches, so those are picked out.
  if (role === 'pattern') return markers(tok, ROLE_STYLE.pattern);
  // A line with no pattern configures nothing; the whole token says so.
  if (role === 'dead') return [{ len: tok.length, style: ROLE_STYLE.dead }];

  const proto = protoOf(tok);
  const valueStyle = role === 'filter' ? 'filter' : 'value';
  if (proto === null) return values(tok, valueStyle);
  return [
    { len: proto.length, style: ROLE_STYLE[role] },
    { len: 3, style: 'separator' },
  ].concat(values(tok.slice(proto.length + 3), valueStyle));
}

/** Highlight `*`, and the `^`/`$`/`!`/`$`-prefix markers, inside a pattern. */
function markers(tok, base) {
  const out = [];
  let buf = 0;
  const flush = () => { if (buf) { out.push({ len: buf, style: base }); buf = 0; } };
  for (let i = 0; i < tok.length; i++) {
    const c = tok[i];
    const special = (c === '*')
      || (i === 0 && (c === '^' || c === '!' || c === '$'))
      || (i === tok.length - 1 && c === '$' && tok[0] === '^');
    if (special) { flush(); out.push({ len: 1, style: 'capture' }); } else buf++;
  }
  flush();
  return out;
}

/** Highlight `$1`-style captures and `{key}` value references inside a value. */
function values(text, base) {
  const out = [];
  let buf = 0;
  const flush = () => { if (buf) { out.push({ len: buf, style: base }); buf = 0; } };
  for (let i = 0; i < text.length; i++) {
    const capture = /^\$\$?[&0-9]/.exec(text.slice(i));
    if (capture) { flush(); out.push({ len: capture[0].length, style: 'capture' }); i += capture[0].length - 1; continue; }
    const ref = /^\{[^}\s]*\}/.exec(text.slice(i));
    if (ref) { flush(); out.push({ len: ref[0].length, style: 'reference' }); i += ref[0].length - 1; continue; }
    buf++;
  }
  flush();
  return out;
}

// The two entry points, reachable from a bundler and from a bare script alike.
// `whistleClassify` is what the Rust test calls; it stands where CodeMirror 5's
// `CodeMirror.__whistleClassify` used to, and answers exactly the same thing.
globalThis.whistleClassify = classify;
globalThis.whistlePieces = pieces;
