// The whistle rules language, as a CodeMirror 6 `StreamLanguage`.
//
// A stream language because that is the shape the classifier already has: one
// pass over a line, emitting coloured runs. Nothing here decides *what* a token
// is — `whistle-classify.js` does, and it is shared verbatim with the Rust test
// that holds it against the parser. This file only carries its answers into
// CodeMirror's tag system.

import { StreamLanguage, HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import type { StreamParser } from '@codemirror/language';
import { Tag } from '@lezer/highlight';
import type { Extension } from '@codemirror/state';
import './whistle-classify.js';

/** One coloured run of a token: `len` characters in style `style`. */
interface Run {
  len: number;
  style: string;
}

interface Token {
  text: string;
  start: number;
  role: string;
}

type Classify = (line: string) => Token[];
type Pieces = (token: string, role: string) => Run[];

const shared = globalThis as unknown as {
  whistleClassify?: Classify;
  whistlePieces?: Pieces;
};
if (!shared.whistleClassify || !shared.whistlePieces) {
  throw new Error('whistle-classify.js did not register its entry points');
}
const classify = shared.whistleClassify;
const pieces = shared.whistlePieces;

/**
 * The roles the classifier names, as CodeMirror tags.
 *
 * Its own tags rather than the standard `tags.keyword`/`tags.def` because these
 * are not general syntax categories — "the token the proxy will match on" has no
 * equivalent in a programming language, and borrowing a name for it would make
 * the stylesheet lie about what it is colouring.
 */
export const whistleTags = {
  pattern: Tag.define(),
  operator: Tag.define(),
  filter: Tag.define(),
  props: Tag.define(),
  dead: Tag.define(),
  separator: Tag.define(),
  value: Tag.define(),
  capture: Tag.define(),
  reference: Tag.define(),
  comment: Tag.define(),
};

/**
 * The classifier's style names → those tags.
 *
 * None of these may be one of CodeMirror 5's legacy names (`def`, `keyword`,
 * `variable-2`, `error`, …): `StreamLanguage` resolves those against its own
 * built-in table *before* it looks in here, and a token so named silently comes
 * out styled as whatever the standard tag of that name paints — which is to
 * say, in this stylesheet, not styled at all.
 */
const tokenTable: Record<string, Tag> = {
  pattern: whistleTags.pattern,
  protocol: whistleTags.operator,
  filter: whistleTags.filter,
  props: whistleTags.props,
  dead: whistleTags.dead,
  separator: whistleTags.separator,
  value: whistleTags.value,
  capture: whistleTags.capture,
  reference: whistleTags.reference,
  comment: whistleTags.comment,
};

interface WhistleState {
  runs: Run[];
  at: number;
}

const parser: StreamParser<WhistleState> = {
  name: 'whistle',
  startState: () => ({ runs: [], at: 0 }),

  token(stream, state) {
    if (stream.sol()) {
      // One classification per line, cached as a queue of coloured runs.
      state.runs = [];
      for (const t of classify(stream.string)) {
        for (const p of pieces(t.text, t.role)) state.runs.push(p);
      }
      state.at = 0;
    }
    if (stream.eatSpace()) return null;
    if (stream.peek() === '#') {
      stream.skipToEnd();
      return 'comment';
    }

    const run = state.runs[state.at];
    if (!run) {
      stream.skipToEnd();
      return null;
    }
    state.at++;
    for (let i = 0; i < run.len && !stream.eol(); i++) stream.next();
    return run.style;
  },

  languageData: {
    commentTokens: { line: '#' },
  },

  tokenTable,
};

export const whistleLanguage = StreamLanguage.define(parser);

/**
 * The palette. Classes rather than inline styles so the colours stay in
 * `app.css` next to everything else the console paints, and so a theme switch
 * is a CSS variable change and nothing more.
 */
const whistleHighlight = HighlightStyle.define([
  { tag: whistleTags.pattern, class: 'tok-pattern' },
  { tag: whistleTags.operator, class: 'tok-operator' },
  { tag: whistleTags.filter, class: 'tok-filter' },
  { tag: whistleTags.props, class: 'tok-props' },
  { tag: whistleTags.dead, class: 'tok-dead' },
  { tag: whistleTags.separator, class: 'tok-separator' },
  { tag: whistleTags.value, class: 'tok-value' },
  { tag: whistleTags.capture, class: 'tok-capture' },
  { tag: whistleTags.reference, class: 'tok-reference' },
  { tag: whistleTags.comment, class: 'tok-comment' },
]);

export function whistle(): Extension {
  return [whistleLanguage, syntaxHighlighting(whistleHighlight)];
}
