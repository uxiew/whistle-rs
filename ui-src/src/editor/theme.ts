// CodeMirror dressed in the console's own variables, so there is one theme
// rather than a page theme and an editor theme that drift apart.
//
// Set here rather than in `app.css` because CodeMirror mounts its base theme
// into the document head itself, and a plain stylesheet only wins that fight by
// accident of load order. Every value is still a `var(--…)`, so switching
// `:root[data-theme]` repaints the editor along with everything else.

import { EditorView } from '@codemirror/view';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags as t } from '@lezer/highlight';
import type { Extension } from '@codemirror/state';

export const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    color: 'var(--fg)',
    backgroundColor: 'var(--bg-sub)',
    border: '1px solid var(--line)',
    borderRadius: '7px',
    fontSize: '12.5px',
    overflow: 'hidden',
  },
  '&.cm-focused': { outline: 'none', borderColor: 'var(--accent)' },
  '.cm-scroller': {
    fontFamily: 'var(--mono)',
    lineHeight: '1.6',
    padding: '6px 0',
  },
  '.cm-content': { caretColor: 'var(--fg)' },
  '.cm-gutters': {
    backgroundColor: 'var(--bg-sub)',
    color: 'var(--fg-faint)',
    border: 'none',
    borderRight: '1px solid var(--line-soft)',
    fontSize: '11px',
  },
  '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--fg-dim)' },
  '.cm-activeLine': { backgroundColor: 'transparent' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--fg)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': {
    backgroundColor: 'color-mix(in srgb, var(--accent) 30%, transparent)',
  },
  '.cm-placeholder': { color: 'var(--fg-faint)' },
  '.cm-matchingBracket, &.cm-focused .cm-matchingBracket': {
    backgroundColor: 'transparent',
    color: 'var(--accent)',
    fontWeight: '600',
  },
  '.cm-nonmatchingBracket': { color: 'var(--err)' },
});

/**
 * JSON, in the same palette as the rules editor: a key reads like a pattern,
 * a string like an operator's value.
 */
const jsonHighlight = HighlightStyle.define([
  { tag: t.propertyName, class: 'tok-pattern' },
  { tag: t.string, class: 'tok-value' },
  { tag: t.number, class: 'tok-filter' },
  { tag: [t.bool, t.null], class: 'tok-operator' },
  { tag: t.punctuation, class: 'tok-separator' },
  { tag: t.invalid, class: 'tok-dead' },
]);

export function jsonPalette(): Extension {
  return syntaxHighlighting(jsonHighlight);
}
