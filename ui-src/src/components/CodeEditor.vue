<script setup lang="ts">
// A CodeMirror 6 view behind a `v-model`.
//
// Only what the two editor panes need is loaded — no autocomplete, no search,
// no lint — because every extension is bytes in a file that ships inside the
// proxy binary.

import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';
import { EditorState } from '@codemirror/state';
import type { Extension } from '@codemirror/state';
import { EditorView, drawSelection, keymap, lineNumbers, placeholder as cmPlaceholder } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, indentUnit } from '@codemirror/language';
import { json } from '@codemirror/lang-json';
import { whistle } from '../editor/whistle-language';
import { editorTheme, jsonPalette } from '../editor/theme';

const props = defineProps<{
  modelValue: string;
  language: 'whistle' | 'json';
  placeholder?: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: string];
  save: [];
}>();

const host = ref<HTMLDivElement | null>(null);
const view = shallowRef<EditorView | null>(null);

function languageExtensions(): Extension {
  return props.language === 'whistle' ? whistle() : [json(), jsonPalette(), bracketMatching()];
}

function makeState(doc: string): EditorState {
  return EditorState.create({
    doc,
    extensions: [
      lineNumbers(),
      history(),
      drawSelection(),
      EditorView.lineWrapping,
      EditorState.tabSize.of(2),
      indentUnit.of('  '),
      cmPlaceholder(props.placeholder ?? ''),
      keymap.of([
        // ⌘S / Ctrl-S saves the pane, which is the only shortcut a rules file
        // really wants; everything else is CodeMirror's own.
        { key: 'Mod-s', run: () => (emit('save'), true) },
        ...defaultKeymap,
        ...historyKeymap,
      ]),
      languageExtensions(),
      editorTheme,
      EditorView.updateListener.of((u) => {
        if (u.docChanged) emit('update:modelValue', u.state.doc.toString());
      }),
    ],
  });
}

onMounted(() => {
  view.value = new EditorView({ state: makeState(props.modelValue), parent: host.value! });
});

onBeforeUnmount(() => view.value?.destroy());

// A value that arrives from outside — a group loaded, a save round-tripped —
// replaces the document *and* the history, the way opening a file should.
watch(
  () => props.modelValue,
  (next) => {
    const v = view.value;
    if (!v || next === v.state.doc.toString()) return;
    v.setState(makeState(next));
  },
);

defineExpose({
  focus: () => view.value?.focus(),
  /** Select the first occurrence of `needle` and scroll it into view. */
  reveal(needle: string) {
    const v = view.value;
    if (!v) return;
    const at = v.state.doc.toString().indexOf(needle);
    if (at < 0) return;
    v.dispatch({
      selection: { anchor: at, head: at + needle.length },
      effects: EditorView.scrollIntoView(at, { y: 'center' }),
    });
    v.focus();
  },
});
</script>

<template>
  <div ref="host" class="cm-host"></div>
</template>
