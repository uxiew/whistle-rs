<script setup lang="ts">
// The rules of the selected group, with the highlighting that says which token
// the proxy will match on.

import { onBeforeUnmount, onMounted } from 'vue';
import CodeEditor from '../components/CodeEditor.vue';
import { deleteGroup, saveRules, state } from '../store';

// Delete the selected group with the keyboard, since the source list has no
// room for a per-row button without crowding the name.
function onKeydown(e: KeyboardEvent): void {
  if (state.pane !== 'rules' || state.group === 'default') return;
  if (e.key !== 'Backspace' && e.key !== 'Delete') return;
  const active = document.activeElement;
  if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) return;
  if (active?.closest('.cm-editor')) return;
  e.preventDefault();
  void deleteGroup(state.group);
}

onMounted(() => document.addEventListener('keydown', onKeydown));
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown));
</script>

<template>
  <section class="pane">
    <div class="editor-wrap">
      <CodeEditor
        v-model="state.rulesText"
        language="whistle"
        placeholder="pattern  operator1  operator2  …"
        @save="saveRules()"
      />
      <p class="hint">
        One rule per line. <code>example.com http://localhost:5173</code> forwards a
        site; <code>host://1.2.3.4</code> only moves the socket. See <code>docs/RULES.md</code>.
      </p>
    </div>
    <div class="actions">
      <button class="btn primary" @click="saveRules()">Save</button>
      <span class="spacer"></span>
      <span class="status">{{ state.rulesStatus }}</span>
    </div>
  </section>
</template>
