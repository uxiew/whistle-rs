<script setup lang="ts">
// The named values, as the JSON object they are stored as.

import { ref, watch } from 'vue';
import CodeEditor from '../components/CodeEditor.vue';
import { saveValues, state } from '../store';

const editor = ref<InstanceType<typeof CodeEditor> | null>(null);

// Picking a key in the source list selects it in the editor.
watch(
  () => state.valueReveal.seq,
  () => editor.value?.reveal(`"${state.valueReveal.key}"`),
);
</script>

<template>
  <section class="pane">
    <div class="editor-wrap">
      <CodeEditor
        ref="editor"
        v-model="state.valuesText"
        language="json"
        placeholder='{ "mock.json": "{\"ok\":true}" }'
        @save="saveValues()"
      />
      <p class="hint">
        A JSON object of named values. Reference one from any operator as
        <code>{name}</code>, or pull a whole rules text in with <code>rule://name</code>.
      </p>
    </div>
    <div class="actions">
      <button class="btn primary" @click="saveValues()">Save</button>
      <span class="spacer"></span>
      <span class="status">{{ state.valuesStatus }}</span>
    </div>
  </section>
</template>
