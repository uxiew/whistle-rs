<script setup lang="ts">
// The named values: one key at a time, or the whole store as the JSON object it
// is stored as.
//
// Whole-object editing was the only way there was, which made every save a
// rewrite of every key — one mistyped brace and the lot goes. The per-key
// editor writes only the key it is showing.

import CodeEditor from '../components/CodeEditor.vue';
import { deleteValue, renameValue, saveValue, state } from '../store';
</script>

<template>
  <section class="pane">
    <div class="editor-wrap">
      <!-- Keyed on the selection so the editor is rebuilt, and its undo history
           with it: stepping back through a *previous* value's edits into this
           one would write the wrong content under this name. -->
      <CodeEditor
        v-if="state.valueKey !== null"
        :key="state.valueKey"
        v-model="state.valueText"
        language="json"
        placeholder="the value, referenced as {name}"
        @save="saveValue()"
      />
      <CodeEditor
        v-else
        v-model="state.valuesText"
        language="json"
        placeholder='{ "mock.json": "{\"ok\":true}" }'
        @save="saveValue()"
      />
      <p v-if="state.valueKey !== null" class="hint">
        Editing <code>{{ state.valueKey }}</code>. Reference it from any operator as
        <code>{{ '{' + state.valueKey + '}' }}</code>, or pull it in as a whole rules
        text with <code>rule://{{ state.valueKey }}</code>.
      </p>
      <p v-else class="hint">
        A JSON object of named values. Reference one from any operator as
        <code>{name}</code>, or pull a whole rules text in with <code>rule://name</code>.
      </p>
    </div>
    <div class="actions">
      <button class="btn primary" @click="saveValue()">Save</button>
      <template v-if="state.valueKey !== null">
        <button class="btn" @click="renameValue(state.valueKey)">Rename</button>
        <button class="btn" @click="deleteValue(state.valueKey)">Delete</button>
      </template>
      <span class="spacer"></span>
      <span class="status">{{ state.valuesStatus }}</span>
    </div>
  </section>
</template>
