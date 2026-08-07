<script setup lang="ts">
// Import and export, at the foot of a source list.
//
// Two exports, because they answer different questions. The plain one is the
// thing itself — a rule group is a rules file, a value is its content — which
// is what goes into a ticket or a repository. The bundle behind "Backup all" is
// every group with its switch plus the whole values store, and is the only form
// a *setup* survives in: taken one group at a time, which of them were on is
// lost, and the values those rules refer to are lost with them.

import { ref } from 'vue';
import { importFile } from '../store';

defineProps<{
  /**
   * What the plain export writes, named in full for the tooltip. The button
   * itself just says "Export": three labels have to share one sidebar's width,
   * and the source list above already shows which thing is selected.
   */
  exportTitle: string;
}>();

const emit = defineEmits<{ export: [] }>();

const picker = ref<HTMLInputElement | null>(null);

async function chosen(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  // Cleared so the same file can be picked twice: re-importing after an edit on
  // disk is ordinary, and `change` does not fire for an unchanged value.
  input.value = '';
  if (file) await importFile(file);
}
</script>

<template>
  <div class="side-transfer">
    <button title="Read a rules file, a value, or an exported bundle" @click="picker?.click()">
      Import…
    </button>
    <button :title="exportTitle" @click="emit('export')">Export</button>
    <a href="/api/export" download title="Every group, its switch, and the values">Backup all</a>
    <input
      ref="picker"
      type="file"
      accept=".rules,.txt,.json,text/plain,application/json"
      hidden
      @change="chosen"
    />
  </div>
</template>
