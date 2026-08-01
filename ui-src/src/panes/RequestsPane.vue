<script setup lang="ts">
// Table above, detail below, a handle between them.

import { onMounted, ref } from 'vue';
import DetailPanel from './DetailPanel.vue';
import RequestTable from './RequestTable.vue';
import { clearSessions, countLabel, loadSessions, replaySelected, state } from '../store';

const HEIGHT_KEY = 'whistle-rs-detail-h';

/**
 * The detail panel's height is remembered, because the useful split depends on
 * what you are doing — reading a long body wants a tall panel, scanning a busy
 * capture wants a short one — and re-dragging it every reload is exactly the
 * kind of friction that makes a tool feel disposable.
 */
const detailHeight = ref<string | undefined>(undefined);
const dragging = ref(false);

function apply(px: number): void {
  const max = window.innerHeight - 180;
  detailHeight.value = Math.max(120, Math.min(px, max)) + 'px';
}

onMounted(() => {
  let saved = 0;
  try {
    saved = Number(localStorage.getItem(HEIGHT_KEY) || 0);
  } catch {
    /* private mode */
  }
  if (saved) apply(saved);
});

function startDrag(e: MouseEvent): void {
  e.preventDefault();
  dragging.value = true;
  const move = (ev: MouseEvent) => apply(window.innerHeight - ev.clientY);
  const up = () => {
    dragging.value = false;
    document.removeEventListener('mousemove', move);
    document.removeEventListener('mouseup', up);
    try {
      localStorage.setItem(HEIGHT_KEY, String(parseFloat(detailHeight.value || '0')));
    } catch {
      /* private mode */
    }
  };
  document.addEventListener('mousemove', move);
  document.addEventListener('mouseup', up);
}

function onClear(): void {
  if (!confirm('Clear all captured sessions?')) return;
  void clearSessions();
}
</script>

<template>
  <section class="pane">
    <RequestTable />

    <div class="actions">
      <button class="btn" @click="onClear">Clear</button>
      <button class="btn" @click="loadSessions()">Reload</button>
      <button class="btn" :disabled="state.selected === null" @click="replaySelected()">Replay</button>
      <label class="check"><input v-model="state.autoRefresh" type="checkbox" /> Auto refresh</label>
      <span class="spacer"></span>
      <span class="status">{{ countLabel }}</span>
    </div>

    <div
      class="splitter"
      :class="{ dragging }"
      title="Drag to resize"
      @mousedown="startDrag"
    ></div>

    <DetailPanel :style="detailHeight ? { flexBasis: detailHeight } : undefined" />
  </section>
</template>
