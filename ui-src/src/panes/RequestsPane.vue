<script setup lang="ts">
// Table above, detail below, a handle between them.

import { onMounted, ref } from 'vue';
import DetailPanel from './DetailPanel.vue';
import RequestTable from './RequestTable.vue';
import {
  captureFiltering,
  captureRefused,
  clearSessions,
  countLabel,
  loadSessions,
  replaySelected,
  state,
} from '../store';

/**
 * The capture filters, shown on demand. Two boxes rather than one because they
 * are AND-ed with each other and OR-ed within themselves, which is `whistle`'s
 * arrangement and is hard to express in a single line.
 */
const showCapture = ref(captureFiltering.value);

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
      <button
        class="btn"
        :class="{ on: captureFiltering }"
        title="Keep or drop requests as they arrive, by URL, m:, H: or i:"
        @click="showCapture = !showCapture"
      >
        Capture filter{{ captureRefused ? ` (${captureRefused} hidden)` : '' }}
      </button>
      <span class="spacer"></span>
      <span class="status">{{ countLabel }}</span>
    </div>

    <!-- Deliberately below the table and not in a dialog: what these do is
         invisible — a request that never appears leaves no trace — so the boxes
         and the count of what they refused stay where the capture is. -->
    <div v-if="showCapture" class="capture-filter">
      <label>
        <span>Include</span>
        <input v-model="state.captureInclude" placeholder="keep only these — space separated, any may match" spellcheck="false" />
      </label>
      <label>
        <span>Exclude</span>
        <input v-model="state.captureExclude" placeholder="drop these — e.g. /heartbeat m:OPTIONS" spellcheck="false" />
      </label>
      <p class="hint">
        Applies to requests that arrive from now on; rows already listed stay.
        Conditions in one box are OR-ed, the two boxes are AND-ed. Prefixes:
        <code>m:</code> <code>H:</code> <code>i:</code> <code>s:</code>
        <code>t:</code>, or a bare word for the URL.
      </p>
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
