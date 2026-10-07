<script setup lang="ts">
// Table above, detail below, a handle between them.

import { onMounted, ref } from 'vue';
import DetailPanel from './DetailPanel.vue';
import RequestTable from './RequestTable.vue';
import {
  captureFiltering,
  captureGaps,
  captureRefused,
  clearSessions,
  purgeSessions,
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

const HEIGHT_KEY = 'whix-detail-h';

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
  // Clear tidies the list. What persistence saved stays on disk and is back
  // after a restart, which a plain "clear all?" did not say.
  if (!confirm('Clear the list? History saved on disk is kept and comes back on the next start — Delete history removes it.')) return;
  void clearSessions();
}

function onPurge(): void {
  if (!confirm('Delete every captured session, including the history saved on disk? This cannot be undone.')) return;
  void purgeSessions();
}
</script>

<template>
  <section class="pane">
    <RequestTable />

    <div class="actions">
      <button class="btn" @click="onClear">Clear</button>
      <button class="btn" @click="onPurge">Delete history</button>
      <button class="btn" @click="loadSessions()">Reload</button>
      <button class="btn" :disabled="state.selected === null" @click="replaySelected()">Replay</button>
      <label class="check"><input v-model="state.autoRefresh" type="checkbox" /> Auto refresh</label>
      <button
        class="btn"
        :class="{ on: captureFiltering }"
        title="Show or hide requests in this list as they arrive. The proxy still records them."
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
        <code>t:</code> <code>e:</code> <code>fc:</code>, or a bare word for the URL.
        This only changes what the list shows: a hidden request is still
        recorded, exported and kept on disk. To keep one out of the record, use
        <code>enable://hide</code> in the rules.
      </p>
      <!-- A condition these boxes cannot act on used to be dropped without a
           word, and a box holding only such conditions let everything in. -->
      <p v-if="captureGaps.length" class="hint warn">
        <span v-for="g in captureGaps" :key="g.prefix">
          Ignored <code>{{ g.prefix }}:</code> — {{ g.why }}.
        </span>
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
