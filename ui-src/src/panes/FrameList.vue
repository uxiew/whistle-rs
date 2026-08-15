<script setup lang="ts">
// A WebSocket conversation, oldest first. A frame `enable://ignoreSend` threw
// away is shown dimmed rather than omitted — a dropped frame is not a gap.
//
// A frame `enable://pauseSend` is *holding* is shown too, marked, above the
// control that lets it go: this is the half of a pause that makes it a pause
// rather than a stall, and without it there would be no reason to have the flag.

import { computed, onUnmounted, watch } from 'vue';
import type { WsFrame } from '../api';
import { loadFrames, releaseWsDir, state } from '../store';

defineProps<{ frames: WsFrame[] | null }>();

/** The directions this connection is currently holding, if it is still live. */
const holds = computed(() => {
  const p = state.wsPause;
  if (!p?.live) return [];
  return ([['send', p.send] as const, ['receive', p.receive] as const])
    .filter(([, d]) => d.paused)
    .map(([dir, d]) => ({ dir, held: d.held }));
});

// A frame list is not a snapshot: a held connection grows while you watch it,
// and so does an event stream — a body cut into frames arrives for as long as
// the server keeps writing, which for SSE is often minutes. So this polls for
// as long as the tab is open, and stops the moment it is not. The cost is one
// small request every two seconds while somebody is looking at exactly this.
let timer: number | undefined;
watch(
  () => state.selected,
  () => {
    clearInterval(timer);
    timer = setInterval(() => {
      if (state.selected !== null) void loadFrames(state.selected);
    }, 2000) as unknown as number;
  },
  { immediate: true },
);
onUnmounted(() => clearInterval(timer));
</script>

<template>
  <div v-if="holds.length" class="holds">
    <div v-for="h in holds" :key="h.dir" class="hold">
      <span class="dir" :class="h.dir">{{ h.dir === 'send' ? '▲ send' : '▼ recv' }}</span>
      <span class="what">
        paused · {{ h.held }} frame{{ h.held === 1 ? '' : 's' }} held
      </span>
      <button class="btn tiny" @click="releaseWsDir(h.dir)">Release</button>
    </div>
  </div>

  <div v-if="frames === null" class="empty">loading frames…</div>
  <div v-else-if="!frames.length" class="empty">no frames captured yet</div>
  <div v-else class="frames">
    <div
      v-for="(f, i) in frames"
      :key="i"
      class="frame"
      :class="[f.dir, { ignored: f.ignored, held: f.held }]"
    >
      <span class="dir">{{ f.dir === 'send' ? '▲ send' : '▼ recv' }}</span>
      <span class="op">{{ f.opcode }}</span>
      <span class="len">{{ f.len }} B</span>
      <span class="pv">{{ f.preview }}</span>
      <span v-if="f.held" class="waiting">held</span>
    </div>
  </div>
</template>
