<script setup lang="ts">
// A WebSocket conversation, oldest first. A frame `enable://ignoreSend` threw
// away is shown dimmed rather than omitted — a dropped frame is not a gap.

import type { WsFrame } from '../api';

defineProps<{ frames: WsFrame[] | null }>();
</script>

<template>
  <div v-if="frames === null" class="empty">loading frames…</div>
  <div v-else-if="!frames.length" class="empty">no frames captured yet</div>
  <div v-else class="frames">
    <div
      v-for="(f, i) in frames"
      :key="i"
      class="frame"
      :class="[f.dir, { ignored: f.ignored }]"
    >
      <span class="dir">{{ f.dir === 'send' ? '▲ send' : '▼ recv' }}</span>
      <span class="op">{{ f.opcode }}</span>
      <span class="len">{{ f.len }} B</span>
      <span class="pv">{{ f.preview }}</span>
    </div>
  </div>
</template>
