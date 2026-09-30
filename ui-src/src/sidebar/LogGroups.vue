<script setup lang="ts">
// The Console pane's source list: one row per `log://` id that has said
// something. `log://ke` on one line and `log://news` on another is how
// `log.md` keeps two sites apart, and this is where they are told apart.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import { state } from '../store';

const counts = computed(() => {
  const n = new Map<string, number>();
  for (const log of state.pageLogs) n.set(log.id, (n.get(log.id) || 0) + 1);
  return state.pageLogIds.map((id) => ({ id, count: n.get(id) || 0 }));
});
</script>

<template>
  <div class="side-title">Console</div>
  <SideItem
    label="All pages"
    :count="state.pageLogs.length"
    :selected="state.pageLogId === null"
    @click="state.pageLogId = null"
  />

  <template v-if="counts.length">
    <div class="side-title">log:// ids</div>
    <SideItem
      v-for="g in counts"
      :key="g.id"
      dot
      :label="g.id || '(no id)'"
      :count="g.count"
      :selected="state.pageLogId === g.id"
      @click="state.pageLogId = g.id"
    />
  </template>
</template>
