<script setup lang="ts">
// The capture, one row per request.

import { nextTick, ref, watch } from 'vue';
import { COLUMNS, statusClass } from '../columns';
import { selectRow, shownRows, state, toggleSort } from '../store';

const body = ref<HTMLElement | null>(null);

// The keyboard walks the list; the list has to follow.
watch(
  () => state.revealSeq,
  async () => {
    await nextTick();
    body.value?.querySelector(`tr[data-id="${state.selected}"]`)?.scrollIntoView({ block: 'nearest' });
  },
);
</script>

<template>
  <div class="table-wrap">
    <table class="requests">
      <thead>
        <tr>
          <th
            v-for="c in COLUMNS"
            :key="c.key"
            :style="c.width ? { width: c.width } : undefined"
            @click="toggleSort(c.key)"
          >
            {{ c.label }} <span v-if="state.sort.key === c.key" class="sort">{{ state.sort.dir === 'asc' ? '▲' : '▼' }}</span>
          </th>
        </tr>
      </thead>
      <tbody ref="body">
        <tr
          v-for="s in shownRows"
          :key="s.id"
          :data-id="s.id"
          :class="{ failed: s.status >= 400 || s.status === 0 }"
          :aria-selected="s.id === state.selected ? 'true' : undefined"
          @click="selectRow(s.id)"
        >
          <td v-for="c in COLUMNS" :key="c.key" :class="{ num: c.num }">
            <template v-if="c.key === 'status'">
              <span class="status-dot" :class="statusClass(s.status)"></span>{{ s.status || '—' }}<span v-if="s.status === 101" class="tag ws">WS</span>
            </template>
            <template v-else>{{ c.text ? c.text(s) : c.get(s) }}</template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
