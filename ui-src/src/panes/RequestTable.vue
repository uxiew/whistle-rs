<script setup lang="ts">
// The capture, one row per request, and the bar for acting on several at once.

import { computed, nextTick, ref, watch } from 'vue';
import { api } from '../api';
import { COLUMNS, statusClass } from '../columns';
import {
  actingOn,
  clearSelected,
  replaySelected,
  selectRow,
  shownRows,
  state,
  toggleMark,
  toggleSort,
} from '../store';

const body = ref<HTMLElement | null>(null);

// The keyboard walks the list; the list has to follow.
watch(
  () => state.revealSeq,
  async () => {
    await nextTick();
    body.value?.querySelector(`tr[data-id="${state.selected}"]`)?.scrollIntoView({ block: 'nearest' });
  },
);

/**
 * The bar appears once there is something for it to act on that the pane's own
 * actions cannot: a selection of more than one, or a mark somewhere in the
 * capture that the "marked only" switch is the way back to.
 */
const showBar = computed(() => state.selection.length > 1 || state.marked.length > 0);

/** Whether the button says Mark or Unmark — a mixed selection marks. */
const allMarked = computed(
  () => actingOn.value.length > 0 && actingOn.value.every((id) => state.marked.includes(id)),
);
</script>

<template>
  <div v-if="showBar" class="picked-bar">
    <span class="count">{{ actingOn.length }} selected</span>
    <button class="btn tiny" :disabled="!actingOn.length" @click="toggleMark(actingOn)">
      {{ allMarked ? 'Unmark' : 'Mark' }}
    </button>
    <!-- A link, not a fetch: `/sessions.har` answers as an attachment, so the
         browser saves it without the page having to hold a copy in memory. -->
    <a
      class="btn tiny"
      :class="{ off: !actingOn.length }"
      :href="api.harUrl(actingOn)"
      download
      >Export as HAR</a
    >
    <button class="btn tiny" :disabled="!actingOn.length" @click="replaySelected()">Replay</button>
    <button class="btn tiny" :disabled="!actingOn.length" @click="clearSelected()">Clear</button>

    <span class="spacer"></span>

    <template v-if="state.marked.length">
      <label class="check">
        <input v-model="state.markedOnly" type="checkbox" />
        {{ state.marked.length }} marked only
      </label>
      <button class="btn tiny" @click="state.marked = []">Clear marks</button>
    </template>
  </div>

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
          :class="{
            failed: s.status >= 400 || s.status === 0,
            marked: state.marked.includes(s.id),
            current: s.id === state.selected,
          }"
          :aria-selected="state.selection.includes(s.id) ? 'true' : undefined"
          @click="selectRow(s.id, { toggle: $event.metaKey || $event.ctrlKey, extend: $event.shiftKey })"
        >
          <td v-for="c in COLUMNS" :key="c.key" :class="{ num: c.num }">
            <template v-if="c.key === 'id'">
              <!-- Inline, because the console carries no icon font and cannot
                   fetch one: it has to render with the network it inspects off. -->
              <svg v-if="state.marked.includes(s.id)" class="mark" viewBox="0 0 8 10" aria-hidden="true">
                <path d="M0 0h8v10L4 7 0 10z" />
              </svg>
              {{ s.id }}
            </template>
            <template v-else-if="c.key === 'status'">
              <span class="status-dot" :class="statusClass(s.status)"></span>{{ s.status || '—' }}<span v-if="s.status === 101" class="tag ws">WS</span>
            </template>
            <template v-else>{{ c.text ? c.text(s) : c.get(s) }}</template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
