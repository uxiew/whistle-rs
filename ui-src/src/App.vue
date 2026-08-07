<script setup lang="ts">
// The shell: a toolbar, a source list whose contents depend on the pane, and
// the work area.

import { onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import AppToolbar from './components/AppToolbar.vue';
import PluginList from './sidebar/PluginList.vue';
import RequestSources from './sidebar/RequestSources.vue';
import RuleGroups from './sidebar/RuleGroups.vue';
import ValueKeys from './sidebar/ValueKeys.vue';
import RequestsPane from './panes/RequestsPane.vue';
import RulesPane from './panes/RulesPane.vue';
import StatusPane from './panes/StatusPane.vue';
import ValuesPane from './panes/ValuesPane.vue';
import { actingOn, clearSelection, loadSessions, moveSelection, state, toggleMark } from './store';
import type { Pane } from './store';

const toolbar = ref<InstanceType<typeof AppToolbar> | null>(null);

/**
 * Panes are built the first time they are shown and kept afterwards, so
 * switching back lands where you left off — and so the editors are not created
 * (and measured) inside a hidden pane on a console that may never open them.
 */
const visited = reactive(new Set<Pane>(['requests']));
watch(() => state.pane, (pane) => visited.add(pane));

function onKeydown(e: KeyboardEvent): void {
  // ⌘F focuses the filter from anywhere, the way a request list should.
  if ((e.metaKey || e.ctrlKey) && e.key === 'f' && state.pane === 'requests') {
    e.preventDefault();
    toolbar.value?.focusFilter();
    return;
  }
  if (state.pane !== 'requests') return;
  // Arrow keys walk the list. They work from the filter box too — you type,
  // then step through what you found without reaching for the mouse — but not
  // from anywhere else that takes text.
  const active = document.activeElement as HTMLElement | null;
  const inEditable =
    !!active &&
    ((/^(INPUT|TEXTAREA)$/.test(active.tagName) && active.id !== 'filter') ||
      !!active.closest('.cm-editor'));
  if (inEditable) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    // Shift-arrow is the keyboard's spelling of a shift-click: the anchor stays
    // where it was and the range grows from it.
    moveSelection(1, e.shiftKey);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    moveSelection(-1, e.shiftKey);
  } else if (e.key === 'Escape') {
    clearSelection();
  } else if (e.key === 'm' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    toggleMark(actingOn.value);
  }
}

let timer: number | undefined;

onMounted(() => {
  document.addEventListener('keydown', onKeydown);
  void loadSessions();
  timer = setInterval(() => {
    if (state.pane === 'requests' && state.autoRefresh) void loadSessions();
  }, 2000) as unknown as number;
});

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown);
  clearInterval(timer);
});
</script>

<template>
  <AppToolbar ref="toolbar" />

  <div class="shell">
    <aside class="sidebar">
      <RequestSources v-if="state.pane === 'requests'" />
      <RuleGroups v-else-if="state.pane === 'rules'" />
      <ValueKeys v-else-if="state.pane === 'values'" />
      <PluginList v-else />
    </aside>

    <div class="work">
      <RequestsPane v-show="state.pane === 'requests'" />
      <RulesPane v-if="visited.has('rules')" v-show="state.pane === 'rules'" />
      <ValuesPane v-if="visited.has('values')" v-show="state.pane === 'values'" />
      <StatusPane v-if="visited.has('status')" v-show="state.pane === 'status'" />
    </div>
  </div>
</template>
