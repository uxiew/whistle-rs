<script setup lang="ts">
// The shell: a toolbar, a source list whose contents depend on the pane, and
// the work area.

import { onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import AppToolbar from './components/AppToolbar.vue';
import { poll } from './poll';
import ComposerHistory from './sidebar/ComposerHistory.vue';
import PluginList from './sidebar/PluginList.vue';
import RequestSources from './sidebar/RequestSources.vue';
import RuleGroups from './sidebar/RuleGroups.vue';
import ValueKeys from './sidebar/ValueKeys.vue';
import ComposerPane from './panes/ComposerPane.vue';
import ConsolePane from './panes/ConsolePane.vue';
import LogGroups from './sidebar/LogGroups.vue';
import RequestsPane from './panes/RequestsPane.vue';
import RulesPane from './panes/RulesPane.vue';
import TestRulesPane from './panes/TestRulesPane.vue';
import StatusPane from './panes/StatusPane.vue';
import ValuesPane from './panes/ValuesPane.vue';
import {
  actingOn,
  clearSelection,
  loadPageLogs,
  loadSessions,
  moveSelection,
  sendComposition,
  state,
  toggleMark,
} from './store';
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
  // ⌘↩ sends the composition from anywhere in the Composer, the body editor
  // included — the one shortcut a form whose fields all take newlines can have.
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && state.pane === 'composer') {
    e.preventDefault();
    void sendComposition();
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

let stopPolling: (() => void) | undefined;

onMounted(() => {
  document.addEventListener('keydown', onKeydown);
  void loadSessions();
  // Every two seconds while the proxy answers, less often while it does not,
  // never while the tab is hidden — see `poll.ts`.
  stopPolling = poll(async () => {
    if (state.pane === 'requests' && state.autoRefresh) await loadSessions();
    // A page being debugged is being watched: the Console pane follows it for
    // as long as it is the pane on screen.
    if (state.pane === 'console') await loadPageLogs();
  });
});

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown);
  stopPolling?.();
});
</script>

<template>
  <AppToolbar ref="toolbar" />

  <div class="shell">
    <aside class="sidebar">
      <RequestSources v-if="state.pane === 'requests'" />
      <ComposerHistory v-else-if="state.pane === 'composer'" />
      <LogGroups v-else-if="state.pane === 'console'" />
      <RuleGroups v-else-if="state.pane === 'rules'" />
      <ValueKeys v-else-if="state.pane === 'values'" />
      <PluginList v-else />
    </aside>

    <div class="work">
      <RequestsPane v-show="state.pane === 'requests'" />
      <ComposerPane v-if="visited.has('composer')" v-show="state.pane === 'composer'" />
      <ConsolePane v-if="visited.has('console')" v-show="state.pane === 'console'" />
      <RulesPane v-if="visited.has('rules')" v-show="state.pane === 'rules'" />
      <ValuesPane v-if="visited.has('values')" v-show="state.pane === 'values'" />
      <TestRulesPane v-if="visited.has('test')" v-show="state.pane === 'test'" />
      <StatusPane v-if="visited.has('status')" v-show="state.pane === 'status'" />
    </div>
  </div>
</template>
