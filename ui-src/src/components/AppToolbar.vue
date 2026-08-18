<script setup lang="ts">
// Brand, pane switcher, the three things you download from a proxy, and the
// filter box.

import { computed, onMounted, ref } from 'vue';
import { applyTheme, filterGaps, loadStatus, showPane, state } from '../store';
import type { Pane } from '../store';

const PANES: { key: Pane; label: string }[] = [
  { key: 'requests', label: 'Requests' },
  { key: 'composer', label: 'Composer' },
  { key: 'rules', label: 'Rules' },
  { key: 'values', label: 'Values' },
  { key: 'test', label: 'Test Rules' },
  { key: 'status', label: 'Status' },
];

/**
 * Version and address, as the Rust side stamped them into the page.
 *
 * `webui.rs` substitutes the placeholders in the served HTML. Under `npm run
 * dev` nothing substitutes them, so they arrive verbatim and the toolbar falls
 * back to what /api/status reports — which is also the answer if the Rust side
 * ever stops substituting.
 */
const stamped = (document.querySelector('meta[name="whistle-build"]') as HTMLMetaElement | null)
  ?.content.split('|') ?? [];
const substituted = stamped.length === 3 && !stamped.some((v) => /^__[A-Z]+__$/.test(v));

const version = computed(() => (substituted ? stamped[0] : state.status?.version));
const address = computed(() =>
  substituted
    ? `${stamped[1]}:${stamped[2]}`
    : state.status
      ? `${state.status.host || '127.0.0.1'}:${state.status.port}`
      : '',
);

// Only when the page was served unsubstituted is a request needed to fill the
// line in; the proxy normally answers it before the page ever loads.
onMounted(() => {
  if (!substituted) void loadStatus();
});

const filterInput = ref<HTMLInputElement | null>(null);

/** The grammar, in the tooltip — the same one `gui/network.md` documents. */
const FILTER_HELP = [
  'A word matches the URL. Prefixes ask about something else:',
  '  m:  method        s:  status        t:  content type',
  '  H:  host          i:  client or server IP',
  '  e:  went wrong    style:  a style:// value    mark:  marked by hand',
  'Each takes a keyword or a /regexp/flags. Several are AND-ed:',
  '  m:POST s:/^5/ H:api.example.com',
].join('\n');

/** ⌘F focuses the filter from anywhere, the way a request list should. */
function focusFilter(): void {
  filterInput.value?.focus();
  filterInput.value?.select();
}

defineExpose({ focusFilter });
</script>

<template>
  <div class="toolbar">
    <span class="brand">
      whistle-rs
      <span class="ver">
        <template v-if="version">v{{ version }} · </template>{{ address }}
      </span>
    </span>

    <div class="segmented" role="tablist">
      <button
        v-for="p in PANES"
        :key="p.key"
        role="tab"
        :aria-selected="state.pane === p.key"
        @click="showPane(p.key)"
      >
        {{ p.label }}
      </button>
    </div>

    <span class="spacer"></span>

    <a class="icon-btn" href="/rootCA.crt" title="Download the root certificate">⛨</a>
    <a class="icon-btn" href="/proxy.pac" title="PAC file">⚙</a>
    <a class="icon-btn" href="/sessions.har" download title="Export as HAR">⤓</a>
    <button
      class="icon-btn"
      title="Toggle appearance"
      @click="applyTheme(state.theme === 'dark' ? 'light' : 'dark')"
    >
      ◐
    </button>

    <!-- Hidden rather than removed on the other panes: the magnifier is a
         pseudo-element on the wrapper, and the toolbar keeps its shape. -->
    <div class="search" :style="state.pane === 'requests' ? undefined : { visibility: 'hidden' }">
      <input
        id="filter"
        ref="filterInput"
        v-model="state.filter"
        :title="FILTER_HELP"
        placeholder="Filter — m: s: t: H: i: e: style: mark:"
        spellcheck="false"
      />
      <!-- A condition this console cannot answer would otherwise just show an
           empty list, which reads as "nothing matched" rather than "I cannot
           ask that". Saying so is the whole point. -->
      <p v-if="filterGaps.length" class="filter-gap">
        <span v-for="g in filterGaps" :key="g.prefix">
          <code>{{ g.prefix }}:</code> {{ g.why }}
        </span>
      </p>
    </div>
  </div>
</template>
