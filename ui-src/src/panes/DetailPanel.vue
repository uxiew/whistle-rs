<script setup lang="ts">
// The selected request, below the table it came from.

import { computed, watch } from 'vue';
import BodyDump from './BodyDump.vue';
import FrameList from './FrameList.vue';
import GeneralTab from './GeneralTab.vue';
import HeaderList from './HeaderList.vue';
import RulesTab from './RulesTab.vue';
import { asCurl } from '../curl';
import { hostOf } from '../format';
import {
  DETAIL_TABS,
  copyText,
  loadFrames,
  selectedSession,
  state,
  tabEnabled,
} from '../store';
import type { DetailTab } from '../store';

const session = selectedSession;

/** A tab whose contents went away falls back to the one that is always there. */
const activeTab = computed<DetailTab>(() =>
  tabEnabled(state.detailTab) ? state.detailTab : 'general',
);

const badge = computed(() => {
  const s = session.value;
  if (!s) return null;
  return {
    text: s.status === 101 ? 'WebSocket' : s.status >= 400 ? 'Failed' : 'Completed',
    cls: s.status >= 400 ? 'bad' : 'ok',
  };
});

watch(
  [activeTab, () => state.selected],
  () => {
    if (activeTab.value === 'frames' && state.selected !== null && state.frames === null) {
      void loadFrames(state.selected);
    }
  },
  { immediate: true },
);
</script>

<template>
  <div class="detail">
    <div class="detail-head">
      <div class="title">
        <h2>{{ session ? `${session.method} ${hostOf(session.url)}` : 'No request selected' }}</h2>
        <div class="url">{{ session ? session.url : 'Pick a row above to inspect it.' }}</div>
      </div>
      <span v-if="session" class="d-actions">
        <button class="btn tiny" @click="copyText(asCurl(session, state.detail), 'cURL copied')">
          Copy as cURL
        </button>
        <button class="btn tiny" @click="copyText(session.url, 'URL copied')">Copy URL</button>
      </span>
      <span v-if="badge" class="badge" :class="badge.cls">{{ badge.text }}</span>
    </div>

    <div class="tabs">
      <button
        v-for="t in DETAIL_TABS"
        :key="t.key"
        :disabled="!tabEnabled(t.key)"
        :aria-selected="activeTab === t.key && tabEnabled(t.key)"
        @click="state.detailTab = t.key"
      >
        {{ t.label }}
      </button>
    </div>

    <div class="detail-body">
      <div v-if="!session" class="empty">Nothing selected</div>
      <GeneralTab v-else-if="activeTab === 'general'" :session="session" :detail="state.detail" />
      <!-- From the summary, not the detail: `/sessions.json` already carries
           which rules matched, so the tab fills with the row rather than a
           round trip after it. -->
      <RulesTab v-else-if="activeTab === 'rules'" :rules="session.rules" />
      <HeaderList v-else-if="activeTab === 'req-head'" :pairs="state.detail?.req_headers" />
      <HeaderList v-else-if="activeTab === 'res-head'" :pairs="state.detail?.res_headers" />
      <!-- Which session and which side, so the panel can ask for the body's
           bytes: a hex view, an image preview and a download need the body
           itself, which `/session.json` does not carry. -->
      <BodyDump
        v-else-if="activeTab === 'req-body'"
        :body="state.detail?.req_body"
        :session="session.id"
        side="req"
      />
      <BodyDump
        v-else-if="activeTab === 'res-body'"
        :body="state.detail?.res_body"
        :session="session.id"
        side="res"
      />
      <FrameList v-else-if="activeTab === 'frames'" :frames="state.frames" />
    </div>
  </div>
</template>
