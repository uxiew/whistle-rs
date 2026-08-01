<script setup lang="ts">
// What came back: the facts about one exchange, grouped so each card answers
// one question.

import { computed } from 'vue';
import InfoCard from '../components/InfoCard.vue';
import type { Pair } from '../components/InfoCard.vue';
import type { SessionDetail, SessionSummary } from '../api';
import { fmtBytes, fmtDateTime, headerOf } from '../format';

const props = defineProps<{ session: SessionSummary; detail: SessionDetail | null }>();

const http = computed<Pair[]>(() => [
  ['Method', props.session.method],
  ['Status', props.session.status || '—'],
]);

const policy = computed<Pair[]>(() => [
  ['Target', props.session.target],
  ['Log tags', (props.session.log || []).join(', ')],
]);

const traffic = computed<Pair[]>(() => [
  ['Upload', fmtBytes(props.session.up)],
  ['Download', fmtBytes(props.session.down)],
]);

const timing = computed<Pair[]>(() => [
  ['Duration', props.session.duration_ms + ' ms'],
  ['Start', fmtDateTime(props.session.time_ms)],
]);

const client = computed<Pair[]>(() => [['Address', props.session.client_ip || 'unknown']]);

const content = computed<Pair[]>(() => [
  ['Type', headerOf(props.detail?.res_headers, 'content-type')],
  ['Encoding', headerOf(props.detail?.res_headers, 'content-encoding') || 'identity'],
  ['Server', headerOf(props.detail?.res_headers, 'server')],
]);
</script>

<template>
  <div class="cards">
    <InfoCard title="HTTP" :pairs="http" />
    <InfoCard title="Policy" :pairs="policy" />
    <InfoCard title="Traffic" :pairs="traffic" />
    <InfoCard title="Timing" :pairs="timing" />
    <InfoCard title="Client" :pairs="client" />
    <InfoCard v-if="detail" title="Content" :pairs="content" />
  </div>
  <p v-if="!detail" class="hint">loading headers…</p>
</template>
