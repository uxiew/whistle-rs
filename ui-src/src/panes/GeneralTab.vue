<script setup lang="ts">
// What came back: the facts about one exchange, grouped so each card answers
// one question.

import { computed } from 'vue';
import InfoCard from '../components/InfoCard.vue';
import Waterfall from './Waterfall.vue';
import type { Pair } from '../components/InfoCard.vue';
import type { SessionDetail, SessionSummary } from '../api';
import { PHASE_TEXT, fmtBytes, fmtDateTime, headerOf } from '../format';

const props = defineProps<{ session: SessionSummary; detail: SessionDetail | null }>();

// First, when there is one: the question a failed request is opened to answer.
// Empty — and so not shown — for every request that got its whole answer.
const failure = computed<Pair[]>(() => {
  const e = props.session.error;
  return e
    ? [
        ['Stopped at', `${PHASE_TEXT[e.phase] || e.phase} (${e.phase})`],
        ['Reason', e.message],
      ]
    : [];
});

const http = computed<Pair[]>(() => [
  ['Method', props.session.method],
  ['Status', props.session.status || '—'],
]);

// "Log tags" used to sit here alone, and people read it as the rules that
// matched. It is nothing of the sort — it is the `log://` channel labels — so
// it is now spelled as the protocol it comes from, with the real answer above
// it and the Rules tab behind that.
const policy = computed<Pair[]>(() => [
  ['Target', props.session.target],
  ['Rules', matched.value],
  ['log:// tags', (props.session.log || []).join(', ')],
]);

/** Never blank: "none" is the answer people come to this card for. */
const matched = computed(() => {
  const n = props.session.rules?.length || 0;
  return n ? `${n} matched` : 'none matched';
});

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
    <InfoCard title="Did not complete" :pairs="failure" />
    <InfoCard title="HTTP" :pairs="http" />
    <InfoCard title="Policy" :pairs="policy" />
    <InfoCard title="Traffic" :pairs="traffic" />
    <InfoCard title="Timing" :pairs="timing" />
    <InfoCard title="Client" :pairs="client" />
    <InfoCard v-if="detail" title="Content" :pairs="content" />
  </div>
  <!-- Below the cards rather than inside one: it is a picture, and a card is a
       list of pairs. Only shown once the detail has loaded, because the phases
       live on the detail — the summary carries the total and nothing else. -->
  <section v-if="detail" class="wf-section">
    <h3>Where the time went</h3>
    <Waterfall :timings="detail.timings" />
  </section>
  <p v-if="!detail" class="hint">loading headers…</p>
</template>
