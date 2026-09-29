<script setup lang="ts">
// Where one request's time went, drawn end to end.
//
// The phases are sequential and non-overlapping as the proxy measures them, so
// each bar starts where the last one ended and the row's width is the whole
// exchange. That is the honest reading: this is not a browser's waterfall over
// many requests, it is one request's own phases.
//
// A phase the proxy did not measure is **absent**, not zero — a plain
// connection has no `ssl`, and `receive` is missing while the body is still
// arriving. An absent phase gets no bar and is listed as "—", because a
// zero-width bar and a zero-length phase would look the same and mean opposite
// things.

import { computed } from 'vue';
import type { Timings } from '../api';

const props = defineProps<{ timings?: Timings }>();

/** The phases in the order they happen, with the colour each is drawn in. */
const ORDER = [
  ['dns', 'DNS', 'wf-dns'],
  ['connect', 'Connect', 'wf-connect'],
  ['ssl', 'TLS', 'wf-ssl'],
  ['wait', 'Wait', 'wf-wait'],
  ['receive', 'Receive', 'wf-receive'],
] as const;

interface Bar {
  key: string;
  label: string;
  cls: string;
  ms: number;
  /** Percentage of the total, for the bar's width. */
  pct: number;
}

const bars = computed<Bar[]>(() => {
  const t = props.timings;
  if (!t) return [];
  const present: Omit<Bar, 'pct'>[] = [];
  for (const [key, label, cls] of ORDER) {
    const ms = t[key];
    // `typeof` and not a truthiness test: a phase that genuinely took 0.0 ms
    // happened, and dropping it here would make the bar disagree with the
    // legend about which phases there were.
    if (typeof ms === 'number') present.push({ key, label, cls, ms });
  }
  const sum = present.reduce((n, b) => n + b.ms, 0);
  return present.map((b) => ({
    ...b,
    // A phase that really took no time still gets a sliver, for the same reason.
    pct: sum > 0 ? Math.max((b.ms / sum) * 100, 0.5) : 100 / present.length,
  }));
});

const total = computed(() => bars.value.reduce((sum, b) => sum + b.ms, 0));

/** The phases a connection is set up in, which a reused one never had. */
const SETUP = new Set(['dns', 'connect', 'ssl']);

/**
 * The phases with nothing to show, named so their absence is legible — less
 * the set-up phases of a reused connection, which are said separately: they
 * did not go unmeasured, they did not happen.
 */
const absent = computed(() => {
  const t = props.timings;
  if (!t) return [];
  return ORDER.filter(([key]) => typeof t[key] !== 'number')
    .filter(([key]) => !(t.reused && SETUP.has(key)))
    .map(([, label]) => label);
});

const fmt = (ms: number) => (ms >= 100 ? ms.toFixed(0) : ms.toFixed(1)) + ' ms';
</script>

<template>
  <div v-if="bars.length" class="waterfall">
    <div class="wf-track">
      <div
        v-for="b in bars"
        :key="b.key"
        class="wf-bar"
        :class="b.cls"
        :style="{ width: b.pct + '%' }"
        :title="`${b.label} ${fmt(b.ms)}`"
      />
    </div>
    <ul class="wf-legend">
      <li v-for="b in bars" :key="b.key">
        <span class="wf-swatch" :class="b.cls" />
        <span class="wf-name">{{ b.label }}</span>
        <span class="wf-ms">{{ fmt(b.ms) }}</span>
      </li>
      <li class="wf-total">
        <span class="wf-name">Total measured</span>
        <span class="wf-ms">{{ fmt(total) }}</span>
      </li>
    </ul>
    <p v-if="timings?.connection" class="wf-absent">
      Origin connection #{{ timings.connection
      }}<span v-if="timings.reused">
        — reused from an earlier request by this client, so there was no DNS,
        Connect or TLS</span
      >.
    </p>
    <p v-if="absent.length" class="wf-absent">
      Not measured: {{ absent.join(', ') }}<span v-if="absent.includes('Receive')">
        — the body had not ended</span
      >. <code>send</code> is never measured; its time is inside Wait.
    </p>
  </div>
  <p v-else class="hint">
    No phases: this request was answered by the proxy and never opened a
    connection.
  </p>
</template>
