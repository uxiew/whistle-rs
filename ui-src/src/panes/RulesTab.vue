<script setup lang="ts">
// Which rules matched — the question a debugging proxy exists to answer, and
// the one this console could not: `Resolved` was consulted for every decision
// and then dropped, leaving only the `log://` labels, which the General tab
// showed under a heading people read as the matched rules.
//
// One row per operator that applied, in the order the rules resolved them:
// important lines first, then the order they are written in (`matched_ops`,
// `src/proxy/mod.rs`). Rendered in the rules editor's own token colours, so a
// row here and the line it came from in the Rules pane look like each other.

import { computed } from 'vue';
import type { MatchedRule } from '../api';

const props = defineProps<{ rules: MatchedRule[] | undefined }>();

const list = computed(() => props.rules ?? []);

/**
 * The token as it was typed, shown only where it is not already on the row.
 *
 * It differs exactly where the rules language did something between the two —
 * a shorthand naming a protocol it does not spell, a `${name}` read from the
 * values store, a `$1` filled in from the pattern — which is where seeing both
 * is worth a column and everywhere else is noise.
 */
function asWritten(r: MatchedRule): string {
  return r.raw === `${r.protocol}://${r.value}` ? '' : r.raw;
}
</script>

<template>
  <div v-if="!list.length" class="empty wide">
    No rule matched this request. It was proxied exactly as it was sent.
  </div>
  <template v-else>
    <p class="hint">
      {{ list.length }} operator{{ list.length === 1 ? '' : 's' }} applied, in the order they were
      resolved — important lines first, then the order they are written in.
    </p>
    <div class="ops">
      <div v-for="(r, i) in list" :key="i" class="op">
        <code class="op-spell"
          ><span class="tok-operator">{{ r.protocol }}</span
          ><span class="tok-separator">://</span
          ><span class="tok-value">{{ r.value }}</span></code
        >
        <code v-if="asWritten(r)" class="op-raw" title="the token as written on the line">{{
          asWritten(r)
        }}</code>
      </div>
    </div>
  </template>
</template>
