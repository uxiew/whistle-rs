<script setup lang="ts">
// Which rules matched — the question a debugging proxy exists to answer, and
// the one this console could not: `Resolved` was consulted for every decision
// and then dropped, leaving only the `log://` labels, which the General tab
// showed under a heading people read as the matched rules.
//
// One row per operator that matched, in the order the rules resolved them:
// important lines first, then the order they are written in (`matched_ops`,
// `src/proxy/mod.rs`). Rendered in the rules editor's own token colours, so a
// row here and the line it came from in the Rules pane look like each other.

import { computed } from 'vue';
import type { MatchedRule, Unapplied } from '../api';

const props = defineProps<{ rules: MatchedRule[] | undefined; unapplied?: Unapplied[] }>();

const list = computed(() => props.rules ?? []);

/**
 * Why a row did not take effect, when it did not. A rule that matched and a
 * rule that acted are two facts: over the rewrite limit, on an event stream,
 * under a coding that would not undo, the proxy passes the body through and
 * the operator matched all the same. The proxy says which, and why.
 */
function whyNot(r: MatchedRule): Unapplied[] {
  return (props.unapplied ?? []).filter((u) => u.ops.includes(r.raw));
}

const skipped = computed(() => list.value.filter((r) => whyNot(r).length).length);

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
      {{ list.length }} operator{{ list.length === 1 ? '' : 's' }} matched, in the order they were
      resolved — important lines first, then the order they are written in.
      <template v-if="skipped">
        <strong class="warn-text">{{ skipped }} did not take effect</strong>; the reason is under
        each.
      </template>
    </p>
    <div class="ops">
      <div v-for="(r, i) in list" :key="i" class="op-row">
        <div class="op" :class="{ 'not-applied': whyNot(r).length }">
          <code class="op-spell"
            ><span class="tok-operator">{{ r.protocol }}</span
            ><span class="tok-separator">://</span
            ><span class="tok-value">{{ r.value }}</span></code
          >
          <span v-if="whyNot(r).length" class="op-tag">not applied</span>
          <code v-if="asWritten(r)" class="op-raw" title="the token as written on the line">{{
            asWritten(r)
          }}</code>
        </div>
        <p v-for="u in whyNot(r)" :key="u.kind" class="op-why">
          <code>{{ u.kind }}</code> {{ u.reason }}
        </p>
      </div>
    </div>
  </template>
</template>
