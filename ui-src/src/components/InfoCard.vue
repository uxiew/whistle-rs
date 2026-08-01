<script setup lang="ts">
// A card of facts. Empty values are dropped, and a card with nothing left to
// say does not appear at all.

import { computed } from 'vue';

export type Pair = [string, string | number | null | undefined];

const props = defineProps<{ title: string; pairs: Pair[] }>();

const rows = computed(() =>
  props.pairs.filter((p) => p[1] !== undefined && p[1] !== null && p[1] !== ''),
);
</script>

<template>
  <div v-if="rows.length" class="card">
    <h3>{{ title }}</h3>
    <dl>
      <template v-for="p in rows" :key="p[0]">
        <dt>{{ p[0] }}</dt>
        <dd>{{ p[1] }}</dd>
      </template>
    </dl>
  </div>
</template>
