<script setup lang="ts">
// The keys of the values object, as a source list. Clicking one selects it in
// the editor rather than filtering to it: the file is the thing being edited,
// and jumping is what a long one needs.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import { revealValue, state } from '../store';

const names = computed(() => Object.keys(state.values).sort());
</script>

<template>
  <div class="side-title">Values</div>
  <SideItem v-if="!names.length" label="none defined" muted />
  <SideItem
    v-for="name in names"
    :key="name"
    :label="name"
    :count="String(state.values[name]).length"
    @click="revealValue(name)"
  />
</template>
