<script setup lang="ts">
// The values, as a source list. Picking a key and picking what to edit are the
// same act, as on the Rules pane — "All values" is to this list what "Default"
// is to the group list: the whole store, edited as the one JSON object it is
// stored as.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import { addValue, selectValue, state } from '../store';

const names = computed(() => Object.keys(state.values).sort());
</script>

<template>
  <div class="side-title">Values</div>
  <SideItem
    label="All values"
    :selected="state.valueKey === null"
    @click="selectValue(null)"
  />

  <SideItem
    v-for="name in names"
    :key="name"
    :label="name"
    :count="String(state.values[name]).length"
    :selected="state.valueKey === name"
    @click="selectValue(name)"
  />

  <div class="side-add" @click="addValue()">+ New value</div>
</template>
