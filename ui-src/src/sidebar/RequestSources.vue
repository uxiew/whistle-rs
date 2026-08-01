<script setup lang="ts">
// The Requests source list: every client that has been seen, and how much
// traffic came from each.

import SideItem from '../components/SideItem.vue';
import { clientCounts, state } from '../store';
</script>

<template>
  <div class="side-title">Requests</div>
  <SideItem
    label="All Clients"
    :count="state.sessions.length"
    :selected="state.client === null"
    @click="state.client = null"
  />

  <template v-if="clientCounts.length">
    <div class="side-title">Clients</div>
    <SideItem
      v-for="c in clientCounts"
      :key="c.name"
      dot
      :label="c.name"
      :count="c.count"
      :selected="state.client === c.name"
      @click="state.client = c.name"
    />
  </template>
</template>
