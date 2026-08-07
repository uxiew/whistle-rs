<script setup lang="ts">
// The Composer's source list: what has been sent from it, newest first.
//
// A composed request is nearly always a variation on the last one, so the
// history is the pane's real navigation — the same role the client list plays
// on Requests and the group list plays on Rules.

import SideItem from '../components/SideItem.vue';
import { methodOf, newComposition, state, useComposition } from '../store';
import type { Composition } from '../api';

/**
 * `GET example.com/api/items` — the scheme carries no information here.
 *
 * The method is the one that will be *sent* rather than the one that was typed,
 * so a row here and the row it becomes in the request table read alike.
 */
function label(c: Composition): string {
  return `${methodOf(c)} ${c.url.replace(/^[a-z]+:\/\//i, '')}`;
}

/** True for the entry the editor is currently holding. */
function current(c: Composition): boolean {
  const d = state.compose;
  return c.method === d.method && c.url === d.url && c.headers === d.headers && c.body === d.body;
}
</script>

<template>
  <div class="side-title">Composer</div>
  <SideItem
    label="New request"
    :selected="!state.compose.url && !state.compose.body"
    @click="newComposition()"
  />

  <template v-if="state.composeHistory.length">
    <div class="side-title">Sent</div>
    <SideItem
      v-for="(c, i) in state.composeHistory"
      :key="i"
      :label="label(c)"
      :title="c.url"
      :selected="current(c)"
      @click="useComposition(c)"
    />
  </template>
</template>
