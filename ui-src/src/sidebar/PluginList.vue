<script setup lang="ts">
// The registered plugins, and what each one hooks.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import { state } from '../store';

const plugins = computed(() => state.status?.plugins ?? []);

// A remote plugin that has never answered has no manifest, and that is worth
// seeing: it means the proxy has never reached it.
const hookCount = (hooks: string[] | null) => (hooks ? hooks.length : '?');
const hookList = (hooks: string[] | null) =>
  hooks ? hooks.join(', ') : 'no manifest — never reached';

function open(name: string): void {
  window.open('/plugin/' + encodeURIComponent(name) + '/', '_blank');
}
</script>

<template>
  <div class="side-title">Plugins</div>
  <SideItem v-if="!plugins.length" label="none registered" muted />
  <SideItem
    v-for="p in plugins"
    :key="p.name"
    dot
    :label="p.name"
    :count="hookCount(p.hooks)"
    :title="hookList(p.hooks)"
    @click="open(p.name)"
  />
</template>
