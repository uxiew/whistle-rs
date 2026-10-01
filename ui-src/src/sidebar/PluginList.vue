<script setup lang="ts">
// The registered plugins, what each one hooks, and whether it is switched on.
// Click opens its page; double-click switches it, as a rule group does.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import { setSwitches, state, togglePlugin } from '../store';

const plugins = computed(() => state.status?.plugins ?? []);
const sw = computed(() => state.switches);
/** Off one by one, or all of them at once — either way no rule reaches it. */
const isOn = (name: string) =>
  !!sw.value && sw.value.plugins && !sw.value.plugins_off.includes(name);

// A remote plugin that has never answered has no manifest, and that is worth
// seeing: it means the proxy has never reached it.
const hookCount = (hooks: string[] | null) => (hooks ? hooks.length : '?');
const hookList = (hooks: string[] | null) =>
  hooks ? hooks.join(', ') : 'no manifest — never reached';

function title(name: string, hooks: string[] | null): string {
  const what = hookList(hooks);
  if (sw.value?.plugins_locked) return `${what} — always on (-M notAllowedDisablePlugins)`;
  if (!sw.value?.plugins) return `${what} — off: every plugin is switched off`;
  return isOn(name)
    ? `${what} — on; double-click to switch off`
    : `${what} — off: no rule reaches it; double-click to switch on`;
}

function open(name: string): void {
  window.open('/plugin/' + encodeURIComponent(name) + '/', '_blank');
}
</script>

<template>
  <div class="side-title">Plugins</div>
  <label
    v-if="sw && plugins.length"
    class="side-switch"
    :title="sw.plugins_locked ? '-M notAllowedDisablePlugins: plugins cannot be switched off' : ''"
  >
    <input
      type="checkbox"
      :checked="sw.plugins"
      :disabled="sw.plugins_locked"
      @change="setSwitches({ plugins: !sw.plugins })"
    />
    All plugins on
  </label>
  <SideItem v-if="!plugins.length" label="none registered" muted />
  <SideItem
    v-for="p in plugins"
    :key="p.name"
    dot
    :label="p.name"
    :count="hookCount(p.hooks)"
    :on="isOn(p.name)"
    :off="!!sw && !isOn(p.name)"
    :title="title(p.name, p.hooks)"
    @click="open(p.name)"
    @dblclick.prevent="!sw?.plugins_locked && togglePlugin(p.name)"
  />
</template>
