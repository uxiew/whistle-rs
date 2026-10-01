<script setup lang="ts">
// On the Rules pane the source list *is* the group list: picking a source and
// picking what to edit are the same act.

import { computed } from 'vue';
import SideItem from '../components/SideItem.vue';
import SideTransfer from '../components/SideTransfer.vue';
import { addGroup, exportGroup, selectGroup, setSwitches, state, toggleGroup } from '../store';

const named = computed(() => state.groups.filter((g) => g.name !== 'default'));
const sw = computed(() => state.switches);
</script>

<template>
  <div class="side-title">Rule Groups</div>
  <label
    v-if="sw"
    class="side-switch"
    :title="sw.rules_locked
      ? '-M notAllowedDisableRules: rules cannot all be switched off'
      : 'Every group at once. Each group keeps its own switch underneath.'"
  >
    <input
      type="checkbox"
      :checked="sw.rules"
      :disabled="sw.rules_locked"
      @change="setSwitches({ rules: !sw.rules })"
    />
    All rules on
  </label>
  <div v-if="sw && !sw.rules" class="side-warn">
    Every rule is off: requests go through untouched, whatever the groups below say.
  </div>
  <SideItem
    label="Default"
    :selected="state.group === 'default'"
    @click="selectGroup('default')"
  />

  <SideItem
    v-for="g in named"
    :key="g.name"
    dot
    :label="g.name"
    :count="g.rules"
    :on="g.enabled"
    :off="!g.enabled"
    :selected="state.group === g.name"
    :title="g.enabled ? 'Enabled — double-click to disable' : 'Disabled — double-click to enable'"
    @click="selectGroup(g.name)"
    @dblclick.prevent="toggleGroup(g.name)"
  />

  <div class="side-add" @click="addGroup()">+ New group</div>
  <SideTransfer
    :export-title="`Save ${state.group} as a rules file`"
    @export="exportGroup()"
  />
</template>
