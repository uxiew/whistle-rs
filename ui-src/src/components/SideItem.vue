<script setup lang="ts">
// One row of a source list: an optional status dot, a name, an optional count.

defineProps<{
  label: string;
  count?: string | number;
  dot?: boolean;
  /** A lit dot — an enabled rule group. */
  on?: boolean;
  /** Struck through — a disabled rule group. */
  off?: boolean;
  selected?: boolean;
  muted?: boolean;
}>();
</script>

<template>
  <div
    class="side-item"
    :class="{ off }"
    :aria-selected="selected ? 'true' : undefined"
  >
    <span v-if="dot" class="dot" :class="{ on }"></span>
    <span class="side-name" :class="{ muted }">{{ label }}</span>
    <span v-if="count !== undefined" class="side-count">{{ count }}</span>
  </div>
</template>
