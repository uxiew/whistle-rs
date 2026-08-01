<script setup lang="ts">
import type { HeaderPair } from '../api';

defineProps<{ pairs: HeaderPair[] | undefined }>();
</script>

<template>
  <div v-if="!pairs || !pairs.length" class="empty">no headers captured</div>
  <dl v-else class="kv">
    <template v-for="(p, i) in pairs" :key="i">
      <dt>{{ p[0] }}</dt>
      <dd>{{ p[1] }}</dd>
    </template>
  </dl>
</template>
