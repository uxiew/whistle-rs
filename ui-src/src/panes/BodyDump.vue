<script setup lang="ts">
// A captured body, re-indented when it is JSON and left alone when it is not.

import { computed } from 'vue';
import type { BodyCapture } from '../api';
import { prettyJson } from '../format';
import { state } from '../store';

const props = defineProps<{ body: BodyCapture | undefined }>();

const note = computed(() =>
  props.body ? `${props.body.len} bytes${props.body.truncated ? ', preview truncated' : ''}` : '',
);

/** Non-null exactly when the body is JSON, which is when the toggle appears. */
const formatted = computed(() => prettyJson(props.body?.text));

const shown = computed(() =>
  state.prettyBody && formatted.value !== null ? formatted.value : (props.body?.text ?? ''),
);
</script>

<template>
  <div v-if="!body || !body.len" class="empty">no body captured</div>
  <template v-else>
    <p class="hint">
      {{ note }}
      <button v-if="formatted !== null" class="btn tiny" @click="state.prettyBody = !state.prettyBody">
        {{ state.prettyBody ? 'Raw' : 'Format JSON' }}
      </button>
    </p>
    <pre class="dump">{{ shown }}</pre>
  </template>
</template>
