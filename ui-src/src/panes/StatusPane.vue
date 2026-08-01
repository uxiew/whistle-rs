<script setup lang="ts">
// What this proxy is, right now.
//
// Everything here is otherwise only visible in the startup log, which is gone
// by the time you have a question — "which port is SOCKS on", "where does the
// root certificate live", "is upstream verification off".

import { computed } from 'vue';
import InfoCard from '../components/InfoCard.vue';
import type { Pair } from '../components/InfoCard.vue';
import { fmtBytes } from '../format';
import { state } from '../store';

const yesNo = (v: boolean) => (v ? 'yes' : 'no');
const st = computed(() => state.status);
const host = computed(() => st.value?.host || '127.0.0.1');

const proxy = computed<Pair[]>(() => [
  ['Version', st.value?.version],
  ['HTTP', `${host.value}:${st.value?.port}`],
  ['SOCKS', st.value?.socks_port ? `${host.value}:${st.value.socks_port}` : 'off'],
  ['Idle timeout', `${st.value?.timeout_ms} ms`],
]);

const tls = computed<Pair[]>(() => [
  ['Intercept HTTPS', yesNo(!!st.value?.intercept_https)],
  ['Verify origin', st.value?.insecure_upstream ? 'NO — --insecure-upstream' : 'yes'],
  ['Root CA', st.value?.root_ca],
]);

const capture = computed<Pair[]>(() => [
  ['Sessions held', st.value?.sessions],
  ['WS frames held', st.value?.frames],
  ['Body preview cap', fmtBytes(st.value?.body_preview_cap)],
  ['Persist', st.value?.persist_sessions ? `${st.value.persist_days} days` : 'off'],
]);

const rules = computed<Pair[]>(() => [
  ['Active rules', st.value?.rules],
  ['Storage', st.value?.storage_dir],
]);
</script>

<template>
  <section class="pane status-pane">
    <div class="detail-body">
      <div v-if="!st" class="empty">{{ state.offline ? 'Could not reach the proxy' : 'loading…' }}</div>
      <template v-else>
        <div class="cards">
          <InfoCard title="Proxy" :pairs="proxy" />
          <InfoCard title="TLS" :pairs="tls" />
          <InfoCard title="Capture" :pairs="capture" />
          <InfoCard title="Rules" :pairs="rules" />
        </div>
        <p class="hint">
          Certificate: <a href="/rootCA.crt">download</a> ·
          PAC: <a href="/proxy.pac">/proxy.pac</a> ·
          Export: <a href="/sessions.har" download>HAR</a>
        </p>
      </template>
    </div>
  </section>
</template>
