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
const onLan = computed(() => !!st.value?.listening_on_lan);

const proxy = computed<Pair[]>(() => [
  ['Version', st.value?.version],
  ['HTTP', `${host.value}:${st.value?.port}`],
  ['SOCKS', st.value?.socks_port ? `${host.value}:${st.value.socks_port}` : 'off'],
  ['Idle timeout', `${st.value?.timeout_ms} ms`],
]);

const tls = computed<Pair[]>(() => [
  // A mode can take the switch away, and the answer without the reason reads
  // like a bug — see `Config::intercepts_https`.
  ['Intercept HTTPS', st.value?.capture_locked_off
    ? 'no — a -M mode turned it off'
    : yesNo(!!st.value?.intercept_https)],
  ['Verify origin', st.value?.insecure_upstream ? 'NO — --insecure-upstream' : 'yes'],
  ['Root CA', st.value?.root_ca],
]);

const capture = computed<Pair[]>(() => [
  ['Sessions held', st.value?.sessions],
  ['WS frames held', st.value?.frames],
  ['Body preview cap', fmtBytes(st.value?.body_preview_cap)],
  ['Persist', st.value?.persist_sessions ? `${st.value.persist_days} days` : 'off'],
]);

/**
 * Where a phone should point, one per address this machine answers on.
 *
 * `gui/mobile.md` is a page about typing a proxy address into a phone; the QR
 * code is how upstream shortens it, and `rootca.pro` only resolves *through*
 * the proxy — so the certificate link has to name an address, and the address
 * has to survive being read off a screen. A camera does not mistype.
 */
const lan = computed(() => (st.value?.lan_addresses || []).map((ip) => {
  const base = `http://${ip}:${st.value?.port}`;
  return { ip, base, cert: `${base}/rootCA.crt` };
}));

const qr = (text: string) => `/api/qr?scale=4&text=${encodeURIComponent(text)}`;

const rules = computed<Pair[]>(() => [
  ['Active rules', st.value?.rules],
  // Off is the default and says nothing; on is worth saying, because it changes
  // who decides where a request goes.
  ...(st.value && st.value.header_rules !== 'off'
    ? [['Rules from request headers', st.value.header_rules === 'multiEnv'
        ? 'yes — and they beat these (-M multiEnv)'
        : 'yes — these still win (-M enableRequestHeaderRules)'] as Pair]
    : []),
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
        <section v-if="!onLan" class="lan">
          <h3>Only this machine</h3>
          <p class="hint">
            The proxy listens on <code>{{ host }}</code>, so a phone or another machine
            cannot reach it. To let them in, restart with <code>-H 0.0.0.0</code> — and
            set a console login with <code>-n</code>/<code>-w</code> first, or anyone on
            the network can change the rules.
          </p>
        </section>
        <section v-else-if="lan.length" class="lan">
          <h3>On this network</h3>
          <p class="hint">
            Set one of these as the proxy on a phone — try each if unsure — then
            scan its code to install the certificate.
          </p>
          <div class="lan-cards">
            <figure v-for="a in lan" :key="a.ip">
              <img :src="qr(a.cert)" :alt="`QR code for ${a.cert}`" width="212" height="212" />
              <figcaption>
                <code>{{ a.ip }}:{{ st?.port }}</code>
                <a :href="a.cert">certificate</a>
              </figcaption>
            </figure>
          </div>
        </section>
      </template>
    </div>
  </section>
</template>
