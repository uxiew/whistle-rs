<script setup lang="ts">
// What pages wrote to their consoles.
//
// A `log://id` rule puts a small script into the pages it matches; the script
// sends `console.*` calls and uncaught errors back, and this is where they are
// read. It is the developer tools of a browser that has none to open — a
// WebView, a phone on the desk.

import { computed, nextTick, ref, watch } from 'vue';
import type { PageLog } from '../api';
import { clearPageLogs, state } from '../store';

type Level = PageLog['level'];
const LEVELS: Level[] = ['error', 'warn', 'info', 'log', 'debug'];

/** Which levels are shown. All of them, until one is switched off. */
const shown = ref<Record<Level, boolean>>({
  error: true,
  warn: true,
  info: true,
  log: true,
  debug: true,
});
const needle = ref('');
/** Keep the newest entry in view, as a terminal does — until the reader scrolls up. */
const follow = ref(true);
const list = ref<HTMLElement | null>(null);

const visible = computed(() => {
  const q = needle.value.trim().toLowerCase();
  return state.pageLogs.filter((log) => {
    if (state.pageLogId !== null && log.id !== state.pageLogId) return false;
    if (!shown.value[log.level]) return false;
    if (!q) return true;
    return log.args.some((a) => a.toLowerCase().includes(q)) || log.page.toLowerCase().includes(q);
  });
});

/** How many of each level the current group holds, for the toggles. */
const counts = computed(() => {
  const n: Record<Level, number> = { error: 0, warn: 0, info: 0, log: 0, debug: 0 };
  for (const log of state.pageLogs) {
    if (state.pageLogId === null || log.id === state.pageLogId) n[log.level] += 1;
  }
  return n;
});

function clock(ms: number): string {
  const d = new Date(ms);
  const p = (v: number, w = 2) => String(v).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/** A page's path, which is what tells two entries apart; the full URL is the title. */
function where(page: string): string {
  try {
    const u = new URL(page);
    return u.host + u.pathname;
  } catch {
    return page;
  }
}

function onScroll(): void {
  const el = list.value;
  if (!el) return;
  follow.value = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
}

watch(
  () => visible.value.length,
  async () => {
    if (!follow.value) return;
    await nextTick();
    if (list.value) list.value.scrollTop = list.value.scrollHeight;
  },
);
</script>

<template>
  <section class="pane console-pane">
    <div class="console-bar">
      <label v-for="level in LEVELS" :key="level" class="check" :class="level">
        <input v-model="shown[level]" type="checkbox" />
        {{ level }}
        <span class="n">{{ counts[level] }}</span>
      </label>
      <span class="spacer"></span>
      <input
        v-model="needle"
        class="console-filter"
        spellcheck="false"
        placeholder="Filter text"
        aria-label="Filter the log"
      />
      <button class="btn tiny" :disabled="!state.pageLogs.length" @click="clearPageLogs()">
        Clear{{ state.pageLogId === null ? '' : ` ${state.pageLogId || '(no id)'}` }}
      </button>
    </div>

    <div v-if="!state.pageLogs.length" class="empty wide">
      <div>
        Nothing yet. Add a rule such as <code>www.example.com log://myapp</code> and
        load the page through this proxy: its <code>console.log</code> calls and
        uncaught errors appear here.
        <template v-if="state.offline"><br />Could not reach the proxy.</template>
      </div>
    </div>
    <div v-else-if="!visible.length" class="empty">nothing matches</div>
    <div v-else ref="list" class="console-list" @scroll="onScroll">
      <div v-for="log in visible" :key="log.seq" class="entry" :class="log.level">
        <span class="time">{{ clock(log.time_ms) }}</span>
        <span class="level">{{ log.level }}</span>
        <span class="text">
          <span v-for="(arg, i) in log.args" :key="i" class="arg">{{ arg }}</span>
        </span>
        <span class="page" :title="`${log.page}${log.client_ip ? ` · ${log.client_ip}` : ''}`">
          <template v-if="state.pageLogId === null && log.id">{{ log.id }} · </template>{{ where(log.page) }}
        </span>
      </div>
    </div>
  </section>
</template>

<style scoped>
.console-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--line);
}
.console-bar .spacer { flex: 1 1 auto; }
.console-bar .n { color: var(--fg-faint); }
.console-bar .check.error { color: var(--err); }
.console-bar .check.warn { color: var(--warn); }
.console-filter {
  width: 200px;
  font-size: 12px;
}
.console-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  font-family: var(--mono);
  font-size: 11.5px;
}
.entry {
  display: flex;
  gap: 10px;
  padding: 3px 12px;
  border-bottom: 1px solid var(--line-soft);
  align-items: baseline;
}
.entry .time { flex: 0 0 auto; color: var(--fg-faint); }
.entry .level { flex: 0 0 38px; color: var(--fg-dim); }
/* Arguments keep their own line breaks — a stack trace is several lines, and
   one long line is how it stops being readable. */
.entry .text {
  flex: 1 1 auto;
  min-width: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.entry .arg + .arg::before { content: ' '; }
.entry .page {
  flex: 0 1 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: right;
  color: var(--fg-faint);
}
.entry.warn { background: color-mix(in srgb, var(--warn) 9%, transparent); }
.entry.warn .level { color: var(--warn); }
.entry.error { background: color-mix(in srgb, var(--err) 8%, transparent); }
.entry.error .level,
.entry.error .text { color: var(--err); }
.entry.debug .text { color: var(--fg-dim); }
</style>
