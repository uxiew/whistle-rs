// One reactive store for the whole console.
//
// A plain `reactive` module rather than Pinia: there is one store, it is never
// instantiated twice, there is no SSR and no route to hydrate from, and the
// console ships as a file embedded in a binary — so the only thing a store
// library would add here is bytes. What Pinia is actually for (many stores,
// hot-swapped modules, devtools timelines) never comes up in a single window
// with four panes.

import { computed, reactive } from 'vue';
import { api } from './api';
import type {
  ProxyStatus,
  RuleGroup,
  SessionDetail,
  SessionSummary,
  WsFrame,
} from './api';
import { COLUMNS } from './columns';
import { clientOf } from './format';

export type Pane = 'requests' | 'rules' | 'values' | 'status';
export type DetailTab =
  | 'general'
  | 'rules'
  | 'req-head'
  | 'res-head'
  | 'req-body'
  | 'res-body'
  | 'frames';
export type Theme = 'light' | 'dark';

// Rules sits second, right after General: "which rules matched this request" is
// the question the proxy exists to answer, and it used to be the one thing the
// console could not tell you.
export const DETAIL_TABS: { key: DetailTab; label: string }[] = [
  { key: 'general', label: 'General' },
  { key: 'rules', label: 'Rules' },
  { key: 'req-head', label: 'Request Header' },
  { key: 'res-head', label: 'Response Header' },
  { key: 'req-body', label: 'Request Body' },
  { key: 'res-body', label: 'Response Body' },
  { key: 'frames', label: 'Frames' },
];

const THEME_KEY = 'whistle-rs-theme';

interface State {
  pane: Pane;
  theme: Theme;
  filter: string;
  autoRefresh: boolean;

  sessions: SessionSummary[];
  /** `null` = every client. */
  client: string | null;
  selected: number | null;
  detail: SessionDetail | null;
  frames: WsFrame[] | null;
  detailTab: DetailTab;
  sort: { key: string; dir: 'asc' | 'desc' };
  prettyBody: boolean;
  /** Bumped when the selection moved by keyboard and wants scrolling into view. */
  revealSeq: number;
  /** A value name the source list asked the Values editor to jump to. */
  valueReveal: { key: string; seq: number };
  /** A transient message shown where the request count normally is. */
  note: string | null;
  /** True once a call to the proxy failed, until one succeeds. */
  offline: boolean;

  groups: RuleGroup[];
  group: string;
  rulesText: string;
  rulesStatus: string;

  values: Record<string, string>;
  valuesText: string;
  valuesStatus: string;

  status: ProxyStatus | null;
}

export const state = reactive<State>({
  pane: 'requests',
  theme: 'light',
  filter: '',
  autoRefresh: true,

  sessions: [],
  client: null,
  selected: null,
  detail: null,
  frames: null,
  detailTab: 'general',
  sort: { key: 'id', dir: 'desc' },
  prettyBody: true,
  revealSeq: 0,
  valueReveal: { key: '', seq: 0 },
  note: null,
  offline: false,

  groups: [],
  group: 'default',
  rulesText: '',
  rulesStatus: '',

  values: {},
  valuesText: '',
  valuesStatus: '',

  status: null,
});

// ── derived ────────────────────────────────────────────────────────────────

/** The sessions the source list and the filter box agree on. */
const visibleSessions = computed(() => {
  const q = state.filter.trim().toLowerCase();
  return state.sessions.filter((s) => {
    if (state.client && clientOf(s) !== state.client) return false;
    if (!q) return true;
    return (
      (s.url || '').toLowerCase().includes(q) ||
      (s.method || '').toLowerCase().includes(q) ||
      (s.target || '').toLowerCase().includes(q) ||
      String(s.status).includes(q)
    );
  });
});

/** The rows as currently shown, which is what the arrow keys move through. */
export const shownRows = computed(() => {
  const col = COLUMNS.find((c) => c.key === state.sort.key) || COLUMNS[0];
  const sign = state.sort.dir === 'asc' ? 1 : -1;
  return visibleSessions.value.slice().sort((a, b) => {
    const x = col.get(a);
    const y = col.get(b);
    if (x === y) return (a.id - b.id) * sign;
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * sign;
    return String(x).localeCompare(String(y)) * sign;
  });
});

export const selectedSession = computed(
  () => state.sessions.find((s) => s.id === state.selected) || null,
);

/** How many requests are in view, and out of how many — or a transient note. */
export const countLabel = computed(() => {
  if (state.note) return state.note;
  // Worth saying plainly: a console polling a proxy that has stopped answering
  // otherwise looks exactly like a proxy through which nothing is passing.
  if (state.offline) return 'proxy not answering';
  const shown = shownRows.value.length;
  const total = state.sessions.length;
  return shown === total ? `${total} requests` : `${shown} of ${total} requests`;
});

/** One entry per client seen, newest capture included, sorted by address. */
export const clientCounts = computed(() => {
  const counts = new Map<string, number>();
  for (const s of state.sessions) {
    const c = clientOf(s);
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  return [...counts.keys()].sort().map((name) => ({ name, count: counts.get(name)! }));
});

/**
 * Whether a detail tab has anything behind it.
 *
 * A tab that would open on an empty panel is disabled instead: with the header
 * and body tabs sitting side by side, "did this request have a body" is a
 * question the tab strip can answer without being clicked.
 *
 * **Rules is the exception, deliberately.** "No rule matched" is an answer, and
 * a greyed-out tab does not give it — it reads the same as a tab whose contents
 * have not loaded. The panel says it in words instead.
 */
export function tabEnabled(key: DetailTab): boolean {
  const s = selectedSession.value;
  const d = state.detail;
  if (!s) return false;
  switch (key) {
    case 'req-head': return !!d?.req_headers?.length;
    case 'res-head': return !!d?.res_headers?.length;
    case 'req-body': return !!d?.req_body?.len;
    case 'res-body': return !!d?.res_body?.len;
    case 'frames': return s.status === 101;
    default: return true;
  }
}

// ── theme ──────────────────────────────────────────────────────────────────

export function applyTheme(mode: Theme): void {
  state.theme = mode;
  document.documentElement.setAttribute('data-theme', mode);
  try {
    localStorage.setItem(THEME_KEY, mode);
  } catch {
    /* private mode */
  }
}

export function initTheme(): void {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch {
    /* private mode */
  }
  const dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(saved === 'dark' || saved === 'light' ? saved : dark ? 'dark' : 'light');
}

// ── talking to the proxy ───────────────────────────────────────────────────

/**
 * Make one call, and remember whether the proxy answered.
 *
 * Every read goes through here so that a proxy that has gone away is reported
 * once, in the console's own furniture, rather than as a stack trace in the
 * browser's — this page polls every two seconds, and it is the one page you
 * cannot open the devtools of without leaving what you were looking at.
 */
async function reach<T>(call: () => Promise<T>): Promise<T | undefined> {
  try {
    const value = await call();
    state.offline = false;
    return value;
  } catch {
    state.offline = true;
    return undefined;
  }
}

// ── requests ───────────────────────────────────────────────────────────────

export async function loadSessions(): Promise<void> {
  const list = await reach(api.sessions);
  if (!list) return;
  state.sessions = list;
  if (state.client && !list.some((s) => clientOf(s) === state.client)) state.client = null;
  if (state.selected !== null && !list.some((s) => s.id === state.selected)) {
    state.selected = null;
    state.detail = null;
    state.frames = null;
  }
}

export async function selectRow(id: number): Promise<void> {
  state.selected = id;
  state.detail = null;
  state.frames = null;
  const detail = await reach(() => api.session(id));
  if (state.selected !== id || detail === undefined) return;
  state.detail = detail;
}

export function clearSelection(): void {
  state.selected = null;
  state.detail = null;
  state.frames = null;
}

/** Move the selection `delta` rows through the list, and keep it in view. */
export function moveSelection(delta: number): void {
  const list = shownRows.value;
  if (!list.length) return;
  const at = list.findIndex((s) => s.id === state.selected);
  const next =
    at < 0
      ? delta > 0
        ? 0
        : list.length - 1
      : Math.max(0, Math.min(list.length - 1, at + delta));
  void selectRow(list[next].id);
  state.revealSeq++;
}

export function toggleSort(key: string): void {
  state.sort =
    state.sort.key === key
      ? { key, dir: state.sort.dir === 'asc' ? 'desc' : 'asc' }
      : { key, dir: key === 'id' || key === 'time_ms' ? 'desc' : 'asc' };
}

export async function loadFrames(id: number): Promise<void> {
  const list = await reach(() => api.frames(id));
  if (state.selected !== id || !list) return;
  // `/frames.json` answers newest-first; a conversation reads oldest-first.
  state.frames = list.slice().reverse();
}

export async function clearSessions(): Promise<void> {
  if (!(await reach(api.clearSessions))) return;
  clearSelection();
  await loadSessions();
}

export async function replaySelected(): Promise<void> {
  if (state.selected === null) return;
  const id = state.selected;
  if (!(await reach(() => api.replay(id)))) return;
  // The replay is fired off asynchronously by the proxy; give it a moment to
  // come back around through the capture before asking for the list again.
  setTimeout(() => void loadSessions(), 400);
}

let noteTimer: number | undefined;

/** Say something where the request count normally is, briefly. */
export function flashNote(text: string): void {
  state.note = text;
  clearTimeout(noteTimer);
  noteTimer = setTimeout(() => {
    state.note = null;
  }, 1600) as unknown as number;
}

export async function copyText(text: string, note: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // No clipboard permission (or no clipboard API): fall back to the old way.
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
    } finally {
      ta.remove();
    }
  }
  flashNote(note);
}

// ── rules ──────────────────────────────────────────────────────────────────

export async function loadRules(): Promise<void> {
  const groups = await reach(api.ruleGroups);
  if (!groups) {
    state.rulesStatus = 'Could not reach the proxy';
    return;
  }
  state.groups = groups;
  await selectGroup(state.group, true);
}

export async function selectGroup(name: string, keepStatus = false): Promise<void> {
  state.group = name;
  if (!keepStatus) state.rulesStatus = '';
  const text = await reach(async () =>
    name === 'default' ? await api.rules() : (await api.ruleGroup(name)).text || '',
  );
  if (text === undefined) {
    state.rulesStatus = 'Could not reach the proxy';
    return;
  }
  state.rulesText = text;
}

export async function saveRules(): Promise<void> {
  try {
    if (state.group === 'default') {
      const res = await api.saveRules(state.rulesText);
      state.rulesStatus = `Saved · ${res.rules} rules active`;
      return;
    }
    const res = await api.updateRuleGroup(state.group, state.rulesText);
    state.rulesStatus = res.ok ? 'Saved' : res.error || 'Save failed';
    await loadRules();
  } catch {
    state.rulesStatus = 'Save failed';
  }
}

export async function addGroup(): Promise<void> {
  const name = prompt('Group name:');
  if (!name || !name.trim()) return;
  const res = await api.addRuleGroup(name.trim());
  if (!res.ok) {
    alert(res.error || 'Failed');
    return;
  }
  state.group = name.trim();
  await loadRules();
}

export async function toggleGroup(name: string): Promise<void> {
  await api.toggleRuleGroup(name);
  await loadRules();
}

export async function deleteGroup(name: string): Promise<void> {
  if (!confirm(`Delete group "${name}"?`)) return;
  const res = await api.deleteRuleGroup(name);
  if (!res.ok) {
    alert(res.error || 'Failed');
    return;
  }
  if (state.group === name) state.group = 'default';
  await loadRules();
}

// ── values ─────────────────────────────────────────────────────────────────

export async function loadValues(): Promise<void> {
  const values = await reach(api.values);
  if (!values) {
    state.valuesStatus = 'Could not reach the proxy';
    return;
  }
  state.values = values;
  state.valuesText = JSON.stringify(values, null, 2);
}

/** Ask the Values editor to jump to a key, from the source list. */
export function revealValue(key: string): void {
  state.valueReveal = { key, seq: state.valueReveal.seq + 1 };
}

export async function saveValues(): Promise<void> {
  try {
    JSON.parse(state.valuesText);
  } catch (e) {
    state.valuesStatus = 'Invalid JSON: ' + (e as Error).message;
    return;
  }
  try {
    await api.saveValues(state.valuesText);
    state.valuesStatus = 'Saved';
    await loadValues();
  } catch {
    state.valuesStatus = 'Save failed';
  }
}

// ── status ─────────────────────────────────────────────────────────────────

export async function loadStatus(): Promise<void> {
  const status = await reach(api.status);
  if (status) state.status = status;
}

// ── panes ──────────────────────────────────────────────────────────────────

export function showPane(name: Pane): void {
  state.pane = name;
  if (name === 'rules') void loadRules();
  if (name === 'values') void loadValues();
  if (name === 'status') void loadStatus();
}

/** ⌘S saves whichever pane is showing, and nothing else has one. */
export function saveCurrentPane(): void {
  if (state.pane === 'rules') void saveRules();
  else if (state.pane === 'values') void saveValues();
}
