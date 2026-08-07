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
  ReplayedSession,
  RuleGroup,
  SessionDetail,
  SessionSummary,
  WsFrame,
} from './api';
import { COLUMNS } from './columns';
import { clientOf, fmtBytes } from './format';

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
  /** The row the detail panel is showing — one of `selection`, or `null`. */
  selected: number | null;
  /** Every row the table has selected, in the order they were picked. */
  selection: number[];
  /** Where a shift-click measures its range from. */
  anchor: number | null;
  /** Rows flagged by hand — see [`toggleMark`]. */
  marked: number[];
  markedOnly: boolean;
  detail: SessionDetail | null;
  frames: WsFrame[] | null;
  detailTab: DetailTab;
  sort: { key: string; dir: 'asc' | 'desc' };
  prettyBody: boolean;
  /** Bumped when the selection moved by keyboard and wants scrolling into view. */
  revealSeq: number;
  /** The value being edited, or `null` for the whole store as one JSON object. */
  valueKey: string | null;
  /** The selected value's content, edited on its own. */
  valueText: string;
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
  selection: [],
  anchor: null,
  marked: [],
  markedOnly: false,
  detail: null,
  frames: null,
  detailTab: 'general',
  sort: { key: 'id', dir: 'desc' },
  prettyBody: true,
  revealSeq: 0,
  valueKey: null,
  valueText: '',
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
    if (state.markedOnly && !state.marked.includes(s.id)) return false;
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
  // A session that has fallen out of the proxy's ring takes its selection and
  // its mark with it: both name a row by an id that now belongs to nothing.
  const live = new Set(list.map((s) => s.id));
  state.selection = state.selection.filter((id) => live.has(id));
  state.marked = state.marked.filter((id) => live.has(id));
  if (state.markedOnly && !state.marked.length) state.markedOnly = false;
  if (state.anchor !== null && !live.has(state.anchor)) state.anchor = null;
  if (state.selected !== null && !live.has(state.selected)) {
    state.selected = null;
    state.detail = null;
    state.frames = null;
  }
}

/** What a click carried, as the table's modifier keys mean it. */
export interface Pick {
  /** ⌘/Ctrl: add this row to the selection, or take it out. */
  toggle?: boolean;
  /** Shift: select everything between the anchor and this row. */
  extend?: boolean;
}

export async function selectRow(id: number, pick: Pick = {}): Promise<void> {
  const rows = shownRows.value.map((s) => s.id);
  const from = state.anchor === null ? -1 : rows.indexOf(state.anchor);
  if (pick.extend && from >= 0 && rows.includes(id)) {
    // The range runs through the rows *as shown*, not by id: the table sorts,
    // and a shift-click means "these, between here and there".
    const to = rows.indexOf(id);
    state.selection = rows.slice(Math.min(from, to), Math.max(from, to) + 1);
  } else if (pick.toggle) {
    state.selection = state.selection.includes(id)
      ? state.selection.filter((x) => x !== id)
      : [...state.selection, id];
    state.anchor = id;
  } else {
    state.selection = [id];
    state.anchor = id;
  }
  // Un-picking the row being shown moves the panel to whatever is still picked,
  // rather than leaving it on a row the table no longer highlights.
  await showDetail(state.selection.includes(id) ? id : (state.selection.at(-1) ?? null));
}

/** Fill the detail panel from one session, or empty it. */
async function showDetail(id: number | null): Promise<void> {
  if (id === state.selected) return;
  state.selected = id;
  state.detail = null;
  state.frames = null;
  if (id === null) return;
  const detail = await reach(() => api.session(id));
  if (state.selected !== id || detail === undefined) return;
  state.detail = detail;
}

export function clearSelection(): void {
  state.selection = [];
  state.anchor = null;
  void showDetail(null);
}

/**
 * Move the selection `delta` rows through the list, and keep it in view.
 * With `extend`, the anchor stays put and the range grows — shift-arrow, the
 * keyboard's spelling of a shift-click.
 */
export function moveSelection(delta: number, extend = false): void {
  const list = shownRows.value;
  if (!list.length) return;
  const at = list.findIndex((s) => s.id === state.selected);
  const next =
    at < 0
      ? delta > 0
        ? 0
        : list.length - 1
      : Math.max(0, Math.min(list.length - 1, at + delta));
  void selectRow(list[next].id, { extend });
  state.revealSeq++;
}

/**
 * Flag rows, or clear the flag — all of them at once, so a marked selection
 * un-marks and a mixed one marks.
 *
 * Marks live in this window and nowhere else, deliberately. A mark names a
 * session by the id the proxy gave it, and those ids start again at 1 every
 * time the proxy restarts — kept in `localStorage`, a mark would come back
 * attached to whatever request took its number next, which is worse than not
 * keeping it. Nor is there anywhere on the proxy to put it: the session ring
 * records what crossed the wire, not what someone thought about it.
 */
export function toggleMark(ids: number[]): void {
  if (!ids.length) return;
  state.marked = ids.every((id) => state.marked.includes(id))
    ? state.marked.filter((id) => !ids.includes(id))
    : [...new Set([...state.marked, ...ids])];
  if (!state.marked.length) state.markedOnly = false;
}

/** The rows the bulk actions act on: the selection, or the one row shown. */
export const actingOn = computed(() =>
  state.selection.length ? state.selection : state.selected === null ? [] : [state.selected],
);

/** Forget the selected sessions, and only those. */
export async function clearSelected(): Promise<void> {
  const ids = actingOn.value.slice();
  if (!ids.length) return;
  if (!(await reach(() => api.clearSessions(ids)))) return;
  clearSelection();
  await loadSessions();
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
  const ids = actingOn.value.slice();
  if (!ids.length) return;
  const res = await reach(() => api.replay(ids));
  if (!res) return;
  // One replay is reported in full — whether its body survived the capture is
  // the thing worth saying. A batch reports the count; naming which of twenty
  // requests lost bytes belongs on the rows, not in a one-line note.
  flashNote(ids.length > 1 ? `Replayed ${res.replayed} requests` : replayNote(res.sessions?.[0]));
  // The replay is fired off asynchronously by the proxy; give it a moment to
  // come back around through the capture before asking for the list again.
  setTimeout(() => void loadSessions(), 400);
}

/**
 * What to say about a replay that went out.
 *
 * A replay is rebuilt from the *captured* body — a decoded, capped preview —
 * so it is not always the request it was made from. Saying so is the point:
 * a replay that silently dropped 190 KB of a 200 KB upload and came back 200
 * would be read as proof the endpoint works.
 */
function replayNote(r: ReplayedSession | undefined): string {
  switch (r?.body) {
    case 'partial':
      return `Replayed · body cut to ${fmtBytes(r.sent)} of ${fmtBytes(r.captured)}`;
    case 'undecodable':
      return 'Replayed without its body · the capture would not decode';
    case 'whole':
      return `Replayed with its ${fmtBytes(r.sent)} body`;
    default:
      return 'Replayed';
  }
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
  // A key that is no longer there — deleted, or renamed from another window —
  // falls back to the whole store rather than editing something that is gone.
  if (state.valueKey !== null && !(state.valueKey in values)) state.valueKey = null;
  if (state.valueKey !== null) state.valueText = values[state.valueKey];
}

/** Edit one value, or `null` for the whole store as one JSON object. */
export function selectValue(name: string | null): void {
  state.valueKey = name;
  state.valuesStatus = '';
  state.valueText = name === null ? '' : (state.values[name] ?? '');
}

/** Save whichever of the two the Values pane is showing. */
export async function saveValue(): Promise<void> {
  if (state.valueKey === null) return saveValues();
  const name = state.valueKey;
  const res = await reach(() => api.setValue(name, state.valueText));
  if (!res) {
    state.valuesStatus = 'Save failed';
    return;
  }
  state.valuesStatus = res.ok ? 'Saved' : res.error || 'Save failed';
  await loadValues();
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

export async function addValue(): Promise<void> {
  const name = prompt('Value name:');
  if (!name || !name.trim()) return;
  const res = await api.setValue(name.trim(), '');
  if (!res.ok) {
    alert(res.error || 'Failed');
    return;
  }
  await loadValues();
  selectValue(name.trim());
}

export async function renameValue(name: string): Promise<void> {
  const to = prompt('Rename value to:', name);
  if (!to || !to.trim() || to.trim() === name) return;
  const res = await api.renameValue(name, to.trim());
  if (!res.ok) {
    alert(res.error || 'Failed');
    return;
  }
  state.valueKey = to.trim();
  await loadValues();
}

export async function deleteValue(name: string): Promise<void> {
  if (!confirm(`Delete value "${name}"?`)) return;
  const res = await api.deleteValue(name);
  if (!res.ok) {
    alert(res.error || 'Failed');
    return;
  }
  selectValue(null);
  await loadValues();
}

// ── import / export ────────────────────────────────────────────────────────

/** The marker the proxy writes into a bundle, and the only way one is known. */
const BUNDLE_MARKER = 'whistle_rs';

/** Hand `text` to the browser as a file, without leaving the page. */
export function downloadText(name: string, text: string, type = 'text/plain'): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** The selected group, as the rules file it is — the editor's text, as shown. */
export function exportGroup(): void {
  downloadText(`${state.group}.rules`, state.rulesText);
}

/** The selected value, or the whole store as the JSON object it is kept as. */
export function exportValues(): void {
  if (state.valueKey === null) downloadText('values.json', state.valuesText, 'application/json');
  else downloadText(state.valueKey, state.valueText);
}

/** The parsed object if `text` is an exported bundle, and `null` otherwise. */
function asBundle(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    if (value && typeof value === 'object' && BUNDLE_MARKER in value) {
      return value as Record<string, unknown>;
    }
  } catch {
    // Not JSON at all, which is what a rules file is.
  }
  return null;
}

/** A JSON object of strings — the shape a plain values export has. */
function asValueStore(text: string): Record<string, string> | null {
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const entries = Object.entries(value);
    if (!entries.length || !entries.every(([, v]) => typeof v === 'string')) return null;
    return Object.fromEntries(entries) as Record<string, string>;
  } catch {
    return null;
  }
}

/**
 * Read a file back in.
 *
 * A bundle — recognised by its marker, never by guessing — restores the groups,
 * their switches and the values in one act. Anything else is the plain text it
 * looks like: a rules file becomes the group it is named after, a values export
 * becomes its keys, and any other file becomes one value.
 *
 * Which of the two a plain file lands in follows the pane it was imported from.
 * A rules group and a value are both just text, and nothing inside the file
 * tells them apart.
 */
export async function importFile(file: File): Promise<void> {
  const text = await file.text();
  const bundle = asBundle(text);
  if (bundle) {
    const res = await api.importBundle(bundle);
    if (!res.ok) {
      alert(res.error || 'Import failed');
      return;
    }
    const note = `Imported ${res.groups ?? 0} groups and ${res.values ?? 0} values`;
    await loadRules();
    await loadValues();
    state.rulesStatus = note;
    state.valuesStatus = note;
    return;
  }

  const name = file.name.replace(/\.(rules|txt|json)$/i, '') || file.name;
  if (state.pane === 'rules') {
    // A group that already exists is updated rather than refused, so a file
    // exported from here imports back over the group it came from.
    const res = state.groups.some((g) => g.name === name)
      ? await api.updateRuleGroup(name, text)
      : await api.addRuleGroup(name, text);
    if (!res.ok) {
      alert(res.error || 'Import failed');
      return;
    }
    state.group = name;
    await loadRules();
    state.rulesStatus = `Imported ${file.name}`;
    return;
  }

  const store = asValueStore(text);
  for (const [key, value] of Object.entries(store ?? { [name]: text })) {
    await api.setValue(key, value);
  }
  await loadValues();
  state.valuesStatus = `Imported ${file.name}`;
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
  else if (state.pane === 'values') void saveValue();
}
