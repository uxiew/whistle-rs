// One reactive store for the whole console.
//
// A plain `reactive` module rather than Pinia: there is one store, it is never
// instantiated twice, there is no SSR and no route to hydrate from, and the
// console ships as a file embedded in a binary — so the only thing a store
// library would add here is bytes. What Pinia is actually for (many stores,
// hot-swapped modules, devtools timelines) never comes up in a single window
// with five panes.

import { computed, reactive, watch } from 'vue';
import { api } from './api';
import type {
  Composition,
  ProxyStatus,
  ReplayedSession,
  RuleGroup,
  SessionDetail,
  SessionSummary,
  WsFrame,
  WsPauseStatus,
} from './api';
import { COLUMNS } from './columns';
import { clientOf, fmtBytes } from './format';

export type Pane = 'requests' | 'composer' | 'rules' | 'values' | 'status';
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
const COMPOSE_KEY = 'whistle-rs-composer';
const COMPOSE_HISTORY_KEY = 'whistle-rs-composer-history';

/** How many sent compositions the source list keeps. Upstream keeps 100. */
const COMPOSE_HISTORY_MAX = 20;

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
  /** Whether the selected WebSocket is being held — `null` until asked. */
  wsPause: WsPauseStatus | null;
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

  /** The request being written in the Composer, and the ones already sent. */
  compose: Composition;
  composeStatus: string;
  composeHistory: Composition[];

  status: ProxyStatus | null;
}

/** What the Composer opens on, and what "New request" goes back to. */
function blankComposition(): Composition {
  return { method: 'GET', url: '', headers: '', body: '' };
}

/** The method as it will be *sent*: trimmed, uppercased, empty meaning GET. */
export const methodOf = (c: Composition): string => (c.method.trim() || 'GET').toUpperCase();

function readStored<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    // Private mode, or a value written by a version that shaped it differently.
    return fallback;
  }
}

function writeStored(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* private mode */
  }
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
  wsPause: null,
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

  // A half-written request survives a reload. It has to: the console is served
  // by the proxy you are reconfiguring, so the page is reloaded far more often
  // here than in an application you would merely be using.
  compose: readStored(COMPOSE_KEY, blankComposition()),
  composeStatus: '',
  composeHistory: readStored<Composition[]>(COMPOSE_HISTORY_KEY, []),

  status: null,
});

watch(() => state.compose, (c) => writeStored(COMPOSE_KEY, c), { deep: true });

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
    state.wsPause = null;
  }
}

export async function selectRow(id: number): Promise<void> {
  state.selected = id;
  state.detail = null;
  state.frames = null;
  state.wsPause = null;
  const detail = await reach(() => api.session(id));
  if (state.selected !== id || detail === undefined) return;
  state.detail = detail;
}

export function clearSelection(): void {
  state.selected = null;
  state.detail = null;
  state.frames = null;
  state.wsPause = null;
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
  // Whether a direction is being held has to be asked for separately: a pause
  // that has caught nothing yet is invisible in the frames themselves.
  const pause = await reach(() => api.wsPause(id));
  if (state.selected === id && pause) state.wsPause = pause;
}

/**
 * Let one held direction of the selected session go.
 *
 * All of it at once, because that is the only granularity whistle has: its own
 * console sets the direction's status back to normal and everything held goes
 * out together. A session that has closed in the meantime answers plainly
 * rather than silently doing nothing — its frames are never getting out now.
 */
export async function releaseWsDir(dir: 'send' | 'receive'): Promise<void> {
  const id = state.selected;
  if (id === null) return;
  const res = await reach(() => api.releaseWs(id, dir));
  if (!res) return;
  flashNote(
    res.ok ? `Released ${res.released ?? 0} held ${dir} frame(s)` : res.error || 'Release failed',
  );
  await loadFrames(id);
}

export async function clearSessions(): Promise<void> {
  if (!(await reach(api.clearSessions))) return;
  clearSelection();
  await loadSessions();
}

export async function replaySelected(): Promise<void> {
  if (state.selected === null) return;
  const id = state.selected;
  const res = await reach(() => api.replay(id));
  if (!res) return;
  flashNote(replayNote(res.sessions?.[0]));
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

// ── composer ───────────────────────────────────────────────────────────────

/** The bytes a string will actually be sent as, which is what `sent` counts. */
const byteLength = (text: string): number => new TextEncoder().encode(text).length;

/**
 * Open a captured request in the Composer, ready to be edited and sent again.
 *
 * The most valuable thing the Composer does: almost nothing anyone composes is
 * written from nothing — it is a request that already happened, with one header
 * changed. `curl.ts` renders the same request for a terminal; this is the same
 * journey without leaving the console.
 *
 * `content-length` and `host` are left out on purpose. Both are recomputed by
 * the proxy from the URL and the body as they stand when Send is pressed, so
 * seeding them would only offer a stale number to edit.
 */
export function composeFrom(s: SessionSummary, d: SessionDetail | null): void {
  state.compose = {
    method: s.method,
    url: s.url,
    headers: (d?.req_headers ?? [])
      .filter(([name]) => !/^(content-length|host)$/i.test(name))
      .map(([name, value]) => `${name}: ${value}`)
      .join('\n'),
    body: d?.req_body?.text ?? '',
  };
  // A capture is a capped preview, so what is seeded is not always what was
  // sent. Saying so is the point: a composition silently missing 190 KB of a
  // 200 KB upload would come back 200 and be read as proof the endpoint works.
  const body = d?.req_body;
  state.composeStatus =
    body?.truncated === true
      ? `Seeded from #${s.id} · the capture held ${fmtBytes(byteLength(body.text))} of a ${fmtBytes(body.len)} body`
      : `Seeded from #${s.id}`;
  showPane('composer');
}

/** Load one of the sent compositions back into the editor. */
export function useComposition(c: Composition): void {
  state.compose = { ...c };
  state.composeStatus = '';
}

export function newComposition(): void {
  state.compose = blankComposition();
  state.composeStatus = '';
}

/** Put a composition at the head of the history, deduplicated as upstream's is. */
function remember(c: Composition): void {
  const same = (h: Composition) =>
    h.method === c.method && h.url === c.url && h.headers === c.headers && h.body === c.body;
  state.composeHistory = [c, ...state.composeHistory.filter((h) => !same(h))].slice(
    0,
    COMPOSE_HISTORY_MAX,
  );
  writeStored(COMPOSE_HISTORY_KEY, state.composeHistory);
}

/**
 * Send what is in the Composer through the proxy.
 *
 * The proxy sends it to *itself*, so the composition is matched, rewritten and
 * captured like any other request rather than being a private conversation
 * between the console and an origin — which is what makes the Composer a way to
 * test rules and not merely a second curl.
 */
export async function sendComposition(): Promise<void> {
  const sending = { ...state.compose };
  if (!sending.url.trim()) {
    state.composeStatus = 'A URL is required';
    return;
  }
  // Everything already captured, so the request this one becomes can be told
  // apart from the traffic that was there before it.
  const before = state.sessions.reduce((max, s) => Math.max(max, s.id), 0);
  const res = await reach(() => api.compose(sending));
  if (!res) {
    state.composeStatus = 'Could not reach the proxy';
    return;
  }
  if (!res.ok) {
    state.composeStatus = res.error || 'The proxy refused it';
    return;
  }
  remember(sending);
  const url = res.url || sending.url;
  state.composeStatus = `Sent · ${url}`;
  flashNote(`Sent ${methodOf(sending)} ${url}`);
  // Fire-and-forget on the proxy's side, as a replay is: the answer arrives in
  // the session list, not here, so give it the same moment to come back around.
  setTimeout(() => void revealComposed(sending, url, before), 400);
}

/**
 * Show what the composition became.
 *
 * The Composer's result is a row in the request list, so that is where this
 * goes — and it selects the row when it can recognise it. It often cannot: a
 * rule that rewrote the URL makes the captured request a different one, which
 * is precisely the case where you most want the list rather than a claim.
 */
async function revealComposed(sent: Composition, url: string, after: number): Promise<void> {
  await loadSessions();
  const method = methodOf(sent);
  const hit = state.sessions.find((s) => s.id > after && s.url === url && s.method === method);
  showPane('requests');
  if (hit) void selectRow(hit.id);
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
