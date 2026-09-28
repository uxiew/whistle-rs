// One reactive store for the whole console.
//
// A plain `reactive` module rather than Pinia: there is one store, it is never
// instantiated twice, there is no SSR and no route to hydrate from, and the
// console ships as a file embedded in a binary — so the only thing a store
// library would add here is bytes. What Pinia is actually for (many stores,
// hot-swapped modules, devtools timelines) never comes up in a single window
// with five panes.

import { computed, reactive, ref, watch } from 'vue';
import { api } from './api';
// The filter grammar, imported for its side effect: the module is plain
// script-shaped JavaScript with no exports, because the same file is evaluated
// by a Rust test in the engine the proxy already carries. One copy, so the
// console and the test cannot drift. See the note at the top of the file.
import './filter/session-filter.js';
import type {
  Composition,
  ExplainQuery,
  Explanation,
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

export type Pane = 'requests' | 'composer' | 'rules' | 'values' | 'test' | 'status';
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
const TEST_KEY = 'whistle-rs-test-rules';
const COMPOSE_HISTORY_KEY = 'whistle-rs-composer-history';
const CAPTURE_KEY = 'whistle-rs-capture-filter';

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
  /** The row the detail panel is showing — one of `selection`, or `null`. */
  selected: number | null;
  /** Every row the table has selected, in the order they were picked. */
  selection: number[];
  /** Where a shift-click measures its range from. */
  anchor: number | null;
  /** Rows flagged by hand — see [`toggleMark`]. */
  marked: number[];
  markedOnly: boolean;
  /**
   * The capture filters — `gui/network.md`'s Include/Exclude Filter. Unlike the
   * search box these decide what is **kept at all**, they read only what a
   * request carries, and they apply to requests that arrive *after* they are
   * set: a row already on screen stays there.
   */
  captureInclude: string;
  captureExclude: string;
  detail: SessionDetail | null;
  frames: WsFrame[] | null;
  /** Whether the selected WebSocket is being held — `null` until asked. */
  wsPause: WsPauseStatus | null;
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

  /** The request being written in the Composer, and the ones already sent. */
  compose: Composition;
  composeStatus: string;
  composeHistory: Composition[];

  status: ProxyStatus | null;

  /** Test Rules: the question, and the last answer. */
  /** The frame the Frames panel's composer is holding. */
  wsCompose: string;

  test: TestQuery;
  testResult: Explanation | null;
  testStatus: string;
}

/** What the Test Rules pane holds between visits. */
export interface TestQuery {
  rules: string;
  url: string;
  method: string;
  headers: string;
  body: string;
  /** Empty for "ask about the request phase only". */
  status: string;
}

/** What Test Rules opens on. */
function blankTest(): TestQuery {
  return { rules: '', url: '', method: 'GET', headers: '', body: '', status: '' };
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
  selection: [],
  anchor: null,
  marked: [],
  markedOnly: false,
  captureInclude: readStored<{ inc: string; exc: string }>(CAPTURE_KEY, { inc: '', exc: '' }).inc,
  captureExclude: readStored<{ inc: string; exc: string }>(CAPTURE_KEY, { inc: '', exc: '' }).exc,
  detail: null,
  frames: null,
  wsPause: null,
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

  // A half-written request survives a reload. It has to: the console is served
  // by the proxy you are reconfiguring, so the page is reloaded far more often
  // here than in an application you would merely be using.
  compose: readStored(COMPOSE_KEY, blankComposition()),
  wsCompose: '',
  test: readStored(TEST_KEY, blankTest()),
  testResult: null,
  testStatus: '',
  composeStatus: '',
  composeHistory: readStored<Composition[]>(COMPOSE_HISTORY_KEY, []),

  status: null,
});

watch(
  () => [state.captureInclude, state.captureExclude],
  ([inc, exc]) => writeStored(CAPTURE_KEY, { inc, exc }),
);
watch(() => state.compose, (c) => writeStored(COMPOSE_KEY, c), { deep: true });
watch(() => state.test, (t) => writeStored(TEST_KEY, t), { deep: true });

/* eslint-disable @typescript-eslint/no-explicit-any */
const parseFilter = (globalThis as any).whistleParseFilter as (
  q: string,
) => { conditions: unknown[]; unsupported: { prefix: string; why: string }[] };
const matchSession = (globalThis as any).whistleMatchSession as (
  s: SessionSummary,
  c: unknown[],
  ctx: { marked: number[] },
) => boolean;
const matchAny = (globalThis as any).whistleMatchAny as (
  s: SessionSummary,
  c: unknown[],
  ctx: { marked: number[] },
) => boolean;

/**
 * Rows the capture filters have already let through.
 *
 * The filters apply to what *arrives*, not to what is on screen — upstream says
 * so in as many words, and it is the useful behaviour: tightening a filter to
 * silence a poller should not make the request you are reading vanish. Since the
 * console re-reads the whole list on every poll rather than accumulating, the
 * only way to keep that promise is to remember what was already admitted.
 */
const admitted = new Set<number>();

/** How many arriving rows the capture filters have refused. */
const refused = ref(0);

/** The refused count, for the status line — a filter nobody can see is a trap. */
export const captureRefused = computed(() => refused.value);

/** Whether either capture filter has anything in it. */
export const captureFiltering = computed(
  () => !!(state.captureInclude.trim() || state.captureExclude.trim()),
);

/** Apply the capture filters to a freshly fetched list. */
function admit(list: SessionSummary[]): SessionSummary[] {
  const inc = parseFilter(state.captureInclude).conditions;
  const exc = parseFilter(state.captureExclude).conditions;
  if (!inc.length && !exc.length) {
    for (const s of list) admitted.add(s.id);
    refused.value = 0;
    return list;
  }
  const ctx = { marked: state.marked };
  let dropped = 0;
  const kept = list.filter((s) => {
    if (admitted.has(s.id)) return true;
    // Include is a whitelist, exclude a blacklist, and the two are AND-ed —
    // conditions *within* a box are OR-ed, which `matchAny` does.
    const ok = (!inc.length || matchAny(s, inc, ctx)) && !(exc.length && matchAny(s, exc, ctx));
    if (ok) admitted.add(s.id);
    else dropped++;
    return ok;
  });
  refused.value = dropped;
  return kept;
}

// ── derived ────────────────────────────────────────────────────────────────

/**
 * The filter box's query, parsed.
 *
 * `whistle`'s little language: a bare word matches the URL, `m:` the method,
 * `s:` the status, and so on, with several conditions AND-ed — see
 * `filter/session-filter.js`, which is the one copy of the grammar and is tested
 * from Rust against the same table.
 */
const parsedFilter = computed(() => parseFilter(state.filter));

/** The prefixes in the box this console has no answer for, with the reason. */
export const filterGaps = computed(() => parsedFilter.value.unsupported);

/** The sessions the source list and the filter box agree on. */
const visibleSessions = computed(() => {
  const { conditions } = parsedFilter.value;
  return state.sessions.filter((s) => {
    if (state.client && clientOf(s) !== state.client) return false;
    if (state.markedOnly && !state.marked.includes(s.id)) return false;
    if (!conditions.length) return true;
    return matchSession(s, conditions, { marked: state.marked });
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
    case 'frames': return s.status === 101 || !!s.has_frames;
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
  const fetched = await reach(api.sessions);
  if (!fetched) return;
  const list = admit(fetched);
  state.sessions = list;
  if (state.client && !list.some((s) => clientOf(s) === state.client)) state.client = null;
  // A session that has fallen out of the proxy's ring takes its selection and
  // its mark with it: both name a row by an id that now belongs to nothing.
  const live = new Set(list.map((s) => s.id));
  // A row that has left the proxy's ring takes its admission with it, so the
  // set cannot grow without bound.
  for (const id of [...admitted]) if (!live.has(id)) admitted.delete(id);
  state.selection = state.selection.filter((id) => live.has(id));
  state.marked = state.marked.filter((id) => live.has(id));
  if (state.markedOnly && !state.marked.length) state.markedOnly = false;
  if (state.anchor !== null && !live.has(state.anchor)) state.anchor = null;
  if (state.selected !== null && !live.has(state.selected)) {
    state.selected = null;
    state.detail = null;
    state.frames = null;
    state.wsPause = null;
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
  state.wsPause = null;
  if (id === null) return;
  const detail = await reach(() => api.session(id));
  if (state.selected !== id || detail === undefined) return;
  state.detail = detail;
}

export function clearSelection(): void {
  state.selection = [];
  state.anchor = null;
  // `showDetail(null)` is what empties the panel — including the pause banner,
  // which is read from the session being shown.
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

/**
 * Send a frame into the selected live WebSocket session.
 *
 * `send` puts it on its way to the server, as if the client had sent it;
 * `receive` on its way to the client. It is recorded like any other frame,
 * because it is one — the peer cannot tell it from traffic.
 */
export async function sendWsFrame(dir: 'send' | 'receive', data: string): Promise<void> {
  const id = state.selected;
  if (id === null || !data) return;
  const answer = await reach(() => api.wsSend(id, dir, data));
  if (answer?.ok) {
    state.wsCompose = '';
    await loadFrames(id);
  }
}

/**
 * Ask the proxy which rules a request would hit — whistle's **Test Rules**.
 *
 * The rules under test are whatever is in the editor, not what the proxy is
 * running: that is the point of the panel. Everything else is optional, and the
 * status field turns the question into one about the *response* phase, where a
 * `resHeaders://` guarded by `includeFilter://s:404` finally has an answer.
 */
export async function runTest(): Promise<void> {
  const t = state.test;
  if (!t.url.trim()) {
    state.testStatus = 'a URL to test against';
    return;
  }
  const headers: Record<string, string> = {};
  for (const line of t.headers.split('\n')) {
    const at = line.indexOf(':');
    if (at > 0) headers[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  const status = parseInt(t.status, 10);
  const query: ExplainQuery = {
    rules: t.rules,
    url: t.url.trim(),
    method: t.method.trim() || 'GET',
    headers,
    body: t.body || undefined,
    response: status > 0 ? { status, headers: {} } : undefined,
  };
  state.testStatus = 'testing…';
  const answer = await reach(() => api.explain(query));
  if (!answer) {
    state.testStatus = 'the proxy did not answer';
    return;
  }
  if (answer.error) {
    state.testResult = null;
    state.testStatus = answer.error;
    return;
  }
  state.testResult = answer;
  const n = answer.ops.length;
  state.testStatus = n ? `${n} operator${n === 1 ? '' : 's'}` : 'no rule matched';
}

/** Fill the editor with the rules the proxy is running. */
export async function testCurrentRules(): Promise<void> {
  const text = await reach(() => api.rules());
  if (typeof text === 'string') state.test.rules = text;
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

/** Clear, and delete the saved history on disk — the one that does not come back. */
export async function purgeSessions(): Promise<void> {
  const res = await reach(api.purgeSessions);
  if (!res) return;
  clearSelection();
  await loadSessions();
  flashNote(`Deleted the session history (${res.files_deleted ?? 0} file(s) on disk)`);
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
