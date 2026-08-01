// whistle-rs console.
//
// Three panes share one shell: the sidebar is a source list whose contents
// depend on the pane, and the work area is a table + detail (Requests) or an
// editor (Rules, Values). No framework and no build step — the console is
// served by the proxy itself and has to work with the network it inspects
// switched off.

'use strict';

const $ = (id) => document.getElementById(id);
const el = (tag, cls) => { const n = document.createElement(tag); if (cls) n.className = cls; return n; };
const esc = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ── formatting ─────────────────────────────────────────────────────────────

/** Bytes at the granularity a traffic column wants: never more than 4 chars. */
function fmtBytes(n) {
  if (!n) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return Math.round(n / 1024) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function fmtTime(ms) {
  if (!ms) return '';
  const d = new Date(Number(ms));
  const p = (v) => String(v).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function fmtDateTime(ms) {
  if (!ms) return '—';
  return new Date(Number(ms)).toLocaleString();
}

/** A short label for the host a request went to, for the source list. */
function clientOf(s) { return s.client_ip || 'unknown'; }

// ── state ──────────────────────────────────────────────────────────────────

const state = {
  pane: 'requests',
  sessions: [],
  client: null,        // null = every client
  selected: null,      // session id
  detailTab: 'general',
  detail: null,        // the loaded detail for `selected`
  sort: { key: 'id', dir: 'desc' },
  groups: [],
  group: 'default',    // the rule group being edited
  values: {},
};

// ── request table ──────────────────────────────────────────────────────────

const COLUMNS = [
  { key: 'id', label: 'ID', width: '56px', get: (s) => s.id },
  { key: 'time_ms', label: 'Date', width: '78px', get: (s) => s.time_ms, cell: (s) => fmtTime(s.time_ms) },
  { key: 'client_ip', label: 'Client', width: '124px', get: (s) => clientOf(s) },
  { key: 'status', label: 'Status', width: '106px', get: (s) => s.status, cell: statusCell },
  { key: 'target', label: 'Policy', width: '170px', get: (s) => s.target, cell: (s) => esc(s.target) },
  { key: 'up', label: 'Up', width: '62px', num: true, get: (s) => s.up || 0, cell: (s) => fmtBytes(s.up) },
  { key: 'down', label: 'Down', width: '66px', num: true, get: (s) => s.down || 0, cell: (s) => fmtBytes(s.down) },
  { key: 'method', label: 'Method', width: '64px', get: (s) => s.method, cell: (s) => esc(s.method) },
  { key: 'url', label: 'URL', get: (s) => s.url, cell: (s) => esc(s.url) },
];

function statusCell(s) {
  const cls = s.status === 101 ? 'st-3' : 'st-' + Math.floor(s.status / 100);
  // Only the upgrade is worth a tag. "has a body" is on almost every row, and
  // the detail tabs already say so by being enabled.
  const tag = s.status === 101 ? '<span class="tag ws">WS</span>' : '';
  return '<span class="status-dot ' + cls + '"></span>' + (s.status || '—') + tag;
}

function renderHead() {
  $('head').innerHTML = COLUMNS.map((c) => {
    const arrow = state.sort.key === c.key
      ? ' <span class="sort">' + (state.sort.dir === 'asc' ? '▲' : '▼') + '</span>' : '';
    const w = c.width ? ' style="width:' + c.width + '"' : '';
    return '<th data-key="' + c.key + '"' + w + '>' + c.label + arrow + '</th>';
  }).join('');
}

/** The sessions the source list and the filter box agree on. */
function visibleSessions() {
  const q = $('filter').value.trim().toLowerCase();
  return state.sessions.filter((s) => {
    if (state.client && clientOf(s) !== state.client) return false;
    if (!q) return true;
    return (s.url || '').toLowerCase().includes(q)
      || (s.method || '').toLowerCase().includes(q)
      || (s.target || '').toLowerCase().includes(q)
      || String(s.status).includes(q);
  });
}

function sortSessions(list) {
  const col = COLUMNS.find((c) => c.key === state.sort.key) || COLUMNS[0];
  const sign = state.sort.dir === 'asc' ? 1 : -1;
  return list.slice().sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    if (x === y) return (a.id - b.id) * sign;
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * sign;
    return String(x).localeCompare(String(y)) * sign;
  });
}

function renderRows() {
  const list = sortSessions(visibleSessions());
  $('rows').innerHTML = list.map((s) => {
    const sel = s.id === state.selected ? ' aria-selected="true"' : '';
    const cells = COLUMNS.map((c) => {
      const cls = c.num ? ' class="num"' : '';
      return '<td' + cls + '>' + (c.cell ? c.cell(s) : esc(c.get(s))) + '</td>';
    }).join('');
    return '<tr data-id="' + s.id + '"' + sel + '>' + cells + '</tr>';
  }).join('');
  const total = state.sessions.length;
  $('count').textContent = list.length === total
    ? total + ' requests'
    : list.length + ' of ' + total + ' requests';
  $('replay').disabled = state.selected === null;
}

// ── source list ────────────────────────────────────────────────────────────

function renderSidebar() {
  const bar = $('sidebar');
  bar.innerHTML = '';
  if (state.pane === 'requests') return renderClientList(bar);
  if (state.pane === 'rules') return renderGroupList(bar);
  return renderValueList(bar);
}

function sideTitle(bar, text) {
  const t = el('div', 'side-title');
  t.textContent = text;
  bar.appendChild(t);
}

function sideItem(bar, opts) {
  const item = el('div', 'side-item' + (opts.extraClass ? ' ' + opts.extraClass : ''));
  if (opts.selected) item.setAttribute('aria-selected', 'true');
  if (opts.dot) {
    const d = el('span', 'dot');
    if (opts.dotClass) d.classList.add(opts.dotClass);
    item.appendChild(d);
  }
  const name = el('span', 'side-name');
  name.textContent = opts.label;
  item.appendChild(name);
  if (opts.count !== undefined) {
    const c = el('span', 'side-count');
    c.textContent = opts.count;
    item.appendChild(c);
  }
  if (opts.onClick) item.addEventListener('click', opts.onClick);
  bar.appendChild(item);
  return item;
}

function renderClientList(bar) {
  sideTitle(bar, 'Requests');
  sideItem(bar, {
    label: 'All Clients',
    count: state.sessions.length,
    selected: state.client === null,
    onClick: () => { state.client = null; renderSidebar(); renderRows(); },
  });

  const counts = new Map();
  for (const s of state.sessions) {
    const c = clientOf(s);
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  if (!counts.size) return;
  sideTitle(bar, 'Clients');
  for (const name of [...counts.keys()].sort()) {
    sideItem(bar, {
      label: name,
      count: counts.get(name),
      dot: true,
      selected: state.client === name,
      onClick: () => { state.client = name; renderSidebar(); renderRows(); },
    });
  }
}

function renderGroupList(bar) {
  sideTitle(bar, 'Rule Groups');
  sideItem(bar, {
    label: 'Default',
    selected: state.group === 'default',
    onClick: () => selectGroup('default'),
  });
  for (const g of state.groups.filter((g) => g.name !== 'default')) {
    const item = sideItem(bar, {
      label: g.name,
      count: g.rules,
      dot: true,
      dotClass: g.enabled ? 'on' : '',
      extraClass: g.enabled ? '' : 'off',
      selected: state.group === g.name,
      onClick: () => selectGroup(g.name),
    });
    item.title = g.enabled ? 'Enabled — double-click to disable' : 'Disabled — double-click to enable';
    item.addEventListener('dblclick', (e) => { e.preventDefault(); toggleGroup(g.name); });
  }
  const add = el('div', 'side-add');
  add.textContent = '+ New group';
  add.addEventListener('click', addGroup);
  bar.appendChild(add);
}

function renderValueList(bar) {
  const names = Object.keys(state.values).sort();
  sideTitle(bar, 'Values');
  if (!names.length) {
    const empty = el('div', 'side-item');
    empty.innerHTML = '<span class="side-name muted">none defined</span>';
    bar.appendChild(empty);
    return;
  }
  for (const name of names) {
    sideItem(bar, {
      label: name,
      count: String(state.values[name]).length,
      onClick: () => {
        const ta = $('values-editor');
        const at = ta.value.indexOf('"' + name + '"');
        if (at >= 0) { ta.focus(); ta.setSelectionRange(at, at + name.length + 2); }
      },
    });
  }
}

// ── detail panel ───────────────────────────────────────────────────────────

const DETAIL_TABS = [
  { key: 'general', label: 'General' },
  { key: 'req-head', label: 'Request Header' },
  { key: 'res-head', label: 'Response Header' },
  { key: 'req-body', label: 'Request Body' },
  { key: 'res-body', label: 'Response Body' },
  { key: 'frames', label: 'Frames' },
];

function currentSession() {
  return state.sessions.find((s) => s.id === state.selected) || null;
}

function tabEnabled(key, s, d) {
  if (!s) return false;
  switch (key) {
    case 'req-head': return !!(d && d.req_headers && d.req_headers.length);
    case 'res-head': return !!(d && d.res_headers && d.res_headers.length);
    case 'req-body': return !!(d && d.req_body && d.req_body.len);
    case 'res-body': return !!(d && d.res_body && d.res_body.len);
    case 'frames': return s.status === 101;
    default: return true;
  }
}

function renderDetail() {
  const s = currentSession();
  const d = state.detail;

  $('d-title').textContent = s ? (s.method + ' ' + hostOf(s.url)) : 'No request selected';
  $('d-url').textContent = s ? s.url : 'Pick a row above to inspect it.';
  const badge = $('d-badge');
  if (s) {
    badge.hidden = false;
    badge.textContent = s.status === 101 ? 'WebSocket' : (s.status >= 400 ? 'Failed' : 'Completed');
    badge.className = 'badge ' + (s.status >= 400 ? 'bad' : 'ok');
  } else {
    badge.hidden = true;
  }

  $('d-tabs').innerHTML = DETAIL_TABS.map((t) => {
    const on = tabEnabled(t.key, s, d);
    const sel = state.detailTab === t.key && on ? ' aria-selected="true"' : '';
    return '<button data-tab="' + t.key + '"' + sel + (on ? '' : ' disabled') + '>' + t.label + '</button>';
  }).join('');

  const body = $('d-body');
  if (!s) { body.innerHTML = '<div class="empty">Nothing selected</div>'; return; }
  if (!tabEnabled(state.detailTab, s, d)) state.detailTab = 'general';

  switch (state.detailTab) {
    case 'general': body.innerHTML = generalCards(s, d); break;
    case 'req-head': body.innerHTML = headerList(d.req_headers); break;
    case 'res-head': body.innerHTML = headerList(d.res_headers); break;
    case 'req-body': body.innerHTML = bodyDump(d.req_body); break;
    case 'res-body': body.innerHTML = bodyDump(d.res_body); break;
    case 'frames': body.innerHTML = '<div class="empty">loading frames…</div>'; loadFrames(s.id); break;
  }
}

function hostOf(url) {
  const m = /^[a-z]+:\/\/([^/?]+)/i.exec(url || '');
  return m ? m[1] : (url || '');
}

function card(title, pairs) {
  const rows = pairs
    .filter((p) => p[1] !== undefined && p[1] !== null && p[1] !== '')
    .map((p) => '<dt>' + esc(p[0]) + '</dt><dd>' + esc(p[1]) + '</dd>').join('');
  if (!rows) return '';
  return '<div class="card"><h3>' + esc(title) + '</h3><dl>' + rows + '</dl></div>';
}

function generalCards(s, d) {
  const cards = [
    card('HTTP', [['Method', s.method], ['Status', s.status || '—']]),
    card('Policy', [['Target', s.target], ['Rules', (s.log || []).join(', ')]]),
    card('Traffic', [['Upload', fmtBytes(s.up)], ['Download', fmtBytes(s.down)]]),
    card('Timing', [['Duration', s.duration_ms + ' ms'], ['Start', fmtDateTime(s.time_ms)]]),
    card('Client', [['Address', s.client_ip || 'unknown']]),
  ].join('');
  return '<div class="cards">' + cards + '</div>'
    + (d ? '' : '<p class="hint">loading headers…</p>');
}

function headerList(pairs) {
  if (!pairs || !pairs.length) return '<div class="empty">no headers captured</div>';
  return '<dl class="kv">' + pairs
    .map((p) => '<dt>' + esc(p[0]) + '</dt><dd>' + esc(p[1]) + '</dd>').join('') + '</dl>';
}

function bodyDump(b) {
  if (!b || !b.len) return '<div class="empty">no body captured</div>';
  const note = b.len + ' bytes' + (b.truncated ? ', preview truncated' : '');
  return '<p class="hint">' + esc(note) + '</p><pre class="dump">' + esc(b.text) + '</pre>';
}

function loadFrames(id) {
  fetch('/frames.json?id=' + id).then((r) => r.json()).then((list) => {
    if (state.selected !== id || state.detailTab !== 'frames') return;
    if (!list.length) { $('d-body').innerHTML = '<div class="empty">no frames captured yet</div>'; return; }
    $('d-body').innerHTML = '<div class="frames">' + list.slice().reverse().map((f) => {
      const cls = 'frame ' + f.dir + (f.ignored ? ' ignored' : '');
      const dir = f.dir === 'send' ? '▲ send' : '▼ recv';
      return '<div class="' + cls + '"><span class="dir">' + dir + '</span>'
        + '<span class="op">' + esc(f.opcode) + '</span>'
        + '<span class="len">' + f.len + ' B</span>'
        + '<span class="pv">' + esc(f.preview) + '</span></div>';
    }).join('') + '</div>';
  });
}

function selectRow(id) {
  state.selected = id;
  state.detail = null;
  renderRows();
  renderDetail();
  fetch('/session.json?id=' + id).then((r) => r.json()).then((d) => {
    if (state.selected !== id) return;
    state.detail = d;
    renderDetail();
  });
}

// ── data loading ───────────────────────────────────────────────────────────

function loadSessions() {
  return fetch('/sessions.json').then((r) => r.json()).then((list) => {
    state.sessions = list;
    if (state.client && !list.some((s) => clientOf(s) === state.client)) state.client = null;
    renderSidebar();
    renderRows();
    if (state.selected !== null && !list.some((s) => s.id === state.selected)) {
      state.selected = null;
      state.detail = null;
      renderDetail();
    }
  });
}

function loadRules() {
  return fetch('/api/rule-groups').then((r) => r.json()).then((groups) => {
    state.groups = groups;
    renderSidebar();
    return selectGroup(state.group, true);
  });
}

function selectGroup(name, keepStatus) {
  state.group = name;
  renderSidebar();
  if (!keepStatus) $('rules-status').textContent = '';
  const url = name === 'default' ? '/api/rules' : '/api/rule-group?name=' + encodeURIComponent(name);
  return fetch(url)
    .then((r) => (name === 'default' ? r.text() : r.json().then((g) => g.text || '')))
    .then((text) => { $('rules-editor').value = text; });
}

function saveRules() {
  const text = $('rules-editor').value;
  const status = $('rules-status');
  const done = (msg) => { status.textContent = msg; };
  if (state.group === 'default') {
    fetch('/api/rules', { method: 'POST', body: text })
      .then((r) => r.json())
      .then((j) => { done('Saved · ' + j.rules + ' rules active'); })
      .catch(() => done('Save failed'));
    return;
  }
  postJson('/api/rule-group/update', { name: state.group, text })
    .then((j) => { done(j.ok ? 'Saved' : (j.error || 'Save failed')); loadRules(); })
    .catch(() => done('Save failed'));
}

function addGroup() {
  const name = prompt('Group name:');
  if (!name || !name.trim()) return;
  postJson('/api/rule-groups', { name: name.trim(), text: '', enabled: true })
    .then((j) => { if (j.ok) { state.group = name.trim(); loadRules(); } else alert(j.error || 'Failed'); });
}

function toggleGroup(name) {
  postJson('/api/rule-group/toggle', { name }).then(() => loadRules());
}

function deleteGroup(name) {
  if (!confirm('Delete group "' + name + '"?')) return;
  postJson('/api/rule-group', { name }, 'DELETE').then((j) => {
    if (!j.ok) return alert(j.error || 'Failed');
    if (state.group === name) state.group = 'default';
    loadRules();
  });
}

function loadValues() {
  return fetch('/api/values').then((r) => r.json()).then((v) => {
    state.values = v || {};
    $('values-editor').value = JSON.stringify(state.values, null, 2);
    renderSidebar();
  });
}

function saveValues() {
  const text = $('values-editor').value;
  const status = $('values-status');
  try { JSON.parse(text); } catch (e) { status.textContent = 'Invalid JSON: ' + e.message; return; }
  fetch('/api/values', { method: 'POST', body: text })
    .then((r) => r.json())
    .then(() => { status.textContent = 'Saved'; loadValues(); })
    .catch(() => { status.textContent = 'Save failed'; });
}

function postJson(url, obj, method) {
  return fetch(url, {
    method: method || 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  }).then((r) => r.json());
}

// ── panes ──────────────────────────────────────────────────────────────────

function showPane(name) {
  state.pane = name;
  for (const btn of $('nav').children) {
    btn.setAttribute('aria-selected', String(btn.dataset.pane === name));
  }
  for (const key of ['requests', 'rules', 'values']) {
    $('pane-' + key).hidden = key !== name;
  }
  // The whole control, not just the input: the magnifier is a pseudo-element
  // on the wrapper and would otherwise be left floating on its own.
  $('filter').parentElement.style.visibility = name === 'requests' ? '' : 'hidden';
  renderSidebar();
  if (name === 'rules') loadRules();
  if (name === 'values') loadValues();
}

// ── wiring ─────────────────────────────────────────────────────────────────

function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  try { localStorage.setItem('whistle-rs-theme', mode); } catch (e) { /* private mode */ }
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('whistle-rs-theme'); } catch (e) { /* private mode */ }
  const dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(saved || (dark ? 'dark' : 'light'));
}

function init() {
  initTheme();
  renderHead();
  renderDetail();

  $('nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-pane]');
    if (btn) showPane(btn.dataset.pane);
  });

  $('theme').addEventListener('click', () => {
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });

  $('head').addEventListener('click', (e) => {
    const th = e.target.closest('th[data-key]');
    if (!th) return;
    const key = th.dataset.key;
    state.sort = state.sort.key === key
      ? { key, dir: state.sort.dir === 'asc' ? 'desc' : 'asc' }
      : { key, dir: key === 'id' || key === 'time_ms' ? 'desc' : 'asc' };
    renderHead();
    renderRows();
  });

  $('rows').addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-id]');
    if (tr) selectRow(Number(tr.dataset.id));
  });

  $('d-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (btn && !btn.disabled) { state.detailTab = btn.dataset.tab; renderDetail(); }
  });

  $('filter').addEventListener('input', renderRows);
  $('reload').addEventListener('click', loadSessions);
  $('clear').addEventListener('click', () => {
    if (!confirm('Clear all captured sessions?')) return;
    fetch('/api/sessions/clear', { method: 'POST' }).then(() => {
      state.selected = null;
      state.detail = null;
      loadSessions();
    });
  });
  $('replay').addEventListener('click', () => {
    if (state.selected === null) return;
    postJson('/api/replay', { id: state.selected }).then(() => setTimeout(loadSessions, 400));
  });

  $('rules-save').addEventListener('click', saveRules);
  $('values-save').addEventListener('click', saveValues);

  // Delete the selected group with the keyboard, since the source list has no
  // room for a per-row button without crowding the name.
  document.addEventListener('keydown', (e) => {
    if (state.pane !== 'rules' || state.group === 'default') return;
    if (e.key !== 'Backspace' && e.key !== 'Delete') return;
    if (/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
    e.preventDefault();
    deleteGroup(state.group);
  });

  loadSessions();
  setInterval(() => {
    if (state.pane === 'requests' && $('auto').checked) loadSessions();
  }, 2000);
}

init();
