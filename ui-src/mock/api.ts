// A mock of the proxy's API, for `npm run dev`.
//
// The console is served by the proxy it inspects, so the only way to develop it
// against the real thing is to have traffic flowing through a running proxy.
// This stands in: the same routes, the same shapes (see `src/proxy/webui.rs`),
// enough variety in the fixture to exercise every branch the UI has — a
// failure, a timeout with status 0, a WebSocket with frames, a truncated body,
// a body that is not JSON, a client with a single request, a disabled rule
// group, a plugin that has never answered.
//
// It is dev-only: `apply: 'serve'` keeps it out of the build.

import type { Plugin } from 'vite';
import type { IncomingMessage, ServerResponse } from 'node:http';

interface MockRule {
  protocol: string;
  value: string;
  raw: string;
}

/**
 * A captured body. `binary` says `text` is a `[binary, N bytes]` marker, and
 * `base64` carries what `/body.bin` would hand over for it — the mock's stand-in
 * for the bytes the proxy keeps in its capture.
 */
interface MockBody {
  len: number;
  truncated: boolean;
  text: string;
  binary: boolean;
  base64?: string;
}

interface MockSession {
  id: number;
  time_ms: number;
  method: string;
  url: string;
  status: number;
  client_ip: string | null;
  target: string;
  duration_ms: number;
  log?: string[];
  rules?: MockRule[];
  req_headers: [string, string][];
  res_headers: [string, string][];
  req_body?: MockBody;
  res_body?: MockBody;
  /**
   * Where the time went. Optional and each phase optional in turn, because that
   * is how the proxy sends it — a missing phase did not happen. The fixture
   * covers all three shapes on purpose: a TLS request with every phase, a plain
   * one with no `ssl`, and a mocked one with no phases at all.
   */
  timings?: {
    dns?: number;
    connect?: number;
    ssl?: number;
    wait?: number;
    receive?: number;
  };
}

/** A text body, which is what most of the fixture is. */
const text = (s: string, truncated = false, len = s.length): MockBody => ({
  len,
  truncated,
  text: s,
  binary: false,
});

/** A body the proxy judged non-textual: a marker, and the bytes behind it. */
const binary = (base64: string, truncated = false): MockBody => {
  const len = Buffer.from(base64, 'base64').length;
  return { len, truncated, text: `[binary, ${len} bytes]`, binary: true, base64 };
};

/** A 32×32 checkerboard PNG — small enough to inline, big enough to look at. */
const PNG_32 =
  'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAOUlEQVR42mN44GGHFenn38aKSFXPMGr' +
  'BqAVDwAJqGYRL/agFoxYMBQtGi4pRC0YtGK0PRi0YtQCIAOJfvkzE9IskAAAAAElFTkSuQmCC';

/** `protocol://value` split the way the proxy records it, plus what was typed. */
const rule = (spelled: string, raw = spelled): MockRule => {
  const at = spelled.indexOf('://');
  return { protocol: spelled.slice(0, at), value: spelled.slice(at + 3), raw };
};

const now = Date.now();

const JSON_RES = JSON.stringify(
  { ok: true, items: [{ id: 1, name: 'first' }, { id: 2, name: 'second' }], page: 1 },
  null,
  0,
);

function session(over: Partial<MockSession> & { id: number }): MockSession {
  return {
    time_ms: now - over.id * 4200,
    method: 'GET',
    url: 'https://example.com/',
    status: 200,
    client_ip: '192.168.1.24',
    target: 'example.com:443',
    duration_ms: 42,
    req_headers: [
      ['host', 'example.com'],
      ['user-agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'],
      ['accept', '*/*'],
    ],
    res_headers: [
      ['content-type', 'application/json; charset=utf-8'],
      ['server', 'nginx/1.25.3'],
      ['content-length', String(JSON_RES.length)],
    ],
    res_body: text(JSON_RES),
    timings: { dns: 3.2, connect: 11.4, ssl: 28.7, wait: 42.1, receive: 1.8 },
    ...over,
  };
}

const FIXTURE: MockSession[] = [
  session({ id: 1, url: 'https://example.com/api/items?page=1' }),
  session({
    id: 2,
    method: 'POST',
    url: 'https://example.com/api/items',
    status: 201,
    target: '127.0.0.1:5173 (http://localhost:5173)',
    log: ['api', 'write'],
    // Every shape the Rules tab has to render: a shorthand whose raw token
    // does not spell its protocol, a `$1` already filled in, a `${name}`
    // already substituted, and one written out in full.
    rules: [
      rule('host://127.0.0.1', '127.0.0.1'),
      rule('reqHeaders://X-Tenant=acme', 'reqHeaders://X-Tenant=$1'),
      rule('resBody://{"ok":true,"from":"values"}', 'resBody://{mock.json}'),
      rule('log://api'),
      rule('log://write'),
    ],
    req_headers: [
      ['host', 'example.com'],
      ['content-type', 'application/json'],
      ['content-length', '38'],
      ['x-tenant', 'acme'],
    ],
    req_body: text('{"name":"third","tags":["a","b"]}', false, 38),
    // Answered by its own `resBody://`, so no connection was ever opened and
    // there are no phases — the waterfall has to say that rather than draw an
    // empty bar.
    timings: undefined,
  }),
  session({
    id: 3,
    url: 'https://cdn.example.com/app.a91f.js',
    target: 'cdn.example.com:443',
    duration_ms: 310,
    res_headers: [
      ['content-type', 'application/javascript'],
      ['content-encoding', 'gzip'],
      ['server', 'cloudfront'],
    ],
    res_body: text(
      '(function(){"use strict";var t=document.createElement("div");t.id="app";',
      true,
      262144,
    ),
  }),
  session({ id: 4, url: 'https://example.com/favicon.ico', status: 404, duration_ms: 12 }),
  session({
    id: 5,
    url: 'https://api.example.com/v2/session',
    status: 500,
    client_ip: '127.0.0.1',
    target: 'api.example.com:443',
    duration_ms: 1204,
    log: ['errors'],
    // A request whose only matched operator is one that fired in the response
    // phase — the case where reading `Resolved` too early would report nothing.
    rules: [rule('log://errors'), rule('resDelay://800')],
    res_headers: [['content-type', 'text/html']],
    res_body: text('<html><body><h1>500 Internal Server Error</h1></body></html>', false, 92),
  }),
  session({
    id: 6,
    url: 'https://unreachable.example.net/ping',
    status: 0,
    target: 'unreachable.example.net:443',
    duration_ms: 30000,
    res_headers: [],
    res_body: undefined,
    // Resolved, then nothing: the connect never completed, so only `dns` exists.
    timings: { dns: 8.4 },
  }),
  session({
    id: 7,
    url: 'wss://live.example.com/socket',
    status: 101,
    client_ip: '10.0.0.7',
    target: 'live.example.com:443',
    duration_ms: 5,
    res_headers: [
      ['upgrade', 'websocket'],
      ['connection', 'Upgrade'],
    ],
    res_body: undefined,
  }),
  session({
    id: 8,
    url: 'http://localhost:5173/@vite/client',
    status: 200,
    client_ip: '127.0.0.1',
    target: 'localhost:5173',
    duration_ms: 3,
    res_headers: [['content-type', 'text/javascript']],
    res_body: text('import { createHotContext } from "/@vite";', false, 41),
    // Plain HTTP: every phase but `ssl`.
    timings: { dns: 0.1, connect: 0.4, wait: 2.1, receive: 0.3 },
  }),
  session({
    id: 9,
    method: 'OPTIONS',
    url: 'https://api.example.com/v2/items',
    status: 204,
    client_ip: '10.0.0.7',
    duration_ms: 8,
    res_headers: [['access-control-allow-origin', '*']],
    res_body: undefined,
  }),
  session({
    id: 10,
    url: 'https://example.com/very/long/path/that/keeps/going/and/going/so/the/url/column/has/something/to/ellipsize?with=a&query=string&and=more',
    status: 301,
    duration_ms: 19,
    res_headers: [['location', 'https://example.com/short']],
    res_body: undefined,
  }),
  // An image, so the body panel's image preview, hex view and download have
  // something real to work on without a proxy in front of them.
  session({
    id: 11,
    url: 'https://cdn.example.com/assets/check.png',
    target: 'cdn.example.com:443',
    duration_ms: 27,
    res_headers: [
      ['content-type', 'image/png'],
      ['cache-control', 'max-age=31536000'],
    ],
    res_body: binary(PNG_32),
  }),
  // And a binary body that is *not* an image, and is truncated as well: the
  // hex view has to cope with both, and the download must not claim to be whole.
  session({
    id: 12,
    url: 'https://cdn.example.com/fonts/inter.woff2',
    target: 'cdn.example.com:443',
    duration_ms: 88,
    res_headers: [['content-type', 'font/woff2']],
    res_body: { ...binary(PNG_32, true), len: 74216 },
  }),
];

// One of everything the list has to render: both directions, a control frame,
// one dropped by `enable://ignoreSend`, and two still held by
// `enable://pauseSend` — which is the state the release control exists for.
const FRAMES = [
  { dir: 'send', opcode: 'text', preview: '{"type":"subscribe","channel":"ticks"}', ignored: false, held: false },
  { dir: 'receive', opcode: 'text', preview: '{"type":"ack","channel":"ticks"}', ignored: false, held: false },
  { dir: 'receive', opcode: 'text', preview: '{"tick":1,"price":100.25}', ignored: false, held: false },
  { dir: 'send', opcode: 'ping', preview: '', ignored: false, held: false },
  { dir: 'receive', opcode: 'pong', preview: '', ignored: false, held: false },
  { dir: 'receive', opcode: 'text', preview: '{"tick":2,"price":100.31}', ignored: true, held: false },
  { dir: 'send', opcode: 'text', preview: '{"type":"order","side":"buy"}', ignored: false, held: true },
  { dir: 'send', opcode: 'text', preview: '{"type":"order","side":"sell"}', ignored: false, held: true },
].map((f, i) => ({
  session: 7,
  time_ms: now - (8 - i) * 900,
  len: f.preview.length,
  ...f,
}));

/** Session 7's send direction starts held, so the control has something to do. */
const wsPause = { live: true, send: { paused: true }, receive: { paused: false } };

const RULES_DEFAULT = `# The default group.
example.com http://localhost:5173
http://a.com/api host://1.1.1.1
^*.example.com/v0/** file:///mock/$1
*.example.com/api reqHeaders://X-Tenant=$1
host://9.9.9.9 a.com b.com c.com
a.com host://1.1.1.1 includeFilter://m:GET lineProps://important
host://x proxy://y
:8080 host://1.1.1.1
/^https?:\\/\\/w+\\.example\\.com/i resBody://{mock.json}
`;

interface Group {
  name: string;
  enabled: boolean;
  text: string;
}

/**
 * What two pages under `log://` rules wrote: every level, an argument that is
 * JSON, an uncaught error with its several lines, and a second id.
 */
const PAGE_LOGS = [
  { level: 'log', id: 'shop', args: ['cart loaded', '{"items":2,"total":59.8}'] },
  { level: 'info', id: 'shop', args: ['user', 'u_1024'] },
  { level: 'warn', id: 'shop', args: ['price missing for sku', 'A-77'] },
  {
    level: 'error',
    id: 'shop',
    args: [
      'TypeError: Cannot read properties of undefined (reading \'price\')\n    at total (cart.js:41:18)\n    at render (cart.js:88:5)\nPage URL: https://shop.example.com/cart\nUser Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
    ],
  },
  { level: 'debug', id: 'news', args: ['feed poll', '200', '18ms'] },
  { level: 'error', id: 'news', args: ['Failed to load <img> https://news.example.com/hero.webp'] },
].map((log, i) => ({
  ...log,
  seq: i + 1,
  time_ms: Date.now() - (6 - i) * 1500,
  page: log.id === 'shop' ? 'https://shop.example.com/cart' : 'https://news.example.com/',
  client_ip: '192.168.1.23',
}));

// ── mutable state ──────────────────────────────────────────────────────────

let pageLogs = PAGE_LOGS.slice();
let sessions = FIXTURE.slice();
let nextId = 100;
let rules = RULES_DEFAULT;
const groups: Group[] = [
  { name: 'staging', enabled: true, text: 'api.example.com host://10.0.0.9\n' },
  { name: 'archive', enabled: false, text: '# kept, not applied\nold.example.com http://localhost:9\n' },
];
let values: Record<string, string> = {
  'mock.json': '{"ok":true,"from":"values"}',
  'greeting.txt': 'hello from a value',
};

/** As many rules as non-blank, non-comment lines — close enough for a mock. */
const ruleCount = (text: string) =>
  text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length;

const summary = (s: MockSession) => ({
  id: s.id,
  time_ms: s.time_ms,
  method: s.method,
  url: s.url,
  status: s.status,
  client_ip: s.client_ip,
  target: s.target,
  duration_ms: s.duration_ms,
  ...(s.log?.length ? { log: s.log } : {}),
  ...(s.rules?.length ? { rules: s.rules } : {}),
  up: s.req_body?.len ?? 0,
  down: s.res_body?.len ?? 0,
  has_req_body: !!s.req_body?.len,
  has_res_body: !!s.res_body?.len,
});

/**
 * The Rust side skips empty collections; the UI has to cope, so the mock does
 * too. `base64` is dropped here for the same reason the proxy never puts bytes
 * in `/session.json`: they are fetched from `/body.bin`, by the one panel that
 * wants them.
 */
const detail = (s: MockSession) => {
  const capture = (b: MockBody | undefined) =>
    b && { len: b.len, truncated: b.truncated, text: b.text, binary: b.binary };
  return {
    ...summary(s),
    ...(s.req_headers.length ? { req_headers: s.req_headers } : {}),
    ...(s.res_headers.length ? { res_headers: s.res_headers } : {}),
    ...(s.req_body ? { req_body: capture(s.req_body) } : {}),
    ...(s.res_body ? { res_body: capture(s.res_body) } : {}),
  };
};

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => resolve(buf));
  });
}

function send(res: ServerResponse, body: unknown, type = 'application/json', status = 200): void {
  const text = type === 'application/json' ? JSON.stringify(body) : String(body);
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.end(text);
}

export function mockApi(): Plugin {
  const middleware = async (
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ) => {
    const url = new URL(req.url || '/', 'http://localhost');
    const path = url.pathname;
    const id = Number(url.searchParams.get('id'));
    const method = req.method || 'GET';

    // Slow the answers down a touch: a detail panel that fills
    // instantly hides the loading states it is supposed to have.
    const reply = (body: unknown, type?: string, status?: number) =>
      setTimeout(() => send(res, body, type, status), 60);

    switch (path) {
      case '/sessions.json':
        // Newest first, as the proxy answers.
        return reply(sessions.slice().reverse().map(summary));
      case '/session.json': {
        const s = sessions.find((x) => x.id === id);
        return reply(s ? detail(s) : null);
      }
      case '/body.bin': {
        // The bytes of one body, as `session_body_bytes` serves them: always an
        // attachment, always `nosniff`, and named `partial-` when the preview
        // was capped.
        const s = sessions.find((x) => x.id === id);
        const side = url.searchParams.get('side') === 'req' ? 'req' : 'res';
        const captured = side === 'req' ? s?.req_body : s?.res_body;
        if (!s || !captured) {
          res.statusCode = 404;
          return res.end('not found');
        }
        const bytes = captured.base64
          ? Buffer.from(captured.base64, 'base64')
          : Buffer.from(captured.text);
        const headers = side === 'req' ? s.req_headers : s.res_headers;
        const type = headers.find((h) => h[0] === 'content-type')?.[1] || 'application/octet-stream';
        const tail = s.url.split(/[?#]/)[0].split('/').pop() || `session-${s.id}-${side}.bin`;
        res.setHeader('Content-Type', type);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="${captured.truncated ? 'partial-' : ''}${tail}"`,
        );
        return setTimeout(() => res.end(bytes), 60);
      }
      case '/frames.json':
        return reply(FRAMES.filter((f) => f.session === id).slice().reverse());
      case '/api/ws/status': {
        // Only a live, paused session is in the proxy's registry; everything
        // else answers `live: false` rather than failing, because this is what
        // the Frames tab polls.
        const held = (dir: string) => FRAMES.filter((f) => f.dir === dir && f.held).length;
        if (id !== 7) {
          return reply({
            live: false,
            send: { paused: false, held: 0 },
            receive: { paused: false, held: 0 },
          });
        }
        return reply({
          live: true,
          send: { paused: wsPause.send.paused, held: held('send') },
          receive: { paused: wsPause.receive.paused, held: held('receive') },
        });
      }
      case '/api/ws/release': {
        const { id: want, dir } = JSON.parse((await readBody(req)) || '{}');
        if (want !== 7 || (dir !== 'send' && dir !== 'receive')) {
          return reply({ ok: false, error: 'no live paused WebSocket session with that id' });
        }
        const freed = FRAMES.filter((f) => f.dir === dir && f.held);
        freed.forEach((f) => (f.held = false));
        wsPause[dir as 'send' | 'receive'].paused = false;
        return reply({ ok: true, released: freed.length });
      }
      case '/sessions.har': {
        // `?ids=` exports only those sessions — what the table's multi-select
        // asks for. Without it, everything.
        const only = url.searchParams.get('ids')?.split(',').map(Number);
        const picked = only ? sessions.filter((s) => only.includes(s.id)) : sessions;
        return reply({
          log: {
            version: '1.2',
            creator: { name: 'whistle-rs-mock' },
            entries: picked.map((s) => ({ request: { url: s.url }, response: { status: s.status } })),
          },
        });
      }
      case '/api/composer': {
        const c = JSON.parse((await readBody(req)) || '{}');
        const typed = String(c.url || '').trim();
        if (!typed) return reply({ ok: false, error: 'a URL is required' }, undefined, 400);
        // The proxy fills in a missing scheme and refuses a header line that is
        // not one; both are visible in the console, so the mock does them too.
        const url = typed.includes('://') ? typed : `http://${typed}`;
        const lines = String(c.headers || '')
          .split('\n')
          .map((l: string) => l.trim())
          .filter(Boolean);
        const bad = lines.find((l: string) => !l.includes(':'));
        if (bad) return reply({ ok: false, error: `not a header: ${bad}` }, undefined, 400);
        const body = String(c.body || '');
        const composed: MockSession = {
          ...session({ id: nextId++ }),
          time_ms: Date.now(),
          method: String(c.method || 'GET').trim().toUpperCase() || 'GET',
          url,
          client_ip: '127.0.0.1',
          target: url.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, ''),
          req_headers: lines.map((l: string): [string, string] => {
            const at = l.indexOf(':');
            return [l.slice(0, at).trim().toLowerCase(), l.slice(at + 1).trim()];
          }),
          // Typed by hand rather than shared, so a composition's body is always
          // the text that was typed into the box — never binary.
          ...(body
            ? { req_body: { len: body.length, truncated: false, text: body, binary: false } }
            : {}),
        };
        sessions.push(composed);
        return reply({ ok: true, url, sent: body.length });
      }
      case '/api/sessions/clear': {
        const { ids } = JSON.parse((await readBody(req)) || '{}');
        sessions = ids ? sessions.filter((s) => !ids.includes(s.id)) : [];
        return reply({ ok: true });
      }
      case '/api/sessions/purge': {
        await readBody(req);
        sessions = [];
        return reply({ ok: true, files_deleted: 2 });
      }
      case '/api/logs': {
        // The Console pane's cursor: only what is newer than `after`.
        const after = Number(url.searchParams.get('after')) || 0;
        return reply({
          ok: true,
          logs: pageLogs.filter((l) => l.seq > after),
          ids: [...new Set(pageLogs.map((l) => l.id))].sort(),
          last: PAGE_LOGS.length,
        });
      }
      case '/api/logs/clear': {
        const { id } = JSON.parse((await readBody(req)) || '{}');
        const before = pageLogs.length;
        pageLogs = id === undefined ? [] : pageLogs.filter((l) => l.id !== id);
        return reply({ ok: true, cleared: before - pageLogs.length });
      }
      case '/api/replay': {
        const body = JSON.parse((await readBody(req)) || '{}');
        const want: number[] = body.ids ?? (body.id === undefined ? [] : [body.id]);
        const picked = want
          .map((id) => sessions.find((x) => x.id === id))
          .filter((s): s is MockSession => !!s);
        // The proxy replays from the capture, which is decoded and capped, so
        // it reports what each replay will actually carry — see `ReplayResult`.
        const report = picked.map((src) => {
          const kind = !src.req_body ? 'empty' : src.req_body.truncated ? 'partial' : 'whole';
          return {
            id: src.id,
            body: kind,
            sent: kind === 'empty' ? 0 : src.req_body!.text.length,
            captured: src.req_body?.len ?? 0,
          };
        });
        for (const src of picked) {
          sessions.push({ ...src, id: nextId++, time_ms: Date.now(), target: src.target });
        }
        return reply({ replayed: picked.length, sessions: report });
      }
      case '/api/rules':
        if (method === 'POST') {
          rules = await readBody(req);
          return reply({ ok: true, rules: ruleCount(rules) });
        }
        return reply(rules, 'text/plain');
      case '/api/export':
        // Everything the console can edit, in the shape `bundle_of` writes it.
        return reply({
          whistle_rs: '0.1.0-mock',
          rules: [
            { name: 'default', enabled: true, text: rules },
            ...groups.map((g) => ({ name: g.name, enabled: g.enabled, text: g.text })),
          ],
          values,
        });
      case '/api/import': {
        const bundle = JSON.parse((await readBody(req)) || '{}');
        if (!('whistle_rs' in bundle)) {
          return reply({ ok: false, error: 'not an exported bundle' });
        }
        let count = 0;
        for (const g of bundle.rules || []) {
          if (!g.name?.trim()) continue;
          count++;
          if (g.name === 'default') {
            rules = g.text || '';
            continue;
          }
          // Updated where it stands: group order is precedence, as in `webui.rs`.
          const at = groups.findIndex((x) => x.name === g.name);
          if (at < 0) groups.push({ name: g.name, enabled: g.enabled !== false, text: g.text || '' });
          else groups[at] = { name: g.name, enabled: g.enabled !== false, text: g.text || '' };
        }
        const named = Object.entries(bundle.values || {});
        for (const [name, value] of named) values[name] = String(value);
        return reply({ ok: true, groups: count, values: named.length });
      }
      case '/api/rule-groups': {
        if (method === 'POST') {
          const g = JSON.parse((await readBody(req)) || '{}');
          if (groups.some((x) => x.name === g.name)) {
            return reply({ ok: false, error: 'group already exists' });
          }
          groups.push({ name: g.name, enabled: g.enabled !== false, text: g.text || '' });
          return reply({ ok: true });
        }
        return reply([
          { name: 'default', enabled: true, rules: ruleCount(rules) },
          ...groups.map((g) => ({ name: g.name, enabled: g.enabled, rules: ruleCount(g.text) })),
        ]);
      }
      case '/api/rule-group': {
        if (method === 'DELETE') {
          const { name } = JSON.parse((await readBody(req)) || '{}');
          const at = groups.findIndex((g) => g.name === name);
          if (at < 0) return reply({ ok: false, error: 'group not found' });
          groups.splice(at, 1);
          return reply({ ok: true });
        }
        const g = groups.find((x) => x.name === url.searchParams.get('name'));
        if (!g) return reply({ ok: false, error: 'group not found' });
        return reply({ name: g.name, text: g.text, enabled: g.enabled, rules: ruleCount(g.text) });
      }
      case '/api/rule-group/update': {
        const { name, text } = JSON.parse((await readBody(req)) || '{}');
        const g = groups.find((x) => x.name === name);
        if (!g) return reply({ ok: false, error: 'group not found' });
        g.text = text;
        return reply({ ok: true });
      }
      case '/api/rule-group/toggle': {
        const { name } = JSON.parse((await readBody(req)) || '{}');
        const g = groups.find((x) => x.name === name);
        if (!g) return reply({ ok: false, error: 'group not found' });
        g.enabled = !g.enabled;
        return reply({ ok: true, enabled: g.enabled });
      }
      case '/api/values':
        if (method === 'POST') {
          values = JSON.parse((await readBody(req)) || '{}');
          return reply({ ok: true });
        }
        return reply(values);
      case '/api/value': {
        const body = JSON.parse((await readBody(req)) || '{}');
        if (method === 'DELETE') {
          if (!(body.name in values)) return reply({ ok: false, error: 'value not found' });
          delete values[body.name];
          return reply({ ok: true });
        }
        if (!body.name?.trim()) return reply({ ok: false, error: 'name is required' });
        values[body.name.trim()] = body.value ?? '';
        return reply({ ok: true });
      }
      case '/api/value/rename': {
        const { name, to } = JSON.parse((await readBody(req)) || '{}');
        if (!(name in values)) return reply({ ok: false, error: 'value not found' });
        if (name !== to && to in values) {
          return reply({ ok: false, error: 'a value by that name already exists' });
        }
        const content = values[name];
        delete values[name];
        values[to] = content;
        return reply({ ok: true });
      }
      case '/api/status':
        return reply({
          version: '0.1.0-mock',
          port: 8899,
          host: '0.0.0.0',
          socks_port: 1080,
          intercept_https: true,
          capture_locked_off: false,
          header_rules: 'off',
          // Two, because the pane's whole point is "try each if unsure" — one
          // address would not show the layout the real thing has.
          listening_on_lan: true,
          lan_addresses: ['192.168.1.42', '10.0.0.7'],
          insecure_upstream: false,
          storage_dir: '/Users/you/.whistle-rs',
          root_ca: '/Users/you/.whistle-rs/rootCA.crt',
          body_preview_cap: 262144,
          persist_sessions: true,
          persist_days: 7,
          timeout_ms: 30000,
          rules: ruleCount(rules),
          sessions: sessions.length,
          frames: FRAMES.length,
          plugins: [
            { name: 'inspector', hooks: ['request', 'response', 'ws/frames'], remote: null },
            { name: 'remote-auth', hooks: null, remote: 'http://127.0.0.1:9001' },
          ],
        });
      case '/api/qr': {
        // A placeholder, not an encoder. The real one is `src/qr.rs`, checked
        // module for module against `qrcode@1.2.0` by `qr-bench.js`; there is
        // nothing for the console to get right about it beyond asking for the
        // right URL, and a mock that drew a real code would be a second
        // encoder to keep correct.
        const text = url.searchParams.get('text') || '';
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="212" height="212" `
          + `viewBox="0 0 212 212"><rect width="212" height="212" fill="#fff"/>`
          + `<rect x="16" y="16" width="180" height="180" fill="none" stroke="#000" `
          + `stroke-width="2" stroke-dasharray="6 4"/>`
          + `<text x="106" y="100" text-anchor="middle" font-family="monospace" `
          + `font-size="11" fill="#000">QR (mock)</text>`
          + `<text x="106" y="118" text-anchor="middle" font-family="monospace" `
          + `font-size="8" fill="#666">${text.replace(/[<&]/g, '')}</text></svg>`;
        return reply(svg, 'image/svg+xml');
      }
      case '/rootCA.crt':
        return reply('-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n', 'text/plain');
      case '/proxy.pac':
        return reply('function FindProxyForURL(url, host) {\n  return "PROXY 127.0.0.1:8899";\n}\n', 'text/plain');
      default:
        return next();
    }
  };

  return {
    name: 'whistle-mock-api',
    apply: 'serve',
    configureServer: (server) => void server.middlewares.use(middleware),
    // `npm run preview` serves dist/index.html: the same mock, against the
    // artifact that actually ships.
    configurePreviewServer: (server) => void server.middlewares.use(middleware),
  };
}
