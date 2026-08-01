// The proxy's HTTP API, typed.
//
// Shapes follow `src/proxy/webui.rs` — every field here is one the Rust side
// actually emits. Fields the Rust side skips when empty (`skip_serializing_if`)
// are optional here, which is why so many of them are.

/**
 * One operator a rule applied to a request.
 *
 * `raw` is the token as it was typed on the line; `value` is what it resolved
 * to. They differ wherever the rules language does work between the two — a
 * shorthand that names a protocol it does not spell (`1.2.3.4` → `host`), a
 * `${name}` read out of the values store, a `$1` filled in from the pattern.
 */
export interface MatchedRule {
  protocol: string;
  value: string;
  raw: string;
}

/** One row of `/sessions.json`. No headers or bodies — those are per-request. */
export interface SessionSummary {
  id: number;
  /** Unix time in milliseconds when the request was received. */
  time_ms: number;
  method: string;
  url: string;
  status: number;
  client_ip: string | null;
  /** Where the request was sent, or "short-circuit". */
  target: string;
  duration_ms: number;
  /** `log://` channel labels attached to this request — *not* the rules. */
  log?: string[];
  /**
   * Every operator that applied, in resolution order: important lines first,
   * then the order they are written in. Absent when no rule matched, which is
   * the common case and why the Rust side skips the field entirely.
   */
  rules?: MatchedRule[];
  /** Body bytes only; the head is never counted on this port. */
  up: number;
  down: number;
  has_req_body: boolean;
  has_res_body: boolean;
}

/** A captured body preview: `len` is the whole body, `text` only the prefix. */
export interface BodyCapture {
  len: number;
  truncated: boolean;
  text: string;
}

export type HeaderPair = [string, string];

/** `/session.json?id=` — a summary plus what was captured of the exchange. */
export interface SessionDetail extends SessionSummary {
  req_headers?: HeaderPair[];
  res_headers?: HeaderPair[];
  req_body?: BodyCapture;
  res_body?: BodyCapture;
}

export interface WsFrame {
  session: number;
  time_ms: number;
  dir: 'send' | 'receive';
  opcode: string;
  len: number;
  preview: string;
  /** Recorded but never delivered — `enable://ignoreSend|ignoreReceive`. */
  ignored: boolean;
}

export interface RuleGroup {
  name: string;
  enabled: boolean;
  /** How many rules the group parses to, not how many lines it has. */
  rules: number;
}

export interface RuleGroupDetail extends RuleGroup {
  text: string;
}

export interface PluginInfo {
  name: string;
  /** `null` for a remote plugin that has never answered: no manifest yet. */
  hooks: string[] | null;
  remote: string | null;
}

export interface ProxyStatus {
  version: string;
  port: number;
  host: string | null;
  socks_port: number | null;
  intercept_https: boolean;
  insecure_upstream: boolean;
  storage_dir: string;
  root_ca: string;
  body_preview_cap: number;
  persist_sessions: boolean;
  persist_days: number;
  timeout_ms: number;
  rules: number;
  sessions: number;
  frames: number;
  plugins: PluginInfo[];
}

/** What the write endpoints answer with. */
export interface OkResult {
  ok: boolean;
  error?: string;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return (await res.json()) as T;
}

async function postJson<T>(url: string, body: unknown, method = 'POST'): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return (await res.json()) as T;
}

/** POST a raw text body — how `/api/rules` and `/api/values` take their input. */
async function postText<T>(url: string, text: string): Promise<T> {
  const res = await fetch(url, { method: 'POST', body: text });
  return (await res.json()) as T;
}

export const api = {
  sessions: () => getJson<SessionSummary[]>('/sessions.json'),
  session: (id: number) => getJson<SessionDetail | null>(`/session.json?id=${id}`),
  frames: (id: number) => getJson<WsFrame[]>(`/frames.json?id=${id}`),
  clearSessions: () => postJson<OkResult>('/api/sessions/clear', {}),
  replay: (id: number) => postJson<{ replayed: number }>('/api/replay', { id }),

  rules: async () => (await fetch('/api/rules')).text(),
  saveRules: (text: string) => postText<{ ok: boolean; rules: number }>('/api/rules', text),

  ruleGroups: () => getJson<RuleGroup[]>('/api/rule-groups'),
  ruleGroup: (name: string) =>
    getJson<RuleGroupDetail>(`/api/rule-group?name=${encodeURIComponent(name)}`),
  addRuleGroup: (name: string, text = '', enabled = true) =>
    postJson<OkResult>('/api/rule-groups', { name, text, enabled }),
  updateRuleGroup: (name: string, text: string) =>
    postJson<OkResult>('/api/rule-group/update', { name, text }),
  toggleRuleGroup: (name: string) =>
    postJson<OkResult & { enabled?: boolean }>('/api/rule-group/toggle', { name }),
  deleteRuleGroup: (name: string) => postJson<OkResult>('/api/rule-group', { name }, 'DELETE'),

  values: () => getJson<Record<string, string>>('/api/values'),
  saveValues: (json: string) => postText<OkResult>('/api/values', json),

  status: () => getJson<ProxyStatus>('/api/status'),
};
