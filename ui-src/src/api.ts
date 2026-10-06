// The proxy's HTTP API, typed.
//
// Shapes follow `src/proxy/webui/` — every field here is one the Rust side
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
  /**
   * Does this session have frames? A WebSocket always does; an ordinary body
   * does when it was cut into frames — an event stream, or a separator named
   * by `x-whistle-custom-frame-separator`.
   */
  has_frames?: boolean;
  /**
   * Why the request did not complete, when it did not. Absent for every request
   * that got its whole answer — an origin's own 502 included.
   */
  error?: SessionFailure;
  /** The response's `content-type`, for the `t:` filter. */
  type?: string | null;
  /** Sent from the Composer or Replay — what `fc:` asks. Absent otherwise. */
  composer?: true;
  /** The response is still arriving; sizes, body and `error` can change. */
  open?: true;
  /** Operators in `rules` that did not take effect, and why. Absent when all did. */
  unapplied?: Unapplied[];
}

/** Why some matched operators did not take effect — `src/proxy/unapplied.rs`. */
export type UnappliedKind =
  | 'body-over-limit'
  | 'request-body-over-limit'
  | 'event-stream'
  | 'decoded-over-limit'
  | 'undecodable'
  | 'unsupported-coding'
  | 'plugin-failed'
  | 'no-weinre-server'
  | 'cipher-unusable'
  | 'script-failed'
  | 'missing-value';

export interface Unapplied {
  kind: UnappliedKind;
  /** The operators it covers, each the `raw` of an entry in `rules`. */
  ops: string[];
  /** What happened, in words, with the numbers that decided it. */
  reason: string;
}

/** `/api/sessions/search`'s answer to the box's `h:`/`b:` conditions. */
export interface SessionSearch {
  /** How many sessions the proxy held and read. */
  scanned: number;
  results: {
    /** The condition as it was sent, e.g. `b:"success":false`. */
    condition: string;
    ids: number[];
    /** `b:` only: no match, but a body was cut short, so it could be past the cut. */
    partly_kept?: number[];
  }[];
}

/** Where a request stopped, in the order a request meets these steps. */
export type FailurePhase =
  | 'client-tls'
  | 'request'
  | 'rules'
  | 'plugin'
  | 'dns'
  | 'connect'
  | 'proxy'
  | 'tls'
  | 'response'
  | 'client'
  | 'abort'
  | 'internal';

export interface SessionFailure {
  phase: FailurePhase;
  /** The error chain, as the client's 502 carried it. */
  message: string;
}

/** A captured body preview: `len` is the whole body, `text` only the prefix. */
export interface BodyCapture {
  len: number;
  truncated: boolean;
  text: string;
  /**
   * `text` is a `[binary, N bytes]` marker rather than the body.
   *
   * The proxy's verdict, not one re-derived here: it applies the same rule when
   * it decides whether to store the preview as text at all, and two copies of
   * that rule would drift. The bytes themselves come from `/body.bin`.
   */
  binary: boolean;
  /**
   * Undoing the body's `content-encoding` failed part-way, so `text` is what
   * came out before it broke. `truncated` is set too; this says why.
   */
  undecodable: boolean;
}

/** The captured bytes of one body, as `/body.bin` hands them over. */
export interface BodyBytes {
  bytes: Uint8Array;
  /** The Content-Type the proxy recorded, without its parameters. */
  type: string;
  /** What to call the file, as the proxy named it — `partial-` when capped. */
  filename: string;
}

export type HeaderPair = [string, string];

/** `/session.json?id=` — a summary plus what was captured of the exchange. */
/**
 * Where a request's time went, in milliseconds — HAR 1.2's phase names.
 *
 * Every phase is optional and a missing one **did not happen**: a plain
 * connection has no `ssl`, a request answered by a rule has no phases at all,
 * and `receive` is absent while the body is still arriving — which for an event
 * stream is permanent. The proxy deliberately does not send zeros for these, so
 * the console must not turn an absent phase into a zero-width bar.
 *
 * `send` is absent by design and not merely unmeasured: hyper offers no
 * observation point between the last byte written and the first byte read, so
 * its duration is inside `wait`. See `src/proxy/timing.rs`.
 */
export interface Timings {
  dns?: number;
  connect?: number;
  ssl?: number;
  wait?: number;
  receive?: number;
  /** Which origin connection carried the request, numbered per proxy process. */
  connection?: number;
  /** The connection was left open by an earlier request from the same client. */
  reused?: boolean;
}

export interface SessionDetail extends SessionSummary {
  req_headers?: HeaderPair[];
  res_headers?: HeaderPair[];
  req_body?: BodyCapture;
  res_body?: BodyCapture;
  timings?: Timings;
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
  /**
   * Recorded and waiting — `enable://pauseSend|pauseReceive` is holding it
   * until someone releases the direction. Cleared when it goes out, so a frame
   * still marked once the connection ended never reached the peer.
   */
  held: boolean;
}

/** One direction of `/api/ws/status`. */
export interface WsDirPause {
  paused: boolean;
  /** How many frames that direction is holding right now. */
  held: number;
}

/**
 * `/api/ws/status?id=` — whether a live WebSocket session is being held.
 *
 * `live` is false for a session that was never paused and for one that has since
 * closed alike: only a paused, running connection can be released.
 */
export interface WsPauseStatus {
  live: boolean;
  send: WsDirPause;
  receive: WsDirPause;
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
  /** Switched on — `false` when off one by one or all at once. */
  on: boolean;
}

export interface ProxyStatus {
  version: string;
  port: number;
  /** The address actually bound — `127.0.0.1` unless started with `-H`. */
  host: string;
  /** Whether anything but this machine can reach it; phone QR codes need it. */
  listening_on_lan: boolean;
  socks_port: number | null;
  intercept_https: boolean;
  /** A `-M` mode has taken the HTTPS switch away — `multiEnv`, `notAllowedEnableHTTPS`. */
  capture_locked_off: boolean;
  /** Whether a request may carry its own rules: `off`, `enableRequestHeaderRules`, `multiEnv`. */
  header_rules: 'off' | 'enableRequestHeaderRules' | 'multiEnv';
  /** Addresses a device on the same network can reach this proxy at. */
  lan_addresses: string[];
  insecure_upstream: boolean;
  storage_dir: string;
  root_ca: string;
  body_preview_cap: number;
  /** Past this a response body is forwarded unchanged and the body operators do not run. */
  body_rewrite_cap: number;
  persist_sessions: boolean;
  persist_days: number;
  /** The history on disk is cut back to this, oldest first. */
  persist_max_bytes: number;
  timeout_ms: number;
  rules: number;
  sessions: number;
  frames: number;
  plugins: PluginInfo[];
}

/** A question for Test Rules. */
export interface ExplainQuery {
  rules: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** The response head, when the question is about the response phase. */
  response?: { status: number; headers?: Record<string, string> };
}

/** One operator a rules text produced for a request. */
export interface ExplainOp {
  protocol: string;
  value: string;
  raw: string;
  pattern: string;
  /** True when the value *is* content rather than a location. */
  content: boolean;
  /** True when this operator won the shared destination slot. */
  slot: boolean;
  order: number;
}

/** What Test Rules answers with. */
export interface Explanation {
  /** The URL as the proxy normalised it — what every pattern was matched on. */
  url: string;
  ops: ExplainOp[];
  /** Set when the question could not be read at all. */
  error?: string;
}

/** What the write endpoints answer with. */
export interface OkResult {
  ok: boolean;
  error?: string;
}

/** What an applied bundle carried — see `/api/export` and `/api/import`. */
export interface ImportResult extends OkResult {
  groups?: number;
  values?: number;
}

/**
 * What one replayed request will actually carry.
 *
 * The proxy replays from the captured body preview, which is decoded and capped
 * — so a replay is not always the request that was captured, and the console
 * has to be able to say which. `sent` is what goes out, `captured` is what was
 * seen on the wire.
 */
export interface ReplayedSession {
  id: number;
  /**
   * `whole` — the body replays byte for byte.
   * `partial` — only the prefix the preview held.
   * `empty` — there was no body.
   * `undecodable` — the capture's decoder failed; nothing is sent.
   */
  body: 'whole' | 'partial' | 'empty' | 'undecodable';
  sent: number;
  captured: number;
}

export interface ReplayResult {
  replayed: number;
  sessions?: ReplayedSession[];
  /** Set, with `ok: false`, when nothing was replayed — see `api_error`. */
  error?: string;
}

/**
 * A request written by hand in the Composer.
 *
 * `headers` is the raw text of the headers box — `Name: value`, one per line —
 * rather than pairs, because that is what a person types and what they paste
 * out of somebody else's terminal. The proxy parses it; see `composed_request`.
 */
export interface Composition {
  method: string;
  url: string;
  headers: string;
  body: string;
}

/**
 * What `POST /api/composer` answers.
 *
 * `url` is the URL as the proxy *resolved* it, which is not always the one that
 * was typed: a bare `example.com/x` acquires an `http://`. `error` is a sentence
 * naming what was wrong — a header line that is not one, a method that is not a
 * method — and the Composer shows it rather than sending something else.
 */
export interface ComposeResult {
  ok: boolean;
  url?: string;
  sent?: number;
  error?: string;
}

/**
 * One thing a page wrote to its console — `console.warn(…)`, or an error
 * nothing caught — sent back by the script a `log://` rule put in the page.
 */
export interface PageLog {
  /** Only grows; `/api/logs?after=` is asked with the last one seen. */
  seq: number;
  /** The page's own clock, Unix milliseconds. */
  time_ms: number;
  level: 'log' | 'info' | 'warn' | 'error' | 'debug';
  /** The rule's id — `audit` for `log://audit`. Empty for a rule with none. */
  id: string;
  /** Each argument as text: a string as it was, anything else as JSON. */
  args: string[];
  page: string;
  client_ip?: string;
}

/**
 * The console's switches — `src/proxy/webui/switches.rs`. Each `*_locked` is a
 * `-M` mode that took that switch away; the API refuses to move it (409).
 */
export interface Switches {
  ok: boolean;
  error?: string;
  intercept_https: boolean;
  intercept_https_locked: boolean;
  /** Every rule on — false is "disable all rules". */
  rules: boolean;
  rules_locked: boolean;
  /** Every plugin on — false is "disable all plugins". */
  plugins: boolean;
  plugins_locked: boolean;
  /** Plugins switched off one by one. */
  plugins_off: string[];
}

export type SwitchPatch = Partial<Pick<Switches, 'intercept_https' | 'rules' | 'plugins'>>;

export interface PageLogs {
  logs: PageLog[];
  /** Every group that has an entry, whatever was asked for. */
  ids: string[];
  last: number;
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

/** The `filename="…"` of a `Content-Disposition`, if it carries one. */
function dispositionName(header: string | null): string {
  return /filename="([^"]*)"/.exec(header || '')?.[1] || 'body.bin';
}

export const api = {
  sessions: () => getJson<SessionSummary[]>('/sessions.json'),
  /**
   * `h:`/`b:` over every session the proxy holds. A refusal (a bad regexp)
   * comes back `{ok: false, error}` and is thrown with its reason.
   */
  searchSessions: async (conditions: string[]): Promise<SessionSearch> => {
    const query = new URLSearchParams(conditions.map((c) => ['c', c]));
    const res = await fetch(`/api/sessions/search?${query}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body?.error || `/api/sessions/search: ${res.status}`);
    return body as SessionSearch;
  },
  session: (id: number) => getJson<SessionDetail | null>(`/session.json?id=${id}`),
  /**
   * The captured body as bytes — what the hex view, the image preview and the
   * download are all built from. Separate from `/session.json` on purpose: see
   * `session_body_bytes` in `webui/sessions.rs`.
   */
  bodyBytes: async (id: number, side: 'req' | 'res'): Promise<BodyBytes> => {
    const res = await fetch(`/body.bin?id=${id}&side=${side}`);
    if (!res.ok) throw new Error(`/body.bin: ${res.status}`);
    return {
      bytes: new Uint8Array(await res.arrayBuffer()),
      type: (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase(),
      // Named by the proxy rather than re-derived here, so the file a download
      // produces and the file `curl` produces have the same name.
      filename: dispositionName(res.headers.get('content-disposition')),
    };
  },
  frames: (id: number) => getJson<WsFrame[]>(`/frames.json?id=${id}`),
  wsPause: (id: number) => getJson<WsPauseStatus>(`/api/ws/status?id=${id}`),
  // Per session and per direction, and all of it at once: that is the only
  // granularity whistle has — there is no release-one-frame anywhere in it.
  releaseWs: (id: number, dir: 'send' | 'receive') =>
    postJson<OkResult & { released?: number }>('/api/ws/release', { id, dir }),
  /** No ids forgets everything; a list forgets exactly those sessions. */
  clearSessions: (ids?: number[]) => postJson<OkResult>('/api/sessions/clear', ids ? { ids } : {}),
  /** Clear, and delete the history persistence wrote to disk. */
  purgeSessions: () => postJson<OkResult & { files_deleted?: number }>('/api/sessions/purge', {}),
  replay: (ids: number[]) => postJson<ReplayResult>('/api/replay', { ids }),
  /** A HAR of the given sessions, as a link the browser downloads. */
  harUrl: (ids: number[]) => `/sessions.har?ids=${ids.join(',')}`,
  // Sent through the proxy's own port, exactly as a replay is, so the rules
  // apply to it and it is captured — see `send_through_self` in `webui/composer.rs`.
  compose: (c: Composition) => postJson<ComposeResult>('/api/composer', c),

  /** Send a frame into a live WebSocket session, from the console. */
  wsSend: (id: number, dir: 'send' | 'receive', data: string) =>
    postJson<OkResult>('/api/ws/send', { id, dir, data }),

  /** Test Rules: which operators a request *would* hit, without making one. */
  explain: (q: ExplainQuery) => postJson<Explanation>('/api/explain', q),

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
  // One key at a time. Editing the store as a whole object rewrites every key
  // on every save, so a typo anywhere loses all of them.
  setValue: (name: string, value: string) => postJson<OkResult>('/api/value', { name, value }),
  renameValue: (name: string, to: string) =>
    postJson<OkResult>('/api/value/rename', { name, to }),
  deleteValue: (name: string) => postJson<OkResult>('/api/value', { name }, 'DELETE'),

  /**
   * Apply an exported bundle. The proxy refuses anything without the marker
   * `/api/export` writes, so a file that merely happens to be JSON is never
   * read as a setup.
   */
  importBundle: (bundle: unknown) => postJson<ImportResult>('/api/import', bundle),

  status: () => getJson<ProxyStatus>('/api/status'),

  /** What pages under a `log://` rule have written since `after`. */
  logs: (after: number) => getJson<PageLogs>(`/api/logs?after=${after}`),
  /** Forget them: one group's, or with no id all of them. */
  clearLogs: (id?: string) =>
    postJson<OkResult & { cleared?: number }>('/api/logs/clear', id === undefined ? {} : { id }),
  switches: () => getJson<Switches>('/api/switches'),
  /** A refusal (a mode took the switch away) comes back `{ok: false, error}`. */
  setSwitches: (patch: SwitchPatch) => postJson<Switches>('/api/switches', patch),
  switchPlugin: (name: string, on: boolean) =>
    postJson<Switches>('/api/plugin/switch', { name, on }),
};
