/**
 * whistle-rs plugin SDK — TypeScript definitions.
 *
 * ```ts
 * import { start, type Plugin, type RequestCtx, type ResponseCtx } from 'whistle-rs-plugin';
 *
 * const plugin = {
 *   name: 'my-plugin',
 *
 *   async onRequest(ctx: RequestCtx) {
 *     if (ctx.url.includes('/api/')) {
 *       ctx.setRules('example.com resHeaders://x-t=1');
 *     }
 *   },
 *
 *   async onResponse(ctx: ResponseCtx) {
 *     ctx.setHeader('x-powered-by', 'whistle-rs');
 *   },
 * } satisfies Plugin;
 *
 * start(plugin);
 * ```
 */

/** A header as sent on the wire: `[name, value]`, in order, casing preserved. */
export type HeaderPair = [string, string];

/** What a plugin may return as a body: text, binary, or anything JSON-serialisable. */
export type BodyInit = string | Buffer | object | number | boolean | null;

/** A response that short-circuits the upstream request. */
export interface MockResponse {
  /** Defaults to 200. `status` is accepted as an alias. */
  statusCode?: number;
  status?: number;
  headers?: Record<string, string>;
  body?: BodyInit;
}

/** Members shared by both hook contexts. */
export interface BaseCtx {
  /** Correlation id — identical in this request's `onRequest` and `onResponse`. */
  readonly id: number;
  readonly method: string;
  /** The absolute request URL. */
  readonly url: string;
  /** The `plugin://name/PARAM` suffix, for routing within a single plugin. */
  readonly param: string;
  /** Headers as `[name, value]` pairs, in wire order. */
  readonly headers: HeaderPair[];
  /**
   * The body — `null` unless the plugin declared `requestBody` / `responseBody`.
   * Asking for a body you don't need costs the proxy its streaming fast path.
   */
  readonly body: Buffer | null;
  /** The request URL, parsed. */
  readonly parsedUrl: URL;

  /** Look up a header, case-insensitively. */
  header(name: string): string | undefined;
  /** Set a header, replacing any existing value of the same name. */
  setHeader(name: string, value: string | number): this;
  /** Remove a header. */
  removeHeader(name: string): this;
  /** The body decoded as UTF-8, or `''` when no body was delivered. */
  text(): string;
  /** The body parsed as JSON, or `undefined` when absent or unparseable. */
  json<T = unknown>(): T | undefined;
  /** A query-string parameter, or `undefined`. */
  query(name: string): string | undefined;
}

/** Context passed to `onRequest`, before the upstream request is made. */
export interface RequestCtx extends BaseCtx {
  /** The client's IP, when known. */
  readonly clientIp?: string;
  /**
   * Inject whistle rules for this request. Callable more than once; the rules
   * are joined with newlines.
   */
  setRules(rules: string): this;
  /**
   * Values for the `{name}` / `${name}` references in the rules you set. They
   * win over the proxy's own values of the same name, and only your rules see
   * them. A non-string value is sent as JSON.
   */
  setValues(values: Record<string, string | number | boolean | object>): this;
  /** Answer the request directly, skipping the upstream entirely. */
  respond(response: MockResponse): this;
}

/** Context passed to `onResponse`, after the upstream response arrives. */
export interface ResponseCtx extends BaseCtx {
  /** The upstream status code. */
  readonly statusCode: number;
  /** Rewrite the response status. */
  setStatus(code: number): this;
  /**
   * Replace the response body. Reading the original requires
   * `responseBody: true`; replacing it does not.
   */
  setBody(body: BodyInit): this;
}

/**
 * Context passed to a streaming hook — everything the buffered hooks receive
 * except the body, which is the stream itself.
 */
export interface PipeCtx {
  /** Correlation id, shared with this request's buffered hooks. */
  readonly id: number;
  readonly method: string;
  readonly url: string;
  /** The `/…` suffix after the plugin name. */
  readonly param: string;
  /** The `pipe://name(value)` argument, when the rule supplied one. */
  readonly pipeValue?: string;
  readonly clientIp?: string;
  /** Request headers in `pipeRequest`, response headers in `pipeResponse`. */
  readonly headers: HeaderPair[];
  /** The upstream status — `pipeResponse` only. */
  readonly statusCode?: number;
  /** Which body is flowing, for a hook that serves both. */
  readonly direction: 'request' | 'response';
  /** The request URL, parsed. */
  readonly parsedUrl: URL;

  /** Look up a header, case-insensitively. */
  header(name: string): string | undefined;
  /** A query-string parameter, or `undefined`. */
  query(name: string): string | undefined;
}

/**
 * A streaming hook: body bytes arrive on `src` and whatever reaches `dest` is
 * what continues on to the origin (`pipeRequest`) or the client
 * (`pipeResponse`). Nothing is buffered at either end.
 *
 * Return a `Duplex` (usually a `Transform`) and the SDK wires
 * `src → returned → dest` for you; otherwise wire the pipeline yourself.
 * Returning nothing without wiring anything leaves the body hanging.
 */
export type PipeHook = (
  src: import('http').IncomingMessage,
  dest: import('http').ServerResponse,
  ctx: PipeCtx
) => import('stream').Duplex | void | Promise<import('stream').Duplex | void>;

/**
 * One WebSocket frame offered to `onWsFrame`.
 *
 * `payload` is a `Buffer` and stays one. Decoding a frame to a string and
 * re-encoding it replaces every byte that is not valid UTF-8 with U+FFFD, which
 * silently corrupts a binary frame and inflates it by half — check `isText`
 * before reaching for `text`.
 *
 * The proxy honours a new payload and a drop. It ignores any change to `fin` or
 * `opcode`: retyping a frame, or restructuring a fragmented message, corrupts
 * the stream it travels in.
 */
export interface WsFrame {
  /** Final frame of its message (the WebSocket FIN bit). */
  readonly fin: boolean;
  /** `0x0` continuation, `0x1` text, `0x2` binary. Control frames never arrive. */
  readonly opcode: number;
  /** The payload as raw bytes. Assign a Buffer to rewrite it in place. */
  payload: Buffer;
  /** `'send'` (client→server) or `'receive'` (server→client). */
  readonly direction: 'send' | 'receive';
  /**
   * A whole text message in one frame — the only shape `text` is safe on. A
   * *fragment* of a text message has `opcode === 0x1` too but is not this,
   * because a multi-byte character can straddle two fragments.
   */
  readonly isText: boolean;
  /** A whole binary message in one frame. */
  readonly isBinary: boolean;
  /**
   * Part of a fragmented message: either a non-final frame or a continuation.
   * Delivered like any other frame, but decode at your peril — reassemble
   * across `isFragment` frames if you need the text.
   */
  readonly isFragment: boolean;
  /** The payload decoded as UTF-8 — deliberately opt-in. */
  readonly text: string;
  /** Replace the payload with the UTF-8 encoding of `value`. */
  setText(value: string): this;
}

/**
 * Context for a hooked WebSocket session: the handshake, and which way this
 * connection's frames are going. One instance per direction, alive for the
 * whole session, so a hook can keep per-session state on it.
 */
export interface WsSession {
  /** The captured session's id — the one `/frames.json` files these under. */
  readonly id: number;
  readonly method: string;
  /** The `ws://…` / `wss://…` URL of the handshake. */
  readonly url: string;
  /** The `/…` suffix after the plugin name. */
  readonly param: string;
  /** The `pipe://name(value)` argument, when the rule supplied one. */
  readonly pipeValue?: string;
  readonly clientIp?: string;
  /** The handshake request's headers, as `[name, value]` pairs. */
  readonly headers: HeaderPair[];
  /** Which direction this connection carries. */
  readonly direction: 'send' | 'receive';
  /** The handshake URL, parsed. */
  readonly parsedUrl: URL;

  /** Look up a handshake header, case-insensitively. */
  header(name: string): string | undefined;
  /** A query-string parameter, or `undefined`. */
  query(name: string): string | undefined;
}

/**
 * What a frame hook may return:
 *
 * - `undefined` / `true` / the frame itself → forward `frame.payload`, so
 *   mutating it in place works and so does `return frame`
 * - `null` / `false` → drop the frame
 * - a `Buffer` → those exact bytes
 * - a string → its UTF-8 encoding
 * - anything else → its JSON encoding
 */
export type WsVerdict = Buffer | string | object | boolean | null | undefined | WsFrame;

/**
 * A WebSocket frame hook. Called once per data frame per direction, in order,
 * and the frame waits for it — see `docs/PLUGINS.md` for the cost.
 */
export type WsFrameHook = (frame: WsFrame, ctx: WsSession) => WsVerdict | Promise<WsVerdict>;

/**
 * Context passed to `onAuth`, the gate in front of every other request hook.
 *
 * Shaped like whistle's: return `false` to block, and say what the blocked
 * client should see with one of the setters. Each setter clears the others — a
 * refusal has exactly one outcome — and calling any of them also implies the
 * block, so forgetting the `return false` cannot accidentally admit a request.
 */
export interface AuthCtx extends BaseCtx {
  /** The client's IP, when known. */
  readonly clientIp?: string;

  /** Block, and serve this HTML. */
  setHtml(html: string | Buffer | null): this;
  /** Block, and serve the contents of this URL or file path. */
  setUrl(url: string): this;
  /** Alias of `setUrl`. */
  setFile(url: string): this;
  /** Block, and redirect there instead (302). */
  setRedirect(url: string): this;
  /** Ask the client for credentials — 401, or 407 with an explicit status. */
  setLogin(login?: boolean): this;
  /** Status for the block. Honoured only in 300–599: a block is never a success. */
  setStatus(code: number): this;

  /**
   * Set a header on the request being **admitted**.
   *
   * Restricted to `x-whistle-*` and `proxy-authorization`; anything else is
   * dropped, by the SDK and again by the proxy. A gate identifies a request, it
   * does not rewrite it.
   */
  setHeader(name: string, value: string): this;
  /** Alias of `setHeader`. */
  set(name: string, value: string): this;
}

/**
 * Context passed to `sniCallback` — everything a TLS handshake knows about
 * itself before there is a request.
 *
 * There is deliberately no method, URL, header or body here: this hook runs
 * during the handshake, and none of those exist yet.
 */
export interface SniCtx {
  /**
   * The name the client asked for in its ClientHello, falling back to the host
   * the tunnel was opened to when it sent no SNI. This is the name the
   * certificate has to satisfy.
   */
  readonly servername: string;
  /** The `sniCallback://<name>(<value>)` argument. `''` when the rule had none. */
  readonly value: string;
  /** The host the tunnel was opened to. May differ from `servername`. */
  readonly tunnelHost: string;
  /** The port the tunnel was opened to. */
  readonly port: number;
  /** The client's IP, when known. */
  readonly clientIp?: string;
  /**
   * Set when whistle-rs is holding a certificate **this plugin** supplied for
   * `servername` — its value is this plugin's own name. Undefined otherwise.
   */
  readonly certCacheName?: string;
  /** The `mtime` that cached certificate carried, or `0`. */
  readonly certCacheTime: number;
  /** Whether whistle-rs holds a certificate of ours for this name. */
  readonly hasCachedCert: boolean;
  /** Return this to keep serving the certificate we supplied last time. */
  reuse(): SniReuse;
}

/** Certificate material for `sniCallback` to return. Both fields are required. */
export interface SniCert {
  /** PEM private key (PKCS#8, PKCS#1 or SEC1). */
  key: string;
  /** PEM certificate — a leaf, optionally followed by its chain. */
  cert: string;
  /**
   * When this certificate was issued. Echoed back as `ctx.certCacheTime` next
   * time, so the hook can tell whether what the proxy holds is current.
   */
  mtime?: number;
}

/** "Keep the one you already have from me." Produced by `ctx.reuse()`. */
export interface SniReuse {
  reuse: true;
}

/**
 * What `sniCallback` may return.
 *
 * * `true` — intercept, with the certificate whistle-rs would have generated.
 * * `false` — **do not intercept**: the connection is relayed to the origin
 *   encrypted, and whistle-rs never sees inside it.
 * * `SniCert` — intercept, presenting this certificate.
 * * `ctx.reuse()` — intercept, with the certificate this plugin supplied last
 *   time for this name.
 * * nothing — no opinion, which means the generated certificate.
 */
export type SniVerdict = boolean | SniCert | SniReuse | void;

/** Context passed to the stats hooks: what happened, with nothing to answer. */
export interface StatsCtx extends BaseCtx {
  /** Which phase this ping reports. */
  readonly phase: 'request' | 'response';
  /** The client's IP, when known. */
  readonly clientIp?: string;
  /** The upstream status — response phase only. */
  readonly statusCode?: number;
}

/**
 * A UI request handler: Node's own `(req, res)`, with `/plugin/<name>` already
 * stripped from `req.url`.
 *
 * Return a string or Buffer to send it as HTML, or any other value to send it
 * as JSON; return nothing and the handler owns `res`.
 *
 * A UI request carries **no** proxied-request context — it is a browser asking
 * this plugin for a page, not part of anyone's traffic.
 */
export type UiHook = (
  req: import('http').IncomingMessage,
  res: import('http').ServerResponse
) => BodyInit | undefined | Promise<BodyInit | undefined>;

/**
 * A whistle-rs plugin. Define at least one hook, or `rules` — which hooks you
 * define is what the capability manifest advertises to the proxy.
 */
export interface Plugin {
  /** Defaults to `$WHISTLE_RS_PLUGIN_NAME`. Matched by `plugin://<name>`. */
  name?: string;
  version?: string;
  /**
   * Rules applied to every request while the plugin is on, with no line of the
   * user's naming the plugin — upstream's `rules.txt`. They rank below the
   * console's rules. Read once, when the proxy first fetches the manifest.
   */
  rules?: string;
  /**
   * Ask for the request body to be delivered on `ctx.body`.
   * Off by default: buffering defeats streaming, so only opt in if you read it.
   */
  requestBody?: boolean;
  /** Ask for the response body to be delivered on `ctx.body`. Off by default. */
  responseBody?: boolean;

  /** Runs before the upstream request. Reached by `plugin://<name>`. */
  onRequest?(ctx: RequestCtx): void | Promise<void>;
  /** Runs after the upstream response arrives. Reached by `plugin://<name>`. */
  onResponse?(ctx: ResponseCtx): void | Promise<void>;

  /**
   * Transform the request body **as it streams** upstream. Reached by
   * `pipe://<name>`; needs no body flag, because nothing is ever buffered.
   */
  pipeRequest?: PipeHook;
  /** Transform the response body as it streams back. Reached by `pipe://<name>`. */
  pipeResponse?: PipeHook;

  /**
   * Inspect, rewrite or drop each frame of a tunnelled WebSocket, both
   * directions. Reached by `plugin://<name>` *or* `pipe://<name>` on the
   * WebSocket's URL — a WebSocket has no buffered-versus-streaming choice for
   * the scheme to express.
   */
  onWsFrame?: WsFrameHook;

  /**
   * Decide whether a request may proceed. Runs before every other request hook,
   * and a block stops the chain — no later plugin runs.
   *
   * **This hook fails closed.** If it throws, hangs, or the plugin is not
   * reachable, the requests it matched are blocked with a `502`, not admitted.
   * Reached by `plugin://<name>` or `pipe://<name>`.
   */
  onAuth?(ctx: AuthCtx): boolean | void | Promise<boolean | void>;

  /**
   * Choose the certificate for an intercepted TLS connection, or decline the
   * interception entirely. Reached by `sniCallback://<name>[(<value>)]`, matched
   * against `https://<the name in the ClientHello>`.
   *
   * Runs **inside the handshake**, before any request exists, so it gets no
   * request context and a client is waiting on every millisecond it spends.
   *
   * Failure degrades to the generated certificate — throwing, hanging or being
   * unreachable means the connection is intercepted as it would have been with
   * no rule at all. It is not a gate, so this is not an admission.
   */
  sniCallback?(ctx: SniCtx): SniVerdict | Promise<SniVerdict>;

  /**
   * Told that a request went past, before it is forwarded. Fire-and-forget: the
   * reply is discarded and nothing waits for it, so it cannot change anything.
   */
  onReqStats?(ctx: StatsCtx): void | Promise<void>;
  /** Told how the request turned out, once the response head is back. */
  onResStats?(ctx: StatsCtx): void | Promise<void>;

  /**
   * Serve the plugin's own pages, routed from the web UI at
   * `http://<proxy>/plugin/<name>/`.
   */
  onUi?: UiHook;
}

export interface StartOptions {
  /** Override the port. Defaults to `$WHISTLE_RS_PLUGIN_PORT`, else an ephemeral port. */
  port?: number;
}

/**
 * Start the plugin's HTTP server. Handles the manifest, routing, body decoding
 * and error isolation; a throwing hook is logged and treated as a no-op.
 */
export function start(plugin: Plugin, opts?: StartOptions): import('http').Server;

/**
 * Build a `Transform` from a plain chunk mapper — the usual shape of a pipe
 * hook. Return a value to emit it, or something falsy to drop the chunk.
 *
 * ```ts
 * pipeResponse: () => transform((chunk) => chunk.toString().toUpperCase()),
 * ```
 */
export function transform(
  fn: (chunk: Buffer, stream: import('stream').Transform) => BodyInit | undefined,
  flush?: (stream: import('stream').Transform) => BodyInit | undefined
): import('stream').Transform;

/** Largest payload the SDK will buffer from the proxy (16 MiB). */
export const MAX_BODY_BYTES: number;

/** Header carrying a piped body's metadata, for non-SDK implementations. */
export const PIPE_META_HEADER: string;

/** Header carrying a hooked WebSocket session's metadata. */
export const WS_META_HEADER: string;

/** WebSocket opcode: continuation of a fragmented message. */
export const WS_CONTINUATION: number;
/** WebSocket opcode: a text message. */
export const WS_TEXT: number;
/** WebSocket opcode: a binary message. */
export const WS_BINARY: number;
