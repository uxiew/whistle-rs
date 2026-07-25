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
 * A whistle-rs plugin. Define at least one hook — which ones you define is what
 * the capability manifest advertises to the proxy.
 */
export interface Plugin {
  /** Defaults to `$WHISTLE_RS_PLUGIN_NAME`. Matched by `plugin://<name>`. */
  name?: string;
  version?: string;
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
