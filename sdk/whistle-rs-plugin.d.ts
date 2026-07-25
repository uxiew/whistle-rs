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

  /** Runs before the upstream request. */
  onRequest?(ctx: RequestCtx): void | Promise<void>;
  /** Runs after the upstream response arrives. */
  onResponse?(ctx: ResponseCtx): void | Promise<void>;
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

/** Largest payload the SDK will buffer from the proxy (16 MiB). */
export const MAX_BODY_BYTES: number;
