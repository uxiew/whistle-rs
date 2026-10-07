'use strict';
//
// whix plugin SDK — zero dependencies, Node's stdlib only.
//
// A plugin is a plain object with a `name` and one or both hooks:
//
//   const { start } = require('whix-plugin');
//
//   start({
//     name: 'my-plugin',
//     async onRequest(ctx) { ctx.setRules('example.com resHeaders://x-t=1'); },
//     async onResponse(ctx) { ctx.setHeader('x-powered-by', 'whix'); },
//   });
//
// `start` speaks the HTTP/JSON protocol for you, including the capability
// manifest: it derives `hooks` from which handlers you defined, and gates body
// delivery on the `requestBody` / `responseBody` flags. Declaring a body you do
// not need costs the proxy its streaming fast path, so both default to false.
//
// For bodies you want to see *as they flow* — SSE, uploads, anything large —
// define a pipe hook instead. It is handed a readable of body bytes and a
// writable for the transformed ones, and nothing is buffered at either end:
//
//   start({
//     name: 'shout',
//     pipeResponse(req, res) { return upperCaseTransform(); },
//   });
//
// Pipe hooks are reached by a `pipe://shout` rule (vs `plugin://` for the
// buffered ones).
//
// A WebSocket is neither: its unit is a frame, so it has its own hook, which
// either rule scheme reaches.
//
//   start({
//     name: 'ws',
//     onWsFrame(frame, ctx) {
//       if (frame.isText) return frame.text.toUpperCase();  // rewrite
//       // binary frames: leave the Buffer alone
//     },
//   });
//
// Three more hooks are not about rewriting traffic at all:
//
//   start({
//     name: 'gate',
//     onAuth(ctx) {                       // decide whether a request proceeds
//       if (!ctx.header('authorization')) { ctx.setLogin(true); return false; }
//       ctx.setHeader('x-whistle-user', 'bob');   // identifies it downstream
//     },
//     onResStats(ctx) { count(ctx.statusCode); }, // told what happened; no reply
//     onUi(req, res) { return `<h1>${count}</h1>`; }, // its own page
//   });
//
// `onAuth` is the one hook whose failure is *not* forgiven: a plugin that
// declares it and then throws, hangs or dies blocks the requests it matched.
// A gate that admits everything when it breaks is not a gate.
//
// One hook is not about a request at all. `sniCallback` runs during the TLS
// handshake of an intercepted connection, and picks the certificate — or
// declines the interception, which nothing else here can do:
//
//   start({
//     name: 'certs',
//     sniCallback(ctx) {
//       if (ctx.servername.endsWith('.pinned.example')) return false;  // don't look
//       if (ctx.hasCachedCert) return ctx.reuse();                     // still good
//       return { key: myKeyPem, cert: myCertPem, mtime: Date.now() };
//     },
//   });
//
// It is reached by `sniCallback://<name>` and gets no request context, because
// at that point there is no request.
//
// TypeScript users: see whix-plugin.d.ts. The same entry point works for
// `export default { … }` — an ES module default export is unwrapped.

const http = require('http');
const { Transform } = require('stream');

/** Bodies larger than this are refused rather than buffered without bound. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;

/**
 * Start the plugin server.
 *
 * The port and name come from the environment whix spawns us with
 * (`WHIX_PLUGIN_PORT`, `WHIX_PLUGIN_NAME`); pass `opts.port` to
 * run standalone, e.g. in tests.
 */
const HOOKS = [
  ['onRequest', 'request'],
  ['onResponse', 'response'],
  ['pipeRequest', 'pipeRequest'],
  ['pipeResponse', 'pipeResponse'],
  ['onWsFrame', 'wsFrame'],
  ['onAuth', 'auth'],
  ['sniCallback', 'sni'],
  ['onReqStats', 'reqStats'],
  ['onResStats', 'resStats'],
  ['onUi', 'ui'],
];

function start(plugin, opts) {
  plugin = unwrapDefault(plugin);
  const defined = HOOKS.filter(([method]) => plugin && typeof plugin[method] === 'function');
  // A plugin may be nothing but the rules it brings — upstream's `rules.txt`.
  const rules = plugin && typeof plugin.rules === 'string' && plugin.rules.trim() ? plugin.rules : undefined;
  if (!defined.length && !rules) {
    throw new TypeError(
      `whix plugin: define at least one of ${HOOKS.map(([m]) => m).join(' / ')}`
    );
  }
  opts = opts || {};

  const port = opts.port != null ? opts.port : parseInt(process.env.WHIX_PLUGIN_PORT || '0', 10);
  const name = plugin.name || process.env.WHIX_PLUGIN_NAME || 'plugin';

  const manifest = {
    name,
    version: plugin.version || '1',
    hooks: defined.map(([, hook]) => hook),
    requestBody: plugin.requestBody === true,
    responseBody: plugin.responseBody === true,
    // Applied to every request while the plugin is on, below the console's
    // own rules. Read once, when the proxy first fetches this manifest.
    ...(rules ? { rules } : {}),
  };

  const server = http.createServer((req, res) => {
    const route = req.url.split('?')[0];

    if (route === '/manifest') {
      return sendJson(res, 200, manifest);
    }

    // Pipe hooks are handed the live streams — never routed through readBody,
    // which would defeat the entire point.
    if (route === '/pipe/request' || route === '/pipe/response') {
      const isReq = route === '/pipe/request';
      return servePipe(plugin, name, isReq ? 'pipeRequest' : 'pipeResponse', req, res);
    }

    // Likewise the frame hook: one long-lived connection carrying a session's
    // frames, not a request with a body.
    if (route === '/ws/frames') {
      return serveWsFrames(plugin, name, req, res);
    }

    // The UI subtree is the plugin's own URL space: an ordinary HTTP request
    // with an ordinary HTTP answer, handed over with the prefix removed.
    if (route === UI_PREFIX || route.indexOf(UI_PREFIX + '/') === 0) {
      return serveUi(plugin, name, req, res);
    }

    readBody(req, (err, raw) => {
      if (err) {
        return sendJson(res, 413, { error: String(err.message || err) });
      }
      let payload;
      try {
        payload = JSON.parse(raw.toString('utf8') || '{}');
      } catch (e) {
        return sendJson(res, 400, { error: 'invalid JSON payload' });
      }

      if (route === '/auth') {
        return serveAuth(plugin, name, payload, res);
      }
      if (route === '/sni') {
        return serveSni(plugin, name, payload, res);
      }
      if (route === '/stats') {
        return serveStats(plugin, name, payload, res);
      }

      // `/` is the legacy v1 request route, kept so older plugins and manual
      // curl-ing both keep working.
      const isRequestHook = route === '/request' || route === '/';
      const handler = isRequestHook ? plugin.onRequest : plugin.onResponse;
      if (typeof handler !== 'function') {
        return sendJson(res, 204, {});
      }

      const ctx = isRequestHook ? new RequestCtx(payload) : new ResponseCtx(payload);
      Promise.resolve()
        .then(() => handler.call(plugin, ctx))
        .then(() => sendJson(res, 200, ctx._result()))
        .catch((e) => {
          // A throwing plugin must never take the proxy down with it: log and
          // return "nothing to do".
          console.error(`[${name}] ${isRequestHook ? 'onRequest' : 'onResponse'} threw:`, e);
          sendJson(res, 200, {});
        });
    });
  });

  server.listen(port, '127.0.0.1', () => {
    const bound = server.address().port;
    console.log(`[${name}] whix plugin listening on 127.0.0.1:${bound} (hooks: ${manifest.hooks.join(', ') || 'none'})`);
  });
  exitWithParent(name);
  return server;
}

/**
 * Leave when the whix that started us is gone.
 *
 * `--node-plugin` gives us a stdin only it holds open, and the operating
 * system closes it when whix exits by any route — `kill -9`, `taskkill
 * /F` and a crash included, none of which let whix stop us itself.
 * Without this, a plugin outlived its proxy and kept its port. Only when
 * whix says stdin means that: a plugin started by hand may have a stdin
 * that is closed from the start.
 */
function exitWithParent(name) {
  if (process.env.WHIX_PLUGIN_STDIN !== 'lifeline') return;
  const leave = () => {
    console.log(`[${name}] whix has exited; stopping`);
    process.exit(0);
  };
  process.stdin.on('end', leave);
  process.stdin.on('close', leave);
  process.stdin.on('error', leave);
  process.stdin.resume();
}

/** Path prefix reserved for the plugin's own pages. */
const UI_PREFIX = '/ui';

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/**
 * Serve one auth decision.
 *
 * Note what happens when the hook throws: a `500`, which whix reads as
 * "the gate failed" and turns into a `502` block. Every other hook in this SDK
 * answers `200 {}` — "nothing to do" — when it throws, because for those the
 * request is better off proceeding. Not here: a gate that admits a request
 * because it crashed is worse than no gate, since it looks like one.
 */
function serveAuth(plugin, name, payload, res) {
  const ctx = new AuthCtx(payload);
  Promise.resolve()
    .then(() => plugin.onAuth.call(plugin, ctx))
    .then((verdict) => sendJson(res, 200, ctx._result(verdict)))
    .catch((e) => {
      console.error(`[${name}] onAuth threw:`, e);
      sendJson(res, 500, { error: String((e && e.message) || e) });
    });
}

// ---------------------------------------------------------------------------
// The certificate chooser
// ---------------------------------------------------------------------------

/**
 * Serve one certificate decision.
 *
 * This hook runs *inside a TLS handshake*, before there is a request — a client
 * is sitting on an open socket waiting for it, so be quick and cache your own
 * certificates. `ctx.certCacheName` tells you what whix already holds
 * from you for this name; returning `ctx.reuse()` when it is still good saves
 * both sides the work of shipping and parsing it again.
 *
 * A throwing hook answers `200` with nothing to say, which whix reads as
 * "use the certificate you would have generated". That is the same degradation
 * every hook here has except `onAuth` — and unlike `onAuth`, this one is not a
 * gate: falling back means the connection is intercepted with whix's own
 * certificate, not that anything is let past a check.
 */
function serveSni(plugin, name, payload, res) {
  const ctx = new SniCtx(payload);
  Promise.resolve()
    .then(() => plugin.sniCallback.call(plugin, ctx))
    .then((out) => sendJson(res, 200, sniReply(out)))
    .catch((e) => {
      console.error(`[${name}] sniCallback threw:`, e);
      sendJson(res, 200, {});
    });
}

/** Normalise whatever the hook returned into the wire's four shapes. */
function sniReply(out) {
  if (out === false) return { intercept: false };
  if (out === true) return { intercept: true };
  if (out && typeof out === 'object') {
    if (out.reuse === true) return { reuse: true };
    if (typeof out.key === 'string' && typeof out.cert === 'string' && out.key && out.cert) {
      const reply = { key: out.key, cert: out.cert };
      if (out.mtime > 0) reply.mtime = out.mtime;
      return reply;
    }
  }
  // Undefined, null, or a shape we do not recognise: no opinion.
  return {};
}

/**
 * Context for the certificate hook. Everything a TLS handshake knows about
 * itself before the first byte of the first request — which is not much, and
 * deliberately not dressed up as more.
 */
class SniCtx {
  constructor(payload) {
    /** The name in the client's ClientHello, or the tunnel's host if it sent none. */
    this.servername = payload.servername || '';
    /** The `sniCallback://name(value)` argument. Empty string when absent. */
    this.value = payload.value || '';
    /** The host the tunnel was opened to — may differ from `servername`. */
    this.tunnelHost = payload.tunnelHost || '';
    /** The port the tunnel was opened to. */
    this.port = payload.port;
    this.clientIp = payload.clientIp || undefined;
    /**
     * The plugin whose certificate whix holds for `servername` — this
     * plugin's own name when it holds one of yours, undefined otherwise.
     */
    this.certCacheName = payload.certCacheName;
    /** The `mtime` that certificate carried (`0` if it carried none). */
    this.certCacheTime = payload.certCacheTime || 0;
  }

  /** Is the certificate whix already holds for this name ours? */
  get hasCachedCert() {
    return this.certCacheName != null;
  }

  /** Keep using the certificate we supplied last time for this name. */
  reuse() {
    return { reuse: true };
  }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/**
 * Serve one stats ping.
 *
 * The reply goes out first and is discarded by the proxy: nothing here can
 * change the request, which is exactly why this hook is safe to put on one. A
 * throwing handler is logged and forgotten.
 */
function serveStats(plugin, name, payload, res) {
  const isRequest = payload.phase !== 'response';
  const handler = isRequest ? plugin.onReqStats : plugin.onResStats;
  sendJson(res, 200, {});
  if (typeof handler !== 'function') return;
  Promise.resolve()
    .then(() => handler.call(plugin, new StatsCtx(payload)))
    .catch((e) => console.error(`[${name}] ${isRequest ? 'onReqStats' : 'onResStats'} threw:`, e));
}

// ---------------------------------------------------------------------------
// The plugin's own pages
// ---------------------------------------------------------------------------

/**
 * Serve one UI request.
 *
 * `req.url` arrives as `/ui/<path>` and is handed over as `/<path>`, so a
 * handler sees its own URL space and knows nothing of the prefix. The handler
 * gets Node's own `(req, res)`; returning a string or an object is a shortcut
 * for the common case of one page.
 *
 * A UI request carries no proxied-request context — it is a browser asking this
 * plugin for a page, not part of anyone's traffic.
 */
function serveUi(plugin, name, req, res) {
  if (typeof plugin.onUi !== 'function') {
    res.writeHead(404, { 'content-length': 0 });
    return res.end();
  }
  req.url = req.url.slice(UI_PREFIX.length) || '/';
  const send = (out) => {
    if (out === undefined || res.writableEnded || res.headersSent) return;
    if (typeof out === 'string' || Buffer.isBuffer(out)) {
      const body = Buffer.isBuffer(out) ? out : Buffer.from(out, 'utf8');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': body.length });
      return res.end(body);
    }
    sendJson(res, 200, out);
  };
  Promise.resolve()
    .then(() => plugin.onUi.call(plugin, req, res))
    .then(send)
    .catch((e) => {
      console.error(`[${name}] onUi threw:`, e);
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
      if (!res.writableEnded) res.end('plugin UI error');
    });
}

/** Header carrying the base64-encoded JSON metadata of a piped body. */
const PIPE_META_HEADER = 'x-whix-pipe';

/**
 * Serve one streaming hook.
 *
 * The `200` goes out *before* the handler runs, and before a single body byte
 * is asked for. That is the contract: whix reads nothing from the body
 * until it sees this head, so answering at once is what starts the stream — and
 * failing to (because we are down, or because we answer anything else) lets the
 * proxy forward the original body untouched instead of losing it.
 */
function servePipe(plugin, name, hookName, req, res) {
  const handler = plugin[hookName];
  if (typeof handler !== 'function') {
    res.writeHead(404, { 'content-length': 0 });
    return res.end();
  }
  res.writeHead(200, { 'content-type': 'application/octet-stream' });
  res.flushHeaders();

  const ctx = new PipeCtx(req, hookName === 'pipeRequest');
  // Whatever goes wrong, the body must still come out the other side.
  const passthrough = () => {
    if (!res.writableEnded && !req.readableFlowing) req.pipe(res);
  };
  const failed = (what, e) => {
    console.error(`[${name}] ${hookName} ${what}:`, e);
  };
  req.on('error', (e) => {
    failed('source stream failed', e);
    res.destroy();
  });

  const wire = (out) => {
    if (!isDuplex(out)) return false;
    out.on('error', (e) => {
      failed('transform failed', e);
      res.end();
    });
    req.pipe(out).pipe(res);
    return true;
  };

  let out;
  try {
    out = handler.call(plugin, req, res, ctx);
  } catch (e) {
    failed('threw', e);
    return passthrough();
  }
  if (wire(out)) return;
  if (out && typeof out.then === 'function') {
    // An async hook: nothing is read while it settles, so no bytes are lost.
    out.then(wire).catch((e) => {
      failed('rejected', e);
      passthrough();
    });
  }
  // Anything else means the hook wired the streams itself.
}

/** Whether `s` can sit in the middle of a pipeline. */
function isDuplex(s) {
  return !!s && typeof s.pipe === 'function' && typeof s.write === 'function';
}

/**
 * Build a `Transform` from a plain chunk mapper — the usual shape of a pipe
 * hook. Return a Buffer/string to emit it, or a falsy value to drop the chunk.
 *
 * ```js
 * pipeResponse: () => transform((chunk) => chunk.toString().toUpperCase()),
 * ```
 */
function transform(fn, flush) {
  return new Transform({
    transform(chunk, encoding, cb) {
      let out;
      try {
        out = fn(chunk, this);
      } catch (e) {
        return cb(e);
      }
      cb(null, out == null || out === '' ? undefined : out);
    },
    flush(cb) {
      if (typeof flush !== 'function') return cb();
      try {
        cb(null, flush(this) || undefined);
      } catch (e) {
        cb(e);
      }
    },
  });
}

/**
 * Context for a streaming hook: everything the buffered hooks get except the
 * body, which is the stream itself.
 */
class PipeCtx {
  constructor(req, isRequestHook) {
    const meta = decodeMeta(req, PIPE_META_HEADER);
    /** Correlation id, shared with this request's buffered hooks. */
    this.id = meta.id;
    this.method = meta.method || 'GET';
    this.url = meta.url || '';
    /** The `/…` suffix after the plugin name. */
    this.param = meta.param || '';
    /** The `pipe://name(value)` argument, when the rule supplied one. */
    this.pipeValue = meta.pipeValue;
    this.clientIp = meta.clientIp;
    /** Request headers in `pipeRequest`, response headers in `pipeResponse`. */
    this.headers = meta.headers || [];
    /** The upstream status — `pipeResponse` only. */
    this.statusCode = meta.statusCode;
    /** `'request'` or `'response'`, for hooks that serve both. */
    this.direction = isRequestHook ? 'request' : 'response';
  }

  /** Look up a header, case-insensitively. Returns undefined if absent. */
  header(name) {
    return findHeader(this.headers, name);
  }

  /** The URL parsed, for convenient access to pathname/query. */
  get parsedUrl() {
    if (!this._parsed) this._parsed = parseUrl(this.url);
    return this._parsed;
  }

  /** A query-string parameter, or undefined. */
  query(name) {
    const v = this.parsedUrl.searchParams.get(name);
    return v === null ? undefined : v;
  }
}

/** Decode a hook's base64-JSON metadata header; never throws. */
function decodeMeta(req, header) {
  try {
    const raw = Buffer.from(String(req.headers[header] || ''), 'base64');
    return JSON.parse(raw.toString('utf8')) || {};
  } catch (e) {
    return {};
  }
}

// ---------------------------------------------------------------------------
// WebSocket frame hook
// ---------------------------------------------------------------------------

/** Header carrying the metadata of a hooked WebSocket session. */
const WS_META_HEADER = 'x-whix-ws';

/** Continuation of a fragmented message. */
const WS_CONTINUATION = 0x0;
/** A text message (UTF-8). */
const WS_TEXT = 0x1;
/** A binary message. */
const WS_BINARY = 0x2;

/** Bytes of record header: flags, opcode, and a 32-bit payload length. */
const RECORD_HEADER = 6;
const FLAG_FIN = 0x01;
const FLAG_DROP = 0x02;

/**
 * Serve the frame hook: one long-lived connection carrying one direction of one
 * WebSocket session, a record per frame in and a verdict record per frame out.
 *
 * The `200` goes out before anything is read, exactly as for a pipe hook —
 * whix holds every frame of the session until it sees this head, and
 * forwards them all unhooked if it never does.
 */
function serveWsFrames(plugin, name, req, res) {
  const handler = plugin.onWsFrame;
  if (typeof handler !== 'function') {
    res.writeHead(404, { 'content-length': 0 });
    return res.end();
  }
  res.writeHead(200, { 'content-type': 'application/octet-stream' });
  res.flushHeaders();

  const ctx = new WsSession(req);
  // Verdicts are written in the order the frames arrived, whatever an async
  // handler does with them: a hook that reordered a WebSocket would be worse
  // than one that is slow.
  let queue = Promise.resolve();

  req.on(
    'data',
    readRecords((flags, opcode, payload) => {
      const frame = new WsFrame(flags, opcode, payload, ctx.direction);
      queue = queue.then(async () => {
        const out = await decide(plugin, name, handler, frame, ctx);
        if (res.writableEnded) return;
        res.cork();
        res.write(recordHeader(frame, out));
        if (out) res.write(out);
        res.uncork();
      });
    })
  );
  // The session is over when the proxy stops sending; answer what is left first.
  req.on('end', () => queue.then(() => res.end(), () => res.end()));
  req.on('error', (e) => {
    console.error(`[${name}] onWsFrame stream failed:`, e);
    res.destroy();
  });
}

/**
 * Feed chunks in, get complete records out.
 *
 * Chunk boundaries mean nothing here — a record may span many, and many may
 * share one — so the pieces are held and joined exactly once per record. A
 * frame can be megabytes; re-joining a growing buffer per chunk would be
 * quadratic in its size.
 */
function readRecords(onRecord) {
  let chunks = [];
  let size = 0;
  let head = null;

  const join = () => {
    const buf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, size);
    chunks = [buf];
    return buf;
  };
  const consume = (buf, n) => {
    chunks = [buf.subarray(n)];
    size = chunks[0].length;
  };

  return (chunk) => {
    chunks.push(chunk);
    size += chunk.length;
    for (;;) {
      if (!head) {
        if (size < RECORD_HEADER) return;
        const buf = join();
        head = { flags: buf[0], opcode: buf[1], len: buf.readUInt32BE(2) };
        consume(buf, RECORD_HEADER);
      }
      if (size < head.len) return;
      const buf = join();
      const payload = buf.subarray(0, head.len);
      const done = head;
      consume(buf, head.len);
      head = null;
      onRecord(done.flags, done.opcode, payload);
    }
  };
}

/**
 * Run the hook for one frame, returning the payload to forward or `null` to
 * drop it. A throwing hook forwards the frame untouched, like every other hook
 * in this SDK.
 */
async function decide(plugin, name, handler, frame, ctx) {
  let out;
  try {
    out = await handler.call(plugin, frame, ctx);
  } catch (e) {
    console.error(`[${name}] onWsFrame threw:`, e);
    return frame.payload;
  }
  return framePayload(frame, out);
}

/**
 * What a hook returned, as bytes:
 *
 * - `undefined` / `true` / the frame itself → `frame.payload`, so mutating it
 *   in place works and so does `return frame`
 * - `null` / `false` → drop the frame
 * - a `Buffer` → those exact bytes
 * - a string → its UTF-8 encoding
 * - anything else → its JSON encoding
 */
function framePayload(frame, out) {
  if (out === null || out === false) return null;
  // Whatever comes back leaves here as a Buffer. A record declares its own
  // length, so letting anything else through — a payload the hook replaced
  // with a string, say — would desync the stream rather than merely misbehave.
  const value = out === undefined || out === true || out === frame ? frame.payload : out;
  if (Buffer.isBuffer(value)) return value;
  if (value == null) return Buffer.alloc(0);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  return Buffer.from(JSON.stringify(value), 'utf8');
}

/** The six-byte header of one verdict record. */
function recordHeader(frame, payload) {
  const head = Buffer.allocUnsafe(RECORD_HEADER);
  head[0] = (frame.fin ? FLAG_FIN : 0) | (payload ? 0 : FLAG_DROP);
  head[1] = frame.opcode;
  head.writeUInt32BE(payload ? payload.length : 0, 2);
  return head;
}

/**
 * One WebSocket frame offered to `onWsFrame`.
 *
 * `payload` is a Buffer and stays one. Decoding a frame to a string and
 * re-encoding it replaces every byte that is not valid UTF-8 with U+FFFD, which
 * silently corrupts a binary frame and inflates it by half — check `isText`
 * before you reach for `text`.
 *
 * The proxy honours a new payload and a drop. It ignores any change to `fin` or
 * `opcode`: retyping a frame, or restructuring a fragmented message, corrupts
 * the stream it travels in.
 */
class WsFrame {
  constructor(flags, opcode, payload, direction) {
    /** Final frame of its message (the WebSocket FIN bit). */
    this.fin = (flags & FLAG_FIN) !== 0;
    /** `0x0` continuation, `0x1` text, `0x2` binary. */
    this.opcode = opcode;
    /** The payload as raw bytes. Assign a Buffer to rewrite it in place. */
    this.payload = payload;
    /** `'send'` (client→server) or `'receive'` (server→client). */
    this.direction = direction;
  }

  /**
   * A whole text message in one frame — the only shape `text` is safe on.
   * A *fragment* of a text message has `opcode === WS_TEXT` too but is not
   * this, because a multi-byte character can straddle two fragments.
   */
  get isText() {
    return this.opcode === WS_TEXT && this.fin;
  }

  /** A whole binary message in one frame. */
  get isBinary() {
    return this.opcode === WS_BINARY && this.fin;
  }

  /**
   * Part of a fragmented message: either a non-final frame or a continuation.
   * Such frames are delivered like any other, but decode them at your peril —
   * reassemble across `isFragment` frames if you need the text.
   */
  get isFragment() {
    return !this.fin || this.opcode === WS_CONTINUATION;
  }

  /** The payload decoded as UTF-8 — deliberately opt-in. */
  get text() {
    return this.payload.toString('utf8');
  }

  /** Replace the payload with the UTF-8 encoding of `value`. */
  setText(value) {
    this.payload = Buffer.from(String(value), 'utf8');
    return this;
  }
}

/**
 * Context for a hooked WebSocket session — the handshake, and which way this
 * connection's frames are going. One instance per direction, alive for the
 * whole session, so a hook can keep per-session state on it.
 */
class WsSession {
  constructor(req) {
    const meta = decodeMeta(req, WS_META_HEADER);
    /** The captured session's id — the one `/frames.json` files these under. */
    this.id = meta.id;
    this.method = meta.method || 'GET';
    /** The `ws://…` / `wss://…` URL of the handshake. */
    this.url = meta.url || '';
    /** The `/…` suffix after the plugin name. */
    this.param = meta.param || '';
    /** The `pipe://name(value)` argument, when the rule supplied one. */
    this.pipeValue = meta.pipeValue;
    this.clientIp = meta.clientIp;
    /** The handshake request's headers, as `[name, value]` pairs. */
    this.headers = meta.headers || [];
    /** `'send'` (client→server) or `'receive'` (server→client). */
    this.direction = meta.direction === 'receive' ? 'receive' : 'send';
  }

  /** Look up a handshake header, case-insensitively. */
  header(name) {
    return findHeader(this.headers, name);
  }

  /** The URL parsed, for convenient access to pathname/query. */
  get parsedUrl() {
    if (!this._parsed) this._parsed = parseUrl(this.url);
    return this._parsed;
  }

  /** A query-string parameter, or undefined. */
  query(name) {
    const v = this.parsedUrl.searchParams.get(name);
    return v === null ? undefined : v;
  }
}

/** Case-insensitive lookup over `[name, value]` pairs. */
function findHeader(headers, name) {
  const want = String(name).toLowerCase();
  for (const [k, v] of headers) {
    if (String(k).toLowerCase() === want) return v;
  }
  return undefined;
}

/** Parse a URL, falling back to a placeholder rather than throwing. */
function parseUrl(url) {
  try {
    return new URL(url);
  } catch (e) {
    return new URL('http://invalid.local/');
  }
}

/** Accept both `module.exports = {…}` and ESM `export default {…}`. */
function unwrapDefault(mod) {
  if (mod && typeof mod === 'object' && mod.default && !mod.name && !mod.onRequest && !mod.onResponse) {
    return mod.default;
  }
  return mod;
}

function readBody(req, cb) {
  const chunks = [];
  let total = 0;
  let done = false;
  const finish = (err, buf) => {
    if (!done) {
      done = true;
      cb(err, buf);
    }
  };
  req.on('data', (c) => {
    total += c.length;
    if (total > MAX_BODY_BYTES) {
      req.destroy();
      return finish(new Error('payload too large'));
    }
    chunks.push(c);
  });
  req.on('end', () => finish(null, Buffer.concat(chunks)));
  req.on('error', finish);
}

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
  });
  res.end(body);
}

/** Shared header helpers for both contexts. */
class BaseCtx {
  constructor(payload) {
    /** Correlation id — the same value in this request's onRequest and onResponse. */
    this.id = payload.id;
    this.method = payload.method || 'GET';
    this.url = payload.url || '';
    /** The `plugin://name/PARAM` suffix, for routing within one plugin. */
    this.param = payload.param || '';
    /** Incoming headers as `[name, value]` pairs, in wire order. */
    this.headers = payload.headers || [];
    this.body = payload.bodyBase64 != null ? Buffer.from(payload.bodyBase64, 'base64') : null;

    this._set = {};
    this._remove = [];
  }

  /** Look up a header, case-insensitively. Returns undefined if absent. */
  header(name) {
    return findHeader(this.headers, name);
  }

  /** Set a header (replacing any existing value of the same name). */
  setHeader(name, value) {
    this._set[name] = String(value);
    return this;
  }

  /** Remove a header. */
  removeHeader(name) {
    this._remove.push(String(name));
    return this;
  }

  /** The body decoded as UTF-8 text, or '' when no body was delivered. */
  text() {
    return this.body ? this.body.toString('utf8') : '';
  }

  /** The body parsed as JSON, or undefined when absent/unparseable. */
  json() {
    if (!this.body) return undefined;
    try {
      return JSON.parse(this.body.toString('utf8'));
    } catch (e) {
      return undefined;
    }
  }

  /** The URL parsed, for convenient access to pathname/query. */
  get parsedUrl() {
    if (!this._parsed) this._parsed = parseUrl(this.url);
    return this._parsed;
  }

  /** A query-string parameter, or undefined. */
  query(name) {
    const v = this.parsedUrl.searchParams.get(name);
    return v === null ? undefined : v;
  }
}

/**
 * Context for the gate.
 *
 * Deliberately shaped like whistle's: return `false` to block, and say what the
 * blocked client should see with `setHtml` / `setUrl` / `setRedirect` /
 * `setLogin`. Each of those clears the others — a refusal has one outcome.
 */
class AuthCtx extends BaseCtx {
  constructor(payload) {
    super(payload);
    this.clientIp = payload.clientIp || undefined;
    this._page = null;
    this._login = false;
    this._status = null;
    this._denied = false;
  }

  /** Block, and serve this HTML. */
  setHtml(html) {
    this._page = html == null ? null : { html: bodyToString(html) };
    return this._deny();
  }

  /** Block, and serve the contents of this URL or file path. */
  setUrl(url) {
    this._page = url ? { url: String(url) } : null;
    this._login = false;
    return this._deny();
  }

  /** Alias of {@link setUrl}, as upstream has. */
  setFile(url) {
    return this.setUrl(url);
  }

  /** Block, and redirect there instead. */
  setRedirect(url) {
    this._page = url ? { redirect: String(url) } : null;
    this._login = false;
    return this._deny();
  }

  /** Ask the client for credentials (401, or 407 with an explicit status). */
  setLogin(login) {
    this._login = login !== false;
    if (this._login) {
      // A login box and a redirect are two different answers to one question.
      if (this._page && (this._page.url || this._page.redirect)) this._page = null;
      this._deny();
    }
    return this;
  }

  /** Status for the block. Only 3xx–5xx: a block is never a success. */
  setStatus(code) {
    this._status = code;
    return this._deny();
  }

  /**
   * Set a header on the request being admitted.
   *
   * Restricted to `x-whistle-*` and `proxy-authorization`, the same names
   * whistle allows — a gate is there to identify a request, not to rewrite it.
   * whix enforces this again on its side, so anything else is dropped
   * whether or not this check runs.
   */
  setHeader(name, value) {
    const key = String(name).toLowerCase();
    if (typeof value !== 'string' || (key.indexOf('x-whistle-') !== 0 && key !== 'proxy-authorization')) {
      return this;
    }
    return super.setHeader(key, value);
  }

  /** Alias of {@link setHeader}, as upstream has. */
  set(name, value) {
    return this.setHeader(name, value);
  }

  /** Mark this request as blocked (implied by every setter above). */
  _deny() {
    this._denied = true;
    return this;
  }

  _result(verdict) {
    // `return false` blocks, as upstream. Any setter also blocks, so a handler
    // that describes a block page but forgets the `return` still blocks.
    const allow = verdict !== false && !this._denied;
    if (allow) {
      const out = { allow: true };
      if (Object.keys(this._set).length) out.setHeaders = this._set;
      return out;
    }
    const out = { allow: false, login: this._login };
    if (this._status != null) out.statusCode = this._status;
    if (this._page) Object.assign(out, this._page);
    return out;
  }
}

/** Context for a stats ping: what happened, with nothing to answer. */
class StatsCtx extends BaseCtx {
  constructor(payload) {
    super(payload);
    /** `'request'` or `'response'`. */
    this.phase = payload.phase === 'response' ? 'response' : 'request';
    this.clientIp = payload.clientIp || undefined;
    /** The upstream status — response phase only. */
    this.statusCode = payload.statusCode;
  }
}

/** Context for the request hook. */
class RequestCtx extends BaseCtx {
  constructor(payload) {
    super(payload);
    this.clientIp = payload.clientIp || undefined;
    this._rules = [];
    this._values = {};
    this._response = null;
  }

  /**
   * Inject whistle rules for this request. Call more than once to add more;
   * they are joined with newlines.
   */
  setRules(rules) {
    if (rules) this._rules.push(String(rules));
    return this;
  }

  /**
   * Values for the `{name}` / `${name}` references in the rules you set — a
   * mock body, a header list. They win over the proxy's own values of the same
   * name, and only your rules see them. A non-string value is sent as JSON.
   * Call more than once to add more; a later name replaces an earlier one.
   */
  setValues(values) {
    Object.assign(this._values, values || {});
    return this;
  }

  /**
   * Answer the request directly, skipping the upstream entirely.
   * `body` may be a string, Buffer, or any JSON-serialisable value.
   */
  respond(response) {
    response = response || {};
    const out = {
      statusCode: response.statusCode || response.status || 200,
      headers: response.headers || {},
    };
    applyBody(out, response.body);
    this._response = out;
    return this;
  }

  _result() {
    const out = {};
    if (this._rules.length) out.rules = this._rules.join('\n');
    if (Object.keys(this._values).length) out.values = this._values;
    if (this._response) out.response = this._response;
    if (Object.keys(this._set).length) out.setHeaders = this._set;
    if (this._remove.length) out.removeHeaders = this._remove;
    return out;
  }
}

/** Context for the response hook. */
class ResponseCtx extends BaseCtx {
  constructor(payload) {
    super(payload);
    this.statusCode = payload.statusCode || 0;
    this._newStatus = null;
    this._newBody = undefined;
  }

  /** Rewrite the response status code. */
  setStatus(code) {
    this._newStatus = code;
    return this;
  }

  /**
   * Replace the response body. A string, Buffer, or JSON-serialisable value.
   *
   * You only receive the original body if the plugin declared
   * `responseBody: true`; replacing it works either way.
   */
  setBody(body) {
    this._newBody = body;
    return this;
  }

  _result() {
    const out = {};
    if (this._newStatus != null) out.statusCode = this._newStatus;
    if (Object.keys(this._set).length) out.setHeaders = this._set;
    if (this._remove.length) out.removeHeaders = this._remove;
    if (this._newBody !== undefined) applyBody(out, this._newBody);
    return out;
  }
}

/** Coerce a page body to text — a block page is text by construction. */
function bodyToString(body) {
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  return typeof body === 'string' ? body : JSON.stringify(body);
}

/**
 * Serialise a body onto `out`, choosing the text or binary field. Buffers go
 * over the wire base64-encoded; everything non-string is JSON-stringified.
 */
function applyBody(out, body) {
  if (body == null) {
    out.body = '';
  } else if (Buffer.isBuffer(body)) {
    out.bodyBase64 = body.toString('base64');
  } else if (typeof body === 'string') {
    out.body = body;
  } else {
    out.body = JSON.stringify(body);
  }
}

module.exports = {
  start,
  transform,
  MAX_BODY_BYTES,
  PIPE_META_HEADER,
  WS_META_HEADER,
  WS_CONTINUATION,
  WS_TEXT,
  WS_BINARY,
};
