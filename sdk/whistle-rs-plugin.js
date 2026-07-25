'use strict';
//
// whistle-rs plugin SDK — zero dependencies, Node's stdlib only.
//
// A plugin is a plain object with a `name` and one or both hooks:
//
//   const { start } = require('whistle-rs-plugin');
//
//   start({
//     name: 'my-plugin',
//     async onRequest(ctx) { ctx.setRules('example.com resHeaders://x-t=1'); },
//     async onResponse(ctx) { ctx.setHeader('x-powered-by', 'whistle-rs'); },
//   });
//
// `start` speaks the HTTP/JSON protocol for you, including the capability
// manifest: it derives `hooks` from which handlers you defined, and gates body
// delivery on the `requestBody` / `responseBody` flags. Declaring a body you do
// not need costs the proxy its streaming fast path, so both default to false.
//
// TypeScript users: see whistle-rs-plugin.d.ts. The same entry point works for
// `export default { … }` — an ES module default export is unwrapped.

const http = require('http');

/** Bodies larger than this are refused rather than buffered without bound. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;

/**
 * Start the plugin server.
 *
 * The port and name come from the environment whistle-rs spawns us with
 * (`WHISTLE_RS_PLUGIN_PORT`, `WHISTLE_RS_PLUGIN_NAME`); pass `opts.port` to
 * run standalone, e.g. in tests.
 */
function start(plugin, opts) {
  plugin = unwrapDefault(plugin);
  if (!plugin || (typeof plugin.onRequest !== 'function' && typeof plugin.onResponse !== 'function')) {
    throw new TypeError('whistle-rs plugin: define at least one of onRequest / onResponse');
  }
  opts = opts || {};

  const port = opts.port != null ? opts.port : parseInt(process.env.WHISTLE_RS_PLUGIN_PORT || '0', 10);
  const name = plugin.name || process.env.WHISTLE_RS_PLUGIN_NAME || 'plugin';

  const manifest = {
    name,
    version: plugin.version || '1',
    hooks: [
      typeof plugin.onRequest === 'function' ? 'request' : null,
      typeof plugin.onResponse === 'function' ? 'response' : null,
    ].filter(Boolean),
    requestBody: plugin.requestBody === true,
    responseBody: plugin.responseBody === true,
  };

  const server = http.createServer((req, res) => {
    const route = req.url.split('?')[0];

    if (route === '/manifest') {
      return sendJson(res, 200, manifest);
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
    console.log(`[${name}] whistle-rs plugin listening on 127.0.0.1:${bound} (hooks: ${manifest.hooks.join(', ') || 'none'})`);
  });
  return server;
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
    const want = String(name).toLowerCase();
    for (const [k, v] of this.headers) {
      if (String(k).toLowerCase() === want) return v;
    }
    return undefined;
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
    if (!this._parsed) {
      try {
        this._parsed = new URL(this.url);
      } catch (e) {
        this._parsed = new URL('http://invalid.local/');
      }
    }
    return this._parsed;
  }

  /** A query-string parameter, or undefined. */
  query(name) {
    const v = this.parsedUrl.searchParams.get(name);
    return v === null ? undefined : v;
  }
}

/** Context for the request hook. */
class RequestCtx extends BaseCtx {
  constructor(payload) {
    super(payload);
    this.clientIp = payload.clientIp || undefined;
    this._rules = [];
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

module.exports = { start, MAX_BODY_BYTES };
