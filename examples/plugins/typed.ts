// A whistle-rs plugin written in TypeScript.
//
// The SDK ships its own .d.ts, so hooks, contexts and the capability flags are
// all typed. `satisfies Plugin` checks the shape without widening it, so
// `ctx` stays precisely typed inside each hook.
//
// Build, then run the emitted JS:
//   npx tsc examples/plugins/typed.ts --outDir /tmp/p --module commonjs --target es2020
//   whistle-rs --node-plugin typed=/tmp/p/typed.js
//
// Or run it directly with a TS-aware loader:
//   whistle-rs --node-plugin typed=examples/plugins/typed.ts   # needs NODE_OPTIONS=--import=tsx

import {
  start,
  transform,
  type Plugin,
  type PipeCtx,
  type RequestCtx,
  type ResponseCtx,
} from '../../sdk/whistle-rs-plugin';

interface ApiPayload {
  userId?: number;
}

const plugin = {
  name: 'typed',
  version: '1.0.0',
  // Only the request body is read, so the response keeps streaming.
  requestBody: true,

  async onRequest(ctx: RequestCtx) {
    const payload = ctx.json<ApiPayload>();
    if (payload?.userId != null) {
      ctx.setHeader('x-user-id', String(payload.userId));
    }

    // Route on the `plugin://typed/<param>` suffix.
    if (ctx.param === 'block') {
      ctx.respond({ statusCode: 403, body: { error: 'blocked by the typed plugin' } });
      return;
    }

    if (ctx.query('debug') === '1') {
      ctx.setRules('* resHeaders://x-debug=1');
    }
  },

  async onResponse(ctx: ResponseCtx) {
    ctx.setHeader('x-handled-by', `typed/${ctx.id}`);
    if (ctx.statusCode >= 500) {
      ctx.setStatus(503).setBody({ error: 'upstream unavailable' });
    }
  },

  // The streaming hook, reached by `pipe://typed` rather than `plugin://typed`.
  // It needs no body flag — nothing is buffered — and sees each chunk as it
  // arrives. Returning the Transform is enough; the SDK wires the pipeline.
  pipeResponse(_src, _dest, ctx: PipeCtx) {
    let bytes = 0;
    return transform((chunk) => {
      bytes += chunk.length;
      return chunk;
    }, () => {
      console.log(`[typed] ${ctx.url} streamed ${bytes} bytes (${ctx.pipeValue ?? 'no value'})`);
      return undefined;
    });
  },
} satisfies Plugin;

start(plugin);
