// A whix plugin that reads the request body and rewrites the response
// body — the two cases that need an explicit opt-in.
//
//   whix --node-plugin rewrite=examples/plugins/body-rewrite.js
//   # rule:  example.com plugin://rewrite
//
// `requestBody` / `responseBody` are what make the bodies show up on `ctx.body`.
// Without them the proxy streams both bodies straight through and never buffers
// — so only ask for what you actually read.

const { start } = require('../../sdk/whix-plugin');

start({
  name: 'rewrite',
  requestBody: true,
  responseBody: true,

  onRequest(ctx) {
    const sent = ctx.json();
    if (sent && sent.mock === true) {
      // Echo the request body straight back without contacting the upstream.
      return ctx.respond({ statusCode: 200, body: { echoed: sent } });
    }
    if (ctx.body) {
      ctx.setHeader('x-req-body-bytes', String(ctx.body.length));
    }
  },

  onResponse(ctx) {
    const text = ctx.text();
    if (!text) return;

    // Rewrite JSON responses by adding a field; leave everything else alone.
    const data = ctx.json();
    if (data && typeof data === 'object') {
      ctx.setBody({ ...data, rewrittenBy: 'whix' });
      ctx.setHeader('x-rewritten', 'json');
    } else {
      ctx.setBody(text.replace(/whistle/gi, 'whix'));
      ctx.setHeader('x-rewritten', 'text');
    }
  },
});
