// A minimal whistle-rs plugin: inject a rule, and mock one path.
//
//   whistle-rs --node-plugin hello=examples/plugins/hello.js
//   # then add a rule:  example.com plugin://hello
//
// Replaces the older example that hand-rolled the HTTP/JSON protocol — the SDK
// handles the wire format, the manifest, and error isolation.

const { start } = require('../../sdk/whistle-rs-plugin');

start({
  name: 'hello',

  onRequest(ctx) {
    // `plugin://hello/mock` — answer directly, never reaching the upstream.
    if (ctx.param === 'mock') {
      return ctx.respond({
        statusCode: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: { hello: 'from whistle-rs', url: ctx.url, method: ctx.method },
      });
    }

    // Otherwise tag the request on its way out, and inject a rule that tags
    // the response on its way back.
    ctx.setHeader('x-hello-plugin', '1');
    ctx.setRules('* resHeaders://x-hello-rule=1');
  },

  onResponse(ctx) {
    ctx.setHeader('x-hello-elapsed', String(ctx.id));
  },
});
