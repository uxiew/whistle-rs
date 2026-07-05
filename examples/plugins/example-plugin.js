// Example whistle-rs Node plugin.
//
// Run it via whistle-rs:
//   whistle-rs --node-plugin demo=examples/plugins/example-plugin.js \
//              --rule 'example.com plugin://demo'
//
// Then requests matching `plugin://demo` are dispatched here. This example
// shows both hooks:
//   * plugin://demo/mock  → returns a mock JSON response (the `response` hook)
//   * plugin://demo       → injects response headers via rules (the `rules` hook)

const { start } = require('./whistle-rs-plugin');

start((req) => {
  // req = { method, url, headers:[[k,v]…], clientIp, param, header(name) }

  // `plugin://demo/mock` → serve a mock response, skipping the real server.
  if (req.param === 'mock') {
    return {
      response: {
        statusCode: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({
          plugin: 'demo (node)',
          youRequested: req.url,
          method: req.method,
          ua: req.header('user-agent') || null,
        }),
      },
    };
  }

  // Otherwise → inject whistle rules for this request (applied then proxied).
  return {
    rules: [
      '* resHeaders://x-node-plugin=demo',
      '* reqHeaders://x-node-plugin-req=' + (req.param || '1'),
    ].join('\n'),
  };
});
