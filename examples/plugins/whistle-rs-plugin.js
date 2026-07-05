// whistle-rs Node plugin helper (zero dependencies).
//
// A whistle-rs plugin is an HTTP server that speaks the JSON protocol:
//   whistle-rs -> plugin:  POST /  { method, url, headers:[[k,v]…], clientIp, param }
//   plugin -> whistle-rs:  { rules?: "<whistle rules>", response?: { statusCode, headers, body } }
//
// Both `rules` and `response` are optional. `rules` is merged into the resolved
// rule set for the request; `response` short-circuits the upstream request.
//
// Usage (see example-plugin.js):
//   const { start } = require('./whistle-rs-plugin');
//   start((req) => ({ rules: '…', response: { statusCode: 200, body: '…' } }));
//
// whistle-rs launches the plugin with:
//   node your-plugin.js   (env WHISTLE_RS_PLUGIN_PORT, WHISTLE_RS_PLUGIN_NAME)

const http = require('http');

function start(dispatch) {
  const port = parseInt(process.env.WHISTLE_RS_PLUGIN_PORT || '0', 10);
  const name = process.env.WHISTLE_RS_PLUGIN_NAME || 'plugin';

  const server = http.createServer((req, res) => {
    let chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      let ctx = {};
      try {
        ctx = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      } catch (e) {
        ctx = {};
      }
      // Convenience: expose headers as both the raw pairs and a lookup map.
      ctx.header = (n) => {
        n = String(n).toLowerCase();
        const found = (ctx.headers || []).find((p) => String(p[0]).toLowerCase() === n);
        return found ? found[1] : undefined;
      };
      let result;
      try {
        result = (await dispatch(ctx)) || {};
      } catch (e) {
        console.error('[' + name + '] dispatch error:', e && e.stack || e);
        result = {};
      }
      const body = JSON.stringify(result || {});
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(body);
    });
  });

  server.listen(port, '127.0.0.1', () => {
    console.error('[whistle-rs plugin ' + name + '] listening on 127.0.0.1:' + port);
  });
  return server;
}

module.exports = { start };
