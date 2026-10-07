// A whix *gate*: it decides whether a request may proceed, keeps a tally
// of what it saw, and serves that tally as its own page.
//
//   whix --node-plugin gate=examples/plugins/token-gate.js
//   # rule:  example.com  plugin://gate/s3cret
//   # page:  http://127.0.0.1:<proxy port>/plugin/gate/
//
// Three hooks, none of which rewrites traffic:
//
//   onAuth      — the gate. Blocks a request, or admits it with an identity.
//   onResStats  — told how each request turned out. Nothing waits for it.
//   onUi        — an ordinary HTTP handler for the plugin's own pages.
//
// The gate is the one hook in this SDK that **fails closed**: if it throws, or
// this process is not reachable, whix blocks the matched requests with a
// 502 rather than letting them through. A gate that admits everything when it
// breaks is not a gate. Everything else here degrades the other way — a stats
// hook that dies costs the request nothing at all.

const { start } = require('../../sdk/whix-plugin');

const seen = { admitted: 0, blocked: 0, byStatus: {} };

start({
  name: 'gate',

  onAuth(ctx) {
    // `plugin://gate/s3cret` puts `s3cret` in ctx.param; with no param, any
    // token will do.
    const expected = ctx.param;
    const token = ctx.header('x-gate-token') || ctx.query('token');

    if (!token) {
      seen.blocked++;
      // 401 + www-authenticate, so a browser offers a login box.
      ctx.setLogin(true).setHtml('<h1>401</h1><p>No <code>x-gate-token</code>.</p>');
      return false;
    }
    if (expected && token !== expected) {
      seen.blocked++;
      // Other shapes, all of which stop the request here:
      //   ctx.setRedirect('https://sso.example.com/login')  -> 302
      //   ctx.setFile('/etc/whistle/blocked.html')          -> that file, 403
      //   ctx.setStatus(451)                                -> any 3xx-5xx
      ctx.setHtml('<h1>403</h1><p>Wrong token.</p>');
      return false;
    }

    seen.admitted++;
    // Identify the caller for everything downstream. Only `x-whistle-*` and
    // `proxy-authorization` survive — a gate is not a header rewriter.
    ctx.setHeader('x-whistle-gate-token', token);
  },

  onResStats(ctx) {
    seen.byStatus[ctx.statusCode] = (seen.byStatus[ctx.statusCode] || 0) + 1;
  },

  onUi(req, res) {
    // `req.url` arrives with `/plugin/gate` already stripped, so this handler
    // owns its own URL space. Relative links work because the browser's URL
    // keeps the trailing slash.
    if (req.url === '/stats.json') {
      return seen; // a non-string return is sent as JSON
    }
    if (req.url !== '/') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('not found');
    }
    const rows = Object.keys(seen.byStatus)
      .map((s) => `<tr><td>${s}<td>${seen.byStatus[s]}`)
      .join('');
    return `<!doctype html><meta charset=utf-8><title>gate</title>
      <style>body{font:14px/1.6 system-ui;margin:2rem}td{padding:.2rem 1rem .2rem 0}</style>
      <h1>plugin://gate</h1>
      <p>admitted <b>${seen.admitted}</b>, blocked <b>${seen.blocked}</b></p>
      <table>${rows || '<tr><td>no responses yet'}</table>
      <p><a href="stats.json">stats.json</a></p>`;
  },
});
