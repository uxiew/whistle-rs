// A whix *streaming* plugin: it transforms the response body as it flows,
// event by event, instead of waiting for the whole thing.
//
//   whix --node-plugin events=examples/plugins/stream-events.js
//   # rule:  example.com pipe://events
//   #        example.com pipe://events(SHOUT)      <- ctx.pipeValue === 'SHOUT'
//
// Note the rule scheme: `pipe://` reaches the streaming hooks, `plugin://` the
// buffered ones. There is no `responseBody: true` here and there must not be —
// a pipe hook never asks the proxy to hold a body in memory. Point it at an SSE
// endpoint and the events still arrive one at a time, transformed on the way.

const { start, transform } = require('../../sdk/whix-plugin');

start({
  name: 'events',

  // Tag every SSE `data:` line as it goes past, and count the events.
  //
  // Returning a Transform is all it takes; the SDK wires
  // upstream → transform → client. `req`/`res` are the raw streams if you would
  // rather drive the pipeline yourself.
  pipeResponse(req, res, ctx) {
    // A *text* transform must never touch a binary body: decoding arbitrary
    // bytes as UTF-8 and re-encoding them replaces every invalid sequence with
    // U+FFFD, which silently corrupts (and inflates) the body. Wire the streams
    // straight through instead — that is the whole cost of opting out.
    if (!/^text\/event-stream\b/i.test(ctx.header('content-type') || '')) {
      req.pipe(res);
      return;
    }

    const prefix = ctx.pipeValue || 'seen';
    let events = 0;
    let pending = '';

    return transform(
      (chunk) => {
        // SSE frames are newline-delimited, but a chunk may split one — keep
        // the tail until its newline arrives rather than corrupting the frame.
        pending += chunk.toString('utf8');
        const cut = pending.lastIndexOf('\n');
        if (cut === -1) return null;
        const ready = pending.slice(0, cut + 1);
        pending = pending.slice(cut + 1);
        return ready.replace(/^data: ?(.*)$/gm, (_, body) => {
          events += 1;
          return `data: [${prefix} #${events}] ${body}`;
        });
      },
      // Flush whatever never got its newline, so nothing is dropped at EOF.
      () => pending || undefined
    );
  },

  // Streaming works on the way up too: this one just counts bytes and leaves
  // them alone, which is what a request-body inspector looks like.
  pipeRequest(req, res, ctx) {
    let bytes = 0;
    return transform(
      (chunk) => {
        bytes += chunk.length;
        return chunk;
      },
      () => {
        console.log(`[events] ${ctx.method} ${ctx.url} uploaded ${bytes} bytes`);
        return undefined;
      }
    );
  },
});
