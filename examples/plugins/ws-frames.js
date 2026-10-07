// A whix *WebSocket frame* plugin: it sees every data frame of a
// tunnelled WebSocket, in both directions, and may rewrite or drop it.
//
//   whix --node-plugin wschat=examples/plugins/ws-frames.js
//   # rule:  ws.example.com  pipe://wschat
//   #        ws.example.com  pipe://wschat(demo)     <- ctx.pipeValue === 'demo'
//
// Either rule scheme reaches this hook: a WebSocket has no
// buffered-versus-streaming choice for `plugin://` and `pipe://` to express.
//
// The frame waits for whatever this function does, in both directions, so keep
// it cheap. See docs/PLUGINS.md for the measured cost.

const { start } = require('../../sdk/whix-plugin');

start({
  name: 'wschat',

  onWsFrame(frame, ctx) {
    // ---- The one discipline: binary frames are bytes, not text. -----------
    //
    // `frame.payload` is a Buffer and must stay one. `Buffer.from(buf.toString())`
    // replaces every byte that is not valid UTF-8 with U+FFFD — an 8 MB upload
    // comes back as 15 MB of mojibake.
    //
    // `isText` is a *whole* text message, which is the only thing `frame.text`
    // is safe on: a fragment can split a multi-byte character down the middle.
    // Everything else — binary, fragments, continuations — goes straight
    // through here. Reassemble across `frame.isFragment` if you need them.
    if (!frame.isText) {
      if (frame.isBinary || frame.isFragment) {
        const kind = frame.isBinary ? 'binary' : `fragment(op ${frame.opcode})`;
        console.log(`[wschat] ${frame.direction} ${kind} ${frame.payload.length}B (untouched)`);
      }
      return; // returning nothing forwards frame.payload as it arrived
    }

    const tag = ctx.pipeValue || ctx.param || 'wschat';
    const text = frame.text;

    // Drop a frame by returning null. It reaches neither the peer nor the
    // Network view: as far as the other end is concerned it never happened.
    if (text.includes('SECRET')) {
      console.log(`[wschat] dropped a ${frame.direction} frame`);
      return null;
    }

    // Rewrite by returning a string (encoded UTF-8), a Buffer, or any JSON
    // value. Both directions are hooked, so a plugin can annotate what the
    // client says and what the server answers.
    if (frame.direction === 'send') {
      return `${text} [${tag} → server]`;
    }
    return `${text} [${tag} → client]`;
  },
});
