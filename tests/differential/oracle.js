// Real whistle, on a fixed port, with a storage directory of its own.
//
// Kept apart from the bench so the oracle can be left running between runs —
// whistle takes a few seconds to come up and there is no reason to pay it
// twice.
const whistle = require('whistle');
const path = require('path');

whistle(
  {
    port: Number(process.env.PORT_BASE || 18700),
    // A directory per port, so several oracles can run side by side.
    baseDir: path.join(__dirname, `.data-${process.env.PORT_BASE || 18700}`),
  },
  () => console.log('whistle listening on', process.env.PORT_BASE || 18700),
);
