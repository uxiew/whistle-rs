// Real whistle, on a fixed port, with a storage directory of its own.
//
// Kept apart from the bench so the oracle can be left running between runs —
// whistle takes a few seconds to come up and there is no reason to pay it
// twice.
const whistle = require('whistle');
const path = require('path');

whistle(
  { port: Number(process.env.W_PORT || 18700), baseDir: path.join(__dirname, '.data') },
  () => console.log('whistle listening on', process.env.W_PORT || 18700),
);
