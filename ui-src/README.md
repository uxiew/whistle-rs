# The whistle-rs console

The web console served on the proxy port: a Vue 3 app that builds to **one
self-contained HTML file**, `dist/index.html`.

## Build it before you build the proxy

`dist/index.html` is **not** in the repository: it is a 445 KB bundle that is
rewritten end to end by every build, which makes every console change an
unreadable diff. Build it here, and the Rust build inlines it.

```sh
npm ci          # once; installs exactly what package-lock.json pins
npm run build   # writes dist/index.html
```

Requiring Node to compile a Rust proxy would still be a bad trade, so it is not
required. `build.rs` copies `dist/index.html` into `OUT_DIR` when it exists and
writes a placeholder page there when it does not — `cargo build` succeeds either
way, with a warning naming what is missing. A binary built without the console
serves every API route as usual; only `/` is the placeholder, and it says so.

The console is inlined at **compile** time, so building it after the proxy
changes nothing until the proxy is rebuilt. `cargo build` notices the new file
by itself (`rerun-if-changed`); it is the `cargo build` you have to remember.

The output has no external references at all: no chunks, no CDN, no fonts, no
images. It has to load with the network it is inspecting switched off, which is
also why the whole editor is inlined rather than fetched. If a build ever emits a
second file, or the HTML grows a `src=`/`href=` that points off the page, that is
a bug — check `vite.config.ts`.

## Developing

```sh
npm run dev       # localhost:5199, against a mock of the proxy's API
npm run preview   # the built dist/index.html, against the same mock
npm run typecheck # vue-tsc
```

`mock/api.ts` is a Vite plugin that answers every route `src/proxy/webui.rs`
answers, with a fixture chosen to reach the corners: a failed request, a request
that timed out with status 0, a WebSocket with frames (one dropped by
`enable://ignoreSend`, two held by `enable://pauseSend` so the release control has
something to release), a truncated body, a body that is not JSON, an image, a
binary body that is neither text nor an image and is truncated as well, a
disabled rule group, and a plugin that has never answered. It is dev-only —
`apply: 'serve'` keeps it out of the build. Its state is per-server-process:
restart `npm run dev` to get the held frames back after releasing them.


## Layout

```
index.html              the shell; carries the __VERSION__/__HOST__/__PORT__ stamp
src/main.ts             theme first, then mount
src/App.vue             toolbar + source list + work area, and the keyboard
src/api.ts              every endpoint of the proxy's API, typed
src/store.ts            one reactive store (see the note at the top of it)
src/columns.ts          the request table's columns
src/format.ts           bytes, times, hosts, JSON
src/curl.ts             the request as a curl command
src/sidebar/*.vue       the five source lists, one per pane
src/panes/*.vue         the five panes, the detail tabs and the timing waterfall
src/components/*.vue    toolbar, side item, card, editor, import/export
src/editor/             the rules language for CodeMirror 6
src/styles/app.css      the palette and everything painted with it
```

## The Composer

`panes/ComposerPane.vue` writes a request by hand and posts it to
`/api/composer`, which sends it **through the proxy's own port** — the same
loopback hop Replay uses (`send_through_self`, `src/proxy/webui.rs`). So a
composed request is matched, rewritten and captured like any other, and
`from:composer` matches it. Nothing here speaks to an origin directly, and
nothing should: a Composer that did would only be a second `curl`.

"Edit & Resend" in the detail panel seeds it from a captured request — the
reverse of `curl.ts`, and the reason most compositions exist. The draft and the
last twenty sent requests live in `localStorage`, because the page you are
reloading is served by the proxy you are reconfiguring.

## The rules editor

`src/editor/whistle-classify.js` decides which token on a line is the *pattern* —
the thing the proxy will actually match on. It is deliberately plain script-shaped
JavaScript with no imports and no CodeMirror dependency, because it is evaluated
in two places: bundled here, and run as a script by a Rust test that holds its
answers against the parser's own `split_line`. Do not turn it into a module, and
do not copy it: two of them would drift, and the drift is the bug it exists to
prevent.

`whistle-language.ts` wraps it as a CodeMirror 6 `StreamLanguage`. Note the
constraint recorded there: the token names it emits must not be CodeMirror 5's
legacy names (`def`, `keyword`, `variable-2`, `error`, …), which version 6
resolves against a built-in table before consulting the language's own.
