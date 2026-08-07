# The whistle-rs console

The web console served on the proxy port: a Vue 3 app that builds to **one
self-contained HTML file**, `dist/index.html`.

## The artifact is committed on purpose

`dist/index.html` is checked in. It is not a build product that happens to be in
the tree by accident — the Rust build reads it with `include_str!`, and requiring
Node to compile a Rust proxy would be a bad trade. Rebuild it and commit it in
the same change as the source you edited.

```sh
npm install     # once
npm run build   # writes dist/index.html
```

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
something to release), a truncated body, a body that is not JSON, a disabled
rule group, and a plugin that has never answered. It is dev-only — `apply:
'serve'` keeps it out of the build. Its state is per-server-process: restart
`npm run dev` to get the held frames back after releasing them.

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
src/sidebar/*.vue       the four source lists, one per pane
src/panes/*.vue         the four panes and the detail tabs
src/components/*.vue    toolbar, side item, card, editor
src/editor/             the rules language for CodeMirror 6
src/styles/app.css      the palette and everything painted with it
```

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
