# whistle-rs

**English** · [简体中文](README.zh-CN.md) · [路线图 / Roadmap](docs/ROADMAP.md)

A Rust port of the **core** of [whistle](https://wproxy.org) — an HTTP / HTTPS /
WebSocket debugging proxy. It implements the load-bearing heart of whistle: the
**rules DSL engine**, the **proxy server** (HTTP forward proxy + CONNECT tunnelling +
HTTPS man-in-the-middle), and **dynamic CA certificate generation**.

The original JavaScript source is **not distributed with this repository** — see
[`docs/UPSTREAM.md`](docs/UPSTREAM.md) for how to fetch it, and at which commit. This port maps
module-for-module onto it (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).

## Contents

- [Features](#features)
- [Install & build](#install--build)
- [Quick start](#quick-start)
- [Configure your client](#configure-your-client)
- [Intercepting HTTPS](#intercepting-https)
- [Writing rules](#writing-rules)
- [Cookbook](docs/COOKBOOK.md) — recipes for the things people actually do
- [Use as a library](#use-as-a-library)
- [CLI reference](#cli-reference)
- [Documentation](#documentation)
- [Scope: what's ported vs. stubbed](#scope-whats-ported-vs-stubbed)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## Features

- **HTTP forward proxy** — standard absolute-form proxying.
- **HTTPS MITM** — `CONNECT` interception with per-host certificates signed on the fly
  by a locally generated, persisted root CA.
- **HTTP/2** — intercepted TLS connections negotiate `h2` via ALPN and are served
  over HTTP/2 (upstream stays HTTP/1.1; hyper translates), falling back to HTTP/1.1.
- **WebSocket** — `ws://` and (via MITM) `wss://` upgrades are tunnelled end-to-end,
  with every frame captured and surfaced in the Network view.
- **Upstream proxies** — route through another HTTP/HTTPS proxy or a SOCKS5 proxy.
- **Inbound SOCKS5 server** — accept SOCKS5 clients (`--socks-port`) into the same
  interception pipeline, auto-detecting TLS vs. plain HTTP.
- **Rules engine** — whistle's rule syntax: domain/prefix, leading-dot subdomain,
  host wildcards, `^`-prefixed path/query wildcards with `$1`…`$9` captures, and regex
  patterns; `lineProps://important` precedence; multi-match accumulation.
- **Forwarding** — point a site at a dev server with a bare URL
  (`www.example.com http://localhost:5173`); the request's remaining path comes along.
- **Destination override** (`host://`) that rewrites the target IP/port while keeping
  the original `Host` header and TLS SNI — the defining behaviour of a debug proxy.
- **Request/response rewriting** — headers, cookies, body (replace/prepend/append/
  regex), URL/query, user-agent, method, content-type, CORS, auth, delays, status
  replacement, redirects, and local file serving.
- **Console** — a self-contained page (open the proxy host in a browser): a source
  list, a sortable request table, and the selected request's headers and bodies in a
  detail panel below it. Arrow keys walk the capture, `Copy as cURL` reproduces a
  request as the origin saw it, and a JSON body can be re-indented in place. A Status
  pane reports ports, TLS posture, the root CA path and the registered plugins.
- **Rules editor with syntax highlighting** — CodeMirror 6 with a whistle-specific mode
  that marks *which token the proxy will match on*, which is the one thing a rules
  file gets wrong silently. The mode runs the parser's own line split, and a test
  holds the two together. The console is a Vue 3 app built to a single
  self-contained file — see [`ui-src/`](ui-src/).
- **Traffic inspection** — each transaction records its request/response headers and a
  bounded body preview (captured via a streaming tee, so chunked/SSE responses are
  inspectable without breaking streaming; `gzip`/`deflate`/`br` bodies are decoded for
  the preview). Filter and sort in the console, fetch `/sessions.json` +
  `/session.json?id=`, or export everything as a HAR file (`/sessions.har`).
- **Session persistence** — captured traffic is written to JSONL files with daily
  rotation; sessions survive restarts and load automatically. Configurable with
  `--no-persist` and `--persist-days`.
- **Request replay** — re-send a captured request through the proxy pipeline via
  `POST /api/replay` or the Replay button.
- **Rule groups** — several named rule sets, listed alongside the default one in the
  console's source list; each can be enabled or disabled on its own (double-click).
  Groups persist to `storage_dir/rules/`.
- Single static binary, no C toolchain needed to build (pinned `ring` TLS provider).

## Install & build

Requires a recent stable Rust toolchain.

```bash
cargo build --release
# binary at ./target/release/whistle-rs
```

The proxy needs nothing else. The **web console** is a separate Vite bundle that
is generated rather than committed, so build it first if you want it — the Rust
build inlines it, and serves a placeholder page at `/` (with a build warning
naming what is missing) when it has not been built:

```bash
cd ui-src && npm install && npm run build && cd ..
cargo build --release
```

## Quick start

```bash
# start on the whistle default port 8899, loading a rules file
./target/release/whistle-rs -p 8899 -r rules.txt

# or with an inline rule and verbose logging
./target/release/whistle-rs --rule "test.local 127.0.0.1:9099" -v
```

A ready-made [`rules.txt`](rules.txt) is included. On startup you'll see the listen
address and the root-CA location logged.

## Configure your client

Point your client's **HTTP and HTTPS** proxy at `HOST:PORT` (default
`127.0.0.1:8899`).

```bash
# curl
curl -x http://127.0.0.1:8899 http://example.com/

# a whole shell session
export http_proxy=http://127.0.0.1:8899 https_proxy=http://127.0.0.1:8899
```

**Browser / OS:** set the system or browser HTTP+HTTPS proxy to the same host/port.
For a device on your LAN, use your machine's IP instead of `127.0.0.1` and make sure
the port is reachable.

Open <http://127.0.0.1:8899/> directly (not through the proxy) to see the status page,
which lists recent captured traffic. `GET /sessions.json` returns the same data as JSON,
and `GET /proxy.pac` serves a PAC file that auto-configures a client to use this proxy.

## Intercepting HTTPS

HTTPS traffic is encrypted, so to read/rewrite it whistle-rs presents a certificate it
signs itself. Your client must trust the root CA first:

1. Start whistle-rs and download the CA from <http://127.0.0.1:8899/rootCA.crt>
   (or copy `~/.whistle-rs/certs/root.crt`).
2. Install & trust it in your OS/browser — **step-by-step per platform in
   [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md)**.
3. Verify:

   ```bash
   curl -x http://127.0.0.1:8899 \
        --cacert ~/.whistle-rs/certs/root.crt \
        https://example.com/ -D - -o /dev/null   # → HTTP/1.1 200 OK
   ```

## Writing rules

Each line is `pattern operator1 operator2 …`. A few examples:

```
# serve a site from a local dev server (the path follows the request)
www.example.com       http://localhost:5173

# map a domain to another address, keeping its Host header (hosts shorthand)
test.local            127.0.0.1:9099

# explicit destination override (applies to http + https)
.cdn.example.com      host://10.0.0.9

# regex pattern → set a response content-type
/\.js(\?|$)/          resType://application/javascript

# host wildcard → redirect (short-circuits upstream)
*.old.example.com     redirect://https://new.example.com/

# `^` makes every `*` a wildcard, and $1… are what they matched
^http://*.example.com/v0/users/**   file:///mock/$1/$2

# inject headers (these accumulate across lines)
example.com           reqHeaders://x-token=abc
example.com           resHeaders://x-mitm=intercepted

# lineProps://important wins over normal rules, whatever the line order
example.com           host://2.2.2.2  lineProps://important

# $-prefix = exact match: the site root, and nothing under it
$example.com          host://3.3.3.3
```

Three things about that grammar are worth knowing before you write a rules file,
because each one produces a rule that silently does nothing:

- **Position decides, not shape.** The first token is the pattern and everything
  after it is an operator — `example.com http://localhost:5173` is a forwarding
  rule, not two patterns.
- **An operator value cannot contain a space.** `reqHeaders://authorization=Bearer secret`
  sets `authorization: Bearer` and then sends the request to a host called
  `secret`. Use a named value and `${name}`.
- **`file`, `redirect`, `statusCode`, the template family and a bare destination
  URL share one slot**, first line wins — so a mock written *below* a forward
  never runs.

**Recipes for the tasks people actually have — point a site at a dev server,
mock an endpoint, throttle a connection, debug a phone, export a HAR — are in
[`docs/COOKBOOK.md`](docs/COOKBOOK.md). The full syntax — every pattern kind and
operator, precedence rules, coverage — is in
[`docs/RULES.md`](docs/RULES.md).**

## Use as a library

whistle-rs is a library with a binary on top, not the other way round. If you are
building something that needs traffic interception or API debugging *inside* it —
a proxy of your own, a test harness, a desktop app — embed it:

```toml
[dependencies]
whistle-rs = { path = "…" }   # or a git/crates.io dependency
tokio = { version = "1", features = ["full"] }
```

```rust
use whistle_rs::embed::Proxy;

let proxy = Proxy::builder()
    .port(0)                        // 0: the OS picks; addr() reports which
    .host("127.0.0.1".parse()?)     // keep it off the network
    .rules("api.example.com  http://127.0.0.1:3000")
    .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
    .start()
    .await?;

println!("point your client at {}", proxy.addr());
proxy.set_rules("api.example.com  statusCode://503");   // live
proxy.shutdown().await;
```

To *change* traffic rather than watch it, register an in-process hook. It is the
same `RustPlugin` trait the built-in plugins use, so it can rewrite request
headers, inject rules, answer the request outright, gate it, transform the
response, or choose the TLS certificate:

```rust
struct MockApi;

impl RustPlugin for MockApi {
    fn name(&self) -> &str { "mock-api" }
    fn on_request(&self, req: &PluginReq) -> PluginResult {
        PluginResult {
            response: Some(PluginResp { status: 200, headers: vec![], body: b"{}".to_vec() }),
            ..Default::default()
        }
    }
}

Proxy::builder().plugin(MockApi).rules("api.test  plugin://mock-api")
```

`cargo run --example embedded` runs all of the above end to end. The builder also
covers a SOCKS5 port, the storage directory (two embedders sharing one share a
CA), values, the body-capture cap, and `intercept_https(false)` for routing TLS
without decrypting it. Anything past the facade is reachable through
`proxy.state()` — the session ring, the rules manager, the plugin registry, the
CA.

## CLI reference

| Flag | Meaning | Default |
|------|---------|---------|
| `-p, --port <PORT>` | Proxy port | `8899` |
| `-H, --host <IP>` | Bind address | all interfaces (`0.0.0.0`) |
| `--socks-port <PORT>` | Also run an inbound SOCKS5 server | off |
| `--plugin <NAME=HOST:PORT>` | Register a remote (Node/HTTP) plugin (repeatable) | — |
| `--node-plugin <NAME=PATH>` | Spawn a Node plugin from a script (repeatable) | — |
| `--value <NAME=CONTENT>` | Define a named value (repeatable); referenced by `{name}` | — |
| `-r, --rules <FILE>` | Rules file to load at startup | — |
| `--rule <TEXT>` | Inline rules, applied after `--rules` | — |
| `--dir <DIR>` | Storage dir (root CA etc.) | `~/.whistle-rs` |
| `--body-preview-limit <BYTES>` | Max captured body bytes kept per transaction | `16384` |
| `--no-persist` | Disable session persistence (in-memory only) | persist on |
| `--persist-days <N>` | Days of session history to retain on disk | `7` |
| `-R, --req-cache-size <N>` | Captured requests kept in memory (whistle's `-R`). Values under the default are ignored, as upstream ignores them | `600` |
| `-F, --frame-cache-size <N>` | Captured WebSocket frames kept in memory (whistle's `-F`). Upstream's floor is written against 720 and lands on 600, so anything between is the default | `600` |
| `--insecure-upstream` | Do **not** verify the origin's TLS certificate. whistle-rs verifies by default, unlike upstream — see [Origin certificate verification](docs/RULES.md#origin-certificate-verification) | verify on |
| `--no-intercept-https` | Do not decrypt HTTPS: relay every TLS connection untouched, still routing it by its rules (whistle's `-M pureProxy`) | intercept on |
| `-t, --timeout <MS>` | How long a connection to an origin or upstream proxy may take to *establish*. Never cuts short a connection that did establish, so streams are unaffected. It only ever **tightens**: a hard 16s ceiling sits underneath, so the default means 16s and this matters only below that | `360000` |
| `-v, --verbose` | Debug logging — the reason behind a failure, which the `502` alone will not tell you | off |
| `-h, --help` / `-V, --version` | Help / version | — |

### `whistle-rs explain` — which rules would this request hit?

whistle's console has this as *Test Rules*; here it is a subcommand, and it
starts nothing — no server, no storage directory, no CA. It answers the question
a rules file poses most often, because **a rule that does not match reports
nothing**: a working line and a silently inert one look identical from the
client side.

```console
$ whistle-rs explain --rules rules.txt -X POST -H 'x-env: staging' \
    'http://www.example.com/api/list?id=2'
http://www.example.com/api/list?id=2
  rule        http://localhost:5173/api/list?id=2   [slot]
      on: www.example.com http://localhost:5173
  reqHeaders  x-env=staging
      on: www.example.com/api reqHeaders://x-env=staging
```

`[slot]` marks the operator that won the [shared
slot](docs/RULES.md#short-circuit-no-upstream-request-is-made) — the losers are
absent entirely, which is the answer to "why is my mock being ignored". Add
`--body` for the `b:` filter conditions, `--client-ip` for `clientIp:`,
`--value NAME=CONTENT` for the values store, `--json` for a machine, and
`--batch` to answer one JSON query per line from stdin. That last one is how
`tests/differential/rules-oracle.js` puts 17k questions through this port and
through whistle's own parser and compares the answers.

## Documentation
- [`docs/UPSTREAM.md`](docs/UPSTREAM.md) — where to fetch the upstream whistle tree the 513 `_original/…` citations point at, and at which commit


| Doc | Contents |
|-----|----------|
| [`docs/COOKBOOK.md`](docs/COOKBOOK.md) | Task-oriented recipes: dev server, mocks, rewriting, throttling, phones, HAR, embedding — start here |
| [`docs/RULES.md`](docs/RULES.md) | Complete rule syntax: patterns, operators, precedence, quick reference, compatibility |
| [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md) | Downloading, installing & trusting the root CA on every platform |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map, request lifecycle, and how to extend the proxy |
| [`docs/PLUGINS.md`](docs/PLUGINS.md) | Writing plugins (Rust in-process + Node subprocess), the JSON protocol |
| [`docs/TEMPLATES.md`](docs/TEMPLATES.md) | Local files and templates: the two render passes, the `${var}` table, jsonp, content-type inference |
| [`docs/LINE_PROPS.md`](docs/LINE_PROPS.md) | Per-line rule properties (`lineProps://`): syntax, the property table, and what each one is wired to |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Future plans and the subsystems still simplified vs. upstream |
| [`README.zh-CN.md`](README.zh-CN.md) | 简体中文说明文档 |

## Scope: what's ported vs. stubbed

> whistle is a mature ~32k-line core plus a 245-file web-UI / plugin layer and a React
> frontend. This is **not** a 1:1 port of all of that — it is a faithful, runnable
> implementation of the proxy + rules core, structured so the rest can be added
> incrementally.

**Fully working (verified end-to-end):**

- HTTP forward proxy; CONNECT tunnelling with HTTPS MITM + dynamic per-host certs
- HTTP/2 interception (ALPN h2) with HTTP/1.1 fallback
- WebSocket (`ws://`/`wss://`) upgrade tunnelling
- Root CA generation, persistence, and `/rootCA.crt` download
- Rules engine: comments, hosts shorthand, regex/wildcard/prefix/dot patterns,
  `lineProps://important` precedence, multi-match accumulation, `ignore://`,
  `filter`/`includeFilter`/`excludeFilter` conditions (method/host/header/clientIp/URL)
- Upstream routing: `proxy`/`http-proxy`/`https-proxy`/`internal-proxy` (HTTP proxy)
  and `socks` (SOCKS5); `pac` (evaluate PAC to pick the proxy)
- Operators applied at runtime: **70 of whistle's 73 registry operators** — headers,
  cookies, `delete`, charset, body rewriting (generic + `css`/`html`/`js` + `resMerge`),
  `trailers`, `headerReplace`, URL/query, `ua`/`referer`/`method`/`auth`/`forwardedFor`,
  delays/speeds, `cache`, `attachment`, `redirect`/`file`/`statusCode`,
  `enable`/`disable` flags, `reqWrite`/`resWrite`(`Raw`), `responseFor`, `log`,
  `cipher` (upstream TLS version pin), `resScript`/`frameScript`, `plugin`/`pipe`,
  `weinre`, `rule`/`rulesFile` includes, and `{name}` value references. Plus the
  **local-file / template family** (`file`/`rawfile`/`tpl`/`jsonp`/`dust` and their
  `x`/`xs` fallback variants) and whistle's **alias operators** (`hosts`, `html`, `css`,
  `js`, `download`, `status`, `skip`, `tlsOptions`, `pathReplace`, `reqMerge`, …),
  normalised to their canonical form. Full mapping in
  [`docs/RULES.md#operator-coverage`](docs/RULES.md#operator-coverage).
- WebSocket frame capture — `ws://`/`wss://` connections appear in the request table
  (status `101`) and every frame (both directions) is recorded; `/frames.json`.
- A three-pane console: requests grouped by client with a sortable table and a
  General / headers / bodies / frames detail panel, plus rule-group and values
  editors; `/sessions.json`, `/session.json?id=`, `/frames.json`, `/sessions.har`
  (HAR export), `/proxy.pac`
- `@`-includes (pull rules from a URL/file) and `${port}`/`${version}` config variables

Only **2** operators remain unimplemented — `G` (global-rule marker) and `style`
(rule colour in the UI) — each documented with its reason in the coverage table.
`sniCallback` used to be a third: it is now implemented, and the record calling it
architecturally unreachable was wrong rather than merely out of date.

**Plugins** are whistle-rs's own system, with two runtimes sharing one contract
(`plugin://name`): **Rust** in-process plugins (the `RustPlugin` trait) and **JS/TS**
plugins built on the zero-dependency SDK in `sdk/`, which ships TypeScript
definitions. whistle-rs can spawn the Node process (`--node-plugin`) or point at a
running one (`--plugin`). A plugin can inject rules, answer a request directly,
rewrite request headers, and rewrite the response status, headers and body. Whether a
body is delivered is driven by the plugin's capability manifest, so plugins that do
not ask for one keep the proxy's streaming fast path. One hook is not about a request
at all: `sniCallback://name` runs during the TLS handshake and picks the certificate
an intercepted connection is served — or declines to intercept it. See
[`docs/PLUGINS.md`](docs/PLUGINS.md).

This is not a reimplementation of the original's plugin API, so `npm i whistle.xxx`
packages do not run unchanged — a deliberate trade-off, reasoned about in the
[roadmap's non-goals](docs/ROADMAP.md).

**Simplified vs. the original** (functional, but not a byte-for-byte port): whistle's
React web UI (`biz/`) is replaced by a lightweight built-in UI; weinre is
script-injection only (the inspector server is external); the traffic capture
(headers, bodies, and WebSocket frames) lives in a bounded in-memory ring buffer with
optional persistence to disk (`--no-persist` turns it off), body previews default to
16 KB (`--body-preview-limit`), and gzip/deflate/brotli bodies are decoded for
viewing.

See [`docs/RULES.md#operator-coverage`](docs/RULES.md#operator-coverage) for the
operator-level detail.

## Troubleshooting

**Ask the capture which rules matched.** Every session records the operators that
resolved for it, as written and as they came out — an operator missing from that
list never matched, and one with an unexpected `value` is a substitution problem
rather than a matching one:

```bash
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
s = json.load(sys.stdin)[0]
print(s["url"])
for r in s["rules"]: print(" ", r["raw"], "->", r["value"])'
```

**Then look at the log.** Every request prints the destination it resolved to,
and that one line usually contains the rest of the answer:

```
INFO GET http://seg.test/path/to/x  -> 127.0.0.1:5173 (http)   # the rule matched
INFO GET http://seg.test/path/toxxx -> seg.test:80    (http)   # it did not
INFO OPTIONS http://api.test/users  -> short-circuit           # answered locally
```

Those are `INFO`, so they are there without any flag. `-v` adds the **reason**
behind a failure, which a bare `502` will not tell you:

```
DEBUG request failed: connecting to 127.0.0.1:9: Connection refused (os error 61)
DEBUG request failed: upstream TLS handshake: invalid peer certificate: …
```

### Nothing is being intercepted

| Symptom | Cause / fix |
|---------|-------------|
| `502 Bad Gateway` with a `Proxy-Connection` header on a **direct** request | Your shell has `http_proxy` set, so even `http://127.0.0.1:8899/` goes through *another* proxy. Add `--noproxy '*'` (curl) or unset the variable. |
| The console shows `CONNECT` lines and nothing inside them | HTTPS is being tunnelled, not decrypted — the client does not trust the root CA. See [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md). Firefox needs it in *its own* store; iOS needs the second, separate "enable full trust" step that most people stop short of. |
| Browser warns the cert is untrusted | The same cause, one step earlier. |
| A device on the LAN cannot reach the proxy | whistle-rs binds all interfaces by default, so check the firewall, and that you gave the device your **LAN** address rather than `127.0.0.1`. Fetching `http://<lan-ip>:8899/proxy.pac` from the device tests reachability and hands you a correct PAC in one go. |
| Port already in use | Another process holds it — pick another with `-p`. |

### A rule does not fire

| Symptom | Cause / fix |
|---------|-------------|
| The rule matches a URL you expected it to miss, or the reverse | A path prefix only matches at a `/`, `\` or `?` boundary: `example.com/path/to` matches `/path/to/x` but **not** `/path/toxxx`. |
| A `*` in the path matches nothing | `*` is a wildcard **in the host only**; in a path it is a literal, because `*` is a legal URL character. Write `^http://example.com/old/**` for a path wildcard. Filter patterns are the exception — they always read as if `^`-prefixed. |
| A mock, redirect or forward is silently ignored | `file`, `redirect`, `statusCode`, the template family and a bare destination URL **share one slot**, and the first line to fill it wins outright. A mock written below a forward never runs — move it up, or mark it `lineProps://important`. |
| An operator value arrives truncated | It contained a space, and the line is split on whitespace. `reqHeaders://authorization=Bearer secret` sets `Bearer` and then routes the request to a host called `secret`. Percent-encoding does not help; use a named value and `${name}`. |
| The whole line does nothing on some requests | A filter scopes the *entire* line, destination included — `includeFilter://from:composer` beside a `host://` means the override applies only to replays. |
| Two lines set the same header and one is missing | A contested name is won by the **first** line, important lines first. |
| A rule you did not expect is winning | `lineProps://important` rules resolve before everything else, whatever the file order. A leading `$` is **not** that — it is whistle's exact-match pattern. |

### It fires, but the result is wrong

| Symptom | Cause / fix |
|---------|-------------|
| `502` on a self-signed or private-CA origin | whistle-rs **verifies** origin certificates; whistle does not (`rejectUnauthorized` is `false` there unless `--safe`). This is the one place the port deliberately does not copy upstream's default, because a debugging proxy that accepts any upstream certificate cannot tell you when the connection it is inspecting has itself been intercepted. `--insecure-upstream` opts out. |
| `502` when forwarding to an intercepted host | The upstream connection or its TLS failed — `-v` gives the target and the error. A `host://` override that points TLS at a non-TLS port fails the handshake. |
| A request hangs for a minute or more before failing | The destination is dropping packets rather than refusing, so the wait is the OS's TCP timeout. `-t 3000` caps connection *establishment* (never an established connection, so streams are safe). |
| `resDelay://1s` is instantaneous | Delays are **milliseconds**, and a unit suffix is parsed off and discarded rather than converted, so `1s` is one millisecond. Write `1000`. |
| A throttle is 8× faster than expected | `reqSpeed://` / `resSpeed://` are **kilobits** per second, not kilobytes. This port read them as kilobytes until recently; multiply values written against that by 8. |
| An SSE or chunked response stops streaming | It should not: `resReplace://` travels with the stream and holds back only a tail, and the prepend/append/`resBody` family needs no buffer at all — measured on an SSE origin emitting one event every 200 ms, first byte at 204 ms with a rule and 206 ms without. What *does* wait for the last byte is an operator that has to read the whole body (`resMerge://`, an injection into markup), which is in its nature. |
| `statusCode://` returned an empty body | That is what it does — it manufactures a response. `replaceStatus://` is the one that changes the status of a response that has a body. |
| An operator given a path sends something you did not write | That is the point: an operator value that names a location is **read** before the operator applies (upstream's `readRuleValue`), so `resBody:///tmp/mock.json` sends the file's contents and `resBody://https://cdn.test/mock.json` fetches per request. To send the text itself, wrap it: `resBody://(/tmp/mock.json)`. |
| A certificate-pinned app breaks under interception | Stop intercepting that one host: `pinned.example.com sniCallback://no-mitm` relays it byte-for-byte while still routing it by its rules. `--no-intercept-https` does the same for everything. |

### It is not in the capture

| Symptom | Cause / fix |
|---------|-------------|
| A failed request is missing from the console entirely | A request that never got a response — connection refused, DNS failure, TLS handshake failure — is **not** recorded as a session. The log is the only place it appears. |
| A body is truncated in the detail panel | Previews are capped at 16 KB; raise it with `--body-preview-limit`. |
| A binary body shows as `[binary, N bytes]` | Binary bodies are replaced at serialisation time, so image and hex views are not available yet — see [`docs/ROADMAP.md`](docs/ROADMAP.md). |
| The capture is empty after a restart | `--no-persist` was on, or `--persist-days` has expired the files under `<storage_dir>/sessions/`. |

Each of these has a worked recipe, with the sharp edge attached, in
[`docs/COOKBOOK.md`](docs/COOKBOOK.md).

## Development

```bash
cargo test                 # rules engine unit tests
cargo build --release
cargo run -- -p 8899 -r rules.txt -v
```

Architecture, the request lifecycle diagram, and worked examples for adding an
operator or an upstream proxy are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

MIT (same as upstream whistle).
