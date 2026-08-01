# whistle-rs

**English** · [简体中文](README.zh-CN.md) · [路线图 / Roadmap](docs/ROADMAP.md)

A Rust port of the **core** of [whistle](https://wproxy.org) — an HTTP / HTTPS /
WebSocket debugging proxy. It implements the load-bearing heart of whistle: the
**rules DSL engine**, the **proxy server** (HTTP forward proxy + CONNECT tunnelling +
HTTPS man-in-the-middle), and **dynamic CA certificate generation**.

The original JavaScript source lives in [`../_original`](../_original); this port maps
module-for-module onto it (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).

## Contents

- [Features](#features)
- [Install & build](#install--build)
- [Quick start](#quick-start)
- [Configure your client](#configure-your-client)
- [Intercepting HTTPS](#intercepting-https)
- [Writing rules](#writing-rules)
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
  patterns; `$`-important precedence; multi-match accumulation.
- **Forwarding** — point a site at a dev server with a bare URL
  (`www.example.com http://localhost:5173`); the request's remaining path comes along.
- **Destination override** (`host://`) that rewrites the target IP/port while keeping
  the original `Host` header and TLS SNI — the defining behaviour of a debug proxy.
- **Request/response rewriting** — headers, cookies, body (replace/prepend/append/
  regex), URL/query, user-agent, method, content-type, CORS, auth, delays, status
  replacement, redirects, and local file serving.
- **Console** — a self-contained page (open the proxy host in a browser): a source
  list, a sortable request table, and the selected request's headers and bodies in a
  detail panel below it. Rule groups and values are edited from the same shell, and a
  rules change applies immediately.
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
cd whistle-rs
cargo build --release
# binary at ./target/release/whistle-rs
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

# $-prefix = important; wins over normal rules
$example.com          host://2.2.2.2
```

**The full syntax — every pattern kind and operator, precedence rules, and a
cookbook — is in [`docs/RULES.md`](docs/RULES.md).**

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
| `-v, --verbose` | Debug logging (per-request decisions) | off |
| `-h, --help` / `-V, --version` | Help / version | — |

## Documentation

| Doc | Contents |
|-----|----------|
| [`docs/RULES.md`](docs/RULES.md) | Complete rule syntax: patterns, operators, precedence, cookbook, compatibility |
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
  `$`-important precedence, multi-match accumulation, `ignore://`,
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

| Symptom | Cause / fix |
|---------|-------------|
| `502 Bad Gateway` with a `Proxy-Connection` header on a **direct** request | Your shell has `http_proxy` set, so the request is going through *another* proxy. Add `--noproxy '*'` (curl) or unset the env var. |
| Browser warns the cert is untrusted on HTTPS | The root CA isn't installed/trusted yet — see [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md). Firefox needs it in *its own* store. |
| `502` when forwarding to an intercepted host | Upstream connection/TLS failed. Run with `-v` to see the target and error. A `host://` override that points TLS at a non-TLS port will fail the handshake. |
| A rule seems ignored | Check precedence (important `$` and file order), and confirm the operator is one that's **applied** (see scope table). `-v` logs each request's resolved destination or short-circuit. |
| Port already in use | Another process holds the port — pick another with `-p`. |

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
