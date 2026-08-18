# Architecture & development

How whistle-rs is put together, how it maps onto the original whistle source, and how
to extend it.

- [Module map](#module-map)
- [Request lifecycle](#request-lifecycle)
- [Dependencies](#dependencies)
- [Extending: add a rule operator](#extending-add-a-rule-operator)
- [Extending: add an upstream proxy](#extending-add-an-upstream-proxy)
- [Testing](#testing)
- [Project layout](#project-layout)

---

## Module map

Each Rust module corresponds to part of the original JS under `../_original/lib`:

> **`Ported from` points at the upstream whistle 2.10.4 tree**, which this
> repository no longer ships. How to fetch it, and at which commit, is in
> [`UPSTREAM.md`](UPSTREAM.md) — the line numbers are only valid for that one.

| Rust module | Ported from | Responsibility |
|-------------|-------------|----------------|
| `src/config.rs` | `lib/config.js` | Runtime config, storage paths, defaults |
| `src/rules/protocols.rs` | `lib/rules/protocols.js` | The protocol registry + multi-match set |
| `src/rules/mod.rs` | `lib/rules/rules.js` | Line parsing, pattern kinds, operator parsing |
| `src/rules/matcher.rs` | `lib/rules/rules.js` (`resolveRules`) | Match a request, resolve per-protocol winners |
| `src/rules/wildcard.rs` | `lib/rules/rules.js` (`parseWildcard`, `isRegUrl`) | The two wildcard pattern kinds, and a filter's own |
| `src/rules/url.rs` | `lib/rules/rules.js` (`joinUrl`, `setProtocol`) | Where a destination's path comes from, and the bracket forms |
| `src/rules/replace.rs` | `lib/util/replace-pattern-transform.js` | `$0`–`$9` expansion, for pattern captures and `*Replace` alike |
| `src/ca.rs` | `lib/https/ca.js` | Root CA generation/persistence, per-host leaf signing |
| `src/proxy/mod.rs` | `lib/index.js`, `lib/tunnel.js` | Server, forward proxy, CONNECT + MITM, WebSocket, capture log, status page/PAC |
| `src/proxy/upstream.rs` | `lib/handlers/http-proxy.js` | Outbound forwarding (host/SNI split), upstream HTTP/SOCKS proxies |
| `src/proxy/apply.rs` | `lib/inspectors/{req,res}.js` | Translate resolved rules into req/res mutations |
| `src/proxy/dest.rs` | `lib/inspectors/rules.js:40` | Where the request is addressed once a URL-replacement rule has spoken |
| `src/proxy/header_rules.rs` | `lib/rules/index.js:558-657` | The five headers a request may carry its own rules in — taken from every request, read only under `-M enableRequestHeaderRules` / `-M multiEnv` |
| `src/proxy/forwarded.rs` | `lib/util/index.js:3697-3728`, `util/common.js:1231-1266` | What a front proxy claims — `x-forwarded-host`/`-proto` behind their modes, and the two whistle spellings upstream reads with no gate |
| `src/proxy/template.rs` | `lib/handlers/file-proxy.js` (`render`) | `tpl`/`dust`/`jsonp` two-pass rendering + `${var}` variables |
| `src/proxy/persist.rs` | — | Session persistence (JSONL, daily rotation) |
| `src/proxy/sni.rs` | `lib/https/index.js:1281`, `lib/https/load-cert.js` | The SNI stage: peek the ClientHello, pick the certificate, or relay the connection untouched |
| `src/proxy/socks.rs` | `lib/index.js` (socks server) | Inbound SOCKS5 server |
| `src/proxy/script.rs` | `lib/inspectors` (script hooks) | JS engine for `resScript`/`frameScript` + PAC eval |
| `src/proxy/ws.rs` | `lib/socket-mgr.js` | WebSocket frame codec + the capturing tunnel: `frameScript`, then plugin frame hooks |
| `src/proxy/webui.rs` | `biz/webui` | The console's routes + `/api/rules`, `/sessions.json`, `/session.json`, `/frames.json`, PAC |
| `ui-src/` | `biz/webui/htdocs` | The console: a Vue 3 / Vite / TypeScript app built to one file and inlined at compile time; `build.rs` substitutes a placeholder when it has not been built, so no Node is needed to build the proxy |
| `ui-src/src/editor/whistle-classify.js` | — | The rules classifier; shares `index_of_pattern` with the parser, and a Rust test holds the two together |
| `src/plugins/mod.rs` | `lib/plugins/` | Plugin registry, capability manifests, request/response hooks, remote JSON protocol |
| `src/plugins/builtin.rs` | (examples) | Built-in Rust plugins (`echo`, `tag`, `stamp`, `upper`, `ws-upper`, `gate`, `no-mitm`) |
| `src/plugins/pipe.rs` | `lib/util/transproto.js` | Streaming body transport (`pipe://`), chunked HTTP rather than upstream's framing |
| `src/plugins/wsframe.rs` | `load-plugin.js` (ws hooks) | Per-frame WebSocket transport, one long-lived record-framed connection per direction |
| `src/plugins/auth.rs` | `load-plugin.js:1746`, `plugins/index.js:831` | Auth gate — fails **closed**: a broken gate is 502, a refusal 403 |
| `src/plugins/ui.rs` | `biz/webui/lib/index.js:466` | `/plugin/<name>/…` served from the plugin's own pages |
| `src/plugins/sni.rs` | `plugins/index.js:228`, `load-plugin.js:1841` | `sniCallback` — the certificate a connection is served, or no interception at all |
| `src/plugins/stats.rs` | `plugins/index.js:1369` | Fire-and-forget per-phase stats |
| `sdk/whistle-rs-plugin.js` | `lib/plugins/load-plugin.js` | Zero-dependency JS/TS plugin SDK (+ `.d.ts` types) |
| `src/proxy/body.rs` | — | Unified boxed response-body type + throttled body |
| `src/embed.rs` | — | The library facade: bind on port 0, observe sessions, swap rules, shut down |
| `src/main.rs` | `bin/whistle.js` | CLI parsing, startup wiring |

## Request lifecycle

```
                       ┌──────────────────────── main port (TcpListener) ─────────────┐
client ── TCP ──▶ hyper http1 serve_connection ──▶ top_level(req)
                       │
   ┌───────────────────┼────────────────────────────────────────────┐
   │ CONNECT           │ absolute-form URI            │ origin-form   │
   ▼                   ▼                              ▼               ▼
handle_connect     serve(Forward)                serve(Forward)   local_ui
   │ 200 + upgrade     │                              │            (status page,
   ▼                   │                              │             /rootCA.crt)
serve_tunnel           │                              │
   │ peek ClientHello  │                              │
   ├─ sni::decide ─ "do not intercept" ──▶ sni::relay (opaque, no rules)
   │ TLS-accept        │                              │
   │ (leaf for the SNI,│                              │
   │  or a plugin's)   │                              │
   ▼                   ▼                              ▼
serve(Mitm) ──────────────────────────────────────────
        │
        ├─ build ReqInfo (scheme, host, port, path, full_url)
        ├─ RuleManager::resolve(&ReqInfo) → Resolved
        ├─ buffer request body?  ── only if a matched plugin's manifest asks
        ├─ plugin onRequest ── responded? ──▶ mock response
        │        │  else: merge injected rules, collect header rewrites
        ├─ apply::short_circuit? ── yes ──▶ 302 / mock status / file / template ─▶ response
        │        no
        ├─ apply::resolve_target (host:// override; keep SNI)
        ├─ apply::apply_request (headers, ua, method, …) + plugin header rewrites
        ├─ upstream::forward (own TCP/TLS conn) ──▶ Response<Incoming>
        ├─ apply::apply_response (status, headers, cors)
        ├─ plugin onResponse ── body-less plugins run here; response keeps streaming
        └─ buffer response body? ── only if a rule or a plugin needs it ──▶ response
```

The two entry origins (`Forward`, `Mitm`) converge on the same `serve()` pipeline;
they differ only in how scheme/host/port are derived. That's why rules apply
identically to plain HTTP and to intercepted HTTPS.

### Why we open our own upstream connection

whistle's defining trick is rewriting **where** a request goes without changing
**what the server sees**. A pooled high-level client keys connections by hostname and
would send SNI/Host for the destination IP. Instead `upstream::forward` connects the
socket to the (possibly overridden) destination itself, but sets the TLS SNI and the
`Host` header from the **original** hostname. See `src/proxy/upstream.rs`.

## What the capture costs

Every proxied body streams through `body::tee`, which copies a bounded prefix into
the session capture as the bytes go past (`src/proxy/body.rs`). Whether that is
affordable for large bodies and under concurrency was measured rather than assumed;
the harness is `src/proxy/bench.rs` and stays out of the normal suite:

```bash
cargo test --release -- --ignored --nocapture bench::
```

Numbers below are from an Apple M4 (10 cores, 16 GB, Darwin 25.3.0 arm64), rustc
1.96.1, stock `--release` profile. Each row is 200 iterations (microbenchmarks) or
150–800 requests (end to end). Configurations are driven **round robin inside one
loop, with the order rotating each pass**, so a scheduler hiccup or a thermal
excursion lands on all of them equally instead of on whichever one happened to be
running — and, since the first slot is the baseline every other row is measured
against, so that it does not silently absorb per-iteration warm-up.

### The tee itself

Against the same body with no tee at all, delivered in 16 KiB frames:

| body (frames) | no tee | tee, cap 0 | tee, cap 16 KiB | tee, uncapped |
|---|---|---|---|---|
| 4 KiB (1) | 192 ns | 529 ns | 793 ns | 795 ns |
| 64 KiB (4) | 222 ns | 688 ns | 1.7 µs | 9.0 µs |
| 1 MiB (64) | 942 ns | 2.3 µs | 3.2 µs | 57.6 µs |
| 16 MiB (1024) | 5.4 µs | 12.2 µs | 12.9 µs | 2.5 ms |

Two things fall out of that.

**The cost goes flat past the cap.** `cap 16 KiB` tracks `cap 0` — which copies
nothing and only counts bytes — to within the single 16 KiB copy that fills the
preview once. From 1 MiB to 16 MiB the body grows 16× and the gap between those two
columns stays at 0.7–0.9 µs. What does keep scaling is the frame count: holding the
body at 1 MiB and shrinking the frames gives 28.2, 11.9, 8.2 and 6.5 ns per frame at
16, 64, 256 and 2048 frames, converging on **≈6.5 ns per frame** — one uncontended
mutex acquisition and two additions. Every body owns its own capture, so that lock
is never contended between concurrent requests.

**The cap is the whole story.** Remove it and a 16 MiB body costs 2.5 ms instead of
12.9 µs, some 200× more, because the preview then copies the entire body.

A compressed body is decoded so its preview is readable, and that is the one fixed
cost worth naming: **≈45 µs per body regardless of size** (44.3 µs for 64 KiB,
45.4 µs for 1 MiB, and the 55.7 µs at 16 MiB is that plus per-frame cost). Fixed,
because decoding stops as soon as 16 KiB of *decoded* output exists.

### Against a socket

Three proxies, one per preview cap, in front of a canned origin; concurrent clients
hold keep-alive connections to all three and rotate between them request by request.
Means, with the delta against `cap 0` in brackets:

| body | conns | cap 0 | cap 16 KiB (default) | cap 1 MiB |
|---|---|---|---|---|
| 4 KiB identity | 1 | 112.2 µs | 112.2 µs (−0.05 µs) | 112.4 µs (+0.2 µs) |
| 4 KiB identity | 32 | 807 µs | 816 µs (+8.6 µs) | 812 µs (+4.7 µs) |
| 1 MiB identity | 1 | 250 µs | 255 µs (+4.7 µs) | 355 µs (+105 µs) |
| 1 MiB identity | 32 | 6.1 ms | 6.2 ms (+41 µs) | 6.5 ms (+407 µs) |
| 1 MiB gzip | 1 | 779 µs | 811 µs (+32 µs) | 2.7 ms (+2.0 ms) |
| 1 MiB gzip | 32 | 6.0 ms | 6.1 ms (+85 µs) | 9.5 ms (+3.5 ms) |

**The shipping configuration is indistinguishable from not capturing at all.** Over
two runs the `cap 16 KiB` delta lands anywhere between −24 µs and +85 µs and changes
sign, while the same rows drift 6% (identity) to 50% (gzip) between runs: the delta
is inside the noise. Even the ≈45 µs that the microbenchmark cleanly attributes to
gzip decoding cannot be recovered from end-to-end timings. `cap 1 MiB` is the only
column that sits outside the noise, and it does so consistently in both runs —
removing the bound is what would cost something.

For scale, the harness counts **1.00 upstream connections per request**: whistle-rs
opens its own connection per request and does not pool (above). A local TCP
handshake is tens of microseconds and a real one is milliseconds, so the tee is
orders of magnitude below the cheapest thing a proxied request already has to do.

**So: nothing to act on for throughput.** The preview cap — `--body-preview-limit`,
default 16 KiB — is what keeps it that way, and lifting it is the one change that
would make the capture expensive.

### What the profile did turn up

Not throughput, but memory. `flate2`'s write-side decompressors accumulate
everything they inflate into an internal `Vec` that `drain_decoder` only ever reads
a bounded prefix of. The preview was capped; the decompressor behind it was not, and
it was kept alive in `CaptureState` for the life of the capture — and captures live
in the session ring, `MAX_SESSIONS` (500) deep.

A 16 MiB response of highly compressible bytes arrives as a single 16 KiB frame,
`write_all` inflates all of it before anything takes a 16 KiB preview off the front,
and all 16 MiB then sat in the session until 500 more requests pushed it out. No
hostile client needed: a large log file or JSON dump over gzip is enough.

The decompressor is now released as soon as it can contribute nothing more — when
the preview fills, and when the tee is dropped, which covers both a body that ended
and a client that hung up half way through. `bench::capture_retained_bytes` reports
what a finished capture still holds, and it now reads 0 B for every case it did not
before. What remains is the transient peak: one frame is still inflated in full
before its prefix is taken, so a single frame's decompressed size is the high water
mark. Bounding *that* means driving `flate2::Decompress` with a fixed output buffer
instead of the write adapter — a larger change, and a much smaller exposure now
that nothing is retained.

## Dependencies

| Crate | Role |
|-------|------|
| `tokio` | async runtime |
| `hyper` 1.x + `hyper-util` | HTTP/1.1 server & client, connection upgrades |
| `http-body-util`, `bytes` | body types |
| `rustls` (ring provider) + `tokio-rustls` | TLS accept (MITM) and connect (upstream) |
| `rcgen` | root CA + leaf certificate generation |
| `webpki-roots` | trust anchors for verifying upstream servers |
| `regex` | wildcard/regex patterns |
| `serde` / `serde_json` | JSON header-operator values |
| `clap` | CLI |
| `tracing` / `tracing-subscriber` | logging |

The `ring` crypto provider is pinned (`default-features = false`) so no C toolchain is
needed to build. It is installed at startup in `main.rs`.

## Extending: add a rule operator

Say you want `delete://header-name` to strip a request header.

1. **Registry** — the name is likely already in `PROTOCOLS`
   (`src/rules/protocols.rs`); add it if not. If it can appear multiple times per
   request, add it to `MULTI_MATCH`.
2. **Apply** — in `src/proxy/apply.rs`, read it from the resolved set and act:

   ```rust
   // in apply_request(...)
   for op in resolved.all("delete") {
       parts.headers.remove(op.value.trim());
   }
   ```
3. **Test** — add a unit test to `src/rules/matcher.rs` proving the operator resolves,
   and (optionally) drive it end-to-end as in the README smoke test.

`Resolved` gives you three accessors, all of them total over single- and
multi-match protocols alike: `get(proto)` is the winning `RuleOp` (for a
multi-match protocol, the head of its list), `value(proto)` its value, and
`all(proto)` every match in resolution order — important lines first, source
order within a pass. A single-match protocol yields a one-element `all`, so a
loop needs no special case. Which protocols accumulate is
`rules::protocols::MULTI_MATCH`; how several values of one operator combine is
per family and documented in [`RULES.md`](RULES.md).

## Extending: add an upstream proxy

`proxy://`, `http-proxy://`, `socks://` etc. already parse and resolve; they just
aren't honoured when forwarding. To wire them up:

1. In `apply::resolve_target`, read `resolved.value("proxy")` (and siblings) and
   carry the proxy address on the `Target` struct.
2. In `upstream::forward`, when a proxy is set, either issue an HTTP `CONNECT` to the
   proxy before the TLS handshake (for HTTPS) or send an absolute-form request to the
   proxy (for HTTP), instead of connecting to the origin directly.

This is the single most impactful missing feature and the cleanest next task.

## Testing

```bash
cargo test                  # unit tests
cargo clippy --all-targets  # expected to be silent; `[lints.clippy]` denies the lot
cargo build --release
```

The capture benchmarks are `#[ignore]`d — they are measurements rather than
assertions, and mean nothing in a debug build. Run them on their own:

```bash
cargo test --release -- --ignored --nocapture bench::
```

Unit tests live in `src/rules/matcher.rs` and cover hosts shorthand, explicit
`host://`, regex and wildcard patterns, multi-match accumulation, `$`-important
precedence, and leading-dot subdomain matching.

**End-to-end smoke test** (what was used to validate the proxy):

```bash
# 1. a local origin
python3 -c "from http.server import *; import sys; \
  HTTPServer(('127.0.0.1',9099), type('H',(BaseHTTPRequestHandler,), {\
  'do_GET': lambda s: (s.send_response(200), s.end_headers(), s.wfile.write(b'origin'))[0],\
  'log_message': lambda *a: None})).serve_forever()" &

# 2. rules + proxy
echo "test.local 127.0.0.1:9099" > /tmp/r.txt
cargo run --release -- -p 8899 -r /tmp/r.txt &

# 3. drive it
curl -x http://127.0.0.1:8899 http://test.local/       # host override → origin
curl -x http://127.0.0.1:8899 --cacert ~/.whistle-rs/certs/root.crt https://example.com/
```

## Project layout

```
whistle-rs/
├── Cargo.toml
├── README.md
├── rules.txt              # example rules
├── docs/
│   ├── RULES.md           # rule syntax reference
│   ├── TEMPLATES.md       # local files + template rendering
│   ├── PLUGINS.md         # plugin system + wire protocol
│   ├── LINE_PROPS.md      # per-line rule properties
│   ├── CERTIFICATES.md    # root CA install guide
│   ├── ROADMAP.md         # what is and isn't ported
│   └── ARCHITECTURE.md    # this file
├── sdk/                   # JS/TS plugin SDK (zero deps) + .d.ts types
├── examples/plugins/      # hello.js, body-rewrite.js, typed.ts
└── src/
    ├── main.rs            # CLI
    ├── lib.rs             # module root
    ├── config.rs
    ├── ca.rs
    ├── rules/
    │   ├── mod.rs
    │   ├── protocols.rs
    │   ├── matcher.rs
    │   ├── wildcard.rs    # `*` in a host, and `^…$` everywhere else
    │   ├── url.rs         # joinUrl/setProtocol + the (inline)/<verbatim> forms
    │   └── replace.rs     # $0-$9 expansion
    └── proxy/
        ├── mod.rs
        ├── apply.rs
        ├── dest.rs        # the URL a request is forwarded to
        ├── template.rs    # tpl/dust/jsonp rendering + ${var} variables
        ├── persist.rs     # session persistence (JSONL)
        ├── upstream.rs
        ├── socks.rs       # inbound SOCKS5 server
        ├── script.rs      # JS engine (resScript/frameScript/pac)
        ├── ws.rs          # WebSocket frame codec + capturing tunnel (frameScript, frame hooks)
        ├── webui.rs       # console routes + API
        └── body.rs
```

## Where to look first

| I want to… | Start at |
|---|---|
| add a rule operator | `src/rules/protocols.rs` (register), then `src/proxy/apply.rs` (act on it) |
| change how rules match | `src/rules/matcher.rs` |
| write a plugin | [`PLUGINS.md`](PLUGINS.md), then `sdk/whistle-rs-plugin.d.ts` |
| add a plugin hook | `src/plugins/mod.rs` (manifest + trait), then the call site — but check first whether the existing dispatch already suffices, as `auth` did |
| touch the request pipeline | `serve()` in `src/proxy/mod.rs` — the one place every request flows through |
| add an endpoint | the route match at the top of `src/proxy/webui.rs` |
| change the console | `ui-src/` — Vue 3 SFCs; `npm run build` writes `dist/index.html`, then `cargo build` inlines it |
