# Architecture & development

> Current verification and limits: [STATUS.md](STATUS.md). Build/test commands:
> [DEVELOPMENT.md](DEVELOPMENT.md). Historical benchmarks below are not a fresh
> measurement of every later commit. The console is the Vue application in
> `ui-src/`; `build.rs` embeds its built HTML, or a placeholder when absent.

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
| `src/rules/regexp.rs` | `lib/util/index.js` (`toRegExp`, `toOriginalRegExp`) | One regexp type for every `/…/` a user writes — pattern, filter, `*Replace`, template — compiled by regress as JavaScript; and the report when one does not compile |
| `src/rules/url.rs` | `lib/rules/rules.js` (`joinUrl`, `setProtocol`) | Where a destination's path comes from, and the bracket forms |
| `src/rules/replace.rs` | `lib/util/replace-pattern-transform.js` | `$0`–`$9` expansion, for pattern captures and `*Replace` alike |
| `src/rules/storage.rs` | `lib/rules/util.js` (`rulesStorage`) | Rule groups and values on disk, and which of them were switched on |
| `src/rules/include.rs` | `lib/rules/util.js` (`getRemoteRulesResolver`) | `@` lines: fetch what they name, keep it fresh, re-parse what changed |
| `src/ca.rs` | `lib/https/ca.js` | Root CA generation/persistence, per-host leaf signing |
| `src/proxy/mod.rs` and its siblings | `lib/index.js`, `lib/tunnel.js` | The server, one kind of work per file: `listen` (ports, accept loop), `tunnel` (CONNECT, MITM, h1/h2 inside a tunnel), `serve` (the request pipeline), `response` (response phase and body operators), `upgrade` (WebSocket), `ledger` (one session per request, failures included), `session`/`capture` (what the console shows), `state`, `markers`, `dumps`. `mod.rs` holds the map |
| `src/proxy/upstream.rs` | `lib/handlers/http-proxy.js` | Outbound forwarding (host/SNI split), upstream HTTP/SOCKS proxies |
| `src/proxy/apply.rs`, `src/proxy/apply/` | `lib/inspectors/{req,res}.js` | Translate resolved rules into req/res mutations, one operator family per file (`req_ops`, `res_ops`, `header_ops`, `body_ops`, `route`, `local`, …); `apply.rs` holds the map |
| `src/proxy/dest.rs` | `lib/inspectors/rules.js:40` | Where the request is addressed once a URL-replacement rule has spoken |
| `src/proxy/header_rules.rs` | `lib/rules/index.js:558-657` | The five headers a request may carry its own rules in — taken from every request, read only under `-M enableRequestHeaderRules` / `-M multiEnv` |
| `src/proxy/forwarded.rs` | `lib/util/index.js:3697-3728`, `util/common.js:1231-1266` | What a front proxy claims — `x-forwarded-host`/`-proto` behind their modes, and the two whistle spellings upstream reads with no gate |
| `src/qr.rs` | `qrcode@1.2.0` (a dependency there) | A QR encoder for the console's LAN addresses: byte mode, level M, versions 1-10. Compared module for module by `tests/differential/qr-bench.js` |
| `src/proxy/template.rs` | `lib/handlers/file-proxy.js` (`render`) | `tpl`/`dust`/`jsonp` two-pass rendering + `${var}` variables |
| `src/proxy/persist.rs` | — | Session persistence (JSONL, daily rotation). A body preview is written with its flags (`truncated`, `binary`, `undecodable`) and, when its text is not its bytes, the bytes; it is restored from those rather than re-derived |
| `src/proxy/search.rs` | `biz/webui/htdocs/src/js/network-modal.js` (`h:`/`b:`) | The search box's `h:` and `b:`, answered over every held session; patterns compiled by regress, so they mean what the browser's `RegExp` means |
| `src/proxy/outcome.rs` | `lib/inspectors/data.js` (`reqError`/`resError`) | How a request ended when it did not complete: the phase, the reason, the error tag that carries them out of `upstream`, and the body wrapper that notices a response breaking off |
| `src/proxy/sni.rs` | `lib/https/index.js:1281`, `lib/https/load-cert.js` | The SNI stage: peek the ClientHello, pick the certificate, or relay the connection untouched |
| `src/proxy/socks.rs` | `lib/index.js` (socks server) | Inbound SOCKS5 server |
| `src/proxy/script.rs`, `src/proxy/script_prelude.js` | `lib/rules/index.js` (`getScriptContext`, `execRulesScript`), `lib/socket-mgr.js` (`execHandleFrame`) | The JS engine (boa) and what a script sees in it: the rules scripts, a connection's `frameScript` on a thread of its own, PAC. The prelude is Node's `Buffer`, `url.parse`, `querystring.parse` and `iconv` helpers, in JavaScript |
| `src/proxy/ws.rs` | `lib/socket-mgr.js` | WebSocket frame codec + the capturing tunnel: `frameScript`, then plugin frame hooks. Also `inspected_relay`, the chunk-by-chunk relay an `enable://inspect` tunnel gets |
| `src/proxy/webui.rs`, `src/proxy/webui/` | `biz/webui` | The console: the route table (`handle`, in `webui.rs`) and its API, one area per file — `access`, `sessions`, `har`, `rules`, `values`, `bundle`, `composer`, `console_hosts`, `plugin_pages` |
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
| `src/proxy/restream.rs` | `lib/inspectors/data.js` (`parseFrameSep`) | A body cut into frames: event streams and `x-whistle-custom-frame-separator` |
| `src/proxy/coding.rs` | `lib/util/index.js` (`getZipType`, transforms) | gzip / deflate / brotli / zstd, decoded to inspect and re-encoded to forward |
| `src/proxy/ciphers.rs` | `lib/rules/index.js` (`getTlsOptions`) | `cipher://` and the TLS options a rule may pin |
| `src/proxy/timing.rs` | `lib/inspectors` (timings) | Per-phase timings, as the console's waterfall reads them |
| `src/proxy/bench.rs` | — | An in-process load harness, kept out of the normal suite |
| `src/explain.rs` | `biz/webui/cgi-bin/rules/test.js` | `whistle-rs explain` — which rules a request would hit, without making one |
| `src/proxy/body.rs` | — | Unified boxed response-body type + throttled body |
| `src/embed.rs` | — | The library facade: bind on port 0, observe sessions, swap rules, shut down |
| `src/main.rs` | `bin/whistle.js` | CLI parsing, startup wiring |
| `src/lib.rs` | — | The module root, and the crate-level documentation |

## Request lifecycle

```
                       ┌──────────────────────── main port (TcpListener) ─────────────┐
client ── TCP ──▶ hyper http1 serve_connection ──▶ top_level(req)
                       │
   ┌───────────────────┼────────────────────────────────────────────┐
   │ CONNECT           │ absolute-form URI            │ origin-form:  │ origin-form:
   │                   │                              │ /-/, or a     │ Host is a
   │                   │                              │ Host that is  │ console name
   │                   │                              │ not a console │
   │                   │                              │ name          │
   ▼                   ▼                              ▼               ▼
handle_connect     serve(Forward)                serve(Forward)   local_ui
   ├─ relayed_unread ─ dial, then 200 (no reply if the dial fails) ──▶ relay_before_reply
   │ 200 + upgrade     │                              │            (status page,
   ▼                   │                              │             /rootCA.crt)
serve_tunnel           │                              │
   │ peek ClientHello  │                              │
   ├─ sni::decide ─ "do not intercept" ──▶ relay_recorded (opaque; one CONNECT session)
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

### How a request becomes exactly one session

Every request `serve()` takes on becomes one session, however it ends. The
caller is `serve_recorded`, which hands `serve()` a `Ledger` — a draft of the
session that fills in as the request goes (method and URL, then the matched
rules, then the target, the outgoing headers and the connection's timings) —
and settles it three ways:

- **A path that answers records its own** through `Ledger::record`: a local
  answer, a plugin's, an abort, the response head from the origin.
- **An error that escapes `serve()`** reaches `guard`, which records the draft
  with the error's phase and answers `502` with `x-whistle-rs-error` and
  `x-whistle-rs-session`. The phase is not guessed from the message: `upstream`
  wraps each failure in an `outcome::Stopped` where it happens (`dial` tags DNS
  and connect separately, the proxy handshake, the TLS handshake, the send), and
  `outcome::phase_of` finds the innermost tag under any `.context()` added on
  top. An untagged error is `internal` — a gap in the tagging, not a category.
- **A dropped future** — hyper drops the service future when the client closes
  the connection or resets the stream — drops the `Ledger`, whose `Drop` records
  the draft as `client`.

`settled` is what keeps the three from doubling up. A forwarded response is
different in one way: its row appears at the head, but it is not *complete*
until the body is. `AppState::record_open` shows it, and `outcome::settle`
wraps the body and calls `AppState::complete` once — when the body ends, fails
(`response`) or is dropped short (`client`). `complete` is the only place the
observer is called and the history written, so both see the final session.
hyper also drops a body it has finished without polling it to the end, once a
`content-length` is written; `settle` counts the bytes so that is not mistaken
for a client leaving.

A tunnel whose contents are not read has no request inside it to do this, so the
CONNECT itself is recorded through a `Tunnel`: when it is relayed (shown once
connected, complete when it closes), when it cannot be routed or its far end
cannot be reached, and when the client refuses the certificate (`client-tls`).

A relay decided on the CONNECT alone — interception off, or `disable://intercept`
on the address the client asked for — goes through `relay_before_reply`, which
dials first and answers `200` only once the far end has, as whistle does
(`_original/lib/tunnel.js:637-695`). A far end that cannot be reached leaves the
CONNECT unanswered and the row at status 0, so the client's own CONNECT fails
rather than succeeding and then hanging up. Every other tunnel has to be
answered before its ClientHello can be read; a relay decided there
(`serve_tunnel` → `relay_recorded`) dials after the `200`, which is also what
whistle does on that path.

### Why we open our own upstream connection

whistle's defining trick is rewriting **where** a request goes without changing
**what the server sees**. A pooled high-level client keys connections by hostname and
would send SNI/Host for the destination IP. Instead `upstream::forward` connects the
socket to the (possibly overridden) destination itself, but sets the TLS SNI and the
`Host` header from the **original** hostname. See `src/proxy/upstream.rs`.

### Reusing origin connections

An origin connection outlives its request only for the **client connection** that
opened it: every connection a client makes to the proxy (a keep-alive HTTP
connection, a CONNECT tunnel, an h2 connection) carries a `ConnPool` in its
requests' extensions, and a later request on it to the same place reuses what an
earlier one left open (`src/proxy/pool.rs`). Nothing is shared between clients,
so a credential bound to a connection rather than to a request (NTLM, Negotiate)
cannot leak from one client to another — the same line upstream draws for the h2
sessions it caches.

The key is everything a fresh connection would have been made from: the address,
the requested host and port, TLS on or off with the `cipher://` versions and
suites, the stripped-TLS marker, and the whole proxy route — kind, address,
`?host=`, `proxyTunnel`, the `Proxy-Authorization` presented and the `User-Agent`
echoed on CONNECT. `pool_tests::every_part_of_the_route_is_in_the_key` changes each
one and checks the key changes with it.

Not pooled: upgrades, CONNECT, anything whose response did not finish cleanly
(hyper closes those), and any request that said `Connection: close` or was HTTP/1.0
without `keep-alive` — hyper only looks at the response for that, so
`upstream::asks_to_close` does. Idle connections close after 15 s; at most 16 per
key and 32 per client connection are kept, the oldest going first — one keep-alive
connection asking for a new host every request would otherwise hold a socket per
host. A connection the origin closes just as a request goes out is the one
failure reuse adds: a body-less request with an idempotent method is sent again on
a fresh connection; any other request only takes a connection idle for under 2 s,
well inside the shortest common server idle timeout (5 s, Node and Apache).

Sessions number the origin connection (`timings.connection`, `timings.reused`;
HAR's `connection`), because a reused one has no DNS, connect or TLS phase and the
console would otherwise only be able to call those "not measured".

**HTTP/2 to the origin.** A request that arrived over h2 — which is every request
a browser sends through an intercepted HTTPS tunnel — offers `h2` in the origin's
ALPN (`upstream::offers_h2`; `enable://h2`/`disable://h2` override it, as in
whistle). An h2 connection is not taken from the pool but shared: every request
the client connection sends to that key goes over it concurrently
(`ConnPool::session`). The first request of a burst makes the connection while
the others wait on `ConnPool::opening`, so the first page load is one handshake,
not one per request in flight; an origin that picks HTTP/1.1 gets HTTP/1.1 on the
socket it already accepted and is remembered, so nobody waits for it again; and a
failed attempt lets the waiters connect side by side rather than one connect
timeout after another. `upstream::for_h2` turns `Host` into `:authority` and drops
the connection-specific headers, as whistle's `formatH2Headers` does.

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

For scale, the harness counted **1.00 upstream connections per request** when
these rows were taken, before origin connections were reused (above). A local TCP
handshake is tens of microseconds and a real one is milliseconds, so the tee is
orders of magnitude below the cheapest thing a proxied request had to do.

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
| `regex` | the patterns this port generates (wildcards, port patterns) and its own internal parsing |
| `regress` | the regular expressions a user writes — ECMAScript syntax, so a `/…/` means what it means in whistle (`src/rules/regexp.rs`) |
| `serde` / `serde_json` | JSON header-operator values |
| `clap` | CLI |
| `tracing` / `tracing-subscriber` | logging |

The `ring` crypto provider is pinned (`default-features = false`) and installed
at startup in `main.rs`. This does not remove its native build requirements or
guarantee fully static binaries on every target; use the platform build toolchain.

## Extending: add a rule operator

Say you want `delete://header-name` to strip a request header.

1. **Registry** — the name is likely already in `PROTOCOLS`
   (`src/rules/protocols.rs`); add it if not. If it can appear multiple times per
   request, add it to `MULTI_MATCH`.
2. **Apply** — in the file under `src/proxy/apply/` for its family (the table
   at the top of `apply.rs` says which; request headers are `req_ops.rs`), read
   it from the resolved set and act:

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

"Silent" holds on the toolchain `rust-toolchain.toml` pins; a newer Clippy may
find more. The full gate and the version rules are in
[DEVELOPMENT.md](DEVELOPMENT.md#工具链).

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
├── build.rs               # inlines the built console into the binary
├── .cargo/config.toml     # Windows: link the C runtime in (no VCRUNTIME140.dll)
├── .github/workflows/     # ci.yml (every push/PR, five platforms), differential.yml (weekly)
├── README.md              # README.zh-CN.md is only a redirect to it
├── rules.txt              # example rules
├── docs/                  # docs/README.md is the index
│   ├── INSTALL.md         # packages, checksums, data directory, upgrade, uninstall
│   ├── COOKBOOK.md        # task-oriented recipes (+ .zh-CN)
│   ├── RULES.md           # rule syntax reference
│   ├── CLI.md             # the command line, flag by flag, against whistle's
│   ├── API.md             # the console's HTTP API
│   ├── OPERATIONS.md      # safe defaults, what is stored, how long
│   ├── TEMPLATES.md       # local files + template rendering
│   ├── PLUGINS.md         # plugin system + wire protocol
│   ├── LINE_PROPS.md      # per-line rule properties
│   ├── CERTIFICATES.md    # root CA: install, trust, remove
│   ├── DEVELOPMENT.md     # toolchain, checks, differential, CI
│   ├── UPSTREAM.md        # which whistle tree the `_original/…` citations mean
│   ├── STATUS.md          # what was measured, per task, and what was not
│   ├── ROADMAP.md         # the task plan (Chinese)
│   └── ARCHITECTURE.md    # this file
├── scripts/
│   ├── smoke.mjs          # use a binary the way a person does, on any OS
│   ├── check-console.sh   # which console page a binary embeds
│   ├── check-links.mjs    # relative links and anchors in the Markdown
│   └── third-party-licenses.mjs # license texts shipped with a release
├── sdk/                   # JS/TS plugin SDK (zero deps) + .d.ts types
├── examples/plugins/      # hello.js, body-rewrite.js, typed.ts
├── ui-src/                # the console: Vue 3 + Vite, built to one file
│   ├── mock/api.ts        # the proxy's API, mocked, for `npm run dev`
│   └── src/               # panes/, sidebar/, components/, editor/, filter/
├── tests/
│   ├── *_e2e.rs           # end-to-end, over a real socket, no node needed
│   ├── data_compat.rs     # data an older release wrote must still load
│   ├── data/<version>/    # …that data, as the release left it
│   └── differential/      # the benches — see its own README
└── src/
    ├── main.rs            # CLI
    ├── lib.rs             # module root
    ├── config.rs
    ├── ca.rs
    ├── embed.rs           # the library facade
    ├── explain.rs         # `whistle-rs explain`
    ├── qr.rs              # the console's QR encoder
    ├── private_fs.rs      # owner-only files, replaced whole on save
    ├── rules/
    │   ├── mod.rs
    │   ├── protocols.rs
    │   ├── matcher.rs
    │   ├── storage.rs     # rule groups and values, on disk
    │   ├── include.rs     # `@` sources, fetched and kept fresh
    │   ├── wildcard.rs    # `*` in a host, and `^…$` everywhere else
    │   ├── url.rs         # joinUrl/setProtocol + the (inline)/<verbatim> forms
    │   └── replace.rs     # $0-$9 expansion
    ├── plugins/           # registry, hooks, `pipe://`, ws frames, auth, sni, ui
    └── proxy/
        ├── mod.rs         # the map of the files below
        ├── serve.rs       # `serve()` — every request flows through it
        ├── tunnel.rs      # CONNECT, MITM, what arrives before a request
        ├── response.rs    # response phase and response body operators
        ├── apply.rs       # resolved rules → mutations; apply/ holds one file per family
        ├── dest.rs        # the URL a request is forwarded to
        ├── header_rules.rs # rules a request carries in its own headers
        ├── forwarded.rs   # what a front proxy claims, and whether to believe it
        ├── template.rs    # tpl/dust/jsonp rendering + ${var} variables
        ├── persist.rs     # session persistence (JSONL)
        ├── search.rs      # the search box's h:/b:, answered here
        ├── upstream.rs
        ├── sni.rs         # peek the ClientHello, pick a certificate, or relay
        ├── socks.rs       # inbound SOCKS5 server
        ├── script.rs      # JS engine (resScript/frameScript/pac)
        ├── ws.rs          # WebSocket frame codec + capturing tunnel
        ├── restream.rs    # a body cut into frames (SSE, custom separators)
        ├── coding.rs      # gzip/deflate/brotli/zstd
        ├── ciphers.rs     # `cipher://` and the TLS options
        ├── timing.rs      # per-phase timings
        ├── webui.rs       # console route table; webui/ holds the API, one area per file
        ├── bench.rs
        └── body.rs
```

## Where to look first

| I want to… | Start at |
|---|---|
| add a rule operator | `src/rules/protocols.rs` (register), then its family's file in `src/proxy/apply/` (act on it) |
| change how rules match | `src/rules/matcher.rs` |
| write a plugin | [`PLUGINS.md`](PLUGINS.md), then `sdk/whistle-rs-plugin.d.ts` |
| add a plugin hook | `src/plugins/mod.rs` (manifest + trait), then the call site — but check first whether the existing dispatch already suffices, as `auth` did |
| touch the request pipeline | `serve()` in `src/proxy/serve.rs` — the one place every request flows through |
| add an endpoint | the route match in `handle`, `src/proxy/webui.rs`, and the handler in the `webui/` file for its area |
| change the console | `ui-src/` — Vue 3 SFCs; `npm run build` writes `dist/index.html`, then `cargo build` inlines it |
