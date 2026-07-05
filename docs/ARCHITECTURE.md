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

| Rust module | Ported from | Responsibility |
|-------------|-------------|----------------|
| `src/config.rs` | `lib/config.js` | Runtime config, storage paths, defaults |
| `src/rules/protocols.rs` | `lib/rules/protocols.js` | The protocol registry + multi-match set |
| `src/rules/mod.rs` | `lib/rules/rules.js` | Line parsing, pattern kinds, operator parsing |
| `src/rules/matcher.rs` | `lib/rules/rules.js` (`resolveRules`) | Match a request, resolve per-protocol winners |
| `src/ca.rs` | `lib/https/ca.js` | Root CA generation/persistence, per-host leaf signing |
| `src/proxy/mod.rs` | `lib/index.js`, `lib/tunnel.js` | Server, forward proxy, CONNECT + MITM, WebSocket, capture log, status page/PAC |
| `src/proxy/upstream.rs` | `lib/handlers/http-proxy.js` | Outbound forwarding (host/SNI split), upstream HTTP/SOCKS proxies |
| `src/proxy/apply.rs` | `lib/inspectors/{req,res}.js` | Translate resolved rules into req/res mutations |
| `src/proxy/socks.rs` | `lib/index.js` (socks server) | Inbound SOCKS5 server |
| `src/proxy/script.rs` | `lib/inspectors` (script hooks) | JS engine for `resScript`/`frameScript` + PAC eval |
| `src/proxy/ws.rs` | `lib/socket-mgr.js` | WebSocket frame codec + capturing/`frameScript` tunnel |
| `src/proxy/webui.rs` | `biz/webui` | Built-in web UI + `/api/rules`, `/sessions.json`, `/session.json`, `/frames.json`, PAC |
| `src/plugins/mod.rs` | `lib/plugins/` | Unified plugin registry + remote (Node/HTTP) JSON protocol |
| `src/plugins/builtin.rs` | (examples) | Built-in Rust example plugins (`echo`, `tag`) |
| `src/proxy/body.rs` | — | Unified boxed response-body type + throttled body |
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
mitm_serve             │                              │
   │ TLS-accept        │                              │
   │ (leaf cert)       │                              │
   ▼                   ▼                              ▼
serve(Mitm) ──────────────────────────────────────────
        │
        ├─ build ReqInfo (scheme, host, port, path, full_url)
        ├─ RuleManager::resolve(&ReqInfo) → Resolved
        ├─ apply::short_circuit? ── yes ──▶ 302 / mock status / file  ─▶ response
        │        no
        ├─ apply::resolve_target (host:// override; keep SNI)
        ├─ apply::apply_request (headers, ua, method, …)
        ├─ upstream::forward (own TCP/TLS conn) ──▶ Response<Incoming>
        └─ apply::apply_response (status, headers, cors) ──▶ response
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

`Resolved` gives you three accessors: `value(proto)` (first-match single),
`get(proto)` (the `RuleOp`), and `all(proto)` (every value, for multi-match).

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
cargo test          # unit tests (rules engine)
cargo build --release
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
│   ├── CERTIFICATES.md    # root CA install guide
│   └── ARCHITECTURE.md    # this file
└── src/
    ├── main.rs            # CLI
    ├── lib.rs             # module root
    ├── config.rs
    ├── ca.rs
    ├── rules/
    │   ├── mod.rs
    │   ├── protocols.rs
    │   └── matcher.rs
    └── proxy/
        ├── mod.rs
        ├── apply.rs
        ├── upstream.rs
        ├── socks.rs       # inbound SOCKS5 server
        ├── script.rs      # JS engine (resScript/frameScript/pac)
        ├── ws.rs          # WebSocket frame codec + capturing/frameScript tunnel
        ├── webui.rs       # built-in web UI + API
        └── body.rs
```
