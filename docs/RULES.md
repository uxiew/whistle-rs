# Rules reference

whistle-rs uses whistle's rule syntax. This document is the complete reference for
the subset the Rust core understands. For the original, exhaustive whistle rule
documentation see <https://wproxy.org>.

- [File format](#file-format)
- [Patterns](#patterns)
- [Operators](#operators)
- [Precedence](#precedence)
- [Cookbook](#cookbook)
- [Operator coverage](#operator-coverage)

---

## File format

A rules file is plain UTF-8 text, one rule per line:

```
pattern  operator1  operator2  …  operatorN
```

- Tokens are separated by **any run of whitespace**.
- A line beginning with `#` is a **comment** and is ignored.
- A blank line, or a line with fewer than two tokens, is ignored.
- The first token is normally the **pattern**; the rest are **operators**. If the
  first token is itself an operator (has a known `protocol://` prefix or is a bare
  `host:port`), whistle-rs falls back to scanning for the first pattern token —
  matching whistle's "operators first, then patterns" form for the common case.

You can load rules three ways:

```bash
whistle-rs -r rules.txt              # from a file
whistle-rs --rule "example.com host://127.0.0.1:8080"   # inline
whistle-rs -r rules.txt --rule "…"   # file first, then inline appended
```

---

## Patterns

A pattern decides **which requests a rule applies to**. whistle-rs supports four
kinds; it picks the kind automatically from the token's shape.

### 1. Domain / URL prefix (most common)

```
example.com                 # any request whose host is exactly example.com
example.com/api             # host example.com AND path starting with /api
http://example.com/api      # …restricted to the http scheme
https://example.com         # …restricted to https
```

Matching rules:

| Pattern part | Behaviour |
|--------------|-----------|
| scheme (`http://`, `https://`, `ws://`, `wss://`) | optional; if present the request scheme must match (with `http↔ws` / `https↔wss` upgrade equivalence) |
| host | matched **exactly** (case-insensitive), unless it starts with a dot (see below) |
| path | matched as a **prefix** of the request path+query |

### 2. Leading-dot subdomain match

A host beginning with `.` matches the domain itself **and every subdomain**:

```
.example.com  host://5.5.5.5
```

matches `example.com`, `www.example.com`, `a.b.example.com`, …

### 3. Wildcard

A pattern containing `*` is compiled to an anchored regular expression, with `*`
meaning "any characters":

```
*.example.com/api/*   redirect://https://api.internal/
http://*/track.gif    statusCode://204
```

### 4. Regular expression

A pattern wrapped in slashes is a regex tested against the **full request URL**
(`scheme://host[:port]/path?query`). A trailing `i` makes it case-insensitive:

```
/\.js(\?|$)/          resType://application/javascript
/^https:\/\/cdn\./i   host://10.0.0.9
```

### `$` — important patterns

Prefix any pattern with `$` to mark the rule **important**: important rules are
resolved before normal ones and win ties.

```
example.com    host://1.1.1.1
$example.com   host://2.2.2.2      # this one wins
```

---

## Operators

An operator is `protocol://value`. whistle-rs recognises the **full whistle protocol
list** at parse time, and applies essentially all of the common operators at runtime
(see [Operator coverage](#operator-coverage) for the exceptions).

### Shorthands

| You write | Interpreted as |
|-----------|----------------|
| `127.0.0.1:8080` | `host://127.0.0.1:8080` |
| `127.0.0.1` | `host://127.0.0.1` |
| `/abs/path` · `~/f` · `./f` | `file:///abs/path` … |

### Destination

| Operator | Value | Effect |
|----------|-------|--------|
| `host` | `ip` / `ip:port` / `host:port` / `:port` | Rewrite the upstream destination. The **Host header and TLS SNI keep the original hostname**, only the socket destination changes. `:port` keeps the host, changes the port. |

```
api.example.com   host://127.0.0.1:9000
.example.com      host://:8443            # same host, force port 8443
```

### Upstream proxy

Route the forwarded request through another proxy. The credential form
`user:pass@host:port` is supported; the port defaults to 80 (http), 443 (https),
or 1080 (socks).

| Operator | Value | Effect |
|----------|-------|--------|
| `proxy` / `http-proxy` / `internal-proxy` | `[user:pass@]host:port` | Route via an HTTP proxy (absolute-form for http, CONNECT for https) |
| `https-proxy` | `[user:pass@]host:port` | Same, but the connection to the proxy is TLS |
| `socks` | `[user:pass@]host:port` | Route via a SOCKS5 proxy |

```
example.com        proxy://127.0.0.1:8888
.internal.corp     http-proxy://user:pass@10.0.0.1:3128
secure.example.com socks://127.0.0.1:1080
```

Precedence when several are present: `socks` > `https-proxy` > `http-proxy` >
`proxy` > `internal-proxy` > `pac`.

`pac://<file>` evaluates a PAC file's `FindProxyForURL(url, host)` to pick the proxy
(`PROXY host:port`, `HTTPS ...`, `SOCKS ...`, or `DIRECT`):

```
.corp.example.com   pac:///etc/whistle/corp.pac
```

### URL rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `urlReplace` | `from=to` (or `/regex/[i]=to`) | Substitute inside the request path+query |
| `params` / `urlParams` | `k=v&k2=v2` or `{json}` | Add/override query params (accumulates) |

```
example.com/api    urlReplace://v1=v2                 # /api/v1/x -> /api/v2/x
example.com/api    urlReplace:///users\/\d+/=/users/me # regex form
example.com        params://debug=1&trace=on
```

> Note the `/regex/` convention: since paths start with `/`, write literals without
> surrounding slashes (`urlReplace://old=new`) and reserve `/…/` for regexes.

### Filter conditions

`filter`/`includeFilter` add an extra condition a request must satisfy for the rule
to apply; `excludeFilter` skips the rule when the condition holds. Several filters on
one line are ANDed.

| Form | Meaning |
|------|---------|
| `filter://m:GET` (or `method:`) | request method |
| `filter://host:example.com` | request host (exact) |
| `filter://h:name=value` (or `header:`) | request header equals; `h:name` = presence |
| `filter://i:1.2.3.4` (or `ip:`, `clientIp:`) | client IP |
| `filter://<regex>` | regex over the full request URL |

**Divergences from upstream — a whistle rules file will not behave identically here.**
Upstream's documented condition syntax is in `_original/docs/docs/rules/filters.md`;
these are the differences, all verified against a running proxy:

| Upstream | Here | Effect |
|---|---|---|
| `reqH.<key>:<pattern>` | `h:<key>=<value>` | Upstream's spelling falls through to the URL-regex fallback and **silently never matches** |
| `resH.<key>:<pattern>` | — | Response headers aren't available at match time; not ported |
| `s:<pattern>` | — | Response status; not ported |
| `b:<pattern>` | — | Request body; not ported |
| `chance:<probability>` | — | Random sampling; silently never matches |
| `serverIp:<pattern>` | — | Not ported |
| `i:<pattern>` | client IP only | Upstream matches the client **or** server IP |
| `/regexp/i` as a condition value | exact match only | e.g. `m:/^P/` is not honoured |

Unknown conditions fall through to the URL-regex fallback, so an unsupported filter
makes its rule **inert** rather than firing wrongly — it fails closed, but silently.

```
example.com   host://10.0.0.1   filter://m:POST        # only POST requests
example.com   resHeaders://x-a=1   excludeFilter://i:127.0.0.1   # skip localhost
.example.com  host://5.5.5.5   filter://h:x-canary=1   # only tagged requests
```

### Disabling operators

| Operator | Value | Effect |
|----------|-------|--------|
| `ignore` | protocol name(s), or `all` | Drop those operators from the resolved set for matching requests |

```
.example.com   host://10.0.0.1
static.example.com   ignore://host        # this host keeps its real destination
example.com/health   ignore://all         # bypass every rule for this path
```

### Short-circuit (no upstream request is made)

| Operator | Value | Effect |
|----------|-------|--------|
| `redirect` / `location` | a URL | Respond `302 Found` with `Location: <url>` |
| `statusCode` | a status number | Respond with that status and an empty body (mock) |
| `file` / `rawfile` | a local path | Serve the file's bytes with a guessed `Content-Type` |

```
old.example.com/*      redirect://https://new.example.com/
/\/track\b/            statusCode://204
example.com/app.js     file:///Users/me/dev/app.js
```

### Request rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `reqHeaders` | `name=value`, `name:value`, or `{json}` | Set/replace request headers (empty value deletes). Accumulates across lines. |
| `ua` | user-agent string | Set the `User-Agent` header |
| `referer` | URL | Set the `Referer` header |
| `method` | HTTP method | Override the request method |
| `reqType` | MIME type | Set the request `Content-Type` |
| `reqCharset` | charset | Set the charset on the request `Content-Type` |
| `reqCors` | origin | Set the request `Origin` header |
| `auth` | `user:pass` | Add an HTTP Basic `Authorization` header |
| `forwardedFor` | IP | Set the `X-Forwarded-For` header |
| `reqWrite` | file path | Append the request body to a file |

```
example.com   reqHeaders://x-token=abc
example.com   reqHeaders://{"x-a":"1","x-b":"2"}
example.com   ua://MyBot/1.0
api.test/*    method://POST
api.test      auth://admin:secret
api.test      forwardedFor://203.0.113.7
```

### Plugins

| Operator | Value | Effect |
|----------|-------|--------|
| `plugin` | `name[/extra]` | Route the request to a registered plugin server |

Register plugin servers on the command line (repeatable):

```bash
whistle-rs --plugin echo=127.0.0.1:9300 --plugin mock=127.0.0.1:9400
```

The matched request is forwarded to the plugin over HTTP with context headers
`x-whistle-plugin`, `x-whistle-req-url`, and `x-whistle-req-method`; the plugin's
response is relayed back. (whistle's Node subprocess plugin loader is not ported;
plugins here are any HTTP server.)

```
api.example.com   plugin://mock
```

### Scripting

| Operator | Value | Effect |
|----------|-------|--------|
| `resScript` | path to a `.js` file (or inline JS) | Run JavaScript against the response |
| `frameScript` | path to a `.js` file (or inline JS) | Run JavaScript on each WebSocket text frame |

The script runs in an embedded JS engine with a global `ctx`:

```js
// ctx = { req: { method, url }, res: { statusCode, headers, body } }
ctx.res.headers['x-scripted'] = 'yes';
ctx.res.body = ctx.res.body.replace(/foo/g, 'bar');
if (ctx.req.url.indexOf('/admin') >= 0) ctx.res.statusCode = 403;
```

Changed `ctx.res.statusCode`, `ctx.res.headers`, and `ctx.res.body` are applied. A
script error leaves the response unchanged.

```
example.com   resScript:///abs/path/patch.js
```

`frameScript` runs on each WebSocket text frame with
`ctx = { direction: 'send'|'receive', frame: { data } }`; assign `ctx.frame.data`
to rewrite the frame:

```js
if (ctx.direction === 'send') ctx.frame.data = ctx.frame.data.toUpperCase();
```

```
chat.example.com   frameScript:///abs/path/frame.js
```

### weinre (HTML debug injection)

| Operator | Value | Effect |
|----------|-------|--------|
| `weinre` | id, or a script URL/path | Inject a weinre `<script>` into HTML responses |

Injected before `</head>` (or after `<body>`). A plain id builds the conventional
`//host:port/weinre/target/target-script-min.js#id` URL; a URL/path value is used
verbatim. The weinre inspector server itself is external (not bundled).

```
.example.com   weinre://mysession
example.com    weinre://https://debug.example.com/target/target-script-min.js#s1
```

### Flags, includes & values

| Operator | Value | Effect |
|----------|-------|--------|
| `enable` | flag(s) | Turn on a behaviour: `abort` (drop the request), `cors` (permissive CORS response) |
| `disable` | flag(s) | `cache` (`no-store`), `keepAlive` (`Connection: close`) |
| `trailers` | `name=value` / `{json}` | Emit HTTP response trailer headers (forces chunked) |
| `headerReplace` | `{"<scope>.<name>:<regex>":"<repl>"}` | Regex-rewrite a header value (`req`/`res` scope) |
| `responseFor` | a URL | Prefetch the URL; annotate the request with `x-whistle-response-for-*` |
| `rule` | value name | Include the named value's rules and apply them too |
| `rulesFile` | file path | Include rules from a file and apply them too |
| `pipe` | plugin name | Route through a registered server (like `plugin`) |

`{name}` anywhere in an operator value is replaced with the content of the named value
(from `--value name=…` or the web UI's Values panel).

```
api.example.com     enable://cors
slow.example.com    enable://abort
static.example.com  disable://cache
example.com         trailers://x-checksum=abc123
example.com         headerReplace://{"resH.set-cookie:Domain=[^;]+":"Domain=example.com"}
page.example.com    responseFor://http://auth.internal/verify
example.com         resBody://{mockJson}        # {mockJson} from the values store
example.com         rulesFile:///etc/whistle/extra.rules
```

### Delays & throttling

| Operator | Value | Effect |
|----------|-------|--------|
| `reqDelay` | milliseconds | Wait before forwarding the request |
| `resDelay` | milliseconds | Wait before returning the response |
| `reqSpeed` | KB/s | Cap request-body upload throughput |
| `resSpeed` | KB/s | Cap response-body download throughput |

```
slow.example.com   reqDelay://500
slow.example.com   resDelay://1000
slow.example.com   resSpeed://20        # ~20 KB/s download
```

> A speed cap buffers the body and re-emits it in paced chunks, so it forces a
> known-length body to chunked transfer.

### Response rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `replaceStatus` / `statusCode` | status number | Replace the upstream response status |
| `resHeaders` | `name=value`, `name:value`, or `{json}` | Set/replace response headers (empty value deletes). Accumulates across lines. |
| `resType` | MIME type | Set the response `Content-Type` |
| `resCharset` | charset | Set the charset on the response `Content-Type` |
| `resCors` | origin or `*` | Set `Access-Control-Allow-Origin` |
| `attachment` | filename | Force download via `Content-Disposition: attachment` |
| `cache` | `no`/`no-store`/seconds/`keep` | Set `Cache-Control` (`keep` leaves it) |
| `resWrite` | file path | Append the response body to a file |

```
example.com        resHeaders://x-mitm=intercepted
example.com/api    resCors://*
cdn.example.com    resType://application/javascript
example.com/404    replaceStatus://200
example.com        cache://no
```

### Deleting

| Operator | Value | Effect |
|----------|-------|--------|
| `delete` | `scope.name` or bare `name` (`\|`/`,`-separated) | Remove headers/cookies/type/charset |

Scopes: `reqHeaders`/`resHeaders` (a bare name deletes the header on that side),
`reqCookies`, `resType`, `resCharset`.

```
example.com   delete://server|x-powered-by
example.com   delete://reqCookies.tracking
```

### Cookies

| Operator | Value | Effect |
|----------|-------|--------|
| `reqCookies` | `name=value`, bare `name` (delete), or `{json}` | Merge into the request `Cookie` header. Accumulates across lines. |
| `resCookies` | `name=value`, bare `name` (expire), or `{json}` | Append `Set-Cookie` headers. Accumulates across lines. |

```
example.com   reqCookies://sid=abc
example.com   reqCookies://tracking          # bare name deletes it from the request
example.com   resCookies://theme=dark
```

### Body

| Operator | Value | Effect |
|----------|-------|--------|
| `reqBody` / `resBody` | replacement text | Replace the entire body |
| `reqReplace` / `resReplace` | `from=to` (or `/regex/[i]=to`) | Substitute inside the body |
| `reqPrepend` / `resPrepend` | text | Insert at the start of the body |
| `reqAppend` / `resAppend` | text | Insert at the end of the body |
| `cssBody`/`cssPrepend`/`cssAppend` | text | Body ops applied only to CSS responses |
| `htmlBody`/`htmlPrepend`/`htmlAppend` | text | Body ops applied only to HTML responses |
| `jsBody`/`jsPrepend`/`jsAppend` | text | Body ops applied only to JavaScript responses |

When any body operator applies, whistle-rs buffers that body, transforms it, and
recomputes `Content-Length` (dropping any `Transfer-Encoding`). Operators apply in
the order **Body → Replace → Prepend → Append**. Requests/responses without a body
operator are streamed through untouched. `*Replace` on a non-UTF-8 (binary) body is a
no-op.

```
api.example.com/echo   reqBody://{"mocked":true}
example.com/app.js     resBody://console.log('patched')
example.com            resReplace://http://=https://
example.com            resReplace:///v\d+/=vX          # regex form
example.com/page       resPrepend://<!-- via whistle-rs -->
example.com/page       resAppend://<script src="/inject.js"></script>
```

> `statusCode` is dual-purpose, matching whistle: when there is no upstream request it
> mocks the response; combined with a forwarded request it replaces the status.

---

## Precedence

For each request whistle-rs walks the rules and builds a resolved set:

1. **Important first.** Rules whose pattern starts with `$` are considered before
   normal rules.
2. **First-match-wins** for single-value protocols (`host`, `redirect`, `ua`, …):
   the first matching rule (respecting importance) sets the value.
3. **Accumulate** for multi-match protocols — `reqHeaders`, `resHeaders`,
   `reqCookies`, `resCookies`, `reqCors`, `resCors`, `trailers`, `plugin`, `log` —
   where every matching value is kept, in top-to-bottom order.

Within a pass, rules are evaluated in **file order**, so put more specific / higher
priority rules earlier (or mark them `$`).

---

## Cookbook

**Local development against a fake domain**

```
test.local        127.0.0.1:9099
```

**Force a CDN through a specific origin while keeping the real hostname/cert**

```
.cdn.example.com  host://10.0.0.9
```

**Mock an API endpoint**

```
api.example.com/health   statusCode://200
api.example.com/users    file:///Users/me/mock/users.json
```

**Inject CORS + auth for a front-end talking to a third-party API**

```
api.thirdparty.com   resCors://*
api.thirdparty.com   reqHeaders://authorization=Bearer abc
```

**Redirect an old path**

```
example.com/old/*    redirect://https://example.com/new/
```

**Tag every intercepted response (useful to confirm MITM is active)**

```
/^https:/i           resHeaders://x-via=whistle-rs
```

---

## Operator coverage

Every operator in whistle's registry (`_original/lib/rules/protocols.js`) and its
status in whistle-rs. **70 of 73 are applied at runtime**; the remaining 3 parse and
resolve (so mixed rule files load) but have no distinct effect.

### Applied at runtime

| Category | Operators |
|----------|-----------|
| Routing / upstream | `host`, `proxy`, `http-proxy`, `https-proxy`, `internal-proxy`, `internal-http-proxy`, `internal-https-proxy`, `https2http-proxy`, `http2https-proxy`, `socks`, `pac`, and `x`/`xs`-prefixed proxy variants |
| Request rewrite | `reqHeaders`, `reqCookies`, `reqType`, `reqCharset`, `reqCors`, `ua`, `referer`, `method`, `auth`, `forwardedFor`, `urlReplace`, `params`, `urlParams`, `reqBody`, `reqPrepend`, `reqAppend`, `reqReplace`, `reqDelay`, `reqSpeed`, `reqWrite`, `reqWriteRaw`, `responseFor` |
| Response rewrite | `resHeaders`, `resCookies`, `resType`, `resCharset`, `resCors`, `replaceStatus`, `statusCode`, `attachment`, `cache`, `resBody`, `resMerge`, `resPrepend`, `resAppend`, `resReplace`, `resDelay`, `resSpeed`, `resWrite`, `resWriteRaw`, `trailers`, `headerReplace` |
| Content-type body | `cssBody`/`cssPrepend`/`cssAppend`, `htmlBody`/`htmlPrepend`/`htmlAppend`, `jsBody`/`jsPrepend`/`jsAppend` |
| Short-circuit / flags | `redirect`, `location`, `locationHref`, `statusCode` mock, `enable`, `disable` |
| Local file / template | `file`, `rawfile`, `tpl`, `jsonp`, `dust`, and their `x`/`xs` fallback variants (`xfile`, `xrawfile`, …) |
| Matching / control | `filter`, `includeFilter`, `excludeFilter`, `ignore`, `delete`, `log`, `rule`, `rulesFile` |
| TLS | `cipher` (upstream TLS version pin) |
| Scripting / extend | `resScript`, `frameScript`, `plugin`, `pipe`, `weinre` |

**Rule-file features:** a line `@<url>` or `@<file>` includes rules fetched/read from
that source at load time; `${port}` and `${version}` in operator values are substituted
(case-insensitive); `locationHref://` injects a client-side redirect into HTML responses.

**Alias operators** are normalised to their canonical form, so all of these work too:
`hosts→host`, `xhost→host`, `html→htmlAppend`, `js→jsAppend`, `css→cssAppend`,
`download→attachment`, `status→statusCode`, `skip→ignore`, `tlsOptions→cipher`,
`pathReplace→urlReplace`, `reqMerge→params`, `resRules→resScript`,
`ruleFile`/`ruleScript`/`rulesScript`/`reqScript`/`reqRules`→`rulesFile`, `P→G`.

Notes: `https2http-proxy`/`http2https-proxy` resolve as HTTP proxies (scheme
conversion approximated); `enable`/`disable` apply a curated flag set
(`abort`, `cors`, `cache`, `keepAlive` — others are inert); `pipe` routes to a
registered server like `plugin` (no mid-stream piping); `rule`/`rulesFile` pull in
extra rules from the values store / a file; `{name}` in any operator value is
substituted from the values store. `cipher` honours the portable part of Node's TLS
options — `minVersion`/`maxVersion`/`secureProtocol` (or a bare `cipher://TLSv1.2`
token) pin the **upstream** TLS protocol version; rustls exposes TLS 1.2 / 1.3 only,
so OpenSSL cipher-suite strings and older-than-1.2 pins are not honoured.

The local-file family serves from disk: `file`/`rawfile` serve bytes (`rawfile`
parses a full HTTP response file — status line + headers + body); the `x`/`xs`
variants (`xfile`, `xrawfile`, …) serve the file **if it exists** and otherwise fall
through to the real server.

`tpl`, `dust` and `jsonp` render a template — and are **byte-identical to each other**,
exactly as upstream: whistle has no template engine, and `jsonp` does no callback
wrapping of its own. Rendering is two passes: `{name}`/`{{name}}` from the query
string, then `${var}` runtime variables. See
[`TEMPLATES.md`](TEMPLATES.md) for the variable table and the gotchas.

WebSocket frames are captured too: every intercepted `ws://`/`wss://` connection is
recorded as a session (status `101`) and each frame (both directions) is surfaced —
click the connection in the Network view, or fetch `/frames.json?id=<session>`.

### Multiple patterns and multi-line blocks

One operator can serve several patterns on a line — the line expands to one rule
per pattern:

```
host://127.0.0.1:8080   www.example.com  api.example.com  static.example.com
```

For longer lists, the block form keeps it readable (whistle's `line\`` syntax):

```
line`
proxy://127.0.0.1:8080
www.example.com
api.example.com
includeFilter://m:GET
excludeFilter:///admin/
`
```

A block is collapsed to a single logical line before parsing, so anything valid
on one line is valid inside a block.

### Comments

`#` starts a comment **anywhere on a line**, not just at the start:

```
a.com  host://1.1.1.1        # this whole tail is ignored
```

This mirrors upstream exactly, including its sharp edge: a `#` inside a URL
fragment is also treated as a comment, so `example.com/a#b file:///x` loses the
`#b`.

### Parsed but not applied (3)

| Operator(s) | Why / note |
|-------------|-----------|
| `sniCallback` | JS hook at SNI time to choose the MITM certificate — resolved before per-request rules, and needs the Node plugin loader |
| `G` | Global-rule marker (a rule-precedence concept, not a per-request traffic effect) |
| `style` | Rule colour in whistle's rule list — the built-in UI is a plain editor with no per-rule rendering |

### Simplified vs. upstream

whistle's template variables (`${…}`), plugin variables (`%name=…`), the full
`lineProps` system, and the Node-subprocess plugin loader are not implemented
(plugins/pipes here are external HTTP servers). `resCors`/`enable://cors` set a
permissive `Access-Control-Allow-Origin` (not the full negotiated CORS set).
Patterns/operators outside the documented forms may parse but not behave exactly as
in upstream whistle.

If a rule doesn't do what you expect, run with `-v` (debug logging) — each request
logs its resolved destination or short-circuit decision.
