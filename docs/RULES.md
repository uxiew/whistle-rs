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

### Path matching stops at a segment boundary

A path prefix only matches at a `/`, `\` or `?` boundary — the same rule
upstream documents (`_original/docs/docs/rules/pattern.md`) and enforces at
`rules.js:1091-1097`:

```
example.com/path/to
  ✅ example.com/path/to
  ✅ example.com/path/to/xxx?q=1
  ✅ example.com/path/to?q=1
  ❌ example.com/path/toxxx        # no boundary after `to`
```

A pattern that already ends in `/` imposes no further boundary. A pattern
carrying a query means "**same path**, query is a prefix":

```
example.com/path/to?xxx
  ✅ example.com/path/to?xxx
  ✅ example.com/path/to?xxxyyy&z
  ❌ example.com/path/to/yyy?xxx   # path must match exactly
  ❌ example.com/path/to           # query required
```

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

### 5. Port

A bare `:<port>` scopes a rule to a port, whatever the host:

```
:8080          host://127.0.0.1:3000    # only requests to port 8080
```

A port on a normal pattern is honoured too — `example.com:8080` matches that host
**only** on that port.

### `!` — negated patterns

`!` before a **regexp** (or a port pattern) inverts it:

```
!/example\.com/   host://127.0.0.1     # everything except example.com
```

Matching upstream, negation is only honoured for regexps and port patterns: a
negated literal or wildcard pattern is **dropped at parse time**
(`_original/lib/rules/rules.js:1259-1268`), so `!example.com host://x` configures
nothing in either implementation.

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

`includeFilter` adds a condition a request must satisfy for the rule to apply;
`excludeFilter` skips the rule when the condition holds. Upstream's reference for the
syntax is `_original/docs/docs/rules/filters.md`.

```
example.com   host://10.0.0.1   includeFilter://reqH.x-canary:1
```

> ⚠️ **`includeFilter://` is the only spelling that includes.** `filter://` and
> `ignore://<condition>` are **exclude** filters — whistle decides with
> `isInclude = matcher[1] === 'n'` (`_original/lib/rules/rules.js:1563`), which is true
> for i**n**cludeFilter alone. whistle-rs read `filter://` as an include until this was
> corrected, so a rules file using it did the *opposite* of what it asked. If you have
> `filter://` rules written against the old behaviour, they now exclude; rewrite them as
> `includeFilter://`.

**How several filters combine** (whistle's `matchExcludeFilters`,
`_original/lib/rules/rules.js:1967`):

- include filters are **OR**ed — one of them holding is enough;
- a matching **exclude** filter vetoes the rule, whatever the includes decided;
- a rule with only exclude filters applies unless one of them holds.

#### Conditions

A condition is written `<name><sep><value>`. `<sep>` is `:` after any filter
operator; `.` and `=` work after `includeFilter`/`excludeFilter` only, which is
upstream's split between its `PROPS_FILTER_RE` and `PURE_FILTER_RE`
(`_original/lib/rules/rules.js:57-60`). **Any** condition's value may be written as
`/regexp/[i]` instead of a literal.

| Condition | Spellings | Matches |
|---|---|---|
| Request header | `reqH.<key>:<v>` ← canonical; also `reqH.<key>=<v>`, `req.`/`reqHeader.`/`reqHeaders.`, `reqH:<key>=<v>`, `h:<key>=<v>`, `header:` | header **contains** `<v>`, case-insensitively. No `<v>` = presence test |
| Method | `m:<v>`, `method:<v>` | request method (regexps always ignore case) |
| Client IP | `clientIp:<v>`, `clientIP:` | the client's IP |
| Client or server IP | `i:<v>`, `ip:<v>` | the client's IP — see the note below |
| Host | `host:<v>`, `host=<v>` | request host |
| Sampling | `chance:<p>`, `chance:<n>%`, `probability:` | a random fraction of requests (`Math.random() < p`) |
| URL | anything else | the full request URL, using the same pattern engine as a rule's own [pattern](#patterns) — regexp, wildcard or prefix |

> ⚠️ **Behaviour change:** header values match by **containment**, like upstream's
> `filterHeader` (`rules.js:1922`) — `reqH.content-type:json` matches
> `application/json`. The `h:<key>=<value>` spelling this port already had used to
> require the value to be **equal**; it now matches by containment too, so it accepts
> strictly more requests than before. Write `reqH.<key>:/^value$/` where you relied on
> an exact match.

A `!` inverts a condition. It goes in front of the value (`m:!GET`), straight after a
header key (`reqH.x-tag!:v`), or in front of a URL pattern (`includeFilter://!*.cdn.com`);
two of them cancel. Note that `!` in front of a condition *name* is not a negation —
`includeFilter://!m:GET` is a negated URL pattern, here and upstream.

```
example.com   host://10.0.0.1      includeFilter://m:POST            # only POST
example.com   host://10.0.0.1      includeFilter://m:/^P/            # POST, PUT, PATCH
example.com   resHeaders://x-a=1   excludeFilter://clientIp:127.0.0.1
.example.com  host://5.5.5.5       includeFilter://reqH.content-type:json
example.com   statusCode://503     includeFilter://chance:5%         # fail 5% of calls
example.com   host://10.0.0.1      excludeFilter://*/health
```

#### Conditions that cannot be evaluated yet

whistle resolves a request's rules twice — once before the request is sent and again
in the response phase — so upstream can answer conditions about the response. This
port resolves once, before the request is sent.

These conditions are therefore **parsed and recognised**, so they are never mistaken
for a URL pattern, but they evaluate to "unknown". Upstream's `getFilterResult`
(`_original/lib/rules/rules.js:1809`) turns an unknown answer into `false` *before* it
consults `!`, and this port does the same: an include filter is never satisfied, an
exclude filter never fires, and no `!` can flip either. The subsystem fails closed.

| Condition | Would need |
|---|---|
| `s:<v>`, `statusCode:<v>` | the response status — i.e. re-resolving rules after the response headers arrive |
| `resH.<key>:<v>`, `res.`/`resHeader.`/`resHeaders.` | the same, plus the response headers threaded into `ReqInfo` |
| `serverIp:<v>` | the resolved upstream address, known only once the connection is made |
| `clientPort:`, `serverPort:`, `remoteAddress:`, `remotePort:` | the socket addresses of both ends, plumbed from the connection into `ReqInfo` |
| `b:<v>`, `body:<v>` | the request body buffered *before* rules resolve (upstream pre-reads it when a line carries a body filter) |
| `env:<key>=<v>` | the plugin environment store |
| `from:<v>` | the request's origin flags (`tunnel`, `composer`, `sni`, …), which the proxy layer knows but does not pass to the matcher |

#### Remaining divergences from upstream

| Upstream | Here | Why |
|---|---|---|
| `i:` matches the client IP, then falls back to the server IP | client IP only | The server IP does not exist yet at match time. Upstream only reaches its server-IP arm when the client IP is unknown, so the two agree in practice. |
| `filter://<url-pattern>` with no trailing `/` is a **pattern**, not a filter | an exclude URL filter | Upstream's `PATTERN_FILTER_RE` requires the payload to end in `/` or `/i`; the bare form falls out of its filter parser and becomes another pattern for the line. Every *documented* `filter://` URL spelling is an exclude filter in both. |
| `host:<v>` routes to proxy-host filtering | matches the request host | `host:` (with a colon) is this port's own spelling; upstream has only `host=`/`host.`, for a different job. |
| header values are also compared against `encodeURIComponent(value)` | not compared | That arm is unreachable upstream: the haystack is lowercased while `encodeURIComponent` emits upper-case hex. |

A filter whose condition cannot be parsed at all (`includeFilter://`, an empty header
key) is dropped, exactly as upstream drops it — the rule then applies without that
condition.

### Disabling operators

| Operator | Value | Effect |
|----------|-------|--------|
| `ignore` | protocol name(s), or `all` | Drop those operators from the resolved set for matching requests |

```
.example.com   host://10.0.0.1
static.example.com   ignore://host        # this host keeps its real destination
example.com/health   ignore://all         # bypass every rule for this path
```

`ignore://` followed by a **[filter condition](#filter-conditions)** rather than a
protocol name is an *exclude filter*, not this operator — `ignore://m:POST` skips the
rule for POST requests, exactly like `excludeFilter://m:POST`. Upstream routes both
spellings through the same parser (`_original/lib/rules/rules.js:57`). The two readings
cannot collide: a protocol name carries no `:`, `.` or `=`.

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
| `reqHeaders` | `name=value` pairs (`&`-separated) or `{json}` | Set/replace request headers (empty value deletes). Accumulates across lines. |
| `ua` | user-agent string | Set the `User-Agent` header |
| `referer` | URL | Set the `Referer` header |
| `method` | HTTP method | Override the request method |
| `reqType` | MIME type or short name | Set the request `Content-Type` (`reqType://json`, `reqType://form`, …) |
| `reqCharset` | charset | Set the charset on the request `Content-Type` |
| `reqCors` | origin | Set the request `Origin` header |
| `auth` | `user:pass` | Add an HTTP Basic `Authorization` header |
| `forwardedFor` | IP | Set the `X-Forwarded-For` header |
| `reqWrite` | file path | Append the request body to a file |

```
example.com   reqHeaders://x-token=abc
example.com   reqHeaders://x-a=1&x-b=2
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
| `enable` | flag(s) | `abort` (drop the request), `cors` (as `resCors://enable`), `safeHtml`/`strictHtml` (gate every injection), `keepCSP`/`keepCache`/`keepAllCache` (survive an injection) |
| `disable` | flag(s) | `cache` (`no-cache`), `csp`, `cookies`, `doctype` (no doctype before an HTML prepend), `keepAlive` (`Connection: close`) |
| `trailers` | `name=value` / `{json}` | Emit HTTP response trailer headers (forces chunked) |
| `headerReplace` | `{"<scope>.<name>:<pattern>":"<repl>"}` | Rewrite a header value; scope is `req.`/`reqH.`/`res.`/`resH.` |
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
example.com         headerReplace://{"resH.set-cookie:/Domain=[^;]+/":"Domain=example.com"}
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
| `replaceStatus` / `statusCode` | status number | Replace the upstream response status (401/407 also send the matching auth challenge) |
| `resHeaders` | `name=value` pairs (`&`-separated) or `{json}` | Set/replace response headers (empty value deletes). Accumulates across lines. |
| `resType` | MIME type or short name | Set the response `Content-Type` |
| `resCharset` | charset | Set the charset on the response `Content-Type` |
| `resCors` | origin, `*`, `enable`, `{json}` or `k=v&…` | Negotiate the CORS response headers |
| `attachment` | filename (optional) | Force download via `Content-Disposition: attachment` |
| `cache` | `no`/`no-cache`/`no-store`/seconds/`keep` | Set `Cache-Control`, `Expires` and `Pragma` |
| `resWrite` | file path | Append the response body to a file |

```
example.com        resHeaders://x-mitm=intercepted
example.com/api    resCors://*
cdn.example.com    resType://application/javascript
example.com/404    replaceStatus://200
example.com        cache://no
```

**`resType` / `reqType`** take a short name as well as a full MIME type:
`resType://json` sets `application/json`, `reqType://form` sets
`application/x-www-form-urlencoded`, and an unknown name falls back to
`application/octet-stream`. A value with no `;` keeps the parameters already on
the header, so `resType://json` on a `text/html; charset=gbk` response yields
`application/json; charset=gbk`.

**`cache`** accepts only a leading integer (`cache://600`, and `cache://60s` is
60 seconds — `parseInt` semantics) or `no`/`no-cache`/`no-store`; `keep` and
`reserve` leave the upstream headers alone, and **any other value is ignored**,
matching upstream. Whatever it sets, it also writes `Expires` and `Pragma`.

**`resCors`** mirrors whistle's negotiation rather than blanket-allowing:

| Value | Effect |
|-------|--------|
| `*` | `Access-Control-Allow-Origin: *`, no credentials |
| a URL | that URL's origin, plus `Access-Control-Allow-Credentials: true` |
| `enable` / `credentials` / `use-credentials` | echo the request's own `Origin`, with credentials |
| `{"methods":…,"headers":…,"credentials":…,"maxAge":…}` or `methods=…&maxAge=…` | set those headers explicitly |

`headers` becomes `Access-Control-Expose-Headers` on a normal request and
`Access-Control-Allow-Headers` on a preflight; on a preflight with `*`/`enable`,
the request's own `Access-Control-Request-Headers` is echoed back. `enable://cors`
is **not** an upstream flag — whistle-rs keeps it as an alias for
`resCors://enable`.

### Deleting

| Operator | Value | Effect |
|----------|-------|--------|
| `delete` | one or more keys, separated by `\|` or `&` | Remove headers, cookies, body properties, or the type/charset |

Keys are matched against a fixed set of spellings; **anything else is silently
ignored**, exactly as upstream. In particular a bare `delete://server` deletes
nothing — you need a scope.

| Key | Deletes |
|-----|---------|
| `resHeaders.x` / `res.headers.x` / `resH.x` / `res.h.x` | that response header (case-insensitive scope) |
| `reqHeaders.x` and the same variants | that request header |
| `headers.x` | the header on both sides (this spelling is case-**sensitive** and must be plural) |
| `reqCookies.x` / `cookies.x` | that cookie from the request `Cookie` header |
| `resType` / `res.type`, `reqType` / `req.type` | the media type (a `charset` parameter survives) |
| `resCharset` / `res.charset`, `reqCharset` / `req.charset` | the charset parameter |
| `body`, `res.body`, `req.body` | the whole body, including anything an operator injects |
| `resBody.a.b` / `resB.a.b`, `reqBody.a.b` | that dotted path from a JSON body |

```
example.com   delete://resHeaders.server|resHeaders.x-powered-by
example.com   delete://reqCookies.tracking
example.com   delete://resBody.debug&resBody.internal.token
```

### Cookies

| Operator | Value | Effect |
|----------|-------|--------|
| `reqCookies` | `name=value` pairs (`&`-separated) or `{json}` | Merge into the request `Cookie` header. Accumulates across lines. |
| `resCookies` | `name=value` pairs (`&`-separated) or `{json}` | Set `Set-Cookie` headers. Accumulates across lines. |

A name written with no `=` gets an **empty value** — it does not delete the
cookie. To remove one, use `delete://reqCookies.<name>`. A `resCookies` entry
**replaces** a `Set-Cookie` the response already sent under the same name rather
than adding a second one.

```
example.com   reqCookies://sid=abc&locale=en
example.com   delete://reqCookies.tracking   # this is how you drop one
example.com   resCookies://theme=dark
```

### Body

| Operator | Value | Effect |
|----------|-------|--------|
| `reqBody` / `resBody` | replacement text | Replace the entire body |
| `reqReplace` / `resReplace` | `from=to` pairs, `&`-separated | Substitute inside the body |
| `reqPrepend` / `resPrepend` | text | Insert at the start of the body |
| `reqAppend` / `resAppend` | text | Insert at the end of the body |
| `resMerge` | `{json}` | Deep-merge a patch into a JSON response body |
| `cssBody`/`cssPrepend`/`cssAppend` | CSS, or a URL | CSS to add to a **CSS or HTML** response |
| `htmlBody`/`htmlPrepend`/`htmlAppend` | markup | Markup to add to an HTML response |
| `jsBody`/`jsPrepend`/`jsAppend` | JavaScript, or a URL | JS to add to a **JS or HTML** response |

When any body operator applies, whistle-rs buffers that body, transforms it, and
recomputes `Content-Length` (dropping any `Transfer-Encoding`). Requests and
responses without a body operator are streamed through untouched.

```
api.example.com/echo   reqBody://{"mocked":true}
example.com/app.js     resBody://console.log('patched')
example.com            resReplace://http://=https://
example.com            resReplace:///v\d+/g=vX         # regex form
example.com/page       resPrepend://<!-- via whistle-rs -->
example.com/page       jsAppend://https://cdn.test/debug.js
```

#### Which typed operator applies to which response

`jsXxx` and `cssXxx` are **not** limited to JS and CSS responses: an HTML
response accepts all three families, which is what makes `jsAppend://alert(1)`
on a page work. On markup the value is wrapped before it goes in — JavaScript in
`<script>…</script>`, CSS in `<style>…</style>` — and a value that is a bare URL
(`https://…` or `//…`) becomes `<script src="…">` / `<link rel="stylesheet">`
instead. Line properties on a `jsXxx` rule become attributes of the generated
`<script>`: `crossorigin`, `anonymous`, `use-credentials`, `defer`, `async`,
`nomodule`, `module`, `importmap`, `speculationrules`.

```
example.com/page  jsAppend://https://cdn.test/a.js  lineProps://defer|module
```

#### Order of operations

Operators do **not** run in the order they are written. Matching whistle's
pipeline, a response is transformed as:

1. `resMerge` and `delete://resBody.…`
2. `resReplace`
3. the injection: `*Body` replaces the body, `*Prepend` goes before it and
   `*Append` after — with the contributors of each slot in the order `res*`,
   `css*`, `html*`, `js*`, joined by CRLF

So a substitution never sees prepended or appended text, and a `*Body` discards
whatever `resMerge`/`resReplace` produced. **The request is the other way round:**
the injection runs first and `reqReplace` afterwards, so it *does* see the
injected text.

Two side effects come with an injection into a response, as upstream: the
`Content-Security-Policy` headers are stripped (so the injected script is not
blocked) and the response is made uncacheable. `enable://keepCSP` and
`enable://keepCache` opt out of each; an explicit `cache://` also survives.
A non-empty prepend into an **HTML** response is additionally preceded by
`<!DOCTYPE html>`, which `disable://doctype` turns off.

#### `*Replace` details

The value is a list of `pattern=replacement` pairs separated by `&`
(`resReplace://a=1&b=2` is two substitutions). A pattern spelled exactly
`/source/flags` — flags drawn from `igmu`, at most four — is a regular
expression; **anything else is a literal string**, replaced everywhere it
occurs. The regexp form follows JavaScript, so without the `g` flag only the
*first* match is replaced. `$&` and `$1`…`$9` work in the replacement, and
`/.*/ ` or `/.+/` replaces the whole body.

`resReplace` is skipped entirely for a response with no `Content-Type` or an
image one. `*Replace` on a non-UTF-8 (binary) body is a no-op.

#### `resMerge` details

`resMerge` applies only to a JavaScript, HTML, JSON or `Content-Type`-less
response. It merges into the **first JSON-looking substring** of the body rather
than the whole body, so a JSONP payload keeps its callback wrapper:

```
api.test/jsonp   resMerge://{"ok":true}     # cb({"a":1}) → cb({"a":1,"ok":true})
```

An HTML (or typeless) body that does not *start* with `{`/`[` is left alone, and
an empty body is replaced by the patch outright.

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
   `reqCookies`, `resCookies`, `reqCors`, `resCors`, `trailers`, `plugin`, `log`,
   `delete`, `params`, `urlParams`, `headerReplace`, `enable`, `disable`, `ignore`,
   `pipe` — where every matching value is kept, in top-to-bottom order.

Within a pass, rules are evaluated in **file order**, so put more specific / higher
priority rules earlier (or mark them `$`).

> whistle also accumulates the **body** operators (`resBody`, `resPrepend`,
> `resAppend`, the `html`/`js`/`css` families, `resReplace`, `resMerge`,
> `reqBody`, `reqPrepend`, `reqAppend`, `urlReplace`); whistle-rs keeps only the
> first matching line of each. Write one line per body operator.

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
| Content-type body | `cssBody`/`cssPrepend`/`cssAppend`, `htmlBody`/`htmlPrepend`/`htmlAppend`, `jsBody`/`jsPrepend`/`jsAppend` (the JS and CSS families reach HTML responses too, wrapped as markup) |
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
conversion approximated); `enable`/`disable` apply a curated flag set (see the
[Flags](#flags-includes--values) table — others are inert); `pipe` routes to a
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

whistle's plugin variables (`%name=…`) and its Node-object plugin API are not
implemented — plugins here are external HTTP servers speaking whistle-rs's own
protocol (see [`PLUGINS.md`](PLUGINS.md)). Template variables and `lineProps`
*are* implemented; see [`TEMPLATES.md`](TEMPLATES.md) and
[`LINE_PROPS.md`](LINE_PROPS.md) for exactly how far.
Patterns/operators outside the documented forms may parse but not behave exactly as
in upstream whistle.

Known gaps in the operator layer, deliberately left:

- **Body operators are first-match-wins here, accumulating upstream.** whistle
  lists `resBody`, `resPrepend`, `resAppend`, the `html`/`js`/`css` families,
  `resReplace`, `resMerge`, `reqBody`, `reqPrepend`, `reqAppend` and `urlReplace`
  among its multi-match protocols, so several matching lines all contribute
  (CRLF-joined for the injecting ones, applied in turn for `resReplace`, deep-merged
  for `resMerge`). whistle-rs keeps only the first matching line of each.
- **`attachment://` with no value** cannot derive a filename from the request URL
  yet — it emits a bare `Content-Disposition: attachment` where upstream would say
  `filename="report.csv"`. Give the name explicitly to be sure.
- **`resCors` cannot echo the request's `Origin` or recognise a preflight** on the
  live path for the same reason; the explicit forms (`*`, a URL, `methods=…`) work.
- **Injected text is UTF-8.** whistle re-encodes it into the response's declared
  charset; a `charset=gbk` page will see mojibake in the injected fragment.
- **`params://` on a request body** is treated as query parameters only. whistle
  also merges them into a form, multipart or JSON request body.
- **`delete://resCookies.x`** does not emit the expiring `Set-Cookie` upstream
  writes, and `delete://trailer.x` is not applied.
- **A cookie declared as a JSON object** (`resCookies://{"sid":{"value":"x","httpOnly":true}}`)
  is serialised rather than expanded into `Set-Cookie` attributes.
- **`headerReplace`'s `$$`-prefixed URL-encoding form** and its quirk of letting an
  unprefixed key inherit the previous key's scope are not ported.

If a rule doesn't do what you expect, run with `-v` (debug logging) — each request
logs its resolved destination or short-circuit decision.
