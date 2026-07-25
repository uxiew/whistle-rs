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

Route the forwarded request through another proxy. The address is
`[user[:pass]@]host[:port]`; the port defaults to 80 (http), 443 (https) or
1080 (socks), and an IPv6 literal may be bracketed (`[::1]:8888`) or bare.

| Operator | Value | Effect |
|----------|-------|--------|
| `proxy` / `http-proxy` | `[user[:pass]@]host[:port]` | Route via an HTTP proxy |
| `https-proxy` | `[user[:pass]@]host[:port]` | Same, but the connection *to the proxy* is TLS |
| `socks` | `[user[:pass]@]host[:port]` | Route via a SOCKS5 proxy |
| `http2https-proxy` | `[user[:pass]@]host[:port]` | HTTP proxy, and the **origin** is reached over TLS even for an `http://` request |
| `https2http-proxy` / `internal-proxy` / `internal-http-proxy` | `[user[:pass]@]host[:port]` | HTTP proxy to another whistle: an `https://` origin's TLS is **stripped** for the hop |
| `internal-https-proxy` | `[user[:pass]@]host[:port]` | The same, with a TLS connection to the proxy |

```
example.com        proxy://127.0.0.1:8888
.internal.corp     http-proxy://user:pass@10.0.0.1:3128
secure.example.com socks://127.0.0.1:1080
```

**Scheme-converting proxies.** Two families change what the *origin* connection
speaks, which is the whole point of their names:

- `http2https-proxy://` reaches the origin over TLS even though the request was
  `http://` (`options.protocol = 'https:'`,
  `_original/lib/inspectors/res.js:236-237`);
- `https2http-proxy://` and the `internal-*` family hand the next hop a
  **plaintext** request — they exist to chain to another whistle, which wants to
  inspect it — and carry the original scheme in the
  `x-whistle-https-request` header so that whistle restores it
  (`res.js:229-234`, `lib/init.js:190-193`). whistle-rs sets that header when it
  is the sending side and honours (and strips) it when it is the receiving one,
  so two whistle-rs instances chain the way whistle does. Point one at a proxy
  you do not control and the request travels in the clear.

**How the hop is made.** Only a plain HTTP proxy fetching a plain HTTP origin
sends the request in absolute-form (`GET http://host/path`); a TLS origin, a
SOCKS proxy, an HTTPS proxy, and a `host://` override travelling with the proxy
each open a `CONNECT` tunnel instead. The absolute-form URI names the host from
the request's `Host` header, so a `reqHeaders://` rule that rewrote `Host` is
honoured and a `host://` override is never handed to the upstream proxy.

**What travels on the hop.** The `CONNECT` carries `Host`,
`Proxy-Connection: keep-alive`, the client's `User-Agent`, and
`Proxy-Authorization` — taken from the proxy URL's credential if it has one,
otherwise from the client's own `Proxy-Authorization`. A credential without a
password (`proxy://user@host`) is base64'd verbatim, matching whistle: it sends
`Basic base64("user")`, not `Basic base64("user:")`. SOCKS5 splits the same
credential at the first colon and sends an empty password. Hostnames are handed
to the proxy unresolved (SOCKS5 address type 3), so the proxy does the DNS.

If the upstream proxy is unreachable or refuses the `CONNECT`, the request
fails with a 502 — it is never retried directly. The same goes for a proxy
operator whose value is empty or unusable (`proxy://`, `socks://@`): the request
fails with `proxy:// is not a usable proxy address` rather than quietly becoming
a direct connection. whistle drops such a rule and connects direct; a rule that
names a proxy and is silently ignored is exactly the failure this port refuses
to reproduce.

**Dropping the proxy.** `ignore://proxy` names the whole family, so it drops
whichever proxy operator matched — `socks://`, `https-proxy://`,
`http2https-proxy://` and the rest, not just a literal `proxy://`. That is
whistle's behaviour, which keeps all of them under one protocol key
(`resolveProxy`, `_original/lib/rules/rules.js:2419-2443`). Naming one spelling
(`ignore://socks`) drops only that one. When a proxy operator matched and was
ignored, a `pac://` rule on the same request is **not** consulted as a fallback
(`_original/lib/rules/index.js:238`); `ignore://pac` drops a PAC rule on its own.

```
example.com   socks://127.0.0.1:1080
example.com   ignore://proxy          # → direct, despite the socks rule
```

**A proxy that is this proxy.** `proxy://127.0.0.1:8899` — this proxy's own port
on this machine, `--socks-port` included — would send the request back to
whistle-rs, which would match the same rule and do it again until the process
ran out of sockets. Such a hop is refused: the request is answered with a 302 to
whistle-rs's own port (whistle's answer on the HTTP path,
`_original/lib/inspectors/res.js:302-316`) and the log carries a
`self loop via <address>` warning. Reaching the origin directly on our own port
is left alone: it cannot recurse, because the request we send is not a proxy
request.

**Combining with `host://`.** By default a matching `host://` wins outright and
the proxy is dropped. `proxyHost` (as `lineProps://proxyHost`, as
`enable://proxyHost`, or written into the proxy's own URL as
`http-proxy://…?proxyHost`) keeps both: the request reaches the origin through
the proxy, and the proxy is asked to connect to the `host://` address.
`proxyFirst` prefers the proxy, and `proxyHostOnly` behaves as `proxyHost` but
additionally drops the proxy when no `host://` matched.

```
pinned.test        http-proxy://127.0.0.1:8888?proxyHost
pinned.test        host://10.0.0.9
```

Precedence when several proxy operators match: `socks` > `https-proxy` >
`http-proxy` > `proxy` > `internal-https-proxy` > `internal-proxy` >
`internal-http-proxy` > `https2http-proxy` > `http2https-proxy` > `pac`.

#### PAC

`pac://<location>` evaluates a PAC file's `FindProxyForURL(url, host)` to pick
the proxy. The result is read left to right; the first `PROXY`/`HTTP host:port`,
`HTTPS host:port` or `SOCKS`/`SOCKS5 host:port` entry wins, and `DIRECT` —
anywhere in the list — means connect without a proxy.

The location may be a local file, a `http(s)://` URL, or (whistle-rs only) the
script itself inline, which in practice means a script with no whitespace in it,
since a rule token ends at the first space.

```
.corp.example.com   pac:///etc/whistle/corp.pac
.corp.example.com   pac://http://wpad.corp.example.com/proxy.pac
```

A remote PAC file is fetched once and cached for 5 minutes, up to ten files at a
time (whistle caches ten and never re-reads them, `cachedPacs`,
`_original/lib/rules/index.js:264-274`). If a refresh fails, the cached copy
keeps being used.

The helper functions a PAC file may call are all present: `isPlainHostName`,
`dnsDomainIs`, `localHostOrDomainIs`, `isResolvable`, `isInNet`, `dnsResolve`,
`myIpAddress`, `dnsDomainLevels`, `shExpMatch`, `weekdayRange`, `dateRange`,
`timeRange`, `convert_addr`, `alert`, and Microsoft's `isResolvableEx`,
`isInNetEx`, `dnsResolveEx`, `myIpAddressEx`, `sortIpAddressList`,
`getClientVersion`. A script that defines its own copy of one overrides ours.
Name resolution is IPv4-only, so the `*Ex` helpers answer from the same data
rather than pretending to know more.

**A PAC file that fails does not mean `DIRECT`.** If the script cannot be
fetched or read, does not parse, defines no `FindProxyForURL`, throws, or
returns something with no usable entry (a `SOCKS4` proxy, say — this port speaks
SOCKS5 only), the request **fails with a 502** naming the reason. whistle logs
the error and connects direct (`_original/lib/rules/index.js:295`); a rule that
pins traffic to a corporate proxy and silently stops doing so is the one outcome
worth refusing. Only an explicit `DIRECT` is a direct connection.

Still missing: a `user@` prefix on the PAC URL is not read as a proxy credential
(upstream's `_pacAuth`), and `SOCKS4` is not supported.

### URL rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `urlReplace` | `from=to` (or `/regex/[i]=to`) | Substitute inside the request path+query (accumulates) |
| `params` | `k=v&k2=v2` or `{json}` | Add/override params — in the **request body** when the request has one whistle recognises, otherwise in the query string (accumulates) |
| `urlParams` | `k=v&k2=v2` or `{json}` | Add/override **query** params, always (accumulates) |

```
example.com/api    urlReplace://v1=v2                 # /api/v1/x -> /api/v2/x
example.com/api    urlReplace:///users\/\d+/=/users/me # regex form
example.com        params://debug=1&trace=on
```

> Note the `/regex/` convention: since paths start with `/`, write literals without
> surrounding slashes (`urlReplace://old=new`) and reserve `/…/` for regexes.

#### Where `params://` lands

`params` addresses **one** place, never both — upstream's `_params = hasBody ? null :
params` (`handleParams`, `_original/lib/inspectors/req.js:157-232,421`). The request's
method and `Content-Type`, *as forwarded* (so after `method://`, `reqType://` and
`reqHeaders://`), decide which:

| Request | Where the params go |
|---|---|
| `Content-Type: multipart/…` **with a `boundary=`** | the body: a part with a matching `name=` is replaced whole, the rest are appended as new parts |
| `Content-Type: application/x-www-form-urlencoded`, **POST only** | the body, as a query string |
| a JSON content type, on any method that may carry a body (not `GET`/`HEAD`/`OPTIONS`/`CONNECT`) | the body, **deep**-merged into its first JSON-looking span |
| anything else | the query string |

The POST-only rule for form bodies is upstream's `isUrlEncoded`
(`_original/lib/util/common.js:692-695`); the same rule on a `PUT` sends the params to
the query string in both implementations.

`delete://reqBody.<path>` rides the same transform, so it too applies only to a body of
one of those three kinds: a dotted path out of a JSON body, a name out of a form body
or a multipart part.

An empty body becomes the params outright — `{"a":"1"}` for JSON, `a=1` for a form.
`params://{"a":{"b":1}}` keeps its structure into a JSON body; against a form body it is
serialised (whistle writes `a[b]=1` there instead).

```
api.example.com   params://uid=42            # POSTed form/JSON body gains uid
api.example.com   urlParams://trace=1        # ?trace=1, whatever the body is
api.example.com   delete://reqBody.password  # dropped from the body
```

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
| Request header | `reqH.<key>:<v>` ← canonical; also `reqH.<key>=<v>`, `req.`/`reqHeader.`/`reqHeaders.`, `reqH:<key>=<v>` | header **contains** `<v>`, case-insensitively. No `<v>` = presence test |
| Either header | `h:<key>=<v>`, `header:<key>=<v>` | the **request's** header, falling back to the **response's** when the request has no such key — see [response phase](#the-response-phase) |
| Response header | `resH.<key>:<v>`; also `res.`/`resHeader.`/`resHeaders.` | that response header, by containment (response phase) |
| Status | `s:<v>`, `statusCode:<v>` | the response status (response phase) |
| Method | `m:<v>`, `method:<v>` | request method (regexps always ignore case) |
| Client IP | `clientIp:<v>`, `clientIP:`, `remoteAddress:<v>` | the client's IP |
| Client or server IP | `i:<v>`, `ip:<v>` | the client's IP — see the note below |
| Client port | `clientPort:<v>`, `remotePort:<v>` | the client socket's port |
| Server address | `serverIp:<v>`, `serverIP:` | the address the request was sent to, when it is known exactly (response phase) |
| Server port | `serverPort:<v>` | the port the request was sent to (response phase) |
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

#### The response phase

whistle resolves a request's rules **twice**: once before the request is sent
(`resolveReqRules`) and again once the response head has arrived
(`resolveResRules` → `pluginMgr.getResRules`, `_original/lib/rules/rules.js:2302-2308`,
`lib/plugins/index.js:1322`). That second pass is what lets a rule ask about the
response. whistle-rs does the same.

**What each pass decides.** Upstream splits the operators between the passes and this
port follows it: the response phase owns `pureResProtocols`
(`_original/lib/rules/protocols.js:82-111`) —

> `replaceStatus`, `cache`, `attachment`, `resMerge`, `resDelay`, `resSpeed`,
> `resType`, `resCharset`, `resCookies`, `resCors`, `resHeaders`, `trailers`,
> `resPrepend`, `resBody`, `resAppend`, `resReplace`, `resWrite`, `resWriteRaw`,
> `cssAppend`/`htmlAppend`/`jsAppend`, `cssBody`/`htmlBody`/`jsBody`,
> `cssPrepend`/`htmlPrepend`/`jsPrepend`, `responseFor`, `log`, `weinre`

— and everything else is decided before the request goes out. So a response condition
can turn `resHeaders://` on, and can never turn `host://` on:

```
example.com   resHeaders://x-slow=1   includeFilter://s:/^5/   # applies on a 5xx
example.com   host://10.0.0.1         includeFilter://s:200    # never applies
```

The second line is not an error — upstream evaluates it too, in the request phase,
where the status is still unknown and the condition therefore fails (see
[fail-closed](#conditions-that-still-cannot-be-evaluated) below). By the time the
status is known the request has already gone to the origin the rules chose.

**Which conditions the second pass answers:** `s:`/`statusCode:`, `resH.` (and its
`res.`/`resHeader.`/`resHeaders.` spellings), `serverIp:`, `serverPort:`, and the
response-header fallback of `h:`/`header:`. In the request phase they are unanswerable
and fail closed; a `!` cannot rescue them there, and can once the answer is known:

```
example.com   resHeaders://x-not-ok=1   includeFilter://s:!200
```

**Precedence.** The two passes are merged by *source order*: an operator carries the
position of the line that wrote it, so the winner is the same one a single walk over
the file would have picked, whichever pass resolved it.

```
example.com   replaceStatus://502
example.com   replaceStatus://500   includeFilter://s:404      # 502 wins, it is first
```

> Upstream's `mergeRule` (`_original/lib/util/index.js:2147-2171`) instead prefers the
> response pass unconditionally. It can afford to: its two passes read *disjoint*
> protocol sets, so it never holds two operators for the same protocol from the same
> rules file. Here they can meet, and source order is what reproduces upstream's
> observable behaviour.

`ignore://` resolved in the response phase reaches what the request phase had already
resolved, restricted to the response-phase protocols above — upstream's
`ignoreRules(origin, …, isResRules)` (`_original/lib/util/index.js:2083`). So
`ignore://resHeaders includeFilter://s:404` suppresses response headers set by *other*
lines when the origin answered 404, and never touches `host://`.

**Cost.** Each rule group records, when it parses, which of its lines could need the
phase. A rules file that never mentions the response skips the second pass entirely
(measured at ~2 ns per response, against ~2.4 µs for a 500-rule request pass), and a
file that does pays for those lines only — one conditional line in 500 costs ~24 ns.

**Not covered by the second pass:** rules pulled in by `rule://` / `rulesFile://` and
rules injected by a plugin are resolved once, in the request phase. Upstream
re-resolves those managers too (`fRules`/`pRules`/`hRules` in `getResRules`).
WebSocket and tunnelled (`CONNECT`) traffic have no response phase here either.

`serverIp:` is answered when the address the request went to is known **exactly** — an
IP-literal origin, or a `host://` override naming an address. For a named origin this
port hands the name to the connect call and never sees which address it picked; asking
the resolver a second time could answer differently, so the condition stays
unanswerable and fails closed rather than matching a guess.

#### Conditions that still cannot be evaluated

These are **parsed and recognised**, so they are never mistaken for a URL pattern, but
they evaluate to "unknown". Upstream's `getFilterResult`
(`_original/lib/rules/rules.js:1809`) turns an unknown answer into `false` *before* it
consults `!`, and this port does the same: an include filter is never satisfied, an
exclude filter never fires, and no `!` can flip either. The subsystem fails closed —
in the request phase this is also how every response condition above behaves.

| Condition | Would need |
|---|---|
| `b:<v>`, `body:<v>` | the request body buffered *before* rules resolve (upstream pre-reads it when a line carries a body filter) |
| `env:<key>=<v>` | the plugin environment store |
| `from:<v>` | the request's origin flags (`tunnel`, `composer`, `sni`, …), which the proxy layer knows but does not pass to the matcher |

#### Remaining divergences from upstream

| Upstream | Here | Why |
|---|---|---|
| `i:` matches the client IP, then falls back to the server IP | client IP only | Upstream's server-IP arm is unreachable: `filterProp` reports an ip filter as handled the moment `req.clientIp` is null, so the `req.hostIp` line below it never runs for one (`rules.js:1824-1830,:1875-1880`). Write `serverIp:` for the server's address. |
| the response pass wins when both passes resolve one protocol | source order wins | See [the response phase](#the-response-phase): upstream's two passes read disjoint protocols and never face the case. |
| `remoteAddress:`/`remotePort:` are the raw socket, distinct from `clientIp:`/`clientPort:` | the same socket | The two differ upstream only for a request forwarded by another whistle, whose client-IP override headers this port does not honour. |
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
| `reqCors` | origin URL, `*`, or `method=…&headers=…` | Set the request `Origin`, and the `Access-Control-Request-Method` / `-Headers` preflight headers. A URL is reduced to its origin. `enable` is the *response*-side spelling and does nothing here. |
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
| `rulesFile` | file path | Include rules from a file and apply them too. Also spelled `reqRules://`, `ruleFile://`, `ruleScript://`, `rulesScript://`, `reqScript://` — see below |
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

#### How several `rulesFile://` lines combine

`rulesFile` accumulates, but its list is filtered before the files are read
(`_original/lib/rules/rules.js:2258-2272`), and the filter turns on how the line was
*spelled*:

* `reqRules://<path>` says "this file is rules" — **every** such line is kept;
* any other spelling (`rulesFile://`, `ruleFile://`, `ruleScript://`,
  `rulesScript://`, `reqScript://`) marks a *candidate script*, and **only the first**
  survives. A second one is dropped silently.

The surviving files are concatenated, in resolution order, and parsed as **one** rules
text — so a single-value protocol contested between two of them is decided by the
order they were included in, not by which file it came from.

```
example.com   reqRules:///etc/whistle/a.rules     # kept
example.com   reqRules:///etc/whistle/b.rules     # kept
example.com   rulesFile:///etc/whistle/c.rules    # kept (first non-reqRules line)
example.com   rulesFile:///etc/whistle/d.rules    # dropped
```

> whistle additionally *executes* the surviving candidate when its content looks like
> JavaScript rather than rules (`isRulesContent`, `_original/lib/rules/index.js:41`),
> and splices the rules the script emits into the join. whistle-rs has no dynamic-rules
> script: every kept file is read as rules text.

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

Every operator in this table accumulates: writing the same one on several
matching lines makes them all contribute, joined per family — see
[How several lines of one operator combine](#how-several-lines-of-one-operator-combine).

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
   `css*`, `html*`, `js*`, joined by CRLF. Every one of these operators is
   multi-match, so each contributor may itself be several lines; see
   [How several lines of one operator combine](#how-several-lines-of-one-operator-combine).

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

Several matching lines do **not** run as separate passes: their pairs are
collapsed into one map first, so a pattern written twice takes the first line's
replacement. See [How several lines of one operator
combine](#how-several-lines-of-one-operator-combine).

#### `resMerge` details

`resMerge` applies only to a JavaScript, HTML, JSON or `Content-Type`-less
response. It merges into the **first JSON-looking substring** of the body rather
than the whole body, so a JSONP payload keeps its callback wrapper:

```
api.test/jsonp   resMerge://{"ok":true}     # cb({"a":1}) → cb({"a":1,"ok":true})
```

An HTML (or typeless) body that does not *start* with `{`/`[` is left alone, and
an empty body is replaced by the patch outright.

Several matching lines fold into one patch before that merge, and the fold is
**shallow** — `resMerge://true` is whistle's marker line for making it deep:

```
api.test/data  resMerge://{"n":{"y":8}}
api.test/data  resMerge://{"n":{"w":7}}   # dropped: shallow, first line wins `n`
api.test/data  resMerge://true            # …unless this asks for a deep fold
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
3. **Accumulate** for multi-match protocols — whistle's `multiMatchs` list, kept
   as it is: `enable`, `disable`, `ignore`, `filter`, `delete`, `plugin`,
   `style`, `cipher`, `trailers`, `urlParams`, `params`, `headerReplace`,
   `reqHeaders`, `resHeaders`, `reqCors`, `resCors`, `reqCookies`, `resCookies`,
   `reqReplace`, `urlReplace`, `resReplace`, `resMerge`, `reqBody`, `reqPrepend`,
   `reqAppend`, `resBody`, `resPrepend`, `resAppend`, the `html`/`js`/`css`
   families, `rulesFile`, `resScript`, `G` (plus `log` and `pipe`, which this
   port also accumulates) — where every matching value is kept, in top-to-bottom
   order.

Within a pass, rules are evaluated in **file order**, so put more specific / higher
priority rules earlier (or mark them `$`).

### How several lines of one operator combine

A multi-match protocol still has a *winner* — the first match, important lines
first — and anything reading a single value (`host`, a file path, a flag) uses it.
The operators that consume the whole list combine it differently per family:

| Family | Combination |
|--------|-------------|
| `resBody` / `resPrepend` / `resAppend`, `reqBody` / `reqPrepend` / `reqAppend`, and the typed `htmlBody`, `jsAppend`, `cssPrepend`, … | **CRLF-joined** in resolution order. Blank lines drop out of the join. Each typed line is wrapped on its own, so two `jsAppend://` lines are two `<script>` tags, each with its own `lineProps` attributes. |
| `reqReplace` / `resReplace` / `urlReplace` | Collapsed into **one pattern map**. Every pattern applies; a pattern written on two lines takes the **first** line's replacement. The map's order is the last line's patterns first, then whatever each earlier line adds — so substitutions chain in that order. |
| `resMerge` | Collapsed into **one patch**, first line winning a contested key. The fold is **shallow** unless one of the lines is the literal `resMerge://true`, whistle's marker for a deep fold; that line contributes no data of its own. The combined patch is then deep-merged into the body. |
| `params` / `urlParams` | Collapsed into one map each, first line winning a contested key; `urlParams` is then laid over `params`. |
| `reqHeaders` / `resHeaders` / `reqCookies` / `resCookies` / `reqCors` / `resCors` / `trailers` | Collapsed into **one map**, first line winning a contested name. These are `parseRuleJson`'s own arguments (`_original/lib/inspectors/req.js:459-468`, `res.js:845-855`), so they take the same fold as `resMerge` and `params`. |
| `headerReplace` | Applied in turn, top to bottom. |

```
example.com/x  resPrepend://<!--head-->
example.com/x  jsAppend://one()
example.com/x  jsAppend://two()
# → <!DOCTYPE html><!--head--><page><script>one()</script><script>two()</script>
```

An `important` (`$`) line leads the list, so it both wins contested keys and comes
first in a join:

```
example.com/x  resAppend://normal
$example.com/x resAppend://important     # → body + "important\r\nnormal"
```

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
An `ignore://` naming an alias is normalised the same way, so `ignore://hosts`
drops `host://` and `ignore://xproxy` drops the upstream-proxy family.

Notes: `http2https-proxy`/`https2http-proxy` and the `internal-*` family do
convert the origin scheme, and the stripped-TLS hop carries whistle's
`x-whistle-https-request` marker (see [Upstream proxy](#upstream-proxy)); what is
still missing from the `internal-*` family is the rest of whistle's
whistle-to-whistle handshake — the client-id and intercept-policy headers. The
`x`-prefixed variants (`xproxy://`, `xsocks://`, …) are aliases of their base
proxy: upstream falls back to a **direct** connection when the proxy fails, this
port does not and returns 502. `enable`/`disable` apply a curated flag set (see the
[Flags](#flags-includes--values) table — others are inert); `pipe` routes to a
registered server like `plugin` (no mid-stream piping); `rule`/`rulesFile` pull in
extra rules from the values store / a file; `{name}` in any operator value is
substituted from the values store. `cipher` honours the portable part of Node's TLS
options — `minVersion`/`maxVersion`/`secureProtocol` (or a bare `cipher://TLSv1.2`
token) pin the **upstream** TLS protocol version; rustls exposes TLS 1.2 / 1.3 only,
so OpenSSL cipher-suite strings and older-than-1.2 pins are not honoured.

**Upstream certificate verification differs from whistle's.** whistle sets
`rejectUnauthorized: false` by default (`_original/lib/config.js:74`) and only
verifies when started with `--safe`, so it happily debugs origins with
self-signed, expired or private-CA certificates. This port verifies the origin
(and an `https-proxy://`) against the webpki root store by default, so those
origins return 502 here unless it is started with `--insecure-upstream`.

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

- **`resRules://` entries of a `resScript` list are not applied.** Upstream folds
  them into a rules text the response phase parses; whistle-rs's `resScript` is a
  JavaScript hook that mutates the response directly, so it has nowhere to put
  them. They are *skipped* rather than run as JavaScript — the script whistle-rs
  executes is the first entry not spelled `resRules://`, which is the one
  upstream executes too.
- **`attachment://` with no value** cannot derive a filename from the request URL
  yet — it emits a bare `Content-Disposition: attachment` where upstream would say
  `filename="report.csv"`. Give the name explicitly to be sure.
- **`resCors` cannot echo the request's `Origin` or recognise a preflight** on the
  live path for the same reason; the explicit forms (`*`, a URL, `methods=…`) work.
- **Injected text is UTF-8.** whistle re-encodes it into the response's declared
  charset; a `charset=gbk` page will see mojibake in the injected fragment.
- **`params://` into a body is buffered, not streamed.** whistle rewrites a
  multipart body part by part so an upload never lands in memory; whistle-rs has
  the body in hand already (every other request-body operator buffers) and splits
  on the boundary. Same result on a well-formed body, more memory on a large one.
  Upstream's `reqMergeBigData` / `MAX_REQ_SIZE` ceilings have no counterpart here.
- **A non-UTF-8 request body is left alone** by the `params://` merge. whistle
  tries GB18030 and re-encodes afterwards; this port stays UTF-8, as it does for
  every other text transform.
- **`delete://resCookies.x`** does not emit the expiring `Set-Cookie` upstream
  writes, and `delete://trailer.x` is not applied.
- **A cookie declared as a JSON object** (`resCookies://{"sid":{"value":"x","httpOnly":true}}`)
  is serialised rather than expanded into `Set-Cookie` attributes.
- **`headerReplace`'s `$$`-prefixed URL-encoding form** and its quirk of letting an
  unprefixed key inherit the previous key's scope are not ported.

If a rule doesn't do what you expect, run with `-v` (debug logging) — each request
logs its resolved destination or short-circuit decision.


## Origin certificate verification

whistle does **not** verify the origin server's certificate: `rejectUnauthorized`
is `false` by default and only `--safe` turns it on
(`_original/lib/config.js:74`). whistle-rs inverts that default — it verifies,
and `--insecure-upstream` opts out:

```bash
whistle-rs --insecure-upstream      # accept self-signed / private-CA origins
```

Without it, a self-signed or private-CA origin returns **502** where whistle
would have proxied it.

The inversion is deliberate and is the one place this port does not reproduce
upstream's default. Everywhere else, fidelity wins — a rules file must resolve
identically in both implementations. But a debugging proxy that silently accepts
any upstream certificate cannot tell its user when the connection it is
inspecting has itself been intercepted, and that is a property worth keeping by
default and spending a flag on.
