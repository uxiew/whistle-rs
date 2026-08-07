# Rules reference

whistle-rs uses whistle's rule syntax. This document is the complete reference for
the subset the Rust core understands. For the original, exhaustive whistle rule
documentation see <https://wproxy.org>.

> **Looking for how to *do* something?** [`COOKBOOK.md`](COOKBOOK.md) is the
> task-oriented half — serve a site from a dev server, mock an endpoint, throttle
> a connection, debug a phone — with worked, executed examples. This file is the
> reference you come back to once you know which operator you want.

## Start here

A rules file is a list of lines. Each line is **one pattern followed by any
number of operators**:

```
example.com          http://localhost:5173
└─ pattern ────┘     └─ operator ───────┘
```

The pattern decides *which requests the line applies to*; the operators decide
*what happens to them*. That is the whole grammar. Three things follow from it,
and they are what a newcomer gets wrong:

**1. Position decides, not shape.** The first token is the pattern and
everything after it is an operator, however it is spelled. So
`example.com http://localhost:5173` is "requests for example.com go to
localhost:5173" — the second token is not a second pattern, even though it looks
like a URL. The one exception is the swapped form, where an operator leads so
that several patterns can share it:

```
example.com     http://localhost:5173     # pattern, then operators
host://9.9.9.9  a.com  b.com  c.com       # operator, then patterns
```

Writing this the wrong way round is the most common way to get a rule that
silently does nothing. The console's rules editor highlights whichever token the
proxy will actually match on, so you can see the answer rather than guess it.

**2. Tokens are separated by whitespace, so an operator value cannot contain a
space.** `reqHeaders://authorization=Bearer secret` sets `authorization: Bearer`
and then reads `secret` as another operator. Percent-encoding does not help.
Put the value in the [values store](#flags-includes--values) and reference it
with `${name}`.

**3. Most operators accumulate; a few compete.** Several `resHeaders://` lines
all apply. But `file://`, `redirect://`, `statusCode://`, the template family
and a bare destination URL share **one slot**, so only the first of them to
match answers — see [Short-circuit](#short-circuit-no-upstream-request-is-made).

The four kinds of thing you can write as a pattern are a
[domain or URL prefix](#1-domain--url-prefix-most-common), a
[wildcard](#3-wildcard), a [regexp](#5-regular-expression) or a
[port](#6-port); `$` in front makes a pattern [exact](#--exact-patterns) and
`^` in front makes [`*` a wildcard everywhere](#4---wildcards-everywhere).

The operators worth knowing before the rest are
[`host://`](#destination) (change where a request goes, keep its `Host` header),
[`file://`](#short-circuit-no-upstream-request-is-made) (answer it locally),
[`reqHeaders://` / `resHeaders://`](#request-rewriting) (add a header),
[`resBody://` and friends](#body) (rewrite what comes back), and
[`includeFilter://`](#filter-conditions) (narrow any of the above).

---

## Contents

- [File format](#file-format)
- [Patterns](#patterns) — [prefix](#1-domain--url-prefix-most-common) ·
  [leading dot](#2-leading-dot-subdomain-match) · [wildcard](#3-wildcard) ·
  [`^`](#4---wildcards-everywhere) · [`$0`…`$9` captures](#09--what-the-pattern-captured) ·
  [regexp](#5-regular-expression) · [port](#6-port) · [`!` negation](#--negated-patterns) ·
  [`$` exact](#--exact-patterns)
- [Operators](#operators)
  - [Where the pattern sits](#where-the-pattern-sits) · [Shorthands](#shorthands)
  - [What an operator's value can be](#what-an-operators-value-can-be) —
    [read from a file or a URL](#values-read-from-a-file-or-a-url) ·
    [backtick templates](#backtick-templates)
  - [Destination](#destination) — [forwarding to another URL](#forwarding-to-another-url)
  - [Upstream proxy](#upstream-proxy) — [PAC](#pac)
  - [URL rewriting](#url-rewriting) — [where `params://` lands](#where-params-lands)
  - [Filter conditions](#filter-conditions) — [conditions](#conditions) ·
    [the response phase](#the-response-phase) · [the body condition](#the-body-condition) ·
    [origin markers](#origin-markers)
  - [Disabling operators](#disabling-operators) ·
    [Short-circuit](#short-circuit-no-upstream-request-is-made)
  - [Request rewriting](#request-rewriting) — [`auth://`](#auth-in-three-spellings)
  - [Plugins](#plugins) · [Choosing the MITM certificate](#choosing-the-mitm-certificate) ·
    [Scripting](#scripting) · [weinre](#weinre-html-debug-injection)
  - [Flags, includes & values](#flags-includes--values) — [trailers](#trailers) ·
    [`enable://abort`](#enableabort-is-two-gates-not-one) ·
    [several `rulesFile://` lines](#how-several-rulesfile-lines-combine)
  - [Dump files](#dump-files) · [Delays & throttling](#delays--throttling)
  - [Response rewriting](#response-rewriting) · [Deleting](#deleting) ·
    [Cookies](#cookies) · [Body](#body)
- [Precedence](#precedence) — [how several lines of one operator combine](#how-several-lines-of-one-operator-combine)
- [Quick reference](#quick-reference)
- [Operator coverage](#operator-coverage) — [applied at runtime](#applied-at-runtime) ·
  [parsed but not applied](#parsed-but-not-applied-2) ·
  [simplified vs. upstream](#simplified-vs-upstream)
- [Origin certificate verification](#origin-certificate-verification)

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

`*` is a wildcard **in the host**, and a literal everywhere else — `*` is a legal
character in a URL path, so whistle will not silently take it away from you
(`_original/docs/docs/rules/pattern.md`, "域名通配符"):

| in the host | matches |
|-------------|---------|
| `*` | any run of characters **without a dot** — `[^/?.]*` |
| `**` | any run without `/` or `?` — `[^/?]*` |
| `***` and up | as `**`, and the dot after it becomes optional |

```
*.example.com          host://10.0.0.9      # www.example.com, but not a.b.example.com
**.example.com:8*      host://10.0.0.9      # any depth, any 8xxx port
.example.com           host://10.0.0.9      # the domain itself and every subdomain
```

The path after the host is matched as an ordinary prefix, on the same segment
boundary as any other pattern.

### 4. `^` — wildcards everywhere

Prefix the pattern with `^` and `*` becomes a wildcard in the **path and query**
as well, with a reach that depends on how many you write:

| | path | query |
|---|---|---|
| `*` | within one segment (`[^?/]*`) | within one value (`[^&]*`) |
| `**` | across segments, up to the `?` (`[^?]*`) | the rest, `&` included (`.*`) |
| `***` | everything left, `?` included (`.*`) | — |

A trailing `$` anchors the end, and a `^` pattern is case-insensitive (write `^^`
to keep case significant):

```
^https://*.example.com/path/*/to$    statusCode://204
^http://*.example.com/v0/users/**    file:///mock/$1/$2
```

### `$0`…`$9` — what the pattern captured

A regexp or wildcard pattern hands what it matched to the operators on its line.
`$0` is the request URL; `$1`…`$9` are the groups, left to right — each `*` in a
`^` pattern is one, as is each `( )` in a regexp:

```
^http://*.example.com/v0/users/**       file:///mock/$1/$2
/\/regexp\/(user|admin)\/(\d+)/         reqHeaders://X-Type=$1&X-ID=$2
*.example.com/api                       reqHeaders://X-Tenant=$1
```

`$$1` inserts the group **percent-encoded**, and `\$1` is a literal `$1` — the
same escapes the [`*Replace` operators](#replace-details) use, because it
is the same expander. A pattern with no groups substitutes nothing, so a `$1` in
one of its values stays as written.

### 5. Regular expression

A pattern wrapped in slashes is a regex tested against the **full request URL**
(`scheme://host[:port]/path?query`). A trailing `i` makes it case-insensitive:

```
/\.js(\?|$)/          resType://application/javascript
/^https:\/\/cdn\./i   host://10.0.0.9
```

### 6. Port

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

### `$` — exact patterns

Prefix a pattern with `$` and the request URL must **equal** it, not begin with
it. Without `$` a pattern is a prefix, which is what makes `example.com/api`
cover everything under `/api`.

```
$http://example.com/api    file:///mock.json   # /api only
http://example.com/api     file:///mock.json   # /api and everything under it
```

The measured truth table — a pattern with no query matches on the path alone, a
pattern with one must match that too, and a pattern with no path names the site
root:

| pattern | `/p` | `/p?a=1` | `/p?b=2` | `/p/s` | `/` |
|---|---|---|---|---|---|
| `$http://example.com/p` | ✅ | ✅ | ✅ | — | — |
| `$http://example.com/p?a=1` | — | ✅ | — | — | — |
| `$example.com` | — | — | — | — | ✅ |

`!$…` is a **negated exact** pattern — every URL but that one. It is allowed
where a negated plain pattern is not, because upstream's `$` branch runs before
the check that drops those.

> **`$` carries no precedence, and this port used to think it did.** It read the
> prefix as an "important" shorthand — a divergence invented rather than
> inherited. Two things followed, both measured against whistle 2.10.8: a normal
> rule written *before* a `$` one still wins there, and `$example.com` named the
> site root where this port matched every URL on the host. Importance has one
> spelling: `lineProps://important`.

---

## Operators

An operator is `protocol://value`. whistle-rs recognises the **full whistle protocol
list** at parse time, and applies essentially all of the common operators at runtime
(see [Operator coverage](#operator-coverage) for the exceptions).

### Where the pattern sits

The first token of a line is the pattern and **every other token is an operator** —
by position, not by shape. That is what makes `example.com http://localhost:5173`
a forwarding rule rather than two patterns.

The one exception is whistle's swapped form, which lets an operator lead so that
several patterns can share it:

```
example.com    http://localhost:5173     # pattern, then operators
host://9.9.9.9  a.com  b.com  c.com      # operator, then patterns
```

whistle decides which form it is looking at by scanning for the first token that
can only be a pattern (`indexOfPattern`, `_original/lib/rules/rules.js:1449`). A
token with a `scheme://` is never it, and a **bare IP address** is never it either
— an IP is the `host://` shorthand. A *name* with a port is not that shorthand:
`localhost:8080` is a destination, `127.0.0.1:8080` is a host override.

### Shorthands

| You write | Interpreted as |
|-----------|----------------|
| `127.0.0.1:8080` | `host://127.0.0.1:8080` |
| `127.0.0.1` | `host://127.0.0.1` |
| `/abs/path` · `~/f` · `./f` | `file:///abs/path` … |
| any other URL | a destination — see below |

### What an operator's value can be

`protocol://value` — and `value` is not always the text you wrote. Six
spellings, resolved in this order:

| You write | The value becomes |
|-----------|-------------------|
| `resBody://patched` | the text `patched` |
| `resBody://(patched)` | the text `patched` — the explicit "this **is** content" form (`getValue`, `_original/lib/rules/rules.js:271-287`), and the only way to write text that would otherwise read as a path |
| `resBody://{mock}` | the whole content of the value named `mock` |
| `resHeaders://x-v=${mock}` | `x-v=` followed by that content |
| `resBody:///tmp/mock.json`<br>`resBody://https://cdn.test/mock.json` | the **contents of that file or that URL** — see below |
| ``resHeaders://`x-m=${method}` `` | rendered against the request — see [Backtick templates](#backtick-templates) |

Remember that tokens are whitespace-separated, so none of these may contain a
space. That is what the values store is for.

#### Values read from a file or a URL

Some operators take a *location* rather than a value. `readRuleValue`
(`_original/lib/util/index.js:1189-1213`) reads it before the operator is
applied, so the operator sees the file's contents:

```
example.com   reqHeaders:///etc/whistle/headers.json    # {"x-env":"staging"}
example.com   resBody://https://cdn.test/mock.json      # fetched per request
example.com   resBody://~/mock/a.html|~/mock/b.html     # both, CRLF-joined
```

**Which operators.** Two families, because upstream feeds them through two
different readers:

| Family | Operators | A value that is neither `{json}` nor `k=v` pairs |
|--------|-----------|--------------------------------------------------|
| JSON-valued (`parseRuleJson`, `_original/lib/inspectors/req.js:463-472`, `res.js:830-841`) | `reqHeaders`, `resHeaders`, `reqCookies`, `resCookies`, `reqCors`, `resCors`, `reqReplace`, `resReplace`, `urlReplace`, `params`, `urlParams`, `resMerge`, `trailers`, `auth`, `cipher` | is a location |
| Text-valued (`getRuleValue`, `req.js:545-548`, `res.js:984`) | `reqBody`, `resBody`, `reqPrepend`, `resPrepend`, `reqAppend`, `resAppend`, `htmlBody`, `htmlPrepend`, `htmlAppend` | is a location |
| Text-valued, **file only** | `jsBody`, `jsPrepend`, `jsAppend`, `cssBody`, `cssPrepend`, `cssAppend` | a path is a location; a URL is not |

The last row is upstream's own split, not a simplification: `readRuleValue`'s
`checkUrl` argument is set for exactly the `js*`/`css*` families
(`util/index.js:1339`), so on an **HTML** response a URL there stays a URL and
becomes `<script src=…>` / `<link rel=stylesheet>`, while on a JS or CSS response
the same URL is fetched and inlined. whistle-rs reads values in the request
phase, before there is a response to classify, so it keeps the HTML meaning —
which is the documented one — and never fetches for those six.

**What counts as a location.** An `http://` or `https://` URL, or a path that
starts at the root (`/tmp/x`), the home directory (`~/x`, also the full-width
`～/x`), a Windows drive (`C:\x`), or an explicit `./` / `../`.

One exception, and it is upstream's: a URL on `reqCors://` / `resCors://` is the
allowed **origin**, folded into `{"origin":…}` before anything would be read
(`isCors`, `_original/lib/util/index.js:1344,:1361-1370`). `resCors://https://app.test`
is a CORS rule, not a fetch. A *path* there is still read.

> **Deliberately narrower than upstream.** whistle has no shape test: for the
> text operators *every* non-inline value is a path, and a bare
> `resBody://patched` is a read of `./patched` — relative to the rules file's
> root (`rule.root`, which only exists for rules a plugin or an `@`-include
> brought in) or else to whistle's own working directory. It fails, and the
> operator quietly sets an **empty** body. whistle-rs has no `rule.root`, and a
> path relative to the proxy's working directory is not something a rules file
> can rely on, so a bare value stays the literal this document already
> describes. Every spelling that *works* upstream still loads.
>
> For the JSON operators there is one more narrowing: a value containing `=` is
> read as pairs and never as a path, so `urlReplace:///api/v1=/api/v2` costs no
> filesystem call. Upstream reaches the same result by the long road — it reads
> the path, gets nothing, and falls back to parsing the matcher as a query
> string (`tryParseMatcher`, `util/index.js:1165-1171,:1303`). The difference
> only shows for a file whose name contains an `=`.

**Details that matter:**

- `a|b|c` **concatenates**, CRLF-joined, missing entries dropping out
  (`readFileText`, `_original/lib/util/file-mgr.js:96-102,:157-166`). This is
  *not* the first-one-wins of a `file://` rule, which serves whichever exists.
- The path is percent-decoded and anything after a `?` or `#` is cut
  (`decodePath`, `util/index.js:1403-1418`).
- A path with a `..` segment is refused outright, as `joinPath` refuses it.
- A file is read through the same mtime-keyed cache as `file://`: every request
  still `stat`s it, so editing a mock takes effect immediately.
- A **URL** is fetched on every matching request — upstream does not cache these
  either — with a 16-second deadline (`TIMEOUT`,
  `_original/lib/util/http-mgr.js:14`) and a 256 KB ceiling (`MAX_URL_VAL_LEN`,
  `lib/plugins/index.js:1497`). A non-200, a timeout, or an oversized body is a
  failure. Put the content in a file if you do not want an outbound call per
  request.
- The content becomes a **string**, so a binary mock body has to go through
  `file://` instead.
- `(inline)` and a whole-value `{name}` are content already and are never read
  (`if (rule.value)`, `util/index.js:1177-1179`).

**When the read fails**, the two families part company, and both halves are
upstream's:

- A **JSON-valued** operator keeps its value as written, because upstream's
  `tryParseMatcher` fallback parses the matcher as a query string once the read
  comes back empty — so a rule that never asked for this feature cannot be
  broken by it. A line is logged at `warn`.
- A **text-valued** operator becomes **empty**. It deliberately does not fall
  back to the text: that text is a path, and a path must never reach an origin
  as a request body.

#### Backtick templates

An operator value wrapped **entirely** in backticks is a template, rendered
against the request before anything else looks at it (`renderTpl`,
`_original/lib/rules/rules.js:762-772`):

```
example.com   reqHeaders://`x-method=${method}&x-when=${now}`
example.com   resHeaders://`x-status=${statusCode}`
example.com   redirect://`https://b.com${path}`
```

The variables are the same closed whitelist `tpl://` files use — one
implementation, so a rule value and a template file can never disagree about
what `${query.id}` means. See [`TEMPLATES.md`](TEMPLATES.md) for the table,
the `.key` subpaths, `${{var}}` URI-encoding and the `.replace(a,b)` modifier.

Two differences from a `tpl://` file, both upstream's:

- **only** the `${var}` pass runs. There is no `{name}` query-string
  interpolation and no "the text must contain `{…}`" gate — those belong to the
  file handler (`file-proxy.js:15,360`), not to `resolveTplVar`.
- the whole value must be backticked. ``reqHeaders://x=`${method}` `` is not a
  template; the backticks are two literal characters.

**The subtle one.** When the value *was* a backtick template, whatever the
[values store](#flags-includes--values) returns for a `${name}` inside it is
rendered too (`rule.isTpl && key ? resolveTplVar(key, req) : key`,
`rules.js:779`):

```
# values: greeting = x-hello=${method}
example.com   reqHeaders://`${greeting}`     # → x-hello=GET
example.com   reqHeaders://${greeting}       # → x-hello=${method}, sent literally
```

That is the only way a stored value ever sees the request: it is written once
and reused by every rule that names it, so the backticks on the *rule* line are
what say "render what this expands to".

`log://` and `weinre://` opt out at parse time upstream (`rule.isTpl = false`,
`rules.js:1357-1359`) — their values name a channel, and a backtick in one is a
backtick.

A backtick value on a **response-phase** operator (`resHeaders://`, `resBody://`,
`trailers://`, …) renders with the response head in hand, so `${statusCode}`,
`${resHeaders.x}`, `${resCookies.x}`, `${serverIp}` and `${serverPort}` answer
there. On a `tpl://` file they are still empty, because a template short-circuits
before any origin replies.

### Destination

| Operator | Value | Effect |
|----------|-------|--------|
| *(a bare URL)* | `[scheme://]host[:port][/path]` | **Forward the request** to that URL: the socket, the `Host` header, the path and the scheme all move |
| `host` | `ip` / `ip:port` / `host:port` / `:port` | Rewrite the upstream destination. The **Host header and TLS SNI keep the original hostname**, only the socket destination changes. `:port` keeps the host, changes the port. |
| `xhost` | as `host` | The **pass-through** spelling: the address is used when it works and *ignored* when the connection cannot be made, where `host://` fails the request. |

```
api.example.com   host://127.0.0.1:9000
.example.com      host://:8443            # same host, force port 8443
api.example.com   xhost://127.0.0.1:9000  # …unless nothing is listening there
```

#### Forwarding to another URL

A bare URL is whistle's most-used rule: it replaces the request's URL outright.
The scheme may be omitted, in which case the request's own is kept:

```
www.example.com        http://localhost:5173     # a site served by a dev server
www.example.com/api    https://staging/v2        # …and its API somewhere else
www.example.com        //localhost:5173          # keep https if the request was https
www.example.com        localhost:5173            # same thing, spelled shorter
```

The difference from `host://` is worth stating once, because both "point the
request somewhere else" and only one of them is visible to the origin:

| | socket | `Host:` header | path | scheme |
|---|---|---|---|---|
| `host://1.2.3.4` | moves | **kept** | kept | kept |
| `http://localhost:5173` | moves | **moves** | rewritten | moves |

**The rest of the path comes along.** Whatever the pattern did not consume is
appended to the destination — the same "automatic path concatenation" that maps a
directory onto a URL prefix:

| rule | request | forwarded to |
|------|---------|--------------|
| `example.com http://localhost:5173` | `/a/b?q=1` | `http://localhost:5173/a/b?q=1` |
| `example.com/api http://dev/v2` | `/api/users?x=2` | `http://dev/v2/users?x=2` |
| `example.com file:///srv/static` | `/js/app.js?v=2` | `/srv/static/js/app.js` |

Wrap the value in `< >` to turn that off, and in `( )` to give the value *as
content* rather than as a location:

```
example.com/api  http://<dev.internal/fixed>       # always this exact URL
example.com/api  file://({"status":"ok"})          # a one-line mock
```

A file rule may list alternatives with `|`, and each one takes the path:

```
static.example.com   file:///srv/a|/srv/b        # first one that exists wins
```

> `rule://<name>` is **not** a destination: it is this port's own spelling for
> pulling a values-store entry in as more rules. Upstream files it in the same
> place, where it can only ever produce the unusable URL `rule://<name>`.

`xhost://` retries **once**, against the host and port the request actually asked for,
and only when the connection could not be *established* — once the request has been
written to a socket it cannot be replayed, which is the same guard the `x`-prefixed
[proxy spellings](#upstream-proxy) carry (`retryXHost`,
`_original/lib/inspectors/res.js:571-600`). A request with any proxy rule never takes
this path: whistle checks the proxy rule first and the host rule in its `else if`, so
the connection that failed was to the proxy. Upstream retries the dead address once
before consulting DNS (`if (retryXHost > 1)`, where `>= 1` was surely meant); this port
skips that wasted attempt.

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

Each of these also has an `x`-prefixed spelling — `xproxy://`, `xsocks://`,
`xhttp-proxy://`, `xhttps-proxy://`, `xinternal-proxy://` — which means the same
thing but **falls back to a direct connection** when the hop cannot be made. See
"If the upstream proxy is unreachable" below.

```
example.com        proxy://127.0.0.1:8888
.internal.corp     http-proxy://user:pass@10.0.0.1:3128
secure.example.com socks://127.0.0.1:1080
flaky.example.com  xproxy://127.0.0.1:8888     # via the proxy, or direct if it is down
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
SOCKS proxy, an HTTPS proxy, and an address override travelling with the proxy
(a `host://` rule or the proxy URL's own `?host=`) each open a `CONNECT` tunnel
instead. The absolute-form URI names the host from
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

**If the upstream proxy is unreachable** or refuses the `CONNECT`, the request
fails with a 502 — the plain spellings are never retried directly. The
`x`-prefixed spellings are the ones that ask for the fallback (`X_RE`,
`_original/lib/inspectors/res.js:31,:546-560`): `xproxy://127.0.0.1:8888` goes
through the proxy when it can and straight to the origin when it cannot. The
retry only covers a hop that could not be **established** — a refused connection
to the proxy, a rejected `CONNECT`, a failed SOCKS handshake. Once the request
has been written to the socket it cannot be replayed, so a proxy that accepts
the tunnel and then fails is reported rather than retried; whistle guards its own
retry the same way (`piped`, `res.js:529`).

A proxy operator whose value is empty or unusable (`proxy://`, `socks://@`) fails
with `proxy:// is not a usable proxy address` rather than quietly becoming a
direct connection. whistle drops such a rule and connects direct; a rule that
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

A proxy URL can carry the same override itself, as `?host=<host[:port]>`
(`P_HOST_RE`, `_original/lib/rules/index.js:81,:243`) — no separate `host://`
line and no `proxyHost` needed, since the query says outright that the proxy is
to be used. A matching `host://` rule wins over it. The port may be left out, in
which case the request's own port is kept.

```
pinned.test        http-proxy://127.0.0.1:8888?host=10.0.0.9
```

Either way the hop switches to `CONNECT`, and the address is what the proxy is
asked to reach — the request inside the tunnel still carries the original `Host`.

**`proxyTunnel`.** With an override in play, `lineProps://proxyTunnel` (or
`enable://proxyTunnel`, or the property on the `host://` line) says the
overridden address is *itself* a proxy: whistle-rs `CONNECT`s to it through the
first proxy, then sends a second `CONNECT` **inside** that tunnel naming the real
origin, marked `x-whistle-policy: intercept` so a whistle at the far end
intercepts rather than blindly relays
(`_original/lib/tunnel.js:535-537`, `lib/util/patch.js:120-140`). Both halves are
required: without an override there is nothing to tunnel through and the flag
does nothing. HTTP and HTTPS proxies only — a SOCKS hop ignores it, as upstream's
does.

```
# via 127.0.0.1:8888, on to 10.0.0.9:8899, and out to the origin from there
chained.test       proxy://127.0.0.1:8888?host=10.0.0.9:8899 lineProps://proxyTunnel
```

Both `CONNECT`s carry the same `Proxy-Authorization`, so the **second** proxy is
shown the credential written for the first — and when the proxy URL carries no
credential of its own, that is the *client's* own `Proxy-Authorization`, a
credential the client aimed at whistle-rs travelling one hop further than the
client can see. This matches whistle (`lib/util/patch.js:120-140`); every address
involved was named by the rule, and withholding the credential would make an
authenticated second hop silently unreachable. Point a chain at a proxy you do
not control and this is what leaves.

**When several proxy operators match**, the one written **first** wins, whatever
its spelling. whistle files every spelling under a single `proxy` key
(`PROXY_RE` → `protocol = 'proxy'`, `_original/lib/rules/rules.js:1286`), so
`socks://` and `proxy://` compete as one operator and rule order decides — with
`important` lines first, as everywhere else. `pac://` is consulted only when no
proxy operator matched at all.

```
example.com        proxy://127.0.0.1:8888     # this one is used
example.com        socks://127.0.0.1:1080     # …and this one is not
```

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
| Server address | `serverIp:<v>`, `serverIP:` | the address the request was actually sent to — the upstream proxy's when one was used (response phase) |
| Server port | `serverPort:<v>` | the port the request was sent to (response phase) |
| Host | `host:<v>`, `host=<v>` | request host |
| Request body | `b:<v>`, `body:<v>` | the request body **contains** `<v>` — see [the body condition](#the-body-condition) |
| Environment | `env:<KEY>=<v>` | whistle's own process environment variable `<KEY>` contains `<v>`. The key is case-**sensitive**, and only `=` separates it |
| Origin | `from:<marker>`, `from=<marker>` | where the request came from — see [origin markers](#origin-markers) |
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
where the status is still unknown and the condition therefore fails closed (the
list of which conditions those are is directly below). By the time the status is
known the request has already gone to the origin the rules chose.

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

**Rules merged in mid-request take both passes too.** A `rule://` value, the
`rulesFile://` join and the rules a plugin injects are each kept in parsed form and
resolved a second time when the head arrives — upstream re-resolves the same managers
(`fRules`/`pRules`/`hRules` in `getResRules`,
`_original/lib/plugins/index.js:1326-1335`). They keep their place *behind* everything
the file that pulled them in resolved, in both passes. Cost per response: ~7 ns with
nothing merged, ~9 ns for a merged text with no response-dependent line, ~250 ns for one
that has one.

**Covered on every path that produces a response**, including the two that do not go
upstream: a `plugin://` hook that answered the request, and a short-circuit rule
(`file://`, `tpl://`, `redirect://`, `statusCode://`). Both are resolved against the
head as produced, before any operator has touched it — so `s:404` sees the plugin's own
404, not the `replaceStatus://200` on the same line. whistle reaches its response
inspectors on both paths too: a `plugin://` rule is a proxy hop to the plugin's own
server, so the answer arrives as an ordinary response
(`_original/lib/inspectors/res.js:825`).

**Not covered:** WebSocket and tunnelled (`CONNECT`) traffic have no response phase
here. Neither do the two paths that produce no response of their own — a self-loop
redirect and an `enable://abort` — which is equally true of the top-level rules.

`serverIp:` is answered from the **connected socket**, so a named origin is answered too:
the address is read back off the connection rather than guessed by asking the resolver a
second time (which, under round-robin DNS, could name a host the request never reached).
When the request went through an upstream proxy the address is the **proxy's** — that is
also what whistle reports, since it sets `req.hostIp` from the resolved proxy address
whenever a proxy rule matched (`_original/lib/inspectors/res.js:238,:259`). A request
that never connected at all leaves the condition unanswerable, and it fails closed.

#### The body condition

`b:` / `body:` reads the **request body**, which means the body has to be buffered
before the rules resolve — the one thing on the request path that cannot be undone
once it is done. Both implementations therefore decide it in two stages, and
whistle-rs follows upstream's:

1. every line carrying a `b:` filter is collected at parse time into a list of its
   own (upstream's `_bodyFilters`, `_original/lib/rules/rules.js:1390-1392`);
2. before resolution, the proxy asks whether any of those lines would match this
   request *but for* the body condition — pattern, method, headers, everything else
   is evaluated as usual. Only then is the body read
   (`resolveBodyFilter` → `req.getPayload`, `rules.js:2455-2465`,
   `lib/inspectors/rules.js:193-205`).

So a rules file with no `b:` in it never touches a body, and one that has a `b:`
scoped to a host or a method pays nothing on the requests it excludes. Measured on a
500-rule file: **4.2 ns** per request with no `b:` line, **11 ns** with one that does
not match this request, **12 ns** with one that does (plus the buffering itself) —
against ~2.8 µs for the resolution that follows.

```
example.com  resBody://blocked  includeFilter://b:password
example.com  resBody://blocked  includeFilter://b:/"role"\s*:\s*"admin"/
```

The comparison is by **containment**, case-insensitively, like a header's; a `/re/`
value is matched against the body as it arrived. An empty body is still a body, so
`b:!x` holds for a request that has none. If nothing caused the body to be buffered —
a `b:` inside a `rulesFile://` include, which is resolved after the decision — the
condition is unknown and fails closed, exactly as upstream's does when
`req._reqBody` is not a string (`rules.js:1903-1906`).

Unlike upstream there is no ceiling on how much is buffered: whistle stops at
`MAX_REQ_SIZE` (2 MB, or 16 MB under `reqMergeBigData`) and matches against the
prefix.

#### Origin markers

`from:` takes a bare word out of a fixed list — not a pattern, and not a `/re/`:
whistle lowercases the value and compares it (`_original/lib/rules/rules.js:1608-1611,
:1834-1859`). Every marker is known before the rules resolve, so the negated spellings
are real answers rather than filters that fail closed.

| Marker | True when |
|---|---|
| `tunnel` | the request came out of a tunnel this proxy intercepted — a `CONNECT`, or a SOCKS connection |
| `sni` | the intercepted TLS handshake named a server. A tunnel carrying plain HTTP is `tunnel` without being `sni` |
| `composer` | the built-in console replayed the request (the Replay button / `POST /api/replay`) |
| `test`, `httpserver`, `httpsserver`, `httpsport` | never, here — see below |

```
example.com  resHeaders://x-src=tunnel  includeFilter://from:tunnel
example.com  statusCode://403           includeFilter://from:!composer
```

The last four are recognised and answer a known **`false`**, so `from:!httpserver`
holds. `test` needs whistle's test header, which this port neither sends nor honours;
the three server markers need the extra HTTP/HTTPS listeners whistle can open beside
its proxy port (`config.httpPort`/`httpsPort`, `_original/lib/index.js:96-111`), which
this port does not have. A whistle started without them answers the same `false`.

`from:composer` is marked with an `x-whistle-composer` request header on the loopback
hop, consumed on arrival so it reaches neither a `reqH.` condition nor the origin. Like
`x-whistle-internal-req` ([`LINE_PROPS.md`](LINE_PROPS.md)) the name is fixed rather than
per-process: the marker labels traffic, it does not guard anything, and a stable name
is what lets a client exercise the condition deliberately.

Two upstream behaviours are **reproduced rather than fixed**:

- `from:internalPath` never matches. whistle lowercases the value before comparing, so
  its own `'internalPath'` branch cannot be reached.
- an unrecognised marker satisfies no filter **however it is written**. Upstream's chain
  ends in `return false` before it consults `!`, so `from:!nonsense` is false too. Here
  that is modelled as an "unknown" answer, which leaves an include filter unsatisfied
  and an exclude filter inert.

Every other condition this port parses now evaluates.

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
spellings through the same parser (`_original/lib/rules/rules.js:57`).

#### Silencing a rule by its text

A third reading names the rule *as written*, which is what you want when the rule
you are trying to disable is one you cannot edit — in an included file, or one a
plugin merged in.

| Value | Silences |
|-------|----------|
| `pattern=<text>` | every rule whose **pattern token** is exactly `<text>` |
| `matcher=<text>` | every **operator token** that is exactly `<text>` |
| `operator=` / `operation=` | the same as `matcher=` |

```
# Turn off one line of an included rules file without touching the file.
*   ignore://pattern=static.example.com
*   ignore://matcher=host://10.0.0.1
```

`:` works in place of `=` (`ignore://pattern:example.com`). The text must match
the token *exactly*, prefixes and all — `$example.com` and `example.com` are
different patterns.

Name an operator by its **expanded** form. A shorthand is expanded before the
line is split, so `example.com /local/path` is silenced by
`matcher=file:///local/path`, not by `matcher=/local/path`. (Upstream accepts
both; this port accepts only the expanded one — the written token is not
recoverable by the time the operator exists.)

Unlike the protocol-name form, this one may be written **anywhere in the file** —
above or below the rule it silences — because the whole set is read before
anything is applied.

The three readings do not collide in practice, but the reason is worth stating
precisely, because it is *not* that their shapes are disjoint: a filter condition
and a `pattern=` value can both carry `:`, `.` and `=`. What separates them is
that each is recognised by its own vocabulary — a leading `m:`/`s:`/`b:`… makes a
filter condition, one of the four keys above makes a text silencer, and anything
that is neither is read as a list of protocol names.

> **`skip://` reads an unkeyed value differently.** `skip://` and `ignore://` are
> the same operator here, with one exception: under `skip://`, a value carrying
> any character a protocol name could not hold is taken *whole* as a `matcher=`.
> So `skip://example.com/path` silences that operator token, while
> `ignore://example.com/path` looks for protocols with those names and finds
> none. Upstream draws the same distinction (`rules.js:1129-1141`); if you are
> not relying on it, prefer the explicit `matcher=` spelling.

### Short-circuit (no upstream request is made)

| Operator | Value | Effect |
|----------|-------|--------|
| `redirect` / `location` | a URL | Respond `302 Found` with `Location: <url>` |
| `statusCode` | a status number | Respond with that status and an empty body (mock) |
| `file` / `rawfile` | a local path | Serve the file's bytes with a guessed `Content-Type` |

```
old.example.com/legacy   redirect://https://new.example.com/
/\/track\b/              statusCode://204
example.com/app.js       file:///Users/me/dev/app.js
```

Note the first line has no `*`. A path prefix already matches everything below
it at a segment boundary, and a `*` in the path of an ordinary pattern is a
**literal** — `old.example.com/legacy/*` matches a URL containing the character
`*` and nothing else. Write `^http://old.example.com/legacy/**` when you need a
path wildcard with a capture.

**These share one slot with each other and with a bare destination URL.** None
of `file`, `rawfile`, `tpl`, `jsonp`, `dust`, `redirect`, `location`,
`statusCode` or a forwarding URL is a name in upstream's `protocols` array, so
`parseRule` files every one of them under the same `rule` list
(`_original/lib/rules/rules.js:1313-1316`) and `getRule` returns the **first**
match (`:799-800`). They cannot coexist: whichever one was written first
answers, and the rest do not apply.

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true})     # never served — the forward won
```

Order the narrow rule above the broad one, or mark it `lineProps://important`, which puts it first
whatever the line order:

```
example.com/api/flags  file://({"beta":true})
example.com            http://localhost:5173
```

Within a *single* line the tie is broken by protocol, in the order `redirect`,
`location`, `statusCode`, then the file family — so
`file://({"id":7}) statusCode://201` answers `201` with an **empty body**. Use
[`replaceStatus://`](#response-rewriting) when you want the mock's body under a
different status; it changes a response rather than manufacturing one.

### Request rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `reqHeaders` | `name=value` pairs (`&`-separated) or `{json}` | Set/replace request headers. An empty value sends an **empty header**, not a deletion — use `delete://reqHeaders.x` for that. Accumulates across lines. |
| `ua` | user-agent string | Set the `User-Agent` header |
| `referer` | URL | Set the `Referer` header |
| `method` | HTTP method | Override the request method. The method is uppercased on **every** request, rule or no rule, and an unusable value falls back to `GET` |
| `reqType` | MIME type or short name | Set the request `Content-Type` (`reqType://json`, `reqType://form`, …) |
| `reqCharset` | charset | Set the charset on the request `Content-Type` |
| `reqCors` | origin URL, `*`, or `method=…&headers=…` | Set the request `Origin`, and the `Access-Control-Request-Method` / `-Headers` preflight headers. A URL is reduced to its origin. `enable` is the *response*-side spelling and does nothing here. |
| `auth` | `user:pass`, `username=…&password=…`, or `{json}` | Add an HTTP Basic `Authorization` header — see below |
| `forwardedFor` | IP | Set the `X-Forwarded-For` header |
| `reqWrite` | file path | Write the request body to a file, once — see [Dump files](#dump-files) |

```
example.com   reqHeaders://x-token=abc
example.com   reqHeaders://x-a=1&x-b=2
example.com   reqHeaders://{"x-a":"1","x-b":"2"}
example.com   ua://MyBot/1.0
api.test/*    method://POST
api.test      auth://admin:secret
api.test      forwardedFor://203.0.113.7
```

`ua://` and `referer://` are assignments too, so writing them with no value
sends an empty header. `disable://ua` and `disable://referer` are the rules that
remove one.

#### `auth://` in three spellings

| Value | Sends |
|-------|-------|
| `admin:secret` | `Authorization: Basic …` for `admin`/`secret` |
| `username=admin&password=secret` | the same |
| `{"username":"admin","password":"secret"}` | the same |
| `{"username":"admin","password":"secret","proxy":true}` | **`Proxy-Authorization`** instead |

Only the first colon splits, so a password may contain one. Naming one half is
allowed and the two halves are not symmetric (`getAuthBasic`,
`_original/lib/util/index.js:3668-3685`): a password with no username still
carries its colon (`:secret`), a username with no password carries none
(`admin`). A value naming neither sends no header at all.

Two edges are upstream's and easy to trip over: the query spelling's `proxy` is
read as `!!value`, so `proxy=false` is **true** — write the JSON form when the
answer is no; and query values are taken raw, so a `%2F` in a password reaches
the server as `%2F`.

> whistle additionally reads a value containing a slash as a **file reference**
> and sends nothing when it cannot load one. whistle-rs has no rule-value loader,
> so it keeps splitting on the colon — which is what `auth://user:pa/ss` needs.

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

A plugin that answers the request is **not** the last word: the response operators on
the line still run over its answer, and so does the [response phase](#the-response-phase)
— the same as for the origin's answer, and the same as upstream, where a `plugin://`
rule is a proxy hop to the plugin's own server and its answer comes back through the
ordinary response inspectors (`_original/lib/inspectors/res.js:825`).

```
api.example.com   plugin://mock  resHeaders://x-mocked=1  replaceStatus://503
```

The plugins' own response hooks (`POST /response` and the streaming `pipe://` ones)
run over that answer too, as they do over the origin's — including for the plugin
that produced it, since upstream establishes its response pipes for every matched
plugin regardless of which one wrote the bytes. See
[`PLUGINS.md`](PLUGINS.md#本地产生的响应也走响应阶段). The one exception is an
`onAuth` refusal, which upstream pins with `ignore://!…` and this port sends
through untouched.

### Choosing the MITM certificate

| Operator | Value | Effect |
|----------|-------|--------|
| `sniCallback` | `name[(value)]` | Ask a plugin which certificate to present for an intercepted TLS connection — or whether to intercept it at all |

```
api.example.com      sniCallback://certs(staging)
pinned.example.com   sniCallback://no-mitm
```

This operator is resolved at a different time from every other one on this page:
during the **TLS handshake**, before there is a request. So it matches on the one
thing that exists by then — the name in the client's ClientHello, as
`https://<that name>` — plus the client's address and port. There is no method,
no path, no header and no body, so a filter that asks about any of those never
matches an `sniCallback` line.

The plugin can answer four ways: present whistle-rs's own generated certificate,
present one of its own, reuse the one it supplied last time, or **decline the
interception entirely** — in which case the connection is relayed to the origin
still encrypted and nothing about it is captured. Writing the plugin is covered
in [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback); the built-in
`sniCallback://no-mitm` needs no plugin at all and always declines.

Three consequences worth knowing:

- **The port is part of the pattern**, because the URL the rule matches carries
  it: `localhost:9443 sniCallback://certs` and `localhost:9444 …` are different
  rules, even though the ClientHello is identical.
- **A declined connection is not proxied by any rule.** whistle-rs has no
  rule pipeline for an opaque tunnel, so the relay goes straight to the address
  the tunnel was opened to — a `proxy://` or `host://` line does not apply to it.
- **A failing plugin does not decline.** Unreachable, slow or incomprehensible
  all mean "the certificate whistle-rs would have generated anyway", with a
  `WARN` naming the plugin. See
  [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback) for why this one hook does not
  fail closed the way `onAuth` does.

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
| `enable` | flag(s) | `abort`/`abortReq`/`abortRes` (destroy the connection — see below), `cors` (as `resCors://enable`), `captureStream` (ask the origin not to compress), `gzip`/`br`/`deflate` (force the response's outgoing encoding), `showHost` (report the address reached as `x-host-ip`), `ignoreSend`/`ignoreReceive` (drop one direction of a WebSocket), `pauseSend`/`pauseReceive` (hold one direction until the console releases it), `safeHtml`/`strictHtml` (gate every injection), `keepCSP`/`keepCache`/`keepAllCache` (survive an injection) |
| `disable` | flag(s) | see the two tables below |
| `trailers` | `name=value` / `{json}` | Add HTTP response trailer headers (forces chunked) — see below |
| `headerReplace` | `{"<scope>.<name>:<pattern>":"<repl>"}` | Rewrite a header value; scope is `req.`/`reqH.`/`res.`/`resH.` |
| `responseFor` | a URL | Prefetch the URL; annotate the request with `x-whistle-response-for-*` |
| `rule` | value name | Include the named value's rules and apply them too |
| `rulesFile` | file path | Include rules from a file and apply them too. Also spelled `reqRules://`, `ruleFile://`, `ruleScript://`, `rulesScript://`, `reqScript://` — see below |
| `pipe` | plugin name | Route through a registered server (like `plugin`) |

`{name}` as a **whole** operator value, and `${name}` anywhere inside one, are
replaced with the content of the named value (from `--value name=…` or the
console's Values pane) — see
[What an operator's value can be](#what-an-operators-value-can-be).

`disable://` takes one or more flags, `|`-separated. They strip something from
the request on its way out, or from the response on its way back:

| Flag | Strips from the request |
|------|-------------------------|
| `ua` | `User-Agent` |
| `gzip` | `Accept-Encoding`, so the origin answers uncompressed |
| `cookie` / `cookies` / `reqCookie` / `reqCookies` | `Cookie` |
| `referer` / `referrer` | `Referer` (both spellings, since the misspelling matches the header) |
| `ajax` | `X-Requested-With` |
| `cache` | `If-None-Match`, `If-Modified-Since`, `ETag`, `Last-Modified`, and sets `Pragma`/`Cache-Control: no-cache` |
| `keepAlive` / `keepalive` | sets `Connection: close`, so the hop to the origin is not pooled |

| Flag | Changes in the response |
|------|-------------------------|
| `cookie` / `cookies` / `resCookie` / `resCookies` | drops `Set-Cookie` |
| `cache` | `Cache-Control: no-cache` plus a past `Expires` and `Pragma` |
| `csp` | drops the `Content-Security-Policy` headers |
| `301` | turns a `301 Moved Permanently` into a `302 Found`, so the browser does not cache the redirect |
| `userLogin` | withholds the `WWW-Authenticate` / `Proxy-Authenticate` challenge a `replaceStatus://401\|407` would send (`enable://userLogin` wins over it) |
| `trailers` / `trailer` | sends no trailer section at all — the origin's included |
| `trailerHeader` | sends the trailers without the `Trailer:` header announcing them |
| `doctype` | no `<!DOCTYPE html>` before an HTML prepend |

`disable://tunnel` belongs to neither table: it strips nothing, it refuses the
connection — see
[Aborting a connection rather than a request](#aborting-a-connection-rather-than-a-request).

A flag this port does not recognise is **inert** — it parses and does nothing,
rather than failing the rule.

> **A response-body operator busts the request cache on its own.** Any of
> `resBody`, `resPrepend`, `resAppend`, `resReplace`, `resMerge`, the
> `html`/`js`/`css` variants, `attachment`, `resWrite` or `resWriteRaw` implies
> the `disable://cache` treatment of the request, without being asked
> (`notAllowCache`, `_original/lib/inspectors/res.js:54-60,:1328`). Without it a
> conditional request answers `304 Not Modified` with no body, and the rewrite
> silently does nothing — intermittently, since it depends on what the client
> already holds.
>
> **This is a deliberate improvement on whistle, not an alignment with it, and
> the entry used to claim otherwise.** whistle has `notAllowCache` and never
> reaches it: it reads `req.rules`, and all seventeen of those operators are in
> `pureResProtocols`, which the *request* pass skips. Measured against real
> whistle 2.10.8, with `resBody://(REWRITTEN)` against an origin that honours
> `If-None-Match`:
>
> ```
>              plain request        with If-None-Match (a browser reload)
> whistle      200 "REWRITTEN"      304 ""
> whistle-rs   200 "REWRITTEN"      200 "REWRITTEN"
> ```
>
> So the rewrite disappears on reload in whistle. whistle-rs does what
> whistle's code says rather than what whistle does.
>
> `log://` and `weinre://` bust the cache too, and there whistle *does* reach
> the code (`disableReqCache`, `_original/lib/inspectors/log.js:30`,
> `weinre.js:26`) — those two are request-phase protocols. They inject a script
> into an HTML response, so they need one to inject into.

#### Trailers

`trailers://` **adds** to whatever trailer section the origin sent; it does not
replace it (`extend(trailers, newTrailers)`,
`_original/lib/inspectors/res.js:1264-1273`). A contested name takes the rule's
value, and the `Trailer:` header announces everything that will follow.

| Flag | Effect |
|------|--------|
| `disable://trailers` / `disable://trailer` | send no trailer section at all — the origin's included |
| `disable://trailerHeader` | send the trailers, but not the `Trailer:` header announcing them |

Names an HTTP trailer section may not carry are dropped, whichever side they
came from (`ILLEGAL_TRAILERS`, `_original/lib/util/common.js:34-53`): `host`,
`transfer-encoding`, `content-length`, `cache-control`, `te`, `max-forwards`,
`authorization`, `set-cookie`, `content-encoding`, `content-type`,
`content-range`, `trailer`, `connection`, `upgrade`, `http2-settings`,
`proxy-connection`, `keep-alive`. A `Content-Length` arriving after the body
contradicts the framing that just delivered it, and a `Set-Cookie` there is a
credential a client is not required to read.

`resSpeed://` applies alongside trailers — the two are not alternatives.

`headerReplace` scopes are `req.` / `reqH.` (request), `res.` / `resH.` (response)
and `trailer.`; a `resHeaders.` key matches none of them and does nothing. Two
details are inherited from upstream and are easy to trip over:

- A key with **no scope prefix** reuses the previous key's scope *and its header
  name*, keeping only its own pattern — so
  `{"resH.location:/^http:/":"https:","x:/y/":"z"}` runs both substitutions
  against `location`, not against `x`. A leading unscoped key is dropped.
- In the replacement, `$&` and `$1`…`$9` insert the match and its groups;
  spelling either with a **double** `$` (`$$1`) inserts it **percent-encoded**.
  A backslash escapes the reference (`\$1` is the literal `$1`), and two keep one
  backslash and still substitute.

```
api.example.com     enable://cors
slow.example.com    enable://abort
static.example.com  disable://cache
example.com         trailers://x-checksum=abc123
example.com         headerReplace://{"resH.set-cookie:/Domain=[^;]+/":"Domain=example.com"}
example.com         headerReplace://{"resH.location:/^http:/":"https:"}
page.example.com    responseFor://http://auth.internal/verify
example.com         resBody://{mockJson}        # {mockJson} from the values store
example.com         rulesFile:///etc/whistle/extra.rules
```

#### `enable://abort` is two gates, not one

An abort **destroys the connection** — the client sees a reset, never a status
code (upstream's `res.destroy()`, `_original/lib/inspectors/data.js:536` and
`res.js:1178`). There are two moments it can happen at, and which one you get
depends on the spelling:

| Flag | Fires | The origin |
|------|-------|------------|
| `abortReq` | before the request leaves | never hears about it |
| `abortRes` | after the response head arrives, and after `resDelay://` | serves the request in full |
| `abort` | both are armed, so the request gate wins | never hears about it |

Each gate is cancelled by a `disable://` of its own name, or by `disable://abort`,
which cancels both (`needAbortReq`/`needAbortRes`,
`_original/lib/util/index.js:3893-3915`). The cancellation is what lets an abort
be armed broadly and exempted narrowly:

```
example.com          enable://abort
example.com/health   disable://abort
```

`enable://abort disable://abortReq` is the way to say "let it reach the origin,
then cut the client off" without changing what the origin sees.

> Upstream also arms these from a `filter://abort` line; in whistle-rs `filter://`
> is only a match condition, so `enable://` is the whole vocabulary here.

#### Aborting a connection rather than a request

A `CONNECT` tunnel and an inbound SOCKS connection have no response of their own
to destroy, so the abort lands on the connection itself, and lands **before the
client is told the connection is open**: the `CONNECT` is never answered at all,
and the SOCKS request comes back *connection not allowed by ruleset*. Upstream
destroys the same socket from either gate (`_original/lib/tunnel.js:372-374`,
`:748-750`) and opens its SOCKS connections by issuing a `CONNECT` against its
own port, so a refused tunnel denies the SOCKS client (`lib/index.js:174-193`).

The two spellings collapse into one here. whistle-rs acknowledges a `CONNECT`
before it can know where the bytes will go, so `abortRes` cannot let the origin
be dialled first the way it does on the request path — both spellings produce the
same silence. Everything else holds, `disable://abort` included.

A connection carries no path and no headers, so a line can refuse one only on
what is known before any request — the address and the client:

```
blocked.test         enable://abort   # the tunnel is refused
example.com/api      enable://abort   # the tunnel is carried; the request inside is not
```

`disable://tunnel` refuses a connection too, and does nothing anywhere else:
upstream reads that flag only here (`_original/lib/util/index.js:3900,:3912`),
and `disable://abort` calls it off exactly as it calls off the other two.

A refused connection is still a session. It appears in the console as a `CONNECT`
with no status, so an abort looks like an abort rather than like a client that
hung up.

On a **WebSocket** the two gates stay apart, because an upgrade does have a
response of its own: `abortReq` fires before the handshake leaves — an upgrade is
an ordinary request until then — and `abortRes` fires once the server's `101` has
arrived, instead of relaying it (`_original/lib/https/index.js:256-259,:783-786`).
So the server has served the handshake and the client never sees the switch.

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

### Dump files

`reqWrite://`, `reqWriteRaw://`, `resWrite://` and `resWriteRaw://` write a
capture to a path. They **do not append**, and they write **once**: whistle stats
the path first and does nothing at all when the file already exists
(`checkWriterFile` / `getFileWriter`, `_original/lib/util/index.js:502-546`). So
a rule left in place over a reload leaves the first capture intact rather than
growing a file that is several runs concatenated with no boundary between them.

| | |
|---|---|
| `enable://forceReqWrite` | write even over an existing file — **overwriting** it, not appending. One flag for all four operators, despite the name (`req.js:601`, `res.js:1304`) |
| a path ending in `/` | names a directory; the dump lands in it as `index.html` |
| missing parent directories | created |
| a response that is not `200` | dumped to `<file>.<status>`, so a run of 502s lands in `dump.502` beside the good capture in `dump` (`getWriterFile`, `res.js:147-153`) |
| `reqWrite://` on a `GET`/`HEAD`/`OPTIONS`/`CONNECT` | not written — there is no body to capture (`req.js:582-584`). `reqWriteRaw://` still dumps the head |
| `resWrite://` on a response with no body | not written, for the same reason. `resWriteRaw://` still dumps the head |

```
api.example.com   reqWriteRaw:///tmp/api-request.http
api.example.com   resWrite:///tmp/api-body.json  enable://forceReqWrite
```

### Delays & throttling

| Operator | Value | Effect |
|----------|-------|--------|
| `reqDelay` | milliseconds | Wait before forwarding the request |
| `resDelay` | milliseconds | Wait before returning the response |
| `reqSpeed` | **kilobits**/s | Cap request-body upload throughput |
| `resSpeed` | **kilobits**/s | Cap response-body download throughput |

```
slow.example.com   reqDelay://500
slow.example.com   resDelay://1000
slow.example.com   resSpeed://800       # 800 kbit/s ≈ 100 kB/s download
```

> A speed cap buffers the body and re-emits it in paced chunks, so it forces a
> known-length body to chunked transfer.

**The speed unit is kilobits, not kilobytes** — upstream's documentation says
千比特 and its implementation is `parseInt(speed * 1000 / 8)`. This port read the
value as kilobytes until recently, so every throttle written against the old
behaviour ran 8.192× too fast; multiply those values by 8.

**Both families take only a number.** A unit suffix parses and is then
*discarded*, not converted (`parseFloat`/`parseInt` semantics): `resDelay://500ms`
is 500 ms as you would hope, but `resDelay://1s` is **1 millisecond**, and
`resSpeed://20kb` is 20 kilobits. Write the number you mean.

### Response rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `replaceStatus` / `statusCode` | status number | Replace the upstream response status. A **changed** 401/407 also sends the matching auth challenge; `disable://userLogin` withholds it |
| `resHeaders` | `name=value` pairs (`&`-separated) or `{json}` | Set/replace response headers. An empty value sends an **empty header**, not a deletion — use `delete://resHeaders.x`. `set-cookie` merges instead of replacing; see below. Accumulates across lines. |
| `resType` | MIME type or short name | Set the response `Content-Type` |
| `resCharset` | charset | Set the charset on the response `Content-Type` |
| `resCors` | origin, `*`, `enable`, `{json}` or `k=v&…` | Negotiate the CORS response headers |
| `attachment` | filename (optional) | Force download via `Content-Disposition: attachment` |
| `cache` | `no`/`no-cache`/`no-store`/seconds/`keep` | Set `Cache-Control`, `Expires` and `Pragma` |
| `resWrite` | file path | Write the response body to a file, once — see [Dump files](#dump-files) |

```
example.com        resHeaders://x-mitm=intercepted
example.com/api    resCors://*
cdn.example.com    resType://application/javascript
example.com/404    replaceStatus://200
example.com        cache://no
```

**`set-cookie` on `resHeaders://` merges, it does not replace** (`setCookies`,
`_original/lib/inspectors/res.js:89-122`). The rule's cookies go first, then
every cookie the origin sent whose *name* the rule did not also name — so
setting `sid` leaves the origin's `csrf` where it was. Two spellings, and they
differ:

```
example.com   resHeaders://set-cookie=a=1,b=2            # two cookies: split on the comma
example.com   resHeaders://{"set-cookie":["a=1,b=2"]}    # one cookie: an array is never split
```

The array form is the only way to write a cookie whose attributes contain a
comma, such as an `Expires=Wed, 21 Oct …`. A JSON array is several header lines
for **any** header, not only this one.

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
| `delete` | one or more keys, separated by `\|` or `&` | Remove headers, cookies, query parameters, path segments, body properties, or the type/charset |

Keys are matched against a fixed set of spellings; **anything else is silently
ignored**, exactly as upstream. In particular a bare `delete://server` deletes
nothing — you need a scope.

| Key | Deletes |
|-----|---------|
| `resHeaders.x` / `res.headers.x` / `resH.x` / `res.h.x` | that response header (case-insensitive scope) |
| `reqHeaders.x` and the same variants | that request header |
| `headers.x` | the header on both sides (this spelling is case-**sensitive** and must be plural) |
| `reqCookies.x` / `cookies.x` | that cookie from the request `Cookie` header |
| `resCookies.x` / `cookies.x` | that cookie **in the client** — see below |
| `trailer.x` | that trailing header (this key takes no `req`/`res` scope, and is the one key that is case-**sensitive**) |
| `query.x` / `params.x` / `urlParams.x` / `url.Param.x` | that query-string parameter, every repeat of it |
| `query` / `params` / `urlParams` (bare) | the whole query string, `?` and all |
| `pathname` | the whole path, keeping the query string |
| `pathname.0` / `pathname.first`, `pathname.2`, `pathname.-1`, `pathname.last` | that path segment, counted from the end when negative |
| `resType` / `res.type`, `reqType` / `req.type` | the media type (a `charset` parameter survives) |
| `resCharset` / `res.charset`, `reqCharset` / `req.charset` | the charset parameter |
| `body`, `res.body`, `req.body` | the whole body, including anything an operator injects |
| `resBody.a.b` / `resB.a.b`, `reqBody.a.b` | that dotted path from a JSON body |

A body path is read the way whistle reads one: `reqBody.a\.b` names a single key
containing a dot (backslashes are halved first, so `a\\.b` is two segments),
`reqBody."k[0]"` takes a segment literally, and `reqBody.a[0]` indexes an array
— the same element `reqBody.a.0` names.

```
example.com   delete://resHeaders.server|resHeaders.x-powered-by
example.com   delete://reqCookies.tracking
example.com   delete://resBody.debug&resBody.internal.token
example.com   delete://query.utm_source|query.utm_medium
example.com   delete://pathname.first        # /v1/users → /users
```

The URL keys have edges worth knowing, all inherited
(`parseDelQuery`/`parsePathReplace`/`deleteQuery`,
`_original/lib/util/index.js:2674-2721,1023-1058`):

* segments are counted in the path **without** its leading slash, so
  `pathname.0` names `v1` in `/v1/users` — the same slice `urlReplace://`
  substitutes into;
* `pathname.last` leaves a trailing slash where the segment was (`/a/b/c` →
  `/a/b/`); `pathname.-1` names the same segment and does not (`/a/b`);
* the dot is optional (`pathname-1` ≡ `pathname.-1`), and `pathname` itself is
  case-insensitive — but `first`/`last` are **not**. `delete://pathname.LAST`
  matches the pattern and then does nothing, because upstream coerces every
  key it does not recognise as the literal `last` with `+key`, and `+'LAST'`
  is `NaN`;
* the query deletion runs **after** `params://`, so it wins over a parameter
  the same line just wrote;
* an index out of range is a no-op rather than an error.

> **Two deliberate divergences.**
>
> A bare `delete://pathname` against a URL that has a query string emits the
> query **twice** upstream (`/a?x=1` → `/?x=1?x=1`, `util/index.js:1033,1057`).
> whistle-rs emits it once; the upstream form is a request line no origin
> parses.
>
> `delete://body` (and `req.body` / `res.body`) does **not** empty the body in
> real whistle, only discard what `reqBody://`, `reqPrepend://` and their
> response twins meant to inject. `removeBody` assigns `EMPTY_BUFFER`, and
> `EMPTY_BUFFER` is `toBuffer('')` — whose first act is `if (!buf) return`
> (`util/common.js:1630-1632`), so the constant is `undefined` and the
> assignment leaves the body alone. whistle-rs empties it, which is what the
> key is documented to do and what upstream's own code means to do.

A response cannot reach into the browser and remove a cookie, so
`delete://resCookies.x` sends back one that has **already expired**
(`Max-Age=0` with a past `Expires`). Two go out per name, plain and `Secure`,
because a `Secure` cookie is not overwritten by a non-`Secure` one and the proxy
cannot tell which is out there. A host with a parent domain worth naming gets
two more scoped to it, for a cookie set on `.example.com` rather than on the
host: `a.b.example.com` adds `Domain=b.example.com`, a three-label host keeps
the leading dot (`.example.com`), and `example.com` has no parent and adds
nothing. The deletion **wins** over a `resCookies://` naming the same cookie on
the same request.

### Cookies

| Operator | Value | Effect |
|----------|-------|--------|
| `reqCookies` | `name=value` pairs (`&`-separated) or `{json}` | Merge into the request `Cookie` header. Accumulates across lines. |
| `resCookies` | `name=value` pairs (`&`-separated) or `{json}` | Set `Set-Cookie` headers. Accumulates across lines. |

A name written with no `=` *inside* a query gets an **empty value** — it does not
delete the cookie; to remove one, use `delete://reqCookies.<name>`. A whole
value with no `=` anywhere is not a query string at all but a **location**, so
`resCookies://sid` reads a file of that name and sets nothing. A `resCookies`
entry **replaces** a `Set-Cookie` the response already sent under the same name
rather than adding a second one.

Deleting every cookie from a request leaves `Cookie:` present and **empty**
rather than removing it, which is upstream's `setHeader(data, 'cookie', '')`.

```
example.com   reqCookies://sid=abc&locale=en
example.com   delete://reqCookies.tracking   # this is how you drop one
example.com   resCookies://theme=dark
```

#### Cookie attributes

The `{json}` spelling of `resCookies` may give a cookie an object instead of a
value, and its fields become `Set-Cookie` attributes:

```
example.com   resCookies://{"sid":{"value":"abc","httpOnly":true,"secure":true,"path":"/","sameSite":"Lax","maxAge":600}}
```

```
Set-Cookie: sid=abc; Expires=<now+600s>; Max-Age=600; Secure; HttpOnly; Path=/; SameSite=Lax
```

`value`, `maxAge`, `secure`, `httpOnly`, `partitioned`, `path`, `domain` and
`sameSite` are recognised, each in the spellings upstream accepts (`maxAge` also
as `maxage` / `MaxAge` / `Max-Age` / `max-age`, and so on). A field that is
absent or falsy is not written, and `maxAge` emits the `Expires`/`Max-Age` pair
together. The order above is upstream's `getCookieItem` order.

An **array** gives one name several `Set-Cookie` lines, which is how you set the
same cookie under more than one scope:

```
example.com   resCookies://{"sid":[{"value":"abc","path":"/a"},{"value":"abc","path":"/b"}]}
```

On the **request** side an object contributes its `value` alone — a `Cookie`
header has nowhere to put attributes, and upstream drops them here too.

### Body

| Operator | Value | Effect |
|----------|-------|--------|
| `reqBody` / `resBody` | replacement text, or a file/URL holding it | Replace the entire body |
| `reqReplace` / `resReplace` | `from=to` pairs, `&`-separated | Substitute inside the body |
| `reqPrepend` / `resPrepend` | text, or a file/URL holding it | Insert at the start of the body |
| `reqAppend` / `resAppend` | text, or a file/URL holding it | Insert at the end of the body |
| `resMerge` | `{json}` | Deep-merge a patch into a JSON response body |
| `cssBody`/`cssPrepend`/`cssAppend` | CSS, or a URL | CSS to add to a **CSS or HTML** response |
| `htmlBody`/`htmlPrepend`/`htmlAppend` | markup | Markup to add to an HTML response |
| `jsBody`/`jsPrepend`/`jsAppend` | JavaScript, or a URL | JS to add to a **JS or HTML** response |

When any body operator applies, whistle-rs buffers that body, transforms it, and
recomputes `Content-Length` (dropping any `Transfer-Encoding`). Requests and
responses without a body operator are streamed through untouched.

**A `GET`, `HEAD`, `OPTIONS` or `CONNECT` request is never given a body.**
`reqBody`/`reqPrepend`/`reqAppend` are dropped on those methods rather than
applied, matching whistle — a GET carrying a payload is what some origins and
CDNs answer with a `400`. The check reads the method being *forwarded*, so
`method://post` alongside the injection restores it. `reqReplace` and
`delete://reqBody.…` are unaffected: they rewrite a body that is already there,
and on these methods there is none.

A **compressed response is decoded first**, transformed as text, then
re-encoded under the same coding on the way out — `gzip`, `deflate` and `br` are
round-tripped. Without this a `resReplace://` against a gzipped page would search
the deflate stream for its pattern and silently find nothing, which is what most
real sites (they compress) would have hit. A coding this port cannot round-trip
(`compress`, a doubly-encoded `gzip, br`) is left alone, and the operators then
run over bytes they will not usefully match — the same non-effect as before,
rather than a corrupted body. `enable://gzip|br|deflate` forces the *outgoing*
coding regardless of what arrived (`br` beats `gzip` beats `deflate`), so it can
compress a body an origin sent in the clear.

Which is why **every** request's `Accept-Encoding` is narrowed on the way out to
the tokens this proxy can undo *and* redo — `gzip` and `br`
(`removeUnsupportsHeaders`, `_original/lib/util/index.js:1549-1570`, run at
`req.js:579`). A browser asks for `gzip, deflate, br, zstd`; left alone, the
origin picks zstd, nothing here can decode it, and every body operator quietly
does nothing. The narrowing is upstream's and so are its edges: the comparison
is against the whole token, so `gzip;q=1.0` is not `gzip` and goes; and a
request left with **no** acceptable coding keeps the header it arrived with
rather than being given one it never asked for.

Every operator in this table accumulates: writing the same one on several
matching lines makes them all contribute, joined per family — see
[How several lines of one operator combine](#how-several-lines-of-one-operator-combine).

A value that names a **file or a URL** is read before the operator applies (see
[Values read from a file or a URL](#values-read-from-a-file-or-a-url)) — which is
also why a URL on `jsAppend`/`cssAppend` still means `<script src>` here and is
never fetched.

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

The response *head* has an order of its own, and one part of it is worth
knowing: `delete://resHeaders.x` runs **after** those two side effects
(`_original/lib/inspectors/res.js:1160-1165` against `:1097-1104`), so it can
take away what the injection just wrote —

```
example.com   resAppend://<!-- x -->   delete://resHeaders.cache-control
```

— leaves the response with no `Cache-Control` at all, rather than with the
`no-store` the injection stamped on it.

`Location` is percent-encoded on the way out (`encodeNonLatin1Char`,
`res.js:946-949`), after every header operator has had its say, so a redirect to
a path with a non-ASCII character in it arrives intact.

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

## Quick reference

One line each. The worked versions — what they do, what surprises people about
them, and what to reach for when they do not fire — are in
[`COOKBOOK.md`](COOKBOOK.md).

| Task | Rule |
|------|------|
| Serve a site from a local dev server | `www.example.com  http://localhost:5173` |
| Send a host somewhere else, keeping its `Host` header | `.cdn.example.com  host://10.0.0.9` |
| Local development against a fake domain | `test.local  127.0.0.1:9099` |
| Mock an endpoint from a file | `api.example.com/users  file:///Users/me/mock/users.json` |
| Mock an endpoint inline | `api.example.com/health  file://({"status":"ok"})  resType://json` |
| Return a bare status | `/\/track\b/  statusCode://204` |
| Redirect an old path (a prefix needs no `*`) | `example.com/old  redirect://https://example.com/new/` |
| …keeping what followed it | `^http://example.com/old/**  redirect://https://example.com/new/$1` |
| Add a request header | `example.com  reqHeaders://x-token=abc` |
| Add a header whose value has a space | `example.com  reqHeaders://authorization=${bearer}` |
| Drop a request header | `example.com  delete://reqHeaders.user-agent` |
| Allow CORS for a front end | `api.thirdparty.com  resCors://*` |
| Change one field of a JSON response | `api.example.com  resMerge://{"env":"staging"}` |
| Slow a response down | `slow.example.com  resDelay://2000  resSpeed://800` |
| Break a connection | `flaky.example.com  enable://abort` |
| Fail a fraction of calls | `api.example.com  statusCode://503  includeFilter://chance:5%` |
| Narrow a rule to one method | `api.example.com  host://10.0.0.1  includeFilter://m:POST` |
| Carve one path out of a broad rule | `example.com/health  ignore://all` |
| Win against an earlier line | `$example.com  host://2.2.2.2` |
| Leave a pinned host alone | `pinned.example.com  sniCallback://no-mitm` |
| Tag every intercepted response (confirms MITM is active) | `/^https:/i  resHeaders://x-via=whistle-rs` |

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
| TLS | `cipher` (upstream TLS version pin + OpenSSL cipher-string evaluation), `sniCallback` (plugin picks the MITM certificate, or declines to intercept) |
| Scripting / extend | `resScript`, `frameScript`, `plugin`, `pipe`, `weinre` |

**Rule-file features:** a line `@<url>` or `@<file>` includes rules fetched/read from
that source at load time; `${port}` and `${version}` in operator values are substituted
(case-insensitive); an operator value that names a file or a URL is
[read before the operator applies](#values-read-from-a-file-or-a-url), and one
wrapped in backticks is [rendered against the request](#backtick-templates);
`locationHref://` injects a client-side redirect into HTML responses.

**Alias operators** are normalised to their canonical form, so all of these work too:
`hosts→host`, `xhost→host` (same operator, but the `x` spelling also falls back — see
[Destination](#destination)), `html→htmlAppend`, `js→jsAppend`, `css→cssAppend`,
`download→attachment`, `status→statusCode`, `skip→ignore`, `tlsOptions→cipher`,
`pathReplace→urlReplace`, `reqMerge→params`, `resRules→resScript`,
`ruleFile`/`ruleScript`/`rulesScript`/`reqScript`/`reqRules`→`rulesFile`, `P→G`.
An `ignore://` naming an alias is normalised the same way, so `ignore://hosts`
drops `host://` and `ignore://xproxy` drops the upstream-proxy family.

Notes: `http2https-proxy`/`https2http-proxy` and the `internal-*` family do
convert the origin scheme, and the stripped-TLS hop carries whistle's
`x-whistle-https-request` marker (see [Upstream proxy](#upstream-proxy)); what is
still missing from the `internal-*` family is the rest of whistle's
whistle-to-whistle handshake — the client-id and intercept-policy headers. **Every** upstream-proxy name also accepts an `x` prefix — `xproxy`, `xsocks`,
`xhttp-proxy`, `xhttps-proxy`, `xinternal-proxy`, `xinternal-http-proxy`,
`xinternal-https-proxy`, `xhttps2http-proxy`, `xhttp2https-proxy` — which is
upstream's one optional `x?` over the whole family (`PROXY_RE`,
`_original/lib/rules/rules.js:37-38`) and is parsed here as an alias of the base
name. Like upstream, an `x`-prefixed proxy that cannot be **established** falls
back to a direct connection — see [the upstream-proxy section](#upstream-proxy)
for what the retry does and does not cover. `enable`/`disable` apply a curated flag set on both
sides of the request (see the [Flags](#flags-includes--values) tables — others are
inert); `pipe` routes to a
registered server like `plugin` (no mid-stream piping); a **bare URL** forwards the
request (see [Destination](#destination)), while the `rule://` spelling of that same
protocol key pulls extra rules in from the values store, as `rulesFile://` does from a
file; `{name}` in any operator value is
substituted from the values store. `cipher` carries Node's TLS options and honours
what rustls can express — see [What `cipher://` can pin](#what-cipher-can-pin).

### What `cipher://` can pin

`minVersion` / `maxVersion` / `secureProtocol` (or a bare `cipher://TLSv1.2`
token) pin the **upstream** TLS protocol version. rustls offers TLS 1.2 and 1.3
only, so a pin older than 1.2 clamps up to 1.2.

`ciphers` is an **OpenSSL cipher string**, and whistle-rs evaluates it. Not
matches names against a table — evaluates the language: aliases (`HIGH`,
`DEFAULT`, `ECDHE`, `AESGCM`, `aRSA`, …), the infix `+` as a conjunction
(`ECDHE+AESGCM`), `!` and `-` exclusions, `+` deprioritisation, `@STRENGTH`
sorting. What differs from OpenSSL is not the language but the **universe** it is
evaluated over: rustls carries nine suites, so `3DES` correctly selects nothing —
exactly as it does on an OpenSSL built without 3DES.

Two details are reproduced because they were **measured against Node 26 /
OpenSSL 3.6**, not inferred:

- **A TLS 1.2 name does not constrain TLS 1.3.** `ciphers: "ECDHE-RSA-AES128-GCM-SHA256"`
  still negotiates TLS 1.3 with its default suite. Applying the pin to the 1.3
  list would leave nothing to offer there and **downgrade the connection to TLS
  1.2** — a rule meaning "prefer this suite" would have weakened it.
- **Only an explicit TLS 1.3 suite name constrains TLS 1.3.** `TLS_AES_128_GCM_SHA256`
  pins it; the alias `CHACHA20` does not, even though it describes a TLS 1.3
  suite too.

A string that selects **nothing at all** fails the request with a message naming
the tokens that came up empty. That is OpenSSL's own behaviour — it throws `no
cipher match` at context creation, before any connection — and it is the honest
answer for the one case evaluation cannot rescue: this build does not have the
algorithm.

```
# evaluated; the origin really negotiates from this set
example.com cipher://{"ciphers":"ECDHE+AESGCM:!AES128"}
# TLS 1.3 pinned by name; the TLS 1.2 list is emptied, as OpenSSL empties it
example.com cipher://{"ciphers":"TLS_AES_128_GCM_SHA256"}
# 502: `no cipher match: 3DES names no cipher suite this build has`
example.com cipher://{"ciphers":"3DES"}
```

The nine suites are the three TLS 1.3 ones (AES-GCM ×2, ChaCha20-Poly1305) and
the six TLS 1.2 ECDHE ones (ECDSA/RSA × AES-128-GCM/AES-256-GCM/ChaCha20). Since
a selection is an **intersection** with that set, a `cipher://` can only narrow
what the proxy will negotiate, never widen it.

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
select the connection in the console and open its Frames tab, or fetch
`/frames.json?id=<session>`.

`enable://ignoreSend` and `enable://ignoreReceive` silence one direction of such a
session: the frames are still **captured and flagged**, they are simply never
delivered to the peer, so the view shows what was dropped instead of a gap.
Control frames are exempt — withholding a `close` would leave the two ends
disagreeing about whether the connection is over, and withholding a `ping`/`pong`
breaks the keep-alive the endpoints agreed on; whistle likewise only ever
withholds data frames.

`enable://pauseSend` and `enable://pauseReceive` **hold** one direction instead of
dropping it. The frames are captured and flagged as they arrive, and the Frames tab
shows which direction is being held, how many frames are waiting, and a **Release**
button that lets them out — in the order they arrived, all of them at once. That is
the only granularity whistle has: its own console sets the direction's status back
to normal, and there is no release-one-frame anywhere in it. A release goes to
`POST /api/ws/release` with `{"id": <session>, "dir": "send"|"receive"}`, and
`GET /api/ws/status?id=<session>` answers what is held.

A pause is not an ignore with a delay, and two differences follow from that:

- It holds this direction's **control** frames too — upstream pauses the byte
  stream rather than the frames in it, so a `ping` sharing a chunk with held data
  is held with it. To stop the peers timing out on a connection that has gone
  quiet, the proxy sends a keep-alive of its own every 22 seconds while the pause
  lasts, exactly as whistle does. `disable://pong` suppresses the one that goes
  to the **server** while the send direction is held, and `disable://ping` the
  one that goes to the **client** while the receive direction is held — the same
  split whistle makes. Suppressing them means a quiet connection is left to
  whatever idle timeout the peers have, which is the point of asking.
- Both flags on the same direction is not a state: whistle keeps one status per
  direction and tests the pause first, so `enable://pauseSend|ignoreSend` pauses,
  and once released the direction stays open rather than starting to drop.

A held direction reads ahead so the console can show what is waiting, up to 64
frames or 4 MiB; past that the peer is back-pressured until the release, and
nothing is lost. Frames still held when the connection ends stay flagged in the
capture — they never reached the peer, and a release then has nothing to find.

### Multiple patterns and multi-line blocks

One operator can serve several patterns on a line — the line expands to one rule
per pattern. This needs the **operator-first** form; written pattern-first, only
the first token is a pattern and the rest are operators (see
[Where the pattern sits](#where-the-pattern-sits)):

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

### Parsed but not applied (2)

| Operator(s) | Why / note |
|-------------|-----------|
| `G` | Global-rule marker (a rule-precedence concept, not a per-request traffic effect) |
| `style` | Rule colour in whistle's rule list — the console's rule editor is plain text with no per-rule rendering |

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
- **Injected text is UTF-8.** whistle re-encodes it into the response's declared
  charset; a `charset=gbk` page will see mojibake in the injected fragment.
- **`params://` into a body is buffered, not streamed.** whistle rewrites a
  multipart body part by part so an upload never lands in memory; whistle-rs has
  the body in hand already (every other request-body operator buffers) and splits
  on the boundary. Same result on a well-formed body, more memory on a large one.
  The size ceiling *is* implemented — see [Request bodies have a
  ceiling](#request-bodies-have-a-ceiling).
- **A non-UTF-8 request body is left alone** by the `params://` merge. whistle
  tries GB18030 and re-encodes afterwards; this port stays UTF-8, as it does for
  every other text transform.
- **`{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` are not substituted**, and
  are a non-goal rather than a gap. Upstream substitutes them into the `rules.txt` /
  `_rules.txt` / `resRules.txt` / `_values.txt` files it reads out of an installed
  npm package's directory, with the package's own `package.json` as the source
  (`renderPluginRules`, `_original/lib/util/index.js:3533-3542`;
  `lib/plugins/get-plugins-sync.js:184-206`). Plugins here are external HTTP servers
  speaking this port's own protocol: there is no package directory, no `package.json`,
  and no static rules file — a plugin injects rules by returning them from its request
  hook, where it already knows its own name. There is nothing to substitute from.

If a rule doesn't do what you expect, run with `-v` (debug logging) — each request
logs its resolved destination or short-circuit decision.


### `x-server` on a response the proxy made itself

Every response whistle generates rather than forwards carries `x-server`
(`wrapResponse`, `_original/lib/util/index.js:1080-1090`) — a `statusCode://`,
a `redirect://`, a `file://` mock, a preflight it answered. It says what a
mocked response otherwise leaves open: this came from the proxy, not the
origin.

whistle-rs does the same and writes `whistle-rs`, because it is not whistle.
Tooling keying off the exact upstream value will not match, which is the right
outcome — it is not talking to whistle.


### Not decrypting a connection

`disable://intercept` relays a TLS connection instead of reading it — the client
gets the **origin's own certificate**, not one this proxy forged. It is what a
certificate-pinned client needs, and what you reach for on a host you do not
want decrypted. `disable://https` and `disable://capture` are the same flag
(`disable.intercept || disable.https || disable.capture`,
`_original/lib/tunnel.js:167-169`).

```
pinned.example.com disable://intercept
```

The connection is still **routed**: `host://` and the proxy family apply to it
as usual, because routing needs no plaintext. What it loses is everything that
does — the session carries no request, no headers and no body, and no request or
response operator runs on it.

It outranks `sniCallback://`: asking a plugin which certificate to forge for a
connection nobody will forge one for is a question with no use for its answer,
so the hook is not called.

`--no-intercept-https` says the same thing for every connection at once.


### Shaping the CONNECT to an upstream proxy

`disable://proxyUA` drops the client's `User-Agent` from the CONNECT this proxy
sends to an upstream one, and `disable://proxyConnection` asks that proxy to
close rather than keep the connection alive — `Proxy-Connection: close` instead
of `keep-alive` (`_original/lib/inspectors/res.js:314-318,:329-333`). Both are
read straight off `disable`, without the `enable://` cancellation, as upstream
reads them.


### Response bodies have a ceiling too

whistle rewrites a response with **stream transforms** (`addTextTransform` /
`addZipTransform`, `_original/lib/inspectors/res.js`), so a rule never costs it
the body. This port's body layer is buffered, so it does: any matching body
operator collects the whole response before touching it.

Measured against an 800 MB download with a single `resReplace://` matching,
resident memory went from 9.9 MB to **1.97 GB** — one ordinary rule and one
large file.

Bounded at **16 MiB** now (`--body-rewrite-limit`), which is upstream's own
"big data" number (`BIG_MAX_RES_SIZE`, `res.js:22`) and generous for the pages,
bundles and JSON payloads rewriting is aimed at. Past it the response streams
through **untouched**: the body operators, `enable://gzip` and any plugin
`responseBody` hook do not apply, and a `WARN` names the request and the limit.
The same 800 MB download now peaks at **33 MB** and arrives byte-complete.

This is one of the few places where the port needs a knob upstream does not,
and the reason is architectural rather than a preference — see
[`ROADMAP.md`](ROADMAP.md).


### 跨域 mock：自动 CORS

用 `file://`（以及 `rawfile`/`tpl`/`dust`/`jsonp` 和它们的 `x`/`xs` 变体）mock 一个
API，而发起请求的页面在**另一个源**上时，whistle 会自己补上 CORS 头 —— 否则浏览器
在任何代码看到响应之前就把它拒了。whistle-rs 现在同样如此
（`isAutoCors`，`_original/lib/handlers/file-proxy.js:178-191`）。

触发条件就是请求带了 `Origin` 头。补的是 `resCors://enable` 那一套：回显请求自己的
`Origin`，并带 `access-control-allow-credentials: true`。

**预检也被直接应答。** 浏览器在真实请求之前先发 `OPTIONS`，而 whistle 对 file 规则的
预检**答 200 + CORS 头，根本不打开文件**（`file-proxy.js:249-252`）。这一半不可省：
文件不存在就会 404 掉预检，规则只对 `POST` 写也会答出错误的东西，真实请求于是永远
不会发生。

```
# 页面在 http://app.test 上，API mock 在 http://api.test 上
api.test/data file:///srv/mock.json
```

关掉它：`disable://autoCors`，或行级属性 `lineProps://disableAutoCors`
（原版的拼写错误别名 `disabledAutoCors` 一并接受）。

只作用于 file 家族。`redirect://` 与 `statusCode://` 在上游由另一个 handler 应答，
不带自动 CORS，这里也一样。


### Request bodies have a ceiling

The operators that rewrite a request body need it in memory, and the body is
whatever the client decided to send. whistle bounds that at **2 MB**, raised to
**16 MB** by `enable://reqMergeBigData` (`MAX_REQ_SIZE` / `BIG_MAX_REQ_SIZE`,
`_original/lib/inspectors/req.js:19-20,:163`), and whistle-rs does the same.

Past the ceiling the request is **not** failed and **not** truncated: the body
streams on to the origin byte for byte, and only the rewriting stops —
`reqBody`, `reqReplace`, `params`, `reqWrite`/`reqWriteRaw` and `reqSpeed` do not
apply. That is upstream's `interrupt` (`handleParams`, `req.js:169-185`), and it
is the right failure for a debugging proxy: traffic must not be damaged by the
inspection of it. whistle-rs logs a `WARN` naming the request when it happens,
so a rule that stopped applying above some size does not look like a rule that
never matched.

`b:` body filters read the body too, in order to decide *which* rules apply, so
they cannot consult a rule for the raised ceiling — they always use the plain
2 MB and match on the prefix they read, as upstream's `resolveBodyFilter` does.


### Event streams

A `text/event-stream` response is never collected. Collecting one would not slow
it down, it would withhold it: the body ends when the server decides, which for
SSE is typically never, so the client would receive nothing at all.

`resReplace://` still applies. It is the one body operator that does not need the
whole body — it needs a window — so it travels with the stream, substituting as
events arrive. whistle-rs holds back only a tail (just enough that a match
straddling a chunk boundary cannot be missed) and flushes through the end of each
complete event, which is upstream's own mechanism
(`_original/lib/util/replace-string-transform.js`,
`replace-pattern-transform.js`). A blank line written `\r\n\r\n` counts as an
event boundary here, where upstream looks only for `\n\n`.

Two cases are refused rather than attempted, and the stream passes through
untouched:

- **a compressed event stream** — searching a deflate stream for a plaintext
  pattern finds nothing, and rewriting it would corrupt what the header promises;
- **the operators that genuinely need an ending**: `resMerge://`, `resScript://`,
  and the typed injections (`htmlPrepend`, `jsAppend`, …), which are selected by
  the response being HTML/JS/CSS and so never match an event stream anyway.

  A plugin that declares `responseBody` is skipped the same way, and logs a
  `WARN` so the hook does not appear to have mysteriously not run. Use a
  streaming hook (`pipe://`) instead — see [`PLUGINS.md`](PLUGINS.md).

`resPrepend://` and `resAppend://` **do** apply: one goes out ahead of the
origin's first byte and the other after its last. On a stream that never ends,
`resAppend://` never fires — there is no "after" a body that does not finish,
and that is the honest answer rather than a missing feature.

`resBody://` applies too, and says there is no origin body to wait for: the
value is sent and the stream ends. That makes it a usable mock for an endpoint
that would otherwise stream forever. No doctype is stamped and
`safeHtml`/`strictHtml` do not gate any of the three, because all of that is
upstream's HTML-injection machinery and an event stream is not HTML.

`disable://trailers` applies to an event stream; `resWriteRaw://` and
`trailers://` do not.


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
