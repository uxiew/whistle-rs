# Rules reference

> Current compatibility scope and executed checks: [STATUS.md](STATUS.md).
> Operator entries describe semantics and limitations; their presence is not
> a claim of whole-product compatibility. Historical audits are preserved in
> [ROADMAP-HISTORY.md](ROADMAP-HISTORY.md).

whix uses whistle's rule syntax. This document is the complete reference for
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

- [File format](#file-format) — [pulling in another rules text (`@`)](#pulling-in-another-rules-text-)
- [Patterns](#patterns) — [prefix](#1-domain--url-prefix-most-common) ·
  [leading dot](#2-leading-dot-subdomain-match) · [wildcard](#3-wildcard) ·
  [`^`](#4---wildcards-everywhere) · [`$0`…`$9` captures](#09--what-the-pattern-captured) ·
  [regexp](#5-regular-expression) · [port](#6-port) · [`!` negation](#--negated-patterns) ·
  [`$` exact](#--exact-patterns) ·
  [where they differ from upstream](#where-patterns-differ-from-upstream)
- [Operators](#operators)
  - [Where the pattern sits](#where-the-pattern-sits) · [Shorthands](#shorthands)
  - [What an operator's value can be](#what-an-operators-value-can-be) —
    [read from a file or a URL](#values-read-from-a-file-or-a-url) ·
    [backtick templates](#backtick-templates) ·
    [values declared in the rules text](#values-declared-in-the-rules-text)
  - [Destination](#destination) — [forwarding to another URL](#forwarding-to-another-url)
  - [Upstream proxy](#upstream-proxy) — [PAC](#pac)
  - [URL rewriting](#url-rewriting) — [where `params://` lands](#where-params-lands)
  - [Filter conditions](#filter-conditions) — [conditions](#conditions) ·
    [the response phase](#the-response-phase) · [the body condition](#the-body-condition) ·
    [origin markers](#origin-markers)
  - [Disabling operators](#disabling-operators) ·
    [Short-circuit](#short-circuit-no-upstream-request-is-made)
  - [Request rewriting](#request-rewriting) — [`auth://`](#auth-in-four-spellings)
  - [Plugins](#plugins) · [Choosing the MITM certificate](#choosing-the-mitm-certificate) ·
    [Scripting](#scripting) · [`log://`](#log--a-pages-console-in-this-one) ·
    [weinre](#weinre-html-debug-injection)
  - [Flags, includes & values](#flags-includes--values) — [trailers](#trailers) ·
    [`enable://abort`](#enableabort-is-two-gates-not-one) ·
    [several `rulesFile://` lines](#how-several-rulesfile-lines-combine)
  - [Dump files](#dump-files) · [Delays & throttling](#delays--throttling)
  - [Response rewriting](#response-rewriting) · [Deleting](#deleting) ·
    [Cookies](#cookies) · [Body](#body)
- [Precedence](#precedence) — [how several lines of one operator combine](#how-several-lines-of-one-operator-combine)
- [Quick reference](#quick-reference)
- [Operator coverage](#operator-coverage) — [applied at runtime](#applied-at-runtime) ·
  [metadata and upstream-only infrastructure](#metadata-and-upstream-only-infrastructure) ·
  [simplified vs. upstream](#simplified-vs-upstream) ·
  [where wproxy.org and whistle disagree](#where-wproxyorg-and-whistle-disagree)
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
  `host:port`), whix falls back to scanning for the first pattern token —
  matching whistle's "operators first, then patterns" form for the common case.

You can load rules three ways:

```bash
whix -r rules.txt              # from a file
whix --rule "example.com host://127.0.0.1:8080"   # inline
whix -r rules.txt --rule "…"   # file first, then inline appended
```

### Pulling in another rules text (`@`)

A line that is **only** `@` and a source is replaced by the rules that source
holds, where the line stands:

```
example.com          host://10.0.0.1
@/etc/whistle/team.rules      # that file, re-read every 5 s
@https://intra/rules.txt      # that URL, re-fetched every 10–30 s
@~/personal.rules             # a path under $HOME
```

This works for **every** rules text: `-r`/`--rule`, the console's editor,
`POST /api/rules`, a named group, an imported bundle, and whatever came back off
disk on restart. Four things follow from how it is done, and each is worth
knowing before you rely on it:

- **It is spliced where the line stands.** The included lines are ordinary lines
  of the text they went into, so [precedence](#precedence) is the ordering you
  can see: a line above the `@` outranks what it brings in, a line below does
  not, and a `lineProps://important` inside the included text outranks a plain
  line above it exactly as it would if you had typed it there.
- **The text you typed stays the text you typed.** The console shows the `@`
  line, and saving does not bake the fetched rules into your file. To see
  whether an include actually landed, ask `GET /api/rule-groups` — its `rules`
  count is of the *parsed* rules, so it goes up when the source arrives.
- **Setting rules never waits for the network.** The save returns immediately
  and the include lands when the fetch does — normally within milliseconds, and
  bounded at 16 s and 256 KB per source. Until then the line contributes
  nothing, which is also upstream's behaviour. All of a text's sources are
  fetched at once, so one that hangs holds up no other.
- **Starting waits for it, but not for long.** A proxy started with includes
  in its rules waits up to 3 s for them before it answers anything, so a
  source that answers is in effect for the very first request (upstream does
  not wait at all). Past 3 s it answers without the rest — the log says
  `rules includes still loading after 3 s` and names them — and their rules
  apply when they land. Before this it waited for every source in turn: three
  on a server that had hung kept it, console included, silent for 48 s.
- **One level.** An `@` line *inside* an included text is not followed, so
  there is no cycle to guard against. At most 20 `@` lines per rules text are
  resolved (upstream's `MAX_REMOTE_RULES_COUNT`).

A source is a `/absolute` path, a `~/` path, a Windows drive path, an
`http(s)://` URL, a `whistle.<plugin>` name, or a `$<key>` plugin-store
reference. The last two are **not implemented here** — plugins in whix are
external HTTP servers with no such endpoint (see [`PLUGINS.md`](PLUGINS.md)) —
and the line is logged and contributes nothing. Anything else is not an include
and keeps whatever meaning it already had:

```
@team.rules              # relative: not an include (upstream's regexp agrees)
@ /etc/team.rules        # a space after the @: not an include
example.com @/etc/x      # a pattern in front: this is the G:// operator
@/etc/team.rules extra   # trailing text: not an include
@`/etc/team.rules`       # backticks are allowed, and ${port} resolves inside them
@/etc/team.rules # note  # a trailing comment is allowed
```

An `@` line inside a ```` ``` ```` [fenced value](#values-declared-in-the-rules-text)
is content, not a line, and is never fetched. A value the included text declares
is available to the text that included it; when both declare the same name, the
**including** text wins.

> **One divergence, and it is the safer one.** A fetch that fails leaves the
> last text that source yielded in place, and logs why. Upstream tolerates three
> consecutive failures and then applies an empty text, deleting the rules that
> source carried — and blanks it at once on a redirect, or when a file that was
> there has gone (`updateBody` / `readFile`,
> `_original/lib/util/http-mgr.js:280-294,:377-401`). A blip on an intranet
> should not silently remove a team's rules from a running session, and the
> state it would leave is indistinguishable from the include never having
> worked. A source that has *never* loaded contributes nothing, which is
> upstream's initial state too, and a source that answers `204` or an empty body
> really does empty itself — that is an answer, not a failure.

---

## Patterns

A pattern decides **which requests a rule applies to**. whix supports four
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
| scheme (`http://`, `https://`, `ws://`, `wss://`, `tunnel://`) | optional; if present it must be the request's own — a WebSocket's URL is `ws://…`, so `http://example.com` does **not** reach it and `example.com` does |
| host | required, and matched **exactly** (case-insensitive — a [deviation](#where-patterns-differ-from-upstream)) unless it starts with a dot (see below) |
| port | optional; `example.com:8080` matches that host only on that port |
| path | matched as a **prefix** of the request path+query |

A pattern with **no host** matches nothing: `http://`, `http:///api`, `:80/api`
and `///example.com` are all dead text, because upstream compares the pattern
against the request URL and every URL has an authority.

That is the general answer for a pattern nobody can evaluate — no host, a regexp
that will not compile, a port that is not a number: it matches **nothing**, and
the line it is on does nothing. A pattern is the gate itself rather than a
modifier on one, so there is no third state for it to fall into and the failure
is always to leave the gate shut. A [filter condition](#filter-conditions) is
the modifier, and it does have one — which is why an unparseable *filter* is the
more dangerous of the two, and is written up there rather than here.

A pattern may carry a query **instead of** a path — `example.com?a=1` means
`example.com/?a=1` — and such a pattern still counts as "a host and nothing
else", so it applies on any port.

Only a host-and-nothing-else pattern ignores the port. `example.com` matches
`http://example.com:8080/x`; `example.com/` and `example.com/api` do not, because
a pattern carrying a path is compared against the URL text, port and all.

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
(`scheme://host[:port]/path?query`), with the host as the client wrote it. A
trailing `i` makes it case-insensitive:

```
/\.js(\?|$)/          resType://application/javascript
/^https:\/\/cdn\./i   host://10.0.0.9
```

The only flags are `i` and `u`, in either order — upstream's `REG_EXP_RE` is
`/^\/(.+)\/(i?u?|ui)$/` and admits nothing else. `/echo/g`, `/echo/m` and
`/echo/s` are **not** regexps; they fall through to the pattern kinds above,
where they have no host and so match nothing.

**The syntax is JavaScript's**, because whistle's is: everything between the
slashes is handed to an ECMAScript engine ([regress](https://docs.rs/regress),
the one the script engine here uses for `RegExp`). Lookahead, lookbehind,
backreferences and named groups all work, in a pattern, in a
[filter](#filter-conditions), in the [`*Replace` family](#replace-details) and in a
template's `.replace(/…/)`:

```
/\/api\/(?!internal\/)/        proxy://127.0.0.1:8888   # everything under /api but /api/internal
/(?<=\/v)\d+\/users/           resHeaders://x-versioned=1
example.com  resReplace://{r}  excludeFilter://m:/^(?!GET$)/   # GET only
```

Until 2026-09-30 these were compiled by Rust's `regex` crate, which has none
of the four. An expression it could not compile was quietly read as something
else, and the three lines above then did: nothing, nothing, and — the dangerous
one — the opposite (an `excludeFilter` that never excluded, so the rule applied
to every method).

What follows from "it is JavaScript's":

- `\d`, `\w` and `\b` are ASCII, as in JavaScript. (`regex` made them Unicode.)
- `u` is JavaScript's Unicode mode and is **stricter**: `/a\-b/u` is a syntax
  error there and here.
- A `/…/` that JavaScript cannot compile either — `/a(/` — drops its rule
  (pattern), is read as literal text (a filter condition's value, a template
  `.replace()`), or replaces nothing (`*Replace`), each as upstream does. It is
  no longer silent: the log says `rules: /a(/ (pattern; the rule is dropped) is
  not a regular expression: …` once, and `whix explain` prints the same
  line under the URL.
- A pathological expression costs what it costs in Node. `/(a+)+$/` against a
  long run of `a` is exponential in both; the engine backtracks, as V8 does.

Patterns this port *generates* — a [wildcard](#3-wildcard)'s expansion, a
[port](#6-port) pattern — are not the user's text and stay on the linear-time
engine.

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

The request's **query** is still handed to the destination, since an exact
pattern consumed only the path: `$example.com/search http://dev.test/search`
forwards `?q=cat` along with it. A pattern that named the query itself has
already consumed it.

`$` in front of a **wildcard** is an exact wildcard, not an exact match against
the literal text: `$*.example.com/api` names `/api` on any one-label subdomain
and nothing under it.

`!$…` is a **negated exact** pattern — every URL but that one. It is allowed
where a negated plain pattern is not, because upstream's `$` branch runs before
the check that drops those.

> **`$` carries no precedence, and this port used to think it did.** It read the
> prefix as an "important" shorthand — a divergence invented rather than
> inherited. Two things followed, both measured against whistle 2.10.8: a normal
> rule written *before* a `$` one still wins there, and `$example.com` named the
> site root where this port matched every URL on the host. Importance has one
> spelling: `lineProps://important`.

### Where patterns differ from upstream

Three, each measured against whistle 2.10.8 and each a place where upstream's
answer is an accident of comparing the pattern against the URL **as text**. Every
one of them turns a rule someone wrote into a rule that fires exactly never, so
no rules file can be relying on the upstream answer.

| Pattern | Upstream | Here |
|---|---|---|
| `EXAMPLE.com` (or a request whose `Host` is upper-case) | no match: the two strings differ | matches — a hostname is not case-sensitive |
| `example.com:80` on an http request (`:443` on https) | no match ever: `getFullUrl` strips the default port before anything is compared, so the URL never contains `:80` | matches port 80, and only port 80 |
| `[::1]` with no port, against `http://[::1]:8080/` | no match: a host-only pattern is also compared against the port-stripped URL, and `removePort` cuts at the first `:` after the scheme — which is inside the brackets, leaving `http://[` | matches |

The case fold is for the plain host-prefix form only. A **regexp** or a
**wildcard** pattern is matched against the URL exactly as the client wrote it,
which is upstream's behaviour and what makes `$0` and `${url}` report the real
request — so `/API\.example\.com/` matches an upper-case host and
`/api\.example\.com/` does not.

---

## Operators

An operator is `protocol://value`. whix recognises the **full whistle protocol
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
| `/abs/path` · `C:\path` | `file:///abs/path` … |
| `(text)` · `{name}` · `<path>` | `file://` and the bracket form — see below |
| any other token | a destination — see below |

**A path here is an absolute one.** `FILE_RE`
(`_original/lib/rules/rules.js:36`) is a drive letter or a *single* leading
slash, and nothing else: measured against whistle 2.10.8, `a.com ~/mock.json`
resolves to the destination `http://~/mock.json/…`, not to a file. This port
read `~/` and `./` as paths too until that was measured; the convenience was
also a silent change of meaning, since `a.com .internal.example` became a local
file that does not exist. Inside an operator's *value* `~/` is still a home
path (`file://~/mock.json`), which is upstream's `convertSlash` →
`getHomePath` (`lib/util/file-mgr.js:13-16`) and a different question.

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

**The three spellings of a data value, and the two roads.** A value written on
the rule line and a value loaded from a `{name}`, a file or a URL are not read
the same way — `tryParseMatcher` sits ahead of `_parseJSON` and only looks at
the former (`_original/lib/util/index.js:1165-1171,:1303`):

| | a value written on the line | a value that was loaded |
|---|---|---|
| JSON | read as JSON | read as JSON |
| `a=1&b=2` | read as a query, whitespace and all | read as a query, **only** if it has no whitespace |
| `a: 1` per line | **nothing** — no `=`, no value | the line format |

So `reqHeaders://x-a=${v}` with a two-line `v` keeps the newline inside the
value and the header is thrown away, while the same two lines inside a
`{value}` become two headers. And `reqHeaders://bare` sets nothing, while
`bare` on a line of a `{value}` sets an empty header. Both measured against
whistle 2.10.8.

In the line format the separator is the first `": "`, else the first `:`, else
the first `=`; a value wrapped in matching `"`, `'` or `` ` `` loses the quotes
(and a backticked one turns `\n` into a real newline); and an unquoted safe
integer becomes a number rather than a string. Only `reqMerge`/`resMerge` read
a dotted name as a path into the object (`RESOLVE_KEY_RE`, `util/index.js:95`).

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
the same URL is fetched and inlined. whix reads values in the request
phase, before there is a response to classify, so it keeps the HTML meaning —
which is the documented one — and never fetches for those six.

**What counts as a location.** An `http://` or `https://` URL, or a path that
starts at the root (`/tmp/x`), the home directory (`~/x`, also the full-width
`～/x`), a Windows drive (`C:\x`), or an explicit `./` / `../`.

> **`temp/…` is not one here, and it is upstream.** whistle's console lets you
> Cmd-click a `protocol://temp.json` in the rules editor, type the content into a
> dialog, and save — it rewrites the line to
> `protocol://temp/<64 hex>.json` and resolves that under its own `temp_files`
> directory (`TEMP_PATH_RE`, `_original/lib/util/common.js:167`;
> `getTempFilePath`, `util/index.js:1180-1187`, which drops the extension and
> keeps it only to guess a type). This port has neither directory nor editor, so
> the value stays the bare literal it looks like and a text operator writes it:
> measured, `resBody://temp/blank.json` returns the origin's page in whistle and
> the six characters `temp/blank.json` here. Recorded rather than half-built —
> the path without the editor is a filename nobody can produce, since it is a
> hash. `auth://temp/…` is unaffected: a slash makes it a location either way,
> and neither proxy sends credentials for it.

One exception, and it is upstream's: a URL on `reqCors://` / `resCors://` is the
allowed **origin**, folded into `{"origin":…}` before anything would be read
(`isCors`, `_original/lib/util/index.js:1344,:1361-1370`). `resCors://https://app.test`
is a CORS rule, not a fetch. A *path* there is still read.

> **Deliberately narrower than upstream.** whistle has no shape test: for the
> text operators *every* non-inline value is a path, and a bare
> `resBody://patched` is a read of `./patched` — relative to the rules file's
> root (`rule.root`, which only exists for rules a plugin or an `@`-include
> brought in) or else to whistle's own working directory. It fails, and the
> operator quietly sets an **empty** body. whix has no `rule.root`, and a
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
>
> **A `{name}` no value answers is not applied**, on the body operators —
> `reqBody`/`reqPrepend`/`reqAppend`, `resBody`/`resPrepend`/`resAppend` and
> the `html*`, `js*`, `css*` three each — as whistle does not apply it: it
> files the matcher under `rule.key` (`getKey`, `rules.js:263-270`), the values
> have nothing under it, and `getRuleValue` hands the operator nothing. The
> response is left alone, without the cache headers an injection would add.
> One brace-wrapped value is not a name: a JSON object — `{`, a `:`, `}`, and
> json5 reads it — is content, as upstream's `isJson` fallback makes it
> (`getValue`, `rules.js:272-288`), so `resBody://{"a":1}` is that body.
>
> The session still lists the operator, with an `unapplied` entry of kind
> `missing-value` naming the reference, so a typo shows in the console rather
> than in the traffic. Until 2026-10-02 this port wrote the six characters
> `{typo}` as the body, on the grounds that telling a reference from a
> brace-wrapped literal takes a grammar neither program has; upstream has one,
> `getKey` and then `isJson`, and this is it. A `${name}` *inside* a value is
> another matter, and there upstream agrees with this port: a lookup that
> misses shows as itself.

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
- For `reqBody`, `resBody`, `reqPrepend`, `resPrepend`, `reqAppend` and
  `resAppend` the content is the file's **bytes**, sent as they are — a GBK
  page or an image works, and a character split across `a|b` joins back — and
  never re-encoded into the response's `charset=`. That is upstream's
  `binProtocols` (`lib/rules/protocols.js:121-128`). Every other operator reads
  the content as UTF-8 text.
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

**A scheme may sit in front of the backticks**, because `TPL_RE` is
`/^((?:[\w.-]+:)?\/\/)?(`.*`)$/` (`rules.js:72`) — the prefix stays where it is
and the body is rendered. It only shows on a **destination**, whose scheme is
part of its value, and both spellings mean the same thing:

```
www.example.com   `http://${method}.dev`
www.example.com   http://`${method}.dev`      # same rule
```

**Rendered first, extended second.** The request's leftover path is appended to
what came *out* of the template, never to the template
(`resolveVar` runs in the resolution walk and `getPathRule` joins after it,
`rules.js:936-948,:1010`), so ``example.com file://`/srv/${method}.json` `` on
`/x` reads `/srv/GET.json/x`. And the bracket forms are read after the render
too: ``resBody://`({"m":"${method}"})` `` mocks `{"m":"GET"}` — parentheses off,
content, and no path appended.

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

The **whole-value** form takes the backticks too, and it is the one place a
pattern's captures reach a stored value — under a different spelling
(`SUB_VAR_RE`, `rules.js:99,:826-830`):

```
# values: mock = {"m":"${method}","id":"${RegExp.$1}"}
/example\.com\/api\/(\d+)/   resBody://`{mock}`   # both substituted
/example\.com\/api\/(\d+)/   resBody://{mock}     # neither: the content is bytes
```

`${RegExp.$1}`…`${RegExp.$9}` and `${RegExp.$&}` (the whole request URL) are the
only capture syntax that works there. A plain `$1` inside the value is left as
written — `$1` is substituted over the rule line, and the rule line said `{mock}`,
six characters with no `$` in them. Inside a **`${name}`** reference it is the
other way round: values expand first and captures second (`resolveVar` then
`replaceSubMatcher`, `rules.js:1010-1012`), so a plain `$1` there does arrive
expanded.

`log://` and `weinre://` opt out at parse time upstream (`rule.isTpl = false`,
`rules.js:1357-1359`) — their values name a channel, and a backtick in one is a
backtick.

A backtick value on a **response-phase** operator (`resHeaders://`, `resBody://`,
`trailers://`, …) renders with the response head in hand, so `${statusCode}`,
`${resHeaders.x}`, `${resCookies.x}`, `${serverIp}` and `${serverPort}` answer
there. On a `tpl://` file they are still empty, because a template short-circuits
before any origin replies.

#### Values declared in the rules text

A ```` ``` ```` fence declares a value beside the rules that use it
(`resolveInlineValues`, `_original/lib/util/index.js:211-224`), which is how a
rules file carries its own mocks:

````
``` mock.json
{"ok": true}
```
example.com/api   file://{mock.json}
````

The name is one whitespace-free token; the closing fence has to be the same run
of backticks, so a block containing a shorter fence survives intact; a name
declared twice keeps its **first** block; and an unterminated fence declares
nothing at all.

What comes back is **content, not rules**: nothing in it is scanned again, so a
`${…}`, a `{…}` or a fence inside a mock body is the text the mock meant to
contain.

**A block belongs to the rule group that declared it.** Another group's `{v}` is
not answered by it, and another group's block of the same name cannot shadow it —
the name is filed under `key + '\n\r' + <group>` and looked up that way, which is
upstream's `getInlineKey` / `getValueFor` (`util/index.js:205-209`,
`rules.js:785-796`). Rules **produced** mid-request are parsed into a rule set
of their own, and the naming file's blocks live in a different one — so a block
three lines above a `reqRules://` does not reach what that line produces. What a
`rulesFile://`/`reqScript://` family text or a `resRules://`/`resScript://` one
*can* read, besides the [values store](#flags-includes--values), is its own:

- the ``` blocks inside the produced text itself;
- what the script that produced it set on `values` (an object as its JSON) —
  the text's own blocks win over those.

````
```mock.js
values.body = 'from the script';
rules.push('example.com resBody://{body}');
```
example.com reqScript://{mock.js}
````

That is upstream's `resolveRulesFile`, which constructs the produced rule set with
the script's `values` and lets `Rules#parse` lay the text's blocks over them
(`rules/index.js:520-529`, `rules.js:2033-2059`) — measured on both proxies. A
`rule://` text and a plugin's rules read the store alone. The *name* on the
including line is read where it was written, so `rule://more` beside a block
fenced as ```` ```more ```` still finds it.

**A block beats a values store entry of the same name**, as it does upstream —
`getValueFor` asks the inline map first and falls back to the store. Values set
in the console are the store. The one thing that beats a block is `--value` on
the command line: it is an instruction for this run, so
`whix -r team.rules --value mock=local` serves `local` even where
`team.rules` declares its own ```` ```mock ````. (Until 2026-09 the store beat
every block; upstream's own test suite caught it — `test/units/keys.test.js`.)

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
| `example.com file:///srv/mock.json` | `/` | `/srv/mock.json` — **nothing** is appended |

That last row is the root, and it is a rule of its own: a **domain** pattern is
stored with the trailing slash (`formatUrl`,
`_original/lib/util/common.js:526-536`), so a request for `/` leaves no tail at
all. It matters for a value that names a *file* — `/srv/mock.json/` is a
directory that does not exist — and it is why `example.com file:///srv/static`
answers `/` with **404** on both proxies: the `index.html` candidate comes from
a trailing slash in the text you wrote (`getRuleFiles`,
`lib/util/index.js:1443-1450`), so write `file:///srv/static/` when you want the
index. A pattern that carries a path is not stored with the slash, so
`example.com/api file:///srv/d` on `/api/` does take the `/`.

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

Only the **file** family is a list. `getFiles` splits the matcher for
`rule.files` and nothing else (`rules.js:290,:943-948`), so a `|` in a
destination is an ordinary character — `example.com http://dev/api?f=a|b`
forwards the filter it was given, where splitting would have handed the origin
half of it.

> `rule://<name>` is **not** a destination: it is this port's own spelling for
> pulling a values-store entry in as more rules. Upstream files it in the same
> place, where it can only ever produce the unusable URL `rule://<name>`.

> **`location://` is not a protocol.** It is in neither upstream's registry nor
> its alias table, so the token is a *destination* whose scheme nothing can
> speak, and both proxies answer **502**. This port used to treat it as a
> synonym for `redirect://` and answer a `302` — a name it invented, and one no
> case had ever asked about until `coverage-ops.js` went looking for operators
> with no case that proves anything. Write `redirect://` for the 302 and
> `locationHref://` for the page that redirects itself.

**A destination has to be `http` or `https`.** A plain request named at any
other scheme answers **502 `unsupported protocol <scheme>:`** rather than being
sent there — which is what `ws://`, `wss://` and `tunnel://` document about
themselves ("普通 HTTP/HTTPS 请求：返回 502"), and what whistle does for every
other spelling on the same line of the same function: `isWebProtocol` is
`protocol == 'http:' || protocol == 'https:'` and everything else is
`next(new Error('Unsupported protocol …'))`
(`_original/lib/rules/protocols.js:269-271`, `lib/handlers/http-proxy.js:5-11`).

The rule that makes this matter is a typo:

```
example.com   socks5://127.0.0.1:1080     # 502 — the operator is socks://
```

`socks://` is an [upstream proxy](#upstream-proxy); `socks5://` is no operator at
all, so the line falls through to this slot as a destination. Forwarding it would
open a **cleartext HTTP** connection to a port that speaks SOCKS. A scheme-less
destination is unaffected: it inherits the request's own, which is one of the two.

*A **WebSocket** request and a **`CONNECT`** tunnel resolve their destination on
their own paths, where `ws://`/`wss://`/`tunnel://` are exactly what they are
for; this applies to plain HTTP requests.*

#### Which URL the routing rules are matched against

Once a bare-URL rule has moved the request, `host://`, the [proxy
family](#upstream-proxy) and `pac://` are matched against **the URL it moved to**,
not the one the client asked for. Nothing else is: the request-header operators,
the body operators, `cipher://`, the flags and the filters that guard them all
keep what the client's own URL matched.

```
a.example.com/    http://b.internal:9311/echo
b.internal        proxy://10.0.0.1:8888        # engages: it matches the destination
a.example.com     proxy://10.0.0.2:8888        # does not: nothing matches this now
```

That is upstream's second resolution pass — `getProxy` is handed the request's
rewritten URL and re-resolves those three against it
(`_original/lib/rules/index.js:125-152`, `lib/inspectors/res.js:196,:207-210`). The
second answer *replaces* the first, including when it is "nothing": a `host://`
that only the original URL matched is dropped rather than kept. Line filters and
`$1`-style captures are re-read against the destination too, since re-matching is
what produces them.

Two narrower things about that pass differ here, both measured in
`tests/differential/cases-proxy.js`:

* the URL is the one the **replacement rule** wrote, before `urlReplace://`,
  `params://` or `delete://` rewrote its path — upstream's is after;
* `enable://proxyHost`, `enable://proxyFirst` and `enable://proxyTunnel` are read
  from the first pass only. Upstream takes the union of both passes for exactly
  those three (`isProxyEnable`, `lib/rules/index.js:87,:154,:229`).

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
1080 (socks), and an IPv6 literal may be bracketed (`[::1]:8888`) or bare. The
address ends there: a path or a query written after it (`proxy://10.0.0.1:8888/x`)
is not part of it, and the query is where whistle's own flags live — see
`?proxyHost` and `?host=` below.

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
  (`res.js:229-234`, `lib/init.js:190-193`). whix sets that header when it
  is the sending side and honours (and strips) it when it is the receiving one,
  so two whix instances chain the way whistle does. Point one at a proxy
  you do not control and the request travels in the clear.

`lineProps://internalProxy` says the second of those about an ordinary
`proxy://` line, without changing its spelling — written on the proxy line, on
the `host://` line, or request-wide as `enable://internalProxy`
(`isInternalProxy`, `_original/lib/util/index.js:3801-3807`).

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
credential at the first colon and sends an empty password, and offers
username/password as the *only* authentication method when a credential is
written — never alongside "no authentication", so a proxy that also accepts
anonymous connections cannot quietly discard it. Hostnames are handed
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
direct connection. whistle refuses it too, though it says so less clearly: the
matcher is still truthy, so it becomes the address `http://` and the request dies
in the resolver with `DNS Lookup Failed`. (An earlier edition of this page said
whistle connects direct here. It does not — measured against 2.10.8 for
`proxy://`, `socks://`, `http-proxy://@` and `proxy://?proxyHost`, all four
answer 502.) A **PAC** file that cannot be fetched or throws is the case where
whistle really does fall back to a direct connection — its failure only reaches
`logger.error` (`_original/lib/rules/index.js:295`) — and this port refuses that
too, for the same reason: a rule that names a proxy has ruled a direct connection
out.

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
whix, which would match the same rule and do it again until the process
ran out of sockets. Such a hop is refused: the request is answered with a 302 to
whix's own port (whistle's answer on the HTTP path,
`_original/lib/inspectors/res.js:302-316`) and the log carries a
`self loop via <address>` warning. Reaching the origin directly on our own port
is left alone: it cannot recurse, because the request we send is not a proxy
request.

**Combining with `host://`.** By default a matching `host://` wins outright and
the proxy is dropped. `proxyHost` (as `lineProps://proxyHost`, as
`enable://proxyHost`, or written into the proxy's own URL as
`http-proxy://…?proxyHost`) keeps both: the request reaches the origin through
the proxy, and the proxy is asked to connect to the `host://` address.
`proxyFirst` prefers the proxy — and, unlike `proxyHost`, it settles which of the
two rules wins rather than combining them, so the `host://` address is **not used
at all**: the request goes to the proxy in absolute form, naming the origin it
originally asked for. `proxyHostOnly` behaves as `proxyHost` but additionally
drops the proxy when no `host://` matched.

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
overridden address is *itself* a proxy: whix `CONNECT`s to it through the
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
credential the client aimed at whix travelling one hop further than the
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
the proxy. The result is read left to right, as a PAC list is meant to be: the
first `PROXY`/`HTTP host:port`, `HTTPS host:port` or `SOCKS`/`SOCKS5 host:port`
entry wins. A `DIRECT` reached **before** any of them is the answer — connect
without a proxy. A `DIRECT` **after** the chosen proxy is that proxy's fallback,
so `PROXY 10.0.0.1:8080; DIRECT` goes through the proxy when it can be reached
and straight out when it cannot, exactly as `xproxy://` does.

Upstream reads the same result with one regexp,
`/(PROXY|SOCKS)\s+([^;\s]+)/i` (`node-pac/lib/Pac.js:7`), which has two
consequences whix does not reproduce: `SOCKS5 host:port` matches nothing
there and the request goes direct, and a `PROXY` entry wins even when `DIRECT`
came first in the list. Order is respected here, and `SOCKS5` is honoured.

The location may be a local file, a `http(s)://` URL, or (whix only) the
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

In a **multipart** body an object is a **file** part — upstream's `toMultipart`
(`lib/inspectors/req.js:61-95`):

```
upload.example.com  params://{"avatar":{"filename":"a.png","base64":"iVBORw0…"},"note":{"value":"hi"}}
```

`filename` (or `name`) names the file, else the field's own name does; the content
is `content` or `value` (an object there is sent as pretty JSON), or the bytes
`base64` decodes to; `Content-Type` is `type` (a bare extension such as `png` is
looked up) or follows from the filename, `application/octet-stream` when neither
says.

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
> for i**n**cludeFilter alone. whix read `filter://` as an include until this was
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
| Host | `host:<v>`, `host=<v>` | request host — a [deviation](#where-filter-conditions-differ-from-upstream) |
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

A URL condition may be written as a regexp, and the four operators spell it two ways.
`includeFilter://` and `excludeFilter://` take `/<expr>/[i]` with its delimiters, like
any other value. `filter://` and `ignore://` instead read a payload whose **last**
character is `/` (or that ends `/i`) as a regexp, with one leading `/` dropped if
present — so `filter:///echo$/`, `filter://echo$/` and `ignore:///echo$/` are the same
expression, and `filter://*/echo` without the trailing slash is a wildcard instead.
Upstream's `PATTERN_FILTER_RE` and `util.isRegExp` (`rules.js:54`, `util/index.js:606`).

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
response. whix does the same.

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
whix follows upstream's:

1. every line carrying a `b:` filter is collected at parse time into a list of its
   own (upstream's `_bodyFilters`, `_original/lib/rules/rules.js:1390-1392`);
2. before resolution, the proxy asks whether any of those lines' **patterns** accept
   this request. Only then is the body read (`resolveBodyFilter` → `req.getPayload`,
   `rules.js:2455-2465`, `lib/inspectors/rules.js:193-205`).

The line's other conditions get no say in stage 2, and deliberately so: upstream's
`resolveBodyFilter` passes `isFilter`, which short-circuits `checkFilter` before
`matchExcludeFilters` runs (`rules.js:983`). Narrowing it by them looked free and was
not — an `excludeFilter://b:` concluded from its own assumed-true condition that the
line was already excluded, and never read the body it needed to decide that.

So a rules file with no `b:` in it never touches a body, and one whose `b:` is scoped
to a host or a path pays almost nothing on the requests that pattern turns away.
Measured on a 500-rule file: **under 1 ns** per request with no `b:` line — one
`is_empty()` per group — **4 ns** with one whose pattern turns the request away, and
**11 ns** with one whose pattern accepts it, against ~2.8 µs for the resolution that
follows.

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

Buffering for a `b:` stops at 2 MB, and the condition is matched against the
prefix read — as upstream's does at `MAX_REQ_SIZE`. Unlike the body operators,
`b:` cannot use `reqMergeBigData` to raise it: the flag is a rule, and `b:` is
deciding which rules apply. See [Request bodies have a ceiling](#request-bodies-have-a-ceiling).

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

#### Where filter conditions differ from upstream

| Upstream | Here | Why |
|---|---|---|
| `i:` matches the client IP, then falls back to the server IP | client IP only | Upstream's server-IP arm is unreachable: `filterProp` reports an ip filter as handled the moment `req.clientIp` is null, so the `req.hostIp` line below it never runs for one (`rules.js:1824-1830,:1875-1880`). Write `serverIp:` for the server's address. |
| the response pass wins when both passes resolve one protocol | source order wins | See [the response phase](#the-response-phase): upstream's two passes read disjoint protocols and never face the case. |
| `remoteAddress:`/`remotePort:` are the raw socket, distinct from `clientIp:`/`clientPort:` | the same socket | The two differ upstream only for a request forwarded by another whistle, whose client-IP override headers this port does not honour. |
| a `host` condition never decides whether a rule applies | matches the request host | Measured against whistle 2.10.8: `host=`/`host.` are filed under `hostFilter`, which only `util.checkProxyHost` reads — it decides which hosts a `proxy://` engages for. `host:` (with a colon) upstream does not recognise at all, and reads as a URL pattern that cannot match. Both spellings match the request's own host here. |
| header values are also compared against `encodeURIComponent(value)` | not compared | That arm is unreachable upstream: the haystack is lowercased while `encodeURIComponent` emits upper-case hex. |

Some filters are **dropped**, and the rule then applies without them: an empty payload
or a bare `!` (`includeFilter://`, `includeFilter://!`); a header key left empty by its
own `!` (`reqH.!!=v` — the first `!` is the value's); and an `i:`/`ip:`/`clientIp:`/
`serverIp:` whose value is neither an address nor a regexp (`i:localhost`).

A dropped condition **fails open**: it is as if it were never written, so the line
widens whichever spelling carried it. That is worth knowing precisely, because it is
the reverse of what a malformed [pattern](#patterns) does — a pattern that fails its
own checks matches nothing and silences its one rule, while a condition that fails
these unleashes the rule it was gating. The blast radius is opposite for the same
kind of typo.

The sharp case is an exemption. `excludeFilter://i:127.0.0.1` keeps a rule off local
traffic; write `excludeFilter://i:localhost` and the condition is dropped, so the rule
applies to *everything*, local traffic included. Nothing reports it.

A condition that merely **never holds** is a different thing, and only on the include
side: it stops an include dead, while leaving an exclude as inert as a dropped one.
Two spellings a character apart land on either side of that line — a header key empty
to begin with is kept (`reqH.=v` asks for a header named `""`, and no message has
one), and a name with nothing after its separator is not a condition at all
(`includeFilter://reqH.` is a URL pattern no URL matches). Each is upstream's answer,
measured.

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
>
> **And `skip://` silences earlier.** It does everything `ignore://` does, and
> also drops the operator as the rules are *walked* rather than after
> (`checkSkip`, `_original/lib/util/index.js:2004-2013`). On every operator with
> a protocol key of its own the two come to the same nothing. On the
> [shared slot](#short-circuit-no-upstream-request-is-made) they are opposite
> answers: `skip://` hands the slot to whatever was written next, `ignore://`
> leaves it empty. One more consequence: only `|` separates a `skip://` name
> list, where `ignore://` also reads `&`.

### Short-circuit (no upstream request is made)

| Operator | Value | Effect |
|----------|-------|--------|
| `redirect` | a URL | Respond `302 Found` with `Location: <url>` |
| `statusCode` | a status number | Respond with that status and an empty body (mock) |
| `file` / `rawfile` | a local path **or a URL** | Serve the file's bytes with a guessed `Content-Type` |

```
old.example.com/legacy   redirect://https://new.example.com/
/\/track\b/              statusCode://204
example.com/app.js       file:///Users/me/dev/app.js
```

**The source may be a URL**, and then it is fetched and its bytes are served as
the mock — `pluginMgr.resolveKey` turns any entry `util.isUrl` accepts into an
HTTP request rather than a path (`_original/lib/plugins/index.js:1521-1529`).

```
example.com/api/flags   file://http://mocks.internal/flags.json
example.com/api         file:///srv/cache|http://mocks.internal/api    # local first
```

It is a **fetch, not a forward**: the request's own headers do not travel, the
answer carries this family's `Server` header, and the request's leftover path is
*not* appended to the URL — `file:///srv/static` extends into a directory,
`file://http://host/x` does not. The entries of a `|` list are decided one at a
time, so the second line above serves the local copy when it is there and fetches
only when it is not. A source is capped at 256 KB (`MAX_URL_VAL_LEN`); one that
answers `404` gives the family's own 404, and one that answers anything else
non-`200` gives a `502` naming the status, because that is a broken mock server
rather than a missing file. `<…>` names a path, never a URL.

Note the first line has no `*`. A path prefix already matches everything below
it at a segment boundary, and a `*` in the path of an ordinary pattern is a
**literal** — `old.example.com/legacy/*` matches a URL containing the character
`*` and nothing else. Write `^http://old.example.com/legacy/**` when you need a
path wildcard with a capture.

**A file never answers a WebSocket or a tunnel.** When the URL being resolved is
not an `http(s)://` one — `ws://`, `wss://`, `tunnel://` — every candidate in the
file family, and `locationHref://` with it, is passed over and the slot falls
through to the next rule (`notHttp && protoMgr.isFileProxy(rule.matcher)`,
`_original/lib/rules/rules.js:920,:977`). A file is a complete HTTP response and
an upgrade wants a `101`, so answering one with a directory listing is a
handshake failure wearing a mock's status line. `statusCode://` and `redirect://`
share the slot and are *not* passed over: both are answers a client can be given
before it upgrades.

`statusCode://101` on a WebSocket is a WebSocket endpoint with nobody behind it:
the proxy completes the handshake itself — the `Sec-WebSocket-Accept` the key
calls for, the first subprotocol asked for, `Upgrade`, `Connection` — and then
keeps the connection, reading and dropping what the client sends, as upstream
does. A client can open it and send into it; nothing answers.

```
chat.example.com   file:///srv/mock.json       # ignored by the WebSocket…
chat.example.com   127.0.0.1:9000              # …which this line still moves
```

**These share one slot with each other and with a bare destination URL.** None
of `file`, `rawfile`, `tpl`, `jsonp`, `dust`, `redirect`,
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

Within a *single* line there is no protocol precedence either: the one written
first wins, because upstream pushes a line's operators onto the shared list in
the order they are typed (`matchers.forEach(parseRule)`, `rules.js:1785-1789`).
So `file://({"id":7}) statusCode://201` serves the file and
`statusCode://201 file://({"id":7})` answers `201` with an **empty body**. Use
[`replaceStatus://`](#response-rewriting) when you want the mock's body under a
different status; it changes a response rather than manufacturing one.

**Silencing one of them is not the same as choosing another.** `ignore://` runs
after the slot has already been reduced to a single winner, so it can only take
that winner out — it never promotes the next line:

```
example.com  statusCode://204  redirect://http://elsewhere/  ignore://statusCode
```

answers from the origin, not with the redirect. Naming a member that *lost*
does nothing at all, because it is not in the resolved set to be named, and the
name has to be the one the winner was **written** with: `ignore://rule` reaches
whichever member holds the slot, `ignore://http` reaches a bare `http://…`
destination, and an alias reaches nothing — a rule written `status://204` is
silenced by neither `ignore://status` nor `ignore://statusCode`, only by
`ignore://rule`. All of that is upstream's `ignoreForwardRule`
(`_original/lib/util/index.js:2047-2059`), which reads the protocol name back
out of the winner's URL.

[`skip://`](#silencing-a-rule-by-its-text) is the spelling that **does** fall through: it silences
the operator as the rules are walked rather than after, so the same line written
`skip://statusCode` redirects. On every other operator the two are
indistinguishable — the slot is the only place a fall-through has anywhere to
go.

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

#### `auth://` in four spellings

| Value | Sends |
|-------|-------|
| `admin:secret` | `Authorization: Basic …` for `admin`/`secret` |
| `username=admin&password=secret` | the same |
| `{"username":"admin","password":"secret"}` | the same |
| `{"username":"admin","password":"secret","proxy":true}` | **`Proxy-Authorization`** instead |
| a **location** — `/etc/whistle/auth.json`, a URL | what it holds, read as `username` / `password` / `proxy` |

Only the first colon splits, so a password may contain one. Naming one half is
allowed and the two halves are not symmetric (`getAuthBasic`,
`_original/lib/util/index.js:3668-3685`): a password with no username still
carries its colon (`:secret`), a username with no password carries none
(`admin`). A value naming neither sends no header at all.

Two edges are upstream's and easy to trip over: the query spelling's `proxy` is
read as `!!value`, so `proxy=false` is **true** — write the JSON form when the
answer is no; and query values are taken raw, so a `%2F` in a password reaches
the server as `%2F`.

**A value with a slash in it is a location, never credentials.** `SLASH_RE`
(`util/index.js:102,:3653`) tests the whole value, so `auth://admin:se/cret`
sends **no** header — a password may not contain a slash, in either program,
however much it looks as though it should. The two spellings that *do* survive a
slash are the ones tested before it: `{"password":"p/q"}` and
`username=u&password=p/q`.

The last row is the road a slash sends the value down, and it is the one the
[official page](https://wproxy.org/docs/rules/auth.html) leads with for anything
shared. What comes back is read as a data object — the line format included, so
the documented file

```
username: admin
password: my secret password
```

is two fields and not one long username. A location that cannot be read sends
nothing.

> **This port used to send the path.** `auth:///Users/john/config/auth.json`
> reached the origin as `Authorization: Basic base64("/Users/john/config/auth.json")`
> whenever the file was missing, because the slash test was skipped on the
> reasoning that a password might contain one, and the line-format file was sent
> whole as a username. Both were found by putting the documentation's own
> examples in front of whistle — `tests/differential/cases-docs.js`.
>
> One spelling on that page does not work in **either** program, and the row
> below records it: an inline ```` ``` ```` block in the line format,
> `auth://{custom-key}`, is read as `user:pass` because the block's content
> reaches `getAuthByRules` as the value itself. Both proxies send `username` as
> the username. Use a file, or the `{"username":…}` JSON form, inside a block.

### Plugins

| Operator | Value | Effect |
|----------|-------|--------|
| `plugin` | `name[/extra]` | Run a registered plugin's hooks for the request |

Three spellings, one rule — the second and third are upstream's:

```
api.example.com   plugin://mock/extra
api.example.com   whistle.mock://extra
api.example.com   mock://extra
```

The plugin sees `extra` as its `param`. The short one, `mock://`, works only for a
name that is **registered when the request arrives**: a protocol this port does not
know is otherwise a destination URL (`example.com http://localhost:5173`), and so is
`mock://` with no plugin called `mock` — which then fails the request with
`unsupported protocol mock:`. Upstream decides it the same way, at request time
(`getPluginByPluginRule`, `_original/lib/plugins/index.js:1406-1421`). The
console's Test Rules knows the registered names; `whix explain` runs without a
proxy and knows only the built-in ones.

Register plugins on the command line (repeatable), or start one from a script:

```bash
whix --plugin echo=127.0.0.1:9300 --plugin mock=127.0.0.1:9400
whix --node-plugin mock=./mock-plugin.js
```

What a plugin is asked, and how it answers, is [`PLUGINS.md`](PLUGINS.md). A
plugin switched off in the console is, to every rule that names it, not there —
see [the switches](API.md#开关https全部规则插件).

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

The plugin can answer four ways: present whix's own generated certificate,
present one of its own, reuse the one it supplied last time, or **decline the
interception entirely** — in which case the connection is relayed to the origin
still encrypted and nothing about it is captured. Writing the plugin is covered
in [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback); the built-in
`sniCallback://no-mitm` needs no plugin at all and always declines.

Three consequences worth knowing:

- **The port is part of the pattern**, because the URL the rule matches carries
  it: `localhost:9443 sniCallback://certs` and `localhost:9444 …` are different
  rules, even though the ClientHello is identical.
- **A declined connection still follows tunnel routing rules.** The SNI path
  retains the resolved target and applies `host://` and the upstream proxy
  family; an unusable required route is not silently replaced with a direct
  connection. Its opaque payload is not captured or processed by HTTP body
  operators, because TLS remains between the client and origin.
- **A failing plugin does not decline.** Unreachable, slow or incomprehensible
  all mean "the certificate whix would have generated anyway", with a
  `WARN` naming the plugin. See
  [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback) for why this one hook does not
  fail closed the way `onAuth` does.

### Scripting

| Operator | Value | Effect |
|----------|-------|--------|
| `resScript` | path to a `.js` file (or inline JS) | Run JavaScript against the response |
| `frameScript` | path to a `.js` file, a `{value}`, or inline JS | Run JavaScript over each WebSocket frame — and, with `enable://inspect`, each chunk of a plain tunnel |

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

This hook is this port's own, and it is recognised by the word `ctx`. Upstream
has no hook: to it a `resScript://` text is **response rules** — and so it is
here, whenever the text does not mention `ctx`:

````
```tps.rules
# rules
example.com jsAppend://(console.log('appended'))
```
example.com   resScript://{tps.rules}
````

A value or path that names nothing runs nothing. Before 2026-09 every
`resScript` text without `rules`/`values` in it was run as JavaScript, so a
rules text failed to parse and silently did nothing.

**A script may instead *produce rules*.** This is upstream's original meaning
for the family and it is now implemented: when the script's text is bracketed,
carries no `#` comment or ``` `` ``` fence, and names `rules` or `values`
(`isRulesContent`, `_original/lib/rules/index.js:41-43`), it runs with those two
as globals and whatever it pushes into `rules` is parsed as more rules. A
request-phase script sees `url`, `method`, `headers`, `body`, `ip` and
`clientPort`; a `resScript` also sees `statusCode`, `serverIp` and `resHeaders`.
A script that throws contributes nothing, not even lines pushed before it threw.

A script of any size goes in a ``` fenced block and the line names it — a rule
line is split on whitespace by both proxies, so an inline `(…)` script ends at
its first space and is never a whole program. (This document used to print
`reqScript://(rules.push(url + ' reqHeaders://x-seen=1'))` as an example. It
resolves to `rulesFile://(rules.push(url` and two more operators, in whistle
2.10.8 as much as here.)

````
```probe.js
rules.push(url + ' reqHeaders://x-seen=1');
```
example.com   reqScript://{probe.js}
````

The context is upstream's `getScriptContext`
(`_original/lib/rules/index.js:349-416`), name for name:

| Name | What it is |
|------|------------|
| `url` / `fullUrl`, `method`, `headers` / `reqHeaders`, `body` | the request. `method` is upper-cased; `body` is at most the preview |
| `ip` / `clientIp`, `clientPort` | who sent it |
| `httpVersion` | what the **client** spoke: `1.0`, `1.1`, `2.0` |
| `pattern` | the pattern of the rule line the script sits on (`example.com/api` for `example.com/api reqScript://{x.js}`) |
| `port`, `uiPort`, `uiHost`, `version` | the proxy: its port, the console's (`-P`, else the same), `local.wproxy.org`, this build's version |
| `rules`, `values` | what the script produces — see above and below |
| `value` | `undefined` (upstream: the request's `G://` value, which this port does not have) |
| `reqScriptData` | one object for the whole request: what a `reqScript` puts there, the same request's `resScript` reads |
| `statusCode`, `serverIp`, `resHeaders` | the response head in a `resScript`; empty strings in the request pass |
| `getValue(name[, onlyValues])` | a ``` block of that name, else the Values store; with `true`, the store alone |
| `render(tpl, data)` / `tpl` | whistle's `<% … %>` / `<%= … %>` micro-template (`rules/index.js:304-347`), the same source transformation |
| `isLocalAddress(ip)` | loopback, the unspecified addresses, this machine's primary address |
| `parseUrl(url)` | Node's legacy `url.parse(url)` |
| `parseQuery(str)` | Node's `querystring.parse(str)` |
| `Buffer` | Node's `Buffer` |
| `decodeBuffer(buf, enc)`, `encodeString(str, enc)`, `encodingExists(enc)` | `iconv-lite`'s `decode`, `encode` and `encodingExists` |

The last four rows are **Node's behaviour, not a summary of it**, because
[`reqScript.md`](https://wproxy.org/docs/rules/reqScript.html) says "同 Node.js
的 `url.parse`" and a script copied from a whistle setup leans on the details:

```js
parseQuery('a=1&a=2&q=a+b')          // { a: ['1', '2'], q: 'a b' }   — not { a: '2', q: 'a+b' }
parseUrl('http://u:p@[::1]:81/a b#h') // auth 'u:p', host '[::1]:81', hostname '::1',
                                      // pathname '/a%20b', hash '#h', search null
Buffer.from('中').toString('hex')      // 'e4b8ad'
encodeString('中', 'gbk')              // <Buffer d6 d0>
```

They are written in JavaScript on top of the engine (`src/proxy/script_prelude.js`)
and compared with whistle 2.10.10 case by case in
`tests/differential/core-bench.js` — 55 script comparisons, 24 of them URLs,
all equal. `Buffer` has the methods a rule script uses (`from`, `alloc`,
`concat`, `isBuffer`, `byteLength`, `toString` in `utf8`/`hex`/`base64`/
`base64url`/`latin1`/`ascii`/`utf16le`, `slice`, `indexOf`, `write`, `copy`,
`equals`, the fixed-width `read…`/`write…` integers); it is not the whole of
Node's. The `iconv` three know the Encoding Standard's set — `gbk`, `gb18030`,
`big5`, `shift_jis`, `euc-kr`, the `windows-125x` and `iso-8859-x` families —
under the names iconv-lite accepts (`GB2312`, `win1252`, `cp936`); an encoding
outside that set (`cp437`, `utf7`) is not there.

Until 2026-09-30 `Buffer` and the `iconv` three did not exist (a script naming
one threw and produced nothing), `parseQuery` and `parseUrl` were ten-line
approximations, and `pattern` and `port` were `''` and `0`.

Also there, because whistle scripts assume them: `substr`, `escape` /
`unescape`, and the `RegExp.$1`…`$9` / `lastMatch` statics.

**What a script may cost.** whistle stops a script after 60 ms; this port
after **1 second**, because its engine is an order of magnitude slower than V8
and a script that finishes there must finish here. A stopped script produces
nothing, as one that throws does — no rules it pushed, no change it made to a
response — and the request goes on. Its session says so: an `unapplied` entry
of kind `script-failed` naming the operator and saying whether it threw (with
the error) or ran out of time. The same second applies to a `frameScript`'s
top level and to each call of its handlers (a handler out of time ends the
script for that connection, and every frame after it passes unscripted), and to
a PAC file and each `FindProxyForURL`.

Two more bounds stop the common runaways sooner and with a clearer error: the
loops of one function call are stopped after 3,000,000 iterations in all
(about 20 ms for an empty loop), and recursion after a few hundred frames.

What the second cannot reach: code a *built-in* calls back into — the callback
of `forEach`, `map`, `sort`, `replace` — and the text the one-line `ctx.frame`
shape of a `frameScript` runs through `eval` each frame. Those run to the end,
bounded only by the loop limit per call. Scripts run off the proxy's worker
threads, so one that cannot be stopped holds its own request (and a thread)
and nothing else; before 2026-10-02 they ran on them, and a loop calling a
looping function — which the per-call loop limit does not see — held its
request for ever, ten of them stopping the whole proxy.

Starting a script costs about 0.5 ms; the first use of `Buffer`, `parseUrl`,
`parseQuery` or an `iconv` helper adds about 3 ms, once per script run.

What the script writes to `values` answers the `{name}` references in the rules
it pushed — see [Values declared in the rules text](#values-declared-in-the-rules-text).

Divergences that remain: `isLocalAddress` does not consult a cache of every name
the proxy has resolved, which whistle's does; and there is no `require`,
`process` or `setTimeout` — there is none upstream either, a `vm` context being
JavaScript and nothing else.

`frameScript` runs JavaScript over the frames of a **WebSocket** and the chunks
of a **plain TCP tunnel** — [`frameScript.md`](https://wproxy.org/docs/rules/frameScript.html):
"操作 WebSocket 和普通 TCP 请求数据帧".

```js
var seen = 0;                                     // kept for the life of the connection
ctx.sendToServer('hello');                        // sent when the connection opens
ctx.handleSendToServerFrame = function (buf, opts) {
  seen++;
  if (seen > 100) return null;                    // nothing delivered
  return String(buf).replace(/1/g, '***');
};
ctx.handleSendToClientFrame = function (buf, opts) {
  ctx.sendToServer('got ' + buf.length + ' bytes'); // a frame of the script's own
  return buf;                                     // unchanged
};
```

```
chat.example.com        frameScript://{frame.js}
db.internal:5432        frameScript://{frame.js} enable://inspect
```

**One script per connection.** It is evaluated once, when the connection opens,
and its two handlers are then called for each frame — so `seen` above counts.
Until 2026-09-30 the script was evaluated afresh for every frame and the counter
answered 1 for ever.

**What a handler is handed**: the frame as a `Buffer` (text frames too — say
`String(buf)`), and `opts`: `{ opcode, mask, compressed, length }`, where
`opcode` is 1 for text and 2 for binary. While it runs the script sees what a
`reqScript` sees — `url`, `method`, `headers`, `getValue`, `parseUrl`, `Buffer`,
and so on — except `rules` and `values`.

**What it returns** is what is delivered, read as upstream's `util.toBuffer`
reads it (`_original/lib/socket-mgr.js:303-323`):

| Returned | Delivered |
|----------|-----------|
| a string, a number | that text |
| an object or array | its JSON |
| a `Buffer` | those bytes |
| `undefined`, `null`, `0`, `''` | **nothing** — the frame is dropped |
| *(it threw)* | the error's message, as `boom (handleSendToServerFrame)` — which is how you find out, in the Frames panel and at the peer |

**Frames the script sends** — `ctx.sendToServer(data, opts)`,
`ctx.sendToClient(data, opts)`, at the top of the script or from inside a
handler — go out before the frame being handled, and each passes through the
handler for the direction it travels with `opts.frameScript === true`, so a
handler can let its own frames by. `{ binary: true }` sends a binary frame.

**A plain tunnel needs `enable://inspect`.** A `CONNECT` tunnel this proxy does
not read — anything that is neither HTTP nor a TLS handshake it intercepts, or
one a rule said to leave alone — and an `Upgrade:` to something other than
WebSocket are relayed as bytes. With `enable://inspect` each chunk read from
either side is shown as a frame under the tunnel's row and handed to the script.
A chunk is whatever one read returned: TCP has no message boundaries, and a
handler that needs a whole message reassembles it, as it must upstream.
`enable://pauseSend` and its three relatives imply `inspect` and do nothing more
on a tunnel.

Where this differs from whistle 2.10.10, each measured by
`tests/differential/core-bench.js` (28 frame and tunnel cases, 22 equal):

| | whistle | here | why |
|---|---|---|---|
| `ctx` and `Buffer` inside a handler | a `ReferenceError`, delivered as the frame — upstream empties the script's globals once it has run, so only a saved reference (`var c = ctx`) works | both work | the documented example reads `ctx.` inside nothing, but every script one would actually write does |
| a binary frame through a handler that returns the `Buffer` | re-sent as a **text** frame (the frame's options say `opcode: 2` and the sender reads `opts.binary`) — bytes that are not UTF-8 then arrive mangled | stays binary | `opts.binary` is honoured when the handler sets it either way; otherwise a string is text and a `Buffer` keeps the frame's type |
| `sendToServer` at the top of a script that also installs that direction's handler | the frame never arrives | it arrives, through the handler | — |
| `sendToClient` at the top of a **tunnel** script | written before the `200` that answers the CONNECT; the client's CONNECT fails | written after it | — |
| `typeof ctx.frame`, `typeof ctx.direction` | `undefined` | an object and a string | this port's one-line shape, below |
| a fragmented WebSocket message | reassembled, then handed over | each fragment is relayed untouched | this port relays frame by frame; a handler is only handed whole messages |
| `enable://pauseSend` … on a tunnel | holds or drops the chunks | shows them, nothing more | not built |

The client's frames go to `handleSendToServerFrame`, as the name says. On a
plain WebSocket, whistle up to 2.10.9 gave them to `handleSendToClientFrame`
instead; 2.10.10 fixed it (avwo/whistle#1358), and `tests/differential/ws-bench.js`
measures it through both proxies.

**This port's one-line shape** still works: a script that installs no handler
and names `ctx.frame` is evaluated for each *text* frame, with the frame in
`ctx.frame.data` and the direction in `ctx.direction`.

```js
if (ctx.direction === 'send') ctx.frame.data = ctx.frame.data.toUpperCase();
```

It runs in the same engine each time, so a global it sets is still there for the
next frame.

**Cost.** A scripted connection has a thread of its own for the script — the
engine cannot move between threads, and a connection's two directions are two
tasks. A connection with no `frameScript` has none. A loop in a handler is cut
at three million iterations, like any script's.

### `log://` — a page's console, in this one

| Operator | Value | Effect |
|----------|-------|--------|
| `log` | an id, or `{name}` | Inject a script into matching pages that sends what they write to `console` — and their uncaught errors — to this proxy's **Console** pane |

It is for a page you cannot open developer tools on: a WebView inside an app, a
browser on a phone.

```
m.example.com   log://shop
```

1. Open the page on the device, through the proxy.
2. Open this proxy's console and click **Console** in the toolbar.
3. Everything the page passes to `console.log` / `info` / `warn` / `error` /
   `debug` is there, newest at the bottom, with the page's address. So is an
   uncaught exception (with its stack), an unhandled promise rejection, and a
   `<script>` or `<img>` that failed to load — each as an `error`.

The id (`shop`) is a group. Several rules with different ids give several
groups, listed at the left of the pane; clicking one shows only its entries.
`log://` with no id files under `(no id)`.

**If nothing shows up**, in the order worth checking:

| What you see | What it is |
|---|---|
| The page's session is in Network, but with a lock and no body | HTTPS to that host is not being intercepted, so there is no page to inject into. The root certificate is not trusted on the device, or interception is off |
| The session's Rules tab shows `log://…` as "not applied" | The body was over `--body-rewrite-limit`, or under a `content-encoding` that could not be undone — the reason is written there |
| The response is `304` | The browser used its cached copy, which has no script in it. Reload once: a `log://` rule removes the request's cache validators, so the next one is a full `200` |
| Entries from `console` are missing but errors arrive | `disable://interceptConsole` matched the request — see below |
| The page has a `<meta http-equiv="Content-Security-Policy">` tag | A CSP in a *header* is removed for you; one written into the HTML is not, and it stops an inline script. Remove it with `resReplace://` |

**What is injected, and where.** Into an HTML response, a `<script>` element as
the first thing in `<head>`, so it runs before any script of the page's own.
Into a JavaScript response, the same source at the front of the file — a page
whose HTML the rule does not match, but whose scripts it does, still reports.
Nothing else is touched: a rule over a whole host also matches its images and
downloads, and those are neither collected nor changed. The script is about
4 KB, is written in ES5 for old WebViews, and does nothing on a second copy.

It is **one line, with no line break after it**, so the line numbers in a stack
are still your source's: `cart.js:41` is line 41 of `cart.js`. Only columns on
the first line move. (A `log://{name}` script of your own — below — is as many
lines as you wrote, and moves everything after it down by that many.)

The script reports by `POST`ing to `/.whix/log` **on the page's own
origin**. The page's requests come through this proxy, so the proxy answers that
path itself (`204`) and the origin never sees it. That is why it works on an
`https://` page without mixed-content errors and needs no CORS. It also means
the path is taken: a site that really serves `/.whix/log` cannot be
reached through this proxy at that path.

Like the `html*`/`js*` operators, injecting removes the response's
`Content-Security-Policy` header and makes it uncacheable
(`_original/lib/inspectors/log.js:47-48`); `enable://keepCSP` and
`enable://keepCache` opt out of each.

**Only errors, not `console`.** `disable://interceptConsole` on the same request
leaves `console` alone and still reports uncaught errors:

```
m.example.com   log://shop disable://interceptConsole
```

**Editing or dropping entries before they are sent.** Define
`window.onBeforeWhistleLogSend(args, level)` in the page. `args` is the array of
arguments as the page passed them; change it in place. Empty it, or return
`false`, and that entry is not sent. `log://{name}` injects the value `name` as
a second script right after the collector, which is where to define it without
touching the site:

````
``` strip-tokens
window.onBeforeWhistleLogSend = function (args, level) {
  if (level === 'debug') { return false; }
  for (var i = 0; i < args.length; i++) {
    if (typeof args[i] === 'string') { args[i] = args[i].replace(/token=\w+/g, 'token=***'); }
  }
};
```
m.example.com   log://{strip-tokens}
````

The group is then called `strip-tokens`.

**Limits, all of them on purpose.** An argument is sent as text: a string as it
is, an `Error` as its stack, a DOM node as `<div#id.class>`, anything else as
JSON with repeated objects written `[Circular]`. One argument is cut at 64 KiB
and one string inside an object at 8 KiB. The proxy keeps the newest 2000
entries, 8 MiB at most, **in memory** — a restart empties the pane. Entries
written while the page is being closed are sent with `navigator.sendBeacon`
where the browser has it, and lost where it does not.

**How this differs from whistle.** The rule, the id, `{name}`,
`interceptConsole` and `onBeforeWhistleLogSend` are whistle's
([log](https://wproxy.org/docs/rules/log.html)). The script is this port's own
rather than whistle's `assets/js/log.js`: whistle posts to a `cgi-bin` route
under its internal path and shows objects as an expandable tree; this port
shows each argument as text. whistle writes the script at the very top of the
document, before the doctype; this port puts it inside `<head>`.
`tests/differential/core-bench.js` (`CASES=log`) checks the part a client can
see against whistle — a page under the rule comes back with a collector in it,
the same page without the rule does not, a plain-text body is left alone — and
`tests/page_log_e2e.rs` checks the round trip to the Console pane's API.

The same entries are readable over HTTP: [`GET /api/logs`](API.md#页面日志).

### weinre (HTML debug injection)

| Operator | Value | Effect |
|----------|-------|--------|
| `weinre` | id, or a script URL/path | Inject a weinre `<script>` into HTML responses |

[weinre](https://www.npmjs.com/package/weinre) is a remote
DOM inspector: a server you run, a script the page loads from it, and an
inspector page you open on that server. **whix does not contain weinre**
— whistle bundles the whole of it and serves it from its own port. So here you
start the server yourself and say where it is:

```sh
npx weinre --boundHost -all- --httpPort 8080     # the weinre server
whix --weinre http://192.168.1.5:8080      # …and where the proxy finds it
```

```
.example.com   weinre://mysession
```

The page then loads `http://192.168.1.5:8080/target/target-script-min.js#mysession`,
and the inspector is at `http://192.168.1.5:8080/client/#mysession`. Use an
address the **device** can reach, not `127.0.0.1`.

Without `--weinre`, a bare id has nowhere to load the script from. Nothing is
injected, the response's headers are left as they came (see the CSP note
below), and the session says so: its Rules tab shows the `weinre://` rule as
"not applied", with the kind `no-weinre-server` in `unapplied`. (It used to
inject a `<script>` pointing at this proxy's own port, which answered `404`:
the page loaded, no inspector ever connected, and nothing said why. After that
it injected nothing but still stripped the page's CSP and cache headers.)

A rule can also name the script itself, which needs no `--weinre`:

```
example.com    weinre://https://debug.example.com/target/target-script-min.js
```

> A `#` in a rules line starts a comment, so `weinre://https://…/script.js#id`
> loses its `#id` before the rule is read. To pass an id with a full URL, put
> the URL in a value and reference it: `weinre://{agent}`.

The tag is injected before `</head>` (or after `<body>`). An `https://` page
will refuse a script from an `http://` weinre server as mixed content; weinre
itself has no TLS, so put it behind something that does, or debug the page over
`http://`.

Injecting costs the response its `Content-Security-Policy` and its cacheability,
exactly as the `html*`/`js*`/`css*` operators do: an agent a page's own CSP
forbids never runs, and one the browser caches outlives the rule that asked for
it (`_original/lib/inspectors/weinre.js:37-38`). Only injecting does this — a
`weinre://` that injects nothing leaves both. `enable://keepCSP` and
`enable://keepCache` opt out of each.

**How this differs from whistle**, measured against 2.10.8 by
`tests/differential/cases-compose.js`: whistle appends its **own bundled agent**
— the whole of `assets/js/weinre.js`, inline, at the *end* of the body — pointed
at a weinre server whistle runs itself. whix bundles neither, so it emits a
`<script src>` naming the server `--weinre` gave and puts it in the `<head>`. Two
further consequences: whistle also reaches **JavaScript** responses, appending
the agent bare (`weinre.js:33-35`), where a `<script src>` tag would mean
nothing; and whistle rewrites a **gzipped** body, where this port leaves a
compressed response alone.

### `locationHref://` — a page that redirects itself

| Operator | Value | Effect |
|----------|-------|--------|
| `locationHref` | `[js:\|html:\|replace:]<url>` | **Answer** the request with a document that navigates the client to `<url>` |

It is a mock, not an injection: whistle files it with `file://` and friends
(`isFileProxy`, `_original/lib/rules/protocols.js:282`), so it shares the one
destination slot with them — whichever line was written first wins — and the
origin is never contacted at all.

| Value | Answer |
|-------|--------|
| `<url>` | `text/html`, `<script>window.location.href = "<url>";</script>` |
| `js:<url>` | `application/javascript`, the assignment with no tag around it |
| `html:<url>` | forced to the HTML form |
| `replace:<url>` | `window.location.replace(…)`, which leaves no history entry |
| empty | `200`, `text/html`, and an empty body |

With no prefix, a request the browser made *for a script*
(`Sec-Fetch-Dest: script`) gets the JavaScript form, so a redirect written for a
page does not arrive nested inside another `<script>`. A value that resolves to
the request's **own** URL answers nothing — the request goes out normally, rather
than redirecting to itself forever.

```
old.example.com    locationHref://https://new.example.com/
cdn.example.com    locationHref://js:https://cdn2.example.com/app.js
example.com/old    locationHref://replace:/new
```

### Flags, includes & values

| Operator | Value | Effect |
|----------|-------|--------|
| `enable` | flag(s) | `abort`/`abortReq`/`abortRes` (destroy the connection — see below), `cors` (as `resCors://enable`), `captureStream` (ask the origin not to compress), `gzip`/`br`/`deflate` (force the response's outgoing encoding), `showHost` (report the address reached as `x-host-ip`), `ignoreSend`/`ignoreReceive` (drop one direction of a WebSocket), `pauseSend`/`pauseReceive` (hold one direction until the console releases it), `safeHtml`/`strictHtml` (gate every injection), `keepCSP`/`keepCache`/`keepAllCache` (survive an injection), `hide`/`show` (keep a request out of the capture, or put it back — see below), `websocket` (read an upgrade as WebSocket whatever it calls itself), `h2`/`http2`/`httpsH2` (offer HTTP/2 to an HTTPS origin — see below) |
| `disable` | flag(s) | see the two tables below |
| `trailers` | `name=value` / `{json}` | Add HTTP response trailer headers (forces chunked) — see below |
| `headerReplace` | `{"<scope>.<name>:<pattern>":"<repl>"}` | Rewrite a header value; scope is `req.`/`reqH.`/`res.`/`resH.` |
| `responseFor` | a name, or `name=<headers>` | Annotate the **response** with `x-whistle-response-for` — see below |
| `rule` | value name | Include the named value's rules and apply them too |
| `rulesFile` | file path, `{value}`, or `(inline)` | Include rules and apply them too. Also spelled `reqRules://`, `ruleFile://`, `ruleScript://`, `rulesScript://`, `reqScript://` — see below |
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
| `userLogin` | withholds the `WWW-Authenticate` / `Proxy-Authenticate` challenge a `statusCode://401\|407` or a changed `replaceStatus://401\|407` would send (`enable://userLogin` wins over it, and `lineProps://disableUserLogin` says it for one line — see [`LINE_PROPS.md`](LINE_PROPS.md)) |
| `trailers` / `trailer` | sends no trailer section at all — the origin's included |
| `trailerHeader` | sends the trailers without the `Trailer:` header announcing them |
| `doctype` | no `<!DOCTYPE html>` before an HTML prepend |

`disable://tunnel` belongs to neither table: it strips nothing, it refuses the
connection — see
[Aborting a connection rather than a request](#aborting-a-connection-rather-than-a-request).
Nor do `disable://h2`, `http2` and `httpsH2`, which keep the hop to an HTTPS
origin on HTTP/1.1 — see [`h2`](#h2--which-http-version-reaches-an-https-origin).

A flag this port does not recognise is **inert** — it parses and does nothing,
rather than failing the rule.

#### Rules in a request header

A request can carry its own rules, in five headers
(`initHeaderRules`, `_original/lib/rules/index.js:576-638`):

| Header | What it carries |
|---|---|
| `x-whistle-rule-value` | the rules text |
| `x-whistle-rule-host` | one more line, appended to it |
| `x-whistle-rule-key` | the name of a **values** entry, whose content is prepended |
| `x-whistle-rule-name` | the name of a **rule group**, whose text is appended — `multiEnv` only |
| `x-whistle-key-value` | a JSON object of values private to that text |

Each is percent-decoded (`decodeURIComponent`, and a malformed escape leaves the
text alone rather than half-decoding it), and they compose in this order:

```
<values[x-whistle-rule-key]>
<x-whistle-rule-value>
<x-whistle-rule-host>
<groups[x-whistle-rule-name]>
```

**Reading them is a mode. Deleting them is not.** `getValue`'s
`delete req.headers[key]` runs before it decides whether to return anything
(`:558-570`), so a rules text a client wrote never reaches the origin — and is
never obeyed by a whistle further up the chain — whatever this proxy is set to.
That is true here too, and always has been.

Which mode, and what changes:

| Started with | The five headers | Who wins |
|---|---|---|
| *(nothing)* | taken, contents dropped | — |
| `-M enableRequestHeaderRules` | read | **the stored rules** |
| `-M multiEnv` (`nohost`, `multienv`, and inside `-M multiple`) | read, including `x-whistle-rule-name` | **the request's** |
| `-M strict` beside either | taken, contents dropped | — |

The precedence is upstream's, and it is one `if` (`initRules`, `:647-652`):
`multiEnv` resolves the stored rules and merges the request's **over** them,
and `enableRequestHeaderRules` does it the other way round.

`-M multiEnv` brings two more things with it, both upstream's and both
measured:

* only the **default** rule group resolves. Named groups stay loaded and stay
  editable, but selecting one does nothing — `getSelectedRulesList()` returns
  `[]` under it (`_original/lib/rules/util.js:204-206`). The console refuses the
  toggle here rather than recording a state the proxy then ignores;
* HTTPS is no longer intercepted from the switch. `isEnableCapture()` opens with
  `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`
  (`rules/util.js:547-550`), so `-M capture|multiEnv` and `-M multiEnv|capture`
  both pass CONNECT through. A `enable://capture` **rule** still works: it is
  resolved from the rules and never consults the switch.

> **`multiEnv` lets whoever sends a request decide where it goes.** It is for
> one proxy serving many environments — each request naming its own, nothing
> stored — and not for a proxy on a shared network. Both proxies are off by
> default for that reason.

`x-whistle-rule-name` is the odd one: outside `multiEnv` upstream never calls
`getValue` for it, so it is neither read **nor deleted** and reaches the origin.
Measured against whistle 2.10.8, and matched here — including the corner where
`-M strict|multiEnv` consumes it and reads nothing, because `strict` suppresses
what the call returns rather than the call.

All of the above is measured probe by probe by
`tests/differential/header-rules-bench.js` (50 probes, 0 differing) and pinned
without node by `tests/header_rules_e2e.rs`.

#### What a front proxy claims

A proxy behind another one is told the client's address, scheme and host in
headers. whistle reads four (`handleForwardedProps`,
`_original/lib/util/index.js:3697-3728`; `getFullUrl`,
`lib/util/common.js:1231-1266`):

| Header | What it claims | Believed when |
|---|---|---|
| `x-forwarded-host` | the host the client asked for | `-M x-forwarded-host` |
| `x-forwarded-proto` | the scheme the client used | `-M x-forwarded-proto` |
| `x-forwarded-for` | the client's address | `-M keepXFF` |
| `x-whistle-real-host` | the host, in whistle's own spelling | **`-M x-forwarded-host`** here; **always** upstream |
| `x-whistle-forwarded-props` | *"open the three gates for me"* | **never** here; **always** upstream |

The first three are removed **only when they are believed** — upstream's delete
lives inside the branch that consumes them, so without the mode a front proxy's
claim still reaches the origin, which may legitimately want it.

**The last two this port removes from every request and does not read.** A mode
is an operator deciding once, at startup, that a front proxy is there. A header
is the *sender* deciding, and a proxy cannot tell an operator's front proxy from
any client on the network, because the header is the only evidence and the
sender wrote it. Measured with no mode set at all: `x-whistle-real-host` sent a
request to a different origin, and `x-whistle-forwarded-props: proto` made
`https://…` patterns fire on a plain request. `x-whistle-real-host` is honoured
under `-M x-forwarded-host`, whose subject is exactly that claim.

**`x-forwarded-proto` changes which pattern matches, not the connection.** A
request labelled `https` is matched as `https://…` (and against port 443 when it
named no port), and still leaves this proxy exactly as it arrived. Measured:
whistle sends no ClientHello for it. `tests/differential/forwarded-bench.js`
counts handshakes at the origin for that reason, and
`tests/forwarded_e2e.rs` reads the first byte the origin receives.

Three more markers go the same way as the rules headers, and for the same
reason — they name facts about the *connection*, which the connection already
answers:

| Header | Where whistle drops it |
|---|---|
| `x-whistle-client-port` | `_original/lib/init.js:181`, and again on the upgrade and tunnel paths |
| `x-whistle-alpn-protocol` | `init.js:224`, where it is consumed |
| `x-whistle-client-id` | `res.js:717-723` — **unless** `enable://keepClientId`, which this port honours for exactly this purpose and nothing else |

#### `websocket` — an upgrade that does not say `websocket`

Some clients speak WebSocket under a name of their own: `Upgrade: ws`, a vendor
string, a typo. Both proxies tunnel such a connection as opaque bytes and
surface no frames, and both take `enable://websocket` as the instruction to
read it as WebSocket anyway — upstream's test is
`socket.enable.websocket || util.isWebSocket(headers)`
(`_original/lib/https/index.js:81`), and this port's is the same expression.

#### A body shown as frames

whistle's Frames panel is not only for WebSockets: an ordinary body is cut into
frames when it is an event stream, and when a header names a separator
(`handleResBody` / `parseFrame`,
`_original/lib/inspectors/data.js:67-135,:323-345`). This port showed such a
body only as one preview, which for a stream that never ends is nothing at all.

* **`content-type: text/event-stream`** is cut at every blank line, one frame
  per SSE event. Only the type counts: `text/event-stream; charset=utf-8` is an
  event stream too. whistle 2.10.8 compared the header whole and showed that one
  as a single body; 2.10.9 fixed it, and this port follows the fix.
* **`x-whistle-custom-frame-separator`** names any separator, on the request or
  the response, and works for any content type — **together with
  `enable://captureStream`**, which is not optional:

  ```
  api.example.com enable://captureStream resHeaders://(x-whistle-custom-frame-separator=%0A)
  ```

  turns a newline-delimited JSON stream into one frame per line. The value is
  percent-decoded (`%0A` is a newline; the FAQ prints `%A0`, which is a
  different byte and frames nothing); a leading `/` keeps the separator on the
  frame it ends. The header is removed before the other end sees it, whether or
  not it was usable.

  The flag is required because the header need not have come from you: it can
  arrive from the origin, or from a whistle further up the chain, and a header
  somebody else sent should not decide what this proxy holds on to. whistle
  2.10.8 wants the same pair — measured through its own frames API, a separator
  with no flag frames nothing there, on the request side as well as the
  response. 2.10.10 frames the response of a request **with no body** (a GET)
  without the flag, as a side effect of a change to when it records that the
  request was sent; its changelog and FAQ still ask for the flag, and so does
  this port. An event stream is the exception and turns the flag on by itself.
* **`disable://captureStream`** turns both off, and a compressed body is never
  framed — searching a deflate stream for a separator finds nothing.

Frames from a request body are marked `send` and from a response `receive`,
which is the only thing that distinguishes them from a WebSocket's in the
panel. A hidden request (`enable://hide`) produces none.

#### `hide` — a request the console never hears about

`enable://hide` lets a request happen and keeps it out of the capture. Four
flags decide, not one (`checkHideProp`,
`_original/lib/util/index.js:3982-3987`): `enable://hide` and `disable://show`
hide; `enable://show` and `disable://hide` un-hide, and the un-hiding half
wins. The pair exists because the two halves usually come from different lines —
a broad `enable://hide` over a whole domain, and an `enable://show` on the one
request being looked at.

A hidden request is not shown, not stored and not replayable, here as there —
upstream gates its data server on the same question (`inspectors/data.js:59`).
Its Composer-only pair (`enable://hideComposer`) and its server-wide capture
switch are not implemented: a session here does not record whether the Composer
sent it.

#### `auto2http` — an https leg that falls back to cleartext

`https://www.example.com` pointed at a dev server that speaks plain HTTP is the
first thing anyone does with a debug proxy, and on its own it cannot work: the
origin leg is https, the server is not, and the handshake fails. whistle sends
the request again without TLS, and [`host.md`](https://wproxy.org/docs/rules/host.html)
documents that as the reason `www.example.com 127.0.0.1:5173` works at all.

It is not unconditional. `checkAuto2Http`
(`_original/lib/util/index.js:3191-3198`) asks for one of three things, and
`disable://auto2http` overrides all of them:

* `enable://auto2http` — said out loud;
* a `host://` rule matched this request, wherever it points;
* the address reached is **local** (loopback, this machine's own, or a proxy
  hop with a host override).

Two differences here, both narrowings of when the retry can happen rather than
of what it does:

* **The address is read as written, not as resolved.** whistle asks the
  question of the IP it has just looked up, so `dev.local` resolving to
  `127.0.0.1` is local there and not here. An IP written into a `host://` rule,
  or `localhost`, or any request carrying a `host://` rule at all — the shapes
  the page is about — reach the retry on both sides.
* **The retry comes sooner.** whistle downgrades on the first failure only when
  the error looks like TLS (`checkTlsError`) and otherwise retries https once
  more first. Here any failure to bring the leg up takes it immediately.

An earlier version of this document declined the flag, on the grounds that a
silent downgrade of an encrypted connection is the same class of thing as not
verifying a certificate. The reasoning still holds for what it described — but
what it described was narrower than the flag: this is the ordinary request path,
not a `wss://` corner, and refusing it means the most common rule anyone writes
answers 502 here and 200 in whistle. It is implemented as whistle implements it,
and `disable://auto2http` is how a request opts out.

#### `h2` — which HTTP version reaches an HTTPS origin

A request that reached this proxy over **HTTP/2** goes on to an HTTPS origin over
HTTP/2 too, when the origin offers it in its TLS handshake; one that arrived over
HTTP/1.1 goes on over HTTP/1.1. That is whistle's default (`checkH2`,
`_original/lib/inspectors/res.js:174-195`). Browsers speak h2 to this proxy for
every HTTPS site it decrypts, so for a browser this is the usual case. The flags
turn it either way for the requests they match:

| Rule | To the origin |
|---|---|
| `enable://h2` (also `http2`, `httpsH2`) | offer HTTP/2 whatever the client spoke |
| `disable://h2` (also `http2`, `httpsH2`) | HTTP/1.1 only; `disable` wins over `enable` |

```
# an origin that misbehaves over h2: talk HTTP/1.1 to it
api.example.com disable://h2
```

What an origin sees over HTTP/2: the `Host` header becomes `:authority` and is not
sent as a header, and the headers that only mean something on one HTTP/1.1
connection — `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
`Upgrade`, `HTTP2-Settings`, and `TE` other than `trailers` — are dropped, as
whistle's `formatH2Headers` drops them. So a `reqHeaders://connection=close` rule
reaches an h2 origin as nothing at all, on both sides. A plain `http://` origin,
a WebSocket upgrade and an `internal-proxy://` hop (which strips the TLS) stay on
HTTP/1.1.

All the h2 requests one client connection sends to one origin share one
connection to it, so a page of fifty resources is one TLS handshake rather than
fifty; the session's timings name that connection and mark every request after
the first as reused. Two differences from whistle, both measured by
`tests/differential/h2-bench.js`:

* `disable://http2` here turns off the **origin** half only. whistle's also stops
  offering h2 to the client, so the client falls back to HTTP/1.1 as well; here
  the client keeps h2. The origin sees the same thing either way.
* `httpH2` — HTTP/2 without TLS to a plain `http://` origin — is not implemented
  (below).

#### The flags this port does not implement

The official [`enable`](https://wproxy.org/docs/rules/enable.html) and
[`disable`](https://wproxy.org/docs/rules/disable.html) pages list 55 and 65
entries between them (a couple name two spellings of one flag). Every name was
looked up in this port's source; these are the ones that appear nowhere, each
with the reason. They parse and do nothing.

| Flag | What it does upstream | Why not here |
|---|---|---|
| `hideComposer`, `hideCaptureError`, `customParser`, `bigData` | shape what whistle's own console shows — which rows are hidden, who renders a capture, and a 2 MB → 16 MB display cap | this port has its own console; the capture cap is `--body-preview-limit`. (`interceptConsole` **is** read — see [`log://`](#log--a-pages-console-in-this-one)) |
| `clientId`, `multiClient` | whistle's `x-whistle-client-id` — a header it stamps so an upstream can tell clients apart | there is no client-id concept here, and inventing one to honour a flag is the wrong way round. `keepClientId` **is** implemented, for the one thing it can mean here: keeping a client-id the *client* sent — see [Rules in a request header](#rules-in-a-request-header) |
| `useLocalHost`, `useSafePort` | rewrite `log://` and `weinre://` URLs to whistle's own built-in host and port | neither rule points at a server of this port's: `log://` reports to the page's own origin, and `weinre://` loads from the server `--weinre` names |
| `authCapture`, `tunnelHeadersFirst`, `tunnelAuthHeader` | order a plugin's `auth` hook against the HTTPS upgrade, and decide whose headers win when a plugin passed some through a tunnel | all three are about whistle's plugin API; this port's is its own — see [`PLUGINS.md`](PLUGINS.md) |
| `flushHeaders`, `secureOptions` | Node plumbing — `response.flushHeaders()` and the TLS socket's `secureOptions` | there is no Node here to flush or configure |
| `httpH2` | HTTP/2 without TLS (h2c) to a plain `http://` origin | not implemented: HTTP/2 to an origin is offered over TLS only — see [`h2`](#h2--which-http-version-reaches-an-https-origin) |
| `keepH2Session` | as `disable://keepH2Session`, share an origin h2 session between a client's connections instead of keeping one per connection | sessions here are always per client connection; sharing them across connections is the thing the pool is built not to do — see [`ARCHITECTURE.md`](ARCHITECTURE.md#reusing-origin-connections) |
| `dnsCache` | turn whistle's DNS cache off | there is no DNS cache here to turn off, so the flag's effect is already the default |
| `clientCert`, `requestCert` | make the forged server ask the **client** for a certificate (mTLS) | not implemented. A client configured for mutual TLS fails against this port where it works against whistle; the missing half is a client-certificate store, not the flag |
| `forceResWrite` | nothing: only `forceReqWrite` is ever read, on **both** sides (`_original/lib/inspectors/req.js:604`, `res.js:1300`) | the flag exists in the documentation and not in the program |
| `timeout` (as `disable://timeout`) | nothing: the name appears in no source file of whistle 2.10.8 | the same — a documented flag the program never reads |

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
> whix   200 "REWRITTEN"      200 "REWRITTEN"
> ```
>
> So the rewrite disappears on reload in whistle. whix does what
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
- A header that appears more than once: every `set-cookie` is rewritten on its
  own and all of them stay; any other name is joined first (`, `, or `; ` for
  `cookie`) and rewritten as one value — the two shapes Node gives upstream.

```
api.example.com     enable://cors
slow.example.com    enable://abort
static.example.com  disable://cache
example.com         trailers://x-checksum=abc123
example.com         headerReplace://{"resH.set-cookie:/Domain=[^;]+/":"Domain=example.com"}
example.com         headerReplace://{"resH.location:/^http:/":"https:"}
page.example.com    responseFor://name=x-served-by,req.x-request-id
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

> Upstream also arms these from a `filter://abort` line; in whix `filter://`
> is only a match condition, so `enable://` is the whole vocabulary here.

#### A flag written on both sides does nothing

`enable://x disable://x` cancels: upstream reads a flag as `enable[name] &&
!disable[name]` (`isEnable`, `_original/lib/util/index.js:678-680`), and reads
the opposite question the mirror way. The order the two were written in does not
decide it. This port had only the mirror until it was measured, so a flag named
on both sides used to be *on* here and inert upstream.

Three names opt out, and the exceptions are upstream's rather than a
simplification: **`userLogin`** lets `enable` win over `disable`
(`util/index.js:3557-3562`), **`showHost`** is a bare read that never consults
`disable` (`res.js:1193`), and **`cors`** has no `enable` reader upstream at all.

#### Two flag divergences, measured

* **`enable://responseWithMatchedRules`** writes the matched rule lines into
  `x-whistle-matched-rules` on the response, `rawPattern + ' ' + rawMatcher` per
  rule, joined with `\n` and URL-encoded whole (`addMatchedRules`,
  `util/index.js:3879-3888`). The order is the **protocol table's**, not the
  written one — whistle assigns `req.rules`' keys as it walks `protocols.js`, so
  `enable://` is reported ahead of `resHeaders://` and a `file://` ahead of
  both. Its request-side twin `requestWithMatchedRules` is dead in **both**
  proxies: upstream calls it from the response inspector (`res.js:770`), after
  the request head has already gone, so the origin never sees the header.
* **`disable://trailers` still announces the trailer upstream.** Asked with
  `TE: trailers`, whistle emits `Trailer: x-t` and then sends no trailer section
  at all; whix drops the announcement along with the section. Announcing a
  field that never arrives is a protocol lie, and not one worth reproducing.

#### Aborting a connection rather than a request

A `CONNECT` tunnel and an inbound SOCKS connection have no response of their own
to destroy, so the abort lands on the connection itself, and lands **before the
client is told the connection is open**: the `CONNECT` is never answered at all,
and the SOCKS request comes back *connection not allowed by ruleset*. Upstream
destroys the same socket from either gate (`_original/lib/tunnel.js:372-374`,
`:748-750`) and opens its SOCKS connections by issuing a `CONNECT` against its
own port, so a refused tunnel denies the SOCKS client (`lib/index.js:174-193`).

The two spellings collapse into one here. whix acknowledges a `CONNECT`
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
> and splices the rules the script emits into the join. whix has no dynamic-rules
> script: every kept file is read as rules text.

The text does not have to be a file. `reqRules://{extra}` names a **value** — from
`--value`, from the console's Values pane, or from a ``` ``` ``` block in the rules
file itself — and `reqRules://(…)` is the inline form; both are `readRuleValue`
returning `rule.value` before it ever looks at a disk
(`_original/lib/util/index.js:1177-1179`).

#### What produced rules can and cannot do

Measured against whistle 2.10.8 (`tests/differential/cases-compose.js`):

* **Composition is one level deep.** A `reqRules://` written *inside* a produced
  text is parsed and never followed: `resolveRulesFile` reads the include once
  and merges it, and nothing asks the merged set for a `rulesFile` of its own. A
  self-reference and a two-step cycle therefore both terminate, having applied
  one round.
* **What is produced wins** over the file that named it, on the same line or on
  another — `mergeRule` returns the new rule for a single-value protocol and puts
  the new list first for a multi-match one (`lib/util/index.js:2147-2170`).
* **`lineProps://important` still outranks it.** An important including line keeps
  a single-value protocol, and for a multi-match one every important operator —
  from either side — sorts ahead of every normal one.
* **The produced rules are matched against the request as it now is**, so a line
  above that rewrote the URL decides which produced patterns match.
* A produced text that is not rules, is empty, names a value that does not exist,
  or names a file that does not exist contributes nothing and is not an error.

#### `resRules://` — rules for the response

`resRules://` is the response-phase twin: whistle keeps it in the same
accumulating list as `resScript://`, parses what the lines hold and merges it
once the response head is in (`getResRules`, `_original/lib/plugins/index.js:1337-1360`).
A rules text under the `resScript://` spelling is merged the same way; only a
`resScript://` text that uses `ctx` is this port's [hook](#scripting) instead.

Only the **response** half of the produced text applies — upstream's
`mergeRules(req, …, isResRules)` is restricted to `resProtocols`
(`lib/util/index.js:2198-2203`) — so a `host://` or a `reqHeaders://` inside it is
parsed and dropped: by the time the text is read the request has gone out. What
does apply is everything response-side, `replaceStatus://` and the body operators
included, and a condition on the response (`includeFilter://s:404`) is answerable
because the head is already in hand.

```
example.com   resRules://{late}          # a value
example.com   resRules:///etc/whistle/response.rules
```

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

**The path takes the unmatched part of the URL**, the same way `file://` does —
the value is read through the tail-joined `rule.url` (`getWriteFilePath`,
`util/index.js:1461-1464`). That is what makes one rule produce **one dump per
URL** instead of one file for the whole run:

```
api.example.com   resWrite:///tmp/dump      # /users → /tmp/dump/users
                                            # /v2/orders/7 → /tmp/dump/v2/orders/7
api.example.com/users  resWrite:///tmp/dump # the pattern eats the path → /tmp/dump
api.example.com   resWrite://</tmp/dump>    # <verbatim> refuses the join
```

The query is not part of the name — `/users?q=1` and `/users` write the same
file — and a request for `/` joins nothing, so it writes `/tmp/dump` itself.

An **empty** value has no path to join onto, so upstream's becomes relative and
whistle dumps into whatever directory it was started in — `resWrite://` on a
request for `/users` writes `./users`. A rule with no path in it writing a file
somewhere in your tree is not a behaviour worth reproducing: whix writes
nothing. Measured on `tests/differential/write-bench.js`.

```
api.example.com   reqWriteRaw:///tmp/api-request.http
api.example.com   resWrite:///tmp/api-body.json  enable://forceReqWrite
```

**One divergence in the raw dumps.** whistle writes each header name as it
arrived, keeping a copy of the original spelling for the purpose
(`rawHeaderNames`, `_original/lib/util/file-writer-transform.js:33`). hyper
normalises every name to lower case before this port can see it, so a
`reqWriteRaw`/`resWriteRaw` dump here reads `connection: keep-alive` where
whistle's reads `Connection: keep-alive`. Recovering the original spelling would
mean carrying a second copy of every header through the proxy for the benefit of
a debug dump. Values, order, framing and body are identical; measured on
`tests/differential/write-bench.js`.

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

**Write a bare number.** The two families read their value differently, and the
difference is upstream's, not a choice:

| | reads the value with | `600ms` | `600` | `0` or `-600` |
|---|---|---|---|---|
| `reqSpeed` / `resSpeed` | `parseFloat` — the longest numeric prefix | 600, unit discarded | 600 | **no cap** |
| `reqDelay` / `resDelay` | `Number` — the whole text or nothing | **no delay at all** | 600 | **no delay** |

A speed suffix is *discarded, not converted*: `resSpeed://20kb` is 20 **kilobits**
and `resSpeed://1mb` is 1. A delay suffix is worse — it silently switches the
rule off, because `exports.delay` never parses anything, it compares the value's
text to zero (`if (time > 0)`, `_original/lib/util/index.js:3686-3691`), and in
JavaScript `'600ms' > 0` is false. Both proxies behave this way; measured on
`tests/differential/timing-bench.js`.

Zero and negative mean *no limit* in all four, upstream's `> 0` guard.

### Response rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `replaceStatus` / `statusCode` | status number | Replace the upstream response status. A mocked `statusCode://401\|407`, and a `replaceStatus://` that actually **changed** the status to one of those, also send the matching auth challenge — the header that makes a browser ask for credentials; `disable://userLogin` or `lineProps://disableUserLogin` withholds it |
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
is **not** an upstream flag — whix keeps it as an alias for
`resCors://enable`.

> The official page has that sentence **inverted** — it says "请求方法为 OPTIONS 时，
> access-control-allow-headers -> access-control-expose-headers"
> (<https://wproxy.org/docs/rules/resCors.html>), and its worked example lists
> `access-control-allow-headers` for a plain `GET`. Both whistle and whix do
> the opposite, which is also the only reading that makes sense: `allow` answers a
> preflight, `expose` answers a real response. Upstream's own line is
> `var operate = isOptions ? 'allow' : 'expose'`
> (`_original/lib/util/index.js:2953`).

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
> whix emits it once; the upstream form is a request line no origin
> parses.
>
> `delete://body` (and `req.body` / `res.body`) does **not** empty the body in
> real whistle, only discard what `reqBody://`, `reqPrepend://` and their
> response twins meant to inject. `removeBody` assigns `EMPTY_BUFFER`, and
> `EMPTY_BUFFER` is `toBuffer('')` — whose first act is `if (!buf) return`
> (`util/common.js:1630-1632`), so the constant is `undefined` and the
> assignment leaves the body alone. whix empties it, which is what the
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

When any body operator applies, whix buffers that body, transforms it, and
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
example.com/page       resPrepend://<!-- via whix -->
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

An SVG (`image/svg+xml`) is **text** here, so `resReplace` runs on it — handy for
recolouring an icon — and a `file://` SVG is served with `; charset=utf-8`. That
is whistle 2.10.8's answer, which tests `xml` before `image/`. whistle 2.10.10
tests `image/` first, so there an SVG is an image and the replacement silently
does nothing; this port keeps the older answer on purpose (STATUS, U1).

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

### The first road is JSON5

"Read as JSON" is read as **JSON5**: `parseRawJson` is `json5.parse`
(`evalJson`, `_original/lib/util/common.js:1673-1679`), and it is the first
thing every road to an object tries — `_parseJSON` before the query and line
formats, `isJson` deciding whether a value is content rather than a path, the
credentials reader, and both body merges, which parse the **body** with it too.

So all of these are objects:

```
{a: 'one', b: 'two'}      unquoted keys, single quotes
{a: 'one',}               a trailing comma
{ /* or a comment */ }    comments, both kinds
{a: 0x1f, b: .5, c: +1}   hex, leading-dot and signed numbers
```

which is why [`reqCookies.md`](https://wproxy.org/docs/rules/reqCookies.html)
can print `{ key1: 'value1', key2: 'value2' }` as a cookie object. This port
read it as text and set a cookie called `{`.

One shape looks as though it should work and does not, in either program: a
**dashed** key cannot be unquoted, because `-` ends a JavaScript identifier.
`{x-a: 'b'}` falls through to the line format, which yields a header named
`{x-a`; Node writes that onto the wire and hyper refuses to build it, so
whistle sends a broken header and this port sends none. Quote the key.

### The line format, exactly

A value that was **loaded** — from a ``` block, a file, a URL or the values
store — is read as JSON5, then as a query string if it holds no whitespace,
then line by line (`_parseJSON`, `_original/lib/util/index.js:1135-1143`). The
third road has details that are not the obvious ones, and each was measured
against whistle 2.10.8 rather than read:

| You write | It becomes | Why |
|---|---|---|
| `a: 123` | `{"a":123}` | a number: the first and last characters differ |
| `a: 1`, `a: 11`, `a: 121`, `a: 0` | `{"a":"1"}` … | **text**: upstream asks `fv === lv` first, and the numeric branch is the `else` of it (`parseLine`, `common.js:1145-1157`) |
| `a: "1"` | `{"a":"1"}` | a quoted value loses its quotes |
| `solo` (no separator) | `{"solo":""}` | a name with an empty value |
| `solo:` | `{"solo:":""}` | **no whitespace**, so it never reaches the line format at all — the query road reads the whole token as a name, and a header called `solo:` is not a token, so nothing is sent |

Two more are seen only by `reqMerge://` / `resMerge://`, because
`RESOLVE_KEY_RE` is tested against the matcher *as written* — the same value
under `params://` keeps its dots:

| You write | It becomes |
|---|---|
| `a.b.c: 1` | `{"a":{"b":{"c":"1"}}}` |
| `c\.d: 1` | `{"c.d":"1"}` — an escaped dot is part of the name |
| `a[0]: 1` | `{"a":["1"]}` — a **bracket** index opens an array; a dotted `a.0` opens an object |

A structure merged into a **form** body is written as nothing (`a=`), because
that is what Node's `querystring.stringify` does with it; a JSON body gets the
structure itself.

> **One difference remains, and it is JavaScript's.** A merged JSON object is
> re-serialised by whistle through a JS object, and JS enumerates integer-like
> keys first: a patch adding `0` to `{"name":"x"}` comes back
> `{"0":…,"name":"x"}` there and `{"name":"x","0":…}` here. Reordering a user's
> JSON to imitate a language's property order is worse than the difference.

### A `^` pattern has no path boundary

`pattern.md`'s wildcard section prints `^wss://*.example.com/path/to` as a miss
for `wss://a.example.com/path/toxxx`, "路径缺少 `/` 边界". It matches. A `^`
pattern is compiled to a prefix regexp with no `/` boundary anywhere in it —
the boundary belongs to the plain URL-fragment form — and the way to forbid the
tail is the trailing `$` the same section documents. Measured on whistle 2.10.8
and matched here; `cases-patterns.js` carries both halves.

### How big a body a merge may read

`resMerge://` is skipped over a response larger than 2 MB upstream, and
`enable://resMergeBigData` or `lineProps://enableBigData` on the line raises
that to 16 MB (`MAX_RES_SIZE` / `BIG_MAX_RES_SIZE`,
`_original/lib/inspectors/res.js:21-22,:1013`). The request side is the same
shape with `reqMergeBigData` (`req.js:19-20,:163`).

Here the bound is one knob for every response operator —
`--body-rewrite-limit`, 16 MB by default, which is already upstream's raised
ceiling — so by default this port merges bodies whistle would have skipped.
The two flags still mean something: they raise **this request's** ceiling to
16 MB, which is what a user who lowered the knob is asking for.

### `socks://` with no port is 1080

[`socks.md`](https://wproxy.org/docs/rules/socks.html) says the default port is
443, twice. It is 1080: `proxyPort = isSocks ? 1080 : isHttpsProxy ? 443 : 80`
(`_original/lib/inspectors/res.js:284`), which is also the SOCKS default
everywhere else. The page appears to have copied the `https-proxy` row. This
port uses 1080, as whistle does.

### Escapes in a prop list

`delete://`, `enable://` and `disable://` split their value on `|` and `&`
through `parseProps` (`_original/lib/util/common.js:73,:111-127`), which is one
regexp over the whole value and does two things: a separator behind an **odd**
number of backslashes is text rather than a split, and `\s`, `\t`, `\n`, `\r`,
`\f` and `\v` become the characters they name. So `delete.md`'s own example —

```
https://www.example.com/path delete://reqBody.\n\ \.p.test\|\&test
```

— addresses a key holding a newline, a space and a dot, and another holding a
pipe and an ampersand. `lineProps://` is the exception and takes the plain
split with no escapes at all (`index.js:1898`), which
[`LINE_PROPS.md`](LINE_PROPS.md) records.

> The page's table writes the space as `\ `; the code reads `\s`. A `\ ` is
> left as written by both proxies, so the difference is in the page.

### A status value that is not a status

`statusCode://` and `replaceStatus://` take a number. Given anything else —
`abc`, `20x`, `099`, `0`, `2000`, a file path — upstream hands it to Node's
`res.writeHead`, which throws, and the client gets a **connection reset**.
Measured against whistle 2.10.8 for every one of those.

There is nothing there to copy, so this port keeps the answer an **empty**
value gets, which upstream does define (`var code = rule || 200`,
`getStatusCodeFromRule`, `_original/lib/util/index.js:3580`): a mock answers
`200`, and `replaceStatus://` leaves the response alone. A typo is not a reason
to drop a response that arrived.

The values that *are* statuses agree, including the two outside the registered
range — `999` and `600` are written as asked, by both.

An **interim** status other than `101` — `statusCode://100`, say — cannot be a
final answer: upstream writes it and the client goes on waiting for the answer
that never follows; this port's HTTP server refuses to send one and answers
`500`. Upstream's own suite expects an error from both kinds
(`test/units/statusCode.test.js`, `statuscode4`/`statuscode5`); the two calls are
declared in `tests/differential/upstream-suite.js` rather than matched.

### A method value that is not a token

Same shape, one operator over. `method://GET;`, `method://{"method":"PUT"}` and
a block of lines all reach Node's `http.request`, which throws
`ERR_INVALID_HTTP_TOKEN`, and whistle answers its `502` page. This port leaves
the method alone. A value that *is* a token agrees, including an unknown verb
(`FROBNICATE` is sent as written) and digits.

### Reaching a rule without a proxy configured

A request sent straight to the proxy's port **origin-form** — a path rather than
a whole URL — is decided by its `Host`:

- **a name for the console** — an IP address, `localhost`, a console hostname
  (built in or added with `-l`): the console answers. That is what makes
  `http://127.0.0.1:8899/api` fetch a page of this program rather than anything
  a rule could touch;
- **any other name**: an ordinary request to that name, rules and all — how a
  client with no proxy setting still reaches the rules, say through a hosts-file
  line pointing `api.example.com` at this machine with `-p 80`. Upstream does
  the same (`_original/biz/index.js:98-106`, `lib/upgrade.js:23-24`).

```console
$ curl -H 'Host: api.example.com' http://127.0.0.1:8899/v1   # → api.example.com/v1, by the rules
```

A name that resolves back to this proxy is not served the console under it — a
page could rebind its own name to `127.0.0.1` and read everything — but answered
with a `302` to the console's address, as upstream answers it.

`/-/` (or `/_/`) in front of the path says the opposite: strip the prefix and
treat what is left as an ordinary request (`_original/biz/index.js:114-129`,
and the FAQ's answer to the same question). The request then names *this*
proxy, so where it goes is a rule's to decide:

```
http://127.0.0.1:8899/hop   https://api.example.com/hop
```

```console
$ curl http://127.0.0.1:8899/-/hop        # → api.example.com/hop
$ curl http://127.0.0.1:8899/hop          # → the console's 404
```

With no rule matching, the request is addressed to the proxy itself and meets
the self-loop guard, which answers `302` — as it does upstream.

## Precedence

For each request whix walks the rules and builds a resolved set:

1. **Important first.** Lines carrying `lineProps://important` are considered
   before normal ones. (`$` is *not* an importance marker — it is exact
   matching; see [`$` — exact patterns](#--exact-patterns).)
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

Within a pass, rules are evaluated in **file order**, so put more specific /
higher priority rules earlier (or mark them `lineProps://important`).

Two orderings sit either side of "file order" and are easy to be surprised by:

* **Rule groups.** Every enabled *named* group is walked first, in the order the
  console lists them, and the **default group last** — so a named group overrides
  the default one. That is upstream's order
  (`addRules(defaultRules, 'Default')` after the named ones), and the reason its
  console shows Default at the bottom.
* **Tokens on one line.** Several operators share a **single slot**: a
  destination (`http://…`, `example.com`, a bare host), the local-file family,
  `statusCode://` and `redirect://`. Only one of them answers a
  request, and it is whichever was written first — on the earlier line, or
  earlier on the same line:

  ```
  example.com  file:///mock.json  statusCode://204   # serves the file
  example.com  statusCode://204  file:///mock.json   # answers 204
  ```

  A `statusCode://` that loses this contest is silent; it does not come back in
  the response phase to overwrite the status of whatever won.

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

An `important` line leads the list, so it both wins contested keys and comes
first in a join:

```
example.com/x  resAppend://normal
example.com/x  resAppend://important lineProps://important
# → body + "important\r\nnormal"
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
| Win against an earlier ordinary line | `example.com  host://2.2.2.2 lineProps://important` (`$` means exact matching, not importance) |
| Leave a pinned host alone | `pinned.example.com  sniCallback://no-mitm` |
| Tag every intercepted response (confirms MITM is active) | `/^https:/i  resHeaders://x-via=whix` |

---

## Operator coverage

The following groups describe implemented runtime paths and their limits.
Do not interpret the old registry-name ratio as semantic coverage: aliases,
metadata, plugin infrastructure and per-request effects need different tests.
The current evidence and deliberate divergences are recorded in STATUS.

### Applied at runtime

| Category | Operators |
|----------|-----------|
| Routing / upstream | `host`, `proxy`, `http-proxy`, `https-proxy`, `internal-proxy`, `internal-http-proxy`, `internal-https-proxy`, `https2http-proxy`, `http2https-proxy`, `socks`, `pac`, and `x`/`xs`-prefixed proxy variants |
| Request rewrite | `reqHeaders`, `reqCookies`, `reqType`, `reqCharset`, `reqCors`, `ua`, `referer`, `method`, `auth`, `forwardedFor`, `urlReplace`, `params`, `urlParams`, `reqBody`, `reqPrepend`, `reqAppend`, `reqReplace`, `reqDelay`, `reqSpeed`, `reqWrite`, `reqWriteRaw` |
| Response rewrite | `resHeaders`, `resCookies`, `resType`, `resCharset`, `resCors`, `replaceStatus`, `statusCode`, `attachment`, `cache`, `resBody`, `resMerge`, `resPrepend`, `resAppend`, `resReplace`, `resDelay`, `resSpeed`, `resWrite`, `resWriteRaw`, `trailers`, `headerReplace`, `responseFor` |
| Content-type body | `cssBody`/`cssPrepend`/`cssAppend`, `htmlBody`/`htmlPrepend`/`htmlAppend`, `jsBody`/`jsPrepend`/`jsAppend` (the JS and CSS families reach HTML responses too, wrapped as markup) |
| Short-circuit / flags | `redirect`, `locationHref`, `statusCode` mock, `enable`, `disable` |
| Local file / template | `file`, `rawfile`, `tpl`, `jsonp`, `dust`, and their `x`/`xs` fallback variants (`xfile`, `xrawfile`, …) |
| Matching / control | `filter`, `includeFilter`, `excludeFilter`, `ignore`, `delete`, `log`, `rule`, `rulesFile` (`reqRules`), `resRules` |
| TLS | `cipher` (upstream TLS version pin + OpenSSL cipher-string evaluation), `sniCallback` (plugin picks the MITM certificate, or declines to intercept) |
| Scripting / extend | `resScript`, `frameScript`, `plugin`, `pipe`, `weinre` |

**Rule-file features:** `${port}` and `${version}` in operator values are substituted
(case-insensitive) — wider than upstream, where `CONFIG_VAR_RE`
(`_original/lib/util/index.js:3262`) has one reader, the source of a backticked
[`@`-include](#pulling-in-another-rules-text-), and a `${port}` elsewhere
resolves only inside [backticks](#backtick-templates). That one reader is here
too, and here it answers the source with or without the backticks. It never
reaches **content**: a `${port}` in an
inline `(…)` payload or in what a `{name}` returned is text the mock meant to
contain. An operator value that names a file or a URL is
[read before the operator applies](#values-read-from-a-file-or-a-url), and one
wrapped in backticks is [rendered against the request](#backtick-templates);
`locationHref://` **answers** the request with a page that redirects itself.

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

### A client certificate for the origin (`tlsOptions://`)

`tlsOptions://` is `cipher://` by its other name, and the first thing
[`cipher.md`](https://wproxy.org/docs/rules/cipher.html) says it is for is
mutual TLS: an origin that asks *this proxy* to prove who it is.

```
# PEM: a key and its certificate, as two files…
api.example.com   tlsOptions://key=/certs/client.key&cert=/certs/client.crt

# …or as text, in a value
api.example.com   tlsOptions://{client.json}

# PKCS#12 (.pfx / .p12) and its passphrase
api.example.com   tlsOptions://passphrase=123456&pfx=/certs/client.p12

# and whom to trust there
internal.example.com   tlsOptions://ca=/certs/corp-root.pem
staging.example.com    tlsOptions://rejectUnauthorized=false
```

````
``` client.json
{ "key": "-----BEGIN PRIVATE KEY-----\n…", "cert": "-----BEGIN CERTIFICATE-----\n…" }
```
````

| Option | What it does |
|--------|--------------|
| `key` + `cert` | The client certificate: PEM, each a path or the text itself (a value beginning `-----`). `cert` may hold a chain, leaf first. The key must be unencrypted |
| `pfx` + `passphrase` (or `pwd`) | The same identity as a PKCS#12 file. Both the old (3DES) and the current (AES, PBKDF2) encryptions are read |
| `base` | A directory the paths above are relative to |
| `ca` | PEM, a path or the text. The roots the **origin's** certificate must chain to, *instead of* the built-in ones — Node's meaning of the option |
| `rejectUnauthorized=false` | Do not verify this origin's certificate |
| `minVersion`, `maxVersion`, `secureProtocol`, `ciphers` | See [below](#what-cipher-can-pin) |
| `crl`, `dhparam`, `ecdhCurve`, `sigalgs`, `secureOptions`, `sessionTimeout`, `sessionIdContext`, `honorCipherOrder`, `allowPartialTrustChain` | **Not supported**: rustls has no equivalent. The request goes ahead, and its session lists the option under `unapplied` |

Several lines merge, as for every `cipher://` option, so the certificate can be
on one line and the version on another.

**A certificate that cannot be used fails the request**, with the reason, before
anything is dialled: `502`, `x-whix-error: rules`, and a body such as
`tlsOptions: cannot read key /certs/client.key: No such file or directory`,
`tlsOptions: the private key does not belong to the certificate`, or
`tlsOptions: pfx could not be opened (wrong passphrase, or not PKCS#12)`.
whistle connects without the certificate in those cases and leaves the origin to
refuse; the client sees a 502 either way, but here it says which file.

**Connections are kept apart by identity.** A connection the origin
authenticated as one client is never reused for a request made under a rule
that names another certificate, or none — the certificate and the trust are
part of what a pooled connection is keyed by, and a rule with an identity has
TLS sessions of its own, so nothing resumes into somebody else's.

`ca` and `rejectUnauthorized` matter more here than in whistle, which verifies
no origin unless started with `--safe`: they are how one rule reaches an origin
with a private CA without `--insecure-upstream` switching verification off for
every origin.

Until 2026-09-30 none of the first five rows was read: the options parsed, and
every origin connection was made with no client certificate.
`tests/differential/core-bench.js` asks both proxies nine ways — PEM by path and
inline, a PFX, a certificate the origin does not trust, a key that is not the
certificate's, a wrong passphrase, a missing file — and they agree on all nine.

Not to be confused with `enable://clientCert` / `requestCert`, which make the
*forged server* ask the **client** for a certificate; that is still
[not implemented](#flags-includes--values).

### What `cipher://` can pin

`minVersion` / `maxVersion` / `secureProtocol` (or a bare `cipher://TLSv1.2`
token) pin the **upstream** TLS protocol version. rustls offers TLS 1.2 and 1.3
only, so a pin older than 1.2 clamps up to 1.2.

The value takes every road a data value takes, which is what
[`cipher.md`](https://wproxy.org/docs/rules/cipher.html) leads with: JSON,
`minVersion=TLSv1.2&maxVersion=TLSv1.3`, the line format, a file, a `{name}`.
The one exception is upstream's: a value made only of `[a-z0-9:!-]` is a **cipher
string** rather than an object (`SEP_CIPHER_RE`,
`_original/lib/rules/index.js:38`), so `cipher://ECDHE-RSA-AES128-GCM-SHA256`
needs no `ciphers=`. And several `cipher://` lines **merge**, first line winning
a contested key — `getTlsOptions` walks the whole list (`:684-691`). This port
read only the JSON form, off the first line, and quietly ignored the rest.

> **This is one of the places the port does more than whistle, deliberately.**
> Measured with `tests/differential/https-bench.js`, which now reports the TLS
> version the origin negotiated: a version pin is **inert upstream on a
> connection that works**. whistle builds the options in `getTlsOptions`
> (`_original/lib/rules/index.js:680-733`) but only ever extends the socket
> options with them while *retrying a ciphers error*
> (`lib/inspectors/res.js:495-497`, `lib/util/common.js:1769-1771`); the first,
> successful handshake never sees them, so `tlsOptions://{"maxVersion":"TLSv1.2"}`
> still negotiates TLS 1.3 there. A bare `cipher://TLSv1.2` does not get even
> that far: `SEP_CIPHER_RE = /[^a-z\d:!-]/i` rejects the dot, so whistle does not
> read it as a cipher string, and it is not JSON either — the value falls through
> to being opened as a *file*. whix applies the pin on the first attempt,
> which is what the rule says it does.

`ciphers` is an **OpenSSL cipher string**, and whix evaluates it. Not
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

A string that selects **nothing at all** drops the **pin** and leaves the request
alone: the connection is made without it and the log says so, naming the tokens
that came up empty. It does *not* fail the request, and the reason is that "no
match" here is not the same fact it is in OpenSSL. OpenSSL throws `no cipher
match` when a string selects nothing out of its own large universe; this selects
nothing out of nine suites, so `cipher://3DES` — a perfectly good string against
an OpenSSL built with 3DES — would fail here for a reason that is about *this
build* rather than about the rule. Failing the request would put that limitation
into somebody else's traffic, under a message about their rules file.

Two more things settle it. `cipher://` is **inert in whistle 2.10.8** — measured
across every spelling, so there is no upstream behaviour to be faithful to, only
the question of what a proxy that does implement it should do; and this port
already answers that question everywhere else, since `statusCode://abc`,
`replaceStatus://1` and `method://GET;` all leave the operator inert rather than
failing anything.

The two halves of the value are read independently, so an unusable cipher string
does not take a usable `maxVersion` with it. Suites that exist but that no
allowed version can use — only TLS 1.3 ones under a `maxVersion` of TLS 1.2 — are
dropped the same way and the version kept; building a connection for them used
to panic the request.

A dropped pin is on the session, not only in the log: `unapplied` names the
`cipher://` operator with the kind `cipher-unusable` and why
([`API.md`](API.md#没生效的规则)). Nothing is said over plain HTTP, which has no
handshake for a pin to be missing from. **A `cipher://` pin is a debugging aid,
not a security policy**: when it cannot be used the connection goes ahead with
the default suites, so it guarantees nothing about what an origin was reached
with.

```
# evaluated; the origin really negotiates from this set
example.com cipher://{"ciphers":"ECDHE+AESGCM:!AES128"}
# TLS 1.3 pinned by name; the TLS 1.2 list is emptied, as OpenSSL empties it
example.com cipher://{"ciphers":"TLS_AES_128_GCM_SHA256"}
# connects, unpinned; the session says `no cipher match: 3DES names no cipher
# suite this build has` — rustls has no 3DES and cannot be argued into one
example.com cipher://{"ciphers":"3DES"}
# the ciphers half is dropped; the version half still holds
example.com cipher://{"ciphers":"3DES","maxVersion":"TLSv1.2"}
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

**No extension is negotiated through the proxy.** The client's
`Sec-WebSocket-Extensions` offer — `permessage-deflate`, which browsers send by
default — is not passed to the server, so frames travel uncompressed and every
one the capture, `frameScript` and the plugins see is the one the ends wrote. The
applications do not notice; the wire carries more bytes. Upstream passes the offer
on and inflates a copy for its display. (Until 2026-09 this port passed it on and
did not keep a frame's "compressed" bit, so a compressing server's messages
arrived as binary noise.)

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

### Metadata and upstream-only infrastructure

| Operator(s) | Why / note |
|-------------|-----------|
| `G` | Upstream global plugin infrastructure has no equivalent in this port; it is not a request body/header operator or an importance marker |
| `style` | Metadata with no traffic rewrite; retained for console `style:` filtering. This does not promise identical visual rendering to the upstream UI |

### Simplified vs. upstream

whistle's plugin variables (`%name=…`) and its Node-object plugin API are not
implemented — plugins here are external HTTP servers speaking whix's own
protocol (see [`PLUGINS.md`](PLUGINS.md)). Template variables and `lineProps`
*are* implemented; see [`TEMPLATES.md`](TEMPLATES.md) and
[`LINE_PROPS.md`](LINE_PROPS.md) for exactly how far.
Patterns/operators outside the documented forms may parse but not behave exactly as
in upstream whistle.

Known gaps in the operator layer, deliberately left:

- **`@` includes of a plugin's rules are not implemented.** The two source
  shapes that name a plugin — `@whistle.<name>[/path]` and
  `@$<key>/…` — reach a plugin's own UI server upstream (`getRemoteRules`,
  `_original/lib/util/index.js:3271-3290`). Plugins here are external HTTP
  servers speaking this port's protocol and have no such endpoint, so the line
  is logged and contributes nothing. Every other source shape works, for every
  rules text — see
  [pulling in another rules text](#pulling-in-another-rules-text-).
- **A `${port}` in an `@` source resolves only once the proxy has bound.** It is
  answered from the *listening* port, which `--port 0` only settles after the
  socket exists, so a source written before that is fetched with the variable
  still in it — and says so in the log rather than fetching port 0. In practice
  this is unreachable: the first fetch happens after the bind.
- **A response with no declared charset is not sniffed.** When a `charset=` is
  present the response operators honour it — the body is decoded before the text
  transforms and re-encoded after, and injected values are written in that
  charset, as whistle does. When there is none, whistle reads the first 25 KB and
  guesses UTF-8 or GB18030; whix treats the body as UTF-8 and, if it is not,
  leaves it alone. So a non-UTF-8 page that never says so is rewritten by whistle
  and passed through here.
- **A request body's charset is not undone.** whistle wraps `reqReplace://` in the
  same decode/encode pair it uses for responses; whix works on the bytes, so
  the operator is a no-op on a non-UTF-8 request body.
- **An HTTP/2 request's `:authority` is forwarded as written.** Translating h2 to
  HTTP/1.1 for a plain-HTTP origin, this port sends the `Host` the client asked for; whistle
  sends the authority the tunnel was opened to instead, so a client that opens
  `CONNECT host:80` and then asks for `:authority: host` sees `host` here and
  `host:80` there. Both name the same server, and a rule matching on `Host` is
  unaffected — patterns are matched against the request URL, which carries the
  port either way.
- **A body-less request with a body-permitting method is framed differently.**
  When a client sends `POST` (or any method that may carry a body) with no
  `Content-Length` and no `Transfer-Encoding` at all, whistle forwards
  `content-length: 0` and whix forwards neither header. Both spell "no
  body" and every origin reads them the same way; the difference is Node's HTTP
  client against hyper's, not a rule. It is invisible on the ordinary proxy path,
  where the client's own library has already chosen a framing — it shows only
  inside a `CONNECT` tunnel carrying cleartext, where the bytes are whatever the
  client wrote.
- **A response trailer section only reaches clients that asked for one.** The
  origin's trailers and `trailers://` are both sent only when the client's request
  carried `TE: trailers` — hyper's HTTP/1 server drops the trailer section
  otherwise (`Conn::write_trailers`, hyper 1.10.1 `src/proto/h1/conn.rs:729-733`,
  from the `TE` header read at `conn.rs:328-332`). whistle sends them regardless.
  Nothing else about the response changes; `curl --raw -H 'TE: trailers'` shows the
  full behaviour.
- **`params://` into a body is buffered, not streamed.** whistle rewrites a
  multipart body part by part so an upload never lands in memory; whix has
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


### Where wproxy.org and whistle disagree

Places the official documentation states something whistle 2.10.8 does not do.
Each was measured against the running program, and **the program wins** — this
port follows whistle, not the prose. They are recorded because a reader who
arrived from those pages would otherwise think whix had the bug.

| The page says | whistle actually | Where |
|---|---|---|
| on an `OPTIONS` request `access-control-allow-headers` becomes `access-control-expose-headers` | exactly the inverse — `allow` on a preflight, `expose` otherwise | [`resCors`](#response-rewriting) above |
| a line-format value with no `: ` "splits at the first colon" | a value written on the rule line reaches the line parser only when it has an `=` in it, and then it is a query string, not lines. Without one it produces **nothing at all**: `reqHeaders://x-a:1` and `reqHeaders://bare` both set no header, and `urlParams://test1:1` adds no query — while the same words on a line of a `{value}` do become entries, because loaded content takes the other road. Measured five ways; whix matches | see "The three spellings of a data value, and the two roads" above |
| `ws://` / `wss://` / `tunnel://` "返回 502" for a plain HTTP request | it does, and the page is right — but only when the line is *read* as a destination. `127.0.0.1:8080 ws://host/x` is not: a bare host is no pattern to `indexOfPattern`, the `ws://` URL is, and the line swaps into "pattern `ws://host/x`, operator `host://127.0.0.1:8080`" (`_original/lib/rules/rules.js:1449-1467,:1774-1789`), which a plain request never matches | `cases.js`, the two "swaps into pattern and host" cases |
| `delete://pathname` "删除请求路径（不包含请求参数）" | it deletes the path and then **doubles the query** | already recorded under [Deleting](#deleting) |
| [`socks`](https://wproxy.org/docs/rules/socks.html) gives the default port as **443** | `1080`, from the one line that assigns all three — `isSocks ? 1080 : isHttpsProxy ? 443 : 80` (`_original/lib/inspectors/res.js:284`). The 443 looks copied from the `https-proxy` page | whix uses 1080; `src/proxy/upstream.rs` |
| [`enable`](https://wproxy.org/docs/rules/enable.html) lists `forceResWrite` beside `forceReqWrite`, one per side | there is no `forceResWrite` in the program. `forceReqWrite` is read on **both** sides — the response dump obeys the request-shaped name (`_original/lib/inspectors/req.js:604`, `res.js:1300`) | the flag table under [Flags](#the-flags-this-port-does-not-implement) |
| [`socks`](https://wproxy.org/docs/rules/socks.html), [`https-proxy`](https://wproxy.org/docs/rules/https-proxy.html) and others print `enable://captureIp` as the way to decrypt an HTTPS request to an IP | it is, but only once whistle is decrypting at all: `enable://captureIp` alone does not turn interception on, so on a default install the connection is relayed either way. `enable://capture` is the one that does both. Measured on both proxies with the console switch off and on | [Not decrypting a connection](#not-decrypting-a-connection) |
| [`auth`](https://wproxy.org/docs/rules/auth.html) form 2: a ```` ``` ```` block holding `username: admin` / `password: …`, referenced as `auth://{custom-key}` | the block's content *is* the value by the time `getAuthByRules` sees it, and it has no slash, so the colon splits it: the username becomes the literal `username` and the password the rest of the file. A **file** in that same format works, because a path has a slash and takes the other road. Measured on both proxies; whix matches | [`auth://`](#auth-in-four-spellings) above; `cases-docs.js` |

The `ws://` row is the one worth remembering: the page is right, and the obvious
way to test it is not — a bench case written as `<host:port> ws://…` is inert on
both sides and proves nothing about the rule it names.

The line-format row used to claim that whistle sets a header literally named
`x-a:1`. It does not; it sets nothing, and so does this port. That row was
itself a mis-measurement, in a table whose whole purpose is to record
mis-statements — which is worth leaving on the record rather than quietly
rewriting.


### `x-server` on a response the proxy made itself

Every response whistle generates rather than forwards carries `x-server`
(`wrapResponse`, `_original/lib/util/index.js:1080-1090`) — a `statusCode://`,
a `redirect://`, a `file://` mock, a preflight it answered. It says what a
mocked response otherwise leaves open: this came from the proxy, not the
origin.

whix does the same and writes `whix`, because it is not whistle.
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

A client can say it for one tunnel itself, with a request header on the
`CONNECT`: `x-whistle-policy: tunnel` (or `connect`, or `weakTunnel`) — whistle's
own convention, used by its plugins and by a whistle chained in front
(`_original/lib/tunnel.js:143-147`). It wins over `enable://capture`, as there.
The values asking for the opposite, `intercept` and `capture`, are not honoured:
with interception on (the default) they change nothing, and with it off the
tunnel is still relayed, where whistle would read it.

**The far end is reached before the client is told the tunnel is open.** When
the rule matches the address in the `CONNECT` itself (or interception is off, or
the header asked),
whix dials first and answers `200` only once the far end has answered, as
whistle does (`_original/lib/tunnel.js:637-695`). A name that does not resolve
or a port that refuses leaves the `CONNECT` with **no reply at all**: the
browser reports `ERR_TUNNEL_CONNECTION_FAILED`, and the console has a `CONNECT`
row at status 0 failed at `dns` or `connect`. A rule that matches only the name
in the ClientHello is decided after the `200` has gone out, so there the client
sees the tunnel open and then close, with the same row.

**Two narrower flags, one for each half of the connections.** The half is decided
by whether the ClientHello named a server, which is a fact about the client and
not about the rule:

| Flag | Relays |
|---|---|
| `disable://captureSNI` | connections whose ClientHello **named** a server |
| `disable://captureNoSNI` | connections whose ClientHello named **nothing** |

**And one default nobody has to write.** A tunnel opened to a **bare IP address**
whose ClientHello named nothing is *not* decrypted — `net.isIP(servername) &&
!isCaptureIp()` (`_original/lib/https/index.js:1287`). TLS forbids an IP literal
in SNI, so `https://10.0.0.5/` is exactly that shape and goes through untouched.
Three spellings ask for it back, and one refuses even then:

```
10.0.0.5   enable://capture      # …or enable://captureIp, or enable://captureIP
10.0.0.5   enable://capture disable://captureIp   # still relayed
```

`enable://capture` is the general one: it is also what turns interception on at
all in whistle, whose global switch starts off. Here interception starts on, so
the flag only ever matters for this row. All of it is measured against whistle
2.10.8 — `tests/differential/https-bench.js` compares **who signed the
certificate** for twelve shapes of connection, which is the only way to see the
difference between a connection that was read and one that was passed through.

> whistle intercepts a **local** hostname whatever the rules say, so
> `disable://intercept` on `localhost` is ignored there and honoured here. See
> [`CERTIFICATES.md`](CERTIFICATES.md#which-connections-are-read-at-all).


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
`responseBody` hook do not apply. The session says so: its `unapplied` list
names each operator that did not run, with the kind `body-over-limit` and the
limit ([`API.md`](API.md#没生效的规则)), and the console's Rules tab marks
them "not applied". A `WARN` names the request too. The same 800 MB download
now peaks at **33 MB** and arrives byte-complete.

The limit counts bytes on the wire, and **undoing a compression counts too**: a
gzip that would inflate past the limit is not inflated. It is forwarded as it
arrived, as `decoded-over-limit` — a 16 MiB gzip of one repeated byte is
gigabytes once inflated. A body whose `content-encoding` will not undo at all —
bytes that are not what the header says (`undecodable`), or `zstd` and stacked
codings (`unsupported-coding`) — is also forwarded untouched rather than have
the operators run over compressed bytes: a `resAppend` there wrote plain text
after the end of a gzip stream, which no client could read.

`--body-rewrite-limit` is reported by `/api/status` (`body_rewrite_cap`) and on
the console's Status pane, and an embedder sets it with `body_rewrite_cap`.
`enable://resMergeBigData`, or `lineProps://enableBigData` on the `resMerge://`
line, raises one request's limit to at least 16 MiB — which only matters when
the knob was set lower.

This is one of the few places where the port needs a knob upstream does not,
and the reason is architectural rather than a preference — see
[`ROADMAP.md`](ROADMAP.md).


### 跨域 mock：自动 CORS

用 `file://`（以及 `rawfile`/`tpl`/`dust`/`jsonp` 和它们的 `x`/`xs` 变体）mock 一个
API，而发起请求的页面在**另一个源**上时，whistle 会自己补上 CORS 头 —— 否则浏览器
在任何代码看到响应之前就把它拒了。whix 现在同样如此
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
**16 MB** by `enable://reqMergeBigData` or by `lineProps://enableBigData` on the
`reqMerge://` line (`MAX_REQ_SIZE` / `BIG_MAX_REQ_SIZE`,
`_original/lib/inspectors/req.js:19-20,:163,:564`), and whix does the same.

Past the ceiling the request is **not** failed and **not** truncated: the body
streams on to the origin byte for byte, and only the rewriting stops —
`reqBody`, `reqReplace`, `params`, `reqWrite`/`reqWriteRaw` and `reqSpeed` do not
apply. That is upstream's `interrupt` (`handleParams`, `req.js:169-185`), and it
is the right failure for a debugging proxy: traffic must not be damaged by the
inspection of it. whix records it on the session — `unapplied`, kind
`request-body-over-limit`, naming the operators (`params://` only when it would
have rewritten a form or JSON body) — and logs a `WARN`, so a rule that stopped
applying above some size does not look like a rule that never matched. A
request body whose `content-encoding` will not undo reaches the origin as sent,
the same way.

`b:` body filters read the body too, in order to decide *which* rules apply, so
they cannot consult a rule for the raised ceiling — they always use the plain
2 MB and match on the prefix they read, as upstream's `resolveBodyFilter` does.


### Event streams

A `text/event-stream` response is never collected. Collecting one would not slow
it down, it would withhold it: the body ends when the server decides, which for
SSE is typically never, so the client would receive nothing at all.

`resReplace://` still applies. It is the one body operator that does not need the
whole body — it needs a window — so it travels with the stream, substituting as
events arrive. whix holds back only a tail (just enough that a match
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

The session names what did not run, as `unapplied` with the kind
`event-stream`: `resMerge`, the typed `html*`/`js*`/`css*` families,
`resSpeed`, `resScript`, `weinre`, `resWrite`/`resWriteRaw`, `trailers` and
`enable://gzip`, and `resReplace` when the stream is compressed. The four that
travel with a stream are not named, because they ran.


## Origin certificate verification

whistle does **not** verify the origin server's certificate: `rejectUnauthorized`
is `false` by default and only `--safe` turns it on
(`_original/lib/config.js:74`). whix inverts that default — it verifies,
and `--insecure-upstream` opts out:

```bash
whix --insecure-upstream      # accept self-signed / private-CA origins
```

Without it, a self-signed or private-CA origin returns **502** where whistle
would have proxied it.

The inversion is deliberate and is the one place this port does not reproduce
upstream's default. Everywhere else, fidelity wins — a rules file must resolve
identically in both implementations. But a debugging proxy that silently accepts
any upstream certificate cannot tell its user when the connection it is
inspecting has itself been intercepted, and that is a property worth keeping by
default and spending a flag on.
