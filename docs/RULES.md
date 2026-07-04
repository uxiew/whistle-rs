# Rules reference

whistle-rs uses whistle's rule syntax. This document is the complete reference for
the subset the Rust core understands. For the original, exhaustive whistle rule
documentation see <https://wproxy.org>.

- [File format](#file-format)
- [Patterns](#patterns)
- [Operators](#operators)
- [Precedence](#precedence)
- [Cookbook](#cookbook)
- [Compatibility notes](#compatibility-notes)

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
list** at parse time (so rule files load without error), but only the operators below
have runtime behaviour today. The rest are resolved and exposed on the matched rule
set, ready to be wired up — see [Compatibility notes](#compatibility-notes).

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

```
example.com   reqHeaders://x-token=abc
example.com   reqHeaders://{"x-a":"1","x-b":"2"}
example.com   ua://MyBot/1.0
api.test/*    method://POST
```

### Response rewriting

| Operator | Value | Effect |
|----------|-------|--------|
| `replaceStatus` / `statusCode` | status number | Replace the upstream response status |
| `resHeaders` | `name=value`, `name:value`, or `{json}` | Set/replace response headers (empty value deletes). Accumulates across lines. |
| `resType` | MIME type | Set the response `Content-Type` |
| `resCors` | origin or `*` | Set `Access-Control-Allow-Origin` |

```
example.com        resHeaders://x-mitm=intercepted
example.com/api    resCors://*
cdn.example.com    resType://application/javascript
example.com/404    replaceStatus://200
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

## Compatibility notes

- **Parsed but not yet applied at runtime.** These operators load and resolve
  correctly (so mixed rule files work), but do not change traffic yet: upstream
  proxying (`proxy`, `http-proxy`, `https-proxy`, `socks`, `internal-proxy`,
  `https2http-proxy`, `http2https-proxy`), `pac`, `weinre`, `plugin`, body rewriting
  (`css/html/js*`), `resScript`/`frameScript`, `filter`/`ignore`,
  `attachment`, `forwardedFor`, delays (`reqDelay`,
  `resDelay`) and speeds (`reqSpeed`, `resSpeed`), `cache`, `cipher`, `sniCallback`.
  Adding runtime behaviour means extending `src/proxy/apply.rs`.
- **Simplified vs. upstream.** whistle's `filter://`/`ignore://` inline conditions,
  template variables (`${…}`), plugin variables (`%name=…`), value references
  (`{key}`), and the full `lineProps` system are not implemented. Patterns and
  operators outside the forms documented above may parse but will not behave exactly
  as in upstream whistle.

If a rule doesn't do what you expect, run with `-v` (debug logging) — each request
logs its resolved destination or short-circuit decision.
