# Cookbook

[项目说明](../README.md) · [中文版本](COOKBOOK.zh-CN.md) · [规则参考 / Rules reference](RULES.md)

Current verification: [STATUS.md](STATUS.md). For local-only debugging add
`-H 127.0.0.1 --no-persist` to startup commands unless a recipe explicitly needs
LAN access or history. See [OPERATIONS.md](OPERATIONS.md) before sharing the proxy.

Task-oriented recipes. Each one is a problem you actually have, the rules that
solve it, and the reason it is written that way. [`RULES.md`](RULES.md) is the
reference for every operator; this file is the part you read first.

Every recipe here was run against the proxy before it was written down.

- [Before you start](#before-you-start)
- [Serve a site from a local dev server](#serve-a-site-from-a-local-dev-server)
- [Mock an API endpoint](#mock-an-api-endpoint)
- [Change a request or a response in flight](#change-a-request-or-a-response-in-flight)
- [Simulate a bad network](#simulate-a-bad-network)
- [Scope a rule precisely](#scope-a-rule-precisely)
- [Debug a phone or another device](#debug-a-phone-or-another-device)
- [Capture, export and replay](#capture-export-and-replay)
- [Drive it from a script, or from an agent](#drive-it-from-a-script-or-from-an-agent)
- [Embed the proxy in your own program](#embed-the-proxy-in-your-own-program)
- [When a rule does not fire](#when-a-rule-does-not-fire)

---

## Before you start

```bash
cargo build --release
./target/release/whistle-rs -p 8899 -r rules.txt
```

Two different things are listening on that one port, and confusing them is the
most common early mistake:

| You want | You do |
|----------|--------|
| to send traffic **through** the proxy | `curl -x http://127.0.0.1:8899 http://example.com/` |
| to talk **to** the proxy — console, PAC, CA, JSON APIs | `curl --noproxy '*' http://127.0.0.1:8899/api/status` |

`--noproxy '*'` matters because a shell that has `http_proxy` set will otherwise
send even `http://127.0.0.1:8899/` through whatever that variable names. The
symptom is a `502` carrying a `Proxy-Connection` header.

Open <http://127.0.0.1:8899/> in a browser for the console: a request table, a
detail panel, and a rules editor that highlights **which token the proxy will
match on**.

While you are iterating, `--no-persist` keeps captured traffic out of
`~/.whistle-rs`, and `--dir` puts the root CA and rule groups somewhere
disposable:

```bash
./target/release/whistle-rs -p 8899 -r rules.txt --no-persist --dir /tmp/w
```

---

## Serve a site from a local dev server

The rule whistle exists for. One token, no operator:

```
www.example.com       http://localhost:5173
```

Now every request for `www.example.com` is answered by your Vite/webpack/whatever
dev server, with the real hostname still in the address bar — so cookies,
`localStorage`, CORS origins and OAuth redirect URIs all keep working, which is
exactly what `localhost:5173` in the address bar breaks.

### The path comes along, and that surprises people

Whatever the pattern did not consume is appended to the destination:

| rule | request | forwarded to |
|------|---------|--------------|
| `example.com http://localhost:5173` | `/a/b?q=1` | `http://localhost:5173/a/b?q=1` |
| `example.com http://localhost:5173/base` | `/a/b?q=1` | `http://localhost:5173/base/a/b?q=1` |
| `example.com/api http://dev.local/v2` | `/api/users?x=2` | `http://dev.local/v2/users?x=2` |

Read the third row twice. The pattern's `/api` is **consumed**, not kept: the
part of the path the pattern matched is replaced by the destination's path.
`/api/users` becomes `/v2/users`, not `/v2/api/users`. If you wanted the prefix
kept, put it on the destination (`http://dev.local/v2/api`).

To stop the concatenation and always hit one exact URL, wrap the value in `< >`:

```
example.com/api    http://<dev.internal/fixed>
```

### `http://…` moves the Host header, `host://` does not

Both point the request somewhere else. Only one of them is visible to the server
that answers:

| | socket | `Host:` header | path | scheme |
|---|---|---|---|---|
| `example.com http://localhost:5173` | moves | **becomes `localhost:5173`** | rewritten | moves |
| `example.com host://127.0.0.1:5173` | moves | **stays `example.com`** | kept | kept |

Use `host://` when the server on the other end routes by `Host` — a staging box
behind nginx, a CDN origin, anything with virtual hosts. Use the bare URL when
you are pointing at a dev server that does not care.

```
# hit the staging machine, but keep the hostname so its vhost matches
www.example.com     host://10.0.0.9

# same host, different port
.example.com        host://:8443

# use this address if something is listening, otherwise carry on to the real one
www.example.com     xhost://10.0.0.9
```

A bare `127.0.0.1:5173` is shorthand for `host://127.0.0.1:5173` — but only
because it is an **IP**. `localhost:5173` is a *name*, and a name is read as a
forwarding destination, so it moves the `Host` header where the IP form does
not. That asymmetry is upstream's (`net.isIP`), and it is easy to trip over.

### A mock has to be written above the forward

`file://`, `redirect://`, `statusCode://`, the template family and a bare
destination URL all compete for **one slot**. The first line to fill it answers,
and the rest do not apply — so this does *not* work:

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true})     # never served
```

The forward is written first, so it wins for `/api/flags` too and the request
goes to the dev server. Put the narrower rule above the broader one:

```
example.com/api/flags  file://({"beta":true})
example.com            http://localhost:5173
```

…or mark it important, which puts it first whatever the line order:

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true}) lineProps://important
```

The same family shares one slot **within a line** too, and there the winner is
whichever was written first:

```
example.com  file://({"beta":true})  statusCode://204   # serves the file
example.com  statusCode://204  file://({"beta":true})   # answers 204
```

Operators that are *not* in that family — `resHeaders://`, `reqHeaders://`,
`resDelay://`, filters — accumulate normally and do not need this treatment.

### When the client cannot be given a proxy

Some clients have no proxy setting — an SDK, a service in a container, a
WebSocket library with a fixed address. Send the request straight to the proxy's
port with the real name in `Host`, and the rules take it as if it had come
through the proxy:

```bash
curl -H 'Host: api.example.com' http://127.0.0.1:8899/v1/users   # api.example.com's rules apply
```

A hosts-file line pointing the name at this machine, with the proxy started on
`-p 80`, does the same for every client on the machine (port 80 needs admin
rights).

Two things to know:

- a `Host` that is an IP address, `localhost` or a console hostname gets the
  **console**, not the rules;
- a name no rule sends elsewhere, and which resolves back to this machine, gets a
  `302` to the console's address — no loop, and no console under that name.

---

## Mock an API endpoint

Three places a mock body can live. All three work; which one you want depends on
whether the mock should travel with the rules.

### In the rule itself

Parentheses mean "this **is** the content", not "here is where to find it":

```
api.example.com/health   file://({"status":"ok"})   resType://json
```

Good for one-liners. There is no way to put a newline in it, and — see below —
no way to put a **space** in it either.

### In a fenced block in the same rules file

A ` ``` ` block declares a named value that the rest of the file can reference.
The rule and the JSON it serves stay in one file, which is what you want when
the rules file is the artefact you share:

````
api.example.com/users    file://{users.json}

``` users.json
[
  {"id": 1, "name": "Ada"},
  {"id": 2, "name": "Grace"}
]
```
````

The opening fence is three or more backticks followed by **one** name and
nothing else; the closing fence must be the same number of backticks. A block
whose body contains a shorter fence survives if you open with a longer one.

### In a file on disk

```
api.example.com/users    file:///Users/me/mock/users.json
```

This is the one that gets the `Content-Type` right for free: whistle-rs guesses
it from the file extension. The other two have no filename to guess from and
default to `text/html; charset=utf-8`, so add `resType://json` when the client
is fussy — a `fetch().then(r => r.json())` will not care, but a strict client
will.

The file goes out byte for byte, never re-encoded — a GBK page or an image works.
So does a file read by `resBody:///path`, `resPrepend://`, `resAppend://` and the
three request-side ones.

A directory works too, and the request path is appended to it:

```
static.example.com       file:///srv/static
# /js/app.js  ->  /srv/static/js/app.js
```

### Statuses, and why `statusCode://` eats your body

`statusCode://` answers with that status and an **empty body**, and it beats
`file://` when both are on the same line:

```
api.example.com/gone     statusCode://410               # 410, no body
api.example.com/created  file://({"id":7})  statusCode://201   # 201, NO body
```

To serve a body *with* a non-200 status, use `replaceStatus://`, which changes
the status of a response rather than manufacturing one:

```
api.example.com/created  file://({"id":7})  replaceStatus://201  resType://json
# -> 201 Created, {"id":7}
```

### A mock that reads the request

`tpl://` renders `${…}` variables against the live request. There is no template
*engine* — no loops, no conditionals; upstream never had one either — but the
variable table is useful:

````
api.example.com/greet    tpl://{greet.json}  resType://json

``` greet.json
{"hello": "${query.name}", "ua": "${reqHeaders.user-agent}"}
```
````

```
$ curl -x http://127.0.0.1:8899 'http://api.example.com/greet?name=world'
{"hello": "world", "ua": "curl/8.7.1"}
```

The full variable table, the `.replace(a,b)` modifier and the two render passes
are in [`TEMPLATES.md`](TEMPLATES.md). One gate to know about: the file must
contain at least one `{…}` **with no whitespace inside the braces**, or neither
pass runs.

### Rewrite the real response instead of replacing it

When you want the origin's answer with one thing changed, keep the request going
upstream and patch what comes back:

```
api.example.com/config   resMerge://{"env":"staging","featureX":true}
```

`resMerge://` deep-merges into the JSON body. `{"env":"production","flag":false,"n":1}`
comes back as `{"env":"staging","featureX":true,"flag":false,"n":1}` — the keys
you did not name are untouched. For non-JSON bodies, `resReplace://from=to`
substitutes text.

To replace the body outright while still letting the request reach the origin —
so the headers, the status and the timing are the real ones — use `resBody://`:

```
api.example.com/config   resBody://({"env":"staging"})   resType://json
api.example.com/config   resBody://{config.json}
```

The parenthesised form means "the value **is** this content", and it works on
**every** operator, not only the body family: `reqBody://(Hello)` sends five
bytes, brackets stripped.

Two of `file://`'s three value forms carry over; the third does not.
`resBody:///Users/me/mock.json` sends the **path** as the body — operator values
are not loaded from a file or a URL here, so a mock that lives on disk has to be
served by `file://` (which short-circuits the request) or pulled in as a value.

Any response-body operator also stops the client's conditional request from
being answered `304 Not Modified` with no body — otherwise the rewrite would
vanish intermittently, depending on what the browser already had cached.

---

## Change a request or a response in flight

### Headers

```
api.example.com    reqHeaders://x-token=abc&x-env=dev
api.example.com    resHeaders://x-mitm=intercepted
api.example.com    delete://reqHeaders.user-agent
```

Lines accumulate: several `reqHeaders://` lines all apply, and when two of them
name the same header the **first** one wins.

**A value cannot contain a space.** Rule lines are split on whitespace, so

```
api.example.com    reqHeaders://authorization=Bearer secret
```

sets `authorization: Bearer` and then reads `secret` as a second operator — a
bare word, which is a *forwarding destination*, so your request is sent to a
host called `secret`. Percent-encoding does not help; `%20` arrives literally.
The fix is a named value, referenced with `${…}`:

````
api.example.com    reqHeaders://authorization=${bearer}

``` bearer
Bearer eyJhbGciOi...
```
````

or from the command line:

```bash
whistle-rs --value 'bearer=Bearer eyJhbGciOi...' -r rules.txt
```

`--value` beats a fenced block of the same name in the rules file, which is what
makes it useful for swapping one value for a run. A value saved in the console's
Values pane does **not**: the rules text's own block wins, as upstream has it.

Note the two brace forms. `{name}` replaces the **whole** operator value
(`file://{users.json}`); `${name}` substitutes **inside** one
(`reqHeaders://authorization=${bearer}`). You want `${name}` for headers.

To delete rather than set, use `delete://` — `reqHeaders://x-a=` sends an
*empty* header, it does not remove one.

### Cookies

```
api.example.com    reqCookies://sid=42
api.example.com    resCookies://{"sid":{"value":"abc","path":"/","httpOnly":true,"maxAge":600}}
api.example.com    delete://reqCookies.tracking
```

`reqCookies://` merges into whatever the client sent (`old=1` becomes
`old=1; sid=42`). Cookie **attributes** need the JSON form — the `k=v` form has
nowhere to put them, and a literal `; Path=/` would be split on the space and
percent-encoded into the value. The JSON above emits:

```
set-cookie: sid=abc; Expires=…; Max-Age=600; HttpOnly; Path=/
```

`resHeaders://set-cookie=…` **merges** with the origin's cookies by name rather
than replacing the header, so setting `sid` leaves the origin's `csrf` alone.

### A field in a JSON body

Response side, deep merge:

```
api.example.com/me    resMerge://{"role":"admin"}
```

Request side, into whatever body shape the request has:

```
api.example.com    params://uid=42          # merged into a JSON or form body
api.example.com    urlParams://trace=1      # always the query string
api.example.com    delete://reqBody.password
```

`params://` addresses the body **or** the query string, never both: a JSON,
form-urlencoded or multipart body takes it, and anything else sends it to the
query string. `urlParams://` is unconditional. See
[`RULES.md#where-params-lands`](RULES.md#where-params-lands) for the table.

### CORS

For a browser talking to an API that does not allow your origin:

```
api.thirdparty.com   resCors://*
```

`resCors://enable` echoes the request's own `Origin` and adds
`Access-Control-Allow-Credentials: true`, which is what you need when the call
sends cookies.

Preflights need a little more care. On an `OPTIONS` with `*` or `enable`,
whistle-rs echoes the requested method back as **`Access-Control-Allow-Method`** —
singular, which is not a real CORS header. That is upstream's typo, reproduced
so the two implementations emit the same bytes; browsers ignore it. Name the
methods yourself, on a second line:

```
api.thirdparty.com   resCors://*
api.thirdparty.com   resCors://methods=GET,POST,PUT&headers=x-token&maxAge=600
```

Both lines fold into one set of headers. If the origin does not handle `OPTIONS`
at all, answer the preflight locally instead of forwarding it:

```
api.thirdparty.com   resCors://*
api.thirdparty.com   statusCode://204   includeFilter://m:OPTIONS
```

The filter keeps the short-circuit off your real `GET`s.

### Method, URL and user-agent

```
api.example.com      method://POST
api.example.com/api  urlReplace://v1=v2            # /api/v1/x -> /api/v2/x
example.com          ua://Mozilla/5.0 (iPhone…)    # …but see the space rule above
example.com          referer://https://example.com/
```

---

## Simulate a bad network

### Delay

```
slow.example.com     reqDelay://500      # wait before forwarding
slow.example.com     resDelay://2000     # wait before answering
```

**Always milliseconds.** Delays use whole-value numeric conversion, not
`parseInt`/`parseFloat`: `resDelay://500ms` and `resDelay://1s` do not delay.
Write `resDelay://500` or `resDelay://1000`. Speed values have different parsing
rules; do not infer delay behaviour from `resSpeed`.

`reqDelay://` runs before every short-circuit, so it delays a `file://` mock too
— which is the whole point of pairing them.

### Throttle

```
slow.example.com     resSpeed://800      # ~100 kB/s down
slow.example.com     reqSpeed://200      # ~25 kB/s up
```

**The unit is kilobits per second, not kilobytes.** `resSpeed://800` is
800 kbit/s ≈ 100 kB/s; a 64 KiB response takes about 0.65 s. This port read the
value as kilobytes until recently, which made every throttle 8.192× too fast —
if you have rules written against the old behaviour, multiply them by 8.

Rough dial:

| you want | write |
|----------|-------|
| 2G-ish (~50 kbit/s) | `resSpeed://50` |
| 3G-ish (~1.6 Mbit/s) | `resSpeed://1600` |
| DSL (~8 Mbit/s) | `resSpeed://8000` |

A speed cap buffers the body and re-emits it in paced chunks, so it forces a
known-length response to chunked transfer.

### Fail

```
flaky.example.com    enable://abort         # destroy the connection, no response
api.example.com      statusCode://503       # a clean 503
api.example.com      statusCode://500  includeFilter://chance:5%   # 5% of calls
```

`enable://abort` destroys the socket rather than answering — the client sees a
connection reset (curl exit 52), which is the failure mode a timeout-handling
code path actually needs to see. `statusCode://` is the polite version.

`chance:` is sampled per request, so it is the tool for "does the retry logic
work" rather than "is this endpoint down".

### Stop waiting on a host that never answers

A destination that drops packets rather than refusing them holds the request for
as long as the operating system's TCP timeout, which is over a minute. `-t` caps
the wait:

```bash
whistle-rs -t 3000 -r rules.txt      # give up on a connection after 3s
```

Two things about it are not obvious from the flag:

- **It bounds connection *establishment* only.** A connection that did connect is
  never cut short, so a slow response, an SSE stream or a long poll is
  unaffected. This is not a "kill the request after N ms" switch.
- **It only ever tightens.** There is a hard 16-second ceiling underneath, so the
  `360000` default really means 16 seconds and `-t` matters only when you set it
  *below* that. `-t 0` is clamped to 1 ms rather than meaning "no limit".

To make a *particular* request slow rather than the whole proxy patient, use
`reqDelay://` — `-t` is a safety net, not a simulation tool.

### What throttling will not do

Streaming behaviour is operator-specific, not a blanket refusal of all SSE
rewrites. `src/proxy/restream.rs` provides incremental text replacement, including
`resReplace` on event streams; whole-body transformations still need different
handling. See the operator's entry in [RULES.md](RULES.md) for its scope.

Non-event-stream rewrites that use the buffered path can delay the first byte
until enough input arrives or the rewrite cap is reached. `--body-rewrite-limit`
and `--body-preview-limit` are separate limits; a body over the rewrite limit is
forwarded unchanged rather than rewritten. Delay and speed rules do not make a
whole-body transformation streaming.

**To see whether an operator actually ran**, open the request's Rules tab: an
operator the proxy did not carry out — over the limit, on an event stream, under
a compression it could not undo, a plugin hook that failed, a `cipher://` it
could not use — is struck through and marked "not applied", with the reason.
The same list is `unapplied` in `/sessions.json`; see
[`API.md`](API.md#没生效的规则).

---

## Scope a rule precisely

### Filters

`includeFilter://` is the only spelling that *includes*. `filter://` and
`ignore://<condition>` both **exclude**.

```
# only POST
api.example.com   host://10.0.0.1     includeFilter://m:POST

# only requests carrying a canary header (matched by containment)
api.example.com   resHeaders://x-canary=1   includeFilter://reqH.x-canary:on

# everything except the health check
api.example.com   host://10.0.0.1     excludeFilter://*/health

# only this client
api.example.com   resHeaders://x-a=1  includeFilter://clientIp:192.168.1.44

# a fraction of traffic
api.example.com   statusCode://503    includeFilter://chance:5%
```

Include filters are OR-ed; one matching exclude filter vetoes the rule whatever
the includes said. Conditions can also test the **response** — `s:404`,
`resH.content-type:json`, `serverIp:` — which is resolved on a second pass after
the response head arrives.

A filter's URL pattern always reads as if it were `^`-prefixed, which is why
`excludeFilter://*/health` wildcards the path while the same token as a rule
pattern would not.

### `lineProps://important` — jump the queue

```
example.com    host://1.1.1.1
example.com    host://2.2.2.2  lineProps://important   # this one wins
```

Important rules are resolved before normal ones, whatever their line order. It
is the escape hatch for "my narrow rule is below a broad one and I do not want
to reorder the file".

`$` is **not** this. It is exact matching — `$example.com` names the site root
and nothing under it — and it carries no precedence at all, in whistle or here.

### `ignore://` — carve a hole in a broad rule

```
.example.com          host://10.0.0.1
static.example.com    ignore://host      # this subdomain keeps its real address
example.com/health    ignore://all       # this path bypasses every rule
```

`ignore://` names **protocols** to drop from the resolved set. If what follows
looks like a filter condition instead (it contains a `:`, `.` or `=`), it is
read as an exclude filter — the two readings cannot collide.

### Rule groups — switch a whole set on and off

Several named rule sets live alongside the default one. In the console they are
the source list on the left, and double-clicking one toggles it. Over HTTP:

```bash
curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"name":"staging","text":"api.example.com host://10.0.0.9\n"}' \
     http://127.0.0.1:8899/api/rule-groups

curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"name":"staging"}' http://127.0.0.1:8899/api/rule-group/toggle
# {"ok":true,"enabled":false}

curl --noproxy '*' http://127.0.0.1:8899/api/rule-groups
# [{"enabled":true,"name":"default","rules":1},{"enabled":false,"name":"staging","rules":1}]
```

Groups persist to `<storage_dir>/rules/` and come back on restart. A disabled
group contributes nothing — not even the values its fenced blocks declare. And
an *enabled* group's fenced blocks are its own: a `{name}` written in one group
is answered by that group's block, never by another's, so two groups may each
carry a mock called `mock.json` without either shadowing the other.

`DELETE /api/rule-group` removes a named group. It **refuses `default`**, which
is the group `GET`/`POST /api/rules` reads and writes and the one the console
opens on; switching it off is `POST /api/rule-group/toggle` with that name, and
the text stays where you can get it back. `POST /api/rule-groups` likewise
refuses a name that is already taken (`400 group already exists`) — changing a
group's text is `POST /api/rule-group/update`.

**Named groups outrank the default one.** Every enabled named group is resolved
first, in list order, and the default group last — whistle's own order, and the
reason its console lists Default at the bottom. So a `staging` group is the place
to put the overrides you switch on and off.

### Pull rules in from elsewhere

```
@/etc/whistle/team.rules          # a line starting with @ includes that file
@https://intra/rules.txt          # …or that URL
```

This works wherever the rules came from — the console's editor, `POST
/api/rules`, a named group, `-r`/`--rule`, an imported bundle. The lines are
spliced in **where the `@` line stands**, so a rule above it still wins and a
rule below it still loses.

Two things you will want to know. The line you typed stays the line you typed:
the console shows `@…`, not the file's contents, and saving does not bake them
in — so to check whether an include landed, watch the rule *count*:

```bash
curl --noproxy '*' http://127.0.0.1:8899/api/rule-groups
# [{"enabled":true,"name":"default","rules":1}]   ← before the fetch
# [{"enabled":true,"name":"default","rules":9}]   ← after it
```

And each source is **re-read on a timer** — a file every 5 s, a URL every
10–30 s — so a shared team rules file takes effect without anyone restarting
anything. A fetch that fails keeps the last text that worked and says so in the
log; it never quietly empties your rules.

The line must be *only* `@` and the source: `@team.rules` (relative),
`@ /etc/x` (a space after the `@`) and `example.com @/etc/x` (a pattern in
front — that is `G://`) are not includes.

For rules that should apply to **some requests only**, this is the wrong tool:
use `rulesFile://` for a file or `rule://` for a named value, both of which are
read per matching request rather than pulled into the file as text.

```
example.com   rulesFile:///etc/whistle/team.rules
example.com   rule://{teamRules}
```

---

## Debug a phone or another device

### 1. Make the proxy reachable

whistle-rs listens on `127.0.0.1` by default — this machine only — so a phone
has to be let in. Set a console login first: anyone who can reach the port can
open the console, and the rules it edits read and write files on this machine.

```bash
whistle-rs -H 0.0.0.0 -n admin -w "$PASSWORD"
```

Then find your LAN address:

```bash
ipconfig getifaddr en0        # macOS
ip -4 addr show scope global  # Linux
```

Everything below assumes `192.168.1.5:8899`. There is no proxy authentication
or IP allow-list: on a network you do not control, a firewall decides who may
use it ([`OPERATIONS.md`](OPERATIONS.md)).

### 2. Point the device at it

Manually: Wi-Fi settings → the network → HTTP proxy → Manual →
`192.168.1.5`, port `8899`. Set it for **both** HTTP and HTTPS.

Or use the PAC file, which several platforms accept where a manual proxy is
awkward:

```
http://192.168.1.5:8899/proxy.pac
```

The PAC is generated from the `Host` header of the request that fetched it, so
whatever address the device used to reach the page is the address it will be
told to proxy through. Fetching it from the device itself is therefore the
reliable way to get it right.

### 3. Install the root CA, or you will only see `CONNECT`

Without a trusted CA the device refuses the certificate whistle-rs shows it,
and all you get is a `CONNECT` row tagged `client-tls` — "the client refused
this proxy's certificate" — with nothing inside it. Open this on the device:

```
http://192.168.1.5:8899/rootCA.crt
```

Then trust it. The per-platform steps — including iOS's two-step
install-then-*enable-full-trust*, which is where most people stop too early, and
Android 7+'s user-store restriction — are in
[`CERTIFICATES.md`](CERTIFICATES.md). Firefox has its own store and ignores the
system one.

Verify from your laptop first, where the failure modes are easier to read:

```bash
curl -x http://127.0.0.1:8899 --cacert ~/.whistle-rs/certs/root.crt \
     https://example.com/ -D - -o /dev/null
```

### 4. Point the device's traffic at your laptop

Now the rules are the same as any other recipe. The one you want first is
usually:

```
www.example.com     http://192.168.1.5:5173
```

Note the LAN address, not `localhost` — the destination is dialled by the
**proxy**, so `localhost` would be the machine running whistle-rs. That happens
to be right when the dev server is on the same laptop, and wrong the moment it
is not.

### Leave one host alone

Certificate-pinned apps break when you intercept them, and the useful answer is
usually to stop intercepting that one host rather than to give up:

```
pinned.example.com    sniCallback://no-mitm
```

`no-mitm` is a built-in plugin that declines interception; the connection is
relayed byte-for-byte. It is still *routed* by its rules — `host://` and the
proxy family apply — but nothing inside it is read: the capture has one
`CONNECT` row for it, with `(tunnel)` in the Policy column, and no requests.

### Route HTTPS without decrypting it, and skip the certificate entirely

Sometimes you do not need to read the traffic — you need to *send it somewhere
else*. Pointing a device's TLS at a staging box, or just learning which hosts an
app talks to, does not require a MITM, and not requiring one means there is no
certificate to install on the device at all:

```bash
whistle-rs -p 8899 --no-intercept-https -r rules.txt
```

```
secure.example.com   host://10.0.0.9
```

What you keep and what you give up, both measured against a self-signed origin:

| | with interception | `--no-intercept-https` |
|---|---|---|
| `host://` and the proxy family | routed | **routed** |
| certificate the client sees | whistle-rs's, signed by its root CA | **the origin's own** |
| root CA must be installed | yes | **no** |
| `resHeaders://` and every other content operator | applied | **not applied** |
| appears in the capture | every request | **one `CONNECT` row per connection**: the host, where it was routed, how long it stayed open — nothing inside it |
| a self-signed origin | `502` unless `--insecure-upstream` | fine — the *client* decides whether to trust it |

The last row is the one that catches people out in the other direction. With
interception on, whistle-rs verifies the origin's certificate itself and a
self-signed origin is a `502`; with interception off there is nothing for the
proxy to verify, because the TLS session is between the client and the origin
and the proxy only moves bytes.

`sniCallback://no-mitm` above is the per-host version of the same thing. Reach
for the flag when you want it for everything, and for the rule when one pinned
host is the problem.

---

## Capture, export and replay

The console at <http://127.0.0.1:8899/> is the interactive view. Everything it
shows is also an endpoint, which is what you want for scripting. All of these
are **direct** requests, not through the proxy:

| Endpoint | Returns |
|----------|---------|
| `GET /sessions.json` | every captured transaction: id, method, url, status, target, bytes up/down, duration, and **which rules matched it** |
| `GET /session.json?id=N` | one transaction with its request/response headers and body previews |
| `GET /sessions.json?after=N` | only the transactions newer than `N`; a row with `open: true` is still receiving its response |
| `GET /api/sessions/search?c=b:…` | the ids whose headers (`h:`) or bodies (`b:`) match, searched by the proxy over everything it holds |
| `GET /frames.json?id=N` | the WebSocket frames of connection `N`, both directions |
| `GET /sessions.har` | everything as a HAR 1.2 file |
| `GET /api/status` | ports, TLS posture, root CA path, rule count, registered plugins. A cross-origin browser fetch from an origin not on `--allow-origin` gets `version` and `port` only — see [`CLI.md`](CLI.md#calling-the-console-from-another-page) |
| `POST /api/sessions/clear` | drop the capture from memory (persisted history returns after a restart) |
| `POST /api/sessions/purge` | drop the capture and delete the persisted history |

```bash
# a table of what has been seen
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
for s in json.load(sys.stdin): print(s["status"], s["method"], s["url"])'

# a HAR you can drag into Chrome DevTools
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.har -o capture.har
```

Body previews are bounded — 16 KB by default, `--body-preview-limit` to change
it. `gzip`/`deflate`/`br` bodies are decoded for viewing, and the capture is a
streaming tee, so a chunked or SSE response is inspectable without breaking the
stream. A preview that is not the whole body says so — `truncated`, and
`undecodable` when the encoding broke part-way — and so does a HAR entry made
from it, with a `comment`. A `b:` search reads only what was kept, and lists
the bodies that were cut short. The fields, the cursor and the search are
specified in [`API.md`](API.md#读取流量).

WebSocket connections appear as a session with status `101`, and every frame in
both directions is recorded:

```json
[{"session":1,"dir":"receive","opcode":"text","len":17,"preview":"hello from origin","ignored":false},
 {"session":1,"dir":"send","opcode":"text","len":16,"preview":"ping from client","ignored":false}]
```

### Replay

Re-send a captured request through the whole pipeline — so it picks up whatever
your rules say **now**, not what they said when it was captured:

```bash
curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"id":6}' http://127.0.0.1:8899/api/replay
```

`{"ids":[6,7,8]}` replays a batch (100 at most). The JSON answer reports what
went out, per session — including how much of the request body was available to
re-send, since a body is only replayable to the extent it was captured, and
captures are bounded by `--body-preview-limit`.

The replayed hop is marked as the Composer's, so a rule can treat it differently
from the traffic it was captured from:

```
api.example.com   resHeaders://x-replayed=1   includeFilter://from:composer
```

The header lands on the replay and on nothing else.

### Keep the capture across restarts

Sessions are written to JSONL under `<storage_dir>/sessions/` with daily
rotation and reloaded at startup. `--persist-days N` sets the retention;
`--no-persist` turns the whole thing off, which is what you want in a test
harness.

---

## Drive it from a script, or from an agent

Everything the console does is an HTTP endpoint taking plain text or JSON, so a
script — or a model with a shell — can run the whole loop without a browser:
**see what an interface does, change it, check the change, and ask why a rule
did or did not fire.** No SDK, no session, no CSRF token; a `curl` is enough.
(A *browser* page on another site is refused when it tries to change things —
a request with no `Origin` header, which is what curl sends, is not.)

The four calls, in the order that loop uses them:

| Step | Call |
|---|---|
| **see** | `GET /sessions.json` — every transaction, with the operators that matched it |
| **change** | `POST /api/rules` — the body *is* the rules text, exactly as typed in the console |
| **check** | send the request through the proxy again and read the answer |
| **explain** | `POST /api/explain` — `{"rules": …, "url": …}` in, the matching operators out, without touching the running proxy |

Worked through, against an origin serving `{"id":1,"name":"real-user"}` at
`/api/user`. Mock that one endpoint and leave the rest of the origin alone:

````bash
curl -s -X POST http://127.0.0.1:8899/api/rules --data-binary '
127.0.0.1:18080/api/user resBody://{mock.json} resHeaders://x-patched=yes statusCode://418

```mock.json
{"id": 42, "name": "patched", "admin": true}
```
'
# {"ok":true,"rules":1}

curl -si -x http://127.0.0.1:8899 http://127.0.0.1:18080/api/user
# HTTP/1.1 418 I'm a teapot
# x-patched: yes
# {"id": 42, "name": "patched", "admin": true}

curl -s -x http://127.0.0.1:8899 http://127.0.0.1:18080/other
# {"other":"endpoint"}      <- same origin, untouched
````

`POST /api/rules` replaces the default group wholesale, so read the current text
back with `GET /api/rules` and append to it if you mean to add rather than
replace. Named groups have their own endpoints (`/api/rule-groups`,
`/api/rule-group/toggle`) when you want a set you can switch off in one call.

### Ask why, instead of guessing

`POST /api/explain` answers the question that costs the most time — *did this
pattern match, and what did the operator resolve to* — for a URL you have not
sent yet, against a rules text that is not installed:

```bash
curl -s -X POST http://127.0.0.1:8899/api/explain -H 'Content-Type: application/json' -d '{
  "rules": "127.0.0.1:18080/api/user statusCode://418",
  "url": "http://127.0.0.1:18080/api/user",
  "method": "GET"
}'
```

```json
{ "url": "http://127.0.0.1:18080/api/user",
  "ops": [ { "protocol": "statusCode", "value": "418",
             "pattern": "127.0.0.1:18080/api/user", "slot": true, "…": "raw, content, order" } ] }
```

An empty `ops` means the pattern did not match — the answer a silent rule never
gives you. The same engine runs offline as `whistle-rs explain`, and
`--batch` reads one JSON query per line and writes one answer per line, which is
how you check a hundred candidate rules without starting a proxy at all.

> **Two things that will waste your time.** `POST /api/rules` returning
> `{"ok":true,"rules":1}` means *parsed and stored*, not *matched* — it is a
> count of lines, not a promise about your URL. And if the change seems not to
> apply, check `/sessions.json` is not empty before suspecting the rule: a
> request that never reached the proxy cannot be modified by it, and
> `--noproxy '*'` together with `-x` is the usual reason it did not.

## Embed the proxy in your own program

whistle-rs is a library with a binary on top. If your own program needs traffic
interception — a test harness that must assert on outbound calls, a desktop app
with a built-in inspector, a proxy of your own — embed it rather than shelling
out:

```rust
use whistle_rs::embed::Proxy;

let proxy = Proxy::builder()
    .port(0)                          // the OS picks; addr() reports which
    .host("127.0.0.1".parse()?)       // keep it off the network
    .rules("api.example.com  http://127.0.0.1:3000")
    .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
    .start()
    .await?;

let addr = proxy.addr();              // point your client here
proxy.set_rules("api.example.com  statusCode://503");   // live, no restart
proxy.shutdown().await;
```

`.port(0)` and `addr()` are the pair that makes this usable in tests: no port to
reserve, no collision between concurrent test binaries. `on_session` is called
once per request, when it is over — its body delivered, or failed, or abandoned
by the client — and a failed one says where in `s.error`.

To *change* traffic rather than watch it, register an in-process hook. It is the
same `RustPlugin` trait the built-in plugins use, so it can rewrite request
headers, inject rules, answer the request outright, gate it, transform the
response, or pick the TLS certificate:

```rust
struct MockApi;

impl RustPlugin for MockApi {
    fn name(&self) -> &str { "mock-api" }
    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult {
            response: Some(PluginResp {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"answered_by":"your program"}"#.to_vec(),
            }),
            ..Default::default()
        }
    }
}

Proxy::builder().plugin(MockApi).rules("api.test  plugin://mock-api")
```

[`examples/embedded.rs`](../examples/embedded.rs) runs all of the above end to
end — `cargo run --example embedded`. The builder also covers a SOCKS5 port, the
storage directory (two embedders sharing one share a CA), values, the
body-capture cap, and `intercept_https(false)` for routing TLS without
decrypting it. Anything past the facade is reachable through `proxy.state()`.

For out-of-process plugins in JS/TS, see [`PLUGINS.md`](PLUGINS.md).

---

## When a rule does not fire

**Ask the capture what matched.** Each session records the operators that
resolved for it, as written and as they came out:

```bash
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
s = json.load(sys.stdin)[0]
print(s["url"])
for r in s["rules"]: print(" ", r["raw"], "->", r["value"])'
```

```
http://api.example.com/anything
  host://127.0.0.1:5173             -> 127.0.0.1:5173
  reqHeaders://x-token=abc          -> x-token=abc
  reqHeaders://authorization=${bearer} -> authorization=Bearer eyJhbGciOi
```

An operator missing from that list never matched — go and look at the pattern.
One present but with a `value` you did not expect is a substitution or a
path-join problem, not a matching one. Note that the list is what *resolved*,
which is not always what *ran*: both contenders for the
[shared slot](#a-mock-has-to-be-written-above-the-forward) appear, and only the
first of them answered.

Then look at the log. Every request prints its resolved destination, and that
one line usually contains the rest of the answer:

```
INFO GET http://seg.test/path/to/x    -> 127.0.0.1:5173 (http)   # rule matched
INFO GET http://seg.test/path/toxxx   -> seg.test:80    (http)   # it did not
INFO OPTIONS http://api.test/users    -> short-circuit           # answered locally
```

Those lines are `INFO`, so they are there without any flag. A request that
fails gets a second line: the session it was recorded as, the step it stopped
at, and why:

```
INFO GET http://dead.test/ -> 127.0.0.1:9 (http)
INFO #12 GET http://dead.test/ -> failed at connect: connecting to 127.0.0.1:9: Connection refused (os error 61)
INFO GET https://sec.test/ -> 127.0.0.1:5443 (https)
INFO #13 GET https://sec.test/ -> failed at tls: upstream TLS handshake: invalid peer certificate: …
```

The same failure is session #12 in the console — a red tag on its row naming
the step, and a "Did not complete" card with the reason — and `error` in
`/sessions.json`. The client's `502` carries it too:

```
HTTP/1.1 502 Bad Gateway
x-whistle-rs-error: connect
x-whistle-rs-session: 12
x-server: whistle-rs

whistle-rs: connecting to 127.0.0.1:9: Connection refused (os error 61)
```

**A `502` without `x-whistle-rs-error` came from the server**, not from here.
The steps, in the order a request meets them:

| `error.phase` | Where it stopped |
|---------------|------------------|
| `client-tls` | the TLS handshake between the client and this proxy: the client refused the certificate it was shown (see the table below) |
| `request` | reading the request from the client: its upload broke off |
| `rules` | a rule could not be carried out: a destination scheme nothing routes (`ws://` on a plain request), a proxy rule with no usable address, a PAC file that failed |
| `plugin` | a plugin's `auth` gate failed (unreachable, too slow, nonsense), as opposed to refusing |
| `dns` | looking up the server's name — or the upstream proxy's |
| `connect` | opening the connection: refused, unreachable, or no answer within 16 s (less with `--timeout`) |
| `proxy` | the upstream proxy would not open the way (its TLS, its CONNECT, its SOCKS handshake) |
| `tls` | the TLS handshake with the server |
| `response` | the server was reached and did not answer properly: it closed before a response, or cut the body short |
| `client` | the client left before the response ended — its own timeout, or a page navigated away |
| `abort` | a rule dropped it on purpose: `enable://abort`, `abortReq`, `abortRes`, `disable://tunnel` |

`response` and `client` can happen after the status line went out, so a row
can say `200` and still be failed: the client got a `200` and half a body.

Then work down this list:

| Symptom | Cause |
|---------|-------|
| the rule matches a URL you expected it to miss, or vice versa | a path prefix only matches at a `/`, `\` or `?` boundary: `example.com/path/to` matches `/path/to/x` but **not** `/path/toxxx` |
| a `*` in the path matches nothing | `*` is a wildcard **in the host only**. In a path it is a literal, because `*` is a legal URL character. `example.com/old/*` matches a URL containing an actual `*`; write `^http://example.com/old/**` for a path wildcard. Filter patterns are the exception — they always read as if `^`-prefixed, which is why `excludeFilter://*/health` works |
| a mock, redirect or forward is ignored | another line of the [shared slot](#a-mock-has-to-be-written-above-the-forward) was written first. Move it up, or mark it `$` |
| an operator value arrives truncated | it contained a space. Use `${name}` and a value — see [Headers](#headers) |
| `502` on a self-signed or private-CA origin | whistle-rs **verifies** origin certificates, unlike upstream. `--insecure-upstream` opts out |
| a delay of `1s` is instant | delays require a numeric millisecond value; a suffix makes the delay invalid. Write `1000` |
| a throttle is 8× faster than expected | `resSpeed://` is **kilobits**, not kilobytes |
| a body rewrite works sometimes | it does not, any more — a response-body operator now busts the request cache, so a `304` cannot swallow it. If you are on an older build, add `disable://cache` |
| a chunked response stops streaming | a body operator on it buffers the whole body. Remove it, or scope it away with a filter |
| a body operator does nothing to an SSE stream | it is skipped there on purpose, so the stream keeps flowing; the Rules tab marks it "not applied" with the reason — see [What throttling will not do](#what-throttling-will-not-do) |
| a rule is listed on the Rules tab and the body is untouched | look for "not applied" on that row: the reason is under it — the body was over `--body-rewrite-limit`, compressed with something the proxy cannot undo, or a plugin hook failed |
| a `CONNECT` row tagged `client-tls`, and nothing inside it | the client refused this proxy's certificate: it does not trust the root CA — see [`CERTIFICATES.md`](CERTIFICATES.md) — or it is an app that pins its server's certificate, which no CA fixes. For the second, relay that host unread: `pinned.example.com disable://intercept` |
| a page opens in the browser, and through the proxy fails at `connect` after 16 seconds | the name has an IPv6 address the network cannot reach, and it was tried first and used up the connect budget. IPv4 is tried first by default now; an older build tried the resolver's order, and `-M ipv6first` or `-M verbatim` still do — update, or drop the mode. See [`CLI.md`](CLI.md#-m--mode) |
| an Android WebView or Chrome shows `ERR_CERT_VALIDITY_TOO_LONG` on an intercepted page | the root is in the system store, where Chromium limits how long a leaf may be valid, and the build signed leaves for a year. Update: leaves are now valid for 43 days — see [`CERTIFICATES.md`](CERTIFICATES.md#android) |
| a `CONNECT` row with `(tunnel)` in its Policy column | the tunnel was relayed without being decrypted — a `disable://intercept` rule, `--no-intercept-https`, or traffic that is not HTTP. The row is the whole record: nothing inside a relayed tunnel is read |
| a direct request to the console returns `502` with `Proxy-Connection` | your shell has `http_proxy` set. `curl --noproxy '*'` |
| a rule does not fire and the capture is empty | first check whether curl bypassed the proxy: use `--noproxy '' -x http://127.0.0.1:8899` to force this route. A request that reached the proxy is in the capture even when it failed, so an empty one means it did not arrive — or that `enable://hide` kept it out of the record. The console's search box and Capture filter only hide rows from the list: `/sessions.json` still has them |
| a `502` and you cannot tell who sent it | look for `x-whistle-rs-error` on it: present, this proxy made it up and names the step (`dns`, `connect`, `tls`, …); absent, the server answered `502` itself |
| the editor highlights the wrong token as the pattern | it is telling you the truth. `example.com http://localhost:5173` is pattern + destination; `http://a.com/x host://1.2.3.4` is pattern + operator. Whichever token it marks is what the proxy will match on |

More failure modes, and the ones that are structural rather than fixable, are in
the READMEs' troubleshooting sections and in [`ROADMAP.md`](ROADMAP.md).
