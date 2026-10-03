# The command line

[项目说明](../README.md) · [Rules](RULES.md) · [Current status](STATUS.md) · [Roadmap](ROADMAP.md)

whistle-rs is one foreground process. There is no `w2 start`, no daemon to stop,
no instance registry — you run the binary, and you stop it with `Ctrl-C`.

```sh
whistle-rs -H 127.0.0.1 -p 8899 -r rules.txt --no-persist
```

Some flags intentionally resemble upstream, but commands are not drop-in
compatible. This reference combines implementation details and historical
measurements against Whistle 2.10.8; current verification is recorded in
[STATUS.md](STATUS.md). Use this binary's `--help` as the accepted-flag list.
UI credentials do not authenticate proxy forwarding; see [OPERATIONS.md](OPERATIONS.md).

- [Flags](#flags)
- [`-M/--mode`](#-m--mode)
- [Coming from `w2`](#coming-from-w2)
- [Recipes](#recipes)

## Flags

`✅` honoured · `⚠️` accepted but not identical · `➖` whistle has it and this has
nothing to apply it to.

| whistle | whistle-rs | |
| --- | --- | --- |
| `-p, --port` | `-p, --port` | ✅ |
| `-H, --host` | `-H, --host` | ⚠️ defaults to `127.0.0.1`, not every interface — [see below](#listening-beyond-this-machine) |
| `-P, --uiport` | `-P, --uiport` | ✅ a second port that serves only the console (it stays on the proxy port too) |
| `-n/-w`, `-N/-W` | same | ⚠️ console login and the read-only account; the passwords are better given as `WHISTLE_RS_PASSWORD`/`WHISTLE_RS_GUEST_PASSWORD` ([why](#listening-beyond-this-machine)); `-N/-W` without `-n/-w` is refused rather than left open |
| `-l, --localUIHost` | `-l, --local-ui-host` | ✅ adds to the built-in three, as upstream does |
| `-M, --mode` | `-M, --mode` | ⚠️ support depends on the mode and its combinations — see the mode table below |
| `-t, --timeout` | `-t, --timeout` | ✅ same default, 360000 ms |
| `-R, --reqCacheSize` | `-R, --req-cache-size` | ✅ |
| `-F, --frameCacheSize` | `-F, --frame-cache-size` | ✅ |
| `--socksPort` | `--socks-port` (and `--socksPort`) | ✅ inbound SOCKS5 |
| `-r, --shadowRules` | `-r, --rules` | ⚠️ **not the same thing** — see the note below |
| `-D, --baseDir` / `-S, --storage` | `--dir` | ⚠️ one directory, named in full; one instance at a time, a second is refused ([why, and how to run two](INSTALL.md#数据目录)) |
| `-z, --certDir` | `-z, --cert-dir` (and `--certDir`) | ✅ [see below](#hand-supplied-certificates) |
| `-c, --dnsCache` / `--dnsServer` | — | ➖ DNS is the OS resolver's |
| `-s, --sockets` | — | ➖ nothing to cap: this never limits how many connections one origin gets; it only keeps idle ones for the client connection that opened them ([how](ARCHITECTURE.md#reusing-origin-connections)). Measured: the flag changes nothing a client can see upstream either — with `sockets: 1`, six concurrent requests still finish in parallel |
| `--httpPort` / `--httpsPort` | — | ➖ one proxy port; `-P` moves the console |
| `--allowOrigin` | `--allow-origin` (and `--allowOrigin`) | ✅ [see below](#calling-the-console-from-another-page) |
| `-A, --addon` / `-L, --pluginHost` / `-e, --extra` | — | ➖ this port has its own plugin system ([`PLUGINS.md`](PLUGINS.md)) |
| `-m, --middlewares` / `-f, --secureFilter` | — | ➖ they name Node modules to load |
| `--cluster` / `--inspect` / `--inspectBrk` | — | ➖ Node process concerns |
| `--init` / `--config` / `--rcPath` / `--no-prev-options` | — | ➖ belong to `w2`'s daemon, which this has no equivalent of |
| `-C, --copy` / `--no-global-plugins` | — | ➖ as above |

Beyond whistle's list: `--rule` (inline rules), `--value`, `--plugin` /
`--node-plugin`, `--insecure-upstream`, `--no-intercept-https`, `--no-persist`,
`--persist-days`, `--body-preview-limit`, `--body-rewrite-limit`,
`--weinre <URL>` (where a weinre server is running, for `weinre://id` rules —
[why it is needed](RULES.md#weinre-html-debug-injection)), `-v/--verbose`.
`whistle-rs --help` prints all of them, and `whistle-rs explain` answers "which
rules would this URL hit" without making a request.

### The one flag that means something different

**`-r` here loads a rules file into the Default group. In whistle, `-r` is
`--shadowRules`.** Both read the file and both apply it. What differs is who can
see it afterwards: whistle's shadow rules are a layer *beneath* everything and do
not appear in the console at all — `/cgi-bin/rules/list` comes back empty while
the rule still fires — where this port's land in the Default group, listed,
editable and switchable off.

If you are copying a command line that used `-r` to impose rules an operator
should not be able to remove, that property does not survive the copy.

## `-M/--mode`

whistle's `--mode` takes a `|`, `,` or `&` separated list out of a vocabulary of
**fifty-six** tokens. `tests/differential/mode-bench.js` starts one proxy per
token — whistle and whistle-rs in turn — and runs the same nine probes through
each. **Sixteen** move anything a client can see (fifteen against whistle's own
defaults, and a sixteenth that only shows once HTTPS interception is on), and
they collapse into six behaviours — **all six of which are honoured here**. The
other forty tokens are console options, deployment shapes and Node concerns.
Two of the console options are honoured as well, because this console has the
switches they lock: `notAllowedDisableRules` (no "all rules off") and
`notAllowedDisablePlugins` (no switching a plugin off; `admin` carries it) —
see [the switches](API.md#开关https全部规则插件).

The historical full run reported `ran: 57, differing: 0, declared: 0`.
It was not repeated in the 2026-09-25 documentation audit and is not a fresh
compatibility certificate for every current upstream version.

| mode (and its spellings) | what it does | |
| --- | --- | --- |
| `pureProxy`, `proxyOnly`, `httpProxy` | stop answering for the console hostnames — `local.whistlejs.com` and friends go back to being ordinary names to forward | ✅ |
| `headless`, `shadowRulesOnly` | no console at all. The root certificate, the PAC file and `/api/status` still answer, because a client that cannot fetch them cannot be configured to use the proxy | ✅ |
| `capture`, `intercept`, `enableCapture`, `enableHttps`, `persistentCapture` | intercept HTTPS from startup — already the default here. `disableCapture` is the off switch, and is `--no-intercept-https` under whistle's name | ✅ |
| `keepXFF`, `forwardedFor` | let a client's own `x-forwarded-for` reach the origin. Both proxies drop it by default, so that a client cannot hand the origin an address the proxy appears to vouch for | ✅ |
| `enableRequestHeaderRules` | let a request carry its own rules in `x-whistle-rule-value` and four companions. The **stored** rules still win | ✅ |
| `multiEnv`, `nohost`, `multienv` | the same, except the request's rules win, `x-whistle-rule-name` is read too, only the default rule group resolves, and HTTPS stops being intercepted from the switch | ✅ |
| `notAllowedEnableHTTPS` | forbid turning HTTPS interception on — which upstream implements by refusing to intercept at all | ✅ |
| `strict` | refuse to read the rules headers after all. Visible only beside one of the two above, which is how upstream's `admin` preset composes | ✅ |
| `x-forwarded-host` | believe a front proxy about the host the client asked for, and send the request there | ✅ |
| `x-forwarded-proto` | believe it about the scheme, which decides whether `https://` patterns match a request that arrived in the clear | ✅ |
| `ipv4first`, `ipv6first`, `verbatim` (also `ipv4First`, `ipv6First`) | which address to dial first when a name has both an IPv4 and an IPv6 one. **IPv4 first is the default**, as in whistle 2.10.10; `verbatim` is the resolver's own order, which was the default up to 2.10.8 | ✅ |

The DNS order switches do not change anything a request carries, so the mode
bench cannot see them; `src/proxy/upstream.rs` tests them by dialling
`localhost` with a listener on each family. The symptom they are about: a site
that opens in the browser but, through the proxy, fails with a connect timeout
after 16 seconds — on a network whose IPv6 route drops packets, the IPv6 address
used to be tried first and took the whole connect budget. `-M ipv6first` or
`-M verbatim` brings that back on such a network. `ipv6Only` is not honoured.

> **`-M multiEnv` lets whoever sends a request decide where it goes.** The
> headers name a destination, a rules text, and values to expand into it. That
> is what the mode is *for* — one proxy serving many environments, each request
> naming its own — and it is why both proxies are off by default. Do not switch
> it on for a proxy anything else on the network can reach.
> [Rules in a request header](RULES.md#rules-in-a-request-header) has the full
> shape, including which of the five headers is the one that reaches the origin.

Two more headers belong to that family and are **read with no gate at all
upstream**, which this port does not follow:

| Header | upstream | here |
|---|---|---|
| `x-whistle-real-host` | redirects the request, in **every** mode | honoured under `-M x-forwarded-host`; removed from every request either way |
| `x-whistle-forwarded-props` | `host` / `proto` / `ip` in its value open those gates **for that one request**, in every mode | removed from every request, never read |

A mode is an operator deciding once, at startup, that a front proxy is there
and is to be believed. A header is the *sender* deciding — and a proxy has no
way to tell an operator's front proxy from any client on the network, because
the header is the only evidence and the sender wrote it. Measured against
whistle 2.10.8 with no mode set: `x-whistle-real-host` sent a request to a
different origin, and `x-whistle-forwarded-props: proto` made `https://…`
patterns fire on a plain request. `tests/differential/forwarded-bench.js`
declares the divergence probe by probe.

Two interactions are worth knowing before you compose a list:

* **`multiEnv` (and `nohost`) turns HTTPS interception off**, whatever `capture`
  said and in whichever order — `isEnableCapture()` opens with
  `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`, so the
  switch never gets consulted. It is not obvious from either name. A per-host
  `enable://capture` **rule** still works;
* **`x-forwarded-host` and `x-forwarded-proto` travel on when they are not
  believed.** Upstream's delete lives inside the branch that consumes them, so
  without the mode the origin still sees a front proxy's claim — which it may
  legitimately want. Dropping them anyway would be this port inventing a policy;
  it does that only for the two ungated headers above, which it will not act on;
* **`strict` takes the reading back away**, and nothing else. Under
  `-M strict|multiEnv` the headers are still consumed, the named groups still
  stop resolving, and HTTPS is still not intercepted — only the rules text is
  ignored. `-M admin` carries `strict`, so an `admin` instance never reads them.

The tokens this port has nothing to do with are not silently swallowed: a mode whistle has and this port cannot apply is
named at startup, and one **neither** program knows is reported as a probable
typo.

`x-forwarded-proto` is implemented and must not be used as an example of an
unsupported token. An unknown spelling such as `notAThing` produces a warning;
consult the mode table and the actual startup output rather than copying old
log transcripts.

With named rule groups on disk, `nohost` adds one more line, because a group
that is loaded and not resolved is worth saying out loud:

```
INFO -M multiEnv: 2 named rule group(s) loaded but not resolved; the default group and each request's own rules apply
```

`multiple` and `admin` are composites and are expanded first, exactly as upstream
expands them, so `-M multiple` really does bring `keepXFF` **and** `multiEnv`
with it, and `-M admin` brings `strict`.

## Listening beyond this machine

whistle-rs binds `127.0.0.1` unless `-H` says otherwise, so a fresh start is a
proxy — and a console — for this machine only. Upstream binds every interface
by default; that made a new instance an open proxy for the whole network, with
a console anyone on it could rewrite, and rules can read and write files. To let
a phone or another machine in, ask for it, and set a login first:

```sh
export WHISTLE_RS_PASSWORD='…'   # from wherever you keep secrets
whistle-rs -H 0.0.0.0 -n admin
```

**The password goes in the environment, not on the command line.**
`WHISTLE_RS_PASSWORD` is `-w`, `WHISTLE_RS_GUEST_PASSWORD` is `-W`. The flags
still work, but `-w "$PASSWORD"` is expanded by the shell into the command line,
and any user of the machine can read a command line with `ps -A -o args=`; a
process's environment only its owner can read. Startup warns when a password
came from a flag. A flag wins when both are set; an empty variable counts as
unset; `--node-plugin` processes are started without these two variables.

Startup says which it is: on loopback, an INFO line with that command; bound
beyond loopback with no `-n/-w`, a WARN. The console's Status pane shows the
phone QR codes only when the proxy is reachable from the network. There is no
proxy authentication or IP allow-list here, so on a shared network a firewall
decides who may connect — [`OPERATIONS.md`](OPERATIONS.md).

## A QR code for a phone

`gui/mobile.md` is a page about typing a proxy address into a phone. Both
consoles shorten it with a QR code per LAN address (shown when started with
`-H 0.0.0.0`); this one is also a command:

```sh
whistle-rs qr "http://192.168.1.5:8899/rootCA.crt"   # drawn in the terminal
whistle-rs qr --svg 6 "http://192.168.1.5:8899/"     # an SVG on stdout
whistle-rs qr --matrix "hello"                       # rows of 0/1
```

The console serves the same thing at `GET /api/qr?text=…&scale=…`. The encoder
handles up to 213 bytes (byte mode, error-correction level M, versions 1-10);
past that it answers 400 and the console falls back to showing the link.

## Hand-supplied certificates

`-z/--cert-dir` names a directory of certificates to serve **instead of forged
ones**. It is how you read a client that pins its server's certificate: give the
proxy the real key and certificate, and it presents them rather than one it
signed.

```
certs/
  api.example.com.key    # the private key
  api.example.com.crt    # …and its certificate (.cer and .pem also work)
  root.key               # optional: replaces the root CA itself
  root.crt
```

The filename only pairs the two files. **What a certificate answers for comes out
of its own `subjectAltName`** — a certificate carrying `DNS:api.example.com` and
`DNS:*.wild.example` answers for both, whatever the file is called, which is the
only reading a TLS client would accept anyway. A wildcard covers one label:
`*.wild.example` answers for `api.wild.example` and not for `wild.example`.

A certificate with no `subjectAltName` names nothing a request could match and is
skipped with a line saying so, as are a file that is not a certificate and a
certificate with no key beside it. Nothing in that directory can stop the proxy
starting.

`root.key` + `root.crt` **replace the root CA**, and that is the only way to
supply one — whistle's console refuses a root through its upload form for the
same reason. Everything not covered by a hand-supplied certificate is then signed
by yours. The startup line names the file actually in use, which is the one to
install:

```
INFO root CA supplied by hand: /path/to/certs/root.crt
INFO root CA: /path/to/certs/root.crt (download at http://127.0.0.1:8899/rootCA.crt)
INFO certificates supplied by hand for: *.wild.example, api.example.com
```

A plugin can also choose a certificate per connection, which is the dynamic
version of the same thing — see `sniCallback://` in [`RULES.md`](RULES.md).

## Calling the console from another page

By default a page on another site cannot read the console's API — the browser
refuses, because no `Access-Control-Allow-Origin` comes back. `--allow-origin`
names the origins that may:

```sh
whistle-rs --allow-origin 'dash.example.com|*.internal.test'
whistle-rs --allow-origin '*'          # anyone
```

Separated by `|`, `,` or `&`. An entry may carry the same domain stars a rule
pattern may — `*` is one label, `**` any number, `***.` makes the label optional
— and a `*` on its own anywhere in the list means every origin.

Matching is on the origin's **host**, with the port dropped; the header echoes
the `Origin` exactly as the browser sent it, port and all. A request with no
`Origin`, or one the browser marks `sec-fetch-site: same-origin`, is not
cross-origin and gets nothing.

**Two paths answer any origin, list or no list** — `/api/status` and the root
certificate. Whether a proxy is alive and which certificate to trust are the two
things a page may reasonably ask of a proxy it does not own, and upstream opens
the same two.

> **`/api/status` answers those callers with less than it answers the console.**
> Upstream's status is a storage name, two labels and a version. This one also
> reports the storage *path* — which carries the account's username — the
> machine's LAN addresses and the installed plugins, which is enough for a page
> the operator never named to fingerprint the host. So a caller allowed *only*
> by the blanket exemption gets the liveness subset:
>
> ```json
> { "version": "0.1.0", "port": 8899 }
> ```
>
> Everyone the operator did trust still sees the whole pane: the console itself
> (same-origin), a host on the `--allow-origin` list, a deliberate
> `--allow-origin '*'`, and any client that sends no `Origin` at all — CORS
> never gated that one, and it can read the port directly regardless. The
> headers are unchanged either way, so "status answers anyone" still holds; only
> the body shrinks.

> **A preflight is not covered**, here or upstream: neither sends
> `Access-Control-Allow-Methods` or `-Allow-Headers`, so a request the browser
> preflights — a custom header, a `Content-Type: application/json` — is refused
> whatever the list says. Widening that would hand a named origin the whole API,
> on a console whose only other gate may be a password.

**Reading is what CORS decides; writing is decided before the request runs.**
A `POST` with a `text/plain` body is a *simple* request, sent without asking,
and CORS only hides the answer afterwards — by which time the rules had
changed. So a `POST` or `DELETE` that carries an `Origin` must come from the
console's own page or an origin on this list, and anything else is a `403`
before the route runs. A request with no `Origin` — curl, a script — is not a
browser acting for a site and is unaffected. Upstream checks nothing here. The
list therefore grants **writes** to the origins it names, and `'*'` grants them
to every site: use names.

The console answers only under one of its names — an IP address, `localhost`, or
a console hostname (the built-in ones and any added with `-l`) — which is what
stops DNS rebinding. On the proxy port a request under any other name is
forwarded to that name like proxied traffic, as upstream does, and a name that
resolves back to this machine gets a `302` to the console's address; on a `-P`
console port it gets `403`. To open the console under another name, add it with
`-l`.

## Coming from `w2`

whistle's CLI is a process manager wrapped around the proxy. This is just the
proxy, so the subcommands have no counterpart — here is what to do instead.

| `w2 …` | here |
| --- | --- |
| `w2 start` / `run` | run the binary. It stays in the foreground; background it with your shell, a service file, or a container |
| `w2 stop` / `restart` | `Ctrl-C`, or whatever supervises the process |
| `w2 status` | `GET /api/status` on the console port — it carries the same `lan_addresses` list `w2 status` prints |
| `w2 ca` | install the certificate yourself — [`CERTIFICATES.md`](CERTIFICATES.md), and on a device just open <http://rootca.pro/> with the proxy set |
| `w2 proxy` | set the system proxy with your OS's own tools |
| `w2 add` | `--rules` / `--rule` at launch, or `POST /api/rules` while running |
| `w2 install` / `uninstall` / `exec` | this port has its own plugin system; see [`PLUGINS.md`](PLUGINS.md) |
| `w2 start -p 8010 -S 8010` (several instances) | `--port 8010 --dir /some/dir/8010` — a port and a directory per instance, same rule |

## Recipes

**A plain forward proxy, no console, nothing to poke at.**

```sh
whistle-rs -p 8899 -M "headless|pureProxy" -r rules.txt
```

Proxying works as normal. The certificate, the PAC file and `/api/status` still
answer — so clients can still be configured and something can still tell whether
the process is alive — and everything else on the console port is a 404.

**A shared proxy on the network, read-only for everyone but you.**

```sh
export WHISTLE_RS_PASSWORD='…' WHISTLE_RS_GUEST_PASSWORD='…'
whistle-rs -H 0.0.0.0 -p 8899 -n admin -N guest
```

The login gates the console and **not** the traffic — proxying keeps working for
clients that know nothing about it, and any device that can connect may use it,
so the network or a firewall decides who that is. The guest account may `GET`
and nothing else — which includes every captured request's headers, cookies
and `Authorization` among them. `-N/-W` without `-n/-w` is refused at startup:
with no admin account nobody would be asked to log in, guest included.

**Watching a streamed body arrive** (an LLM's tokens, a chunked JSON feed):

```
api.example.com enable://captureStream resHeaders://(x-whistle-custom-frame-separator=%0A)
```

Each line becomes a frame in the Frames panel. An event stream
(`content-type: text/event-stream`, with or without a `charset`) needs neither
the flag nor the header. The
flag is not optional for the header form — whistle wants the same pair, and a
separator header can arrive from the origin rather than from you.

> whistle's FAQ prints this example with `%A0`, which is a different byte from
> the newline it means (`%0A`) and frames the whole body as one. Both proxies do
> the same thing with it, so the recipe fails the same way in each.

**Behind another proxy, keeping the real client address.**

```sh
whistle-rs -p 8899 -M keepXFF
```

**Not intercepting HTTPS at all** (tunnel everything through untouched):

```sh
whistle-rs -p 8899 --no-intercept-https      # or: -M disableCapture
```

That is where a run starts. The console's Status page can switch it while
running (`POST /api/switches {"intercept_https":false}`), for new connections
only, and a restart goes back to the command line.

**One console for several proxies** — give each its own port and directory, and
put the console somewhere predictable:

```sh
whistle-rs -p 8899 -P 9899 --dir ~/.whistle-rs/a
whistle-rs -p 8900 -P 9900 --dir ~/.whistle-rs/b
```
