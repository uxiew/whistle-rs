# The command line

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [Rules](RULES.md) · [Roadmap](ROADMAP.md)

whistle-rs is one foreground process. There is no `w2 start`, no daemon to stop,
no instance registry — you run the binary, and you stop it with `Ctrl-C`.

```sh
whistle-rs -p 8899 -r rules.txt
```

That difference aside, the flags are whistle's flags, and a command line copied
from whistle's docs mostly works. This page says exactly where "mostly" ends:
every flag whistle documents, what it does here, and what to do instead when it
does nothing. Everything below was **measured against whistle 2.10.8**, not read
off its help text.

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
| `-H, --host` | `-H, --host` | ✅ |
| `-P, --uiport` | `-P, --uiport` | ✅ console on a port of its own |
| `-n/-w`, `-N/-W` | same | ✅ console login, and the read-only account |
| `-l, --localUIHost` | `-l, --local-ui-host` | ✅ adds to the built-in three, as upstream does |
| `-M, --mode` | `-M, --mode` | ⚠️ four of the fifty-six tokens mean something here — [see below](#-m--mode) |
| `-t, --timeout` | `-t, --timeout` | ✅ same default, 360000 ms |
| `-R, --reqCacheSize` | `-R, --req-cache-size` | ✅ |
| `-F, --frameCacheSize` | `-F, --frame-cache-size` | ✅ |
| `--socksPort` | `--socks-port` (and `--socksPort`) | ✅ inbound SOCKS5 |
| `-r, --shadowRules` | `-r, --rules` | ⚠️ **not the same thing** — see the note below |
| `-D, --baseDir` / `-S, --storage` | `--dir` | ⚠️ one directory, named in full |
| `-z, --certDir` | `-z, --cert-dir` (and `--certDir`) | ✅ [see below](#hand-supplied-certificates) |
| `-c, --dnsCache` / `--dnsServer` | — | ➖ DNS is the OS resolver's |
| `-s, --sockets` | — | ➖ no per-host connection cap to tune |
| `--httpPort` / `--httpsPort` | — | ➖ one proxy port; `-P` moves the console |
| `--allowOrigin` | — | ➖ the console API sends no CORS headers |
| `-A, --addon` / `-L, --pluginHost` / `-e, --extra` | — | ➖ this port has its own plugin system ([`PLUGINS.md`](PLUGINS.md)) |
| `-m, --middlewares` / `-f, --secureFilter` | — | ➖ they name Node modules to load |
| `--cluster` / `--inspect` / `--inspectBrk` | — | ➖ Node process concerns |
| `--init` / `--config` / `--rcPath` / `--no-prev-options` | — | ➖ belong to `w2`'s daemon, which this has no equivalent of |
| `-C, --copy` / `--no-global-plugins` | — | ➖ as above |

Beyond whistle's list: `--rule` (inline rules), `--value`, `--plugin` /
`--node-plugin`, `--insecure-upstream`, `--no-intercept-https`, `--no-persist`,
`--persist-days`, `--body-preview-limit`, `--body-rewrite-limit`, `-v/--verbose`.
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
they collapse into six behaviours. Four of the six mean something here; the other
forty are console options, deployment shapes and Node concerns.

| mode (and its spellings) | what it does | |
| --- | --- | --- |
| `pureProxy`, `proxyOnly`, `httpProxy` | stop answering for the console hostnames — `local.whistlejs.com` and friends go back to being ordinary names to forward | ✅ |
| `headless`, `shadowRulesOnly` | no console at all. The root certificate, the PAC file and `/api/status` still answer, because a client that cannot fetch them cannot be configured to use the proxy | ✅ |
| `capture`, `intercept`, `enableCapture`, `enableHttps`, `persistentCapture` | intercept HTTPS from startup — already the default here. `disableCapture` is the off switch, and is `--no-intercept-https` under whistle's name | ✅ |
| `keepXFF`, `forwardedFor` | let a client's own `x-forwarded-for` reach the origin. Both proxies drop it by default, so that a client cannot hand the origin an address the proxy appears to vouch for | ✅ |
| `multiEnv`, `nohost`, `enableRequestHeaderRules` | read rules out of a request's own `x-whistle-rule-value` header, which is how one whistle serves many environments | ➖ this port deletes those headers on arrival and never reads them |
| `x-forwarded-proto`, `x-forwarded-host` | trust a front proxy's forwarded headers and let them decide the scheme and the destination | ➖ they travel on untouched here, which is also whistle's default |
| `notAllowedEnableHTTPS` | forbid turning HTTPS interception on from the console — which upstream implements by refusing to intercept at all | ➖ there is no console switch here for it to forbid |

One interaction is worth knowing before you compose a list: **`multiEnv` (and
`nohost`) turns HTTPS interception off**, whatever `capture` said —
`isEnableCapture()` opens with `if (config.multiEnv || config.notAllowedEnableHTTPS)
return false`. It is not obvious from either name.

The tokens this port has nothing to do with are not silently swallowed: a mode whistle has and this port cannot apply is
named at startup, and one **neither** program knows is reported as a probable
typo.

```
$ whistle-rs -M "pureProxy|nohost|notAThing"
INFO mode: pureProxy
INFO mode: nohost — whistle has these and this port has nothing to apply them to; see docs/ROADMAP.md
WARN mode: notAThing — no such mode in whistle either, so probably a typo
```

`multiple` and `admin` are composites and are expanded first, exactly as upstream
expands them, so `-M multiple` really does bring `keepXFF` with it.

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
INFO root CA: /path/to/certs/root.crt (download at http://0.0.0.0:8899/rootCA.crt)
INFO certificates supplied by hand for: *.wild.example, api.example.com
```

A plugin can also choose a certificate per connection, which is the dynamic
version of the same thing — see `sniCallback://` in [`RULES.md`](RULES.md).

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
whistle-rs -p 8899 -n admin -w "$PASSWORD" -N guest -W look
```

The login gates the console and **not** the traffic — proxying keeps working for
clients that know nothing about it. The guest account may `GET` and nothing else.

**Watching a streamed body arrive** (an LLM's tokens, a chunked JSON feed):

```
api.example.com enable://captureStream resHeaders://(x-whistle-custom-frame-separator=%0A)
```

Each line becomes a frame in the Frames panel. An event stream
(`content-type: text/event-stream`) needs neither the flag nor the header. The
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

**One console for several proxies** — give each its own port and directory, and
put the console somewhere predictable:

```sh
whistle-rs -p 8899 -P 9899 --dir ~/.whistle-rs/a
whistle-rs -p 8900 -P 9900 --dir ~/.whistle-rs/b
```
