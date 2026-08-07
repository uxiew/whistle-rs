# The differential bench

The same rule and the same request, put through **real whistle** and through
whistle-rs, with both answers compared.

Reading upstream's source finds what it *says*. This finds what it *does* — and
the two are not always the same. Everything below was found by running it, and
none of it by reading:

* `headerReplace://` was read only in its JSON spelling, so the shorter
  `headerReplace://resH.x-a:/yes/=no` parsed, matched and rewrote nothing;
* `x-server` was missing, so a mocked response was indistinguishable from a
  forwarded one;
* the cache-busting entry in `docs/RULES.md` claimed to be an alignment with
  `notAllowCache`, when upstream never reaches that code and its own `resBody://`
  therefore vanishes on a browser reload.

It is **not** part of `cargo test`: it needs two live proxies, a live origin, and
an npm install of whistle. It is a tool you reach for, not a gate you pass.

## Running it

```sh
cd tests/differential
npm install                                  # once — pulls real whistle
PORT_BASE=18700 node oracle.js &             # real whistle on :18700
cargo run -- --port 18701 --no-persist --dir /tmp/rs-diff &   # from the repo root
PORT_BASE=18700 npm run bench
```

`PORT_BASE` claims three consecutive ports — whistle, whistle-rs, and the echo
origin — so several benches can run at once, one per area under audit:

```sh
PORT_BASE=19100 CASES=./cases-filters.js npm run bench
```

One corpus claims more than three. `cases-proxy.js` is about **where a request is
sent and through what**, which a response cannot show, so it stands up eight more
servers at `PORT_BASE+10`…`+17` — a proxy that records the request line and
headers it was given, a second echo origin, a proxy that answers 407, one that
never answers, a SOCKS5 proxy, PAC files, and a TLS hop. Both proxies are pointed
at the same recording proxy and their two recordings are compared. It needs
`--insecure-upstream` for the TLS hop's self-signed certificate; the corpus header
says which port is which.

It prints the cases it ran and every difference it could not explain. A clean
run says `differing: 0` — except for the two corpora whose own header declares a
number, because the reason those cases differ is a rule the harness cannot see:
`cases-delete.js` at `differing: 10` and `cases-values.js` at `differing: 16`.

Three corpora are not clean on a bare run, by design:

* `cases-filters.js` asks about `env:`, which reads the **proxy's** environment.
  Both proxies have to be started with `WHISTLE_DIFF_ENV=Alpha` — the oracle
  *and* whistle-rs. Starting only the oracle reports five differences that are
  the launch, not the port.
* `cases-delete.js` ends at `differing: 8`. All eight come from one fact:
  `EMPTY_BUFFER` is `undefined` in whistle 2.10.8, so upstream's "empty the
  body" paths forward the real body instead. Two more used to be on that list —
  `reqBody with an empty value` and `resBody with an empty value` — and closed
  when the bodies audit matched upstream: an operator written with *no value*
  now does nothing here either. That is a different question from
  `delete://body`, where this port still empties the body on purpose.
* `cases-compose.js` ends at `differing: 8`, also named at the top of the file:
  six are `weinre://`, which appends whistle's own bundled debug agent and points
  it at a weinre server whistle runs — neither of which this port has; one is
  `intercept://`, which is not a protocol in either proxy and fails in each one's
  own words; and one is the OS byte of a gzip header.

## The HTTPS bench

`https-bench.js` is the same idea over a **TLS** origin: it opens a real CONNECT
tunnel through each proxy, trusting that proxy's own root CA, and compares the
decrypted exchange. Nothing the plain bench runs touches CONNECT, certificate
forging, SNI, or the `https://` half of pattern matching.

```sh
PORT_BASE=19600 node oracle.js &
cargo run -- --port 19601 --no-persist --insecure-upstream --dir /tmp/rs-tls &
PORT_BASE=19600 node https-bench.js
```

Its origin also echoes the **TLS version it negotiated with the proxy**, which is
the only place `cipher://` / `tlsOptions://` is observable at all: a version pin
changes nothing the client can see. Without it, a case that pins a version and a
case that pins nothing compare equal.

It refuses to run its cases until a plain request really works through both —
because it once reported "18 cases, 0 differences" while **every tunnel was
dying of `EPROTO`**. Two proxies that fail identically compare equal. The cause
was in the bench: the tunnel's socket is already decrypted, so what travels
inside it is plain HTTP, and using an HTTPS client on it negotiated TLS a second
time.

## Reading a difference

Two divergences are **deliberate** and declared in `EXPECTED` at the top of
`harness.js`, with the reason. Anything else is news, and the first question to
ask is whether the *bench* is right — it has been wrong twice:

* a case whose rule rewrote the origin's JSON echo made the echo unparseable,
  which the bench read as "the header was dropped";
* the header allow-list has to exclude things neither proxy could agree on
  (`Date`, hop-by-hop headers, framing) without excluding so much that a real
  difference hides.

`repro`-style debugging is easiest by cutting the corpus down to one case in
`cases.js` and printing both answers whole.

**A rare flake exists and has not been identified.** Roughly one run in four to
eight of `cases.js` or `cases-bodies.js` reports exactly one difference; every
re-run of the same corpus immediately afterwards comes back clean, and five
consecutive rounds aimed at catching its name produced nothing. So a *single*
difference that vanishes on a re-run is probably this, and a difference that
survives a re-run is not. Do not treat the first as a regression, and do not
treat the second as the flake — the distinguishing test is one re-run, which
costs less than the argument.

And the third thing to suspect is whether the case exercises the rule at all.
`cases-file.js` opened with eleven cases where `127.0.0.1:PORT file:///tmp/x.txt`
was asked for `/echo` — the unmatched path is concatenated onto the value, so
both proxies looked for `/tmp/x.txt/echo`, both 404'd, and eleven cases agreed on
nothing. A rule that fires and a rule that misses look identical in the output.

The sharper version of that: a case can exercise *a* rule and not the one it
names, because an earlier layer claimed the token. `cases-patterns.js` has five
cases asking whether `/echo/g` is a regexp — it is not, and both proxies agree —
but not for that reason: a `/`-led token that is not a valid regexp is a **file
path**, and `formatShorthand` rewrites it to `file:///echo/g` before the line is
even split into pattern and operators. The five agree on the shorthand's flag
test, and say nothing about the pattern parser's. Only two `//`-led cases
(`////` and `///host`) reach that parser at all, and one of them is what caught
the bug.

No amount of reading the parser shows this; the layer above it has to be run.
When a case is inert on both sides, the question to answer before believing it
is *which* layer made it inert.

## Adding cases

`cases.js` is a list of `{ name, rules, request? }`. `rules` is the text both
proxies are given; `request` defaults to a `GET /echo`, which the origin answers
with a JSON echo of everything that reached it — so a rule that rewrites the
*request* is visible too. A rule that rewrites the response body will make that
echo unparseable, which is fine: the bench falls back to comparing the body.

`request.url` names a whole absolute URL instead of a path under the echo origin.
That is how `cases-patterns.js` asks about a **hostname** and about the **default
port**, neither of which the origin's own `127.0.0.1:<port>` address can express:
it points every host at the origin with a `* host://…` line and then asks which
patterns match `http://a.example.test/echo`.
