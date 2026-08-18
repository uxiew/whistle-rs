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
run says `differing: 0` — except for the corpora whose own header declares a
number, because the reason those cases differ is a rule the harness cannot see:
`cases-delete.js` at 8, `cases-values.js` at 13, `cases-compose.js` at 9,
`cases-docs.js` at 5, `cases-groups.js` at 3, `cases-file.js` at 2,
`cases-proxy.js` at 25, `cases-frames.js` at 6 and `cases-paths.js` at 9.

Every run also reports `inert` — the cases that would answer the same with no
rules loaded at all, and therefore prove nothing. See [below](#inert-which-cases-prove-nothing).

One corpus claims a fourth port. `cases-includes.js` is about `@` includes, and
half of them name a **URL**, so it stands up a rules-serving HTTP server at
`PORT_BASE+10`. It runs clean at `differing: 0`.

Eight corpora are not clean on a bare run, by design:

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
* `cases-compose.js` ends at `differing: 7`, also named at the top of the file:
  six are `weinre://`, which appends whistle's own bundled debug agent and points
  it at a weinre server whistle runs — neither of which this port has; one is
  `intercept://`, which is not a protocol in either proxy and fails in each one's
  own words; and one is the OS byte of a gzip header.
* `cases-file.js` ends at `differing: 2`, named at the top of the file: a URL
  file source spelled `https://` against a plaintext origin, which whistle
  answers anyway and this port refuses; and `<…>`, which names a path here and
  is fetched by upstream when the pattern leaves nothing to append.
* `cases-docs.js` ends at `differing: 5`, named at the top of the file: three
  are the gateway error's prose, one is this port's deliberate cache-busting
  showing through the only body operator that leaves the origin's echo intact,
  and one is `temp/…`, whistle's console-editable temp file, which this port has
  no directory or editor for.
* `cases-groups.js` ends at `differing: 3`, named at the top of the file: one is
  the two APIs' answer to adding a group twice. A fenced ``` block is private to
  the rule group that declared it in both proxies now; what is left in the other
  two is the older "a bare value stays the literal" divergence, reached because
  a reference that is out of scope is a reference nothing answers.
* `cases-frames.js` ends at `differing: 6`, and all six are one fact:
  `parseFrameSep` deletes the `x-whistle-custom-frame-separator` header from
  inside itself, so every branch that skips the call leaks the proxy's own
  control header to the origin or the client — a gzipped body,
  `disable://captureStream`, `enable://hide`, and an empty value. This port
  removes it first and decides afterwards.
* `cases-paths.js` ends at `differing: 9`, named at the top of the file: two are
  a UNC path failing in each proxy's own words, one is a filename containing a
  `%`, four are a header value above ASCII (which Node cannot write and whistle
  therefore drops — for a *response* header it loses the whole response), and
  two are `urlReplace://` values whistle declines to apply at all.

## The console's front door

`auth-bench.js` is the one bench that never installs a rule, because its subject
is the way in to the console every *other* bench installs its rules through —
the login, and the hostnames that open it.

`-n`/`-w` name the account that may do anything and `-N`/`-W` one that may only
read; a corpus that locked itself out would have nothing left to say, so this
stands alone and both proxies are launched with the credentials.

```sh
W2_USER=admin W2_PASS=s3cret W2_GUEST=guest W2_GUEST_PASS=look \
  PORT_BASE=19800 node oracle.js &
cargo run -- --port 19801 --no-persist --dir /tmp/rs-auth \
  -n admin -w s3cret -N guest -W look &
PORT_BASE=19800 node auth-bench.js
```

The two consoles are different programs with different route tables, so what it
compares is not what a path *answers* but whether the request got past the gate:
the status, and whether a `WWW-Authenticate` came back. A path that exists in
neither (`/no-such-route`) isolates that exactly — 401 when the credentials are
wrong and 404 when they are right, and the difference between those two is the
gate and nothing else. The prose and content type of the 401 body are each
proxy's own words and are not compared.

54 cases: every spelling of a credential (`Basic`, `basic`, no scheme at all,
padding trimmed, no colon, a password containing one), each of the three places
upstream reads them from, the read-only account against five methods, the
`.js`/`.css`/`.ico`/`.png` exemption, the root certificate answering before the
login does, and — the case that would matter most if it ever broke — that a
console login **does not gate proxied traffic**. A clean run is
`differing: 0, declared: 6`, the six being upstream's static-suffix exemption,
which a console that is one self-contained page has nothing to use and would only
be a hole.

It also carries the **hostnames that are the console**. `w2 status` tells people
to open `http://local.whistlejs.com/` through the proxy, and `rootca.pro` is how
a phone gets the certificate — set the proxy, open the name, install what it
hands you. Both resolve to `127.0.0.1`, where nothing is listening on port 80, so
a proxy that does not know them answers `502`, which is what this port did.
Compared on status and content type: two different consoles serve two different
pages and two different roots are two different certificates, so the bytes were
never going to match. They are asked **logged in**, because this bench runs both
consoles gated and an anonymous request for a console hostname is a 401 on both
sides with only the prose of the refusal left to differ; two more ask them
anonymously, to say that the login still stands in front of the console and that
the certificate still answers anyway. `https-bench.js` asks the same questions
inside a tunnel.

It found two things this port had wrong, both now fixed and both pinned in
`login_tests`: `parseAuth` decodes a value with **no scheme** and does not
insist on the padding, and a header and a query parameter are **two
candidates** — either satisfies the login on its own, where this port took the
first source that carried anything, so a browser holding a stale `Authorization`
masked the `?authorization=…` the user had just pasted and no reload could get
past it.

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

Its origin also echoes the **TLS version and the cipher suite it negotiated with
the proxy**, which is the only place `cipher://` / `tlsOptions://` is observable
at all: nothing about a pin reaches the client. Without the version, a case that
pins a version and a case that pins nothing compare equal — and the suite was
missing for just as long, so a rule naming one suite and a rule naming another
negotiated the same version and compared equal too. Every `ciphers` case here was
inert until the origin started reporting `getCipher().name`.

Three cases at the end are **one-sided**, and have to be. `cipher://` turns out to
do nothing at all in whistle 2.10.8 — it builds the options and then merges them
into the socket only while *retrying a ciphers error*, so the first, successful
handshake never sees them — which means a two-proxy comparison can only ever say
"whistle-rs pinned something and whistle did not". Those three ask the question
that matters instead: name a suite, and read back what the origin actually
negotiated. Four more ask that a string selecting **nothing** leaves the
connection unpinned and alive rather than failing it, which is what it used to
do; see `src/proxy/ciphers.rs` for why that changed.

**It turns whistle's `Enable HTTPS` switch on before it starts, and that is not a
convenience.** whistle does not decrypt HTTPS in a fresh data directory; with the
switch off it only intercepts hosts that already have a custom certificate
(`_original/lib/tunnel.js:187-199`), while whistle-rs intercepts by default. For
a long time this file did not know that, and passed anyway — because its origin
is `localhost`, which whistle intercepts whatever the rules say. Under any other
name every case here would have been comparing "whistle passed the connection
through" against "this port read it", which is a fact about a switch and not
about a rule.

Two sections at the end look at the tunnel itself rather than at what travels
inside it, and neither can be written with `throughTunnel`, which verifies
against the proxy's own root and so turns every un-intercepted connection into
the same TLS error:

* **who signed the certificate** (12 cases) — the only way to see the difference
  between a connection that was read and one that was passed through. It is
  where the bare-IP default lives: a `CONNECT` to an address whose ClientHello
  named nothing is not decrypted by either proxy. These run under `probe.test`
  and a `host://` line rather than under `localhost`, for the reason above;
* **what the tunnel is carrying** (8 cases) — cleartext HTTP, an unknown method,
  cleartext HTTP/2, and bytes that are neither HTTP nor TLS, which both proxies
  relay. These compare through `sameTunnelAnswer`, which drops the same
  hop-by-hop and framing headers `compare` does: the origin echoes the request
  headers it was given, so a raw compare would fail on `connection` (whistle
  stamps it, hyper does not) and on `host` (whistle rewrites it to the tunnel's
  authority, this port forwards the `:authority` the client sent).

It refuses to run its cases until a plain request really works through both —
because it once reported "18 cases, 0 differences" while **every tunnel was
dying of `EPROTO`**. Two proxies that fail identically compare equal. The cause
was in the bench: the tunnel's socket is already decrypted, so what travels
inside it is plain HTTP, and using an HTTPS client on it negotiated TLS a second
time.

## The rules oracle

`rules-oracle.js` asks a narrower question than everything above, and pays
almost nothing for it: **which rules match this request, and what does each
operator end up holding**. It needs no proxy, no origin and no port — whistle's
own `Rules` (`lib/rules/rules.js`) is driven in-process, this port answers
through `whistle-rs explain --batch`, and the two answers are compared.

```sh
cargo build                     # the bench runs target/debug/whistle-rs
node rules-oracle.js            # which operators matched
node rules-oracle.js --values   # …and what each one resolved to
node rules-oracle.js --grep host --limit 5
```

Its corpus is `cases-rulelines.js`, written by `gen-rulelines.js` from a
checkout of the docs: **every concrete rule line the whistle documentation
prints**, kept verbatim — `docs/docs/**/*.md` from the upstream
repository, the rule pages and the pages beside them. `cases-docs.js` had to
repoint each pattern at a live origin and drop every line that would make a
proxy dial a stranger; this one resolves rather than runs, so
`/Users/john/mock.json`, `www.test.com` and `10.1.0.1:8080` all stay as written.
Each line is asked about a fixed set of URLs plus URLs derived from its own
pattern — 17k questions in under a second, which is cheap enough to run on every
change.

It has a second corpus: `--from-cases` reads the fourteen **hand-written**
corpora as *rules* instead of running them as requests. Each of those cases
already carries its own request — a method, a path, headers, sometimes a body —
so it can be asked exactly, and they are the awkward lines somebody sat down and
thought of rather than the ones a website prints (1842 questions, and they need
`PORT_BASE` set to the same value the corpora were written against).

It is the layer most of this port's bugs have lived in, and the first run found
six: a bare `~/mock.json` read as a file where whistle reads a destination; a
`file://` rule answering a WebSocket upgrade; a domain pattern appending `/` to
its value at the root, so `file:///srv/mock.json` opened `/srv/mock.json/`; a `|`
in a destination's query string split in half; a backtick template joined to the
request's path *before* it was rendered, which left the template unrendered; and
a ``` block's `\r\n` rewritten to `\n`, which is the framing of the raw HTTP
response such a block is usually written to hold.

**What it cannot see.** Resolution is not application: two proxies that resolve
a rule identically can still apply it differently, and that is the live bench's
subject. Neither does it see the response phase, plugins, or anything an
`@`-include pulls in mid-request.

A clean run is `differing: 0, value differences: 0`. It also reports
**`declared`** — differences this port has declared, each with its reason and a
matcher narrow enough that it cannot excuse anything else, the same discipline
`EXPECTED` keeps below — and **`host-case folds`** — questions whose only difference is that a domain pattern
matches `Host: EXAMPLE.COM` here and not upstream, which `docs/RULES.md` declares
and the bench proves case by case by re-asking upstream with the host lowered.

### Why a case proves nothing

`inert` is a number; `triage-inert.js` is the reason behind it.

```sh
PORT_BASE=19500 CASES=./cases-bodies.js npm run bench \
  | PORT_BASE=19500 node triage-inert.js ./cases-bodies.js
```

It takes the inert list out of the bench's own JSON and resolves each of those
cases' rules against its own request — through the oracle's machinery, so the
answer is the resolver's — and sorts them into four:

* **baselines**, which carry no rules and whose whole claim is what the origin
  does;
* **matched and did nothing**, which is most of them and usually correct:
  `jsAppend://` on a CSS response is *supposed* to do nothing, and the case
  says so by being inert. It prints the operators, so a family that should have
  had an effect stands out;
* **never matched, and the line says why** — a filter, an `ignore://`, a
  `skip://`, a negated pattern, an `@` source that is not one;
* **never matched, with nothing to explain it.** That is the bug: the case has
  been passing in the shape of a rule that fires and does nothing, which is the
  shape a *missing feature* has too.

A case that means to miss says so with `inert: true`, and the tool checks that
claim both ways — a case that declares itself inert and turns out to
discriminate is a stale marker, and is reported too.

It found four cases that had fallen into the same trap: **a token cannot
contain a space**, so `resBody://(NEW BODY)` parses as `resBody://(NEW` plus a
second *pattern* `BODY)`, and the line then matches nothing at all. One case in
the same corpus documents that trap on purpose; two others had walked into it,
along with two `resCookies://` values carrying a `; ` and a date. All fourteen
corpora now report zero unexplained.

### Which operators the bench proves anything about

`every_documented_rule_has_a_differential_case` (a Rust test) says every
documented rule name appears in a corpus. It says so in the weakest possible
terms, and admits it: a case exists, not that the case has any force.
`coverage-ops.js` asks the stronger question.

```sh
PORT_BASE=19500 node coverage-ops.js     # runs all fourteen benches, a few minutes
```

For each operator: is there at least one case that resolves it **and** whose
answer would change if the rule were removed? The universe is `operators.js` —
one spelling of everything this port parses — so an operator nobody wrote a case
for cannot hide by being absent from both the corpus and the list.

It found two things on its first run. `xsfile://` had exactly one case and that
case was inert by design (an unsplit path that does not exist falls through to
the origin), so nothing had ever proved the operator does anything at all.
And `location://`, which no case asked about, turned out not to be a protocol:
it is in neither upstream's registry nor its alias table, so whistle answers
`502 Unsupported protocol location:` where this port answered a `302`.

What is left is eight operators the corpora here cannot reach — dumps, ciphers,
delays, frames, plugins — each named with the bench or the test that does reach
it.

## Which whistle, though

Every number here is measured against whistle **2.10.8**, and "agrees with
2.10.8" is not the same claim as "agrees with whistle". Some alignment somewhere
is bound to be with behaviour a single release happened to have, and a corpus
cannot ask that question about itself.

`bench-versions.js` asks it. Two runs of every corpus against two releases, and
a diff **by case name** — two runs that both report three differences are not
thereby the same three, and a corpus that gained one and lost one would show as
unchanged under a count.

```sh
WHISTLE_DIFF_ENV=Alpha cargo run -- --port 19401 --no-persist \
  --insecure-upstream --dir /tmp/rs-versions &        # once; it does not change

WHISTLE_DIFF_ENV=Alpha PORT_BASE=19400 node oracle.js &
PORT_BASE=19400 node bench-versions.js > /tmp/v2.10.8.json
kill %2

mkdir -p /tmp/w29 && (cd /tmp/w29 && npm i whistle@2.9.109)
WHISTLE_PKG=/tmp/w29/node_modules/whistle \
  WHISTLE_DIFF_ENV=Alpha PORT_BASE=19400 node oracle.js &
WHISTLE_PKG=/tmp/w29/node_modules/whistle PORT_BASE=19400 \
  node bench-versions.js > /tmp/v2.9.109.json

node bench-versions.js --diff /tmp/v2.10.8.json /tmp/v2.9.109.json
```

`oracle.js` takes `WHISTLE_PKG` for this, and keys its storage directory on the
version as well as the port — two releases sharing one directory would each read
the other's state, and the answer to "did this change between versions" would be
partly an answer about a file the other one wrote.

**The first run of it, 2.10.8 against 2.9.109: 60 differences, and every one of
them additive.** Not a single case that differs against 2.10.8 agrees with
2.9.109 — so nothing here is an alignment with one release's quirk. What the 60
are is whistle's own feature set moving: 2.9.109 has no header filter conditions
at all (`reqH.`, `resH.`, `h:` — 30 cases), no `*://` scheme wildcards (2), no
`parseFrameSep` and so no body framing (14), no `resCors` preflight and no
escaped separators in `delete://` keys (7), and — worth naming on its own — **no
refusal of a `..` path segment**, which 2.10 added and this port has.

Eight corpora are byte-identical between the two releases, which is its own
finding: the pattern layer, the body layer, the value loader, the proxy family
and the groups API did not move at all.

The specialty benches are not run from here; each wants its own launch.

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

**The flake that used to be here is identified and declared.** Roughly one run
in six reported exactly one difference and the next run was clean. It was an
HTTP date rendered from the clock — an injection strips the cache and stamps
`Expires` — with the two proxies asked one after the other, so a run crossing a
second boundary saw them a second apart. `EXPECTED`'s `oneSecondApart` now names
it, scoped to `expires`/`set-cookie`, to two dates that both parse, to a delta of
at most 1000 ms, and only when the rest of the value is identical.

It took four rounds to catch by name, which is worth remembering: a difference
that vanishes on a re-run is not thereby explained. Re-running tells you it is
intermittent; it does not tell you what it was, and "intermittent" is where a
real race would also hide.

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

## `inert`: which cases prove nothing

`differing: 0` says the two proxies agree. It does not say the case was *about*
anything. A case whose rule never matched, or whose operator has no effect the
bench can see, agrees with upstream perfectly — and would go on agreeing if the
operator were deleted from this port's source. In the output the two are
indistinguishable, which is this bench's oldest blind spot and the reason the
notes above already name eleven cases in `cases-file.js` that 404 on both sides.

So every run also asks a third question: **would the answer change if the rules
were not there?** Before the corpus starts, with nothing loaded, each distinct
request shape is put through whistle-rs once and the answer kept. A case whose
answer is byte-identical to that one is reported as `inert`.

```
ran 152  differing 0  inert 33
```

Inert is not the same as wrong. A case pinning that a filter correctly excludes
a line, or that a malformed rule is ignored, *should* be inert; so should one
about an effect this bench cannot see — `resWrite://` goes to disk, and
`write-bench.js` is where that is measured. What the number is for is that each
of those needs a reason, and until it existed none of them were even listed.

It found four kinds of dead case on its first run, all in the oldest corpus:

* **seven pinned to port `18800`**, which no `PORT_BASE` has produced for a long
  time — including the only cases here for wildcard patterns, regexp submatches
  and port-only patterns. They had been passing as misses;
* **six the bench itself could not see**, because `user-agent` and `accept` were
  on the ignore list while the rules under test were `ua://`, `disable://ua` and
  both `headerReplace://` doc forms;
* **three whose names described something they do not measure** — `127.0.0.1:P
  http://…` reads as *pattern = the URL*, so the line does nothing at all;
* **one that needed a `content-type`** to make the body it rewrote count as text.

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

## Several rule groups at once

`rules` is one text and it is the **Default** group. A case may say `groups`
instead — or as well — and get several:

```js
{ name: 'a named group overrides Default',
  rules: `${P} method://PUT`,
  groups: [{ name: 'A', value: `${P} method://DELETE` }] }
```

Each entry is `{ name, value, selected? }`, in the order the console would list
them, and `selected: false` adds the group without switching it on. `Default` is
a name like any other here, except that both proxies resolve it **last**. A
third key, `remove: ['A']`, deletes named groups again *after* they were
installed, which is the only way to ask what a deletion mid-session does as
opposed to what never adding the group would have done.

Two things the harness does for this, and they matter for every corpus:

* **It pins `allowMultipleChoice` on.** Upstream selects one rule file at a time
  otherwise, so selecting the second group silently unselects the first
  (`selectRulesFile`, `_original/lib/rules/util.js:148-161`).
* **It clears named groups** before the corpus and after any case that installed
  one, and puts Default's switch back on. Both proxies persist their groups, so
  a corpus that did not do this would inherit whatever the last run left in the
  same data directory — and a probe leaking group state between cases is how a
  single divergence gets reported as five.

A case that says only `rules` issues exactly the two calls it always issued.

`cases-groups.js` is the corpus for all of this and ends at `differing: 3`, for
the two reasons its header names.
