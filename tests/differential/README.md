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

It prints the cases it ran and every difference it could not explain. A clean
run says `differing: 0`.

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

## Adding cases

`cases.js` is a list of `{ name, rules, request? }`. `rules` is the text both
proxies are given; `request` defaults to a `GET /echo`, which the origin answers
with a JSON echo of everything that reached it — so a rule that rewrites the
*request* is visible too. A rule that rewrites the response body will make that
echo unparseable, which is fine: the bench falls back to comparing the body.
