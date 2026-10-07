# Notices

whix is released under the MIT license — see [LICENSE](LICENSE). This
file says what in it comes from elsewhere, and under which terms.

## whistle

whix reimplements the proxy and rules core of
[whistle](https://github.com/avwo/whistle) by avwo and contributors, which is
under the MIT license reproduced at the end of this section.

What comes from it:

- **Behaviour and design.** The rule syntax and its semantics, the protocol
  names and the console's feature set are whistle's. They were reimplemented
  from whistle's documentation and from reading and running its source.
- **Logic translated from its source.** Parts of the Rust code follow upstream
  JavaScript closely, and say so: comments cite the upstream file and line they
  follow, as `_original/lib/…:NNN` (866 of them under `src/` today). Those lines
  refer to whistle 2.10.8, commit `1df0805` — see
  [docs/UPSTREAM.md](docs/UPSTREAM.md). This notice covers that code.
- **Text taken verbatim, in the test suite only.**
  `tests/differential/cases-rulelines.js` holds every concrete rule line printed
  in whistle's documentation (`docs/docs/**/*.md` in the upstream repository),
  and `tests/differential/cases-docs.js` runs the documentation's examples.
  None of it is compiled into the binary.

What does not come from it: the web console (`ui-src/`) is a separate Vue
application written for this project, the plugin protocol and its SDK
(`sdk/`) are this project's own, and no whistle source file is included.

whistle itself is **not distributed** with whix. The differential tests
install whistle 2.10.8 from npm to compare against; that is a test dependency,
pinned by `tests/differential/package-lock.json`, and never part of a release.

```text
The MIT License (MIT)

Copyright (c) 2015 avwo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Everything a release binary is built from

A release binary also contains the Rust crates it links (223 on
x86_64-unknown-linux-gnu at the time of writing) and the npm packages the
console is bundled from (36). Their licenses and license texts are in
`THIRD-PARTY-LICENSES.md`, which `scripts/third-party-licenses.mjs` generates
from the lockfiles for each release and which ships beside the binary.

Most are MIT and/or Apache-2.0. The others each ask for their text to travel
with the binary, which that file does: BSD-2-Clause, BSD-3-Clause, ISC, Zlib,
Unicode-3.0, CDLA-Permissive-2.0 (the Mozilla root-certificate data in
`webpki-roots`) and MPL-2.0 (`option-ext`, whose source is the published crate
on crates.io). Twelve crates declare a license without shipping its text; the
generated file lists them by SPDX identifier.
