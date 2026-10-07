//! Hand the console's built HTML to `include_str!`, or a page that says why not.
//!
//! `ui-src/dist/index.html` is a Vite build product and is **not** tracked: it
//! is 445 KB of generated bundle that changes wholesale on every UI build, and
//! keeping it in the history made every console change unreviewable. The cost of
//! that decision is paid here.
//!
//! The rule the proxy has to keep is that **`cargo build` must work on a machine
//! with no Node**. `include_str!` cannot express "this file, or that one" — a
//! missing path is a compile error — so the choice is made before compilation:
//! this script copies the built console into `OUT_DIR` when it exists, and
//! writes a placeholder there when it does not. `src/proxy/webui.rs` includes
//! the `OUT_DIR` copy and never looks at `ui-src/` itself.
//!
//! A binary built without the console still serves every API route; only the
//! page at `/` is the placeholder, and it says so rather than 404ing, because a
//! blank page at the address the README gives you is indistinguishable from a
//! broken proxy.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Served at `/` when `ui-src/dist/index.html` was not built.
///
/// Self-contained for the same reason the real console is: it is served by the
/// proxy being debugged, and has to render with the network it is inspecting
/// switched off. The `__VERSION__`/`__HOST__`/`__PORT__` stamps are the ones
/// `index_html` substitutes, so the page can state the address it is answering
/// on — the one fact a reader needs to check the API by hand.
const PLACEHOLDER: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>whix __VERSION__ — console not built</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; padding: 2.5rem 1.5rem; font: 15px/1.65 ui-sans-serif, system-ui, sans-serif; }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.35rem; margin: 0 0 .35rem; }
  p.sub { margin: 0 0 1.75rem; opacity: .7; }
  pre { padding: .85rem 1rem; border-radius: 6px; overflow-x: auto;
        background: rgba(127,127,127,.13); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  ul { padding-left: 1.2rem; }
  li { margin: .3rem 0; }
</style>
<main>
  <h1>The console was not built</h1>
  <p class="sub">whix __VERSION__ is running and proxying on __HOST__:__PORT__. This page is
     a placeholder: the web console is a separate Vite build, and its output was
     not present when this binary was compiled.</p>
  <p>Build it, then rebuild the proxy:</p>
  <pre><code>cd ui-src &amp;&amp; npm ci &amp;&amp; npm run build
cargo build --release</code></pre>
  <p>Nothing else is missing. The proxy itself is complete, and its API answers
     on this same port — for example:</p>
  <ul>
    <li><code>GET /sessions.json</code> — the captured traffic</li>
    <li><code>GET /api/rules</code> — the rule groups</li>
    <li><code>GET /api/values</code> — the value store</li>
    <li><code>GET /ssl-certificate</code> — the CA certificate to trust</li>
  </ul>
</main>
"#;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let built = manifest.join("ui-src").join("dist").join("index.html");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("console.html");

    // Named whether or not it exists: cargo re-runs this script when a watched
    // path appears, so building the console once is enough to pick it up.
    println!("cargo::rerun-if-changed=ui-src/dist/index.html");
    println!("cargo::rerun-if-changed=build.rs");

    match fs::read(&built) {
        Ok(html) => fs::write(&out, html).expect("write console.html"),
        Err(_) => {
            println!(
                "cargo::warning=ui-src/dist/index.html not found — serving a placeholder console. \
                 Run `cd ui-src && npm ci && npm run build` to build it."
            );
            fs::write(&out, PLACEHOLDER).expect("write console.html");
        }
    }
}
