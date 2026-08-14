//! whistle-rs — a Rust port of the core of [whistle](https://wproxy.org).
//!
//! Modules mirror the original layout under `_original/lib`:
//! * [`config`] — runtime configuration (`lib/config.js`)
//! * [`rules`] — the rules DSL: parse + match + resolve (`lib/rules/`)
//! * [`ca`] — root CA + per-host cert signing for MITM (`lib/https/ca.js`)
//! * [`proxy`] — the HTTP/HTTPS proxy server (`lib/index.js`, `lib/tunnel.js`)
//! * [`plugins`] — the unified plugin system (Rust + Node runtimes) (`lib/plugins/`)
//!
//! # Embedding
//!
//! whistle-rs is a library first and a binary second. [`embed`] is the facade
//! for running it inside another program — traffic interception and API
//! debugging as a component rather than a tool you launch beside your
//! application:
//!
//! ```no_run
//! use whistle_rs::embed::Proxy;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let proxy = Proxy::builder()
//!     .port(0)
//!     .rules("api.example.com http://127.0.0.1:3000")
//!     .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
//!     .start()
//!     .await?;
//! # Ok(())
//! # }
//! ```

pub mod ca;
pub mod config;
pub mod embed;
pub mod explain;
pub mod plugins;
pub mod proxy;
pub mod rules;
