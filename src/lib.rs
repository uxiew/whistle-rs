//! whistle-rs — a Rust port of the core of [whistle](https://wproxy.org).
//!
//! Modules mirror the original layout under `_original/lib`:
//! * [`config`] — runtime configuration (`lib/config.js`)
//! * [`rules`] — the rules DSL: parse + match + resolve (`lib/rules/`)
//! * [`ca`] — root CA + per-host cert signing for MITM (`lib/https/ca.js`)
//! * [`proxy`] — the HTTP/HTTPS proxy server (`lib/index.js`, `lib/tunnel.js`)

pub mod ca;
pub mod config;
pub mod proxy;
pub mod rules;
