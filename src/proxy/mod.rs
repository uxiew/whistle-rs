//! The proxy server: HTTP forward proxy, CONNECT tunnelling with HTTPS MITM,
//! inbound SOCKS5, and the console on the same port.
//!
//! Ported from `_original/lib/index.js`, `lib/tunnel.js` and the handlers. The
//! server's own work is one kind per file:
//!
//! | file | what it does |
//! | --- | --- |
//! | `listen` | binding the ports, the accept loop, the LAN addresses to suggest |
//! | `tunnel` | what arrives before a request: plain request or `CONNECT`; a tunnel refused, relayed unread, or intercepted and served as h1/h2 |
//! | `serve` | the request pipeline: rules, the request side, a local answer or a forward |
//! | `response` | the response phase, response body operators, plugin response hooks, trailers |
//! | `upgrade` | WebSocket and other upgrades |
//! | `ledger` | every request ends as exactly one session, failures included |
//! | `session`, `capture` | what the console shows of a request, and capturing its bodies |
//! | `state`, `markers`, `dumps` | shared state, whistle's own marker headers, `reqWrite`/`resWrite` files |
//!
//! The `pub mod`s below are subsystems of their own: `apply` turns rules into
//! mutations, `upstream` (with `pool`) connects to origins, `webui` is the
//! console, and `ws`, `sni`, `socks` handle their protocols.

pub mod apply;
#[cfg(test)]
mod bench;
pub mod body;
pub mod ciphers;
pub mod coding;
pub mod dest;
#[cfg(test)]
mod failure_tests;
pub mod forwarded;
pub mod header_rules;
pub mod outcome;
pub mod persist;
pub mod pool;
pub mod restream;
pub mod script;
pub mod search;
pub mod sni;
pub mod socks;
pub mod template;
pub mod timing;
pub mod unapplied;
#[cfg(test)]
mod unapplied_tests;
pub mod upstream;
pub mod webui;
pub mod ws;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::rules::{ReqInfo, Resolved, RuleManager};
use body::DynBody;

// One file per kind of work the server does. Each takes what it needs from
// here with `use super::*` and is imported whole, so the rest of the crate
// still names everything `proxy::…`. What was private here is `pub(super)`
// there: the same reach it had before.
mod capture;
mod dumps;
mod ledger;
mod listen;
mod markers;
mod response;
mod serve;
mod session;
mod state;
mod tunnel;
mod upgrade;

pub use capture::*;
use dumps::*;
pub use ledger::*;
pub use listen::*;
pub use markers::*;
use response::*;
use serve::*;
pub use session::*;
pub use state::*;
use tunnel::*;
use upgrade::*;
