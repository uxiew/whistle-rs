//! Translate resolved rules into concrete request/response mutations.
//!
//! Ported from the request/response inspectors in `_original/lib/inspectors/`
//! (`req.js`, `res.js`) and the handlers. This file builds the facts the
//! matcher needs ([`build_req_info`], [`build_res_info`]); the operators live
//! one kind of work per file:
//!
//! | file | what it does |
//! | --- | --- |
//! | `substitute` | backtick templates, `{value}` references, `$1`, `${…}` in operator values |
//! | `value_sources` | loading values that name a file or URL, before anything applies |
//! | `merge` | rules that arrive late: plugin text, includes, `resRules`, the response phase |
//! | `route` | where a request goes: `host`/`proxy`/`pac`, and the [`Target`] |
//! | `flags` | `enable://`/`disable://` and the questions asked of them |
//! | `local`, `files` | answers made without the origin, and finding their files |
//! | `req_ops`, `res_ops` | the request and response heads |
//! | `header_ops`, `cookies`, `deletes`, `cors`, `cache`, `content_types` | one operator family each, both sides |
//! | `path_query` | the request's path and query |
//! | `body_ops`, `op_data` | rewriting bodies, and parsing operator values as data |
//! | `pacing`, `trailers`, `writes` | delays and speeds, trailers, `reqWrite`/`resWrite` |
//!
//! The tests are in `tests.rs`, one module for the lot.

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request;
use hyper::http::response;
use hyper::{HeaderMap, Response, StatusCode};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use super::body::{self, DynBody};
use super::upstream::{ProxyKind, Target, parse_proxy, parse_proxy_rule};
use crate::rules::{LineProps, ReqInfo, Resolved, RuleManager, RuleOp};

// One file per kind of work. Each takes what it needs from here with
// `use super::*` and is imported whole, so callers still name everything
// `apply::…` and the split is invisible outside this module. What was private
// here is `pub(super)` there: the same reach it had before.
mod body_ops;
mod cache;
mod content_types;
mod cookies;
mod cors;
mod deletes;
mod files;
mod flags;
mod header_ops;
mod local;
mod merge;
mod op_data;
mod pacing;
mod path_query;
mod req_ops;
mod res_ops;
mod route;
mod substitute;
mod trailers;
mod value_sources;
mod writes;

pub use body_ops::*;
use cache::*;
use content_types::*;
use cookies::*;
use cors::*;
use deletes::*;
pub use files::*;
pub use flags::*;
pub use header_ops::*;
pub use local::*;
pub use merge::*;
use op_data::*;
pub use pacing::*;
pub use path_query::*;
pub use req_ops::*;
pub use res_ops::*;
pub use route::*;
pub use substitute::*;
pub use trailers::*;
pub use value_sources::*;
pub use writes::*;

/// Build the request facts the matcher needs.
pub fn build_req_info(
    method: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &HeaderMap,
    client_ip: Option<String>,
) -> ReqInfo {
    // The URL every pattern is matched against, and the one `$0` and `${url}`
    // report — so it carries the host **as the client wrote it**. Upstream
    // builds it the same way (`getFullUrl`,
    // `_original/lib/util/common.js:1231-1267`, which lower-cases nothing), and
    // folding the case here meant a regexp pattern naming an upper-case host
    // could never match one, and `$0` handed the rule a URL nobody had asked
    // for. [`ReqInfo::host`] is still folded, because that one is compared as a
    // *host* rather than as text.
    let full_url = crate::rules::url::full_url(scheme, host, port, path);
    let host = host.to_ascii_lowercase();
    let hdrs = headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    ReqInfo {
        method: method.to_string(),
        scheme: scheme.to_string(),
        host,
        port,
        path: path.to_string(),
        full_url,
        headers: hdrs,
        client_ip,
        // Set by the caller when it knows them: the client's port comes from the
        // accepted socket, where the request came from is `serve`'s to say, the
        // response head only exists later, and the body is buffered only when a
        // `b:` filter has asked for it.
        client_port: None,
        from: Default::default(),
        res: None,
        req_body: None,
        script_data: Default::default(),
    }
}

/// The response facts the second resolution pass needs.
///
/// Read from the response head exactly as it arrived, before any operator or
/// plugin has touched it — upstream stamps `req.statusCode` / `req.resHeaders`
/// from the raw upstream response too (`_original/lib/inspectors/res.js:802-806`).
pub fn build_res_info(
    status: u16,
    headers: &HeaderMap,
    server_ip: Option<String>,
    server_port: Option<u16>,
) -> crate::rules::ResInfo {
    crate::rules::ResInfo {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect(),
        server_ip,
        server_port,
    }
}

// ---------------------------------------------------------------------------
// Operator values read from a file or a URL (`readRuleValue`)
// ---------------------------------------------------------------------------

/// Collect every value for a protocol, in resolution order.
fn collect_values<'a>(resolved: &'a Resolved, protocol: &str) -> Vec<&'a str> {
    resolved
        .all(protocol)
        .iter()
        .map(|o| o.value.as_str())
        .collect()
}

#[cfg(test)]
mod tests;
