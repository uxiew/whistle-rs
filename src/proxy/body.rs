//! A single boxed response-body type so generated responses (redirects, files,
//! errors) and forwarded upstream bodies share one signature.

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

/// Uniform response body used throughout the proxy.
pub type DynBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Box an in-memory body (redirects, error pages, served files).
pub fn full<T: Into<Bytes>>(data: T) -> DynBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// An empty body.
pub fn empty() -> DynBody {
    full(Bytes::new())
}

/// Box a forwarded upstream body, adapting its error type.
pub fn from_incoming(body: Incoming) -> DynBody {
    body.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .boxed()
}
