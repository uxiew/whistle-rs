//! A single boxed response-body type so generated responses (redirects, files,
//! errors) and forwarded upstream bodies share one signature.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::HeaderMap;
use hyper::body::{Body, Frame, Incoming};

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

/// A body that emits `data` in paced chunks to cap throughput at `kb_per_sec`
/// (whistle's `reqSpeed`/`resSpeed`, in KB/s).
pub fn throttled<T: Into<Bytes>>(data: T, kb_per_sec: f64) -> DynBody {
    let bytes_per_sec = (kb_per_sec * 1024.0).max(1.0);
    let interval = Duration::from_millis(50);
    let chunk = ((bytes_per_sec * interval.as_secs_f64()) as usize).max(1);
    ThrottledBody {
        data: data.into(),
        chunk,
        delay: interval,
        sleep: None,
    }
    .map_err(|never| match never {})
    .boxed()
}

/// An in-memory body that emits `data` then a trailers frame (`trailers://`).
pub fn with_trailers<T: Into<Bytes>>(data: T, trailers: HeaderMap) -> DynBody {
    TrailersBody {
        data: Some(data.into()),
        trailers: Some(trailers),
    }
    .map_err(|never| match never {})
    .boxed()
}

struct TrailersBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for TrailersBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            if !data.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// Body impl that paces chunk delivery (see [`throttled`]).
struct ThrottledBody {
    data: Bytes,
    chunk: usize,
    delay: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for ThrottledBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(sleep) = this.sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => this.sleep = None,
            }
        }
        if this.data.is_empty() {
            return Poll::Ready(None);
        }
        let n = this.chunk.min(this.data.len());
        let chunk = this.data.split_to(n);
        if !this.data.is_empty() {
            this.sleep = Some(Box::pin(tokio::time::sleep(this.delay)));
        }
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }
}
