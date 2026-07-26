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

/// The error a [`DynBody`] can fail with.
pub type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// Uniform response body used throughout the proxy.
pub type DynBody = BoxBody<Bytes, BodyError>;

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

/// A body fed frame-by-frame from another task — the writable half of a
/// streaming transform (see [`crate::plugins::pipe`]).
///
/// The channel is bounded, so a slow reader back-pressures the writer and no
/// more than `capacity` frames are ever in flight. That bound is what lets a
/// plugin sit in the middle of a body without the proxy buffering it: dropping
/// the sender ends the body, and sending an `Err` fails it.
pub fn channel(capacity: usize) -> (tokio::sync::mpsc::Sender<Result<Bytes, BodyError>>, DynBody) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
    (tx, ChannelBody { rx }.boxed())
}

/// Body impl backing [`channel`].
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, BodyError>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut().rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Box a forwarded body while copying a bounded preview of its bytes into
/// `capture` as they stream past. Frames are forwarded unchanged and
/// immediately, so streaming (including SSE) is never delayed.
pub fn tee(body: DynBody, capture: super::Capture) -> DynBody {
    TeeBody {
        inner: Box::pin(body),
        capture,
    }
    .boxed()
}

/// Body wrapper for [`tee`]: passes frames through, recording data bytes.
struct TeeBody {
    inner: Pin<Box<DynBody>>,
    capture: super::Capture,
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.capture.append(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
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
        if let Some(data) = this.data.take()
            && !data.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(data))));
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
