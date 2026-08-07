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

impl Drop for TeeBody {
    /// Nothing more can reach the capture once the tee is gone, whether the
    /// body ran to its end or the client hung up part-way through it. Release
    /// the preview decompressor here rather than at end-of-stream, so an
    /// abandoned body does not leave its buffer pinned in the session ring.
    fn drop(&mut self) {
        self.capture.finish();
    }
}

/// A body that emits `data` in paced chunks to cap throughput at `kbits_per_sec`.
///
/// The unit is whistle's, and it is **kilobits**, not kilobytes: its own
/// documentation says so — "单位：kb/s，千比特/每秒"
/// (`_original/docs/docs/rules/resSpeed.md:2`) — and its implementation agrees,
/// `parseInt((options.speed * 1000) / 8)` bytes per second
/// (`_original/lib/util/whistle-transform.js:10`).
///
/// This port read it as KB/s, which is 8.192× too fast: `resSpeed://3` throttled
/// to 3072 B/s where whistle gives 375 B/s. A throttle that is off by that much
/// does not reproduce the slow link it was written to simulate.
pub fn throttled<T: Into<Bytes>>(data: T, kbits_per_sec: f64) -> DynBody {
    let bytes_per_sec = (kbits_per_sec * 1000.0 / 8.0).max(1.0);
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

/// The result of reading a body up to a limit — see [`collect_capped`].
pub enum Capped {
    /// The whole body arrived within the limit.
    Whole(Bytes),
    /// The body is larger than the limit. Nothing has been lost: this is the
    /// same body, from its first byte, with the part already read queued in
    /// front of the part still arriving. It can only be streamed, not rewritten.
    TooBig(DynBody),
}

/// Read a body into memory, giving up if it exceeds `limit`.
///
/// The operators that rewrite a request body need it whole, so the proxy reads
/// it whole — and a proxy that reads whatever a client sends, without a bound,
/// is one upload away from being killed by the operating system. whistle bounds
/// it: `MAX_REQ_SIZE` is 2MB, or 16MB behind `enable://reqMergeBigData`
/// (`_original/lib/inspectors/req.js:19-20,:163`).
///
/// What happens at the bound is the part worth copying. whistle does not fail
/// the request and does not truncate the body — it sets `interrupt`, flushes
/// what it has, and lets the remainder stream past **untransformed**
/// (`handleParams`, `req.js:169-185`). So an upload that is too big to rewrite
/// still arrives at the origin, whole and unharmed; only the rule stops
/// applying. That is the right failure for a debugging proxy: the traffic it
/// was asked to inspect must not be damaged by the inspection.
pub async fn collect_capped(body: DynBody, limit: usize) -> Result<Capped, BodyError> {
    let mut seen: Vec<Frame<Bytes>> = Vec::new();
    let mut total = 0usize;
    let mut body = Box::pin(body);
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            total += data.len();
        }
        seen.push(frame);
        if total > limit {
            return Ok(Capped::TooBig(
                QueuedBody { queued: seen.into(), inner: body }.boxed(),
            ));
        }
    }
    let mut whole = bytes::BytesMut::with_capacity(total);
    for frame in seen {
        if let Ok(data) = frame.into_data() {
            whole.extend_from_slice(&data);
        }
    }
    Ok(Capped::Whole(whole.freeze()))
}

/// Body impl backing [`Capped::TooBig`]: replays the frames already read, then
/// continues from where the read stopped.
struct QueuedBody {
    queued: std::collections::VecDeque<Frame<Bytes>>,
    inner: Pin<Box<DynBody>>,
}

impl Body for QueuedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.queued.pop_front() {
            Some(frame) => Poll::Ready(Some(Ok(frame))),
            None => this.inner.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.queued.is_empty() && self.inner.is_end_stream()
    }
}

#[cfg(test)]
mod capped_tests {
    use super::*;

    /// A body delivered in several frames, as one arrives off a socket.
    fn framed(parts: &[&[u8]]) -> DynBody {
        let (tx, body) = channel(parts.len().max(1));
        for part in parts {
            tx.try_send(Ok(Bytes::copy_from_slice(part))).expect("capacity");
        }
        drop(tx);
        body
    }

    async fn drain(body: DynBody) -> Vec<u8> {
        let mut body = Box::pin(body);
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Some(data) = frame.expect("no error").data_ref() {
                out.extend_from_slice(data);
            }
        }
        out
    }

    #[tokio::test]
    async fn a_body_within_the_limit_comes_back_whole() {
        let got = collect_capped(framed(&[b"hello ", b"world"]), 1024).await.expect("ok");
        match got {
            Capped::Whole(bytes) => assert_eq!(&bytes[..], b"hello world"),
            Capped::TooBig(_) => panic!("11 bytes is not too big for 1024"),
        }
    }

    /// The failure that matters: the request must reach the origin unharmed.
    /// Not truncated, not reordered, not one byte short — only un-rewritten.
    #[tokio::test]
    async fn a_body_over_the_limit_still_arrives_byte_for_byte() {
        let got = collect_capped(framed(&[b"aaaa", b"bbbb", b"cccc"]), 6).await.expect("ok");
        match got {
            Capped::Whole(_) => panic!("12 bytes is too big for 6"),
            Capped::TooBig(body) => assert_eq!(drain(body).await, b"aaaabbbbcccc"),
        }
    }

    /// The bound is on what was read, so a body that is exactly the limit is
    /// still rewritable — `len > maxReqSize`, not `>=` (`req.js:177`).
    #[tokio::test]
    async fn a_body_exactly_at_the_limit_is_still_whole() {
        let got = collect_capped(framed(&[b"123456"]), 6).await.expect("ok");
        assert!(matches!(got, Capped::Whole(b) if &b[..] == b"123456"));
    }

    /// An empty body is whole, not a stream to give up on: `b:!x` has to hold
    /// for a request with no body at all.
    #[tokio::test]
    async fn an_empty_body_is_whole() {
        let got = collect_capped(empty(), 1024).await.expect("ok");
        assert!(matches!(got, Capped::Whole(b) if b.is_empty()));
    }
}
