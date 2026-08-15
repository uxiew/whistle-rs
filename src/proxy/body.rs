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

/// Box a body while splitting it into **frames** for the console, the way
/// whistle's Frames panel shows an event stream.
///
/// The bytes travel on untouched and immediately — this only watches them. The
/// session id is *reserved* before either body is built (`AppState::reserve_id`),
/// because a request body streams long before the session it belongs to is
/// recorded.
pub fn frames(
    body: DynBody,
    state: std::sync::Arc<super::AppState>,
    session: u64,
    splitter: super::restream::FrameSplitter,
    dir: &'static str,
) -> DynBody {
    FrameBody {
        inner: Box::pin(body),
        state,
        session,
        splitter: Some(splitter),
        dir,
    }
    .boxed()
}

/// Body wrapper for [`frames`].
struct FrameBody {
    inner: Pin<Box<DynBody>>,
    state: std::sync::Arc<super::AppState>,
    session: u64,
    /// Taken when the inner body ends, so the last frame is emitted once.
    splitter: Option<super::restream::FrameSplitter>,
    /// `"send"` for a request body, `"receive"` for a response's — the only
    /// thing that tells the two apart in the Frames panel.
    dir: &'static str,
}

impl FrameBody {
    /// File one frame under the session this body belongs to.
    fn emit(&self, payload: &[u8]) {
        self.state
            .record_frame(super::WsFrame::body_frame(self.session, self.dir, payload));
    }
}

impl Body for FrameBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(splitter) = this.splitter.as_mut()
                {
                    for payload in splitter.push(data) {
                        this.emit(&payload);
                    }
                }
                // A body whose length was known ends here rather than at a
                // `None`: hyper stops polling once `is_end_stream` is true, so
                // waiting for the end would lose the last piece — the one after
                // the final separator, which for a request body is usually the
                // whole point.
                if this.inner.is_end_stream()
                    && let Some(mut splitter) = this.splitter.take()
                    && let Some(tail) = splitter.finish()
                {
                    this.emit(&tail);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                if let Some(mut splitter) = this.splitter.take()
                    && let Some(tail) = splitter.finish()
                {
                    this.emit(&tail);
                }
                Poll::Ready(None)
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
    /// The whole body arrived within the limit, with the trailer section it
    /// carried. Collecting a body drops its trailers otherwise, and a response
    /// that arrived with them must not reach the client without them.
    Whole {
        bytes: Bytes,
        trailers: Option<hyper::HeaderMap>,
    },
    /// The body is larger than the limit. Nothing has been lost: `body` is the
    /// same body from its first byte, with the part already read queued in
    /// front of the part still arriving, and it can only be streamed rather
    /// than rewritten.
    ///
    /// `prefix` is that same read-so-far part on its own. A filter that asks
    /// whether the body *contains* something can still answer from it, which is
    /// what upstream's body filters do — they match on the prefix they buffered
    /// rather than declining to match at all.
    TooBig { prefix: Bytes, body: DynBody },
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
            return Ok(Capped::TooBig {
                prefix: flatten(&seen, total),
                body: QueuedBody { queued: seen.into(), inner: body }.boxed(),
            });
        }
    }
    let trailers = seen.iter().find_map(|f| f.trailers_ref().cloned());
    Ok(Capped::Whole { bytes: flatten(&seen, total), trailers })
}

/// The data bytes of `frames`, in order. Trailer frames carry none and are
/// skipped rather than dropped — the frames themselves are still queued.
fn flatten(frames: &[Frame<Bytes>], total: usize) -> Bytes {
    let mut out = bytes::BytesMut::with_capacity(total);
    for frame in frames {
        if let Some(data) = frame.data_ref() {
            out.extend_from_slice(data);
        }
    }
    out.freeze()
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
            Capped::Whole { bytes, .. } => assert_eq!(&bytes[..], b"hello world"),
            Capped::TooBig { .. } => panic!("11 bytes is not too big for 1024"),
        }
    }

    /// The failure that matters: the request must reach the origin unharmed.
    /// Not truncated, not reordered, not one byte short — only un-rewritten.
    #[tokio::test]
    async fn a_body_over_the_limit_still_arrives_byte_for_byte() {
        let got = collect_capped(framed(&[b"aaaa", b"bbbb", b"cccc"]), 6).await.expect("ok");
        match got {
            Capped::Whole { .. } => panic!("12 bytes is too big for 6"),
            Capped::TooBig { prefix, body } => {
                // What a body filter gets to match on: the part that had been
                // read when the limit was passed, not nothing at all.
                assert_eq!(&prefix[..], b"aaaabbbb");
                assert_eq!(drain(body).await, b"aaaabbbbcccc");
            }
        }
    }

    /// The bound is on what was read, so a body that is exactly the limit is
    /// still rewritable — `len > maxReqSize`, not `>=` (`req.js:177`).
    #[tokio::test]
    async fn a_body_exactly_at_the_limit_is_still_whole() {
        let got = collect_capped(framed(&[b"123456"]), 6).await.expect("ok");
        assert!(matches!(got, Capped::Whole { bytes, .. } if &bytes[..] == b"123456"));
    }

    /// The trailer section survives the collection. Dropping it is how a
    /// response that arrived with trailers reached the client without them.
    #[tokio::test]
    async fn a_collected_body_keeps_its_trailers() {
        let (tx, body) = channel(2);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        tx.try_send(Ok(Bytes::from_static(b"data"))).expect("capacity");
        drop(tx);
        // `channel` carries data frames only, so the trailer is added by hand
        // through the same path a real body would take.
        let with_trailers = TrailerAfter { inner: Box::pin(body), trailers: Some(trailers) }.boxed();
        match collect_capped(with_trailers, 1024).await.expect("ok") {
            Capped::Whole { bytes, trailers } => {
                assert_eq!(&bytes[..], b"data");
                assert_eq!(trailers.expect("kept").get("x-checksum").unwrap(), "abc");
            }
            Capped::TooBig { .. } => panic!("4 bytes is not too big"),
        }
    }

    /// A body that ends with a trailer frame, for the test above.
    struct TrailerAfter {
        inner: Pin<Box<DynBody>>,
        trailers: Option<hyper::HeaderMap>,
    }

    impl Body for TrailerAfter {
        type Data = Bytes;
        type Error = BodyError;
        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(None) => Poll::Ready(
                    this.trailers.take().map(|t| Ok(Frame::trailers(t))),
                ),
                other => other,
            }
        }
    }

    /// An empty body is whole, not a stream to give up on: `b:!x` has to hold
    /// for a request with no body at all.
    #[tokio::test]
    async fn an_empty_body_is_whole() {
        let got = collect_capped(empty(), 1024).await.expect("ok");
        assert!(matches!(got, Capped::Whole { bytes, .. } if bytes.is_empty()));
    }
}

/// Put `top` in front of a body and `bottom` after it, without waiting for it.
///
/// This is what `resPrepend://` and `resAppend://` mean for a body that is
/// still arriving. Neither needs the body: one goes before the first byte and
/// the other after the last, and the bytes in between are forwarded as they
/// come. The buffered path reaches the same bytes by concatenation
/// ([`crate::proxy::apply`]'s `Injection::apply`); this reaches them without
/// holding the stream, which is the only way an event stream can have them at
/// all.
///
/// No doctype is stamped and no HTML gate is consulted, because neither applies:
/// upstream stamps a doctype only for an HTML response and its `allowInject`
/// lets everything through when `isHtml` is unset
/// (`_original/lib/util/whistle-transform.js:80-…`). A caller that has an HTML
/// body has an ending too, and belongs on the buffered path.
pub fn surround(body: DynBody, top: Vec<u8>, bottom: Vec<u8>) -> DynBody {
    SurroundBody {
        top: (!top.is_empty()).then(|| Bytes::from(top)),
        inner: Box::pin(body),
        bottom: (!bottom.is_empty()).then(|| Bytes::from(bottom)),
        inner_done: false,
    }
    .boxed()
}

/// Body impl backing [`surround`].
struct SurroundBody {
    /// Taken on the first poll, so it goes out ahead of everything.
    top: Option<Bytes>,
    inner: Pin<Box<DynBody>>,
    /// Taken when the inner body ends, so it goes out exactly once.
    bottom: Option<Bytes>,
    inner_done: bool,
}

impl Body for SurroundBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(top) = this.top.take() {
            return Poll::Ready(Some(Ok(Frame::data(top))));
        }
        if !this.inner_done {
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(None) => this.inner_done = true,
                other => return other,
            }
        }
        match this.bottom.take() {
            Some(bottom) => Poll::Ready(Some(Ok(Frame::data(bottom)))),
            None => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod surround_tests {
    use super::*;

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
    async fn the_top_and_bottom_land_around_the_body() {
        let got = surround(full("MIDDLE"), b"TOP".to_vec(), b"BOTTOM".to_vec());
        assert_eq!(drain(got).await, b"TOPMIDDLEBOTTOM");
    }

    /// The point of doing it this way: the prefix is on the wire before the
    /// body has produced anything, so a stream that never ends still gets it.
    #[tokio::test]
    async fn the_top_goes_out_before_the_body_is_polled() {
        let (tx, rx) = channel(4);
        let mut body = Box::pin(surround(rx, b"TOP".to_vec(), b"BOTTOM".to_vec()));
        let first = body.frame().await.expect("a frame").expect("no error");
        assert_eq!(
            first.data_ref().map(|d| &d[..]),
            Some(&b"TOP"[..]),
            "the prefix does not wait for the origin"
        );
        tx.send(Ok(Bytes::from_static(b"x"))).await.expect("send");
        drop(tx);
        let mut rest = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Some(d) = frame.expect("no error").data_ref() {
                rest.extend_from_slice(d);
            }
        }
        assert_eq!(rest, b"xBOTTOM");
    }

    #[tokio::test]
    async fn an_empty_slot_adds_no_frame() {
        assert_eq!(drain(surround(full("B"), Vec::new(), Vec::new())).await, b"B");
        assert_eq!(drain(surround(full("B"), b"T".to_vec(), Vec::new())).await, b"TB");
        assert_eq!(drain(surround(full("B"), Vec::new(), b"E".to_vec())).await, b"BE");
    }
}
