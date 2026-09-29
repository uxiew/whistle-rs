//! How a request ended, when it did not end with a whole response.
//!
//! A request that fails still has to become a session. Before this existed, the
//! ones that failed early — a name that did not resolve, a refused connection, a
//! TLS handshake the origin rejected — left a `502` for the client and a `debug`
//! line in the log, and nothing at all in the console. That is backwards for a
//! debugging proxy: the failed request is the one being debugged.
//!
//! [`Failure`] is what a session carries when its request did not complete: the
//! [`Phase`] it stopped in and what went wrong there. A session without one got
//! its whole answer — including an origin that answered `502` itself, which is a
//! response like any other and is exactly what this field tells apart from a
//! `502` this proxy made up.
//!
//! [`Outcome`] is the shared handle a session holds it in, like
//! [`Capture`](super::Capture) and [`Timings`](super::timing::Timings): a
//! forwarded request is recorded when its response head arrives, and the body
//! can still fail — or the client leave — after that.

use std::sync::{Arc, Mutex};

/// The step of a request's life that did not complete, in the order a request
/// meets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The TLS handshake between the client and this proxy, on a tunnel it
    /// meant to read: the client would not take the certificate it was shown.
    /// Almost always a client that does not trust the root certificate, or an
    /// app that pins the server's real one.
    #[serde(rename = "client-tls")]
    ClientTls,
    /// Reading the request from the client: its body stopped arriving.
    Request,
    /// A rule could not be carried out — a destination scheme nothing routes, a
    /// proxy rule with no usable proxy in it, a PAC file that would not load.
    Rules,
    /// A plugin the request could not go on without failed.
    Plugin,
    /// Looking up the address of the server, or of the upstream proxy.
    Dns,
    /// Opening the TCP connection: refused, unreachable, or out of time.
    Connect,
    /// The upstream proxy would not open the way to the server.
    Proxy,
    /// The TLS handshake with the server.
    Tls,
    /// The server was reached and did not answer properly: it closed before
    /// sending a response head, sent one that could not be read, or broke off
    /// the body.
    Response,
    /// The client went away before the whole response reached it.
    Client,
    /// A rule dropped the request on purpose — `enable://abort`, `abortReq`,
    /// `abortRes`, or `disable://tunnel` on a tunnel.
    Abort,
    /// Something failed that no step above names. Every failure this proxy
    /// knows how to reach is tagged with one of them, so seeing this is seeing
    /// a gap in the tagging — worth reporting.
    Internal,
}

impl Phase {
    /// The name the API, the console and the `x-whistle-rs-error` header use.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::ClientTls => "client-tls",
            Phase::Request => "request",
            Phase::Rules => "rules",
            Phase::Plugin => "plugin",
            Phase::Dns => "dns",
            Phase::Connect => "connect",
            Phase::Proxy => "proxy",
            Phase::Tls => "tls",
            Phase::Response => "response",
            Phase::Client => "client",
            Phase::Abort => "abort",
            Phase::Internal => "internal",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a request did not complete.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Failure {
    pub phase: Phase,
    /// What went wrong, as the error chain put it — the same text the client's
    /// `502` carries.
    pub message: String,
}

impl Failure {
    pub fn new(phase: Phase, message: impl Into<String>) -> Self {
        Failure {
            phase,
            message: message.into(),
        }
    }
}

/// A session's [`Failure`], if it has one, shared between the session and the
/// response body that may still produce one — and whether that body is still
/// arriving, since the copy in the console's list learns it through this too.
#[derive(Clone, Default)]
pub struct Outcome(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    failure: Option<Failure>,
    /// Recorded at its response head, and not over yet — see
    /// [`AppState::record_open`](super::AppState). Nothing about the session is
    /// final while this is set: its body preview grows, and it can still fail.
    open: bool,
}

impl Outcome {
    /// An outcome that is already known to be a failure.
    pub fn failed(failure: Failure) -> Self {
        Outcome(Arc::new(Mutex::new(State {
            failure: Some(failure),
            open: false,
        })))
    }

    /// The failure, if there was one.
    pub fn get(&self) -> Option<Failure> {
        self.0.lock().unwrap().failure.clone()
    }

    /// Record a failure. The first one stands: a body that broke off and was
    /// then dropped has one cause, and it is the break.
    pub fn fail(&self, failure: Failure) {
        self.0.lock().unwrap().failure.get_or_insert(failure);
    }

    /// No failure recorded — the request got its whole answer, or has not
    /// finished yet.
    pub fn is_ok(&self) -> bool {
        self.0.lock().unwrap().failure.is_none()
    }

    /// Whether the transaction is still under way: its response is arriving.
    pub fn is_open(&self) -> bool {
        self.0.lock().unwrap().open
    }

    pub(super) fn set_open(&self, open: bool) {
        self.0.lock().unwrap().open = open;
    }
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl serde::Serialize for Outcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Outcome {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Outcome(Arc::new(Mutex::new(State {
            failure: Option::deserialize(d)?,
            open: false,
        }))))
    }
}

/// An error that knows which [`Phase`] it stopped the request in.
///
/// Carried inside an [`anyhow::Error`], so the `?`s along the way need not
/// change, and found again by [`phase_of`] however many `.context()` layers
/// were added on top. Its text is the wrapped error's whole chain, so wrapping
/// changes nothing a person reads.
#[derive(Debug)]
pub struct Stopped {
    pub phase: Phase,
    pub error: anyhow::Error,
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for Stopped {}

/// Tag `error` with the phase it stopped the request in.
pub fn stopped(phase: Phase, error: impl Into<anyhow::Error>) -> anyhow::Error {
    anyhow::Error::new(Stopped {
        phase,
        error: error.into(),
    })
}

/// [`stopped`] as a `map_err` argument: `.map_err(at(Phase::Rules))?`.
pub fn at<E: Into<anyhow::Error>>(phase: Phase) -> impl FnOnce(E) -> anyhow::Error {
    move |error| stopped(phase, error)
}

/// The phase an error was tagged with, if any. The innermost tag wins: it was
/// attached where the failure happened, and anything outside it only knows
/// that something below it failed.
pub fn phase_of(error: &anyhow::Error) -> Option<Phase> {
    let mut found = error.downcast_ref::<Stopped>()?;
    while let Some(inner) = found.error.downcast_ref::<Stopped>() {
        found = inner;
    }
    Some(found.phase)
}

/// Call `done` once `body` is over, with the reason if it did not end well.
///
/// A response body ends one of three ways, and this tells them apart:
///
/// * it runs to its end — `done(None)`;
/// * it fails — the origin broke off, or something between it and the client
///   did — and the error travels on to the client as it always did:
///   `done(Some(Phase::Response))`;
/// * it is dropped before either, which is hyper giving up on a client that
///   went away: `done(Some(Phase::Client))`.
///
/// The third needs care, because hyper also drops a body it has *finished*
/// without polling it to the end: when the body says [`is_end_stream`], or
/// when the `content-length` it promised has all been written. `expected` is
/// that length, so a body that delivered every byte it promised is not taken
/// for one the client walked away from.
///
/// [`is_end_stream`]: hyper::body::Body::is_end_stream
pub fn settle(
    body: super::body::DynBody,
    expected: Option<u64>,
    done: impl FnOnce(Option<Failure>) + Send + Sync + 'static,
) -> super::body::DynBody {
    use http_body_util::BodyExt;
    Settle {
        inner: Box::pin(body),
        expected,
        sent: 0,
        done: Some(Box::new(done)),
    }
    .boxed()
}

type Done = Box<dyn FnOnce(Option<Failure>) + Send + Sync>;

/// Body wrapper for [`settle`].
struct Settle {
    inner: std::pin::Pin<Box<super::body::DynBody>>,
    expected: Option<u64>,
    sent: u64,
    /// Taken on the first ending, so a body polled after it ended, or dropped
    /// after it failed, reports once.
    done: Option<Done>,
}

impl Settle {
    fn finish(&mut self, failure: Option<Failure>) {
        if let Some(done) = self.done.take() {
            done(failure);
        }
    }
}

impl hyper::body::Body for Settle {
    type Data = bytes::Bytes;
    type Error = super::body::BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        let out = this.inner.as_mut().poll_frame(cx);
        match &out {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.sent += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(err))) => this.finish(Some(Failure::new(
                Phase::Response,
                format!("the response body broke off: {err}"),
            ))),
            Poll::Ready(None) => this.finish(None),
            Poll::Pending => {}
        }
        out
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Settle {
    fn drop(&mut self) {
        use hyper::body::Body as _;
        let delivered =
            self.inner.is_end_stream() || self.expected.is_some_and(|len| self.sent >= len);
        let failure = (!delivered).then(|| {
            Failure::new(
                Phase::Client,
                "the client closed the connection before the response ended",
            )
        });
        self.finish(failure);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use http_body_util::BodyExt;

    /// The tag survives the context a caller adds on the way out, which is how
    /// the connect path reports "connecting to host:port" around the real error.
    #[test]
    fn a_phase_is_found_under_the_context_added_on_top() {
        let err: anyhow::Result<()> = Err(stopped(Phase::Dns, anyhow::anyhow!("no such host")));
        let err = err.context("connecting to example.com:80").unwrap_err();
        assert_eq!(phase_of(&err), Some(Phase::Dns));
        // And the text reads as it did before the tag existed.
        assert_eq!(
            format!("{err:#}"),
            "connecting to example.com:80: no such host"
        );
    }

    /// Nested tags: the one nearest the failure is the one that says where it
    /// happened.
    #[test]
    fn the_innermost_phase_wins() {
        let inner = stopped(Phase::Tls, anyhow::anyhow!("bad certificate"));
        let outer = stopped(Phase::Proxy, inner);
        assert_eq!(phase_of(&outer), Some(Phase::Tls));
        assert_eq!(phase_of(&anyhow::anyhow!("untagged")), None);
    }

    /// The first failure is the cause; a later one — the body dropped after it
    /// broke — does not overwrite it.
    #[test]
    fn the_first_failure_stands() {
        let o = Outcome::default();
        assert!(o.is_ok());
        o.fail(Failure::new(Phase::Response, "origin closed"));
        o.fail(Failure::new(Phase::Client, "client left"));
        assert_eq!(o.get().unwrap().phase, Phase::Response);
    }

    /// Serialized as the failure itself, or as nothing, and read back the same.
    #[test]
    fn an_outcome_round_trips_as_its_failure() {
        let o = Outcome::failed(Failure::new(Phase::Connect, "refused"));
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"phase": "connect", "message": "refused"})
        );
        let back: Outcome = serde_json::from_value(v).unwrap();
        assert_eq!(back.get(), o.get());
        assert_eq!(
            serde_json::to_value(Outcome::default()).unwrap(),
            serde_json::Value::Null
        );
    }

    /// What `settle` reported, once it has reported.
    fn watched(
        body: super::super::body::DynBody,
        expected: Option<u64>,
    ) -> (
        super::super::body::DynBody,
        std::sync::mpsc::Receiver<Option<Failure>>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let body = settle(body, expected, move |f| tx.send(f).unwrap());
        (body, rx)
    }

    /// A body `n` bytes long that never says it has ended — the kind of
    /// wrapper hyper stops polling once the promised length is written.
    fn endless_after(n: usize) -> super::super::body::DynBody {
        let (tx, body) = super::super::body::channel(4);
        tx.try_send(Ok(bytes::Bytes::from(vec![b'x'; n]))).unwrap();
        // Keep the sender alive: the body must not end on its own.
        std::mem::forget(tx);
        body
    }

    #[tokio::test]
    async fn a_body_read_to_its_end_settles_without_a_failure() {
        let (body, rx) = watched(super::super::body::full("hello"), Some(5));
        body.collect().await.unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert!(rx.try_recv().is_err(), "reported once");
    }

    #[tokio::test]
    async fn a_body_that_errors_settles_as_the_responses_failure() {
        let (tx, inner) = super::super::body::channel(4);
        tx.send(Ok(bytes::Bytes::from_static(b"par")))
            .await
            .unwrap();
        tx.send(Err("origin went away".into())).await.unwrap();
        let (body, rx) = watched(inner, None);
        assert!(body.collect().await.is_err());
        let failure = rx.try_recv().unwrap().expect("a failure");
        assert_eq!(failure.phase, Phase::Response);
        assert!(
            failure.message.contains("origin went away"),
            "{}",
            failure.message
        );
        assert!(rx.try_recv().is_err(), "reported once");
    }

    /// Dropped part-way: the client left.
    #[tokio::test]
    async fn a_body_dropped_part_way_settles_as_the_clients_doing() {
        let (mut body, rx) = watched(endless_after(3), Some(10));
        body.frame().await.unwrap().unwrap();
        drop(body);
        assert_eq!(
            rx.try_recv().unwrap().expect("a failure").phase,
            Phase::Client
        );
    }

    /// Dropped after every promised byte went out: hyper does that with a
    /// `content-length` body, and it is not the client leaving.
    #[tokio::test]
    async fn a_body_dropped_after_its_promised_length_settles_cleanly() {
        let (mut body, rx) = watched(endless_after(10), Some(10));
        body.frame().await.unwrap().unwrap();
        drop(body);
        assert_eq!(rx.try_recv().unwrap(), None);
    }
}
