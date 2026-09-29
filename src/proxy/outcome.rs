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
/// response body that may still produce one.
#[derive(Clone, Default)]
pub struct Outcome(Arc<Mutex<Option<Failure>>>);

impl Outcome {
    /// An outcome that is already known to be a failure.
    pub fn failed(failure: Failure) -> Self {
        Outcome(Arc::new(Mutex::new(Some(failure))))
    }

    /// The failure, if there was one.
    pub fn get(&self) -> Option<Failure> {
        self.0.lock().unwrap().clone()
    }

    /// Record a failure. The first one stands: a body that broke off and was
    /// then dropped has one cause, and it is the break.
    pub fn fail(&self, failure: Failure) {
        self.0.lock().unwrap().get_or_insert(failure);
    }

    /// No failure recorded — the request got its whole answer, or has not
    /// finished yet.
    pub fn is_ok(&self) -> bool {
        self.0.lock().unwrap().is_none()
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
        Ok(Outcome(Arc::new(Mutex::new(Option::deserialize(d)?))))
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

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
}
