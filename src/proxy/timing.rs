//! Where a request's time went.
//!
//! The console had a duration and nothing else, and the HAR export filled the
//! standard `timings` object with `{send: 0, wait: <everything>, receive: 0}` —
//! not a rounding, an invention. Every HAR reader draws a waterfall from that
//! field, so the export was drawing a picture of a request that never happened.
//!
//! The phases are HAR 1.2's, because that is the vocabulary the format already
//! has and the console has no reason to invent a second one
//! (`log.entries[].timings`, HAR 1.2 §5.5):
//!
//! | phase     | here                                                      |
//! |-----------|-----------------------------------------------------------|
//! | `dns`     | resolving the origin's name                               |
//! | `connect` | the TCP connect — **and `ssl`, per the spec**              |
//! | `ssl`     | the TLS handshake with the origin                         |
//! | `send`    | **not measured** — see below                              |
//! | `wait`    | the request going out until the response head comes back  |
//! | `receive` | the response head until the last byte of the body         |
//!
//! `send` is not separable here: hyper takes the request and returns a future
//! that resolves on the response head, with no observation point between the
//! last byte written and the first byte read. It is reported as `-1`, which is
//! HAR's own spelling of "does not apply", rather than as `0`, which would claim
//! it took no time. Its duration is inside `wait`.
//!
//! # Why this is shared rather than returned
//!
//! A session is recorded when its **response head** arrives — that is what makes
//! the console show a row while the body is still streaming. `receive` is not
//! known then, and will not be known until the body ends, which for an event
//! stream is never. So [`Timings`] is a handle onto shared state, exactly as
//! [`Capture`](crate::proxy::Capture) is and for the same reason: the row is
//! recorded once and fills in afterwards.
//!
//! A phase that never happened stays `None` and serializes to nothing — a direct
//! connection has no proxy, a plain one has no `ssl`, and a request answered by
//! a rule never connects at all. `None` and zero are different answers and the
//! console shows them differently.

use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Milliseconds, as HAR writes them: fractional, so a sub-millisecond phase is
/// not reported as zero.
type Ms = f64;

/// The phases of one request, shared between the connection that measures them
/// and the session that reports them.
#[derive(Clone, Default)]
pub struct Timings(Arc<Mutex<Phases>>);

impl std::fmt::Debug for Timings {
    /// The phases themselves, not the handle: a `Session` derives `Debug` and a
    /// pointer would be the one thing nobody wants to read there.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = *self.0.lock().unwrap();
        f.debug_struct("Timings")
            .field("dns", &p.dns)
            .field("connect", &p.connect)
            .field("ssl", &p.ssl)
            .field("wait", &p.wait)
            .field("receive", &p.receive)
            .field("connection", &p.connection)
            .field("reused", &p.reused)
            .finish()
    }
}

/// What [`Timings`] holds. Every field is `None` until its phase happens.
#[derive(Default, Clone, Copy)]
struct Phases {
    dns: Option<Ms>,
    connect: Option<Ms>,
    ssl: Option<Ms>,
    wait: Option<Ms>,
    receive: Option<Ms>,
    /// Which origin connection carried the request — see [`Timings::connection`].
    connection: Option<u64>,
    reused: bool,
}

impl Timings {
    /// A fresh set of phases, none of them measured yet.
    pub fn new() -> Self {
        Timings::default()
    }

    fn set(&self, f: impl FnOnce(&mut Phases)) {
        f(&mut self.0.lock().unwrap());
    }

    /// Name resolution took `at`.
    pub fn dns(&self, at: Instant) {
        let ms = elapsed_ms(at);
        self.set(|p| p.dns = Some(ms));
    }

    /// The TCP connect took `at`. Recorded **without** the TLS handshake; the
    /// HAR export adds `ssl` in, because the format says `connect` contains it.
    pub fn connect(&self, at: Instant) {
        let ms = elapsed_ms(at);
        self.set(|p| p.connect = Some(ms));
    }

    /// The TLS handshake with the origin took `at`.
    pub fn ssl(&self, at: Instant) {
        let ms = elapsed_ms(at);
        self.set(|p| p.ssl = Some(ms));
    }

    /// The response head came back `at` after the request went out.
    pub fn wait(&self, at: Instant) {
        let ms = elapsed_ms(at);
        self.set(|p| p.wait = Some(ms));
    }

    /// The body finished `at` after the head arrived.
    pub fn receive(&self, at: Instant) {
        let ms = elapsed_ms(at);
        self.set(|p| p.receive = Some(ms));
    }

    /// The request went out on origin connection `id`: one opened for it, or —
    /// `reused` — one an earlier request from the same client left open.
    ///
    /// A reused connection has no `dns`, `connect` or `ssl` phase, because it
    /// had none; without saying why, the console could only list them as not
    /// measured. The number is also HAR's `connection`, and it is what shows
    /// which requests shared a connection. Numbers count up from 1 per process.
    pub fn connection(&self, id: u64, reused: bool) {
        self.set(|p| {
            p.connection = Some(id);
            p.reused = reused;
        });
    }

    /// The origin connection's number, if the request reached one.
    pub fn connection_id(&self) -> Option<u64> {
        self.0.lock().unwrap().connection
    }

    /// Has anything at all been measured? A request answered by a rule never
    /// leaves the proxy, so it has no phases and reports none rather than a row
    /// of zeros.
    pub fn measured(&self) -> bool {
        let p = *self.0.lock().unwrap();
        p.dns
            .or(p.connect)
            .or(p.ssl)
            .or(p.wait)
            .or(p.receive)
            .is_some()
    }

    /// The phases as HAR 1.2 wants them: `connect` including `ssl`, `send` as
    /// `-1`, and a phase that did not happen as `-1` too — the format's own
    /// spelling of "does not apply" (§5.5). `receive` is `-1` while the body is
    /// still arriving, which for an event stream is the permanent answer.
    pub fn har(&self) -> serde_json::Value {
        let p = *self.0.lock().unwrap();
        // "If this field is defined then the time is also included in the
        // connect field" — so a TLS connection's `connect` is both halves.
        let connect = match (p.connect, p.ssl) {
            (Some(c), Some(s)) => Some(c + s),
            (c, _) => c,
        };
        serde_json::json!({
            "blocked": -1,
            "dns": p.dns.unwrap_or(-1.0),
            "connect": connect.unwrap_or(-1.0),
            "ssl": p.ssl.unwrap_or(-1.0),
            "send": -1,
            "wait": p.wait.unwrap_or(-1.0),
            "receive": p.receive.unwrap_or(-1.0),
        })
    }
}

/// Milliseconds since `at`, rounded to a tenth — enough to tell phases apart
/// without pretending to nanosecond accuracy over a network.
fn elapsed_ms(at: Instant) -> Ms {
    round_ms(at.elapsed().as_secs_f64())
}

/// Seconds to tenths of a millisecond. Split out from [`elapsed_ms`] so it can
/// be tested against a number rather than against a clock — reading `Instant`
/// twice measures the reading as well as the phase.
fn round_ms(secs: f64) -> Ms {
    (secs * 10_000.0).round() / 10.0
}

impl serde::Serialize for Timings {
    /// Only the phases that happened, so the console can tell "did not happen"
    /// from "took no time" without a sentinel. The HAR export uses
    /// [`Timings::har`] instead, which has to spell out both.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let p = *self.0.lock().unwrap();
        let fields = [
            ("dns", p.dns),
            ("connect", p.connect),
            ("ssl", p.ssl),
            ("wait", p.wait),
            ("receive", p.receive),
        ];
        let mut m = s.serialize_map(None)?;
        for (name, value) in fields {
            if let Some(v) = value {
                m.serialize_entry(name, &v)?;
            }
        }
        if let Some(id) = p.connection {
            m.serialize_entry("connection", &id)?;
        }
        if p.reused {
            m.serialize_entry("reused", &true)?;
        }
        m.end()
    }
}

impl<'de> serde::Deserialize<'de> for Timings {
    /// Read back what [`Serialize`](serde::Serialize) wrote, so a session
    /// restored from disk still knows where its time went. A missing phase is a
    /// phase that did not happen, which is what the writer meant by omitting it.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            dns: Option<Ms>,
            connect: Option<Ms>,
            ssl: Option<Ms>,
            wait: Option<Ms>,
            receive: Option<Ms>,
            // Absent from sessions written before connections were numbered.
            #[serde(default)]
            connection: Option<u64>,
            #[serde(default)]
            reused: bool,
        }
        let w = Wire::deserialize(d)?;
        Ok(Timings(Arc::new(Mutex::new(Phases {
            dns: w.dns,
            connect: w.connect,
            ssl: w.ssl,
            wait: w.wait,
            receive: w.receive,
            connection: w.connection,
            reused: w.reused,
        }))))
    }
}

/// Stamp `receive` on `timings` when this body ends.
///
/// Separate from [`crate::proxy::body::tee`] rather than folded into it: a body
/// is teed on several paths that have no upstream connection to time, and a
/// phase measured for a body that was never fetched would be a phase invented.
pub fn measure_receive(body: super::body::DynBody, timings: Timings) -> super::body::DynBody {
    use http_body_util::BodyExt;
    ReceiveTimed {
        inner: Box::pin(body),
        timings,
        head_at: Instant::now(),
        done: false,
    }
    .boxed()
}

/// Body wrapper for [`measure_receive`].
struct ReceiveTimed {
    inner: std::pin::Pin<Box<super::body::DynBody>>,
    timings: Timings,
    /// When the response head arrived, which is when this was built.
    head_at: Instant,
    /// Set once, so a body polled after its end does not restamp.
    done: bool,
}

impl hyper::body::Body for ReceiveTimed {
    type Data = bytes::Bytes;
    type Error = super::body::BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let out = this.inner.as_mut().poll_frame(cx);
        // An error ends the body as surely as an end does, and how long it took
        // to fail is as much a fact as how long it took to finish.
        if !this.done && matches!(out, std::task::Poll::Ready(None | Some(Err(_)))) {
            this.done = true;
            this.timings.receive(this.head_at);
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

impl Drop for ReceiveTimed {
    /// A client that hangs up mid-body ends the body too, and the time it lasted
    /// is what the console should show rather than a phase that never resolves.
    fn drop(&mut self) {
        if !self.done {
            self.timings.receive(self.head_at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A phase that did not happen is absent, not zero. The console draws them
    /// differently and a HAR reader treats `-1` as "not applicable".
    #[test]
    fn an_unmeasured_phase_is_absent_rather_than_zero() {
        let t = Timings::new();
        assert!(!t.measured(), "a request answered by a rule times nothing");
        assert_eq!(serde_json::to_string(&t).unwrap(), "{}");

        t.connect(Instant::now());
        assert!(t.measured());
        let json = serde_json::to_value(&t).unwrap();
        assert!(json.get("connect").is_some());
        assert!(
            json.get("ssl").is_none(),
            "a plain connection has no handshake"
        );
    }

    /// HAR says `connect` includes `ssl`, so a TLS connection reports the sum
    /// there and the handshake again in its own field.
    #[test]
    fn har_folds_the_handshake_into_connect() {
        let t = Timings::new();
        t.set(|p| {
            p.connect = Some(10.0);
            p.ssl = Some(25.0);
            p.wait = Some(100.0);
        });
        let har = t.har();
        assert_eq!(har["connect"], 35.0, "10 of TCP and 25 of TLS");
        assert_eq!(har["ssl"], 25.0);
        assert_eq!(har["wait"], 100.0);
        assert_eq!(har["dns"], -1.0, "not measured is -1, not 0");
        assert_eq!(
            har["send"], -1,
            "not separable from wait — see the module doc"
        );
        assert_eq!(har["receive"], -1.0, "the body has not ended");
    }

    /// The reason this is shared at all: the row is recorded at the response
    /// head, and `receive` lands afterwards through the same handle.
    #[test]
    fn receive_lands_on_a_handle_already_handed_out() {
        let t = Timings::new();
        let recorded = t.clone();
        assert!(
            serde_json::to_value(&recorded)
                .unwrap()
                .get("receive")
                .is_none()
        );
        t.receive(Instant::now() - Duration::from_millis(40));
        let seen = serde_json::to_value(&recorded).unwrap();
        assert!(
            seen["receive"].as_f64().expect("a number") >= 40.0,
            "the copy handed to the session sees it: {seen}"
        );
    }

    /// Which connection carried a request survives a trip to disk, and a
    /// session written before connections were numbered still reads back.
    #[test]
    fn the_connection_is_written_and_read_back() {
        let t = Timings::new();
        t.connection(7, true);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json, serde_json::json!({ "connection": 7, "reused": true }));
        let back: Timings = serde_json::from_value(json).unwrap();
        assert_eq!(back.connection_id(), Some(7));
        assert_eq!(
            serde_json::to_value(&back).unwrap()["reused"],
            true,
            "reuse is kept, not just the number"
        );

        let fresh = Timings::new();
        fresh.connection(8, false);
        assert!(
            serde_json::to_value(&fresh)
                .unwrap()
                .get("reused")
                .is_none(),
            "a connection opened for the request is the ordinary case"
        );

        let old: Timings = serde_json::from_str(r#"{"wait":3.5}"#).unwrap();
        assert_eq!(old.connection_id(), None);
    }

    /// Sub-millisecond phases are common against a local origin, and reporting
    /// them as `0` would say the connection was free.
    #[test]
    fn a_fast_phase_keeps_a_tenth_of_a_millisecond() {
        assert_eq!(round_ms(0.0015), 1.5);
        assert_eq!(
            round_ms(0.000_04),
            0.0,
            "below a tenth there is nothing to say"
        );
        assert_eq!(round_ms(1.0), 1000.0);
    }
}
