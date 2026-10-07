//! Every request becomes exactly one session, however it ends. The [`Ledger`]
//! is that promise: it records a request that failed — at which phase, with
//! the `x-whix-error` and `x-whix-session` headers on the 502 this
//! proxy answers — and one the client walked away from.

use super::*;

/// What an aborted request leaves behind: nothing.
///
/// whistle answers an abort with `res.destroy()`
/// (`_original/lib/inspectors/data.js:536`, `res.js:1178`), which tears the
/// socket down mid-transaction — the client sees a reset, not a status. hyper
/// does the same when the service resolves to an error, so the abort travels
/// out of [`serve`] as one and [`guard`] passes it through instead of dressing
/// it up as a 502. A 502 with a body is a *served* response: it satisfies a
/// fetch, gets cached as a failure page, and cannot be told apart from a real
/// gateway error — which is not what `enable://abort` is for.
#[derive(Debug)]
pub(super) struct Destroyed;

impl std::fmt::Display for Destroyed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection destroyed by enable://abort")
    }
}

impl std::error::Error for Destroyed {}

/// The header on a response this proxy made up because the request failed,
/// naming the [`outcome::Phase`] it failed in. Its presence is what tells a
/// `502` from here apart from a `502` the origin sent.
pub const ERROR_HEADER: &str = "x-whix-error";

/// The header carrying the id of the session a failed request was recorded
/// as, so the client that got the error can find it in the console.
pub const SESSION_HEADER: &str = "x-whix-session";

/// A request on its way to becoming a session.
///
/// Every request [`serve`] takes on becomes **exactly one** session, however it
/// ends. The paths that answer record their own, through [`Ledger::record`]; a
/// failure that escapes [`serve`] as an error is recorded by [`guard`] from the
/// draft; and a request whose future is dropped — which is what hyper does when
/// the client closes the connection or resets the stream while waiting — is
/// recorded when the ledger is dropped with it. Before this, only the first of
/// the three existed, so every request that failed before its response head
/// arrived was in the log and nowhere else.
pub(crate) struct Ledger {
    pub(super) state: Arc<AppState>,
    /// What is known about the request so far. `None` until [`serve`] knows
    /// this is a request the console records — the console's own traffic is not.
    pub(super) draft: Option<Session>,
    /// When the request arrived. Every session's `time_ms` and `duration_ms`
    /// count from here.
    pub(super) started: Instant,
    pub(super) time_ms: u128,
    /// A session has been recorded; this request owes nothing more.
    pub(super) settled: bool,
    /// Matched operators that did not take effect, noted as `serve` found
    /// out, for whichever session this request becomes — see [`unapplied`].
    pub(super) unapplied: Vec<unapplied::Unapplied>,
    /// What the request's rules and scripts noted where this ledger cannot be
    /// reached — see [`crate::rules::ReqInfo::noted`]. Read when the session
    /// is stamped, which is after the last of them can run.
    pub(super) noted: Option<crate::rules::Noted>,
}

impl Ledger {
    pub(crate) fn new(state: &Arc<AppState>) -> Self {
        Ledger {
            state: state.clone(),
            draft: None,
            started: Instant::now(),
            time_ms: now_ms(),
            settled: false,
            unapplied: Vec::new(),
            noted: None,
        }
    }

    /// Put what the request's rules and scripts note on its session — see
    /// [`Ledger::noted`].
    pub(super) fn watch(&mut self, noted: crate::rules::Noted) {
        self.noted = Some(noted);
    }

    /// Note that matched operators did not take effect. `None` notes nothing:
    /// [`unapplied::Unapplied::over`] returns it when no rule was waiting.
    pub(super) fn unapplied(&mut self, note: Option<unapplied::Unapplied>) {
        self.unapplied.extend(note);
    }

    /// Put what was noted on the session this request is recorded as.
    pub(super) fn stamp(&mut self, session: &mut Session) {
        if let Some(noted) = &self.noted
            && let Ok(mut noted) = noted.lock()
        {
            self.unapplied.append(&mut noted);
        }
        session.unapplied.append(&mut self.unapplied);
    }

    /// The request is one the console records: this much is known about it.
    pub(super) fn open(&mut self, draft: Session) {
        self.draft = Some(Session {
            time_ms: self.time_ms,
            ..draft
        });
    }

    /// Add to what the draft knows. A no-op before [`Ledger::open`].
    pub(super) fn note(&mut self, f: impl FnOnce(&mut Session)) {
        if let Some(draft) = &mut self.draft {
            f(draft);
        }
    }

    /// Record `session` as this request's one session.
    pub(super) fn record(&mut self, mut session: Session) -> u64 {
        self.settled = true;
        self.stamp(&mut session);
        self.state.record(session)
    }

    /// Record `session` as this request's one session, its response `body`
    /// still to come: it is completed when the body is over, and fails then
    /// if the body breaks off or the client leaves before the end. `expected`
    /// is the `content-length` the response promises, if any — see
    /// [`outcome::settle`].
    pub(super) fn record_streaming(
        &mut self,
        mut session: Session,
        body: DynBody,
        expected: Option<u64>,
    ) -> (u64, DynBody) {
        self.settled = true;
        self.stamp(&mut session);
        let (id, open) = self.state.record_open(session);
        let Some(session) = open else {
            return (id, body);
        };
        let state = self.state.clone();
        let body = outcome::settle(body, expected, move |failure| {
            if let Some(failure) = failure {
                log_failure(Some(session.id), &session.method, &session.url, &failure);
                session.error.fail(failure);
            }
            state.complete(&session);
        });
        (id, body)
    }

    /// Record `session` as this request's one session, and say whether there is
    /// one to look up — see [`AppState::record_visible`].
    pub(super) fn record_visible(&mut self, mut session: Session) -> Option<u64> {
        self.settled = true;
        self.stamp(&mut session);
        self.state.record_visible(session)
    }

    /// Record the draft as a request that failed with `failure`, the client
    /// having been answered with `status` (0: nothing at all), and return the
    /// session id to name. `None` when there is none: no draft, a session
    /// already recorded, or a request a rule hides.
    pub(super) fn fail(&mut self, failure: outcome::Failure, status: u16) -> Option<u64> {
        if self.settled {
            return None;
        }
        let draft = self.draft.take()?;
        let (method, url) = (draft.method.clone(), draft.url.clone());
        let id = self.record_visible(Session {
            status,
            duration_ms: self.started.elapsed().as_millis(),
            error: outcome::Outcome::failed(failure.clone()),
            ..draft
        });
        log_failure(id, &method, &url, &failure);
        id
    }
}

/// The log line for a request that did not complete. It leads with the session
/// id — the one the console lists and a failed request's 502 carries in
/// [`SESSION_HEADER`] — so the three can be matched up. A hidden request has no
/// session to match, and says so rather than quoting an id that names nothing.
pub(super) fn log_failure(id: Option<u64>, method: &str, url: &str, failure: &outcome::Failure) {
    let id = id.map_or_else(|| "(hidden)".to_string(), |id| format!("#{id}"));
    tracing::info!(
        "{id} {method} {} -> failed at {}: {}",
        without_query(url),
        failure.phase,
        without_query_of(url, &failure.message)
    );
}

/// `url` up to its `?` or `#`, for the lines logged without `-v`. A query
/// often carries a token, and the default log is where it would outlive the
/// request: a service manager keeps it, and anyone who can read the logs can
/// read it. The session in the console keeps the whole URL.
pub(crate) fn without_query(url: &str) -> &str {
    url.find(['?', '#']).map_or(url, |end| &url[..end])
}

/// `message` without `url`'s query and fragment, wherever it quotes them.
///
/// An error may name the request: a PAC file that throws is reported as
/// `FindProxyForURL(<url>) threw`, and the failure line put back the token
/// [`without_query`] had just taken off the URL in front of it.
fn without_query_of<'a>(url: &str, message: &'a str) -> std::borrow::Cow<'a, str> {
    let query = &url[without_query(url).len()..];
    if query.len() > 1 && message.contains(query) {
        message.replace(query, "").into()
    } else {
        message.into()
    }
}

impl Drop for Ledger {
    /// The request's future was dropped before it settled. Nothing else drops
    /// it: [`serve`] and [`guard`] settle every way out of it they can see, so
    /// what is left is hyper giving up on a client that has gone.
    fn drop(&mut self) {
        self.fail(
            outcome::Failure::new(
                outcome::Phase::Client,
                "the client closed the connection before the response arrived",
            ),
            0,
        );
    }
}

/// A `cipher://` pin that could not be used, on the session: the connection
/// went ahead without it — see [`super::super::ciphers`] for why — and a pin that
/// silently did not happen is the last thing to find out from a log.
pub(super) fn note_cipher_dropped(
    ledger: &mut Ledger,
    target: &upstream::Target,
    resolved: &Resolved,
) {
    if let Some(why) = &target.cipher_dropped {
        ledger.unapplied(unapplied::Unapplied::over(
            &matched_ops(resolved),
            |op| op.protocol == "cipher",
            unapplied::Kind::CipherUnusable,
            why.clone(),
        ));
    }
}

/// Where a forwarded request went, as its session's `target` says it.
pub(super) fn target_desc(target: &upstream::Target) -> String {
    let mut desc = format!("{}:{}", target.connect_host, target.connect_port);
    if target.proxy.is_some() {
        desc.push_str(" (via proxy)");
    }
    desc
}

/// The outcome of a request a rule dropped on purpose.
pub(super) fn aborted(how: &str) -> outcome::Outcome {
    outcome::Outcome::failed(outcome::Failure::new(outcome::Phase::Abort, how))
}

#[cfg(test)]
mod tests {
    use super::{without_query, without_query_of};

    #[test]
    fn a_failure_that_quotes_the_url_loses_its_query_too() {
        let url = "http://a.test/pac?token=secret#frag";
        assert_eq!(
            without_query_of(
                url,
                "pac:///p.pac: FindProxyForURL(http://a.test/pac?token=secret#frag) threw"
            ),
            "pac:///p.pac: FindProxyForURL(http://a.test/pac) threw"
        );
        assert_eq!(
            without_query_of(url, "connecting to a.test:80: refused"),
            "connecting to a.test:80: refused"
        );
        // Nothing to take out: a URL with no query, or only a bare `?`.
        assert_eq!(without_query_of("http://a.test/p", "what?"), "what?");
        assert_eq!(
            without_query_of("http://a.test/p?", "at http://a.test/p? here"),
            "at http://a.test/p? here"
        );
    }

    #[test]
    fn the_logged_url_stops_before_its_query_and_fragment() {
        assert_eq!(
            without_query("http://a.test/api?token=secret"),
            "http://a.test/api"
        );
        assert_eq!(without_query("http://a.test/p#frag?x"), "http://a.test/p");
        assert_eq!(without_query("http://a.test/p?x#y"), "http://a.test/p");
        assert_eq!(without_query("http://a.test/plain"), "http://a.test/plain");
        assert_eq!(without_query("a.test:443"), "a.test:443");
    }
}
