//! Origin connections a client connection keeps for its next request.
//!
//! Without this every request opened a connection of its own to the origin —
//! a TCP handshake, and for HTTPS a TLS one — and closed it after one response.
//! On loopback that is under a millisecond; across a 20 ms round trip it is
//! 40–60 ms added to every request, and a page of fifty resources opened fifty
//! connections to the same host (`tests/differential/perf-bench.js`).
//!
//! **Scoped to one client connection.** The pool lives as long as the client's
//! connection to this proxy and is reachable only from requests that arrive on
//! it, so an origin connection is never handed to a different client. That is
//! the line that matters for credentials bound to a connection rather than to
//! a request — NTLM and Negotiate authenticate the TCP connection, and a shared
//! pool would give client B the identity client A logged in with. It is also
//! the arrangement a browser has without a proxy: its connection to an origin
//! carries its own requests and nobody else's. Upstream draws the same line for
//! the one kind of origin connection it does reuse — an h2 session is cached
//! per client session or client address (`_original/lib/https/h2.js:384-400`);
//! its HTTP/1.1 agent is off by default on any Node after 10
//! (`lib/config.js:28,:1104`).
//!
//! **Keyed by everything that shapes the connection** — see [`Key`]: where the
//! socket goes, the host that was asked for, the TLS policy, and the whole
//! proxy route with its credentials. Two requests share a connection only when
//! a fresh one would have been made the same way for both.
//!
//! **Never pooled:** a request that upgrades (the connection becomes the
//! upgraded stream), a tunnel (`CONNECT` is a byte pipe, not an exchange), and
//! any connection that did not finish its response cleanly — a response the
//! client abandoned, `Connection: close` from either side (which is what
//! `disable://keepAlive` sends), or an origin that hung up. hyper closes those
//! itself and [`ConnPool::park_when_ready`] only ever parks a connection hyper
//! says can take another request.
//!
//! **HTTP/2 connections are shared, not taken.** One h2 connection carries
//! every request the client connection sends to its key, concurrently — see
//! [`ConnPool::session`]. The first request to a key that may speak h2 opens
//! the connection while the others wait for it ([`ConnPool::opening`]), so a
//! page's first burst is one handshake rather than fifty; an origin that
//! answers the offer with HTTP/1.1 is remembered, and nobody waits for it again.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use hyper::client::conn::{http1::SendRequest, http2};

use super::body::DynBody;
use super::ciphers::CipherPolicy;
use super::upstream::{HostOverride, ProxyKind, TlsVersions};

/// How long a connection may sit idle before it is closed.
///
/// Origins close idle connections on timers of their own — 5 s for Node and
/// Apache, 75 s for nginx — and a request sent down a connection the origin is
/// closing at that instant fails. Past this long, the chance of that is not
/// worth the handshake saved. A request that can be sent again is retried on a
/// fresh connection when it happens anyway; see [`FRESH_ENOUGH`] for one that
/// cannot.
pub(crate) const IDLE_LIMIT: Duration = Duration::from_secs(15);

/// How long a connection may have been idle and still carry a request that
/// could not be sent twice.
///
/// A request with a body streams it straight from the client, so if the origin
/// closes the connection under it there is nothing left to send again: the
/// client gets a 502. Keeping such requests to connections that were busy a
/// moment ago stays well inside the shortest common server timeout (5 s), so
/// the race needs an origin that closes connections far sooner than anyone
/// configures them to.
pub(crate) const FRESH_ENOUGH: Duration = Duration::from_secs(2);

/// Idle connections kept per key. An HTTP/2 client can have a hundred requests
/// in flight on one connection to this proxy, each of which needs an HTTP/1.1
/// connection of its own upstream; this bounds how many of those outlive the
/// burst.
pub(crate) const MAX_IDLE_PER_KEY: usize = 16;

/// Idle connections kept per client connection, whatever their keys.
///
/// One keep-alive connection to the proxy can ask for a different host with
/// every request — a crawler, or a script, pointed at the proxy — and each
/// would leave a connection behind for [`IDLE_LIMIT`]. At a thousand hosts a
/// second that is fifteen thousand sockets, which is the file-descriptor limit
/// on most machines. Past this many, the one idle longest is closed.
pub(crate) const MAX_IDLE: usize = 32;

/// Everything about a request that decides which connection it needs.
///
/// Missing a field here would let a request ride a connection made for a
/// different one: to another address, under another TLS policy, or through a
/// proxy that authenticated someone else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    /// Where the connection goes: the origin, or — through a proxy — the
    /// address the proxy is asked to reach. Includes a `host://` override.
    pub addr: (String, u16),
    /// The host and port that were requested, which the `Host` header, the SNI
    /// and an absolute-form URI are built from.
    pub requested: (String, u16),
    /// `Some` when the origin speaks TLS: what the handshake was allowed to be.
    pub tls: Option<TlsPolicy>,
    /// An `internal-proxy://` hop stripped the origin's TLS.
    pub tls_stripped: bool,
    /// The upstream proxy, credentials and all.
    pub proxy: Option<ProxyRoute>,
    /// HTTP/2 was offered in the TLS handshake. A connection made with the
    /// offer can be h2 or HTTP/1.1, whichever the origin chose; one made
    /// without it is always HTTP/1.1.
    pub h2: bool,
}

/// The TLS half of a [`Key`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TlsPolicy {
    pub versions: TlsVersions,
    pub ciphers: Option<CipherPolicy>,
    /// The client certificate presented and the roots trusted, as the digest
    /// [`crate::proxy::tls_options::TlsExtras`] computes. A connection the
    /// origin authenticated as one client must never carry a request made
    /// under a rule that named another, or none.
    pub extras: Option<String>,
}

/// The proxy half of a [`Key`]: the hop, and what was said to it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProxyRoute {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub host_override: Option<HostOverride>,
    pub tunnel: bool,
    /// The `Proxy-Authorization` presented on the hop — the proxy URL's own,
    /// or the client's when the URL has none. The proxy decides who the tunnel
    /// belongs to from this, so it is part of the connection's identity.
    pub auth: Option<String>,
    /// The `User-Agent` echoed on `CONNECT`, when it is.
    pub user_agent: Option<String>,
    pub connection_close: bool,
}

/// An open origin connection: the handle requests are sent on, the address it
/// reached, and its number — see [`super::timing::Timings::connection`].
pub(crate) struct Conn {
    pub sender: SendRequest<DynBody>,
    pub peer: Option<SocketAddr>,
    pub number: u64,
}

/// An HTTP/2 connection, which every request to its key shares.
#[derive(Clone)]
pub(crate) struct Session {
    pub sender: http2::SendRequest<DynBody>,
    pub peer: Option<SocketAddr>,
    pub number: u64,
}

/// The origin connections one client connection is holding for reuse.
///
/// Cheap to clone: every request on the client connection carries a handle in
/// its extensions, and the idle connections close when the last handle goes —
/// that is, once the client connection and every request on it have finished.
#[derive(Clone, Default)]
pub struct ConnPool(Arc<Mutex<Idle>>);

#[derive(Default)]
struct Idle {
    parked: Vec<Parked>,
    sessions: Vec<Shared>,
    /// Keys whose origin answered an h2 offer with HTTP/1.1.
    h1_only: HashSet<Key>,
    /// One lock per key that may speak h2, held while its connection is made.
    opening: HashMap<Key, Arc<tokio::sync::Mutex<()>>>,
    /// Keys whose last attempt under that lock ended with neither an h2
    /// connection nor an answer of HTTP/1.1 — it failed.
    failed: HashSet<Key>,
}

struct Shared {
    key: Key,
    session: Session,
    last_used: Instant,
}

struct Parked {
    key: Key,
    conn: Conn,
    since: Instant,
}

impl ConnPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// An idle connection for `key` that has not been idle for `max_idle`, most
    /// recently used first — the one least likely to have been closed by now.
    pub(crate) fn take(&self, key: &Key, max_idle: Duration) -> Option<Conn> {
        let mut idle = self.0.lock().unwrap();
        // What the origin closed while it sat here is gone for good.
        idle.parked.retain(|c| !c.conn.sender.is_closed());
        let now = Instant::now();
        let at = idle.parked.iter().rposition(|c| {
            &c.key == key && c.conn.sender.is_ready() && now.duration_since(c.since) < max_idle
        })?;
        Some(idle.parked.remove(at).conn)
    }

    /// Park `conn` for the next request once its current response has been
    /// read to the end, and close it after [`IDLE_LIMIT`] unused.
    ///
    /// hyper answers "ready" only when the response finished cleanly on a
    /// connection both ends meant to keep; a response that was abandoned, or
    /// that the origin marked `Connection: close`, closes the connection and
    /// the wait ends in an error. Nothing is parked in that case.
    ///
    /// The task holds the pool weakly: a client that has gone does not keep
    /// its pool alive by having had a response in flight.
    pub(crate) fn park_when_ready(&self, key: Key, mut conn: Conn) {
        let pool = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            if conn.sender.ready().await.is_err() {
                return;
            }
            let number = conn.number;
            if !park(&pool, key, conn, Instant::now()) {
                return;
            }
            tokio::time::sleep(IDLE_LIMIT).await;
            if let Some(inner) = pool.upgrade() {
                inner
                    .lock()
                    .unwrap()
                    .parked
                    .retain(|c| c.conn.number != number);
            }
        });
    }

    /// The h2 connection for `key`, if one is open and still taking requests.
    pub(crate) fn session(&self, key: &Key) -> Option<Session> {
        let mut idle = self.0.lock().unwrap();
        // A connection the origin closed, or sent GOAWAY on, takes no more.
        idle.sessions.retain(|s| s.session.sender.is_ready());
        let shared = idle.sessions.iter_mut().find(|s| &s.key == key)?;
        shared.last_used = Instant::now();
        Some(shared.session.clone())
    }

    /// Keep `session` for every later request to `key`, and close it once it has
    /// gone [`IDLE_LIMIT`] without starting one. Requests still streaming on it
    /// then keep it open until they finish; nothing new is sent on it.
    pub(crate) fn share(&self, key: Key, session: Session) {
        let number = session.number;
        {
            let mut idle = self.0.lock().unwrap();
            idle.failed.remove(&key);
            idle.sessions.retain(|s| s.key != key);
            idle.sessions.push(Shared {
                key,
                session,
                last_used: Instant::now(),
            });
        }
        let pool = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(IDLE_LIMIT).await;
                let Some(inner) = pool.upgrade() else {
                    return;
                };
                let mut idle = inner.lock().unwrap();
                let Some(at) = idle
                    .sessions
                    .iter()
                    .position(|s| s.session.number == number)
                else {
                    return;
                };
                if idle.sessions[at].last_used.elapsed() >= IDLE_LIMIT {
                    idle.sessions.remove(at);
                    return;
                }
            }
        });
    }

    /// Forget the h2 connection numbered `number`: a request just failed on it.
    pub(crate) fn forget_session(&self, number: u64) {
        let mut idle = self.0.lock().unwrap();
        idle.sessions.retain(|s| s.session.number != number);
    }

    /// Did this origin answer an h2 offer with HTTP/1.1 before?
    pub(crate) fn speaks_http1(&self, key: &Key) -> bool {
        self.0.lock().unwrap().h1_only.contains(key)
    }

    /// Remember that this origin answered an h2 offer with HTTP/1.1, so that
    /// nobody waits in [`opening`](Self::opening) for an h2 connection to it.
    pub(crate) fn mark_http1(&self, key: Key) {
        let mut idle = self.0.lock().unwrap();
        idle.failed.remove(&key);
        idle.h1_only.insert(key);
    }

    /// Wait for the turn to open a connection to `key`, which may be h2.
    ///
    /// The requests of a page arrive together. Without this each would open
    /// its own connection before any of them knew the origin speaks h2, and
    /// the first burst — the one that decides how fast the page loads — would
    /// cost as many handshakes as there are requests. The turn is held only
    /// while the connection is made; whoever gets it next finds the session,
    /// or learns that there will not be one.
    ///
    /// Nobody queues behind a failure. If the attempt before this one ended
    /// with no connection at all, the rest of the burst connect side by side,
    /// as they would with no pool: waiting in line for an origin that is not
    /// answering would cost each of them the whole connect budget in turn.
    pub(crate) async fn opening(&self, key: &Key) -> Turn {
        let gate = {
            let mut idle = self.0.lock().unwrap();
            idle.opening.entry(key.clone()).or_default().clone()
        };
        let held = gate.lock_owned().await;
        let idle = self.0.lock().unwrap();
        if idle.h1_only.contains(key)
            || idle
                .sessions
                .iter()
                .any(|s| &s.key == key && s.session.sender.is_ready())
        {
            return Turn::Settled;
        }
        if idle.failed.contains(key) {
            return Turn::Alone;
        }
        drop(idle);
        Turn::Open(Box::new(Opening {
            pool: self.clone(),
            key: key.clone(),
            _held: held,
        }))
    }

    /// How many connections are parked — for tests.
    #[cfg(test)]
    pub(crate) fn idle(&self) -> usize {
        self.0.lock().unwrap().parked.len()
    }

    /// Drop every h2 connection — for tests, standing in for an origin that
    /// went away.
    #[cfg(test)]
    pub(crate) fn close_sessions(&self) {
        self.0.lock().unwrap().sessions.clear();
    }
}

/// What [`ConnPool::opening`] found when this request's turn came.
pub(crate) enum Turn {
    /// The connection was settled while it waited — an h2 session to share,
    /// or the news that the origin speaks HTTP/1.1.
    Settled,
    /// The last attempt failed: connect, and hold nobody up doing it.
    Alone,
    /// Make the connection; the rest of the burst waits for this to drop.
    /// Boxed: a whole [`Key`] rides in it, and the other two carry nothing.
    Open(Box<Opening>),
}

/// The turn to make the connection a burst is waiting for.
///
/// Dropped once the connection is made or has failed, which lets the next
/// waiter in. What it finds is recorded here: dropped with neither a session
/// shared nor HTTP/1.1 marked, the attempt failed, and the waiters go
/// [`Turn::Alone`].
pub(crate) struct Opening {
    pool: ConnPool,
    key: Key,
    _held: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for Opening {
    fn drop(&mut self) {
        let mut idle = self.pool.0.lock().unwrap();
        let settled =
            idle.h1_only.contains(&self.key) || idle.sessions.iter().any(|s| s.key == self.key);
        if settled {
            idle.failed.remove(&self.key);
        } else {
            idle.failed.insert(self.key.clone());
        }
    }
}

/// Put a ready connection in the pool as idle since `since`, unless the pool is
/// gone or full for its key. False when it was not parked, and is dropped —
/// which closes it.
fn park(pool: &Weak<Mutex<Idle>>, key: Key, conn: Conn, since: Instant) -> bool {
    let Some(inner) = pool.upgrade() else {
        return false;
    };
    let mut idle = inner.lock().unwrap();
    if idle.parked.iter().filter(|c| c.key == key).count() >= MAX_IDLE_PER_KEY {
        return false;
    }
    if idle.parked.len() >= MAX_IDLE {
        // Parked in the order they went idle, so the first is the oldest.
        idle.parked.remove(0);
    }
    idle.parked.push(Parked { key, conn, since });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str) -> Key {
        Key {
            addr: (host.to_string(), 80),
            requested: (host.to_string(), 80),
            tls: None,
            tls_stripped: false,
            proxy: None,
            h2: false,
        }
    }

    /// A real sender over an in-memory pipe, ready for a request: what the
    /// pool holds, without a socket.
    async fn sender() -> SendRequest<DynBody> {
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(ours))
                .await
                .expect("handshake");
        tokio::spawn(async move {
            let _theirs = _theirs;
            let _ = conn.await;
        });
        sender.ready().await.expect("ready");
        sender
    }

    async fn conn() -> Conn {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NUMBER: AtomicU64 = AtomicU64::new(0);
        Conn {
            sender: sender().await,
            peer: None,
            number: NUMBER.fetch_add(1, Ordering::Relaxed),
        }
    }

    async fn park_idle_for(pool: &ConnPool, k: Key, idle: Duration) {
        assert!(park(
            &Arc::downgrade(&pool.0),
            k,
            conn().await,
            Instant::now() - idle
        ));
    }

    /// A request that cannot be sent twice takes only a connection that was
    /// busy a moment ago; one that can takes any the idle limit still allows.
    #[tokio::test]
    async fn how_long_a_connection_has_been_idle_decides_who_may_take_it() {
        let pool = ConnPool::new();
        park_idle_for(&pool, key("a"), Duration::from_secs(5)).await;
        assert!(
            pool.take(&key("a"), FRESH_ENOUGH).is_none(),
            "5 s idle is past what a request with a body may risk"
        );
        assert!(pool.take(&key("a"), IDLE_LIMIT).is_some());
    }

    #[tokio::test]
    async fn a_connection_is_only_taken_for_its_own_key() {
        let pool = ConnPool::new();
        park_idle_for(&pool, key("a"), Duration::ZERO).await;
        assert!(pool.take(&key("b"), IDLE_LIMIT).is_none());
        assert!(pool.take(&key("a"), IDLE_LIMIT).is_some());
        assert!(
            pool.take(&key("a"), IDLE_LIMIT).is_none(),
            "taken means gone"
        );
    }

    /// A burst of concurrent requests leaves at most this many behind per key;
    /// the rest close.
    #[tokio::test]
    async fn the_idle_connections_per_key_are_bounded() {
        let pool = ConnPool::new();
        let weak = Arc::downgrade(&pool.0);
        for _ in 0..MAX_IDLE_PER_KEY {
            assert!(park(&weak, key("a"), conn().await, Instant::now()));
        }
        assert!(!park(&weak, key("a"), conn().await, Instant::now()));
        assert!(
            park(&weak, key("b"), conn().await, Instant::now()),
            "another key has its own allowance"
        );
        assert_eq!(pool.idle(), MAX_IDLE_PER_KEY + 1);
    }

    /// A client asking for a new host with every request keeps only the most
    /// recent ones.
    #[tokio::test]
    async fn the_idle_connections_per_client_are_bounded_too() {
        let pool = ConnPool::new();
        let weak = Arc::downgrade(&pool.0);
        for host in 0..MAX_IDLE + 3 {
            assert!(park(
                &weak,
                key(&format!("h{host}")),
                conn().await,
                Instant::now()
            ));
        }
        assert_eq!(pool.idle(), MAX_IDLE);
        assert!(
            pool.take(&key("h0"), IDLE_LIMIT).is_none(),
            "the oldest went first"
        );
        let newest = key(&format!("h{}", MAX_IDLE + 2));
        assert!(pool.take(&newest, IDLE_LIMIT).is_some());
    }

    /// A burst waits for the first attempt, and only for a successful one: a
    /// turn dropped with nothing to show lets the rest connect side by side.
    #[tokio::test]
    async fn nobody_queues_behind_a_failed_attempt() {
        let pool = ConnPool::new();
        let k = Key {
            h2: true,
            ..key("a")
        };
        let Turn::Open(first) = pool.opening(&k).await else {
            panic!("the first request makes the connection");
        };
        drop(first); // no session, no HTTP/1.1: it failed
        assert!(matches!(pool.opening(&k).await, Turn::Alone));

        // Succeeding clears it, and the next burst waits again.
        pool.mark_http1(k.clone());
        assert!(matches!(pool.opening(&k).await, Turn::Settled));
    }

    /// Once the client connection's last handle is gone there is nowhere to
    /// park, and the connection is dropped — which closes it.
    #[tokio::test]
    async fn nothing_is_parked_once_the_client_connection_is_gone() {
        let pool = ConnPool::new();
        let weak = Arc::downgrade(&pool.0);
        drop(pool);
        assert!(!park(&weak, key("a"), conn().await, Instant::now()));
    }
}
