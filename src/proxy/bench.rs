//! Cost of the capture tee, measured against the same body without it.
//!
//! Not part of the normal suite — these are measurements, not assertions, and
//! they are meaningless in a debug build. Run them with:
//!
//! ```text
//! cargo test --release -- --ignored --nocapture bench::
//! ```
//!
//! Method, throughout: the configurations under test are driven **round robin
//! within one loop**, so a scheduler hiccup or a thermal excursion lands on
//! every configuration rather than on whichever one happened to run during it.
//! Each iteration's wall time is kept, and the report gives mean/p50/p95 over
//! the whole run so the noise floor stays visible instead of being averaged
//! away. The bodies are pre-built `Bytes` sliced per frame, so a refcount bump
//! is all that separates the measurement from the tee itself.
//!
//! [`proxied_request_latency`] is the end-to-end counterpart: real proxies,
//! real sockets, concurrent clients. It compares preview caps rather than tee
//! against no-tee, because there is no configuration that removes the tee — at
//! a cap of 0 it still counts the body's bytes, which is what the session list
//! shows as the body size. The microbenchmarks above are where tee-against-no-
//! tee is measured; this one says what that difference is worth against a
//! socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::Capture;
use super::body::{BodyError, DynBody, tee};
use crate::ca::CertAuthority;
use crate::config::Config;
use crate::rules::RuleManager;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// A body that hands out `total` bytes in `chunk`-sized frames, every one of
/// them already ready. No I/O, no allocation per frame: the frames are slices
/// of one pre-built buffer, so what is timed is the body pipeline alone.
struct ChunkedBody {
    source: Bytes,
    remaining: usize,
    chunk: usize,
}

impl ChunkedBody {
    fn new(source: Bytes, chunk: usize) -> Self {
        let remaining = source.len();
        ChunkedBody {
            source,
            remaining,
            chunk,
        }
    }
}

impl Body for ChunkedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let take = this.chunk.min(this.remaining);
        let start = this.source.len() - this.remaining;
        this.remaining -= take;
        Poll::Ready(Some(Ok(Frame::data(
            this.source.slice(start..start + take),
        ))))
    }
}

/// Poll a body to exhaustion, returning the bytes seen. Every frame is ready,
/// so no runtime is involved and no wakeup latency enters the measurement.
fn drain(body: DynBody) -> usize {
    let mut body = Box::pin(body);
    let mut cx = Context::from_waker(Waker::noop());
    let mut seen = 0usize;
    loop {
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    seen += std::hint::black_box(data).len();
                }
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => break,
            Poll::Pending => unreachable!("every frame of a ChunkedBody is ready"),
        }
    }
    seen
}

/// Timings for one configuration, in the order they were taken.
struct Samples {
    label: &'static str,
    times: Vec<Duration>,
}

impl Samples {
    fn new(label: &'static str) -> Self {
        Samples {
            label,
            times: Vec::new(),
        }
    }

    fn stats(&self) -> (Duration, Duration, Duration) {
        let mut sorted = self.times.clone();
        sorted.sort_unstable();
        let sum: Duration = sorted.iter().sum();
        let mean = sum / sorted.len() as u32;
        let at = |q: f64| sorted[((sorted.len() as f64 * q) as usize).min(sorted.len() - 1)];
        (mean, at(0.50), at(0.95))
    }
}

/// Print one table: every configuration's mean/p50/p95, and what the mean costs
/// over the first row, which is always the cheapest configuration. `frames`
/// divides that delta down to a per-frame figure where the number of frames is
/// the interesting axis; pass `None` where it is not.
///
/// Deliberately no throughput column for the microbenchmarks. Their baseline
/// body hands out slices of a buffer that is already resident, so its "GB/s"
/// would describe the poll loop and nothing a network could do; the honest
/// quantity is the delta the tee adds.
fn report(title: &str, frames: Option<usize>, runs: &[Samples]) {
    println!("\n{title}  ({} samples per row)", runs[0].times.len());
    println!(
        "  {:<22} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "configuration",
        "mean",
        "p50",
        "p95",
        "vs. first",
        if frames.is_some() { "per frame" } else { "" }
    );
    let base = runs[0].stats().0;
    for r in runs {
        let (mean, p50, p95) = r.stats();
        let delta = mean.as_secs_f64() - base.as_secs_f64();
        let per_frame = match frames {
            Some(f) => format!("{:>9.1} ns", delta * 1e9 / f as f64),
            None => String::new(),
        };
        println!(
            "  {:<22} {:>9.1?} {:>9.1?} {:>9.1?} {:>12} {per_frame:>12}",
            r.label,
            mean,
            p50,
            p95,
            signed(delta),
        );
    }
}

/// A signed duration. The delta against the baseline can come out negative —
/// that is what the noise floor looks like — and clamping it at zero would
/// quietly turn "indistinguishable" into "free".
fn signed(secs: f64) -> String {
    let sign = if secs < 0.0 { "-" } else { "+" };
    format!("{sign}{:.1?}", Duration::from_secs_f64(secs.abs()))
}

/// The configurations paired with their slot, starting from `offset` and
/// wrapping — see the call sites for why the order rotates.
fn rotated<T: Copy>(configs: &[T], offset: usize) -> Vec<(usize, T)> {
    (0..configs.len())
        .map(|k| {
            let slot = (offset + k) % configs.len();
            (slot, configs[slot])
        })
        .collect()
}

/// Body of `size` bytes that does not compress to nothing, so a gzip capture
/// has real work to do rather than folding the whole thing into a few bytes.
fn payload(size: usize) -> Bytes {
    let mut v = Vec::with_capacity(size);
    let mut x: u32 = 0x1234_5678;
    while v.len() < size {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // Bias towards printable bytes: real captured bodies are mostly text,
        // and text is what the preview decoder is built for.
        v.push(b' ' + (x >> 24) as u8 % 95);
    }
    Bytes::from(v)
}

fn gzipped(data: &[u8]) -> Bytes {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("gzip");
    Bytes::from(e.finish().expect("gzip finish"))
}

/// Does the tee cost anything measurable on a plain (identity) body, and is
/// that cost flat once the preview cap is reached?
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn tee_overhead_by_body_size() {
    let iterations = 200;
    let chunk = 16 * KIB;

    for &size in &[4 * KIB, 64 * KIB, MIB, 16 * MIB] {
        let src = payload(size);
        let mut runs = vec![
            Samples::new("no tee"),
            Samples::new("tee, cap 0"),
            Samples::new("tee, cap 16 KiB"),
            Samples::new("tee, cap = body"),
        ];
        // Warmup, then the measured loop. Round robin: one iteration of each
        // configuration before the next iteration of the first.
        for i in 0..iterations + 20 {
            // Rotate the order each iteration. A fixed order would hand every
            // per-iteration warm-up cost to whichever configuration is always
            // first, which is the baseline every other row is measured against.
            for (slot, cap) in rotated(&[None, Some(0), Some(16 * KIB), Some(size)], i) {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match cap {
                    None => body,
                    Some(cap) => tee(body, Capture::new(Some("text/plain".into()), None, cap)),
                };
                let t = Instant::now();
                let seen = drain(body);
                let dt = t.elapsed();
                assert_eq!(seen, size, "the tee must forward every byte");
                if i >= 20 {
                    runs[slot].times.push(dt);
                }
            }
        }
        report(
            &format!(
                "identity body, {} in {} KiB frames ({} frames)",
                human(size),
                chunk / KIB,
                size.div_ceil(chunk)
            ),
            Some(size.div_ceil(chunk)),
            &runs,
        );
    }
}

/// The per-frame cost is a mutex acquisition, so it scales with frame count
/// rather than byte count. Hold the body size still and shrink the frames.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn tee_overhead_by_frame_size() {
    let iterations = 200;
    let size = MIB;
    let src = payload(size);

    for &chunk in &[64 * KIB, 16 * KIB, 4 * KIB, 512] {
        let mut runs = vec![Samples::new("no tee"), Samples::new("tee, cap 16 KiB")];
        for i in 0..iterations + 20 {
            for (slot, cap) in rotated(&[None, Some(16 * KIB)], i) {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match cap {
                    None => body,
                    Some(cap) => tee(body, Capture::new(Some("text/plain".into()), None, cap)),
                };
                let t = Instant::now();
                let seen = drain(body);
                let dt = t.elapsed();
                assert_eq!(seen, size);
                if i >= 20 {
                    runs[slot].times.push(dt);
                }
            }
        }
        report(
            &format!(
                "identity body, 1 MiB in {} frames of {}",
                size.div_ceil(chunk),
                human(chunk)
            ),
            Some(size.div_ceil(chunk)),
            &runs,
        );
    }
}

/// A compressed body is the expensive case: the preview is decoded so it can
/// be read, which means running gzip over the front of the body.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn tee_overhead_when_decoding() {
    let iterations = 200;
    let chunk = 16 * KIB;

    for &size in &[64 * KIB, MIB, 16 * MIB] {
        let raw = payload(size);
        let src = gzipped(&raw);
        let wire = src.len();
        let mut runs = vec![
            Samples::new("no tee"),
            Samples::new("tee, identity"),
            Samples::new("tee, gzip decode"),
        ];
        for i in 0..iterations + 20 {
            for (slot, enc) in rotated(&[None, Some(None), Some(Some("gzip"))], i) {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match enc {
                    None => body,
                    Some(enc) => tee(body, Capture::new(Some("text/plain".into()), enc, 16 * KIB)),
                };
                let t = Instant::now();
                let seen = drain(body);
                let dt = t.elapsed();
                assert_eq!(seen, wire);
                if i >= 20 {
                    runs[slot].times.push(dt);
                }
            }
        }
        report(
            &format!(
                "gzip body, {} raw / {} on the wire, {} KiB frames",
                human(size),
                human(wire),
                chunk / KIB
            ),
            Some(wire.div_ceil(chunk)),
            &runs,
        );
    }
}

/// What a finished capture still holds. The preview is capped, but a decoding
/// capture also keeps the decoder — and the decoder keeps everything it has
/// decompressed so far.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn capture_retained_bytes() {
    println!("\nbytes still held by one capture after the body has been drained");
    println!(
        "  {:<30} {:>12} {:>12} {:>14}",
        "body", "preview cap", "preview", "decoder buffer"
    );
    for &(label, size, compressible) in &[
        ("1 MiB text, identity", MIB, false),
        ("16 MiB text, identity", 16 * MIB, false),
        ("1 MiB text, gzip", MIB, true),
        ("16 MiB text, gzip", 16 * MIB, true),
        ("16 MiB zeros, gzip", 16 * MIB, true),
    ] {
        let raw = if label.contains("zeros") {
            Bytes::from(vec![0u8; size])
        } else {
            payload(size)
        };
        let (src, enc) = if compressible {
            (gzipped(&raw), Some("gzip"))
        } else {
            (raw, None)
        };
        let cap = Capture::new(Some("text/plain".into()), enc, 16 * KIB);
        let body = tee(ChunkedBody::new(src, 16 * KIB).boxed(), cap.clone());
        drain(body); // dropping the tee is what releases the decompressor
        let st = cap.0.lock().unwrap();
        let decoder = match &st.decoder {
            super::BodyDecoder::Gzip(d) => d.get_ref().capacity(),
            super::BodyDecoder::Deflate(d) => d.get_ref().capacity(),
            super::BodyDecoder::Brotli(d) => d.get_ref().capacity(),
            // Identity, failed, or already released: nothing held.
            _ => 0,
        };
        println!(
            "  {:<30} {:>12} {:>12} {:>14}",
            label,
            human(16 * KIB),
            human(st.data.capacity()),
            human(decoder)
        );
    }
}

fn human(n: usize) -> String {
    if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

// ---------------------------------------------------------------------------
// End to end: real proxies, real sockets, concurrent clients.
// ---------------------------------------------------------------------------

/// A canned origin. Answers every request with the same pre-rendered response,
/// so the server side contributes a `write` and nothing else to the timings.
async fn origin(response: Bytes, accepted: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            let response = response.clone();
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                let mut buf = [0u8; 8192];
                let mut pending = Vec::new();
                loop {
                    // Keep-alive: one response per request line seen.
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    pending.extend_from_slice(&buf[..n]);
                    while let Some(end) = find_headers_end(&pending) {
                        pending.drain(..end);
                        if sock.write_all(&response).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    port
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Start a proxy with the given preview cap, returning the port it listens on.
async fn proxy_with_cap(cap: usize, dir: &std::path::Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // hand the port to the proxy itself

    let config = Config {
        port,
        host: Some("127.0.0.1".parse().unwrap()),
        storage_dir: dir.join(format!("cap-{cap}")),
        body_preview_cap: cap,
        intercept_https: false,
        ..Config::default()
    };
    let ca = CertAuthority::load_or_create(&config).expect("root CA");
    let state = Arc::new(super::AppState::new(config, RuleManager::new(), ca));
    tokio::spawn(async move {
        let _ = super::run(state).await;
    });
    // Wait for the listener to be up rather than sleeping a guessed interval.
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return port;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("proxy on {port} never came up");
}

/// One keep-alive client connection to `proxy_port`, fetching from `origin_port`
/// in absolute form (which is what a forward proxy expects).
struct Client {
    sock: TcpStream,
    request: Vec<u8>,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(proxy_port: u16, origin_port: u16) -> Client {
        let sock = TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .expect("connect to proxy");
        let _ = sock.set_nodelay(true);
        let request = format!(
            "GET http://127.0.0.1:{origin_port}/body HTTP/1.1\r\n\
             Host: 127.0.0.1:{origin_port}\r\n\
             Connection: keep-alive\r\n\r\n"
        )
        .into_bytes();
        Client {
            sock,
            request,
            buf: Vec::with_capacity(64 * KIB),
        }
    }

    /// Issue one request and read the whole response. Returns its duration.
    async fn round_trip(&mut self) -> Duration {
        let start = Instant::now();
        self.sock.write_all(&self.request).await.expect("write");
        self.buf.clear();
        let mut chunk = [0u8; 32 * KIB];
        let mut want: Option<usize> = None;
        loop {
            let n = self.sock.read(&mut chunk).await.expect("read");
            assert!(n > 0, "proxy closed the connection mid-response");
            self.buf.extend_from_slice(&chunk[..n]);
            if want.is_none()
                && let Some(head) = find_headers_end(&self.buf)
            {
                let headers = String::from_utf8_lossy(&self.buf[..head]).to_ascii_lowercase();
                let len: usize = headers
                    .split("content-length:")
                    .nth(1)
                    .and_then(|s| s.split("\r\n").next())
                    .and_then(|s| s.trim().parse().ok())
                    .expect("a content-length on the proxied response");
                want = Some(head + len);
            }
            if want.is_some_and(|w| self.buf.len() >= w) {
                return start.elapsed();
            }
        }
    }
}

/// Build the canned origin response for a body of `size`, optionally gzipped.
fn canned_response(size: usize, gzip: bool) -> Bytes {
    let raw = payload(size);
    let (body, enc) = if gzip {
        (gzipped(&raw), "Content-Encoding: gzip\r\n")
    } else {
        (raw, "")
    };
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{enc}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    Bytes::from(out)
}

/// What the capture costs a request that actually crosses a socket, under
/// concurrency, at preview caps spanning the body size.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn proxied_request_latency() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let dir = std::env::temp_dir().join(format!("whix-bench-{}", std::process::id()));

    rt.block_on(async {
        // One proxy per configuration, all live at once, so a client can send
        // successive requests to each and no run is measured at a different
        // moment from the others.
        let caps = [0usize, 16 * KIB, MIB];
        let labels = ["cap 0 (count only)", "cap 16 KiB (default)", "cap 1 MiB"];
        let mut ports = Vec::new();
        for cap in caps {
            ports.push(proxy_with_cap(cap, &dir).await);
        }

        for &(size, gzip) in &[(4 * KIB, false), (MIB, false), (MIB, true)] {
            let accepted = Arc::new(AtomicUsize::new(0));
            let origin_port = origin(canned_response(size, gzip), accepted.clone()).await;
            for &concurrency in &[1usize, 32] {
                // Sized for when every request opened an upstream connection
                // of its own and held an ephemeral port through TIME_WAIT. Each
                // client here keeps one connection per proxy, so the pool now
                // reuses one upstream connection per client and the line
                // printed below says so.
                let requests = if concurrency == 1 { 150 } else { 25 };
                let before = accepted.load(Ordering::Relaxed);
                let mut workers = Vec::new();
                for _ in 0..concurrency {
                    let ports = ports.clone();
                    workers.push(tokio::spawn(async move {
                        let mut clients = Vec::new();
                        for &p in &ports {
                            clients.push(Client::connect(p, origin_port).await);
                        }
                        let mut times = vec![Vec::new(); ports.len()];
                        // Warmup, then measure. Round robin over the
                        // configurations inside the request loop.
                        for i in 0..requests + 10 {
                            for k in 0..clients.len() {
                                let slot = (i + k) % clients.len();
                                let dt = clients[slot].round_trip().await;
                                if i >= 10 {
                                    times[slot].push(dt);
                                }
                            }
                        }
                        times
                    }));
                }

                let mut runs: Vec<Samples> = labels.iter().map(|l| Samples::new(l)).collect();
                for w in workers {
                    for (slot, times) in w.await.expect("worker").into_iter().enumerate() {
                        runs[slot].times.extend(times);
                    }
                }
                let issued = concurrency * (requests + 10) * ports.len();
                let upstream = accepted.load(Ordering::Relaxed) - before;
                report(
                    &format!(
                        "GET {} {} body, {concurrency} concurrent connection(s)",
                        human(size),
                        if gzip { "gzip" } else { "identity" },
                    ),
                    None,
                    &runs,
                );
                println!(
                    "    {upstream} upstream connections for {issued} requests \
                     ({:.2} per request)",
                    upstream as f64 / issued as f64
                );
                // Let TIME_WAIT drain before the next round claims more ports.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    });
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// What reading the ClientHello costs.
// ---------------------------------------------------------------------------

/// A plugin that answers the certificate hook with "no opinion", in process.
///
/// It is here to price the *dispatch* — the rule resolution, the manifest check,
/// the call — with nothing on the other side of it. A remote plugin adds one
/// local HTTP round trip on top, which is the same price every other remote hook
/// in this system pays and is measured with those.
struct SilentSni;

impl crate::plugins::RustPlugin for SilentSni {
    fn name(&self) -> &str {
        "bench-sni"
    }

    fn manifest(&self) -> crate::plugins::PluginManifest {
        crate::plugins::PluginManifest {
            sni: true,
            ..crate::plugins::PluginManifest::none(self.name())
        }
    }

    fn sni(&self, _req: &crate::plugins::sni::SniReq) -> crate::plugins::sni::SniVerdict {
        crate::plugins::sni::SniVerdict::Generated
    }

    fn on_request(&self, _req: &crate::plugins::PluginReq) -> crate::plugins::PluginResult {
        crate::plugins::PluginResult::default()
    }
}

/// The name every handshake in these benchmarks asks for.
const BENCH_SNI: &str = "bench.example.com";

/// How an intercepted connection's TLS is set up.
#[derive(Clone, Copy)]
enum Setup {
    /// The pre-change path: build the acceptor from the tunnel's hostname and
    /// hand rustls the socket.
    Eager,
    /// Read the ClientHello first, replay it into the handshake. No
    /// `sniCallback://` rule exists, so the decision is one `bool`.
    Peek,
    /// As above, with an `sniCallback://` rule in the file that does not match
    /// this connection — the flag is set, so the rules actually resolve.
    RuleMiss,
    /// A matching rule, dispatched to an in-process plugin that has no opinion.
    Plugin,
    /// One socket read and the replay wrapper, with no ClientHello parse at
    /// all. It separates what the *plumbing* of the restructure costs from what
    /// rustls parsing the hello a second time costs.
    RawRead,
}

fn bench_state(
    setup: Setup,
    dir: &std::path::Path,
    ca: Arc<CertAuthority>,
) -> Arc<super::AppState> {
    let label = match setup {
        Setup::Eager => "eager",
        Setup::Peek => "peek",
        Setup::RuleMiss => "miss",
        Setup::Plugin => "plugin",
        Setup::RawRead => "rawread",
    };
    let config = Config {
        storage_dir: dir.join(label),
        persist_sessions: false,
        ..Config::default()
    };
    let mut rules = RuleManager::new();
    match setup {
        Setup::Eager | Setup::Peek | Setup::RawRead => {}
        Setup::RuleMiss => rules.set_text("somewhere.else sniCallback://bench-sni"),
        Setup::Plugin => rules.set_text("bench.example.com sniCallback://bench-sni"),
    }
    let mut plugins = crate::plugins::Plugins::new();
    plugins.register_rust(Box::new(SilentSni));
    Arc::new(super::AppState::with_plugins(config, rules, ca, plugins))
}

/// Serve one handshake the way `serve_tunnel` would under `setup`.
async fn bench_accept(setup: Setup, state: &Arc<super::AppState>, stream: TcpStream) {
    // A fixed address rather than `peer_addr()`: the real caller already has it,
    // so charging this measurement a syscall the proxy does not make would be
    // measuring the harness.
    let peer: std::net::SocketAddr = "127.0.0.1:51234".parse().unwrap();
    if let Setup::Eager = setup {
        let acceptor = state.ca.acceptor_for(BENCH_SNI).expect("acceptor");
        acceptor.accept(stream).await.ok();
        return;
    }
    let mut stream = stream;
    // The plumbing on its own: read once, replay, hand rustls the socket.
    if let Setup::RawRead = setup {
        let mut prefix = Vec::with_capacity(8192);
        tokio::io::AsyncReadExt::read_buf(&mut stream, &mut prefix)
            .await
            .ok();
        let s = super::sni::Prefixed::new(prefix, stream);
        let acceptor = state.ca.acceptor_for(BENCH_SNI).expect("acceptor");
        acceptor.accept(s).await.ok();
        return;
    }
    let hello = super::sni::peek_client_hello(&mut stream).await;
    let has_sni = hello.server_name.is_some();
    let name = hello.server_name.unwrap_or_else(|| BENCH_SNI.to_string());
    let stream = super::sni::Prefixed::new(hello.prefix, stream);
    let acceptor = match super::sni::decide(
        state,
        &name,
        &name,
        443,
        peer,
        has_sni,
        super::sni::Carried::Tls,
    )
    .await
    {
        super::sni::Decision::Generated => state.ca.acceptor_for(&name).expect("acceptor"),
        super::sni::Decision::Plugin(a) => a,
        // Neither is reachable in this benchmark — its rules name no plugin —
        // and both mean "no handshake here", which is the same thing to it.
        super::sni::Decision::Bypass(_)
        | super::sni::Decision::Unroutable(_)
        | super::sni::Decision::Cleartext(_) => return,
    };
    acceptor.accept(stream).await.ok();
}

/// What the restructure costs a real TLS handshake.
///
/// The question this answers is narrow on purpose: reading the ClientHello
/// ourselves means rustls parses it twice, and this says what that is worth
/// against the key exchange and signature that follow. Four configurations run
/// round robin inside one loop, so a scheduler hiccup lands on all of them.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn tls_handshake_latency() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let dir = std::env::temp_dir().join(format!("whix-sni-bench-{}", std::process::id()));

    rt.block_on(async {
        let setups = [
            Setup::Eager,
            Setup::RawRead,
            Setup::Peek,
            Setup::RuleMiss,
            Setup::Plugin,
        ];
        let labels = [
            "eager (pre-change)",
            "read + replay, no parse",
            "peek + replay",
            "peek + rule miss",
            "peek + rust plugin",
        ];
        // One CA for every configuration: separate roots would put a different
        // certificate on each row and measure the client's verifier as much as
        // the server's SNI stage.
        let ca_config = Config {
            storage_dir: dir.join("ca"),
            persist_sessions: false,
            ..Config::default()
        };
        let ca = CertAuthority::load_or_create(&ca_config).expect("root CA");
        ca.acceptor_for(BENCH_SNI).expect("warm the cert cache");

        let mut ports = Vec::new();
        for setup in setups {
            let state = bench_state(setup, &dir, ca.clone());
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            ports.push(listener.local_addr().unwrap().port());
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let _ = sock.set_nodelay(true);
                    let state = state.clone();
                    tokio::spawn(async move { bench_accept(setup, &state, sock).await });
                }
            });
        }

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.root_cert_der()).expect("trust the root");
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Every row serves the same name, so a ticket from one server would be
        // offered to the next. Resuming half the time and not the other half is
        // not a difference between these configurations.
        cfg.resumption = rustls::client::Resumption::disabled();
        let client_cfg = Arc::new(cfg);

        let mut runs: Vec<Samples> = labels.iter().map(|l| Samples::new(l)).collect();
        let iterations = 400usize;
        for i in 0..iterations + 20 {
            for k in 0..ports.len() {
                let slot = (i + k) % ports.len();
                let name = rustls::pki_types::ServerName::try_from(BENCH_SNI).unwrap();
                // The TCP connection is set up outside the timed region: an
                // ephemeral port and a SYN exchange are the same for every row,
                // and at this sample count they are the loudest thing in it.
                let sock = TcpStream::connect(("127.0.0.1", ports[slot]))
                    .await
                    .expect("connect");
                let _ = sock.set_nodelay(true);
                let start = Instant::now();
                tokio_rustls::TlsConnector::from(client_cfg.clone())
                    .connect(name, sock)
                    .await
                    .expect("handshake");
                let dt = start.elapsed();
                if i >= 20 {
                    runs[slot].times.push(dt);
                }
            }
        }
        report("TLS handshake through the SNI stage", None, &runs);
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ClientHello parse on its own, with no socket and no handshake around it.
///
/// This is the honest price of the restructure: everything else in the
/// handshake is unchanged, so whatever this costs is what a connection with no
/// `sniCallback://` rule now pays that it did not before. The first row is the
/// same loop without the parse, so the harness itself is subtracted out.
#[test]
#[ignore = "measurement, not an assertion; needs --release"]
fn client_hello_peek_cost() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        // A real ClientHello, produced by rustls rather than hand-written.
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(BENCH_SNI).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).expect("hello");
        println!("\nClientHello: {} bytes", hello.len());

        let mut runs = vec![
            Samples::new("copy the bytes only"),
            Samples::new("peek (parse + copy)"),
        ];
        for i in 0..5_000 + 200 {
            for k in 0..2 {
                let slot = (i + k) % 2;
                let start = Instant::now();
                if slot == 0 {
                    let mut cursor = std::io::Cursor::new(hello.clone());
                    let mut sink = Vec::new();
                    tokio::io::AsyncReadExt::read_to_end(&mut cursor, &mut sink)
                        .await
                        .expect("read");
                    std::hint::black_box(sink);
                } else {
                    let mut cursor = std::io::Cursor::new(hello.clone());
                    let peeked = super::sni::peek_client_hello(&mut cursor).await;
                    assert_eq!(peeked.server_name.as_deref(), Some(BENCH_SNI));
                    std::hint::black_box(peeked.prefix);
                }
                let dt = start.elapsed();
                if i >= 200 {
                    runs[slot].times.push(dt);
                }
            }
        }
        report("Reading one ClientHello", None, &runs);
    });
}
