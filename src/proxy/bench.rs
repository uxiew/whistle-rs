//! Cost of the capture tee, measured against the same body without it.
//!
//! Not part of the normal suite — these are measurements, not assertions, and
//! they are meaningless in a debug build. Run them with:
//!
//! ```text
//! cargo test --release -- --ignored --nocapture bench::
//! ```
//!
//! Method, in all three: the configurations under test are driven **round
//! robin within one loop**, so a scheduler hiccup or a thermal excursion lands
//! on every configuration rather than on whichever one happened to run during
//! it. Each iteration's wall time is kept, and the report gives mean/p50/p95
//! over the whole run so the noise floor stays visible instead of being
//! averaged away. The bodies are pre-built `Bytes` sliced per frame, so a
//! refcount bump is all that separates the measurement from the tee itself.

use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};

use super::Capture;
use super::body::{BodyError, DynBody, tee};

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
        Poll::Ready(Some(Ok(Frame::data(this.source.slice(start..start + take)))))
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
/// over the first row, per body and per frame.
///
/// Deliberately no throughput column. The baseline body hands out slices of a
/// buffer that is already resident, so its "GB/s" describes the poll loop and
/// nothing a network could do; the honest quantity is the delta the tee adds.
fn report(title: &str, frames: usize, runs: &[Samples]) {
    println!("\n{title}  ({} iterations)", runs[0].times.len());
    println!(
        "  {:<22} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "configuration", "mean", "p50", "p95", "vs. no tee", "per frame"
    );
    let base = runs[0].stats().0;
    for r in runs {
        let (mean, p50, p95) = r.stats();
        let delta = mean.as_secs_f64() - base.as_secs_f64();
        println!(
            "  {:<22} {:>9.1?} {:>9.1?} {:>9.1?} {:>+11.1?} {:>9.1} ns",
            r.label,
            mean,
            p50,
            p95,
            Duration::from_secs_f64(delta.max(0.0)),
            delta * 1e9 / frames as f64
        );
    }
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
            for (slot, cap) in [None, Some(0), Some(16 * KIB), Some(size)].iter().enumerate() {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match cap {
                    None => body,
                    Some(cap) => tee(body, Capture::new(Some("text/plain".into()), None, *cap)),
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
            size.div_ceil(chunk),
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
            for (slot, cap) in [None, Some(16 * KIB)].iter().enumerate() {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match cap {
                    None => body,
                    Some(cap) => tee(body, Capture::new(Some("text/plain".into()), None, *cap)),
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
            size.div_ceil(chunk),
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
            for (slot, enc) in [None, Some(None), Some(Some("gzip"))].iter().enumerate() {
                let body = ChunkedBody::new(src.clone(), chunk).boxed();
                let body = match enc {
                    None => body,
                    Some(enc) => tee(
                        body,
                        Capture::new(Some("text/plain".into()), *enc, 16 * KIB),
                    ),
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
            wire.div_ceil(chunk),
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
