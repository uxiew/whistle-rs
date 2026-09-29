//! Capturing a body as it streams past: a bounded, decoded preview for the
//! console and a count of every byte, without holding the body back.

use super::*;

/// Longest body prefix retained for the inspection preview (per body).
pub const BODY_PREVIEW_CAP: usize = 16 * 1024;

/// A streaming decompressor for the capture preview. It decodes `Content-Encoding`
/// so the preview shows readable text; the *proxied* body is never touched.
#[derive(Default)]
pub(super) enum BodyDecoder {
    /// No (or unknown) encoding — bytes stored verbatim.
    #[default]
    Identity,
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    /// A decode error occurred — stop decoding this body.
    Failed,
    /// Nothing left to decode: the preview filled up, or the body ended. The
    /// decompressor has been dropped, and with it the decompressed bytes it
    /// was holding — see [`CaptureState::release_decoder`].
    Done,
}

impl BodyDecoder {
    /// Whether this variant owns a decompressor (and therefore a buffer).
    pub(super) fn is_decompressor(&self) -> bool {
        matches!(
            self,
            BodyDecoder::Gzip(_) | BodyDecoder::Deflate(_) | BodyDecoder::Brotli(_)
        )
    }
}

/// Build a decoder for a `Content-Encoding` value (identity for none/unknown).
pub(super) fn make_decoder(encoding: Option<&str>) -> BodyDecoder {
    // Take the first token of e.g. "gzip" / "br" / "gzip, chunked".
    let enc = encoding
        .map(|e| {
            e.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    match enc.as_str() {
        "gzip" | "x-gzip" => BodyDecoder::Gzip(flate2::write::GzDecoder::new(Vec::new())),
        "deflate" => BodyDecoder::Deflate(flate2::write::ZlibDecoder::new(Vec::new())),
        "br" => BodyDecoder::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 4096))),
        _ => BodyDecoder::Identity,
    }
}

/// Feed compressed `bytes` to a `Write` decoder, then copy any newly-decoded
/// output (beyond what's already in `data`) into `data`, bounded to the cap.
/// Returns false on a decode error.
pub(super) fn drain_decoder<D>(
    dec: &mut D,
    get_ref: impl Fn(&D) -> &[u8],
    bytes: &[u8],
    data: &mut Vec<u8>,
    cap: usize,
) -> bool
where
    D: std::io::Write,
{
    if dec.write_all(bytes).is_err() {
        return false;
    }
    let _ = dec.flush();
    let out = get_ref(dec);
    if out.len() > data.len() {
        let room = cap.saturating_sub(data.len());
        let new = &out[data.len()..];
        let take = room.min(new.len());
        data.extend_from_slice(&new[..take]);
    }
    true
}

/// Mutable capture state for one body, filled as the body streams past.
/// Memory is bounded to `cap`; `total` still counts every raw byte.
#[derive(Default)]
pub struct CaptureState {
    /// Decoded body prefix (≤ `cap` bytes) kept for the preview.
    pub(super) data: Vec<u8>,
    /// Total raw bytes observed (may exceed `data.len()`).
    pub(super) total: usize,
    /// The body's Content-Type, for text-vs-binary rendering.
    pub(super) content_type: Option<String>,
    /// Streaming decoder for the body's Content-Encoding.
    pub(super) decoder: BodyDecoder,
    /// Preview byte cap (`None` → [`BODY_PREVIEW_CAP`] default).
    pub(super) cap: Option<usize>,
    /// For a capture read back from history: whether it was short of the body
    /// when it was written. What decided that then — the cap it was taken
    /// under, whether it arrived compressed — is not stored, and re-deriving it
    /// from what is got it wrong both ways (see [`Capture::restored`]).
    pub(super) restored_truncated: Option<bool>,
}

impl CaptureState {
    pub(super) fn cap(&self) -> usize {
        self.cap.unwrap_or(BODY_PREVIEW_CAP)
    }

    /// Record raw `bytes` flowing through, decoding into a bounded preview.
    pub(super) fn append(&mut self, bytes: &[u8]) {
        self.total += bytes.len();
        let cap = self.cap();
        if self.data.len() >= cap {
            // Preview already full — stop decoding/copying. `release_decoder`
            // has already run, so there is no buffer left to grow either.
            return;
        }
        let mut failed = false;
        match &mut self.decoder {
            BodyDecoder::Identity => {
                let room = cap - self.data.len();
                let take = room.min(bytes.len());
                self.data.extend_from_slice(&bytes[..take]);
            }
            BodyDecoder::Failed | BodyDecoder::Done => {}
            BodyDecoder::Gzip(d) => {
                failed = !drain_decoder(d, |d| d.get_ref(), bytes, &mut self.data, cap)
            }
            BodyDecoder::Deflate(d) => {
                failed = !drain_decoder(d, |d| d.get_ref(), bytes, &mut self.data, cap)
            }
            BodyDecoder::Brotli(d) => {
                failed = !drain_decoder(d.as_mut(), |d| d.get_ref(), bytes, &mut self.data, cap)
            }
        }
        if failed {
            self.decoder = BodyDecoder::Failed;
        } else if self.data.len() >= cap {
            self.release_decoder();
        }
    }

    /// Whether the preview falls short of the body: it either hit the cap,
    /// bytes went past uncompressed after it was full, or decoding failed and
    /// nothing after the failure was kept.
    ///
    /// One predicate rather than three, because [`Capture::snapshot`],
    /// [`Capture::preview_bytes`] and [`Capture::replay_body`] each have to
    /// answer it and three copies of it would drift.
    pub(super) fn is_truncated(&self) -> bool {
        if let Some(truncated) = self.restored_truncated {
            return truncated;
        }
        self.data.len() >= self.cap()
            || matches!(self.decoder, BodyDecoder::Failed)
            || (matches!(self.decoder, BodyDecoder::Identity) && self.total > self.data.len())
    }

    /// Drop the decompressor once it can contribute nothing further.
    ///
    /// A `write`-side decompressor accumulates *everything* it has inflated in
    /// an internal `Vec`, which [`drain_decoder`] only ever reads a bounded
    /// prefix of. Holding one after the preview is complete pins the whole
    /// decompressed body: a 16 MiB response of highly compressible bytes
    /// arrives as one 16 KiB frame that inflates in full before the 16 KiB
    /// preview is taken off the front of it. The capture then lives on in the
    /// session ring — 500 entries deep — still holding all 16 MiB.
    ///
    /// Only a decompressor is released. `Identity` stays as it is, because
    /// [`Capture::snapshot`] reads that variant to decide `truncated`.
    pub(super) fn release_decoder(&mut self) {
        if self.decoder.is_decompressor() {
            self.decoder = BodyDecoder::Done;
        }
    }
}

/// A shareable handle to a body's [`CaptureState`]. Cloning shares the state, so
/// the copy stored in a [`Session`] sees updates made by the streaming tee.
#[derive(Clone, Default)]
pub struct Capture(pub(super) Arc<Mutex<CaptureState>>);

impl Capture {
    /// A fresh, empty capture for a body of the given content type/encoding,
    /// keeping at most `cap` decoded preview bytes.
    pub fn new(content_type: Option<String>, content_encoding: Option<&str>, cap: usize) -> Self {
        Capture(Arc::new(Mutex::new(CaptureState {
            content_type,
            decoder: make_decoder(content_encoding),
            cap: Some(cap),
            ..Default::default()
        })))
    }

    /// A capture already populated from a fully-buffered body.
    pub(crate) fn from_bytes(
        bytes: &[u8],
        content_type: Option<String>,
        content_encoding: Option<&str>,
        cap: usize,
    ) -> Self {
        let c = Capture::new(content_type, content_encoding, cap);
        {
            let mut st = c.0.lock().unwrap();
            st.append(bytes);
            // The whole body was in `bytes`; nothing follows it.
            st.release_decoder();
        }
        c
    }

    /// A capture read back from history, with the facts about it that were
    /// written down with it rather than re-derived.
    ///
    /// Rebuilding one by feeding the kept bytes through [`Capture::from_bytes`]
    /// derived `truncated` from them, under a cap made up for the occasion: a
    /// body cut at the preview limit came back whole, and a whole body that had
    /// arrived gzipped — kept decoded, and so longer than its wire length —
    /// came back cut short.
    pub(crate) fn restored(
        bytes: &[u8],
        content_type: Option<String>,
        total: usize,
        truncated: bool,
        undecodable: bool,
    ) -> Self {
        Capture(Arc::new(Mutex::new(CaptureState {
            data: bytes.to_vec(),
            total,
            content_type,
            decoder: if undecodable {
                BodyDecoder::Failed
            } else {
                BodyDecoder::Done
            },
            cap: None,
            restored_truncated: Some(truncated),
        })))
    }

    /// The body has ended, so no further bytes can arrive. Releases the
    /// decompressor for a body that finished before filling the preview —
    /// without this, every small compressed response leaves an inflate state
    /// and its buffer alive for as long as the session is retained.
    pub fn finish(&self) {
        self.0.lock().unwrap().release_decoder();
    }

    /// Append streamed bytes to the shared state.
    pub fn append(&self, bytes: &[u8]) {
        self.0.lock().unwrap().append(bytes);
    }

    /// Total bytes seen so far.
    pub(super) fn total(&self) -> usize {
        self.0.lock().unwrap().total
    }

    /// A `(len, truncated, text)` snapshot of the preview. `len` is the raw
    /// (wire) byte count; `text` is the decoded preview (or a binary marker).
    pub fn snapshot(&self) -> (usize, bool, String) {
        let st = self.0.lock().unwrap();
        let truncated = st.is_truncated();
        let text = if is_textual(st.content_type.as_deref()) {
            String::from_utf8_lossy(&st.data).into_owned()
        } else {
            format!("[binary, {} bytes]", st.total)
        };
        (st.total, truncated, text)
    }

    /// Whether [`Capture::snapshot`]'s `text` is a marker rather than the body.
    pub fn is_binary(&self) -> bool {
        !is_textual(self.0.lock().unwrap().content_type.as_deref())
    }

    /// Whether undoing the body's `Content-Encoding` failed part-way, so what
    /// was kept is the decoder's output up to the failure and nothing after.
    pub fn is_undecodable(&self) -> bool {
        matches!(self.0.lock().unwrap().decoder, BodyDecoder::Failed)
    }

    /// The preview as **bytes**, with what is needed to serve them.
    ///
    /// Deliberately *not* built on [`Capture::snapshot`], for the same reason
    /// [`Capture::replay_body`] is not: `snapshot` renders the preview for a
    /// human and loses the body doing it — `from_utf8_lossy` flattens every
    /// invalid byte to U+FFFD, and a non-textual type is replaced outright by a
    /// `[binary, N bytes]` marker. That marker *was* the whole story the console
    /// got for a PNG, which is why it could show neither the image, nor its
    /// bytes, nor offer it as a download.
    pub fn preview_bytes(&self) -> BodyBytes {
        let st = self.0.lock().unwrap();
        BodyBytes {
            bytes: Bytes::copy_from_slice(&st.data),
            content_type: st.content_type.clone(),
            total: st.total,
            truncated: st.is_truncated(),
        }
    }

    /// What a replay can honestly re-send of this body — see [`ReplayBody`].
    ///
    /// Deliberately *not* built on [`Capture::snapshot`]: that renders the
    /// preview for a human, lossily. `from_utf8_lossy` turns any byte that is
    /// not valid UTF-8 into U+FFFD, and a non-textual content type is replaced
    /// outright by a `[binary, N bytes]` marker — replaying either would send
    /// a body the client never sent, under the original's `content-type`. The
    /// stored bytes are neither: they are the body as decoded, byte for byte,
    /// up to the preview cap.
    pub fn replay_body(&self) -> ReplayBody {
        let st = self.0.lock().unwrap();
        if matches!(st.decoder, BodyDecoder::Failed) {
            // The decompressor gave up part-way, so `data` is a prefix of
            // something that was never the body. Sending it would be a lie the
            // length header would make look deliberate.
            return ReplayBody::Undecodable;
        }
        // Nothing kept of a body that had bytes is not an empty body: a preview
        // limit of 0, or a body from history none of which was written down.
        if st.data.is_empty() && !st.is_truncated() {
            return ReplayBody::Empty;
        }
        let bytes = Bytes::copy_from_slice(&st.data);
        match !st.is_truncated() {
            true => ReplayBody::Whole(bytes),
            false => ReplayBody::Partial {
                bytes,
                of: st.total,
            },
        }
    }
}

/// A captured body as the bytes it is, for the console's hex view, its image
/// preview and its download — and for a HAR entry, which has to carry a body no
/// text field can hold.
#[derive(Clone, Debug)]
pub struct BodyBytes {
    /// The decoded preview, byte for byte, up to the preview cap.
    pub bytes: Bytes,
    /// The `Content-Type` recorded for the body, if it had one.
    pub content_type: Option<String>,
    /// Raw (wire) bytes seen. Exceeds `bytes.len()` when the preview was capped
    /// — and, for a body that arrived compressed, is not comparable to it.
    pub total: usize,
    /// The preview is short of the body: it must not be offered as the whole.
    pub truncated: bool,
}

/// What of a captured request body a replay can re-send.
///
/// The capture is a **bounded, decoded** preview, not the bytes that crossed the
/// wire, so a replay is only ever as faithful as the preview is. Naming the
/// cases is what lets [`webui`] set the framing headers to match what it
/// actually sends, and lets the console say so when the two differ — before
/// this, `do_replay` copied every captured header and sent an empty body, so
/// replaying a POST re-sent its `content-length: 402` with zero bytes behind it.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplayBody {
    /// Nothing was captured: the request had no body, or none was recorded.
    Empty,
    /// The whole body, decoded. Whatever `content-encoding` it arrived under has
    /// been undone, so the header must go with it.
    Whole(Bytes),
    /// The first bytes of a body that did not fit the preview. `of` is the raw
    /// (wire) byte count seen — which, for a body that arrived compressed, is
    /// not the size of what is being sent.
    Partial { bytes: Bytes, of: usize },
    /// The capture cannot stand in for the body at all: decoding it failed
    /// part-way, so it holds a prefix of nothing in particular.
    Undecodable,
}

impl ReplayBody {
    /// The bytes to send, if any.
    pub fn bytes(&self) -> Option<&Bytes> {
        match self {
            ReplayBody::Whole(b) | ReplayBody::Partial { bytes: b, .. } => Some(b),
            ReplayBody::Empty | ReplayBody::Undecodable => None,
        }
    }

    /// A one-word name for the console, so a replay that differs from what was
    /// captured says which way it differs.
    pub fn kind(&self) -> &'static str {
        match self {
            ReplayBody::Empty => "empty",
            ReplayBody::Whole(_) => "whole",
            ReplayBody::Partial { .. } => "partial",
            ReplayBody::Undecodable => "undecodable",
        }
    }
}

impl serde::Serialize for Capture {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (len, truncated, text) = self.snapshot();
        let mut o = s.serialize_struct("BodyCapture", 5)?;
        o.serialize_field("len", &len)?;
        o.serialize_field("truncated", &truncated)?;
        o.serialize_field("text", &text)?;
        // Whether `text` is the body or a marker standing in for it. The console
        // needs to know, and re-deriving [`is_textual`] from the Content-Type in
        // TypeScript would be a second copy of a rule this side already applied
        // — the kind that drifts silently and is only noticed as a body that
        // renders as mojibake.
        o.serialize_field("binary", &self.is_binary())?;
        // Why a `truncated` body is short when it is not the preview limit: its
        // encoding would not decode, so `text` is what came out before it broke.
        o.serialize_field("undecodable", &self.is_undecodable())?;
        o.end()
    }
}

/// Whether a body of this content type should be previewed as text.
pub(super) fn is_textual(content_type: Option<&str>) -> bool {
    match content_type {
        None => true, // no type → try as text
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/")
                || ct.contains("json")
                || ct.contains("xml")
                || ct.contains("javascript")
                || ct.contains("ecmascript")
                || ct.contains("html")
                || ct.contains("css")
                || ct.contains("urlencoded")
        }
    }
}

#[cfg(test)]
pub(super) mod capture_tests {
    use super::super::*;
    use std::io::Write;

    fn preview(data: Vec<u8>, ct: &str, enc: &str) -> (usize, bool, String) {
        let cap = Capture::new(Some(ct.into()), Some(enc), BODY_PREVIEW_CAP);
        cap.append(&data);
        let v = serde_json::to_value(&cap).unwrap();
        (
            v["len"].as_u64().unwrap() as usize,
            v["truncated"].as_bool().unwrap(),
            v["text"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn gzip_preview_decoded() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"{\"hi\":\"gzipped\"}").unwrap();
        let gz = e.finish().unwrap();
        let (len, _, text) = preview(gz.clone(), "application/json", "gzip");
        assert_eq!(len, gz.len()); // len = wire (compressed) bytes
        assert_eq!(text, "{\"hi\":\"gzipped\"}");
    }

    #[test]
    fn deflate_preview_decoded() {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"deflated-body").unwrap();
        let df = e.finish().unwrap();
        let (_, _, text) = preview(df, "text/plain", "deflate");
        assert_eq!(text, "deflated-body");
    }

    #[test]
    fn brotli_preview_decoded() {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(b"brotli-body-text").unwrap();
        }
        let (_, _, text) = preview(out, "text/plain", "br");
        assert_eq!(text, "brotli-body-text");
    }

    #[test]
    fn unknown_encoding_shows_binary() {
        let (_, _, text) = preview(vec![0u8, 159, 146, 150], "application/octet-stream", "zstd");
        assert!(text.starts_with("[binary"), "got {text}");
    }

    #[test]
    fn identity_text_passthrough() {
        let (len, trunc, text) = preview(b"plain body".to_vec(), "text/plain", "identity");
        assert_eq!(len, 10);
        assert!(!trunc);
        assert_eq!(text, "plain body");
    }

    /// Bytes the capture's decompressor is still holding.
    fn decoder_bytes(cap: &Capture) -> usize {
        match &cap.0.lock().unwrap().decoder {
            BodyDecoder::Gzip(d) => d.get_ref().len(),
            BodyDecoder::Deflate(d) => d.get_ref().len(),
            BodyDecoder::Brotli(d) => d.get_ref().len(),
            _ => 0,
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A `write`-side decompressor keeps everything it has inflated, and the
    /// capture outlives the body by up to [`MAX_SESSIONS`] entries. Once the
    /// preview is full the decompressor must be let go, or one highly
    /// compressible response pins its whole decompressed size for as long as
    /// the session is retained.
    #[test]
    fn a_full_preview_releases_the_decompressor() {
        let body = gzip(&vec![b'a'; 8 * 1024 * 1024]);
        assert!(
            body.len() < BODY_PREVIEW_CAP,
            "8 MiB of 'a' fits in one frame"
        );
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&body);

        let (len, truncated, text) = cap.snapshot();
        assert_eq!(len, body.len(), "len still counts wire bytes");
        assert!(truncated);
        assert_eq!(text.len(), BODY_PREVIEW_CAP, "the preview is still filled");
        assert!(text.bytes().all(|b| b == b'a'), "and still decoded");
        assert_eq!(
            decoder_bytes(&cap),
            0,
            "8 MiB of inflated bytes must not outlive the preview that needed 16 KiB of them"
        );
    }

    /// A body that ends before filling the preview never trips the cap, so the
    /// release has to happen at end-of-stream too.
    #[test]
    fn a_finished_body_releases_the_decompressor() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&gzip(b"small enough to fit"));
        assert!(
            decoder_bytes(&cap) > 0,
            "still decoding: the body may continue"
        );

        cap.finish();
        assert_eq!(decoder_bytes(&cap), 0);
        let (_, _, text) = cap.snapshot();
        assert_eq!(
            text, "small enough to fit",
            "the preview survives the release"
        );
    }

    /// Releasing must not disturb an identity capture: [`Capture::snapshot`]
    /// reads that variant to decide whether the preview was truncated.
    #[test]
    fn releasing_leaves_an_identity_capture_alone() {
        let cap = Capture::new(Some("text/plain".into()), None, 8);
        cap.append(b"0123456789");
        cap.finish();
        let (len, truncated, text) = cap.snapshot();
        assert_eq!((len, truncated, text.as_str()), (10, true, "01234567"));
    }

    /// A body that fitted the preview replays byte for byte.
    #[test]
    fn a_whole_body_replays_whole() {
        let cap = Capture::from_bytes(b"name=third&tags=a", Some("text/plain".into()), None, 64);
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from_static(b"name=third&tags=a"))
        );
    }

    /// A body the preview could not hold replays as its prefix, and says so.
    /// Sending it as if it were whole is the failure this case exists to
    /// prevent: a 200 KB upload would be re-sent as its first 16 KB under a
    /// `content-length` copied from the original, and nothing would say which
    /// of the two the origin saw.
    #[test]
    fn a_capped_body_replays_as_a_prefix_that_admits_it() {
        let cap = Capture::new(Some("text/plain".into()), None, 8);
        cap.append(b"0123456789");
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Partial {
                bytes: Bytes::from_static(b"01234567"),
                of: 10,
            }
        );
    }

    /// The bytes, not the preview *text*. A JPEG is stored verbatim and shown
    /// as `[binary, N bytes]`; a replay built on `snapshot` would have posted
    /// that sentence to the origin under `image/jpeg`.
    #[test]
    fn a_binary_body_replays_as_its_bytes_not_as_its_marker() {
        let raw = [0u8, 159, 146, 150];
        let cap = Capture::from_bytes(&raw, Some("image/jpeg".into()), None, 64);
        assert!(cap.snapshot().2.starts_with("[binary"));
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from(raw.to_vec()))
        );
    }

    /// A compressed body is replayed **decoded** — which is why the replay drops
    /// `content-encoding` with it (see `webui::replay_request`).
    #[test]
    fn a_compressed_body_replays_decoded() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(&gzip(b"deflate me"));
        cap.finish();
        assert_eq!(
            cap.replay_body(),
            ReplayBody::Whole(Bytes::from_static(b"deflate me"))
        );
    }

    /// A decode that failed leaves a prefix of something that was never a body.
    /// Replaying it would be a fabrication the length header made look
    /// deliberate, so nothing is sent and the console is told why.
    #[test]
    fn a_body_that_would_not_decode_is_not_replayed() {
        let cap = Capture::new(Some("text/plain".into()), Some("gzip"), BODY_PREVIEW_CAP);
        cap.append(b"this was never gzip");
        assert_eq!(cap.replay_body(), ReplayBody::Undecodable);
        assert_eq!(cap.replay_body().bytes(), None);
    }

    #[test]
    fn a_request_without_a_body_replays_without_one() {
        assert_eq!(Capture::default().replay_body(), ReplayBody::Empty);
    }

    /// The gap this closes: a PNG reached the console as the sentence
    /// `[binary, 4 bytes]` and nothing else, so there was no hex view, no image
    /// and no download to build — the bytes were discarded at serialization.
    #[test]
    fn a_binary_body_keeps_its_bytes_beside_its_marker() {
        let raw = [0x89, b'P', b'N', b'G'];
        let cap = Capture::from_bytes(&raw, Some("image/png".into()), None, 64);
        assert_eq!(cap.snapshot().2, "[binary, 4 bytes]");

        let pv = cap.preview_bytes();
        assert_eq!(pv.bytes, Bytes::from(raw.to_vec()));
        assert_eq!(pv.content_type.as_deref(), Some("image/png"));
        assert_eq!(pv.total, 4);
        assert!(!pv.truncated);
    }

    /// A compressed body is served to the console **decoded**, like everything
    /// else read out of the capture: what the hex view shows is the body, not
    /// the transfer encoding it arrived under.
    #[test]
    fn the_bytes_the_console_gets_are_decoded() {
        let cap = Capture::new(Some("application/octet-stream".into()), Some("gzip"), 4096);
        cap.append(&gzip(&[0u8, 1, 2, 3, 255]));
        cap.finish();
        assert_eq!(
            cap.preview_bytes().bytes,
            Bytes::from_static(&[0, 1, 2, 3, 255])
        );
    }

    /// The bytes a capped preview holds are a prefix, and the flag that says so
    /// travels with them — a download offered as the whole file would be wrong
    /// in a way the file itself could not reveal.
    #[test]
    fn a_capped_preview_hands_over_a_prefix_that_admits_it() {
        let cap = Capture::new(Some("image/png".into()), None, 8);
        cap.append(&[b'x'; 200]);
        let pv = cap.preview_bytes();
        assert_eq!(pv.bytes.len(), 8);
        assert_eq!(pv.total, 200);
        assert!(pv.truncated);
    }

    /// Whether `text` is the body or a marker standing in for it, decided on
    /// this side so the console does not have to re-derive it.
    #[test]
    fn the_capture_says_whether_its_text_is_a_marker() {
        let binary = |ct: &str| {
            let v = serde_json::to_value(Capture::new(Some(ct.into()), None, 64)).unwrap();
            v["binary"].as_bool().unwrap()
        };
        assert!(binary("image/png"));
        assert!(binary("application/octet-stream"));
        assert!(!binary("text/html; charset=utf-8"));
        assert!(!binary("application/json"));
    }

    #[test]
    fn iso8601_conversion() {
        assert_eq!(super::super::iso8601_utc(0), "1970-01-01T00:00:00.000Z");
        // 1_000_000_000 s since epoch = 2001-09-09T01:46:40Z
        assert_eq!(
            super::super::iso8601_utc(1_000_000_000_000),
            "2001-09-09T01:46:40.000Z"
        );
        // milliseconds are preserved
        assert_eq!(
            super::super::iso8601_utc(1_609_459_200_123),
            "2021-01-01T00:00:00.123Z"
        );
    }
}
