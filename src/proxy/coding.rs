//! Whole-body decompression and recompression for the rewrite path.
//!
//! Every response-body operator (`resBody://`, `resReplace://`, the injections,
//! `resMerge://`, …) works on text. A response that arrives `Content-Encoding:
//! gzip` is not text, so rewriting its bytes directly does nothing at all: the
//! pattern is never found, the injection lands in a gzip stream the client then
//! fails to inflate, or — most often — the body goes out exactly as it came in
//! and the rule looks broken.
//!
//! whistle avoids this by decompressing before its transforms and recompressing
//! after: any `addZipTransform` sets `_needGunzip`
//! (`_original/lib/inspectors/data.js:445-470`), which makes `getDecoder` inflate
//! the body on the way in and `getEncoder` deflate it again on the way out
//! (`lib/inspectors/rules.js:60-140`). This module is that pair.
//!
//! Deliberately **whole-body**, not streaming: every operator here already needs
//! the complete body in memory (a regex may span any two chunks), so a streaming
//! codec would buy nothing. A response no operator touches never reaches this
//! module — it stays on the streaming path, uncompressed and uncopied.

use std::io::Write;

use bytes::Bytes;

/// A `Content-Encoding` this proxy can both undo and redo.
///
/// Anything else — `compress`, a multi-layer `gzip, br`, an unknown token — is
/// [`Coding::Other`] and means "leave this body alone". Rewriting a body we
/// cannot faithfully put back is worse than not rewriting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    /// No encoding, or none we need to undo.
    Identity,
    Gzip,
    Deflate,
    Brotli,
    /// An encoding we recognise the *name* of but cannot round-trip.
    Other,
}

impl Coding {
    /// Classify a `Content-Encoding` header value.
    ///
    /// A header naming two codings is `Other`: whistle only ever undoes one
    /// layer (`getUnzipStream` switches on the whole value,
    /// `_original/lib/util/index.js:1560-1573`), and a body wrapped twice would
    /// come back out wrapped once.
    pub fn of(value: Option<&str>) -> Coding {
        let Some(value) = value else {
            return Coding::Identity;
        };
        let value = value.trim();
        if value.is_empty() {
            return Coding::Identity;
        }
        if value.contains(',') {
            return Coding::Other;
        }
        match value.to_ascii_lowercase().as_str() {
            "identity" => Coding::Identity,
            // `x-gzip` is the pre-RFC spelling, still sent by some servers.
            "gzip" | "x-gzip" => Coding::Gzip,
            "deflate" => Coding::Deflate,
            "br" => Coding::Brotli,
            _ => Coding::Other,
        }
    }

    /// Whether a body under this coding has to be decompressed before a text
    /// operator can see it.
    pub fn needs_decoding(self) -> bool {
        matches!(self, Coding::Gzip | Coding::Deflate | Coding::Brotli)
    }

    /// The `Content-Encoding` value that describes this coding, or `None` for
    /// identity (where the header is removed rather than set).
    pub fn header_value(self) -> Option<&'static str> {
        match self {
            Coding::Gzip => Some("gzip"),
            Coding::Deflate => Some("deflate"),
            Coding::Brotli => Some("br"),
            Coding::Identity | Coding::Other => None,
        }
    }
}

/// Decompress a whole body. `None` means the bytes could not be decoded, and
/// the caller must then leave the body exactly as it found it.
///
/// A truncated stream counts as undecodable: `flate2`'s writer reports the error
/// on `finish`, and a partially-inflated body is not something to rewrite and
/// serve — the client would get a body shorter than the origin sent, with no
/// indication anything was lost.
pub fn decode(coding: Coding, body: &[u8]) -> Option<Vec<u8>> {
    match coding {
        Coding::Identity | Coding::Other => None,
        Coding::Gzip => {
            let mut d = flate2::write::GzDecoder::new(Vec::new());
            d.write_all(body).ok()?;
            d.finish().ok()
        }
        Coding::Deflate => {
            // zlib-wrapped first, which is what `Content-Encoding: deflate`
            // means by the RFC. Some servers send it raw, so that is tried
            // second rather than treated as a failure — Node's zlib accepts
            // both and a body this proxy refuses to decode is a body no
            // operator can touch.
            let mut d = flate2::write::ZlibDecoder::new(Vec::new());
            if d.write_all(body).is_ok()
                && let Ok(out) = d.finish()
            {
                return Some(out);
            }
            let mut d = flate2::write::DeflateDecoder::new(Vec::new());
            d.write_all(body).ok()?;
            d.finish().ok()
        }
        Coding::Brotli => {
            let mut out = Vec::new();
            {
                let mut w = brotli::DecompressorWriter::new(&mut out, 4096);
                w.write_all(body).ok()?;
                // Flushed by `Drop`, but an error there is invisible, so the
                // writer is finished explicitly.
                w.flush().ok()?;
            }
            Some(out)
        }
    }
}

/// Recompress a rewritten body under `coding`. `None` means it could not be
/// encoded, and the caller should serve the body as identity instead — the bytes
/// are correct either way, only the framing differs.
pub fn encode(coding: Coding, body: &[u8]) -> Option<Vec<u8>> {
    match coding {
        Coding::Identity | Coding::Other => None,
        Coding::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).ok()?;
            e.finish().ok()
        }
        Coding::Deflate => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).ok()?;
            e.finish().ok()
        }
        Coding::Brotli => {
            let mut out = Vec::new();
            {
                // Quality 5 / window 22: what the capture preview's compressor
                // already uses here, and a middle ground between a proxy's
                // latency budget and the ratio a client expects from `br`.
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                w.write_all(body).ok()?;
                w.flush().ok()?;
            }
            Some(out)
        }
    }
}

/// A body taken off the wire, decompressed for rewriting.
///
/// Carries what is needed to put it back: the coding it arrived under, and
/// whether it was actually decoded (a body that arrived as identity is
/// [`Coding::Identity`] and goes back out untouched).
pub struct Decoded {
    /// The bytes an operator should see — plain text when the body was decoded.
    pub body: Bytes,
    /// What to put back on the way out.
    pub restore: Restore,
}

/// What [`reencode`] needs to know about where a body came from.
///
/// The two fields exist separately because the coding alone cannot answer the
/// question that matters. `Identity` means *both* "the body arrived
/// uncompressed" and "we could not decompress it, so here it is as it came" —
/// and those must not be confused on the way out, because re-encoding bytes
/// that were never decoded produces a body compressed twice and labelled once.
#[derive(Debug, Clone, Copy)]
pub struct Restore {
    /// The coding to put back, or [`Coding::Identity`] for none.
    pub coding: Coding,
    /// Are the bytes actually in the clear?
    pub plain: bool,
}

/// Decompress `body` for rewriting, if it is compressed under a coding we can
/// round-trip.
///
/// The failure path is deliberately quiet in effect but loud in the log: a body
/// that cannot be inflated is returned as it arrived with `restore` set to
/// identity, so the operators run over bytes they will not usefully match —
/// exactly what happened before this module existed — rather than the response
/// being corrupted or failed.
pub fn decode_for_rewrite(body: Bytes, encoding: Option<&str>) -> Decoded {
    let coding = Coding::of(encoding);
    if !coding.needs_decoding() {
        return Decoded {
            body,
            restore: Restore {
                coding: Coding::Identity,
                // Identity really is plain; a coding we cannot round-trip is not.
                plain: coding == Coding::Identity,
            },
        };
    }
    match decode(coding, &body) {
        Some(plain) => Decoded {
            body: Bytes::from(plain),
            restore: Restore {
                coding,
                plain: true,
            },
        },
        None => {
            tracing::warn!(
                "content-encoding {} could not be decoded ({} bytes); body operators \
                 ran over the encoded bytes",
                encoding.unwrap_or(""),
                body.len()
            );
            Decoded {
                body,
                restore: Restore {
                    coding: Coding::Identity,
                    plain: false,
                },
            }
        }
    }
}

/// Put a coding back on a rewritten body, and say which one went on.
///
/// `restore` is what [`decode_for_rewrite`] undid; `forced` is an
/// `enable://gzip|br|deflate` asking for something else. The forced coding wins,
/// which is what makes that flag able to compress a body that arrived plain —
/// upstream reaches the same result by preferring `getEnableEncoding` over the
/// body's own headers (`getEncoder`, `_original/lib/inspectors/rules.js:117-119`).
///
/// A compressor that fails leaves the body plain rather than failing the
/// response, and the returned coding then says identity — so the header always
/// describes the bytes that actually go out.
pub fn reencode(body: Bytes, restore: Restore, forced: Option<Coding>) -> (Bytes, Coding) {
    // A forced coding may only be applied to bytes we actually hold in the
    // clear. When the body arrived under a coding this proxy cannot undo —
    // `zstd`, a stacked `gzip, br`, a corrupt stream — it is still compressed,
    // and compressing it again while labelling the result `gzip` hands the
    // client something no client can read: it inflates once and finds the
    // original coding underneath.
    //
    // So the request is refused rather than half-honoured. The body goes out as
    // it arrived, under the coding it arrived with, which is the same thing that
    // happens to a body operator on such a response — see `decode_for_rewrite`.
    let forced = match restore.plain {
        true => forced,
        false => {
            if forced.is_some() {
                tracing::warn!(
                    "enable:// asked for a coding on a body that could not be decoded;                      leaving it as it arrived"
                );
            }
            None
        }
    };
    let want = forced.unwrap_or(restore.coding);
    if !want.needs_decoding() || body.is_empty() {
        // An empty body is left empty: gzipping nothing produces a 20-byte
        // header that says "nothing", which is worse than saying nothing.
        return (body, Coding::Identity);
    }
    match encode(want, &body) {
        Some(out) => (Bytes::from(out), want),
        None => {
            tracing::warn!("could not re-encode {} bytes as {want:?}; sent plain", body.len());
            (body, Coding::Identity)
        }
    }
}

/// The character encoding a response declares, when it is one this proxy has to
/// undo before a text operator can read the body.
///
/// whistle runs every text transform inside an `iconv` decode/encode pair keyed
/// on the `charset=` parameter (`getPipeIconvStream`,
/// `_original/lib/util/index.js:1622-1664`), and encodes each injected value
/// into the same charset (`toBuffer(value, charset)`, `index.js:1388`;
/// `WhistleTransform`, `util/whistle-transform.js:21-45`). Without that a
/// `resReplace://` on a `text/html; charset=gbk` page searched bytes that are
/// not UTF-8, found nothing, and left the page exactly as it arrived — silently.
///
/// `None` means "the bytes are already the text": no `charset=`, `utf-8`, or a
/// label no decoder knows. The last is deliberate — upstream's `getCharset`
/// returns nothing for a charset `iconv` cannot name (`common.js:1605-1615`),
/// and a body decoded under a guess is worse than one left alone.
///
/// Matches upstream's `CHARSET_RE` (`/charset=([\w-]+)/i`, `common.js:1603`),
/// which is looser than the media-type grammar: it finds the parameter anywhere
/// in the header.
pub fn charset_of(content_type: Option<&str>) -> Option<&'static encoding_rs::Encoding> {
    let ct = content_type?;
    let at = ct.to_ascii_lowercase().find("charset=")? + "charset=".len();
    let label: String = ct[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())?;
    // UTF-8 needs no round trip: the operators already work on UTF-8.
    (encoding != encoding_rs::UTF_8).then_some(encoding)
}

/// Decode a body written in `charset` into the UTF-8 the operators work on.
///
/// Lossy on purpose, as `iconv.decodeStream` is: a byte the charset cannot
/// explain becomes U+FFFD rather than failing the response. The alternative —
/// refusing — is what this port did before, and it made the operator silently
/// inert on exactly the pages whistle exists to debug.
pub fn decode_charset(encoding: &'static encoding_rs::Encoding, body: &[u8]) -> String {
    encoding.decode(body).0.into_owned()
}

/// Put `text` back into `charset` on the way out, so the body still matches the
/// `Content-Type` the client was given.
pub fn encode_charset(encoding: &'static encoding_rs::Encoding, text: &str) -> Vec<u8> {
    encoding.encode(text).0.into_owned()
}

/// Set (or remove) `Content-Encoding` so it describes `coding`.
///
/// Removing it for identity matters as much as setting it: a body that arrived
/// gzipped, was rewritten, and goes out plain must not keep the header that
/// tells the client to inflate it.
pub fn set_content_encoding(headers: &mut hyper::HeaderMap, coding: Coding) {
    match coding.header_value() {
        Some(v) => {
            headers.insert(
                hyper::header::CONTENT_ENCODING,
                hyper::header::HeaderValue::from_static(v),
            );
        }
        None => {
            headers.remove(hyper::header::CONTENT_ENCODING);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        encode(Coding::Gzip, data).expect("gzip")
    }

    #[test]
    fn every_supported_coding_round_trips() {
        let text = b"<html><body>ORIGINAL</body></html>".repeat(20);
        for coding in [Coding::Gzip, Coding::Deflate, Coding::Brotli] {
            let wire = encode(coding, &text).unwrap_or_else(|| panic!("encode {coding:?}"));
            assert_ne!(wire, text, "{coding:?} must actually compress");
            let back = decode(coding, &wire).unwrap_or_else(|| panic!("decode {coding:?}"));
            assert_eq!(back, text, "{coding:?} round trip");
        }
    }

    /// The header spellings that decide whether a body gets decoded at all.
    #[test]
    fn the_header_decides_the_coding() {
        assert_eq!(Coding::of(None), Coding::Identity);
        assert_eq!(Coding::of(Some("")), Coding::Identity);
        assert_eq!(Coding::of(Some("identity")), Coding::Identity);
        assert_eq!(Coding::of(Some("gzip")), Coding::Gzip);
        assert_eq!(Coding::of(Some("GZIP")), Coding::Gzip);
        assert_eq!(Coding::of(Some("x-gzip")), Coding::Gzip);
        assert_eq!(Coding::of(Some(" br ")), Coding::Brotli);
        assert_eq!(Coding::of(Some("deflate")), Coding::Deflate);
        // Not round-trippable: left alone rather than half-undone.
        assert_eq!(Coding::of(Some("gzip, br")), Coding::Other);
        assert_eq!(Coding::of(Some("compress")), Coding::Other);
        assert!(!Coding::Other.needs_decoding());
        assert!(!Coding::Identity.needs_decoding());
    }

    /// The whole point: a gzip body reaches an operator as text, and says how to
    /// put it back.
    #[test]
    fn a_compressed_body_is_handed_over_as_text() {
        let d = decode_for_rewrite(Bytes::from(gzip(b"ORIGINAL")), Some("gzip"));
        assert_eq!(&d.body[..], b"ORIGINAL");
        assert_eq!(d.restore.coding, Coding::Gzip);
        assert!(d.restore.plain);

        // An identity body is not copied or changed, and needs no restoring.
        let d = decode_for_rewrite(Bytes::from_static(b"plain"), None);
        assert_eq!(&d.body[..], b"plain");
        assert_eq!(d.restore.coding, Coding::Identity);
    }

    /// A body that lies about its encoding must not break the response: the
    /// bytes come back as they arrived, and nothing is re-encoded over them.
    #[test]
    fn an_undecodable_body_survives_as_it_arrived() {
        let d = decode_for_rewrite(Bytes::from_static(b"not actually gzip"), Some("gzip"));
        assert_eq!(&d.body[..], b"not actually gzip");
        assert_eq!(
            d.restore.coding,
            Coding::Identity,
            "nothing was undone, so nothing may be redone"
        );
        assert!(decode(Coding::Gzip, b"garbage").is_none());
        // A truncated stream is a failure too, not a short body.
        let full = gzip(b"some text long enough to matter");
        assert!(decode(Coding::Gzip, &full[..full.len() / 2]).is_none());
    }

    /// `reencode` restores what was undone, and an `enable://` flag overrides it.
    #[test]
    fn reencode_restores_or_forces_a_coding() {
        // Restore the coding a body arrived under.
        let (out, c) = reencode(Bytes::from_static(b"hello"), Restore { coding: Coding::Gzip, plain: true }, None);
        assert_eq!(c, Coding::Gzip);
        assert_eq!(decode(Coding::Gzip, &out).as_deref(), Some(&b"hello"[..]));

        // A forced coding wins over the arrived one (`enable://br` on a gzip body).
        let (out, c) = reencode(Bytes::from_static(b"hello"), Restore { coding: Coding::Gzip, plain: true }, Some(Coding::Brotli));
        assert_eq!(c, Coding::Brotli);
        assert_eq!(decode(Coding::Brotli, &out).as_deref(), Some(&b"hello"[..]));

        // A body that arrived plain and stays plain is untouched.
        let (out, c) = reencode(Bytes::from_static(b"hello"), Restore { coding: Coding::Identity, plain: true }, None);
        assert_eq!(c, Coding::Identity);
        assert_eq!(&out[..], b"hello");

        // `enable://gzip` compresses a body that arrived plain.
        let (out, c) = reencode(Bytes::from_static(b"hello"), Restore { coding: Coding::Identity, plain: true }, Some(Coding::Gzip));
        assert_eq!(c, Coding::Gzip);
        assert_eq!(decode(Coding::Gzip, &out).as_deref(), Some(&b"hello"[..]));

        // An empty body is never compressed — the header would outweigh it.
        let (out, c) = reencode(Bytes::new(), Restore { coding: Coding::Gzip, plain: true }, None);
        assert_eq!(c, Coding::Identity);
        assert!(out.is_empty());
    }

    /// The header always describes the bytes that go out — set for a real
    /// coding, removed for identity so a stale `gzip` can't mislead the client.
    #[test]
    fn set_content_encoding_matches_the_body() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::CONTENT_ENCODING,
            hyper::header::HeaderValue::from_static("gzip"),
        );
        set_content_encoding(&mut h, Coding::Identity);
        assert!(h.get(hyper::header::CONTENT_ENCODING).is_none());
        set_content_encoding(&mut h, Coding::Brotli);
        assert_eq!(h.get(hyper::header::CONTENT_ENCODING).unwrap(), "br");
    }

    /// Which `charset=` values put a body through the round trip, and which are
    /// already the text the operators want.
    #[test]
    fn only_a_charset_that_is_not_utf8_needs_undoing() {
        let label = |ct: &str| charset_of(Some(ct)).map(|e| e.name());
        assert_eq!(label("text/html; charset=gbk"), Some("GBK"));
        assert_eq!(label("text/html;charset=GB2312"), Some("GBK"));
        assert_eq!(label("text/html; charset=big5"), Some("Big5"));
        assert_eq!(label("text/plain; charset=iso-8859-1"), Some("windows-1252"));
        // Already UTF-8, in either spelling: nothing to undo.
        assert_eq!(label("text/html; charset=utf-8"), None);
        assert_eq!(label("text/html; charset=UTF8"), None);
        // No parameter, and a label no decoder knows — both left alone.
        assert_eq!(label("text/html"), None);
        assert_eq!(label("text/html; charset=nonesuch"), None);
        assert_eq!(charset_of(None), None);
    }

    /// The round trip is lossless for text the charset can express, and lossy
    /// rather than fatal for what it cannot — which is `iconv`'s behaviour too.
    #[test]
    fn a_charset_round_trip_returns_the_bytes_it_was_given() {
        let gbk = charset_of(Some("text/html; charset=gbk")).expect("gbk");
        let bytes = b"\xd6\xd0\xce\xc4 ORIGINAL";
        let text = decode_charset(gbk, bytes);
        assert_eq!(text, "中文 ORIGINAL");
        assert_eq!(encode_charset(gbk, &text), bytes);
        // A glyph GBK cannot write becomes its replacement rather than an error.
        assert!(!encode_charset(gbk, "🦀").is_empty());
    }

    /// `deflate` is sent both zlib-wrapped and raw; both are accepted.
    #[test]
    fn raw_deflate_is_accepted_too() {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"raw deflate body").expect("write");
        let raw = e.finish().expect("finish");
        assert_eq!(
            decode(Coding::Deflate, &raw).as_deref(),
            Some(&b"raw deflate body"[..])
        );
    }

    /// `enable://gzip` may not compress bytes the proxy never decompressed.
    ///
    /// `restore == Identity` means two different things — "arrived plain" and
    /// "arrived under a coding we cannot undo, here it is as it came" — and
    /// conflating them hands the client a body compressed twice and labelled
    /// once: it inflates one layer and finds the original coding underneath.
    #[test]
    fn a_forced_coding_is_refused_on_a_body_that_was_never_decoded() {
        let payload = Bytes::from_static(b"a body that is not really plain");

        // Arrived under a coding we cannot round-trip: the force is refused and
        // the bytes go out exactly as they came.
        let opaque = Restore { coding: Coding::Identity, plain: false };
        let (out, c) = reencode(payload.clone(), opaque, Some(Coding::Gzip));
        assert_eq!(out, payload, "an undecodable body must not be re-encoded");
        assert_eq!(c, Coding::Identity, "and must not be labelled as encoded");

        // Genuinely plain: the force is honoured, which is the whole point of
        // the flag.
        let plain = Restore { coding: Coding::Identity, plain: true };
        let (out, c) = reencode(payload.clone(), plain, Some(Coding::Gzip));
        assert_eq!(c, Coding::Gzip);
        assert_eq!(decode(Coding::Gzip, &out).as_deref(), Some(&payload[..]));

        // And `decode_for_rewrite` reports the distinction in the first place.
        assert!(!decode_for_rewrite(payload.clone(), Some("zstd")).restore.plain);
        assert!(decode_for_rewrite(payload.clone(), None).restore.plain);
        // A gzip header that does not decode is not plain either.
        assert!(!decode_for_rewrite(payload, Some("gzip")).restore.plain);
    }
}
