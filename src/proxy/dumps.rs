//! Writing a request or response to disk for `reqWrite://`, `resWrite://` and
//! their `Raw` forms — the body alone, or the head and body as they went over
//! the wire. Where they go is `apply::writes`'s decision.

use super::*;

/// Append a captured body to a file (`reqWrite`/`resWrite`). Best-effort.
pub(super) fn write_body_file(path: &str, data: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    if let Err(e) = f.write_all(data) {
        tracing::debug!("write body to {path} failed: {e}");
    }
}

/// Open a dump file for one of the four write operators, or refuse.
///
/// whistle writes a dump file **once**: `getFileWriter` stats the path first and
/// hands back no writer at all when it already exists, so only `ENOENT` produces
/// one (`checkWriterFile`/`getFileWriter`,
/// `_original/lib/util/index.js:502-546`). `enable://forceReqWrite` is the
/// override, and it overwrites rather than appends — the stream is opened with
/// Node's default `w`.
///
/// Appending, which is what this did, is a different tool: point a rule at a
/// path once and every reload of the page grows the file, so what you open is a
/// concatenation of runs with no boundary between them, and the "capture" of the
/// request you meant is somewhere in the middle of it.
///
/// A path ending in a separator names a directory, and the dump goes in it as
/// `index.html` (`END_RE`, `util/index.js:54,:521-523`).
///
/// Upstream's `pendingFiles` guard — which also refuses a file another request
/// is mid-write on — is not reproduced: it exists because its writers are
/// asynchronous streams, and these are one synchronous `write_all`.
pub(super) fn open_writer(path: &str, force: bool) -> Option<std::fs::File> {
    let path = match path.ends_with('/') || path.ends_with('\\') {
        true => std::path::Path::new(path).join("index.html"),
        false => std::path::PathBuf::from(path),
    };
    if !force && path.exists() {
        tracing::debug!("{} already exists; not written", path.display());
        return None;
    }
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        tracing::debug!("create {} failed: {e}", dir.display());
        return None;
    }
    match std::fs::File::create(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::debug!("open {} for write failed: {e}", path.display());
            None
        }
    }
}

/// Serialise headers as `name: value\r\n` lines.
pub(super) fn header_dump(headers: &hyper::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(value.to_str().unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// Write a raw message — head, blank line, body — to a file.
///
/// Nothing follows the body. Upstream writes `getRawData(…)`, which is the
/// first line, the headers and one blank line, and then pipes the body straight
/// into the same stream (`FileWriterTransform`,
/// `_original/lib/util/file-writer-transform.js:6-13,:53-58`). This port used to
/// add a trailing `\r\n\r\n` on the end, on the theory that a dump might hold
/// several messages — it never does, because `getFileWriter` refuses a path that
/// already exists. What it produced instead was a dump of a bodiless request
/// ending in four CRLFs where whistle's ends in two, which is not a raw record
/// of anything that went over the wire.
pub(super) fn write_raw_file(path: &str, head: &str, body: &Bytes, force: bool) {
    use std::io::Write;
    let Some(mut f) = open_writer(path, force) else {
        return;
    };
    let _ = f.write_all(head.as_bytes());
    let _ = f.write_all(b"\r\n");
    let _ = f.write_all(body);
}

#[cfg(test)]
pub(super) mod writer_tests {
    use super::super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "whistle-rs-writer-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join(name)
    }

    /// A dump file is written **once**: whistle stats the path first and hands
    /// back no writer when it already exists (`checkWriterFile`/`getFileWriter`,
    /// `_original/lib/util/index.js:502-546`).
    ///
    /// This appended instead, so a rule left in place over a reload produced a
    /// file that is a concatenation of runs with no boundary between them — and
    /// the request you meant to capture somewhere in the middle of it.
    #[test]
    fn a_dump_file_is_written_once() {
        let path = scratch("body.txt");
        let p = path.to_str().expect("utf-8 path");

        write_body_file(p, &Bytes::from_static(b"first"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // The second request through the same rule leaves it alone.
        write_body_file(p, &Bytes::from_static(b"second"), false);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        // `enable://forceReqWrite` overwrites — it does not append, because
        // upstream reopens the stream with Node's default `w`.
        write_body_file(p, &Bytes::from_static(b"second"), true);
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    /// The raw dump takes the same gate, and missing parent directories are
    /// created (`fse.ensureFile`, `util/index.js:536`).
    #[test]
    fn the_raw_dump_takes_the_same_gate_and_makes_its_directory() {
        let path = scratch("nested/deeper/raw.txt");
        let p = path.to_str().expect("utf-8 path");

        write_raw_file(p, "GET / HTTP/1.1", &Bytes::from_static(b"body"), false);
        let written = std::fs::read(&path).expect("read");
        // Head, blank line, body — and nothing after it. The trailing `\r\n\r\n`
        // this used to add made a bodiless dump end in four CRLFs where
        // whistle's ends in two; measured on `tests/differential/write-bench.js`.
        assert_eq!(written, b"GET / HTTP/1.1\r\nbody");

        write_raw_file(p, "GET /other HTTP/1.1", &Bytes::from_static(b"x"), false);
        assert_eq!(std::fs::read(&path).expect("read"), written);
    }

    /// A path ending in a separator names a directory, and the dump goes in it
    /// as `index.html` (`END_RE`, `_original/lib/util/index.js:54,:521-523`).
    #[test]
    fn a_trailing_separator_names_a_directory() {
        let dir = scratch("dumpdir");
        let p = format!("{}/", dir.to_str().expect("utf-8 path"));
        write_body_file(&p, &Bytes::from_static(b"page"), false);
        assert_eq!(
            std::fs::read(dir.join("index.html")).expect("read"),
            b"page"
        );
    }

    /// A non-200 response is dumped beside the good capture, not over it
    /// (`getWriterFile`, `_original/lib/inspectors/res.js:147-153`).
    #[test]
    fn a_failing_response_is_dumped_under_its_status() {
        let mut m = RuleManager::new();
        m.set_text("example.com resWrite:///tmp/dump  resWriteRaw:///tmp/raw\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        assert_eq!(
            apply::res_write_path(&resolved, 200),
            Some("/tmp/dump".to_string())
        );
        assert_eq!(
            apply::res_write_path(&resolved, 502),
            Some("/tmp/dump.502".to_string())
        );
        // The raw dump is named the same way.
        assert_eq!(
            apply::res_write_raw_path(&resolved, 404),
            Some("/tmp/raw.404".to_string())
        );
    }

    /// `reqWrite://` is gated on the request actually having a body
    /// (`util.hasRequestBody(req) ? … : null`,
    /// `_original/lib/inspectors/req.js:582-584`).
    ///
    /// Without the gate a `GET` created an empty file, which reads as "the
    /// capture worked and there was no body" rather than "there was never a
    /// body to capture". `reqWriteRaw://` is *not* gated: the head is worth
    /// dumping either way.
    #[test]
    fn req_write_needs_a_method_that_carries_a_body() {
        let mut m = RuleManager::new();
        m.set_text("example.com reqWrite:///tmp/req  reqWriteRaw:///tmp/rawreq\n");
        let info = apply::build_req_info(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &hyper::HeaderMap::new(),
            None,
        );
        let resolved = m.resolve(&info);

        for method in ["GET", "HEAD", "OPTIONS", "CONNECT"] {
            assert_eq!(apply::req_write_path(&resolved, method), None, "{method}");
        }
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                apply::req_write_path(&resolved, method),
                Some("/tmp/req".to_string()),
                "{method}"
            );
        }
        assert_eq!(
            apply::req_write_raw_path(&resolved),
            Some("/tmp/rawreq".to_string())
        );
    }
}
