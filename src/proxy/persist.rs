//! Session persistence: JSONL append-write with daily rotation.
//!
//! Each completed Session is serialised to a flat JSON object (with body
//! previews snapshotted as text) and appended to a date-stamped JSONL file
//! under `storage_dir/sessions/`. On startup the most recent files are loaded
//! back into memory so the Network view survives restarts.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{MatchedOp, Session};

/// A JSON-serialisable snapshot of a [`Session`], with body captures flattened
/// to their text previews (the `Arc<Mutex<CaptureState>>` is not serialisable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub id: u64,
    pub time_ms: u128,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub client_ip: Option<String>,
    pub target: String,
    pub duration_ms: u128,
    /// Where the time went, when the request left the proxy at all.
    ///
    /// `default` so a file written before this field existed still loads: an
    /// older record simply has no phases, which is also what a request answered
    /// by a rule reports. See [`super::timing::Timings`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timings: Option<super::timing::Timings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    /// The operators that applied — see [`MatchedOp`]. `default` so a file
    /// written before the field existed still loads: which rules matched is
    /// worth keeping across a restart, but not at the price of dropping every
    /// session recorded yesterday.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MatchedOp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub res_headers: Vec<(String, String)>,
    /// Snapshotted request body preview text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_body_preview: Option<BodySnapshot>,
    /// Snapshotted response body preview text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub res_body_preview: Option<BodySnapshot>,
    /// Why the request did not complete, when it did not — see
    /// [`super::outcome`]. `default` so older files, which never had it, load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<super::outcome::Failure>,
    /// Sent from the Composer or Replay — see [`Session::composer`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub composer: bool,
    /// Matched operators that did not take effect — see [`Session::unapplied`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unapplied: Vec<super::unapplied::Unapplied>,
}

/// A body preview as written to history: what the API showed for it, and the
/// kept bytes when the text cannot carry them.
///
/// Every flag is written down rather than re-derived on load, because the state
/// that decided it — the decoder, the cap — is not written; see
/// [`Capture::restored`](super::Capture::restored).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodySnapshot {
    /// Raw (wire) bytes the body had.
    pub len: usize,
    pub truncated: bool,
    /// The preview as text, or the `[binary, N bytes]` marker for a body that
    /// is not text — what anything reading the file as text wants.
    pub text: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub binary: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub undecodable: bool,
    /// The kept bytes, when `text` is not them: a body that is not text, or
    /// text that is not UTF-8 (a GBK page). Absent when `text` is exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl BodySnapshot {
    fn of(c: &super::Capture) -> Self {
        use base64::Engine;
        let (len, truncated, text) = c.snapshot();
        let binary = c.is_binary();
        let bytes = c.preview_bytes().bytes;
        let exact = !binary && text.as_bytes() == bytes.as_ref();
        BodySnapshot {
            len,
            truncated,
            text,
            binary,
            undecodable: c.is_undecodable(),
            base64: (!exact).then(|| base64::engine::general_purpose::STANDARD.encode(&bytes)),
        }
    }

    /// Back into a capture. `content_type` is the one the session's headers
    /// carry, which is where the live capture got it from too.
    fn restore(self, content_type: Option<String>) -> super::Capture {
        use base64::Engine;
        let kept = self
            .base64
            .as_deref()
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
        // A line written before the bytes were kept has only the marker for a
        // body that is not text: none of that body was kept, and saying it was
        // whole would make its marker its content.
        let marker_only =
            kept.is_none() && (self.binary || !super::is_textual(content_type.as_deref()));
        let (bytes, truncated) = match (kept, marker_only) {
            (Some(bytes), _) => (bytes, self.truncated),
            (None, true) => (Vec::new(), self.len > 0),
            (None, false) => (self.text.into_bytes(), self.truncated),
        };
        super::Capture::restored(&bytes, content_type, self.len, truncated, self.undecodable)
    }
}

/// A header's value, by name in any case.
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

impl PersistedSession {
    /// Snapshot a live [`Session`] into a persistable form.
    pub fn from_session(s: &Session) -> Self {
        PersistedSession {
            id: s.id,
            time_ms: s.time_ms,
            method: s.method.clone(),
            url: s.url.clone(),
            status: s.status,
            client_ip: s.client_ip.clone(),
            target: s.target.clone(),
            duration_ms: s.duration_ms,
            log: s.log.clone(),
            rules: s.rules.clone(),
            req_headers: s.req_headers.clone(),
            res_headers: s.res_headers.clone(),
            req_body_preview: s.req_body.as_ref().map(BodySnapshot::of),
            res_body_preview: s.res_body.as_ref().map(BodySnapshot::of),
            timings: s.timings.clone(),
            error: s.error.get(),
            composer: s.composer,
            unapplied: s.unapplied.clone(),
        }
    }

    /// Reconstruct a (partial) live [`Session`] from persisted data.
    pub fn into_session(self) -> Session {
        let req_type = header_value(&self.req_headers, "content-type");
        let res_type = header_value(&self.res_headers, "content-type");
        Session {
            id: self.id,
            time_ms: self.time_ms,
            method: self.method,
            url: self.url,
            status: self.status,
            client_ip: self.client_ip,
            target: self.target,
            duration_ms: self.duration_ms,
            log: self.log,
            rules: self.rules,
            timings: self.timings,
            req_headers: self.req_headers,
            res_headers: self.res_headers,
            req_body: self.req_body_preview.map(|snap| snap.restore(req_type)),
            res_body: self.res_body_preview.map(|snap| snap.restore(res_type)),
            error: self
                .error
                .map(super::outcome::Outcome::failed)
                .unwrap_or_default(),
            composer: self.composer,
            unapplied: self.unapplied,
        }
    }
}

/// Format a Unix-epoch millisecond timestamp as `YYYY-MM-DD` for file naming.
fn date_tag(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Today's date tag.
fn today_tag() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    date_tag(ms)
}

/// The JSONL file path for a given date tag.
fn jsonl_path(dir: &Path, tag: &str) -> PathBuf {
    dir.join(format!("sessions-{tag}.jsonl"))
}

/// What the writer task is asked to do.
enum Msg {
    /// Boxed: a session is hundreds of bytes and a purge is one pointer.
    Save(Box<PersistedSession>),
    /// Delete every session file; answers with how many there were.
    Purge(tokio::sync::oneshot::Sender<usize>),
    /// Answers once every save queued before it is on disk.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Handles for the persist background task.
pub struct SessionStore {
    tx: mpsc::UnboundedSender<Msg>,
}

impl SessionStore {
    /// Create a new store writing to `dir`, retaining `retain_days` days of
    /// files. Spawns a background tokio task for writes.
    pub fn new(dir: PathBuf, retain_days: u32) -> Self {
        // Sessions hold cookies and `Authorization` headers verbatim.
        crate::private_fs::create_dir(&dir).ok();
        crate::private_fs::tighten(&dir);
        // The retention promise is kept at startup too, not only when a run
        // happens to cross midnight UTC: a proxy started for an hour a week
        // never pruned anything.
        prune_old_files(&dir, retain_days);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer_task(dir, retain_days, rx));
        SessionStore { tx }
    }

    /// Queue a session for persistence (non-blocking).
    pub fn persist(&self, session: &Session) {
        let snap = PersistedSession::from_session(session);
        // Ignore send errors (task shutdown).
        let _ = self.tx.send(Msg::Save(Box::new(snap)));
    }

    /// Delete every persisted session file; returns how many there were.
    ///
    /// Done by the writer task, not here: it holds today's file open, and a
    /// file unlinked under an open handle keeps being written — to an inode
    /// nothing can find, so "deleted" history would have quietly gone on
    /// being recorded.
    pub async fn purge(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Msg::Purge(tx)).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Wait until every session queued so far is written.
    ///
    /// For shutting down: a session is queued the moment it completes and
    /// written a moment later by the writer task, and a process that exits in
    /// between loses it — the last request before Ctrl+C was the one missing
    /// from history. The channel is first in, first out, so the answer to this
    /// message comes after every save sent before it.
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// Load historical sessions from the most recent JSONL files in `dir`,
    /// returning up to `max` entries (newest last).
    ///
    /// Files past `retain_days` are deleted first rather than read: loading
    /// read every file of any age, so the history on screen after a restart
    /// could be months old while the documentation said seven days.
    pub fn load(dir: &Path, max: usize, retain_days: u32) -> Vec<Session> {
        prune_old_files(dir, retain_days);
        let mut files = list_jsonl_files(dir);
        // Sort by name ascending (date order).
        files.sort();
        let mut out = Vec::new();
        for path in &files {
            if let Ok(f) = File::open(path) {
                let reader = BufReader::new(f);
                for line in reader.lines() {
                    let Ok(line) = line else { continue };
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(ps) = serde_json::from_str::<PersistedSession>(&line) {
                        out.push(ps.into_session());
                    }
                }
            }
        }
        // Keep only the most recent `max` entries.
        if out.len() > max {
            out.drain(..out.len() - max);
        }
        out
    }
}

/// Background task: receives snapshots via channel, appends to today's JSONL,
/// and periodically prunes old files.
async fn writer_task(dir: PathBuf, retain_days: u32, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let mut current_tag = today_tag();
    let mut file = open_append(&jsonl_path(&dir, &current_tag));
    let mut write_count: u64 = 0;

    while let Some(msg) = rx.recv().await {
        let snap = match msg {
            Msg::Save(snap) => snap,
            Msg::Flush(done) => {
                if let Some(f) = &mut file {
                    let _ = f.flush();
                }
                let _ = done.send(());
                continue;
            }
            Msg::Purge(done) => {
                // Close today's file before deleting it, then start afresh.
                if let Some(mut f) = file.take() {
                    let _ = f.flush();
                }
                let files = list_jsonl_files(&dir);
                let mut removed = 0;
                for path in &files {
                    if fs::remove_file(path).is_ok() {
                        removed += 1;
                    }
                }
                tracing::info!("deleted {removed} persisted session file(s)");
                file = open_append(&jsonl_path(&dir, &current_tag));
                let _ = done.send(removed);
                continue;
            }
        };
        let tag = today_tag();
        if tag != current_tag {
            // Day rolled over: open a new file and prune old ones.
            current_tag = tag;
            file = open_append(&jsonl_path(&dir, &current_tag));
            prune_old_files(&dir, retain_days);
        }
        if let Some(f) = &mut file
            && let Ok(line) = serde_json::to_string(&snap)
        {
            let _ = writeln!(f, "{line}");
            write_count += 1;
            // Flush every 10 writes for durability without per-line fsync.
            if write_count.is_multiple_of(10) {
                let _ = f.flush();
            }
        }
    }
}

/// Open (or create) a file for appending.
fn open_append(path: &Path) -> Option<File> {
    crate::private_fs::open_append(path).ok()
}

/// List all `sessions-*.jsonl` files in `dir`.
fn list_jsonl_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("sessions-") && n.ends_with(".jsonl"))
        })
        .map(|e| e.path())
        .collect()
}

/// Remove JSONL files older than `retain_days`.
fn prune_old_files(dir: &Path, retain_days: u32) {
    let cutoff = {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let cutoff_ms = now_ms.saturating_sub(retain_days as u128 * 86_400_000);
        date_tag(cutoff_ms)
    };
    for path in list_jsonl_files(dir) {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Extract date from "sessions-YYYY-MM-DD.jsonl".
            let tag = name
                .strip_prefix("sessions-")
                .and_then(|s| s.strip_suffix(".jsonl"))
                .unwrap_or("");
            if !tag.is_empty() && tag < cutoff.as_str() {
                tracing::info!("pruning old session file: {name}");
                fs::remove_file(&path).ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Capture;
    use super::*;

    #[test]
    fn date_tag_correct() {
        // 2021-01-01T00:00:00Z = 1609459200000 ms
        assert_eq!(date_tag(1_609_459_200_000), "2021-01-01");
        // epoch
        assert_eq!(date_tag(0), "1970-01-01");
    }

    #[test]
    fn persisted_roundtrip() {
        let ps = PersistedSession {
            timings: None,
            id: 42,
            time_ms: 1_609_459_200_000,
            method: "GET".into(),
            url: "http://example.com/".into(),
            status: 200,
            client_ip: Some("127.0.0.1".into()),
            target: "example.com:80".into(),
            duration_ms: 100,
            log: vec![],
            rules: vec![MatchedOp {
                protocol: "host".into(),
                value: "1.2.3.4".into(),
                raw: "host://1.2.3.4".into(),
            }],
            req_headers: vec![("host".into(), "example.com".into())],
            res_headers: vec![],
            req_body_preview: None,
            res_body_preview: Some(BodySnapshot {
                len: 5,
                truncated: false,
                text: "hello".into(),
                binary: false,
                undecodable: false,
                base64: None,
            }),
            error: Some(super::super::outcome::Failure::new(
                super::super::outcome::Phase::Connect,
                "connecting to example.com:80: Connection refused",
            )),
            composer: true,
            unapplied: vec![super::super::unapplied::Unapplied {
                kind: super::super::unapplied::Kind::BodyOverLimit,
                ops: vec!["resReplace://a=b".into()],
                reason: "over the limit".into(),
            }],
        };
        let json = serde_json::to_string(&ps).unwrap();
        let back: PersistedSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 42);
        assert_eq!(back.url, "http://example.com/");
        let session = back.into_session();
        assert_eq!(session.id, 42);
        assert!(session.res_body.is_some());
        // Which rules matched outlives the process too: a session reloaded
        // after a restart that could not say what applied to it is a session
        // the console cannot answer its central question about.
        assert_eq!(session.rules[0].raw, "host://1.2.3.4");
        // Why it failed survives a restart too: a failed request reloaded as
        // an ordinary one would be the exact confusion the field exists to end.
        let failure = session.error.get().expect("the failure survives");
        assert_eq!(failure.phase, super::super::outcome::Phase::Connect);
        // And so does where it was sent from, or `fc:` forgets it at a restart.
        assert!(session.composer);
        // And what did not take effect, or a restart would make it look applied.
        assert_eq!(session.unapplied[0].ops, ["resReplace://a=b"]);
    }

    /// A body as the console and the API show it, as `/body.bin` serves it and
    /// as a replay would re-send it.
    fn seen(c: &Capture) -> (serde_json::Value, Vec<u8>, &'static str) {
        (
            serde_json::to_value(c).unwrap(),
            c.preview_bytes().bytes.to_vec(),
            c.replay_body().kind(),
        )
    }

    /// `c` as a response body, written to a history line and read back.
    fn reloaded(c: Capture, content_type: &str) -> Capture {
        let session = Session {
            res_headers: vec![("content-type".into(), content_type.into())],
            res_body: Some(c),
            ..Session::default()
        };
        let line = serde_json::to_string(&PersistedSession::from_session(&session)).unwrap();
        let back: PersistedSession = serde_json::from_str(&line).unwrap();
        back.into_session().res_body.expect("the body comes back")
    }

    /// History used to keep only the preview's text and re-derive the rest on
    /// load, and each derivation was wrong for some body: a PNG came back as
    /// the text of its `[binary, N bytes]` marker, a GBK page as U+FFFD, a body
    /// cut at the preview limit as whole (so a replay sent the prefix as the
    /// body), and a whole gzipped body as cut short.
    #[test]
    fn a_body_reads_back_from_history_as_it_was_written() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"{\"whole\":true}").unwrap();
        let gz = gz.finish().unwrap();
        let body = |bytes: &[u8], ct: &str, enc: Option<&str>, cap: usize| {
            (
                Capture::from_bytes(bytes, Some(ct.into()), enc, cap),
                ct.to_string(),
            )
        };
        let cases = [
            ("whole text", body(b"hello", "text/plain", None, 64)),
            (
                "cut at the limit",
                body(&[b'a'; 100], "text/plain", None, 10),
            ),
            (
                "gzipped, whole",
                body(&gz, "application/json", Some("gzip"), 64),
            ),
            (
                "binary",
                body(&[0x89, b'P', b'N', b'G', 0, 1, 2], "image/png", None, 64),
            ),
            (
                "not UTF-8",
                body(
                    &[0xc4, 0xe3, 0xba, 0xc3],
                    "text/html; charset=gbk",
                    None,
                    64,
                ),
            ),
            (
                "undecodable",
                body(b"this is not gzip", "text/plain", Some("gzip"), 64),
            ),
        ];
        for (name, (c, ct)) in cases {
            let before = seen(&c);
            assert_eq!(
                before.0["undecodable"],
                name == "undecodable",
                "{name}: {}",
                before.0
            );
            // A body that would not decode is short of itself: nothing after
            // the failure was kept, whatever the limit.
            let short = matches!(name, "cut at the limit" | "undecodable");
            assert_eq!(before.0["truncated"], short, "{name}: {}", before.0);
            assert_eq!(seen(&reloaded(c, &ct)), before, "{name}");
        }
    }

    /// A line written before the bytes were kept has only the marker for a body
    /// that is not text. It comes back as what it is — a binary body none of
    /// which was kept — and not as a text body reading `[binary, 7 bytes]`.
    #[test]
    fn an_older_binary_body_comes_back_as_not_kept() {
        let line = r#"{"id":1,"time_ms":0,"method":"GET","url":"http://a/","status":200,
            "client_ip":null,"target":"a:80","duration_ms":1,
            "res_headers":[["content-type","image/png"]],
            "res_body_preview":{"len":7,"truncated":false,"text":"[binary, 7 bytes]"}}"#;
        let back: PersistedSession = serde_json::from_str(line).expect("an older session");
        let body = back.into_session().res_body.expect("body");
        let (json, bytes, replay) = seen(&body);
        assert_eq!(json["binary"], true, "{json}");
        assert_eq!(json["truncated"], true, "none of it was kept: {json}");
        assert_eq!(json["len"], 7, "{json}");
        assert!(bytes.is_empty());
        // Not "empty": that says the request had no body, and a replay would
        // then report nothing amiss while sending none.
        assert_eq!(replay, "partial");
    }

    /// A JSONL file written before `rules` existed still loads. Sessions are
    /// kept for `persist_days`, so an upgrade lands on a directory full of
    /// them — and a deserialization error would drop every line of the file,
    /// not just the field.
    #[test]
    fn a_session_written_without_the_rules_field_still_loads() {
        let line = r#"{"id":1,"time_ms":0,"method":"GET","url":"http://a/","status":200,
            "client_ip":null,"target":"a:80","duration_ms":1}"#;
        let back: PersistedSession = serde_json::from_str(line).expect("an older session");
        assert!(back.rules.is_empty());
        assert!(back.error.is_none());
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("whistle-rs-persist-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        dir
    }

    const LINE: &str = r#"{"id":1,"time_ms":0,"method":"GET","url":"http://a/","status":200,"client_ip":null,"target":"a:80","duration_ms":1}"#;

    /// Loading keeps the retention promise instead of reading every file ever
    /// written: a file from 2000 is deleted, not shown.
    #[test]
    fn loading_deletes_history_past_retention_instead_of_reading_it() {
        let dir = scratch("retain");
        fs::write(dir.join("sessions-2000-01-01.jsonl"), format!("{LINE}\n")).expect("old");
        fs::write(jsonl_path(&dir, &today_tag()), format!("{LINE}\n")).expect("today");
        let loaded = SessionStore::load(&dir, 100, 7);
        assert_eq!(loaded.len(), 1, "only today's session");
        assert!(!dir.join("sessions-2000-01-01.jsonl").exists());
    }

    /// Purge deletes the files, including the one the writer holds open — and
    /// later sessions still land in a file that exists.
    #[tokio::test]
    async fn purge_deletes_the_files_and_writing_carries_on() {
        let dir = scratch("purge");
        fs::write(dir.join("sessions-2026-01-01.jsonl"), format!("{LINE}\n")).expect("older");
        let store = SessionStore::new(dir.clone(), 36_500);
        let session: PersistedSession = serde_json::from_str(LINE).expect("line");
        store.persist(&session.clone().into_session());
        // Round-trip through the writer, so the save is on disk before purge.
        assert!(store.purge().await >= 1);
        assert!(
            list_jsonl_files(&dir)
                .iter()
                .all(|p| fs::metadata(p).map(|m| m.len() == 0).unwrap_or(true))
        );
        assert!(!dir.join("sessions-2026-01-01.jsonl").exists());
        store.persist(&session.into_session());
        // A second purge reports the file the new session went to.
        assert_eq!(store.purge().await, 1);
    }

    /// What was queued before `flush` is in the file when it returns — what
    /// shutting down waits for.
    #[tokio::test]
    async fn flush_returns_once_what_was_queued_is_written() {
        let dir = scratch("flush");
        let store = SessionStore::new(dir.clone(), 7);
        let session: PersistedSession = serde_json::from_str(LINE).expect("line");
        for _ in 0..3 {
            store.persist(&session.clone().into_session());
        }
        store.flush().await;
        let written = fs::read_to_string(jsonl_path(&dir, &today_tag())).expect("today's file");
        assert_eq!(written.lines().count(), 3);
    }
}
