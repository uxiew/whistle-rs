//! Session persistence: JSONL append-write with daily rotation.
//!
//! Each completed Session is serialised to a flat JSON object (with body
//! previews snapshotted as text) and appended to a date-stamped JSONL file
//! under `storage_dir/sessions/`. On startup the most recent files are loaded
//! back into memory so the Network view survives restarts.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::Session;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodySnapshot {
    pub len: usize,
    pub truncated: bool,
    pub text: String,
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
            req_headers: s.req_headers.clone(),
            res_headers: s.res_headers.clone(),
            req_body_preview: s.req_body.as_ref().map(|c| {
                let (len, truncated, text) = c.snapshot();
                BodySnapshot {
                    len,
                    truncated,
                    text,
                }
            }),
            res_body_preview: s.res_body.as_ref().map(|c| {
                let (len, truncated, text) = c.snapshot();
                BodySnapshot {
                    len,
                    truncated,
                    text,
                }
            }),
        }
    }

    /// Reconstruct a (partial) live [`Session`] from persisted data. Body
    /// captures are rebuilt from the snapshot text so the UI can display them.
    pub fn into_session(self) -> Session {
        use super::Capture;
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
            req_headers: self.req_headers,
            res_headers: self.res_headers,
            req_body: self.req_body_preview.map(|snap| {
                Capture::from_bytes(
                    snap.text.as_bytes(),
                    None,
                    None,
                    snap.text.len().max(snap.len),
                )
            }),
            res_body: self.res_body_preview.map(|snap| {
                Capture::from_bytes(
                    snap.text.as_bytes(),
                    None,
                    None,
                    snap.text.len().max(snap.len),
                )
            }),
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

/// Handles for the persist background task.
pub struct SessionStore {
    tx: mpsc::UnboundedSender<PersistedSession>,
}

impl SessionStore {
    /// Create a new store writing to `dir`, retaining `retain_days` days of
    /// files. Spawns a background tokio task for writes.
    pub fn new(dir: PathBuf, retain_days: u32) -> Self {
        fs::create_dir_all(&dir).ok();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer_task(dir, retain_days, rx));
        SessionStore { tx }
    }

    /// Queue a session for persistence (non-blocking).
    pub fn persist(&self, session: &Session) {
        let snap = PersistedSession::from_session(session);
        // Ignore send errors (task shutdown).
        let _ = self.tx.send(snap);
    }

    /// Load historical sessions from the most recent JSONL files in `dir`,
    /// returning up to `max` entries (newest last).
    pub fn load(dir: &Path, max: usize) -> Vec<Session> {
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
async fn writer_task(
    dir: PathBuf,
    retain_days: u32,
    mut rx: mpsc::UnboundedReceiver<PersistedSession>,
) {
    let mut current_tag = today_tag();
    let mut file = open_append(&jsonl_path(&dir, &current_tag));
    let mut write_count: u64 = 0;

    while let Some(snap) = rx.recv().await {
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
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
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
            id: 42,
            time_ms: 1_609_459_200_000,
            method: "GET".into(),
            url: "http://example.com/".into(),
            status: 200,
            client_ip: Some("127.0.0.1".into()),
            target: "example.com:80".into(),
            duration_ms: 100,
            log: vec![],
            req_headers: vec![("host".into(), "example.com".into())],
            res_headers: vec![],
            req_body_preview: None,
            res_body_preview: Some(BodySnapshot {
                len: 5,
                truncated: false,
                text: "hello".into(),
            }),
        };
        let json = serde_json::to_string(&ps).unwrap();
        let back: PersistedSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 42);
        assert_eq!(back.url, "http://example.com/");
        let session = back.into_session();
        assert_eq!(session.id, 42);
        assert!(session.res_body.is_some());
    }
}
