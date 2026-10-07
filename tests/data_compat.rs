//! A storage directory written by an older release has to load in this one.
//!
//! Upgrading is replacing the binary and starting it on the same directory, so
//! whatever an earlier version wrote there — history, rule groups, values — is
//! read by code that has changed since. `tests/data/<version>/` is such a
//! directory as that version left it; each test copies it to a scratch
//! directory first, because loading history also prunes it.
//!
//! What this holds a later version to (docs/INSTALL.md, "升级"):
//! - every history line written by 0.1.0 reads back as the same record;
//! - its rule groups, their order and on/off state, and its values come back;
//! - a line or file with fields this version does not know still loads, which
//!   is what lets an older binary read a newer one's files after a downgrade.
//!
//! If a change means old data cannot be read as it was, that is a migration to
//! write and to document, not this test to edit.
//!
//! `0.1.0/` was made by driving whix 0.1.0 through the kinds of request
//! it records (plain, binary, truncated, gzip, event stream, GBK, a body that
//! would not decompress, a refused connection, a POST, a Composer request),
//! with the root CA left out: a private key does not belong in a repository.

use std::fs;
use std::path::{Path, PathBuf};

use whix::proxy::outcome::Phase;
use whix::proxy::persist::{PersistedSession, SessionStore};
use whix::rules::RuleManager;
use whix::rules::storage::{load_groups, load_values};

/// History files are dated; this keeps any date as within retention.
const FOREVER_DAYS: u32 = 36_500;

fn copy_of(version: &str, name: &str) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(version);
    let to = std::env::temp_dir().join(format!("whix-data-compat-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&to);
    copy_dir(&from, &to);
    to
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create");
    for entry in fs::read_dir(from).expect("read fixture") {
        let entry = entry.expect("entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).expect("copy");
        }
    }
}

fn written_lines(dir: &Path) -> Vec<serde_json::Value> {
    let file = dir.join("sessions").join("sessions-2026-09-29.jsonl");
    fs::read_to_string(file)
        .expect("history")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a line of JSON"))
        .collect()
}

#[test]
fn history_written_by_0_1_0_reads_back_as_it_was_written() {
    let dir = copy_of("0.1.0", "history");
    let written = written_lines(&dir);
    let loaded = SessionStore::load(&dir.join("sessions"), 1000, FOREVER_DAYS);
    assert_eq!(loaded.len(), 11, "every line loads");

    // The whole record: what this version would write for the session it
    // read is what 0.1.0 wrote.
    for (session, line) in loaded.iter().zip(&written) {
        let again = serde_json::to_value(PersistedSession::from_session(session)).expect("json");
        assert_eq!(
            &again, line,
            "session #{} changed on the way in",
            session.id
        );
    }

    // And the parts a person looks for, spelled out.
    let by_path = |path: &str| {
        loaded
            .iter()
            .find(|s| s.url == format!("http://compat.test{path}"))
            .unwrap_or_else(|| panic!("no session for {path}"))
    };
    let png = by_path("/png").res_body.as_ref().expect("png body");
    assert!(png.is_binary());
    assert_eq!(&png.preview_bytes().bytes[..4], b"\x89PNG");
    let big = by_path("/big").res_body.as_ref().expect("big body");
    assert!(
        big.snapshot().1,
        "a body past the preview limit stays marked truncated"
    );
    let refused = by_path("/refused");
    assert_eq!(refused.status, 502);
    assert_eq!(
        refused.error.get().expect("a failure").phase,
        Phase::Connect
    );
    assert!(by_path("/text?composer").composer);
    let badgz = by_path("/badgz");
    assert!(badgz.res_body.as_ref().expect("body").is_undecodable());
    assert_eq!(badgz.unapplied.len(), 1);
    assert_eq!(badgz.unapplied[0].ops, ["resReplace://gzip/zipped"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rules_and_values_written_by_0_1_0_come_back() {
    let dir = copy_of("0.1.0", "rules");
    let mut manager = RuleManager::new();
    load_groups(&dir.join("rules"), &mut manager);
    let groups: Vec<(&str, bool)> = manager
        .groups()
        .iter()
        .map(|g| (g.name.as_str(), g.enabled))
        .collect();
    assert_eq!(groups, [("default", true), ("extra", false)]);
    assert!(
        manager.groups()[0]
            .text
            .contains("compat.test/valued resBody://{compat-token}")
    );
    assert_eq!(
        manager.groups()[1].text.trim(),
        "compat.test/extra statusCode://204"
    );
    assert_eq!(
        load_values(&dir).get("compat-token").map(String::as_str),
        Some("abc")
    );
    let _ = fs::remove_dir_all(&dir);
}

/// What a downgrade meets: files from a version that added fields. Serde skips
/// what it does not know, and this test keeps anyone from turning that off
/// (`deny_unknown_fields`) without noticing.
#[test]
fn fields_from_a_newer_version_are_skipped_not_fatal() {
    let dir = copy_of("0.1.0", "newer");
    let mut line = written_lines(&dir).remove(0);
    line["added_later"] = serde_json::json!({ "anything": [1, 2] });
    line["res_body_preview"]["added_later"] = serde_json::json!(true);
    let history = dir.join("sessions").join("sessions-2026-09-29.jsonl");
    fs::write(&history, format!("{line}\n")).expect("write");
    assert_eq!(
        SessionStore::load(&dir.join("sessions"), 10, FOREVER_DAYS).len(),
        1
    );

    let groups = dir.join("rules").join("groups.json");
    fs::write(
        &groups,
        r#"{"groups":[{"name":"default","enabled":true,"added_later":1},
                      {"name":"extra","enabled":false,"color":"red"}],
            "added_later":"x"}"#,
    )
    .expect("write");
    let mut manager = RuleManager::new();
    load_groups(&dir.join("rules"), &mut manager);
    assert_eq!(manager.groups().len(), 2);
    assert!(groups.exists(), "read, not set aside as unreadable");
    let _ = fs::remove_dir_all(&dir);
}
