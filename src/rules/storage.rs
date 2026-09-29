//! Persist rule groups to disk as individual `.rules` files + a `groups.json`
//! metadata file. Stored under `storage_dir/rules/`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::RuleManager;

/// Metadata for one persisted group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMeta {
    pub name: String,
    pub enabled: bool,
}

/// Full metadata file (`groups.json`) — order determines precedence.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GroupsConfig {
    pub groups: Vec<GroupMeta>,
}

/// Sanitise a group name into a safe filename (no path traversal).
fn safe_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Read a JSON store; absent is empty.
///
/// A file that is there and does not parse — cut short by a crash in an older
/// version, edited by hand, or written by a newer version in a shape this one
/// cannot read — is renamed to `<name>.unreadable-<ms>` and reported, then
/// treated as empty. It used to be treated as empty where it lay, and the
/// next save from the console wrote over it: every rule group or value in it
/// was gone without a word.
fn read_store<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            tracing::warn!("cannot read {}: {e}; starting without it", path.display());
            return T::default();
        }
    };
    match serde_json::from_str(&text) {
        Ok(store) => store,
        Err(e) => {
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            let aside = path.with_file_name(format!("{name}.unreadable-{ms}"));
            match fs::rename(path, &aside) {
                Ok(()) => tracing::warn!(
                    "{} is not valid ({e}); moved to {} so it is not overwritten, \
                     and starting without it",
                    path.display(),
                    aside.display()
                ),
                Err(move_err) => tracing::warn!(
                    "{} is not valid ({e}) and could not be moved aside ({move_err}); \
                     starting without it, and the next save will replace it",
                    path.display()
                ),
            }
            T::default()
        }
    }
}

/// Load all rule groups from `dir` into `manager`.
pub fn load_groups(dir: &Path, manager: &mut RuleManager) {
    let config: GroupsConfig = read_store(&dir.join("groups.json"));
    for meta in &config.groups {
        let file = dir.join(format!("{}.rules", safe_filename(&meta.name)));
        let text = fs::read_to_string(&file).unwrap_or_default();
        // The default group always exists by the time this runs — the manager is
        // built with one — so `add_group` refuses it and what the console saved
        // was silently dropped on the next start. It has to be *set*, not added.
        //
        // Unless the command line named rules explicitly: `-r`/`--rule` is an
        // instruction for this run, and a file on disk from a previous session
        // must not quietly override it.
        if meta.name == "default" {
            if !manager.default_is_empty() {
                continue;
            }
            manager.set_text(&text);
            continue;
        }
        manager.add_group(&meta.name, &text, meta.enabled);
    }
}

/// Save all rule groups from `manager` to `dir`.
pub fn save_groups(dir: &Path, manager: &RuleManager) {
    // Owner-only: rules carry hostnames, credentials in proxy:// URLs, file
    // paths. See `crate::private_fs`.
    crate::private_fs::create_dir(dir).ok();
    crate::private_fs::tighten(dir);

    let config = GroupsConfig {
        groups: manager
            .groups()
            .iter()
            .map(|g| GroupMeta {
                name: g.name.clone(),
                enabled: g.enabled,
            })
            .collect(),
    };

    // Write groups.json.
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        crate::private_fs::write(&dir.join("groups.json"), json.as_bytes()).ok();
    }

    // Write each group's text.
    for g in manager.groups() {
        let file = dir.join(format!("{}.rules", safe_filename(&g.name)));
        crate::private_fs::write(&file, g.text.as_bytes()).ok();
    }
}

/// Save just the metadata (enabled states, order) without re-writing rule text.
pub fn save_meta(dir: &Path, manager: &RuleManager) {
    let config = GroupsConfig {
        groups: manager
            .groups()
            .iter()
            .map(|g| GroupMeta {
                name: g.name.clone(),
                enabled: g.enabled,
            })
            .collect(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        crate::private_fs::write(&dir.join("groups.json"), json.as_bytes()).ok();
    }
}

/// Where the named-values store lives on disk.
fn values_path(dir: &Path) -> std::path::PathBuf {
    dir.join("values.json")
}

/// Load the persisted values store, if there is one.
///
/// Values were previously **command-line only**: the console's Values pane
/// wrote to memory and said "Saved", and the next start had none of it. They
/// are referenced by `{name}` from any operator, so losing them silently breaks
/// every rule that used one.
pub fn load_values(dir: &Path) -> std::collections::HashMap<String, String> {
    read_store(&values_path(dir))
}

/// Write the values store to disk.
pub fn save_values(dir: &Path, values: &std::collections::HashMap<String, String>) {
    // `dir` is the storage root, which may be a directory the operator chose
    // and already had: created owner-only if new, otherwise left alone. The
    // file itself — values often hold tokens — is always owner-only.
    crate::private_fs::create_dir(dir).ok();
    if let Ok(json) = serde_json::to_string_pretty(values) {
        crate::private_fs::write(&values_path(dir), json.as_bytes()).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_sanitises() {
        assert_eq!(safe_filename("my-group_1"), "my-group_1");
        assert_eq!(safe_filename("foo/bar..baz"), "foo_bar__baz");
    }

    #[test]
    fn roundtrip_groups() {
        let dir = std::env::temp_dir().join("whistle-rs-test-groups");
        let _ = fs::remove_dir_all(&dir);

        let mut mgr = RuleManager::new();
        mgr.add_group("default", "*.example.com host://127.0.0.1:8080", true);
        mgr.add_group("debug", "# debug rules\ntest.local 127.0.0.1:9099", false);
        save_groups(&dir, &mgr);

        let mut mgr2 = RuleManager::new();
        load_groups(&dir, &mut mgr2);
        assert_eq!(mgr2.groups().len(), 2);
        assert_eq!(mgr2.groups()[0].name, "default");
        assert!(mgr2.groups()[0].enabled);
        assert_eq!(mgr2.groups()[1].name, "debug");
        assert!(!mgr2.groups()[1].enabled);
        assert!(mgr2.groups()[1].text.contains("test.local"));

        let _ = fs::remove_dir_all(&dir);
    }

    /// A store that does not parse is kept, under another name, rather than
    /// read as empty and then overwritten by the next save.
    #[test]
    fn an_unreadable_store_is_moved_aside_not_emptied() {
        let dir =
            std::env::temp_dir().join(format!("whistle-rs-test-unreadable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        // Cut short mid-write, as a crash left it before writes were atomic.
        let half = r#"{"token":"abc","other":"de"#;
        fs::write(values_path(&dir), half).expect("seed");

        assert!(load_values(&dir).is_empty());
        let names: Vec<String> = fs::read_dir(&dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("values.json.unreadable-"), "{names:?}");
        assert_eq!(fs::read_to_string(dir.join(&names[0])).expect("kept"), half);

        // The next save starts a fresh store and leaves the old one alone.
        save_values(&dir, &[("a".to_string(), "1".to_string())].into());
        assert_eq!(load_values(&dir).get("a").map(String::as_str), Some("1"));
        assert!(dir.join(&names[0]).exists());

        fs::create_dir_all(dir.join("rules")).expect("rules");
        fs::write(dir.join("rules").join("groups.json"), "{\"groups\": [").expect("seed");
        let mut mgr = RuleManager::new();
        load_groups(&dir.join("rules"), &mut mgr);
        assert!(!dir.join("rules").join("groups.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
