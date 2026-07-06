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

/// Load all rule groups from `dir` into `manager`.
pub fn load_groups(dir: &Path, manager: &mut RuleManager) {
    let config_path = dir.join("groups.json");
    let config: GroupsConfig = fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    for meta in &config.groups {
        let file = dir.join(format!("{}.rules", safe_filename(&meta.name)));
        let text = fs::read_to_string(&file).unwrap_or_default();
        manager.add_group(&meta.name, &text, meta.enabled);
    }
}

/// Save all rule groups from `manager` to `dir`.
pub fn save_groups(dir: &Path, manager: &RuleManager) {
    fs::create_dir_all(dir).ok();

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
        fs::write(dir.join("groups.json"), json).ok();
    }

    // Write each group's text.
    for g in manager.groups() {
        let file = dir.join(format!("{}.rules", safe_filename(&g.name)));
        fs::write(&file, &g.text).ok();
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
        fs::write(dir.join("groups.json"), json).ok();
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
}
