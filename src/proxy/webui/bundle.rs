//! Rules and values as one file: export every group — on or off — with the
//! values store, and import it back, so a set of rules arrives on another
//! machine with the values it refers to.

use super::*;

/// The marker that identifies an exported bundle, so a file that merely happens
/// to be JSON is never applied as one.
pub(super) const BUNDLE_MARKER: &str = "whistle_rs";

/// Everything the console can edit, as one object: every rule group with the
/// text and the enabled state it has, and the whole values store.
///
/// A group is plain text and the console can save one straight out of its
/// editor, so this exists for what a per-group file cannot carry: a *setup*.
/// Exporting groups one at a time loses which of them were switched off, and
/// loses the values store entirely — which is how a set of rules arrives on
/// another machine resolving `{mock.json}` to nothing at all.
pub(super) fn bundle_of(
    mgr: &crate::rules::RuleManager,
    values: &std::collections::HashMap<String, String>,
) -> serde_json::Value {
    let groups: Vec<serde_json::Value> = mgr
        .groups()
        .iter()
        .map(|g| serde_json::json!({ "name": g.name, "enabled": g.enabled, "text": g.text }))
        .collect();
    serde_json::json!({
        BUNDLE_MARKER: crate::config::VERSION,
        "rules": groups,
        "values": values,
    })
}

/// Apply an exported bundle, returning how many groups and values it carried.
///
/// A group that is already there is updated **in place**. Group order is
/// precedence, so removing and re-adding one would move it to the back and
/// quietly change which rule wins — an import that says it restored a setup
/// must not reorder the rules that were already in it. A group that is not
/// there is appended, in the order the bundle lists it.
///
/// The default group is set rather than added, for the reason
/// [`crate::rules::storage::load_groups`] does the same: it always exists, and
/// `add_group` would refuse it and drop what the bundle carried for it.
pub(super) fn apply_bundle(
    mgr: &mut crate::rules::RuleManager,
    values: &mut std::collections::HashMap<String, String>,
    bundle: &serde_json::Value,
) -> (usize, usize) {
    let mut groups = 0;
    for g in bundle
        .get("rules")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
    {
        let Some(name) = g.get("name").and_then(|v| v.as_str()).map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let text = g.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let enabled = g.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let was = mgr
            .groups()
            .iter()
            .find(|x| x.name == name)
            .map(|x| x.enabled);
        match (name, was) {
            ("default", _) => mgr.set_text(text),
            (_, Some(_)) => {
                mgr.update_group(name, text);
            }
            (_, None) => {
                mgr.add_group(name, text, enabled);
            }
        }
        // `update_group` and `set_text` leave the switch alone, so it is moved
        // separately — and only when it differs, since a toggle is all there is.
        if was.is_some_and(|w| w != enabled) {
            mgr.toggle_group(name);
        }
        groups += 1;
    }
    let mut count = 0;
    if let Some(map) = bundle.get("values").and_then(|v| v.as_object()) {
        for (name, value) in map {
            let Some(value) = value.as_str() else {
                continue;
            };
            values.insert(name.clone(), value.to_string());
            count += 1;
        }
    }
    (groups, count)
}

pub(super) fn bundle_export(state: &Arc<AppState>) -> Response<DynBody> {
    let bundle = {
        let mgr = state.rules.read().unwrap();
        let values = state.values.read().unwrap();
        bundle_of(&mgr, &values)
    };
    let body = serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whistle-rs-rules-and-values.json\"",
        )
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

pub(super) async fn bundle_import(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let bundle = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if bundle.get(BUNDLE_MARKER).is_none() {
        return json_error("not an exported bundle");
    }
    let (groups, values) = {
        let mut mgr = state.rules.write().unwrap();
        let mut store = state.values.write().unwrap();
        let counts = apply_bundle(&mut mgr, &mut store, &bundle);
        save_groups(state, &mgr);
        save_values(state, &store);
        counts
    };
    fetch_new_includes(state);
    tracing::info!("imported {groups} rule groups and {values} values via UI");
    let body = format!("{{\"ok\":true,\"groups\":{groups},\"values\":{values}}}");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

#[cfg(test)]
pub(super) mod bundle_tests {
    use super::super::*;
    use crate::rules::RuleManager;
    use std::collections::HashMap;

    /// A manager with a default group and two named ones, the second off.
    fn setup() -> (RuleManager, HashMap<String, String>) {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com http://localhost:5173\n");
        mgr.add_group("staging", "api.example.com host://10.0.0.9\n", true);
        mgr.add_group("archive", "# kept, not applied\n", false);
        let values = HashMap::from([("mock.json".to_string(), "{\"ok\":true}".to_string())]);
        (mgr, values)
    }

    /// What a group list reduces to for comparison: name, switch and text, in
    /// order — order being precedence, it is part of what has to survive.
    fn shape(mgr: &RuleManager) -> Vec<(String, bool, String)> {
        mgr.groups()
            .iter()
            .map(|g| (g.name.clone(), g.enabled, g.text.clone()))
            .collect()
    }

    /// The whole point of the format: what comes out goes back in unchanged.
    #[test]
    fn a_bundle_restores_the_setup_it_was_taken_from() {
        let (mgr, values) = setup();
        let bundle = bundle_of(&mgr, &values);

        let mut restored = RuleManager::new();
        let mut restored_values = HashMap::new();
        let (groups, count) = apply_bundle(&mut restored, &mut restored_values, &bundle);
        assert_eq!((groups, count), (3, 1));
        assert_eq!(shape(&restored), shape(&mgr));
        assert_eq!(restored_values, values);
    }

    /// Applying a bundle over the setup it came from must be a no-op — not a
    /// second copy of every group, and not a reordering of them.
    #[test]
    fn re_importing_a_bundle_changes_nothing() {
        let (mut mgr, mut values) = setup();
        let bundle = bundle_of(&mgr, &values);
        let before = shape(&mgr);
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(shape(&mgr), before);
    }

    /// Group order is precedence. A group that is already there is updated
    /// where it stands, so an import cannot silently change which rule wins.
    #[test]
    fn an_imported_group_keeps_the_position_it_had() {
        let (mut mgr, mut values) = setup();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [{ "name": "staging", "enabled": true, "text": "changed\n" }],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(
            mgr.groups()
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>(),
            ["default", "staging", "archive"]
        );
        assert_eq!(mgr.groups()[1].text, "changed\n");
    }

    /// Whether a group is switched on is the thing a plain-text export cannot
    /// carry, so the bundle has to.
    #[test]
    fn an_import_moves_a_groups_switch_to_what_the_bundle_says() {
        let (mut mgr, mut values) = setup();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [
                { "name": "staging", "enabled": false, "text": "api.example.com host://10.0.0.9\n" },
                { "name": "archive", "enabled": true, "text": "# kept, not applied\n" },
            ],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert!(!mgr.groups()[1].enabled);
        assert!(mgr.groups()[2].enabled);
    }

    /// The default group always exists, so `add_group` refuses it — the same
    /// trap `storage::load_groups` documents. Its text has to be *set*.
    #[test]
    fn a_bundle_can_restore_the_default_group() {
        let mut mgr = RuleManager::new();
        mgr.set_text("# whatever was here\n");
        let mut values = HashMap::new();
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "rules": [{ "name": "default", "enabled": true, "text": "a.com host://1.1.1.1\n" }],
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(mgr.text(), "a.com host://1.1.1.1\n");
        assert_eq!(mgr.groups().len(), 1);
    }

    /// An import adds to the values store rather than replacing it: the bundle
    /// says what it carries, not what the machine it lands on may keep.
    #[test]
    fn imported_values_are_laid_over_the_ones_already_there() {
        let mut mgr = RuleManager::new();
        let mut values = HashMap::from([
            ("keep.txt".to_string(), "mine".to_string()),
            ("mock.json".to_string(), "old".to_string()),
        ]);
        let bundle = serde_json::json!({
            BUNDLE_MARKER: "test",
            "values": { "mock.json": "new" },
        });
        apply_bundle(&mut mgr, &mut values, &bundle);
        assert_eq!(values.get("keep.txt").map(String::as_str), Some("mine"));
        assert_eq!(values.get("mock.json").map(String::as_str), Some("new"));
    }
}
