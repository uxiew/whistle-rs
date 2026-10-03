//! The Values store over HTTP: reading it, saving it whole, and setting,
//! renaming or deleting one value.

use super::*;

pub(super) fn values_get(state: &Arc<AppState>) -> Response<DynBody> {
    let values = state.values.read().unwrap().clone();
    let body = serde_json::to_string(&values).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

pub(super) async fn values_post(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    match serde_json::from_slice::<std::collections::HashMap<String, String>>(&body) {
        Ok(map) => {
            save_values(state, &map);
            *state.values.write().unwrap() = map;
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from_static(b"{\"ok\":true}")))
                .unwrap()
        }
        Err(_) => refused("expected a JSON object of names to text values"),
    }
}

/// Read-modify-write the values store, persisting whatever the edit left.
///
/// The disk write happens under the same lock as the edit. Editing one key at a
/// time means the console makes several of these calls in quick succession, and
/// a save that ran outside the lock could write a copy of the store taken before
/// its neighbour's change — a key that comes back after a restart having quietly
/// lost an edit is the same failure this store was fixed for once already.
pub(super) fn edit_values(
    state: &Arc<AppState>,
    edit: impl FnOnce(&mut std::collections::HashMap<String, String>) -> bool,
) -> bool {
    let mut values = state.values.write().unwrap();
    if !edit(&mut values) {
        return false;
    }
    save_values(state, &values);
    true
}

/// Move a value from one name to another.
///
/// Refuses to rename onto a name that is taken: `{name}` references resolve by
/// name, so overwriting one here would silently repoint every rule that used it
/// at somebody else's content.
pub(super) fn rename_value(
    values: &mut std::collections::HashMap<String, String>,
    from: &str,
    to: &str,
) -> Result<(), &'static str> {
    let Some(content) = values.get(from).cloned() else {
        return Err("value not found");
    };
    if from == to {
        return Ok(());
    }
    if values.contains_key(to) {
        return Err("a value by that name already exists");
    }
    values.remove(from);
    values.insert(to.to_string(), content);
    Ok(())
}

/// The `name` a value endpoint was given, trimmed. A blank one is not a name:
/// `{}` resolves to nothing, so a value stored under it could never be read.
pub(super) fn value_name(payload: &serde_json::Value, key: &str) -> Option<String> {
    let name = payload
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Create or replace one named value (`{"name":…,"value":…}`).
///
/// Editing the store as a whole JSON object — the only way there was — means
/// every edit rewrites every key, so a typo anywhere loses the lot and two
/// tabs open on the pane overwrite each other silently.
pub(super) async fn value_set(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(name) = value_name(&payload, "name") else {
        return json_error("name is required");
    };
    let value = payload
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    edit_values(state, |values| {
        values.insert(name, value);
        true
    });
    json_ok()
}

/// Rename one value (`{"name":…,"to":…}`).
pub(super) async fn value_rename(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (Some(from), Some(to)) = (value_name(&payload, "name"), value_name(&payload, "to")) else {
        return json_error("name is required");
    };
    let mut failure = None;
    edit_values(state, |values| match rename_value(values, &from, &to) {
        Ok(()) => true,
        Err(why) => {
            failure = Some(why);
            false
        }
    });
    match failure {
        Some(why) => json_error(why),
        None => json_ok(),
    }
}

/// Delete one value (`{"name":…}`).
pub(super) async fn value_delete(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(name) = value_name(&payload, "name") else {
        return json_error("name is required");
    };
    match edit_values(state, |values| values.remove(&name).is_some()) {
        true => json_ok(),
        false => json_error("value not found"),
    }
}

#[cfg(test)]
pub(super) mod value_tests {
    use super::super::*;
    use std::collections::HashMap;

    fn store(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_renamed_value_keeps_its_content_under_the_new_name() {
        let mut values = store(&[("mock.json", "{\"ok\":true}")]);
        assert_eq!(
            rename_value(&mut values, "mock.json", "fixture.json"),
            Ok(())
        );
        assert_eq!(
            values.get("fixture.json").map(String::as_str),
            Some("{\"ok\":true}")
        );
        assert!(!values.contains_key("mock.json"));
    }

    /// A `{name}` reference resolves by name, so a rename onto a name that is
    /// taken would repoint every rule that used it at somebody else's content —
    /// and nothing in the rules text would have changed to say so.
    #[test]
    fn a_rename_will_not_overwrite_a_value_that_exists() {
        let mut values = store(&[("a", "first"), ("b", "second")]);
        assert!(rename_value(&mut values, "a", "b").is_err());
        assert_eq!(values.get("b").map(String::as_str), Some("second"));
        assert_eq!(values.get("a").map(String::as_str), Some("first"));
    }

    /// Renaming to the same name is what a rename dialogue answers with when
    /// nothing was typed, and it must not read as a collision with itself.
    #[test]
    fn renaming_a_value_to_its_own_name_does_nothing() {
        let mut values = store(&[("a", "first")]);
        assert_eq!(rename_value(&mut values, "a", "a"), Ok(()));
        assert_eq!(values.get("a").map(String::as_str), Some("first"));
    }

    #[test]
    fn renaming_a_value_that_is_not_there_is_an_error() {
        assert!(rename_value(&mut store(&[]), "gone", "new").is_err());
    }
}
