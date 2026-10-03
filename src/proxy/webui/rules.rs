//! The rules over HTTP: the rules text, the rule groups — listed, added,
//! switched on and off, edited, deleted — and fetching any `@include` a save
//! just introduced.

use super::*;

pub(super) fn rules_get(state: &Arc<AppState>) -> Response<DynBody> {
    let text = state.rules.read().unwrap().text().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(text)))
        .unwrap()
}

pub(super) async fn rules_post(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let text = String::from_utf8_lossy(&body).into_owned();
    let count = {
        let mut mgr = state.rules.write().unwrap();
        mgr.set_text(&text);
        // Persist, like every *named* group endpoint already does. Without this
        // the default group — the one the console opens on — was in memory only:
        // edit, restart, gone, having been told "Saved".
        save_groups(state, &mgr);
        mgr.len()
    };
    fetch_new_includes(state);
    tracing::info!("rules updated via UI: {count} rules");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!(
            "{{\"ok\":true,\"rules\":{count}}}"
        ))))
        .unwrap()
}

/// A rules text that just changed may name an `@` source nothing has fetched.
///
/// Spawned rather than awaited, and this is the whole contract of the feature:
/// someone typing in the console gets their answer back at the speed of the
/// parse, and the include lands when the fetch lands — at which point the
/// groups that carry an `@` line are re-parsed under the write lock. Blocking
/// the save on an intranet that is down would make a rules editor unusable for
/// exactly the reason includes exist.
///
/// Costs nothing when there is nothing to fetch: [`load_pending`] reads the set
/// of never-loaded sources, which is empty in every rule set that names none.
///
/// [`load_pending`]: crate::rules::include::load_pending
pub(super) fn fetch_new_includes(state: &Arc<AppState>) {
    if !state.rules.read().unwrap().resolves_includes() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        crate::rules::include::load_pending(&state.rules).await;
    });
}

// ── Rule group management API ──

// The console's saves. Each is skipped where the next start would not read
// it back — an embedded proxy, see `Config::persist_edits`.

/// Write every rule group, text and all, under `rules/`.
pub(super) fn save_groups(state: &Arc<AppState>, mgr: &crate::rules::RuleManager) {
    if state.config.persist_edits {
        crate::rules::storage::save_groups(&state.config.data_dir().join("rules"), mgr);
    }
}

/// Write the groups' order and on/off state, not their text.
pub(super) fn save_meta(state: &Arc<AppState>, mgr: &crate::rules::RuleManager) {
    if state.config.persist_edits {
        crate::rules::storage::save_meta(&state.config.data_dir().join("rules"), mgr);
    }
}

/// Write the values store, at the storage root beside `rules/`.
pub(super) fn save_values(
    state: &Arc<AppState>,
    values: &std::collections::HashMap<String, String>,
) {
    if state.config.persist_edits {
        crate::rules::storage::save_values(state.config.data_dir(), values);
    }
}

pub(super) fn rule_groups_get(state: &Arc<AppState>) -> Response<DynBody> {
    let mgr = state.rules.read().unwrap();
    let groups: Vec<serde_json::Value> = mgr
        .groups()
        .iter()
        .map(|g| {
            serde_json::json!({
                "name": g.name,
                "enabled": g.enabled,
                "rules": g.len(),
            })
        })
        .collect();
    let body = serde_json::to_string(&groups).unwrap_or_else(|_| "[]".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

pub(super) fn rule_group_get(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let name = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("name="))
                .map(|v| v.replace("%20", " ").replace("+", " "))
        })
        .unwrap_or_default();
    let mgr = state.rules.read().unwrap();
    if let Some(g) = mgr.groups().iter().find(|g| g.name == name) {
        let body = serde_json::json!({
            "name": g.name,
            "text": g.text,
            "enabled": g.enabled,
            "rules": g.len(),
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body::full(Bytes::from(body.to_string())))
            .unwrap()
    } else {
        json_error("group not found")
    }
}

pub(super) async fn rule_groups_add(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return json_error("name is required");
    }
    let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.add_group(name, text, enabled);
        if ok {
            save_groups(state, &mgr);
        }
        ok
    };
    if ok {
        fetch_new_includes(state);
        json_ok()
    } else {
        json_error("group already exists")
    }
}

pub(super) async fn rule_group_toggle(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let result = {
        let mut mgr = state.rules.write().unwrap();
        // `-M multiEnv` resolves the default group alone, so switching a named
        // one on would record a state the proxy then ignores. Upstream refuses
        // the same call for the same reason — `selectRulesFile` returns without
        // doing anything under `config.multiEnv`
        // (`_original/lib/rules/util.js:148-151`).
        if mgr.is_default_group_only() && name != "default" {
            return json_error(
                "-M multiEnv is on: only the default group resolves, and each \
                 request brings its own rules",
            );
        }
        let r = mgr.toggle_group(name);
        if r.is_some() {
            save_meta(state, &mgr);
        }
        r
    };
    match result {
        Some(enabled) => {
            // A group switched back on re-registers its sources, which may
            // never have been fetched — or were swept while it was off.
            fetch_new_includes(state);
            let body = format!("{{\"ok\":true,\"enabled\":{enabled}}}");
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from(body)))
                .unwrap()
        }
        None => json_error("group not found"),
    }
}

pub(super) async fn rule_group_update(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let text = payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.update_group(name, text);
        if ok {
            save_groups(state, &mgr);
        }
        ok
    };
    if ok {
        fetch_new_includes(state);
        json_ok()
    } else {
        json_error("group not found")
    }
}

pub(super) async fn rule_group_delete(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // Said here rather than left to "group not found", which would be a lie:
    // the default group is there, and is the one group that may not go. See
    // [`crate::rules::RuleManager::remove_group`] for why.
    if name == "default" {
        return json_error("the default group cannot be removed; switch it off instead");
    }
    let ok = {
        let mut mgr = state.rules.write().unwrap();
        let ok = mgr.remove_group(name);
        if ok {
            save_groups(state, &mgr);
        }
        ok
    };
    if ok {
        json_ok()
    } else {
        json_error("group not found")
    }
}
