//! The console's three switches: HTTPS interception, every rule at once, and
//! the plugins — all of them, or one.
//!
//! Upstream keeps each in its `properties` and puts each in a menu: "Enable
//! HTTPS" (`interceptHttpsConnects`), "Disable all rules" (`disabledAllRules`),
//! "Disable all plugins" and a checkbox per plugin (`disabledAllPlugins`,
//! `disabledPlugins`). This port had the HTTPS one as a startup flag only and
//! the other two not at all — turning every rule off meant switching each
//! group off by hand, and forgetting which had been on.

use super::*;

/// `GET /api/switches` — where each switch stands, and which a mode has taken
/// away.
pub(super) fn switches_get(state: &Arc<AppState>) -> Response<DynBody> {
    json_value(&snapshot(state))
}

/// `POST /api/switches` — set any of `intercept_https`, `rules`, `plugins`
/// (each `true` for on). Absent fields are left as they are. Nothing is
/// changed unless every field asked for can be: a request that would half
/// apply is refused whole, with the reason.
pub(super) async fn switches_set(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let field = |name: &str| -> Result<Option<bool>, String> {
        match payload.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Bool(b)) => Ok(Some(*b)),
            Some(other) => Err(format!("`{name}` must be true or false, not {other}")),
        }
    };
    let (https, rules, plugins) = match (field("intercept_https"), field("rules"), field("plugins"))
    {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return json_error(&e),
    };
    if https.is_none() && rules.is_none() && plugins.is_none() {
        return json_error("nothing to set: send intercept_https, rules or plugins");
    }
    // Every refusal before any change.
    if https.is_some() && state.config.capture_locked_off {
        return locked(
            "a mode has taken the HTTPS switch away (-M multiEnv or -M notAllowedEnableHTTPS)",
        );
    }
    if rules == Some(false) && state.config.rules_switch_locked {
        return locked("-M notAllowedDisableRules is on: rules cannot all be switched off");
    }
    if plugins == Some(false) && state.plugins.switches_locked() {
        return locked("-M notAllowedDisablePlugins is on: plugins cannot be switched off");
    }
    if let Some(on) = https {
        // Checked above; cannot fail now.
        let _ = state.set_intercept_https(on);
        tracing::info!("console: HTTPS interception {}", on_off(on));
    }
    if let Some(on) = rules {
        state.rules.write().unwrap().set_all_off(!on);
        tracing::info!("console: all rules {}", on_off(on));
    }
    if let Some(on) = plugins {
        let _ = state.plugins.set_all_on(on);
        tracing::info!("console: all plugins {}", on_off(on));
    }
    if rules.is_some() || plugins.is_some() {
        save(state);
    }
    json_value(&snapshot(state))
}

/// `POST /api/plugin/switch` — `{"name": "audit", "on": false}`.
pub(super) async fn plugin_switch(
    state: &Arc<AppState>,
    req: Request<Incoming>,
) -> Response<DynBody> {
    let payload = match read_json_body(req).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(name) = payload.get("name").and_then(|v| v.as_str()) else {
        return json_error("`name` is required");
    };
    let Some(on) = payload.get("on").and_then(|v| v.as_bool()) else {
        return json_error("`on` must be true or false");
    };
    if let Err(e) = state.plugins.set_on(name, on) {
        return match state.plugins.switches_locked() {
            true => locked(&e),
            false => api_error(StatusCode::NOT_FOUND, &e),
        };
    }
    tracing::info!("console: plugin {name} {}", on_off(on));
    save(state);
    json_value(&snapshot(state))
}

fn snapshot(state: &Arc<AppState>) -> serde_json::Value {
    let rules_off = state.rules.read().unwrap().all_off();
    serde_json::json!({
        "ok": true,
        "intercept_https": state.intercepts_https(),
        "intercept_https_locked": state.config.capture_locked_off,
        "rules": !rules_off,
        "rules_locked": state.config.rules_switch_locked,
        "plugins": !state.plugins.all_off(),
        "plugins_locked": state.plugins.switches_locked(),
        "plugins_off": state.plugins.switched_off(),
    })
}

/// Write what outlives a restart — see [`crate::rules::storage::Switches`] —
/// where there is a restart to outlive (`Config::persist_edits`).
fn save(state: &Arc<AppState>) {
    if !state.config.persist_edits {
        return;
    }
    let switches = crate::rules::storage::Switches {
        rules_off: state.rules.read().unwrap().all_off(),
        plugins_off: state.plugins.all_off(),
        plugins_switched_off: state.plugins.switched_off(),
    };
    crate::rules::storage::save_switches(state.config.data_dir(), &switches);
}

/// A switch a mode has taken away: `409`, because the request is fine and the
/// proxy's state is what says no.
fn locked(msg: &str) -> Response<DynBody> {
    api_error(StatusCode::CONFLICT, msg)
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}
