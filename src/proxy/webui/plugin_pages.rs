//! A plugin's own pages under `/plugin/<name>/`, served by the plugin's UI hook,
//! and the index listing them.

use super::*;

/// Serve `/plugin/<name>/…` from the named plugin's own UI hook.
///
/// The prefix is stripped here and re-added by the plugin runtime as `/ui`, so a
/// plugin's pages live in their own subtree and can use any path they like
/// without colliding with a hook endpoint. See [`crate::plugins::ui`].
pub(super) async fn plugin_ui(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let (parts, incoming) = req.into_parts();
    let raw = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let Some((name, rest)) = crate::plugins::ui::split_route(parts.uri.path()) else {
        return not_found();
    };
    if name.is_empty() {
        return plugin_index(state).await;
    }
    // A UI served without a trailing slash breaks every relative link on the
    // page, so redirect rather than serve it — as upstream does
    // (`biz/webui/lib/index.js:489-491`).
    if rest.is_none() {
        return redirect_to(&format!("{}{name}/", crate::plugins::ui::UI_ROUTE_PREFIX));
    }
    let name = name.to_string();
    // Rebuild the path from the raw target so percent-encoding survives.
    let tail = &raw[crate::plugins::ui::UI_ROUTE_PREFIX.len() + name.len()..];
    let Ok(uri) = tail.parse::<hyper::Uri>() else {
        return not_found();
    };

    let mut forwarded = Request::builder().method(parts.method).uri(uri);
    for (k, v) in parts.headers.iter() {
        // The console's own login stops here. The console has already checked
        // it; a plugin page is served *behind* that check and has no use for
        // it — but it used to receive it, so every plugin with a UI could read
        // the admin password off its first request.
        if CONSOLE_CREDENTIALS.contains(&k.as_str()) {
            continue;
        }
        forwarded = forwarded.header(k, v);
    }
    let Ok(forwarded) = forwarded.body(body::from_incoming(incoming)) else {
        return not_found();
    };
    match state.plugins.serve_ui(&name, forwarded).await {
        Some(resp) => resp,
        None => not_found(),
    }
}

/// Index of the plugins that serve a UI, so they are reachable without knowing
/// the URL by heart.
pub(super) async fn plugin_index(state: &Arc<AppState>) -> Response<DynBody> {
    let names = state.plugins.ui_names().await;
    let items: String = names
        .iter()
        .map(|n| {
            let n = crate::plugins::ui::escape_html(n);
            format!("<li><a href=\"{n}/\">{n}</a></li>")
        })
        .collect();
    let list = if items.is_empty() {
        "<p>No registered plugin serves a UI.</p>".to_string()
    } else {
        format!("<ul>{items}</ul>")
    };
    html_ok(format!(
        "<!doctype html><meta charset=utf-8><title>whix plugins</title>\
         <style>body{{font:14px/1.6 system-ui;margin:2rem}}</style>\
         <h1>Plugin pages</h1>{list}"
    ))
}

/// A `302` to `location`.
pub(super) fn redirect_to(location: &str) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, location)
        .body(body::empty())
        .unwrap_or_else(|_| not_found())
}
