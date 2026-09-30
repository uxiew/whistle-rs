//! What pages have written to their consoles, for the console's Console pane —
//! the reading half of `log://`. The writing half, and what a page log is, are
//! in [`crate::proxy::pagelog`].

use super::*;

/// `GET /api/logs[?after=<seq>][&id=<id>]` — the page logs held, oldest first.
///
/// `after` makes it a cursor: pass the `last` of the previous answer and only
/// what arrived since comes back, which is how the pane follows a page without
/// fetching two thousand entries every two seconds. `id` keeps one rule's
/// group. `ids` lists every group that has an entry, whatever was asked for,
/// so the pane can offer them.
pub(super) fn logs_get(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let after = query_param(req, "after")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    // An id is a word of the rule file's own; the one thing a query string can
    // do to it is percent-encode it.
    let id = query_param(req, "id").map(|raw| percent_decode(&raw));
    let logs = state.page_logs.lock().unwrap();
    json_value(&serde_json::json!({
        "ok": true,
        "logs": logs.after(after, id.as_deref()),
        "ids": logs.ids(),
        "last": logs.last(),
    }))
}

/// `POST /api/logs/clear` — forget the page logs: all of them, or one group's
/// with `{"id":"…"}`.
pub(super) async fn logs_clear(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let id = read_json_body(req)
        .await
        .ok()
        .and_then(|v| v.get("id")?.as_str().map(str::to_string));
    let cleared = state.page_logs.lock().unwrap().clear(id.as_deref());
    json_value(&serde_json::json!({ "ok": true, "cleared": cleared }))
}

/// `%41` → `A`, leniently: an escape that is not one stays as written.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
