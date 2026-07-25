//! The `reqStats` / `resStats` hooks — telling a plugin what went past.
//!
//! ## Fire and forget, on purpose
//!
//! Every other hook in this system is a negotiation: the proxy hands something
//! over and waits, because the answer changes what happens next. Stats are the
//! one hook with no answer. Upstream makes that explicit — it opens the request,
//! discards the response (`response.on('data', util.noop)`), swallows errors and
//! never calls back (`lib/plugins/index.js:1369-1408`).
//!
//! So does this. [`post`] spawns and returns; nothing on the request path ever
//! awaits it. That is the whole design, and it is what makes the hook safe to
//! put on a hot path: a stats plugin that hangs, dies, or answers `500` costs
//! the request one `tokio::spawn` and a socket, never a millisecond of latency.
//! It is also why stats are *not* the place to make decisions — a plugin that
//! wants to change a request has [`super::auth`] or the request hook, both of
//! which are waited for precisely because they matter.
//!
//! ## Once per phase
//!
//! Upstream guards with `req._postReqStats` / `req._postResStats` so a request
//! that passes through several stages still reports once. Here the shape of the
//! call sites gives that for free: the proxy walks each matched plugin exactly
//! once per phase, so [`post`] fires once per plugin per phase without a guard.
//!
//! ## What it costs
//!
//! One local HTTP request per matched plugin per phase, off the critical path.
//! No retry: unlike the request hook, there is nothing to salvage by trying
//! again, and a retry storm aimed at a plugin that is already struggling helps
//! no one. Same reasoning as upstream, which registers `noop` error handlers and
//! moves on.

use serde_json::json;

use super::{PluginReq, PluginRes};

/// Which phase a stats ping reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before the request goes upstream.
    Request,
    /// After the response head comes back.
    Response,
}

impl Phase {
    /// Label carried in the payload, so one handler can serve both.
    pub fn label(self) -> &'static str {
        match self {
            Phase::Request => "request",
            Phase::Response => "response",
        }
    }
}

/// Payload for the request phase.
pub fn request_payload(req: &PluginReq) -> serde_json::Value {
    json!({
        "phase": Phase::Request.label(),
        "id": req.id,
        "method": req.method,
        "url": req.url,
        "headers": req.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "clientIp": req.client_ip,
        "param": req.param,
    })
}

/// Payload for the response phase. Carries the status — the reason the phase
/// exists at all.
pub fn response_payload(res: &PluginRes) -> serde_json::Value {
    json!({
        "phase": Phase::Response.label(),
        "id": res.id,
        "method": res.method,
        "url": res.url,
        "statusCode": res.status,
        "headers": res.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "param": res.param,
    })
}

/// Send one stats ping and stop caring about it.
///
/// Returns the instant the task is spawned. The caller is on the request path;
/// nothing here may make it wait.
pub fn post(name: &str, base_url: &str, payload: serde_json::Value) {
    let url = format!("{base_url}/stats");
    let name = name.to_string();
    tokio::spawn(async move {
        match crate::proxy::upstream::simple_post_json(&url, &payload.to_string()).await {
            Ok(_) => {}
            // Debug, not warn: a stats endpoint that is down changes nothing
            // about the request, and a warning per request would be noise.
            Err(e) => tracing::debug!("stats {name}: {e:#}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shapes() {
        let req = PluginReq {
            id: 9,
            method: "POST".into(),
            url: "http://a/b".into(),
            headers: vec![("host".into(), "a".into())],
            client_ip: Some("1.2.3.4".into()),
            param: "p".into(),
            body: Some(b"ignored".to_vec()),
        };
        let v = request_payload(&req);
        assert_eq!(v["phase"], "request");
        assert_eq!(v["id"], 9);
        assert_eq!(v["headers"][0][1], "a");
        // The body is never reported: stats must not be a reason to buffer one.
        assert!(v.get("body").is_none() && v.get("bodyBase64").is_none());

        let res = PluginRes {
            id: 9,
            method: "POST".into(),
            url: "http://a/b".into(),
            status: 503,
            headers: vec![],
            param: "p".into(),
            body: None,
        };
        let v = response_payload(&res);
        assert_eq!(v["phase"], "response");
        assert_eq!(v["statusCode"], 503);
    }

    /// The load-bearing property: posting to a plugin that is not there returns
    /// immediately and never fails the caller.
    #[test]
    fn post_never_blocks_the_caller() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let started = std::time::Instant::now();
            // Port 1 is not listening; a synchronous implementation would stall
            // here on the connection attempt.
            post("gone", "http://127.0.0.1:1", json!({"phase":"request"}));
            assert!(started.elapsed() < std::time::Duration::from_millis(50));
        });
    }
}
