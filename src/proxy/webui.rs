//! The built-in web UI, served when a client hits the proxy port directly.
//!
//! A self-contained single-page app (no external assets) mirroring the purpose
//! of whistle's `biz/webui`: inspect live traffic and view/edit rules. Also
//! serves the root CA, a PAC file, and a JSON traffic feed.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::body::{self, DynBody};
use super::{AppState, Session};

/// Route a direct (non-proxied) request to the UI / API.
pub async fn handle(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let path = req.uri().path().to_string();
    match (req.method().as_str(), path.as_str()) {
        (_, "/rootCA.crt") | (_, "/rootca.crt") => root_ca(state),
        (_, "/proxy.pac") | (_, "/pac") => pac(state, &req),
        (_, "/sessions.json") => sessions_json(state),
        ("GET", "/api/rules") => rules_get(state),
        ("POST", "/api/rules") => rules_post(state, req).await,
        ("GET", "/api/values") => values_get(state),
        ("POST", "/api/values") => values_post(state, req).await,
        ("GET", "/") | ("GET", "/index.html") => html_ok(index_html(state)),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body::full(Bytes::from_static(b"not found")))
            .unwrap(),
    }
}

fn root_ca(state: &Arc<AppState>) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/x-x509-ca-cert")
        .header(
            hyper::header::CONTENT_DISPOSITION,
            "attachment; filename=\"whistle-rs-rootCA.crt\"",
        )
        .body(body::full(Bytes::from(state.ca.root_cert_pem().to_string())))
        .unwrap()
}

fn pac(state: &Arc<AppState>, req: &Request<Incoming>) -> Response<DynBody> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                state
                    .config
                    .host
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                state.config.port
            )
        });
    let pac = format!("function FindProxyForURL(url, host) {{\n  return \"PROXY {host}\";\n}}\n");
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-ns-proxy-autoconfig",
        )
        .body(body::full(Bytes::from(pac)))
        .unwrap()
}

fn sessions_json(state: &Arc<AppState>) -> Response<DynBody> {
    let sessions: Vec<Session> = {
        let q = state.sessions.lock().unwrap();
        q.iter().rev().cloned().collect()
    };
    let body = serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

fn rules_get(state: &Arc<AppState>) -> Response<DynBody> {
    let text = state.rules.read().unwrap().text().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body::full(Bytes::from(text)))
        .unwrap()
}

async fn rules_post(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap();
        }
    };
    let text = String::from_utf8_lossy(&body).into_owned();
    let count = {
        let mut mgr = state.rules.write().unwrap();
        mgr.set_text(&text);
        mgr.len()
    };
    tracing::info!("rules updated via UI: {count} rules");
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(format!("{{\"ok\":true,\"rules\":{count}}}"))))
        .unwrap()
}

fn values_get(state: &Arc<AppState>) -> Response<DynBody> {
    let values = state.values.read().unwrap().clone();
    let body = serde_json::to_string(&values).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body::full(Bytes::from(body)))
        .unwrap()
}

async fn values_post(state: &Arc<AppState>, req: Request<Incoming>) -> Response<DynBody> {
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body::full(Bytes::from_static(b"could not read body")))
                .unwrap();
        }
    };
    match serde_json::from_slice::<std::collections::HashMap<String, String>>(&body) {
        Ok(map) => {
            *state.values.write().unwrap() = map;
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body::full(Bytes::from_static(b"{\"ok\":true}")))
                .unwrap()
        }
        Err(_) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(body::full(Bytes::from_static(b"expected a JSON object")))
            .unwrap(),
    }
}

fn html_ok(html: String) -> Response<DynBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body::full(Bytes::from(html)))
        .unwrap()
}

/// The single-page UI (all CSS/JS inline; no external requests).
fn index_html(state: &Arc<AppState>) -> String {
    let version = crate::config::VERSION;
    let host = state
        .config
        .host
        .map(|h| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = state.config.port;
    format!(
        r##"<!doctype html><html data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>whistle-rs</title>
<style>
:root{{--bg:#fff;--fg:#222;--muted:#888;--line:#eee;--accent:#2d7ff9;--code:#f4f4f4}}
@media(prefers-color-scheme:dark){{:root{{--bg:#1e1e1e;--fg:#e0e0e0;--muted:#999;--line:#333;--accent:#4c9ffe;--code:#2a2a2a}}}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
header{{display:flex;align-items:center;gap:16px;padding:10px 16px;border-bottom:1px solid var(--line)}}
header h1{{font-size:16px;margin:0}}
header .sp{{flex:1}}
header a{{color:var(--accent);text-decoration:none;font-size:13px}}
nav{{display:flex;gap:4px;padding:8px 16px;border-bottom:1px solid var(--line)}}
nav button{{background:none;border:1px solid var(--line);color:var(--fg);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:13px}}
nav button.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
main{{padding:12px 16px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);white-space:nowrap}}
td.url{{white-space:normal;word-break:break-all}}
.s2{{color:#2e9d4f}}.s3{{color:#3b8fd6}}.s4,.s5{{color:#e05a5a}}
textarea{{width:100%;height:60vh;font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--code);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:10px}}
.bar{{display:flex;gap:10px;align-items:center;margin-bottom:8px}}
.bar button{{background:var(--accent);color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer}}
.hint{{color:var(--muted);font-size:12px}}
.hidden{{display:none}}
</style></head><body>
<header>
  <h1>whistle-rs</h1><span class="hint">v{version} · proxy {host}:{port}</span>
  <span class="sp"></span>
  <a href="/rootCA.crt">rootCA.crt</a>
  <a href="/proxy.pac">proxy.pac</a>
</header>
<nav>
  <button id="tab-net" class="active" onclick="show('net')">Network</button>
  <button id="tab-rules" onclick="show('rules')">Rules</button>
  <button id="tab-values" onclick="show('values')">Values</button>
</nav>
<main>
  <section id="net">
    <div class="bar">
      <button onclick="loadNet()">Refresh</button>
      <label class="hint"><input type="checkbox" id="auto" checked> auto-refresh</label>
      <span class="hint" id="netcount"></span>
    </div>
    <table><thead><tr><th>#</th><th>Method</th><th>Status</th><th>URL</th><th>Target</th><th>ms</th></tr></thead>
    <tbody id="rows"></tbody></table>
  </section>
  <section id="rules" class="hidden">
    <div class="bar">
      <button onclick="saveRules()">Save</button>
      <span class="hint" id="rulestatus"></span>
    </div>
    <textarea id="editor" spellcheck="false" placeholder="pattern operator1 operator2 ..."></textarea>
    <p class="hint">One rule per line. See the docs for the full syntax.</p>
  </section>
  <section id="values" class="hidden">
    <div class="bar">
      <button onclick="saveValues()">Save</button>
      <span class="hint" id="valstatus"></span>
    </div>
    <textarea id="valeditor" spellcheck="false" placeholder='{{"name":"content"}}'></textarea>
    <p class="hint">A JSON object of named values. Reference them with <code>{{name}}</code> in rules.</p>
  </section>
</main>
<script>
var esc=function(s){{return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}};
function show(t){{
  ['net','rules','values'].forEach(function(x){{
    document.getElementById(x).classList.toggle('hidden',x!==t);
    document.getElementById('tab-'+x).classList.toggle('active',x===t);
  }});
  if(t==='rules') loadRules();
  if(t==='values') loadValues();
}}
function loadNet(){{
  fetch('/sessions.json').then(function(r){{return r.json()}}).then(function(list){{
    document.getElementById('netcount').textContent=list.length+' captured';
    document.getElementById('rows').innerHTML=list.map(function(s){{
      var cls='s'+Math.floor(s.status/100);
      return '<tr><td>'+s.id+'</td><td>'+esc(s.method)+'</td><td class="'+cls+'">'+s.status+
        '</td><td class="url">'+esc(s.url)+'</td><td>'+esc(s.target)+'</td><td>'+s.duration_ms+'</td></tr>';
    }}).join('');
  }});
}}
function loadRules(){{
  fetch('/api/rules').then(function(r){{return r.text()}}).then(function(t){{
    document.getElementById('editor').value=t;
  }});
}}
function saveRules(){{
  var txt=document.getElementById('editor').value;
  fetch('/api/rules',{{method:'POST',body:txt}}).then(function(r){{return r.json()}}).then(function(j){{
    document.getElementById('rulestatus').textContent='Saved · '+j.rules+' rules active';
  }}).catch(function(){{document.getElementById('rulestatus').textContent='Save failed'}});
}}
function loadValues(){{
  fetch('/api/values').then(function(r){{return r.json()}}).then(function(v){{
    document.getElementById('valeditor').value=JSON.stringify(v,null,2);
  }});
}}
function saveValues(){{
  var txt=document.getElementById('valeditor').value;
  try{{JSON.parse(txt);}}catch(e){{document.getElementById('valstatus').textContent='Invalid JSON';return;}}
  fetch('/api/values',{{method:'POST',body:txt}}).then(function(r){{return r.json()}}).then(function(){{
    document.getElementById('valstatus').textContent='Saved';
  }}).catch(function(){{document.getElementById('valstatus').textContent='Save failed'}});
}}
loadNet();
setInterval(function(){{if(document.getElementById('auto').checked && !document.getElementById('net').classList.contains('hidden')) loadNet();}},2000);
</script>
</body></html>"##,
        version = version,
        host = host,
        port = port,
    )
}
