//! `log://` — what a **page** writes to its console, brought to this proxy's.
//!
//! [`log.md`]: "自动在页面中注入 JavaScript 代码，捕获 JavaScript 异常及
//! `console.xxx` 日志，并在 Whistle 管理界面中实时显示". It is how a page on a
//! phone, with no developer tools to open, is debugged from the desk.
//!
//! This port read `log://` as a label on the session and injected nothing. A
//! 31-byte page came back as 31 bytes; upstream's came back with the script in
//! it.
//!
//! Three parts, all here:
//!
//! 1. [`inject`] puts [`SCRIPT`] into an HTML or JavaScript response a
//!    `log://` rule matched. The script wraps `console.*`, listens for
//!    uncaught errors and unhandled rejections, and posts what it sees to
//!    [`PATH`] **on the page's own origin**.
//! 2. [`accept`] answers that path. The page's requests come through this
//!    proxy like any other, so a path on the page's own origin is a path this
//!    proxy sees — and answering it here means no cross-origin request, no
//!    mixed content on an https page, and nothing for the page's CSP to refuse
//!    beyond what it would refuse its own origin. It never reaches the origin
//!    and leaves no session.
//! 3. [`PageLogs`] keeps what arrived, bounded, for the console's Console pane
//!    (`GET /api/logs`).
//!
//! The script is this port's own rather than upstream's `assets/js/log.js`:
//! the transport differs (upstream posts to a `cgi-bin` route on its own
//! internal path), and so does what is kept. What a page can rely on is the
//! documented part: `window.onBeforeWhistleLogSend(result, level)`.
//!
//! [`log.md`]: https://wproxy.org/docs/rules/log.html

use std::collections::VecDeque;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};

use super::body::{self, DynBody};
use super::{AppState, now_ms};

/// Where an injected page reports to, on its own origin.
///
/// A path no site has a use for. A request for it through this proxy is the
/// script's, whatever host it names; it is answered here and goes no further.
pub const PATH: &str = "/.whix/log";

/// How many entries are kept before the oldest goes.
const MAX_ENTRIES: usize = 2000;
/// …and how much text they may hold between them. One `console.log` of a large
/// object is tens of kilobytes; two thousand of those is not a ring buffer.
const MAX_BYTES: usize = 8 * 1024 * 1024;
/// The most one report may carry. The script sends at most twenty entries of
/// at most 64 KiB each; anything larger did not come from it.
const MAX_REPORT: usize = 2 * 1024 * 1024;
/// The most one entry keeps, whatever the page sent.
const MAX_ENTRY: usize = 64 * 1024;

/// One thing a page said.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PageLog {
    /// A number that only grows, so a console can ask for "everything after".
    pub seq: u64,
    /// When the page said it, by the page's clock, in Unix milliseconds.
    pub time_ms: u128,
    /// `log`, `info`, `warn`, `error` or `debug`.
    pub level: String,
    /// The rule's id — `audit` for `log://audit` — which is what the console
    /// groups by.
    pub id: String,
    /// The arguments, each already text: a string as it was, anything else as
    /// the script rendered it.
    pub args: Vec<String>,
    /// The page that said it.
    pub page: String,
    /// Who was looking at it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
}

impl PageLog {
    fn size(&self) -> usize {
        self.args.iter().map(String::len).sum::<usize>() + self.page.len() + 64
    }
}

/// What pages have said, newest last.
#[derive(Default)]
pub struct PageLogs {
    entries: VecDeque<PageLog>,
    bytes: usize,
    next: u64,
}

impl PageLogs {
    fn push(&mut self, mut log: PageLog) {
        self.next += 1;
        log.seq = self.next;
        self.bytes += log.size();
        self.entries.push_back(log);
        while self.entries.len() > MAX_ENTRIES || self.bytes > MAX_BYTES {
            match self.entries.pop_front() {
                Some(old) => self.bytes -= old.size(),
                None => break,
            }
        }
    }

    /// Entries after `after`, optionally one id's only, oldest first.
    pub fn after(&self, after: u64, id: Option<&str>) -> Vec<PageLog> {
        self.entries
            .iter()
            .filter(|log| log.seq > after)
            .filter(|log| id.is_none_or(|id| log.id == id))
            .cloned()
            .collect()
    }

    /// Every id that has an entry, sorted — the console's group list.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.entries.iter().map(|log| log.id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// The highest sequence number handed out, whether or not its entry is
    /// still held.
    pub fn last(&self) -> u64 {
        self.next
    }

    /// Forget everything, or one id's entries. Sequence numbers carry on.
    pub fn clear(&mut self, id: Option<&str>) -> usize {
        let before = self.entries.len();
        match id {
            Some(id) => self.entries.retain(|log| log.id != id),
            None => self.entries.clear(),
        }
        self.bytes = self.entries.iter().map(PageLog::size).sum();
        before - self.entries.len()
    }
}

/// The rule's id and the script it names, if it names one.
///
/// `LOG_ID_RE` (`_original/lib/inspectors/log.js:10`): a plain word of up to
/// 36 characters is the id. `log://{name}` is the id `name` **and** a script
/// of the user's own, read from the values, injected after this one — which is
/// how `log.md`'s "日志预处理" is set up without a second rule. Anything else
/// (empty, a path, too long) is the unnamed group.
pub fn id_and_script(
    value: &str,
    group: Option<&str>,
    values: &std::collections::HashMap<String, String>,
) -> (String, Option<String>) {
    let plain = |s: &str| {
        !s.is_empty()
            && s.chars().count() <= 36
            && !s
                .chars()
                .any(|c| c.is_whitespace() || "/\\{}()<>".contains(c))
    };
    if let Some(name) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}'))
        && !name.is_empty()
        && name.chars().count() <= 36
        && !name.chars().any(char::is_whitespace)
    {
        let script = super::apply::value_for(values, name, group).cloned();
        return (name.to_string(), script);
    }
    match plain(value) {
        true => (value.to_string(), None),
        false => (String::new(), None),
    }
}

/// What is injected. `$LOG_ID`, `$LOG_PATH` and `$INTERCEPT_CONSOLE` are
/// filled in by [`script`].
///
/// Written for the browsers this exists for — an old WebView on a phone — so
/// no arrow functions, no `let`, nothing newer than ES5 outside a `try`.
const SCRIPT: &str = r#";(function () {
  if (typeof window === 'undefined' || window.__whixLog) { return; }
  window.__whixLog = true;
  var ID = '$LOG_ID';
  var URL = '$LOG_PATH';
  var INTERCEPT = $INTERCEPT_CONSOLE;
  var MAX_TEXT = 65536;
  var queue = [];
  var timer = null;
  var busy = false;

  function clip(text) {
    return text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) + '...(' + (text.length - MAX_TEXT) + ' more)' : text;
  }

  // One argument, as text. A string is itself; an Error is its stack; anything
  // else is its JSON, with a repeat of an object already seen named rather
  // than followed — a DOM node or a store is a cycle as often as not.
  function show(value) {
    if (typeof value === 'string') { return value; }
    if (value === undefined) { return 'undefined'; }
    if (typeof value === 'function') { return String(value).slice(0, 200); }
    try {
      if (value instanceof Error) { return value.stack ? String(value.stack) : value.name + ': ' + value.message; }
      if (typeof Node !== 'undefined' && value instanceof Node) {
        var tag = value.nodeName ? value.nodeName.toLowerCase() : 'node';
        return '<' + tag + (value.id ? '#' + value.id : '') + (typeof value.className === 'string' && value.className ? '.' + value.className.split(/\s+/).join('.') : '') + '>';
      }
      var seen = [];
      var json = JSON.stringify(value, function (key, v) {
        if (v && typeof v === 'object') {
          for (var i = 0; i < seen.length; i++) { if (seen[i] === v) { return '[Circular]'; } }
          seen.push(v);
        }
        if (typeof v === 'function') { return '[Function]'; }
        if (typeof v === 'string' && v.length > 8192) { return v.slice(0, 8192) + '...(' + (v.length - 8192) + ' more)'; }
        return v;
      });
      return json === undefined ? String(value) : json;
    } catch (e) {
      try { return String(value); } catch (e2) { return '[unprintable]'; }
    }
  }

  function flush() {
    timer = null;
    if (busy || !queue.length) { return; }
    var batch = queue.splice(0, 20);
    var body;
    try { body = JSON.stringify({ page: String(location.href), list: batch }); } catch (e) { return; }
    try {
      var xhr = new XMLHttpRequest();
      busy = true;
      xhr.open('POST', URL, true);
      // `text/plain`: a simple request, so no preflight wherever the page is.
      xhr.setRequestHeader('Content-Type', 'text/plain');
      xhr.onloadend = function () { busy = false; if (queue.length) { schedule(); } };
      xhr.send(body);
    } catch (e) { busy = false; }
  }

  function schedule() {
    if (!timer) { timer = setTimeout(flush, 60); }
  }

  function add(level, list) {
    // The documented hook: edit `result` in place; empty it, or return false,
    // and the entry is not sent.
    if (typeof window.onBeforeWhistleLogSend === 'function') {
      try { if (window.onBeforeWhistleLogSend(list, level) === false) { return; } } catch (e) {}
      if (!list.length) { return; }
    }
    var args = [];
    for (var i = 0; i < list.length; i++) { args.push(clip(show(list[i]))); }
    queue.push({ t: new Date().getTime(), level: level, id: ID, args: args });
    // A page in a loop must not take the phone's memory with it.
    if (queue.length > 500) { queue.splice(0, queue.length - 500); }
    schedule();
  }

  function where() {
    return '\nPage URL: ' + location.href + '\nUser Agent: ' + navigator.userAgent;
  }

  if (INTERCEPT) {
    var con = window.console = window.console || {};
    var levels = ['log', 'info', 'warn', 'error', 'debug'];
    for (var n = 0; n < levels.length; n++) {
      (function (level) {
        var original = con[level];
        con[level] = function () {
          var list = [];
          for (var i = 0; i < arguments.length; i++) { list.push(arguments[i]); }
          try { add(level, list); } catch (e) {}
          if (typeof original === 'function') { return original.apply(con, arguments); }
        };
      })(levels[n]);
    }
  }

  if (window.addEventListener) {
    window.addEventListener('error', function (event) {
      var target = event && event.target;
      // A resource that would not load: the event is on the element, and says
      // nothing but which one.
      if (target && target !== window && (target.src || target.href)) {
        add('error', ['Failed to load <' + String(target.nodeName).toLowerCase() + '> ' + (target.src || target.href) + where()]);
        return;
      }
      var error = event && event.error;
      var text;
      if (error && error.stack) {
        text = String(error.stack);
      } else {
        // No stack (a cross-origin script, an old engine): the event's own
        // file and line are all there is. With a stack they are its first
        // frame, and saying them again is a line that looks like a second one.
        text = String((event && event.message) || 'Script error');
        if (event && event.filename) { text += '\n    at ' + event.filename + ':' + event.lineno + ':' + event.colno; }
      }
      add('error', [text + where()]);
    }, true);
    window.addEventListener('unhandledrejection', function (event) {
      var reason = event && event.reason;
      add('error', ['Unhandled promise rejection: ' + show(reason) + where()]);
    });
    // What is still queued when the page goes: a beacon survives the unload
    // that an XHR started now would not.
    window.addEventListener('pagehide', function () {
      if (!queue.length || !navigator.sendBeacon) { return; }
      try { navigator.sendBeacon(URL, JSON.stringify({ page: String(location.href), list: queue.splice(0, 20) })); } catch (e) {}
    });
  }
})();
"#;

/// [`SCRIPT`] for one rule: its id in, and whether `console.*` is wrapped.
///
/// `intercept_console` is `!disable.interceptConsole || enable.interceptConsole`
/// (`_original/lib/inspectors/log.js:46`): off, the script still reports
/// uncaught errors and leaves `console` alone.
///
/// **One line.** The script goes in front of a page's own source, and every
/// line it takes moves everything after it down by one: a stack that says
/// `cart.js:41` would be pointing at line 41 of a file nobody has. On one
/// line, with no line break after it, the numbers in a stack are still the
/// numbers in the source — only columns on the line it shares move.
pub fn script(id: &str, intercept_console: bool) -> String {
    // The id goes inside a single-quoted JavaScript string, in a `<script>`
    // element: nothing in it may end either.
    let safe: String = id
        .chars()
        .filter(|c| !matches!(c, '\'' | '\\' | '<' | '>' | '\n' | '\r'))
        .collect();
    // Every statement in `SCRIPT` ends in `;` or `}` and every comment has a
    // line to itself, which is what makes joining its lines safe. The test
    // that runs the result in an engine is what holds that true.
    let one_line = SCRIPT
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ");
    one_line
        .replace("$LOG_ID", &safe)
        .replace("$LOG_PATH", PATH)
        .replace(
            "$INTERCEPT_CONSOLE",
            if intercept_console { "true" } else { "false" },
        )
}

/// What a `log://` rule asks to have injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    pub id: String,
    /// `log://{name}`'s own script, injected after the collector.
    pub user_script: Option<String>,
    pub intercept_console: bool,
}

/// Put the collector into `body`, if it is a page or a script.
///
/// * **HTML** — a `<script>` element first thing in `<head>` (or after
///   `<html>`, or at the very top with a doctype in front), so it runs before
///   any script of the page's own and nothing the page logs is missed.
///   Upstream always writes it at the very top of the document; inside
///   `<head>` runs as early and leaves the page's own doctype first.
/// * **JavaScript** — the source, in front. A page whose HTML is not under the
///   rule but whose scripts are still reports; the guard at the top of the
///   script makes a second copy a no-op.
///
/// No line break follows the collector in either — see [`script`]. A
/// `log://{name}` script of the user's own is as many lines as they wrote, and
/// does get one after it: it may end in a `//` comment, which would otherwise
/// swallow the first line of the source.
/// * anything else — `None`, and the body is left alone.
pub fn inject(body: &Bytes, content_type: Option<&str>, injection: &Injection) -> Option<Bytes> {
    let source = script(&injection.id, injection.intercept_console);
    match kind_of(content_type?)? {
        Kind::Html => {
            let mut tag = format!("<script>{source}</script>");
            if let Some(user) = &injection.user_script {
                tag.push_str(&format!("<script>{user}\n</script>"));
            }
            Some(first_in_html(body, &tag))
        }
        Kind::Js => {
            let mut out = Vec::with_capacity(body.len() + source.len() + 4);
            out.extend_from_slice(source.as_bytes());
            if let Some(user) = &injection.user_script {
                out.extend_from_slice(user.as_bytes());
                out.extend_from_slice(b"\n");
            }
            out.extend_from_slice(body);
            Some(Bytes::from(out))
        }
    }
}

/// The two kinds of body the collector can stand in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Html,
    Js,
}

/// Which, if either, a `Content-Type` names — whistle's `getContentType`
/// order, where `javascript` is asked before `html` and only the media type
/// is looked at (`_original/lib/util/index.js`, and `apply::res_class` here).
fn kind_of(content_type: &str) -> Option<Kind> {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media.contains("javascript") {
        Some(Kind::Js)
    } else if media.contains("css") {
        None
    } else if media.contains("html") {
        Some(Kind::Html)
    } else {
        None
    }
}

/// Whether a `log://` rule has anything to inject into a body of this type.
/// A response that is neither a page nor a script is not collected for it.
pub fn injects_into(content_type: Option<&str>) -> bool {
    content_type.and_then(kind_of).is_some()
}

/// `tag` as the first thing a browser runs in this document.
fn first_in_html(body: &Bytes, tag: &str) -> Bytes {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    // After the opening `<head …>` or, failing that, `<html …>`. `<header` is
    // not `<head`: the character after the name has to end it.
    let after_open = |name: &str| {
        let mut from = 0;
        while let Some(at) = lower[from..].find(name) {
            let start = from + at;
            let next = lower[start + name.len()..].chars().next();
            if matches!(
                next,
                Some('>') | Some(' ') | Some('\t') | Some('\r') | Some('\n') | Some('/')
            ) && let Some(close) = lower[start..].find('>')
            {
                return Some(start + close + 1);
            }
            from = start + name.len();
        }
        None
    };
    let mut out = String::with_capacity(text.len() + tag.len() + 20);
    match after_open("<head").or_else(|| after_open("<html")) {
        Some(at) => {
            out.push_str(&text[..at]);
            out.push_str(tag);
            out.push_str(&text[at..]);
        }
        None => {
            // No document structure to stand inside. A script before anything
            // else would put the page in quirks mode, so say the doctype first
            // — upstream's `logHtmlScript`.
            out.push_str("<!DOCTYPE html>");
            out.push_str(tag);
            out.push_str(&text);
        }
    }
    Bytes::from(out)
}

/// What a report from the script looks like.
#[derive(serde::Deserialize)]
struct Report {
    #[serde(default)]
    page: String,
    #[serde(default)]
    list: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    #[serde(default)]
    t: f64,
    #[serde(default)]
    level: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    args: Vec<String>,
}

/// Answer a request for [`PATH`]: keep what it reports, say so, send nothing
/// on. Always `204` for a well-formed POST — a page's logging must never be
/// able to break the page, and there is nobody on the other end to read an
/// error.
pub async fn accept<B>(state: &AppState, req: Request<B>, peer: SocketAddr) -> Response<DynBody>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let answer = |status: StatusCode| {
        Response::builder()
            .status(status)
            // The page and this path are one origin, so this is for the beacon
            // from a sandboxed frame, whose origin is `null`.
            .header("access-control-allow-origin", "*")
            .header("cache-control", "no-store")
            .body(body::empty())
            .expect("a static response")
    };
    if req.method() == hyper::Method::OPTIONS {
        return answer(StatusCode::NO_CONTENT);
    }
    if req.method() != hyper::Method::POST {
        return answer(StatusCode::METHOD_NOT_ALLOWED);
    }
    let mut body = req.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len() + data.len() > MAX_REPORT {
            return answer(StatusCode::PAYLOAD_TOO_LARGE);
        }
        bytes.extend_from_slice(&data);
    }
    let Ok(report) = serde_json::from_slice::<Report>(&bytes) else {
        return answer(StatusCode::BAD_REQUEST);
    };
    let client_ip = Some(peer.ip().to_string());
    let page: String = report.page.chars().take(2048).collect();
    let mut logs = state.page_logs.lock().unwrap();
    for entry in report.list.into_iter().take(50) {
        let level = match entry.level.as_str() {
            level @ ("log" | "info" | "warn" | "error" | "debug") => level.to_string(),
            _ => "log".to_string(),
        };
        let mut room = MAX_ENTRY;
        let args = entry
            .args
            .into_iter()
            .take(32)
            .map(|arg| {
                let kept: String = arg.chars().take(room).collect();
                room = room.saturating_sub(kept.len());
                kept
            })
            .collect();
        logs.push(PageLog {
            seq: 0,
            time_ms: if entry.t.is_finite() && entry.t > 0.0 {
                entry.t as u128
            } else {
                now_ms()
            },
            level,
            id: entry.id.chars().take(64).collect(),
            args,
            page: page.clone(),
            client_ip: client_ip.clone(),
        });
    }
    answer(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn injection(id: &str) -> Injection {
        Injection {
            id: id.to_string(),
            user_script: None,
            intercept_console: true,
        }
    }

    /// The script goes first in `<head>`, so it is running before any script
    /// of the page's own; without a head, after `<html>`; without either, at
    /// the top behind a doctype. And `<header>` is not `<head>`.
    #[test]
    fn the_script_is_the_first_thing_the_page_runs() {
        let html = Some("text/html; charset=utf-8");
        let inject_into = |page: &str| {
            String::from_utf8(
                inject(&Bytes::from(page.to_string()), html, &injection("app"))
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        };
        let out = inject_into(
            "<!doctype html><html><HEAD lang=x><script>first()</script></head><body>hi</body></html>",
        );
        let at = out.find("__whixLog").expect("injected");
        assert!(
            out.starts_with("<!doctype html><html><HEAD lang=x><script>;(function"),
            "{}",
            &out[..80]
        );
        assert!(
            at < out.find("first()").unwrap(),
            "before the page's own script"
        );
        assert!(out.ends_with("<body>hi</body></html>"));
        assert!(out.contains("var ID = 'app';") && out.contains(PATH));

        let out = inject_into("<html><body><header>x</header></body></html>");
        assert!(
            out.starts_with("<html><script>;(function"),
            "{}",
            &out[..40]
        );

        let out = inject_into("<header>no document</header>");
        assert!(
            out.starts_with("<!DOCTYPE html><script>;(function"),
            "{}",
            &out[..40]
        );
        assert!(out.ends_with("<header>no document</header>"));
    }

    /// The collector takes no line of its own, so a stack's line numbers are
    /// still the source's: `cart.js:41` is line 41 of `cart.js`.
    #[test]
    fn the_collector_adds_no_line_to_what_it_is_put_into() {
        let lines = |text: &[u8]| text.iter().filter(|b| **b == b'\n').count();
        for (ct, body) in [
            (
                "text/html",
                "<!doctype html>\n<html>\n<head>\n<script>a()</script>\n</head>\n</html>\n",
            ),
            (
                "application/javascript",
                "'use strict';\nfirst();\nsecond();\n",
            ),
        ] {
            let out = inject(&Bytes::from(body), Some(ct), &injection("a")).unwrap();
            assert_eq!(lines(&out), lines(body.as_bytes()), "{ct}");
        }
        // The user's own script is as long as they made it, and is closed off
        // so that a comment on its last line cannot reach the source.
        let mut both = injection("a");
        both.user_script = Some("hook(); // mine".into());
        let out = inject(
            &Bytes::from_static(b"app();"),
            Some("text/javascript"),
            &both,
        )
        .unwrap();
        assert!(out.ends_with(b"})();hook(); // mine\napp();"), "{out:?}");
    }

    /// A script gets the source in front; anything else is left alone.
    #[test]
    fn a_script_gets_the_source_and_other_bodies_nothing() {
        let body = Bytes::from_static(b"app();");
        let out = inject(&body, Some("application/javascript"), &injection("a")).unwrap();
        let out = String::from_utf8(out.to_vec()).unwrap();
        assert!(out.starts_with(";(function") && out.ends_with("})();app();"));
        assert!(!out.contains("<script>"));
        for ct in [
            Some("application/json"),
            Some("image/png"),
            Some("text/css"),
            None,
        ] {
            assert!(inject(&body, ct, &injection("a")).is_none(), "{ct:?}");
        }
    }

    /// `log://{name}` is the id `name` and the value's text as a script of the
    /// page author's own, after the collector; `disable://interceptConsole`
    /// leaves `console` alone.
    #[test]
    fn the_rule_names_an_id_a_script_and_whether_console_is_wrapped() {
        let mut values = std::collections::HashMap::new();
        values.insert(
            "pre.js".to_string(),
            "window.onBeforeWhistleLogSend = f;".to_string(),
        );
        assert_eq!(
            id_and_script("audit", None, &values),
            ("audit".to_string(), None)
        );
        assert_eq!(
            id_and_script("{pre.js}", None, &values),
            (
                "pre.js".to_string(),
                Some("window.onBeforeWhistleLogSend = f;".to_string())
            )
        );
        // A name nothing defines is still the id.
        assert_eq!(
            id_and_script("{nope}", None, &values),
            ("nope".to_string(), None)
        );
        // Not an id: the unnamed group.
        for value in ["", "a/b", "has space", &"x".repeat(37)] {
            assert_eq!(id_and_script(value, None, &values).0, "", "{value}");
        }

        let with_user = Injection {
            id: "pre.js".into(),
            user_script: Some("window.onBeforeWhistleLogSend = f;".into()),
            intercept_console: false,
        };
        let out = inject(
            &Bytes::from_static(b"<html><head></head></html>"),
            Some("text/html"),
            &with_user,
        )
        .unwrap();
        let out = String::from_utf8(out.to_vec()).unwrap();
        let collector = out.find("__whixLog").unwrap();
        let user = out.find("onBeforeWhistleLogSend = f").unwrap();
        assert!(
            collector < user,
            "the collector first, then the page author's script"
        );
        assert!(out.contains("var INTERCEPT = false;"));

        // An id cannot break out of the string or the element it is written in.
        let hostile = script("a'</script><script>alert(1)//", true);
        assert!(
            hostile.contains("var ID = 'a/scriptscriptalert(1)//';"),
            "{}",
            &hostile[..200]
        );
    }

    /// The ring is bounded by count and by bytes, numbers only grow, and one
    /// id's entries can be asked for or cleared on their own.
    #[test]
    fn what_is_kept_is_bounded_and_addressable() {
        let mut logs = PageLogs::default();
        let log = |id: &str, text: &str| PageLog {
            seq: 0,
            time_ms: 1,
            level: "log".into(),
            id: id.into(),
            args: vec![text.to_string()],
            page: "http://a/".into(),
            client_ip: None,
        };
        for i in 0..(MAX_ENTRIES + 10) {
            logs.push(log(if i % 2 == 0 { "even" } else { "odd" }, "x"));
        }
        assert_eq!(logs.entries.len(), MAX_ENTRIES);
        assert_eq!(logs.last(), (MAX_ENTRIES + 10) as u64);
        assert_eq!(logs.entries.front().unwrap().seq, 11, "the oldest ten went");
        assert_eq!(logs.ids(), ["even", "odd"]);
        assert_eq!(logs.after(logs.last() - 3, None).len(), 3);
        assert!(logs.after(0, Some("odd")).iter().all(|l| l.id == "odd"));
        assert_eq!(logs.clear(Some("odd")), MAX_ENTRIES / 2);
        assert_eq!(logs.ids(), ["even"]);
        // By bytes: a few very large entries push out everything before them.
        let big = "y".repeat(MAX_BYTES / 4);
        for _ in 0..6 {
            logs.push(log("big", &big));
        }
        assert!(logs.bytes <= MAX_BYTES, "{}", logs.bytes);
        assert!(logs.entries.len() <= 4 && logs.ids() == ["big"]);
        let held = logs.entries.len();
        assert_eq!(logs.clear(None), held);
        assert_eq!(logs.bytes, 0);
    }

    /// The collector itself, run in a JavaScript engine against a page that is
    /// nothing but the handful of things it touches. Not a browser — that is
    /// checked by hand, see `docs/STATUS.md` — but the same source, executing:
    /// what `console.warn` sends, what an uncaught error sends, what the
    /// documented hook may change, and what a second copy of the script does.
    #[test]
    fn the_collector_reports_console_calls_and_errors() {
        use boa_engine::{Context, Source};
        const PAGE: &str = r#"
            var window = this;
            var sent = [], timers = [], listeners = {}, native = [];
            var location = { href: 'http://shop.test/cart' };
            var navigator = { userAgent: 'TestPhone/1.0' };
            var console = {
                log: function () { native.push('log:' + arguments.length); },
                error: function () { native.push('error:' + arguments.length); }
            };
            function setTimeout(fn) { timers.push(fn); return timers.length; }
            function addEventListener(type, fn) { listeners[type] = fn; }
            function XMLHttpRequest() {}
            XMLHttpRequest.prototype.open = function (method, url) { this.to = method + ' ' + url; };
            XMLHttpRequest.prototype.setRequestHeader = function () {};
            XMLHttpRequest.prototype.send = function (body) {
                sent.push({ to: this.to, body: JSON.parse(body) });
                if (this.onloadend) { this.onloadend(); }
            };
            function run() { while (timers.length) { timers.shift()(); } }
        "#;
        /// Evaluate `src` and hand back its value as text.
        fn eval(ctx: &mut Context, src: &str) -> String {
            let value = ctx
                .eval(Source::from_bytes(src.as_bytes()))
                .unwrap_or_else(|e| panic!("{e}\n--- in ---\n{}", &src[..src.len().min(300)]));
            value.to_string(ctx).unwrap().to_std_string_escaped()
        }
        let mut ctx = Context::default();
        let ctx = &mut ctx;
        eval(ctx, PAGE);
        let collector = script("audit", true);
        eval(ctx, &collector);
        // A second copy — the page's HTML and one of its scripts both matched —
        // does nothing: `console` is wrapped once.
        eval(ctx, &collector);

        eval(
            ctx,
            r#"
            console.log('cart', { items: 2, self: null }, 7, undefined);
            var loop = { name: 'a' }; loop.me = loop;
            console.warn(loop);
            console.error(new Error('boom'));
            listeners.error({ message: 'x is not defined', filename: 'http://shop.test/a.js', lineno: 3, colno: 9 });
            listeners.unhandledrejection({ reason: { code: 42 } });
            run();
        "#,
        );
        let sent = eval(ctx, "JSON.stringify(sent)");
        let sent: serde_json::Value = serde_json::from_str(&sent).expect("what was posted");
        assert_eq!(sent.as_array().map(Vec::len), Some(1), "one batch: {sent}");
        assert_eq!(sent[0]["to"], format!("POST {PATH}"));
        assert_eq!(sent[0]["body"]["page"], "http://shop.test/cart");
        let list = sent[0]["body"]["list"].as_array().expect("list");
        let of = |i: usize| (list[i]["level"].as_str().unwrap(), list[i]["args"].clone());
        assert_eq!(list.len(), 5, "{list:?}");
        assert!(list.iter().all(|entry| entry["id"] == "audit"));
        // Strings as they were, everything else as JSON, `undefined` by name.
        assert_eq!(
            of(0),
            (
                "log",
                serde_json::json!(["cart", "{\"items\":2,\"self\":null}", "7", "undefined"])
            )
        );
        // A cycle is named, not followed.
        assert_eq!(
            of(1),
            (
                "warn",
                serde_json::json!(["{\"name\":\"a\",\"me\":\"[Circular]\"}"])
            )
        );
        // An Error is its stack (or its name and message where there is none).
        let (level, args) = of(2);
        assert_eq!(level, "error");
        assert!(args[0].as_str().unwrap().contains("boom"), "{args}");
        // An uncaught error: the message, where, and which page on what device.
        let (level, args) = of(3);
        let text = args[0].as_str().unwrap();
        assert_eq!(level, "error");
        assert!(
            text.starts_with("x is not defined\n    at http://shop.test/a.js:3:9"),
            "{text}"
        );
        assert!(
            text.contains("Page URL: http://shop.test/cart") && text.contains("TestPhone/1.0"),
            "{text}"
        );
        let (level, args) = of(4);
        assert_eq!(level, "error");
        assert_eq!(
            args[0].as_str().unwrap().lines().next(),
            Some("Unhandled promise rejection: {\"code\":42}")
        );
        // The page's own console still got every call, once each.
        assert_eq!(
            eval(ctx, "native.join()"),
            "log:4,error:1",
            "`warn` did not exist on this page's console and must not have been invented as a call"
        );

        // The documented hook: edit the arguments, or empty them to drop the entry.
        eval(
            ctx,
            r#"
            sent = [];
            window.onBeforeWhistleLogSend = function (result, level) {
                for (var i = 0; i < result.length; i++) {
                    if (typeof result[i] === 'string' && result[i].indexOf('password') !== -1) { result[i] = '[hidden]'; }
                }
                if (result[0] === 'ignore-this-message') { result.splice(0, result.length); }
            };
            console.log('password=hunter2', 'kept');
            console.log('ignore-this-message');
            run();
        "#,
        );
        let sent = eval(ctx, "JSON.stringify(sent[0].body.list)");
        let list: serde_json::Value = serde_json::from_str(&sent).unwrap();
        assert_eq!(list.as_array().map(Vec::len), Some(1), "{list}");
        assert_eq!(list[0]["args"], serde_json::json!(["[hidden]", "kept"]));
    }

    /// `disable://interceptConsole`: errors are still reported, and `console`
    /// is the page's own.
    #[test]
    fn without_console_interception_only_errors_are_reported() {
        use boa_engine::{Context, Source};
        let mut ctx = Context::default();
        let page = r#"
            var window = this, sent = [], timers = [], listeners = {};
            var location = { href: 'http://a.test/' }, navigator = { userAgent: 'UA' };
            var original = function () {};
            var console = { log: original };
            function setTimeout(fn) { timers.push(fn); return 1; }
            function addEventListener(type, fn) { listeners[type] = fn; }
            function XMLHttpRequest() {}
            XMLHttpRequest.prototype.open = function () {};
            XMLHttpRequest.prototype.setRequestHeader = function () {};
            XMLHttpRequest.prototype.send = function (body) { sent.push(JSON.parse(body)); };
        "#;
        ctx.eval(Source::from_bytes(page.as_bytes())).expect("page");
        ctx.eval(Source::from_bytes(script("q", false).as_bytes()))
            .expect("collector");
        let out = ctx
            .eval(Source::from_bytes(
                br#"
                console.log('not reported');
                listeners.error({ message: 'reported' });
                while (timers.length) { timers.shift()(); }
                JSON.stringify([console.log === original, sent.length, sent[0].list.length, sent[0].list[0].level])
            "#,
            ))
            .expect("runs");
        assert_eq!(
            out.to_string(&mut ctx).unwrap().to_std_string_escaped(),
            "[true,1,1,\"error\"]"
        );
    }
}
