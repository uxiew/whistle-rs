//! `@`-includes: a rules line that is **only** `@` and a source pulls that
//! source's rules text in where the line stands.
//!
//! ```text
//! example.com  host://10.0.0.1
//! @/etc/whistle/team.rules      # spliced in here
//! @https://intra/rules.txt      # …and here
//! ```
//!
//! Upstream resolves these for **every** rules text it parses — the console's
//! own included — and keeps each source fresh on a timer. The two halves live in
//! different files there: `REMOTE_RULES_RE` + `getRemoteRulesResolver`
//! (`_original/lib/util/index.js:3294-3308`) decide *which* lines are includes
//! and splice the cached text in, and `http-mgr` (`_original/lib/util/http-mgr.js`)
//! is the cache — a map of source to last-fetched body, a poll timer, and a
//! listener that re-parses the whole rule list when a body changes
//! (`lib/rules/util.js:61-111`).
//!
//! This port keeps the same split, minus the process-global state: [`Includes`]
//! is the cache and it is **owned by the [`RuleManager`](super::RuleManager)
//! whose text refers to it**. A rules text built for one request — what
//! `rulesFile://` and `rule://` produce — gets a manager with no include layer
//! at all, so its `@` lines stay literal. That is upstream's behaviour too, from
//! the other direction: `resolveRulesFile` calls `rulesFileMgr.parse(text)`
//! straight (`_original/lib/rules/index.js:519-537`) and the resolver never sees
//! it, so an `@` line inside a produced rules text is not an include there
//! either.
//!
//! # The shape of the update
//!
//! **A rules update never waits for the network.** Setting a text registers the
//! sources it names and returns; the `@` line contributes nothing until a fetch
//! has landed, at which point the groups that carry one are re-parsed. That is
//! upstream's shape exactly — `httpMgr.add` returns `data.body`, which is `''`
//! the first time it is asked, and starts the fetch that will later fire the
//! change listener (`http-mgr.js:421-437`).
//!
//! Two things drive the fetching:
//!
//! * [`load_pending`] — everything registered and never yet loaded, right now.
//!   Called once before the first connection is accepted, and again after every
//!   rules change, so a source named in the console lands in about the time the
//!   fetch takes rather than in the time the poll interval takes.
//! * [`poll`] — one source per tick, round-robin, forever. This is upstream's
//!   `addQueue`/`updateBody` pair (`http-mgr.js:332-415`) and it is what makes a
//!   team's rules file take effect without anyone restarting a proxy.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use super::RuleManager;

/// How long one include's fetch may take.
///
/// The same budget [`crate::proxy::apply`] gives a URL-valued operator, for the
/// same reason and out of the same upstream constant: `TIMEOUT = 16000` in
/// `_original/lib/util/http-mgr.js:14`, which is the timer `updateBody`'s own
/// request runs under. There it is an *idle* timer rearmed on every chunk; here
/// it is a deadline on the whole exchange, which can only be stricter.
const FETCH_TIMEOUT: Duration = Duration::from_secs(16);

/// The most one include may contribute.
///
/// Upstream has two ceilings for the same thing — `MAX_RULES_LEN` = 72 KB for a
/// URL and `MAX_FILE_LEN` = 256 KB for a file (`http-mgr.js:15-16`) — and
/// **truncates** at both: the URL fetch is made with `ignoreExceedError`, and
/// the file read simply stops mid-stream. A rules file cut off mid-line is a
/// rules file whose last rule means something else, so this port takes the
/// larger of the two numbers for both and *refuses* an oversized body instead of
/// half-applying it. 256 KB is also what [`crate::proxy::apply`] allows a
/// URL-valued operator, so the two limits a rules file can run into are one
/// number.
const MAX_INCLUDE: usize = 256 * 1024;

/// How many `@` lines one group's text may resolve
/// (`MAX_REMOTE_RULES_COUNT`, `_original/lib/util/index.js:3294`).
///
/// Upstream counts across every rules file in one parse, because the resolver
/// that holds the counter is built once per parse (`lib/rules/util.js:73`);
/// here each group is parsed on its own, so the budget is per group. The
/// difference is only reachable by a setup with more than twenty includes
/// spread over several groups, and in that direction this port resolves more of
/// them rather than fewer.
const MAX_INCLUDES: usize = 20;

/// The longest a source goes un-refetched, and the shortest gap between two
/// fetches — `MAX_INTERVAL` / `MIN_INTERVAL` (`http-mgr.js:17-18`).
///
/// Upstream spends the budget across the sources it has:
/// `max(MIN, ceil(MAX / n))` per tick, one source per tick, round-robin. With
/// three sources or fewer that is a full sweep every 30 s; past that the sweep
/// stretches rather than the request rate climbing.
const POLL_MAX: Duration = Duration::from_secs(30);
const POLL_MIN: Duration = Duration::from_secs(10);

/// A source on this machine is re-read four times as often — `isLocal` in
/// `getInterval` (`http-mgr.js:38-45`). Reading a file costs nothing anyone can
/// notice, and a rules file being edited beside the proxy is the case where the
/// wait is felt.
const POLL_LOCAL: Duration = Duration::from_secs(5);

/// How long the poller sleeps when the rules name no includes at all. It is not
/// an interval anything is waiting on — only how often a proxy with no includes
/// asks whether it has acquired one.
const POLL_IDLE: Duration = Duration::from_secs(5);

/// One include's cached text and how its last fetch went.
#[derive(Debug, Default)]
struct Entry {
    /// The text of the last **successful** fetch. Empty until one lands.
    body: String,
    /// Has a fetch ever succeeded? Distinguishes "not fetched yet" from
    /// "fetched, and the source really is empty" — which the body alone cannot,
    /// and which is the difference between an include that is about to work and
    /// one that is working.
    loaded: bool,
    /// Consecutive failures since the last success. Reported in the log, so
    /// that a source which has been unreachable for an hour says so rather than
    /// repeating one line that reads like a first attempt.
    failures: u32,
}

/// The `@` sources one rule set refers to, with the text each last yielded.
///
/// Default is the **inert** layer: `@` lines are ordinary text, nothing is
/// registered and nothing is fetched. [`Includes::resolving`] is what a
/// long-lived rule set — the one the console and the command line own — turns
/// on, and it is deliberately not the default, so that a rules text assembled
/// for a single request cannot register a source the proxy will then poll for
/// the rest of its life.
#[derive(Debug, Default)]
pub struct Includes {
    resolving: bool,
    entries: HashMap<String, Entry>,
    /// The port this proxy bound, for a `${port}` inside a backticked target.
    /// Zero until [`set_port`](Includes::set_port) is told, which is after the
    /// listening socket exists — there is no other moment it is known.
    port: u16,
}

impl Includes {
    /// An include layer that resolves — see the type's own note on why this is
    /// not what [`Default`] gives you.
    pub(super) fn resolving() -> Self {
        Includes {
            resolving: true,
            ..Default::default()
        }
    }

    /// Does this rule set resolve `@` lines at all?
    pub(super) fn resolves(&self) -> bool {
        self.resolving
    }

    /// Returns whether this changed anything, so the caller only re-parses when
    /// it did.
    pub(super) fn set_port(&mut self, port: u16) -> bool {
        let changed = self.resolving && self.port != port;
        self.port = port;
        changed
    }

    /// How many distinct sources are referred to right now.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every source referred to right now, in no particular order.
    pub(super) fn targets(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// The sources no fetch has ever succeeded for.
    pub(super) fn pending(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.loaded)
            .map(|(t, _)| t.clone())
            .collect()
    }

    /// Replace the set of sources referred to, keeping what is already loaded.
    ///
    /// A source that no longer appears in any enabled group's text is dropped,
    /// which is upstream's `newUrls` sweep: it rebuilds the cache from the
    /// sources the re-parse actually asked for and throws the rest away
    /// (`http-mgr.js:55-67`). Without it, deleting an `@` line would leave the
    /// proxy fetching that URL every 30 seconds until it was restarted.
    pub(super) fn set_referenced(&mut self, targets: &[String]) {
        if !self.resolving {
            return;
        }
        self.entries.retain(|k, _| targets.iter().any(|t| t == k));
        for target in targets {
            self.entries.entry(target.clone()).or_default();
        }
    }

    /// Record the outcome of one fetch. Returns whether the text changed, which
    /// is the only reason to re-parse anything (upstream asks the same question
    /// before firing its listeners, `http-mgr.js:47-54`).
    ///
    /// **A failed fetch keeps the last good text.** Upstream keeps it too, but
    /// only for three consecutive failures — after that, or immediately on a
    /// redirect, it applies `''` and the rules that source carried disappear
    /// (`updateBody`, `http-mgr.js:377-401`). That is the wrong way to fail for
    /// a debugging proxy: a blip on the intranet should not silently delete a
    /// team's rules from a running session, and the state it leaves — rules
    /// gone, no rule visibly changed — is indistinguishable from the include
    /// never having worked. So the text stands until a fetch replaces it, and
    /// every failure is logged. An include that has *never* loaded contributes
    /// nothing, which is upstream's initial state as well.
    pub(super) fn record(&mut self, target: &str, body: Option<String>) -> bool {
        let Some(entry) = self.entries.get_mut(target) else {
            return false;
        };
        match body {
            Some(body) => {
                entry.failures = 0;
                let changed = !entry.loaded || entry.body != body;
                entry.loaded = true;
                entry.body = body;
                changed
            }
            None => {
                entry.failures += 1;
                // The fetch has already said *what* went wrong; this says what
                // it cost. A source that has never loaded is contributing
                // nothing and the streak is not news; one that has is holding
                // rules the proxy is still applying, which is worth saying out
                // loud every time it fails to confirm them.
                if entry.loaded {
                    tracing::warn!(
                        "include @{target}: keeping the last text it gave ({} failures in a row)",
                        entry.failures
                    );
                }
                false
            }
        }
    }

    /// Splice every include of `text` in where its line stands, lifting any
    /// value the included text declares into `values`.
    ///
    /// The included text's own ``` blocks lose to the including text's, which is
    /// upstream's order rather than a preference: `handleInlineValues` runs over
    /// the outer text *before* `resolveRemoteRules` runs at all
    /// (`lib/rules/util.js:85`), and `resolveInlineValues` only fills a name that
    /// is not already there (`util/index.js:218`). Running the outer lift first
    /// is also what stops an `@` line **inside** a fenced block from being an
    /// include: by the time this sees the text, that line is the content of a
    /// value and no longer a line.
    ///
    /// An `@` line inside an *included* text is not followed. `String.replace`
    /// never re-scans what it substituted, so upstream is one level deep and
    /// cannot cycle; this walks the outer text once, for the same result.
    pub(super) fn expand(&self, text: &str, values: &mut HashMap<String, String>) -> String {
        if !self.resolving || !text.contains('@') {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut resolved = 0usize;
        for (i, line) in text.lines().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            let Some(target) = include_target(line) else {
                out.push_str(line);
                continue;
            };
            // Past the ceiling the line is dropped rather than kept as text —
            // upstream returns `''` for it (`util/index.js:3301-3303`).
            if resolved >= MAX_INCLUDES {
                continue;
            }
            resolved += 1;
            let Some(entry) = self.entries.get(&self.source_of(target)) else {
                continue;
            };
            let (body, inline) = super::lift_inline_values(&entry.body);
            for (name, value) in inline {
                values.entry(name).or_insert(value);
            }
            out.push_str(body.trim_end_matches(['\n', '\r']));
        }
        out
    }

    /// What a target written on a rule line finally names — the string this
    /// layer registers, fetches and looks up by.
    ///
    /// The only thing between the two is `${port}` / `${version}`, which
    /// upstream answers for a backticked target and nowhere else
    /// (`CONFIG_VAR_RE`'s one reader is `getRemoteRules`,
    /// `_original/lib/util/index.js:3283-3285`); this port answers it for both
    /// spellings, the same widening `substitute_config_vars` already declares
    /// for operator values. An unbound port is left as written so a failure
    /// names the variable rather than fetching port 0.
    pub(super) fn source_of(&self, target: &str) -> String {
        if !target.contains("${") {
            return target.to_string();
        }
        let mut out = target.to_string();
        if self.port != 0 {
            out = replace_ci(&out, "${port}", &self.port.to_string());
        }
        replace_ci(&out, "${version}", crate::config::VERSION)
    }
}

/// Case-insensitive replace-all of `needle`; the replacement goes in verbatim.
fn replace_ci(haystack: &str, needle: &str, repl: &str) -> String {
    let (hay, need) = (haystack.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0;
    while let Some(at) = hay[last..].find(&need) {
        let at = last + at;
        out.push_str(&haystack[last..at]);
        out.push_str(repl);
        last = at + need.len();
    }
    out.push_str(&haystack[last..]);
    out
}

/// The source an `@` line names, or `None` when the line is not an include.
///
/// Hand-written rather than a `Regex` because upstream's `REMOTE_RULES_RE`
/// (`_original/lib/util/index.js:3295`) pairs an optional backtick with a
/// backreference, which the `regex` crate does not have. Every shape it accepts
/// and every shape it does not is pinned by the tests below; the ones worth
/// naming here are the near misses:
///
/// * a **relative** path is not an include (`@team.rules`, `@./team.rules`) —
///   the alternatives all demand `/`, `~/`, a drive letter, `http(s)://`, a
///   `whistle.` plugin name or a `$` key;
/// * a line with a pattern in front of it is not an include
///   (`example.com @/tmp/rules`) — that is the `G://` global-value operator;
/// * a space after the `@` is not an include (`@ /tmp/rules`);
/// * anything after the source other than a `#` comment is not an include
///   (`@/tmp/rules extra`).
pub fn include_target(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('@')?;
    let (rest, quoted) = match rest.strip_prefix('`') {
        Some(inner) => (inner, true),
        None => (rest, false),
    };
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '#')
        .unwrap_or(rest.len());
    let (mut target, mut tail) = rest.split_at(end);
    if quoted {
        // `[^\s#]+` swallows the closing backtick and the greedy match then
        // gives it back, so the run of non-space characters is where it is —
        // unless upstream's `\s*?` put whitespace in front of it.
        match target.rfind('`') {
            Some(at) => (target, tail) = (&rest[..at], &rest[at + 1..]),
            None => tail = tail.trim_start().strip_prefix('`')?,
        }
    }
    let tail = tail.trim_start();
    if !tail.is_empty() && !tail.starts_with('#') {
        return None;
    }
    is_source(target).then_some(target)
}

/// Every source one rules text names.
///
/// The ``` blocks come out first, for the reason [`Includes::expand`] takes
/// them out first: an `@` line inside a fence is the content of a value and
/// must not be fetched, registered or polled.
pub(super) fn targets_in(text: &str) -> Vec<String> {
    if !text.contains('@') {
        return Vec::new();
    }
    let (body, _) = super::lift_inline_values(text);
    body.lines()
        .filter_map(include_target)
        .map(str::to_string)
        .collect()
}

/// Whether `target` is one of the four source shapes upstream's regexp accepts.
fn is_source(target: &str) -> bool {
    // `whistle.<plugin>` or `whistle.<plugin>/<path>` — a plugin serving rules.
    if let Some(rest) = strip_prefix_ci(target, "whistle.") {
        let name = plugin_name_len(rest);
        return name > 0 && matches!(rest.as_bytes().get(name), None | Some(b'/'));
    }
    // `$<key>/…`, `$<key>:…`, `$whistle.<plugin>/…` — a plugin's key/value store.
    if let Some(rest) = target.strip_prefix('$') {
        let rest = strip_prefix_ci(rest, "whistle.").unwrap_or(rest);
        let name = plugin_name_len(rest);
        return name > 0
            && matches!(rest.as_bytes().get(name), Some(b'/' | b':'))
            && rest.len() > name + 1;
    }
    for scheme in ["http://", "https://"] {
        if let Some(rest) = strip_prefix_ci(target, scheme) {
            return !rest.is_empty();
        }
    }
    if let Some(rest) = target.strip_prefix("~/") {
        return !rest.is_empty();
    }
    if let Some(rest) = target.strip_prefix('/') {
        return !rest.is_empty();
    }
    // `c:\x` / `c:/x`, and at least one character of path after the slash.
    let bytes = target.as_bytes();
    bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

/// How many leading bytes of `s` spell a plugin name (`[a-z\d_-]+`, and the
/// regexp's `i` flag makes it case-insensitive).
fn plugin_name_len(s: &str) -> usize {
    s.bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        .count()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|head| &s[head.len()..])
}

/// Is this source on this machine? Decides only how often it is re-read —
/// `isLocalUrl || isLocalPath` (`http-mgr.js:427-428`).
fn is_local(target: &str) -> bool {
    !is_url(target) || target.starts_with("http://127.0.0.1:")
}

fn is_url(target: &str) -> bool {
    strip_prefix_ci(target, "http://").is_some() || strip_prefix_ci(target, "https://").is_some()
}

/// How long to wait before refreshing the next source — `getInterval`
/// (`_original/lib/util/http-mgr.js:38-45`), minus the correction for how long
/// the previous fetch took, which this port does not need: upstream measures a
/// fetch to keep its *sweep* period honest, and the sweep here is the same
/// round-robin without the arithmetic.
fn poll_interval(sources: usize, local: bool) -> Duration {
    if local {
        return POLL_LOCAL;
    }
    POLL_MIN.max(POLL_MAX / sources.max(1) as u32)
}

/// Read one source. `None` is a failure of any kind, all of them logged.
async fn fetch(target: &str) -> Option<String> {
    if is_url(target) {
        return fetch_url(target).await;
    }
    if target.starts_with("whistle.") || target.starts_with('$') {
        // Upstream routes both to a plugin's own UI server (`getRemoteRules`,
        // `_original/lib/util/index.js:3274-3282`). Plugins here are external
        // HTTP servers speaking this port's protocol and have no such endpoint.
        tracing::warn!("include @{target}: rules served by a plugin are not supported");
        return None;
    }
    fetch_file(target).await
}

async fn fetch_url(url: &str) -> Option<String> {
    let fetch = crate::proxy::upstream::simple_get(url);
    match tokio::time::timeout(FETCH_TIMEOUT, fetch).await {
        Ok(Ok((status, body))) => url_answer(url, status, &body),
        Ok(Err(err)) => {
            tracing::warn!("include @{url}: {err}");
            None
        }
        Err(_) => {
            tracing::warn!("include @{url}: timed out");
            None
        }
    }
}

/// What a rules server's answer amounts to. Split out from the fetch because
/// the two edges of it — an empty answer that *is* an answer, and a body too
/// large to be one — are worth a test that needs no server.
fn url_answer(url: &str, status: u16, body: &[u8]) -> Option<String> {
    match status {
        // 204 is a source that is deliberately empty, and upstream applies it
        // as one: `code != 200 && code != 204` is what counts as not found
        // (`_original/lib/util/http-mgr.js:379-381`). Not a failure, and it must
        // not be treated as one, or an include could never be emptied on
        // purpose.
        204 => Some(String::new()),
        200 if body.len() <= MAX_INCLUDE => Some(String::from_utf8_lossy(body).into_owned()),
        200 => {
            tracing::warn!("include @{url}: {} bytes exceeds the limit", body.len());
            None
        }
        status => {
            tracing::warn!("include @{url}: responded {status}");
            None
        }
    }
}

async fn fetch_file(target: &str) -> Option<String> {
    let path = local_path(target);
    match tokio::fs::read(&path).await {
        Ok(body) if body.len() <= MAX_INCLUDE => Some(String::from_utf8_lossy(&body).into_owned()),
        Ok(body) => {
            tracing::warn!("include @{target}: {} bytes exceeds the limit", body.len());
            None
        }
        Err(err) => {
            tracing::warn!("include @{target}: {err}");
            None
        }
    }
}

/// Where a non-URL source lives. Only absolute forms get here — a relative path
/// is not an include at all, so there is no base directory to resolve against.
///
/// An include may name a **drive letter** — `is_source` admits `[a-z]:[\\/]`
/// because upstream's `REMOTE_RULES_RE` does — and upstream reads it through
/// `fileMgr.convertSlash` (`http-mgr.js:274`), the same conversion a `file://`
/// value gets. So `@D:\team\rules.txt` written on Windows names
/// `D:/team/rules.txt` when the file travels to a Mac, which is where it will
/// not be found either; what matters is that it is looked for in the same place
/// both proxies look.
fn local_path(target: &str) -> PathBuf {
    let target = match target.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest)
            .to_string_lossy()
            .into_owned(),
        None => target.to_string(),
    };
    PathBuf::from(crate::proxy::apply::convert_slash(&target))
}

/// Fetch every source that has never loaded, and re-parse if any landed.
///
/// Returns how many sources this call brought in — a number worth logging at
/// startup, because an include that never happened and an include of an empty
/// file are otherwise the same silence.
///
/// The rules lock is taken three times and held across no `await`: the targets
/// are read, the fetches happen with nothing locked, and the results are
/// applied. A console save must never be waiting on someone's intranet.
pub async fn load_pending(rules: &RwLock<RuleManager>) -> usize {
    let pending = {
        let mgr = rules.read().unwrap();
        mgr.includes().pending()
    };
    let mut landed = 0;
    for target in pending {
        let body = fetch(&target).await;
        let ok = body.is_some();
        let changed = rules.write().unwrap().record_include(&target, body);
        if ok {
            landed += 1;
            if changed {
                tracing::info!("included rules from @{target}");
            }
        }
    }
    landed
}

/// Re-read one source per tick, round-robin, forever.
///
/// Upstream's `addQueue` (`_original/lib/util/http-mgr.js:332-351`) with its
/// queue and its single timer. A source that stopped being referenced while it
/// sat in the queue is skipped, since [`Includes::record`] only writes to an
/// entry that is still there.
pub async fn poll(rules: &RwLock<RuleManager>) {
    let mut queue: Vec<String> = Vec::new();
    loop {
        if queue.is_empty() {
            queue = rules.read().unwrap().includes().targets();
        }
        let Some(target) = queue.pop() else {
            tokio::time::sleep(POLL_IDLE).await;
            continue;
        };
        let sources = rules.read().unwrap().includes().len();
        tokio::time::sleep(poll_interval(sources, is_local(&target))).await;
        let body = fetch(&target).await;
        if rules.write().unwrap().record_include(&target, body) {
            tracing::info!("include @{target} changed, rules re-parsed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manager that resolves includes, with one loaded source.
    fn manager_with(text: &str, source: &str, body: &str) -> RuleManager {
        let mut mgr = RuleManager::with_includes();
        mgr.set_text(text);
        mgr.record_include(source, Some(body.to_string()));
        mgr
    }

    fn req(url: &str) -> crate::rules::ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        crate::rules::ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host: host.into(),
            port: if scheme == "https" { 443 } else { 80 },
            path,
            full_url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_line_that_is_only_an_at_and_a_source_is_an_include() {
        for line in [
            "@/etc/whistle/team.rules",
            "@~/team.rules",
            "@http://intra/rules.txt",
            "@https://intra/rules.txt",
            "@HTTP://INTRA/rules.txt",
            "@c:/whistle/team.rules",
            "@C:\\whistle\\team.rules",
            "@//host/share/team.rules",
            "@whistle.plugin",
            "@whistle.plugin/rules",
            "@$key/name",
            "@$key:name",
            "@$whistle.plugin/name",
            "  @/etc/team.rules",
            "@/etc/team.rules   ",
            "@/etc/team.rules # the team's",
            "@/etc/team.rules#the-team's",
        ] {
            assert!(
                include_target(line).is_some(),
                "should be an include: {line}"
            );
        }
    }

    /// The shapes that look like an include and are not. Each of these is a line
    /// someone will write, and each has to keep behaving as whatever it already
    /// is rather than quietly fetching something.
    #[test]
    fn the_near_misses_are_not_includes() {
        for line in [
            "@team.rules",                  // relative
            "@./team.rules",                // relative
            "@team/rules.txt",              // relative
            "@ /etc/team.rules",            // a space after the @
            "example.com @/etc/team.rules", // the G:// operator
            "@/etc/team.rules extra",       // trailing text
            "@/etc/team rules",             // a space inside the source
            "@ftp://intra/rules.txt",       // not a scheme upstream reads
            "@",
            "@/",
            "@@/etc/team.rules",
            "@whistle.plugin.extra",
            "@$key",
            "@$key/",
        ] {
            assert!(
                include_target(line).is_none(),
                "should not be an include: {line}"
            );
        }
    }

    #[test]
    fn a_backticked_source_loses_its_backticks() {
        assert_eq!(
            include_target("@`/etc/team.rules`"),
            Some("/etc/team.rules")
        );
        assert_eq!(
            include_target("@`/etc/team.rules` # note"),
            Some("/etc/team.rules")
        );
        assert_eq!(
            include_target("@`/etc/team.rules `"),
            Some("/etc/team.rules")
        );
        assert_eq!(include_target("@`/etc/team.rules"), None);
    }

    #[test]
    fn a_backticked_source_answers_port_and_version() {
        let mut inc = Includes::resolving();
        assert!(inc.set_port(8899));
        assert_eq!(
            inc.source_of("http://127.0.0.1:${port}/r"),
            "http://127.0.0.1:8899/r"
        );
        assert_eq!(
            inc.source_of("http://x/${VERSION}"),
            format!("http://x/{}", crate::config::VERSION)
        );
        // An unbound port is left as written: a fetch of port 0 would fail in a
        // way that names nothing.
        let unbound = Includes::resolving();
        assert_eq!(
            unbound.source_of("http://127.0.0.1:${port}/r"),
            "http://127.0.0.1:${port}/r"
        );
    }

    #[test]
    fn an_include_splices_where_the_line_stands() {
        let mgr = manager_with(
            "a.com resBody://(first)\n@/t/inc.rules\nc.com resBody://(third)\n",
            "/t/inc.rules",
            "b.com resBody://(second)\n",
        );
        let patterns: Vec<&str> = mgr.groups()[0]
            .rules
            .iter()
            .map(|r| r.raw_pattern.as_str())
            .collect();
        assert_eq!(patterns, ["a.com", "b.com", "c.com"]);
    }

    /// The include is text where the line was, so the ordering that decides
    /// which rule wins is the ordering of the file it was spliced into — and
    /// `lineProps://important` on a line inside it outranks a plain line above,
    /// exactly as it would if the line had been typed there.
    #[test]
    fn an_important_line_inside_an_include_still_outranks_one_above_it() {
        let mgr = manager_with(
            "example.com host://10.0.0.1\n@/t/inc.rules\n",
            "/t/inc.rules",
            "example.com host://10.0.0.2 lineProps://important\n",
        );
        assert_eq!(
            mgr.resolve(&req("http://example.com/")).value("host"),
            Some("10.0.0.2")
        );
    }

    #[test]
    fn an_include_that_has_not_loaded_yet_contributes_nothing() {
        let mut mgr = RuleManager::with_includes();
        mgr.set_text("a.com resBody://(x)\n@/t/inc.rules\n");
        assert_eq!(mgr.len(), 1);
        // …and the line is not left behind as a rule of its own.
        assert_eq!(mgr.groups()[0].rules[0].raw_pattern, "a.com");
    }

    #[test]
    fn an_include_that_fails_to_fetch_keeps_the_last_good_text() {
        let mut mgr = manager_with("@/t/inc.rules\n", "/t/inc.rules", "b.com host://10.0.0.2\n");
        assert_eq!(mgr.len(), 1);
        // Three failures — one more than upstream tolerates before it blanks
        // the source — and the rules that came from it are still there.
        for _ in 0..3 {
            assert!(!mgr.record_include("/t/inc.rules", None));
        }
        assert_eq!(mgr.len(), 1);
        assert_eq!(
            mgr.resolve(&req("http://b.com/")).value("host"),
            Some("10.0.0.2")
        );
    }

    /// A source answering 204 *is* empty, and emptying it is something a rules
    /// server is allowed to do. Distinguished from a failure at the fetch, so
    /// this is the layer that has to honour the distinction.
    #[test]
    fn a_source_that_becomes_empty_empties_the_rules_it_brought() {
        let mut mgr = manager_with("@/t/inc.rules\n", "/t/inc.rules", "b.com host://10.0.0.2\n");
        assert_eq!(mgr.len(), 1);
        assert!(mgr.record_include("/t/inc.rules", Some(String::new())));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn an_at_line_inside_an_included_text_is_not_followed() {
        let mgr = manager_with(
            "@/t/inc.rules\n",
            "/t/inc.rules",
            "b.com host://10.0.0.2\n@/t/other.rules\n",
        );
        // The nested line is neither followed nor registered — one level, and so
        // no cycle to guard against.
        assert!(
            !mgr.includes()
                .targets()
                .iter()
                .any(|t| t == "/t/other.rules")
        );
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn an_at_line_inside_a_fenced_value_is_not_an_include() {
        let mut mgr = RuleManager::with_includes();
        mgr.set_text("```v\n@/t/inc.rules\n```\na.com resBody://{v}\n");
        assert!(mgr.includes().targets().is_empty());
        // Keyed to the group that declared it — see `RuleManager::inline_values`.
        let key = crate::rules::inline_key("v", "default");
        assert_eq!(
            mgr.inline_values().get(&key).map(String::as_str),
            Some("@/t/inc.rules")
        );
    }

    #[test]
    fn an_include_declaring_a_value_loses_to_the_including_text() {
        let mgr = manager_with(
            "```v\nOUTER\n```\n@/t/inc.rules\n",
            "/t/inc.rules",
            "```v\nINNER\n```\n```w\nONLY-INNER\n```\na.com resBody://{v}\n",
        );
        let key = |name| crate::rules::inline_key(name, "default");
        assert_eq!(
            mgr.inline_values().get(&key("v")).map(String::as_str),
            Some("OUTER")
        );
        assert_eq!(
            mgr.inline_values().get(&key("w")).map(String::as_str),
            Some("ONLY-INNER")
        );
    }

    #[test]
    fn only_twenty_includes_are_resolved() {
        let mut text = String::new();
        for i in 0..25 {
            text.push_str(&format!("@/t/inc{i}.rules\n"));
        }
        let mut mgr = RuleManager::with_includes();
        mgr.set_text(&text);
        for i in 0..25 {
            mgr.record_include(
                &format!("/t/inc{i}.rules"),
                Some(format!("h{i}.com host://10.0.0.1\n")),
            );
        }
        assert_eq!(mgr.len(), MAX_INCLUDES);
    }

    /// A rules text built for one request — `rulesFile://`, `rule://` — has no
    /// include layer, so its `@` lines are text. Upstream is the same: the
    /// resolver is only applied to the rule list, never to a produced text
    /// (`_original/lib/rules/index.js:519-537`).
    #[test]
    fn a_transient_rule_set_keeps_its_at_lines() {
        let mut mgr = RuleManager::new();
        mgr.set_text("a.com resBody://(x)\n@/t/inc.rules\n");
        assert!(!mgr.includes().resolves());
        assert!(mgr.includes().targets().is_empty());
        // The source is not registered, so nothing can be recorded against it
        // and nothing is ever spliced in: the line stays the text it is, which
        // parses to no rule of its own — a pattern with no operator never does.
        assert!(!mgr.record_include("/t/inc.rules", Some("b.com host://10.0.0.2\n".into())));
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.groups()[0].text, "a.com resBody://(x)\n@/t/inc.rules\n");
    }

    #[test]
    fn dropping_the_last_reference_forgets_the_include() {
        let mut mgr = manager_with("@/t/inc.rules\n", "/t/inc.rules", "b.com host://10.0.0.2\n");
        assert_eq!(mgr.includes().len(), 1);
        mgr.set_text("a.com resBody://(x)\n");
        assert!(mgr.includes().targets().is_empty());
        assert_eq!(mgr.len(), 1);
    }

    /// Upstream only registers the sources of the rules files it is about to
    /// parse, and an unselected file is not one of them
    /// (`_original/lib/rules/util.js:94-100`). So switching a group off stops
    /// its includes being fetched, and switching it back on starts them again.
    #[test]
    fn a_disabled_group_registers_no_includes() {
        let mut mgr = RuleManager::with_includes();
        mgr.add_group("staging", "@/t/inc.rules\n", true);
        assert_eq!(mgr.includes().len(), 1);
        mgr.toggle_group("staging");
        assert!(mgr.includes().targets().is_empty());
        mgr.toggle_group("staging");
        assert_eq!(mgr.includes().len(), 1);
    }

    #[test]
    fn a_named_group_resolves_its_own_includes() {
        let mut mgr = RuleManager::with_includes();
        mgr.set_text("a.com resBody://(x)\n");
        mgr.add_group("staging", "@/t/inc.rules\n", true);
        mgr.record_include("/t/inc.rules", Some("b.com host://10.0.0.2\n".into()));
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn the_poll_interval_spends_upstreams_budget() {
        // One source: the whole 30 s window. Three: 10 s each, still a 30 s
        // sweep. Ten: the floor holds and the sweep stretches instead.
        assert_eq!(poll_interval(1, false), Duration::from_secs(30));
        assert_eq!(poll_interval(3, false), Duration::from_secs(10));
        assert_eq!(poll_interval(10, false), Duration::from_secs(10));
        assert_eq!(poll_interval(0, false), Duration::from_secs(30));
        assert_eq!(poll_interval(1, true), Duration::from_secs(5));
    }

    #[test]
    fn a_file_source_is_local_and_a_url_is_not() {
        assert!(is_local("/etc/team.rules"));
        assert!(is_local("~/team.rules"));
        assert!(is_local("http://127.0.0.1:8899/rules"));
        assert!(!is_local("http://intra/rules.txt"));
        assert!(!is_local("https://intra/rules.txt"));
    }

    /// The whole point of the change, end to end: a rules text set at runtime
    /// names a file, the update returns without waiting, and the include lands
    /// on the next pass.
    #[tokio::test]
    async fn a_rules_text_set_at_runtime_pulls_its_include_in() {
        let dir = std::env::temp_dir().join("whistle-rs-test-include-runtime");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("team.rules");
        std::fs::write(&file, "b.com host://10.0.0.2\n").unwrap();

        let rules = RwLock::new(RuleManager::with_includes());
        rules
            .write()
            .unwrap()
            .set_text(&format!("a.com resBody://(x)\n@{}\n", file.display()));
        // The update itself did not wait for the file.
        assert_eq!(rules.read().unwrap().len(), 1);

        assert_eq!(load_pending(&rules).await, 1);
        assert_eq!(rules.read().unwrap().len(), 2);
        // Nothing is pending any more, so a second pass fetches nothing.
        assert_eq!(load_pending(&rules).await, 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rules server's answer, by status. The two that are not "read the
    /// body" are the ones worth pinning: `204` means the source really is
    /// empty, and a body past the ceiling is refused rather than truncated —
    /// a rules file cut off mid-line is a rules file whose last rule means
    /// something else.
    #[test]
    fn a_rules_server_answers_with_a_status_as_well_as_a_body() {
        assert_eq!(
            url_answer("u", 200, b"a.com host://1.1.1.1\n").as_deref(),
            Some("a.com host://1.1.1.1\n")
        );
        assert_eq!(url_answer("u", 204, b"").as_deref(), Some(""));
        // Upstream reads 204 as empty whatever body came with it.
        assert_eq!(url_answer("u", 204, b"ignored").as_deref(), Some(""));
        assert_eq!(url_answer("u", 404, b"nope"), None);
        assert_eq!(url_answer("u", 302, b""), None);
        assert_eq!(url_answer("u", 500, b""), None);
        assert!(url_answer("u", 200, &vec![b'x'; MAX_INCLUDE]).is_some());
        assert_eq!(url_answer("u", 200, &vec![b'x'; MAX_INCLUDE + 1]), None);
    }

    #[tokio::test]
    async fn an_include_larger_than_the_ceiling_is_refused_rather_than_truncated() {
        let dir = std::env::temp_dir().join("whistle-rs-test-include-oversized");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("huge.rules");
        let line = "a.com host://10.0.0.2\n";
        std::fs::write(&file, line.repeat(MAX_INCLUDE / line.len() + 1)).unwrap();

        assert_eq!(fetch_file(file.to_str().unwrap()).await, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_include_of_a_file_that_is_not_there_leaves_the_rules_alone() {
        let missing = std::env::temp_dir().join("whistle-rs-test-include-absent.rules");
        std::fs::remove_file(&missing).ok();

        let rules = RwLock::new(RuleManager::with_includes());
        rules
            .write()
            .unwrap()
            .set_text(&format!("a.com resBody://(x)\n@{}\n", missing.display()));
        assert_eq!(load_pending(&rules).await, 0);
        // The rule that was written by hand survives; the include contributes
        // nothing and says so in the log.
        assert_eq!(rules.read().unwrap().len(), 1);
    }
}
