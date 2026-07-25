//! The `tpl://` / `dust://` / `jsonp://` template engine.
//!
//! Despite the name, whistle's `dust://` is **not** dust.js, and `jsonp://` has
//! no JSONP-specific code at all: `_original/lib/handlers/file-proxy.js:14`
//! treats all three as one protocol (`TPL_RE = /(?:dust|tpl|jsonp):$/`) and
//! renders them through the same ~20-line `render()` function at
//! `file-proxy.js:358`. There are no sections, no loops, no partials and no
//! conditionals anywhere in it — just two ordered regex passes over the file:
//!
//! 1. **Query interpolation** (`file-proxy.js:16,364`) — `{name}` and
//!    `{{name}}` are replaced by the request's query-string parameters. A
//!    leading `$` escapes the placeholder, and an *unknown* name is left in the
//!    output verbatim rather than blanked.
//! 2. **Built-in variables** (`_original/lib/rules/rules.js:715` `resolveTplVar`)
//!    — `${name}`, `${name.key}`, `${{name}}` (URI-encoded) and `$${name}` (raw,
//!    undecoded) are resolved against a *fixed whitelist* of request facts.
//!    Names outside the whitelist are left untouched. A resolved value can be
//!    post-processed by a `.replace(pattern,replacement)` modifier
//!    (`rules.js:725-752`).
//!
//! Both passes only run when the body contains something shaped like `{...}`
//! (`VAR_RE = /\{\S+\}/`, `file-proxy.js:15,360`), so a template with no
//! placeholders is returned byte-for-byte.
//!
//! JSONP is therefore expressed *in the template*, not by the protocol —
//! `_original/docs/docs/rules/tpl.md:20` mocks it with a file containing
//! `{callback}({ec: 0})` and a request of `?callback=test`.
//!
//! See `docs/TEMPLATES.md` for the user-facing reference, including the
//! variables whistle-rs cannot yet resolve.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use regex::{Captures, Regex};

use crate::rules::ReqInfo;

/// Gate matching whistle's `VAR_RE`: skip both passes unless the body holds a
/// `{...}` with no whitespace inside.
static HAS_PLACEHOLDER: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{\S+\}").unwrap());

/// Pass 1, whistle's `QUERY_VAR_RE`: `{{name}}` or `{name}`, where the name is
/// restricted to word characters, `$` and `-`.
///
/// Upstream spells this `\$?(?:\{\{…\}\}|\{…\})`, folding in the `$` that
/// suppresses substitution. We cannot: the `regex` crate resolves the
/// alternation differently once any branch can start with `$` — against
/// `{{b}}` every such form matches the inner `{b}`, leaving stray braces
/// (verified for `\$?(?:A|B)`, `\$?A|\$?B` and `\$A|\$B|A|B` alike, while the
/// bare `A|B` below is correct). So the `$` is matched by looking at the byte
/// before the placeholder instead, which yields identical output: the `$` is
/// simply never part of the match.
static QUERY_VAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\{\{([\w$-]+)\}\}|\{([\w$-]+)\}").unwrap());

/// Pass 2, whistle's `TPL_VAR_RE`. Group 1 is the raw-mode `$` of `$${...}`,
/// group 2 the URI-encoding `{` of `${{...}}`, group 3 the whitelisted name,
/// group 4 the optional `.key` suffix, group 5 the closing `}` of `${{...}}`.
///
/// Alternatives are ordered longest-first so the intent stays readable; the
/// name list is copied from `rules.js:78`.
static TPL_VAR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)(\$)?\$\{(\{)?(",
        r"randomUUID|randomInt\(\d{1,15}(?:-\d{1,15})?\)|random",
        r"|reqId|id|whistle|env|now|version|hostname",
        r"|realPort|realHost|realUrl|host|port",
        r"|queryString|searchString|query|search|pathname|path|url",
        r"|localClientId|clientId|clientIp|clientPort|ip",
        r"|remoteAddress|remotePort|serverIp|serverPort",
        r"|method|statusCode",
        r"|reqCookies?|resCookies?|re[qs]H(?:eaders?)?",
        r")(?:\.([^{}]+))?\}(\})?",
    ))
    .unwrap()
});

/// whistle's `REPLACE_PATTERN_RE` (`rules.js:81`): a `.replace(...)` suffix on a
/// variable key, e.g. `${url.replace(/a/g,b)}`. The suffix is a modifier on the
/// resolved *value*, not part of the key.
static REPLACE_SUFFIX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(^|\.)replace\((.+)\)$").unwrap());

/// whistle's `ORIG_REG_EXP` (`_original/lib/util/index.js:610`): the `/…/flags`
/// spelling that turns a replace pattern into a real regular expression.
static JS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^/(.+)/([igmu]{0,4})$").unwrap());

/// whistle's `SUB_MATCH_RE` (`rules.js:16`): does a replacement reference the
/// match at all? Only then does whistle use its own expander instead of
/// JavaScript's native one (`rules.js:746-751`).
static HAS_SUB_MATCH: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$[&\d]").unwrap());

/// whistle's back-reference token (`replace-pattern-transform.js:6`), minus its
/// `^` alternative: `(^|\\{0,2})` and `(\\{0,2})` accept the same text at every
/// position, because the backslash run may be empty.
static SUB_MATCH: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\\{0,2})(\$\$?(b)?[&\d])").unwrap());

/// Render a template body against the current request.
///
/// Never fails: anything unrecognised is passed through unchanged, matching
/// whistle's own graceful degradation.
pub fn render(body: &str, info: &ReqInfo, env: ProxyEnv<'_>) -> String {
    if !HAS_PLACEHOLDER.is_match(body) {
        return body.to_string();
    }
    let query = Query::parse(query_of(&info.full_url));
    let stage1 = interpolate_query(body, &query);
    interpolate_vars(&stage1, info, &query, env)
}

/// The handful of `${…}` variables that describe **whistle itself** rather than
/// the request: `${host}`, `${port}`, `${realHost}`, `${realPort}` and
/// `${version}` all read whistle's own config upstream
/// (`resolveVarValue`, `_original/lib/rules/rules.js:657-668`) — `${host}` is
/// the proxy's bind address, *not* the request's Host header.
#[derive(Clone, Copy)]
pub struct ProxyEnv<'a> {
    /// The proxy's bind address; empty when bound to all interfaces, matching
    /// upstream's `config.host || ''`.
    pub host: &'a str,
    pub port: u16,
    pub version: &'a str,
}

/// The query string of a full URL, without the leading `?`.
fn query_of(full_url: &str) -> &str {
    match full_url.split_once('?') {
        Some((_, q)) => q,
        None => "",
    }
}

/// Pass 1: `{name}` / `{{name}}` from the query string.
fn interpolate_query(body: &str, query: &Query) -> String {
    // whistle skips this pass entirely when the URL carries no query string.
    // Leaving every placeholder untouched is the same outcome, but skipping is
    // cheaper and keeps the two implementations obviously equivalent.
    if query.is_empty() {
        return body.to_string();
    }
    let bytes = body.as_bytes();
    QUERY_VAR
        .replace_all(body, |caps: &Captures| {
            let whole = caps.get(0).expect("group 0 always exists");
            let text = whole.as_str();
            // A `$` immediately before the placeholder means "this belongs to
            // pass 2" — leave it exactly as written.
            if whole.start() > 0 && bytes[whole.start() - 1] == b'$' {
                return text.to_string();
            }
            let name = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str())
                .unwrap_or_default();
            // Unknown names survive into the output; whistle does not blank them.
            query.get(name, Decode::Full).unwrap_or_else(|| text.to_string())
        })
        .into_owned()
}

/// Pass 2: `${name}` / `${name.key}` / `${{name}}` / `$${name}`.
fn interpolate_vars(body: &str, info: &ReqInfo, query: &Query, env: ProxyEnv<'_>) -> String {
    TPL_VAR
        .replace_all(body, |caps: &Captures| {
            let all = &caps[0];
            let raw = caps.get(1).is_some();
            let encode = caps.get(2).is_some();
            let closed = caps.get(5).is_some();
            // `${{name}` — unbalanced braces are left alone (`rules.js:717`).
            if encode && !closed {
                return all.to_string();
            }
            let name = &caps[3];
            // A trailing `.replace(...)` modifies the value, so it has to come
            // off the key before the variable is resolved (`rules.js:725-733`).
            let (key, modifier) = match split_modifier(caps.get(4).map(|m| m.as_str())) {
                Modifier::Parsed(key, modifier) => (key, modifier),
                Modifier::Unsupported => return all.to_string(),
            };
            let Some(mut value) = resolve_var(info, query, raw, name, key, env) else {
                return all.to_string();
            };
            if let Some(modifier) = modifier {
                value = modifier.apply(value);
            }
            if encode && !value.is_empty() {
                value = encode_uri_component(&value);
            }
            // `${name}}` keeps its trailing brace (`rules.js:757`).
            if !encode && closed {
                value.push('}');
            }
            value
        })
        .into_owned()
}

/// Resolve one whitelisted variable.
///
/// `None` means "leave the placeholder in the output": whistle-rs has no data
/// source for the name (client identity, `${whistle.*}` plugin values).
fn resolve_var(
    info: &ReqInfo,
    query: &Query,
    raw: bool,
    name: &str,
    key: Option<&str>,
    env: ProxyEnv<'_>,
) -> Option<String> {
    let lname = name.to_ascii_lowercase();
    if let Some(n) = random_int_bounds(&lname) {
        return Some(n.to_string());
    }
    let url = ParsedUrl::of(&info.full_url);
    let mode = if raw { Decode::None } else { Decode::KeepPlus };

    let value = match lname.as_str() {
        // -- generated ------------------------------------------------------
        "now" => now_millis().to_string(),
        "random" => format_random_unit(),
        "randomuuid" => random_uuid(),

        // -- request URL ----------------------------------------------------
        "url" => url.prop(key, query, mode)?,
        "path" | "pathname" | "search" => match key {
            // whistle blanks these when a sub-key is present (`rules.js:645`).
            Some(_) => String::new(),
            None => url.prop(Some(&lname), query, mode)?,
        },
        "querystring" | "searchstring" => match key {
            Some(_) => String::new(),
            None => {
                let search = url.prop(Some("search"), query, mode)?;
                if search.is_empty() { "?".to_string() } else { search }
            }
        },
        "query" => match key {
            Some(k) => query.get(k, mode).unwrap_or_default(),
            None => url.query.to_string(),
        },
        "method" => info.method.clone(),
        "ip" | "clientip" => info.client_ip.clone().unwrap_or_default(),

        // -- request headers ------------------------------------------------
        "reqh" | "reqheader" | "reqheaders" => match key {
            Some(k) => header(info, k),
            None => String::new(),
        },
        "reqcookie" | "reqcookies" => {
            let cookie = header(info, "cookie");
            match key {
                Some(k) => cookie_value(&cookie, k, mode),
                None => cookie,
            }
        }

        // -- host machine ---------------------------------------------------
        "hostname" => os_hostname(),
        "env" => match key {
            Some(k) => std::env::var(k).unwrap_or_default(),
            None => String::new(),
        },

        // -- known to whistle, but empty for a short-circuited template ------
        // There is no upstream response and no request-id/client bookkeeping in
        // whistle-rs yet; whistle itself also yields "" for the response-side
        // names here, because `tpl://` never reaches a server.
        "statuscode" | "serverip" | "serverport" | "resh" | "resheader" | "resheaders"
        | "rescookie" | "rescookies" | "id" | "reqid" | "clientid" | "clientport"
        | "remoteaddress" | "remoteport" | "realurl" => String::new(),

        // -- whistle's own config, not the request's
        "host" | "realhost" => env.host.to_string(),
        "port" | "realport" => env.port.to_string(),
        "version" => env.version.to_string(),

        // -- needs the plugin runtime / client identity, which this call site lacks
        "localclientid" | "whistle" => return None,

        _ => return None,
    };
    Some(value)
}

/// Look up a request header (names in `ReqInfo` are already lowercased).
fn header(info: &ReqInfo, name: &str) -> String {
    let name = name.to_ascii_lowercase();
    info.headers
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Extract one cookie from a `Cookie` header value.
fn cookie_value(cookie: &str, name: &str, mode: Decode) -> String {
    cookie
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| decode(k, mode) == name)
        .map(|(_, v)| decode(v, mode))
        .unwrap_or_default()
}

/// `randomInt(max)` / `randomInt(min-max)`, mirroring `rules.js:617`:
/// `Math.floor(Math.random() * (max + 1)) + min`, and `0` when the span is 0.
fn random_int_bounds(lname: &str) -> Option<u64> {
    let inner = lname.strip_prefix("randomint(")?.strip_suffix(')')?;
    let (min, max) = match inner.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?);
            let (lo, hi) = if b < a { (b, a) } else { (a, b) };
            (lo, hi - lo)
        }
        None => (0, inner.parse::<u64>().ok()?),
    };
    if max == 0 {
        return Some(0);
    }
    Some(min + next_random_u64() % (max + 1))
}

// ---------------------------------------------------------------------------
// The `.replace(pattern,replacement)` modifier
// ---------------------------------------------------------------------------

/// What splitting a `.replace(...)` suffix off a variable key produced.
enum Modifier<'a> {
    /// The key with the suffix removed — `None` once nothing is left, which is
    /// how whistle's falsy `''` behaves — and the modifier, when one was written.
    Parsed(Option<&'a str>, Option<Replace>),
    /// A `/…/flags` pattern JavaScript accepts and the `regex` crate does not
    /// (look-around, back-references). The placeholder is then left verbatim
    /// rather than rendered with the modifier silently dropped.
    Unsupported,
}

/// Split a trailing `.replace(pattern,replacement)` off a variable key.
fn split_modifier(key: Option<&str>) -> Modifier<'_> {
    let Some(key) = key else {
        return Modifier::Parsed(None, None);
    };
    let Some(caps) = REPLACE_SUFFIX.captures(key) else {
        return Modifier::Parsed(Some(key), None);
    };
    // The suffix is anchored at the end, so what precedes the match is the key
    // (`key.substring(0, key.length - 9 - dot.length - pattern.length)`,
    // `rules.js:729`).
    let rest = &key[..caps.get(0).expect("group 0 always exists").start()];
    match Replace::parse(&caps[2]) {
        Some(replace) => Modifier::Parsed((!rest.is_empty()).then_some(rest), Some(replace)),
        None => Modifier::Unsupported,
    }
}

/// A parsed `.replace(pattern,replacement)` modifier (`rules.js:725-752`).
struct Replace {
    /// The search pattern, commas unescaped. An *empty* pattern is meaningful:
    /// the modifier then supplies a default value instead of replacing anything.
    pattern: String,
    replacement: String,
    /// Set when the pattern was written as `/…/flags`.
    regex: Option<Regex>,
    /// The `g` flag — replace every match rather than only the first.
    global: bool,
}

impl Replace {
    /// Parse the raw text between `replace(` and `)`.
    ///
    /// `None` means the pattern is a regex whistle-rs cannot compile; see
    /// [`Modifier::Unsupported`].
    fn parse(arg: &str) -> Option<Replace> {
        // Pattern and replacement are separated by the first *unescaped* comma.
        // whistle parks escaped commas on control characters while it splits
        // (`COMMA1_RE`/`COMMA2_RE` and `resetComma`, `rules.js:711-713,730-736`),
        // so `\,` survives as a literal comma and `\\,` as a literal `\,`.
        let mut pattern = arg.to_string();
        let mut replacement = String::new();
        if pattern.contains(',') {
            let escaped = pattern.replace("\\\\,", "\n").replace("\\,", "\r");
            pattern = match escaped.split_once(',') {
                Some((p, r)) => {
                    replacement = reset_comma(r);
                    reset_comma(p)
                }
                None => reset_comma(&escaped),
            };
        }

        let mut regex = None;
        let mut global = false;
        if let Some(caps) = JS_REGEX.captures(&pattern) {
            let flags = &caps[2];
            // Repeated flags make `new RegExp` throw, and whistle's
            // `toOriginalRegExp` then returns null — i.e. a literal replace of
            // the `/…/` text itself (`util/index.js:623-631`).
            let repeated = flags
                .char_indices()
                .any(|(i, c)| flags[..i].contains(c));
            if !repeated {
                let mut inline = String::new();
                if flags.contains('i') {
                    inline.push('i');
                }
                if flags.contains('m') {
                    inline.push('m');
                }
                // `u` needs no translation: the `regex` crate is Unicode-aware
                // by default.
                let source = match inline.is_empty() {
                    true => caps[1].to_string(),
                    false => format!("(?{inline}){}", &caps[1]),
                };
                regex = Some(Regex::new(&source).ok()?);
                global = flags.contains('g');
            }
        }
        Some(Replace {
            pattern,
            replacement,
            regex,
            global,
        })
    }

    /// Apply the modifier to a resolved variable value.
    fn apply(&self, value: String) -> String {
        // `val = pattern ? val : val || replacement` (`rules.js:744-746`): with
        // an empty pattern the modifier stops replacing and becomes a *default*,
        // which is how `${query.x.replace(,fallback)}` is written.
        if self.pattern.is_empty() {
            return match value.is_empty() {
                true => self.replacement.clone(),
                false => value,
            };
        }
        if value.is_empty() {
            return value;
        }
        match &self.regex {
            // whistle only routes through its own expander when the replacement
            // actually references the match (`rules.js:746-751`).
            Some(re) if HAS_SUB_MATCH.is_match(&self.replacement) => {
                self.replace_with(re, &value, expand_sub_match)
            }
            Some(re) => self.replace_with(re, &value, expand_native),
            // A plain substring pattern goes through `String.prototype.replace`,
            // which rewrites only the first occurrence and has no capture groups.
            None => match value.find(&self.pattern) {
                Some(at) => {
                    let end = at + self.pattern.len();
                    let parts = MatchParts {
                        groups: vec![Some(value[at..end].to_string())],
                        before: &value[..at],
                        after: &value[end..],
                    };
                    let mut out = String::with_capacity(value.len());
                    out.push_str(&value[..at]);
                    out.push_str(&expand_native(&self.replacement, &parts));
                    out.push_str(&value[end..]);
                    out
                }
                None => value,
            },
        }
    }

    /// Run a compiled pattern over `value`, honouring the `g` flag.
    fn replace_with(
        &self,
        re: &Regex,
        value: &str,
        expand: fn(&str, &MatchParts<'_>) -> String,
    ) -> String {
        let substitute = |caps: &Captures| {
            let whole = caps.get(0).expect("group 0 always exists");
            let parts = MatchParts {
                groups: caps.iter().map(|g| g.map(|g| g.as_str().to_string())).collect(),
                before: &value[..whole.start()],
                after: &value[whole.end()..],
            };
            expand(&self.replacement, &parts)
        };
        match self.global {
            true => re.replace_all(value, substitute).into_owned(),
            false => re.replace(value, substitute).into_owned(),
        }
    }
}

/// whistle's `resetComma` (`rules.js:711-713`): put the escaped commas back,
/// `\r` as a literal comma and `\n` as a literal `\,`.
fn reset_comma(s: &str) -> String {
    s.replace('\r', ",").replace('\n', "\\,")
}

/// The pieces a replacement's `$`-expansion can refer to.
struct MatchParts<'a> {
    /// Index 0 is the whole match, 1.. the capture groups.
    groups: Vec<Option<String>>,
    /// Text before the match, for ``$` ``.
    before: &'a str,
    /// Text after the match, for `$'`.
    after: &'a str,
}

impl MatchParts<'_> {
    fn group(&self, index: usize) -> &str {
        self.groups
            .get(index)
            .and_then(|g| g.as_deref())
            .unwrap_or_default()
    }
}

/// JavaScript's native replacement-string expansion: `$$`, `$&`, ``$` ``, `$'`
/// and `$1`..`$99`.
///
/// A `$n` past the last capture group stays verbatim — which is why a `$1`
/// written against a *plain substring* pattern survives into the output.
fn expand_native(replacement: &str, parts: &MatchParts<'_>) -> String {
    let mut out = String::with_capacity(replacement.len());
    let mut rest = replacement;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 1..];
        let bytes = tail.as_bytes();
        // `used` is how much of `tail` the token consumed; 0 leaves the `$`
        // itself in the output and re-examines the rest on the next pass.
        let (text, used): (&str, usize) = match bytes.first() {
            Some(b'$') => ("$", 1),
            Some(b'&') => (parts.group(0), 1),
            Some(b'`') => (parts.before, 1),
            Some(b'\'') => (parts.after, 1),
            Some(d) if d.is_ascii_digit() => {
                let two = bytes
                    .get(1)
                    .filter(|c| c.is_ascii_digit())
                    .map(|c| (d - b'0') as usize * 10 + (c - b'0') as usize);
                // The two-digit form wins only when it names a real group.
                match two.filter(|n| parts.groups.get(*n).is_some() && *n > 0) {
                    Some(n) => (parts.group(n), 2),
                    None => {
                        let n = (d - b'0') as usize;
                        match parts.groups.get(n).is_some() && n > 0 {
                            true => (parts.group(n), 1),
                            false => ("$", 0),
                        }
                    }
                }
            }
            _ => ("$", 0),
        };
        out.push_str(text);
        rest = &tail[used..];
    }
    out.push_str(rest);
    out
}

/// whistle's own back-reference expander (`replacePattern`,
/// `_original/lib/util/replace-pattern-transform.js:64-90`).
///
/// On top of `$&` and `$0`..`$9` it understands `$$&` (URI-encode the
/// substitution) and `\$&` (emit the token literally, `\\$&` a backslash then
/// the value).
fn expand_sub_match(replacement: &str, parts: &MatchParts<'_>) -> String {
    SUB_MATCH
        .replace_all(replacement, |caps: &Captures| {
            let slashes = &caps[1];
            let token = &caps[2];
            // `$b&` selects whistle's *body* value list, which `resolveTplVar`
            // never passes (`rules.js:750`); upstream then emits the token
            // unchanged, and so do we.
            if caps.get(3).is_some() {
                return format!("{slashes}{token}");
            }
            // `\$&` escapes the token; `\\$&` keeps one backslash before the value.
            if slashes == "\\" {
                return token.to_string();
            }
            let prefix = match slashes {
                "\\\\" => "\\",
                other => other,
            };
            let encode = token.as_bytes().get(1) == Some(&b'$');
            let selector = &token[if encode { 2 } else { 1 }..];
            let index = match selector {
                "&" => 0,
                digit => digit.parse().unwrap_or(0),
            };
            let value = parts.group(index);
            match encode && !value.is_empty() {
                true => format!("{prefix}{}", encode_uri_component(value)),
                false => format!("{prefix}{value}"),
            }
        })
        .into_owned()
}

// ---------------------------------------------------------------------------
// Query strings
// ---------------------------------------------------------------------------

/// How aggressively to decode a query/cookie value.
///
/// whistle uses three different decoders for the same data, which is why this
/// exists: pass 1 goes through Node's `querystring.parse` (`+` becomes a space),
/// `${query.x}` goes through `util.parseQuery` which deliberately round-trips
/// `+` through a token so it stays a literal `+` (`_original/lib/util/common.js:133`),
/// and `$${query.x}` disables decoding entirely (`rawDecoder2`, `common.js:127`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Decode {
    /// Percent-decode and turn `+` into a space.
    Full,
    /// Percent-decode but keep `+` literal.
    KeepPlus,
    /// Return the bytes exactly as they appeared in the URL.
    None,
}

fn decode(s: &str, mode: Decode) -> String {
    match mode {
        Decode::None => s.to_string(),
        Decode::Full => percent_decode(s, true),
        Decode::KeepPlus => percent_decode(s, false),
    }
}

/// A parsed query string, kept as the raw pairs so each caller can apply its
/// own decoding. Order and repeats are preserved.
struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    /// Split on `&` then on the first `=`. A key with no `=` keeps an empty
    /// value, exactly like Node's `querystring.parse` (`?a&b=1` → `a` = "").
    fn parse(query: &str) -> Query {
        let pairs = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (kv.to_string(), String::new()),
            })
            .collect();
        Query { pairs }
    }

    fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Look up a parameter. Repeated keys become a JSON array, matching
    /// `util.getQueryValue`'s `JSON.stringify` of the array Node builds
    /// (`_original/lib/util/index.js:1104`).
    fn get(&self, name: &str, mode: Decode) -> Option<String> {
        let mut found: Vec<String> = self
            .pairs
            .iter()
            .filter(|(k, _)| decode(k, mode) == name)
            .map(|(_, v)| decode(v, mode))
            .collect();
        match found.len() {
            0 => None,
            1 => Some(found.pop().unwrap_or_default()),
            _ => Some(serde_json::to_string(&found).unwrap_or_default()),
        }
    }
}

/// Percent-decode, optionally mapping `+` to a space. Invalid escapes are kept
/// verbatim (Node's decoder throws and `querystring` then falls back to the raw
/// text); invalid UTF-8 is replaced rather than dropped.
fn percent_decode(s: &str, plus_to_space: bool) -> String {
    if !s.contains('%') && !(plus_to_space && s.contains('+')) {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_to_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// JavaScript's `encodeURIComponent`: everything outside the unreserved set
/// `A-Za-z0-9-_.!~*'()` is percent-encoded.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// URL properties
// ---------------------------------------------------------------------------

/// The subset of Node's legacy `url.parse` output that `${url.*}` exposes.
///
/// Built from `ReqInfo::full_url` rather than the structured fields so that,
/// like Node, `${url.port}` is empty when the URL omits a default port.
struct ParsedUrl<'a> {
    href: &'a str,
    protocol: &'a str,
    /// `host[:port]` exactly as written.
    host: &'a str,
    hostname: &'a str,
    port: &'a str,
    pathname: &'a str,
    /// Query string without `?`.
    query: &'a str,
    /// `?`-prefixed query string, or empty.
    search: &'a str,
    /// `pathname` + `search`.
    path: &'a str,
}

impl<'a> ParsedUrl<'a> {
    fn of(full_url: &'a str) -> ParsedUrl<'a> {
        let (protocol, rest) = match full_url.find("://") {
            Some(i) => (&full_url[..i + 1], &full_url[i + 3..]),
            None => ("", full_url),
        };
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (hostname, port) = match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p),
            _ => (host, ""),
        };
        let (pathname, search, query) = match path.find('?') {
            Some(i) => (&path[..i], &path[i..], &path[i + 1..]),
            None => (path, "", ""),
        };
        ParsedUrl {
            href: full_url,
            protocol,
            host,
            hostname,
            port,
            pathname,
            query,
            search,
            path,
        }
    }

    /// `${url}` with no key yields the whole URL; `${url.key}` one property.
    /// Unknown properties yield "" (Node's `options[key] || ''`).
    fn prop(&self, key: Option<&str>, query: &Query, mode: Decode) -> Option<String> {
        let Some(key) = key else {
            return Some(self.href.to_string());
        };
        if let Some(name) = key.strip_prefix("query.") {
            return Some(query.get(name, mode).unwrap_or_default());
        }
        let value = match key.to_ascii_lowercase().as_str() {
            "href" => self.href,
            "protocol" => self.protocol,
            "host" => self.host,
            "hostname" => self.hostname,
            "port" => self.port,
            "pathname" => self.pathname,
            "path" => self.path,
            "search" => self.search,
            "query" => self.query,
            // `${url.actualPort}` / `${url.realPort}` fall back to the scheme's
            // default when the URL omits the port (`rules.js:1117`).
            "actualport" | "realport" => {
                let port = if self.port.is_empty() {
                    if self.protocol == "https:" || self.protocol == "wss:" {
                        "443"
                    } else {
                        "80"
                    }
                } else {
                    self.port
                };
                return Some(port.to_string());
            }
            _ => "",
        };
        Some(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Generated values
// ---------------------------------------------------------------------------

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// A fresh pseudo-random `u64`. `RandomState` is seeded from the OS once per
/// process and bumped per instance, which is ample for mock data and avoids
/// pulling in a RNG crate.
fn next_random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(now_millis());
    hasher.finish()
}

/// `Math.random()`: a double in `[0, 1)` with 53 bits of entropy, formatted the
/// way JavaScript would print it.
fn format_random_unit() -> String {
    let bits = next_random_u64() >> 11;
    let value = bits as f64 / (1u64 << 53) as f64;
    value.to_string()
}

/// A version-4 UUID, matching `crypto.randomUUID()`'s output shape.
fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let r = next_random_u64().to_ne_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The machine's hostname, for `${hostname}`. Falls back to "" when the OS
/// provides no answer; whistle-rs never fails a render over this.
fn os_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    /// Build a `ReqInfo` the way the proxy would, for a `scheme://host/path` URL.
    fn req(url: &str, headers: &[(&str, &str)]) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match host_port.split_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(80)),
            None => (host_port, if scheme == "https" { 443 } else { 80 }),
        };
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        crate::proxy::apply::build_req_info(
            "GET",
            scheme,
            host,
            port,
            path,
            &map,
            Some("10.0.0.7".to_string()),
        )
    }

    /// The proxy facts a test renders against, mirroring a default server.
    const ENV: ProxyEnv<'static> = ProxyEnv {
        host: "",
        port: 8899,
        version: "9.9.9",
    };

    fn render_url(body: &str, url: &str) -> String {
        render(body, &req(url, &[]), ENV)
    }

    // -- pass 1: query interpolation ----------------------------------------

    #[test]
    fn single_and_double_brace_interpolation() {
        assert_eq!(render_url("{a}/{{b}}", "http://x.com/?a=1&b=2"), "1/2");
    }

    #[test]
    fn unknown_name_is_left_verbatim() {
        // whistle keeps the placeholder rather than blanking it.
        assert_eq!(render_url("[{nope}]", "http://x.com/?a=1"), "[{nope}]");
    }

    #[test]
    fn dollar_prefix_escapes_a_query_placeholder() {
        assert_eq!(render_url("${a} {a}", "http://x.com/?a=1"), "${a} 1");
    }

    #[test]
    fn body_without_placeholders_is_untouched() {
        let body = "plain { spaced } body";
        assert_eq!(render_url(body, "http://x.com/?a=1"), body);
    }

    #[test]
    fn percent_encoded_and_plus_values_are_decoded() {
        // Pass 1 uses Node's querystring decoder: `+` becomes a space.
        assert_eq!(
            render_url("{q}", "http://x.com/?q=a%20b+c%2Fd"),
            "a b c/d"
        );
    }

    #[test]
    fn valueless_keys_are_kept_as_empty() {
        assert_eq!(render_url("[{a}][{b}]", "http://x.com/?a&b=1"), "[][1]");
    }

    #[test]
    fn repeated_keys_become_a_json_array() {
        assert_eq!(render_url("{a}", "http://x.com/?a=1&a=2"), r#"["1","2"]"#);
    }

    #[test]
    fn jsonp_is_expressed_by_the_template_itself() {
        // The documented mechanism (_original/docs/docs/rules/tpl.md:20).
        assert_eq!(
            render_url("{callback}({ec:0});", "http://x.com/t?callback=test"),
            "test({ec:0});"
        );
    }

    // -- pass 2: built-in variables -----------------------------------------

    #[test]
    fn url_parts_resolve() {
        let out = render_url(
            "${url.hostname}|${url.pathname}|${url.query}|${method}",
            "http://api.x.com/a/b?k=v",
        );
        assert_eq!(out, "api.x.com|/a/b|k=v|GET");
    }

    #[test]
    fn nested_query_path_resolves() {
        assert_eq!(
            render_url("${url.query.cb}|${query.cb}", "http://x.com/?cb=go"),
            "go|go"
        );
    }

    #[test]
    fn double_brace_uri_encodes() {
        assert_eq!(
            render_url("${{query.q}}", "http://x.com/?q=a%20b%2Fc"),
            "a%20b%2Fc"
        );
    }

    #[test]
    fn dollar_dollar_keeps_the_raw_value() {
        // `$${...}` disables decoding, so the escape survives.
        assert_eq!(render_url("$${query.q}", "http://x.com/?q=a%20b"), "a%20b");
        assert_eq!(render_url("${query.q}", "http://x.com/?q=a%20b"), "a b");
    }

    #[test]
    fn plus_stays_literal_in_pass_two() {
        // `util.parseQuery` round-trips `+` so it is not turned into a space,
        // unlike pass 1. This asymmetry is whistle's, and is reproduced here.
        assert_eq!(render_url("${query.q}", "http://x.com/?q=a+b"), "a+b");
        assert_eq!(render_url("{q}", "http://x.com/?q=a+b"), "a b");
    }

    #[test]
    fn unbalanced_and_trailing_braces() {
        // `${{x}` is left alone; `${method}}` keeps its extra brace.
        assert_eq!(render_url("${{method}", "http://x.com/?a=1"), "${{method}");
        assert_eq!(render_url("${method}}", "http://x.com/?a=1"), "GET}");
    }

    #[test]
    fn unknown_variable_names_are_left_verbatim() {
        assert_eq!(render_url("${nope}", "http://x.com/?a=1"), "${nope}");
    }

    #[test]
    fn proxy_config_variables_resolve() {
        // Upstream reads these off whistle's own config, not the request
        // (`resolveVarValue`, rules.js:657-668) — `${host}` is the proxy's bind
        // address, which is empty when bound to all interfaces.
        assert_eq!(render_url("${port}/${version}", "http://x.com/?a=1"), "8899/9.9.9");
        assert_eq!(render_url("[${host}]", "http://x.com/?a=1"), "[]");
        assert_eq!(render_url("${realPort}", "http://x.com/?a=1"), "8899");

        let bound = ProxyEnv { host: "127.0.0.1", port: 1234, version: "1.0" };
        assert_eq!(render("${host}:${port}", &req("http://x.com/?a=1", &[]), bound), "127.0.0.1:1234");
    }

    // -- pass 2: the `.replace(...)` modifier -------------------------------

    #[test]
    fn replace_substitutes_a_plain_substring() {
        // A string pattern goes through `String.replace`, which rewrites only
        // the first occurrence.
        assert_eq!(
            render_url("${query.replace(a,Z)}", "http://x.com/?a=1&ba=2"),
            "Z=1&ba=2"
        );
        assert_eq!(render_url("${method.replace(GET,PUT)}", "http://x.com/?a=1"), "PUT");
    }

    #[test]
    fn replace_keeps_the_rest_of_the_key() {
        // `${query.<name>.replace(...)}` must still resolve `<name>`.
        assert_eq!(
            render_url("${query.who.replace(world,there)}", "http://x.com/?who=hello%20world"),
            "hello there"
        );
    }

    #[test]
    fn replace_accepts_a_regexp_pattern_with_flags() {
        // `/…/flags` becomes a real regex (`toOriginalRegExp`); `g` replaces
        // every match, `i` ignores case, and without `g` only the first.
        assert_eq!(
            render_url("${url.replace(/A/gi,-)}", "http://x.com/a/A?a=1"),
            "http://x.com/-/-?-=1"
        );
        assert_eq!(
            render_url("${url.replace(/a/i,-)}", "http://x.com/A/a?a=1"),
            "http://x.com/-/a?a=1"
        );
    }

    #[test]
    fn replace_expands_back_references() {
        assert_eq!(
            render_url("${query.v.replace(/b(c)/,[$&|$1])}", "http://x.com/?v=abcd"),
            "a[bc|c]d"
        );
        // `$$1` URI-encodes the group, `\$1` emits the token literally.
        assert_eq!(
            render_url("${query.v.replace(/(.+)/,$$1)}", "http://x.com/?v=a%2Fb"),
            "a%2Fb"
        );
        assert_eq!(
            render_url(r"${query.v.replace(/(x)/,\$1)}", "http://x.com/?v=x"),
            "$1"
        );
    }

    #[test]
    fn replace_back_reference_needs_a_regexp() {
        // With a plain substring pattern there are no capture groups, so JS
        // leaves `$1` alone while still expanding `$&`.
        assert_eq!(
            render_url("${query.v.replace(b,[$&$1])}", "http://x.com/?v=abc"),
            "a[b$1]c"
        );
    }

    #[test]
    fn replace_unescapes_commas() {
        // `\,` is a literal comma inside the arguments (`resetComma`).
        assert_eq!(
            render_url(r"${query.v.replace(a\,b,-)}", "http://x.com/?v=1a,b2"),
            "1-2"
        );
        assert_eq!(
            render_url(r"${query.v.replace(x,a\,b)}", "http://x.com/?v=x"),
            "a,b"
        );
        // `\\,` survives as a literal `\,`.
        assert_eq!(
            render_url(r"${query.v.replace(x,a\\,b)}", "http://x.com/?v=x"),
            r"a\,b"
        );
    }

    #[test]
    fn empty_pattern_makes_the_replacement_a_default() {
        // `val = pattern ? val : val || replacement` (rules.js:744-746).
        assert_eq!(
            render_url("${query.missing.replace(,fallback)}", "http://x.com/?a=1"),
            "fallback"
        );
        assert_eq!(
            render_url("${query.v.replace(,fallback)}", "http://x.com/?v=set"),
            "set"
        );
        // An empty value with a *non*-empty pattern stays empty — no default.
        assert_eq!(
            render_url("[${query.missing.replace(a,fallback)}]", "http://x.com/?a=1"),
            "[]"
        );
    }

    #[test]
    fn replace_with_no_replacement_deletes() {
        assert_eq!(
            render_url("${query.v.replace(/[0-9]/g)}", "http://x.com/?v=a1b2"),
            "ab"
        );
    }

    #[test]
    fn replace_composes_with_uri_encoding() {
        // The modifier runs before `${{...}}` encodes the result.
        assert_eq!(
            render_url("${{query.v.replace(b,/)}}", "http://x.com/?v=a-b"),
            "a-%2F"
        );
    }

    #[test]
    fn unsupported_regexp_leaves_the_placeholder_verbatim() {
        // Look-around has no `regex`-crate equivalent; rendering it as a no-op
        // would silently lie about what the template did.
        let body = "${url.replace(/(?=a)/g,-)}";
        assert_eq!(render_url(body, "http://x.com/?a=1"), body);
    }

    #[test]
    fn request_headers_and_cookies_resolve() {
        let info = req(
            "http://x.com/?a=1",
            &[("x-token", "abc"), ("cookie", "sid=s1; other=o2")],
        );
        assert_eq!(render("${reqHeaders.x-token}", &info, ENV), "abc");
        assert_eq!(render("${reqH.x-token}", &info, ENV), "abc");
        assert_eq!(render("${reqCookies.sid}", &info, ENV), "s1");
        assert_eq!(render("${reqCookies.missing}", &info, ENV), "");
    }

    #[test]
    fn client_ip_resolves() {
        assert_eq!(render_url("${clientIp}", "http://x.com/?a=1"), "10.0.0.7");
    }

    #[test]
    fn response_side_variables_are_empty() {
        // A template short-circuits before any upstream response exists.
        assert_eq!(render_url("[${statusCode}]", "http://x.com/?a=1"), "[]");
        assert_eq!(render_url("[${resHeaders.x}]", "http://x.com/?a=1"), "[]");
    }

    #[test]
    fn search_and_query_string_fallbacks() {
        assert_eq!(render_url("${search}|${queryString}", "http://x.com/a?k=v"), "?k=v|?k=v");
        // `${queryString}` degrades to "?" when there is no query; `${search}`
        // to "". A trailing `{x}` only satisfies the placeholder gate.
        assert_eq!(render_url("${search}|${queryString}|{x}", "http://x.com/a"), "|?|{x}");
    }

    #[test]
    fn case_insensitive_variable_names() {
        assert_eq!(render_url("${METHOD}", "http://x.com/?a=1"), "GET");
    }

    #[test]
    fn generated_values_have_the_right_shape() {
        let now = render_url("${now}", "http://x.com/?a=1");
        assert!(now.len() >= 13 && now.chars().all(|c| c.is_ascii_digit()), "{now}");

        let uuid = render_url("${randomUUID}", "http://x.com/?a=1");
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'4', "version nibble: {uuid}");
        assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'), "{uuid}");

        let unit: f64 = render_url("${random}", "http://x.com/?a=1").parse().unwrap();
        assert!((0.0..1.0).contains(&unit), "{unit}");

        let n: u64 = render_url("${randomInt(5-9)}", "http://x.com/?a=1").parse().unwrap();
        assert!((5..=9).contains(&n), "{n}");
        assert_eq!(render_url("${randomInt(0)}", "http://x.com/?a=1"), "0");
    }

    // -- helpers -------------------------------------------------------------

    #[test]
    fn encode_uri_component_matches_javascript() {
        assert_eq!(encode_uri_component("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_uri_component("-_.!~*'()"), "-_.!~*'()");
        assert_eq!(encode_uri_component("中"), "%E4%B8%AD");
    }

    #[test]
    fn percent_decode_keeps_invalid_escapes() {
        assert_eq!(percent_decode("100%25", false), "100%");
        assert_eq!(percent_decode("a%zz", false), "a%zz");
        assert_eq!(percent_decode("trailing%", false), "trailing%");
    }

    #[test]
    fn parsed_url_splits_default_and_explicit_ports() {
        let u = ParsedUrl::of("https://x.com/a?k=v");
        assert_eq!((u.protocol, u.hostname, u.port, u.path), ("https:", "x.com", "", "/a?k=v"));
        let u = ParsedUrl::of("http://x.com:8080/a");
        assert_eq!((u.host, u.hostname, u.port, u.search), ("x.com:8080", "x.com", "8080", ""));
    }
}
