//! whistle rules engine (parse + match + resolve).
//!
//! Ported from `_original/lib/rules/`. The original is ~9k lines with an
//! enormous surface of edge cases; this port implements the load-bearing core:
//!
//! * line parsing: `pattern op1 op2 …` (comments, blank lines, shorthands)
//! * pattern kinds: regexp (`/re/i`), wildcard (`*`), and scheme/host/path
//!   prefix matching
//! * operator parsing for the full protocol set (see [`protocols`])
//! * per-line properties (`lineProps://…`, see [`LineProps`])
//! * per-request resolution with first-match-wins (and multi-match for the
//!   protocols whistle allows to repeat)
//!
//! What is intentionally simplified vs. the original is documented inline and in
//! the project README.

pub mod include;
pub mod matcher;
pub mod protocols;
pub mod replace;
pub mod storage;
pub mod url;
pub mod wildcard;

use regex::Regex;
use std::collections::{BTreeSet, HashMap};

/// Every line property whistle's editor offers
/// (`LINE_PROPS_HINTS` in `_original/biz/webui/htdocs/src/js/rules-hint.js:69`),
/// plus the spellings only the runtime knows about. Unknown actions are kept
/// too — whistle never validates them — so this list is documentation, not a
/// filter. See `docs/LINE_PROPS.md` for what each one does and which are wired
/// up in this port.
pub const LINE_PROP_ACTIONS: &[&str] = &[
    "important",
    "safeHtml",
    "strictHtml",
    "disableAutoCors",
    "disableUserLogin",
    "enableUserLogin",
    "internal",
    "internalOnly",
    "internalProxy",
    "proxyFirst",
    "proxyHost",
    "proxyHostOnly",
    "proxyTunnel",
    "weakRule",
    "enableBigData",
    // Undocumented but honoured by the original runtime.
    "disabledAutoCors",
    "originUrl",
];

/// Per-line properties declared with `lineProps://<action>[|&<action>…]`.
///
/// `lineProps` (`resolveMatchFilter` in `_original/lib/rules/rules.js:1542`,
/// `parseLineProps` in `_original/lib/util/index.js:1892`) is the line-scoped
/// counterpart of the global `enable://`/`disable://` switches: the actions
/// listed on a rule line only affect the operators written on *that* line.
/// Every operator of a line therefore carries a copy — see [`RuleOp::props`].
///
/// Actions are stored verbatim, exactly like the original's `{action: true}`
/// map, so spellings this port does not act on still reach consumers that do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineProps {
    actions: BTreeSet<String>,
}

/// Shared empty set, so [`Resolved::props`] can hand out a reference for
/// protocols that never matched.
static NO_PROPS: LineProps = LineProps {
    actions: BTreeSet::new(),
};

impl LineProps {
    /// Merge one `lineProps://` payload. Separators are `|` and `&`
    /// (`SEP_RE = /[|&]/` in the original); empty segments are dropped, so
    /// `lineProps://`, `lineProps://|` and `lineProps://a||b` all behave.
    fn merge(&mut self, spec: &str) {
        for action in spec.split(['|', '&']) {
            if !action.is_empty() {
                self.actions.insert(action.to_string());
            }
        }
    }

    /// Build properties from explicit action names, as if a line had declared
    /// them.
    ///
    /// The proxy layer folds the request-scoped `enable://safeHtml` /
    /// `enable://strictHtml` switches into the same gate as the per-line ones —
    /// upstream stamps them onto every injecting rule of the request
    /// (`_original/lib/inspectors/res.js:966-982`).
    pub fn from_actions<'a>(actions: impl IntoIterator<Item = &'a str>) -> Self {
        let mut props = LineProps::default();
        for action in actions {
            props.merge(action);
        }
        props
    }

    /// Is `action` set on this line?
    pub fn has(&self, action: &str) -> bool {
        self.actions.contains(action)
    }

    /// True when the line declared no properties at all.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// The declared actions, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.actions.iter().map(String::as_str)
    }

    /// `important` — like CSS's `!important`, this line's operators outrank the
    /// same protocol from non-important lines regardless of file position
    /// (`isImportant` in `_original/lib/util/index.js:2156`).
    pub fn important(&self) -> bool {
        self.has("important")
    }

    /// `internal` / `internalOnly` — whether a rule carrying these properties
    /// applies to a request with this origin. `internalOnly` restricts the line
    /// to whistle's own outgoing requests, `internal` widens it to both.
    /// Ported from `checkInternal` (`_original/lib/rules/rules.js:910`).
    pub fn allows_scope(&self, is_internal_req: bool) -> bool {
        if is_internal_req {
            self.has("internal") || self.has("internalOnly")
        } else {
            !self.has("internalOnly")
        }
    }

    /// `safeHtml` / `strictHtml` — should this line's `htmlXxx`/`jsXxx`/`cssXxx`
    /// content be injected into `body`?
    ///
    /// Ported from `WhistleTransform#allowInject` + `filterHtml`
    /// (`_original/lib/util/whistle-transform.js:47`). A body whose first
    /// non-whitespace byte is `<` (or which is blank) is proper markup and
    /// always accepts injection; otherwise `strictHtml` refuses outright and
    /// `safeHtml` refuses only JSON-looking bodies (`{`/`[`). Callers must gate
    /// on the response actually being HTML — non-HTML bodies never reach this.
    pub fn allows_injection(&self, body: &[u8]) -> bool {
        let first = body.iter().find(|b| !b.is_ascii_whitespace());
        match first {
            None | Some(b'<') => true,
            Some(b'{') | Some(b'[') => !self.has("strictHtml") && !self.has("safeHtml"),
            Some(_) => !self.has("strictHtml"),
        }
    }
}

/// One resolved operator on a rule line, e.g. `host://127.0.0.1:8080`.
#[derive(Debug, Clone, Default)]
pub struct RuleOp {
    /// Protocol name (`host`, `resHeaders`, `redirect`, …).
    pub protocol: String,
    /// Value after `protocol://` (or the shorthand's implied value).
    pub value: String,
    /// The original token as written, for diagnostics.
    pub raw: String,
    /// Properties of the line this operator was written on. Copied per operator
    /// so that resolution — which mixes operators from many lines — keeps each
    /// one's line scope.
    pub props: LineProps,
    /// Is [`value`](RuleOp::value) the **content** rather than a location?
    ///
    /// Set when a whole-value `{name}` reference was replaced by what the values
    /// store held. It is the distinction upstream draws between `rule.value` and
    /// `rule.files`: `readRuleValue` hands back `rule.value` as the body and
    /// never looks at the filesystem (`_original/lib/util/index.js:1178-1180`).
    ///
    /// Without it, `file://{mock.json}` substituted correctly and was then
    /// opened as a *path* — so the console reported "file not found" naming the
    /// JSON it was supposed to serve.
    pub value_is_content: bool,
    /// The values-store name [`value`](RuleOp::value) came from, when it came
    /// from one.
    ///
    /// It is upstream's `rule.key` (`getKey`, `_original/lib/rules/rules.js:817-820`),
    /// and the local-file family reads it as a *filename*: the content type of
    /// `file://{mock.json}` is guessed from `mock.json`, not from the request
    /// URL (`_original/lib/handlers/file-proxy.js:270-272`). A named value is
    /// the only body whose extension is written nowhere else.
    pub value_key: Option<String>,
    /// `$0`…`$9` from the pattern that matched, kept for the text the values
    /// store contributes *after* the match.
    ///
    /// Upstream substitutes captures **after** it expands values — `resolveVar`
    /// runs first and `replaceSubMatcher` second, in every branch of
    /// `resolveRuleList` (`_original/lib/rules/rules.js:957-958,:1010-1012,:1057-1058,:1084-1085`)
    /// — so a `$1` written inside a stored value reaches the operator expanded.
    /// This port expands at match time, before the store is consulted, which is
    /// the right order for the value as *written*; the groups ride along so that
    /// [`crate::proxy::apply::substitute_values`] can expand what the store
    /// hands back too.
    pub captures: Option<Vec<String>>,
    /// Has [`crate::proxy::apply::substitute_values`] already run on this
    /// operator?
    ///
    /// It runs more than once over the same resolved set — once before rules are
    /// merged in from a `rule://` or `rulesFile://` include and once after, and
    /// again after a plugin injects rules — because each merge brings operators
    /// that have never seen the values store. Upstream expands each rule's
    /// matcher exactly once (`resolveVar`, `rules.js:774-783`), and a second pass
    /// over an *already expanded* value is not a no-op: it re-reads the store
    /// content as if it were rule text, so a `${name}` or `{name}` inside a mock
    /// body gets expanded and a body that opens and closes with a backtick loses
    /// one from each end to the backtick-template test.
    pub values_substituted: bool,
    /// Where this operator sits in the resolution order — important lines first,
    /// then source order (see [`order_key`]). Stamped when a rule resolves.
    ///
    /// It exists so that the response phase can slot its operators back into the
    /// list *as if* both passes had been one walk: without it, re-resolving a
    /// rule later would move its operators to one end of the list and change
    /// which one wins. Operators merged in from another rules text sort last —
    /// see [`crate::proxy::apply::merge_rules_text`].
    pub order: u64,
}

/// The resolution-order key of the rule at `index`: important lines sort before
/// normal ones, source order within each group. Both passes derive it from the
/// same rule list, so a key means the same thing in either.
///
/// The bottom [`TOKEN_ORDER_BITS`] are left free for [`token_order`], so that
/// two operators on the *same* line still have an order between them.
pub fn order_key(index: usize, important: bool) -> u64 {
    // `+ 1` so that **zero belongs to nobody**. Operators merged in mid-request
    // are stamped `MERGED_ORDER = 0` to make them win every contest decided by
    // this key (`crate::proxy::apply::merge_resolved`), and without the shift an
    // `lineProps://important` rule on the first line would land on 0 as well.
    // The two would then tie, and `min_by_key` resolves a tie by iteration
    // order — which is a map's, not the file's. Both passes derive the key from
    // this one function, so shifting it shifts nothing relative to itself.
    ((!important as u64) << (32 + TOKEN_ORDER_BITS)) | ((index as u64 + 1) << TOKEN_ORDER_BITS)
}

/// How many low bits of an [`order_key`] belong to the operator's position on
/// its own line. 16 is more tokens than any line has.
const TOKEN_ORDER_BITS: u64 = 16;

/// Fold an operator's position on its line into its line's [`order_key`].
///
/// Upstream pushes a line's matchers onto their protocol lists in the order they
/// are written (`matchers.forEach(parseRule)`,
/// `_original/lib/rules/rules.js:1785-1789`), and several of them — `file://`,
/// `statusCode://`, `redirect://`, a bare destination, a `rule://` include —
/// share **one** list, so which of those answers a request is decided by which
/// was typed first. Without this the whole line shared one key, and the tie fell
/// to whatever order [`crate::proxy::apply::slot_winner`] happened to enumerate
/// the protocols in: `example.com file:///mock statusCode://204` served the mock
/// upstream and answered 204 here.
pub fn token_order(line: u64, at: usize) -> u64 {
    line + (at as u64).min((1 << TOKEN_ORDER_BITS) - 1)
}

/// How a rule's pattern decides whether a request matches.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// `/regexp/flags` — tested against the full request URL.
    Regex(Regex),
    /// A host wildcard (`*.example.com/api`): a regexp for the host part and an
    /// ordinary prefix for the path. See [`wildcard`].
    Wildcard(Box<wildcard::Wildcard>),
    /// Scheme/host/path prefix match (the common whistle case).
    Prefix {
        /// Restrict to this scheme (`http`/`https`/`ws`/…) if present.
        scheme: Option<String>,
        /// Exact host (lowercased). Empty means "any host".
        host: String,
        /// Leading-dot wildcard, e.g. `.example.com` matches subdomains.
        host_suffix: bool,
        /// Explicit port written in the pattern (`example.com:8080`), which
        /// scopes the rule to that port. `None` means "any port".
        port: Option<u16>,
        /// Upstream's `rule.isDomain` (`_original/lib/rules/rules.js:1343-1348`):
        /// the pattern is a host and nothing else, its query not counted. Only
        /// these are also matched against the port-stripped URL, which is what
        /// makes `example.com` apply on every port while `example.com/` does
        /// not.
        is_domain: bool,
        /// Path prefix (may be empty). A pattern that carries only a query
        /// keeps the `/` upstream's `formatUrl` puts in front of it, so this is
        /// `/?q=1` rather than `?q=1`.
        path: String,
    },
    /// `$`-prefixed: the request URL must **equal** this, not begin with it
    /// (`isExact`, `_original/lib/rules/rules.js:1265-1267`, matched at
    /// `:1070-1071` by `pattern === url || pattern === curUrl`).
    ///
    /// The stored string is normalised: a pattern with no path gets `/`, so
    /// `$example.com` names the site root and nothing else. Measured against
    /// whistle 2.10.8 — see [`Pattern::exact_matches`] for the truth table.
    Exact(String),
    /// Matches every request (bare operator lines aren't produced here, but
    /// kept for completeness / `*` patterns collapse to this when trivial).
    Any,
    /// Matches nothing: the token carried no host, path, scheme or port, so
    /// there is nothing to test. Upstream drops the rule outright; keeping it as
    /// a pattern that never matches costs one arm and keeps the parse total.
    Nothing,
}

impl Pattern {
    /// Does an exact (`$`-prefixed) pattern name this URL?
    ///
    /// Upstream compares the pattern against two forms of the request
    /// (`pattern === url || pattern === curUrl`), and the pair of them is what
    /// produces this behaviour — measured against whistle 2.10.8:
    ///
    /// ```text
    /// pattern                      /p    /p?a=1  /p?b=2  /p/s   /
    /// $http://example.test/p       HIT   HIT     HIT     -      -
    /// $http://example.test/p?a=1   -     HIT     -       -      -
    /// $example.test                -     -       -       -      HIT
    /// ```
    ///
    /// So: a pattern **without** a query matches on the path alone, a pattern
    /// **with** one must match the query too, and the scheme is optional in the
    /// pattern. A sub-path never matches, which is the whole point of `$` and
    /// what this port used to get wrong — `$example.test` matched every URL on
    /// the host rather than its root.
    fn exact_matches(pattern: &str, full_url: &str) -> bool {
        let without_query = full_url.split('?').next().unwrap_or(full_url);
        // The pattern may omit the scheme, so each form is offered with and
        // without one.
        [full_url, without_query].into_iter().any(|form| {
            let bare = form.split_once("://").map_or(form, |(_, rest)| rest);
            pattern == form || pattern == bare
        })
    }

    /// Is this a bare host pattern, with no path of its own? Upstream's
    /// `isDomain` (`_original/lib/rules/rules.js:1343-1348`) — a non-regexp,
    /// non-negated pattern whose protocol- and query-stripped form has no `/`.
    pub fn is_host_only(&self) -> bool {
        matches!(self, Pattern::Prefix { path, .. } if path.is_empty())
    }
}

/// A single parsed rule line.
#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: Pattern,
    pub ops: Vec<RuleOp>,
    pub raw_line: String,
    /// `lineProps://important` — this line outranks the ones before it.
    ///
    /// Only that spelling. A `$` pattern used to set this too, on the reading
    /// that `$` meant "important"; it does not. Measured against whistle
    /// 2.10.8, a normal rule written *before* a `$` one still wins there, so
    /// the extra precedence was this port's invention. `$` is exact matching —
    /// see [`Pattern::Exact`].
    pub important: bool,
    /// `!`-prefixed pattern: the rule applies to every request the pattern does
    /// *not* match (`NON_RE`, `_original/lib/rules/rules.js:19`; the inversion
    /// itself is at `rules.js:994-998`).
    pub negate: bool,
    /// Extra `filter`/`includeFilter`/`excludeFilter` conditions.
    pub filters: Vec<Filter>,
    /// `lineProps://…` declared on this line (also mirrored onto every op).
    pub props: LineProps,
    /// The pattern token exactly as written, `$`/`!` prefixes and all.
    ///
    /// Upstream's `rawPattern`, captured before any stripping
    /// (`_original/lib/rules/rules.js:1227`). It exists for one reader:
    /// `ignore://pattern=…`, which matches on what the user typed rather than on
    /// what it parsed to. Keeping the parsed [`Pattern`] alone would make the
    /// feature unusable — there is no way to write a `Prefix { host, port, … }`
    /// in a rules file.
    pub raw_pattern: String,
    /// Precomputed: does this line write an operator the response phase decides
    /// ([`protocols::is_res_phase`]), or an `ignore://` that could drop one?
    pub res_phase_ops: bool,
    /// Precomputed: does this line carry an `ignore://`/`skip://` naming a rule
    /// *exactly* — `pattern=…`, `matcher=…`, `operator=…`, `operation=…`?
    ///
    /// These cannot be applied where the name-based ignores are, because they
    /// drop a rule by text the resolved operator no longer carries, and they can
    /// be written on a line *below* the rule they silence. Both force a pre-scan
    /// (upstream resolves the ignore list first, `rules.js:1118-1147`), and a
    /// pre-scan over every rule on every request is not free — so the flag says
    /// whether one is needed at all. Rule sets that use none pay nothing.
    pub has_exact_skip: bool,
    /// Precomputed: might one of its filters need the response head?
    pub res_dependent: bool,
    /// Precomputed: does one of its filters read the request body (`b:`)?
    /// Upstream keeps the same fact as a separate `_bodyFilters` rule list
    /// (`_original/lib/rules/rules.js:1390-1392`), for the same reason: the body
    /// has to be buffered before resolution, and only these lines can ask.
    pub has_body_filter: bool,
    /// Precomputed: does any operator on this line write `$0`…`$9`?
    ///
    /// Only then does a match have to collect what the pattern captured, which
    /// costs ten small allocations. Upstream asks the same question per value
    /// (`SUB_MATCH_RE`, `_original/lib/rules/rules.js:947-950`); asking once per
    /// line at parse time answers it for free on the hot path, where the
    /// overwhelming majority of rules contain no `$` at all.
    pub has_capture_ref: bool,
}

impl Rule {
    /// Effective importance: whistle's `lineProps://important`, plus this port's
    /// `$`-prefix shorthand. Important rules are resolved before normal ones,
    /// per protocol — mirroring the original, which splices important rules to
    /// the front of each protocol's rule list (`_original/lib/rules/rules.js:1393`).
    pub fn is_important(&self) -> bool {
        self.important || self.props.important()
    }

    /// Could this line's effect depend on the response head?
    ///
    /// Both halves are precomputed at parse time, so the request pass pays one
    /// `bool` per rule to find out that it has nothing to do — which is the
    /// common case, and the reason the second pass costs nothing when no rule
    /// asks for it.
    ///
    /// Deliberately conservative: [`Cond::may_need_response`] over-reports where
    /// the precise answer needs the request. [`Rule::needs_response_phase`] is
    /// the exact test.
    pub fn may_need_response_phase(&self) -> bool {
        self.res_phase_ops && self.res_dependent
    }

    /// Must this line's response-phase operators wait for the response head?
    ///
    /// True when one of its filters asks about the response *and* it has
    /// something to say about the response. Those operators are then withheld
    /// from the request pass and resolved again once the head is in — which is
    /// upstream's arrangement, where the response-phase protocols are simply
    /// absent from the request pass (`reqProtocols`,
    /// `_original/lib/rules/protocols.js:156`).
    ///
    /// A line whose filters ask about the response but whose operators are all
    /// request-phase is *not* response-dependent: `host://` has to be decided
    /// before the request is sent, so upstream decides it with the status still
    /// unknown, and the condition fails closed there for good.
    pub fn needs_response_phase(&self, req: &ReqInfo) -> bool {
        self.may_need_response_phase() && self.filters.iter().any(|f| f.cond.needs_response(req))
    }
}

/// A `filter`/`includeFilter`/`excludeFilter` match condition on a rule.
///
/// Whether a set of filters lets a rule through is decided by
/// [`matcher::filters_match`], which mirrors upstream's `matchExcludeFilters`
/// (`_original/lib/rules/rules.js:1967`): include filters are **or**-ed, and any
/// matching exclude filter vetoes the rule.
#[derive(Debug, Clone)]
pub struct Filter {
    /// The rule is skipped when the condition holds. True for every filter
    /// operator except `includeFilter://` — see [`filter_excludes`].
    pub exclude: bool,
    /// A `!` written in front of the condition's value (`m:!GET`), in front of a
    /// URL pattern (`includeFilter://!*.cdn.com`), or straight after a header
    /// key (`reqH.x-tag!:v`) inverts the condition
    /// (`_original/lib/rules/rules.js:1565,1652`).
    ///
    /// It only ever inverts a *known* answer: a condition this port cannot
    /// evaluate leaves an include filter unsatisfied *and* an exclude filter
    /// inert, however it is written (`matcher::filter_holds`).
    pub negate: bool,
    pub cond: Cond,
}

/// Which message a header condition reads.
///
/// Upstream files header conditions under three property names, picked by the
/// third character of the condition's own name — `re**q**H` → `reqHeader`,
/// `re**s**H` → `resHeader`, anything else (`h`, `header`) → `header`
/// (`_original/lib/rules/rules.js:1668-1681`). Only the last of the three
/// consults both messages, and it does so in that order:
/// `filterHeader(req.headers, filter.header, req.resHeaders)` (`rules.js:1953`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderScope {
    /// `reqH.<key>:` — the request's headers, and only those.
    Request,
    /// `resH.<key>:` — the response's headers, and only those.
    Response,
    /// `h:<key>=` / `header:<key>=` — the request's headers, falling back to the
    /// response's when the request does not carry the key at all.
    RequestThenResponse,
}

/// What a [`Filter`] tests.
///
/// Conditions are evaluated to `Option<bool>`: `None` says "the fact this tests
/// is not knowable yet", which upstream's `getFilterResult`
/// (`_original/lib/rules/rules.js:1809`) collapses to `false` *without* applying
/// `not`. Everything therefore fails closed.
///
/// Several of these test facts that only exist once the response head has
/// arrived. They answer `None` in the request phase and for real in the response
/// phase — see [`ResInfo`] and [`Cond::needs_response`].
#[derive(Debug, Clone)]
pub enum Cond {
    /// `m:GET` / `method:GET` — request method (always case-insensitive).
    Method(CondValue),
    /// `host:example.com` — request host.
    Host(CondValue),
    /// `reqH.<key>:<value>` (and the `h:`/`header:`/`resH.` spellings) — a
    /// header of the request, the response, or both; see [`HeaderScope`].
    /// Upstream tests *containment*, not equality.
    Header {
        name: String,
        value: CondValue,
        scope: HeaderScope,
    },
    /// `clientIp:1.2.3.4` — the client's IP.
    ClientIp(CondValue),
    /// `i:1.2.3.4` / `ip:` — documented as client **or** server IP, but the
    /// server-IP arm is unreachable upstream: `filterProp` returns a truthy
    /// "handled" as soon as an ip filter is seen with `req.clientIp == null`,
    /// so the `req.hostIp` line below it never runs for one
    /// (`_original/lib/rules/rules.js:1824-1830,:1875-1880`). This tests the
    /// client's IP, and matches upstream by doing so.
    Ip(CondValue),
    /// `chance:0.25` / `chance:25%` — sample a fraction of requests, upstream's
    /// `Math.random() < probability` (`_original/lib/rules/rules.js:1860-1868`).
    /// A value that is not a number is stored as `NaN`, which never matches —
    /// the same coercion JS performs.
    Chance(f64),
    /// `s:404` / `statusCode:/^5/` — the response status. Response phase only.
    StatusCode(CondValue),
    /// `serverIp:1.2.3.4` — the address the request was actually sent to.
    /// Response phase only, and only when that address is known exactly.
    ServerIp(CondValue),
    /// `serverPort:8080` — the port the request was sent to. Response phase only.
    ServerPort(CondValue),
    /// `clientPort:54321` — the client socket's port.
    ClientPort(CondValue),
    /// `remoteAddress:1.2.3.4` — the client socket's address, before any
    /// forwarding header is honoured (`getRemoteAddr`, `lib/util/common.js:1738`).
    RemoteAddress(CondValue),
    /// `remotePort:54321` — the client socket's port, as above.
    RemotePort(CondValue),
    /// `b:keyword` / `body:/re/` — the request body, by containment (or by
    /// regexp). Answerable only when the body was buffered before resolution;
    /// see [`ReqInfo::req_body`].
    Body(CondValue),
    /// `env:KEY=value` — one of **whistle's own process environment**
    /// variables (`env = process.env`, `_original/lib/rules/rules.js:14`,
    /// consulted at `:1961`). Not a plugin store, despite the name: the key is
    /// case-**sensitive** and the value is compared by containment, like a
    /// header's.
    Env { name: String, value: CondValue },
    /// `from:tunnel` — where the request came from. See [`FromMarker`].
    From(FromMarker),
    /// A URL pattern, written exactly like a rule's own pattern (regexp,
    /// wildcard, or scheme/host/path prefix). This is the fallback for anything
    /// that is not a recognised condition name.
    Url(Pattern),
}

/// The origin markers `from:` accepts (`_original/lib/rules/rules.js:1834-1859`).
///
/// whistle lowercases the value at parse time (`value = value.toLowerCase()`,
/// `rules.js:1610`) and then compares it against a fixed list. One entry on that
/// list is `'internalPath'`, which no lowercased value can ever equal — the
/// branch is dead upstream, and `from:internalPath` is [`Self::Unknown`] here
/// for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromMarker {
    /// Out of an intercepted tunnel — [`ReqOrigin::tunnel`].
    Tunnel,
    /// From the Web UI's replay — [`ReqOrigin::composer`].
    Composer,
    /// The TLS handshake carried an SNI — [`ReqOrigin::sni`].
    Sni,
    /// Recognised by whistle, and a known **false** in this port: `test` needs
    /// whistle's test header, which this port neither sends nor honours, and
    /// the three server markers need the *extra* HTTP/HTTPS listeners whistle
    /// can open beside its proxy port (`config.httpPort`/`httpsPort`,
    /// `_original/lib/index.js:96-111`), which this port does not have. On a
    /// whistle started without them the answer is the same `false`, so
    /// `from:!httpserver` holds in both.
    NeverHere,
    /// Anything else. Upstream's chain ends in `return false` *before* it
    /// consults `filter.not`, so an unrecognised marker satisfies no filter
    /// however it is written — which is what [`Cond`] reports by answering
    /// "unknown".
    Unknown,
}

impl FromMarker {
    fn parse(value: &str) -> FromMarker {
        match value.to_ascii_lowercase().as_str() {
            "tunnel" => FromMarker::Tunnel,
            "composer" => FromMarker::Composer,
            "sni" => FromMarker::Sni,
            "test" | "httpserver" | "httpsserver" | "httpsport" => FromMarker::NeverHere,
            _ => FromMarker::Unknown,
        }
    }
}

impl Cond {
    /// Can this condition only be answered once the response head is in?
    ///
    /// `req` is consulted because one spelling is conditional: `h:<key>` reads
    /// the *request's* header when there is one and only then falls back to the
    /// response's, so it needs the response phase exactly when the request does
    /// not carry the key.
    ///
    /// The answer decides two things: whether the rule's response-phase
    /// operators are withheld from the request pass, and whether a second pass
    /// runs at all. It must therefore never under-report.
    pub fn needs_response(&self, req: &ReqInfo) -> bool {
        match self {
            Cond::StatusCode(_) | Cond::ServerIp(_) | Cond::ServerPort(_) => true,
            Cond::Header { name, scope, .. } => match scope {
                HeaderScope::Response => true,
                HeaderScope::Request => false,
                HeaderScope::RequestThenResponse => !req.has_header(name),
            },
            _ => false,
        }
    }

    /// [`Cond::needs_response`] without a request to consult: `true` whenever
    /// *some* request would need the response phase. Computed once at parse
    /// time, so the per-request checks can be skipped wholesale.
    pub fn may_need_response(&self) -> bool {
        matches!(
            self,
            Cond::StatusCode(_)
                | Cond::ServerIp(_)
                | Cond::ServerPort(_)
                | Cond::Header {
                    scope: HeaderScope::Response | HeaderScope::RequestThenResponse,
                    ..
                }
        )
    }
}

/// The right-hand side of a filter condition.
///
/// Any condition's value may be written as `/regexp/[i]` instead of a literal:
/// upstream funnels every one of them through `util.toRegExp`
/// (`_original/lib/util/index.js:723`), whose `REG_EXP_RE` is
/// `^/(.+)/(i?u?|ui)$`. A `/…/` that fails to compile degrades to a literal,
/// exactly like `toRegExp` returning `null`.
#[derive(Debug, Clone)]
pub enum CondValue {
    /// `/re/[i]`.
    Regex(Regex),
    /// A literal, lowercased — all literal comparisons are case-insensitive.
    Literal(String),
}

impl CondValue {
    /// Parse a condition's value. `always_ignore_case` mirrors the second
    /// argument of `util.toRegExp`, which whistle passes only for the method
    /// condition (`_original/lib/rules/rules.js:1603`).
    fn parse(raw: &str, always_ignore_case: bool) -> Self {
        Self::as_regex(raw, always_ignore_case)
            .unwrap_or_else(|| CondValue::Literal(raw.to_lowercase()))
    }

    /// `/body/flags` → a compiled regexp, or `None` when this is a literal (or
    /// a regexp Rust's engine cannot compile — JS-only constructs such as
    /// lookbehind degrade to a literal rather than dropping the rule).
    fn as_regex(raw: &str, always_ignore_case: bool) -> Option<Self> {
        let rest = raw.strip_prefix('/')?;
        let end = rest.rfind('/')?;
        let (body, flags) = (&rest[..end], &rest[end + 1..]);
        // `(.+)` — an empty body is not a regexp, and `u` is implied in Rust.
        if body.is_empty() || !matches!(flags, "" | "i" | "u" | "iu" | "ui") {
            return None;
        }
        let src = if always_ignore_case || flags.contains('i') {
            format!("(?i){body}")
        } else {
            body.to_string()
        };
        Regex::new(&src).ok().map(CondValue::Regex)
    }

    /// Scalar comparison (`m:`, `i:`, `host:`): whistle compares the whole
    /// value, so this is equality — case-insensitively, since the literal was
    /// lowercased at parse time.
    pub fn matches(&self, actual: &str) -> bool {
        match self {
            CondValue::Regex(re) => re.is_match(actual),
            CondValue::Literal(lit) => actual.eq_ignore_ascii_case(lit),
        }
    }

    /// Header comparison: upstream's `filterHeader`
    /// (`_original/lib/rules/rules.js:1922-1945`) tests **containment**, not
    /// equality — which is what makes `reqH.content-type:json` match
    /// `application/json`. An empty expected value therefore matches any value,
    /// i.e. it is a presence test.
    ///
    /// Upstream additionally compares against `encodeURIComponent(value)`; that
    /// arm is unreachable, because the haystack is lowercased while
    /// `encodeURIComponent` emits upper-case hex, so it is not ported.
    pub fn matches_header(&self, actual: &str) -> bool {
        match self {
            CondValue::Regex(re) => re.is_match(actual),
            CondValue::Literal(lit) => actual.to_lowercase().contains(lit.as_str()),
        }
    }
}

/// Parsed request facts the matcher needs. Built by the proxy layer.
#[derive(Debug, Clone, Default)]
pub struct ReqInfo {
    pub method: String,
    pub scheme: String,
    /// Lowercased host without port.
    pub host: String,
    pub port: u16,
    /// Path plus query string (starts with `/`).
    pub path: String,
    /// `scheme://host[:port]/path` used for regex/prefix matching.
    pub full_url: String,
    /// Request headers as (lowercased-name, value) pairs, for filter conditions.
    pub headers: Vec<(String, String)>,
    /// Client IP, if known, for `i:` / `clientIp:` filter conditions.
    pub client_ip: Option<String>,
    /// The client socket's port, for `clientPort:` / `remotePort:`.
    pub client_port: Option<u16>,
    /// The response head, once there is one — see [`ResInfo`]. `None` during the
    /// request phase, which is what makes every response-phase condition fail
    /// closed there.
    pub res: Option<ResInfo>,
    /// The request body, buffered **before** the rules resolved because some
    /// line carries a `b:` filter whose pattern matches this request.
    ///
    /// `None` means nothing asked for it, and a `b:` condition is then
    /// unanswerable and fails closed — upstream's state too, where `matchFilter`
    /// bails on `typeof req._reqBody !== 'string'`
    /// (`_original/lib/rules/rules.js:1903-1906`). See
    /// [`RuleManager::needs_request_body`] for who decides.
    pub req_body: Option<String>,
    /// Where the request came from, for the `from:` condition — see
    /// [`ReqOrigin`].
    pub from: ReqOrigin,
}

/// The origin markers `from:` tests (`_original/lib/rules/rules.js:1834-1859`).
///
/// whistle stamps these on the request as it arrives, so all of them are known
/// by the time rules resolve. That makes `from:` a *known* answer in both
/// directions: `from:!tunnel` holds for a request that did not come through one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReqOrigin {
    /// The request arrived inside a tunnel this proxy intercepted (CONNECT or
    /// SOCKS), rather than as a plain forward-proxy request.
    ///
    /// whistle reaches the same conclusion the long way round: after decrypting
    /// a tunnel it re-injects its own client-info header into the request bytes
    /// and feeds them back to its HTTP server (`addClientInfo`,
    /// `_original/lib/https/index.js:1203-1210`), and it is that header that
    /// sets `req.fromTunnel` (`parseClientInfo`, `lib/util/index.js:3397-3410`).
    pub tunnel: bool,
    /// The intercepted TLS handshake carried an SNI extension — whistle's
    /// `useSNI` (`checkSNI`, `_original/lib/https/index.js:1281,:1296`).
    /// False for a plain-HTTP tunnel and for a forward-proxy request.
    pub sni: bool,
    /// The request was replayed from the built-in Web UI — whistle's Composer
    /// (`FROM_COM_HEADER`, `_original/lib/util/index.js:3391-3396`).
    pub composer: bool,
}

impl ReqInfo {
    /// Does the request carry `name` at all (whatever its value)?
    fn has_header(&self, name: &str) -> bool {
        self.headers.iter().any(|(n, _)| n == name)
    }
}

/// The response facts a second resolution pass adds to [`ReqInfo`].
///
/// These live on the request rather than beside it because that is where
/// upstream puts them: `req.statusCode = _res.statusCode` and
/// `req.resHeaders = res.headers` are stamped onto the request object before the
/// response rules resolve (`_original/lib/inspectors/res.js:802-806`,
/// `lib/plugins/index.js:1323-1326`), and its `matchFilter` reads them straight
/// off `req`.
#[derive(Debug, Clone, Default)]
pub struct ResInfo {
    /// The status the origin (or a short-circuit rule) answered with.
    pub status: u16,
    /// Response headers as (lowercased-name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// The address the request was sent to, when it is known exactly —
    /// upstream's `req.hostIp`. A named origin whose address this port never saw
    /// leaves it `None`, so `serverIp:` fails closed rather than matching a
    /// second, possibly different, resolver answer.
    pub server_ip: Option<String>,
    /// The port the request was sent to — upstream's `req.serverPort`.
    pub server_port: Option<u16>,
}

/// The winning operators for a request, keyed by protocol.
///
/// A protocol lands in exactly one of the two maps, decided once by
/// [`protocols::is_multi_match`]. The accessors below hide that split: upstream
/// exposes a multi-match protocol *both* as its first match (`_rules[name]`,
/// from `getRule`) and as the full list (`rule.list`, from `getRuleList`,
/// `_original/lib/rules/rules.js:2240-2258`), so [`Resolved::get`] and
/// [`Resolved::all`] are each total over both maps rather than one map apiece.
#[derive(Debug, Default, Clone)]
pub struct Resolved {
    /// First-match-wins single-value protocols.
    pub single: HashMap<String, RuleOp>,
    /// Accumulated values for multi-match protocols (top-to-bottom order).
    pub multi: HashMap<String, Vec<RuleOp>>,
}

impl Resolved {
    /// The operator that won `protocol` — for a multi-match protocol, the first
    /// entry of its list, which is upstream's `_rules[name]`.
    pub fn get(&self, protocol: &str) -> Option<&RuleOp> {
        self.single
            .get(protocol)
            .or_else(|| self.multi.get(protocol).and_then(|list| list.first()))
    }

    /// The winning operator's value; see [`Resolved::get`].
    pub fn value(&self, protocol: &str) -> Option<&str> {
        self.get(protocol).map(|o| o.value.as_str())
    }

    /// Every operator matching `protocol`, in resolution order — important
    /// lines first, source order within a pass. A single-match protocol yields
    /// its one winner, so callers that accumulate need no special case.
    pub fn all(&self, protocol: &str) -> &[RuleOp] {
        match self.multi.get(protocol) {
            Some(list) => list,
            None => self
                .single
                .get(protocol)
                .map(std::slice::from_ref)
                .unwrap_or(&[]),
        }
    }

    /// Line properties of the winning operator for `protocol` (empty when the
    /// protocol did not match). This is how `lineProps` stays *line*-scoped
    /// after resolution: the original consults `req.rules.<protocol>.lineProps`,
    /// i.e. the properties of the line that won that protocol — never a union
    /// across lines. Consumers that walk every match read each
    /// [`RuleOp::props`] instead, since each injected value carries the
    /// properties of the line that produced it.
    pub fn props(&self, protocol: &str) -> &LineProps {
        self.get(protocol).map(|o| &o.props).unwrap_or(&NO_PROPS)
    }

    /// Shorthand for `props(protocol).has(action)`.
    pub fn has_prop(&self, protocol: &str, action: &str) -> bool {
        self.props(protocol).has(action)
    }

    /// Fold a response-phase resolution into this request-phase one.
    ///
    /// The two hold *disjoint* operators — the request pass withheld exactly
    /// what the response pass resolved (see [`Rule::needs_response_phase`]) — so
    /// this is an insertion, not a contest, and each operator goes where it
    /// would have gone had one walk produced both: by [`RuleOp::order`], which
    /// is important lines first and source order within.
    ///
    /// That differs from upstream's `mergeRule` (`lib/util/index.js:2147`),
    /// which unconditionally prefers the response pass — it can afford to,
    /// because its two passes read *different* protocols and so never hold two
    /// operators from the same rules file. Reconstructing the source order is
    /// what makes both files below behave the same, as they do upstream:
    ///
    /// ```text
    /// example.com  replaceStatus://502
    /// example.com  replaceStatus://500  includeFilter://s:404
    /// ```
    ///
    /// An operator merged in from somewhere else — a plugin's rules, a
    /// `rule://` include — carries `order == u64::MAX` and therefore stays
    /// behind everything either pass resolved, which is where the request phase
    /// already put it.
    pub fn merge_response_phase(&mut self, mut res: Resolved) {
        // Taken out first: an `ignore://` resolved in the response phase has to
        // reach what the *request* phase resolved, which the merge below — an
        // insertion of operators the request phase never saw — does not touch.
        let ignores = res.multi.remove("ignore").unwrap_or_default();
        for (protocol, op) in res.single {
            match self.single.get(&protocol) {
                Some(cur) if cur.order <= op.order => {}
                _ => {
                    self.single.insert(protocol, op);
                }
            }
        }
        for (protocol, ops) in res.multi {
            let list = self.multi.entry(protocol).or_default();
            // `ops` is already in resolution order, and the scan resumes after
            // the last insertion so operators sharing a key — two `resHeaders://`
            // on one line — keep the order they were written in.
            let mut from = 0;
            for op in ops {
                let at = list[from..]
                    .iter()
                    .position(|cur| cur.order > op.order)
                    .map_or(list.len(), |i| from + i);
                list.insert(at, op);
                from = at + 1;
            }
        }
        self.apply_response_ignores(&ignores);
    }

    /// Drop the response-phase operators an `ignore://` resolved in the response
    /// phase names.
    ///
    /// Kept apart from [`matcher::resolve_refs_scoped`]'s own ignore handling
    /// because these ignores have to reach operators the *request* pass
    /// resolved, and because they may only reach response-phase ones — which is
    /// upstream's `ignoreRules(origin, …, isResRules)` restricting itself to
    /// `resProtocols` (`_original/lib/util/index.js:2083`).
    fn apply_response_ignores(&mut self, ignores: &[RuleOp]) {
        for op in ignores {
            for name in op.value.split(['|', ',', ' ']) {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                if name == "all" {
                    self.single.retain(|k, _| !protocols::is_res_phase(k));
                    self.multi.retain(|k, _| !protocols::is_res_phase(k));
                    return;
                }
                let name = protocols::canonical(name).unwrap_or(name);
                if !protocols::is_res_phase(name) {
                    continue;
                }
                self.single.remove(name);
                self.multi.remove(name);
            }
        }
    }
}

/// A named group of rules that can be individually enabled/disabled.
#[derive(Debug, Clone)]
pub struct RuleGroup {
    /// Display name (e.g. "default", "debug-rules", "staging").
    pub name: String,
    /// Raw source text of this group.
    pub text: String,
    /// Whether this group participates in rule resolution.
    pub enabled: bool,
    /// Parsed rules from `text`.
    rules: Vec<Rule>,
    /// Values this group's own text declared in a ``` fenced block. Merged
    /// under the configured values, so a `--value` of the same name wins.
    inline_values: HashMap<String, String>,
    /// Indices into `rules` of the lines that carry response-phase operators
    /// behind a filter that asks about the response.
    ///
    /// Kept as a list rather than a flag so the response pass costs what those
    /// lines cost and not what the whole group costs: a rules file with a
    /// thousand lines and one `includeFilter://s:` walks one rule.
    res_candidates: Vec<u32>,
    /// Indices into `rules` of the lines carrying a `b:` filter — upstream's
    /// `_bodyFilters` (`_original/lib/rules/rules.js:1390-1392`). Empty for
    /// every rules file that never mentions the body, which is what lets the
    /// request path skip buffering entirely.
    body_candidates: Vec<u32>,
    /// Does any line here carry an `sniCallback://` operator?
    ///
    /// Precomputed for the same reason [`res_candidates`] is, but the stakes are
    /// higher: this one is read inside the TLS handshake of *every* intercepted
    /// connection, before a single certificate has been chosen. A rules file
    /// with no `sniCallback://` in it has to cost one `bool`, not a resolution.
    has_sni_callback: bool,
    /// Does any line here ask for a connection **not** to be intercepted —
    /// `disable://intercept`, `disable://https` or `disable://capture`?
    ///
    /// Precomputed for exactly the reason [`Self::has_sni_callback`] is, and
    /// read at the same moment: a rules file that never says so must cost one
    /// `bool` inside every TLS handshake, not a resolution.
    has_no_intercept: bool,
}

impl RuleGroup {
    /// A group whose `@` lines are ordinary text. The manager builds its groups
    /// through [`RuleGroup::unparsed`] instead, so that a group joining a rule
    /// set that *does* resolve includes is parsed once, against that set's
    /// [`include::Includes`].
    pub fn new(name: &str, text: &str, enabled: bool) -> Self {
        let mut group = RuleGroup::unparsed(name, text, enabled);
        group.reparse(&include::Includes::default());
        group
    }

    /// A group holding `text` and nothing parsed from it yet.
    fn unparsed(name: &str, text: &str, enabled: bool) -> Self {
        RuleGroup {
            name: name.to_string(),
            text: text.to_string(),
            enabled,
            rules: Vec::new(),
            inline_values: HashMap::new(),
            res_candidates: Vec::new(),
            body_candidates: Vec::new(),
            has_sni_callback: false,
            has_no_intercept: false,
        }
    }

    /// Re-parse rules from the current text.
    ///
    /// The three steps are upstream's, in upstream's order: the text's own
    /// ``` blocks are lifted out, then every `@` line is replaced by the text
    /// its source last yielded, then what is left is parsed
    /// (`addRules`, `_original/lib/rules/util.js:74-93`). Lifting first is
    /// load-bearing — see [`include::Includes::expand`].
    fn reparse(&mut self, includes: &include::Includes) {
        let (body, mut inline) = lift_inline_values(&self.text);
        let body = includes.expand(&body, &mut inline);
        self.inline_values = inline;
        self.rules = parse_text(&body);
        self.res_candidates = res_candidates(&self.rules);
        self.body_candidates = body_candidates(&self.rules);
        self.has_sni_callback = has_sni_callback(&self.rules);
        self.has_no_intercept = has_no_intercept(&self.rules);
    }

    /// Number of parsed rules in this group.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the group's text parsed to no rules at all — an empty group is
    /// still a group (it keeps its name and enabled flag), so this is not the
    /// same as the group being absent.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Which of `rules` might need the response phase — see
/// [`Rule::may_need_response_phase`] and [`RuleGroup::res_candidates`].
fn res_candidates(rules: &[Rule]) -> Vec<u32> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.may_need_response_phase())
        .map(|(i, _)| i as u32)
        .collect()
}

/// Whether any of `rules` writes an `sniCallback://` operator — see
/// [`RuleGroup::has_sni_callback`].
fn has_sni_callback(rules: &[Rule]) -> bool {
    rules
        .iter()
        .any(|rule| rule.ops.iter().any(|op| op.protocol == "sniCallback"))
}

/// Does any rule ask for a connection not to be intercepted?
///
/// The three spellings are upstream's, read together as one question
/// (`disable.intercept || disable.https || disable.capture`,
/// `_original/lib/tunnel.js:167-169`). Only the *presence* of the flag is
/// precomputed; whether it matches this connection is decided per handshake.
fn has_no_intercept(rules: &[Rule]) -> bool {
    rules.iter().any(|rule| {
        rule.ops.iter().any(|op| {
            op.protocol == "disable"
                && op
                    .value
                    .split(['|', '&'])
                    .any(|f| matches!(f.trim(), "intercept" | "https" | "capture"))
        })
    })
}

/// Which of `rules` carry a `b:` filter — see [`RuleGroup::body_candidates`].
fn body_candidates(rules: &[Rule]) -> Vec<u32> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.has_body_filter)
        .map(|(i, _)| i as u32)
        .collect()
}

/// Holds rule groups and answers match queries.
#[derive(Debug, Default)]
pub struct RuleManager {
    /// Rule groups in console order. Rules from earlier groups take precedence
    /// (first-match-wins across groups, top to bottom) — with one exception the
    /// order alone does not show: the **default group is resolved last**, so a
    /// named group overrides it. See [`RuleManager::resolution_order`].
    groups: Vec<RuleGroup>,
    /// The `@` sources this rule set's text refers to, and what each last
    /// yielded — see [`include::Includes`]. Inert unless the manager was built
    /// by [`RuleManager::with_includes`].
    includes: include::Includes,
}

impl RuleManager {
    /// A rule set whose `@` lines are ordinary text.
    ///
    /// What a `rulesFile://` or a `rule://` produces for one request wants this
    /// one: it is thrown away when the request ends, so a source it named would
    /// be registered and polled by a proxy that can never use it again.
    pub fn new() -> Self {
        RuleManager {
            groups: Vec::new(),
            includes: include::Includes::default(),
        }
    }

    /// A rule set whose `@` lines pull in the text they name, and keep it fresh.
    ///
    /// The long-lived one: what the command line loaded, what the console saves,
    /// and what came back off disk. See [`include`] for the shape of it.
    pub fn with_includes() -> Self {
        RuleManager {
            groups: Vec::new(),
            includes: include::Includes::resolving(),
        }
    }

    pub(crate) fn includes(&self) -> &include::Includes {
        &self.includes
    }

    /// Does this rule set resolve `@` lines? Answered before anything is spent
    /// on them: a proxy whose rules name no include should never start a poller.
    pub fn resolves_includes(&self) -> bool {
        self.includes.resolves()
    }

    /// Tell the include layer which port this proxy bound, for a `${port}`
    /// inside a backticked source. Called once the listening socket exists,
    /// which is the first moment it is knowable — `--port 0` asks the operating
    /// system.
    pub fn set_include_port(&mut self, port: u16) {
        if self.includes.set_port(port) {
            self.sync_includes();
            self.reparse_including_groups();
        }
    }

    /// Record what a fetch yielded for one source, re-parsing the groups that
    /// refer to it when the text changed. Returns whether anything changed.
    pub(crate) fn record_include(&mut self, target: &str, body: Option<String>) -> bool {
        if !self.includes.record(target, body) {
            return false;
        }
        self.reparse_including_groups();
        true
    }

    /// Re-register the sources every **enabled** group's text names.
    ///
    /// Upstream registers only the rules files it is about to parse, and an
    /// unselected one is not among them (`_original/lib/rules/util.js:94-100`),
    /// so a group switched off in the console stops its includes being fetched.
    fn sync_includes(&mut self) {
        if !self.includes.resolves() {
            return;
        }
        let targets: Vec<String> = self
            .groups
            .iter()
            .filter(|g| g.enabled)
            .flat_map(|g| include::targets_in(&g.text))
            .map(|target| self.includes.source_of(&target))
            .collect();
        self.includes.set_referenced(&targets);
    }

    /// Re-parse every group whose text carries an `@` line. The groups that do
    /// not are untouched, which is most of them in most setups.
    fn reparse_including_groups(&mut self) {
        let includes = &self.includes;
        for group in self.groups.iter_mut() {
            if !include::targets_in(&group.text).is_empty() {
                group.reparse(includes);
            }
        }
    }

    /// Re-register sources and re-parse `name` — what every mutation of a
    /// group's text or switch ends with.
    fn after_change(&mut self, name: &str) {
        self.sync_includes();
        let includes = &self.includes;
        if let Some(group) = self.groups.iter_mut().find(|g| g.name == name) {
            group.reparse(includes);
        }
    }

    /// Total number of parsed rules across all groups.
    pub fn len(&self) -> usize {
        self.groups.iter().map(|g| g.rules.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|g| g.rules.is_empty())
    }

    /// The current rules source text of the default group (backward compat).
    pub fn text(&self) -> &str {
        self.groups
            .iter()
            .find(|g| g.name == "default")
            .map(|g| g.text.as_str())
            .unwrap_or("")
    }

    /// Replace all rules in the default group (backward compat for UI single-text editor).
    pub fn set_text(&mut self, text: &str) {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == "default") {
            g.text = text.to_string();
        } else {
            self.groups
                .insert(0, RuleGroup::unparsed("default", text, true));
        }
        self.after_change("default");
    }

    /// Is the default group empty — i.e. did nothing on the command line or in
    /// a rules file put anything there?
    ///
    /// Read by [`crate::rules::storage::load_groups`] to decide whether a
    /// persisted default group may be restored over it.
    pub fn default_is_empty(&self) -> bool {
        self.groups
            .iter()
            .find(|g| g.name == "default")
            .is_none_or(|g| g.text.trim().is_empty())
    }

    /// Append rules parsed from `text` to the default group.
    pub fn append_text(&mut self, text: &str) {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == "default") {
            if !g.text.is_empty() && !g.text.ends_with('\n') {
                g.text.push('\n');
            }
            g.text.push_str(text);
        } else {
            self.groups
                .insert(0, RuleGroup::unparsed("default", text, true));
        }
        self.after_change("default");
    }

    /// Resolve the winning operators for a request, considering only enabled
    /// groups. Rules from earlier groups take precedence.
    pub fn resolve(&self, req: &ReqInfo) -> Resolved {
        self.resolve_scoped(req, false)
    }

    /// Like [`resolve`](Self::resolve) for a request whose origin is known, so
    /// that the `internal`/`internalOnly` line properties can be honoured. Pass
    /// `true` for requests whistle itself issues (plugin calls, internal paths).
    pub fn resolve_scoped(&self, req: &ReqInfo, is_internal_req: bool) -> Resolved {
        let rules: Vec<&Rule> = self.enabled_rules().map(|(_, rule)| rule).collect();
        matcher::resolve_refs_scoped(&rules, req, is_internal_req)
    }

    /// Resolve everything in one pass, for a rule set that gets no second one —
    /// see [`matcher::resolve_refs_once`].
    pub fn resolve_once(&self, req: &ReqInfo, is_internal_req: bool) -> Resolved {
        let rules: Vec<&Rule> = self.enabled_rules().map(|(_, rule)| rule).collect();
        matcher::resolve_refs_once(&rules, req, is_internal_req)
    }

    /// Could *any* enabled rule need a second, response-phase resolution?
    ///
    /// Answered from a flag each group precomputes when it parses, so the
    /// overwhelmingly common answer — "no rule mentions the response" — costs
    /// one comparison per group and the response pass is skipped outright.
    pub fn may_need_response_phase(&self) -> bool {
        self.groups
            .iter()
            .any(|g| g.enabled && !g.res_candidates.is_empty())
    }

    /// Could any enabled rule choose the certificate for an intercepted TLS
    /// connection (`sniCallback://`)?
    ///
    /// Read once per intercepted connection, from inside the handshake, and
    /// answered from a flag each group precomputes when it parses. The whole
    /// point is the negative answer: a rules file that never mentions
    /// `sniCallback` costs one comparison per group, and the connection then
    /// takes exactly the path it took before the hook existed. See
    /// [`crate::proxy::sni::decide`].
    pub fn has_sni_callback(&self) -> bool {
        self.groups.iter().any(|g| g.enabled && g.has_sni_callback)
    }

    /// Does any enabled group ask for connections not to be intercepted?
    /// See [`RuleGroup::has_no_intercept`].
    pub fn has_no_intercept(&self) -> bool {
        self.groups.iter().any(|g| g.enabled && g.has_no_intercept)
    }

    /// Must this request's body be buffered before the rules resolve?
    ///
    /// True when some enabled line carries a `b:` filter *and* would match this
    /// request but for that filter — upstream's `resolveBodyFilter`, which runs
    /// the same pattern test over its separate `_bodyFilters` list before the
    /// payload is read (`_original/lib/rules/rules.js:2455-2465`,
    /// `lib/inspectors/rules.js:193-205`).
    ///
    /// The two-stage shape is the whole point: buffering a request body is the
    /// one thing on this path that cannot be undone, so a rules file with no
    /// `b:` in it answers `false` after one `is_empty()` per group and the body
    /// keeps streaming. A file that does have one pays for those lines only.
    pub fn needs_request_body(&self, req: &ReqInfo, is_internal_req: bool) -> bool {
        self.groups.iter().filter(|g| g.enabled).any(|group| {
            group.body_candidates.iter().any(|&i| {
                matcher::matches_but_for_body(&group.rules[i as usize], req, is_internal_req)
            })
        })
    }

    /// Resolve the response-phase operators the request pass withheld, given a
    /// [`ReqInfo`] carrying the response head ([`ReqInfo::res`]).
    ///
    /// `None` means there was nothing to do — no rule's response-phase operators
    /// were withheld for this request — and the caller can keep the request
    /// phase's answer as it stands. See [`matcher::resolve_response_ops`] for
    /// what the pass covers and [`Resolved::merge_response_phase`] for how the
    /// two are put back together.
    ///
    /// The rules are indexed the same way [`RuleManager::resolve_scoped`]
    /// indexes them, so an operator's [`order_key`] means the same thing in
    /// either pass. Only the lines that withheld something are collected, and
    /// they are sorted rather than swept twice: a response pass over a large
    /// rules file should cost what its few conditional lines cost, not what the
    /// whole file costs.
    pub fn resolve_response(&self, req: &ReqInfo, is_internal_req: bool) -> Option<Resolved> {
        if !self.may_need_response_phase() {
            return None;
        }
        let mut candidates: Vec<(u64, &Rule)> = Vec::new();
        let mut base = 0;
        for group in self.resolution_order() {
            for &i in &group.res_candidates {
                let rule = &group.rules[i as usize];
                if rule.needs_response_phase(req) {
                    candidates.push((order_key(base + i as usize, rule.is_important()), rule));
                }
            }
            base += group.rules.len();
        }
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by_key(|(order, _)| *order);
        Some(matcher::resolve_response_ops(
            &candidates,
            req,
            is_internal_req,
        ))
    }

    /// The enabled groups in the order they are *resolved*, which is not the
    /// order they are stored in: the **default group goes last**.
    ///
    /// Upstream builds its rule list by walking every selected named group and
    /// only then appending the default one (`addRules(defaultRules, 'Default')`
    /// after the `getAllRulesFile().forEach`,
    /// `_original/lib/rules/util.js:94-101`), which is why its console lists
    /// Default at the bottom: a named group overrides it. This port resolved the
    /// default group first, so a named group could never override anything —
    /// measured against whistle 2.10.8 with two groups setting the same
    /// single-value operator, which answers with the *named* group's value there
    /// and answered with the default group's here.
    fn resolution_order(&self) -> impl Iterator<Item = &RuleGroup> {
        self.groups
            .iter()
            .filter(|g| g.enabled && g.name != "default")
            .chain(self.groups.iter().filter(|g| g.enabled && g.name == "default"))
    }

    /// Every rule of every enabled group, with its resolution index.
    ///
    /// Both passes enumerate the same sequence, so a rule keeps its index — and
    /// therefore its [`order_key`] — across them.
    fn enabled_rules(&self) -> impl Iterator<Item = (usize, &Rule)> {
        self.resolution_order().flat_map(|g| &g.rules).enumerate()
    }

    // ── Group management API ──

    /// Immutable access to all groups.
    /// Every value declared in a ``` fenced block by any **enabled** group.
    ///
    /// The proxy lays these *under* the configured values, so a `--value` or a
    /// console-edited value of the same name wins — an inline block travels with
    /// the rules file, and an explicit setting should be able to override what
    /// a file brought with it.
    pub fn inline_values(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for group in self.groups.iter().filter(|g| g.enabled) {
            out.extend(group.inline_values.clone());
        }
        out
    }

    pub fn groups(&self) -> &[RuleGroup] {
        &self.groups
    }

    /// Add a new group (appended at the end). Returns false if name already exists.
    pub fn add_group(&mut self, name: &str, text: &str, enabled: bool) -> bool {
        if self.groups.iter().any(|g| g.name == name) {
            return false;
        }
        self.groups.push(RuleGroup::unparsed(name, text, enabled));
        self.after_change(name);
        true
    }

    /// Remove a group by name. Returns true if found and removed.
    pub fn remove_group(&mut self, name: &str) -> bool {
        let before = self.groups.len();
        self.groups.retain(|g| g.name != name);
        let removed = self.groups.len() < before;
        if removed {
            // The sources only that group named are no longer referenced, and
            // stop being fetched.
            self.sync_includes();
        }
        removed
    }

    /// Toggle a group's enabled state. Returns the new state, or None if not found.
    pub fn toggle_group(&mut self, name: &str) -> Option<bool> {
        let state = self.groups.iter_mut().find(|g| g.name == name).map(|g| {
            g.enabled = !g.enabled;
            g.enabled
        })?;
        // A group switched off stops registering its sources, and switching it
        // back on re-registers them — so its text is re-parsed either way.
        self.after_change(name);
        Some(state)
    }

    /// Update a group's text. Returns false if not found.
    pub fn update_group(&mut self, name: &str, text: &str) -> bool {
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == name) {
            g.text = text.to_string();
            self.after_change(name);
            true
        } else {
            false
        }
    }

    /// Rename a group. Returns false if old name not found or new name already exists.
    pub fn rename_group(&mut self, old_name: &str, new_name: &str) -> bool {
        if self.groups.iter().any(|g| g.name == new_name) {
            return false;
        }
        if let Some(g) = self.groups.iter_mut().find(|g| g.name == old_name) {
            g.name = new_name.to_string();
            true
        } else {
            false
        }
    }
}

/// Strip a `#` comment: the `#` and everything after it, **anywhere** on the
/// line — whistle's `removeComment` (`_original/lib/util/common.js:2043`) is a
/// global `/#[^\r\n]*/g`.
///
/// Deliberately aggressive: upstream also eats a `#` inside a URL fragment, so
/// `example.com/a#b file:///x` loses `#b`. Matched rather than "improved", so a
/// rules file behaves the same in both implementations.
fn remove_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Collapse whistle's multi-line rule blocks into single lines.
///
/// ```text
/// line`
/// proxy://127.0.0.1:8080
/// www.example.com
/// api.example.com
/// `
/// ```
/// becomes `proxy://127.0.0.1:8080 www.example.com api.example.com`
/// (`MULTI_TO_ONE_RE` + `toLine`, `_original/lib/rules/rules.js:21,:369-375`).
///
/// One deviation: upstream's replacement keeps the `` line` `` opener and the
/// closing backtick in the collapsed text, where they survive as extra pattern
/// tokens that can never match. We drop them instead — same effective rules,
/// without the dead entries.
///
/// Comments are stripped *before* this runs, matching `mergeLines`; the other
/// order would change what a `#` inside a block does.
/// Split a rules text into lines the way whistle does — `LINE_END_RE`
/// (`_original/lib/rules/rules.js:44`) is `/\n|\r\n|\r/`, so a **bare carriage
/// return separates two rules**.
///
/// Rust's `str::lines()` splits on `\n` and `\r\n` and leaves a lone `\r` inside
/// the line. A rules file saved with classic Mac endings — or one line of it,
/// pasted from somewhere that used them — was therefore a *single* rule here and
/// several upstream, and the difference is silent: the tokens of the merged
/// lines are simply read as more operators on the first line's pattern. A rule
/// whose pattern sat on the second line never matched anything.
/// The alternation is ordered, so `\r\n` counts as **one** separator and a
/// doubled `\r\r\n` as two — which is what dropping the trailing `\r` before
/// splitting the rest reproduces.
fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'))
}

fn merge_lines(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut block: Option<Vec<String>> = None;
    for raw in split_lines(text) {
        let trimmed = raw.trim();
        match &mut block {
            None => {
                if trimmed == "line`" {
                    block = Some(Vec::new());
                } else {
                    out.push(raw.to_string());
                }
            }
            Some(parts) => {
                if trimmed == "`" {
                    out.push(parts.join(" "));
                    block = None;
                } else if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
            }
        }
    }
    // An unterminated block still yields its rule rather than vanishing.
    if let Some(parts) = block
        && !parts.is_empty()
    {
        out.push(parts.join(" "));
    }
    out.join("\n")
}

/// Lift ``` fenced blocks out of a rules text and into named values.
///
/// whistle calls these 内嵌值 — a rules file carrying its own mocks, so a
/// `file://{mock.json}` and the JSON it serves live in one place
/// (`resolveInlineValues`, `_original/lib/util/index.js:208-218`; the shape is
/// `MULTI_LINE_VALUE_RE` at `:98`). The outer fence below is four backticks so
/// that the three-backtick fences *inside* the example stay literal — with a
/// three-backtick outer fence rustdoc closes the block early and then compiles
/// the remaining prose as Rust.
///
/// ````text
/// ``` mock.json
/// {"ok": true}
/// ```
/// example.com file://{mock.json}
/// ````
///
/// Without this pass the fence lines were parsed as rules — three tokens that
/// configure nothing — and `{mock.json}` resolved to nothing, so the rule
/// silently served a 404.
///
/// Returns the text with the blocks removed, and the values they declared. A
/// name that appears twice keeps its **first** block, matching upstream's
/// `if (inlineValues[key] == null)`.
pub fn lift_inline_values(text: &str) -> (String, HashMap<String, String>) {
    if !text.contains("```") {
        return (text.to_string(), HashMap::new());
    }
    let mut values: HashMap<String, String> = HashMap::new();
    let mut kept: Vec<&str> = Vec::new();
    let mut lines = split_lines(text).peekable();

    while let Some(line) = lines.next() {
        // An opening fence is a run of at least three backticks and a name, and
        // nothing else. The closing fence has to be the *same* run length, so a
        // block whose content contains a shorter fence survives intact.
        let trimmed = line.trim();
        let ticks = trimmed.bytes().take_while(|b| *b == b'`').count();
        let name = trimmed[ticks..].trim();
        if ticks < 3 || name.is_empty() || name.contains(char::is_whitespace) {
            kept.push(line);
            continue;
        }

        let fence = "`".repeat(ticks);
        let mut body: Vec<&str> = Vec::new();
        let mut closed = false;
        for inner in lines.by_ref() {
            if inner.trim() == fence {
                closed = true;
                break;
            }
            body.push(inner);
        }
        // An unterminated block is not a block: put the line back as a rule line
        // rather than swallowing the rest of the file.
        if !closed {
            kept.push(line);
            kept.extend(body);
            continue;
        }
        values.entry(name.to_string()).or_insert_with(|| body.join("\n"));
    }

    (kept.join("\n"), values)
}

/// Does this operator value ask the values store for anything?
///
/// Either spelling counts: the whole-value `{name}` reference and the `${name}`
/// one that may sit anywhere inside a value (`VALUE_KEY_RE` and `VAR_RE`,
/// `_original/lib/rules/rules.js:42,:39`). Both are answered with text this
/// parser never sees, which is why the question is asked at all — see
/// [`RuleOp::captures`].
fn names_a_value(value: &str) -> bool {
    // A backtick template hides the reference from a naive test: the whole
    // value of ``reqHeaders://`{name}` `` is the template, and the `{name}` is
    // inside it.
    let inner = value
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .unwrap_or(value);
    url::is_values_key(inner) || inner.contains("${")
}

/// Parse whole rules text into a list of [`Rule`]s.
/// Mirrors `parseText` in `_original/lib/rules/rules.js:1738`.
pub fn parse_text(text: &str) -> Vec<Rule> {
    // Order matters: whistle's `mergeLines` strips comments over the whole text
    // and only then collapses `line`…`` blocks.
    let stripped: String = split_lines(text)
        .map(remove_comment)
        .collect::<Vec<_>>()
        .join("\n");
    let merged = merge_lines(&stripped);

    let mut out = Vec::new();
    for raw_line in split_lines(&merged) {
        let tokens: Vec<&str> = raw_line.split_whitespace().collect();
        if tokens.len() < 2 {
            // A lone token isn't a rule (whistle needs pattern + ≥1 operator).
            continue;
        }
        out.extend(parse_line(&tokens, raw_line));
    }
    out
}

/// Split a line's tokens into its patterns and its operators, or `None` when
/// the line has no pattern and therefore configures nothing.
///
/// Public because the console's rules editor highlights the same split, and the
/// two must not drift: what the editor paints as a pattern has to be what this
/// function calls one. A test in [`crate::proxy::webui`] runs both over the same
/// lines. (The filter and line-property tokens are *not* separated here — they
/// come out among the operators and are sorted in [`parse_line`], which is also
/// where upstream sorts them.)
pub fn split_line<'t>(tokens: &[&'t str]) -> Option<(Vec<&'t str>, Vec<&'t str>)> {
    // Where the line's pattern sits decides how the rest is read — see
    // [`index_of_pattern`]. A line with no pattern at all configures nothing,
    // which is upstream's `if (patternIndex === -1) return`.
    Some(match index_of_pattern(tokens)? {
        // `pattern op1 op2 …`: the first token is the pattern and every other
        // token is an operator, however it is shaped.
        0 => (vec![tokens[0]], tokens[1..].to_vec()),
        // `op1 … pattern1 pattern2 …`: the first token is an operator, and the
        // rest split by shape. Upstream's filter is `isPattern(p) || isHost(p)
        // || !hasProtocol(p)` — note that a bare address is a *pattern* on this
        // side of the line, where it was an operator on the other.
        _ => {
            let (mut ops, mut patterns) = (vec![tokens[0]], Vec::new());
            for tok in &tokens[1..] {
                match is_pattern_token(tok) || parse_ip_shorthand(tok).is_some() || !has_protocol(tok)
                {
                    true => patterns.push(*tok),
                    false => ops.push(*tok),
                }
            }
            (patterns, ops)
        }
    })
}

/// Is this token a filter condition rather than an operator? The console's
/// editor asks the same question to colour it.
pub fn is_filter_spelling(tok: &str) -> bool {
    is_filter_token(tok)
}

/// Parse one logical rule line into **one rule per pattern**.
///
/// whistle splits a line's tokens into patterns and operators regardless of
/// order, then produces a rule for every (operator set × pattern) pair — which
/// is what makes `host://1.1.1.1 a.com b.com` apply to *both* hosts, and what
/// the multi-line `line`…`` block relies on. Returning a single rule silently
/// dropped every pattern after the first.
fn parse_line(tokens: &[&str], raw_line: &str) -> Vec<Rule> {
    // Shorthands are expanded **before** the line is split, because expanding
    // one changes what the token *is*: `/srv/mock.json` is a bare path until it
    // becomes `file:///srv/mock.json`, and only then does the splitter know it
    // is an operator rather than the line's pattern. Upstream is explicit about
    // the order — `line.map(formatShorthand)` then `indexOfPattern(line)`
    // (`_original/lib/rules/rules.js:1766-1767`).
    let expanded: Vec<String> = tokens.iter().map(|t| format_shorthand(t)).collect();
    let tokens: Vec<&str> = expanded.iter().map(String::as_str).collect();
    let Some((pattern_toks, op_toks)) = split_line(&tokens) else {
        return Vec::new();
    };

    // Separate line properties, filter conditions and ordinary operators.
    let mut props = LineProps::default();
    let mut ops: Vec<RuleOp> = Vec::new();
    let mut filters: Vec<Filter> = Vec::new();
    for t in &op_toks {
        if let Some(spec) = line_props_spec(t) {
            props.merge(spec);
        } else if is_filter_token(t) {
            // A filter whose condition does not parse is dropped, never demoted
            // to an operator named `includeFilter`.
            filters.extend(parse_filter(t));
        } else if let Some(op) = parse_op(t) {
            ops.push(op);
        }
    }
    // `lineProps` is a modifier, not an operator: a line carrying nothing else
    // configures nothing (the original drops it the same way).
    if ops.is_empty() && filters.is_empty() {
        return Vec::new();
    }
    for op in &mut ops {
        op.props = props.clone();
    }

    // Both answers are the same for every rule this line produces, and both are
    // read on the hot path — the request pass asks each matched rule whether to
    // withhold its response-phase operators.
    let res_phase_ops = ops
        .iter()
        .any(|op| protocols::is_res_phase(&op.protocol) || op.protocol == "ignore");
    let res_dependent = filters.iter().any(|f| f.cond.may_need_response());
    let has_body_filter = filters.iter().any(|f| matches!(f.cond, Cond::Body(_)));
    // A line that names a values-store entry needs the groups too: the store's
    // content can carry its own `$1`, and upstream expands captures *after* the
    // store has answered — see [`RuleOp::captures`]. `has_reference` cannot see
    // that text, so the reference itself is what arms the collection.
    let has_capture_ref = ops
        .iter()
        .any(|op| replace::has_reference(&op.value) || names_a_value(&op.value));
    let has_exact_skip = ops
        .iter()
        .any(|op| op.protocol == "ignore" && parse_exact_skip(&op.value, is_skip_token(&op.raw)).is_some());

    pattern_toks
        .into_iter()
        .filter_map(|tok| {
            let parsed = parse_pattern(tok)?;
            Some(Rule {
                pattern: parsed.pattern,
                ops: ops.clone(),
                raw_line: raw_line.to_string(),
                important: props.important(),
                negate: parsed.negate,
                filters: filters.clone(),
                props: props.clone(),
                // As written, before `parse_pattern` strips `$`/`!` — upstream
                // captures `rawPattern` at the same point.
                raw_pattern: tok.to_string(),
                res_phase_ops,
                res_dependent,
                has_body_filter,
                has_capture_ref,
                has_exact_skip,
            })
        })
        .collect()
}

/// Which text an `ignore://`/`skip://` names a rule by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactSkip {
    /// `pattern=…` — the pattern token as written ([`Rule::raw_pattern`]).
    Pattern,
    /// `matcher=…`, `operator=…`, `operation=…` — the operator token.
    Matcher,
}

/// Read the exact form out of an `ignore://`/`skip://` value.
///
/// Upstream's two regexps (`_original/lib/rules/rules.js:94-98`):
///
/// ```text
/// EXACT_SKIP_RE = /^(pattern|matcher|operator|operation)[=:](.+)$/
/// NO_PROTO_RE   = /[^\w!*|.-]/
/// ```
///
/// Three of the four keys mean the same thing: only `pattern` selects the
/// pattern, and `matcher`/`operator`/`operation` all select the operator
/// (`rules.js:1133`). A value that matches neither regexp is not an exact form
/// at all — it is a list of protocol names, which this port already handles by
/// folding `skip` onto `ignore` ([`protocols::canonical`]).
///
/// The `NO_PROTO_RE` branch is the subtle one, in two ways.
///
/// It takes a value carrying any character a protocol name could not contain
/// *whole* as a matcher — and it belongs to `skip://` **only**. Plain
/// `ignore://` is read by `EXACT_IGNORE_RE`, which demands one of the four
/// keys (`rules.js:1142`), so `ignore://host&ua` is a two-name list while
/// `skip://host&ua` is a matcher. This port folds `skip` onto `ignore` in
/// [`protocols::canonical`], which loses that distinction; `from_skip` carries
/// it back, read off the token as written. Getting this wrong is not
/// theoretical — it broke `ignore://host&ua` in this very change, and the test
/// that caught it was already there.
///
/// Second, upstream writes the branch reading `RegExp.$1`/`$2`, which belong to
/// whichever regexp last matched — so its answer looks like it could depend on
/// the preceding rule. It does not: `NO_PROTO_RE` has no capture groups and a
/// successful `test` clears both, which lands every such value on
/// `matcher=<whole value>`. Confirmed by running upstream's own branch over
/// this port's cases in node rather than by reading it, because a stale-capture
/// bug would have been invisible to reading.
pub fn parse_exact_skip(value: &str, from_skip: bool) -> Option<(ExactSkip, String)> {
    if let Some(at) = value.find(['=', ':']) {
        let (key, rest) = value.split_at(at);
        let rest = &rest[1..];
        if !rest.is_empty() {
            match key {
                "pattern" => return Some((ExactSkip::Pattern, rest.to_string())),
                "matcher" | "operator" | "operation" => {
                    return Some((ExactSkip::Matcher, rest.to_string()));
                }
                _ => {}
            }
        }
    }
    // Not one of the four keys, so `NO_PROTO_RE` decides — and only for
    // `skip://`, which is what `from_skip` is for.
    (from_skip && has_non_protocol_char(value))
        .then(|| (ExactSkip::Matcher, value.to_string()))
}

/// Was this operator written `skip://` rather than `ignore://`?
///
/// The two are one protocol here ([`protocols::canonical`] folds them), but they
/// read their value differently — see [`parse_exact_skip`]. The token as written
/// is the only place the difference survives.
pub fn is_skip_token(raw: &str) -> bool {
    raw.starts_with("skip://")
}

/// Upstream's `NO_PROTO_RE`: is there a character no protocol name could carry?
fn has_non_protocol_char(value: &str) -> bool {
    value
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '!' | '*' | '|' | '.' | '-')))
}

/// The `lineProps://…` payload of `tok`, if it declares line properties.
///
/// Also recognises the two legacy spellings `includeFilter://safeHtml` and
/// `includeFilter://strictHtml`, which the original rewrites to `lineProps://`
/// before parsing (`formatShorthand`, `_original/lib/rules/rules.js:224`).
fn line_props_spec(tok: &str) -> Option<&str> {
    if let Some(spec) = tok.strip_prefix("lineProps://") {
        return Some(spec);
    }
    match tok {
        "includeFilter://safeHtml" => Some("safeHtml"),
        "includeFilter://strictHtml" => Some("strictHtml"),
        _ => None,
    }
}

/// What a condition prefix builds, before its value has been parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondKind {
    Method,
    Host,
    Ip,
    ClientIp,
    ServerIp,
    ClientPort,
    ServerPort,
    RemoteAddress,
    RemotePort,
    StatusCode,
    /// A header condition, in one of the three scopes upstream distinguishes.
    Header(HeaderScope),
    Chance,
    /// `b:` / `body:` — the request body.
    Body,
    /// `env:` — one of whistle's own process environment variables.
    Env,
    /// `from:` — one of whistle's origin markers.
    From,
}

/// Every condition spelling whistle understands: `(name, kind, props, pure)`.
///
/// Upstream splits them across two regexes
/// (`_original/lib/rules/rules.js:57-60`):
///
/// * `PROPS_FILTER_RE` — `<name>:<value>`, after any of
///   `filter`/`includeFilter`/`excludeFilter`/`ignore` (the `props` column);
/// * `PURE_FILTER_RE` — `<name>.<value>` or `<name>=<value>`, after
///   `includeFilter`/`excludeFilter` only, for a slightly different name set
///   (the `pure` column).
///
/// The distinction is worth keeping: a spelling upstream does *not* recognise
/// falls through to its URL-pattern branch and matches nothing, so accepting
/// more here would make rules fire that upstream leaves inert.
///
/// Order does not matter — a name only wins if the character right after it is
/// a separator that name allows, so `host` can never be read as `h`.
const COND_SPECS: &[(&str, CondKind, bool, bool)] = &[
    ("m", CondKind::Method, true, false),
    ("method", CondKind::Method, true, false),
    ("i", CondKind::Ip, true, false),
    ("ip", CondKind::Ip, true, false),
    // `h`/`header` are upstream's `filter.header`, the one header spelling that
    // reads the response too — see [`HeaderScope`].
    ("h", CondKind::Header(HeaderScope::RequestThenResponse), true, false),
    ("header", CondKind::Header(HeaderScope::RequestThenResponse), true, false),
    // `host:` is this port's own spelling (upstream has only the pure form, and
    // routes it to proxy-host filtering rather than to the request's host).
    ("host", CondKind::Host, true, true),
    ("clientIp", CondKind::ClientIp, true, true),
    ("clientIP", CondKind::ClientIp, true, true),
    ("req", CondKind::Header(HeaderScope::Request), true, true),
    ("reqH", CondKind::Header(HeaderScope::Request), true, true),
    ("reqHeader", CondKind::Header(HeaderScope::Request), true, true),
    ("reqHeaders", CondKind::Header(HeaderScope::Request), true, true),
    ("chance", CondKind::Chance, true, true),
    ("probability", CondKind::Chance, true, true),
    ("s", CondKind::StatusCode, true, false),
    ("statusCode", CondKind::StatusCode, true, true),
    ("b", CondKind::Body, true, false),
    ("body", CondKind::Body, true, false),
    ("res", CondKind::Header(HeaderScope::Response), true, true),
    ("resH", CondKind::Header(HeaderScope::Response), true, true),
    ("resHeader", CondKind::Header(HeaderScope::Response), true, true),
    ("resHeaders", CondKind::Header(HeaderScope::Response), true, true),
    ("serverIp", CondKind::ServerIp, true, true),
    ("serverIP", CondKind::ServerIp, true, true),
    ("clientPort", CondKind::ClientPort, true, true),
    ("serverPort", CondKind::ServerPort, true, true),
    ("remoteAddress", CondKind::RemoteAddress, true, true),
    ("remotePort", CondKind::RemotePort, true, true),
    ("env", CondKind::Env, true, true),
    ("from", CondKind::From, true, true),
];

/// `Some(pure_ok)` when `proto` is one of the four filter operators, where
/// `pure_ok` says whether it also takes the `.`/`=` separated *pure* forms.
///
/// The two spellings that do are `includeFilter` and `excludeFilter`, the only
/// two `PURE_FILTER_RE` names (`_original/lib/rules/rules.js:59`) — and the same
/// two whose URL branch differs from `filter://`'s, so one flag settles both.
///
/// Which of the four *include* is a separate question, and only
/// `includeFilter://` does: whistle decides with `isInclude = matcher[1] === 'n'`
/// (`rules.js:1563`), true for i**n**cludeFilter alone — `filter://` yields `'i'`
/// and `ignore://` yields `'g'`, so both are *exclude* filters. This port used to
/// read `filter://` as an include, which did not merely fail on a whistle rules
/// file: it did the opposite of what the file asked, silently.
fn filter_pure_form(proto: &str) -> Option<bool> {
    match proto {
        "includeFilter" | "excludeFilter" => Some(true),
        "filter" | "ignore" => Some(false),
        _ => None,
    }
}

/// `PATTERN_FILTER_RE` — `^(?:filter|ignore)://(.+)/(i)?$`, split into the
/// expression and whether it carried the `i` flag.
///
/// The `(.+)` is greedy, so a payload that ends in `/` keeps everything before
/// that last slash and takes no flag; only when it does not is the trailing `i`
/// read as one. `filter://a/i/` is therefore the expression `a/i`, and
/// `filter://a/i` the expression `a`, case-insensitively.
fn pattern_filter_split(spec: &str) -> Option<(&str, bool)> {
    if let Some(body) = spec.strip_suffix('/')
        && !body.is_empty()
    {
        return Some((body, false));
    }
    let body = spec.strip_suffix("/i")?;
    (!body.is_empty()).then_some((body, true))
}

/// `PATTERN_WILD_FILTER_RE` — `^(?:filter|ignore)://(!)?(\*+/)`, returning the
/// payload with its `!` stripped and whether it carried one.
fn wild_filter_split(spec: &str) -> Option<(&str, bool)> {
    let (negate, body) = strip_negation(spec);
    let stars = body.bytes().take_while(|b| *b == b'*').count();
    (stars > 0 && body[stars..].starts_with('/')).then_some((body, negate))
}

/// Does a `filter://`/`ignore://` payload name a URL, rather than protocols to
/// suppress? True for exactly the two shapes those two spellings accept.
fn is_url_filter_payload(spec: &str) -> bool {
    pattern_filter_split(spec).is_some() || wild_filter_split(spec).is_some()
}

/// Compile a filter's URL expression, which upstream rebuilds as
/// `'/' + body + '/' + (caseIns ? 'i' : '')` (`_original/lib/rules/rules.js:1712`).
///
/// That rebuild is why a `/re/u` is case-**in**sensitive here: upstream tests
/// the captured flags for truthiness, not for `i`.
fn compile_url_regexp(body: &str, ignore_case: bool) -> Option<Regex> {
    if body.is_empty() {
        return None;
    }
    let src = match ignore_case {
        true => format!("(?i){body}"),
        false => body.to_string(),
    };
    Regex::new(&src).ok()
}

/// The URL filter that `filter://` and `ignore://` share — the first and third
/// branches of `resolveFilterPattern` (`_original/lib/rules/rules.js:1469-1514`).
///
/// A payload ending `/` or `/i` is a **regexp**, after an optional `!` and an
/// optional leading `/`; one beginning `*/` is a wildcard URL. This port read
/// both through the wildcard compiler, so `filter:///echo$/` — the form the
/// documentation leads with — silenced nothing.
fn parse_pattern_url_filter(spec: &str) -> Option<(Cond, bool)> {
    let (body, negate) = match pattern_filter_split(spec) {
        Some((body, case_ins)) => {
            let (negate, body) = strip_negation(body);
            // `filter:///re/` and `filter://re/` are the same expression: one
            // leading slash is the delimiter, and is dropped (`rules.js:1478`).
            let body = body.strip_prefix('/').unwrap_or(body);
            let re = compile_url_regexp(body, case_ins)?;
            return Some((Cond::Url(Pattern::Regex(re)), negate));
        }
        None => wild_filter_split(spec)?,
    };
    let re = wildcard::parse_filter(body)?;
    Some((Cond::Url(Pattern::Regex(re)), negate))
}

/// The URL filter `includeFilter://` and `excludeFilter://` take — the second
/// branch of `resolveFilterPattern` (`_original/lib/rules/rules.js:1487-1511`).
///
/// Their `/re/` spelling is `util.isRegExp`, which allows the `u` flag the
/// `filter://` form does not; everything else is the wildcard compiler.
fn parse_url_filter(spec: &str) -> Option<(Cond, bool)> {
    // Only here may a `!` precede the payload: with a condition name present it
    // belongs to the value, so `includeFilter://!m:GET` is a (negated) URL
    // pattern upstream, not a method condition.
    let (negate, body) = strip_negation(spec);
    if let Some(rest) = body.strip_prefix('/')
        && let Some(end) = rest.rfind('/')
        && matches!(&rest[end + 1..], "" | "i" | "u" | "iu" | "ui")
        && let Some(re) = compile_url_regexp(&rest[..end], end + 1 < rest.len())
    {
        return Some((Cond::Url(Pattern::Regex(re)), negate));
    }
    // Anything else is a URL pattern — compiled the way *filters* are, which is
    // not the way a rule's own pattern is: every filter is read as if it carried
    // a `^`, so its stars wildcard the path too ([`wildcard::parse_filter`]).
    let re = wildcard::parse_filter(body)?;
    Some((Cond::Url(Pattern::Regex(re)), negate))
}

/// Is this token a filter condition (as opposed to an operator or a pattern)?
///
/// Used by [`parse_line`] so that a filter whose condition does not parse is
/// dropped instead of degrading into an operator named `includeFilter`.
fn is_filter_token(tok: &str) -> bool {
    let Some((proto, spec)) = split_protocol(tok) else {
        return false;
    };
    let Some(pure_ok) = filter_pure_form(proto) else {
        return false;
    };
    // The `filter://`/`ignore://` that names protocols is an operator, not a
    // filter — see [`parse_filter`]. Reporting it as a filter here would drop
    // it, since `parse_filter` refuses it. Brackets come off first, exactly as
    // they do there and in upstream's `INLINE_RE` pass.
    let spec = strip_inline_brackets(spec);
    pure_ok || is_url_filter_payload(spec) || split_cond_name(spec, false).is_some()
}

/// A condition may be written inside brackets, which whistle strips before
/// parsing (`INLINE_RE`, `_original/lib/rules/rules.js:62,:1549-1551`). The form
/// exists so a condition containing characters that would otherwise end the
/// token can be written at all. Unstripped, the payload fell through to the
/// URL-pattern branch and could never hold, so an `includeFilter://(m:GET)`
/// meant the rule never applied — silently.
fn strip_inline_brackets(spec: &str) -> &str {
    match (spec.starts_with('(') && spec.ends_with(')'))
        || (spec.starts_with('<') && spec.ends_with('>'))
    {
        true if spec.len() > 1 => &spec[1..spec.len() - 1],
        _ => spec,
    }
}

/// Parse a `filter://` / `includeFilter://` / `excludeFilter://` / `ignore://`
/// token.
///
/// Returns `None` for a token that is not a filter at all, and for one whose
/// condition is unusable (an empty payload, a header key of only `!`, an `i:`
/// that is neither an address nor a regexp) — upstream drops those too
/// (`resolveMatchFilter`, `_original/lib/rules/rules.js:1556`).
fn parse_filter(tok: &str) -> Option<Filter> {
    let (proto, spec) = split_protocol(tok)?;
    let pure_ok = filter_pure_form(proto)?;
    let spec = strip_inline_brackets(spec);
    let (cond, negate) = match split_cond_name(spec, pure_ok) {
        Some((kind, rest)) => build_cond(kind, rest)?,
        // `filter://` and `ignore://` are two operators wearing one name, and
        // read a URL differently from the other two besides. A payload that is
        // neither a named condition nor one of their two URL shapes is the
        // *other* operator: a value naming protocols to suppress, folded into
        // the ignore set (`resolveFilter`, `rules.js:2188-2196`). This port
        // treated every payload as a URL filter, so `filter://host` excluded
        // nothing and the `host://` it was written to suppress went on applying.
        None if !pure_ok => parse_pattern_url_filter(spec)?,
        // whistle drops these two before it reads the payload at all
        // (`rules.js:1489-1491`), which leaves the *line* unfiltered.
        None if spec.is_empty() || spec == "!" => return None,
        None => parse_url_filter(spec)?,
    };
    Some(Filter {
        exclude: proto != "includeFilter",
        negate,
        cond,
    })
}

/// Split `<name><sep><rest>` when `<name>` is a known condition and `<sep>` is a
/// separator that name accepts.
///
/// `<rest>` must not be empty: both of upstream's condition regexes end `(.+)`
/// (`_original/lib/rules/rules.js:57-60`), so `includeFilter://reqH.` is not a
/// header condition at all — it falls through to the URL branch and becomes a
/// pattern that cannot match. Accepting it here dropped the filter instead, and
/// a dropped include filter leaves the line applying to everything.
fn split_cond_name(spec: &str, pure_ok: bool) -> Option<(CondKind, &str)> {
    for &(name, kind, props, pure) in COND_SPECS {
        let Some(rest) = spec.strip_prefix(name) else {
            continue;
        };
        let sep = rest.as_bytes().first()?;
        let accepted = match sep {
            b':' => props,
            b'.' | b'=' => pure && pure_ok,
            _ => false,
        };
        if accepted && rest.len() > 1 {
            return Some((kind, &rest[1..]));
        }
    }
    None
}

/// `!value` → negated. Upstream folds the flag with `not = !not`, so a token can
/// carry it in more than one place (`_original/lib/rules/rules.js:1565`).
fn strip_negation(value: &str) -> (bool, &str) {
    match value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, value),
    }
}

/// The value of an `i:`/`ip:`/`clientIp:`/`serverIp:` condition, or `None` when
/// it is neither a regexp nor a literal address.
///
/// Upstream drops the *whole filter* for one that is neither
/// (`net.isIP`, `_original/lib/rules/rules.js:1592-1594`), which is not the same
/// as a condition that never holds: a dropped include filter leaves the line
/// applying to everything, where a never-holding one would stop it. `i:localhost`
/// is the spelling this catches, and it silently disabled the line here.
fn address_value(rest: &str) -> Option<CondValue> {
    match CondValue::parse(rest, false) {
        CondValue::Literal(lit) if lit.parse::<std::net::IpAddr>().is_err() => None,
        value => Some(value),
    }
}

/// Build the condition for `kind` from everything after its separator.
fn build_cond(kind: CondKind, rest: &str) -> Option<(Cond, bool)> {
    let (negate, rest) = strip_negation(rest);
    let cond = match kind {
        // whistle compiles method regexps with a forced `i` flag.
        CondKind::Method => Cond::Method(CondValue::parse(rest, true)),
        CondKind::Host => Cond::Host(CondValue::parse(rest, false)),
        CondKind::Ip => Cond::Ip(address_value(rest)?),
        CondKind::ClientIp => Cond::ClientIp(address_value(rest)?),
        CondKind::ServerIp => Cond::ServerIp(address_value(rest)?),
        CondKind::ClientPort => Cond::ClientPort(CondValue::parse(rest, false)),
        CondKind::ServerPort => Cond::ServerPort(CondValue::parse(rest, false)),
        CondKind::RemoteAddress => Cond::RemoteAddress(CondValue::parse(rest, false)),
        CondKind::RemotePort => Cond::RemotePort(CondValue::parse(rest, false)),
        CondKind::StatusCode => Cond::StatusCode(CondValue::parse(rest, false)),
        CondKind::Header(scope) => {
            let (key, key_negate, value) = split_keyed_value(rest, true)?;
            return Some((
                Cond::Header {
                    name: key.to_lowercase(),
                    value: CondValue::parse(value, false),
                    scope,
                },
                negate != key_negate,
            ));
        }
        CondKind::Chance => {
            let (key, key_negate, _) = split_keyed_value(rest, false)?;
            return Some((Cond::Chance(parse_probability(key)), negate != key_negate));
        }
        CondKind::Body => Cond::Body(CondValue::parse(rest, false)),
        // `env` takes the same shape as a header condition but is *not* one:
        // `isHeader` is false for it upstream, so the key keeps its case and
        // only `=` separates it (`_original/lib/rules/rules.js:1648-1653`).
        CondKind::Env => {
            let (key, key_negate, value) = split_keyed_value(rest, false)?;
            return Some((
                Cond::Env {
                    name: key.to_string(),
                    value: CondValue::parse(value, false),
                },
                negate != key_negate,
            ));
        }
        // The value is a bare word, not a pattern: whistle lowercases it and
        // compares it against a fixed list (`_original/lib/rules/rules.js:1608-1611`),
        // so `/re/` is not accepted here as it is elsewhere.
        CondKind::From => Cond::From(FromMarker::parse(rest)),
    };
    Some((cond, negate))
}

/// Split a keyed condition (`<key>=<value>`, or `<key>:<value>` for headers)
/// into its key, whether the key carried a trailing `!`, and its value.
///
/// Upstream looks for `=` first and only falls back to `:` for header-shaped
/// conditions, which is why `chance:50%` keeps its `%` and why
/// `reqH.referer:http://x` splits at the *first* colon
/// (`_original/lib/rules/rules.js:1645-1660`). A key left empty by its `!`
/// drops the whole filter.
///
/// A key that was empty to begin with does **not**: upstream checks emptiness
/// only inside the `!` arm (`rules.js:1657`), so `includeFilter://reqH.=v` keeps
/// a condition that asks for a header named `""` and never finds one. Dropping
/// it here left the line with no include filter, and so applying to everything.
fn split_keyed_value(rest: &str, colon_separates: bool) -> Option<(&str, bool, &str)> {
    let sep = rest
        .find('=')
        .or_else(|| if colon_separates { rest.find(':') } else { None });
    let (key, value) = match sep {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    match key.strip_suffix('!') {
        Some("") => None,
        Some(k) => Some((k, true, value)),
        None => Some((key, false, value)),
    }
}

/// `chance:0.25` / `chance:25%` → the probability to sample at.
///
/// A value JS would coerce to `NaN` stays `NaN` here, so the comparison against
/// a random number is false however it is written — including for a bare `%`,
/// which upstream's length check also leaves alone.
fn parse_probability(key: &str) -> f64 {
    let parsed = match key.strip_suffix('%') {
        Some(n) => n.parse::<f64>().map(|v| v / 100.0),
        None => key.parse::<f64>(),
    };
    parsed.unwrap_or(f64::NAN)
}

/// Expand a token's shorthand into the operator it stands for — `formatShorthand`
/// (`_original/lib/rules/rules.js:219-260`).
///
/// whistle lets several kinds of operator be written without their protocol, and
/// normalises them all before it decides which token on the line is the pattern.
/// Running this first is the whole point: until `/srv/mock.json` has become
/// `file:///srv/mock.json` it has no protocol, and a token with no protocol is
/// what [`index_of_pattern`] takes for the line's pattern. So an operator-first
/// line naming a mock — `/srv/mock.json  www.example.com  api.example.com` —
/// used to classify the *path* as the pattern and both domains as destinations.
///
/// Returns an owned string because most tokens are unchanged and a `Cow` would
/// buy one allocation per line at parse time, which is not on any hot path.
fn format_shorthand(tok: &str) -> String {
    // `//host/path` is scheme-relative — a pattern, and left alone.
    if tok.starts_with("//") && !tok.starts_with("///") {
        return tok.to_string();
    }
    // Two filter spellings whistle rewrites into line properties.
    match tok {
        "includeFilter://safeHtml" => return "lineProps://safeHtml".to_string(),
        "includeFilter://strictHtml" => return "lineProps://strictHtml".to_string(),
        _ => {}
    }
    // `{key}`, `<path>`, `(value)` and the empty object all name file content.
    if tok == "{}" || is_wrapped(tok, '{', '}') || is_wrapped(tok, '<', '>') || is_wrapped(tok, '(', ')')
    {
        return format!("file://{tok}");
    }
    // A filesystem path: `/x`, `C:\x`, `C:/x` — but not a `/regexp/`.
    if (tok == "/" || is_file_path(tok)) && !is_regexp_token(tok) {
        return format!("file://{tok}");
    }
    // Chrome pastes a Windows path as `file:///C:/…`; whistle keeps the drive.
    if let Some(rest) = tok.strip_prefix("file:///")
        && rest.len() > 2
        && rest.as_bytes()[0].is_ascii_uppercase()
        && rest[1..].starts_with(":/")
    {
        return format!("file://{rest}");
    }
    // `@name` includes another rules source; whistle files it under `G`.
    if let Some(rest) = tok.strip_prefix('@') {
        let body = match tok.contains("@://") {
            true => rest.to_string(),
            false => format!("://{rest}"),
        };
        return format!("G{body}");
    }
    tok.to_string()
}

/// `FILE_RE` (`_original/lib/rules/rules.js:36`) — `/^(?:[a-z]:(?:\\|\/[^/])|\/[^/])/i`:
/// a drive letter followed by a separator, or a single leading slash.
fn is_file_path(tok: &str) -> bool {
    let bytes = tok.as_bytes();
    if let Some(rest) = tok.strip_prefix('/') {
        return !rest.starts_with('/');
    }
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return match bytes[2] {
            b'\\' => true,
            b'/' => bytes.get(3).is_some_and(|c| *c != b'/'),
            _ => false,
        };
    }
    false
}

/// Is `tok` wrapped in this pair of brackets, with something between them?
fn is_wrapped(tok: &str, open: char, close: char) -> bool {
    tok.len() > 1 && tok.starts_with(open) && tok.ends_with(close)
}

/// Does this token *look like* a pattern on its own — whistle's `isPattern`
/// (`_original/lib/rules/rules.js:1403-1412`)?
///
/// "On its own" is the whole point: the answer decides nothing by itself, it
/// only feeds [`index_of_pattern`], which is what actually splits a line. A
/// token can be a pattern here and an operator on the line — `http://a.com` is a
/// pattern when it comes first and a URL-replacement operator when it does not.
fn is_pattern_token(tok: &str) -> bool {
    // `!`-negated, `$`-exact, and `:8080` port patterns.
    if tok.starts_with('!') || tok.starts_with('$') || port_pattern(tok).is_some() {
        return true;
    }
    // `//host/path` — a scheme-relative pattern.
    if let Some(rest) = tok.strip_prefix("//")
        && !rest.starts_with('/')
    {
        return true;
    }
    // A web-protocol URL, and a `/regexp/` — both unambiguous.
    if web_protocol(tok).is_some() || is_regexp_token(tok) {
        return true;
    }
    // A `^`-prefixed wildcard URL (upstream's `isRegUrl`).
    tok.starts_with('^')
}

/// The scheme of a token written with one of the four request schemes whistle
/// recognises plus `tunnel` (`WEB_PROTOCOL_RE`, `_original/lib/rules/rules.js:22`).
fn web_protocol(tok: &str) -> Option<&str> {
    let (proto, _) = split_protocol(tok)?;
    matches!(proto, "http" | "https" | "ws" | "wss" | "tunnel").then_some(proto)
}

/// A `/body/flags` regexp token — `isRegExp`
/// (`REG_EXP_RE = /^\/(.+)\/(i?u?|ui)$/`, `_original/lib/util/index.js:603-607`).
///
/// The flag set is closed, and that matters: this test used to accept anything
/// with a second slash, so a **file path** like `/Users/me/mock.json` read as a
/// regexp. Combined with [`format_shorthand`] not existing, an operator-first
/// line naming a mock file compiled the path into an unanchored pattern and
/// promoted the line's real patterns to destinations.
fn is_regexp_token(tok: &str) -> bool {
    let Some(rest) = tok.strip_prefix('/') else {
        return false;
    };
    let Some(end) = rest.rfind('/') else {
        return false;
    };
    // `(.+)` — the body may not be empty.
    end > 0 && matches!(&rest[end + 1..], "" | "i" | "u" | "iu" | "ui")
}

/// whistle's `hasProtocol` — `/^[a-zA-Z0-9.-]+:\/\//`
/// (`_original/lib/util/common.js:491-493`). Deliberately laxer than
/// [`protocols::is_protocol`]: an operator whose protocol whistle does not know
/// is still an operator (a URL-replacement rule), not a pattern.
fn has_protocol(tok: &str) -> bool {
    let Some((proto, _)) = split_protocol(tok) else {
        return false;
    };
    !proto.is_empty()
        && proto
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Where the pattern starts on a rule line — upstream's `indexOfPattern`
/// (`_original/lib/rules/rules.js:1449-1466`).
///
/// `0` means the ordinary form (`pattern op1 op2 …`), in which **every**
/// remaining token is an operator whatever its shape; anything else means the
/// swapped form (`op pattern1 pattern2 …`) whistle also accepts. `None` means
/// the line has no pattern and configures nothing.
///
/// The distinction is load-bearing rather than cosmetic. `example.com
/// http://localhost:5173` — the forwarding rule whistle's own getting-started
/// guide leads with — only works because the second token is an operator *by
/// position*: judged on its own shape it reads as a URL pattern, and this port
/// used to classify both tokens as patterns and drop the line entirely.
fn index_of_pattern(tokens: &[&str]) -> Option<usize> {
    let mut ip_index = None;
    for (i, tok) in tokens.iter().enumerate() {
        if is_pattern_token(tok) {
            return Some(i);
        }
        if !has_protocol(tok) {
            // A bare address is an operator (the hosts shorthand); anything else
            // without a protocol can only be a pattern.
            if parse_ip_shorthand(tok).is_none() {
                return Some(i);
            }
            if ip_index.is_none() {
                ip_index = Some(i);
            }
        }
    }
    ip_index
}

/// The plugin a `whistle.<name>` / `plugin.<name>` protocol names.
///
/// `PLUGIN_RE`'s name class (`_original/lib/rules/rules.js:24`) is
/// `[a-z\d_\-]+` — deliberately narrow, so an ordinary dotted hostname written
/// as a protocol cannot be mistaken for a plugin.
fn plugin_package(proto: &str) -> Option<&str> {
    let name = proto
        .strip_prefix("whistle.")
        .or_else(|| proto.strip_prefix("plugin."))?;
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    ok.then_some(name)
}

/// Split `proto://rest` → `(proto, rest)`.
fn split_protocol(tok: &str) -> Option<(&str, &str)> {
    tok.find("://").map(|i| (&tok[..i], &tok[i + 3..]))
}

/// Recognise whistle's bare-address operator — `parseHost`
/// (`_original/lib/rules/rules.js:1418-1440`) — returning the address and the
/// port written beside it, if any.
///
/// The address has to be an **IP literal**: `net.isIP` is the whole test, so
/// `127.0.0.1:8080` is this shorthand while `localhost:8080` is not. That is not
/// a detail — a name with a port falls through to a URL-replacement rule
/// upstream, which rewrites the `Host` header where `host://` would have
/// preserved it. This port used to accept any `name:port` here and quietly gave
/// the two forms the same meaning.
///
/// The two accepted spellings beyond a bare literal are upstream's: a bracketed
/// IPv6 address with an optional port, and an IPv4 address (optionally
/// v4-mapped) with an optional port. A v4-mapped address is reported unmapped,
/// as upstream reports its `RegExp.$1`.
fn parse_ip_shorthand(tok: &str) -> Option<(String, Option<u16>)> {
    use std::net::IpAddr;

    let port_of = |p: &str| -> Option<Option<u16>> {
        match p.is_empty() {
            true => Some(None),
            false => p.parse::<u16>().ok().map(Some),
        }
    };

    // `[addr]` / `[addr]:port` — `IP_WITH_PORT_RE`.
    if let Some(rest) = tok.strip_prefix('[')
        && let Some((addr, tail)) = rest.split_once(']')
        && addr.parse::<IpAddr>().is_ok()
    {
        let port = tail.strip_prefix(':').map_or(Some(None), port_of)?;
        return Some((addr.to_string(), port));
    }

    // `1.2.3.4[:port]`, including the `::ffff:` v4-mapped spellings — `IPV4_RE`.
    let v4 = tok
        .strip_prefix("::ffff:")
        .or_else(|| tok.strip_prefix("::"))
        .unwrap_or(tok);
    if v4.starts_with(|c: char| c.is_ascii_digit()) {
        let (addr, port) = match v4.split_once(':') {
            Some((a, p)) => (a, port_of(p)?),
            None => (v4, None),
        };
        if addr.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some((addr.to_string(), port));
        }
    }

    // A bare literal of either family, port and all (`::1`, `fe80::1`).
    tok.parse::<IpAddr>().ok().map(|ip| (ip.to_string(), None))
}

/// Parse one operator token into a [`RuleOp`].
/// Mirrors `formatShorthand` + operator handling in the original.
///
/// Line properties are left at their default here and stamped on by
/// [`parse_line`], which is the only place that has seen the whole line.
fn parse_op(tok: &str) -> Option<RuleOp> {
    let op = |protocol: &str, value: &str| {
        // `proto://(text)` means the value **is** `text` — whistle's inline
        // form, which `getValue` unwraps into `rule.value` for *every* operator
        // (`_original/lib/rules/rules.js:271-287`), not only the file family.
        // `readRuleValue` then hands that back directly and never looks at the
        // filesystem or the network (`lib/util/index.js:1178-1180`).
        //
        // It was only unwrapped for `file://` here, so `reqBody://(Hello)` —
        // upstream's own documented example — sent the seven characters
        // `(Hello)` to the origin, parentheses and all.
        let inline = matches!(
            url::fixed_value(value),
            Some((url::Fixed::Inline, _))
        );
        let value = match inline {
            true => url::fixed_value(value).map(|(_, v)| v).unwrap_or_default(),
            false => value.to_string(),
        };
        Some(RuleOp {
            protocol: protocol.to_string(),
            value,
            raw: tok.to_string(),
            value_is_content: inline,
            ..Default::default()
        })
    };
    // A bare IP address (with an optional port) is the hosts shorthand. It is
    // tested before the protocol split so a v6 literal cannot be read as one.
    if parse_ip_shorthand(tok).is_some() {
        return op("host", tok);
    }
    if let Some((proto, rest)) = split_protocol(tok) {
        // `whistle.<name>://…` and `plugin.<name>://…` name a plugin — it is how
        // every npm-published whistle plugin is written, so a rules file carried
        // over from whistle is full of them (`PLUGIN_RE`,
        // `_original/lib/rules/rules.js:24,:1284-1285`).
        //
        // Without this the protocol is unknown, the token becomes a
        // URL-replacement rule, and `whistle.vase://x` sends the traffic to a
        // host called `x`. Fail-open, and pointed at whatever the plugin's
        // argument happened to say.
        if let Some(name) = plugin_package(proto) {
            let value = match rest.is_empty() {
                true => name.to_string(),
                // The port's own `plugin://name/extra` spelling, which is what
                // `plugins::matched` splits on.
                false => format!("{name}/{rest}"),
            };
            return op("plugin", &value);
        }
        if protocols::is_protocol(proto) {
            // A `filter://` that reached this far names protocols to suppress,
            // and upstream folds its value into the very set `ignore://` builds
            // (`resolveFilter`, `_original/lib/util/index.js:1945-1955`, called
            // from `rules.js:2188-2196`). One mechanism, two spellings.
            if proto == "filter" {
                return op("ignore", rest);
            }
            // Normalise alias protocols (e.g. `hosts` → `host`) to canonical names.
            return op(protocols::canonical(proto).unwrap_or(proto), rest);
        }
        // A protocol whistle does not know names no operator — the token is a
        // URL, and a URL is a destination. Upstream reaches the same place by
        // `rules[protocol]` coming back undefined and falling through to the
        // `rule` list (`_original/lib/rules/rules.js:1313-1316`); it is what
        // makes `example.com http://localhost:5173` forward to a dev server.
        return op(protocols::URL_REPLACE, tok);
    }
    // `//host/path` — a URL that inherits the request's own scheme.
    if tok.starts_with("//") && !tok.starts_with("///") {
        return op(protocols::URL_REPLACE, tok);
    }
    // Bare path / file shorthand → file operator. The bracket forms count too:
    // upstream rewrites `{key}`, `(value)` and `<path>` to `file://…` before
    // parsing (`formatShorthand`, `_original/lib/rules/rules.js:222-240`), so a
    // line may name a mock without naming a protocol.
    if tok.starts_with('/')
        || tok.starts_with('~')
        || tok.starts_with('.')
        || url::fixed_value(tok).is_some()
        || url::is_values_key(tok)
    {
        return op("file", tok);
    }
    // Anything else with no protocol at all is still a destination: upstream's
    // fall-through does not require one, so `example.com localhost:5173`
    // forwards just as the spelled-out `http://localhost:5173` does.
    op(protocols::URL_REPLACE, tok)
}

/// A pattern token after its `!` / `$` prefixes have been peeled off.
///
/// The comment that used to sit here called `$` "this port's important-rule
/// shorthand" and noted, correctly, that upstream uses it for exact-URL
/// matching — and then kept the shorthand anyway. That was a divergence
/// invented rather than inherited, and it made `$example.com` match every URL
/// on the host instead of its root. `$` is exact matching now, and importance
/// is `lineProps://important` alone.
struct ParsedPattern {
    pattern: Pattern,
    /// `!` — invert the pattern test.
    negate: bool,
}

/// Parse a pattern token into a [`Pattern`] plus its prefix modifiers.
///
/// The order mirrors `parseRule` (`_original/lib/rules/rules.js:1235-1252`),
/// whose `// 位置不能变` comment marks exactly this: `!` comes off first, the
/// port-pattern test runs on what is left — so `!:8080` is a *negated* port
/// pattern while `$:8080` is not a port pattern at all — and only then is the
/// `$` prefix handled.
fn parse_pattern(tok: &str) -> Option<ParsedPattern> {
    let (negate, tok) = match tok.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, tok),
    };
    let done = |pattern| {
        Some(ParsedPattern {
            pattern,
            negate,
        })
    };

    // A `^`-prefixed URL turns every `*` into a wildcard, in the path and the
    // query as well as the host. Upstream tests this first too — `regUrlCache`
    // is consulted before anything else in `parseRule` (`rules.js:1226-1234`) —
    // and the result is a plain regexp over the whole URL.
    if let Some(re) = wildcard::parse_reg_url(tok) {
        return done(Pattern::Regex(re));
    }

    // Port pattern: `:8080` scopes the rule to one port.
    if let Some(re) = port_pattern(tok) {
        return done(Pattern::Regex(re));
    }

    // `//host/path` is scheme-relative: the `//` comes off and any scheme
    // matches (`NO_SCHEMA_RE`, `rules.js:1241-1244`). Without this the `//`
    // ended up in the *path*, and the pattern matched every host.
    let tok = match tok.strip_prefix("//") {
        Some(rest) if !rest.starts_with('/') => rest,
        _ => tok,
    };

    // Regexp pattern: /body/flags
    if let Some(re) = slash_regexp(tok) {
        return done(Pattern::Regex(re));
    }

    // A host wildcard. Asked before the negation check below because upstream
    // asks in that order, and it is `parseWildcard` that decides a *negated*
    // wildcard is dropped (`rules.js:1171-1173`).
    //
    // Asked before the `$` branch for the same reason: upstream runs
    // `parseWildcard` first and only reads `$` as exact matching when the
    // pattern is **not** a wildcard (`if (!wildcard && isExactPattern(pattern))`,
    // `rules.js:1263-1270`). `parseWildcard` reads the `$` itself, so
    // `$*.example.com/api` is an exact *wildcard*. With the two the other way
    // round it was an exact match against the literal text `*.example.com/api`,
    // which no request can ever be.
    match wildcard::parse(tok, negate) {
        wildcard::Parsed::Wildcard(w) => return done(Pattern::Wildcard(w)),
        wildcard::Parsed::Dropped => return None,
        wildcard::Parsed::NotWildcard => {}
    }

    // `$` is exact matching, not precedence. This port read it as an
    // "important" marker that also won ties, which upstream does not do:
    // measured, a normal rule written *before* a `$` one still wins there.
    if let Some(rest) = tok.strip_prefix('$') {
        let rest = rest.trim();
        if rest.is_empty() {
            // A bare `$` names nothing — upstream drops the rule.
            return done(Pattern::Nothing);
        }
        // No path means the site root, so `$example.com` is the root and not
        // the whole host. `formatUrl` puts the `/` *before* the query, so
        // `$example.com?q=1` names `example.com/?q=1`
        // (`_original/lib/util/common.js:526-536`).
        let (base, query) = match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let authority_end = base.split_once("://").map_or(base, |(_, r)| r);
        let normalised = match authority_end.contains('/') {
            true => rest.to_string(),
            false => format!("{base}/{query}"),
        };
        return done(Pattern::Exact(normalised));
    }

    // Everything below is a literal pattern, and whistle refuses to negate
    // those: a negated plain pattern falls into the `else if (not) return;` at
    // `rules.js:1266`. Dropping the rule — rather than inventing an inversion
    // the original does not have — keeps a rules file behaving the same in both
    // implementations.
    if negate {
        return None;
    }

    // Scheme/host/path prefix.
    done(parse_prefix(tok))
}

/// Compile a `/body/flags` regexp pattern — `util.isRegExp` / `util.toRegExp`
/// (`_original/lib/util/index.js:606-612,:726-735`).
///
/// `REG_EXP_RE = /^\/(.+)\/(i?u?|ui)$/` admits **four** flag spellings and no
/// others: nothing, `i`, `u`, and the two orderings of `iu`. A token whose
/// trailing characters are anything else is not a regexp at all, and falls
/// through to the pattern kinds below it.
///
/// This port read everything after the last `/` as flags and looked only for an
/// `i` in it, which made `/echo/g` a regexp upstream does not have — and, worse,
/// turned `///a.example.com` into the regexp `/`, matching every URL that
/// contains a slash. That is every URL.
///
/// **Which tokens reach here** is worth knowing before writing a test for it,
/// because it is not the obvious set: [`format_shorthand`] runs over every token
/// first, and it claims any `/`-led token that is *not* already a valid regexp
/// as a file path (`FILE_RE.test(url) && !util.isRegExp(url)`,
/// `_original/lib/rules/rules.js:1195`). So `/echo/g` never arrives — it is
/// `file:///echo/g` by then, and its line has no pattern left. What arrives is
/// the tokens with a valid flag set, which this accepts, and the `///…` family,
/// which `FILE_RE` will not take and `parse_pattern`'s `//` strip leaves alone.
/// The second is the only shape whose rejection is observable, and the one the
/// bench caught the bug with.
fn slash_regexp(tok: &str) -> Option<Regex> {
    let body_and_flags = tok.strip_prefix('/')?;
    let end = body_and_flags.rfind('/')?;
    let (body, flags) = (&body_and_flags[..end], &body_and_flags[end + 1..]);
    // `(.+)` demands a body, and `$` demands the flags be one of the four.
    if body.is_empty() || !matches!(flags, "" | "i" | "u" | "iu" | "ui") {
        return None;
    }
    // `u` is Unicode mode, which this regexp engine is always in; only `i`
    // changes what matches.
    let prefix = match flags.contains('i') {
        true => "(?i)",
        false => "",
    };
    Regex::new(&format!("{prefix}{body}")).ok()
}

/// Compile a `:8080`-style port pattern.
///
/// `PORT_PATTERN_RE = /^!?:\d{1,5}$/` (`_original/lib/rules/rules.js:71`) and
/// the compilation at `rules.js:1249-1252`: `^[\w]+://[^/?]+:<port>/`. Matching
/// the URL text means the port has to be *spelled out*, so `:80` does not match
/// `http://example.com/` in either implementation.
///
/// Anything less than a real port test is dangerous: this port used to fall
/// through to the prefix parser, which dropped the port, ended up with an empty
/// host and matched **every** request.
fn port_pattern(tok: &str) -> Option<Regex> {
    let digits = tok.strip_prefix(':')?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Regex::new(&format!(r"^[\w]+://[^/?]+:{digits}/")).ok()
}

/// Build a scheme/host/path prefix pattern from a plain token.
fn parse_prefix(tok: &str) -> Pattern {
    let (scheme, rest) = match tok.find("://") {
        Some(i) => (Some(tok[..i].to_lowercase()), &tok[i + 3..]),
        None => (None, tok),
    };
    // The authority ends at the first `/` **or `?`** — upstream splits the query
    // off before it looks for the path (`formatUrl`,
    // `_original/lib/util/common.js:526-536`), and puts the `/` back between the
    // two: `example.com?q=1` is the pattern `example.com/?q=1`. Splitting on `/`
    // alone left the whole `example.com?q=1` in the *host*, where it matched
    // nothing at all.
    let (host_part, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    // An explicit port scopes the rule to that port. The original matches the
    // pattern as a literal prefix of the request URL, port and all, so dropping
    // it here (as this port used to) made `example.com:8080` match every port.
    // A `:port` that is not a valid u16 is left as part of the host, which then
    // simply never matches — better than silently widening the rule.
    let (host_no_port, port) = match host_part.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, Some(port)),
            Err(_) => (host_part, None),
        },
        None => (host_part, None),
    };
    let (host_suffix, host) = if let Some(stripped) = host_no_port.strip_prefix('.') {
        (true, stripped.to_lowercase())
    } else {
        (false, host_no_port.to_lowercase())
    };
    if host.is_empty() {
        // No host to match on. Upstream is matching the pattern as a literal
        // prefix of the request URL, and a URL always carries an authority — so
        // `http://`, `http:///echo`, `:80/echo` and `///example.com` all compile
        // to text (`http:///echo`, `http://:80/echo`) that no request can begin
        // with, and the rule is dead (`setProtocol` + `formatUrl`,
        // `rules.js:294-305`). Here they were a *scheme* filter, a *path* filter
        // and a *port* filter over every host on the proxy — `http://` alone
        // applied its line's operators to every plain-HTTP request that arrived.
        //
        // A pattern with no host and no anything else is the same answer for the
        // older reason: upstream drops it (`if (!pattern) return`,
        // `rules.js:1247-1249`), and reaching `Pattern::Any` here meant a stray
        // token — a lone `$`, a lone `!` — matched everything.
        return Pattern::Nothing;
    }
    Pattern::Prefix {
        scheme,
        host,
        host_suffix,
        port,
        // `rule.isDomain` (`rules.js:1343-1348`): the pattern names a host and
        // nothing else, once its scheme and query are taken off. Those are the
        // only patterns matched against the *port-stripped* URL as well, which
        // is what lets `example.com` apply on every port while `example.com/`
        // does not. The query goes before the `/` test, so `example.com?q=1`
        // counts as one of them.
        is_domain: path.is_empty() || path.starts_with("/?"),
        path,
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse().unwrap())
            }
            _ => (
                host_port.to_string(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path: path.clone(),
            full_url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn disabled_group_skipped() {
        let mut mgr = RuleManager::new();
        mgr.add_group("a", "example.com host://1.2.3.4", true);
        mgr.add_group("b", "example.com host://5.6.7.8", false);

        let r = mgr.resolve(&req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("1.2.3.4"));
        assert_eq!(mgr.len(), 2); // both parsed
    }

    #[test]
    fn toggle_changes_resolution() {
        let mut mgr = RuleManager::new();
        mgr.add_group("main", "example.com host://1.1.1.1", true);
        assert!(mgr.resolve(&req("http://example.com/")).single.contains_key("host"));

        mgr.toggle_group("main");
        assert!(mgr.resolve(&req("http://example.com/")).single.is_empty());
    }

    #[test]
    fn add_remove_groups() {
        let mut mgr = RuleManager::new();
        assert!(mgr.add_group("a", "", true));
        assert!(!mgr.add_group("a", "", true)); // duplicate
        assert_eq!(mgr.groups().len(), 1);

        assert!(mgr.remove_group("a"));
        assert!(!mgr.remove_group("a")); // already removed
        assert_eq!(mgr.groups().len(), 0);
    }

    #[test]
    fn set_text_backward_compat() {
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com host://1.1.1.1");
        assert_eq!(mgr.groups().len(), 1);
        assert_eq!(mgr.groups()[0].name, "default");
        assert!(mgr.resolve(&req("http://example.com/")).single.contains_key("host"));

        mgr.set_text("other.com host://2.2.2.2");
        assert_eq!(mgr.groups().len(), 1);
        assert!(mgr.resolve(&req("http://example.com/")).single.is_empty());
    }

    /// The **default group resolves last**, so a named group overrides it.
    ///
    /// Upstream appends it after every selected named group
    /// (`addRules(defaultRules, 'Default')`,
    /// `_original/lib/rules/util.js:94-101`), which is why its console lists
    /// Default at the bottom. This port resolved it first, so a named group
    /// could never override anything — measured against whistle 2.10.8, which
    /// answers with the named group's value where this answered with the default
    /// group's.
    #[test]
    fn the_default_group_resolves_last() {
        let host_of = |mgr: &RuleManager| {
            mgr.resolve(&req("http://example.com/"))
                .value("host")
                .map(str::to_string)
        };
        let mut mgr = RuleManager::new();
        mgr.set_text("example.com host://1.1.1.1");
        mgr.add_group("named", "example.com host://2.2.2.2", true);
        assert_eq!(host_of(&mgr).as_deref(), Some("2.2.2.2"));

        // Named groups keep their own order between themselves.
        mgr.add_group("later", "example.com host://3.3.3.3", true);
        assert_eq!(host_of(&mgr).as_deref(), Some("2.2.2.2"));

        // A disabled named group is not in the running at all.
        mgr.toggle_group("named");
        assert_eq!(host_of(&mgr).as_deref(), Some("3.3.3.3"));
        mgr.toggle_group("later");
        assert_eq!(host_of(&mgr).as_deref(), Some("1.1.1.1"));
    }
}


#[cfg(test)]
mod line_props_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        let port = if scheme == "https" { 443 } else { 80 };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path,
            full_url: url.into(),
            ..Default::default()
        }
    }

    fn one(text: &str) -> Rule {
        let rules = parse_text(text);
        assert_eq!(rules.len(), 1, "expected exactly one rule from {text:?}");
        rules.into_iter().next().unwrap()
    }

    // ── parsing ──

    /// Separators are `|` *and* `&` (`SEP_RE = /[|&]/`), and empty segments
    /// are dropped rather than stored as an empty action.
    #[test]
    fn both_separators_and_empty_segments() {
        let r = one("example.com file:///tmp/x lineProps://a|b&c||d");
        let got: Vec<&str> = r.props.iter().collect();
        assert_eq!(got, vec!["a", "b", "c", "d"]);
    }

    /// Several `lineProps://` tokens on one line merge, like the original's
    /// repeated `extend(lineProps, …)`.
    #[test]
    fn multiple_tokens_merge() {
        let r = one("example.com file:///tmp/x lineProps://important lineProps://safeHtml");
        assert!(r.props.has("important"));
        assert!(r.props.has("safeHtml"));
    }

    /// `lineProps://` with an empty payload is a no-op, not an empty action.
    #[test]
    fn empty_payload_is_noop() {
        let r = one("example.com file:///tmp/x lineProps://");
        assert!(r.props.is_empty());
        assert_eq!(r.ops.len(), 1, "lineProps must not become an operator");
    }

    /// whistle never validates action names — unknown ones are kept so that
    /// consumers this port does not implement still receive them.
    #[test]
    fn unknown_actions_preserved() {
        let r = one("example.com file:///tmp/x lineProps://totallyMadeUp");
        assert!(r.props.has("totallyMadeUp"));
    }

    /// A line whose only non-pattern token is `lineProps://` configures nothing.
    #[test]
    fn line_props_alone_is_not_a_rule() {
        assert!(parse_text("example.com lineProps://important").is_empty());
    }

    /// Every operator on the line carries the line's properties, since
    /// resolution mixes operators from many lines.
    #[test]
    fn props_copied_onto_every_op() {
        let r = one("example.com host://1.2.3.4 resType://json lineProps://safeHtml");
        assert_eq!(r.ops.len(), 2);
        assert!(r.ops.iter().all(|op| op.props.has("safeHtml")));
    }

    /// The two legacy `includeFilter://` spellings are rewritten to
    /// `lineProps://` before parsing (`formatShorthand`,
    /// `_original/lib/rules/rules.js:224-229`), so they must become properties
    /// rather than filter conditions.
    #[test]
    fn legacy_include_filter_aliases() {
        let r = one("example.com htmlAppend://<!--x--> includeFilter://safeHtml");
        assert!(r.props.has("safeHtml"));
        assert!(r.filters.is_empty(), "must not become a filter condition");
        assert!(one("example.com htmlAppend://<!--x--> includeFilter://strictHtml")
            .props
            .has("strictHtml"));
    }

    // ── important ──

    /// `lineProps://important` outranks an earlier normal line for the same
    /// protocol, exactly like the `$` prefix already does.
    #[test]
    fn important_wins_over_earlier_normal_line() {
        let rules = parse_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2 lineProps://important",
        );
        let refs: Vec<&Rule> = rules.iter().collect();
        let r = matcher::resolve_refs(&refs, &req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("2.2.2.2"));
    }

    /// Without it, first-match-wins still holds.
    #[test]
    fn without_important_first_line_wins() {
        let rules = parse_text(
            "example.com host://1.1.1.1\n\
             example.com host://2.2.2.2",
        );
        let refs: Vec<&Rule> = rules.iter().collect();
        let r = matcher::resolve_refs(&refs, &req("http://example.com/"));
        assert_eq!(r.single.get("host").map(|o| o.value.as_str()), Some("1.1.1.1"));
    }

    // ── internal / internalOnly scoping ──

    #[test]
    fn internal_only_is_hidden_from_client_requests() {
        let rules = parse_text("example.com host://1.1.1.1 lineProps://internalOnly");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.is_empty());
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.contains_key("host"));
    }

    #[test]
    fn internal_applies_to_both_origins() {
        let rules = parse_text("example.com host://1.1.1.1 lineProps://internal");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.contains_key("host"));
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.contains_key("host"));
    }

    /// A plain line is invisible to whistle's own outgoing requests.
    #[test]
    fn plain_line_is_client_only() {
        let rules = parse_text("example.com host://1.1.1.1");
        let refs: Vec<&Rule> = rules.iter().collect();
        let info = req("http://example.com/");

        assert!(matcher::resolve_refs_scoped(&refs, &info, false).single.contains_key("host"));
        assert!(matcher::resolve_refs_scoped(&refs, &info, true).single.is_empty());
    }

    // ── safeHtml / strictHtml injection gating ──

    #[test]
    fn injection_gating() {
        let plain = LineProps::default();
        let mut safe = LineProps::default();
        safe.merge("safeHtml");
        let mut strict = LineProps::default();
        strict.merge("strictHtml");

        // Real markup: everyone injects.
        for p in [&plain, &safe, &strict] {
            assert!(p.allows_injection(b"  <html></html>"));
        }
        // JSON-looking: safeHtml and strictHtml both refuse.
        assert!(plain.allows_injection(b"{\"a\":1}"));
        assert!(!safe.allows_injection(b"{\"a\":1}"));
        assert!(!strict.allows_injection(b"[1,2]"));
        // Bare text: only strictHtml refuses.
        assert!(safe.allows_injection(b"hello"));
        assert!(!strict.allows_injection(b"hello"));
        // Empty body counts as markup.
        assert!(strict.allows_injection(b""));
    }
}

#[cfg(test)]
mod filter_parse_tests {
    use super::*;

    /// The single filter parsed from a one-line rule.
    fn cond_of(token: &str) -> Filter {
        let text = format!("example.com host://1.1.1.1 {token}");
        let rules = parse_text(&text);
        assert_eq!(rules.len(), 1, "expected one rule from {text:?}");
        let mut filters = rules.into_iter().next().unwrap().filters;
        assert_eq!(filters.len(), 1, "expected one filter from {token:?}");
        filters.remove(0)
    }

    /// Filters parsed from a token, which may be none.
    fn filters_of(token: &str) -> Vec<Filter> {
        let text = format!("example.com host://1.1.1.1 {token}");
        parse_text(&text).into_iter().next().unwrap().filters
    }

    // ── condition spellings ──

    /// Upstream's canonical request-header syntax, in every spelling its two
    /// regexes accept (`_original/lib/rules/rules.js:57-60`).
    #[test]
    fn request_header_spellings() {
        for token in [
            "includeFilter://reqH.x-tag:yes",
            "includeFilter://reqH.x-tag=yes",
            "includeFilter://req.x-tag:yes",
            "includeFilter://reqHeader.x-tag:yes",
            "includeFilter://reqHeaders.x-tag:yes",
            "includeFilter://reqH:x-tag=yes",
            "filter://reqH:x-tag=yes",
            "filter://h:x-tag=yes",
            "filter://header:x-tag=yes",
            "filter://h:x-tag:yes",
        ] {
            match cond_of(token).cond {
                Cond::Header { name, value, .. } => {
                    assert_eq!(name, "x-tag", "{token}");
                    assert!(value.matches_header("yes"), "{token}");
                }
                other => panic!("{token} parsed as {other:?}"),
            }
        }
    }

    /// Which message a header spelling reads, upstream's `propName[2]` switch
    /// (`_original/lib/rules/rules.js:1668-1681`): `re**q**H` the request,
    /// `re**s**H` the response, and the bare `h`/`header` both.
    #[test]
    fn header_spellings_carry_their_scope() {
        let scope_of = |token: &str| match cond_of(token).cond {
            Cond::Header { scope, .. } => scope,
            other => panic!("{token} parsed as {other:?}"),
        };
        for token in ["includeFilter://reqH.x:1", "includeFilter://reqHeaders.x:1"] {
            assert_eq!(scope_of(token), HeaderScope::Request, "{token}");
        }
        for token in ["includeFilter://resH.x:1", "includeFilter://resHeaders.x:1"] {
            assert_eq!(scope_of(token), HeaderScope::Response, "{token}");
        }
        for token in ["filter://h:x=1", "filter://header:x=1"] {
            assert_eq!(scope_of(token), HeaderScope::RequestThenResponse, "{token}");
        }
    }

    /// Header keys are case-folded, since `ReqInfo` stores them lowercased.
    #[test]
    fn header_key_is_lowercased() {
        match cond_of("includeFilter://reqH.X-Tag:yes").cond {
            Cond::Header { name, .. } => assert_eq!(name, "x-tag"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// A header condition with no value at all is a presence test.
    #[test]
    fn header_without_a_value_matches_anything() {
        match cond_of("includeFilter://reqH.x-tag").cond {
            Cond::Header { name, value, .. } => {
                assert_eq!(name, "x-tag");
                assert!(value.matches_header("whatever"));
                assert!(value.matches_header(""));
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    /// The `.`/`=` form belongs to `includeFilter`/`excludeFilter`; upstream's
    /// `PROPS_FILTER_RE` is the only one `filter://` reaches. A dotted name is
    /// therefore not a condition for `filter://` — and not a URL either, since
    /// both of its URL shapes need a `/` marker — so the token stays an ordinary
    /// operator, upstream's `matchers.push` (`_original/lib/rules/rules.js:1701`).
    #[test]
    fn pure_form_is_not_available_to_plain_filter() {
        assert!(filters_of("filter://reqH.x-tag:yes").is_empty());
        assert!(matches!(
            cond_of("includeFilter://reqH.x-tag:yes").cond,
            Cond::Header { .. }
        ));
    }

    /// Names are matched whole: the separator that follows decides, so `host`
    /// is never mistaken for `h`, nor `statusCode` for `s`.
    #[test]
    fn longer_names_are_not_shadowed() {
        assert!(matches!(cond_of("filter://host:example.com").cond, Cond::Host(_)));
        assert!(matches!(
            cond_of("filter://statusCode:200").cond,
            Cond::StatusCode(_)
        ));
        assert!(matches!(cond_of("filter://ip:1.2.3.4").cond, Cond::Ip(_)));
        assert!(matches!(
            cond_of("includeFilter://reqHeaders.x:1").cond,
            Cond::Header { .. }
        ));
    }

    /// The conditions whose facts arrive with the response head parse into
    /// conditions of their own — they are answered in the response phase, not
    /// deferred forever.
    #[test]
    fn response_phase_conditions_are_recognised() {
        assert!(matches!(cond_of("filter://s:200").cond, Cond::StatusCode(_)));
        assert!(matches!(
            cond_of("filter://statusCode:200").cond,
            Cond::StatusCode(_)
        ));
        assert!(matches!(
            cond_of("includeFilter://resH.content-type:json").cond,
            Cond::Header {
                scope: HeaderScope::Response,
                ..
            }
        ));
        assert!(matches!(
            cond_of("filter://serverIp:1.2.3.4").cond,
            Cond::ServerIp(_)
        ));
        assert!(matches!(
            cond_of("includeFilter://serverIp=1.2.3.4").cond,
            Cond::ServerIp(_)
        ));
        assert!(matches!(
            cond_of("filter://serverPort:8080").cond,
            Cond::ServerPort(_)
        ));
        assert!(matches!(
            cond_of("filter://clientPort:8080").cond,
            Cond::ClientPort(_)
        ));
        assert!(matches!(
            cond_of("filter://remoteAddress:1.2.3.4").cond,
            Cond::RemoteAddress(_)
        ));
        assert!(matches!(
            cond_of("filter://remotePort:80").cond,
            Cond::RemotePort(_)
        ));
    }

    /// `from:` takes a bare word out of a fixed list, and anything else is an
    /// [`FromMarker::Unknown`] that satisfies no filter — never a URL pattern.
    #[test]
    fn from_markers_parse_to_their_fixed_list() {
        let cases = [
            ("filter://from:tunnel", FromMarker::Tunnel),
            ("filter://from:Composer", FromMarker::Composer),
            ("filter://from:sni", FromMarker::Sni),
            ("filter://from:test", FromMarker::NeverHere),
            ("filter://from:httpsPort", FromMarker::NeverHere),
            // Upstream lowercases the value, so its own `internalPath` branch
            // is unreachable — reproduced rather than fixed.
            ("filter://from:internalPath", FromMarker::Unknown),
            ("filter://from:nonsense", FromMarker::Unknown),
        ];
        for (token, want) in cases {
            match cond_of(token).cond {
                Cond::From(got) => assert_eq!(got, want, "{token}"),
                other => panic!("{token} parsed as {other:?}"),
            }
        }
        // `!` still lands on the filter, not on the marker.
        let f = cond_of("filter://from:!tunnel");
        assert!(f.negate);
        assert!(matches!(f.cond, Cond::From(FromMarker::Tunnel)));
    }

    /// `b:` / `body:` and `env:` are now answered rather than deferred.
    #[test]
    fn body_and_env_conditions_parse() {
        for token in ["filter://b:keyword", "filter://body:keyword"] {
            assert!(matches!(cond_of(token).cond, Cond::Body(_)), "{token}");
        }
        // `env` keeps its key's case — upstream lower-cases header keys only
        // (`isHeader` is false for it, `_original/lib/rules/rules.js:1648-1653`).
        match cond_of("filter://env:MyVar=1").cond {
            Cond::Env { name, .. } => assert_eq!(name, "MyVar"),
            other => panic!("parsed as {other:?}"),
        }
        // …and only `=` separates it, so a colon stays in the key.
        match cond_of("filter://env:A:B=1").cond {
            Cond::Env { name, .. } => assert_eq!(name, "A:B"),
            other => panic!("parsed as {other:?}"),
        }
    }

    // ── regexp-valued conditions ──

    /// Any condition's value may be a `/regexp/[i]`.
    #[test]
    fn regexp_values() {
        assert!(matches!(
            cond_of("filter://m:/^P/").cond,
            Cond::Method(CondValue::Regex(_))
        ));
        assert!(matches!(
            cond_of("includeFilter://reqH.x-tag:/^ye/i").cond,
            Cond::Header {
                value: CondValue::Regex(_),
                ..
            }
        ));
        assert!(matches!(
            cond_of("filter://i:/^10\\./").cond,
            Cond::Ip(CondValue::Regex(_))
        ));
    }

    /// whistle compiles method regexps with a forced `i` flag
    /// (`util.toRegExp(value, true)`), unlike every other condition.
    #[test]
    fn method_regexps_ignore_case_without_the_flag() {
        match cond_of("filter://m:/^post$/").cond {
            Cond::Method(v) => assert!(v.matches("POST")),
            other => panic!("parsed as {other:?}"),
        }
        match cond_of("filter://host:/^EXAMPLE\\.com$/").cond {
            Cond::Host(v) => assert!(!v.matches("example.com"), "no implicit `i` here"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// `REG_EXP_RE` is `^/(.+)/(i?u?|ui)$`: an empty body or an unknown flag is
    /// a literal, and so is a pattern Rust's engine cannot compile.
    #[test]
    fn near_misses_degrade_to_literals() {
        for token in [
            "filter://m:／/",     // not a slash at all
            "filter://m://",      // empty body
            "filter://m:/GET/g",  // flag whistle's regex does not accept
            "filter://m:/(?<=x)/", // valid in JS, unsupported by Rust's engine
        ] {
            assert!(
                matches!(cond_of(token).cond, Cond::Method(CondValue::Literal(_))),
                "{token} should be a literal"
            );
        }
    }

    // ── chance ──

    #[test]
    fn chance_values() {
        let p = |token: &str| match cond_of(token).cond {
            Cond::Chance(p) => p,
            other => panic!("{token} parsed as {other:?}"),
        };
        assert_eq!(p("includeFilter://chance:0.25"), 0.25);
        assert_eq!(p("includeFilter://chance:25%"), 0.25);
        assert_eq!(p("includeFilter://probability:1"), 1.0);
        assert_eq!(p("includeFilter://chance=0.5"), 0.5);
        assert_eq!(p("filter://chance:0"), 0.0);
        // Anything JS would coerce to NaN stays NaN, and NaN never matches.
        assert!(p("includeFilter://chance:half").is_nan());
        assert!(p("includeFilter://chance:%").is_nan());
    }

    // ── negation ──

    /// `!` may sit in front of a condition's value, after a header key, or in
    /// front of a URL pattern.
    #[test]
    fn negation_spellings() {
        assert!(cond_of("filter://m:!GET").negate);
        assert!(cond_of("includeFilter://reqH.x-tag!:yes").negate);
        assert!(cond_of("includeFilter://!*.cdn.example.com").negate);
        assert!(!cond_of("filter://m:GET").negate);
        // A `!` in front of a condition *name* is not a negation: upstream's
        // props regex requires the name first, so this is a URL pattern.
        assert!(matches!(cond_of("includeFilter://!m:GET").cond, Cond::Url(_)));
    }

    /// A header condition can carry a `!` in both places, and they cancel —
    /// upstream folds each one in with `not = !not`.
    #[test]
    fn double_negation_cancels() {
        let f = cond_of("includeFilter://reqH.!x-tag!:yes");
        assert!(!f.negate);
        match f.cond {
            Cond::Header { name, .. } => assert_eq!(name, "x-tag"),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// The value's `!` is only read before the *key*: once the key separator
    /// has been passed, a `!` is part of the expected value.
    #[test]
    fn bang_after_the_separator_is_literal() {
        let f = cond_of("includeFilter://reqH.x-tag:!yes");
        assert!(!f.negate);
        match f.cond {
            Cond::Header { value, .. } => {
                assert!(value.matches_header("!yes"));
                assert!(!value.matches_header("yes"));
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    // ── URL-pattern fallback ──

    /// An unrecognised condition is a URL pattern, parsed with the same engine
    /// as a rule's own pattern — wildcards and prefixes included, where the old
    /// "strip the slashes and hope it is a regex" fallback dropped them.
    #[test]
    fn url_fallback_uses_the_pattern_engine() {
        for token in [
            "includeFilter://*/cgi-*",
            "excludeFilter://www.test.com",
            "includeFilter://https://www.test.com/path",
            "excludeFilter:///admin/",
        ] {
            assert!(
                matches!(cond_of(token).cond, Cond::Url(_)),
                "{token} should be a URL pattern"
            );
        }
    }

    // ── graceful degradation ──

    /// A filter that cannot be parsed is dropped, and must never be demoted to
    /// an operator called `includeFilter`.
    #[test]
    fn unusable_filters_are_dropped_not_demoted() {
        for token in [
            "includeFilter://",
            // `!` alone, which whistle refuses before it reads the payload
            // (`_original/lib/rules/rules.js:1489-1491`).
            "includeFilter://!",
            "excludeFilter://!",
            // A key left empty by its own `!` (`rules.js:1657`). It takes two:
            // the first is the value's negation, stripped before the key is cut.
            "includeFilter://reqH.!!:yes",
            "includeFilter://env.!!=v",
            // An address condition naming no address (`rules.js:1592-1594`).
            "includeFilter://i:localhost",
        ] {
            assert!(filters_of(token).is_empty(), "{token} should be dropped");
            let rules = parse_text(&format!("example.com host://1.1.1.1 {token}"));
            assert_eq!(rules[0].ops.len(), 1, "{token} must not become an operator");
        }
    }

    /// Dropping a filter and keeping one that cannot hold are opposite
    /// outcomes — the first leaves the line applying to everything, the second
    /// stops it — so the line between them is worth pinning exactly.
    ///
    /// A header key that is empty *to begin with* is kept: upstream tests for
    /// emptiness only inside its `!` arm, and then asks for a header named `""`
    /// that no message carries (`_original/lib/rules/rules.js:1655-1661`).
    #[test]
    fn an_empty_header_key_is_kept_not_dropped() {
        for token in [
            "includeFilter://reqH.=yes",
            "includeFilter://reqH.:yes",
            "includeFilter://h:=yes",
            // One `!` is the value's, and leaves the key empty but present.
            "includeFilter://reqH.!:yes",
        ] {
            match cond_of(token).cond {
                Cond::Header { name, .. } => assert_eq!(name, "", "{token}"),
                other => panic!("{token} parsed as {other:?}"),
            }
        }
    }

    /// A condition name with nothing after its separator is not a condition:
    /// both of upstream's regexes end `(.+)` (`_original/lib/rules/rules.js:57-60`).
    /// It falls through to the URL branch, where `^reqH.` is a pattern no URL
    /// matches — which is not the same as being dropped.
    #[test]
    fn a_condition_name_with_no_value_is_a_url_pattern() {
        for token in ["includeFilter://reqH.", "includeFilter://m:", "includeFilter://s:"] {
            assert!(
                matches!(cond_of(token).cond, Cond::Url(_)),
                "{token} should be a URL pattern"
            );
        }
    }

    /// `includeFilter://` is the only spelling that *includes*: whistle's
    /// `isInclude = matcher[1] === 'n'` (`_original/lib/rules/rules.js:1563`) is
    /// true for i**n**cludeFilter alone, so `filter://` (`'i'`) and `ignore://`
    /// (`'g'`) both exclude. This port used to read `filter://` the other way,
    /// which made a whistle rules file do the opposite of what it asked.
    #[test]
    fn only_include_filter_includes() {
        assert!(!cond_of("includeFilter://m:GET").exclude);
        assert!(cond_of("excludeFilter://m:GET").exclude);
        assert!(cond_of("filter://m:GET").exclude);
    }

    /// `ignore://` carrying a condition is an exclude filter, like `filter://`.
    #[test]
    fn ignore_with_a_condition_is_a_filter() {
        let f = cond_of("ignore://m:GET");
        assert!(f.exclude);
        assert!(matches!(f.cond, Cond::Method(_)));
    }

    /// …but `ignore://<protocol>` keeps its operator meaning. The two cannot
    /// collide: a protocol name carries no separator.
    #[test]
    fn ignore_without_a_condition_stays_an_operator() {
        let rules = parse_text("example.com host://1.1.1.1 ignore://host");
        assert!(rules[0].filters.is_empty());
        assert!(rules[0].ops.iter().any(|op| op.protocol == "ignore"));
        assert!(parse_text("example.com host://1.1.1.1 ignore://all")[0]
            .filters
            .is_empty());
    }
}

#[cfg(test)]
mod pattern_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => {
                (h.to_string(), p.parse().unwrap())
            }
            _ => (
                host_port.to_string(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port,
            path,
            full_url: url.into(),
            ..Default::default()
        }
    }

    /// Does `text`'s rule match `url`?
    fn hits(text: &str, url: &str) -> bool {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        mgr.resolve(&req(url)).value("host").is_some()
    }

    // ── `:port` patterns ──

    /// `:8080` scopes a rule to one port, on any host. It used to reach the
    /// prefix parser, which dropped the port and left an empty host — i.e. a
    /// pattern that quietly matched **every** request.
    #[test]
    fn port_pattern_matches_only_that_port() {
        let text = ":8080 host://1.1.1.1";
        assert!(hits(text, "http://any.test:8080/"));
        assert!(hits(text, "https://other.test:8080/deep/path?q=1"));
        assert!(!hits(text, "http://any.test/"), "port 80 must not match");
        assert!(!hits(text, "http://other.test:9999/"));
        assert!(!hits(text, "http://any.test:18080/"), "not a suffix match");
    }

    /// Like upstream, the port has to be spelled out in the URL: the compiled
    /// pattern is `^[\w]+://[^/?]+:<port>/`, so a default port does not match.
    #[test]
    fn default_port_is_not_spelled_out() {
        assert!(!hits(":80 host://1.1.1.1", "http://any.test/"));
        assert!(hits(":80 host://1.1.1.1", "http://any.test:80/"));
    }

    /// `!:8080` is recognised as *both* a port pattern and a negation — the
    /// ordering upstream marks with `// 位置不能变`.
    #[test]
    fn negated_port_pattern() {
        let text = "!:8080 host://1.1.1.1";
        assert!(!hits(text, "http://any.test:8080/"));
        assert!(hits(text, "http://any.test/"));
        // …and it must not be mistaken for a `host:port` operator.
        let rules = parse_text("!:8080 statusCode://418");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ops.len(), 1);
        assert_eq!(rules[0].ops[0].protocol, "statusCode");
    }

    /// A port written into an ordinary pattern scopes it just the same —
    /// upstream matches the pattern as a literal prefix of the URL, port
    /// included.
    #[test]
    fn explicit_port_in_a_host_pattern() {
        let text = "example.test:8080 host://1.1.1.1";
        assert!(hits(text, "http://example.test:8080/"));
        assert!(!hits(text, "http://example.test/"));
        assert!(!hits(text, "http://other.test:8080/"));
        // A portless pattern still matches any port.
        assert!(hits("example.test host://1.1.1.1", "http://example.test:8080/"));
    }

    /// A `:` that is not a port stays part of the host, which then matches
    /// nothing — rather than being dropped and widening the rule.
    #[test]
    fn unparsable_port_does_not_widen_the_pattern() {
        assert!(!hits("example.test:99999 host://1.1.1.1", "http://example.test/"));
        assert!(!hits(": host://1.1.1.1", "http://example.test/"));
    }

    // ── `!` negation ──

    /// `!/re/` matches every request the regexp does not
    /// (`_original/lib/rules/rules.js:994-998`).
    #[test]
    fn negated_regexp_inverts_the_match() {
        let text = "!/example\\.test/ host://1.1.1.1";
        assert!(!hits(text, "http://example.test/"));
        assert!(hits(text, "http://other.test/"));
    }

    /// Only the *pattern* test is inverted: filter conditions still have to
    /// hold as written.
    #[test]
    fn negation_leaves_filters_alone() {
        let text = "!/example\\.test/ host://1.1.1.1 includeFilter://m:POST";
        assert!(!hits(text, "http://other.test/"), "GET fails the filter");

        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        let post = |url: &str| {
            let mut r = req(url);
            r.method = "POST".into();
            r
        };
        assert!(mgr.resolve(&post("http://other.test/")).value("host").is_some());
        assert!(
            mgr.resolve(&post("http://example.test/")).value("host").is_none(),
            "the negated pattern still excludes example.test"
        );
    }

    /// Upstream refuses to negate a literal pattern: `parseWildcard` bails out
    /// for a negated wildcard (`rules.js:1171-1173`) and a negated plain
    /// pattern hits `else if (not) return;` (`rules.js:1266`). Both drop the
    /// rule, so this port drops it too rather than inventing an inversion.
    #[test]
    fn literal_patterns_cannot_be_negated() {
        assert!(parse_text("!example.test host://1.1.1.1").is_empty());
        assert!(parse_text("!*.example.test host://1.1.1.1").is_empty());
        // And the whole line goes with it. A negated token *is* a pattern to
        // `index_of_pattern`, so it is the line's only one — every token after
        // it is an operator, whatever its shape.
        assert!(parse_text("!example.test other.test host://1.1.1.1").is_empty());
    }

    /// `$` is **exact matching**, and it carries no precedence.
    ///
    /// This port read it as an "important" shorthand — a divergence it invented
    /// rather than inherited. Two things were wrong with that, both measured
    /// against whistle 2.10.8: a normal rule written *before* a `$` one still
    /// wins there, and `$example.test` names the site **root**, where this port
    /// matched every URL on the host.
    #[test]
    fn a_dollar_pattern_is_exact_and_not_important() {
        let rules = parse_text("$example.test host://1.1.1.1");
        assert!(!rules[0].is_important(), "`$` is not a precedence marker");
        assert!(!rules[0].negate);
        assert!(matches!(&rules[0].pattern, Pattern::Exact(p) if p == "example.test/"));

        // Importance has one spelling, and it is not this one.
        let rules = parse_text("example.test host://1.1.1.1 lineProps://important");
        assert!(rules[0].is_important());
    }

    /// `!$…` is a **negated exact** pattern: everything but that one URL.
    ///
    /// Upstream allows it where it refuses a negated literal, because the `$`
    /// branch runs first and the `else if (not) return` never fires
    /// (`_original/lib/rules/rules.js:1265-1268`). Confirmed against whistle:
    /// `!$http://example.test/p` matched `/p/s`, `/` and `/q`, and not `/p`.
    #[test]
    fn a_negated_exact_pattern_is_allowed_where_a_literal_is_not() {
        let rules = parse_text("!$example.test/p host://1.1.1.1");
        assert_eq!(rules.len(), 1, "not dropped, unlike a negated literal");
        assert!(rules[0].negate);
        assert!(matches!(&rules[0].pattern, Pattern::Exact(p) if p == "example.test/p"));
        // …and the plain literal is still refused.
        assert!(parse_text("!example.test host://1.1.1.1").is_empty());
    }

    /// `$` in front of a **wildcard** is an exact wildcard, not an exact match
    /// against the literal text `*.example.test/echo`.
    ///
    /// Upstream asks `parseWildcard` first and only reads `$` as exact matching
    /// when the answer is no (`if (!wildcard && isExactPattern(pattern))`,
    /// `_original/lib/rules/rules.js:1263-1270`); `parseWildcard` reads the `$`
    /// itself and sets `isExact` on the wildcard it builds. This port asked in
    /// the other order, so every `$`-prefixed wildcard matched nothing at all.
    #[test]
    fn an_exact_pattern_may_be_a_wildcard() {
        let text = "$*.example.test/echo host://1.1.1.1";
        assert!(hits(text, "http://a.example.test/echo"));
        assert!(hits(text, "http://a.example.test/echo?q=1"), "the query may differ");
        assert!(!hits(text, "http://a.example.test/echo/more"), "still exact");
        assert!(!hits(text, "http://a.example.test/ec"));
        assert!(!hits(text, "http://a.b.example.test/echo"), "one label only");
        // The leading-dot and multi-star hosts are wildcards too.
        assert!(hits("$.example.test/echo host://1.1.1.1", "http://a.example.test/echo"));
        assert!(hits("$**.example.test/echo host://1.1.1.1", "http://a.b.example.test/echo"));
        // And a `$` with no wildcard in it is still a plain exact pattern.
        assert!(matches!(
            &parse_text("$example.test/p host://1.1.1.1")[0].pattern,
            Pattern::Exact(p) if p == "example.test/p"
        ));
    }

    /// An exact match consumed the path, so only the request's **query** is left
    /// — and upstream hands it to the destination (`getRelativePath`,
    /// `_original/lib/rules/rules.js:848-858`). This port dropped it, so
    /// `$a.test/search http://dev/search` lost every search term.
    #[test]
    fn an_exact_match_hands_the_query_to_its_destination() {
        let url_for = |text: &str, url: &str| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            mgr.resolve(&req(url))
                .value(protocols::URL_REPLACE)
                .map(str::to_string)
        };
        assert_eq!(
            url_for("$a.test/p http://dev.test/x", "http://a.test/p?q=1").as_deref(),
            Some("http://dev.test/x?q=1")
        );
        // A destination that already has a query takes it as another parameter —
        // the `?`-or-`&` decision `join_url` makes for every other pattern kind.
        assert_eq!(
            url_for("$a.test/p http://dev.test/x?k=1", "http://a.test/p?q=1").as_deref(),
            Some("http://dev.test/x?k=1&q=1")
        );
        // A pattern that named the query has already consumed it.
        assert_eq!(
            url_for("$a.test/p?q=1 http://dev.test/x", "http://a.test/p?q=1").as_deref(),
            Some("http://dev.test/x")
        );
        assert_eq!(
            url_for("$a.test/p http://dev.test/x", "http://a.test/p").as_deref(),
            Some("http://dev.test/x")
        );
        // The same three answers for the wildcard spelling, whose own
        // `relative_query` made the second test against the *pattern* rather
        // than the destination and so appended a query it had already consumed.
        assert_eq!(
            url_for("$*.test/p http://dev.test/x", "http://a.test/p?q=1").as_deref(),
            Some("http://dev.test/x?q=1")
        );
        assert_eq!(
            url_for("$*.test/p?q=1 http://dev.test/x", "http://a.test/p?q=1").as_deref(),
            Some("http://dev.test/x")
        );
    }

    /// A pattern may carry a query **instead of** a path: upstream's `formatUrl`
    /// splits the query off before it looks for the path and puts a `/` between
    /// the two (`_original/lib/util/common.js:526-536`), so `example.test?q=1`
    /// is the pattern `example.test/?q=1`.
    ///
    /// This port split the token on `/` alone, leaving `example.test?q=1` in the
    /// *host*, where it matched nothing.
    #[test]
    fn a_pattern_may_carry_a_query_instead_of_a_path() {
        let text = "example.test?q=1 host://1.1.1.1";
        assert!(hits(text, "http://example.test/?q=1"));
        assert!(hits(text, "http://example.test/?q=1&r=2"), "a query prefix");
        assert!(!hits(text, "http://example.test/?q=2"));
        assert!(!hits(text, "http://example.test/"), "the request has no query");
        // The query goes before the `/` test that decides `rule.isDomain`
        // (`rules.js:1343-1348`), so this is still a domain pattern and still
        // matches on any port.
        assert!(hits(text, "http://example.test:8080/?q=1"));
        // …where a pattern with a real path is scoped to the default port.
        assert!(!hits("example.test/p host://1.1.1.1", "http://example.test:8080/p"));
        // A bare `?` is a query prefix of everything.
        assert!(hits("example.test? host://1.1.1.1", "http://example.test/?q=1"));
    }

    /// A pattern with no host matches nothing.
    ///
    /// Upstream compares the pattern as a literal prefix of the request URL, and
    /// a URL always carries an authority — so `http://`, `http:///echo`,
    /// `:80/echo` and `///example.test` all compile to text no request can begin
    /// with. Here each was a filter over **every host on the proxy**: `http://`
    /// alone applied its line to every plain-HTTP request that arrived.
    #[test]
    fn a_pattern_with_no_host_matches_nothing() {
        for pattern in ["http://", "http:///", "http:///echo", ":80/echo", "///example.test", "/echo"] {
            assert!(
                !hits(&format!("{pattern} host://1.1.1.1"), "http://example.test/echo"),
                "{pattern}"
            );
        }
    }

    /// A `/re/` token takes **four** flag spellings and no others — upstream's
    /// `REG_EXP_RE = /^\/(.+)\/(i?u?|ui)$/`
    /// (`_original/lib/util/common.js:606`). Anything else is not a regexp, and
    /// falls through to the pattern kinds below it.
    ///
    /// This port read everything after the last `/` as flags and looked only for
    /// an `i`, which made `/echo/g` a regexp upstream does not have — and turned
    /// `///example.test` into the regexp `/`, matching every URL there is.
    #[test]
    fn only_i_and_u_are_regexp_flags() {
        for flags in ["", "i", "u", "iu", "ui"] {
            assert!(
                hits(&format!("/echo/{flags} host://1.1.1.1"), "http://example.test/echo"),
                "/echo/{flags}"
            );
        }
        for flags in ["g", "m", "s", "gi", "ig", "xyz", "I"] {
            assert!(
                !hits(&format!("/echo/{flags} host://1.1.1.1"), "http://example.test/echo"),
                "/echo/{flags}"
            );
        }
        // `i` is the only one that changes what matches.
        assert!(hits("/ECHO/i host://1.1.1.1", "http://example.test/echo"));
        assert!(!hits("/ECHO/ host://1.1.1.1", "http://example.test/echo"));
        // A body is required, and an unterminated token is not a regexp.
        assert!(!hits("//i host://1.1.1.1", "http://example.test/echo"));
        assert!(!hits("/echo host://1.1.1.1", "http://example.test/echo"));

        // Where each of them ends up, so the assertions above cannot pass for
        // the wrong reason. `/echo/g` is not a regexp, so `format_shorthand`
        // reads it as a **file path** and the line loses its only pattern —
        // upstream's answer too, and for the same two lines of code
        // (`FILE_RE.test(url) && !util.isRegExp(url)`, `rules.js:1195`).
        assert!(parse_text("/echo/g host://1.1.1.1").is_empty());
        // `///host` is no file path, so it stays a pattern — one that used to
        // compile to the regexp `/`, which every URL contains.
        let rules = parse_text("///example.test host://1.1.1.1");
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].pattern, Pattern::Nothing));
    }

    /// A bare carriage return separates two rules — `LINE_END_RE = /\n|\r\n|\r/`
    /// (`_original/lib/rules/rules.js:44`).
    ///
    /// Rust's `str::lines()` splits on `\n` and `\r\n` and leaves a lone `\r`
    /// inside the line, so a text with classic Mac endings was **one** rule here
    /// and several upstream. The failure is silent rather than loud: the second
    /// line's tokens are read as more operators on the first line's pattern, so
    /// a rule whose pattern sat on a later line simply never matched.
    ///
    /// The corpus case for this agreed on both sides for a year of an afternoon,
    /// because its two lines still answer the same when merged. These do not:
    /// the matching pattern is on the second line.
    #[test]
    fn a_bare_carriage_return_separates_two_rules() {
        let text = "b.test statusCode://204\rexample.test host://1.1.1.1";
        assert_eq!(parse_text(text).len(), 2);
        assert!(hits(text, "http://example.test/"));
        // …and the other order, where the merged reading would have matched.
        let text = "example.test host://1.1.1.1\rb.test statusCode://204";
        assert_eq!(parse_text(text).len(), 2);
        assert!(hits(text, "http://example.test/"));

        // `\r\n` is one separator, not two, and `\r\r\n` is two — the ordered
        // alternation upstream's regexp gives.
        assert_eq!(parse_text("a.test host://1.1.1.1\r\nb.test host://2.2.2.2").len(), 2);
        assert_eq!(parse_text("a.test host://1.1.1.1\r\r\nb.test host://2.2.2.2").len(), 2);
        assert_eq!(parse_text("a.test host://1.1.1.1\n\rb.test host://2.2.2.2").len(), 2);
    }

    /// A `ws://` pattern does not reach a plain request, and an `http://` one
    /// does not reach a WebSocket.
    ///
    /// whistle matches the pattern as a prefix of the request URL, and that URL
    /// names exactly one scheme — `ws`/`wss` for a WebSocket, `http`/`https`
    /// otherwise (`getFullUrl`, `_original/lib/util/common.js:1266`). The
    /// pattern that reaches both is the one with no scheme. This port folded the
    /// two families together in both directions.
    #[test]
    fn a_scheme_names_one_scheme() {
        let ws = |url: &str| {
            let mut r = req(url);
            r.scheme = "ws".into();
            r
        };
        let matched = |text: &str, info: &ReqInfo| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            mgr.resolve(info).value("host").is_some()
        };
        assert!(!hits("ws://example.test host://1.1.1.1", "http://example.test/"));
        assert!(!hits("wss://example.test host://1.1.1.1", "https://example.test/"));
        assert!(!matched("http://example.test host://1.1.1.1", &ws("ws://example.test/c")));
        assert!(matched("ws://example.test host://1.1.1.1", &ws("ws://example.test/c")));
        // A pattern with no scheme reaches both, which is whistle's idiom for it.
        assert!(matched("example.test host://1.1.1.1", &ws("ws://example.test/c")));
        assert!(hits("example.test host://1.1.1.1", "http://example.test/"));
    }

    /// The truth table the oracle produced, pinned.
    #[test]
    fn exact_matching_follows_the_measured_table() {
        let hits = |pattern: &str, url: &str| Pattern::exact_matches(pattern, url);
        // No query in the pattern: the path must match, the query may be anything.
        assert!(hits("example.test/p", "http://example.test/p"));
        assert!(hits("example.test/p", "http://example.test/p?a=1"));
        assert!(!hits("example.test/p", "http://example.test/p/s"), "no sub-paths");
        // A query in the pattern makes both exact.
        assert!(hits("http://example.test/p?a=1", "http://example.test/p?a=1"));
        assert!(!hits("http://example.test/p?a=1", "http://example.test/p"));
        assert!(!hits("http://example.test/p?a=1", "http://example.test/p?b=2"));
        // The root, and only the root.
        assert!(hits("example.test/", "http://example.test/"));
        assert!(!hits("example.test/", "http://example.test/p"));
    }
}

#[cfg(test)]
mod parse_text_tests {
    use super::*;

    fn req(url: &str) -> ReqInfo {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (host, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        ReqInfo {
            method: "GET".into(),
            scheme: scheme.into(),
            host,
            port: if scheme == "https" { 443 } else { 80 },
            path,
            full_url: url.into(),
            ..Default::default()
        }
    }

    fn host_for(text: &str, url: &str) -> Option<String> {
        let mut mgr = RuleManager::new();
        mgr.set_text(text);
        mgr.resolve(&req(url)).value("host").map(str::to_string)
    }

    // ── where the pattern sits ──

    /// The split has to agree with upstream's `indexOfPattern` token for token,
    /// because it decides whether a token is read as a pattern or an operator —
    /// and the two readings have nothing in common.
    ///
    /// Every case below was checked against the original's own classifier.
    #[test]
    fn the_pattern_index_agrees_with_upstream() {
        for (line, want) in [
            // Ordinary form: the first token is the pattern.
            ("example.com http://localhost:5173", Some(0)),
            ("example.com localhost:5173", Some(0)),
            ("example.com 1.2.3.4", Some(0)),
            ("a.com b.com host://8.8.8.8", Some(0)),
            ("http://a.com/api host://1.1.1.1", Some(0)),
            ("^www.example.com/user/*/profile file:///x", Some(0)),
            ("*.example.com/api host://1.1.1.1", Some(0)),
            ("!example.test other.test host://1.1.1.1", Some(0)),
            ("$example.com host://1.1.1.1", Some(0)),
            (":8080 host://1.1.1.1", Some(0)),
            ("/re/ host://1.1.1.1", Some(0)),
            ("//a.com/x host://1.1.1.1", Some(0)),
            // Swapped form: an operator leads, the patterns follow.
            ("host://x a.com b.com", Some(1)),
            ("proxy://1.1.1.1:8080 a.com b.com", Some(1)),
            ("127.0.0.1 example.com", Some(1)),
            // A bare address is an operator wherever it sits, so a line of
            // nothing but addresses has no pattern until one of them can be
            // one — here, the first.
            ("127.0.0.1 1.2.3.4", Some(0)),
            // Nothing but operators: no pattern, no rule.
            ("host://x proxy://y", None),
        ] {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(index_of_pattern(&tokens), want, "{line}");
        }
    }

    /// The bare-address shorthand is `net.isIP`, nothing looser: a *name* with a
    /// port is a destination, and giving it `host://`'s meaning instead would
    /// quietly preserve a `Host` header upstream rewrites.
    #[test]
    fn only_an_ip_literal_is_the_address_shorthand() {
        for tok in ["127.0.0.1", "1.2.3.4:8080", "[::1]:8080", "::1", "::ffff:1.2.3.4:80"] {
            assert!(parse_ip_shorthand(tok).is_some(), "{tok} is an address");
        }
        for tok in ["localhost:8080", "example.com", "example.com:80", "1.2.3", "1.2.3.4:abc"] {
            assert!(parse_ip_shorthand(tok).is_none(), "{tok} is not an address");
        }
        // The port travels with the address, and a v4-mapped form is unmapped.
        assert_eq!(parse_ip_shorthand("1.2.3.4:8080"), Some(("1.2.3.4".into(), Some(8080))));
        assert_eq!(parse_ip_shorthand("::ffff:1.2.3.4"), Some(("1.2.3.4".into(), None)));
        assert_eq!(parse_ip_shorthand("[::1]:9"), Some(("::1".into(), Some(9))));
    }

    /// Every shorthand whistle expands before it decides which token on a line
    /// is the pattern. The expected column is upstream's own `formatShorthand`,
    /// run over the same inputs — not restated from its source.
    #[test]
    fn shorthands_expand_the_way_upstream_expands_them() {
        for (input, want) in [
            ("/srv/mock.json", "file:///srv/mock.json"),
            ("/", "file:///"),
            ("C:\\mock\\a.json", "file://C:\\mock\\a.json"),
            ("C:/mock/a.json", "file://C:/mock/a.json"),
            ("(hello)", "file://(hello)"),
            ("<//dev.internal/fixed>", "file://<//dev.internal/fixed>"),
            ("{myMock}", "file://{myMock}"),
            ("{}", "file://{}"),
            // A scheme-relative pattern is left alone…
            ("//a.com/x", "//a.com/x"),
            // …and so is a real regexp, whose flag set is closed — which is how
            // a path is told apart from one.
            ("/re/", "/re/"),
            ("/re/i", "/re/i"),
            ("/re/gm", "file:///re/gm"),
            ("/Users/me/mock.json", "file:///Users/me/mock.json"),
            // Chrome's paste of a Windows path keeps the drive letter.
            ("file:///C:/x/y.json", "file://C:/x/y.json"),
            ("@https://x/rules.txt", "G://https://x/rules.txt"),
            ("@name", "G://name"),
            ("includeFilter://safeHtml", "lineProps://safeHtml"),
            // Untouched.
            ("example.com", "example.com"),
            ("http://a.com", "http://a.com"),
            ("host://1.2.3.4", "host://1.2.3.4"),
            ("~/mock.json", "~/mock.json"),
        ] {
            assert_eq!(format_shorthand(input), want, "{input}");
        }
    }

    /// The failure the expansion above exists to prevent: an operator-first line
    /// naming a mock file. Until the path becomes `file://…` it has no protocol,
    /// so the splitter took *it* for the pattern and promoted both domains to
    /// destinations — and the path, accepted as a regexp by a too-lax test,
    /// compiled to the unanchored pattern `Users/me`.
    #[test]
    fn an_operator_first_line_naming_a_file_is_read_correctly() {
        let rules = parse_text("/Users/me/mock.json  www.example.com  api.example.com");
        assert_eq!(rules.len(), 2, "one rule per pattern");
        for rule in &rules {
            let op = rule.ops.iter().find(|op| op.protocol == "file").expect("a file operator");
            assert_eq!(op.value, "/Users/me/mock.json");
        }
        let file_for = |text: &str, url: &str| {
            let mut mgr = RuleManager::new();
            mgr.set_text(text);
            mgr.resolve(&req(url)).value("file").map(str::to_string)
        };
        const LINE: &str = "/Users/me/mock.json www.example.com";
        assert_eq!(
            file_for(LINE, "http://www.example.com/x").as_deref(),
            Some("/Users/me/mock.json/x")
        );
        // And it no longer matches an unrelated host that merely contains the path.
        assert_eq!(file_for(LINE, "http://cdn.test/Users/me/pic.png"), None);
    }

    /// A condition may be written inside brackets — the form that lets one
    /// contain characters which would otherwise end the token. Unstripped, the
    /// payload fell through to the URL-pattern branch and could never hold, so
    /// the rule silently never applied.
    #[test]
    fn a_bracketed_filter_condition_is_unwrapped() {
        let host_of = |text: &str, url: &str| {
            let mut m = RuleManager::new();
            m.set_text(text);
            m.resolve(&req(url)).value("host").map(str::to_string)
        };
        // `(…)` and `<…>` both wrap.
        for line in [
            "example.com host://1.1.1.1 includeFilter://(m:GET)",
            "example.com host://1.1.1.1 includeFilter://<m:GET>",
        ] {
            assert_eq!(host_of(line, "http://example.com/x").as_deref(), Some("1.1.1.1"), "{line}");
        }
        // The condition is still a condition — a GET filter excludes a POST.
        let mut m = RuleManager::new();
        m.set_text("example.com host://1.1.1.1 includeFilter://(m:POST)");
        assert!(m.resolve(&req("http://example.com/x")).value("host").is_none());
    }

    /// `filter://` is two operators sharing one name, and this port only knew
    /// the one. A payload that is not a URL and not a named condition names
    /// **protocols to suppress**, and upstream folds it into the very set
    /// `ignore://` builds — so `filter://host` used to suppress nothing and the
    /// `host://` beside it went on applying.
    #[test]
    fn filter_naming_a_protocol_suppresses_it() {
        let host_of = |text: &str| {
            let mut m = RuleManager::new();
            m.set_text(text);
            m.resolve(&req("http://example.com/x")).value("host").map(str::to_string)
        };
        assert_eq!(host_of("example.com host://1.1.1.1 filter://host"), None);
        assert_eq!(host_of("example.com host://1.1.1.1 filter://ua").as_deref(), Some("1.1.1.1"));

        // A URL payload is still a URL filter — it ends in `/`…
        assert_eq!(host_of("example.com host://1.1.1.1 filter:///api/"), Some("1.1.1.1".into()));
        // …and one that matches excludes the rule.
        let mut m = RuleManager::new();
        m.set_text("example.com host://1.1.1.1 filter:///x/");
        assert!(m.resolve(&req("http://example.com/x/y")).value("host").is_none());

        // And a named condition is still a condition. `filter://` excludes, so
        // a condition that *holds* is what removes the rule.
        let mut m = RuleManager::new();
        m.set_text("example.com host://1.1.1.1 filter://m:GET");
        assert!(m.resolve(&req("http://example.com/x")).value("host").is_none());
        m.set_text("example.com host://1.1.1.1 filter://m:POST");
        assert!(m.resolve(&req("http://example.com/x")).value("host").is_some());
    }

    /// A rules file can carry its own mocks in a ``` fenced block. Without the
    /// lifting pass the fence lines were parsed as rule lines — configuring
    /// nothing — and `{mock.json}` resolved to nothing, so the rule it was
    /// written for silently served a 404.
    #[test]
    fn a_fenced_block_becomes_a_named_value() {
        let text = concat!(
            "``` mock.json\n",
            "{\"ok\": true,\n",
            " \"n\": 1}\n",
            "```\n",
            "example.com file://{mock.json}\n",
        );
        let (body, values) = lift_inline_values(text);
        assert_eq!(values.get("mock.json").map(String::as_str), Some("{\"ok\": true,\n \"n\": 1}"));
        assert_eq!(body.trim(), "example.com file://{mock.json}");
        // The rule survives the lift and is the only one.
        assert_eq!(parse_text(&body).len(), 1);

        // A longer fence may contain a shorter one, and the block ends only at
        // its own length.
        let nested = "````` outer\n```\ninner\n```\n`````\na.com file://{outer}\n";
        let (body, values) = lift_inline_values(nested);
        assert_eq!(values.get("outer").map(String::as_str), Some("```\ninner\n```"));
        assert_eq!(body.trim(), "a.com file://{outer}");

        // A name declared twice keeps the first block.
        let twice = "``` k\nfirst\n```\n``` k\nsecond\n```\n";
        assert_eq!(lift_inline_values(twice).1.get("k").map(String::as_str), Some("first"));

        // An unterminated fence is not a block: the text is left alone rather
        // than swallowing the rest of the file.
        let open = "``` k\na.com host://1.1.1.1\n";
        let (body, values) = lift_inline_values(open);
        assert!(values.is_empty());
        assert!(body.contains("a.com host://1.1.1.1"));

        // Things that merely look like fences are not.
        for text in ["`` k\n``\n", "``` \n```\n", "``` two words\n```\n"] {
            assert!(lift_inline_values(text).1.is_empty(), "{text:?}");
        }
        // And a text with no backticks at all is returned untouched.
        let plain = "a.com host://1.1.1.1\n";
        assert_eq!(lift_inline_values(plain).0, plain);
    }

    /// The group exposes what its own text declared, and only while enabled.
    #[test]
    fn inline_values_come_from_enabled_groups() {
        let mut mgr = RuleManager::new();
        mgr.set_text("``` a\nfrom-default\n```\nexample.com file://{a}\n");
        assert_eq!(mgr.inline_values().get("a").map(String::as_str), Some("from-default"));

        mgr.add_group("extra", "``` b\nfrom-extra\n```\n", true);
        assert_eq!(mgr.inline_values().get("b").map(String::as_str), Some("from-extra"));

        mgr.toggle_group("extra");
        assert!(!mgr.inline_values().contains_key("b"), "a disabled group contributes nothing");
    }

    /// `proto://(text)` means the value **is** `text`, for every operator and
    /// not just the file family. It was unwrapped only for `file://` here, so
    /// `reqBody://(Hello)` — upstream's own documented example — sent the seven
    /// characters `(Hello)` to the origin, parentheses and all.
    #[test]
    fn the_inline_form_unwraps_for_every_operator() {
        let op_of = |line: &str, proto: &str| {
            let rules = parse_text(line);
            rules[0]
                .ops
                .iter()
                .find(|op| op.protocol == proto)
                .cloned()
                .unwrap_or_else(|| panic!("no {proto} in {line}"))
        };

        for (line, proto, want) in [
            ("a.com reqBody://(Hello)", "reqBody", "Hello"),
            ("a.com resBody://(<h1>hi</h1>)", "resBody", "<h1>hi</h1>"),
            ("a.com ua://(MyBot/1.0)", "ua", "MyBot/1.0"),
            ("a.com file://({\"ok\":true})", "file", "{\"ok\":true}"),
        ] {
            let op = op_of(line, proto);
            assert_eq!(op.value, want, "{line}");
            assert!(op.value_is_content, "{line} is content, not a location");
        }

        // The other two bracket forms are not content. `<path>` is a location
        // pinned in place…
        let op = op_of("a.com file://</srv/mock.json>", "file");
        assert!(!op.value_is_content);
        // …and `{key}` is a reference the values store answers later.
        let op = op_of("a.com file://{mock.json}", "file");
        assert!(!op.value_is_content);
        assert_eq!(op.value, "{mock.json}");

        // A value that merely contains parentheses is not the inline form.
        let op = op_of("a.com ua://Mozilla(compatible)/5", "ua");
        assert_eq!(op.value, "Mozilla(compatible)/5");
        assert!(!op.value_is_content);
    }

    /// `whistle.<name>://` and `plugin.<name>://` name a plugin. It is how every
    /// npm-published whistle plugin is written, so a rules file carried over
    /// from whistle is full of them — and without this the protocol is unknown,
    /// the token becomes a URL-replacement rule, and `whistle.vase://x` sends
    /// the traffic to a host called `x`.
    #[test]
    fn a_plugin_package_protocol_names_a_plugin() {
        for (line, want) in [
            ("example.com whistle.vase://", "vase"),
            ("example.com plugin.vase://", "vase"),
            ("example.com whistle.my-plugin://arg", "my-plugin/arg"),
        ] {
            let rules = parse_text(line);
            let op = rules[0]
                .ops
                .iter()
                .find(|op| op.protocol == "plugin")
                .unwrap_or_else(|| panic!("{line} should name a plugin"));
            assert_eq!(op.value, want, "{line}");
        }
        // A dotted *hostname* written as a protocol is not a plugin: upstream's
        // name class is `[a-z\d_-]+`, deliberately narrow.
        let rules = parse_text("example.com whistle.Example.COM://x");
        assert!(rules[0].ops.iter().all(|op| op.protocol != "plugin"));
    }

    /// A destination is an operator, so the line configures one — this is the
    /// rule whistle's getting-started guide opens with, and it used to parse as
    /// two patterns and nothing else.
    #[test]
    fn a_bare_url_is_an_operator_not_a_second_pattern() {
        for (line, want) in [
            ("example.com http://localhost:5173", "http://localhost:5173"),
            ("example.com //localhost:5173", "//localhost:5173"),
            ("example.com localhost:5173", "localhost:5173"),
            ("example.com tunnel://a.com:443", "tunnel://a.com:443"),
        ] {
            let rules = parse_text(line);
            assert_eq!(rules.len(), 1, "{line}");
            assert_eq!(
                rules[0]
                    .ops
                    .iter()
                    .find(|op| op.protocol == protocols::URL_REPLACE)
                    .map(|op| op.value.as_str()),
                Some(want),
                "{line}"
            );
        }
        // A bare IP is still the address shorthand, not a destination.
        let rules = parse_text("example.com 1.2.3.4:8080");
        assert_eq!(rules[0].ops[0].protocol, "host");
        // …and so are the bracket forms, which name a mock rather than a place
        // (`formatShorthand`). The inline one is unwrapped on the way through,
        // which is what makes it *content* rather than a path.
        for (tok, want, content) in [
            ("(hello)", "hello", true),
            ("<~/mock.json>", "<~/mock.json>", false),
            ("{mock.json}", "{mock.json}", false),
        ] {
            let rules = parse_text(&format!("example.com {tok}"));
            assert_eq!(rules[0].ops[0].protocol, "file", "{tok}");
            assert_eq!(rules[0].ops[0].value, want, "{tok}");
            assert_eq!(rules[0].ops[0].value_is_content, content, "{tok}");
        }
    }

    // ── one rule per pattern ──

    /// whistle expands a line into one rule per pattern; taking only the first
    /// silently dropped every other host on the line.
    #[test]
    fn every_pattern_on_a_line_gets_the_operator() {
        let text = "host://9.9.9.9 a.com b.com c.com";
        for h in ["a.com", "b.com", "c.com"] {
            assert_eq!(
                host_for(text, &format!("http://{h}/")).as_deref(),
                Some("9.9.9.9"),
                "{h} should match"
            );
        }
        assert_eq!(host_for(text, "http://d.com/"), None);
    }

    /// …and **only** that spelling: several patterns on a line is the
    /// operator-first form's privilege. Written pattern-first, the first token
    /// is the line's one pattern and everything after it is an operator — so
    /// `b.com` here names a destination, not a second host to match.
    ///
    /// This is upstream's split, not a simplification: `indexOfPattern` returns
    /// 0 for this line, and its `patternIndex > 0` branch — the one that hands
    /// out several patterns — is the only place that ever does
    /// (`_original/lib/rules/rules.js:1767-1793`).
    #[test]
    fn pattern_first_form_takes_one_pattern_and_the_rest_are_operators() {
        let text = "a.com b.com host://8.8.8.8";
        assert_eq!(host_for(text, "http://a.com/").as_deref(), Some("8.8.8.8"));
        assert_eq!(host_for(text, "http://b.com/"), None);
        let rules = parse_text(text);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]
                .ops
                .iter()
                .find(|op| op.protocol == protocols::URL_REPLACE)
                .map(|op| op.value.as_str()),
            Some("b.com"),
            "the second token is a destination"
        );
    }

    /// Filters and line properties must not be mistaken for patterns — doing so
    /// both loses their effect and mints a rule that can never match.
    #[test]
    fn filters_and_props_are_not_patterns() {
        let rules = parse_text("a.com host://1.1.1.1 excludeFilter://m:GET lineProps://important");
        assert_eq!(rules.len(), 1, "only `a.com` is a pattern");
        assert_eq!(rules[0].filters.len(), 1);
        assert!(rules[0].props.has("important"));
    }

    // ── comments ──

    /// whistle's removeComment is a global `/#[^\r\n]*/g`, so a trailing comment
    /// is stripped rather than parsed as extra tokens.
    #[test]
    fn trailing_comment_is_stripped() {
        assert_eq!(
            host_for("a.com host://1.1.1.1   # 说明文字", "http://a.com/").as_deref(),
            Some("1.1.1.1")
        );
        let rules = parse_text("a.com host://1.1.1.1 # b.com c.com");
        assert_eq!(rules.len(), 1, "commented-out patterns must not become rules");
    }

    #[test]
    fn whole_line_comment_still_ignored() {
        assert!(parse_text("# a.com host://1.1.1.1").is_empty());
        assert!(parse_text("   # indented").is_empty());
    }

    // ── multi-line blocks ──

    #[test]
    fn multi_line_block_collapses() {
        let text = "line`\nhost://7.7.7.7\nwww.example.com\napi.example.com\n`";
        assert_eq!(
            host_for(text, "http://www.example.com/").as_deref(),
            Some("7.7.7.7")
        );
        assert_eq!(
            host_for(text, "http://api.example.com/").as_deref(),
            Some("7.7.7.7")
        );
        // The block markers must not survive as rules of their own.
        assert_eq!(parse_text(text).len(), 2);
    }

    #[test]
    fn rules_around_a_block_still_parse() {
        let text = "before.com host://1.1.1.1\nline`\nhost://2.2.2.2\ninside.com\n`\nafter.com host://3.3.3.3";
        assert_eq!(host_for(text, "http://before.com/").as_deref(), Some("1.1.1.1"));
        assert_eq!(host_for(text, "http://inside.com/").as_deref(), Some("2.2.2.2"));
        assert_eq!(host_for(text, "http://after.com/").as_deref(), Some("3.3.3.3"));
    }

    /// Comments are stripped before blocks are collapsed, so a `#` inside a
    /// block comments out that line only.
    #[test]
    fn comment_inside_a_block() {
        let text = "line`\nhost://4.4.4.4\nkept.com\n# skipped.com\n`";
        assert_eq!(host_for(text, "http://kept.com/").as_deref(), Some("4.4.4.4"));
        assert_eq!(host_for(text, "http://skipped.com/"), None);
    }

    /// An unterminated block still yields its rule rather than vanishing.
    #[test]
    fn unterminated_block_is_salvaged() {
        assert_eq!(
            host_for("line`\nhost://5.5.5.5\nlonely.com", "http://lonely.com/").as_deref(),
            Some("5.5.5.5")
        );
    }
}

#[cfg(test)]
mod documented_rules {
    //! Every rule the documentation lists, checked against the parser.
    //!
    //! The list is the sidebar of <https://wproxy.org/docs/rules/>, which is the
    //! contract a user reads. Checking against it is a different question from
    //! checking against `protocols.js`: the docs name aliases and destination
    //! forms the registry does not (`reqMerge`, `tlsOptions`, `ws`, `tunnel`),
    //! and they are what people actually type.
    //!
    //! Grepping for the names was tried first and answered wrong twice — once
    //! because a name is built with `format!`, once because `"intercept"` also
    //! appears as a JSON key in an unrelated hook. So this asks the parser.

    use super::*;

    /// What one documented name turns into when a rule is written with it.
    #[derive(PartialEq, Debug)]
    enum Lands {
        /// A named operator, after alias folding — the ordinary case. The
        /// string is the protocol as resolved, so an alias shows what it became.
        Operator(String),
        /// A destination rewrite. Correct for the `Map Remote` family: a
        /// `ws://…` token *is* a URL, and upstream files it the same way.
        Destination,
        /// A line property, not an operator (`lineProps`).
        LineProp,
        /// A filter condition rather than an operator.
        Filter,
        /// Nothing at all: the name configures nothing.
        Nothing,
    }

    fn lands(name: &str) -> Lands {
        // A value shaped so every family has something plausible to parse.
        let value = match name {
            "lineProps" => "important",
            "excludeFilter" | "includeFilter" => "m:GET",
            _ => "x",
        };
        // `lineProps` is a modifier, not an operator: a line carrying nothing
        // else configures nothing and is dropped — by this port and by upstream
        // alike. So it is probed alongside an operator, which is the only way it
        // is ever written.
        let line = match name {
            "lineProps" => format!("example.com ua://probe {name}://{value}\n"),
            _ => format!("example.com {name}://{value}\n"),
        };
        let rules = parse_text(&line);
        let Some(rule) = rules.first() else {
            return Lands::Nothing;
        };
        if name == "lineProps" {
            return match rule.ops.first().is_some_and(|op| op.props.has("important")) {
                true => Lands::LineProp,
                false => Lands::Nothing,
            };
        }
        if !rule.filters.is_empty() && rule.ops.is_empty() {
            return Lands::Filter;
        }
        match rule.ops.first() {
            None => Lands::Nothing,
            Some(op) if op.protocol == protocols::URL_REPLACE => Lands::Destination,
            Some(op) => Lands::Operator(op.protocol.clone()),
        }
    }

    /// The 92 names the documentation's rules sidebar lists.
    const DOCUMENTED: &[&str] = &[
        // Map Local
        "file", "xfile", "tpl", "xtpl", "rawfile", "xrawfile",
        // Map Remote — destinations, not named operators
        "https", "http", "wss", "ws", "tunnel",
        // DNS spoofing
        "host", "xhost", "proxy", "xproxy", "https-proxy", "xhttps-proxy", "socks", "xsocks", "pac",
        // Rewrite request
        "urlParams", "pathReplace", "sniCallback", "method", "tlsOptions", "reqHeaders",
        "forwardedFor", "ua", "auth", "cache", "referer", "reqType", "reqCharset", "reqCookies",
        "reqCors", "reqBody", "reqMerge", "reqPrepend", "reqAppend", "reqReplace", "reqWrite",
        "reqWriteRaw", "reqRules", "reqScript",
        // Rewrite response
        "statusCode", "replaceStatus", "redirect", "locationHref", "resHeaders", "responseFor",
        "resType", "resCharset", "resCookies", "attachment", "resCors", "resBody", "resMerge",
        "resPrepend", "resAppend", "resReplace", "htmlPrepend", "htmlBody", "htmlAppend",
        "cssPrepend", "cssBody", "cssAppend", "jsPrepend", "jsBody", "jsAppend", "trailers",
        "resWrite", "resWriteRaw", "resRules", "resScript", "frameScript",
        // General
        "pipe", "delete", "headerReplace",
        // Throttle
        "reqDelay", "resDelay", "reqSpeed", "resSpeed",
        // Tools
        "weinre", "log",
        // Settings
        "style", "enable", "disable", "lineProps",
        // Filters
        "excludeFilter", "includeFilter", "ignore", "skip",
    ];

    /// **What this proves and what it does not.** It proves every documented
    /// name reaches an operator rather than falling through the parser. It says
    /// nothing about whether that operator *behaves* like upstream's — that is
    /// what the unit tests and `tests/differential` are for, and it is the
    /// harder half. `style` is recognised here and deliberately has no traffic
    /// effect at all (it colours a row in whistle's own rule list).
    ///
    /// Not one of the 92 may configure nothing.
    ///
    /// `Destination` is a pass for the `Map Remote` family and only for it —
    /// those *are* URLs, and a name landing there by accident (because the
    /// parser did not recognise it) is exactly the fail-open this port has
    /// found and fixed four times.
    #[test]
    fn every_documented_rule_is_recognised() {
        const MAP_REMOTE: &[&str] = &["https", "http", "wss", "ws", "tunnel"];
        let mut missing = Vec::new();
        let mut stray = Vec::new();
        for name in DOCUMENTED {
            match lands(name) {
                Lands::Nothing => missing.push(*name),
                Lands::Destination if !MAP_REMOTE.contains(name) => stray.push(*name),
                _ => {}
            }
        }
        assert!(missing.is_empty(), "configure nothing: {missing:?}");
        assert!(
            stray.is_empty(),
            "silently became a destination rewrite, which is fail-open: {stray:?}"
        );
        assert_eq!(DOCUMENTED.len(), 92, "the sidebar had 92 entries when this was written");
    }

    /// Every documented rule is *measured* against real whistle, not merely
    /// recognised by the parser.
    ///
    /// The test above asks the parser a question the parser answers. This one
    /// asks whether anybody ever put the rule in front of the real thing —
    /// `tests/differential/` is where that happens, and a rule with no case
    /// there has been verified by reading only.
    ///
    /// It exists because the coverage figure kept being *quoted*. Twice today a
    /// number survived several rounds of reporting purely because using it never
    /// re-derived it; the remedy is to make quoting it the same act as running
    /// it. A name appearing in a corpus is a weak claim — it says a case exists,
    /// not that the case discriminates — but it is a claim that cannot rot
    /// silently, and today's other lesson is that the weak checks are the ones
    /// worth automating.
    #[test]
    fn every_documented_rule_has_a_differential_case() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differential");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // A checkout without the bench is not a failing checkout.
            return;
        };
        let mut corpus = String::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "js")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                corpus.push_str(&text);
            }
        }
        assert!(
            corpus.contains("reqHeaders://"),
            "read no corpus at all from {dir:?} — the check would pass vacuously"
        );
        let missing: Vec<_> = DOCUMENTED
            .iter()
            .filter(|name| !corpus.contains(&format!("{name}://")))
            .collect();
        assert!(
            missing.is_empty(),
            "documented but never put in front of real whistle: {missing:?}"
        );
    }

    /// The same walk, printed. Not a gate — a report, for when the question is
    /// "what does this port do with each of them" rather than "does it".
    ///
    /// `cargo test --lib -- --ignored --nocapture documented_rules::report`
    #[test]
    #[ignore]
    fn report() {
        let mut by_kind: std::collections::BTreeMap<String, Vec<&str>> = Default::default();
        for name in DOCUMENTED {
            let kind = match lands(name) {
                Lands::Operator(p) => match *name == p {
                    true => "operator".to_string(),
                    false => format!("alias -> {p}"),
                },
                Lands::Destination => "destination rewrite".to_string(),
                Lands::LineProp => "line property".to_string(),
                Lands::Filter => "filter condition".to_string(),
                Lands::Nothing => "NOTHING".to_string(),
            };
            by_kind.entry(kind).or_default().push(name);
        }
        println!("\n{} documented rules\n", DOCUMENTED.len());
        for (kind, names) in &by_kind {
            println!("  {:22} {:>3}   {}", kind, names.len(), names.join(" "));
        }
    }
}
