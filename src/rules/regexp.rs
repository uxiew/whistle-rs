//! The regular expressions a rules file is written with.
//!
//! whistle is a Node program, so a `/…/` in a rule is a JavaScript `RegExp`:
//! [`pattern.md`] says so, and rules copied from a whistle setup rely on it —
//! `/api\/(?!internal)/`, `/(?<=\/v)\d+/`, `/(["'])(.*?)\1/` are all ordinary
//! there. This port compiled them with the `regex` crate, which has no
//! lookaround and no backreferences, and an expression it could not compile
//! was quietly read as something else: a literal, or nothing. A rule with a
//! lookahead in its pattern never matched; an `excludeFilter://` with one
//! never excluded, so the rule it guarded applied to everything.
//!
//! [`Regexp::js`] compiles with [regress], an ECMAScript engine — the one the
//! script engine here already uses for `RegExp`, so a regexp means the same
//! thing in a rule as it does in a `reqScript`.
//!
//! The patterns this port *generates* — a wildcard's expansion, a port
//! pattern — stay on the `regex` crate ([`Regexp::generated`]): they are
//! written here, in its syntax, and its linear-time guarantee is worth keeping
//! where the expression is ours.
//!
//! # What a user's expression can now cost
//!
//! regress backtracks, as V8 does. `/(a+)+$/` against a long run of `a`s takes
//! exponential time in both programs. That is the price of the syntax, and the
//! same one whistle charges.
//!
//! An ordinary expression costs more too, by a constant: measured on an M4 in
//! a release build, one pattern against one 80-byte URL takes 0.25–0.4 µs with
//! regress where the `regex` crate took 0.01–0.02 µs (`tests::cost_of_one_pattern_test`).
//! A rules file with a hundred regexp patterns therefore adds about 30 µs to a
//! request. Trying the `regex` crate first and falling back was considered and
//! not done: the two disagree on expressions both compile — `\d`, `\w`, `\b`,
//! `.` and case folding all differ — so the fast path would have been the old
//! bug with a narrower opening.
//!
//! [`pattern.md`]: https://wproxy.org/docs/rules/pattern.html
//! [regress]: https://docs.rs/regress

use std::cell::RefCell;
use std::collections::HashSet;
use std::ops::Range;
use std::sync::Mutex;

/// A compiled pattern, whichever engine it needed.
#[derive(Debug, Clone)]
pub struct Regexp(Engine);

#[derive(Debug, Clone)]
enum Engine {
    /// Written by the user, in JavaScript's syntax.
    Js(regress::Regex),
    /// Written by this port, in the `regex` crate's.
    Generated(regex::Regex),
}

impl From<regex::Regex> for Regexp {
    fn from(re: regex::Regex) -> Self {
        Regexp(Engine::Generated(re))
    }
}

impl Regexp {
    /// Compile `source` as `new RegExp(source, flags)` would.
    ///
    /// `flags` are JavaScript's. `g` and `y` are about *how a match is used*,
    /// not what matches, and are the caller's to read; every other letter is
    /// passed to the engine. `Err` is the engine's own message.
    pub fn js(source: &str, flags: &str) -> Result<Regexp, String> {
        regress::Regex::with_flags(source, flags)
            .map(|re| Regexp(Engine::Js(re)))
            .map_err(|e| e.to_string())
    }

    /// [`Regexp::js`] for a caller that carries on without the expression when
    /// it does not compile — which is every caller, because that is what
    /// whistle does (`toRegExp` catches and returns `null`,
    /// `_original/lib/util/index.js:723-735`).
    ///
    /// Carrying on is upstream's behaviour; doing it *silently* was this
    /// port's. The failure is [`report`]ed: once in the log, and to whoever is
    /// [`collect`]ing, which is how `whistle-rs explain` names the expression.
    /// `role` says where it was written — "pattern", "includeFilter" — and
    /// what happens without it.
    pub fn parsed(source: &str, flags: &str, role: &str) -> Option<Regexp> {
        match Regexp::js(source, flags) {
            Ok(re) => Some(re),
            Err(why) => {
                report(format!(
                    "/{source}/{flags} ({role}) is not a regular expression: {why}"
                ));
                None
            }
        }
    }

    /// A pattern this port generated itself.
    pub fn generated(re: regex::Regex) -> Regexp {
        Regexp(Engine::Generated(re))
    }

    pub fn is_match(&self, text: &str) -> bool {
        match &self.0 {
            Engine::Js(re) => re.find(text).is_some(),
            Engine::Generated(re) => re.is_match(text),
        }
    }

    /// The first match in `text`, with its groups.
    pub fn captures<'t>(&self, text: &'t str) -> Option<Caps<'t>> {
        self.captures_iter(text).next()
    }

    /// Every non-overlapping match in `text`, in order.
    pub fn captures_iter<'r, 't>(&'r self, text: &'t str) -> CapsIter<'r, 't> {
        match &self.0 {
            Engine::Js(re) => CapsIter::Js(re.find_iter(text), text),
            Engine::Generated(re) => CapsIter::Generated(re.captures_iter(text), text),
        }
    }

    /// `String.prototype.replace` with a function: the first match when
    /// `global` is false, every match when it is true.
    pub fn replace(
        &self,
        text: &str,
        global: bool,
        mut with: impl FnMut(&Caps<'_>) -> String,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for caps in self.captures_iter(text) {
            out.push_str(&text[last..caps.start()]);
            out.push_str(&with(&caps));
            last = caps.end();
            if !global {
                break;
            }
        }
        out.push_str(&text[last..]);
        out
    }
}

/// One match: the whole of it at index 0, the capture groups after.
#[derive(Debug, Clone)]
pub struct Caps<'t> {
    text: &'t str,
    groups: Vec<Option<Range<usize>>>,
}

impl<'t> Caps<'t> {
    /// Group `n`, or `None` when there is no such group or it took no part in
    /// the match (the untaken side of an alternation).
    pub fn get(&self, n: usize) -> Option<&'t str> {
        let range = self.groups.get(n)?.clone()?;
        Some(&self.text[range])
    }

    /// How many groups the expression has, the whole match included.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Every group in order, index 0 first.
    pub fn iter(&self) -> impl Iterator<Item = Option<&'t str>> + '_ {
        (0..self.groups.len()).map(|n| self.get(n))
    }

    pub fn start(&self) -> usize {
        self.whole().start
    }

    pub fn end(&self) -> usize {
        self.whole().end
    }

    fn whole(&self) -> Range<usize> {
        self.groups[0].clone().expect("group 0 is the match")
    }
}

/// [`Regexp::captures_iter`].
pub enum CapsIter<'r, 't> {
    Js(regress::Matches<'r, 't>, &'t str),
    Generated(regex::CaptureMatches<'r, 't>, &'t str),
}

impl<'t> Iterator for CapsIter<'_, 't> {
    type Item = Caps<'t>;

    fn next(&mut self) -> Option<Caps<'t>> {
        match self {
            CapsIter::Js(matches, text) => {
                let m = matches.next()?;
                let mut groups = Vec::with_capacity(m.captures.len() + 1);
                groups.push(Some(m.range()));
                groups.extend(m.captures);
                Some(Caps { text, groups })
            }
            CapsIter::Generated(matches, text) => {
                let caps = matches.next()?;
                let groups = caps.iter().map(|g| g.map(|g| g.range())).collect();
                Some(Caps { text, groups })
            }
        }
    }
}

// ── saying so when an expression does not compile ──────────────────────────

thread_local! {
    /// What [`collect`] is gathering on this thread, when it is.
    static COLLECTING: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Messages already logged, so an expression compiled once per request — the
/// `*Replace` family reads its pattern when the body arrives — warns once.
static LOGGED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// How many distinct messages are remembered before the memory is dropped and
/// started again. A bound, not a policy: a rules file has a handful.
const LOGGED_MAX: usize = 512;

/// Note a rule-text problem: to the collector on this thread if there is one,
/// and to the log the first time it is seen.
pub fn report(message: String) {
    COLLECTING.with(|c| {
        if let Some(list) = c.borrow_mut().as_mut()
            && !list.contains(&message)
        {
            list.push(message.clone());
        }
    });
    let mut logged = LOGGED.lock().unwrap_or_else(|e| e.into_inner());
    let seen = logged.get_or_insert_with(HashSet::new);
    if seen.len() >= LOGGED_MAX {
        seen.clear();
    }
    if seen.insert(message.clone()) {
        tracing::warn!("rules: {message}");
    }
}

/// Run `f` and hand back what it [`report`]ed along with its result.
///
/// Parsing is synchronous and single-threaded, so a thread-local is the whole
/// mechanism: nothing about the parser's signatures has to know that one
/// caller wants to hear what went wrong.
pub fn collect<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let outer = COLLECTING.with(|c| c.borrow_mut().replace(Vec::new()));
    let out = f();
    let problems = COLLECTING.with(|c| std::mem::replace(&mut *c.borrow_mut(), outer));
    (out, problems.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js(source: &str, flags: &str) -> Regexp {
        Regexp::js(source, flags).unwrap_or_else(|e| panic!("/{source}/{flags}: {e}"))
    }

    /// The constructs the `regex` crate refuses, each with a twin that must
    /// not match — "compiles" is not the claim, "means what JavaScript means"
    /// is.
    #[test]
    fn javascript_only_syntax_matches_as_javascript_does() {
        for (source, flags, yes, no) in [
            // Lookahead, positive and negative.
            (
                r"probe(?=\.test)",
                "",
                "http://probe.test/",
                "http://probe.nope/",
            ),
            (
                r"\/api\/(?!internal)",
                "",
                "http://a/api/users",
                "http://a/api/internal",
            ),
            // Lookbehind, positive and negative.
            (r"(?<=\/v)\d+", "", "http://a/v12", "http://a/x12"),
            (r"(?<!\/v)\d+$", "", "http://a/x7", "http://a/v7"),
            // A backreference.
            (r#"(["'])a\1"#, "", "x='a'", "x='a\""),
            // A named group and a reference to it.
            (r"(?<q>[ab])\k<q>", "", "xaay", "xaby"),
            // `\d` is ASCII in JavaScript; it is every Unicode digit in the
            // `regex` crate. An Arabic-Indic digit is not a `\d` there.
            (r"^\d$", "", "7", "\u{0663}"),
            // `\w` likewise, and `\b` with it.
            (r"^\w+$", "", "abc_1", "h\u{00e9}llo"),
            // Case-insensitivity is a flag, not the default.
            (r"PROBE", "i", "probe", "prob"),
            // `[^]` — any character, newline included. Not valid in `regex`.
            (r"a[^]b", "", "a\nb", "ab"),
            // `{` is a literal where it cannot be a quantifier.
            (r"a{,2}", "", "a{,2}", "aa"),
            // `\/` and other identity escapes.
            (r"a\/b\-c", "", "a/b-c", "a/b c"),
            // `s`: dot matches a newline.
            (r"a.b", "s", "a\nb", "a\n\nb"),
            // `m`: anchors at line breaks.
            (r"^b$", "m", "a\nb\nc", "ab"),
        ] {
            let re = js(source, flags);
            assert!(re.is_match(yes), "/{source}/{flags} should match {yes:?}");
            assert!(
                !re.is_match(no),
                "/{source}/{flags} should not match {no:?}"
            );
        }
    }

    /// What the change of engine costs on the path every request takes: one
    /// pattern tested against one URL. Run with
    /// `cargo test --release --lib regexp::tests::cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn cost_of_one_pattern_test() {
        let url = "https://www.example.com/static/js/app.3f9c2b.chunk.js?v=20260930&lang=zh-CN";
        for source in [r"\.js(\?|$)", r"^https://cdn\.", r"/api/v\d+/users/(\d+)"] {
            let js = js(source, "");
            let native = Regexp::generated(regex::Regex::new(source).unwrap());
            for (name, re) in [("regress", &js), ("regex  ", &native)] {
                let n = 200_000u32;
                let started = std::time::Instant::now();
                let mut hits = 0u32;
                for _ in 0..n {
                    hits += u32::from(re.is_match(std::hint::black_box(url)));
                }
                let each = started.elapsed().as_nanos() / u128::from(n);
                println!("{name} /{source}/  {each} ns per test ({hits} hits)");
            }
        }
    }

    #[test]
    fn groups_are_numbered_from_the_whole_match() {
        let re = js(r"\/(?<first>echo)\/(a\d)(x)?", "");
        let caps = re.captures("http://h/echo/a1?q").expect("matches");
        assert_eq!(caps.get(0), Some("/echo/a1"));
        assert_eq!(caps.get(1), Some("echo"));
        assert_eq!(caps.get(2), Some("a1"));
        // A group that took no part is there and empty-handed.
        assert_eq!(caps.get(3), None);
        assert_eq!(caps.len(), 4);
        assert_eq!(caps.get(9), None);
        assert_eq!((caps.start(), caps.end()), (8, 16));
    }

    #[test]
    fn replace_is_first_match_or_all() {
        let re = js(r"(?<=a)\d", "");
        let digit = |c: &Caps<'_>| format!("<{}>", c.get(0).unwrap());
        assert_eq!(re.replace("a1 b2 a3", false, digit), "a<1> b2 a3");
        assert_eq!(re.replace("a1 b2 a3", true, digit), "a<1> b2 a<3>");
        assert_eq!(re.replace("none", true, digit), "none");
        // An expression that can match nothing still terminates, and visits
        // each position once.
        let empty = js(r"x*", "");
        assert_eq!(empty.replace("ab", true, |_| "-".into()), "-a-b-");
    }

    #[test]
    fn a_generated_pattern_answers_the_same_questions() {
        let re = Regexp::generated(regex::Regex::new(r"^(\w+)://([^/]+)").unwrap());
        let caps = re.captures("http://example.com/x").expect("matches");
        assert_eq!(caps.get(1), Some("http"));
        assert_eq!(caps.get(2), Some("example.com"));
        assert!(re.is_match("ws://h"));
        assert!(!re.is_match("no scheme"));
    }

    /// An expression that is not JavaScript either is reported, by name, to
    /// whoever asked — and the caller carries on without it.
    #[test]
    fn an_expression_that_does_not_compile_is_reported() {
        let (re, problems) = collect(|| Regexp::parsed("a(", "", "pattern"));
        assert!(re.is_none());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("/a(/") && problems[0].contains("pattern"),
            "{problems:?}"
        );

        // Nothing is collected when nobody asked, and nothing leaks into the
        // next collection.
        assert!(Regexp::parsed("b(", "", "pattern").is_none());
        let ((), problems) = collect(|| ());
        assert!(problems.is_empty());

        // `u` makes JavaScript strict about escapes, and so it is here.
        assert!(Regexp::js(r"\-", "").is_ok());
        assert!(Regexp::js(r"\-", "u").is_err());
    }
}
