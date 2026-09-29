//! The search box's `h:` and `b:`, answered by the proxy.
//!
//! A row of `/sessions.json` carries neither headers nor bodies — carrying them
//! for every row on every poll is what the summary exists to avoid — so the
//! console cannot answer these two conditions from its list. It sends them to
//! `/api/sessions/search`, which reads every session held here, and filters its
//! rows by the ids that come back. Before this the console could only report
//! the two as unsupported.
//!
//! The grammar is the console's (`ui-src/src/filter/session-filter.js`): a
//! keyword is a case-insensitive substring, and `/…/flags` is an ECMAScript
//! regular expression. It is compiled by `regress`, which implements the same
//! syntax as the browser's `RegExp`, so a pattern means the same thing in the
//! box whichever side answers it — Rust's `regex` has no lookaround and would
//! refuse patterns the browser takes.
//!
//! What each condition reads, and how it differs from upstream:
//!
//! - `h:` — every request and response header. Upstream tests each name and
//!   each value on its own (`inObject`, `_original/biz/webui/htdocs/src/js/
//!   network-modal.js:465-477`), while its documentation's example
//!   `h:/cookie:\s*test=123/i` needs `name: value` as one line. A header here
//!   matches when its name, its value, or `name: value` does, so both work.
//! - `b:` — the request body and the response body as captured
//!   (`network-modal.js:184-193`), read as UTF-8 whatever their type. A capture
//!   is a bounded preview, so a match past what was kept cannot be found; the
//!   answer names the sessions that did not match *and* had a body cut short,
//!   so the console can say its "no" about them is not a "no".

use super::Session;

/// One `h:…` or `b:…` condition, compiled.
pub struct Condition {
    /// As the console wrote it, which is how the answer is matched back.
    raw: String,
    body: bool,
    test: Test,
}

enum Test {
    Keyword(regex::Regex),
    Pattern(regress::Regex),
}

impl Test {
    fn find(&self, text: &str) -> bool {
        match self {
            Test::Keyword(re) => re.is_match(text),
            Test::Pattern(re) => re.find(text).is_some(),
        }
    }
}

impl Condition {
    /// Compile `h:value` or `b:value`, or say why it cannot be.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (prefix, value) = raw
            .split_once(':')
            .ok_or_else(|| format!("{raw:?} has no prefix; this answers h: and b:"))?;
        let body = match prefix {
            "h" => false,
            "b" => true,
            _ => {
                return Err(format!(
                    "{prefix}: is not answered here; this answers h: and b:"
                ));
            }
        };
        if value.is_empty() {
            return Err(format!("{prefix}: has nothing to look for"));
        }
        Ok(Condition {
            raw: raw.to_string(),
            body,
            test: compile(value).map_err(|why| format!("{raw}: {why}"))?,
        })
    }
}

/// `/…/flags` is a regexp; anything else a case-insensitive substring — the
/// same split `toTest` makes in the console.
fn compile(value: &str) -> Result<Test, String> {
    let pattern = value
        .strip_prefix('/')
        .and_then(|rest| rest.rfind('/').map(|end| (&rest[..end], &rest[end + 1..])))
        .filter(|(_, flags)| flags.chars().all(|c| c.is_ascii_lowercase()));
    let Some((source, flags)) = pattern else {
        return regex::RegexBuilder::new(&regex::escape(value))
            .case_insensitive(true)
            .build()
            .map(Test::Keyword)
            .map_err(|e| e.to_string());
    };
    // The flags the browser's `RegExp` takes. `g`, `y` and `d` change how
    // repeated calls or match indices behave, which a yes/no test never sees.
    if let Some(bad) = flags.chars().find(|c| !"dgimsuvy".contains(*c)) {
        return Err(format!("{bad:?} is not a regexp flag"));
    }
    let kept: String = flags.chars().filter(|c| "imsuv".contains(*c)).collect();
    regress::Regex::with_flags(source, kept.as_str())
        .map(Test::Pattern)
        .map_err(|e| e.to_string())
}

/// What one condition found.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct Answer {
    pub condition: String,
    /// The sessions that match, oldest first.
    pub ids: Vec<u64>,
    /// `b:` only: sessions that did not match and had a body cut short — at
    /// the preview limit, or where its encoding stopped decoding. The part
    /// not kept could hold a match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partly_kept: Option<Vec<u64>>,
}

/// A session's searchable text, read once however many conditions ask.
struct Searchable {
    id: u64,
    headers: Vec<String>,
    bodies: Vec<String>,
    cut: bool,
}

impl Searchable {
    fn of(s: &Session) -> Self {
        let headers = s
            .req_headers
            .iter()
            .chain(&s.res_headers)
            .flat_map(|(name, value)| [name.clone(), value.clone(), format!("{name}: {value}")])
            .collect();
        let mut cut = false;
        let bodies = [&s.req_body, &s.res_body]
            .into_iter()
            .flatten()
            .map(|c| {
                let kept = c.preview_bytes();
                cut |= kept.truncated;
                String::from_utf8_lossy(&kept.bytes).into_owned()
            })
            .collect();
        Searchable {
            id: s.id,
            headers,
            bodies,
            cut,
        }
    }
}

/// Answer every condition over `sessions`.
pub fn search(sessions: &[Session], conditions: &[Condition]) -> Vec<Answer> {
    let held: Vec<Searchable> = sessions.iter().map(Searchable::of).collect();
    conditions
        .iter()
        .map(|c| {
            let mut ids = Vec::new();
            let mut partly_kept = Vec::new();
            for s in &held {
                let texts = if c.body { &s.bodies } else { &s.headers };
                if texts.iter().any(|t| c.test.find(t)) {
                    ids.push(s.id);
                } else if c.body && s.cut {
                    partly_kept.push(s.id);
                }
            }
            Answer {
                condition: c.raw.clone(),
                ids,
                partly_kept: c.body.then_some(partly_kept),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::Capture;
    use super::*;

    fn session(id: u64, headers: &[(&str, &str)], body: Option<Capture>) -> Session {
        Session {
            id,
            req_headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            res_body: body,
            ..Session::default()
        }
    }

    fn text(s: &str, cap: usize) -> Capture {
        Capture::from_bytes(s.as_bytes(), Some("application/json".into()), None, cap)
    }

    fn ask(sessions: &[Session], raw: &str) -> Answer {
        let c = Condition::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        search(sessions, &[c]).remove(0)
    }

    #[test]
    fn h_matches_a_name_a_value_or_the_line() {
        let held = [
            session(1, &[("cookie", "test=123; other=1")], None),
            session(2, &[("x-cookie-free", "yes")], None),
        ];
        assert_eq!(ask(&held, "h:test=123").ids, [1], "a value");
        assert_eq!(ask(&held, "h:COOKIE").ids, [1, 2], "a name, any case");
        // Upstream's documented example, which needs the whole line.
        assert_eq!(ask(&held, r"h:/cookie:\s*test=123/i").ids, [1]);
        // And a value on its own, anchored, as upstream's code tests it.
        assert_eq!(ask(&held, "h:/^yes$/").ids, [2]);
        assert_eq!(ask(&held, "h:nowhere").ids, [] as [u64; 0]);
        assert!(ask(&held, "h:x").partly_kept.is_none(), "headers are whole");
    }

    #[test]
    fn b_reads_the_kept_body_and_names_the_ones_cut_short() {
        let held = [
            session(1, &[], Some(text(r#"{"success":false}"#, 64))),
            session(2, &[], Some(text(r#"{"success":true, "pad": "…"}"#, 64))),
            // Cut after 5 bytes: whatever it says later, nobody can know.
            session(3, &[], Some(text(r#"{"success":false}"#, 5))),
            session(4, &[], None),
        ];
        let answer = ask(&held, r#"b:"success":false"#);
        assert_eq!(answer.ids, [1]);
        assert_eq!(answer.partly_kept, Some(vec![3]));
        // Cut, but matched in what was kept: a match, not a maybe.
        assert_eq!(ask(&held, "b:/^\\{\"su/").partly_kept, Some(vec![]));
    }

    /// The browser's `RegExp` syntax, which Rust's `regex` does not have.
    #[test]
    fn a_pattern_means_what_it_means_in_the_browser() {
        let held = [
            session(1, &[("x-price", "USD100")], None),
            session(2, &[("x-price", "EUR100")], None),
        ];
        assert_eq!(ask(&held, "h:/(?<=USD)100/").ids, [1], "lookbehind");
        assert_eq!(ask(&held, "h:/eur/i").ids, [2]);
        assert_eq!(ask(&held, "h:/eur/g").ids, [] as [u64; 0], "g is not i");
    }

    #[test]
    fn what_cannot_be_answered_is_refused_with_a_reason() {
        for (raw, says) in [
            ("m:POST", "not answered here"),
            ("b:", "nothing to look for"),
            ("b:/(unclosed/", "b:/(unclosed/"),
            ("h:/x/q", "not a regexp flag"),
            ("cookie", "no prefix"),
        ] {
            let why = Condition::parse(raw)
                .err()
                .unwrap_or_else(|| panic!("{raw} parsed"));
            assert!(why.contains(says), "{raw}: {why}");
        }
    }
}
