//! An operator's value read as data: the `{json}`, `a=b&c=d` and `a: b` lines
//! whistle accepts, nested `a.b[0]` keys built into objects and arrays, and
//! keeping the order the value was written in. Headers, cookies, params and
//! the body merges all read their values through this.

use super::*;

/// whistle's `_parseJSON` (`_original/lib/util/index.js:1135-1143`): the three
/// spellings a data-valued operator accepts, tried in order.
///
/// 1. **JSON** — `parseRawJson`, a plain `JSON.parse` in a `try`.
/// 2. **A query string** — `parseInlineJSON`, but *only* when the text contains
///    no whitespace at all (`SPACE_RE.test(text)` returns early otherwise), so
///    `a=1&b=2` is a pair list and `a=1 &b=2` is not.
/// 3. **The line format** — [`parse_plain_text`], one `name: value` per line.
///
/// The third was missing here, everywhere, and the documentation leads with it:
/// <https://wproxy.org/docs/rules/resMerge.html> opens with `resMerge://test=123`
/// and the `行格式` section of every data-operator page shows the multi-line form
/// through a `{value}` reference. Both did nothing in this port.
///
/// `resolve_keys` is `RESOLVE_KEY_RE` (`util/index.js:95`), which is exactly
/// `^re[qs]Merge://` — only the merge pair reads a dotted name as a path into
/// the object. Every other operator takes the name literally.
pub(super) fn parse_data_object(
    text: &str,
    resolve_keys: bool,
    is_content: bool,
) -> Option<serde_json::Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // `tryParseMatcher` comes **first**, and only for a value that is the rule's
    // own matcher rather than text some loader produced — its guard is `!text`
    // (`_original/lib/util/index.js:1165-1171`, ahead of `_parseJSON` at
    // `:1303`). It asks one question: does the matcher contain an `=`? If so the
    // whole thing is a query string, whitespace and newlines included.
    //
    // That is why `reqHeaders://x-a=${v}` with a two-line `v` sets **no** header
    // upstream: the value stays whole, carries a newline, and `setHeader` throws
    // on it. Splitting it into lines here instead produced a header whistle
    // never sends. A value that came from the values store takes the other road.
    if let Some(value) = crate::rules::url::parse_json(text) {
        return Some(value);
    }
    if !is_content {
        // A written matcher is a query string when it has an `=`, and **nothing
        // at all** when it does not. Measured, five shapes: `x-a=1` sets the
        // header; `x-a=line1\nline2` keeps the newline in the value and is
        // thrown away by the header layer; `bare` and a lone backtick set
        // nothing. The same words inside loaded content *do* become headers with
        // empty values, which is the line format doing its job — so the two
        // roads really are different, not one road read twice.
        let pairs = text.contains('=').then(|| ordered_pairs(text))??;
        return Some(serde_json::Value::Object(pairs.into_iter().collect()));
    }
    if !text.contains(char::is_whitespace) {
        let pairs = ordered_pairs(text)?;
        return Some(serde_json::Value::Object(pairs.into_iter().collect()));
    }
    parse_plain_text(text, resolve_keys)
}

/// The line format: one `name: value` per line, folded into an object.
///
/// `common.parsePlainText` (`_original/lib/util/common.js:1178-1217`). Upstream
/// starts the result as an array when the first key is numeric; this port always
/// builds an object, because the array case only arises through `resolve_keys`
/// and a numeric first segment, and every consumer here indexes by name.
pub(super) fn parse_plain_text(text: &str, resolve_keys: bool) -> Option<serde_json::Value> {
    let mut out = serde_json::Map::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = parse_data_line(line);
        match resolve_keys {
            true => insert_at_path(&mut out, &parse_json_path(&name), value),
            false => {
                out.insert(name, value);
            }
        }
    }
    (!out.is_empty()).then(|| serde_json::Value::Object(out))
}

/// One line of the line format (`parseLine`, `common.js:1134-1168`).
///
/// The separator is the first `": "`, else the first `':'`, else the first `'='`
/// — in that order, so `x-a: b:c` splits at the space-colon and keeps `b:c`. A
/// line with none of them is a name with an empty value.
///
/// A value wrapped in a matching pair of `"`, `'` or `` ` `` loses the quotes,
/// and a backticked one also turns its literal `\n` and `\r` into the real
/// characters. An unquoted value that is a safe integer becomes a number rather
/// than a string.
pub(super) fn parse_data_line(line: &str) -> (String, serde_json::Value) {
    let at = line
        .find(": ")
        .or_else(|| line.find(':'))
        .or_else(|| line.find('='));
    let Some(at) = at else {
        return (line.to_string(), serde_json::Value::String(String::new()));
    };
    let name = line[..at].trim().to_string();
    let value = line[at + 1..].trim();
    // Upstream asks one question first — **do the first and last characters
    // match?** — and only then which of the two branches to take:
    //
    // ```js
    // if (fv === lv) { …unquote…} else if (isSafeNumStr(value)) { value = parseInt(value, 10); }
    // ```
    //
    // (`parseLine`, `_original/lib/util/common.js:1145-1157`.) So the numeric
    // conversion is *unreachable* for a value whose ends match, and that is not
    // a quirk of quoting alone: `1`, `11` and `121` all stay strings while `123`
    // and `-12` become numbers. Measured against whistle 2.10.8 for each.
    let mut ends = value.chars();
    let first = ends.next();
    let last = ends.next_back().or(first);
    if first == last {
        if let Some(q) = first.filter(|c| "\"'`".contains(*c))
            && value.chars().count() >= 2
        {
            let inner = &value[q.len_utf8()..value.len() - q.len_utf8()];
            let inner = match q == '`' {
                true => inner.replace("\\n", "\n").replace("\\r", "\r"),
                false => inner.to_string(),
            };
            return (name, serde_json::Value::String(inner));
        }
        return (name, serde_json::Value::String(value.to_string()));
    }
    match safe_num(value) {
        Some(n) => (name, serde_json::Value::Number(n.into())),
        None => (name, serde_json::Value::String(value.to_string())),
    }
}

/// `isSafeNumStr` (`_original/lib/util/common.js:1016-1029`): `0`, or an
/// optionally-signed run of 1–16 digits with no leading zero, within JavaScript's
/// safe-integer range.
pub(super) fn safe_num(value: &str) -> Option<i64> {
    if value == "0" {
        return Some(0);
    }
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    let ok = (1..=16).contains(&digits.len())
        && digits.starts_with(|c: char| c.is_ascii_digit() && c != '0')
        && digits.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| value.parse::<i64>().ok())
        .flatten()
        .filter(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
}

/// Place `value` at a dotted path, creating the objects along the way.
/// A path segment, and whether it arrived as a bracket index.
///
/// The distinction is upstream's and it is the only thing that decides between
/// an array and an object: `parseKey` turns `a[0]` into the pair `['a', 0]` with
/// a **number** for the index (`+result[1]`, `_original/lib/util/common.js:1064`),
/// while a dotted `a.0` stays two strings. `parsePlainText` then opens an array
/// exactly when the next key is a number (`:1209-1212`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathSegment {
    pub(super) name: String,
    pub(super) is_index: bool,
}

impl PathSegment {
    pub(super) fn key(name: impl Into<String>) -> Self {
        PathSegment {
            name: name.into(),
            is_index: false,
        }
    }
    pub(super) fn index(name: impl Into<String>) -> Self {
        PathSegment {
            name: name.into(),
            is_index: true,
        }
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// Write `value` at `path`, opening the containers the path implies.
pub(super) fn insert_at_path(
    out: &mut serde_json::Map<String, serde_json::Value>,
    path: &[PathSegment],
    value: serde_json::Value,
) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        out.insert(first.name.clone(), value);
        return;
    }
    let slot = open_slot(out, &first.name, rest[0].is_index);
    insert_into(slot, rest, value);
}

/// The container under `name`, made if it is not there and replaced if what is
/// there cannot hold a path.
pub(super) fn open_slot<'a>(
    map: &'a mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    wants_array: bool,
) -> &'a mut serde_json::Value {
    map.entry(name.to_string())
        .and_modify(|v| {
            if !v.is_object() && !v.is_array() {
                *v = empty_container(wants_array);
            }
        })
        .or_insert_with(|| empty_container(wants_array))
}

pub(super) fn insert_into(
    node: &mut serde_json::Value,
    path: &[PathSegment],
    value: serde_json::Value,
) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    match node {
        serde_json::Value::Array(items) => {
            let at: usize = first.name.parse().unwrap_or(0);
            while items.len() <= at {
                items.push(serde_json::Value::Null);
            }
            if rest.is_empty() {
                items[at] = value;
                return;
            }
            if !items[at].is_object() && !items[at].is_array() {
                items[at] = empty_container(rest[0].is_index);
            }
            insert_into(&mut items[at], rest, value);
        }
        serde_json::Value::Object(map) => {
            if rest.is_empty() {
                map.insert(first.name.clone(), value);
                return;
            }
            let slot = open_slot(map, &first.name, rest[0].is_index);
            insert_into(slot, rest, value);
        }
        // A scalar cannot hold a path; the caller replaced one before
        // descending, so this is only reachable for a root that is neither.
        _ => {}
    }
}

/// The container a path segment opens: an array when the segment below it is a
/// bracket index, an object otherwise.
pub(super) fn empty_container(wants_array: bool) -> serde_json::Value {
    match wants_array {
        true => serde_json::Value::Array(Vec::new()),
        false => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// The entries of a `headerReplace://` value, in source order, in either
/// spelling upstream accepts.
///
/// `readRuleList` reads these operators as JSON **or** as a query string
/// (`parseRuleJson` → `tryParseMatcher` → `parseQuery`,
/// `_original/lib/util/index.js`), and the query-string form is the shorter of
/// the two: `headerReplace://resH.x-origin:/yes/=no`. This port took only the
/// JSON one, so that rule parsed, matched, and rewrote nothing — silently,
/// which is the failure mode the whole audit keeps turning up.
///
/// Splitting is upstream's `parseQuery`: `&` between entries, the **first** `=`
/// between key and value. A key here is `<scope>.<name>:<pattern>` and the
/// pattern may well contain `/` and `:`, which is why only the first `=` counts.
pub(super) fn ordered_pairs(text: &str) -> Option<Vec<(String, serde_json::Value)>> {
    if text.starts_with('{') {
        return json_object_in_order(text);
    }
    if text.is_empty() {
        return None;
    }
    let pairs: Vec<(String, serde_json::Value)> = text
        .split('&')
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((k, v)) => (k.to_string(), serde_json::Value::String(v.to_string())),
            // A key with no `=` replaces its pattern with nothing, which is how
            // `parseQuery` reads a bare name — an empty string, not a missing
            // entry.
            None => (entry.to_string(), serde_json::Value::String(String::new())),
        })
        .collect();
    (!pairs.is_empty()).then_some(pairs)
}

/// Parse a JSON object into its entries **in source order**.
///
/// `serde_json::Map` is a `BTreeMap` by default, which sorts — fine everywhere a
/// key is looked up by name, wrong wherever one entry's meaning depends on the
/// one before it (see [`apply_header_replace`]). Returns `None` for anything
/// that is not a JSON object.
pub(super) fn json_object_in_order(text: &str) -> Option<Vec<(String, serde_json::Value)>> {
    use serde::de::{MapAccess, Visitor};

    struct Ordered;

    impl<'de> Visitor<'de> for Ordered {
        type Value = Vec<(String, serde_json::Value)>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut out = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                out.push((k, v));
            }
            Ok(out)
        }
    }

    let mut de = serde_json::Deserializer::from_str(text);
    serde::Deserializer::deserialize_map(&mut de, Ordered).ok()
}
