//! What resolving a rules file costs one request — a measurement, not a check.
//!
//! Written for one question (ROADMAP R3-05): rule `/regexp/`s went from the
//! `regex` crate to a JavaScript engine on 2026-09-30 (`107be00`), and a single
//! test of one pattern against one URL went from 0.01–0.02 µs to 0.25–0.4 µs.
//! Whether a request notices depends on how many regexps a rules file has and
//! how much else resolving costs, which this measures on files of a realistic
//! shape. It uses only the public API, so the same file runs on a commit from
//! before the change:
//!
//! ```sh
//! cargo test --release --test rule_matching_cost -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use hyper::HeaderMap;
use whix::proxy::apply::build_req_info;
use whix::rules::RuleManager;

/// A rules file of `lines` rules, `regexps` of them `/…/` patterns spread
/// through it, the rest host and wildcard patterns — the mix a file kept by
/// hand for a few projects has.
fn rules_file(lines: usize, regexps: usize) -> String {
    // Every `every`th line is a regexp; none when there are none.
    let every = lines.checked_div(regexps);
    let mut out = String::new();
    for i in 0..lines {
        let line = if every.is_some_and(|e| i % e == 0 && i / e < regexps) {
            format!("/\\/api\\/v\\d+\\/item{i}\\/(\\d+)/ reqHeaders://x-item=$1\n")
        } else if i % 3 == 0 {
            format!("*.cdn{i}.example.net/static/ cache://60\n")
        } else {
            format!("host{i}.example.com resHeaders://x-host={i}\n")
        };
        out.push_str(&line);
    }
    out
}

/// The median of `rounds` timings of resolving `rules` for each of `urls`.
fn per_request(rules: &str, urls: &[(&str, &str)], rounds: usize) -> Duration {
    let mut mgr = RuleManager::new();
    mgr.set_text(rules);
    let infos: Vec<_> = urls
        .iter()
        .map(|(host, path)| {
            build_req_info("GET", "https", host, 443, path, &HeaderMap::new(), None)
        })
        .collect();
    let mut times = Vec::with_capacity(rounds);
    for round in 0..rounds + 50 {
        let started = Instant::now();
        for info in &infos {
            std::hint::black_box(mgr.resolve(std::hint::black_box(info)));
        }
        if round >= 50 {
            times.push(started.elapsed() / infos.len() as u32);
        }
    }
    times.sort();
    times[times.len() / 2]
}

#[test]
#[ignore = "a measurement, not a check; needs --release"]
fn cost_of_resolving_a_rules_file() {
    // Mostly misses, as most requests through a debugging proxy are; one hit
    // on a regexp line and one on a host line.
    let urls = [
        ("www.example.org", "/index.html"),
        ("static.example.org", "/js/app.3f9c2b.chunk.js?v=20260930"),
        ("api.example.org", "/api/v2/item0/42"),
        ("host1.example.com", "/"),
        ("img.cdn9.example.net", "/static/a.png"),
    ];
    println!("lines  regexps  per request");
    for (lines, regexps) in [
        (50, 0),
        (50, 10),
        (300, 0),
        (300, 30),
        (300, 100),
        (1000, 100),
        (1000, 300),
    ] {
        let rules = rules_file(lines, regexps);
        let each = per_request(&rules, &urls, 400);
        println!(
            "{lines:>5}  {regexps:>7}  {:>8.1} µs",
            each.as_secs_f64() * 1e6
        );
    }
}
