//! A storage directory belongs to one whistle-rs at a time (`whistle_rs::dir_lock`).
//!
//! Every instance holds the whole of its rule groups and values in memory and
//! writes the whole back on each save, so two on one directory silently undid
//! each other's edits (docs/STATUS.md, 2026-10-03). What is under test is one
//! process meeting another, so these start the real binary.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;

#[test]
fn a_second_instance_on_the_same_directory_is_refused() {
    let dir = scratch("same");
    let first = start(&dir, &[]);
    let before = snapshot(&dir);

    let (status, stderr) = run_to_exit(command(&dir, &[]), Duration::from_secs(10));
    assert!(!status.success(), "refused, not started: {stderr}");
    assert!(
        stderr.contains(&dir.display().to_string()),
        "names the directory: {stderr}"
    );
    assert!(
        stderr.contains(&format!("pid {}", first.child.id())) && stderr.contains(&first.addr),
        "says which instance holds it: {stderr}"
    );
    assert!(
        stderr.contains("--dir") && stderr.contains("-z"),
        "and what to do instead: {stderr}"
    );
    assert_eq!(snapshot(&dir), before, "touched nothing in the directory");
    assert_eq!(
        get(&first.addr, "/api/values").0,
        200,
        "the first one still answers"
    );

    // However the holder ends — here the way `kill -9` and a crash do, with no
    // code of its own running — the directory is free again.
    drop(first);
    let next = restart(&dir);
    assert_eq!(get(&next.addr, "/api/values").0, 200);
}

#[test]
fn separate_directories_share_a_root_through_the_certificate_directory() {
    // A root made the way the binary makes one, then handed to both by `-z`.
    let made = scratch("made");
    let config = whistle_rs::config::Config {
        storage_dir: made.clone(),
        ..whistle_rs::config::Config::default()
    };
    whistle_rs::ca::CertAuthority::load_or_create(&config).expect("root CA");
    let certs = scratch("certs");
    for name in ["root.key", "root.crt"] {
        std::fs::copy(made.join("certs").join(name), certs.join(name)).expect("copy");
    }
    let certs_arg = certs.to_str().expect("utf-8 path");

    let a = start(&scratch("a"), &["-z", certs_arg]);
    let b = start(&scratch("b"), &["-z", certs_arg]);
    let (status_a, root_a) = get(&a.addr, "/rootCA.crt");
    let (status_b, root_b) = get(&b.addr, "/rootCA.crt");
    assert_eq!((status_a, status_b), (200, 200));
    assert_eq!(root_a, root_b, "both hand out the same root");
    assert_eq!(
        root_a,
        std::fs::read(certs.join("root.crt")).expect("root.crt"),
        "the one in the certificate directory"
    );
}

/// A directory as the binary leaves it: a named group, a value.
fn kept_by_the_binary(name: &str) -> PathBuf {
    let dir = scratch(name);
    let rules = dir.join("rules");
    std::fs::create_dir_all(&rules).expect("rules dir");
    std::fs::write(
        rules.join("groups.json"),
        r#"{"groups":[{"name":"default","enabled":true},{"name":"alpha","enabled":true}]}"#,
    )
    .expect("groups.json");
    std::fs::write(rules.join("default.rules"), "kept.test 1.1.1.1").expect("default");
    std::fs::write(rules.join("alpha.rules"), "alpha.test 2.2.2.2").expect("alpha");
    std::fs::write(dir.join("values.json"), r#"{"token":"kept"}"#).expect("values");
    dir
}

/// An embedded proxy never reads the rule groups, values or switches on disk —
/// its rules come from the program embedding it — so it does not write them
/// either. It used to, on every console save, and its default directory is the
/// binary's: one save replaced the groups the binary kept there with its own.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_console_leaves_the_kept_rules_and_values_alone() {
    let dir = kept_by_the_binary("embedded-edits");
    let proxy = whistle_rs::embed::Proxy::builder()
        .port(0)
        .storage_dir(&dir)
        .rules("embedded.test 3.3.3.3")
        .start()
        .await
        .expect("embedded proxy");
    let addr = proxy.addr().to_string();
    let before = snapshot(&dir);

    let bundle = get(&addr, "/api/export").1;
    for (method, path, body) in [
        ("POST", "/api/rules", &b"edited.test 4.4.4.4"[..]),
        (
            "POST",
            "/api/rule-groups",
            br#"{"name":"beta","text":"b.test 5.5.5.5","enabled":true}"#,
        ),
        (
            "POST",
            "/api/rule-group/update",
            br#"{"name":"beta","text":"b.test 6.6.6.6"}"#,
        ),
        ("POST", "/api/rule-group/toggle", br#"{"name":"beta"}"#),
        ("DELETE", "/api/rule-group", br#"{"name":"beta"}"#),
        ("POST", "/api/value", br#"{"name":"other","value":"b"}"#),
        (
            "POST",
            "/api/value/rename",
            br#"{"name":"other","to":"renamed"}"#,
        ),
        ("DELETE", "/api/value", br#"{"name":"renamed"}"#),
        ("POST", "/api/values", br#"{"whole":"store"}"#),
        ("POST", "/api/switches", br#"{"rules":false}"#),
        ("POST", "/api/import", &bundle[..]),
    ] {
        let (status, answer) = request(&addr, method, path, body);
        assert_eq!(
            status,
            200,
            "{method} {path}: {}",
            String::from_utf8_lossy(&answer)
        );
    }

    assert_eq!(snapshot(&dir), before, "nothing on disk changed");
    proxy.shutdown().await;
}

/// History is the one thing an embedded proxy does keep in the directory, when
/// asked to. Then it needs the directory to itself, as the binary does; without
/// history it only reads the root there, and may share it with anyone.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_proxy_keeping_history_needs_the_directory_to_itself() {
    let dir = scratch("embedded-history");
    let binary = start(&dir, &[]);

    let refused = whistle_rs::embed::Proxy::builder()
        .port(0)
        .storage_dir(&dir)
        .persist_sessions(true)
        .start()
        .await
        .err()
        .expect("refused: the binary holds the directory");
    let text = refused.to_string();
    assert!(
        text.contains(&dir.display().to_string()) && text.contains(&binary.addr),
        "{text}"
    );
    assert!(
        text.contains("storage_dir") && text.contains("persist_sessions"),
        "advice in the embedder's terms, not the command line's: {text}"
    );

    let sharing = whistle_rs::embed::Proxy::builder()
        .port(0)
        .storage_dir(&dir)
        .start()
        .await
        .expect("without history it only shares the root");
    assert_eq!(
        sharing.root_ca_pem().as_bytes(),
        get(&binary.addr, "/rootCA.crt").1,
        "the same root the binary hands out"
    );
    sharing.shutdown().await;
}

/// The other side of the embedded test above: the binary keeps the console's
/// edits, because it is what reads them back on the next start.
#[test]
fn the_binary_keeps_console_edits_for_its_next_start() {
    let dir = scratch("binary-edits");
    let first = start(&dir, &[]);
    for (path, body) in [
        (
            "/api/rule-groups",
            &br#"{"name":"beta","text":"b.test 5.5.5.5","enabled":true}"#[..],
        ),
        ("/api/value", br#"{"name":"token","value":"kept"}"#),
        ("/api/switches", br#"{"rules":false}"#),
    ] {
        let (status, answer) = request(&first.addr, "POST", path, body);
        assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&answer));
    }
    drop(first);

    let next = restart(&dir);
    let text = |path| String::from_utf8(get(&next.addr, path).1).expect("utf-8");
    assert!(text("/api/rule-groups").contains("beta"), "the group");
    assert!(
        text("/api/values").contains("\"token\":\"kept\""),
        "the value"
    );
    assert!(
        text("/api/switches").contains("\"rules\":false"),
        "the switch"
    );
}
