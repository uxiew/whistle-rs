//! A storage directory belongs to one whistle-rs at a time (`whistle_rs::dir_lock`).
//!
//! Every instance holds the whole of its rule groups and values in memory and
//! writes the whole back on each save, so two on one directory silently undid
//! each other's edits (docs/STATUS.md, 2026-10-03). What is under test is one
//! process meeting another, so these start the real binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_whistle-rs");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "whistle-rs-data-dir-e2e-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A running binary, killed when dropped so a failed assertion leaves no
/// process behind.
struct Instance {
    child: Child,
    addr: String,
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command(dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["-p", "0", "--dir"]).arg(dir).args(extra);
    cmd
}

/// Start the binary on `dir` and wait for it to say where it listens.
fn start(dir: &Path, extra: &[&str]) -> Instance {
    try_start(dir, extra).expect("the instance starts")
}

/// Start on `dir` once its previous holder, just killed, has let go of it.
/// Windows releases a dead process's locks "depending on available system
/// resources", hence a few tries rather than one.
fn restart(dir: &Path) -> Instance {
    let began = Instant::now();
    loop {
        if let Some(instance) = try_start(dir, &[]) {
            return instance;
        }
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the directory stayed locked after its holder was killed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// [`start`], or `None` when the binary exits instead of listening.
fn try_start(dir: &Path, extra: &[&str]) -> Option<Instance> {
    let mut child = command(dir, extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn whistle-rs");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    // Keeps reading after the address, or a full pipe would stall the child.
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(rest) = line.split("whistle-rs listening on http://").nth(1) {
                let addr: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                    .collect();
                let _ = tx.send(addr);
            }
        }
    });
    let addr = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(addr) => addr,
        // Its stdout closed without an address: it exited.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.wait();
            return None;
        }
        Err(timeout) => panic!("the instance never said where it listens: {timeout}"),
    };
    // The log line comes from inside the bind, a moment before the address is
    // recorded beside the lock for the next instance's message.
    let owner = dir.join("lock.owner");
    let began = Instant::now();
    while !std::fs::read_to_string(&owner).is_ok_and(|line| line.contains(&addr)) {
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{} never named {addr}",
            owner.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Some(Instance { child, addr })
}

/// Run the binary on `dir` expecting it to stop by itself; its exit status
/// and what it wrote to stderr. A run still going after `limit` is a failure:
/// it means the second instance started.
fn run_to_exit(dir: &Path, limit: Duration) -> (std::process::ExitStatus, String) {
    let mut child = command(dir, &[])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn whistle-rs");
    let began = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .expect("stderr")
                .read_to_string(&mut stderr)
                .expect("read stderr");
            return (status, stderr);
        }
        if began.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running after {limit:?}: a second instance started on the directory");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `GET path` over HTTP/1.0, so the body comes back unframed.
fn get(addr: &str, path: &str) -> (u16, Vec<u8>) {
    request(addr, "GET", path, b"")
}

/// One request to the console over HTTP/1.0; its status and body.
fn request(addr: &str, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        sock,
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .expect("write head");
    sock.write_all(body).expect("write body");
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).expect("read");
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let status = std::str::from_utf8(&raw[..head_end])
        .expect("utf-8 head")
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status");
    (status, raw[head_end + 4..].to_vec())
}

/// Every file under `dir` with its size and modification time.
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, SystemTime)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).expect("read_dir") {
            let entry = entry.expect("entry");
            let meta = entry.metadata().expect("metadata");
            if meta.is_dir() {
                todo.push(entry.path());
            } else {
                out.push((entry.path(), meta.len(), meta.modified().expect("mtime")));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_second_instance_on_the_same_directory_is_refused() {
    let dir = scratch("same");
    let first = start(&dir, &[]);
    let before = snapshot(&dir);

    let (status, stderr) = run_to_exit(&dir, Duration::from_secs(10));
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
