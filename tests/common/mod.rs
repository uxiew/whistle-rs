//! Starting the real binary and talking to it, for the tests that need a
//! process rather than the library: one process meeting another, a flag, an
//! environment variable. Each test file uses some of these, hence the allow.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

pub const BIN: &str = env!("CARGO_BIN_EXE_whistle-rs");

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("whistle-rs-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A running binary, killed when dropped so a failed assertion leaves no
/// process behind.
pub struct Instance {
    pub child: Child,
    pub addr: String,
    /// Every line it has written to stdout so far — its log.
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn command(dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["-p", "0", "--dir"]).arg(dir).args(extra);
    cmd
}

/// Start the binary on `dir` and wait for it to say where it listens.
pub fn start(dir: &Path, extra: &[&str]) -> Instance {
    try_start(command(dir, extra), dir).expect("the instance starts")
}

/// Start on `dir` once its previous holder, just killed, has let go of it.
/// Windows releases a dead process's locks "depending on available system
/// resources", hence a few tries rather than one.
pub fn restart(dir: &Path) -> Instance {
    let began = Instant::now();
    loop {
        if let Some(instance) = try_start(command(dir, &[]), dir) {
            return instance;
        }
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the directory stayed locked after its holder was killed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run `cmd` — [`command`] with whatever else the test needs, on `dir` — and
/// wait for it to listen; `None` when it exits instead.
pub fn try_start(mut cmd: Command, dir: &Path) -> Option<Instance> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn whistle-rs");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    let log = Arc::new(Mutex::new(Vec::new()));
    let lines = log.clone();
    // Keeps reading after the address, or a full pipe would stall the child.
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            lines.lock().unwrap().push(line.clone());
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
    Some(Instance { child, addr, log })
}

/// Run `cmd` expecting it to stop by itself: refused, not started. Its exit
/// status and what it wrote to stderr; still running after `limit` fails.
pub fn run_to_exit(mut cmd: Command, limit: Duration) -> (std::process::ExitStatus, String) {
    let mut child = cmd
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
            panic!("still running after {limit:?}: it started instead of refusing");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `GET path` over HTTP/1.0, so the body comes back unframed.
pub fn get(addr: &str, path: &str) -> (u16, Vec<u8>) {
    request(addr, "GET", path, b"")
}

/// One request to the console over HTTP/1.0; its status and body.
pub fn request(addr: &str, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    request_with(addr, method, path, &[], body)
}

/// [`request`], with headers of its own.
pub fn request_with(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes()).expect("write head");
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
pub fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, SystemTime)> {
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
