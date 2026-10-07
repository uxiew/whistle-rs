//! A rule's script cannot stop the proxy.
//!
//! The script below held its request for ever before 2026-10-02: the engine's
//! loop limit counts per call, so a loop that calls a looping function passes
//! it on every call. And scripts ran on tokio's worker threads, so as many of
//! them as there are workers stopped everything else — other requests, the
//! console, the handler that makes SIGTERM exit. This runs the proxy on two
//! workers and sends it four.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RUNAWAY: &str = "function f() { for (var i = 0; i < 2000000; i++) {} }\n\
                       for (var j = 0; j < 2000000; j++) f();\n\
                       rules.push('* reqHeaders://x-ran=yes');";

/// An origin that answers `ok` and keeps the head of every request it gets.
async fn origin() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read_exact(&mut byte).await.is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, heads)
}

/// One request through the proxy; the whole answer back.
async fn get(proxy: std::net::SocketAddr, url: &str, host: &str) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read answer");
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_that_will_not_stop_holds_its_own_request_and_nothing_else() {
    let (addr, heads) = origin().await;
    let rules = format!(
        "slow.test host://{addr}\nslow.test reqScript://{{s.js}}\nquick.test host://{addr}\n\n\
         ``` s.js\n{RUNAWAY}\n```\n"
    );
    let proxy = whix::embed::Proxy::builder()
        .port(0)
        .persist_sessions(false)
        .storage_dir(
            std::env::temp_dir().join(format!("whix-script-limit-e2e-{}", std::process::id())),
        )
        .rules(rules)
        .start()
        .await
        .expect("proxy starts");
    let at = proxy.addr();

    // Twice as many scripts as there are workers.
    let started = Instant::now();
    let slow: Vec<_> = (0..4)
        .map(|_| tokio::spawn(get(at, "http://slow.test/", "slow.test")))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // While they run, the console and a request no script touches answer at
    // once — well inside the time the scripts are given.
    let asked = Instant::now();
    let status = get(at, "/api/status", &at.to_string()).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let quick = get(at, "http://quick.test/", "quick.test").await;
    assert!(quick.ends_with("ok"), "{quick}");
    let waited = asked.elapsed();
    assert!(
        waited < Duration::from_millis(500),
        "the console and an unscripted request waited {waited:?} behind the scripts"
    );

    // Each scripted request goes on once its script is stopped, without what
    // the script pushed — upstream's answer to a script past its 60 ms.
    for answer in slow {
        let answer = answer.await.expect("request task");
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("ok"), "{answer}");
    }
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 5, "{heads:?}");
    assert!(
        heads.iter().all(|h| !h.contains("x-ran")),
        "a stopped script's rules were applied: {heads:?}"
    );

    // And each says why on its session.
    let list = get(at, "/sessions.json", &at.to_string()).await;
    let rows: serde_json::Value =
        serde_json::from_str(list.split_once("\r\n\r\n").map_or("", |(_, b)| b)).expect("json");
    let stopped: Vec<_> = rows
        .as_array()
        .expect("a list")
        .iter()
        .filter(|r| r["url"].as_str().is_some_and(|u| u.contains("slow.test")))
        .collect();
    assert_eq!(stopped.len(), 4, "{rows}");
    for row in stopped {
        let note = &row["unapplied"][0];
        assert_eq!(note["kind"], "script-failed", "{row}");
        assert_eq!(note["ops"][0], "reqScript://{s.js}", "{row}");
        assert!(
            note["reason"]
                .as_str()
                .is_some_and(|r| r.contains("still running")),
            "{row}"
        );
    }
}
