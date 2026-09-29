//! `enable://hide` promises that a request is not recorded — not that it is
//! left off the screen. This checks the promise where it can be checked: every
//! way the console, the API and the embedding observer read the capture, and
//! every file the proxy wrote. A request that is shown is sent alongside, so an
//! empty answer means "hidden" and not "nothing was recorded at all".

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request over a fresh connection, read to the end.
async fn get(proxy: std::net::SocketAddr, target: &str, host: &str) -> String {
    let mut sock = TcpStream::connect(proxy).await.expect("connect proxy");
    sock.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write");
    let mut out = Vec::new();
    sock.read_to_end(&mut out).await.expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// An origin that answers with a body and a header nothing else here says.
async fn origin() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nx-secret: header-7c1\r\n\
                          content-length: 15\r\nconnection: close\r\n\r\nbody-secret-9f2",
                    )
                    .await;
            });
        }
    });
    addr
}

/// Every file under `dir`, as text.
fn files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
    out
}

#[tokio::test]
async fn a_hidden_request_is_not_recorded_anywhere() {
    let dir = std::env::temp_dir().join(format!("whistle-rs-hide-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let site = origin().await;
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };

    let observed: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = observed.clone();
    let proxy = whistle_rs::embed::Proxy::builder()
        .host("127.0.0.1".parse().unwrap())
        .storage_dir(&dir)
        .persist_sessions(true)
        .rules(format!(
            "http://{site}/hidden enable://hide\nhttp://{dead}/hidden enable://hide"
        ))
        .on_session(move |s| sink.lock().unwrap().push(s.url.clone()))
        .start()
        .await
        .expect("proxy starts");
    let addr = proxy.addr();
    let console = addr.to_string();

    // Hidden, and answered: the client gets its answer all the same.
    let answer = get(addr, &format!("http://{site}/hidden"), &site.to_string()).await;
    assert!(answer.ends_with("body-secret-9f2"), "{answer}");
    // Hidden, and failed: the 502 still says where it failed, but names no
    // session, because there is none to look up.
    let failed = get(addr, &format!("http://{dead}/hidden"), &dead.to_string()).await;
    assert!(failed.starts_with("HTTP/1.1 502"), "{failed}");
    assert_eq!(header(&failed, "x-whistle-rs-error"), Some("connect"));
    assert_eq!(header(&failed, "x-whistle-rs-session"), None, "{failed}");
    // Shown: the control.
    let shown = get(addr, &format!("http://{site}/shown"), &site.to_string()).await;
    assert!(shown.ends_with("body-secret-9f2"), "{shown}");

    // The observer is told about the shown one, and only it. It is told when
    // the body is over, so wait for that rather than for the answer.
    for _ in 0..200 {
        if !observed.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let told = observed.lock().unwrap().clone();
    assert_eq!(told, [format!("http://{site}/shown")], "{told:?}");

    // The API, every way it reads the capture.
    let list = get(addr, "/sessions.json", &console).await;
    let rows: serde_json::Value = serde_json::from_str(body(&list)).expect("json");
    let urls: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, [format!("http://{site}/shown")], "{rows}");
    let har = get(addr, "/sessions.har", &console).await;
    assert!(!body(&har).contains("/hidden"), "{har}");
    assert_eq!(
        body(&har).matches("body-secret-9f2").count(),
        1,
        "the shown one"
    );
    let search = get(addr, "/api/sessions/search?c=h%3Aheader-7c1", &console).await;
    let search: serde_json::Value = serde_json::from_str(body(&search)).expect("json");
    assert_eq!(search["scanned"], 1, "{search}");
    // No id nearby leads to a hidden one either: ids are not reused, so the
    // ones the hidden requests were given answer nothing.
    let shown_id = rows[0]["id"].as_u64().unwrap();
    for id in 1..shown_id {
        let detail = get(addr, &format!("/session.json?id={id}"), &console).await;
        assert_eq!(body(&detail), "null", "session {id}");
    }

    proxy.shutdown().await;

    // Disk: the history holds the shown request and nothing of the hidden
    // ones. The rules file names `/hidden` — it is the rule — so the check is
    // on what only a recorded session would carry: its URL in a history line.
    let written = files(&dir);
    let history: Vec<&(std::path::PathBuf, String)> = written
        .iter()
        .filter(|(p, _)| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    assert!(!history.is_empty(), "the shown request was written");
    for (path, text) in &history {
        assert!(!text.contains("/hidden"), "{}: {text}", path.display());
    }
    let lines: usize = history.iter().map(|(_, t)| t.lines().count()).sum();
    assert_eq!(lines, 1, "one history line, the shown request's");
    let _ = std::fs::remove_dir_all(&dir);
}
