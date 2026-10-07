//! One failed request, followed everywhere it is supposed to show up: the 502
//! the client gets, the console's API, the embedding observer, the history file
//! on disk, and the history read back after a restart. The acceptance for
//! failed sessions is that these all tell the same story.

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

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
}

#[tokio::test]
async fn a_failed_request_tells_the_same_story_everywhere() {
    let dir = std::env::temp_dir().join(format!("whix-failure-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };

    let observed: Arc<Mutex<Vec<whix::proxy::Session>>> = Arc::default();
    let sink = observed.clone();
    let proxy = whix::embed::Proxy::builder()
        .host("127.0.0.1".parse().unwrap())
        .storage_dir(&dir)
        .persist_sessions(true)
        .on_session(move |s| sink.lock().unwrap().push(s.clone()))
        .start()
        .await
        .expect("proxy starts");
    let addr = proxy.addr();

    // The client: a 502 that says it was made here, where it failed, and
    // which session to look up.
    let answer = get(addr, &format!("http://{dead}/gone"), &dead.to_string()).await;
    assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");
    assert_eq!(header(&answer, "x-whix-error"), Some("connect"));
    let id: u64 = header(&answer, "x-whix-session")
        .expect("names its session")
        .parse()
        .unwrap();
    let reason = body(&answer).trim_start_matches("whix: ").to_string();

    // The console's API: the list and the detail agree with the client.
    let list = get(addr, "/sessions.json", &addr.to_string()).await;
    let rows: serde_json::Value = serde_json::from_str(body(&list)).expect("json list");
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("session {id} listed: {rows}"));
    assert_eq!(row["error"]["phase"], "connect");
    assert_eq!(row["error"]["message"], reason.as_str());
    let detail = get(addr, &format!("/session.json?id={id}"), &addr.to_string()).await;
    let detail: serde_json::Value = serde_json::from_str(body(&detail)).expect("json detail");
    assert_eq!(detail["status"], 502);
    assert_eq!(detail["error"]["phase"], "connect");

    // The observer: told once.
    {
        let seen = observed.lock().unwrap();
        let mine: Vec<_> = seen.iter().filter(|s| s.id == id).collect();
        assert_eq!(mine.len(), 1, "observed exactly once");
        assert_eq!(mine[0].error.get().unwrap().message, reason);
    }

    // Disk: the history file holds the same failure. The writer is a task, so
    // give it a moment.
    let sessions_dir = dir.join("sessions");
    let mut line = None;
    for _ in 0..200 {
        line = std::fs::read_dir(&sessions_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .flat_map(|text| text.lines().map(str::to_string).collect::<Vec<_>>())
            .find(|l| l.contains(&format!("\"id\":{id},")));
        if line.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let line: serde_json::Value =
        serde_json::from_str(&line.expect("the failed session was written to disk")).unwrap();
    assert_eq!(line["error"]["phase"], "connect");
    assert_eq!(line["error"]["message"], reason.as_str());

    proxy.shutdown().await;

    // A restart: the history comes back with the reason still on it.
    let loaded = whix::proxy::persist::SessionStore::load(&sessions_dir, 600, 7);
    let back = loaded
        .iter()
        .find(|s| s.id == id)
        .expect("reloaded after a restart");
    assert_eq!(back.error.get().unwrap().message, reason);
    let _ = std::fs::remove_dir_all(&dir);
}
