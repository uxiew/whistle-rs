//! A starting proxy answers while the `@` includes in its rules are still on
//! their way, as upstream does.
//!
//! It used to fetch them one after another, each with 16 s to answer, before
//! answering anything at all — its console included. Three includes on a
//! server that had hung (an intranet with the VPN down) kept it silent for
//! 48 s, where upstream answered in 0.3 s (docs/STATUS.md, 2026-10-06).

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use common::*;

/// A server on 127.0.0.1 that runs `answer` on every connection, each in a
/// thread of its own.
fn serve(answer: fn(std::net::TcpStream)) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            std::thread::spawn(move || answer(sock));
        }
    });
    port
}

/// Read the request head, then answer `body` with a 200.
fn reply(mut sock: std::net::TcpStream, body: &str) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && sock.read_exact(&mut byte).is_ok() {
        head.push(byte[0]);
    }
    let _ = write!(
        sock,
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
}

#[test]
fn includes_that_hang_do_not_keep_the_proxy_from_answering() {
    // Accepts, and never says a word.
    let hung = serve(|sock| {
        std::thread::sleep(Duration::from_secs(60));
        drop(sock);
    });
    let origin = serve(|sock| reply(sock, "origin"));
    // The include that does answer, at once: its rule applies from the start.
    let rules_server = serve(|sock| {
        let origin = std::env::var("WHIX_TEST_ORIGIN").unwrap_or_default();
        reply(
            sock,
            &format!("127.0.0.1:{origin}/inc resHeaders://x-included=1\n"),
        );
    });
    // SAFETY: set before any thread of this test reads it, and nothing else in
    // this test binary reads or writes the environment.
    unsafe { std::env::set_var("WHIX_TEST_ORIGIN", origin.to_string()) };

    let dir = scratch("includes-hang");
    let rules = dir.join("rules.txt");
    std::fs::write(
        &rules,
        format!(
            "@http://127.0.0.1:{hung}/a.txt\n@http://127.0.0.1:{hung}/b.txt\n\
             @http://127.0.0.1:{hung}/c.txt\n@http://127.0.0.1:{rules_server}/rules.txt\n\
             127.0.0.1:{origin} resHeaders://x-local=1\n"
        ),
    )
    .expect("rules");
    let proxy = start(&dir, &["-r", rules.to_str().expect("utf-8 path")]);

    let asked = Instant::now();
    let (status, _) = get(&proxy.addr, "/api/status");
    let took = asked.elapsed();
    assert_eq!(status, 200);
    assert!(
        took < Duration::from_secs(5),
        "the console answered after {took:?}"
    );

    // Through the proxy: the local rule and the include that answered.
    let mut sock = std::net::TcpStream::connect(&proxy.addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        sock,
        "GET http://127.0.0.1:{origin}/inc HTTP/1.0\r\nHost: 127.0.0.1:{origin}\r\n\r\n"
    )
    .expect("write");
    let mut answer = String::new();
    sock.read_to_string(&mut answer).expect("read");
    let head = answer.to_ascii_lowercase();
    assert!(head.contains("x-local: 1"), "{answer}");
    assert!(head.contains("x-included: 1"), "{answer}");

    let log = proxy.log.lock().unwrap().join("\n");
    assert!(
        log.contains("still loading") && log.contains(&format!("127.0.0.1:{hung}/a.txt")),
        "the log names what has not arrived: {log}"
    );
}
