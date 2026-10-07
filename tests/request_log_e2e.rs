//! What the log says about each request, by default and with `-v`.
//!
//! Every request used to be an INFO line with its whole URL, query and all —
//! `GET http://host/api?token=secret -> …` — where upstream logs no request at
//! all. Run under a service manager, that is a file of tokens anyone who can
//! read the logs can read (docs/STATUS.md, 2026-10-06).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use common::*;

/// An origin that answers every request with a 200.
fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for mut sock in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && sock.read_exact(&mut byte).is_ok() {
                head.push(byte[0]);
            }
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    port
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// `GET url` through the proxy at `proxy`; the status.
fn through(proxy: &str, url: &str) -> u16 {
    let host = url.split('/').nth(2).expect("host");
    let mut sock = TcpStream::connect(proxy).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(sock, "GET {url} HTTP/1.0\r\nHost: {host}\r\n\r\n").expect("write");
    let mut answer = String::new();
    sock.read_to_string(&mut answer).expect("read");
    answer
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status")
}

/// The log once the lines for what was just sent have been written.
fn log_after(proxy: &Instance) -> String {
    std::thread::sleep(Duration::from_millis(300));
    proxy.log.lock().unwrap().join("\n")
}

#[test]
fn by_default_no_request_url_is_logged_and_a_failure_has_no_query() {
    let (ok, closed) = (origin(), closed_port());
    let proxy = start(&scratch("log-default"), &[]);
    assert_eq!(
        through(
            &proxy.addr,
            &format!("http://127.0.0.1:{ok}/api?token=secret")
        ),
        200
    );
    assert_eq!(
        through(
            &proxy.addr,
            &format!("http://127.0.0.1:{closed}/down?token=secret")
        ),
        502
    );
    let log = log_after(&proxy);
    assert!(!log.contains("token=secret"), "{log}");
    assert!(
        !log.contains("/api"),
        "a request that went through is not logged: {log}"
    );
    assert!(
        log.contains(&format!("http://127.0.0.1:{closed}/down -> failed at")),
        "a failure is, without its query: {log}"
    );
}

/// An error that quotes the request's URL loses its query in that line too: a
/// PAC file that throws is reported as `FindProxyForURL(<url>) threw`, which
/// put the token back after the URL in front of it had dropped it.
#[test]
fn a_failure_that_quotes_the_url_has_no_query_either() {
    let dir = scratch("log-pac");
    let pac = dir.join("throws.pac");
    std::fs::write(
        &pac,
        "function FindProxyForURL(url, host) { throw new Error('pac broke'); }",
    )
    .expect("pac");
    // Forward slashes, which a path on Windows takes as well as its own.
    let pac = pac.display().to_string().replace('\\', "/");
    let rules = dir.join("rules.txt");
    std::fs::write(&rules, format!("pac.test pac://{pac}\n")).expect("rules");
    let proxy = start(&dir, &["-r", rules.to_str().expect("utf-8 path")]);
    assert_eq!(
        through(&proxy.addr, "http://pac.test/api?token=secret"),
        502
    );
    let log = log_after(&proxy);
    assert!(
        log.contains("pac broke"),
        "the failure is still told: {log}"
    );
    assert!(!log.contains("token=secret"), "{log}");
}

#[test]
fn with_v_every_request_is_logged_in_full() {
    let ok = origin();
    let proxy = start(&scratch("log-verbose"), &["-v"]);
    assert_eq!(
        through(
            &proxy.addr,
            &format!("http://127.0.0.1:{ok}/api?token=secret")
        ),
        200
    );
    let log = log_after(&proxy);
    assert!(
        log.contains(&format!("GET http://127.0.0.1:{ok}/api?token=secret ->")),
        "{log}"
    );
}
