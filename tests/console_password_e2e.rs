//! The console passwords can come from the environment instead of `-w`/`-W`.
//!
//! On the command line a password is in the process list, which any user of
//! the machine can read with `ps -A -o args=` (docs/STATUS.md, 2026-10-03).
//! The environment of a process is its owner's alone.

mod common;

use std::process::Command;
use std::time::Duration;

use base64::Engine;
use common::*;

const PASSWORD: &str = "WHIX_PASSWORD";
const GUEST_PASSWORD: &str = "WHIX_GUEST_PASSWORD";

/// The binary on a scratch directory, with none of the variables set unless
/// the test sets them — a developer's own shell may have them.
fn whistle(name: &str, args: &[&str]) -> (Command, std::path::PathBuf) {
    let dir = scratch(name);
    let mut cmd = command(&dir, args);
    cmd.env_remove(PASSWORD).env_remove(GUEST_PASSWORD);
    (cmd, dir)
}

/// The status a console call gets with these credentials, or none.
fn status(addr: &str, method: &str, login: Option<(&str, &str)>) -> u16 {
    let header = login.map(|(user, pass)| {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {token}")
    });
    let headers: Vec<(&str, &str)> = header
        .as_deref()
        .map(|h| vec![("Authorization", h)])
        .unwrap_or_default();
    let (path, body): (&str, &[u8]) = match method {
        "GET" => ("/api/values", b""),
        _ => ("/api/value", br#"{"name":"k","value":"v"}"#),
    };
    request_with(addr, method, path, &headers, body).0
}

fn log_of(instance: &Instance) -> String {
    instance.log.lock().unwrap().join("\n")
}

#[test]
fn a_password_from_the_environment_guards_the_console() {
    let (mut cmd, dir) = whistle("env-password", &["-n", "admin"]);
    cmd.env(PASSWORD, "from-env");
    let proxy = try_start(cmd, &dir).expect("starts");

    assert_eq!(status(&proxy.addr, "GET", None), 401, "no login");
    assert_eq!(status(&proxy.addr, "GET", Some(("admin", "wrong"))), 401);
    assert_eq!(status(&proxy.addr, "GET", Some(("admin", "from-env"))), 200);
    assert_eq!(
        status(&proxy.addr, "POST", Some(("admin", "from-env"))),
        200
    );

    let log = log_of(&proxy);
    assert!(!log.contains("process list"), "no warning: {log}");
    assert!(
        !log.contains("from-env"),
        "the password is not logged: {log}"
    );
    let token = base64::engine::general_purpose::STANDARD.encode("admin:from-env");
    let auth = format!("Basic {token}");
    let (code, body) = request_with(
        &proxy.addr,
        "GET",
        "/api/status",
        &[("Authorization", auth.as_str())],
        b"",
    );
    let body = String::from_utf8_lossy(&body);
    assert_eq!(code, 200, "{body}");
    assert!(!body.contains("from-env"), "nor reported: {body}");
}

#[test]
fn the_read_only_password_too() {
    let (mut cmd, dir) = whistle("env-guest", &["-n", "admin", "-N", "guest"]);
    cmd.env(PASSWORD, "admin-pass")
        .env(GUEST_PASSWORD, "guest-pass");
    let proxy = try_start(cmd, &dir).expect("starts");

    assert_eq!(
        status(&proxy.addr, "GET", Some(("guest", "guest-pass"))),
        200
    );
    assert_eq!(
        status(&proxy.addr, "POST", Some(("guest", "guest-pass"))),
        401,
        "read-only"
    );
    assert_eq!(status(&proxy.addr, "GET", Some(("guest", "wrong"))), 401);
    assert_eq!(
        status(&proxy.addr, "POST", Some(("admin", "admin-pass"))),
        200
    );
}

#[test]
fn a_password_on_the_command_line_still_works_and_is_warned_about() {
    let (cmd, dir) = whistle("argv-password", &["-n", "admin", "-w", "on-argv"]);
    let proxy = try_start(cmd, &dir).expect("starts");

    assert_eq!(status(&proxy.addr, "GET", Some(("admin", "on-argv"))), 200);
    let log = log_of(&proxy);
    assert!(
        log.contains("process list") && log.contains(PASSWORD),
        "says why, and what to use instead: {log}"
    );
    assert!(!log.contains("on-argv"), "without repeating it: {log}");
}

#[test]
fn the_command_line_wins_over_the_environment() {
    let (mut cmd, dir) = whistle("both", &["-n", "admin", "-w", "on-argv"]);
    cmd.env(PASSWORD, "from-env");
    let proxy = try_start(cmd, &dir).expect("starts");

    assert_eq!(status(&proxy.addr, "GET", Some(("admin", "on-argv"))), 200);
    assert_eq!(status(&proxy.addr, "GET", Some(("admin", "from-env"))), 401);
}

/// `-N/-W` with no admin account leaves the console open to everyone, and is
/// refused; a read-only password from the environment counts the same.
#[test]
fn a_read_only_password_alone_is_still_refused() {
    let (mut cmd, _dir) = whistle("guest-alone", &["-N", "guest"]);
    cmd.env(GUEST_PASSWORD, "guest-pass");
    let (status, stderr) = run_to_exit(cmd, Duration::from_secs(10));
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("-n and -w"), "{stderr}");
}

/// An empty variable is no password, rather than a password nobody can type.
#[test]
fn an_empty_variable_is_unset() {
    let (mut cmd, dir) = whistle("empty", &[]);
    cmd.env(PASSWORD, "");
    let proxy = try_start(cmd, &dir).expect("starts");
    assert_eq!(status(&proxy.addr, "GET", None), 200, "no login asked for");
}
