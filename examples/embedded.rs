//! Run whix inside your own program.
//!
//! ```sh
//! cargo run --example embedded
//! ```
//!
//! Three things an embedder wants and a standalone proxy does not give you:
//! the port it actually got, each transaction delivered to your code, and an
//! in-process hook that can change a request without a plugin subprocess.
//!
//! The example proves all three against a real request, then stops the proxy.

use std::sync::{Arc, Mutex};

use whix::embed::Proxy;
use whix::plugins::{PluginReq, PluginResp, PluginResult, RustPlugin};

/// An in-process interceptor. Anything a plugin can do, your own code can do
/// here — rewrite headers, inject rules, gate the request, or, as below, answer
/// it outright.
struct MockApi;

impl RustPlugin for MockApi {
    fn name(&self) -> &str {
        "mock-api"
    }

    fn on_request(&self, req: &PluginReq) -> PluginResult {
        println!("  [plugin] intercepted {} {}", req.method, req.url);
        PluginResult {
            response: Some(PluginResp {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"answered_by":"your program"}"#.to_vec(),
            }),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();

    let proxy = Proxy::builder()
        // Port 0: the OS picks, and `proxy.addr()` reports what it picked.
        .port(0)
        .host("127.0.0.1".parse()?)
        .storage_dir(std::env::temp_dir().join("whix-example"))
        .rules(
            "\
            # An endpoint your own code answers.\n\
            api.test        plugin://mock-api\n\
            # …and one forwarded somewhere else entirely.\n\
            docs.test       http://example.com\n",
        )
        // Every transaction, handed to you as it completes.
        .on_session(move |s| {
            recorder
                .lock()
                .unwrap()
                .push(format!("{} {} -> {}", s.method, s.url, s.status));
        })
        .plugin(MockApi)
        .start()
        .await?;

    let addr = proxy.addr();
    println!("proxy listening on {addr}");
    println!("root CA (install in a client to intercept its TLS):");
    println!("  {} bytes of PEM\n", proxy.root_ca_pem().len());

    // Drive one request through it, the way any HTTP client configured with
    // this proxy would.
    let body = get_via(addr, "http://api.test/users").await?;
    println!("  [client]  got: {body}\n");

    // Rules are live: swap them and the next request sees the change.
    proxy.set_rules("api.test statusCode://503");
    let again = get_via(addr, "http://api.test/users").await;
    println!(
        "  [client]  after swapping rules: {}\n",
        match again {
            Ok(b) => b,
            Err(e) => e.to_string(),
        }
    );

    println!("sessions your program was told about:");
    for line in seen.lock().unwrap().iter() {
        println!("  {line}");
    }

    proxy.shutdown().await;
    println!("\nproxy stopped; {addr} is free again");
    Ok(())
}

/// One request through the proxy, in the absolute form a forward proxy expects.
async fn get_via(addr: std::net::SocketAddr, url: &str) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut sock = tokio::net::TcpStream::connect(addr).await?;
    let host = url.split('/').nth(2).unwrap_or_default();
    sock.write_all(
        format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    let status = text.lines().next().unwrap_or("").to_string();
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(format!("{status} · {body}"))
}
