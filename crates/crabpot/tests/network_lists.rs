//! A running sandbox follows the network lists it is given while it runs.
//!
//! Like `windows_sandbox`, it is its own host: on Linux bwrap runs this binary
//! again as the helper in front of each command, so `main` calls
//! `run_from_args` first. The sandboxed command is `curl` asking an origin on
//! loopback through the proxy, and what it prints is the proxy's status.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::process::Command;
    use std::thread;

    use crabpot::{Config, Sandbox};

    /// A config that allows `allowed` and denies `denied`, and nothing else.
    fn config(allowed: &[&str], denied: &[&str]) -> Config {
        Config::from_json(
            &serde_json::json!({
                "network": {"allowedDomains": allowed, "deniedDomains": denied},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
            })
            .to_string(),
        )
        .expect("the config parses")
    }

    /// The port of an origin on loopback that answers every request with a 200.
    fn origin() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("the origin binds");
        let port = listener
            .local_addr()
            .expect("the origin has an address")
            .port();
        thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(mut client) = connection else { continue };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.ends_with(b"\r\n\r\n") {
                    match client.read(&mut buf) {
                        Ok(read @ 1..) => head.extend_from_slice(&buf[..read]),
                        _ => break,
                    }
                }
                let _ = client.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        port
    }

    /// The status the proxy answers `sandbox`'s command with for a request to
    /// the origin on `port`.
    fn status(sandbox: &Sandbox, port: u16) -> String {
        let mut curl = Command::new("sh");
        // The sandbox exempts loopback from the proxy, so the proxy is named
        // and the exemption dropped.
        curl.arg("-c").arg(format!(
            "unset NO_PROXY no_proxy; exec curl -s -o /dev/null -w '%{{http_code}}' \
             --max-time 20 --proxy \"$http_proxy\" http://127.0.0.1:{port}/"
        ));
        let output = sandbox
            .command(&curl)
            .expect("the command is wrapped")
            .output()
            .expect("the wrapped command runs");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    pub fn a_running_sandbox_follows_replaced_network_lists() {
        let port = origin();
        let sandbox = Sandbox::start(&config(&[], &[])).expect("the sandbox starts");
        assert_eq!(status(&sandbox, port), "403", "nothing is allowed yet");

        sandbox.replace_network_lists(&config(&["127.0.0.1"], &[]));
        assert_eq!(status(&sandbox, port), "200", "the added domain");

        sandbox.replace_network_lists(&config(&["127.0.0.1"], &["127.0.0.1"]));
        assert_eq!(status(&sandbox, port), "403", "the denied domain wins");

        sandbox.replace_network_lists(&config(&["127.0.0.1"], &[]));
        assert_eq!(status(&sandbox, port), "200", "the denial is lifted");
    }

    pub fn a_sandbox_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Sandbox>();

        let port = origin();
        let sandbox = Sandbox::start(&config(&[], &[])).expect("the sandbox starts");
        let open = config(&["127.0.0.1"], &[]);
        let shut = config(&[], &[]);
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..20 {
                        sandbox.replace_network_lists(&shut);
                        sandbox.replace_network_lists(&open);
                    }
                });
            }
        });
        assert_eq!(status(&sandbox, port), "200", "the last list is whole");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn main() {
    crabpot::run_from_args();
    let cases: [(&str, fn()); 2] = [
        (
            "a_running_sandbox_follows_replaced_network_lists",
            unix::a_running_sandbox_follows_replaced_network_lists,
        ),
        (
            "a_sandbox_can_be_shared_between_threads",
            unix::a_sandbox_can_be_shared_between_threads,
        ),
    ];
    for (name, case) in cases {
        case();
        println!("test {name} ... ok");
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn main() {}
