//! `network.publish` on Linux: the host listens on each published address and
//! the helper's relay passes what connects into the command's network namespace.
//! The cases drive the `crabpot` binary. They sit apart from `linux.rs`, which is
//! at the size limit.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

/// Binds `address` inside the sandbox, says `ready` once it listens, then
/// answers each client's four bytes with `name`. A fourth argument is a file
/// to wait for first, after saying `waiting`.
const SERVER: &str = r#"
import os, socket, sys, time
address, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if len(sys.argv) > 4:
    print('waiting', flush=True)
    while not os.path.exists(sys.argv[4]):
        time.sleep(0.05)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((address, port))
server.listen()
print('ready', flush=True)
while True:
    client, _ = server.accept()
    with client:
        client.settimeout(5)
        request = b''
        while len(request) < 4:
            chunk = client.recv(4 - len(request))
            if not chunk:
                break
            request += chunk
        client.sendall(name.encode())
"#;

/// A sandbox that is ended when the case ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = kill(Pid::from_raw(self.0.id() as i32), Signal::SIGTERM);
        let _ = self.0.wait();
    }
}

/// A settings file that publishes `published`, written where only this case
/// reads it.
fn settings_publishing(case: &str, published: &[SocketAddr]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("publish-{case}-{}.json", std::process::id()));
    fs::write(
        &path,
        serde_json::json!({
            "network": {
                "allowedDomains": [],
                "deniedDomains": [],
                "publish": published.iter().map(ToString::to_string).collect::<Vec<_>>(),
            },
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
        })
        .to_string(),
    )
    .unwrap();
    path
}

fn crabpot_command(settings: &Path) -> Command {
    let mut command = Command::new(CRABPOT);
    command
        // The default write roots start with `~`, so the sandbox needs a `HOME`.
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .arg("-s")
        .arg(settings);
    command
}

/// Starts `SERVER` bound to `bind` as `name` in a sandbox that publishes
/// `published`, waiting for `gate` to exist first when it is given. The lines it
/// prints arrive on the receiver.
fn spawn_server(
    case: &str,
    published: SocketAddr,
    bind: SocketAddr,
    name: &str,
    gate: Option<&Path>,
) -> (Running, mpsc::Receiver<String>) {
    let settings = settings_publishing(case, &[published]);
    let mut child = crabpot_command(&settings)
        .args(["--", "python3", "-c", SERVER])
        .args([&bind.ip().to_string(), &bind.port().to_string(), name])
        .args(gate)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let running = Running(child);
    let (sender, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in stdout.lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    (running, lines)
}

/// The next line the sandboxed server prints, which must be `expected`.
fn expect_line(lines: &mpsc::Receiver<String>, expected: &str) {
    let line = lines
        .recv_timeout(Duration::from_secs(30))
        .expect("the sandboxed server did not start");
    assert_eq!(line, expected);
}

/// Starts `SERVER` bound to `bind` as `name` in a sandbox that publishes
/// `published`, and returns once it listens.
fn serve(case: &str, published: SocketAddr, bind: SocketAddr, name: &str) -> Running {
    let (running, lines) = spawn_server(case, published, bind, name, None);
    expect_line(&lines, "ready");
    running
}

/// What the command behind `address` answers a host client, empty when the
/// connection was closed on it. The port opens a moment after the command
/// listens, so a refusal is tried again for a while.
fn ask(address: SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client = loop {
        match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            Ok(client) => break client,
            Err(error)
                if error.kind() == ErrorKind::ConnectionRefused && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("{address} did not accept: {error}"),
        }
    };
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    let mut answer = String::new();
    // A connection the relay closes may be reset instead of ended.
    let _ = client.read_to_string(&mut answer);
    answer
}

/// A loopback port nothing holds now.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn host_address() -> Ipv4Addr {
    nix::ifaddrs::getifaddrs()
        .unwrap()
        .find_map(|interface| {
            let ip = interface.address?.as_sockaddr_in()?.ip();
            (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
        })
        .expect("the host has a non-loopback IPv4 address")
}

#[test]
fn a_command_listening_on_loopback_answers_a_host_client_through_publish() {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let _sandbox = serve("loopback", address, address, "inside");

    assert_eq!(ask(address), "inside");
    assert_eq!(ask(address), "inside", "the listener serves another client");
}

#[test]
fn a_host_probe_is_refused_until_the_command_listens_on_loopback() {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let gate = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("publish-gate-{}", std::process::id()));
    // A gate left by an earlier run would open this one before the probe.
    let _ = fs::remove_file(&gate);
    let (_sandbox, lines) = spawn_server("gated", address, address, "inside", Some(&gate));
    expect_line(&lines, "waiting");

    let probe = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap_err();
    assert_eq!(probe.kind(), ErrorKind::ConnectionRefused);

    fs::write(&gate, "").unwrap();
    expect_line(&lines, "ready");
    assert_eq!(ask(address), "inside");
}

#[test]
fn a_second_sandbox_publishing_the_same_port_starts_and_both_answer() {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let _first = serve("cutover-first", address, address, "first");
    let _second = serve("cutover-second", address, address, "second");

    // The system spreads clients over both listeners by their source ports, so
    // each answers within a few connections, once both are open.
    let mut answered = std::collections::BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while answered.len() < 2 && Instant::now() < deadline {
        answered.insert(ask(address));
    }

    assert_eq!(
        answered,
        ["first".to_owned(), "second".to_owned()]
            .into_iter()
            .collect()
    );
}

#[test]
fn a_command_bound_to_a_published_non_loopback_address_answers_through_it() {
    let address = SocketAddr::from((IpAddr::V4(host_address()), free_port()));
    let _sandbox = serve("non-loopback", address, address, "inside");

    assert_eq!(ask(address), "inside");
}

#[test]
fn a_published_port_the_host_holds_without_reuseport_refuses_the_sandbox() {
    // `TcpListener` sets no `SO_REUSEPORT`.
    let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = held.local_addr().unwrap();
    let settings = settings_publishing("held", &[address]);

    let output = crabpot_command(&settings)
        .args(["--", "python3", "-c", "print('ran')"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(&address.to_string()), "{error}");
}
