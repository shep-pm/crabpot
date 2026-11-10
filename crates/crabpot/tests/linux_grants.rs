//! The destinations a Linux sandbox lets its command reach: the
//! `network.allowTcp` addresses and the `network.allowUnixSockets` paths. Each
//! case starts the `crabpot` binary on a settings file that grants one thing and
//! nothing else, and runs `python3` as the command. They sit apart from
//! `linux.rs`, which is at the size limit (IR-48).

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{PoisonError, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use nix::sys::signal::Signal;

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn allow_tcp_exchanges_bytes_with_a_host_address() {
    tcp_round_trip("host", host_address(), None);
}

#[test]
fn allow_tcp_exchanges_bytes_with_an_address_resolved_at_startup() {
    tcp_round_trip("resolved", std::net::Ipv4Addr::LOCALHOST, Some("localhost"));
}

#[test]
fn allow_tcp_on_a_proxy_port_of_another_address_still_starts_the_sandbox() {
    // The relay's HTTP port is 3128 inside the sandbox.
    tcp_round_trip_on("proxy-port", host_address(), 3128, None);
}

#[test]
fn allow_tcp_refuses_a_scoped_ipv6_address_naming_it() {
    let settings = settings_allowing_tcp("scoped", &["[fe80::1%2]:22".to_owned()]);
    let output = run_script(&settings, "print('ran')");

    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("fe80::1%2"), "{error}");
}

fn tcp_round_trip(case: &str, address: std::net::Ipv4Addr, host: Option<&str>) {
    tcp_round_trip_on(case, address, 0, host);
}

fn tcp_round_trip_on(case: &str, address: std::net::Ipv4Addr, port: u16, host: Option<&str>) {
    let server = TcpListener::bind((address, port)).unwrap();
    let destination = server.local_addr().unwrap();
    let (done, answered) = mpsc::channel();
    thread::spawn(move || {
        let (mut client, _) = server.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        client.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"ping");
        client.write_all(b"pong").unwrap();
        done.send(()).unwrap();
    });
    let entry = match host {
        Some(host) => format!("{host}:{}", destination.port()),
        None => destination.to_string(),
    };
    let settings = settings_allowing_tcp(case, &[entry]);
    let output = run_script(
        &settings,
        &format!(
            r#"
import socket
with socket.create_connection(('{address}', {port}), timeout=5) as client:
    client.sendall(b'ping')
    client.shutdown(socket.SHUT_WR)
    with client.makefile('rb') as response:
        assert response.read() == b'pong'
print('exchanged')
"#,
            port = destination.port()
        ),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "exchanged\n");
    answered.recv_timeout(Duration::from_secs(10)).unwrap();
}

fn host_address() -> std::net::Ipv4Addr {
    nix::ifaddrs::getifaddrs()
        .unwrap()
        .find_map(|interface| {
            let address = interface.address?;
            let ip = address.as_sockaddr_in()?.ip();
            (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
        })
        .expect("the host has a non-loopback IPv4 address")
}

fn settings_allowing_tcp(case: &str, destinations: &[String]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("allow-tcp-{case}.json"));
    fs::write(
        &path,
        serde_json::json!({
            "network": {"allowedDomains": [], "deniedDomains": [], "allowTcp": destinations},
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
        })
        .to_string(),
    )
    .unwrap();
    path
}

/// Held shared by every sandbox a case here launches, and exclusively by one
/// whose settings list Unix sockets.
///
/// A plan with an `allowUnixSockets` list mounts `/dev/null` over every socket
/// `/proc/net/unix` names when it is built, and bwrap cannot mount over a path
/// that was unlinked since. The cases run in parallel threads, and each sandbox
/// binds a proxy socket of its own and unlinks it on exit, so a case that lists
/// sockets would meet a vanished one now and then (exit 125). It launches with
/// no other sandbox running instead.
static LAUNCH: RwLock<()> = RwLock::new(());

/// Runs `script` as `python3 -c` for the command of a sandbox started with
/// `settings`, and ends the sandbox if it has not finished in 20 seconds.
fn run_script(settings: &std::path::Path, script: &str) -> Output {
    let _launching = LAUNCH.read().unwrap_or_else(PoisonError::into_inner);
    run_script_unlocked(settings, script)
}

/// [`run_script`] for settings that list Unix sockets: no other sandbox is
/// launched while it runs. See [`LAUNCH`].
fn run_script_alone(settings: &std::path::Path, script: &str) -> Output {
    let _launching = LAUNCH.write().unwrap_or_else(PoisonError::into_inner);
    run_script_unlocked(settings, script)
}

fn run_script_unlocked(settings: &std::path::Path, script: &str) -> Output {
    let child = Command::new(CRABPOT)
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .args([
            "-s",
            settings.to_str().unwrap(),
            "--",
            "python3",
            "-c",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let (done, completed) = mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    match completed.recv_timeout(Duration::from_secs(20)) {
        Ok(output) => output.unwrap(),
        Err(error) => {
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGKILL);
            panic!("allowTcp command did not end: {error}");
        }
    }
}

#[test]
fn allow_tcp_refuses_a_host_server_on_an_unlisted_port() {
    let address = host_address();
    let server = TcpListener::bind((address, 0)).unwrap();
    let destination = server.local_addr().unwrap();
    let listed = TcpListener::bind((address, 0)).unwrap();
    let settings =
        settings_allowing_tcp("unlisted-port", &[listed.local_addr().unwrap().to_string()]);
    let output = run_script(
        &settings,
        &format!(
            r#"
import socket
try:
    socket.create_connection(('{address}', {port}), timeout=5)
except OSError:
    print('refused')
else:
    raise AssertionError('unlisted port was reachable')
"#,
            port = destination.port()
        ),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "refused\n");
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn allow_tcp_refuses_an_unresolved_host_before_running_the_command() {
    let settings =
        settings_allowing_tcp("unresolved", &["database.crabpot.invalid:5432".to_owned()]);
    let output = run_script(&settings, "print('ran')");

    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("database.crabpot.invalid"), "{error}");
    assert!(error.contains("cannot resolve"), "{error}");
}

/// A settings file whose `network.allowUnixSockets` is `sockets`, written where
/// the wrapper can read it.
fn settings_with_unix_sockets(case: &str, sockets: &[&str]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("allow-unix-{case}.json"));
    fs::write(
        &path,
        serde_json::json!({
            "network": {"allowedDomains": [], "deniedDomains": [], "allowUnixSockets": sockets},
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
        })
        .to_string(),
    )
    .unwrap();
    path
}

/// A Unix socket the host is listening on, named for `case`, held for as long as
/// a sandbox needs to dial it. The plan reads the kernel's socket listing when
/// it is built, so a socket must be there before `crabpot` starts.
fn listening(case: &str, name: &str) -> (PathBuf, std::os::unix::net::UnixListener) {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{case}-{name}"));
    let _ = fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("a socket to listen on");
    (path, listener)
}

#[test]
fn a_listed_unix_socket_is_reachable_from_the_command() {
    let (live, _held) = listening("listed", "live.sock");
    let settings = settings_with_unix_sockets("listed", &[live.to_str().unwrap()]);
    let output = run_script_alone(
        &settings,
        &format!(
            r#"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({live:?})
print('connected')
"#
        ),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "connected\n");
}

#[test]
fn a_unix_socket_the_list_leaves_out_is_refused() {
    let (listed, _listed) = listening("unlisted", "listed.sock");
    let (other, _other) = listening("unlisted", "other.sock");
    let settings = settings_with_unix_sockets("unlisted", &[listed.to_str().unwrap()]);
    let output = run_script_alone(
        &settings,
        &format!(
            r#"
import socket
for name, path in (('listed', {listed:?}), ('other', {other:?})):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path)
    except OSError:
        print(name, 'refused')
    else:
        print(name, 'connected')
"#
        ),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "listed connected\nother refused\n");
}

#[test]
fn a_listed_directory_leaves_every_socket_beneath_it_reachable() {
    let socks = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("listed-dir-socks");
    fs::create_dir_all(&socks).unwrap();
    // A listener's drop does not unlink its file, so a second run in this
    // target directory finds the last one's.
    let _ = fs::remove_file(socks.join("a.sock"));
    let _held = std::os::unix::net::UnixListener::bind(socks.join("a.sock")).unwrap();
    let settings = settings_with_unix_sockets("listed-dir", &[socks.to_str().unwrap()]);
    let output = run_script_alone(
        &settings,
        &format!(
            r#"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({a:?})
print('connected')
"#,
            a = socks.join("a.sock")
        ),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "connected\n");
}

#[test]
fn with_no_list_socket_af_unix_is_refused() {
    let settings = settings_with_unix_sockets("none", &[]);
    let output = run_script(
        &settings,
        r#"
import socket
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except PermissionError:
    print('refused')
else:
    raise AssertionError('AF_UNIX was open with no list')
"#,
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "refused\n");
}
