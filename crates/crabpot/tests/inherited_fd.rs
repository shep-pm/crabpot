//! A descriptor the launcher inherits on fd 3 reaches the sandboxed command, as
//! shep's shepherd channel does, and so does one on fd 7 when `network.publish`
//! is set. The cases drive the `crabpot` binary.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

/// A folder of the case's own, holding permissive-enough settings, since cases
/// of this binary run in parallel.
fn home(case: &str) -> PathBuf {
    home_publishing(case, "")
}

/// [`home`], with `publish` as the settings' `network.publish` entries.
fn home_publishing(case: &str, publish: &str) -> PathBuf {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fd-{case}-{}", std::process::id()));
    // The proxy's socket, `claude-http-<16 hex>.sock`, is made in this folder,
    // and a `sockaddr_un` takes 107 bytes of path.
    let socket = home.as_os_str().len() + "/claude-http-0123456789abcdef.sock".len();
    assert!(
        socket <= 107,
        "{} is too long for the proxy's socket",
        home.display()
    );
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("settings.json"),
        format!(
            r#"{{
            "network": {{"allowedDomains": [], "deniedDomains": [], "publish": [{publish}]}},
            "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
        }}"#
        ),
    )
    .unwrap();
    home
}

/// Runs `script` in the sandbox, with `redirect` applied to the launcher by a
/// shell, which is how a host hands a command a descriptor.
fn launch(home: &Path, redirect: &str, stdin: Stdio, script: &str) -> Output {
    Command::new("sh")
        .args(["-c", &format!(r#"exec "$@" {redirect}"#), "sh", CRABPOT])
        .arg("-s")
        .arg(home.join("settings.json"))
        .args(["--", "sh", "-c", script])
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("CLAUDE_CODE_TMPDIR", home.join("tmp"))
        .stdin(stdin)
        .output()
        .unwrap()
}

#[test]
fn a_descriptor_inherited_on_fd_3_reaches_the_command() {
    let home = home("reaches");
    let (ours, theirs) = UnixStream::pair().unwrap();

    let output = launch(
        &home,
        "3<&0 </dev/null",
        Stdio::from(std::os::fd::OwnedFd::from(theirs)),
        "echo from the command >&3",
    );

    assert!(output.status.success(), "{output:?}");
    let mut line = String::new();
    // The launcher and the command are gone, so no writer is left to wait on.
    (&ours).read_to_string(&mut line).unwrap();
    assert_eq!(line, "from the command\n");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_descriptor_inherited_on_fd_3_stays_open_after_startup() {
    let home = home("stays-open");
    let marker = home.join("marker");
    fs::write(&marker, "").unwrap();

    let output = launch(
        &home,
        "3<&0 </dev/null",
        Stdio::from(fs::File::open(&marker).unwrap()),
        "ls -l /proc/self/fd/3",
    );

    assert!(output.status.success(), "{output:?}");
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(
        listing.trim_end().ends_with(&*marker.to_string_lossy()),
        "{listing}"
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_descriptor_inherited_on_fd_7_reaches_the_command_when_network_publish_is_set() {
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let home = home_publishing("publish", &format!(r#""127.0.0.1:{port}""#));
    let (ours, theirs) = UnixStream::pair().unwrap();

    let output = launch(
        &home,
        "7<&0 </dev/null",
        Stdio::from(std::os::fd::OwnedFd::from(theirs)),
        "echo from the command >&7",
    );

    assert!(output.status.success(), "{output:?}");
    let mut line = String::new();
    (&ours).read_to_string(&mut line).unwrap();
    assert_eq!(line, "from the command\n");
    fs::remove_dir_all(home).unwrap();
}
