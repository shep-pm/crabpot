//! A descriptor the launcher inherits on fd 3 reaches the sandboxed command, as
//! shep's shepherd channel does. The cases drive the `crabpot` binary.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

/// A folder of the case's own, holding permissive-enough settings, since cases
/// of this binary run in parallel.
fn home(case: &str) -> PathBuf {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("inherited-fd-{case}-{}", std::process::id()));
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("settings.json"),
        r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
        }"#,
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
