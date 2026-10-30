//! Signals sent to the wrapper must reach the command while the sandbox stays alive.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Signals the wrapper's pid, or its whole process group, which is how a host
/// that leads one signals it.
fn signal_through_wrapper(signal: &str, whole_group: bool) {
    // Tests of this binary run in parallel, so each case has a folder of its own.
    let mode = if whole_group { "group" } else { "pid" };
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("signal-{mode}-{signal}-{}", std::process::id()));
    fs::create_dir_all(&home).unwrap();
    let settings = home.join("settings.json");
    fs::write(
        &settings,
        r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
        }"#,
    )
    .unwrap();
    // A builtin read waits without a subprocess holding stdout open after the trap exits.
    let script = format!("trap 'echo trapped; exit 3' {signal}; echo ready; read -r line; exit 9");
    let mut launch = Command::new(env!("CARGO_BIN_EXE_crabpot"));
    if whole_group {
        launch.process_group(0);
    }
    let mut wrapper = launch
        .arg("-s")
        .arg(&settings)
        .args(["--", "sh", "-c", &script])
        .env("HOME", &home)
        .env("TMPDIR", &home)
        .env("CLAUDE_CODE_TMPDIR", home.join("tmp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = wrapper.id();
    let stdin = wrapper.stdin.take().unwrap();
    let mut stdout = BufReader::new(wrapper.stdout.take().unwrap());
    let (ready_sender, ready) = mpsc::channel();
    let (output_sender, output) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        ready_sender.send(line).unwrap();
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).unwrap();
        let _ = output_sender.send(rest);
    });
    let (exit_sender, exited) = mpsc::channel();
    thread::spawn(move || {
        let _ = exit_sender.send(wrapper.wait().unwrap());
    });

    let timeout = Duration::from_secs(20);
    assert_eq!(ready.recv_timeout(timeout).unwrap(), "ready\n");
    let target = if whole_group {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    let sent = Command::new("/bin/kill")
        .args(["-s", signal, "--", &target])
        .status()
        .unwrap();
    assert!(sent.success());
    let status = exited
        .recv_timeout(timeout)
        .expect("the wrapper did not exit after the signal");
    drop(stdin);
    let rest = output
        .recv_timeout(timeout)
        .expect("the command did not close stdout");
    fs::remove_dir_all(home).unwrap();

    assert_eq!(status.code(), Some(3), "{status:?}, stdout: {rest:?}");
    assert_eq!(rest, "trapped\n");
}

#[test]
fn sigquit_reaches_the_command_through_the_launcher() {
    signal_through_wrapper("QUIT", false);
}

#[test]
fn sigusr2_reaches_the_command_through_the_launcher() {
    signal_through_wrapper("USR2", false);
}

/// bwrap's own processes die on a signal they have no handler for, and take the
/// sandbox with them, so the group's signal must reach only the wrapper.
#[cfg(target_os = "linux")]
#[test]
fn a_signal_to_the_launchers_group_reaches_the_command_once() {
    for signal in ["USR1", "QUIT", "TERM"] {
        signal_through_wrapper(signal, true);
    }
}
