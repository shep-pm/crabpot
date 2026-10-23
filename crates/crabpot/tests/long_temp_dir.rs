//! The proxy's backend socket lives in the temp dir, and upstream's Node binds
//! it however long the dir's name makes the path (ADR-0003). Std refuses past
//! the 104 bytes of macOS's `sun_path`, and the differential harness cannot
//! name the temp dir each wrapper runs with, so this runs the wrapper itself.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// The length of the temp dir the wrapper runs with, which puts the mux socket
/// 25 bytes or so further, past 104.
const TEMP_DIR_LEN: usize = 100;

/// A temp dir of exactly [`TEMP_DIR_LEN`] bytes under one of its own.
fn long_temp_dir(test: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("crabpot-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let padding = TEMP_DIR_LEN
        .checked_sub(root.as_os_str().len() + 1)
        .expect("the temp dir is short enough to pad");
    let dir = root.join("t".repeat(padding));
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(dir.as_os_str().len(), TEMP_DIR_LEN);
    (root, dir)
}

#[test]
fn a_command_runs_with_a_temp_dir_that_carries_the_mux_socket_past_104_bytes() {
    let (root, temp) = long_temp_dir("long-temp-dir");
    let settings = root.join("settings.json");
    fs::write(
        &settings,
        r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
        }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crabpot"))
        .arg("-s")
        .arg(&settings)
        .args(["-c", "echo ran"])
        .env("TMPDIR", &temp)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&root);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ran\n");
}
