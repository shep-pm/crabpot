//! The sandbox makes the folder `TMPDIR` names and lets the command write in
//! it. `CLAUDE_CODE_TMPDIR` is process-wide, so each case runs the binary with
//! its own.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};

/// A folder of its own under the target's temp folder, removed when it drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("tmpdir-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `sh -c script` in a sandbox that allows no writes of its own, with
/// `CLAUDE_CODE_TMPDIR` set to `tmpdir`.
fn run_in(scratch: &Scratch, tmpdir: &PathBuf, script: &str) -> Output {
    let settings = scratch.0.join("settings.json");
    fs::write(
        &settings,
        r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
        }"#,
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_crabpot"))
        .arg("-s")
        .arg(&settings)
        .args(["--", "sh", "-c", script])
        .env("HOME", &scratch.0)
        .env("CLAUDE_CODE_TMPDIR", tmpdir)
        .output()
        .unwrap()
}

#[test]
fn a_tmpdir_outside_allow_write_is_made_and_the_command_writes_in_it() {
    let scratch = Scratch::new("made");
    let tmpdir = scratch.0.join("claude-code");

    let output = run_in(&scratch, &tmpdir, r#"echo written > "$TMPDIR/out""#);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(tmpdir.join("out")).unwrap(), "written\n");
    assert_eq!(
        fs::metadata(&tmpdir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn a_tmpdir_that_is_a_link_refuses_the_start() {
    let scratch = Scratch::new("link");
    let target = scratch.0.join("target");
    fs::create_dir(&target).unwrap();
    let tmpdir = scratch.0.join("claude-code");
    symlink(&target, &tmpdir).unwrap();

    let output = run_in(&scratch, &tmpdir, "echo ran");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("the temp folder is a symbolic link"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn a_tmpdir_that_is_relative_refuses_the_start() {
    let scratch = Scratch::new("relative");

    let output = run_in(&scratch, &PathBuf::from("claude-code"), "echo ran");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not an absolute path"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}
