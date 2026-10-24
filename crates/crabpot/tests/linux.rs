//! The binary re-enters inside bwrap as the helper (ADR-0014). The cases drive
//! the `crabpot` binary, since a unit test would re-enter the test binary.

#![cfg(target_os = "linux")]

use std::process::{Command, Output};

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

fn crabpot(args: &[&str]) -> Output {
    Command::new(CRABPOT)
        // The default write roots start with `~`, so the sandbox needs a `HOME`,
        // and one with no settings file in it keeps the default config.
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_helper_runs_the_command_and_passes_its_exit_status() {
    let direct = crabpot(&["--crabpot-helper", "init", "sh", "-c", "echo ran; exit 7"]);
    assert_eq!(direct.status.code(), Some(7), "{direct:?}");
    assert_eq!(direct.stdout, b"ran\n");

    let sandboxed = crabpot(&["--", "sh", "-c", "exit 5"]);
    assert_eq!(sandboxed.status.code(), Some(5), "{sandboxed:?}");

    let missing = crabpot(&["--crabpot-helper", "init", "/no/such/program"]);
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("/no/such/program"),
        "{missing:?}"
    );
}

#[test]
fn the_helper_passes_its_arguments_untouched() {
    let args = ["-d", "--", "--crabpot", "--crabpot-helper", "a b", ""];
    let mut helper = vec![
        "--crabpot-helper",
        "init",
        "sh",
        "-c",
        r#"printf '[%s]\n' "$@""#,
        "sh",
    ];
    helper.extend(args);

    let output = crabpot(&helper);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "[-d]\n[--]\n[--crabpot]\n[--crabpot-helper]\n[a b]\n[]\n"
    );
}

#[test]
fn the_binary_is_bound_read_only_inside_the_sandbox() {
    // The root is bound read-only too, so a refused write proves nothing. The
    // binary's own mount point, listed read-only, is the bind the wrap adds.
    let script =
        r#"awk -v p="$0" '$5 == p { split($6, o, ","); print o[1] }' /proc/self/mountinfo"#;

    let output = crabpot(&["--", "sh", "-c", script, CRABPOT]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ro\n");
}
