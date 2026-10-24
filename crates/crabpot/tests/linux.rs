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

/// Runs `script` as the command of the helper itself, with no bwrap around it,
/// so the namespaces under test are the ones the helper makes.
fn in_helper(script: &str) -> Output {
    let output = crabpot(&["--crabpot-helper", "init", "sh", "-c", script]);
    assert!(output.status.success(), "{output:?}");
    output
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_command_sees_itself_as_a_child_of_pid_1() {
    let output = in_helper("echo $$ $PPID");

    assert_eq!(stdout(&output), "2 1\n");
}

#[test]
fn proc_shows_only_the_sandbox_pids() {
    // A loop in the shell starts no process, so the pids are init's and the
    // shell's.
    let output = in_helper(r#"for p in /proc/[0-9]*; do echo "${p#/proc/}"; done"#);

    assert_eq!(stdout(&output), "1\n2\n");
}

#[test]
fn an_orphaned_grandchild_is_reaped() {
    // The middle shell prints the grandchild's pid and exits at once, so the
    // grandchild is left to init. The loop is bounded by a count, not a sleep.
    let script = r#"
        pid=$(sh -c 'sh -c "exit 0" >/dev/null & echo $!')
        i=0
        while [ -e /proc/$pid ] && [ $i -lt 2000000 ]; do i=$((i + 1)); done
        if [ -e /proc/$pid ]; then echo zombie; else echo reaped; fi
    "#;

    let output = in_helper(script);

    assert_eq!(stdout(&output), "reaped\n");
}

#[test]
fn the_user_namespace_fallback_runs_when_unshare_is_refused() {
    // Only a process without `CAP_SYS_ADMIN` is refused the first `unshare`.
    if stdout(&in_helper("id -u")) == "0\n" {
        return;
    }

    let output = in_helper("cat /proc/self/setgroups");

    assert_eq!(stdout(&output), "deny\n");
}

#[test]
fn the_process_is_not_dumpable() {
    // A process that is not dumpable cannot have its `environ` read by one
    // without `CAP_SYS_PTRACE`, and the command's own `environ` stays open to
    // it.
    let output = in_helper(
        r#"
        cat /proc/$$/environ >/dev/null || exit 1
        cat /proc/1/environ >/dev/null 2>&1 && echo readable || echo refused
        "#,
    );

    assert_eq!(stdout(&output), "refused\n");
}

#[test]
fn ambient_capabilities_are_cleared() {
    let output = in_helper("grep CapAmb /proc/self/status");

    assert_eq!(stdout(&output), "CapAmb:\t0000000000000000\n");
}
