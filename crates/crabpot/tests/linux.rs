//! The binary re-enters inside bwrap as the helper (ADR-0014). The cases drive
//! the `crabpot` binary, since a unit test would re-enter the test binary.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nix::sys::signal::{SigSet, Signal};

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
fn the_command_sees_the_sandbox_environment() {
    // `CLAUDE_CODE_TMPDIR` is pinned so the temp folder the command is handed
    // is known whatever the runner carries.
    let output = Command::new(CRABPOT)
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .env("CLAUDE_CODE_TMPDIR", "/tmp/claude-integration")
        .args([
            "--",
            "sh",
            "-c",
            r#"printf '%s\n' "$SANDBOX_RUNTIME" "$TMPDIR""#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "1\n/tmp/claude-integration\n"
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

/// Starts the helper on `script` with its standard output piped, so a test can
/// signal it and read what the command wrote.
fn spawn_helper(script: &str) -> Child {
    Command::new(CRABPOT)
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .args(["--crabpot-helper", "init", "sh", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

fn send(signal: &str, helper: &Child) {
    let sent = Command::new("kill")
        .args([format!("-{signal}"), helper.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
}

/// Sends `signal` to the helper once the command says it is ready, and returns
/// what the command wrote after that with the helper's exit status.
fn signal_a_ready_command(signal: &str) -> (String, ExitStatus) {
    // `wait` returns as soon as a trapped signal arrives, where a foreground
    // `sleep` would not.
    let script = format!("trap 'echo trapped; exit 3' {signal}; echo ready; sleep 30 & wait");
    let mut helper = spawn_helper(&script);
    let mut stdout = BufReader::new(helper.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");

    send(signal, &helper);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    (rest, helper.wait().unwrap())
}

#[test]
fn sigterm_reaches_the_command() {
    let (rest, status) = signal_a_ready_command("TERM");

    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn sigint_reaches_the_command() {
    let (rest, status) = signal_a_ready_command("INT");

    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn a_signal_death_gives_128_plus_the_signal() {
    // SIGKILL is not one the helper forwards, so the status is the mapping and
    // nothing else.
    let script = "kill -KILL $$";

    let direct = crabpot(&["--crabpot-helper", "init", "sh", "-c", script]);
    let sandboxed = crabpot(&["--", "sh", "-c", script]);

    assert_eq!(direct.status.code(), Some(137), "{direct:?}");
    assert_eq!(sandboxed.status.code(), Some(137), "{sandboxed:?}");
}

#[test]
fn a_signal_during_startup_is_not_lost() {
    // The helper starts with SIGTERM blocked and already pending, so the signal
    // arrives before it has a handler or a command to pass it to. The command
    // may start before the signal reaches it, so it is one that would run for a
    // minute: it must end by the signal, not run on.
    let mut term = SigSet::empty();
    term.add(Signal::SIGTERM);
    term.thread_block().unwrap();
    let helper = spawn_helper("exec sleep 60");
    send("TERM", &helper);
    term.thread_unblock().unwrap();

    // A signal lost on the way would leave the command to run its minute, and
    // one that looped in the helper would never end.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(helper.wait_with_output()));
    let output = receiver
        .recv_timeout(Duration::from_secs(20))
        .expect("the helper did not end")
        .unwrap();

    assert_eq!(output.status.code(), Some(143), "{output:?}");
}

/// Runs `script` under bash inside the sandbox, whose only way out is the
/// relays. bash opens `/dev/tcp`, which `sh` may not.
fn in_sandbox(script: &str) -> Output {
    let output = crabpot(&["--", "bash", "-c", script]);
    assert!(output.status.success(), "{output:?}");
    output
}

#[test]
fn the_relay_forwards_an_http_connect_to_the_proxy() {
    // No credential, so the proxy refuses the tunnel, and its refusal is the
    // proof the request got through port 3128 to the proxy.
    let output = in_sandbox(
        r#"exec 3<>/dev/tcp/localhost/3128 || exit 2
        printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' >&3
        head -n 1 <&3"#,
    );

    assert_eq!(
        stdout(&output),
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
    );
}

#[test]
fn the_relay_forwards_socks_to_the_proxy() {
    // Offering no login, the client is told no method is acceptable: `05 ff`.
    let output = in_sandbox(
        r#"exec 3<>/dev/tcp/localhost/1080 || exit 2
        printf '\005\001\000' >&3
        head -c 2 <&3 | od -An -tx1"#,
    );

    assert_eq!(stdout(&output).trim(), "05 ff");
}

#[test]
fn a_relay_that_cannot_bind_makes_the_helper_exit_1() {
    // The helper runs here with no network namespace of its own, so a listener
    // on 3128 is a port the relay cannot take. If another process holds it
    // already, that is the same.
    let _held = TcpListener::bind(("::", 3128)).or_else(|_| TcpListener::bind(("0.0.0.0", 3128)));

    let output = crabpot(&[
        "--crabpot-helper",
        "init",
        "--relay",
        "/no/such/proxy.sock",
        "echo",
        "ran",
    ]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "the command must not run: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("3128"),
        "{output:?}"
    );
}
