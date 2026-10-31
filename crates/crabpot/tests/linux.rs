//! The binary re-enters inside bwrap as the helper (ADR-0014). The cases drive
//! the `crabpot` binary, since a unit test would re-enter the test binary.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

    for code in [0, 1, 5, 125] {
        let sandboxed = crabpot(&[
            "--",
            "sh",
            "-c",
            &format!("test ! -e /proc/self/fd/3 || exit 99; exit {code}"),
        ]);
        assert_eq!(sandboxed.status.code(), Some(code), "{sandboxed:?}");
    }

    let missing = crabpot(&["--crabpot-helper", "init", "/no/such/program"]);
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("/no/such/program"),
        "{missing:?}"
    );
}

#[test]
fn a_bwrap_that_ends_without_reporting_a_pid_exits_125() {
    bwrap_that_never_starts_the_helper(false);
}

#[test]
fn a_bwrap_that_reports_a_pid_but_never_starts_the_helper_exits_125() {
    bwrap_that_never_starts_the_helper(true);
}

fn bwrap_that_never_starts_the_helper(reports_pid: bool) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "bwrap-without-helper-{reports_pid}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let bwrap = root.join("bwrap");
    fs::write(
        &bwrap,
        r#"#!/bin/sh
case "$1" in
    --version) echo 'bubblewrap 0.9.0'; exit 0 ;;
    --unshare-user) exit 0 ;;
esac
if [ "$CRABPOT_TEST_BWRAP_REPORT" = 1 ]; then
    echo '{"child-pid": 4242}' >&8
fi
echo 'bwrap ended without starting the helper' >&2
exit "$CRABPOT_TEST_BWRAP_EXIT"
"#,
    )
    .unwrap();
    fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o700)).unwrap();
    let settings = root.join("settings.json");
    fs::write(
        &settings,
        r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
        }"#,
    )
    .unwrap();

    for code in [0, 1, 7] {
        let output = Command::new(CRABPOT)
            .env("HOME", &root)
            .env("PATH", &root)
            .env("CRABPOT_TEST_BWRAP_EXIT", code.to_string())
            .env(
                "CRABPOT_TEST_BWRAP_REPORT",
                if reports_pid { "1" } else { "0" },
            )
            .arg("--settings")
            .arg(&settings)
            .args(["--", "/bin/sh", "-c", "echo ran"])
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(125),
            "bwrap exit {code}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("bwrap ended without starting the helper"),
            "{output:?}"
        );
    }
    fs::remove_dir_all(root).unwrap();
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

#[test]
fn the_command_runs_under_the_seccomp_filters_with_no_new_privs() {
    // Mode 2 is a filter installed, and the bit is what let an unprivileged
    // process install it.
    let output = in_helper("grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status");

    assert_eq!(stdout(&output), "NoNewPrivs:\t1\nSeccomp:\t2\n");
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
fn sigusr1_reaches_the_command() {
    let (rest, status) = signal_a_ready_command("USR1");

    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn sigusr2_reaches_the_command() {
    let (rest, status) = signal_a_ready_command("USR2");

    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
}

/// How long the launcher may take to start its command and to end it after a
/// signal. A signal that is lost leaves it running, so the wait is bounded and
/// a hang fails the test instead of the job.
const LAUNCHER_WAIT: Duration = Duration::from_secs(30);

/// What arrives on `lines`, or a failure that ends `launcher` first, so no
/// sandbox outlives the test. `stderr` is what a background thread reads from
/// the launcher's stderr, which the sandboxed command may hold open after the
/// launcher is killed, so it is collected for a bounded time and not to its end.
fn within_wait(
    lines: &mpsc::Receiver<String>,
    stderr: &mpsc::Receiver<String>,
    launcher: &mut Child,
    what: &str,
) -> String {
    match lines.recv_timeout(LAUNCHER_WAIT) {
        Ok(text) => text,
        Err(_) => {
            let _ = launcher.kill();
            let stderr = stderr
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| "(still open after the launcher was killed)".to_owned());
            panic!("the launcher gave no {what} in {LAUNCHER_WAIT:?}; stderr: {stderr}");
        }
    }
}

/// Starts the launcher on a command that traps `signal`, signals the launcher
/// once the command says it is ready, and returns what the command wrote after
/// that with the launcher's exit status.
fn signal_a_ready_launcher(signal: &str) -> (String, ExitStatus) {
    let script = format!("trap 'echo trapped; exit 3' {signal}; echo ready; sleep 30 & wait");
    let mut launcher = Command::new(CRABPOT)
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .args(["--", "sh", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = launcher.stdout.take().unwrap();
    let mut stderr_pipe = launcher.stderr.take().unwrap();
    let (sender, lines) = mpsc::channel();
    thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let _ = stdout.read_line(&mut line);
        let _ = sender.send(line);
        let mut rest = String::new();
        let _ = stdout.read_to_string(&mut rest);
        let _ = sender.send(rest);
    });
    let (stderr_sender, stderr) = mpsc::channel();
    thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr_pipe.read_to_string(&mut text);
        let _ = stderr_sender.send(text);
    });
    let ready = within_wait(&lines, &stderr, &mut launcher, "ready line");
    assert_eq!(ready, "ready\n");

    send(signal, &launcher);
    let rest = within_wait(&lines, &stderr, &mut launcher, "end after the signal");
    (rest, launcher.wait().unwrap())
}

#[test]
fn sigterm_through_the_launcher_reaches_the_command() {
    let (rest, status) = signal_a_ready_launcher("TERM");

    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn sigint_through_the_launcher_reaches_the_command() {
    let (rest, status) = signal_a_ready_launcher("INT");

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

fn helper_in_bwrap(options: &[&str], script: &str) -> Output {
    let proxy = crabpot_core::proxy::Proxy::start(&[], &[], &[], false, None).unwrap();
    let bwrap = crabpot_linux::deps::check_here().unwrap();
    let wrapped = crabpot_linux::wrap::words(
        &bwrap,
        &crabpot_core::config::Config::default(),
        std::path::Path::new(CRABPOT),
        proxy.mux_socket(),
        crabpot_linux::deps::is_root_with_setfcap_here(),
    )
    .unwrap();
    Command::new(&wrapped.words[0])
        .args(&wrapped.words[1..])
        .args([
            "--",
            "sh",
            "-c",
            "readlink /proc/self/ns/net; exec \"$@\"",
            "sh",
            CRABPOT,
            "--crabpot-helper",
            "init",
            "--relay",
        ])
        .arg(proxy.mux_socket())
        .args(options)
        .args(["python3", "-c", script])
        .output()
        .unwrap()
}

#[test]
fn loopback_addresses_are_dialable_in_a_new_network_namespace_with_the_proxy() {
    let output = helper_in_bwrap(
        &[
            "--loopback",
            "10.9.9.9",
            "--loopback",
            "10.9.9.10",
            "--loopback",
            "fd00::5",
        ],
        r#"
import os, socket
print(os.readlink('/proc/self/ns/net'))
for family, address in [(socket.AF_INET, '10.9.9.9'), (socket.AF_INET, '10.9.9.10'), (socket.AF_INET6, 'fd00::5')]:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.settimeout(5)
        server.bind((address, 0))
        server.listen()
        with socket.create_connection((address, server.getsockname()[1]), timeout=5) as client:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                client.sendall(b'ping')
                assert connection.recv(4) == b'ping'
    print('dialed ' + address)
with socket.create_connection(('127.0.0.1', 3128), timeout=5) as proxy:
    proxy.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')
    with proxy.makefile('rb') as response:
        assert response.readline() == b'HTTP/1.1 407 Proxy Authentication Required\r\n'
print('proxy reached')
assert sorted(p for p in os.listdir('/proc') if p.isdigit()) == ['1', '2']
"#,
    );

    assert!(output.status.success(), "{output:?}");
    let text = stdout(&output);
    let lines: Vec<_> = text.lines().collect();
    assert_ne!(lines[0], lines[1], "{text}");
    assert_eq!(
        &lines[2..],
        [
            "dialed 10.9.9.9",
            "dialed 10.9.9.10",
            "dialed fd00::5",
            "proxy reached"
        ]
    );
}

#[test]
fn without_loopback_the_helper_keeps_bwraps_network_namespace() {
    let output = helper_in_bwrap(&[], "import os; print(os.readlink('/proc/self/ns/net'))");

    assert!(output.status.success(), "{output:?}");
    let text = stdout(&output);
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0], lines[1], "{text}");
}

#[test]
fn repeated_loopback_addresses_are_configured_once() {
    let output = helper_in_bwrap(
        &[
            "--loopback",
            "10.9.9.9",
            "--loopback",
            "10.9.9.9",
            "--loopback",
            "fd00::5",
            "--loopback",
            "fd00::5",
        ],
        r#"
import socket
for family, address in [(socket.AF_INET, '10.9.9.9'), (socket.AF_INET6, 'fd00::5')]:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.bind((address, 0))
    print('bound ' + address)
"#,
    );

    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("10.9.9.9"),
        "{output:?}"
    );
    assert!(!stdout(&output).contains("ran"), "{output:?}");
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
fn a_relay_that_cannot_bind_makes_the_helper_exit_125() {
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

    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "the command must not run: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("3128"),
        "{output:?}"
    );
}

/// A settings file that allows exactly `allowed` and nothing else, written where
/// the wrapper can read it.
fn settings_allowing(case: &str, allowed: &[&str]) -> PathBuf {
    let list: Vec<String> = allowed.iter().map(|host| format!("\"{host}\"")).collect();
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("connect-{case}.json"));
    fs::write(
        &path,
        format!(
            r#"{{"network": {{"allowedDomains": [{}], "deniedDomains": []}}, "filesystem": {{"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}}}}"#,
            list.join(", ")
        ),
    )
    .unwrap();
    path
}

/// Runs `script` as the command of a sandbox whose only allowed host is
/// `allowed`, with this binary passed to it as `$0`.
fn in_sandbox_allowing(case: &str, allowed: &[&str], script: &str) -> Output {
    let settings = settings_allowing(case, allowed);
    crabpot(&[
        "-s",
        settings.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        script,
        CRABPOT,
    ])
}

#[test]
fn the_command_sees_the_ssh_proxy_command_and_its_credential() {
    let output = crabpot(&[
        "--",
        "sh",
        "-c",
        r#"printf '%s\n' "$GIT_SSH_COMMAND" "$SRT_SSH_PROXY_BINARY" "$SRT_SSH_PROXY_CREDENTIAL""#,
    ]);

    assert!(output.status.success(), "{output:?}");
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{output:?}");
    assert!(
        lines[0].contains("--crabpot-helper connect 3128")
            && lines[0].contains("SRT_SSH_PROXY_BINARY"),
        "{}",
        lines[0]
    );
    assert_eq!(
        lines[1], CRABPOT,
        "the binary the command expands, on the environment and not in its text"
    );
    assert!(!lines[2].is_empty(), "the credential is set to read");
}

#[test]
fn connect_mode_tunnels_to_an_allowed_host() {
    // An IP literal in `allowedDomains` is what lets the proxy dial loopback, so
    // this listener on the host is the host the tunnel reaches.
    let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = held.local_addr().unwrap().port();
    let answered = thread::spawn(move || {
        let (mut client, _) = held.accept().unwrap();
        let mut asked = String::new();
        BufReader::new(&mut client).read_line(&mut asked).unwrap();
        client.write_all(format!("got:{asked}").as_bytes()).unwrap();
    });

    let script =
        format!(r#"printf 'ping\n' | "$0" --crabpot-helper connect 3128 127.0.0.1 {port}"#);
    let output = in_sandbox_allowing("allowed", &["127.0.0.1"], &script);
    let seen = format!(
        "stdout: {}stderr: {}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "{seen}");
    assert_eq!(stdout(&output), "got:ping\n", "{seen}");
    answered.join().unwrap();
}

#[test]
fn connect_mode_reports_a_refused_host() {
    let script = r#""$0" --crabpot-helper connect 3128 not-allowed.example 80"#;
    let output = in_sandbox_allowing("refused", &["127.0.0.1"], script);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("not-allowed.example:80"), "{text}");
    assert!(text.contains("host is not on the allow list"), "{text}");
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
    let output = run_with_tcp(&settings, "print('ran')");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
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
    let output = run_with_tcp(
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

fn run_with_tcp(settings: &std::path::Path, script: &str) -> Output {
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
    let output = run_with_tcp(
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
    let output = run_with_tcp(&settings, "print('ran')");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("database.crabpot.invalid"), "{error}");
    assert!(error.contains("cannot resolve"), "{error}");
}
