//! The binary re-enters inside bwrap as the helper (ADR-0014). The cases drive
//! the `crabpot` binary, since a unit test would re-enter the test binary.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::{fs, thread};

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

#[test]
fn a_sigterm_to_the_helper_reaches_the_command() {
    // `wait` returns as soon as a trapped signal arrives, where a foreground
    // `sleep` would not.
    let script = r#"trap 'echo trapped; exit 3' TERM; echo ready; sleep 30 & wait"#;
    let mut helper = Command::new(CRABPOT)
        .env("HOME", env!("CARGO_TARGET_TMPDIR"))
        .args(["--crabpot-helper", "init", "sh", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(helper.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");

    let sent = Command::new("kill")
        .args(["-TERM", &helper.id().to_string()])
        .status()
        .unwrap();
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let status = helper.wait().unwrap();

    assert!(sent.success());
    assert_eq!(rest, "trapped\n");
    assert_eq!(status.code(), Some(3));
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
