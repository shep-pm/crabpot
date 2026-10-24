//! The layers that read `GIT_SSH_COMMAND`, run for real.
//!
//! git runs the value through a shell of its own, ssh expands `%` in the
//! `ProxyCommand` it was given, and ssh runs what is left through a shell
//! again. A unit test can only pin the text crabpot writes, so these stand-ins
//! record the argv each layer hands the next, and the binary they name is a
//! path no shell could be handed: an apostrophe, a dollar sign, a percent sign,
//! a double quote, a backtick, a backslash and a space.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{fs, io::Write};

use crabpot_linux::net::ssh;

/// The path the install is asked to put the binary at.
const NASTY: &str = "it's a $dir %with \"quotes\" `back` \\slash";

/// Writes `body` at `path` as a script any shell can run.
fn script(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(path).unwrap();
    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "{body}").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The lines one of the scripts wrote to its log.
fn logged(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} was not written: {e}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A sandbox's folder for one case, emptied of the last run's logs.
fn folder(case: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(case);
    fs::remove_dir_all(&dir).ok();
    script(
        &dir.join(NASTY).join("crabpot"),
        r#"printf '%s\n' "$@" >"$PROXY_ARGV_LOG""#,
    );
    script(
        &dir.join("bin").join("ssh"),
        r#"printf '%s\n' "$@" >"$SSH_ARGV_LOG""#,
    );
    dir
}

/// git's layer: `sh -c "$GIT_SSH_COMMAND <the ssh args git adds>"`, with the
/// stand-in for ssh on the `PATH`. Returns what ssh was given, and the
/// `ProxyCommand` word among it.
fn what_ssh_was_given(command: &str, dir: &Path) -> (Vec<String>, String) {
    let ssh_log = dir.join("ssh-argv");
    let git = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "{command} -o SendEnv=GIT_PROTOCOL git@example.invalid git-upload-pack 'repo'"
        ))
        .env("PATH", dir.join("bin"))
        .env("SSH_ARGV_LOG", &ssh_log)
        .env(ssh::BINARY_VARIABLE, dir.join(NASTY).join("crabpot"))
        .output()
        .unwrap();
    assert!(ssh_log.exists(), "git never reached ssh: {git:?}");

    let argv = logged(&ssh_log);
    let Some(found) = argv
        .iter()
        .find_map(|word| word.strip_prefix("ProxyCommand="))
    else {
        panic!("ssh was given no ProxyCommand: {argv:?}");
    };
    let proxy_command = found.to_owned();

    (argv, proxy_command)
}

/// ssh's layer: the `%` expansion of the host and port, then a shell over what
/// is left, which is how ssh starts its `ProxyCommand`. `binary` is the
/// variable's value, or `None` for one that is not on the environment.
fn what_the_proxy_was_given(proxy_command: &str, binary: Option<&Path>, dir: &Path) -> Output {
    let asked = proxy_command
        .replace("%h", "example.invalid")
        .replace("%p", "22");
    let mut run = Command::new("/bin/sh");
    run.arg("-c")
        .arg(asked)
        .env("PROXY_ARGV_LOG", dir.join("proxy-argv"));
    match binary {
        Some(path) => run.env(ssh::BINARY_VARIABLE, path),
        None => run.env_remove(ssh::BINARY_VARIABLE),
    }
    .output()
    .unwrap()
}

/// The value of `GIT_SSH_COMMAND` from `vars`.
fn git_ssh_command(vars: &[(&'static str, OsString)]) -> String {
    vars.iter()
        .find(|(name, _)| *name == "GIT_SSH_COMMAND")
        .map(|(_, value)| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| panic!("GIT_SSH_COMMAND is not set"))
}

#[test]
fn git_and_ssh_reach_a_binary_no_shell_could_be_handed() {
    let dir = folder("ssh-command");
    let binary = dir.join(NASTY).join("crabpot");

    let vars = ssh::vars(&binary, "srt", "0123abcd");
    let (ssh_argv, proxy_command) = what_ssh_was_given(&git_ssh_command(&vars), &dir);

    assert!(
        ssh_argv.contains(&"ControlMaster=no".to_owned())
            && ssh_argv.contains(&"ControlPath=none".to_owned()),
        "ssh was given the mux override: {ssh_argv:?}"
    );
    assert!(
        !ssh_argv.iter().any(|word| word.contains(NASTY)),
        "the path is not a word of ssh's argv: {ssh_argv:?}"
    );

    let started = what_the_proxy_was_given(&proxy_command, Some(&binary), &dir);
    assert!(started.status.success(), "{started:?}");
    assert_eq!(
        logged(&dir.join("proxy-argv")),
        [
            "--crabpot-helper",
            "connect",
            "3128",
            "example.invalid",
            "22"
        ],
        "the argv the connect mode is asked for, with the path read by one shell"
    );
}

/// The command is a named error and not an empty word run as a command when the
/// variable is not on the environment to expand.
#[test]
fn a_binary_variable_that_is_not_there_is_named() {
    let dir = folder("ssh-command-unset");
    let binary = dir.join(NASTY).join("crabpot");

    let vars = ssh::vars(&binary, "srt", "0123abcd");
    let (_, proxy_command) = what_ssh_was_given(&git_ssh_command(&vars), &dir);

    let started = what_the_proxy_was_given(&proxy_command, None, &dir);
    assert!(!started.status.success(), "{started:?}");
    assert!(
        String::from_utf8_lossy(&started.stderr)
            .contains("SRT_SSH_PROXY_BINARY: unset, but GIT_SSH_COMMAND needs it"),
        "{started:?}"
    );
    assert!(
        !dir.join("proxy-argv").exists(),
        "no connect mode ran: {started:?}"
    );
}
