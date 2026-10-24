//! The layers that read `GIT_SSH_COMMAND`, run for real.
//!
//! git runs the value through a shell of its own, ssh expands `%h` and `%p` in
//! the `ProxyCommand` it was given, and ssh hands what is left to `$SHELL -c`,
//! which is the caller's own shell that crabpot passes into the sandbox and
//! never sets. Real `git` and real `ssh` do those three. Only ssh itself and
//! the binary in the `connect` mode are stand-ins, and each records the argv it
//! was handed. The path they name is one no shell could be handed: an
//! apostrophe, a dollar sign, a percent sign, a double quote, a backtick, a
//! backslash and a space.
//!
//! Needs `git` and `ssh`. Where either cannot be run the case is skipped, except
//! under CI, where both must be there.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{env, ffi::OsString, fs, io::Write};

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

/// The lines one of the stand-ins wrote to its log.
fn logged(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} was not written: {e}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The folder for one case, or `None` where the machine has no `git` or no `ssh`
/// to run the layers with. It holds a stand-in for ssh on the `PATH` and a
/// stand-in for this binary under the nasty path.
fn case(name: &str) -> Option<PathBuf> {
    for tool in ["git", "ssh"] {
        if Command::new(tool).arg("--version").output().is_err() {
            if env::var_os("CI").is_none() {
                eprintln!("skipped: no {tool} to run the layers with");
                return None;
            }
            panic!("CI has {tool}");
        }
    }

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::remove_dir_all(&dir).ok();
    script(
        &dir.join("bin").join("ssh"),
        r#"printf '%s\n' "$@" >"$SSH_ARGV_LOG""#,
    );
    script(
        &dir.join(NASTY).join("crabpot"),
        r#"printf '%s\n' "$@" >"$PROXY_ARGV_LOG""#,
    );
    Some(dir)
}

/// The value of `GIT_SSH_COMMAND` from `vars`.
fn git_ssh_command(vars: &[(&'static str, OsString)]) -> String {
    vars.iter()
        .find(|(name, _)| *name == "GIT_SSH_COMMAND")
        .map(|(_, value)| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| panic!("GIT_SSH_COMMAND is not set"))
}

/// git's layer, with the real git and the stand-in ssh on its `PATH`. Returns
/// what ssh was handed, and the `ProxyCommand` word among it.
fn what_ssh_was_given(command: &str, dir: &Path) -> (Vec<String>, String) {
    let ssh_log = dir.join("ssh-argv");
    // The stand-in ssh goes in front of the `PATH` git's own shell searches, and
    // git itself is still found on the caller's `PATH`, which this does not
    // change.
    let mut path = OsString::from(dir.join("bin"));
    path.push(":");
    path.push(env::var_os("PATH").unwrap_or_default());

    let git = Command::new("git")
        .arg("ls-remote")
        .arg("git@example.invalid:repo")
        .env("GIT_SSH_COMMAND", command)
        .env("PATH", path)
        // A caller's own gitconfig could rewrite the remote or the ssh command.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("SSH_ARGV_LOG", &ssh_log)
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

/// ssh's layer, with the real ssh. It expands `%h` and `%p` and runs what is
/// left with `$SHELL -c`, and `shell` is that `SHELL`. `binary` is the value of
/// the binary's variable, or `None` for one that is not on the environment.
fn what_the_proxy_was_given(
    proxy_command: &str,
    shell: &str,
    binary: Option<&Path>,
    dir: &Path,
) -> Output {
    let mut started = Command::new("ssh");
    started
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
        ])
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("example.invalid")
        .env("SHELL", shell)
        .env("PROXY_ARGV_LOG", dir.join("proxy-argv"));
    match binary {
        Some(path) => started.env(ssh::BINARY_VARIABLE, path),
        None => started.env_remove(ssh::BINARY_VARIABLE),
    }
    .output()
    .unwrap()
}

/// The argv the connect mode was given, or a panic that names what went wrong.
fn proxy_argv(dir: &Path, started: &Output) -> Vec<String> {
    let log = dir.join("proxy-argv");
    if !log.exists() {
        panic!(
            "the connect mode never started: ssh stderr {}",
            String::from_utf8_lossy(&started.stderr)
        );
    }
    logged(&log)
}

#[test]
fn git_and_ssh_reach_a_binary_no_shell_could_be_handed() {
    let Some(dir) = case("ssh-command") else {
        return;
    };
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

    let started = what_the_proxy_was_given(&proxy_command, "/bin/sh", Some(&binary), &dir);
    assert_eq!(
        proxy_argv(&dir, &started),
        [
            "--crabpot-helper",
            "connect",
            "3128",
            "example.invalid",
            "22"
        ],
        "the argv the connect mode is asked for"
    );
}

/// `SHELL` is the caller's own, and a shell that is not POSIX is not obliged to
/// read a POSIX parameter expansion. `csh` and `tcsh` answer `${VAR:?msg}` with
/// `Bad : modifier in $ '?'.`, and fish calls it a syntax error. The command
/// hands that text to `/bin/sh` and nothing else.
#[test]
fn a_login_shell_that_is_not_posix_still_reaches_the_binary() {
    let Some(shell) = ["/bin/csh", "/bin/tcsh", "/usr/bin/fish", "/usr/bin/nu"]
        .into_iter()
        .find(|shell| Path::new(shell).exists())
    else {
        eprintln!("skipped: this machine has no shell that is not POSIX");
        return;
    };
    let Some(dir) = case("ssh-command-non-posix") else {
        return;
    };
    let binary = dir.join(NASTY).join("crabpot");

    let vars = ssh::vars(&binary, "srt", "0123abcd");
    let (_, proxy_command) = what_ssh_was_given(&git_ssh_command(&vars), &dir);

    let started = what_the_proxy_was_given(&proxy_command, shell, Some(&binary), &dir);
    assert_eq!(
        proxy_argv(&dir, &started),
        [
            "--crabpot-helper",
            "connect",
            "3128",
            "example.invalid",
            "22"
        ],
        "with SHELL={shell}"
    );
}

/// The command is a named error from `/bin/sh` and not an empty word run as a
/// command when the variable is not on the environment to expand.
#[test]
fn a_binary_variable_that_is_not_there_is_named() {
    let Some(dir) = case("ssh-command-unset") else {
        return;
    };
    let binary = dir.join(NASTY).join("crabpot");

    let vars = ssh::vars(&binary, "srt", "0123abcd");
    let (_, proxy_command) = what_ssh_was_given(&git_ssh_command(&vars), &dir);

    let started = what_the_proxy_was_given(&proxy_command, "/bin/sh", None, &dir);
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
