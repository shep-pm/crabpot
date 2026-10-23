//! Runs a command as the wrapper's child, and maps how it ended to the
//! wrapper's own exit status.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crabpot_core::config::Config;

use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;

use crate::args::{self, Invocation};
use crate::sandbox::Sandbox;

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// Where upstream looks for settings when `-s` names none, under `$HOME`.
const DEFAULT_SETTINGS: &str = ".srt-settings.json";

/// Takes over the process when its first argument is `--crabpot`: runs the
/// command the rest of the arguments name inside a sandbox, and exits with its
/// status. Any other arguments leave it a no-op, so a host calls it first
/// thing in `main` (ADR-0010).
pub fn run_from_args() {
    let mut args = env::args_os().skip(1);
    if args.next().is_some_and(|arg| arg == "--crabpot") {
        run_args(args);
    }
}

/// Runs the command `args` name inside a sandbox, then exits the process with
/// its status. The arguments are the `crabpot` command line without the
/// program's name: `-s/--settings`, `-c`, `-d` and `--`.
///
/// Blocks until the command ends, forwarding SIGINT and SIGTERM to it
/// meanwhile. A command line, a settings file or a sandbox that is refused
/// prints why to stderr and exits 1.
///
/// It never returns: tokio keeps the signal handlers it installs for the
/// rest of the process, so a caller that carried on would no longer be ended
/// by SIGINT or SIGTERM.
pub fn run_args(args: impl IntoIterator<Item = OsString>) -> ! {
    std::process::exit(run_status(args))
}

fn run_status(args: impl IntoIterator<Item = OsString>) -> i32 {
    match prepare(args) {
        Ok((_sandbox, command)) => execute(command),
        Err(e) => {
            eprintln!("crabpot: {e}");
            1
        }
    }
}

/// The sandbox, which has to outlive the command, and the command wrapped in it.
fn prepare(args: impl IntoIterator<Item = OsString>) -> Result<(Sandbox, Command), Box<dyn Error>> {
    let args = args::parse(args)?;
    let config = load_config(args.settings.as_deref())?;
    let sandbox = Sandbox::start(&config)?;
    let command = match args.command {
        Invocation::Argv(argv) => {
            let mut command = Command::new(&argv[0]);
            command.args(&argv[1..]);
            command
        }
        Invocation::Shell(line) => {
            let mut command = Command::new("bash");
            command.arg("-c").arg(line);
            command
        }
    };
    let wrapped = sandbox.command(&command)?;
    if args.debug {
        eprintln!("crabpot: running {wrapped:?}");
    }
    Ok((sandbox, wrapped))
}

/// Reads the settings file, as upstream does: a file that is not there is the
/// default config, and one that is there and wrong is refused.
fn load_config(settings: Option<&Path>) -> Result<Config, Box<dyn Error>> {
    let path = match (settings, env::var_os("HOME")) {
        (Some(path), _) => path.to_owned(),
        (None, Some(home)) => PathBuf::from(home).join(DEFAULT_SETTINGS),
        (None, None) => return Ok(Config::default()),
    };
    match fs::read_to_string(&path) {
        Ok(text) => Config::from_json(&text).map_err(|e| format!("{}: {e}", path.display()).into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound && settings.is_none() => {
            Ok(Config::default())
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display()).into()),
    }
}

/// Spawns `command` and waits for it, forwarding SIGINT and SIGTERM to it
/// meanwhile, and returns the status the wrapper exits with.
pub(crate) fn execute(command: Command) -> i32 {
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("crabpot: cannot start the async runtime: {e}");
            return 1;
        }
    };
    runtime.block_on(run(command))
}

async fn run(command: Command) -> i32 {
    // Listening comes before spawning, so no signal falls in between.
    let forwarders = match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(interrupt), Ok(terminate)) => [("INT", interrupt), ("TERM", terminate)],
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("crabpot: cannot listen for signals: {e}");
            return 1;
        }
    };
    let mut child = match tokio::process::Command::from(command).spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("crabpot: cannot run the command: {e}");
            return 1;
        }
    };
    let forwarders: Vec<JoinHandle<()>> = match child.id() {
        Some(pid) => forwarders
            .into_iter()
            .map(|(name, mut stream)| {
                tokio::spawn(async move {
                    while stream.recv().await.is_some() {
                        forward(name, pid).await;
                    }
                })
            })
            .collect(),
        None => Vec::new(),
    };
    let status = child.wait().await;
    for forwarder in forwarders {
        forwarder.abort();
    }
    match status {
        Ok(status) => exit_code(status),
        Err(e) => {
            eprintln!("crabpot: cannot wait for the command: {e}");
            1
        }
    }
}

/// Sends the signal `name` to `pid` through `kill(1)`, since tokio can only
/// send SIGKILL and `kill(2)` is unsafe to call. A signal that does not go
/// through is dropped: the command is gone, or it was never ours to signal.
async fn forward(name: &str, pid: u32) {
    let _ = tokio::process::Command::new("/bin/kill")
        .args(["-s", name, &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// How upstream maps a child's end: SIGINT and SIGTERM are a clean stop, any
/// other signal is a failure, and a code is itself.
fn exit_code(status: ExitStatus) -> i32 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(SIGINT | SIGTERM)) => 0,
        (None, _) => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A signal reaches every wrapper in the process, so the tests that run a
    /// command take turns.
    static TURN: Mutex<()> = Mutex::new(());

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    fn run(command: Command) -> i32 {
        let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        execute(command)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_command_line_runs_under_the_sandbox_and_exits_with_the_command() {
        let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

        assert_eq!(run_status(args(&["--", "sh", "-c", "exit 4"])), 4);
        assert_eq!(run_status(args(&["-c", "exit 5"])), 5);
        assert_eq!(run_status(args(&["-d"])), 1, "no command is refused");
    }

    #[test]
    fn a_settings_file_that_is_named_and_missing_is_refused() {
        let missing = Path::new("/no/such/settings.json");

        assert!(load_config(Some(missing)).is_err());
    }

    #[test]
    fn exit_status_is_mapped_as_upstream_maps_it() {
        assert_eq!(run(sh("exit 3")), 3, "a code passes through");
        assert_eq!(run(sh("kill -INT $$")), 0, "SIGINT is a clean end");
        assert_eq!(run(sh("kill -TERM $$")), 0, "SIGTERM is a clean end");
        assert_eq!(run(sh("kill -KILL $$")), 1, "another signal is a failure");
        assert_eq!(
            run(Command::new("/no/such/program")),
            1,
            "a spawn failure is a failure"
        );
    }

    #[test]
    fn sigterm_sent_to_the_wrapper_reaches_the_command() {
        // The command signals its parent, which is this process, and then
        // waits long enough for the wrapper to forward the signal back.
        let script = r#"trap 'exit 7' TERM
            kill -TERM $PPID
            n=0
            while [ $n -lt 2000000 ]; do n=$((n+1)); done
            exit 9"#;

        assert_eq!(run(sh(script)), 7);
    }
}
