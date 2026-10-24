//! Runs a command as the wrapper's child, and maps how it ended to the
//! wrapper's own exit status.

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::io;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Command, ExitStatus};

use crabpot_core::config::{Config, ConfigError};

use tokio::runtime::Builder;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(unix)]
use tokio::task::JoinHandle;

use crate::args::{self, Helper, HelperMode, Invocation};
use crate::sandbox::Sandbox;

#[cfg(unix)]
const SIGINT: i32 = 2;
#[cfg(unix)]
const SIGTERM: i32 = 15;

/// Where upstream looks for settings when `-s` names none, under `$HOME`.
const DEFAULT_SETTINGS: &str = ".srt-settings.json";

/// Takes over the process when its first argument is `--crabpot`: runs the
/// command the rest of the arguments name inside a sandbox, and exits with its
/// status. Any other arguments leave it a no-op, so a host calls it first
/// thing in `main` (ADR-0010).
///
/// A first argument of `--srt-win` is srt-win running this binary again, and
/// is not for a person to type: on Windows, the whole command line goes to
/// srt-win, which exits with its code. Off Windows it is an ordinary argument.
///
/// A first argument of `--crabpot-helper` is the sandbox calling the binary
/// back, and is not for a person to type: on Linux, bwrap runs the host's
/// binary inside the sandbox with it, to run the command (ADR-0014). A host
/// that does not call this first thing in `main` runs its own `main` there in
/// place of the command.
pub fn run_from_args() {
    if let Some(helper) = args::parse_helper(env::args_os().skip(1)) {
        run_helper(helper);
    }
    let mut args = env::args_os().skip(1);
    match route(args.next().as_deref()) {
        Some(Route::SrtWin) => srt_win_hop(),
        Some(Route::Crabpot) => run_args(args),
        None => {}
    }
}

/// What a first argument asks [`run_from_args`] to take over the process for.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// `--srt-win`: srt-win ran this binary again, and the Windows half answers.
    SrtWin,
    /// `--crabpot`: the wrapper.
    Crabpot,
}

fn route(first: Option<&OsStr>) -> Option<Route> {
    match first {
        Some(arg) if arg == "--srt-win" => Some(Route::SrtWin),
        Some(arg) if arg == "--crabpot" => Some(Route::Crabpot),
        _ => None,
    }
}

/// Hands the whole command line to srt-win and exits with its code.
#[cfg(windows)]
fn srt_win_hop() -> ! {
    std::process::exit(crabpot_windows::run_from_args(env::args_os()))
}

/// Off Windows `--srt-win` is an ordinary argument.
#[cfg(not(windows))]
fn srt_win_hop() {}

/// Becomes the helper `helper` names. It never returns.
fn run_helper(helper: Result<Helper, args::ArgsError>) -> ! {
    let helper = helper.unwrap_or_else(|e| fail(e));
    match helper.mode {
        HelperMode::Init => {
            let (relay, command) = args::split_relay(&helper.args);
            helper_init(relay, command)
        }
        HelperMode::Relay | HelperMode::Connect => fail(format!(
            "helper mode {} is not supported yet",
            helper.mode.word()
        )),
    }
}

#[cfg(target_os = "linux")]
fn helper_init(relay: Option<&Path>, command: &[OsString]) -> ! {
    match crabpot_linux::helper::init(relay, command) {
        Ok(status) => std::process::exit(status),
        Err(e) => fail(e),
    }
}

#[cfg(not(target_os = "linux"))]
fn helper_init(_relay: Option<&Path>, _command: &[OsString]) -> ! {
    fail("the helper runs only on Linux")
}

fn fail(reason: impl core::fmt::Display) -> ! {
    eprintln!("crabpot: {reason}");
    std::process::exit(1)
}

/// Runs the command `args` name inside a sandbox, then exits the process with
/// its status. The arguments are the `crabpot` command line without the
/// program's name: `-s/--settings`, `-c`, `-d` and `--`.
///
/// Blocks until the command ends. A command line, a settings file or a sandbox
/// that is refused prints why to stderr and exits 1. A SIGINT, SIGTERM or
/// console Ctrl-C is the command's to answer: the wrapper keeps waiting for it
/// to end.
///
/// It never returns: on Unix, tokio keeps the signal handlers it installs for
/// the rest of the process, so a caller that carried on would no longer be
/// ended by SIGINT or SIGTERM.
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
    let config = load_config(args.settings.as_deref(), env::var_os("HOME"))?;
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

/// Reads the settings file, as upstream does: a default file that is not there
/// is the default config, and any other file that is not there, or is empty,
/// unreadable or invalid, is refused.
fn load_config(settings: Option<&Path>, home: Option<OsString>) -> Result<Config, Box<dyn Error>> {
    let path = match (settings, home) {
        (Some(path), _) => path.to_owned(),
        (None, Some(home)) => PathBuf::from(home).join(DEFAULT_SETTINGS),
        (None, None) => return Ok(Config::default()),
    };
    match Config::from_file(&path) {
        Ok(config) => Ok(config),
        Err(ConfigError::Missing) if settings.is_none() => Ok(Config::default()),
        Err(e) => Err(format!("{}: {e}", path.display()).into()),
    }
}

/// Spawns `command` and waits for it, and returns the status the wrapper exits
/// with.
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

/// Spawns `command`, waits for it with SIGINT and SIGTERM forwarded to it, and
/// returns the status the wrapper exits with.
#[cfg(unix)]
async fn run(command: Command) -> i32 {
    // Listening comes before spawning, so no signal falls in between.
    let listeners = match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(interrupt), Ok(terminate)) => [("INT", interrupt), ("TERM", terminate)],
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("crabpot: cannot listen for signals: {e}");
            return 1;
        }
    };
    let mut child = match spawn(command) {
        Ok(child) => child,
        Err(e) => {
            eprintln!("crabpot: cannot run the command: {e}");
            return 1;
        }
    };
    let forwarders: Vec<JoinHandle<()>> = match child.id() {
        Some(pid) => listeners
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
    exit_after_wait(status)
}

/// Spawns `command`, waits for it, and returns the status the wrapper exits
/// with. A console Ctrl-C reaches every process attached to the console, the
/// wrapper included, so the wrapper listens for it here and lets the handler
/// swallow it: the child is attached to the same console and answers the event
/// itself, and the wrapper still waits for it and exits with its code.
#[cfg(not(unix))]
async fn run(command: Command) -> i32 {
    let listener = tokio::spawn(listen_for_ctrl_c());
    let mut child = match spawn(command) {
        Ok(child) => child,
        Err(e) => {
            eprintln!("crabpot: cannot run the command: {e}");
            return 1;
        }
    };
    let status = child.wait().await;
    listener.abort();
    exit_after_wait(status)
}

/// Holds a Ctrl-C listener for as long as it runs, which is what keeps the
/// console handler swallowing the event in this process. Once it stops, the
/// default handler ends the process again.
#[cfg(not(unix))]
async fn listen_for_ctrl_c() {
    loop {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("crabpot: cannot listen for signals: {e}");
            break;
        }
    }
}

fn spawn(command: Command) -> io::Result<tokio::process::Child> {
    tokio::process::Command::from(command).spawn()
}

/// The status the wrapper exits with once the child has ended, or 1 when the
/// wait itself failed.
fn exit_after_wait(status: io::Result<ExitStatus>) -> i32 {
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
#[cfg(unix)]
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
#[cfg(unix)]
fn exit_code(status: ExitStatus) -> i32 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(SIGINT | SIGTERM)) => 0,
        (None, _) => 1,
    }
}

/// The child's own code, or 1 for an end with no code at all. This platform
/// reports no signal, so a child killed from outside still reports a code.
#[cfg(not(unix))]
fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use super::*;

    /// A signal reaches every wrapper in the process, so the tests that run a
    /// command take turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// This platform's shell, as the argv that runs it on `line`.
    fn shell_argv(line: &str) -> Vec<OsString> {
        #[cfg(unix)]
        {
            ["sh", "-c", line].map(OsString::from).to_vec()
        }
        #[cfg(not(unix))]
        {
            ["cmd", "/C", line].map(OsString::from).to_vec()
        }
    }

    /// This platform's shell, run on `line`.
    fn shell(line: &str) -> Command {
        let argv = shell_argv(line);
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
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

    fn route_of(args: &[&str]) -> Option<Route> {
        route(args.first().map(OsStr::new))
    }

    #[test]
    fn srt_win_as_first_argument_selects_the_windows_hop() {
        assert_eq!(route_of(&["--srt-win", "--help"]), Some(Route::SrtWin));
    }

    #[test]
    fn srt_win_after_other_arguments_is_an_ordinary_argument() {
        assert_eq!(route_of(&["ls", "--srt-win"]), None);
        assert_eq!(route_of(&["--crabpot", "--srt-win"]), Some(Route::Crabpot));
    }

    #[test]
    fn crabpot_as_first_argument_still_selects_the_wrapper() {
        assert_eq!(route_of(&["--crabpot", "ls"]), Some(Route::Crabpot));
        assert_eq!(route_of(&[]), None);
    }

    /// A folder of its own, removed on drop.
    struct Dir(PathBuf);

    impl Dir {
        fn new(test: &str) -> Self {
            let dir = env::temp_dir().join(format!("crabpot-run-{}-{test}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_four_file_refusals_exit_1() {
        let dir = Dir::new("refusals");
        let empty = dir.0.join("empty.json");
        let invalid = dir.0.join("invalid.json");
        fs::write(&empty, "  \n").unwrap();
        fs::write(&invalid, "{not json").unwrap();
        // A command that ran would exit 7, so 1 is the refusal and not the
        // command.
        let command = shell_argv("exit 7");

        for (name, settings) in [
            ("missing", dir.0.join("none.json")),
            ("empty", empty),
            ("unreadable", dir.0.clone()),
            ("invalid", invalid),
        ] {
            let mut args = vec![
                OsString::from("--settings"),
                settings.into(),
                OsString::from("--"),
            ];
            args.extend(command.iter().cloned());

            assert_eq!(run_status(args), 1, "{name}");
        }
    }

    #[test]
    fn a_default_settings_file_that_is_missing_runs_the_default_config() {
        let home = Dir::new("home");

        assert_eq!(
            load_config(None, Some(home.0.clone().into())).unwrap(),
            Config::default()
        );
        fs::write(home.0.join(DEFAULT_SETTINGS), "").unwrap();
        assert!(
            load_config(None, Some(home.0.clone().into())).is_err(),
            "a default file that is there and empty is refused"
        );
    }

    #[test]
    fn a_refusal_names_the_file_and_why() {
        let dir = Dir::new("messages");
        let invalid = dir.0.join("invalid.json");
        fs::write(&invalid, r#"{"network": {"allowedDomains": ["*.com"]}}"#).unwrap();
        let text = |settings: &Path| load_config(Some(settings), None).unwrap_err().to_string();

        assert_eq!(
            text(&dir.0.join("none.json")),
            format!("{}: does not exist", dir.0.join("none.json").display())
        );
        assert!(text(&invalid).contains("network.allowedDomains"));
    }

    #[test]
    fn a_childs_exit_code_passes_through() {
        assert_eq!(run(shell("exit 3")), 3);
    }

    #[test]
    fn a_command_that_cannot_spawn_is_a_failure() {
        assert_eq!(run(Command::new("/no/such/program")), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_signalled_child_reports_a_failure_code() {
        assert_eq!(run(shell("kill -KILL $$")), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_child_stopped_by_sigint_or_sigterm_is_a_clean_stop() {
        assert_eq!(run(shell("kill -INT $$")), 0, "SIGINT is a clean end");
        assert_eq!(run(shell("kill -TERM $$")), 0, "SIGTERM is a clean end");
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_sent_to_the_wrapper_reaches_the_command() {
        // The command signals its parent, which is this process, and then
        // waits long enough for the wrapper to forward the signal back.
        let script = r#"trap 'exit 7' TERM
            kill -TERM $PPID
            n=0
            while [ $n -lt 2000000 ]; do n=$((n+1)); done
            exit 9"#;

        assert_eq!(run(shell(script)), 7);
    }
}
