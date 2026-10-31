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

#[cfg(target_os = "linux")]
use crabpot_linux::info::Report;

use crate::args::{self, Helper, HelperMode, Invocation, SRT_WIN_FLAG, Subcommand};
use crate::sandbox::Sandbox;
use crate::windows::install::{self, Machine};

#[cfg(unix)]
const SIGINT: i32 = 2;
#[cfg(unix)]
const SIGTERM: i32 = 15;

// Poll at most 100 times per second until bwrap creates its descendants.
#[cfg(unix)]
const TARGET_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// Where upstream looks for settings when `-s` names none, under `$HOME`.
const DEFAULT_SETTINGS: &str = ".srt-settings.json";

const REFUSED: i32 = 125;

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
/// binary inside the sandbox with it, to run the command (ADR-0014), and a
/// sandboxed ssh runs it the same way for its `ProxyCommand`. A host that does
/// not call this first thing in `main` runs its own `main` there in place of
/// the command.
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
        Some(arg) if arg == SRT_WIN_FLAG => Some(Route::SrtWin),
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
            let init = args::parse_init(&helper.args).unwrap_or_else(|e| fail(e));
            helper_init(init)
        }
        HelperMode::Connect => helper_connect(&helper.args),
        HelperMode::Relay => fail(format!(
            "helper mode {} is not supported yet",
            helper.mode.word()
        )),
    }
}

#[cfg(target_os = "linux")]
fn helper_init(init: args::Init<'_>) -> ! {
    if let Some(fd) = init.report_started
        && let Err(error) = crabpot_linux::startup::notify(fd)
    {
        eprintln!("crabpot: cannot report helper startup: {error}");
        std::process::exit(REFUSED);
    }
    match crabpot_linux::helper::init_with_publish(
        init.relay,
        &init.loopback,
        &init.tcp,
        init.publish_fd,
        init.command,
    ) {
        Ok(status) => std::process::exit(status),
        Err(e @ crabpot_linux::helper::InitError::Exec(_)) => fail(e),
        Err(e) => {
            eprintln!("crabpot: {e}");
            std::process::exit(REFUSED)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn helper_init(_init: args::Init<'_>) -> ! {
    fail("the helper runs only on Linux")
}

/// Tunnels this process's stdin and stdout to the host and port `args` name,
/// through the sandbox's relay, which is what a sandboxed ssh's `ProxyCommand`
/// asks for (ADR-0014).
#[cfg(target_os = "linux")]
fn helper_connect(args: &[OsString]) -> ! {
    match crabpot_linux::helper::connect(args) {
        Ok(()) => std::process::exit(0),
        Err(e) => fail(e),
    }
}

#[cfg(not(target_os = "linux"))]
fn helper_connect(_args: &[OsString]) -> ! {
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
/// A first argument of `windows-install` or `windows-uninstall` sets the
/// Windows sandbox up or takes it down instead, and exits 0 when that is done
/// and 1 when it is refused or fails.
///
/// Blocks until the command ends. A command line, a settings file or a sandbox
/// that is refused prints why to stderr and exits 125. Otherwise, the command's
/// exit code passes through, including 1 and 125. On Unix, a SIGINT,
/// SIGTERM, SIGHUP, SIGQUIT, SIGUSR1 or SIGUSR2 is passed on to the command,
/// and a console Ctrl-C is the command's to answer: the wrapper keeps waiting
/// for it to end.
///
/// It never returns: on Unix, tokio keeps the signal handlers it installs for
/// the rest of the process, so a caller that carried on would no longer be
/// ended by SIGINT or SIGTERM.
pub fn run_args(args: impl IntoIterator<Item = OsString>) -> ! {
    std::process::exit(run_status(args))
}

fn run_status(args: impl IntoIterator<Item = OsString>) -> i32 {
    let args: Vec<OsString> = args.into_iter().collect();
    match args::parse_subcommand(args.iter().cloned()) {
        Some(Ok(subcommand)) => return run_subcommand(subcommand),
        Some(Err(e)) => {
            eprintln!("crabpot: {e}");
            return 1;
        }
        None => {}
    }
    match prepare(args) {
        Ok((_sandbox, command, target)) => {
            #[cfg(target_os = "linux")]
            let command = {
                let mut command = command;
                crabpot_linux::helper::hold_signals(&mut command);
                command
            };
            execute(command, target)
        }
        Err(e) => {
            eprintln!("crabpot: {e}");
            REFUSED
        }
    }
}

/// Sets the Windows sandbox up or takes it down, and returns the status the
/// wrapper exits with.
fn run_subcommand(subcommand: Subcommand) -> i32 {
    let mut machine = Machine;
    let done = match subcommand {
        Subcommand::WindowsInstall(options) => install::install(&mut machine, &options),
        Subcommand::WindowsUninstall(options) => install::uninstall(&mut machine, &options),
    };
    match done {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("crabpot: {e}");
            1
        }
    }
}

/// The sandbox, which has to outlive the command, the command wrapped in it,
/// and the process that is to get the signals meant for the command.
fn prepare(
    args: impl IntoIterator<Item = OsString>,
) -> Result<(Sandbox, Command, ForwardTarget), Box<dyn Error>> {
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
    #[cfg(windows)]
    let command = {
        let mut command = command;
        command.envs(crate::windows::inherited::carried(env::vars_os()));
        command
    };
    #[cfg(target_os = "linux")]
    let (wrapped, target) = {
        let (wrapped, info, startup) = sandbox.command_reporting(&command)?;
        (wrapped, ForwardTarget::Helper { info, startup })
    };
    #[cfg(not(target_os = "linux"))]
    let (wrapped, target) = (sandbox.command(&command)?, ForwardTarget::Child);
    if args.debug {
        eprintln!("crabpot: running {}", debug_line(&wrapped));
    }
    Ok((sandbox, wrapped, target))
}

/// `command` as `--debug` prints it: the program and its arguments, with the
/// value of each `--env NAME=VALUE` pair left out, since the environment holds
/// credentials and a log keeps what is printed.
fn debug_line(command: &Command) -> String {
    let mut words = vec![format!("{:?}", command.get_program())];
    let mut after_env = false;
    for arg in command.get_args() {
        let arg = arg.to_string_lossy();
        if after_env {
            let name = arg.split('=').next().unwrap_or_default();
            words.push(format!("{:?}", format!("{name}=<redacted>")));
        } else {
            words.push(format!("{arg:?}"));
        }
        after_env = !after_env && arg == "--env";
    }
    words.join(" ")
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
fn execute(command: Command, target: ForwardTarget) -> i32 {
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("crabpot: cannot start the async runtime: {e}");
            return REFUSED;
        }
    };
    #[cfg(unix)]
    {
        runtime.block_on(run(command, target))
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        runtime.block_on(run(command))
    }
}

/// Which process a signal for the command is sent to.
#[derive(Debug, Clone)]
enum ForwardTarget {
    /// The spawned child itself.
    #[cfg(any(not(target_os = "linux"), test))]
    Child,
    /// The helper, which only it forwards signals on to the command: bwrap's
    /// processes do not, and a signal that ends them kills the sandbox.
    #[cfg(target_os = "linux")]
    Helper {
        info: crabpot_linux::info::Info,
        startup: crabpot_linux::startup::Startup,
    },
}

#[cfg(unix)]
impl ForwardTarget {
    /// The process to signal for the spawned `child`, or `None` while it is not
    /// known yet.
    fn pid(&self, child: u32) -> Option<u32> {
        match self {
            #[cfg(any(not(target_os = "linux"), test))]
            Self::Child => Some(child),
            #[cfg(target_os = "linux")]
            Self::Helper { info, .. } => match info.report() {
                // bwrap reports its namespace init, and the helper is the first
                // process that starts.
                Report::Pid(init) => first_child(init),
                Report::Pending => None,
                // The report never came: walk down from bwrap, whose first
                // child is the init.
                Report::Missing => first_child(first_child(child)?),
            },
        }
    }
}

/// The lowest pid among the processes `pid` started, or `None` while it has
/// started none.
#[cfg(target_os = "linux")]
fn first_child(pid: u32) -> Option<u32> {
    children_in(Path::new("/proc"), pid)
}

/// [`first_child`] reading the `proc` filesystem mounted at `root`. A kernel
/// built without `CONFIG_PROC_CHILDREN`, or gVisor, has no `children` file, so
/// it falls back to the parent pid every process's `stat` names.
#[cfg(target_os = "linux")]
fn children_in(root: &Path, pid: u32) -> Option<u32> {
    match std::fs::read_to_string(root.join(format!("{pid}/task/{pid}/children"))) {
        Ok(children) => children
            .split_whitespace()
            .filter_map(|child| child.parse().ok())
            .min(),
        Err(_) => std::fs::read_dir(root)
            .ok()?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter(|&child| parent_of(root, child) == Some(pid))
            .min(),
    }
}

/// The parent pid in `root/<pid>/stat`, whose command name may hold spaces and
/// parentheses, so the fields are counted from its last `)`.
#[cfg(target_os = "linux")]
fn parent_of(root: &Path, pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(root.join(format!("{pid}/stat"))).ok()?;
    let (_, after_name) = stat.rsplit_once(')')?;
    after_name.split_whitespace().nth(1)?.parse().ok()
}

/// Spawns `command`, waits for it with host shutdown signals forwarded to it, and
/// returns the status the wrapper exits with.
#[cfg(unix)]
async fn run(command: Command, target: ForwardTarget) -> i32 {
    // Listening comes before spawning, so no signal falls in between.
    // Keep this set aligned with FORWARDED in crates/crabpot-linux/src/helper/init.rs.
    let listeners = [
        ("INT", SignalKind::interrupt()),
        ("TERM", SignalKind::terminate()),
        ("HUP", SignalKind::hangup()),
        ("QUIT", SignalKind::quit()),
        ("USR1", SignalKind::user_defined1()),
        ("USR2", SignalKind::user_defined2()),
    ]
    .into_iter()
    .map(|(name, kind)| signal(kind).map(|stream| (name, stream)))
    .collect::<io::Result<Vec<_>>>();
    let listeners = match listeners {
        Ok(listeners) => listeners,
        Err(e) => {
            eprintln!("crabpot: cannot listen for signals: {e}");
            return REFUSED;
        }
    };
    let mut child = match spawn(command) {
        Ok(child) => child,
        Err(e) => {
            eprintln!("crabpot: cannot run the command: {e}");
            return REFUSED;
        }
    };
    let forwarders: Vec<JoinHandle<()>> = match child.id() {
        Some(pid) => listeners
            .into_iter()
            .map(|(name, mut stream)| {
                let target = target.clone();
                tokio::spawn(async move {
                    while stream.recv().await.is_some() {
                        forward(name, pid, |pid| target.pid(pid)).await;
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
    #[cfg(target_os = "linux")]
    if status.is_ok()
        && let ForwardTarget::Helper { startup, .. } = target
    {
        loop {
            match startup.report() {
                crabpot_linux::startup::Report::Started => break,
                crabpot_linux::startup::Report::Missing => return REFUSED,
                // The reader may still be draining the helper's acknowledgement.
                crabpot_linux::startup::Report::Pending => {
                    tokio::time::sleep(TARGET_RETRY_INTERVAL).await
                }
            }
        }
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
            return REFUSED;
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
async fn forward(name: &str, pid: u32, target: impl Fn(u32) -> Option<u32>) {
    // The owning run task aborts this retry when its child exits.
    let pid = loop {
        if let Some(pid) = target(pid) {
            break pid;
        }
        tokio::time::sleep(TARGET_RETRY_INTERVAL).await;
    };
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

    #[test]
    fn debug_does_not_print_the_value_of_an_env_pair() {
        let mut command = Command::new("crabpot");
        command.args(["--env", "TOKEN=secret", "--", "echo", "TOKEN=plain"]);

        let line = debug_line(&command);

        assert_eq!(
            line,
            r#""crabpot" "--env" "TOKEN=<redacted>" "--" "echo" "TOKEN=plain""#
        );
    }

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
        execute(command, ForwardTarget::Child)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_command_line_runs_under_the_sandbox_and_exits_with_the_command() {
        let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

        assert_eq!(run_status(args(&["--", "sh", "-c", "exit 4"])), 4);
        assert_eq!(run_status(args(&["-c", "exit 5"])), 5);
    }

    #[test]
    fn a_command_line_without_a_command_exits_125() {
        assert_eq!(run_status([OsString::from("-d")]), 125);
    }

    #[cfg(not(windows))]
    #[test]
    fn the_windows_subcommands_are_refused_off_windows() {
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

        assert_eq!(run_status(args(&["windows-install"])), 1);
        assert_eq!(run_status(args(&["windows-uninstall"])), 1);
        assert_eq!(run_status(args(&["windows-install", "--nope"])), 1);
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
    fn the_four_file_refusals_exit_125() {
        let dir = Dir::new("refusals");
        let empty = dir.0.join("empty.json");
        let invalid = dir.0.join("invalid.json");
        fs::write(&empty, "  \n").unwrap();
        fs::write(&invalid, "{not json").unwrap();
        // A command that ran would exit 7.
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

            assert_eq!(run_status(args), 125, "{name}");
        }
    }

    #[test]
    fn a_command_line_that_does_not_parse_exits_125() {
        assert_eq!(run_status([OsString::from("--unknown")]), 125);
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
        for code in [0, 1, 3, 125] {
            assert_eq!(run(shell(&format!("exit {code}"))), code);
        }
    }

    #[test]
    fn a_command_that_cannot_spawn_exits_125() {
        assert_eq!(run(Command::new("/no/such/program")), 125);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_is_found_without_a_children_file() {
        let dir = Dir::new("proc");
        // Process 20's name holds the characters that end a naive parse.
        for (pid, stat) in [
            (10, "10 (init) S 1 10 10 0"),
            (20, "20 (a) b) S 10 20 20 0"),
            (30, "30 (late) S 10 30 30 0"),
            (40, "40 (other) S 5 40 40 0"),
        ] {
            fs::create_dir_all(dir.0.join(pid.to_string())).unwrap();
            fs::write(dir.0.join(format!("{pid}/stat")), stat).unwrap();
        }
        fs::create_dir_all(dir.0.join("self")).unwrap();

        assert_eq!(children_in(&dir.0, 10), Some(20), "the lowest child");
        assert_eq!(children_in(&dir.0, 20), None, "a process with no child");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_is_read_from_its_children_file() {
        let dir = Dir::new("proc-children");
        fs::create_dir_all(dir.0.join("10/task/10")).unwrap();
        fs::write(dir.0.join("10/task/10/children"), "31 22 \n").unwrap();

        assert_eq!(children_in(&dir.0, 10), Some(22));
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
    fn a_shutdown_signal_waits_for_its_target_to_appear() {
        use std::cell::Cell;
        use std::future::{Future, poll_fn};
        use std::io::{BufRead, BufReader};
        use std::sync::mpsc;
        use std::task::Poll;
        use std::thread;
        use std::time::Duration;

        let mut command = shell("trap 'exit 7' TERM; echo ready; read -r line; exit 9");
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let _stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (ready_sender, ready) = mpsc::channel();
        let (exit_sender, exited) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            let _ = ready_sender.send(line);
            let _ = exit_sender.send(child.wait().unwrap());
        });
        // Real time bounds the shell and kill subprocesses.
        let timeout = Duration::from_secs(5);
        assert_eq!(ready.recv_timeout(timeout).unwrap(), "ready\n");
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();

        runtime.block_on(async {
            let discoverable = Cell::new(false);
            let mut forwarding = std::pin::pin!(forward("TERM", pid, |pid| {
                discoverable.get().then_some(pid)
            }));
            poll_fn(|cx| {
                assert!(
                    forwarding.as_mut().poll(cx).is_pending(),
                    "the signal was dropped before its target appeared"
                );
                Poll::Ready(())
            })
            .await;

            discoverable.set(true);
            tokio::time::timeout(timeout, forwarding)
                .await
                .expect("the pending signal was not forwarded");
        });

        assert_eq!(exited.recv_timeout(timeout).unwrap().code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn host_shutdown_signals_sent_to_the_wrapper_reach_the_command() {
        // The command signals its parent, which is this process, and then
        // waits long enough for the wrapper to forward the signal back.
        for signal in ["INT", "TERM", "HUP", "QUIT", "USR1", "USR2"] {
            let script = format!(
                r#"trap 'exit 7' {signal}
                kill -{signal} $PPID
                n=0
                while [ $n -lt 2000000 ]; do n=$((n+1)); done
                exit 9"#
            );

            assert_eq!(run(shell(&script)), 7, "{signal}");
        }
    }
}
