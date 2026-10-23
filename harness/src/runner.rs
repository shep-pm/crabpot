//! Runs a case under upstream and under crabpot, and compares the probes.
//!
//! Each probe is one run of a wrapper around the `probe` binary, so the probe's
//! exit code is the wrapper's exit status.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

use crate::case::{self, Case, Probe};
use crate::{probe, serve};

/// Something that runs one probe in a sandbox and reports the probe's exit code.
pub trait Runner {
    /// Who the runner is, for a failure's message.
    fn name(&self) -> &'static str;

    /// Runs `probe` under the settings file at `settings`.
    ///
    /// # Errors
    ///
    /// An [`Error`] when the probe cannot be run or does not end with a code.
    fn run(&self, settings: &Path, probe: &Probe) -> Result<u8, Error>;

    /// Whether the wrapper refuses the settings at `settings`: it exits 1
    /// without running `probe`.
    ///
    /// # Errors
    ///
    /// An [`Error`] when the wrapper cannot be run, or exits with a status
    /// other than 1 without its probe reporting one.
    fn refuses(&self, settings: &Path, probe: &Probe) -> Result<bool, Error>;
}

/// Why a case failed or could not be run.
#[derive(Debug)]
pub enum Error {
    /// The case file is not a case.
    Case(case::Error),
    /// A file, the case's root or a wrapper could not be created or started.
    Io(std::io::Error),
    /// A wrapper ended by a signal, with no exit status.
    Signalled(&'static str),
    /// A wrapper's exit status is not the code its probe reported, or the probe
    /// reported none: the wrapper failed before it ran the probe.
    Unreported {
        /// The runner whose wrapper it is.
        runner: &'static str,
        /// The wrapper's exit status.
        status: i32,
    },
    /// A probe exited with [`probe::ERROR`]: it could not tell what the sandbox did.
    Erred {
        /// The runner that ran it.
        runner: &'static str,
        /// The probe that could not tell.
        probe: Probe,
    },
    /// The two runners gave a probe different codes.
    Differ {
        /// The probe they disagree on.
        probe: Probe,
        /// What upstream gave.
        upstream: u8,
        /// What crabpot gave.
        crabpot: u8,
    },
    /// A runner did not refuse settings the case says are refused: the probe
    /// ran, or left the marker it writes.
    NotRefused {
        /// The runner that ran it.
        runner: &'static str,
        /// The probe that ran.
        probe: Probe,
    },
    /// Upstream cannot be run, for want of Node or of `npm ci` in `harness/`.
    NoUpstream(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Case(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Signalled(runner) => write!(f, "the {runner} wrapper ended by a signal"),
            Self::Unreported { runner, status } => write!(
                f,
                "the {runner} wrapper exited {status} without the probe reporting it: it failed before running the probe"
            ),
            Self::Erred { runner, probe } => {
                write!(
                    f,
                    "{probe:?} could not tell under {runner}: it exited {}",
                    probe::ERROR
                )
            }
            Self::Differ {
                probe,
                upstream,
                crabpot,
            } => {
                write!(
                    f,
                    "{probe:?} exited {upstream} under upstream and {crabpot} under crabpot"
                )
            }
            Self::NotRefused { runner, probe } => write!(
                f,
                "{probe:?} ran under {runner}, which should have refused the settings first"
            ),
            Self::NoUpstream(why) => write!(f, "upstream cannot run: {why}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Case(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::Signalled(_)
            | Self::Unreported { .. }
            | Self::Erred { .. }
            | Self::Differ { .. }
            | Self::NotRefused { .. }
            | Self::NoUpstream(_) => None,
        }
    }
}

/// Runs every probe of `case` under both runners.
///
/// `restore` puts the fixture back as the case describes it. It runs before
/// every runner's run of every probe, so a probe that changes the fixture, such
/// as a write that creates a file, leaves the next run's precondition alone.
///
/// # Errors
///
/// [`Error::Erred`] for the first probe that exits [`probe::ERROR`] under either
/// runner, [`Error::Differ`] for the first probe the runners disagree on, and
/// whatever `restore` or a runner returns.
pub fn compare(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    for probe in &case.probes {
        restore()?;
        let upstream = code(upstream, settings, probe)?;
        restore()?;
        let crabpot = code(crabpot, settings, probe)?;
        if upstream != crabpot {
            return Err(Error::Differ {
                probe: probe.clone(),
                upstream,
                crabpot,
            });
        }
    }
    Ok(())
}

/// Runs every probe of `case` under both runners, which must refuse the
/// settings before any probe runs. A `write` probe is the marker: its file
/// must not be there afterwards.
///
/// # Errors
///
/// [`Error::NotRefused`] for the first probe that runs under either runner,
/// and whatever `restore` or a runner returns.
pub fn compare_refused(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    for probe in &case.probes {
        for runner in [upstream, crabpot] {
            restore()?;
            if !runner.refuses(settings, probe)? || written(probe) {
                return Err(Error::NotRefused {
                    runner: runner.name(),
                    probe: probe.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Whether the file a `write` probe creates is there.
fn written(probe: &Probe) -> bool {
    matches!(probe, Probe::Write(marker) if Path::new(marker).exists())
}

fn code(runner: &dyn Runner, settings: &Path, probe: &Probe) -> Result<u8, Error> {
    match runner.run(settings, probe)? {
        probe::ERROR => Err(Error::Erred {
            runner: runner.name(),
            probe: probe.clone(),
        }),
        code => Ok(code),
    }
}

/// Runs the case file's `text` in a fresh root named after `name`: creates its
/// files and its settings file, serves whatever socket it asks for, then
/// compares its probes, restoring the root before each run.
///
/// # Errors
///
/// [`Error::Case`] when `text` is not a case, [`Error::Io`] when the root, its
/// files or a served socket cannot be created, and what [`compare`] returns.
pub fn run_case(
    text: &str,
    name: &str,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    let mut root = Root::new(name, false).map_err(Error::Io)?;
    let mut case = Case::parse(text, &root.0).map_err(Error::Case)?;
    // A served socket lives under the root, and its path has to fit a socket
    // name. A case whose root makes it too long gets a short root, and is read
    // again with that root in it. The root it outgrows is dropped as it is
    // replaced.
    if case
        .serve
        .as_ref()
        .is_some_and(|serve| serve.unix_socket.len() > MAX_SOCKET_PATH)
    {
        root = Root::new(name, true).map_err(Error::Io)?;
        case = Case::parse(text, &root.0).map_err(Error::Case)?;
    }
    let settings = Path::new(&root.0).join("settings.json");
    let served = case
        .serve
        .as_ref()
        .map(|serve| serve::Served::start(Path::new(&serve.unix_socket), &serve.status))
        .transpose()
        .map_err(Error::Io)?;
    let keep: &Path = case
        .serve
        .as_ref()
        .map_or(Path::new(""), |serve| Path::new(&serve.unix_socket));
    let restore = || {
        root.empty(keep).map_err(Error::Io)?;
        for (path, contents) in &case.files {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            fs::write(path, contents).map_err(Error::Io)?;
        }
        match &case.settings {
            Value::Null => Ok(()),
            Value::String(text) => fs::write(&settings, text).map_err(Error::Io),
            other => fs::write(&settings, other.to_string()).map_err(Error::Io),
        }
    };
    let outcome = if case.refused {
        compare_refused(&case, &settings, &restore, upstream, crabpot)
    } else {
        compare(&case, &settings, &restore, upstream, crabpot)
    };
    drop(served);
    outcome
}

/// The longest a Unix socket path can be. macOS's `sun_path` is 104 bytes with
/// its terminator, and the cases run on macOS.
const MAX_SOCKET_PATH: usize = 103;

/// A fresh folder, its path as `pwd -P` prints it, removed on drop.
struct Root(String);

impl Root {
    /// A folder named after `name`. `short` leaves the name out, for a case
    /// whose served socket's path has to fit [`MAX_SOCKET_PATH`].
    fn new(name: &str, short: bool) -> std::io::Result<Self> {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        let dir = if short {
            std::env::temp_dir().join(format!(
                "cp-{pid}-{}",
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ))
        } else {
            std::env::temp_dir().join(format!("crabpot-case-{pid}-{name}"))
        };
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let real = dir.canonicalize()?;
        let text = real.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the temp folder is not UTF-8",
            )
        })?;
        Ok(Self(text.to_owned()))
    }

    /// Removes everything in the folder but `keep`, and leaves the folder.
    fn empty(&self, keep: &Path) -> std::io::Result<()> {
        for entry in fs::read_dir(&self.0)? {
            let path = entry?.path();
            if path == keep {
                continue;
            }
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Upstream's `srt`, from the npm package pinned in `harness/package.json`.
#[derive(Debug)]
pub struct Upstream {
    cli: PathBuf,
    probe: PathBuf,
}

impl Upstream {
    /// Finds Node and the installed package, to run the `probe` binary at `probe`.
    ///
    /// # Errors
    ///
    /// [`Error::NoUpstream`] when `node` does not run or `npm ci` has not been
    /// run in `harness/`.
    pub fn find(probe: impl Into<PathBuf>) -> Result<Self, Error> {
        let node = Command::new("node").arg("--version").output();
        if !node.is_ok_and(|output| output.status.success()) {
            return Err(Error::NoUpstream("`node --version` fails".to_owned()));
        }
        let cli = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js");
        if !cli.is_file() {
            return Err(Error::NoUpstream(format!(
                "{} is missing: run `npm ci` in harness/",
                cli.display()
            )));
        }
        Ok(Self {
            cli,
            probe: probe.into(),
        })
    }
}

impl Runner for Upstream {
    fn name(&self) -> &'static str {
        "upstream"
    }

    fn run(&self, settings: &Path, probe: &Probe) -> Result<u8, Error> {
        exit_code(self.command(settings, probe), self.name())
    }

    fn refuses(&self, settings: &Path, probe: &Probe) -> Result<bool, Error> {
        refusal(self.command(settings, probe), self.name())
    }
}

impl Upstream {
    fn command(&self, settings: &Path, probe: &Probe) -> Command {
        let mut command = Command::new("node");
        command
            .arg(&self.cli)
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args())
            .env("HOME", home(settings));
        command
    }
}

/// crabpot, through the `probe` binary in multicall: it calls
/// `crabpot::run_from_args` first thing, so `probe --crabpot ...` is the wrapper.
#[derive(Debug)]
pub struct Crabpot {
    probe: PathBuf,
}

impl Crabpot {
    /// Wraps the `probe` binary at `probe`.
    pub fn new(probe: impl Into<PathBuf>) -> Self {
        Self {
            probe: probe.into(),
        }
    }
}

impl Runner for Crabpot {
    fn name(&self) -> &'static str {
        "crabpot"
    }

    fn run(&self, settings: &Path, probe: &Probe) -> Result<u8, Error> {
        exit_code(self.command(settings, probe), self.name())
    }

    fn refuses(&self, settings: &Path, probe: &Probe) -> Result<bool, Error> {
        refusal(self.command(settings, probe), self.name())
    }
}

impl Crabpot {
    fn command(&self, settings: &Path, probe: &Probe) -> Command {
        let mut command = Command::new(&self.probe);
        command
            .arg("--crabpot")
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args())
            .env("HOME", home(settings));
        command
    }
}

/// The case's root, which holds the settings file: a `~` in a case names a path
/// the case made and not the machine's.
fn home(settings: &Path) -> &Path {
    settings.parent().unwrap_or(settings)
}

/// What a wrapper did: the status it exited with, and the code its probe
/// reported, which is there only if the probe ran.
struct Wrapped {
    status: i32,
    reported: Option<u8>,
}

/// Runs the wrapper to its end. Its stderr is inherited, so a failing run
/// leaves its diagnostics in the log; it is never compared.
fn wrapped(mut command: Command, runner: &'static str) -> Result<Wrapped, Error> {
    let output = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(Error::Io)?;
    let status = output.status.code().ok_or(Error::Signalled(runner))?;
    let reported = String::from_utf8_lossy(&output.stdout)
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(probe::REPORT)?.parse::<u8>().ok());
    Ok(Wrapped { status, reported })
}

/// Runs the wrapper to its end and returns the code its probe reported, which
/// must be the wrapper's exit status.
fn exit_code(command: Command, runner: &'static str) -> Result<u8, Error> {
    let Wrapped { status, reported } = wrapped(command, runner)?;
    match reported {
        Some(code) if i32::from(code) == status => Ok(code),
        _ => Err(Error::Unreported { runner, status }),
    }
}

/// Runs the wrapper to its end and says whether it refused: it exited 1 and
/// its probe reported nothing, so the probe never ran.
fn refusal(command: Command, runner: &'static str) -> Result<bool, Error> {
    match wrapped(command, runner)? {
        Wrapped {
            reported: Some(_), ..
        } => Ok(false),
        Wrapped { status: 1, .. } => Ok(true),
        Wrapped { status, .. } => Err(Error::Unreported { runner, status }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    /// Answers each probe with what `answer` says.
    struct StandIn(&'static str, fn(&Probe) -> u8);

    impl Runner for StandIn {
        fn name(&self) -> &'static str {
            self.0
        }

        fn run(&self, _settings: &Path, probe: &Probe) -> Result<u8, Error> {
            Ok((self.1)(probe))
        }

        fn refuses(&self, _settings: &Path, _probe: &Probe) -> Result<bool, Error> {
            Ok(false)
        }
    }

    fn case() -> Case {
        Case {
            files: Vec::new(),
            settings: json!({}),
            refused: false,
            serve: None,
            probes: vec![Probe::Read("/r/in".to_owned()), Probe::Bind],
        }
    }

    fn compare_with(upstream: fn(&Probe) -> u8, crabpot: fn(&Probe) -> u8) -> Result<(), Error> {
        compare(
            &case(),
            Path::new("/r/settings.json"),
            &|| Ok(()),
            &StandIn("upstream", upstream),
            &StandIn("crabpot", crabpot),
        )
    }

    #[test]
    fn differing_probe_outcomes_fail_the_case() {
        let outcome = compare_with(
            |_| probe::ALLOWED,
            |probe| match probe {
                Probe::Bind => probe::REFUSED,
                _ => probe::ALLOWED,
            },
        );
        assert!(matches!(
            outcome,
            Err(Error::Differ {
                probe: Probe::Bind,
                upstream: probe::ALLOWED,
                crabpot: probe::REFUSED,
            })
        ));
    }

    #[test]
    fn matching_probe_outcomes_pass_the_case() {
        let outcome = compare_with(
            |probe| match probe {
                Probe::Bind => probe::REFUSED,
                _ => probe::ALLOWED,
            },
            |probe| match probe {
                Probe::Bind => probe::REFUSED,
                _ => probe::ALLOWED,
            },
        );
        outcome.unwrap();
    }

    #[test]
    fn a_probe_that_exits_2_fails_the_case_even_when_both_agree() {
        let outcome = compare_with(|_| probe::ERROR, |_| probe::ERROR);
        assert!(matches!(
            outcome,
            Err(Error::Erred {
                runner: "upstream",
                probe: Probe::Read(_),
            })
        ));
    }

    /// Runs only on a restored fixture, which its run then spoils.
    struct Spoiling<'a>(&'static str, &'a Cell<bool>);

    impl Runner for Spoiling<'_> {
        fn name(&self) -> &'static str {
            self.0
        }

        fn run(&self, _settings: &Path, _probe: &Probe) -> Result<u8, Error> {
            assert!(self.1.replace(false), "{} ran on a spoiled fixture", self.0);
            Ok(probe::ALLOWED)
        }

        fn refuses(&self, _settings: &Path, _probe: &Probe) -> Result<bool, Error> {
            unreachable!("a compared case is not a refused one")
        }
    }

    #[test]
    fn each_runner_gets_a_restored_fixture_for_each_probe() {
        let clean = Cell::new(false);
        compare(
            &case(),
            Path::new("/r/settings.json"),
            &|| {
                clean.set(true);
                Ok(())
            },
            &Spoiling("upstream", &clean),
            &Spoiling("crabpot", &clean),
        )
        .unwrap();
    }

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn a_wrapper_that_fails_before_the_probe_runs_is_not_a_refusal() {
        let outcome = exit_code(sh("echo 'crabpot: bad settings' >&2; exit 1"), "crabpot");
        assert!(matches!(
            outcome,
            Err(Error::Unreported {
                runner: "crabpot",
                status: 1
            })
        ));
    }

    #[test]
    fn the_code_a_probe_reports_is_the_wrappers_status() {
        let outcome = exit_code(sh("echo 'probe exited 1'; exit 1"), "upstream");
        assert_eq!(outcome.unwrap(), probe::REFUSED);
    }

    #[test]
    fn a_status_the_probe_did_not_report_is_not_a_probe_outcome() {
        let outcome = exit_code(sh("echo 'probe exited 0'; exit 71"), "upstream");
        assert!(matches!(
            outcome,
            Err(Error::Unreported {
                runner: "upstream",
                status: 71
            })
        ));
    }

    #[test]
    fn a_wrapper_that_exits_1_without_its_probe_refuses() {
        assert!(refusal(sh("echo 'crabpot: bad settings' >&2; exit 1"), "crabpot").unwrap());
    }

    #[test]
    fn a_wrapper_whose_probe_ran_did_not_refuse() {
        assert!(!refusal(sh("echo 'probe exited 0'; exit 0"), "upstream").unwrap());
        assert!(!refusal(sh("echo 'probe exited 1'; exit 1"), "upstream").unwrap());
    }

    #[test]
    fn a_wrapper_that_fails_in_another_way_is_not_a_refusal() {
        assert!(matches!(
            refusal(sh("exit 71"), "upstream"),
            Err(Error::Unreported {
                runner: "upstream",
                status: 71
            })
        ));
    }

    /// Refuses, or says it ran, as built.
    struct Refusing(&'static str, bool);

    impl Runner for Refusing {
        fn name(&self) -> &'static str {
            self.0
        }

        fn run(&self, _settings: &Path, _probe: &Probe) -> Result<u8, Error> {
            unreachable!("a refused case is not run")
        }

        fn refuses(&self, _settings: &Path, _probe: &Probe) -> Result<bool, Error> {
            Ok(self.1)
        }
    }

    fn refused_case(marker: &Path) -> Case {
        Case {
            probes: vec![Probe::Write(marker.display().to_string())],
            refused: true,
            ..case()
        }
    }

    fn compare_refused_with(
        case: &Case,
        upstream: &dyn Runner,
        crabpot: &dyn Runner,
    ) -> Result<(), Error> {
        compare_refused(
            case,
            Path::new("/r/settings.json"),
            &|| Ok(()),
            upstream,
            crabpot,
        )
    }

    #[test]
    fn a_case_passes_when_both_runners_refuse_and_leave_no_marker() {
        let case = refused_case(Path::new("/r/never-written"));
        compare_refused_with(
            &case,
            &Refusing("upstream", true),
            &Refusing("crabpot", true),
        )
        .unwrap();
    }

    #[test]
    fn a_runner_that_does_not_refuse_fails_the_case() {
        let case = refused_case(Path::new("/r/never-written"));
        let outcome = compare_refused_with(
            &case,
            &Refusing("upstream", true),
            &Refusing("crabpot", false),
        );
        assert!(matches!(
            outcome,
            Err(Error::NotRefused {
                runner: "crabpot",
                ..
            })
        ));
    }

    #[test]
    fn a_marker_left_behind_fails_the_case_even_when_both_refuse() {
        let marker = std::env::current_exe().unwrap();
        let case = refused_case(&marker);
        let outcome = compare_refused_with(
            &case,
            &Refusing("upstream", true),
            &Refusing("crabpot", true),
        );
        assert!(matches!(
            outcome,
            Err(Error::NotRefused {
                runner: "upstream",
                ..
            })
        ));
    }
}
