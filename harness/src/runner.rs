//! Runs a case under upstream and under crabpot, and compares the probes.
//!
//! Each probe is one run of a wrapper around the `probe` binary, so the probe's
//! exit code is the wrapper's exit status.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::case::{self, Case, Probe};
use crate::probe;

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
    /// Upstream cannot be run, for want of Node or of `npm ci` in `harness/`.
    NoUpstream(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Case(source) => write!(f, "{source}"),
            Self::Io(source) => write!(f, "{source}"),
            Self::Signalled(runner) => write!(f, "the {runner} wrapper ended by a signal"),
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
            Self::NoUpstream(why) => write!(f, "upstream cannot run: {why}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Case(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::Signalled(_) | Self::Erred { .. } | Self::Differ { .. } | Self::NoUpstream(_) => {
                None
            }
        }
    }
}

/// Runs every probe of `case` under both runners.
///
/// # Errors
///
/// [`Error::Erred`] for the first probe that exits [`probe::ERROR`] under either
/// runner, [`Error::Differ`] for the first probe the runners disagree on, and
/// whatever a runner returns.
pub fn compare(
    case: &Case,
    settings: &Path,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    for probe in &case.probes {
        let upstream = code(upstream, settings, probe)?;
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
/// files and its settings file, then compares its probes.
///
/// # Errors
///
/// [`Error::Case`] when `text` is not a case, [`Error::Io`] when the root or its
/// files cannot be created, and what [`compare`] returns.
pub fn run_case(
    text: &str,
    name: &str,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    let root = Root::new(name).map_err(Error::Io)?;
    let case = Case::parse(text, &root.0).map_err(Error::Case)?;
    for (path, contents) in &case.files {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        fs::write(path, contents).map_err(Error::Io)?;
    }
    let settings = Path::new(&root.0).join("settings.json");
    fs::write(&settings, case.settings.to_string()).map_err(Error::Io)?;
    compare(&case, &settings, upstream, crabpot)
}

/// A fresh folder, its path as `pwd -P` prints it, removed on drop.
struct Root(String);

impl Root {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("crabpot-case-{}-{name}", std::process::id()));
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
        let mut command = Command::new("node");
        command
            .arg(&self.cli)
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args());
        exit_code(command, self.name())
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
        let mut command = Command::new(&self.probe);
        command
            .arg("--crabpot")
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args());
        exit_code(command, self.name())
    }
}

/// Runs the wrapper to its end and returns its exit status. Its stderr is
/// inherited, so a failing run leaves its diagnostics in the log; it is never compared.
fn exit_code(mut command: Command, runner: &'static str) -> Result<u8, Error> {
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(Error::Io)?;
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .ok_or(Error::Signalled(runner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Answers each probe with what `answer` says.
    struct StandIn(&'static str, fn(&Probe) -> u8);

    impl Runner for StandIn {
        fn name(&self) -> &'static str {
            self.0
        }

        fn run(&self, _settings: &Path, probe: &Probe) -> Result<u8, Error> {
            Ok((self.1)(probe))
        }
    }

    fn case() -> Case {
        Case {
            files: Vec::new(),
            settings: json!({}),
            probes: vec![Probe::Read("/r/in".to_owned()), Probe::Bind],
        }
    }

    fn compare_with(upstream: fn(&Probe) -> u8, crabpot: fn(&Probe) -> u8) -> Result<(), Error> {
        compare(
            &case(),
            Path::new("/r/settings.json"),
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
}
