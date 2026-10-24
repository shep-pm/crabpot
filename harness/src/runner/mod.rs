//! Runs a case under upstream and under crabpot, and compares the probes.
//!
//! Each probe is one run of a wrapper around the `probe` binary, so the probe's
//! exit code is the wrapper's exit status.
//!
//! `upstream` and `crabpot` build the two wrapper commands, and `wrapper` reads
//! what running one of them reported. `windows` holds what upstream's Windows
//! runner needs set up first. They are separate files because the
//! comparison and both wrappers together passed 1000 lines (IR-48).

mod crabpot;
mod upstream;
#[cfg(windows)]
mod windows;
mod wrapper;

#[cfg(test)]
mod tests;

pub use self::crabpot::Crabpot;
pub use self::upstream::Upstream;

use std::fs;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::case::{self, Case, Platform, Probe};
use crate::probe;
#[cfg(unix)]
use crate::serve;

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
    /// Upstream cannot be run, for want of Node, of `npm ci` in `harness/`, or,
    /// on Linux, of `bwrap`, or, on Windows, of `windows-install`.
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
/// A `connect-unix` probe gets a socket the harness serves, which `restore`
/// wipes with the rest of the fixture, so it is served again for each run.
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
    run_probes(case, settings, restore, &[upstream, crabpot])
}

/// Runs every probe of `case` under each runner in `runners`, in order. Two of
/// them are compared, and one runner alone is a case run without a comparison:
/// its probes must still each report a code, so a runner that cannot run the
/// probe at all fails the case.
///
/// A probe that reported a code and still could not tell what the sandbox did
/// ([`probe::ERROR`]) fails a comparison, which is what a code is for. The
/// exception is a read of a file the case made: a read deny hides it, so the
/// code is the answer there and the runners must still give the same one. With one
/// runner there is nothing to compare the answer with, so the answer is the
/// finding and the run reports it and goes on: upstream's bwrap path answers a
/// read deny by mounting an empty tmpfs over the denied folder, and a probe of
/// a file that was in it then reads a path that is not there.
fn run_probes(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    runners: &[&dyn Runner],
) -> Result<(), Error> {
    let compare = runners.len() > 1;
    for probe in &case.probes {
        let mut codes = Vec::with_capacity(runners.len());
        for runner in runners {
            restore()?;
            let strict = compare && !hidden_by_a_deny(case, probe);
            let outcome = {
                let _served = serve(probe, settings)?;
                code(*runner, settings, probe, strict)?
            };
            if outcome == probe::ERROR {
                eprintln!(
                    "report: {probe:?} could not tell under {}: it exited {}",
                    runner.name(),
                    probe::ERROR
                );
            }
            codes.push(outcome);
        }
        let (Some(upstream), Some(crabpot)) = (codes.first().copied(), codes.get(1).copied())
        else {
            // One runner alone has nothing to agree with.
            continue;
        };
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

/// The socket a `connect-unix` probe dials, which no probe of the case itself
/// can hold open: each probe is its own sandboxed process, and a listener dies
/// with it. None is served for any other probe.
///
/// It is served where the probe runs, which is the case root for a path named
/// against it, and not where the harness happens to be.
#[cfg(unix)]
fn serve(probe: &Probe, settings: &Path) -> Result<Option<UnixListener>, Error> {
    let Probe::ConnectUnix(path) = probe else {
        return Ok(None);
    };
    let path = socket_path(settings, path);
    // A listener that has gone leaves its file behind, and a bind onto one that
    // is there answers `EADDRINUSE`.
    let _ = fs::remove_file(&path);
    UnixListener::bind(&path).map(Some).map_err(Error::Io)
}

/// Windows has no socket for the harness to serve, so a `connect-unix` probe is
/// an error there and a case that holds one names the platforms it means.
#[cfg(not(unix))]
fn serve(probe: &Probe, _settings: &Path) -> Result<Option<()>, Error> {
    match probe {
        Probe::ConnectUnix(_) => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the harness serves no Unix socket on this platform",
        ))),
        _ => Ok(None),
    }
}

/// Where a probe's socket is, with a path named against the case root read
/// from that root, as each wrapper's working directory reads it.
#[cfg(unix)]
fn socket_path(settings: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        home(settings).join(path)
    }
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
    run_refusals(case, settings, restore, &[upstream, crabpot])
}

/// Runs every probe of `case` under each runner in `runners`, which must all
/// refuse the settings before any probe runs. A `write` probe is the marker:
/// its file must not be there afterwards.
fn run_refusals(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    runners: &[&dyn Runner],
) -> Result<(), Error> {
    for probe in &case.probes {
        for runner in runners {
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

/// Whether `probe` reads a file the case made, which a read deny can hide
/// under an empty tmpfs: the probe then finds no path and exits
/// [`probe::ERROR`]. A path the case never made is not that, it is a typo.
fn hidden_by_a_deny(case: &Case, probe: &Probe) -> bool {
    matches!(probe, Probe::Read(path) if case.files.iter().any(|(made, _)| made == Path::new(path)))
}

/// The code `runner`'s probe reported. A probe that could not tell is an error
/// only where `strict`: where its answer is compared with another runner's and
/// is not one a read deny gives. Otherwise the code is the answer, and a runner
/// that gave another still differs.
fn code(runner: &dyn Runner, settings: &Path, probe: &Probe, strict: bool) -> Result<u8, Error> {
    let outcome = runner.run(settings, probe)?;
    if strict && outcome == probe::ERROR {
        return Err(Error::Erred {
            runner: runner.name(),
            probe: probe.clone(),
        });
    }
    Ok(outcome)
}

/// Runs the case file's `text` under `upstream` and under `crabpot`.
///
/// Reports whether the case ran: one that names platforms this machine is not
/// one of, or that sets a loopback mode other than the one Windows has installed,
/// runs nothing, and is not a failure. See [`Case::runs_on`].
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
) -> Result<bool, Error> {
    run_case_under(text, name, &[upstream, crabpot])
}

/// Runs the case file's `text` under `upstream` alone, with nothing compared.
/// Every probe must still report the code it exited with, so a runner that
/// cannot run its probe at all, or that does not refuse settings the case says
/// are refused, fails the case. A probe that reported a code and could not tell
/// what the sandbox did is reported in the log rather than failed: with nothing
/// to compare it with it says what upstream's runner did, which is what this
/// leg is for.
///
/// Reports whether the case ran, as [`run_case`] does.
///
/// # Errors
///
/// [`Error::Case`] when `text` is not a case, [`Error::Io`] when the root, its
/// files or a served socket cannot be created, [`Error::Unreported`] for a probe
/// the runner never ran, and [`Error::NotRefused`] for a probe that ran under
/// a runner that should have refused the settings first.
pub fn run_upstream_only(text: &str, name: &str, upstream: &dyn Runner) -> Result<bool, Error> {
    run_case_under(text, name, &[upstream])
}

/// Runs the case file's `text` in a fresh root named after `name` under each
/// runner in `runners`, which is the whole comparison for two of them and one
/// runner's own run for one.
fn run_case_under(text: &str, name: &str, runners: &[&dyn Runner]) -> Result<bool, Error> {
    let mut prepared = Prepared::new(text, name)?;
    if !prepared.means_here() {
        return Ok(false);
    }
    prepared.start_serving()?;
    prepared.run(runners).map(|()| true)
}

/// A case file read into a fresh root: the case, its settings file, and the
/// socket it asked the harness to serve, which lives as long as the run does.
struct Prepared {
    root: Root,
    case: Case,
    settings: PathBuf,
    /// Served for the run, and stopped by [`Prepared`]'s `Drop` before the root
    /// is removed, on every way out of the run.
    #[cfg(unix)]
    served: Option<serve::Served>,
}

impl Prepared {
    /// Reads `text` into a root named after `name`.
    ///
    /// # Errors
    ///
    /// [`Error::Case`] when `text` is not a case, [`Error::Io`] when the root
    /// cannot be created.
    fn new(text: &str, name: &str) -> Result<Self, Error> {
        let root = Root::new(name).map_err(Error::Io)?;
        let case = Case::parse(text, &root.0).map_err(Error::Case)?;
        let settings = Path::new(&root.0).join("settings.json");
        Ok(Self {
            root,
            case,
            settings,
            #[cfg(unix)]
            served: None,
        })
    }

    /// Starts whatever socket the case asks the harness to serve, which only a
    /// case that means this platform needs.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the socket cannot be served, or, off Unix, when the
    /// case asks for one.
    #[cfg(unix)]
    fn start_serving(&mut self) -> Result<(), Error> {
        self.served = self
            .case
            .serve
            .as_ref()
            .map(|serve| serve::Served::start(Path::new(&serve.unix_socket), &serve.status))
            .transpose()
            .map_err(Error::Io)?;
        Ok(())
    }

    /// Starts nothing: there is no socket to serve off Unix.
    #[cfg(not(unix))]
    fn start_serving(&mut self) -> Result<(), Error> {
        match self.case.serve {
            None => Ok(()),
            Some(_) => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the harness serves no Unix socket on this platform",
            ))),
        }
    }

    /// Whether the case means the platform this harness runs on, and, on
    /// Windows, the loopback mode the filters were installed with.
    fn means_here(&self) -> bool {
        self.case.runs_on(Platform::current()) && fits_install(&self.case)
    }

    /// The closure that puts the fixture back as the case describes it.
    fn restore(&self) -> impl Fn() -> Result<(), Error> + '_ {
        let keep = self
            .case
            .serve
            .as_ref()
            .map_or(Path::new(""), |serve| Path::new(&serve.unix_socket));
        let root = &self.root;
        let settings = &self.settings;
        move || {
            root.empty(keep).map_err(Error::Io)?;
            for (path, contents) in &self.case.files {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(Error::Io)?;
                }
                fs::write(path, contents).map_err(Error::Io)?;
            }
            match &self.case.settings {
                Value::Null => Ok(()),
                Value::String(text) => fs::write(settings, text).map_err(Error::Io),
                other => fs::write(settings, other.to_string()).map_err(Error::Io),
            }
        }
    }

    /// Runs the case's probes under `runners`, restoring the fixture before
    /// each run.
    fn run(&self, runners: &[&dyn Runner]) -> Result<(), Error> {
        // The socket the case asked the harness to serve stays served for the
        // whole run, and no probe of the case itself may hold it.
        #[cfg(unix)]
        let _served = &self.served;
        let restore = self.restore();
        if self.case.refused {
            run_refusals(&self.case, &self.settings, &restore, runners)
        } else {
            run_probes(&self.case, &self.settings, &restore, runners)
        }
    }
}

#[cfg(unix)]
impl Drop for Prepared {
    /// Stops the served socket before any field drops, which is the order the
    /// run needs on every way out of it, a panic's unwinding included. The
    /// socket is under the root, and a serve ends only when something connects
    /// to its path: a root that is already gone has removed that path, and the
    /// serve then waits in `accept` for a connect that cannot come, so the case
    /// hangs instead of ending. `Prepared`'s fields would otherwise drop in the
    /// order they are declared, root first.
    fn drop(&mut self) {
        self.served = None;
    }
}

/// Whether upstream accepts the case's loopback setting under the install it
/// runs against, see [`windows::loopback_installed`].
#[cfg(windows)]
fn fits_install(case: &Case) -> bool {
    case.allows_loopback() == windows::loopback_installed()
}

/// Every case fits: only the Windows filters are installed in a mode.
#[cfg(not(windows))]
fn fits_install(_: &Case) -> bool {
    true
}

/// Where a case's root is made. On Windows the temp folder will not do, see
/// [`windows::scratch`].
fn scratch() -> PathBuf {
    #[cfg(windows)]
    return windows::scratch();
    #[cfg(not(windows))]
    std::env::temp_dir()
}

/// A fresh folder, its path as `pwd -P` prints it, removed on drop. On Windows
/// the path is spelled for upstream, see [`spell_for_upstream`].
struct Root(String);

impl Root {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = scratch().join(folder(name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let real = dir.canonicalize()?;
        let text = real.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the temp folder is not UTF-8",
            )
        })?;
        if cfg!(windows) {
            Ok(Self(spell_for_upstream(text)))
        } else {
            Ok(Self(text.to_owned()))
        }
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

/// The case folder's name: `c`, this process's id, `name`'s first eight bytes,
/// and eight hex digits of a hash of all of it.
///
/// The whole name does not fit. A Unix socket under the folder is a path the
/// kernel caps at `sun_path`, 104 bytes on macOS, and a Mac's per-user TMPDIR
/// is about 57 of them before the folder is named. The hash keeps two case
/// names that share a start apart, and the id keeps two runs apart.
fn folder(name: &str) -> String {
    let head: String = name.chars().take(8).collect();
    let hash = name.bytes().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_01a3)
    });
    format!("c{}-{head}{hash:08x}", std::process::id())
}

/// `path` as upstream's Windows runner reads an argument: it wraps one that
/// holds a backslash in single quotes, which `cmd` does not read as quotes, so
/// the path takes forward slashes. The `\\?\` prefix of a drive path that
/// `canonicalize` adds is dropped, since a path without a backslash needs none.
/// A UNC path stays as it is.
fn spell_for_upstream(path: &str) -> String {
    let plain = match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
        Some(_) => return path.to_owned(),
        None => path,
    };
    plain.replace('\\', "/")
}

/// The case's root, which holds the settings file: a `~` in a case names a path
/// the case made and not the machine's. It is also the working directory, which
/// the mandatory write denies are under and which a relative probe path reads
/// against.
pub(super) fn home(settings: &Path) -> &Path {
    settings.parent().unwrap_or(settings)
}
