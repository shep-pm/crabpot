//! Runs a case under upstream and under crabpot, and compares the probes.
//!
//! Each probe is one run of a wrapper around the `probe` binary, so the probe's
//! exit code is the wrapper's exit status.
//!
//! `upstream` and `crabpot` build the two wrapper commands, and `wrapper` reads
//! what running one of them reported. `windows` holds what upstream's Windows
//! runner needs set up first. They are separate files because the
//! comparison and both wrappers together passed 1000 lines (IR-48).
//!
//! Every probe run goes through `gated`, which holds one slot of the gate that
//! caps how many sandboxes the harness runs at once. See `GATE`.

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
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};

use serde_json::Value;

use crate::case::{self, Case, Endpoint, Env, Platform, Probe};
use crate::probe;
use crate::serve;

/// Something that runs one probe in a sandbox and reports the probe's exit code.
pub trait Runner {
    /// Who the runner is, for a failure's message.
    fn name(&self) -> &'static str;

    /// Runs `probe` under the settings file at `settings`, with `env` set on
    /// the wrapper beside the harness's own variables.
    ///
    /// # Errors
    ///
    /// An [`Error`] when the probe cannot be run or does not end with a code.
    fn run(&self, settings: &Path, probe: &Probe, env: &Env) -> Result<u8, Error>;

    /// Whether the wrapper refuses the settings at `settings`: it exits 1
    /// without running `probe`. `env` is set on the wrapper as for [`Runner::run`].
    ///
    /// # Errors
    ///
    /// An [`Error`] when the wrapper cannot be run, or exits with a status
    /// other than 1 without its probe reporting one.
    fn refuses(&self, settings: &Path, probe: &Probe, env: &Env) -> Result<bool, Error>;
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
    /// A runner alone gave a probe a code other than the one the case is held to.
    Unexpected {
        /// The runner that ran it.
        runner: &'static str,
        /// The probe that gave another code.
        probe: Probe,
        /// The code the probe had to give.
        expected: u8,
        /// The code it gave.
        got: u8,
    },
    /// Upstream gave a probe a code other than the one the case records for it,
    /// so the difference the case pins is no longer measured.
    Changed {
        /// The probe that carries the record.
        probe: Probe,
        /// The code the case records for upstream.
        recorded: u8,
        /// What upstream gave.
        upstream: u8,
    },
    /// Crabpot gave a probe the code upstream gives, where the case records
    /// that it differs on purpose.
    NotDifferent {
        /// The probe that carries the record.
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
            Self::Unexpected {
                runner,
                probe,
                expected,
                got,
            } => write!(f, "{probe:?} exited {got} under {runner}, not {expected}"),
            Self::Changed {
                probe,
                recorded,
                upstream,
            } => write!(
                f,
                "{probe:?} exited {upstream} under upstream, where the case records {recorded}"
            ),
            Self::NotDifferent {
                probe,
                upstream,
                crabpot,
            } => write!(
                f,
                "{probe:?} exited {crabpot} under crabpot and {upstream} under upstream, where the case records that they differ"
            ),
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
            | Self::Unexpected { .. }
            | Self::Changed { .. }
            | Self::NotDifferent { .. }
            | Self::NotRefused { .. }
            | Self::NoUpstream(_) => None,
        }
    }
}

/// The gate on how many sandboxes this harness process runs at once.
///
/// On Windows every sandbox takes two loopback ports from the range the
/// installed filters permit, and a sandbox whose proxies find none left fails
/// its probe for want of a port. `cargo test` runs one case per logical CPU, so
/// a machine with more CPUs than the range holds ports runs more sandboxes than
/// the range answers for. Every probe run holds one slot of this gate for as
/// long as its wrapper lives, and a run that finds none waits for one to free.
///
/// The capacity is what the install's range holds, which `windows` reads from
/// `wfp status` once and hands to `set_gate` before any probe runs. Off Windows
/// no shared port range bounds the sandboxes, and the gate is never set: it
/// holds [`UNLIMITED`] of them, and a slot costs one lock.
static GATE: OnceLock<Gate> = OnceLock::new();

/// The capacity of a gate nothing set: every platform but Windows has no port
/// range for the sandboxes to share.
const UNLIMITED: usize = usize::MAX;

/// The loopback ports one sandbox's proxies take from the install's range: the
/// mux's front end and its HTTP backend.
const PORTS_PER_SANDBOX: u16 = 2;

/// A counting semaphore over the sandboxes this harness process runs at once.
#[derive(Debug)]
struct Gate {
    /// The slots still free, which `waiting` guards: every waiter sleeps on
    /// this same lock.
    free: Mutex<usize>,
    /// Woken by every slot given back.
    waiting: Condvar,
}

impl Gate {
    /// A gate that holds `slots` sandboxes at once.
    fn new(slots: usize) -> Self {
        Self {
            free: Mutex::new(slots),
            waiting: Condvar::new(),
        }
    }

    /// Takes a slot, waiting for one to free when every slot is held. The slot
    /// goes back when the returned guard is dropped, which is on every way out
    /// of the run that took it, a panic's unwinding included.
    fn acquire(&self) -> Slot<'_> {
        let mut free = self.lock();
        while *free == 0 {
            free = self
                .waiting
                .wait(free)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *free -= 1;
        drop(free);
        Slot { gate: self }
    }

    /// The slots, taken back from a panic that poisoned the lock rather than
    /// failing a run for it.
    fn lock(&self) -> MutexGuard<'_, usize> {
        self.free
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One slot of the harness's gate, held for as long as the run that took it
/// lives.
#[derive(Debug)]
struct Slot<'gate> {
    gate: &'gate Gate,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut free = self.gate.lock();
        *free += 1;
        self.gate.waiting.notify_one();
    }
}

/// Sets the harness's gate to `slots` sandboxes at once, once per process: a
/// gate a run has already reached keeps the capacity that run found.
///
/// The Windows leg of `Upstream::find` is the only caller: off Windows nothing
/// bounds the sandboxes, and the gate keeps its [`UNLIMITED`] capacity.
#[cfg(windows)]
fn set_gate(slots: usize) {
    GATE.get_or_init(|| Gate::new(slots));
}

/// Runs `run` with one slot of the harness's gate held. See [`GATE`].
fn gated<T>(run: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    let _slot = GATE.get_or_init(|| Gate::new(UNLIMITED)).acquire();
    run()
}

/// How many sandboxes a proxy port range from `first` to `last`, both included,
/// holds at once: each sandbox takes [`PORTS_PER_SANDBOX`] ports, so the range
/// holds half as many sandboxes as it has ports, and the odd port out holds
/// none.
///
/// A range too narrow to pair holds no sandbox, and this still answers one: a
/// case run under such a range then gets the answer a proxy that could not bind
/// gives, and not a harness waiting on a slot that never frees.
///
/// `windows` is the only caller, for the range it reads from `wfp status`, so
/// off Windows this is used by its tests alone.
#[cfg_attr(not(windows), allow(dead_code))]
fn sandboxes_in_range(first: u16, last: u16) -> usize {
    let ports = usize::from(last) - usize::from(first) + 1;
    (ports / usize::from(PORTS_PER_SANDBOX)).max(1)
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
/// runner, [`Error::Differ`] for the first probe the runners disagree on,
/// [`Error::Changed`] and [`Error::NotDifferent`] for a probe that records a
/// difference and does not show it, and whatever `restore` or a runner returns.
pub fn compare(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    run_probes(case, settings, restore, &[upstream, crabpot])
}

/// Runs every probe of `case` under `runner` alone, which must give each the
/// code `expected`. This holds a runner to an answer where there is no second
/// runner to agree with.
///
/// # Errors
///
/// [`Error::Unexpected`] for the first probe that gives another code, and
/// whatever `restore`, serving a socket or the runner returns.
pub fn expect(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    runner: &dyn Runner,
    expected: u8,
) -> Result<(), Error> {
    for probe in &case.probes {
        restore()?;
        let _served = serve(probe, settings)?;
        let got = code(runner, settings, probe, &case.env, false)?;
        if got != expected {
            return Err(Error::Unexpected {
                runner: runner.name(),
                probe: probe.clone(),
                expected,
                got,
            });
        }
    }
    Ok(())
}

/// Runs every probe of `case` under each runner in `runners`, in order. Two of
/// them are compared, and one runner alone is a case run without a comparison:
/// its probes must still each report a code, so a runner that cannot run the
/// probe at all fails the case.
///
/// A probe that records the code upstream gives, where crabpot differs on
/// purpose, passes a comparison only if upstream gives that code and crabpot
/// gives another.
///
/// Each run goes through [`gated`], so the sandboxes live at once never
/// outnumber what the install's proxy port range holds.
///
/// A probe that reported a code and still could not tell what the sandbox did
/// ([`probe::ERROR`]) fails a comparison, which is what a code is for. The
/// exception is a read of a file the case made: a read deny hides it, so the
/// code is the answer there and the runners must still give the same one. So is
/// a probe the case records upstream as giving that code. With one
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
    for (index, probe) in case.probes.iter().enumerate() {
        let mut codes = Vec::with_capacity(runners.len());
        let recorded = case.upstream_exit(index);
        for (position, runner) in runners.iter().enumerate() {
            restore()?;
            // Upstream is the first runner, and a case may record that its
            // probe could not tell: a write into a folder only crabpot makes.
            let recorded_error = position == 0 && recorded == Some(probe::ERROR);
            let strict = compare && !hidden_by_a_deny(case, probe) && !recorded_error;
            let outcome = {
                let _served = serve(probe, settings)?;
                code(*runner, settings, probe, &case.env, strict)?
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
        if let Some(recorded) = recorded {
            if upstream != recorded {
                return Err(Error::Changed {
                    probe: probe.clone(),
                    recorded,
                    upstream,
                });
            }
            if crabpot == upstream {
                return Err(Error::NotDifferent {
                    probe: probe.clone(),
                    upstream,
                    crabpot,
                });
            }
            continue;
        }
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
/// its file must not be there afterwards. Each refusal is a wrapper run, and
/// each goes through [`gated`] like every other probe run.
fn run_refusals(
    case: &Case,
    settings: &Path,
    restore: &dyn Fn() -> Result<(), Error>,
    runners: &[&dyn Runner],
) -> Result<(), Error> {
    for probe in &case.probes {
        for runner in runners {
            restore()?;
            if !gated(|| runner.refuses(settings, probe, &case.env))? || written(probe) {
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

/// The code `runner`'s probe reported, with one slot of the harness's gate held
/// for the whole run. A probe that could not tell is an error only where
/// `strict`: where its answer is compared with another runner's and is not one a
/// read deny gives. Otherwise the code is the answer, and a runner that gave
/// another still differs.
fn code(
    runner: &dyn Runner,
    settings: &Path,
    probe: &Probe,
    env: &Env,
    strict: bool,
) -> Result<u8, Error> {
    let outcome = gated(|| runner.run(settings, probe, env))?;
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

/// Runs the case file's `text` under `runner` alone, which must give every probe
/// the code `expected`. See [`expect`].
///
/// Reports whether the case ran, as [`run_case`] does.
///
/// # Errors
///
/// [`Error::Case`] when `text` is not a case, [`Error::Io`] when the root, its
/// files or a served socket cannot be created, and what [`expect`] returns.
pub fn run_expecting(
    text: &str,
    name: &str,
    runner: &dyn Runner,
    expected: u8,
) -> Result<bool, Error> {
    let mut prepared = Prepared::new(text, name)?;
    if !prepared.means_here() {
        return Ok(false);
    }
    prepared.start_serving()?;
    let restore = prepared.restore();
    expect(
        &prepared.case,
        &prepared.settings,
        &restore,
        runner,
        expected,
    )?;
    Ok(true)
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
            served: None,
        })
    }

    /// Starts whatever socket the case asks the harness to serve.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the socket cannot be served.
    fn start_serving(&mut self) -> Result<(), Error> {
        self.served = self
            .case
            .serve
            .as_ref()
            .map(|serve| serve::Served::start(&serve.endpoint, &serve.status))
            .transpose()
            .map_err(Error::Io)?;
        Ok(())
    }

    /// Whether the case means the platform this harness runs on, and, on
    /// Windows, the loopback mode the filters were installed with.
    fn means_here(&self) -> bool {
        self.case.runs_on(Platform::current()) && fits_install(&self.case)
    }

    /// The closure that puts the fixture back as the case describes it.
    fn restore(&self) -> impl Fn() -> Result<(), Error> + '_ {
        let keep = match self.case.serve.as_ref().map(|serve| &serve.endpoint) {
            Some(Endpoint::UnixSocket(socket)) => Path::new(socket),
            Some(Endpoint::NamedPipe(_)) | None => Path::new(""),
        };
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
        let _served = &self.served;
        let restore = self.restore();
        if self.case.refused {
            run_refusals(&self.case, &self.settings, &restore, runners)
        } else {
            run_probes(&self.case, &self.settings, &restore, runners)
        }
    }
}

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
