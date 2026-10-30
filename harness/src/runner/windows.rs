//! What upstream's Windows runner asks of the harness: a probe at a path with
//! no backslash in it, folders the sandbox user can enter, one command run
//! before the first case, and the count of sandboxes the install's proxy port
//! range holds.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use crate::case::{Env, Probe};

use super::wrapper::exit_code;
use super::{Error, Upstream, gated, sandboxes_in_range, spell_for_upstream};

/// How many times the warm-up command is tried. `srt-win wfp verify` times out
/// after 30 s, and has done so on the first run on a runner that had only just
/// installed the filters.
const ATTEMPTS: u32 = 3;

/// The argument that hands a multicall binary's whole command line to srt-win,
/// which is `crabpot_windows::SRT_WIN_DISPATCH_ARG1`. crabpot's own status read
/// passes it the same way.
const SRT_WIN_FLAG: &str = "--srt-win";

/// The loopback ports `windows-install` leaves open for the proxy unless it is
/// told another. It is what a sandbox binds in when its status reports no range
/// at all, and so the same default `crabpot_core::proxy::PortRange::DEFAULT`
/// and srt-win's `DEFAULT_PROXY_PORT_RANGE` hold.
const DEFAULT_PROXY_PORT_RANGE: (u16, u16) = (60080, 60089);

/// The folder every case root and staged probe goes under, on the system drive.
///
/// The temp folder will not do. The sandbox runs as another user, which has no
/// rights in the runner's profile but the read grant `windows-install` makes,
/// and that grant leaves `AppData\Local\Temp` out on purpose. Upstream passes
/// the working directory to the sandbox as it is and grants it nothing, so a
/// folder under the temp folder fails before the probe runs, with
/// `mapped_drive_cwd`, which is what it says for any working directory that the
/// sandbox user cannot enter. A folder made under the drive's root inherits read
/// access for `Users`, which the sandbox user is in. It does not inherit write
/// access, since the sandbox's write-restricted token drops the rights a group
/// holds, so a write is still refused unless the case grants it.
pub(super) fn scratch() -> PathBuf {
    let drive = std::env::var_os("SystemDrive").unwrap_or_else(|| "C:".into());
    PathBuf::from(format!(
        r"{}\crabpot-harness",
        drive.to_string_lossy().trim_end_matches(['\\', '/'])
    ))
}

/// The environment variable that says how `windows-install` was run: `open` when
/// it was given `--allow-loopback`, and any other value, or none, when it was not.
const LOOPBACK_VAR: &str = "CRABPOT_HARNESS_LOOPBACK";

/// Whether the filters were installed with loopback open. Upstream refuses a
/// session whose `network.allowLocalBinding` is not the installed mode, in either
/// direction, so the harness runs only the cases that match, and CI installs
/// twice.
pub(super) fn loopback_installed() -> bool {
    std::env::var(LOOPBACK_VAR).is_ok_and(|mode| mode == "open")
}

/// The smallest settings upstream accepts: it requires both `network` and
/// `filesystem`, and refuses `{}` before it runs anything. They set the
/// loopback mode the filters were installed with, which upstream checks.
fn warm_up_settings() -> String {
    serde_json::json!({
        "network": {
            "allowedDomains": [],
            "deniedDomains": [],
            "allowLocalBinding": loopback_installed(),
        },
        "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []},
    })
    .to_string()
}

/// `path` spelled for upstream.
fn spelled(path: &Path) -> io::Result<PathBuf> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the scratch folder is not UTF-8",
        )
    })?;
    Ok(PathBuf::from(spell_for_upstream(text)))
}

/// The `probe` binary copied into a folder of its own and spelled with forward
/// slashes, which is how upstream passes it to the sandboxed shell. The copy is
/// under [`scratch`], which the sandbox user can read, and the build folder it
/// comes from is not.
#[derive(Debug)]
pub(super) struct Staged {
    dir: PathBuf,
    settings: PathBuf,
    probe: PathBuf,
}

impl Staged {
    /// Copies the binary at `probe` into a fresh folder.
    pub(super) fn new(probe: &Path) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = scratch().join(format!(
            "crabpot-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir)?;
        let dir = dir.canonicalize()?;
        let copy = dir.join("probe.exe");
        fs::copy(probe, &copy)?;
        let settings = dir.join("settings.json");
        fs::write(&settings, warm_up_settings())?;
        Ok(Self {
            probe: spelled(&copy)?,
            settings: spelled(&settings)?,
            dir,
        })
    }

    /// The warm-up's settings file, spelled for upstream.
    pub(super) fn settings(&self) -> &Path {
        &self.settings
    }

    /// The copy, spelled for upstream.
    pub(super) fn probe(&self) -> &Path {
        &self.probe
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// How many sandboxes this machine's install holds at once, which is what the
/// harness's gate is set to before any probe runs. See `sandboxes_in_range`.
///
/// The count comes from the range `wfp status` reports, read once for the
/// harness process by running `probe` as srt-win, which is how crabpot's own
/// status reads the install. BFE's filter enum is admin-gated, and an
/// unelevated `wfp status` answers `state:"cannot-read"` with no range at all:
/// the harness then holds to the install's default, which is the range a sandbox
/// binds in under that status too.
pub(super) fn sandboxes_at_once(probe: &Path) -> usize {
    static SANDBOXES: OnceLock<usize> = OnceLock::new();
    *SANDBOXES.get_or_init(|| match read_port_range(probe) {
        Some((first, last)) => sandboxes_in_range(first, last),
        None => {
            eprintln!(
                "report: `wfp status` named no proxy port range, so the harness runs no more \
                 than {} sandboxes at once: what the install's default {}-{} holds",
                sandboxes_in_range(DEFAULT_PROXY_PORT_RANGE.0, DEFAULT_PROXY_PORT_RANGE.1),
                DEFAULT_PROXY_PORT_RANGE.0,
                DEFAULT_PROXY_PORT_RANGE.1,
            );
            sandboxes_in_range(DEFAULT_PROXY_PORT_RANGE.0, DEFAULT_PROXY_PORT_RANGE.1)
        }
    })
}

/// The range the installed filters permit the proxy to listen in, or `None` for
/// a `wfp status` that did not run, answered what is not JSON, or named no
/// range. An unelevated one names none: BFE's filter enum is admin-gated, and
/// the query degrades to `state:"cannot-read"` rather than failing.
fn read_port_range(probe: &Path) -> Option<(u16, u16)> {
    let output = Command::new(probe)
        .arg(SRT_WIN_FLAG)
        .args(["wfp", "status"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let status: Value = serde_json::from_slice(&output.stdout).ok()?;
    let range = status.get("port_range")?.as_array()?;
    // A range that is not two ports is not the pair the fence was installed
    // with, and a port that does not fit a `u16` is not a port.
    let (Some(low), Some(high)) = (
        range.first().and_then(Value::as_u64),
        range.get(1).and_then(Value::as_u64),
    ) else {
        return None;
    };
    let (Ok(low), Ok(high)) = (u16::try_from(low), u16::try_from(high)) else {
        return None;
    };
    (low <= high).then_some((low, high))
}

/// Runs one trivial probe under `upstream`, the first time any case in this
/// process asks. It is the first sandboxed command since the install, so it
/// pays for the filters coming up, and the cases that follow do not. Every
/// later call answers what the first one found.
///
/// # Errors
///
/// [`Error::NoUpstream`] when no attempt ran the probe, for want of
/// `windows-install` or of a working filter set.
pub(super) fn warm_up(upstream: &Upstream, staged: &Staged) -> Result<(), Error> {
    static WARMED: OnceLock<Result<(), String>> = OnceLock::new();
    WARMED
        .get_or_init(|| attempt(upstream, staged))
        .clone()
        .map_err(Error::NoUpstream)
}

fn attempt(upstream: &Upstream, staged: &Staged) -> Result<(), String> {
    let probe = Probe::Read(staged.probe.display().to_string());
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match gated(|| {
            exit_code(
                upstream.command(staged.settings(), &probe, &Env::new()),
                "upstream",
            )
        }) {
            Ok(_) => return Ok(()),
            Err(error) => {
                eprintln!("report: warm-up attempt {attempt} of {ATTEMPTS}: {error}");
                last = error.to_string();
            }
        }
    }
    Err(format!(
        "the warm-up command never ran its probe ({last}): run `node \
         harness/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js windows-install` first"
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn the_warm_up_settings_hold_the_sections_upstream_requires() {
        let settings: Value = serde_json::from_str(&warm_up_settings()).unwrap();
        assert!(settings["network"].is_object());
        assert!(settings["filesystem"].is_object());
    }

    #[test]
    fn the_warm_up_settings_name_the_installed_loopback_mode() {
        let settings: Value = serde_json::from_str(&warm_up_settings()).unwrap();
        assert_eq!(
            settings["network"]["allowLocalBinding"],
            Value::Bool(loopback_installed())
        );
    }

    #[test]
    fn the_scratch_folder_is_not_under_the_temp_folder() {
        assert!(!scratch().starts_with(std::env::temp_dir()));
    }

    #[test]
    fn a_staged_probe_and_settings_have_no_backslash_or_verbatim_prefix() {
        let staged = Staged::new(&std::env::current_exe().unwrap()).unwrap();
        for path in [staged.probe(), staged.settings()] {
            let text = path.to_str().unwrap();
            assert!(!text.contains('\\'), "{text}");
        }
        assert!(staged.settings().exists());
    }
}
