//! What upstream's Windows runner asks of the harness: a probe at a path with
//! no backslash in it, folders the sandbox user can enter, and one command run
//! before the first case.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::case::Probe;

use super::wrapper::exit_code;
use super::{Error, Upstream, spell_for_upstream};

/// How many times the warm-up command is tried. `srt-win wfp verify` times out
/// after 30 s, and has done so on the first run on a runner that had only just
/// installed the filters.
const ATTEMPTS: u32 = 3;

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

/// The smallest settings upstream accepts: it requires both `network` and
/// `filesystem`, and refuses `{}` before it runs anything.
const WARM_UP_SETTINGS: &str = r#"{
  "network": {"allowedDomains": [], "deniedDomains": []},
  "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
}"#;

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
        fs::write(&settings, WARM_UP_SETTINGS)?;
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
        match exit_code(upstream.command(staged.settings(), &probe), "upstream") {
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
        let settings: Value = serde_json::from_str(WARM_UP_SETTINGS).unwrap();
        assert!(settings["network"].is_object());
        assert!(settings["filesystem"].is_object());
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
