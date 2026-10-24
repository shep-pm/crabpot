//! What upstream's Windows runner asks of the harness: a probe at a path with
//! no backslash in it, and one command run before the first case.

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

/// The `probe` binary copied into a folder of its own and spelled with forward
/// slashes, which is how upstream passes it to the sandboxed shell. The copy is
/// under the temp folder, which the sandbox user can read once `windows-install`
/// has granted it the profile, and the build folder it comes from is not.
#[derive(Debug)]
pub(super) struct Staged {
    dir: PathBuf,
    probe: PathBuf,
}

impl Staged {
    /// Copies the binary at `probe` into a fresh folder.
    pub(super) fn new(probe: &Path) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "crabpot-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir)?;
        let dir = dir.canonicalize()?;
        let copy = dir.join("probe.exe");
        fs::copy(probe, &copy)?;
        let spelled = copy.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "the temp folder is not UTF-8")
        })?;
        Ok(Self {
            probe: PathBuf::from(spell_for_upstream(spelled)),
            dir,
        })
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
    let settings = staged.dir.join("settings.json");
    fs::write(&settings, "{}").map_err(|error| error.to_string())?;
    let probe = Probe::Read(staged.probe.display().to_string());
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match exit_code(upstream.command(&settings, &probe), "upstream") {
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
