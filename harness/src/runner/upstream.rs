//! Upstream's wrapper: the `srt` from npm, run over the `probe` binary.
//!
//! On Windows it runs upstream's `srt-win` path, which needs `windows-install`
//! run once on the machine: `node harness/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js
//! windows-install`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::case::Probe;

use super::wrapper::{exit_code, refusal};
use super::{Error, Runner, home};

/// Upstream's `srt`, from the npm package pinned in `harness/package.json`.
#[derive(Debug)]
pub struct Upstream {
    cli: PathBuf,
    probe: PathBuf,
    /// Keeps the probe's copy until the runner is dropped.
    #[cfg(windows)]
    _staged: super::windows::Staged,
}

impl Upstream {
    /// Finds Node and the installed package, to run the `probe` binary at `probe`.
    /// On Linux it also finds `bwrap`, which upstream's runner needs and a
    /// developer's machine may not have. On Windows it copies the probe to a
    /// path upstream can pass on, and runs a warm-up command the first time.
    ///
    /// # Errors
    ///
    /// [`Error::NoUpstream`] when `node` does not run, when `npm ci` has not been
    /// run in `harness/`, on Linux when `bwrap` does not run, or on Windows when
    /// the warm-up command cannot run the probe. [`Error::Io`] when the probe
    /// cannot be copied.
    pub fn find(probe: impl Into<PathBuf>) -> Result<Self, Error> {
        let node = Command::new("node").arg("--version").output();
        if !node.is_ok_and(|output| output.status.success()) {
            return Err(Error::NoUpstream("`node --version` fails".to_owned()));
        }
        if cfg!(target_os = "linux") {
            let bwrap = Command::new("bwrap").arg("--version").output();
            if !bwrap.is_ok_and(|output| output.status.success()) {
                return Err(Error::NoUpstream(
                    "`bwrap --version` fails: install bubblewrap, and with it socat and ripgrep, which upstream also needs".to_owned(),
                ));
            }
        }
        let cli = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js");
        if !cli.is_file() {
            return Err(Error::NoUpstream(format!(
                "{} is missing: run `npm ci` in harness/",
                cli.display()
            )));
        }
        let probe = probe.into();
        #[cfg(windows)]
        {
            let staged = super::windows::Staged::new(&probe).map_err(Error::Io)?;
            let upstream = Self {
                cli,
                probe: staged.probe().to_path_buf(),
                _staged: staged,
            };
            super::windows::warm_up(&upstream, &upstream._staged)?;
            Ok(upstream)
        }
        #[cfg(not(windows))]
        Ok(Self { cli, probe })
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
    pub(super) fn command(&self, settings: &Path, probe: &Probe) -> Command {
        let mut command = Command::new("node");
        command
            .arg(&self.cli)
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args())
            .env("HOME", home(settings))
            .current_dir(home(settings));
        command
    }
}
