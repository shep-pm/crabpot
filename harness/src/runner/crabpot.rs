//! crabpot's wrapper: the `probe` binary in multicall, asked for crabpot first.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::case::{Env, Probe};

use super::wrapper::{exit_code, export_env, export_harness_pid, refusal};
use super::{Error, Runner, home};

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

    fn run(&self, settings: &Path, probe: &Probe, env: &Env) -> Result<u8, Error> {
        exit_code(self.command(settings, probe, env), self.name())
    }

    fn refuses(&self, settings: &Path, probe: &Probe, env: &Env) -> Result<bool, Error> {
        refusal(self.command(settings, probe, env), self.name(), 125)
    }
}

impl Crabpot {
    fn command(&self, settings: &Path, probe: &Probe, env: &Env) -> Command {
        let mut command = Command::new(&self.probe);
        command
            .arg("--crabpot")
            .arg("--settings")
            .arg(settings)
            .arg("--")
            .arg(&self.probe)
            .args(probe.args());
        // The case's env goes first, so it cannot move the case root `HOME`
        // names.
        export_env(&mut command, env);
        command
            .env("HOME", home(settings))
            .current_dir(home(settings));
        export_harness_pid(&mut command);
        command
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn the_case_cannot_move_the_home_the_wrapper_runs_in() {
        let env = Env::from([
            ("HOME".to_owned(), "/elsewhere".to_owned()),
            ("CLAUDE_CODE_TMPDIR".to_owned(), "/r/fresh".to_owned()),
        ]);

        let command =
            Crabpot::new("probe").command(Path::new("/r/settings.json"), &Probe::Bind, &env);

        let set = |name: &str| {
            command
                .get_envs()
                .find(|(set, _)| *set == OsStr::new(name))
                .and_then(|(_, value)| value)
        };
        assert_eq!(set("HOME"), Some(OsStr::new("/r")));
        assert_eq!(set("CLAUDE_CODE_TMPDIR"), Some(OsStr::new("/r/fresh")));
    }
}
