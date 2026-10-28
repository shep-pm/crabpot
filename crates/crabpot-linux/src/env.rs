//! The environment a sandboxed command is given on Linux.
//!
//! The base part is the platform-independent one
//! ([`crabpot_core::env::base`]), and the names it sets are the sandbox's own:
//! they are set over whatever the command carried, since the sandbox is what
//! makes the folder `TMPDIR` names writable. The git part is the config's
//! `git.safeDirectories`, and it is set only when the config names some.

use std::env;
use std::ffi::OsString;
use std::process::Command;

use crabpot_core::config::Config;

/// The name a command carries its git config count in.
const GIT_CONFIG_COUNT: &str = "GIT_CONFIG_COUNT";

/// What the environment is built from: the names the command inherits from the
/// host, and the config's list of directories git is told are safe.
#[derive(Debug, Clone)]
pub struct Facts {
    /// `CLAUDE_CODE_TMPDIR`, as the host carries it.
    pub claude_code_tmpdir: Option<OsString>,
    /// `CLAUDE_TMPDIR`, as the host carries it.
    pub claude_tmpdir: Option<OsString>,
    /// `git.safeDirectories`: the directories git is told are safe.
    pub git_safe_directories: Vec<String>,
    /// `GIT_CONFIG_COUNT`, as the host carries it, or as one command carries
    /// it after [`Facts::for_command`].
    pub git_config_count: Option<OsString>,
}

impl Facts {
    /// The facts of a sandbox that runs `config`, started by this process. The
    /// inherited names come from this process's environment, which is the
    /// environment a wrapped command inherits from too.
    #[must_use]
    pub fn for_sandbox(config: &Config) -> Self {
        Self {
            claude_code_tmpdir: env::var_os("CLAUDE_CODE_TMPDIR"),
            claude_tmpdir: env::var_os("CLAUDE_TMPDIR"),
            git_safe_directories: config.git.safe_directories.clone(),
            git_config_count: env::var_os(GIT_CONFIG_COUNT),
        }
    }

    /// The facts for one command, whose own `env` and `env_remove` calls are
    /// where its environment lands. Only `GIT_CONFIG_COUNT` is read from the
    /// command: the base part's names are the host's, the way upstream reads
    /// them.
    #[must_use]
    pub fn for_command(&self, command: &Command) -> Self {
        let mut facts = self.clone();
        if let Some((_, value)) = command
            .get_envs()
            .filter(|(key, _)| *key == GIT_CONFIG_COUNT)
            .last()
        {
            facts.git_config_count = value.map(OsString::from);
        }
        facts
    }
}

/// The variables to set on a wrapped command, in the order to set them in.
#[must_use]
pub fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    let mut vars = crabpot_core::env::base::vars(
        facts.claude_code_tmpdir.as_deref(),
        facts.claude_tmpdir.as_deref(),
    );
    if !facts.git_safe_directories.is_empty() {
        let carried = facts
            .git_config_count
            .as_deref()
            .map(|count| count.to_string_lossy());
        vars.extend(
            crabpot_core::env::git::safe_directory_vars(
                &facts.git_safe_directories,
                carried.as_deref(),
            )
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        );
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(claude_code_tmpdir: Option<&str>, claude_tmpdir: Option<&str>) -> Facts {
        Facts {
            claude_code_tmpdir: claude_code_tmpdir.map(OsString::from),
            claude_tmpdir: claude_tmpdir.map(OsString::from),
            git_safe_directories: Vec::new(),
            git_config_count: None,
        }
    }

    fn tmpdir(facts: &Facts) -> Option<OsString> {
        vars(facts)
            .into_iter()
            .find(|(name, _)| name == "TMPDIR")
            .map(|(_, value)| value)
    }

    #[test]
    fn sandbox_runtime_and_tmpdir_are_set() {
        assert_eq!(
            vars(&facts(None, None)),
            vec![
                (OsString::from("SANDBOX_RUNTIME"), OsString::from("1")),
                (OsString::from("TMPDIR"), OsString::from("/tmp/claude")),
            ],
        );
    }

    #[test]
    fn tmpdir_prefers_claude_code_tmpdir_then_claude_tmpdir() {
        assert_eq!(
            tmpdir(&facts(Some("/tmp/code"), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/code")),
        );
        assert_eq!(
            tmpdir(&facts(None, Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
        );
    }

    #[test]
    fn an_empty_name_is_no_answer() {
        assert_eq!(
            tmpdir(&facts(Some(""), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
            "an empty name is no answer, as upstream's `||` reads it",
        );
        assert_eq!(
            tmpdir(&facts(Some("/tmp/code"), Some(""))),
            Some(OsString::from("/tmp/code")),
            "the empty name is skipped, not chosen",
        );
        assert_eq!(
            tmpdir(&facts(Some(""), Some(""))),
            Some(OsString::from("/tmp/claude")),
            "two empty names are no answer either",
        );
    }

    fn pairs(vars: Vec<(OsString, OsString)>) -> Vec<(String, String)> {
        vars.into_iter()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn a_configured_safe_directory_is_given_to_git() {
        let facts = Facts {
            git_safe_directories: vec!["/repo".to_owned()],
            ..facts(None, None)
        };
        let vars = pairs(vars(&facts));

        for expected in [
            ("GIT_CONFIG_KEY_0", "safe.directory"),
            ("GIT_CONFIG_VALUE_0", "/repo"),
            ("GIT_CONFIG_KEY_1", "safe.directory"),
            ("GIT_CONFIG_VALUE_1", "/repo/*"),
            ("GIT_CONFIG_COUNT", "2"),
        ] {
            assert!(
                vars.contains(&(expected.0.to_owned(), expected.1.to_owned())),
                "{expected:?} is missing from {vars:?}"
            );
        }
    }

    #[test]
    fn an_empty_list_emits_no_git_config_name() {
        let vars = pairs(vars(&facts(None, None)));

        assert!(
            vars.iter()
                .all(|(name, _)| !name.starts_with("GIT_CONFIG_")),
            "{vars:?}"
        );
    }

    #[test]
    fn the_commands_own_count_wins_over_the_hosts() {
        let host = Facts {
            git_safe_directories: vec!["/repo".to_owned()],
            git_config_count: Some(OsString::from("5")),
            ..facts(None, None)
        };
        let first_key = |facts: &Facts| {
            pairs(vars(facts))
                .into_iter()
                .find(|(name, _)| name.starts_with("GIT_CONFIG_KEY_"))
                .map(|(name, _)| name)
        };
        assert_eq!(first_key(&host).as_deref(), Some("GIT_CONFIG_KEY_5"));

        let mut command = Command::new("git");
        command.env("GIT_CONFIG_COUNT", "1");
        assert_eq!(
            first_key(&host.for_command(&command)).as_deref(),
            Some("GIT_CONFIG_KEY_1")
        );

        command.env_remove("GIT_CONFIG_COUNT");
        assert_eq!(
            first_key(&host.for_command(&command)).as_deref(),
            Some("GIT_CONFIG_KEY_0"),
            "a count the command removed is not carried back"
        );
    }
}
