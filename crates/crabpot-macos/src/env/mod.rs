//! The environment a sandboxed command is given.
//!
//! A part is a file in this folder with a `vars` function, and it is
//! registered by naming it in the `parts!` call. The parts apply in that
//! order, and after whatever the command carried in, so a later part wins
//! over an earlier one and over the host.
//!
//! Two kinds of name come out of them. A name the sandbox owns, such as
//! `TMPDIR`, is set over whatever the command carried, since the profile is
//! what makes the folder it names writable. A name the command owns, such as
//! `JAVA_TOOL_OPTIONS`, is set only when a part has something to add, and
//! then as the command's own value with that addition joined on.
//!
//! [`http`], [`socks`] and [`ssh`] are the proxies' parts. The wrapper applies
//! them beside [`vars`], for they need the proxies' ports and credential, which
//! the wrapper holds and this module does not.

pub use crabpot_core::env::{http, socks};

pub mod ssh;

use std::ffi::OsString;
use std::process::Command;

use crabpot_core::config::Config;

/// Declares each part's module and lists them in the order they apply.
macro_rules! parts {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const PARTS: &[fn(&Facts) -> Vec<(OsString, OsString)>] = &[$($name::vars),*];
    };
}

parts!(base, java, git);

/// What the parts are built from: what the sandbox lets the command reach,
/// and the names it inherits. [`Facts::for_command`] turns the host's names
/// into the ones one command carries.
#[derive(Debug, Clone)]
pub struct Facts {
    /// Whether the sandbox lets the command reach loopback at all.
    pub loopback_reachable: bool,
    /// `CLAUDE_CODE_TMPDIR`, as the host carries it.
    pub claude_code_tmpdir: Option<OsString>,
    /// `CLAUDE_TMPDIR`, as the host carries it.
    pub claude_tmpdir: Option<OsString>,
    /// `JAVA_TOOL_OPTIONS`, as the host carries it, or as one command carries
    /// it after [`Facts::for_command`].
    pub java_tool_options: Option<OsString>,
    /// `git.safeDirectories`: the directories git is told are safe.
    pub git_safe_directories: Vec<String>,
    /// `GIT_CONFIG_COUNT`, as the host carries it, or as one command carries
    /// it after [`Facts::for_command`].
    pub git_config_count: Option<OsString>,
}

impl Facts {
    /// The facts of a sandbox that runs `config` with its network through the
    /// proxy on `proxy_port`, which is what decides whether the command reaches
    /// loopback. The inherited names come from this process's environment,
    /// which is the environment a wrapped command inherits from too.
    #[must_use]
    pub fn for_sandbox(config: &Config, proxy_port: Option<u16>) -> Self {
        use std::env;

        Self {
            // The proxy's own port and `allowLocalBinding` are the two ways a
            // profile lets a command reach loopback at all.
            loopback_reachable: config.network.allows_local_binding() || proxy_port.is_some(),
            claude_code_tmpdir: env::var_os("CLAUDE_CODE_TMPDIR"),
            claude_tmpdir: env::var_os("CLAUDE_TMPDIR"),
            java_tool_options: env::var_os("JAVA_TOOL_OPTIONS"),
            git_safe_directories: config.git.safe_directories.clone(),
            git_config_count: env::var_os(git::GIT_CONFIG_COUNT),
        }
    }

    /// The facts for one command, whose own `env` and `env_remove` calls are
    /// where its environment lands. Only `JAVA_TOOL_OPTIONS` and
    /// `GIT_CONFIG_COUNT` are read from the command: the base part's names are
    /// the host's, the way upstream reads them.
    #[must_use]
    pub fn for_command(&self, command: &Command) -> Self {
        let mut facts = self.clone();
        if let Some((_, value)) = command
            .get_envs()
            .filter(|(key, _)| *key == java::JAVA_TOOL_OPTIONS)
            .last()
        {
            facts.java_tool_options = value.map(OsString::from);
        }
        if let Some((_, value)) = command
            .get_envs()
            .filter(|(key, _)| *key == git::GIT_CONFIG_COUNT)
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
    let mut vars = Vec::new();
    for part in PARTS {
        vars.extend(part(facts));
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(claude_code_tmpdir: Option<&str>, claude_tmpdir: Option<&str>) -> Facts {
        Facts {
            loopback_reachable: false,
            claude_code_tmpdir: claude_code_tmpdir.map(OsString::from),
            claude_tmpdir: claude_tmpdir.map(OsString::from),
            java_tool_options: None,
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
        assert_eq!(
            tmpdir(&facts(Some(""), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
            "an empty name is no answer, as upstream's `||` reads it",
        );
    }

    #[test]
    fn the_flag_joins_the_value_the_command_carries() {
        let host = Facts {
            loopback_reachable: true,
            claude_code_tmpdir: None,
            claude_tmpdir: None,
            java_tool_options: Some(OsString::from("-Xmx256m")),
            git_safe_directories: Vec::new(),
            git_config_count: None,
        };

        let mut command = Command::new("java");
        command.env("JAVA_TOOL_OPTIONS", "-Xmx2g");
        assert_eq!(
            java::vars(&host.for_command(&command)),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Xmx2g -Djava.net.preferIPv4Stack=true"),
            )],
            "the command's own value, not the host's"
        );

        command.env_remove("JAVA_TOOL_OPTIONS");
        assert_eq!(
            java::vars(&host.for_command(&command)),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Djava.net.preferIPv4Stack=true"),
            )],
            "a value the command removed is not carried back"
        );
    }

    fn safe_directories(names: &[&str]) -> Facts {
        Facts {
            git_safe_directories: names.iter().map(|name| (*name).to_owned()).collect(),
            ..facts(None, None)
        }
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
        let vars = pairs(vars(&safe_directories(&["/repo"])));

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
        let vars = pairs(vars(&safe_directories(&[])));

        assert!(
            vars.iter()
                .all(|(name, _)| !name.starts_with("GIT_CONFIG_")),
            "{vars:?}"
        );
    }

    #[test]
    fn the_commands_own_count_wins_over_the_hosts() {
        let host = Facts {
            git_config_count: Some(OsString::from("5")),
            ..safe_directories(&["/repo"])
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

        command.env("GIT_CONFIG_COUNT", "0");
        assert_eq!(
            first_key(&host.for_command(&command)),
            None,
            "an explicit 0 opts out of environment git config"
        );
    }
}
