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
//! [`http`] is the proxy's part. The wrapper applies it beside [`vars`], for
//! it needs the proxy's port and credential, which the wrapper holds and
//! this module does not.

pub mod http;

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

parts!(base, java);

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
        }
    }

    /// The facts for one command, whose own `env` and `env_remove` calls are
    /// where its environment lands. Only `JAVA_TOOL_OPTIONS` is read from the
    /// command: the base part's names are the host's, the way upstream reads
    /// them.
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
}
