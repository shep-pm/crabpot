//! The words of a bwrap invocation for one [`Config`].

use std::ffi::OsString;
use std::path::Path;

use crabpot_core::PathError;
use crabpot_core::config::Config;

use crate::fs::Plan;

/// The words that make a bwrap invocation, `bwrap` itself first, for a command
/// under `config`.
///
/// `helper` is the binary that runs the command inside the sandbox. It is bound
/// read-only at its own path after the filesystem words, so no `denyRead` hides
/// it.
///
/// `root_with_setfcap` is whether this process is uid 0 with `CAP_SETFCAP`,
/// which [`is_root_with_setfcap_here`](crate::deps::is_root_with_setfcap_here)
/// answers. The command follows them, after a `--`, as `argv::render` puts it.
///
/// # Errors
///
/// [`PathError`] when a path in `config` starts with `~` and `HOME` is not set,
/// or is relative and there is no working directory.
pub fn words(
    bwrap: &Path,
    config: &Config,
    helper: &Path,
    root_with_setfcap: bool,
) -> Result<Vec<OsString>, PathError> {
    let mut words = vec![bwrap.as_os_str().to_owned()];
    words.extend_from_slice(Plan::build(config)?.words());
    words.extend([OsString::from("--ro-bind"), helper.into(), helper.into()]);
    words.extend(capability_words(root_with_setfcap));
    Ok(words)
}

/// Upstream's `capabilityArgs`: every capability dropped, and `CAP_SETFCAP`
/// kept for uid 0 that has it, since bwrap needs it to write its user
/// namespace's uid map.
fn capability_words(root_with_setfcap: bool) -> impl Iterator<Item = OsString> {
    let keep: &[&str] = if root_with_setfcap {
        &["--cap-add", "CAP_SETFCAP"]
    } else {
        &[]
    };
    ["--cap-drop", "ALL"].iter().chain(keep).map(OsString::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabpot_core::config::PathEntry;

    const BWRAP: &str = "/usr/bin/bwrap";

    const HELPER: &str = "/opt/crabpot/bin/crabpot";

    fn words_for(root_with_setfcap: bool) -> Vec<String> {
        words_at(&Config::default(), root_with_setfcap)
    }

    fn words_at(config: &Config, root_with_setfcap: bool) -> Vec<String> {
        words(
            Path::new(BWRAP),
            config,
            Path::new(HELPER),
            root_with_setfcap,
        )
        .expect("the config resolves")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn the_base_words_start_with_the_read_only_root() {
        let words = words_for(false);

        assert_eq!(words[..4], [BWRAP, "--ro-bind", "/", "/"]);
        for flag in [
            "--unshare-net",
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
        ] {
            assert!(words.iter().any(|word| word == flag), "{flag}: {words:?}");
        }
        for mount in [["--dev", "/dev"], ["--proc", "/proc"]] {
            let at = words
                .windows(2)
                .position(|pair| pair == mount)
                .unwrap_or_else(|| panic!("{mount:?}: {words:?}"));
            assert!(at > 1, "{mount:?} mounts over the root, so it follows it");
        }

        let position = |flag: &str| words.iter().position(|word| word == flag).unwrap();
        assert!(
            position("--unshare-pid") < position("--proc"),
            "a proc mount needs the pid namespace it shows: {words:?}"
        );
    }

    /// bwrap applies its mounts in the order it reads them, and the sandbox's
    /// own `/dev` and `/proc` are the last mounts in the plan. No write bind,
    /// not one of the whole root, lands over them.
    #[test]
    fn the_private_mounts_follow_every_bind() {
        let mut config = Config::default();
        config.filesystem.allow_write = vec![PathEntry::Spelled("/".to_owned())];

        let words = words_at(&config, false);
        let last_bind = words
            .iter()
            .rposition(|word| word == "--bind")
            .expect("the bind of the root");
        for mount in [["--dev", "/dev"], ["--proc", "/proc"]] {
            let at = words
                .windows(2)
                .position(|pair| pair == mount)
                .unwrap_or_else(|| panic!("{mount:?}: {words:?}"));
            assert!(
                last_bind < at,
                "{mount:?} is the plan's own mount: {words:?}"
            );
        }
    }

    #[test]
    fn the_helper_binary_is_bound_read_only_after_the_filesystem_words() {
        let words = words_for(false);

        let at = words
            .windows(3)
            .position(|run| run == ["--ro-bind", HELPER, HELPER])
            .unwrap_or_else(|| panic!("{words:?}"));
        let fs_words = Plan::build(&Config::default()).unwrap();
        assert!(
            at > fs_words.words().len(),
            "a deny bind before it cannot hide it: {words:?}"
        );
    }

    #[test]
    fn capabilities_are_dropped_for_a_non_root_user() {
        let words = words_for(false);

        assert!(
            words.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]),
            "{words:?}"
        );
        assert!(!words.iter().any(|word| word == "--cap-add"), "{words:?}");
    }

    #[test]
    fn root_with_cap_setfcap_keeps_only_that_capability() {
        let words = words_for(true);

        assert!(
            words
                .windows(4)
                .any(|run| run == ["--cap-drop", "ALL", "--cap-add", "CAP_SETFCAP"]),
            "{words:?}"
        );
        assert_eq!(
            words.iter().filter(|word| *word == "--cap-add").count(),
            1,
            "{words:?}"
        );
    }
}
