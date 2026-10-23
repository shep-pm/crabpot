//! The words of a bwrap invocation for one [`Config`].

use std::ffi::OsString;
use std::path::Path;

use crabpot_core::PathError;
use crabpot_core::config::Config;

use crate::fs::Plan;

/// The words that make a bwrap invocation, `bwrap` itself first, for a command
/// under `config`.
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
    root_with_setfcap: bool,
) -> Result<Vec<OsString>, PathError> {
    let mut words = vec![bwrap.as_os_str().to_owned()];
    words.extend_from_slice(Plan::build(config)?.words());
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

    const BWRAP: &str = "/usr/bin/bwrap";

    fn words_for(root_with_setfcap: bool) -> Vec<String> {
        words(Path::new(BWRAP), &Config::default(), root_with_setfcap)
            .expect("the default config resolves")
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
