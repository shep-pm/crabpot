//! The probe of how an argument travels through the sandbox's launcher.
//!
//! Upstream's Windows runner wraps an argument that holds a backslash in single
//! quotes, which the program then reads as part of the argument.

use super::{Error, Outcome};

/// Whether an argument that holds a backslash arrived without a pair of single
/// quotes round it.
///
/// Allowed when it arrived as it was written, refused when it is wrapped. An
/// argument with no backslash is an [`Error::NoBackslash`].
pub(super) fn backslash(argument: &str) -> Outcome {
    if !argument.contains('\\') {
        return Err(Error::NoBackslash(argument.to_owned()));
    }
    let wrapped = argument.len() > 1 && argument.starts_with('\'') && argument.ends_with('\'');
    Ok(!wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backslash_argument_that_arrives_whole_is_allowed() {
        assert!(backslash(r"C:\work\out.txt").unwrap());
        assert!(backslash(r"\\host\share").unwrap());
    }

    #[test]
    fn a_backslash_argument_wrapped_in_single_quotes_is_refused() {
        assert!(!backslash(r"'C:\work\out.txt'").unwrap());
    }

    #[test]
    fn an_argument_with_no_backslash_is_an_error() {
        for argument in ["C:/work/out.txt", "'C:/work'"] {
            assert!(
                matches!(backslash(argument), Err(Error::NoBackslash(_))),
                "{argument}"
            );
        }
    }
}
