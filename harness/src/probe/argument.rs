//! The probe of how an argument travels through the sandbox's launcher.
//!
//! Upstream's Windows runner wraps an argument that holds a backslash in single
//! quotes, which the program then reads as part of the argument. The probe is
//! given what the argument should be a second time, in hex, which holds no
//! character a launcher rewrites, and compares the two.

use super::{Error, Outcome};

/// Whether `argument` is `expected_hex` decoded, byte for byte.
///
/// Allowed when it arrived as it was written, refused when it arrived changed
/// in any way: wrapped in quotes, with its backslashes doubled or dropped.
///
/// # Errors
///
/// [`Error::Usage`] when `expected_hex` is not an even number of hex digits or
/// not UTF-8 once decoded, and [`Error::NoBackslash`] when what it decodes to has
/// no backslash, which proves nothing about how one travels.
pub(super) fn backslash(argument: &str, expected_hex: &str) -> Outcome {
    let expected = decode(expected_hex).ok_or(Error::Usage)?;
    if !expected.contains('\\') {
        return Err(Error::NoBackslash(expected));
    }
    Ok(argument == expected)
}

/// `text` as lowercase hex, two digits a byte.
pub fn encode(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}

fn decode(hex: &str) -> Option<String> {
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).ok().filter(|d| d.len() == 2)?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = r"C:\work\out.txt";

    fn check(argument: &str) -> Outcome {
        backslash(argument, &encode(PATH))
    }

    #[test]
    fn an_argument_that_arrives_whole_is_allowed() {
        assert!(check(PATH).unwrap());
    }

    #[test]
    fn an_argument_that_arrives_changed_is_refused() {
        for changed in [
            r"'C:\work\out.txt'",
            r#""C:\work\out.txt""#,
            r"C:\\work\\out.txt",
            r"C:work\out.txt",
            "C:/work/out.txt",
            r"C:\work\out.tx",
        ] {
            assert!(!check(changed).unwrap(), "{changed}");
        }
    }

    #[test]
    fn what_is_expected_is_a_backslash_text_in_hex() {
        assert_eq!(encode(r"C:\w"), "433a5c77");
        for bad in ["4", "zz", "ff", "é"] {
            assert!(matches!(backslash(PATH, bad), Err(Error::Usage)), "{bad}");
        }
        assert!(matches!(
            backslash("C:/work", &encode("C:/work")),
            Err(Error::NoBackslash(_))
        ));
    }
}
