//! What a sandboxed command presents to the proxy: a random token, and a
//! username that says which command it is, as upstream's `proxyUsernameFor`
//! and `checkAuth` have them.

use core::fmt;
use std::fs::File;
use std::io::{self, Read};

/// The base username. The token is the credential and this is a label.
const USER: &str = "srt";

/// RFC 1929 caps a SOCKS5 username at 255 bytes, and one proxy username serves
/// both protocols.
const MAX_USERNAME_BYTES: usize = 255;

/// How many UTF-16 code units of a command ride in the username.
const COMMAND_KEY_UNITS: usize = 100;

/// The username a command presents: `srt.<base64 of the command>`, or bare
/// `srt` when there is no command, or when its base64 would not fit in a
/// username. Attribution is lost then and connectivity is not.
///
/// The command is cut to 100 UTF-16 code units first, as upstream cuts it, so
/// two commands that share that much of a prefix share a username.
#[must_use]
pub fn username_for(command: &str) -> String {
    let key = truncate_units(command, COMMAND_KEY_UNITS);
    if key.is_empty() {
        return USER.to_owned();
    }
    let user = format!("{USER}.{}", base64_encode(key.as_bytes()));
    if user.len() <= MAX_USERNAME_BYTES {
        user
    } else {
        USER.to_owned()
    }
}

/// `text` cut to `units` UTF-16 code units. A character the cut would split
/// becomes U+FFFD, which is what JavaScript's slice leaves a UTF-8 encoder to
/// write for the lone surrogate.
fn truncate_units(text: &str, units: usize) -> String {
    let mut cut = String::new();
    let mut used = 0;
    for c in text.chars() {
        let width = c.len_utf16();
        if used + width > units {
            if used < units {
                cut.push('\u{FFFD}');
            }
            break;
        }
        cut.push(c);
        used += width;
    }
    cut
}

/// The proxy's credential: 16 random bytes in hex, made once for each proxy.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Token(String);

impl Token {
    /// Reads 16 bytes from `/dev/urandom`.
    pub(super) fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(Self(hex))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a `Proxy-Authorization` header value is `Basic` with a
    /// non-empty username and this token, which is all `checkAuth` asks.
    pub(super) fn accepts(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Some((scheme, rest)) = header.split_once(|c: char| c.is_ascii_whitespace()) else {
            return false;
        };
        let encoded = rest.trim_matches(|c: char| c.is_ascii_whitespace());
        if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
            return false;
        }
        let Some(decoded) = base64_decode(encoded) else {
            return false;
        };
        let decoded = String::from_utf8_lossy(&decoded);
        match decoded.split_once(':') {
            Some((user, password)) => !user.is_empty() && same(password, &self.0),
            None => false,
        }
    }
}

/// Equal strings, in a time that does not depend on where they differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(super) fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (at, &byte)| {
            word | u32::from(byte) << (16 - 8 * at)
        });
        for place in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[(word >> (18 - 6 * place) & 63) as usize],
            ));
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

/// Standard base64, with the padding optional. Anything outside the alphabet,
/// or padding that is not at the end, is `None`.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim_end_matches('=');
    if text.len() - digits.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    let mut word = 0u32;
    let mut held = 0;
    for byte in digits.bytes() {
        let value = ALPHABET.iter().position(|&a| a == byte)?;
        word = word << 6 | value as u32;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((word >> held) as u8);
            word &= (1 << held) - 1;
        }
    }
    // A last digit that leaves a whole bit set past the data is not a
    // truncation of anything the encoder writes.
    (word == 0 && digits.len() % 4 != 1).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded, "{plain}");
            assert_eq!(base64_decode(encoded).as_deref(), Some(plain.as_bytes()));
        }
        assert_eq!(base64_decode("Zg").as_deref(), Some(&b"f"[..]), "unpadded");
        assert_eq!(base64_decode("Zm9v!"), None);
        assert_eq!(base64_decode("Zg=g"), None);
    }

    #[test]
    fn a_username_names_the_command_in_base64() {
        assert_eq!(username_for("ls -la"), "srt.bHMgLWxh");
        assert_eq!(username_for(""), "srt");
    }

    #[test]
    fn a_username_keeps_the_first_100_utf16_units_of_the_command() {
        let a100 = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==";
        let a99_then_replacement = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh77+9";

        assert_eq!(username_for(&"a".repeat(150)), format!("srt.{a100}"));
        // 99 units, then a character of two that does not fit.
        let split = format!("{}\u{1F600}", "a".repeat(99));
        assert_eq!(username_for(&split), format!("srt.{a99_then_replacement}"));
    }

    #[test]
    fn a_username_too_long_for_socks_is_the_bare_label() {
        // 100 units of three bytes each is 300 bytes, 400 in base64.
        assert_eq!(username_for(&"€".repeat(100)), "srt");
    }

    fn basic(user_and_password: &str) -> String {
        format!("Basic {}", base64_encode(user_and_password.as_bytes()))
    }

    #[test]
    fn the_token_is_32_hex_digits_and_differs_each_time() {
        let first = Token::generate().unwrap();
        let second = Token::generate().unwrap();

        assert_eq!(first.as_str().len(), 32);
        assert!(first.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn a_credential_is_accepted_only_with_a_user_and_the_token() {
        let token = Token("0123456789abcdef0123456789abcdef".to_owned());
        let good = basic("srt:0123456789abcdef0123456789abcdef");

        assert!(token.accepts(Some(&good)));
        assert!(token.accepts(Some(&good.replacen("Basic", "bAsIc", 1))));
        assert!(token.accepts(Some(&basic("srt.bHM=:0123456789abcdef0123456789abcdef"))));
        for refused in [
            None,
            Some(""),
            Some("Basic"),
            Some("Bearer abc"),
            Some("Basic !!!"),
            Some(&basic("srt:wrong")[..]),
            Some(&basic(":0123456789abcdef0123456789abcdef")[..]),
            Some(&basic("0123456789abcdef0123456789abcdef")[..]),
        ] {
            assert!(!token.accepts(refused), "{refused:?}");
        }
    }

    #[test]
    fn a_token_debug_shows_nothing_of_it() {
        let token = Token("secret".to_owned());

        assert_eq!(format!("{token:?}"), "Token(<redacted>)");
    }
}
