//! The host of a proxied request, checked and spelled as upstream's
//! `isValidHost` and `canonicalizeHost` (`src/sandbox/parent-proxy.ts`) have it.

use crate::domain::{canonicalize_host, is_ip, strip_brackets};

/// The longest host name DNS has.
const MAX_HOST_BYTES: usize = 255;

/// Whether `host` is a DNS name or an IP literal, with no zone.
///
/// This keeps control characters (CRLF, a null byte that truncates at the DNS
/// layer) and zone identifiers (`::ffff:127.0.0.1%x.allowed.com` would pass a
/// `*.allowed.com` suffix check and connect to 127.0.0.1) from reaching the
/// allow list or the wire.
pub(super) fn is_valid(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_BYTES {
        return false;
    }
    let bare = strip_brackets(host);
    if bare.contains('%') {
        return false;
    }
    is_ip(bare)
        || (!bare.is_empty()
            && bare
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

/// `host` as the URL parser spells it, which is what `getaddrinfo` dials: no
/// brackets, lower case, no trailing dot, an IPv4 address in dotted decimal and
/// an IPv6 address compressed. A host the parser would refuse is returned as
/// it came, without its brackets.
pub(super) fn canonical(host: &str) -> String {
    let bare = strip_brackets(host);
    canonicalize_host(bare).unwrap_or_else(|| bare.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_addresses_are_valid() {
        for host in [
            "example.com",
            "api.example.com.",
            "_dmarc.example.com",
            "localhost",
            "127.0.0.1",
            "0x7f.1",
            "::1",
            "[::1]",
            "[2001:db8::1]",
        ] {
            assert!(is_valid(host), "{host}");
        }
    }

    #[test]
    fn control_characters_zones_and_junk_are_not() {
        for host in [
            "",
            "evil.com\0.allowed.com",
            "evil.com\r\nHost: x",
            "evil.com\t",
            "fe80::1%eth0",
            "::ffff:127.0.0.1%x.allowed.com",
            "a b.com",
            "a/b.com",
            "a@b.com",
            "bücher.example",
            &"a".repeat(256),
        ] {
            assert!(!is_valid(host), "{host:?}");
        }
    }

    #[test]
    fn a_host_is_spelled_as_it_will_be_dialed() {
        for (host, dialed) in [
            ("Api.Example.com.", "api.example.com"),
            ("127.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("0x7f.0.0.1", "127.0.0.1"),
            ("[0:0:0:0:0:0:0:1]", "::1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("example.com", "example.com"),
        ] {
            assert_eq!(canonical(host), dialed, "{host}");
        }
    }
}
