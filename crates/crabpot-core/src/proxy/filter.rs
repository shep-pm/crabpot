//! Whether a command may reach a host: upstream's `filterNetworkRequest`
//! (`src/sandbox/sandbox-manager.ts`), as far as the allow list goes. The deny
//! list and the strict allow list come with their keys.

use super::host;
use crate::domain::DomainEntry;

/// Why a host was refused. The reason rides in the status line of the 403, as
/// upstream's does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Denial {
    /// The host is not a DNS name or an IP literal.
    MalformedHost,
    /// No allowed entry covers the host and port.
    NotAllowed,
}

impl Denial {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::MalformedHost => "malformed host",
            Self::NotAllowed => "host is not on the allow list",
        }
    }
}

/// The hosts a command may reach.
#[derive(Debug)]
pub(super) struct Filter {
    allowed: Vec<DomainEntry>,
}

impl Filter {
    pub(super) fn new(allowed: &[DomainEntry]) -> Self {
        Self {
            allowed: allowed.to_vec(),
        }
    }

    /// The host spelled as the allow list judged it, which the caller dials and
    /// no other spelling, or the reason it is refused.
    pub(super) fn check(&self, host: &str, port: u16) -> Result<String, Denial> {
        if !host::is_valid(host) {
            return Err(Denial::MalformedHost);
        }
        let canonical = host::canonical(host);
        if self
            .allowed
            .iter()
            .any(|entry| entry.matches(&canonical, port))
        {
            Ok(canonical)
        } else {
            Err(Denial::NotAllowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(entries: &[&str]) -> Filter {
        let entries: Vec<DomainEntry> = entries
            .iter()
            .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
            .collect();
        Filter::new(&entries)
    }

    #[test]
    fn a_host_an_entry_covers_is_allowed_as_it_will_be_dialed() {
        let filter = filter(&["example.com", "*.example.org", "api.test:8443", "127.0.0.1"]);

        assert_eq!(
            filter.check("example.com", 443).as_deref(),
            Ok("example.com")
        );
        assert_eq!(
            filter.check("Example.COM.", 80).as_deref(),
            Ok("example.com")
        );
        assert_eq!(
            filter.check("a.example.org", 443).as_deref(),
            Ok("a.example.org")
        );
        assert_eq!(filter.check("api.test", 8443).as_deref(), Ok("api.test"));
        assert_eq!(filter.check("0x7f.1", 80).as_deref(), Ok("127.0.0.1"));
    }

    #[test]
    fn a_host_no_entry_covers_is_not_allowed() {
        let filter = filter(&["example.com", "*.example.org", "api.test:8443"]);

        for (host, port) in [
            ("example.net", 443),
            ("example.org", 443),
            ("api.test", 443),
            ("evil-example.com", 443),
            ("example.com.evil.net", 443),
        ] {
            assert_eq!(filter.check(host, port), Err(Denial::NotAllowed), "{host}");
        }
        assert_eq!(
            super::Filter::new(&[]).check("example.com", 443),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn a_control_character_cannot_ride_a_suffix_past_the_allow_list() {
        let filter = filter(&["*.allowed.com"]);

        assert_eq!(
            filter.check("evil.com\0.allowed.com", 443),
            Err(Denial::MalformedHost)
        );
        assert_eq!(
            filter.check("a\r\nHost: x.allowed.com", 443),
            Err(Denial::MalformedHost)
        );
    }

    #[test]
    fn a_zone_cannot_pass_for_a_subdomain() {
        let filter = filter(&["*.allowed.com"]);

        assert_eq!(
            filter.check("::ffff:127.0.0.1%x.allowed.com", 443),
            Err(Denial::MalformedHost)
        );
    }
}
