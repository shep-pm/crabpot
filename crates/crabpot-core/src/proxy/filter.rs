//! Whether a command may reach a host: upstream's `filterNetworkRequest`
//! (`src/sandbox/sandbox-manager.ts`), which weighs `network.deniedDomains`
//! before `network.allowedDomains`.

use super::{TcpGrant, host};
use crate::domain::DomainEntry;

/// Why a host was refused. The reason rides in the status line of the 403, as
/// upstream's does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Denial {
    /// The host is not a DNS name or an IP literal.
    MalformedHost,
    /// An entry of `deniedDomains` covers the host and port.
    Denied,
    /// No allowed entry covers the host and port.
    NotAllowed,
}

impl Denial {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            // Upstream's own phrases, less the per-entry reasons of
            // `deniedDomainReasons`, which crabpot does not read yet.
            Self::MalformedHost => "malformed host",
            Self::Denied => "host is on the deny list",
            Self::NotAllowed => "host is not on the allow list",
        }
    }
}

/// The hosts a command may reach.
#[derive(Debug)]
pub(super) struct Filter {
    allowed: Vec<DomainEntry>,
    denied: Vec<DomainEntry>,
    strict: bool,
    tcp: Vec<TcpGrant>,
}

impl Filter {
    pub(super) fn new(allowed: &[DomainEntry], denied: &[DomainEntry], strict: bool) -> Self {
        Self {
            allowed: allowed.to_vec(),
            denied: denied.to_vec(),
            strict,
            tcp: Vec::new(),
        }
    }

    pub(super) fn with_tcp(mut self, tcp: &[TcpGrant]) -> Self {
        self.tcp = tcp.to_vec();
        self
    }

    /// The host spelled as the lists judged it, which the caller dials and no
    /// other spelling, or the reason it is refused.
    pub(super) fn check(&self, host: &str, port: u16) -> Result<String, Denial> {
        if !host::is_valid(host) {
            return Err(Denial::MalformedHost);
        }
        let canonical = host::canonical(host);
        let grants: Vec<_> = self
            .tcp
            .iter()
            .filter(|grant| {
                grant.address.port() == port
                    && host::canonical(&grant.address.ip().to_string()) == canonical
            })
            .collect();
        if grants.iter().any(|grant| {
            self.denied
                .iter()
                .any(|entry| entry.matches(&grant.host, port))
        }) {
            return Err(Denial::Denied);
        }
        if self
            .denied
            .iter()
            .any(|entry| entry.matches(&canonical, port))
        {
            return Err(Denial::Denied);
        }
        if !grants.is_empty()
            || self
                .allowed
                .iter()
                .any(|entry| entry.matches(&canonical, port))
        {
            return Ok(canonical);
        }
        // Upstream's `strictAllowlist` gates only the two ways it widens the
        // configured allow list once both configured lists have failed: the list
        // registered for one command, and its ask callback
        // (`src/sandbox/sandbox-manager.ts:532-566`). crabpot has neither (issue
        // #7), and upstream denies an unlisted host with the same phrase on the
        // path where the flag is off as on the path where it is on, so the flag
        // decides nothing here. It is held for the day crabpot grows a way to
        // ask.
        let _ = self.strict;
        Err(Denial::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lists a test's filter weighs, with `strictAllowlist` left out as
    /// upstream's settings file leaves it, which reads as not strict.
    fn filter_with(allowed: &[&str], denied: &[&str]) -> Filter {
        let allowed: Vec<DomainEntry> = allowed
            .iter()
            .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
            .collect();
        let denied: Vec<DomainEntry> = denied
            .iter()
            .map(|entry| DomainEntry::parse_denied(entry).unwrap())
            .collect();
        Filter::new(&allowed, &denied, false)
    }

    #[test]
    fn an_allow_tcp_address_is_allowed_only_on_its_port() {
        let filter = filter_with(&[], &[]).with_tcp(&[super::super::TcpGrant {
            host: "db.example.com".to_owned(),
            address: "10.0.0.5:5432".parse().unwrap(),
        }]);

        assert_eq!(filter.check("10.0.0.5", 5432).as_deref(), Ok("10.0.0.5"));
        assert_eq!(filter.check("10.0.0.5", 5433), Err(Denial::NotAllowed));
        assert_eq!(filter.check("10.0.0.6", 5432), Err(Denial::NotAllowed));
        assert_eq!(
            filter.check("db.example.com", 5432),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn denied_domains_beat_an_allow_tcp_grant() {
        for denied in ["10.0.0.5", "db.example.com", "*.example.com:5432", "*"] {
            let filter = filter_with(&["10.0.0.5"], &[denied]).with_tcp(&[TcpGrant {
                host: "db.example.com".to_owned(),
                address: "10.0.0.5:5432".parse().unwrap(),
            }]);

            assert_eq!(
                filter.check("10.0.0.5", 5432),
                Err(Denial::Denied),
                "{denied}"
            );
        }
    }

    #[test]
    fn a_host_an_entry_covers_is_allowed_as_it_will_be_dialed() {
        let filter = filter_with(
            &["example.com", "*.example.org", "api.test:8443", "127.0.0.1"],
            &[],
        );

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
        let filter = filter_with(&["example.com", "*.example.org", "api.test:8443"], &[]);

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
            super::Filter::new(&[], &[], false).check("example.com", 443),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn a_denied_host_is_refused_though_allowed() {
        let filter = filter_with(&["*.example.com", "example.org"], &["private.example.com"]);

        assert_eq!(
            filter.check("private.example.com", 443),
            Err(Denial::Denied),
            "the deny list is checked first"
        );
        assert_eq!(
            filter.check("a.example.com", 443).as_deref(),
            Ok("a.example.com")
        );
        assert_eq!(
            filter.check("Private.Example.COM.", 443),
            Err(Denial::Denied),
            "a spelling the allow list would have canonicalized"
        );
    }

    #[test]
    fn a_port_suffix_denies_only_that_port() {
        let filter = filter_with(
            &["github.com", "*.npmjs.org"],
            &["github.com:22", "*.npmjs.org:443"],
        );

        assert_eq!(filter.check("github.com", 22), Err(Denial::Denied));
        assert_eq!(filter.check("github.com", 443).as_deref(), Ok("github.com"));
        assert_eq!(filter.check("a.npmjs.org", 443), Err(Denial::Denied));
        assert_eq!(
            filter.check("a.npmjs.org", 8443).as_deref(),
            Ok("a.npmjs.org"),
            "an entry with a port covers that port alone"
        );
    }

    #[test]
    fn a_bare_star_denies_everything() {
        let filter = filter_with(&["*.example.com"], &["*"]);

        for host in ["example.com", "a.example.com", "127.0.0.1"] {
            assert_eq!(filter.check(host, 443), Err(Denial::Denied), "{host}");
        }

        let only_ssh = filter_with(&["example.com"], &["*:22"]);
        assert_eq!(
            only_ssh.check("example.com", 22),
            Err(Denial::Denied),
            "`*:22` is upstream's deny-everything-on-one-port entry"
        );
        assert_eq!(
            only_ssh.check("example.com", 443).as_deref(),
            Ok("example.com")
        );
    }

    /// Upstream canonicalizes the request host and never a list entry: its
    /// `splitDomainPatternPort` returns the entry's host as written for an
    /// unbracketed entry with no port, and `filterNetworkRequest` calls
    /// `canonicalizeHost` on the request alone. So a deny entry in a shorthand
    /// IPv4 spelling covers nothing, and crabpot leaves it so.
    #[test]
    fn a_deny_entry_is_matched_as_written() {
        let filter = filter_with(&["*.example.com", "127.0.0.1"], &["127.1", "0x7f.0.0.1"]);

        assert_eq!(filter.check("127.0.0.1", 443).as_deref(), Ok("127.0.0.1"));
        assert_eq!(filter.check("0x7f.1", 443).as_deref(), Ok("127.0.0.1"));
        assert_eq!(
            filter.check("127.1", 443).as_deref(),
            Ok("127.0.0.1"),
            "the request is canonicalized, and the entry is not"
        );
    }

    #[test]
    fn strict_and_not_strict_deny_an_unlisted_host_alike() {
        for strict in [true, false] {
            let filter = Filter::new(
                &[DomainEntry::parse_allowed("example.com").unwrap()],
                &[],
                strict,
            );

            assert_eq!(
                filter.check("unlisted.example", 443),
                Err(Denial::NotAllowed),
                "strictAllowlist {strict}"
            );
        }
    }

    #[test]
    fn a_control_character_cannot_ride_a_suffix_past_the_allow_list() {
        let filter = filter_with(&["*.allowed.com"], &[]);

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
        let filter = filter_with(&["*.allowed.com"], &[]);

        assert_eq!(
            filter.check("::ffff:127.0.0.1%x.allowed.com", 443),
            Err(Denial::MalformedHost)
        );
    }
}
