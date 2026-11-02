//! The guard around a direct dial, as upstream's `createResolvedAddressGuard`
//! (`src/sandbox/resolved-address-guard.ts`) builds it.
//!
//! The domain lists decide by name, but whoever controls a permitted name's DNS
//! records decides what it resolves to. The guard judges each address a name
//! resolves to, so the address that passes is one of the addresses dialed, with
//! no second resolution between.
//!
//! It judges names only. An IP literal in the request is never re-judged. A
//! name may resolve to an address that a rule refuses only when that literal
//! (and port) is in `allowedDomains`, and a literal in `deniedDomains` is
//! refused by name too. `localhost` and the names under it resolve to loopback
//! or to an allowed literal, and to nothing else. A dial through a parent proxy
//! or a MITM socket is not resolved here, but crabpot has neither.

use core::net::IpAddr;

use crate::address::{
    AddressRange, DenialReason, RuleSet, builtin_denial, is_loopback_address, is_loopback_name,
};
use crate::domain::{DomainEntry, ip_literal_rules};

/// Which addresses a name may resolve to.
#[derive(Debug)]
pub(super) struct Guard {
    /// The literals of `deniedDomains`.
    refused: RuleSet,
    /// The literals of `allowedDomains`.
    allowed: RuleSet,
    /// `deniedResolvedAddresses`.
    listed: RuleSet,
    /// This host's own addresses, read for each lookup since they change.
    local: fn() -> Vec<IpAddr>,
}

/// Why every address a name resolved to was dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Refusal {
    hostname: String,
    /// The classes that dropped an address, in upstream's order.
    classes: Vec<DenialReason>,
}

impl Refusal {
    /// What the client is told: the classes, never the addresses, which the
    /// sandboxed client should not learn from a refusal.
    pub(super) fn reason(&self) -> String {
        let classes: Vec<&str> = self.classes.iter().map(|class| class.phrase()).collect();
        format!("resolved to {}", classes.join(" / "))
    }

    pub(super) fn message(&self) -> String {
        format!("Connection to {} blocked: {}", self.hostname, self.reason())
    }
}

impl Guard {
    pub(super) fn new(
        allowed: &[DomainEntry],
        denied: &[DomainEntry],
        listed: &[AddressRange],
    ) -> Self {
        Self {
            refused: literal_rules(denied),
            allowed: literal_rules(allowed),
            listed: RuleSet::from_ranges(listed.iter().map(|&range| (range, None))),
            local: interface_addresses,
        }
    }

    /// A guard built from `allowed`, `denied` and `listed`, with this one's
    /// `local`.
    pub(super) fn replaced(
        &self,
        allowed: &[DomainEntry],
        denied: &[DomainEntry],
        listed: &[AddressRange],
    ) -> Self {
        Self {
            local: self.local,
            ..Self::new(allowed, denied, listed)
        }
    }

    /// The addresses of `resolved` that `hostname` may be dialed at on `port`,
    /// in the order given. When every one is dropped the answer is the
    /// refusal, and an empty answer is left for the caller to report.
    pub(super) fn vet(
        &self,
        hostname: &str,
        port: u16,
        resolved: &[IpAddr],
    ) -> Result<Vec<IpAddr>, Refusal> {
        let local = RuleSet::from_ranges(
            (self.local)()
                .into_iter()
                .map(|address| (AddressRange::host(address), None)),
        );
        let mut kept = Vec::new();
        let mut classes = Vec::new();
        for &address in resolved {
            match self.denial(hostname, address, port, &local) {
                None => kept.push(address),
                Some(class) => classes.push(class),
            }
        }
        if kept.is_empty() && !classes.is_empty() {
            classes.sort_unstable();
            classes.dedup();
            return Err(Refusal {
                hostname: hostname.to_owned(),
                classes,
            });
        }
        Ok(kept)
    }

    /// Why `hostname:port` may not use `address`, or `None` if it may. Every
    /// refusal also binds the IPv4 address an IPv6 address carries (NAT64 and
    /// the like), but a grant never does: `::1` must not ride a carve-out for its
    /// IPv4-compatible form.
    fn denial(
        &self,
        hostname: &str,
        address: IpAddr,
        port: u16,
        local: &RuleSet,
    ) -> Option<DenialReason> {
        if hostname.parse::<IpAddr>().is_ok() {
            return None;
        }
        if self.refused.contains_or_carried(address, port) {
            return Some(DenialReason::DenyListed);
        }
        if self.allowed.contains(address, port) {
            return None;
        }
        if is_loopback_name(hostname) {
            return (!is_loopback_address(address)).then_some(DenialReason::NonLoopback);
        }
        if let Some(class) = builtin_denial(address) {
            return Some(class);
        }
        if self.listed.contains_or_carried(address, port) {
            return Some(DenialReason::Listed);
        }
        local
            .contains_or_carried(address, port)
            .then_some(DenialReason::HostAddress)
    }
}

/// The entries that name an IP address, as the rules that let a name resolve to
/// it or refuse it.
fn literal_rules(entries: &[DomainEntry]) -> RuleSet {
    let entries: Vec<&str> = entries.iter().map(DomainEntry::as_str).collect();
    RuleSet::from_ranges(
        ip_literal_rules(&entries)
            .into_iter()
            .map(|rule| (AddressRange::host(rule.range), rule.port)),
    )
}

/// The unicast addresses assigned to this host's interfaces. Where they cannot
/// be listed the built-in classes still apply.
#[cfg(unix)]
fn interface_addresses() -> Vec<IpAddr> {
    let Ok(interfaces) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    interfaces
        .filter_map(|interface| {
            let address = interface.address?;
            match (address.as_sockaddr_in(), address.as_sockaddr_in6()) {
                (Some(v4), _) => Some(IpAddr::V4(v4.ip())),
                (_, Some(v6)) => Some(IpAddr::V6(v6.ip())),
                _ => None,
            }
        })
        .collect()
}

#[cfg(windows)]
use crate::win32::interface_addresses;

#[cfg(not(any(unix, windows)))]
fn interface_addresses() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a test address parses")
    }

    fn entries(
        entries: &[&str],
        parse: fn(&str) -> Result<DomainEntry, crate::domain::DomainParseError>,
    ) -> Vec<DomainEntry> {
        entries.iter().map(|entry| parse(entry).unwrap()).collect()
    }

    fn ranges(ranges: &[&str]) -> Vec<AddressRange> {
        ranges
            .iter()
            .map(|range| AddressRange::parse(range).unwrap())
            .collect()
    }

    /// A guard over this host having no addresses of its own.
    fn guard(allowed: &[&str], denied: &[&str], listed: &[&str]) -> Guard {
        Guard {
            local: Vec::new,
            ..Guard::new(
                &entries(allowed, DomainEntry::parse_allowed),
                &entries(denied, DomainEntry::parse_denied),
                &ranges(listed),
            )
        }
    }

    fn refusal(guard: &Guard, hostname: &str, port: u16, resolved: &[&str]) -> String {
        let resolved: Vec<IpAddr> = resolved.iter().map(|address| ip(address)).collect();
        guard
            .vet(hostname, port, &resolved)
            .expect_err("the name is refused")
            .reason()
    }

    #[test]
    fn a_name_that_resolves_to_loopback_is_refused() {
        let guard = guard(&["example.com"], &[], &[]);

        for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"] {
            assert_eq!(
                refusal(&guard, "example.com", 443, &[address]),
                "resolved to a loopback address",
                "{address}"
            );
        }
    }

    #[test]
    fn a_listed_cidr_is_refused() {
        let guard = guard(&["example.com"], &[], &["10.0.0.0/8", "fc00::/7"]);

        for address in ["10.1.2.3", "::ffff:10.1.2.3", "fd00::1", "64:ff9b::a01:203"] {
            assert_eq!(
                refusal(&guard, "example.com", 443, &[address]),
                "resolved to a listed address",
                "{address}"
            );
        }
        assert_eq!(
            guard.vet("example.com", 443, &[ip("203.0.113.7")]),
            Ok(vec![ip("203.0.113.7")])
        );
    }

    #[test]
    fn an_allowed_ip_literal_may_be_a_resolution() {
        let guard = guard(
            &["example.com", "127.0.0.1:8443", "10.0.0.0"],
            &[],
            &["10.0.0.0/8"],
        );

        assert_eq!(
            guard.vet("example.com", 8443, &[ip("127.0.0.1")]),
            Ok(vec![ip("127.0.0.1")])
        );
        assert_eq!(
            guard.vet("example.com", 443, &[ip("10.0.0.0")]),
            Ok(vec![ip("10.0.0.0")])
        );
        assert_eq!(
            refusal(&guard, "example.com", 443, &["127.0.0.1"]),
            "resolved to a loopback address"
        );
        assert_eq!(
            refusal(&guard, "example.com", 443, &["10.0.0.9"]),
            "resolved to a listed address"
        );
    }

    #[test]
    fn the_reason_names_the_class_not_the_address() {
        let guard = guard(&["example.com"], &[], &["10.0.0.0/8"]);
        let resolved = [ip("127.0.0.1"), ip("10.9.8.7")];

        let refusal = guard.vet("example.com", 443, &resolved).unwrap_err();

        assert_eq!(
            refusal.reason(),
            "resolved to a loopback address / a listed address"
        );
        assert_eq!(
            refusal.message(),
            "Connection to example.com blocked: resolved to a loopback address / a listed address"
        );
        for text in [refusal.reason(), refusal.message()] {
            assert!(!text.contains("127.0.0.1") && !text.contains("10.9.8.7"));
        }
    }

    #[test]
    fn an_address_that_passes_is_dialed_and_one_that_fails_is_dropped() {
        let guard = guard(&["example.com"], &[], &[]);

        assert_eq!(
            guard.vet(
                "example.com",
                443,
                &[ip("127.0.0.1"), ip("203.0.113.7"), ip("169.254.169.254")]
            ),
            Ok(vec![ip("203.0.113.7")])
        );
        assert_eq!(guard.vet("example.com", 443, &[]), Ok(vec![]));
    }

    #[test]
    fn an_ip_literal_is_never_judged() {
        let guard = guard(&[], &["127.0.0.1"], &["127.0.0.0/8"]);

        assert_eq!(
            guard.vet("127.0.0.1", 443, &[ip("127.0.0.1")]),
            Ok(vec![ip("127.0.0.1")])
        );
    }

    #[test]
    fn a_denied_literal_is_refused_by_name_beyond_an_allowed_one() {
        let guard = guard(&["example.com", "203.0.113.7"], &["203.0.113.7"], &[]);

        assert_eq!(
            refusal(&guard, "example.com", 443, &["203.0.113.7"]),
            "resolved to a deny-listed address"
        );
    }

    #[test]
    fn localhost_names_resolve_to_loopback_and_nothing_else() {
        let guard = guard(&["localhost", "app.localhost", "203.0.113.7"], &[], &[]);

        assert_eq!(
            guard.vet("localhost", 80, &[ip("::1"), ip("127.0.0.1")]),
            Ok(vec![ip("::1"), ip("127.0.0.1")])
        );
        assert_eq!(
            guard.vet("app.localhost", 80, &[ip("::ffff:127.0.0.1")]),
            Ok(vec![ip("::ffff:127.0.0.1")])
        );
        assert_eq!(
            refusal(&guard, "localhost", 80, &["198.51.100.9"]),
            "resolved to a non-loopback address"
        );
        assert_eq!(
            guard.vet("localhost", 80, &[ip("203.0.113.7")]),
            Ok(vec![ip("203.0.113.7")])
        );
    }

    #[test]
    fn this_hosts_own_addresses_are_refused() {
        let guard = Guard {
            local: || {
                vec![
                    "192.168.1.5".parse().unwrap(),
                    "2001:db8::5".parse().unwrap(),
                ]
            },
            ..guard(&["example.com"], &[], &[])
        };

        for address in ["192.168.1.5", "::ffff:192.168.1.5", "2001:db8::5"] {
            assert_eq!(
                refusal(&guard, "example.com", 443, &[address]),
                "resolved to one of this host's addresses",
                "{address}"
            );
        }
        assert_eq!(
            guard.vet("example.com", 443, &[ip("192.168.1.6")]),
            Ok(vec![ip("192.168.1.6")])
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_interfaces_of_this_host_include_loopback() {
        assert!(interface_addresses().contains(&ip("127.0.0.1")));
    }

    #[test]
    fn a_replaced_guard_judges_by_the_new_lists_and_keeps_its_local_function() {
        let guard = Guard {
            local: || vec!["192.168.1.5".parse().unwrap()],
            ..guard(&[], &[], &[])
        };

        let replaced = guard.replaced(
            &entries(&["example.com"], DomainEntry::parse_allowed),
            &[],
            &ranges(&["203.0.113.0/24"]),
        );

        assert_eq!(
            refusal(&replaced, "example.com", 443, &["203.0.113.9"]),
            "resolved to a listed address"
        );
        assert_eq!(
            refusal(&replaced, "example.com", 443, &["192.168.1.5"]),
            "resolved to one of this host's addresses"
        );
    }
}
