//! Which addresses a resolved name may not reach: the rules behind
//! `deniedResolvedAddresses`, over `std::net` types.
//!
//! This is upstream's `src/sandbox/address.ts` and the rule half of
//! `src/sandbox/resolved-address-guard.ts`. It resolves no names and dials
//! nothing. Matching follows Node's `BlockList`: an IPv4 rule also binds the
//! IPv4-mapped IPv6 spelling of an address, and an IPv6 rule sees an IPv4
//! address as its mapped form.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a range or rule was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddressError {
    /// The entry is not an IP literal, or its `/prefix` is not one to three
    /// digits within the family's width (32 or 128), or it is an IPv4-mapped
    /// IPv6 range with a prefix under 96. IPv6 must be unbracketed.
    InvalidRange {
        /// The entry as given.
        entry: String,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange { entry } => {
                write!(f, "invalid IP address or CIDR range: {entry:?}")
            }
        }
    }
}

impl core::error::Error for AddressError {}

/// An IP literal or CIDR range.
///
/// An IPv4-mapped IPv6 range is stored as the IPv4 range it stands for
/// (`::ffff:10.0.0.0/104` is `10.0.0.0/8`), so the two spellings are one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressRange {
    network: IpAddr,
    prefix: u8,
}

impl AddressRange {
    const fn v4(octets: [u8; 4], prefix: u8) -> Self {
        let [a, b, c, d] = octets;
        Self {
            network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix,
        }
    }

    const fn v6(segments: [u16; 8], prefix: u8) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        Self {
            network: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
            prefix,
        }
    }

    /// Parses `10.0.0.0/8`, `fc00::/7` or a bare address (a host range). A
    /// zone id (`fe80::1%en0`) is dropped.
    ///
    /// # Errors
    ///
    /// [`AddressError::InvalidRange`] under the condition on that variant.
    pub(crate) fn parse(entry: &str) -> Result<Self, AddressError> {
        let invalid = || AddressError::InvalidRange {
            entry: entry.to_owned(),
        };
        let (host, raw_prefix) = match entry.split_once('/') {
            Some((host, raw)) => (host, Some(raw)),
            None => (entry, None),
        };
        let network = parse_address(host).ok_or_else(invalid)?;
        let width = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match raw_prefix {
            None => width,
            Some(raw) => {
                let digits =
                    (1..=3).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit());
                digits
                    .then(|| raw.parse::<u8>().ok())
                    .flatten()
                    .filter(|&prefix| prefix <= width)
                    .ok_or_else(invalid)?
            }
        };
        if let IpAddr::V6(v6) = network
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            let prefix = prefix.checked_sub(96).ok_or_else(invalid)?;
            return Ok(Self {
                network: IpAddr::V4(v4),
                prefix,
            });
        }
        Ok(Self { network, prefix })
    }

    /// Whether `address` is in the range.
    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        let prefix = u32::from(self.prefix);
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => same_prefix_v4(network, address, prefix),
            (IpAddr::V4(network), IpAddr::V6(address)) => address
                .to_ipv4_mapped()
                .is_some_and(|address| same_prefix_v4(network, address, prefix)),
            (IpAddr::V6(network), IpAddr::V6(address)) => same_prefix_v6(network, address, prefix),
            (IpAddr::V6(network), IpAddr::V4(address)) => {
                same_prefix_v6(network, address.to_ipv6_mapped(), prefix)
            }
        }
    }
}

fn same_prefix_v4(network: Ipv4Addr, address: Ipv4Addr, prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(network) & mask == u32::from(address) & mask
}

fn same_prefix_v6(network: Ipv6Addr, address: Ipv6Addr, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    u128::from(network) & mask == u128::from(address) & mask
}

/// An address literal with an IPv6 zone id (`fe80::1%en0`) dropped, since a
/// zoned address is a non-match on some runtimes.
fn parse_address(text: &str) -> Option<IpAddr> {
    let unzoned = text.split_once('%').map_or(text, |(address, _)| address);
    unzoned.parse().ok()
}

/// The IPv4 address an IPv6 address carries in one of the forms a network
/// delivers to that IPv4 destination: IPv4-mapped and IPv4-compatible
/// (`::ffff:0:0/96`, `::/96`), IPv4-translated (`::ffff:0:0:0/96`), the NAT64
/// well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`).
///
/// `None` for anything else, including the local-use NAT64 prefix
/// `64:ff9b:1::/48` and network-specific prefixes, whose embedded IPv4 could
/// be anywhere (RFC 6052 §2.2).
pub(crate) fn embedded_ipv4(address: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(address) = address else {
        return None;
    };
    let g = address.segments();
    let zero = |from: usize, to: usize| g[from..to].iter().all(|&group| group == 0);
    if g[0] == 0x2002 {
        return Some(quad(g[1], g[2]));
    }
    let nat64 = g[0] == 0x64 && g[1] == 0xff9b && zero(2, 6);
    let compatible_or_mapped = zero(0, 5) && (g[5] == 0 || g[5] == 0xffff);
    let translated = zero(0, 4) && g[4] == 0xffff && g[5] == 0;
    (nat64 || compatible_or_mapped || translated).then(|| quad(g[6], g[7]))
}

fn quad(high: u16, low: u16) -> Ipv4Addr {
    let [a, b] = high.to_be_bytes();
    let [c, d] = low.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// Whether `matches` holds for `address` or for the IPv4 address it carries.
/// The carried form only adds matches, so a rule that grants must not use it.
fn matches_or_carries(address: IpAddr, matches: impl Fn(IpAddr) -> bool) -> bool {
    matches(address) || embedded_ipv4(address).is_some_and(|carried| matches(IpAddr::V4(carried)))
}

/// Loopback in both families.
const LOOPBACK_RANGES: [AddressRange; 2] = [
    AddressRange::v4([127, 0, 0, 0], 8),
    AddressRange::v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
];

/// True for an IPv4 or IPv6 loopback address, including IPv4-mapped forms.
pub(crate) fn is_loopback_address(address: IpAddr) -> bool {
    LOOPBACK_RANGES.iter().any(|range| range.contains(address))
}

/// `localhost` and names under `.localhost` (RFC 6761 §6.3).
pub(crate) fn is_loopback_name(hostname: &str) -> bool {
    let lowered = hostname.to_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    name == "localhost" || name.ends_with(".localhost")
}

/// An IP literal or CIDR range, optionally restricted to one destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressRule<'a> {
    range: &'a str,
    port: Option<u16>,
}

impl<'a> AddressRule<'a> {
    /// A rule for `range` on every port.
    pub(crate) const fn any_port(range: &'a str) -> Self {
        Self { range, port: None }
    }

    /// A rule for `range` on `port` only.
    pub(crate) const fn on_port(range: &'a str, port: u16) -> Self {
        Self {
            range,
            port: Some(port),
        }
    }
}

/// Parsed [`AddressRule`]s, matched by address and destination port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleSet {
    rules: Vec<(AddressRange, Option<u16>)>,
}

impl RuleSet {
    /// Parses every rule.
    ///
    /// # Errors
    ///
    /// [`AddressError::InvalidRange`] for the first rule whose range is invalid.
    pub(crate) fn new<'a>(
        rules: impl IntoIterator<Item = AddressRule<'a>>,
    ) -> Result<Self, AddressError> {
        let rules = rules
            .into_iter()
            .map(|rule| Ok((AddressRange::parse(rule.range)?, rule.port)))
            .collect::<Result<_, _>>()?;
        Ok(Self { rules })
    }

    /// Whether a rule for `port`, or for every port, covers `address`.
    pub(crate) fn contains(&self, address: IpAddr, port: u16) -> bool {
        self.rules.iter().any(|(range, scoped)| {
            scoped.is_none_or(|scoped| scoped == port) && range.contains(address)
        })
    }

    /// [`contains`](Self::contains), or an IPv4 rule covering the address an
    /// IPv6 `address` carries (see [`embedded_ipv4`]). This is the test for a
    /// rule that denies.
    pub(crate) fn contains_or_carried(&self, address: IpAddr, port: u16) -> bool {
        matches_or_carries(address, |address| self.contains(address, port))
    }
}

/// What a refusal reports. The variants run in upstream's `REASON_ORDER`, so
/// sorting a set of them gives the order a multi-address reason reads in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DenialReason {
    /// The name's own deny list holds the address.
    DenyListed,
    /// Loopback.
    Loopback,
    /// Unspecified, which connects to the local host on common stacks.
    Unspecified,
    /// Link-local, including most instance-metadata endpoints.
    LinkLocal,
    /// Multicast.
    Multicast,
    /// The IPv4 broadcast address.
    Broadcast,
    /// A cloud instance-metadata endpoint outside link-local space.
    CloudMetadata,
    /// `deniedResolvedAddresses` holds the address.
    Listed,
    /// An address assigned to one of this host's interfaces.
    HostAddress,
    /// A `localhost` name resolved to something other than loopback.
    NonLoopback,
    /// The resolver returned something that is not an IP address.
    Unparsable,
}

impl DenialReason {
    /// The phrase after `resolved to` in a refusal, which `ignoreViolations`
    /// matches by substring.
    pub(crate) const fn phrase(self) -> &'static str {
        match self {
            Self::DenyListed => "a deny-listed address",
            Self::Loopback => "a loopback address",
            Self::Unspecified => "an unspecified address",
            Self::LinkLocal => "a link-local address",
            Self::Multicast => "a multicast address",
            Self::Broadcast => "the broadcast address",
            Self::CloudMetadata => "a cloud metadata address",
            Self::Listed => "a listed address",
            Self::HostAddress => "one of this host's addresses",
            Self::NonLoopback => "a non-loopback address",
            Self::Unparsable => "an unparsable address",
        }
    }
}

/// Cloud instance-metadata endpoints outside link-local space, so
/// `169.254.0.0/16` and `fe80::/10` do not cover them. Single addresses (or a
/// provider-reserved block), so nothing else is caught.
const CLOUD_METADATA_RANGES: [AddressRange; 9] = [
    AddressRange::v4([100, 100, 100, 200], 32), // Alibaba Cloud
    AddressRange::v4([168, 63, 129, 16], 32),   // Azure WireServer / host agent endpoint
    AddressRange::v4([192, 0, 0, 192], 32),     // Oracle Cloud Infrastructure Classic
    AddressRange::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0], 32), // AWS IPv6 service block
    AddressRange::v6([0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254], 128), // Google Cloud, IPv6-only
    AddressRange::v6([0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe], 128), // Oracle Cloud IPv6
    AddressRange::v6([0xfd00, 0x0042, 0, 0, 0, 0, 0, 0x0042], 128), // Scaleway IPv6
    AddressRange::v6([0xfd00, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 1], 128), // Akamai / Linode IPv6
    AddressRange::v6([0xfd00, 0x0100, 0, 0, 0, 0, 0x0100, 0x0200], 128), // Alibaba Cloud IPv6
];

/// Destinations an allow-listed hostname may not resolve to, by the reason a
/// refusal reports, in priority order. Private-use ranges (RFC 1918, ULA,
/// CGNAT) are absent on purpose: allow-listing an intranet hostname is
/// legitimate, so those are opt-in through `deniedResolvedAddresses`.
const DENIED_CLASSES: [(DenialReason, &[AddressRange]); 6] = [
    (DenialReason::Loopback, &LOOPBACK_RANGES),
    (
        DenialReason::Unspecified,
        &[
            AddressRange::v4([0, 0, 0, 0], 8),
            AddressRange::v6([0; 8], 128),
        ],
    ),
    (
        DenialReason::LinkLocal,
        &[
            AddressRange::v4([169, 254, 0, 0], 16),
            AddressRange::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
        ],
    ),
    (
        DenialReason::Multicast,
        &[
            AddressRange::v4([224, 0, 0, 0], 4),
            AddressRange::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
        ],
    ),
    (
        DenialReason::Broadcast,
        &[AddressRange::v4([255, 255, 255, 255], 32)],
    ),
    (DenialReason::CloudMetadata, &CLOUD_METADATA_RANGES),
];

/// The first built-in class that refuses `address`, or `None`. IPv4 rules also
/// bind the IPv6 forms that carry an IPv4 address (see [`embedded_ipv4`]).
pub(crate) fn builtin_denial(address: IpAddr) -> Option<DenialReason> {
    DENIED_CLASSES
        .iter()
        .find(|(_, ranges)| {
            matches_or_carries(address, |address| {
                ranges.iter().any(|range| range.contains(address))
            })
        })
        .map(|&(reason, _)| reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a test address parses")
    }

    /// Each row is an address and the class upstream refuses it as against the
    /// built-in classes alone, with no listed rules and no local addresses.
    /// Generated by bundling `src/sandbox/resolved-address-guard.ts` from
    /// `@anthropic-ai/sandbox-runtime` 0.0.81 with `bun build --target node`,
    /// then running it under Node 26 (whose `BlockList` it uses): per address,
    /// `createResolvedAddressGuard({ localAddresses: () => [], resolve })`,
    /// `lookupFor(443)('example.com', ...)`, and the refusal's `reason`.
    const UPSTREAM_VERDICTS: &[(&str, Option<DenialReason>)] = &[
        ("127.0.0.0", Some(DenialReason::Loopback)),
        ("127.0.0.1", Some(DenialReason::Loopback)),
        ("127.255.255.255", Some(DenialReason::Loopback)),
        ("126.255.255.255", None),
        ("128.0.0.0", None),
        ("::1", Some(DenialReason::Loopback)),
        ("0:0:0:0:0:0:0:1", Some(DenialReason::Loopback)),
        ("::2", Some(DenialReason::Unspecified)),
        ("::ffff:127.0.0.1", Some(DenialReason::Loopback)),
        ("::ffff:7f00:1", Some(DenialReason::Loopback)),
        ("::ffff:7f00:2", Some(DenialReason::Loopback)),
        ("0.0.0.0", Some(DenialReason::Unspecified)),
        ("0.255.255.255", Some(DenialReason::Unspecified)),
        ("1.0.0.0", None),
        ("::", Some(DenialReason::Unspecified)),
        ("::ffff:0.0.0.1", Some(DenialReason::Unspecified)),
        ("::ffff:0:1", Some(DenialReason::Unspecified)),
        ("169.254.0.0", Some(DenialReason::LinkLocal)),
        ("169.254.169.254", Some(DenialReason::LinkLocal)),
        ("169.254.255.255", Some(DenialReason::LinkLocal)),
        ("169.253.255.255", None),
        ("169.255.0.0", None),
        ("fe80::", Some(DenialReason::LinkLocal)),
        ("fe80::1", Some(DenialReason::LinkLocal)),
        (
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(DenialReason::LinkLocal),
        ),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
        ("fec0::", None),
        ("224.0.0.0", Some(DenialReason::Multicast)),
        ("239.255.255.255", Some(DenialReason::Multicast)),
        ("223.255.255.255", None),
        ("240.0.0.0", None),
        ("ff00::", Some(DenialReason::Multicast)),
        ("ff02::1", Some(DenialReason::Multicast)),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(DenialReason::Multicast),
        ),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
        ("::ffff:224.0.0.1", Some(DenialReason::Multicast)),
        ("255.255.255.255", Some(DenialReason::Broadcast)),
        ("255.255.255.254", None),
        ("::ffff:255.255.255.255", Some(DenialReason::Broadcast)),
        ("100.100.100.200", Some(DenialReason::CloudMetadata)),
        ("100.100.100.199", None),
        ("100.100.100.201", None),
        ("168.63.129.16", Some(DenialReason::CloudMetadata)),
        ("168.63.129.15", None),
        ("168.63.129.17", None),
        ("192.0.0.192", Some(DenialReason::CloudMetadata)),
        ("192.0.0.191", None),
        ("192.0.0.193", None),
        ("fd00:ec2::", Some(DenialReason::CloudMetadata)),
        ("fd00:ec2::254", Some(DenialReason::CloudMetadata)),
        (
            "fd00:ec2:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(DenialReason::CloudMetadata),
        ),
        ("fd00:ec3::", None),
        ("fd00:ec1:ffff:ffff:ffff:ffff:ffff:ffff", None),
        ("fd20:ce::254", Some(DenialReason::CloudMetadata)),
        ("fd20:ce::253", None),
        ("fd20:ce::255", None),
        ("fd00:c1::a9fe:a9fe", Some(DenialReason::CloudMetadata)),
        ("fd00:c1::a9fe:a9ff", None),
        ("fd00:42::42", Some(DenialReason::CloudMetadata)),
        ("fd00:42::43", None),
        ("fd00:a9fe:a9fe::1", Some(DenialReason::CloudMetadata)),
        ("fd00:a9fe:a9fe::2", None),
        ("fd00:100::100:200", Some(DenialReason::CloudMetadata)),
        ("fd00:100::100:201", None),
        ("8.8.8.8", None),
        ("1.1.1.1", None),
        ("10.0.0.1", None),
        ("192.168.1.1", None),
        ("172.16.0.1", None),
        ("100.64.0.1", None),
        ("fc00::1", None),
        ("2001:4860:4860::8888", None),
        ("::ffff:8.8.8.8", None),
        ("::ffff:169.254.169.254", Some(DenialReason::LinkLocal)),
        ("::ffff:100.100.100.200", Some(DenialReason::CloudMetadata)),
        ("64:ff9b::a9fe:a9fe", Some(DenialReason::LinkLocal)),
        ("64:ff9b::7f00:1", Some(DenialReason::Loopback)),
        ("64:ff9b::808:808", None),
        ("64:ff9b::6464:64c8", Some(DenialReason::CloudMetadata)),
        ("64:ff9b:1::7f00:1", None),
        ("64:ff9b::1:7f00:1", None),
        ("2002:7f00:1::1", Some(DenialReason::Loopback)),
        ("2002:a9fe:a9fe::1", Some(DenialReason::LinkLocal)),
        ("2002:808:808::1", None),
        ("2002:6464:64c8::", Some(DenialReason::CloudMetadata)),
        ("::ffff:0:7f00:1", Some(DenialReason::Loopback)),
        ("::ffff:0:808:808", None),
        ("::7f00:1", Some(DenialReason::Loopback)),
        ("::a9fe:a9fe", Some(DenialReason::LinkLocal)),
        ("::808:808", None),
        ("::ffff:0:6464:64c8", Some(DenialReason::CloudMetadata)),
    ];

    #[test]
    fn every_table_address_gets_upstreams_verdict() {
        for (text, expected) in UPSTREAM_VERDICTS {
            assert_eq!(builtin_denial(ip(text)), *expected, "{text}");
        }
    }

    #[test]
    fn an_ipv4_mapped_loopback_is_loopback() {
        assert!(is_loopback_address(ip("::ffff:127.0.0.1")));
        assert!(is_loopback_address(ip("::ffff:7f00:1")));
        assert!(is_loopback_address(ip("127.0.0.1")));
        assert!(is_loopback_address(ip("::1")));
        assert!(!is_loopback_address(ip("::ffff:8.8.8.8")));
        assert!(!is_loopback_address(ip("::")));
    }

    #[test]
    fn a_port_scoped_rule_does_not_match_another_port() {
        let rules = RuleSet::new([
            AddressRule::any_port("10.0.0.0/8"),
            AddressRule::on_port("192.168.0.0/16", 8080),
        ])
        .expect("the rules are valid");
        assert!(rules.contains(ip("10.1.2.3"), 443));
        assert!(rules.contains(ip("192.168.1.1"), 8080));
        assert!(!rules.contains(ip("192.168.1.1"), 443));
        assert!(!rules.contains(ip("172.16.0.1"), 8080));
        assert!(rules.contains(ip("::ffff:192.168.1.1"), 8080));
        assert!(!rules.contains(ip("::ffff:192.168.1.1"), 80));
    }

    #[test]
    fn an_invalid_cidr_is_refused_with_upstreams_condition() {
        for entry in [
            "10.0.0.0/33",
            "fc00::/129",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "10.0.0.0/1000",
            "10.0.0.0/8/8",
            "[::1]",
            "[fc00::]/7",
            "::ffff:10.0.0.0/95",
            "example.com",
            "",
        ] {
            assert_eq!(
                AddressRange::parse(entry),
                Err(AddressError::InvalidRange {
                    entry: entry.to_owned()
                }),
                "{entry:?}"
            );
        }
        assert_eq!(
            RuleSet::new([AddressRule::any_port("[::1]")])
                .unwrap_err()
                .to_string(),
            r#"invalid IP address or CIDR range: "[::1]""#
        );
    }

    #[test]
    fn a_mapped_range_is_the_ipv4_range_it_stands_for() {
        let mapped = AddressRange::parse("::ffff:10.0.0.0/104").expect("a valid range");
        assert_eq!(
            mapped,
            AddressRange::parse("10.0.0.0/8").expect("a valid range")
        );
        assert!(mapped.contains(ip("10.9.9.9")));
        assert!(mapped.contains(ip("::ffff:10.9.9.9")));
        assert!(!mapped.contains(ip("11.0.0.0")));
    }

    #[test]
    fn a_zone_id_is_dropped_from_a_range() {
        let zoned = AddressRange::parse("fe80::1%en0").expect("a valid range");
        assert!(zoned.contains(ip("fe80::1")));
        assert!(!zoned.contains(ip("fe80::2")));
    }

    #[test]
    fn an_ipv6_rule_sees_an_ipv4_address_as_its_mapped_form() {
        // Node's `BlockList` says the same for `::/80` and `::/96`.
        let wide = AddressRange::parse("::/80").expect("a valid range");
        let narrow = AddressRange::parse("::/96").expect("a valid range");
        assert!(wide.contains(ip("1.2.3.4")));
        assert!(!narrow.contains(ip("1.2.3.4")));
    }

    #[test]
    fn a_carried_ipv4_address_is_denied_but_never_granted() {
        let rules = RuleSet::new([AddressRule::any_port("10.0.0.0/8")]).expect("a valid rule");
        assert!(rules.contains_or_carried(ip("64:ff9b::a00:1"), 443));
        assert!(rules.contains_or_carried(ip("2002:a00:1::"), 443));
        assert!(!rules.contains(ip("64:ff9b::a00:1"), 443));
        assert!(!rules.contains_or_carried(ip("64:ff9b:1::a00:1"), 443));
    }

    #[test]
    fn localhost_and_names_under_it_are_loopback_names() {
        for name in ["localhost", "LOCALHOST.", "app.localhost", "a.b.Localhost."] {
            assert!(is_loopback_name(name), "{name}");
        }
        for name in ["localhost.example.com", "notlocalhost", "example.com", ""] {
            assert!(!is_loopback_name(name), "{name}");
        }
    }

    #[test]
    fn reasons_sort_in_upstreams_order() {
        let mut reasons = [
            DenialReason::Unparsable,
            DenialReason::NonLoopback,
            DenialReason::HostAddress,
            DenialReason::Listed,
            DenialReason::CloudMetadata,
            DenialReason::Broadcast,
            DenialReason::Multicast,
            DenialReason::LinkLocal,
            DenialReason::Unspecified,
            DenialReason::Loopback,
            DenialReason::DenyListed,
        ];
        reasons.sort();
        assert_eq!(
            reasons.map(DenialReason::phrase),
            [
                "a deny-listed address",
                "a loopback address",
                "an unspecified address",
                "a link-local address",
                "a multicast address",
                "the broadcast address",
                "a cloud metadata address",
                "a listed address",
                "one of this host's addresses",
                "a non-loopback address",
                "an unparsable address",
            ]
        );
    }
}
