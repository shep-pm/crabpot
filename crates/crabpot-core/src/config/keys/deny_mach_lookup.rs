//! `network.denyMachLookup`: Mach service names a command may not look up,
//! such as the keychain's. A key of crabpot's own (ADR-0003, ADR-0011), so
//! upstream's schema says nothing about it.

pub(crate) const PATH: &str = "network.denyMachLookup";
