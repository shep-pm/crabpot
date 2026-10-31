//! The kelpie keys: one module for each, registered by one line below.
//!
//! A module holds what reads and checks its key's value, and, until the key is
//! honoured, its `PATH`, the dotted path `unsupported` refuses it by. Upstream's
//! other keys are fields of `Config` or are dropped; they have no module.

pub(crate) mod allow_local_binding;
pub(crate) mod allow_mach_lookup;
pub(crate) mod allow_read;
pub(crate) mod allow_tcp;
pub(crate) mod allow_unix_sockets;
pub(crate) mod allow_write;
pub(crate) mod allowed_domains;
pub(crate) mod denied_domains;
pub(crate) mod denied_resolved_addresses;
pub(crate) mod deny_mach_lookup;
pub(crate) mod deny_read;
pub(crate) mod deny_write;
pub(crate) mod enable_weaker_network_isolation;
pub(crate) mod mitm_proxy;
pub(crate) mod publish;
pub(crate) mod strict_allowlist;
pub(crate) mod windows;
