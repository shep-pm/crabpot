//! The JSON Schema of the settings document, behind the `schema` feature.
//!
//! The deserializers read most values as strings and parse them, which a
//! derive cannot see, so the shapes are written out here. A `pattern` is an
//! approximation of the parser, which stays the authority: it also refuses
//! what a regular expression cannot say, such as a port above 65535.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

use super::{Config, Filesystem, Network};

/// A TCP port written without a leading zero.
const PORT: &str = "[1-9][0-9]{0,4}";
/// A host with at least one dot and no empty first or last label.
const DOTTED: &str = r"[^*:/.][^*:/]*\.[^*:/]*[^*:/.]";
const BRACKETED_IPV6: &str = r"\[[0-9A-Fa-f:.]+(%[0-9A-Za-z.:-]+)?\]";
const BARE_IPV6: &str = r"[0-9A-Fa-f.]*:[0-9A-Fa-f:.]+(%[0-9A-Za-z.:-]+)?";

/// The settings `-s` reads, as [`Config::from_json`] accepts them.
///
/// A key `from_json` does not know is allowed, since it drops it. The
/// refusals that depend on the platform, kept in `config/unsupported.rs`, are
/// not in the schema: a document that passes it can still be refused.
impl JsonSchema for Config {
    fn schema_name() -> Cow<'static, str> {
        "Config".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "properties": {
                "network": generator.subschema_for::<Network>(),
                "filesystem": generator.subschema_for::<Filesystem>(),
                "enableWeakerNetworkIsolation": {"type": "boolean"},
                "windows": windows(),
                "git": generator.subschema_for::<super::Git>()
            },
            "required": ["network", "filesystem"]
        })
    }
}

impl JsonSchema for Network {
    fn schema_name() -> Cow<'static, str> {
        "Network".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "description": "What a command may reach.",
            "properties": {
                "allowedDomains": list(domain_entry(false)),
                "deniedDomains": list(domain_entry(true)),
                "strictAllowlist": {"type": "boolean"},
                "deniedResolvedAddresses": list(address_range()),
                "allowUnixSockets": list(json_schema!({"type": "string"})),
                "allowLocalBinding": {"type": "boolean"},
                "publish": list(socket_addr()),
                "allowTcp": list(tcp_destination()),
                "allowMachLookup": list(json_schema!({"type": "string"})),
                "denyMachLookup": list(json_schema!({"type": "string"})),
                "mitmProxy": mitm_proxy()
            },
            "required": ["allowedDomains", "deniedDomains"]
        })
    }
}

impl JsonSchema for Filesystem {
    fn schema_name() -> Cow<'static, str> {
        "Filesystem".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "description": "What a command may read and write.",
            "properties": {
                "denyRead": list(path_entry()),
                "allowRead": list(path_entry()),
                "allowWrite": list(path_entry()),
                "denyWrite": list(path_entry()),
                "allowGitConfig": {"type": "boolean"}
            },
            "required": ["denyRead", "allowWrite", "denyWrite"]
        })
    }
}

fn list(items: Schema) -> Schema {
    json_schema!({"type": "array", "items": items})
}

fn text(pattern: &str) -> Schema {
    json_schema!({"type": "string", "pattern": format!("^({pattern})$")})
}

/// `DomainEntry`: a host and an optional port. Only a denied entry may be `*`.
fn domain_entry(denied: bool) -> Schema {
    let wildcard = if denied { r"|\*" } else { "" };
    text(&format!(
        r"((\*\.)?{DOTTED}|localhost|{BRACKETED_IPV6}{wildcard})(:{PORT})?"
    ))
}

/// `DomainPattern`: a host alone.
fn domain_pattern() -> Schema {
    text(&format!(r"(\*\.)?{DOTTED}|localhost|{BARE_IPV6}"))
}

/// `AddressRange`: an IP literal or a CIDR range.
fn address_range() -> Schema {
    text(r"[0-9A-Fa-f:.]+(%[^/]*)?(/[0-9]{1,3})?")
}

/// `TcpDestination`: a DNS name or IP literal, and a port.
fn tcp_destination() -> Schema {
    text(&format!(
        r"(\[[0-9A-Fa-f:.%A-Za-z0-9]+\]|[0-9A-Za-z.-]+):{PORT}"
    ))
}

/// `SocketAddr`: an IP literal and a port.
fn socket_addr() -> Schema {
    text(&format!(r"([0-9.]+|\[[0-9A-Fa-f:.]+(%[0-9]+)?\]):{PORT}"))
}

/// `PathEntry`: a path, or a path marked literal.
fn path_entry() -> Schema {
    json_schema!({
        "oneOf": [
            {"type": "string", "minLength": 1},
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "literal": {"const": true}
                },
                "required": ["path", "literal"],
                "additionalProperties": false
            }
        ]
    })
}

/// `MitmProxy`: a socket and at least one domain routed through it.
fn mitm_proxy() -> Schema {
    json_schema!({
        "type": "object",
        "properties": {
            "socketPath": {"type": "string", "minLength": 1},
            "domains": {"type": "array", "items": domain_pattern(), "minItems": 1}
        },
        "required": ["socketPath", "domains"]
    })
}

/// `Windows`: `wfpSublayerGuid` is read when `sublayerGuid` is absent.
fn windows() -> Schema {
    let guid = text("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");
    json_schema!({
        "type": "object",
        "properties": {
            "sandboxUser": {"type": "string", "minLength": 1, "maxLength": 20},
            "sublayerGuid": guid,
            "wfpSublayerGuid": guid,
            "proxyPortRange": {
                "type": "array",
                "items": {"type": "integer", "minimum": 1, "maximum": 65535},
                "minItems": 2,
                "maxItems": 2,
                "description": "Inclusive loopback ports, low at most high, no more than 64 apart."
            }
        }
    })
}
