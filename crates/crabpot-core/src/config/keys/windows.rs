//! `windows`: the install a Windows session runs against, as upstream's
//! `WindowsConfigSchema` writes it. `srtWin`, which locates the helper binary,
//! is dropped, since crabpot's own binary is the helper.

use serde::{Deserialize, Deserializer};

use super::super::leaf::{non_empty, parsed};

/// The Windows install a session expects. Every setting is left to srt-win's
/// default when it is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "Written")]
#[non_exhaustive]
pub struct Windows {
    /// `sandboxUser`: the name of the sandbox account the install created.
    pub sandbox_user: Option<String>,
    /// `sublayerGuid`, or its alias `wfpSublayerGuid` when that is the only one
    /// set: the WFP sublayer the filters were installed under.
    pub sublayer_guid: Option<String>,
    /// `proxyPortRange`: the inclusive loopback ports the proxy listens in,
    /// which are the ones the install's firewall rule permits.
    pub proxy_port_range: Option<[u16; 2]>,
}

/// `windows` as written, with the alias beside the key it stands for.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Written {
    #[serde(default, deserialize_with = "sandbox_user")]
    sandbox_user: Option<String>,
    #[serde(default, deserialize_with = "guid")]
    sublayer_guid: Option<String>,
    #[serde(default, deserialize_with = "guid")]
    wfp_sublayer_guid: Option<String>,
    #[serde(default, deserialize_with = "proxy_port_range")]
    proxy_port_range: Option<[u16; 2]>,
}

impl From<Written> for Windows {
    fn from(written: Written) -> Self {
        Self {
            sandbox_user: written.sandbox_user,
            sublayer_guid: written.sublayer_guid.or(written.wfp_sublayer_guid),
            proxy_port_range: written.proxy_port_range,
        }
    }
}

/// The longest local account name Windows allows.
const SANDBOX_USER_MAX: usize = 20;

fn sandbox_user<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let name = parsed(deserializer, non_empty)?;
    if name.chars().count() > SANDBOX_USER_MAX {
        return Err(serde::de::Error::custom(
            "Windows local usernames are limited to 20 characters",
        ));
    }
    Ok(Some(name))
}

/// Eight, four, four, four and twelve hex digits between dashes, which is what
/// zod's `uuid()` reads, whatever the version.
fn guid<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let text = String::deserialize(deserializer)?;
    let groups: Vec<&str> = text.split('-').collect();
    let shaped = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()));
    if shaped {
        Ok(Some(text))
    } else {
        Err(serde::de::Error::custom("invalid uuid"))
    }
}

fn proxy_port_range<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u16; 2]>, D::Error> {
    let (low, high) = <(u64, u64)>::deserialize(deserializer)?;
    let low = u16::try_from(low).ok().filter(|low| *low >= 1);
    let high = u16::try_from(high).ok();
    match (low, high) {
        (Some(low), Some(high)) if low <= high && high - low <= 64 => Ok(Some([low, high])),
        (Some(_), Some(_)) => Err(serde::de::Error::custom(
            "low must be ≤ high and range width ≤ 64",
        )),
        _ => Err(serde::de::Error::custom(
            "ports must be between 1 and 65535",
        )),
    }
}
