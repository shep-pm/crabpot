//! The `windows` group, which upstream's schema reads on every platform and
//! applies on Windows.

use serde_json::json;

use super::*;

#[test]
fn the_windows_keys_are_read_into_the_config() {
    let config = Config::from_json(&with(
        "windows",
        json!({
            "sandboxUser": "ci-sandbox",
            "sublayerGuid": "0f4b1c2d-0000-4000-8000-000000000001",
            "proxyPortRange": [61000, 61009]
        }),
    ))
    .unwrap();

    assert_eq!(config.windows.sandbox_user.as_deref(), Some("ci-sandbox"));
    assert_eq!(
        config.windows.sublayer_guid.as_deref(),
        Some("0f4b1c2d-0000-4000-8000-000000000001")
    );
    assert_eq!(config.windows.proxy_port_range, Some([61000, 61009]));
}

#[test]
fn the_sublayer_alias_is_read_when_the_canonical_key_is_absent() {
    let alias = "0f4b1c2d-0000-4000-8000-000000000002";
    let canonical = "0f4b1c2d-0000-4000-8000-000000000003";

    let alone = Config::from_json(&with("windows", json!({"wfpSublayerGuid": alias}))).unwrap();
    let both = Config::from_json(&with(
        "windows",
        json!({"wfpSublayerGuid": alias, "sublayerGuid": canonical}),
    ))
    .unwrap();

    assert_eq!(alone.windows.sublayer_guid.as_deref(), Some(alias));
    assert_eq!(both.windows.sublayer_guid.as_deref(), Some(canonical));
}

#[test]
fn a_config_without_windows_has_no_windows_settings() {
    assert_eq!(Config::default().windows, Windows::default());
    assert_eq!(
        Config::from_json(&with("windows", json!({}))),
        Ok(Config::default())
    );
}

#[test]
fn a_windows_key_that_upstreams_schema_refuses_is_invalid() {
    for (path, value) in [
        ("windows.sandboxUser", json!("")),
        ("windows.sandboxUser", json!("a-name-over-twenty-one")),
        ("windows.sandboxUser", json!(5)),
        ("windows.sublayerGuid", json!("not-a-guid")),
        (
            "windows.sublayerGuid",
            json!("{0f4b1c2d-0000-4000-8000-000000000001}"),
        ),
        ("windows.wfpSublayerGuid", json!("not-a-guid")),
        ("windows.proxyPortRange", json!([0, 5])),
        ("windows.proxyPortRange", json!([1, 65536])),
        ("windows.proxyPortRange", json!([9, 8])),
        ("windows.proxyPortRange", json!([1, 66])),
        ("windows.proxyPortRange", json!([5])),
        ("windows.proxyPortRange", json!("60080-60089")),
    ] {
        assert_eq!(
            invalid_key(&with(path, value.clone())),
            path,
            "{path}: {value}"
        );
    }
}

#[test]
fn a_range_of_sixty_five_ports_is_read_as_upstream_reads_it() {
    let config = Config::from_json(&with("windows.proxyPortRange", json!([1, 65]))).unwrap();

    assert_eq!(config.windows.proxy_port_range, Some([1, 65]));
}

#[test]
fn a_windows_group_that_is_not_an_object_is_invalid() {
    assert_eq!(invalid_key(&with("windows", json!(["srt"]))), "windows");
}

#[test]
fn the_srt_win_location_is_accepted_and_ignored() {
    let loaded = Config::from_json(&with("windows.srtWin", json!({"path": "C:\\srt-win.exe"})));

    assert_eq!(loaded, Ok(Config::default()));
}
