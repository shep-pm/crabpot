//! The generated schema and `Config::from_json`, on the same documents.

use jsonschema::Validator;
use serde_json::{Value, json};

use super::*;

fn validator() -> Validator {
    let schema = serde_json::to_value(schemars::schema_for!(Config)).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

/// The schema's verdict and the parser's, in that order. A platform refusal
/// is not the parser calling the document malformed, and the schema leaves
/// those out.
fn verdicts(document: &Value) -> (bool, bool) {
    let parsed = Config::from_json(&document.to_string());
    (
        validator().is_valid(document),
        matches!(parsed, Ok(_) | Err(ConfigError::Unsupported { .. })),
    )
}

/// The value of `key` that holds `entry`: a list of it, or the entry alone for
/// the one key that is an object.
fn holding(key: &str, entry: Value) -> Value {
    if key == "network.mitmProxy" {
        entry
    } else {
        json!([entry])
    }
}

#[test]
fn a_minimal_config_passes_the_schema_and_the_parser() {
    assert_eq!(verdicts(&minimal()), (true, true));
}

#[test]
fn a_document_missing_a_required_list_fails_the_schema_and_the_parser() {
    for key in [
        "network.allowedDomains",
        "network.deniedDomains",
        "filesystem.denyRead",
        "filesystem.allowWrite",
        "filesystem.denyWrite",
    ] {
        let (group, list) = key.split_once('.').unwrap();
        let mut document = minimal();
        document[group].as_object_mut().unwrap().remove(list);

        assert_eq!(verdicts(&document), (false, false), "{key}");
    }
}

#[test]
fn a_null_optional_key_fails_the_schema_and_the_parser() {
    for key in [
        "enableWeakerNetworkIsolation",
        "windows",
        "windows.sandboxUser",
        "windows.sublayerGuid",
        "windows.wfpSublayerGuid",
        "windows.proxyPortRange",
        "git",
        "git.safeDirectories",
        "network.strictAllowlist",
        "network.deniedResolvedAddresses",
        "network.allowUnixSockets",
        "network.allowLocalBinding",
        "network.publish",
        "network.allowTcp",
        "network.allowMachLookup",
        "network.denyMachLookup",
        "network.mitmProxy",
        "filesystem.allowRead",
        "filesystem.allowGitConfig",
    ] {
        let document = settings_with(key, Value::Null);

        assert_eq!(verdicts(&document), (false, false), "{key}");
    }
}

#[test]
fn an_unknown_key_passes_the_schema_and_the_parser() {
    for key in [
        "futureSetting",
        "network.futureSetting",
        "filesystem.futureSetting",
    ] {
        let document = settings_with(key, json!({"anything": [1, null]}));

        assert_eq!(verdicts(&document), (true, true), "{key}");
    }
}

#[test]
fn every_entry_type_agrees_with_its_parser_on_a_good_and_a_bad_string() {
    for (key, good, bad) in [
        (
            "network.allowedDomains",
            json!("*.example.com:443"),
            json!("https://example.com"),
        ),
        ("network.allowedDomains", json!("[::1]:8080"), json!("*")),
        (
            "network.deniedDomains",
            json!("*"),
            json!("example.com/path"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("10.0.0.0/8"),
            json!("not an ip"),
        ),
        (
            "network.publish",
            json!("127.0.0.1:8080"),
            json!("localhost:80"),
        ),
        (
            "network.allowTcp",
            json!("example.com:443"),
            json!("example.com"),
        ),
        (
            "network.allowedDomains",
            json!("example.com:65535"),
            json!("example.com:65536"),
        ),
        (
            "network.allowedDomains",
            json!("example.com:1"),
            json!("example.com:0443"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("10.0.0.0/32"),
            json!("10.0.0.0/33"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("192.0.2.1"),
            json!("192.0.2.999"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("fc00::/128"),
            json!("fc00::/129"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("fe80::1%en0"),
            json!("1.2.3"),
        ),
        (
            "network.publish",
            json!("[::1]:65535"),
            json!("127.0.0.1:65536"),
        ),
        (
            "network.allowTcp",
            json!("example.com:0443"),
            json!("example.com:65536"),
        ),
        (
            "network.allowMachLookup",
            json!("com.example.*"),
            json!("com.*.x"),
        ),
        ("network.denyMachLookup", json!("*"), json!("*example.com")),
        ("network.allowedDomains", json!("*.a.b"), json!("*.a..b")),
        (
            "network.allowedDomains",
            json!("[example.com]:443"),
            json!("[example.com/x]:443"),
        ),
        (
            "network.deniedDomains",
            json!("[*]:443"),
            json!("[a:b.com]"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("10.0.0.0/032"),
            json!("10.0.0.0/0032"),
        ),
        (
            "network.deniedResolvedAddresses",
            json!("fc00::/128"),
            json!("fc00::/00128"),
        ),
        (
            "network.mitmProxy",
            json!({"socketPath": "/m", "domains": ["*.a.b"]}),
            json!({"socketPath": "/m", "domains": ["*.a..b"]}),
        ),
        ("filesystem.denyRead", json!("~/.ssh"), json!("")),
        (
            "filesystem.allowWrite",
            json!({"path": "/tmp/a*", "literal": true}),
            json!({"path": "/tmp"}),
        ),
        (
            "network.mitmProxy",
            json!({"socketPath": "/run/m.sock", "domains": ["a.com"]}),
            json!({"socketPath": "/run/m.sock", "domains": []}),
        ),
    ] {
        assert_eq!(
            verdicts(&settings_with(key, holding(key, good.clone()))),
            (true, true),
            "{key}: {good}"
        );
        assert_eq!(
            verdicts(&settings_with(key, holding(key, bad.clone()))),
            (false, false),
            "{key}: {bad}"
        );
    }
}

#[test]
fn the_windows_key_and_its_wfp_sublayer_guid_alias_both_pass() {
    let guid = "0f4b1c2d-0000-4000-8000-000000000001";
    for windows in [
        json!({"sublayerGuid": guid}),
        json!({"wfpSublayerGuid": guid}),
        json!({"sandboxUser": "ci-sandbox", "proxyPortRange": [61000, 61009]}),
    ] {
        assert_eq!(verdicts(&settings_with("windows", windows)), (true, true));
    }
    for windows in [
        json!({"wfpSublayerGuid": "not-a-guid"}),
        json!({"sandboxUser": "a-name-longer-than-twenty"}),
        json!({"proxyPortRange": [0, 9]}),
    ] {
        assert_eq!(verdicts(&settings_with("windows", windows)), (false, false));
    }
}

#[test]
fn the_schema_marks_the_five_required_lists_required() {
    let schema = serde_json::to_value(schemars::schema_for!(Config)).unwrap();
    let required = |group: &str| {
        let definition = schema["properties"][group]["$ref"].as_str().unwrap();
        schema.pointer(&definition[1..]).unwrap()["required"].clone()
    };

    assert_eq!(schema["required"], json!(["network", "filesystem"]));
    assert_eq!(
        required("network"),
        json!(["allowedDomains", "deniedDomains"])
    );
    assert_eq!(
        required("filesystem"),
        json!(["denyRead", "allowWrite", "denyWrite"])
    );
}
