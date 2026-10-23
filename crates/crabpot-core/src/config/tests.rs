use serde_json::{Value, json};

use super::*;

/// A settings file that sets only what upstream's schema requires.
fn minimal() -> Value {
    json!({
        "network": {"allowedDomains": [], "deniedDomains": []},
        "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
    })
}

/// `minimal()` with the key at the dotted `path` set to `value`.
fn with(path: &str, value: Value) -> String {
    let mut settings = minimal();
    let mut at = &mut settings;
    let mut keys = path.split('.').peekable();
    while let Some(key) = keys.next() {
        let fields = at.as_object_mut().expect("a group is an object");
        if keys.peek().is_none() {
            fields.insert(key.to_owned(), value);
            break;
        }
        at = fields.entry(key).or_insert_with(|| json!({}));
    }
    settings.to_string()
}

#[test]
fn the_default_config_shape_loads() {
    assert_eq!(
        Config::from_json(&minimal().to_string()),
        Ok(Config::default())
    );
}

/// Every key crabpot refuses, with a value that asks for something and is
/// valid for upstream's schema. The test below holds this to `unsupported`'s list.
const ASKING: &[(&str, &str)] = &[
    ("network.deniedDomains", r#"["example.com"]"#),
    ("network.allowUnixSockets", r#"["/tmp/x.sock"]"#),
    ("network.denyMachLookup", r#"["com.apple.x"]"#),
    ("network.allowLocalBinding", "true"),
    ("enableWeakerNetworkIsolation", "true"),
    ("network.deniedResolvedAddresses", r#"["10.0.0.0/8"]"#),
    (
        "network.mitmProxy",
        r#"{"socketPath": "/tmp/m.sock", "domains": ["example.com"]}"#,
    ),
    ("filesystem.allowRead", r#"["/secret/ok"]"#),
    ("filesystem.denyWrite", r#"["/work/.env"]"#),
    ("network.allowAllUnixSockets", "true"),
    ("network.httpProxyPort", "8080"),
    ("network.socksProxyPort", "1080"),
    ("network.deniedDomainReasons", r#"{"a.com": "no"}"#),
    ("network.stripResponseHeaders", r#"["set-cookie"]"#),
    ("network.refuseOpaqueTunnels", "true"),
    ("network.requireHostMatch", "true"),
    ("network.tlsTerminate", "{}"),
    ("network.parentProxy", r#"{"http": "http://proxy:3128"}"#),
    ("filesystem.disabled", "true"),
    ("filesystem.allowGitConfig", "true"),
    (
        "credentials",
        r#"{"files": [{"path": "~/.aws", "mode": "deny"}]}"#,
    ),
    ("ignoreViolations", r#"{"*": ["/tmp"]}"#),
    ("allowPty", "true"),
    ("allowAppleEvents", "true"),
    ("javaAgentJarPath", r#""/opt/srt-proxy-agent.jar""#),
    ("git.safeDirectories", r#"["/repo"]"#),
];

#[test]
fn each_unsupported_key_is_refused_naming_its_path() {
    for (path, value) in ASKING {
        let value: Value = serde_json::from_str(value).unwrap();

        assert_eq!(
            Config::from_json(&with(path, value)),
            Err(ConfigError::Unsupported { key: path }),
            "{path}"
        );
    }
}

#[test]
fn the_asking_table_covers_the_whole_unsupported_list() {
    let mut listed: Vec<&str> = unsupported::PATHS.to_vec();
    let mut tested: Vec<&str> = ASKING.iter().map(|(path, _)| *path).collect();
    listed.sort_unstable();
    tested.sort_unstable();

    assert_eq!(listed, tested);
}

#[test]
fn a_key_that_asks_for_nothing_loads() {
    for (path, value) in [
        ("network.allowUnixSockets", json!([])),
        ("network.allowMachLookup", json!([])),
        ("network.deniedResolvedAddresses", json!([])),
        ("network.allowLocalBinding", json!(false)),
        ("enableWeakerNetworkIsolation", json!(false)),
        ("filesystem.allowRead", json!([])),
        ("network.stripResponseHeaders", json!([])),
        ("git.safeDirectories", json!([])),
        ("allowPty", json!(false)),
    ] {
        let loaded = Config::from_json(&with(path, value));

        assert!(loaded.is_ok(), "{path}: {loaded:?}");
    }
}

#[test]
fn an_unknown_key_is_dropped() {
    for (path, value) in [
        ("bogus", json!(1)),
        ("network.bogus", json!(["x"])),
        ("filesystem.bogus", json!({"a": true})),
    ] {
        assert_eq!(
            Config::from_json(&with(path, value)),
            Ok(Config::default()),
            "{path}"
        );
    }
}

#[test]
fn a_key_upstream_ignores_on_macos_is_accepted_and_ignored() {
    for (path, value) in [
        ("bwrapPath", json!("/usr/bin/bwrap")),
        ("socatPath", json!("/usr/bin/socat")),
        ("seccomp", json!({"applyPath": "/x"})),
        ("mandatoryDenySearchDepth", json!(5)),
        ("enableWeakerNestedSandbox", json!(true)),
        ("allowNestedUserNamespaces", json!(true)),
        ("windows", json!({"sandboxUser": "srt"})),
        ("ripgrep", json!({"command": "rg"})),
    ] {
        assert_eq!(
            Config::from_json(&with(path, value)),
            Ok(Config::default()),
            "{path}"
        );
    }
}

fn invalid_key(json: &str) -> String {
    match Config::from_json(json) {
        Err(ConfigError::Invalid { key, .. }) => key,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn a_config_without_network_is_refused() {
    let mut settings = minimal();
    settings.as_object_mut().unwrap().remove("network");

    assert_eq!(invalid_key(&settings.to_string()), "network");
}

#[test]
fn a_config_without_filesystem_or_a_required_list_is_refused() {
    let mut settings = minimal();
    settings.as_object_mut().unwrap().remove("filesystem");
    assert_eq!(invalid_key(&settings.to_string()), "filesystem");

    let mut settings = minimal();
    settings["network"]
        .as_object_mut()
        .unwrap()
        .remove("allowedDomains");
    assert_eq!(invalid_key(&settings.to_string()), "network.allowedDomains");
}

#[test]
fn text_that_is_not_settings_is_invalid_at_the_root() {
    for json in ["[1]", "{", "null", ""] {
        assert_eq!(invalid_key(json), "", "{json:?}");
    }
}

#[test]
fn a_group_that_is_not_an_object_is_invalid() {
    for (json, key) in [
        (r#"{"filesystem": "~/.ssh"}"#, "filesystem"),
        (r#"{"network": ["example.com"]}"#, "network"),
        (r#"{"network": null}"#, "network"),
    ] {
        assert_eq!(invalid_key(json), key, "{json}");
    }
}

#[test]
fn a_refused_key_of_the_wrong_type_is_invalid_not_dropped() {
    for (path, value) in [
        ("git", json!(["/repo"])),
        ("git", json!("x")),
        ("git.safeDirectories", json!("/repo")),
        ("credentials", json!(false)),
        ("ignoreViolations", json!([])),
        ("network.tlsTerminate", json!(false)),
        ("network.parentProxy", json!([])),
        ("network.allowAllUnixSockets", json!("")),
        ("network.httpProxyPort", json!(null)),
        ("network.stripResponseHeaders", json!(false)),
        ("filesystem.disabled", json!([])),
        ("allowPty", json!("")),
    ] {
        assert_eq!(
            invalid_key(&with(path, value.clone())),
            path,
            "{path}: {value}"
        );
    }
}

#[test]
fn a_bad_leaf_is_refused_naming_its_key_path() {
    for (path, value, key) in [
        (
            "network.allowedDomains",
            json!(["example.com", "*.com"]),
            "network.allowedDomains.1",
        ),
        (
            "network.allowedDomains",
            json!(["*"]),
            "network.allowedDomains.0",
        ),
        (
            "network.deniedDomains",
            json!(["ok.com", "https://bad.com"]),
            "network.deniedDomains.1",
        ),
        (
            "network.deniedResolvedAddresses",
            json!(["10.0.0.0/33"]),
            "network.deniedResolvedAddresses.0",
        ),
        (
            "network.deniedResolvedAddresses",
            json!(["::ffff:10.0.0.0/64"]),
            "network.deniedResolvedAddresses.0",
        ),
        (
            "network.allowMachLookup",
            json!(["com.*.x"]),
            "network.allowMachLookup.0",
        ),
        (
            "network.mitmProxy",
            json!({"socketPath": "/m", "domains": []}),
            "network.mitmProxy.domains",
        ),
        (
            "network.mitmProxy",
            json!({"socketPath": "", "domains": ["a.com"]}),
            "network.mitmProxy.socketPath",
        ),
        (
            "network.mitmProxy",
            json!({"socketPath": "/m"}),
            "network.mitmProxy.domains",
        ),
        (
            "filesystem.denyRead",
            json!(["/a", ""]),
            "filesystem.denyRead.1",
        ),
        (
            "filesystem.allowWrite",
            json!([{"path": "/a"}]),
            "filesystem.allowWrite.0",
        ),
        (
            "filesystem.allowRead",
            json!([{"path": "/a", "literal": true, "extra": 1}]),
            "filesystem.allowRead.0",
        ),
        (
            "filesystem.denyWrite",
            json!(["/ok", "/work/*/"]),
            "filesystem.denyWrite.1",
        ),
        (
            "network.allowLocalBinding",
            json!("yes"),
            "network.allowLocalBinding",
        ),
        (
            "network.allowUnixSockets",
            json!("/a"),
            "network.allowUnixSockets",
        ),
        (
            "network.allowLocalBinding",
            json!(null),
            "network.allowLocalBinding",
        ),
    ] {
        assert_eq!(invalid_key(&with(path, value)), key, "{path}");
    }
}

#[test]
fn what_upstream_accepts_loads() {
    for (path, value) in [
        (
            "network.allowedDomains",
            json!(["a.com:443", "*.b.org", "[::1]:80"]),
        ),
        ("network.deniedDomains", json!(["*", "*:22"])),
        (
            "network.deniedResolvedAddresses",
            json!([
                "10.0.0.0/8",
                "fc00::/7",
                "::ffff:10.0.0.0/104",
                "fe80::1%en0"
            ]),
        ),
        ("network.allowMachLookup", json!(["*", "com.example.*"])),
        ("network.allowUnixSockets", json!([""])),
        (
            "filesystem.denyRead",
            json!(["/a/*", "build/*/", {"path": "/w/[x]/", "literal": true}]),
        ),
        ("filesystem.allowWrite", json!(["/w/*/"])),
    ] {
        let loaded = Config::from_json(&with(path, value));
        assert!(
            matches!(loaded, Ok(_) | Err(ConfigError::Unsupported { .. })),
            "{path}: {loaded:?}"
        );
    }
}

#[test]
fn a_bad_leaf_beats_an_unsupported_key() {
    let json = with("network.deniedDomains", json!(["*.com"]));

    assert!(matches!(
        Config::from_json(&json),
        Err(ConfigError::Invalid { .. })
    ));
}

#[test]
fn deserializing_a_config_refuses_what_from_json_refuses() {
    let json = with("network.deniedDomains", json!(["example.com"]));

    let error = serde_json::from_str::<Config>(&json).unwrap_err();

    assert!(
        error.to_string().contains("network.deniedDomains"),
        "{error}"
    );
}

mod files {
    use std::path::PathBuf;

    use super::*;

    /// A folder of its own, with `name` inside it holding `contents` when there are some.
    struct Dir(PathBuf);

    impl Dir {
        fn new(test: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("crabpot-config-{}-{test}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, contents: &str) -> PathBuf {
            let path = self.0.join("settings.json");
            std::fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_is_read_as_its_text_is() {
        let dir = Dir::new("read");

        assert_eq!(
            Config::from_file(&dir.file(&minimal().to_string())),
            Ok(Config::default())
        );
        assert!(matches!(
            Config::from_file(&dir.file("{not json")),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn a_file_that_is_missing_empty_or_unreadable_is_told_apart() {
        let dir = Dir::new("kinds");

        assert_eq!(
            Config::from_file(&dir.0.join("none.json")),
            Err(ConfigError::Missing)
        );
        assert_eq!(
            Config::from_file(&dir.file(" \n\t ")),
            Err(ConfigError::Empty)
        );
        assert!(matches!(
            Config::from_file(&dir.0),
            Err(ConfigError::Unreadable { .. })
        ));
    }
}
