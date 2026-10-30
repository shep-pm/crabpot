use super::*;
use serde_json::json;
use std::path::Path;

#[test]
fn a_case_file_parses_and_expands_root() {
    let text = r#"{
        "files": {"$ROOT/in": "hello"},
        "settings": {"filesystem": {"allowWrite": ["$ROOT/out"]}},
        "probes": [
            {"kind": "read", "path": "$ROOT/in"},
            {"kind": "write", "path": "$ROOT/out"},
            {"kind": "rename", "from": "$ROOT/in", "to": "$ROOT/moved"},
            {"kind": "connect", "host": "example.com", "port": 443},
            {"kind": "connect", "host": "example.com", "port": 443, "via": "socks5"},
            {"kind": "bind"},
            {"kind": "bind-unix", "path": "$ROOT/socks/a.sock"},
            {"kind": "connect-unix", "path": "$ROOT/socks/live.sock"},
            {"kind": "loopback"},
            {"kind": "signal-group"},
            {"kind": "ps"}
        ]
    }"#;
    let case = Case::parse(text, "/r").unwrap();
    assert_eq!(case.files, [(PathBuf::from("/r/in"), "hello".to_owned())]);
    assert_eq!(
        case.settings,
        json!({"filesystem": {"allowWrite": ["/r/out"]}})
    );
    assert_eq!(
        case.probes,
        [
            Probe::Read("/r/in".to_owned()),
            Probe::Write("/r/out".to_owned()),
            Probe::Rename {
                from: "/r/in".to_owned(),
                to: "/r/moved".to_owned()
            },
            Probe::Connect {
                host: "example.com".to_owned(),
                port: 443,
                via: None,
            },
            Probe::Connect {
                host: "example.com".to_owned(),
                port: 443,
                via: Some(Via::Socks5),
            },
            Probe::Bind,
            Probe::BindUnix("/r/socks/a.sock".to_owned()),
            Probe::ConnectUnix("/r/socks/live.sock".to_owned()),
            Probe::Loopback,
            Probe::SignalGroup,
            Probe::Ps,
        ]
    );
}

#[test]
fn the_kernel_probes_parse_and_spell_their_words() {
    let text = r#"{
        "files": {},
        "settings": {},
        "probes": [
            {"kind": "socket", "family": "unix"},
            {"kind": "socket", "family": "vsock"},
            {"kind": "io-uring-setup"},
            {"kind": "unshare-user"},
            {"kind": "ps-outside"}
        ]
    }"#;
    let case = Case::parse(text, "/r").unwrap();
    assert_eq!(
        case.probes,
        [
            Probe::Socket(Family::Unix),
            Probe::Socket(Family::Vsock),
            Probe::IoUringSetup,
            Probe::UnshareUser,
            Probe::PsOutside,
        ]
    );
    let words: Vec<Vec<String>> = case.probes.iter().map(Probe::args).collect();
    assert_eq!(
        words,
        [
            ["socket", "unix"].as_slice(),
            ["socket", "vsock"].as_slice(),
            ["io-uring-setup"].as_slice(),
            ["unshare-user"].as_slice(),
            ["ps-outside"].as_slice(),
        ]
    );
}

#[test]
fn a_socket_probe_needs_a_family_the_probe_knows() {
    for probe in [
        r#"{"kind": "socket"}"#,
        r#"{"kind": "socket", "family": "inet"}"#,
    ] {
        let text = format!(r#"{{"files": {{}}, "settings": {{}}, "probes": [{probe}]}}"#);
        assert!(
            matches!(Case::parse(&text, "/r"), Err(Error::Shape(_))),
            "{probe}"
        );
    }
}

/// A socket probe may name its socket against the case root instead, which
/// is where each wrapper runs and where the harness serves it.
#[test]
fn a_socket_probe_named_against_the_case_root_stays_relative() {
    let text = r#"{
        "files": {},
        "settings": {},
        "probes": [
            {"kind": "bind-unix", "path": "socks/a.sock"},
            {"kind": "connect-unix", "path": "socks/live.sock"}
        ]
    }"#;
    let case = Case::parse(text, "/r").unwrap();
    assert_eq!(
        case.probes,
        [
            Probe::BindUnix("socks/a.sock".to_owned()),
            Probe::ConnectUnix("socks/live.sock".to_owned()),
        ]
    );
}

/// A backslash-argument probe is known to give a code under upstream, which
/// is the difference the case pins.
#[test]
fn a_backslash_argument_probe_records_the_code_upstream_gives() {
    let text = r#"{
        "files": {},
        "settings": {},
        "probes": [{"kind": "backslash-argument", "value": "C:\\work", "upstream": 1}]
    }"#;
    let case = Case::parse(text, "/r").unwrap();
    let [probe] = case.probes.as_slice() else {
        panic!("one probe: {:?}", case.probes);
    };

    assert_eq!(
        *probe,
        Probe::BackslashArgument {
            value: r"C:\work".to_owned(),
        }
    );
    assert_eq!(
        probe.args(),
        ["backslash-argument", r"C:\work", "433a5c776f726b"]
    );
    assert_eq!(case.upstream_exit(0), Some(1));
}

#[test]
fn a_backslash_argument_probe_needs_a_value() {
    let text = r#"{"files": {}, "settings": {}, "probes": [{"kind": "backslash-argument"}]}"#;
    assert!(matches!(Case::parse(text, "/r"), Err(Error::Shape(_))));
}

/// Any probe may record the code upstream gives, not only the one made for
/// it.
#[test]
fn any_probe_may_record_the_code_upstream_gives() {
    let text = r#"{
        "files": {},
        "settings": {},
        "probes": [
            {"kind": "write", "path": "/r/a", "upstream": 1},
            {"kind": "write", "path": "/r/b"},
            {"kind": "bind", "upstream": 0}
        ]
    }"#;
    let case = Case::parse(text, "/r").unwrap();

    assert_eq!(case.upstream_exit(0), Some(1));
    assert_eq!(case.upstream_exit(1), None);
    assert_eq!(case.upstream_exit(2), Some(0));
    assert_eq!(case.upstream_exit(3), None);
    assert_eq!(case.probes[0], Probe::Write("/r/a".to_owned()));
}

#[test]
fn an_upstream_code_must_fit_8_bits() {
    for upstream in ["256", "-1", r#""1""#, "null"] {
        let text = format!(
            r#"{{"files": {{}}, "settings": {{}}, "probes": [{{"kind": "bind", "upstream": {upstream}}}]}}"#
        );
        assert!(
            matches!(Case::parse(&text, "/r"), Err(Error::Shape(_))),
            "{upstream}"
        );
    }
}

/// A case sets the host environment the wrappers run under, with `$ROOT`
/// expanded in names and values like the rest of the case.
#[test]
fn a_case_may_set_the_environment_its_wrappers_run_under() {
    let text = r#"{
        "files": {},
        "settings": {},
        "env": {"CLAUDE_CODE_TMPDIR": "$ROOT/fresh", "OTHER": "x"},
        "probes": []
    }"#;
    let case = Case::parse(text, "/r").unwrap();

    assert_eq!(
        case.env,
        Env::from([
            ("CLAUDE_CODE_TMPDIR".to_owned(), "/r/fresh".to_owned()),
            ("OTHER".to_owned(), "x".to_owned()),
        ])
    );
    let case = Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r").unwrap();
    assert!(case.env.is_empty());
}

#[test]
fn a_case_prints_the_names_of_its_env_and_not_the_values() {
    let text = r#"{
        "files": {},
        "settings": {},
        "env": {"API_KEY": "hunter2"},
        "probes": []
    }"#;
    let case = Case::parse(text, "/r").unwrap();

    let printed = format!("{case:?}");

    assert!(
        printed.contains(r#"env: {"API_KEY": "<redacted>"}"#),
        "{printed}"
    );
    assert!(!printed.contains("hunter2"), "{printed}");
}

#[test]
fn an_env_must_be_an_object_of_strings() {
    for env in ["[]", r#""A=b""#, r#"{"A": 1}"#, r#"{"A": null}"#] {
        let text = format!(r#"{{"files": {{}}, "settings": {{}}, "env": {env}, "probes": []}}"#);
        assert!(
            matches!(Case::parse(&text, "/r"), Err(Error::Shape(_))),
            "{env}"
        );
    }
}

#[test]
fn a_case_may_say_its_settings_are_refused() {
    let text = |refused: &str| {
        format!(r#"{{"files": {{}}, "settings": "", "refused": {refused}, "probes": []}}"#)
    };

    let case = Case::parse(&text("true"), "/r").unwrap();
    assert!(case.refused);
    assert_eq!(case.settings, json!(""));
    assert!(
        !Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r")
            .unwrap()
            .refused
    );
    assert!(matches!(
        Case::parse(&text("1"), "/r"),
        Err(Error::Shape(_))
    ));
}

#[test]
fn a_case_may_serve_a_named_pipe_named_for_its_root() {
    let text = r#"{
        "files": {},
        "settings": {"network": {"mitmProxy": {"socketPath": "$PIPE"}}},
        "serve": {"namedPipe": "$PIPE", "status": "200 Connection Established"},
        "probes": []
    }"#;
    let pipe = r"\\.\pipe\crabpot-harness-case";
    for root in ["/tmp/case", r"C:\tmp\case"] {
        let case = Case::parse(text, root).unwrap();

        assert_eq!(
            case.serve,
            Some(Serve {
                endpoint: Endpoint::NamedPipe(pipe.to_owned()),
                status: "200 Connection Established".to_owned(),
            })
        );
        assert_eq!(case.settings["network"]["mitmProxy"]["socketPath"], pipe);
    }
}

#[test]
fn a_case_may_serve_a_unix_socket() {
    let text = r#"{
        "files": {},
        "settings": {},
        "serve": {"unixSocket": "$ROOT/mitm.sock", "status": "403 Forbidden"},
        "probes": []
    }"#;
    let case = Case::parse(text, "/r").unwrap();

    assert_eq!(
        case.serve,
        Some(Serve {
            endpoint: Endpoint::UnixSocket("/r/mitm.sock".to_owned()),
            status: "403 Forbidden".to_owned(),
        })
    );
    let case = Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r").unwrap();
    assert_eq!(case.serve, None);
    for text in [
        r#"{"files": {}, "settings": {}, "serve": [], "probes": []}"#,
        r#"{"files": {}, "settings": {}, "serve": {}, "probes": []}"#,
        r#"{"files": {}, "settings": {}, "serve": {"unixSocket": 1}, "probes": []}"#,
        r#"{"files": {}, "settings": {}, "serve": {"unixSocket": "/a", "namedPipe": "p", "status": "200 OK"}, "probes": []}"#,
    ] {
        assert!(
            matches!(Case::parse(text, "/r"), Err(Error::Shape(_))),
            "{text}"
        );
    }
}

#[test]
fn a_case_without_platforms_runs_everywhere() {
    let case = Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r").unwrap();
    assert!(case.platforms.is_empty());
    assert!(case.runs_on(Platform::MacOs));
    assert!(case.runs_on(Platform::Linux));
}

#[test]
fn a_case_allows_loopback_only_when_its_settings_say_true() {
    let with = |network: &str| {
        Case::parse(
            &format!(r#"{{"files": {{}}, "settings": {{"network": {network}}}, "probes": []}}"#),
            "/r",
        )
        .unwrap()
    };

    assert!(with(r#"{"allowLocalBinding": true}"#).allows_loopback());
    assert!(!with(r#"{"allowLocalBinding": false}"#).allows_loopback());
    assert!(!with("{}").allows_loopback());
    let text = Case::parse(
        r#"{"files": {}, "settings": "not json", "probes": []}"#,
        "/r",
    );
    assert!(!text.unwrap().allows_loopback());
}

#[test]
fn a_case_runs_only_on_the_platforms_it_names() {
    let named = |platforms: &str| {
        Case::parse(
            &format!(
                r#"{{"files": {{}}, "settings": {{}}, "platforms": {platforms}, "probes": []}}"#
            ),
            "/r",
        )
    };

    let case = named(r#"["macos"]"#).unwrap();
    assert_eq!(case.platforms, [Platform::MacOs]);
    assert!(case.runs_on(Platform::MacOs));
    assert!(!case.runs_on(Platform::Linux));

    let case = named(r#"["linux", "macos"]"#).unwrap();
    assert_eq!(case.platforms, [Platform::Linux, Platform::MacOs]);
    assert!(case.runs_on(Platform::MacOs));
    assert!(case.runs_on(Platform::Linux));

    assert_eq!(
        named(r#"["plan9"]"#),
        Err(Error::UnknownPlatform("plan9".to_owned()))
    );
    for platforms in [r#""macos""#, "[1]", r#"["macos", 2]"#] {
        assert!(
            matches!(named(platforms), Err(Error::Shape(_))),
            "{platforms}"
        );
    }
}

#[test]
fn a_case_that_names_other_platforms_is_skipped_on_windows() {
    let named = |platforms: &str| {
        Case::parse(
            &format!(
                r#"{{"files": {{}}, "settings": {{}}, "platforms": {platforms}, "probes": []}}"#
            ),
            "/r",
        )
        .unwrap()
    };

    let unix_only = named(r#"["macos", "linux"]"#);
    assert!(!unix_only.runs_on(Platform::Windows));
    assert!(unix_only.runs_on(Platform::MacOs));

    let windows = named(r#"["windows"]"#);
    assert_eq!(windows.platforms, [Platform::Windows]);
    assert!(windows.runs_on(Platform::Windows));
    assert!(!windows.runs_on(Platform::Linux));

    let everywhere = named("[]");
    assert!(everywhere.runs_on(Platform::Windows));
}

#[test]
fn an_unknown_probe_kind_is_a_harness_error() {
    let text = r#"{"files": {}, "settings": {}, "probes": [{"kind": "ping"}]}"#;
    assert_eq!(
        Case::parse(text, "/r"),
        Err(Error::UnknownProbe("ping".to_owned()))
    );
}

#[test]
fn every_case_file_in_the_folder_parses() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/cases");
    let mut parsed = 0;
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        if let Err(error) = Case::parse(&text, "/r") {
            panic!("{}: {error}", path.display());
        }
        parsed += 1;
    }
    assert!(parsed >= 4, "only {parsed} case files found");
}

#[test]
fn every_write_and_rename_in_a_case_file_has_a_folder_to_land_in() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/cases");
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let case = Case::parse(&text, "/r").unwrap();
        let mut folders = std::collections::HashSet::new();
        let mut sources = std::collections::HashSet::new();
        for (file, _) in &case.files {
            sources.insert(file.clone());
            for ancestor in file.ancestors().skip(1) {
                folders.insert(ancestor.to_owned());
                sources.insert(ancestor.to_owned());
            }
        }
        // A probe cannot tell a missing folder from a refusal, so one
        // that lands in a folder the case never made exits 2. A folder the
        // case's `env` names is one the sandbox's wrapper makes.
        // The folder the sandbox sets `TMPDIR` to: `CLAUDE_CODE_TMPDIR`,
        // else `CLAUDE_TMPDIR`.
        let tmpdir = case
            .env
            .get("CLAUDE_CODE_TMPDIR")
            .or_else(|| case.env.get("CLAUDE_TMPDIR"));
        let lands = |target: &str| match Path::new(target).parent() {
            Some(parent) => {
                !target.starts_with("/r/")
                    || folders.contains(parent)
                    || parent == Path::new("/r")
                    || tmpdir.is_some_and(|set| Path::new(set) == parent)
            }
            None => true,
        };
        for probe in &case.probes {
            match probe {
                Probe::Write(target) => {
                    assert!(lands(target), "{}: no folder for {target}", path.display())
                }
                Probe::Rename { from, to } => {
                    assert!(
                        !from.starts_with("/r/") || sources.contains(Path::new(from)),
                        "{}: nothing to move at {from}",
                        path.display()
                    );
                    assert!(lands(to), "{}: no folder for {to}", path.display());
                }
                Probe::BindUnix(target) | Probe::ConnectUnix(target) => {
                    assert!(lands(target), "{}: no folder for {target}", path.display())
                }
                Probe::Read(_) | Probe::Connect { .. } | Probe::Bind | Probe::Loopback => {}
                Probe::SignalGroup | Probe::Ps => {}
                Probe::Socket(_)
                | Probe::IoUringSetup
                | Probe::UnshareUser
                | Probe::PsOutside
                | Probe::BackslashArgument { .. } => {}
            }
        }
    }
}
