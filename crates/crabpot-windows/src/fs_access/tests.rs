use crabpot_core::config::PathEntry;

use super::fake::FakeDisk;
use super::{
    Access, ConflictOptions, ExclusionKind, ExpandError, Held, Host, Lists, Mode, ProfileGrant,
    Relation, Settings, access, expand_paths, grants_beneath_denies, profile_exclusion_conflicts,
    rank,
};

fn host(disk: FakeDisk) -> Host<FakeDisk> {
    Host::new(Some(r"C:\Users\Dev"), Some(r"C:\Work\Proj"), disk)
}

fn spelled(paths: &[&str]) -> Vec<PathEntry> {
    paths
        .iter()
        .map(|path| PathEntry::Spelled((*path).to_owned()))
        .collect()
}

fn strings(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|path| (*path).to_owned()).collect()
}

fn lists<'a>(
    allow_read: &'a [String],
    allow_write: &'a [String],
    deny_read: &'a [String],
    deny_write: &'a [String],
    credential_deny: &'a [String],
) -> Lists<'a> {
    Lists {
        allow_read,
        allow_write,
        deny_read,
        deny_write,
        credential_deny,
        held: None,
    }
}

#[test]
fn drive_letters_and_case_fold_to_one_key() {
    let host = host(FakeDisk::default().dir(r"C:\Users\Dev\Proj"));
    for spelling in [
        r"c:\users\dev\proj",
        "C:/Users/Dev/PROJ/",
        r"\\?\C:\Users\Dev\Proj\",
        r"C:\Users\Dev\Other\..\Proj",
    ] {
        assert_eq!(host.key(spelling), "c:/users/dev/proj", "{spelling}");
    }
    // A path that is not there is compared as spelled.
    assert_eq!(host.key(r"c:\Nope\X/"), "c:/nope/x");
    assert_eq!(host.key(r"C:\"), "c:");
}

#[test]
fn an_8_3_name_and_a_junction_resolve_to_their_target() {
    let host = host(
        FakeDisk::default()
            .dir(r"C:\Program Files\App")
            .link(r"C:\PROGRA~1", r"C:\Program Files")
            .link(r"C:\Work\Current", r"C:\Program Files\App"),
    );
    assert_eq!(host.key(r"C:\PROGRA~1\App"), "c:/program files/app");
    assert_eq!(host.key(r"c:\work\current"), "c:/program files/app");
}

#[test]
fn a_deny_write_over_an_allow_write_downgrades_it_to_read() {
    let host = host(FakeDisk::default());
    let allow_write = strings(&[r"C:\Proj", r"C:\Proj\.git\hooks"]);
    let deny_write = strings(&[r"c:\proj\.GIT"]);
    let ranked = rank(&host, &lists(&[], &allow_write, &[], &deny_write, &[]));
    assert_eq!(
        ranked,
        Access {
            read: strings(&[r"C:\Proj\.git\hooks"]),
            write: strings(&[r"C:\Proj"]),
            deny_read: vec![],
            deny_write,
            metadata: vec![],
        }
    );
}

#[test]
fn a_credential_deny_drops_the_grants_beneath_it() {
    let host = host(FakeDisk::default());
    let allow_read = strings(&[r"C:\Users\Dev", r"C:\Users\Dev\.ssh\config"]);
    let allow_write = strings(&[r"C:\USERS\dev\.ssh", r"C:\Proj"]);
    let credential = strings(&[r"C:\Users\Dev\.ssh"]);
    let ranked = rank(
        &host,
        &lists(&allow_read, &allow_write, &[], &[], &credential),
    );
    assert_eq!(
        ranked,
        Access {
            read: strings(&[r"C:\Users\Dev"]),
            write: strings(&[r"C:\Proj"]),
            deny_read: credential,
            deny_write: vec![],
            metadata: vec![],
        }
    );
}

#[test]
fn a_held_grant_beneath_a_deny_gets_the_deny_at_its_own_path() {
    let host = host(FakeDisk::default());
    let held_read = strings(&[r"C:\Users\Dev\.ssh\cfg", r"C:\Elsewhere"]);
    let held_write = strings(&[r"C:\Proj\.git\hooks", r"C:\Proj"]);
    let credential = strings(&[r"C:\Users\Dev\.ssh"]);
    let deny_write = strings(&[r"C:\Proj\.git"]);
    let mut input = lists(&[], &[], &[], &deny_write, &credential);
    input.held = Some(Held {
        read: &held_read,
        write: &held_write,
    });
    let ranked = rank(&host, &input);
    assert_eq!(
        ranked.deny_read,
        strings(&[r"C:\Users\Dev\.ssh", r"C:\Users\Dev\.ssh\cfg"])
    );
    assert_eq!(
        ranked.deny_write,
        strings(&[r"C:\Proj\.git", r"C:\Proj\.git\hooks"])
    );
}

#[test]
fn deny_read_except_regrants_beneath_a_deny() {
    let host = host(FakeDisk::default());
    let grants = strings(&[r"C:\Proj\src\lib", r"C:\Proj\src", r"C:\Proj", r"C:\Other"]);
    let denies = strings(&[r"C:\Proj"]);
    assert_eq!(
        grants_beneath_denies(&host, &grants, &denies),
        strings(&[r"C:\Proj\src"])
    );
    assert!(grants_beneath_denies(&host, &grants, &[]).is_empty());
}

#[test]
fn a_glob_expands_case_insensitively() {
    let host = host(
        FakeDisk::default()
            .file(r"C:\Proj\Secrets\Key.pem")
            .file(r"C:\Proj\Secrets\notes.txt")
            .file(r"C:\Proj\Secrets\Sub\Deep.PEM"),
    );
    assert_eq!(
        expand_paths(&host, &spelled(&[r"c:\proj\secrets\*.PEM"]), Mode::Grant),
        Ok(strings(&[r"C:\proj\secrets\Key.pem"]))
    );
    assert_eq!(
        expand_paths(&host, &spelled(&[r"C:\Proj\**\*.pem"]), Mode::Deny),
        Ok(strings(&[
            r"C:\Proj\Secrets\Key.pem",
            r"C:\Proj\Secrets\Sub\Deep.PEM"
        ]))
    );
}

#[test]
fn a_pattern_ending_in_a_separator_matches_directories_only() {
    let host = host(
        FakeDisk::default()
            .file(r"C:\Proj\Secrets\Key.pem")
            .file(r"C:\Proj\notes.txt"),
    );
    assert_eq!(
        expand_paths(&host, &spelled(&[r"C:\Proj\*\"]), Mode::Deny),
        Ok(strings(&[r"C:\Proj\Secrets"]))
    );
}

#[test]
fn a_directory_with_brackets_in_its_name_is_walked_as_that_name() {
    let host = host(
        FakeDisk::default()
            .file(r"C:\[WIP]\Key.pem")
            .file(r"C:\Other\Key.pem"),
    );
    assert_eq!(
        expand_paths(&host, &spelled(&[r"C:\[WIP]\*.pem"]), Mode::Deny),
        Ok(strings(&[r"C:\[WIP]\Key.pem"]))
    );
}

#[test]
fn home_expands_from_userprofile() {
    let host = host(FakeDisk::default());
    let entries = spelled(&[
        r"~\.ssh",
        r"%USERPROFILE%\.aws",
        r"%homedrive%%homepath%\.gnupg",
        "~",
    ]);
    assert_eq!(
        expand_paths(&host, &entries, Mode::Deny),
        Ok(strings(&[
            r"C:\Users\Dev\.ssh",
            r"C:\Users\Dev\.aws",
            r"C:\Users\Dev\.gnupg",
            r"C:\Users\Dev",
        ]))
    );
    // `~/` keeps the slash it was spelled with; the key is the same.
    let slashed = expand_paths(&host, &spelled(&["~/.ssh"]), Mode::Deny).unwrap();
    assert_eq!(host.key(&slashed[0]), host.key(r"C:\Users\Dev\.ssh"));
}

#[test]
fn a_path_with_no_home_to_start_from_is_an_error() {
    let no_home = Host::new(None, Some(r"C:\Work"), FakeDisk::default());
    assert_eq!(
        expand_paths(&no_home, &spelled(&["~/.ssh"]), Mode::Deny),
        Err(ExpandError::NoHomeDirectory)
    );
    let no_cwd = Host::new(Some(r"C:\Users\Dev"), None, FakeDisk::default());
    assert_eq!(
        expand_paths(&no_cwd, &spelled(&[r"rel\dir"]), Mode::Deny),
        Err(ExpandError::NoWorkingDirectory)
    );
    assert_eq!(
        expand_paths(&no_cwd, &spelled(&[r"C:\abs"]), Mode::Deny),
        Ok(strings(&[r"C:\abs"]))
    );
}

#[test]
fn a_relative_path_starts_at_the_working_directory() {
    let host = host(FakeDisk::default());
    assert_eq!(
        expand_paths(&host, &spelled(&[r".\sub\..\x\", "y"]), Mode::Deny),
        Ok(strings(&[r"C:\Work\Proj\x\", r"C:\Work\Proj\y"]))
    );
}

#[test]
fn only_a_deny_keeps_a_path_that_is_not_there() {
    let host = host(FakeDisk::default().dir(r"C:\Here"));
    let entries = spelled(&[r"C:\Here", r"C:\Gone", r"C:\Gone\Dir\"]);
    assert_eq!(
        expand_paths(&host, &entries, Mode::Grant),
        Ok(strings(&[r"C:\Here"]))
    );
    assert_eq!(
        expand_paths(&host, &entries, Mode::Deny),
        Ok(strings(&[r"C:\Here", r"C:\Gone", r"C:\Gone\Dir\"]))
    );
}

#[test]
fn a_share_is_passed_through_without_a_look_at_the_disk() {
    let host = host(FakeDisk::default());
    let entries = spelled(&["//srv/share/Dir", r"\\?\UNC\srv\share\x"]);
    assert_eq!(
        expand_paths(&host, &entries, Mode::Grant),
        Ok(strings(&[r"\\srv\share\Dir", r"\\srv\share\x"]))
    );
    assert_eq!(host.disk().probes(), 0);
    assert_eq!(host.key(r"\\SRV\share\Dir\"), "//srv/share/dir");
    assert_eq!(host.disk().probes(), 0);
}

#[test]
fn a_device_path_is_passed_through_without_a_look_at_the_disk() {
    let host = host(FakeDisk::default());
    let entries = spelled(&[r"\\?\GLOBALROOT\Device\Mup\srv\share\x", r"\\.\pipe\name"]);
    for mode in [Mode::Grant, Mode::Deny] {
        assert_eq!(
            expand_paths(&host, &entries, mode),
            Ok(strings(&[
                r"\\?\GLOBALROOT\Device\Mup\srv\share\x",
                r"\\.\pipe\name"
            ]))
        );
    }
    assert_eq!(host.disk().probes(), 0);
}

#[test]
fn a_literal_path_is_not_a_pattern_and_one_with_a_wildcard_is_skipped() {
    let host = host(FakeDisk::default().dir(r"C:\[prod].env").file(r"C:\a.pem"));
    let entries = [
        PathEntry::Literal(r"C:\[prod].env".to_owned()),
        PathEntry::Literal(r"C:\*.pem".to_owned()),
        PathEntry::Spelled(r"C:\[prod].env".to_owned()),
    ];
    assert_eq!(
        expand_paths(&host, &entries, Mode::Grant),
        Ok(strings(&[r"C:\[prod].env"]))
    );
}

#[test]
fn the_access_serializes_as_the_stdin_of_acl_grant() {
    let host = host(FakeDisk::default().dir(r"C:\Proj").dir(r"C:\Proj\.git"));
    let allow_write = spelled(&[r"C:\Proj", r"c:\proj\.git"]);
    let deny_write = spelled(&[r"C:\Proj\.git"]);
    let credential = spelled(&[r"C:\Users\Dev\.ssh"]);
    let masked = strings(&[r"C:\Users\Dev\.netrc"]);
    let granted = access(
        &host,
        &Settings {
            allow_read: &[],
            allow_write: &allow_write,
            deny_read: &[],
            deny_write: &deny_write,
            credential_deny: &credential,
            masked_files: &masked,
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&granted).unwrap(),
        concat!(
            r#"{"read":["C:\\proj\\.git"],"write":["C:\\Proj"],"#,
            r#""denyRead":["C:\\Users\\Dev\\.ssh","C:\\Users\\Dev\\.netrc"],"#,
            r#""denyWrite":["C:\\Proj\\.git"]}"#
        )
    );
}

fn grant<'a>(exclusions: &'a [String], ungranted_only: &'a [String]) -> ProfileGrant<'a> {
    ProfileGrant {
        exclusions,
        ungranted_only,
    }
}

#[test]
fn a_grant_at_inside_or_above_an_exclusion_conflicts() {
    let host = host(FakeDisk::default());
    let exclusions = strings(&[r"C:\Users\Dev\.ssh"]);
    let paths = strings(&[
        r"c:\users\dev\.SSH",
        r"C:\Users\Dev\.ssh\id_ed25519",
        r"C:\Users\Dev",
        r"C:\Users\Dev\Docs",
    ]);
    let found = profile_exclusion_conflicts(
        &host,
        &paths,
        &grant(&exclusions, &[]),
        &ConflictOptions::default(),
    );
    let seen: Vec<_> = found
        .iter()
        .map(|c| (c.path.as_str(), c.relation, c.kind))
        .collect();
    assert_eq!(
        seen,
        [
            (paths[0].as_str(), Relation::Equal, ExclusionKind::Protected),
            (
                paths[1].as_str(),
                Relation::Inside,
                ExclusionKind::Protected
            ),
            (paths[2].as_str(), Relation::Above, ExclusionKind::Protected),
        ]
    );
}

#[test]
fn an_override_admits_a_read_but_not_a_write() {
    let host = host(FakeDisk::default());
    let exclusions = strings(&[r"C:\Users\Dev\.ssh"]);
    let paths = strings(&[r"C:\Users\Dev\.ssh\known_hosts"]);
    let admit = strings(&[r"C:\Users\Dev\.ssh\known_hosts"]);
    let read = ConflictOptions {
        override_: &admit,
        write: false,
    };
    let write = ConflictOptions {
        override_: &admit,
        write: true,
    };
    let profile = grant(&exclusions, &[]);
    assert!(profile_exclusion_conflicts(&host, &paths, &profile, &read).is_empty());
    assert_eq!(
        profile_exclusion_conflicts(&host, &paths, &profile, &write).len(),
        1
    );
}

#[test]
fn an_ungranted_only_directory_conflicts_only_as_itself_or_above() {
    let host = host(FakeDisk::default());
    let ungranted = strings(&[r"C:\Users\Dev\AppData\Local\Temp"]);
    let paths = strings(&[
        r"C:\Users\Dev\AppData\Local\Temp",
        r"C:\Users\Dev\AppData\Local\Temp\x",
        r"C:\Users\Dev\AppData",
    ]);
    let found = profile_exclusion_conflicts(
        &host,
        &paths,
        &grant(&[], &ungranted),
        &ConflictOptions::default(),
    );
    let seen: Vec<_> = found
        .iter()
        .map(|c| (c.path.as_str(), c.relation))
        .collect();
    assert_eq!(
        seen,
        [
            (paths[0].as_str(), Relation::Equal),
            (paths[2].as_str(), Relation::Above),
        ]
    );
    assert!(found.iter().all(|c| c.kind == ExclusionKind::UngrantedOnly));
}

#[test]
fn a_wildcard_exclusion_conflicts_above_only_where_something_matches() {
    let host = host(
        FakeDisk::default()
            .dir(r"C:\Users\Dev\AppData\Local\Chrome\User Data")
            .dir(r"C:\Users\Dev\Empty")
            .unreadable(r"C:\Users\Dev\Locked")
            .dir(r"C:\Users\Dev\Mail\Sub"),
    );
    let exclusions = strings(&[
        r"C:\Users\Dev\AppData\*\Chrome\User*",
        r"C:\Users\Dev\Empty\*\x",
        r"C:\Users\Dev\Locked\*",
        r"C:\Users\Dev\Mail\*\y",
    ]);
    let paths = strings(&[
        r"C:\Users\Dev\AppData",
        r"C:\Users\Dev\Empty",
        r"C:\Users\Dev\Locked",
        r"C:\Users\Dev\Mail",
    ]);
    let found = profile_exclusion_conflicts(
        &host,
        &paths,
        &grant(&exclusions, &[]),
        &ConflictOptions::default(),
    );
    let seen: Vec<_> = found
        .iter()
        .map(|c| (c.path.as_str(), c.unexamined.is_some()))
        .collect();
    assert_eq!(
        seen,
        [(paths[0].as_str(), false), (paths[2].as_str(), true)]
    );
}

/// The same rules against the real volume, where drive letters, case and the
/// kernel's own real paths are the host's.
#[cfg(windows)]
mod on_windows {
    use std::{env, fs, path::PathBuf};

    use super::{Host, Mode, PathEntry, expand_paths};
    use crate::fs_access::StdDisk;

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("crabpot-fs-access-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(dir.join("Secrets")).unwrap();
        fs::write(dir.join("Secrets").join("Key.PEM"), b"").unwrap();
        dir
    }

    #[test]
    fn a_glob_finds_a_file_of_another_case_on_the_volume() {
        let dir = scratch("glob");
        let pattern = format!("{}\\secrets\\*.pem", dir.to_str().unwrap().to_lowercase());
        let host = Host::new(None, None, StdDisk);
        let found = expand_paths(&host, &[PathEntry::Spelled(pattern)], Mode::Grant).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].to_lowercase().ends_with("\\secrets\\key.pem"));
    }

    #[test]
    fn two_spellings_of_a_directory_are_one_key() {
        let dir = scratch("key");
        let path = dir.to_str().unwrap().to_owned();
        let host = Host::new(None, None, StdDisk);
        let same = host.key(&path) == host.key(&path.to_uppercase());
        fs::remove_dir_all(&dir).unwrap();
        assert!(same);
    }
}
