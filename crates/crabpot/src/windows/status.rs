//! What a Windows host reads before a command runs: the sandbox user, the WFP
//! fence and the profile grant, from the three srt-win queries upstream's
//! `getWindowsSandboxUserStatus`, `mapWfpStatus` and
//! `checkWindowsSandboxStatus` make.

use core::ops::RangeInclusive;

use serde::Deserialize;

use crate::StartError;

/// What the install says about the sandbox, read without elevation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WindowsStatus {
    /// Whether a command can be launched as the sandbox user.
    pub user: UserState,
    /// The sandbox user's SID, when it has an account.
    pub sandbox_sid: Option<String>,
    /// The SID of the account this process runs as, when the machine names it.
    pub real_user_sid: Option<String>,
    /// The SID of the user who owns the session this process runs in, when the
    /// machine names one.
    pub session_user_sid: Option<String>,
    /// The install's setup version beside this build's.
    pub setup_version: SetupVersion,
    /// Whether the WFP fence leaves loopback open.
    pub loopback: LoopbackMode,
    /// The loopback ports the fence leaves open for the proxy, when it has
    /// filters to read them from.
    pub proxy_ports: Option<RangeInclusive<u16>>,
    /// Whether a profile read grant is in place.
    pub profile: ProfileState,
    /// What the profile read grant keeps unreadable, empty when there is none.
    pub profile_exclusions: ProfileExclusions,
    /// Whether the Secondary Logon service can launch the sandbox user. False
    /// when it is disabled or missing, and true when it could not be read,
    /// which is not proof of a problem.
    pub seclogon_runs: bool,
    /// Whether this process runs as the user who owns its session.
    pub in_desktop_session: bool,
}

/// Whether a command can be launched as the sandbox user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserState {
    /// The user exists, its credential is stored, and the install's setup
    /// version is this build's.
    Provisioned,
    /// Any of those is missing. A setup version mismatch reads as this, since
    /// srt-win refuses a launch for it the way it does for no install.
    NotProvisioned,
}

/// The setup version of the install and of this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetupVersion {
    /// What the install recorded, or `None` when there is no install.
    pub installed: Option<u32>,
    /// What this build needs.
    pub expected: u32,
}

/// Whether the sandbox user may connect to loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoopbackMode {
    /// Every loopback port is open.
    Open,
    /// Only the proxy's ports are open.
    Closed,
}

/// The paths a profile read grant keeps out of a session's grants, as
/// `profile status` records them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ProfileExclusions {
    /// Every protected path the grant keeps unreadable, wildcards as written. A
    /// session may not grant one, a path inside one, or a path above one.
    #[serde(default)]
    pub exclusions: Vec<String>,
    /// Directories the grant leaves ungranted without denying them. A session
    /// may not grant one, or a path above one.
    #[serde(default)]
    pub ungranted_only: Vec<String>,
}

/// Whether the profile read grant is in place, as `profile status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileState {
    /// No grant.
    None,
    /// A grant a session may rely on.
    Current,
    /// A grant an older list made.
    Outdated,
    /// A grant that did not finish.
    Incomplete,
    /// A grant or forget is running.
    InProgress,
    /// The record could not be read, or says what this build does not know.
    Unknown,
}

/// The error a srt-win query that exits with `code` stands for, when it is one
/// of the exits a host acts on: 15 for no usable install, 18 for seclogon.
pub fn refusal_for_exit(code: i32) -> Option<StartError> {
    match code {
        15 => Some(StartError::NotProvisioned),
        18 => Some(StartError::SeclogonDisabled),
        _ => None,
    }
}

/// `user status`, as far as a status reads it.
#[derive(Deserialize)]
struct UserJson {
    user: UserAccount,
    cred_present: bool,
    marker_version: Option<u32>,
    setup_version: u32,
    real_user_sid: Option<String>,
    session_user_sid: Option<String>,
    seclogon: String,
}

#[derive(Deserialize)]
struct UserAccount {
    exists: bool,
    sid: Option<String>,
}

/// `wfp status`, as far as a status reads it.
#[derive(Deserialize)]
struct WfpJson {
    port_range: Option<[u16; 2]>,
    allow_loopback: bool,
}

/// `profile status`, as far as a status reads it.
#[derive(Deserialize)]
struct ProfileJson {
    state: String,
    #[serde(flatten)]
    exclusions: ProfileExclusions,
}

/// Reads the status through `run`, which runs one srt-win query with the
/// arguments after it and returns what it printed. `sublayer` is the WFP
/// sublayer the filters were installed under, when it is not the default.
pub(crate) fn read(
    sublayer: Option<&str>,
    run: impl Fn(&'static str, &[&str]) -> Result<String, StartError>,
) -> Result<WindowsStatus, StartError> {
    let user: UserJson = parse("user status", &[], &run)?;
    let wfp_args: Vec<&str> = sublayer
        .into_iter()
        .flat_map(|guid| ["--sublayer-guid", guid])
        .collect();
    let wfp: WfpJson = parse("wfp status", &wfp_args, &run)?;
    let profile: ProfileJson = parse("profile status", &[], &run)?;
    let provisioned =
        user.user.exists && user.cred_present && user.marker_version == Some(user.setup_version);
    // A session without an owner is session 0, which is refused by name before
    // the status is read.
    let in_desktop_session =
        user.session_user_sid.is_some() && user.session_user_sid == user.real_user_sid;
    Ok(WindowsStatus {
        user: if provisioned {
            UserState::Provisioned
        } else {
            UserState::NotProvisioned
        },
        sandbox_sid: user.user.sid,
        real_user_sid: user.real_user_sid,
        session_user_sid: user.session_user_sid,
        setup_version: SetupVersion {
            installed: user.marker_version,
            expected: user.setup_version,
        },
        loopback: if wfp.allow_loopback {
            LoopbackMode::Open
        } else {
            LoopbackMode::Closed
        },
        proxy_ports: wfp.port_range.map(|[low, high]| low..=high),
        profile: match profile.state.as_str() {
            "none" => ProfileState::None,
            "current" => ProfileState::Current,
            "outdated" => ProfileState::Outdated,
            "incomplete" => ProfileState::Incomplete,
            "in_progress" => ProfileState::InProgress,
            _ => ProfileState::Unknown,
        },
        profile_exclusions: profile.exclusions,
        seclogon_runs: !matches!(user.seclogon.as_str(), "disabled" | "missing"),
        in_desktop_session,
    })
}

/// Runs `command` through `run` and reads what it printed as `T`.
fn parse<T: for<'de> Deserialize<'de>>(
    command: &'static str,
    args: &[&str],
    run: &impl Fn(&'static str, &[&str]) -> Result<String, StartError>,
) -> Result<T, StartError> {
    serde_json::from_str(&run(command, args)?).map_err(|_| StartError::StatusFailed {
        command,
        code: None,
    })
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;

    const PROVISIONED: &str = r#"{
        "user": {"name": "crabpot-sandbox", "exists": true, "sid": "S-1-5-21-1",
                 "group_exists": true, "in_builtin_users": true,
                 "in_sandbox_group": true, "hidden_from_logon": true},
        "cred_present": true, "marker_version": 3, "setup_version": 3,
        "real_user_sid": "S-1-5-21-2", "session_user_sid": "S-1-5-21-2",
        "profile_grant": {"state": "present"}, "seclogon": "ok"
    }"#;
    const WFP: &str =
        r#"{"state":"installed","filters":4,"port_range":[3128,3130],"allow_loopback":false}"#;
    const PROFILE: &str = r#"{"state":"current","record_version":1}"#;

    /// A srt-win whose three queries print what it is given.
    fn fake(user: &str, wfp: &str) -> impl Fn(&'static str, &[&str]) -> Result<String, StartError> {
        let (user, wfp) = (user.to_owned(), wfp.to_owned());
        move |command, _| match command {
            "user status" => Ok(user.clone()),
            "wfp status" => Ok(wfp.clone()),
            "profile status" => Ok(PROFILE.to_owned()),
            other => panic!("unexpected query {other}"),
        }
    }

    #[test]
    fn user_status_json_maps_to_the_state() {
        let status = read(None, fake(PROVISIONED, WFP)).unwrap();

        assert_eq!(status.user, UserState::Provisioned);
        assert_eq!(status.sandbox_sid.as_deref(), Some("S-1-5-21-1"));
        assert_eq!(status.real_user_sid.as_deref(), Some("S-1-5-21-2"));
        assert_eq!(status.session_user_sid.as_deref(), Some("S-1-5-21-2"));
        assert_eq!(
            status.setup_version,
            SetupVersion {
                installed: Some(3),
                expected: 3
            }
        );
        assert_eq!(status.loopback, LoopbackMode::Closed);
        assert_eq!(status.profile, ProfileState::Current);
        assert!(status.seclogon_runs);
        assert!(status.in_desktop_session);
    }

    #[test]
    fn setup_version_mismatch_is_reported_not_provisioned() {
        let older = PROVISIONED.replace(r#""marker_version": 3"#, r#""marker_version": 2"#);

        let status = read(None, fake(&older, WFP)).unwrap();

        assert_eq!(status.user, UserState::NotProvisioned);
        assert_eq!(
            status.setup_version,
            SetupVersion {
                installed: Some(2),
                expected: 3
            }
        );
    }

    #[test]
    fn no_install_is_not_provisioned() {
        let none = r#"{"user": {"exists": false}, "cred_present": false,
            "marker_version": null, "setup_version": 3, "real_user_sid": "S-1-5-21-2",
            "session_user_sid": "S-1-5-21-2", "profile_grant": {"state": "none"},
            "seclogon": "disabled"}"#;
        let absent = r#"{"state":"absent","filters":0,"allow_loopback":true}"#;

        let status = read(None, fake(none, absent)).unwrap();

        assert_eq!(status.user, UserState::NotProvisioned);
        assert_eq!(status.setup_version.installed, None);
        assert_eq!(status.proxy_ports, None);
        assert_eq!(status.loopback, LoopbackMode::Open);
        assert!(!status.seclogon_runs);
    }

    #[test]
    fn the_profile_exclusions_come_from_profile_status() {
        let profile = r#"{"state":"current","exclusions":["C:\\Users\\me\\.ssh"],
            "ungranted_only":["C:\\Users\\me\\AppData\\Local\\Temp"]}"#;

        let status = read(None, |command, _| match command {
            "user status" => Ok(PROVISIONED.to_owned()),
            "wfp status" => Ok(WFP.to_owned()),
            _ => Ok(profile.to_owned()),
        })
        .unwrap();

        assert_eq!(
            status.profile_exclusions,
            ProfileExclusions {
                exclusions: vec![r"C:\Users\me\.ssh".to_owned()],
                ungranted_only: vec![r"C:\Users\me\AppData\Local\Temp".to_owned()],
            }
        );
    }

    #[test]
    fn exit_codes_15_and_18_map_to_their_errors() {
        assert_eq!(refusal_for_exit(15), Some(StartError::NotProvisioned));
        assert_eq!(refusal_for_exit(18), Some(StartError::SeclogonDisabled));
        assert_eq!(refusal_for_exit(0), None);
        assert_eq!(refusal_for_exit(1), None);
    }

    #[test]
    fn the_port_range_comes_from_wfp_status() {
        let status = read(None, fake(PROVISIONED, WFP)).unwrap();

        assert_eq!(status.proxy_ports, Some(3128..=3130));
    }

    #[test]
    fn a_user_in_another_users_session_is_not_in_the_desktop_session() {
        let runas = PROVISIONED.replace(
            r#""session_user_sid": "S-1-5-21-2""#,
            r#""session_user_sid": "S-1-5-21-9""#,
        );

        let status = read(None, fake(&runas, WFP)).unwrap();

        assert!(!status.in_desktop_session);
    }

    #[test]
    fn the_sublayer_reaches_wfp_status_alone() {
        let asked = RefCell::new(Vec::new());
        let guid = "0f4b1c2d-0000-4000-8000-000000000001";

        read(Some(guid), |command, args| {
            asked.borrow_mut().push((command, args.join(" ")));
            fake(PROVISIONED, WFP)(command, args)
        })
        .unwrap();

        assert_eq!(
            asked.into_inner(),
            [
                ("user status", String::new()),
                ("wfp status", format!("--sublayer-guid {guid}")),
                ("profile status", String::new()),
            ]
        );
    }

    #[test]
    fn output_that_is_not_json_is_a_failed_query() {
        let error = read(None, fake("not json", WFP)).unwrap_err();

        assert_eq!(
            error,
            StartError::StatusFailed {
                command: "user status",
                code: None
            }
        );
    }
}
