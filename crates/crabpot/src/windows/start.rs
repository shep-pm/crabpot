//! Starting a Windows session, as upstream's `initialize`
//! (`src/sandbox/sandbox-manager.ts`) does once the status checks have passed:
//! the profile grant is read, the session's grants are made, the fence is
//! verified, and the proxy starts in the range the fence permits.

use core::any::Any;
use core::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};

use crabpot_core::config::Config;
use crabpot_core::proxy::{PortRange, Proxy};
use serde::Deserialize;

use super::command::{self, Params};
use super::plan::Plan;
use super::srt::{Call, Output, Srt};
use super::status::{ProfileState, WindowsStatus};
use crate::{StartError, WrapError};

/// Which sandbox users the fence has been verified for in this process, and in
/// which loopback mode. The fence is installed for the machine and not for a
/// session, so one pass holds for every session after it.
#[derive(Debug, Default)]
pub(crate) struct Verified(Mutex<Vec<(String, bool)>>);

impl Verified {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    fn holds(&self, sid: &str, allow_loopback: bool) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(verified, loopback)| verified == sid && *loopback == allow_loopback)
    }

    fn record(&self, sid: &str, allow_loopback: bool) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((sid.to_owned(), allow_loopback));
    }
}

/// A started Windows sandbox: the grants it holds, and the proxy its commands
/// reach the network through.
#[derive(Debug)]
pub(crate) struct Session {
    proxy: Proxy,
    exe: PathBuf,
    write_roots: Vec<String>,
    allow_loopback: bool,
    // Last, so the grants are released once the proxy has stopped.
    held: Held,
}

impl Session {
    /// `command`, wrapped to run through `srt-win exec` in this session.
    ///
    /// # Errors
    ///
    /// [`WrapError::Cmd`] when a word of `command` cannot be put on a `cmd.exe`
    /// line as itself.
    pub(crate) fn command(&self, command: &Command) -> Result<Command, WrapError> {
        command::wrap(
            &Params {
                exe: &self.exe,
                held_by: self.held.holder,
                write_roots: &self.write_roots,
                allow_loopback: self.allow_loopback,
                proxy_port: self.proxy.port(),
                token: self.proxy.token(),
            },
            command,
        )
    }
}

/// The grants one process holds for a sandbox user, released when it drops.
struct Held {
    srt: Arc<dyn Srt>,
    sid: String,
    holder: u32,
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Held")
            .field("sid", &self.sid)
            .field("holder", &self.holder)
            .finish_non_exhaustive()
    }
}

impl Held {
    fn call(&self, verb: &str) -> Call {
        Call::new([
            "acl",
            verb,
            "--holder-pid",
            &self.holder.to_string(),
            "--sandbox-user-sid",
            &self.sid,
            "--json",
        ])
    }
}

impl Drop for Held {
    /// Revokes the grants, then restores the denies. A revoke that did not
    /// finish leaves the denies in place, since a grant may still be on disk.
    fn drop(&mut self) {
        if revoked(&self.srt.run(&self.call("revoke"))) {
            let _ = self.srt.run(&self.call("restore"));
        } else {
            eprintln!(
                "crabpot: the sandbox's grants could not all be revoked, so its denies stay in place; `crabpot --srt-win acl recover` clears them once this process has exited"
            );
        }
    }
}

/// One path `acl revoke` reports on.
#[derive(Deserialize)]
struct Outcome {
    path: String,
    status: String,
}

impl Outcome {
    /// Whether the grant is released. A status this build does not know is not.
    fn released(&self) -> bool {
        match self.status.as_str() {
            "revoked" | "stillHeld" | "downgraded" | "relocated" | "mismatch" | "noRow"
            | "gone" => true,
            // An older srt-win says it of a path it could not open too, so it
            // counts only when the path is gone.
            "missing" => matches!(
                Path::new(&self.path).symlink_metadata(),
                Err(e) if e.kind() == io::ErrorKind::NotFound
            ),
            _ => false,
        }
    }
}

/// Whether an `acl revoke` ran to the end and released every grant.
fn revoked(output: &io::Result<Output>) -> bool {
    let Ok(output) = output else {
        return false;
    };
    output.succeeded()
        && serde_json::from_str::<Vec<Outcome>>(&output.stdout)
            .is_ok_and(|outcomes| outcomes.iter().all(Outcome::released))
}

/// What a session is started from: the calls to srt-win, this binary, and the
/// process the grants are held for.
pub(crate) struct Host {
    pub(crate) srt: Arc<dyn Srt>,
    pub(crate) exe: PathBuf,
    pub(crate) holder: u32,
}

/// A loopback listener a `wfp verify` attempt is aimed at, and what keeps it
/// open until the attempt has ended.
pub(crate) struct Probe {
    target: SocketAddr,
    _open: Box<dyn Any>,
}

/// A session whose grants are made and whose fence is verified, and whose proxy
/// is not yet started. It releases the grants if it is dropped.
#[derive(Debug)]
struct Prepared {
    held: Held,
    exe: PathBuf,
    plan: Plan,
    allow_loopback: bool,
    range: PortRange,
}

/// Starts a session for `config` under `status`, which has passed the status
/// checks.
///
/// # Errors
///
/// Those of [`prepare`], then [`StartError::Proxy`] when the proxy cannot
/// start, which releases the grants.
pub(crate) fn start_with(
    host: Host,
    verified: &Verified,
    status: &WindowsStatus,
    config: &Config,
) -> Result<Session, StartError> {
    prepare(host, verified, status, config, &listener_outside)?.start_proxy(config)
}

/// Makes the session's grants and verifies the fence, with `listen` opening the
/// listener the verification is aimed at.
///
/// # Errors
///
/// [`StartError::ProfileGrantOutdated`] for a profile grant that is neither none
/// nor current, [`StartError::StatusFailed`] for a status with no sandbox user
/// SID, [`StartError::GrantBlocked`] or [`StartError::GrantFailed`] when the
/// grant call fails, and the errors of
/// [`wfp::interpret`](super::wfp::interpret) when the fence is not verified. A
/// failure after the grant releases it.
fn prepare(
    host: Host,
    verified: &Verified,
    status: &WindowsStatus,
    config: &Config,
    listen: &dyn Fn(PortRange) -> io::Result<Probe>,
) -> Result<Prepared, StartError> {
    if !matches!(status.profile, ProfileState::None | ProfileState::Current) {
        return Err(StartError::ProfileGrantOutdated {
            state: status.profile,
        });
    }
    let sid = status.sandbox_sid.clone().ok_or(StartError::StatusFailed {
        command: "user status",
        code: None,
    })?;
    let plan = Plan::build(config)?;
    let allow_loopback = config.network.allow_local_binding == Some(true);
    let range = match &status.proxy_ports {
        Some(ports) => PortRange::new(*ports.start(), *ports.end()),
        None => Ok(PortRange::DEFAULT),
    }
    .map_err(|e| StartError::Proxy(io::Error::from(e).kind()))?;

    // Held before the call, so that a grant that landed in part is released.
    let held = Held {
        srt: host.srt,
        sid,
        holder: host.holder,
    };
    plan.apply(&*held.srt, &held.sid, held.holder)?;
    if !verified.holds(&held.sid, allow_loopback) {
        verify(&*held.srt, &plan, allow_loopback, listen(range))?;
        verified.record(&held.sid, allow_loopback);
    }
    Ok(Prepared {
        held,
        exe: host.exe,
        plan,
        allow_loopback,
        range,
    })
}

impl Prepared {
    fn start_proxy(self, config: &Config) -> Result<Session, StartError> {
        let proxy = Proxy::start_in_range(
            &config.network.allowed_domains,
            &config.network.denied_domains,
            config
                .network
                .denied_resolved_addresses
                .as_deref()
                .unwrap_or_default(),
            config.network.strict_allowlist.unwrap_or(false),
            config.network.mitm_proxy.as_ref(),
            self.range,
        )
        .map_err(|e| StartError::Proxy(io::Error::from(e).kind()))?;
        Ok(Session {
            proxy,
            exe: self.exe,
            write_roots: self.plan.write_roots().to_vec(),
            allow_loopback: self.allow_loopback,
            held: self.held,
        })
    }
}

/// Runs `wfp verify` against `probe`, under the token a command of the session
/// gets, and judges the answer.
fn verify(
    srt: &dyn Srt,
    plan: &Plan,
    allow_loopback: bool,
    probe: io::Result<Probe>,
) -> Result<(), StartError> {
    // Held while the call runs. A connect that gets through completes against
    // its backlog, so it is never accepted.
    let probe = probe.map_err(|e| StartError::Proxy(e.kind()))?;
    let mut args = vec![
        "wfp".to_owned(),
        "verify".to_owned(),
        "--target".to_owned(),
        probe.target.to_string(),
    ];
    if allow_loopback {
        args.push("--allow-loopback".to_owned());
    }
    args.push("--write-restricted-token".to_owned());
    for root in plan.write_roots() {
        args.push("--write-root".to_owned());
        args.push(root.clone());
    }
    let output = srt
        .run(&Call::new(args))
        .map_err(|e| StartError::FenceUnverified {
            detail: format!("`srt-win wfp verify` did not run: {e}"),
        })?;
    drop(probe);
    super::wfp::interpret(&output)
}

/// A loopback listener on a port the fence does not permit, since a port it
/// permits would connect even with the fence active.
fn listener_outside(range: PortRange) -> io::Result<Probe> {
    for _ in 0..5 {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let target = listener.local_addr()?;
        if !(range.first()..=range.last()).contains(&target.port()) {
            return Ok(Probe {
                target,
                _open: Box::new(listener),
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no loopback port outside the proxy port range in 5 tries",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::srt::fake::{BLOCKED, Calls, Fake, exit};
    use crate::windows::status::{LoopbackMode, SetupVersion, UserState};

    fn status() -> WindowsStatus {
        WindowsStatus {
            user: UserState::Provisioned,
            sandbox_sid: Some("S-1-5-21-7".to_owned()),
            setup_version: SetupVersion {
                installed: Some(3),
                expected: 3,
            },
            loopback: LoopbackMode::Closed,
            // A range of this suite's own, wide enough for every test at once.
            proxy_ports: Some(40000..=40063),
            profile: ProfileState::Current,
            seclogon_runs: true,
            in_desktop_session: true,
        }
    }

    fn open_loopback() -> Config {
        let mut config = Config::default();
        config.network.allow_local_binding = Some(true);
        config
    }

    /// A probe that opens nothing, aimed at a port nothing listens on.
    fn no_listener(_: PortRange) -> io::Result<Probe> {
        Ok(Probe {
            target: SocketAddr::from(([127, 0, 0, 1], 9)),
            _open: Box::new(()),
        })
    }

    fn start(
        srt: Fake,
        verified: &Verified,
        status: &WindowsStatus,
        config: &Config,
    ) -> Result<Prepared, StartError> {
        prepare(
            Host {
                srt: Arc::new(srt),
                exe: PathBuf::from(r"C:\crabpot\crabpot.exe"),
                holder: 4242,
            },
            verified,
            status,
            config,
            &no_listener,
        )
    }

    fn verifies(calls: &Calls) -> Vec<Call> {
        calls.starting(&["wfp", "verify"])
    }

    fn verbs(calls: &Calls) -> Vec<String> {
        calls
            .all()
            .iter()
            .map(|call| call.args[..2].join(" "))
            .collect()
    }

    #[test]
    fn wfp_verify_runs_once_per_loopback_mode() {
        let (srt, calls) = Fake::passing();
        let verified = Verified::new();
        let closed = Config::default();

        drop(start(srt, &verified, &status(), &closed).unwrap());
        for _ in 0..2 {
            let (srt, again) = Fake::passing();
            drop(start(srt, &verified, &status(), &closed).unwrap());
            assert!(verifies(&again).is_empty(), "a second start verified again");
        }
        let (srt, open) = Fake::passing();
        drop(start(srt, &verified, &status(), &open_loopback()).unwrap());

        assert_eq!(verifies(&calls).len(), 1);
        let second = verifies(&open);
        assert_eq!(second.len(), 1);
        assert!(second[0].args.contains(&"--allow-loopback".to_owned()));
    }

    #[test]
    fn an_outdated_profile_grant_is_an_error() {
        let (srt, calls) = Fake::passing();
        let outdated = WindowsStatus {
            profile: ProfileState::Outdated,
            ..status()
        };

        let error = start(srt, &Verified::new(), &outdated, &Config::default()).unwrap_err();

        assert_eq!(
            error,
            StartError::ProfileGrantOutdated {
                state: ProfileState::Outdated
            }
        );
        assert!(
            calls.all().is_empty(),
            "nothing is granted: {:?}",
            calls.all()
        );
    }

    #[test]
    fn the_proxy_range_is_the_installed_one_or_the_default() {
        let (srt, _) = Fake::passing();
        let installed = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();
        let (srt, _) = Fake::passing();
        let unread = WindowsStatus {
            proxy_ports: None,
            ..status()
        };
        let default = start(srt, &Verified::new(), &unread, &Config::default()).unwrap();

        assert_eq!(installed.range, PortRange::new(40000, 40063).unwrap());
        assert_eq!(default.range, PortRange::DEFAULT);
    }

    #[test]
    fn no_profile_grant_starts() {
        let (srt, _) = Fake::passing();
        let none = WindowsStatus {
            profile: ProfileState::None,
            ..status()
        };

        start(srt, &Verified::new(), &none, &Config::default()).unwrap();
    }

    #[test]
    fn a_status_with_no_sandbox_sid_is_a_failed_status() {
        let (srt, _) = Fake::passing();
        let no_sid = WindowsStatus {
            sandbox_sid: None,
            ..status()
        };

        let error = start(srt, &Verified::new(), &no_sid, &Config::default()).unwrap_err();

        assert_eq!(
            error,
            StartError::StatusFailed {
                command: "user status",
                code: None
            }
        );
    }

    #[test]
    fn the_verify_call_carries_the_target_and_the_restricted_token() {
        let (srt, calls) = Fake::passing();

        drop(start(srt, &Verified::new(), &status(), &Config::default()).unwrap());

        assert_eq!(
            verifies(&calls)[0].args,
            [
                "wfp",
                "verify",
                "--target",
                "127.0.0.1:9",
                "--write-restricted-token"
            ]
        );
    }

    #[test]
    fn the_grant_is_made_once_for_the_sandbox_user_and_this_process() {
        let (srt, calls) = Fake::passing();

        let session = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        let grants = calls.starting(&["acl", "grant"]);
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0].args,
            [
                "acl",
                "grant",
                "--holder-pid",
                "4242",
                "--sandbox-user-sid",
                "S-1-5-21-7",
                "--persistent"
            ]
        );
        drop(session);
    }

    #[test]
    fn a_failed_grant_is_an_error_and_releases_what_landed() {
        let (srt, calls) = Fake::answering(|call| {
            if call
                .args
                .starts_with(&["acl".to_owned(), "grant".to_owned()])
            {
                exit(2, "")
            } else {
                exit(0, "[]")
            }
        });

        let error = start(srt, &Verified::new(), &status(), &Config::default()).unwrap_err();

        assert_eq!(error, StartError::GrantFailed { code: Some(2) });
        assert_eq!(verbs(&calls), ["acl grant", "acl revoke", "acl restore"]);
    }

    #[test]
    fn an_inactive_fence_is_an_error_and_releases_the_grant() {
        let (srt, calls) = Fake::answering(|call| {
            if call
                .args
                .starts_with(&["wfp".to_owned(), "verify".to_owned()])
            {
                exit(3, r#"{"egress_probe":"connected"}"#)
            } else {
                exit(0, "[]")
            }
        });
        let verified = Verified::new();

        let error = start(srt, &verified, &status(), &Config::default()).unwrap_err();

        assert!(matches!(error, StartError::FenceInactive { .. }), "{error}");
        assert_eq!(
            verbs(&calls),
            ["acl grant", "wfp verify", "acl revoke", "acl restore"]
        );
        assert!(
            !verified.holds("S-1-5-21-7", false),
            "a failure is not remembered"
        );
    }

    #[test]
    fn dropping_a_session_revokes_then_restores() {
        let (srt, calls) = Fake::passing();
        let session = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        drop(session);

        let all = calls.all();
        let [.., revoke, restore] = all.as_slice() else {
            panic!("calls: {all:?}");
        };
        let release = |verb: &str| {
            ["acl", verb, "--holder-pid", "4242"]
                .into_iter()
                .chain(["--sandbox-user-sid", "S-1-5-21-7", "--json"])
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(revoke.args, release("revoke"));
        assert_eq!(restore.args, release("restore"));
    }

    #[test]
    fn a_revoke_that_did_not_finish_leaves_the_denies_in_place() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(1, r#"[{"path":"C:\\work","status":"pending"}]"#),
            "verify" => exit(0, BLOCKED),
            _ => exit(0, "[]"),
        });
        let session = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        drop(session);

        assert!(calls.starting(&["acl", "restore"]).is_empty());
    }

    #[test]
    fn a_revoke_that_found_a_substituted_path_is_finished() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(0, r#"[{"path":"C:\\work","status":"mismatch"}]"#),
            "verify" => exit(0, BLOCKED),
            _ => exit(0, "[]"),
        });
        let session = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        drop(session);

        assert_eq!(calls.starting(&["acl", "restore"]).len(), 1);
    }

    #[test]
    fn a_revoke_that_printed_an_unknown_status_is_not_finished() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(0, r#"[{"path":"C:\\work","status":"somethingNew"}]"#),
            "verify" => exit(0, BLOCKED),
            _ => exit(0, "[]"),
        });
        let session = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        drop(session);

        assert!(calls.starting(&["acl", "restore"]).is_empty());
    }
}
