//! Starting a Windows session, as upstream's `initialize`
//! (`src/sandbox/sandbox-manager.ts`) does once the status checks have passed:
//! the profile grant is read, the session's grants are made, the fence is
//! verified, and the proxy starts in the range the fence permits.

use core::any::Any;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};

use crabpot_core::config::Config;
use crabpot_core::proxy::{PortRange, Proxy, RangeError};

use super::command::{self, Params};
use super::held::Held;
use super::plan::Plan;
use super::runner::Runner;
use super::srt::{Call, Srt};
use super::status::{LoopbackMode, ProfileState, WindowsStatus};
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

/// What a session is started from: the calls to srt-win, the binary the
/// sandbox user has to be able to read, and the process the grants are held
/// for.
pub(crate) struct Host {
    pub(crate) srt: Arc<dyn Srt>,
    pub(crate) holder: u32,
    pub(crate) runner: Runner,
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
/// Those of [`prepare`], then [`StartError::ProxyRangeFull`] when every port of
/// the proxy port range is taken, and [`StartError::Proxy`] for the other ways
/// the proxy cannot start, which releases the grants.
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
/// SID, [`StartError::LoopbackMismatch`] for a session whose
/// `network.allowLocalBinding` is not the loopback mode the install made,
/// [`StartError::RunnerUnreadable`] for a runner the sandbox user cannot read,
/// [`StartError::ProfileConflicts`] for a grant that meets the profile read
/// grant's exclusions, [`StartError::GrantBlocked`], [`StartError::ProfileBusy`]
/// or [`StartError::GrantFailed`] when the grant call fails,
/// [`StartError::ProxyRangeRefused`] for a proxy port range the install reports
/// or the settings name that is no range at all, and the errors of
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
        stderr: String::new(),
    })?;
    // The loopback mode is the install's, not the session's: a session that
    // asks for the other is refused here, before anything is granted. `srt-win
    // exec` refuses it too, as exit 19, and so does `wfp verify` for an install
    // whose filters have drifted from what `wfp status` reported.
    let allow_loopback = config.network.allow_local_binding == Some(true);
    if allow_loopback != (status.loopback == LoopbackMode::Open) {
        return Err(StartError::LoopbackMismatch);
    }
    // Before anything is granted, and before anything runs as the sandbox user:
    // seclogon answers an unreadable runner with a message about the service,
    // and the grant that would open a runner under the profile is the install's
    // to make.
    if !host.runner.readable() {
        return Err(StartError::RunnerUnreadable);
    }
    let plan = Plan::build(config, &status.profile_exclusions)?;
    // The range the install's filters name, which the fence probe must stay
    // outside of, and the range the proxy binds: the configured one first, as
    // upstream binds its proxies, then the installed one.
    let installed = match &status.proxy_ports {
        Some(ports) => named_range(*ports.start(), *ports.end())?,
        None => PortRange::DEFAULT,
    };
    let range = match config.windows.proxy_port_range {
        Some([first, last]) => named_range(first, last)?,
        None => installed,
    };

    // Held before the call, so that a grant that landed in part is released.
    let held = Held {
        srt: host.srt,
        sid,
        holder: host.holder,
    };
    plan.apply(&*held.srt, &held.sid, held.holder)?;
    if !verified.holds(&held.sid, allow_loopback) {
        verify(&*held.srt, &plan, allow_loopback, listen(installed))?;
        verified.record(&held.sid, allow_loopback);
    }
    Ok(Prepared {
        held,
        exe: host.runner.exe,
        plan,
        allow_loopback,
        range,
    })
}

impl Prepared {
    /// Starts the proxy in `self.range`, which releases the grants when it
    /// cannot.
    ///
    /// # Errors
    ///
    /// [`StartError::ProxyRangeFull`] when every port of the range is taken, and
    /// [`StartError::Proxy`] for the other ways the proxy cannot start.
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
        .map_err(|e| match e {
            RangeError::Full(range) => StartError::ProxyRangeFull {
                first: range.first(),
                last: range.last(),
            },
            other => StartError::Proxy(io::Error::from(other).kind()),
        })?;
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

/// The range `first..=last`, or the [`StartError`] that names it as a range the
/// proxy cannot bind in.
fn named_range(first: u16, last: u16) -> Result<PortRange, StartError> {
    // `RangeError` is `non_exhaustive`: a refusal this build does not know of
    // is a range the proxy cannot bind in either.
    PortRange::new(first, last).map_err(|_| StartError::ProxyRangeRefused { first, last })
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
    use core::sync::atomic::{AtomicU16, Ordering};
    use std::net::Ipv4Addr;

    use super::*;
    use crate::windows::srt::fake::{Calls, Fake, exit, fail};
    use crate::windows::status::{LoopbackMode, ProfileExclusions, SetupVersion, UserState};

    /// Where the next window of ports to hold is looked for, so that tests
    /// running together do not hold the same ports.
    static NEXT_PORT: AtomicU16 = AtomicU16::new(20_000);

    fn status() -> WindowsStatus {
        WindowsStatus {
            user: UserState::Provisioned,
            sandbox_sid: Some("S-1-5-21-7".to_owned()),
            sandbox_group_sid: Some("S-1-5-21-9".to_owned()),
            real_user_sid: Some("S-1-5-21-2".to_owned()),
            session_user_sid: Some("S-1-5-21-2".to_owned()),
            setup_version: SetupVersion {
                installed: Some(3),
                expected: 3,
            },
            loopback: LoopbackMode::Closed,
            // A range of this suite's own, wide enough for every test at once.
            proxy_ports: Some(40000..=40063),
            profile: ProfileState::Current,
            profile_exclusions: ProfileExclusions::default(),
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
        start_under(srt, runner(), verified, status, config)
    }

    fn start_under(
        srt: Fake,
        runner: Runner,
        verified: &Verified,
        status: &WindowsStatus,
        config: &Config,
    ) -> Result<Prepared, StartError> {
        prepare(
            Host {
                srt: Arc::new(srt),
                holder: 4242,
                runner,
            },
            verified,
            status,
            config,
            &no_listener,
        )
    }

    /// A runner the sandbox user can read on its own: its access list names the
    /// sandbox account, its group, or one of the groups of its token as able to
    /// read and execute it, and no profile grant is needed for it.
    fn runner() -> Runner {
        Runner {
            exe: PathBuf::from(r"C:\crabpot\crabpot.exe"),
            dacl_allows: Some(true),
        }
    }

    /// A runner under the profile whose own access list carries nothing for the
    /// sandbox: the grant has not reached it.
    fn runner_the_grant_never_reached() -> Runner {
        Runner {
            exe: PathBuf::from(r"C:\Users\me\.cargo\bin\crabpot.exe"),
            dacl_allows: Some(false),
        }
    }

    /// A status whose install was made with `--allow-loopback`.
    fn open_install() -> WindowsStatus {
        WindowsStatus {
            loopback: LoopbackMode::Open,
            ..status()
        }
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
        drop(start(srt, &verified, &open_install(), &open_loopback()).unwrap());

        assert_eq!(verifies(&calls).len(), 1);
        let second = verifies(&open);
        assert_eq!(second.len(), 1);
        assert!(second[0].args.contains(&"--allow-loopback".to_owned()));
    }

    #[test]
    fn local_binding_needs_a_loopback_install() {
        let (srt, calls) = Fake::passing();

        let error = start(srt, &Verified::new(), &status(), &open_loopback()).unwrap_err();

        assert_eq!(error, StartError::LoopbackMismatch);
        assert!(
            calls.all().is_empty(),
            "nothing is granted: {:?}",
            calls.all()
        );
    }

    #[test]
    fn a_loopback_install_refuses_a_closed_session() {
        let (srt, calls) = Fake::passing();

        let error = start(srt, &Verified::new(), &open_install(), &Config::default()).unwrap_err();

        assert_eq!(error, StartError::LoopbackMismatch);
        assert!(
            calls.all().is_empty(),
            "nothing is granted: {:?}",
            calls.all()
        );
    }

    #[test]
    fn exit_19_maps_to_the_loopback_mismatch_error() {
        let (srt, calls) = Fake::answering(|call| {
            if call
                .args
                .starts_with(&["wfp".to_owned(), "verify".to_owned()])
            {
                exit(
                    19,
                    r#"{"egress_probe":"not-run","allow_loopback_mismatch":true}"#,
                )
            } else {
                exit(0, "[]")
            }
        });
        let verified = Verified::new();

        let error = start(srt, &verified, &status(), &Config::default()).unwrap_err();

        assert_eq!(error, StartError::LoopbackMismatch);
        assert_eq!(
            verbs(&calls),
            ["acl grant", "wfp verify", "acl revoke", "acl restore"]
        );
        assert!(
            !verified.holds("S-1-5-21-7", false),
            "a failure is not remembered"
        );
    }

    /// The mode a session hands `command`, and so the `--allow-loopback` flag
    /// `srt-win exec` is launched under: the one the session asked for and the
    /// install has, which is the one `wfp verify` was verified under.
    #[test]
    fn a_session_carries_the_agreed_loopback_mode() {
        let (srt, open_calls) = Fake::passing();
        let open = start(srt, &Verified::new(), &open_install(), &open_loopback()).unwrap();
        let (srt, closed_calls) = Fake::passing();
        let closed = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        assert!(open.allow_loopback, "an open install and an open session");
        assert!(
            !closed.allow_loopback,
            "a closed install and a closed session"
        );
        assert!(
            verifies(&open_calls)[0]
                .args
                .contains(&"--allow-loopback".to_owned())
        );
        assert!(
            !verifies(&closed_calls)[0]
                .args
                .contains(&"--allow-loopback".to_owned()),
            "a closed session's verify carries no flag"
        );
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
    fn the_proxy_range_comes_from_the_installed_range() {
        let (srt, _) = Fake::passing();

        let prepared = start(srt, &Verified::new(), &status(), &Config::default()).unwrap();

        assert_eq!(prepared.range, PortRange::new(40000, 40063).unwrap());
    }

    #[test]
    fn the_proxy_range_is_the_default_when_the_install_reports_none() {
        let (srt, _) = Fake::passing();
        let unread = WindowsStatus {
            proxy_ports: None,
            ..status()
        };

        let prepared = start(srt, &Verified::new(), &unread, &Config::default()).unwrap();

        assert_eq!(prepared.range, PortRange::DEFAULT);
    }

    #[test]
    fn a_configured_proxy_range_wins_over_the_installed_one() {
        let (srt, _) = Fake::passing();
        let mut config = Config::default();
        config.windows.proxy_port_range = Some([41000, 41009]);

        let prepared = start(srt, &Verified::new(), &status(), &config).unwrap();

        assert_eq!(prepared.range, PortRange::new(41000, 41009).unwrap());
    }

    #[test]
    fn the_fence_probe_stays_outside_the_installed_range_not_the_configured_one() {
        let (srt, _) = Fake::passing();
        let mut config = Config::default();
        config.windows.proxy_port_range = Some([41000, 41009]);
        let asked = std::cell::Cell::new(None);
        let listen = |range: PortRange| {
            asked.set(Some(range));
            no_listener(range)
        };

        prepare(
            Host {
                srt: Arc::new(srt),
                holder: 4242,
                runner: runner(),
            },
            &Verified::new(),
            &status(),
            &config,
            &listen,
        )
        .unwrap();

        assert_eq!(asked.get(), Some(PortRange::new(40000, 40063).unwrap()));
    }

    #[test]
    fn a_configured_proxy_range_wider_than_the_proxy_takes_is_an_error() {
        let (srt, calls) = Fake::passing();
        let mut config = Config::default();
        config.windows.proxy_port_range = Some([1, 65]);

        let error = start(srt, &Verified::new(), &status(), &config).unwrap_err();

        assert_eq!(error, StartError::ProxyRangeRefused { first: 1, last: 65 });
        assert!(error.to_string().contains("1-65"), "{error}");
        assert!(calls.all().is_empty(), "nothing is granted");
    }

    /// An install whose filters name a range that starts at port 0 is no range
    /// the proxy can bind in, and the session says so before it grants anything.
    #[test]
    fn an_installed_range_that_starts_at_port_0_is_an_error() {
        let (srt, calls) = Fake::passing();
        let zero = WindowsStatus {
            proxy_ports: Some(0..=10),
            ..status()
        };

        let error = start(srt, &Verified::new(), &zero, &Config::default()).unwrap_err();

        assert_eq!(error, StartError::ProxyRangeRefused { first: 0, last: 10 });
        assert!(error.to_string().contains("0-10"), "{error}");
        assert!(calls.all().is_empty(), "nothing is granted");
    }

    /// A range of `width` ports, each one held by a listener this test opens, so
    /// the proxy has none of them left to bind.
    fn held_range(width: u16) -> (PortRange, Vec<TcpListener>) {
        loop {
            let first = NEXT_PORT.fetch_add(width, Ordering::Relaxed);
            let last = first + width - 1;
            let held: Result<Vec<TcpListener>, io::Error> = (first..=last)
                .map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)))
                .collect();
            match held {
                Ok(held) => return (PortRange::new(first, last).unwrap(), held),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("cannot hold {first}-{last}: {error}"),
            }
        }
    }

    #[test]
    fn a_full_range_names_the_range_and_the_flag() {
        let (range, _held) = held_range(2);
        let (srt, calls) = Fake::passing();
        let mut config = Config::default();
        config.windows.proxy_port_range = Some([range.first(), range.last()]);

        let error = start_with(
            Host {
                srt: Arc::new(srt),
                holder: 4242,
                runner: runner(),
            },
            &Verified::new(),
            &status(),
            &config,
        )
        .unwrap_err();

        assert!(
            matches!(error, StartError::ProxyRangeFull { first, last }
                if first == range.first() && last == range.last()),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains(&range.to_string()), "{message}");
        assert!(message.contains("--proxy-port-range"), "{message}");
        assert_eq!(
            verbs(&calls),
            ["acl grant", "wfp verify", "acl revoke", "acl restore"],
            "the grant is released once the proxy is refused"
        );
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

    /// A crabpot under the profile is what `cargo install` puts there, and what
    /// kelpie's binary is. The sandbox user cannot read it without the profile
    /// read grant, and seclogon answers that with a message about the service
    /// instead of about the binary.
    #[test]
    fn an_unreadable_runner_is_refused_by_name() {
        let (srt, calls) = Fake::passing();

        let error = start_under(
            srt,
            runner_the_grant_never_reached(),
            &Verified::new(),
            &status(),
            &Config::default(),
        )
        .unwrap_err();

        assert_eq!(error, StartError::RunnerUnreadable);
        assert!(
            calls.all().is_empty(),
            "nothing is granted: {:?}",
            calls.all()
        );
    }

    #[test]
    fn a_runner_the_grant_reached_starts() {
        let (srt, _) = Fake::passing();
        let granted = Runner {
            dacl_allows: Some(true),
            ..runner_the_grant_never_reached()
        };

        drop(
            start_under(
                srt,
                granted,
                &Verified::new(),
                &status(),
                &Config::default(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn a_runner_check_the_machine_could_not_make_refuses_nothing() {
        let (srt, _) = Fake::passing();
        let unread = Runner {
            dacl_allows: None,
            ..runner_the_grant_never_reached()
        };

        drop(start_under(srt, unread, &Verified::new(), &status(), &Config::default()).unwrap());
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
                code: None,
                stderr: String::new()
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
                fail(2, "deny refused: x")
            } else {
                exit(0, "[]")
            }
        });

        let error = start(srt, &Verified::new(), &status(), &Config::default()).unwrap_err();

        assert_eq!(
            error,
            StartError::GrantFailed {
                code: Some(2),
                stderr: "deny refused: x".to_owned()
            }
        );
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
}
