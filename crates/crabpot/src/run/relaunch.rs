//! Making a launch again when bwrap fails before the helper starts.

#[cfg(target_os = "linux")]
use std::process::Command;

use super::REFUSED;
#[cfg(target_os = "linux")]
use super::{ForwardTarget, execute, user_command};
#[cfg(target_os = "linux")]
use crate::args::Invocation;
#[cfg(target_os = "linux")]
use crate::sandbox::Sandbox;

/// How many more times a launch is made after bwrap fails before the helper
/// starts, for a sandbox whose `network.allowUnixSockets` list has masks.
#[cfg(target_os = "linux")]
const RELAUNCHES: usize = 2;

/// What one launch came to.
pub(super) struct Ran {
    /// The status the wrapper would exit with.
    pub(super) status: i32,
    /// Whether the helper never reported starting, so the command never ran.
    pub(super) unstarted: bool,
}

/// Makes `launch` until the command starts, at most `1 + extra` times, and
/// returns the status of the last one.
///
/// The masks of a socket list are made from the sockets the host holds when the
/// command is wrapped, and a socket that goes away before bwrap mounts over it
/// fails the launch before the helper runs (see the `unix_sockets` section of
/// `crabpot-linux`). Nothing of the command has run then, so a launch made
/// again with the masks made afresh costs nothing but time. A command that
/// started and exited 125 is not made again, nor is any other status.
///
/// `launch` gives `Err` when it cannot make another one, which ends the loop
/// with the status of the launch before.
pub(super) fn relaunching(extra: usize, mut launch: impl FnMut() -> Result<Ran, ()>) -> i32 {
    let mut last = REFUSED;
    for _ in 0..=extra {
        let Ok(ran) = launch() else { break };
        if !(ran.status == REFUSED && ran.unstarted) {
            return ran.status;
        }
        last = ran.status;
    }
    last
}

/// [`execute`] for a command wrapped in bwrap, made again when the helper never
/// started and the sandbox's socket masks may be why: see [`relaunching`].
#[cfg(target_os = "linux")]
pub(super) fn execute_relaunching(
    sandbox: &Sandbox,
    invocation: &Invocation,
    command: Command,
    target: ForwardTarget,
) -> i32 {
    let extra = if sandbox.lists_unix_sockets() {
        RELAUNCHES
    } else {
        0
    };
    let mut next = Some((command, target));
    relaunching(extra, || {
        let (mut command, target) = match next.take() {
            Some(launch) => launch,
            None => {
                eprintln!("crabpot: bwrap did not start; making the socket masks again");
                let (command, info, startup) = sandbox
                    .command_reporting(&user_command(invocation))
                    .map_err(|_| ())?;
                (command, ForwardTarget::Helper { info, startup })
            }
        };
        crabpot_linux::helper::hold_signals(&mut command);
        let status = execute(command, target.clone());
        Ok(Ran {
            status,
            unstarted: target.unstarted(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A launch that ran with `status`, and whether the helper never started.
    fn ran(status: i32, unstarted: bool) -> Result<Ran, ()> {
        Ok(Ran { status, unstarted })
    }

    /// The launches `relaunching` makes of `launches`, and the status it gives.
    fn relaunched(extra: usize, launches: &[Result<Ran, ()>]) -> (usize, i32) {
        let mut made = 0;
        let status = relaunching(extra, || {
            let launch = &launches[made];
            made += 1;
            match launch {
                Ok(ran) => Ok(Ran {
                    status: ran.status,
                    unstarted: ran.unstarted,
                }),
                Err(()) => Err(()),
            }
        });
        (made, status)
    }

    #[test]
    fn a_launch_that_started_is_made_once() {
        assert_eq!(relaunched(2, &[ran(0, false)]), (1, 0));
    }

    #[test]
    fn a_command_that_started_and_exited_125_is_not_made_again() {
        assert_eq!(relaunched(2, &[ran(REFUSED, false)]), (1, REFUSED));
    }

    #[test]
    fn a_launch_that_never_started_is_made_again_until_one_does() {
        let launches = [ran(REFUSED, true), ran(REFUSED, true), ran(7, false)];

        assert_eq!(relaunched(2, &launches), (3, 7));
    }

    #[test]
    fn a_launch_that_never_starts_is_made_one_time_more_than_extra() {
        let launches = [ran(REFUSED, true), ran(REFUSED, true), ran(REFUSED, true)];

        assert_eq!(relaunched(2, &launches), (3, REFUSED));
    }

    #[test]
    fn no_extra_launch_is_made_without_a_socket_list() {
        assert_eq!(relaunched(0, &[ran(REFUSED, true)]), (1, REFUSED));
    }

    #[test]
    fn a_launch_that_cannot_be_made_ends_with_the_status_before_it() {
        let launches = [ran(REFUSED, true), Err(())];

        assert_eq!(relaunched(2, &launches), (2, REFUSED));
    }
}
