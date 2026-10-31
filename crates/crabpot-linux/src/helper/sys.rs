//! The helper's calls that nix has no safe form of.
//!
//! This is one of the crate's two modules of FFI (IR-22); the other opens the
//! args file.

#![allow(unsafe_code)]

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::errno::Errno;
use nix::net::if_::if_nametoindex;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, kill, sigaction};
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, sendto,
    socket,
};
use nix::unistd::{self, ForkResult, Pid};

/// The process the installed handler passes a signal to, or 0 for none.
static FORWARD_TO: AtomicI32 = AtomicI32::new(0);

/// Brings up `lo` in the calling process's network namespace.
pub(super) fn loopback_up() -> Result<(), Errno> {
    let index = if_nametoindex("lo")?;
    // `ifinfomsg`: family, padding, type, index, flags, changed flags.
    let mut link = vec![0; 4];
    link.extend_from_slice(&index.to_ne_bytes());
    link.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    link.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    netlink_request(libc::RTM_NEWLINK, 0, &link)
}

/// Adds `address` to `lo` as a host route, ready for immediate binding.
pub(super) fn add_loopback(address: IpAddr) -> Result<(), Errno> {
    let (family, prefix, octets) = match address {
        IpAddr::V4(address) => (libc::AF_INET, 32, address.octets().to_vec()),
        IpAddr::V6(address) => (libc::AF_INET6, 128, address.octets().to_vec()),
    };
    // `ifaddrmsg`: family, prefix, flags, scope, index. No IPv6 DAD wait on isolated loopback.
    let mut addr = vec![family as u8, prefix, libc::IFA_F_NODAD as u8, 0];
    addr.extend_from_slice(&if_nametoindex("lo")?.to_ne_bytes());
    for kind in [libc::IFA_LOCAL, libc::IFA_ADDRESS] {
        // Both address lengths make the attribute a multiple of netlink's four-byte alignment.
        addr.extend_from_slice(&((4 + octets.len()) as u16).to_ne_bytes());
        addr.extend_from_slice(&kind.to_ne_bytes());
        addr.extend_from_slice(&octets);
    }
    netlink_request(
        libc::RTM_NEWADDR,
        libc::NLM_F_CREATE | libc::NLM_F_EXCL,
        &addr,
    )
}

fn netlink_request(kind: u16, flags: i32, payload: &[u8]) -> Result<(), Errno> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
    let header_len = size_of::<libc::nlmsghdr>();
    let mut request = Vec::new();
    request.extend_from_slice(&((header_len + payload.len()) as u32).to_ne_bytes());
    request.extend_from_slice(&kind.to_ne_bytes());
    request
        .extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK | flags) as u16).to_ne_bytes());
    request.extend_from_slice(&1_u32.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(payload);
    sendto(
        fd.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )?;

    // This unicast socket requests only acknowledgements, each with a signed error after its header.
    let mut reply = [0; 256];
    let len = recv(fd.as_raw_fd(), &mut reply, MsgFlags::empty())?;
    if len < header_len + 4 || u16::from_ne_bytes([reply[4], reply[5]]) != libc::NLMSG_ERROR as u16
    {
        return Err(Errno::EPROTO);
    }
    let code = i32::from_ne_bytes([
        reply[header_len],
        reply[header_len + 1],
        reply[header_len + 2],
        reply[header_len + 3],
    ]);
    if code == 0 {
        Ok(())
    } else {
        Err(Errno::from_raw(-code))
    }
}

/// Splits this process in two, as `fork(2)` does.
pub(super) fn fork() -> Result<ForkResult, Errno> {
    // SAFETY: `fork` is unsafe because a child of a multithreaded process may
    // meet a lock another thread held. The helper is entered first thing in
    // `main` (`run_from_args`), before the host starts a thread, and starts
    // none itself, so there is no other thread to hold one.
    unsafe { unistd::fork() }
}

/// Empties this process's ambient capability set, which a command would
/// inherit across `exec` as permitted and effective.
pub(super) fn clear_ambient_capabilities() -> Result<(), Errno> {
    // SAFETY: `PR_CAP_AMBIENT_CLEAR_ALL` takes no pointer and no descriptor,
    // and the three arguments after it must be zero. `prctl` reads its
    // arguments as `unsigned long`, so each is passed as one.
    let result = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    Errno::result(result).map(drop)
}

extern "C" fn forward(number: c_int) {
    let target = FORWARD_TO.load(Ordering::Relaxed);
    if let Ok(signal) = Signal::try_from(number) {
        // Nothing to do if the target is gone: the caller is about to see it end.
        let _ = kill(Pid::from_raw(target), signal);
    }
}

/// Passes each of `signals`, when this process gets it, on to `child`.
pub(super) fn forward_signals(child: Pid, signals: &[Signal]) -> Result<(), Errno> {
    FORWARD_TO.store(child.as_raw(), Ordering::Relaxed);
    let action = SigAction::new(
        SigHandler::Handler(forward),
        SaFlags::empty(),
        SigSet::all(),
    );
    for &signal in signals {
        // SAFETY: `forward` only loads an atomic and calls `kill`, which is
        // async-signal-safe, so it is sound to run in the middle of any other
        // code. The target is stored before the first handler is installed.
        unsafe { sigaction(signal, &action) }?;
    }
    Ok(())
}

/// Has `command`'s child start with `signals` blocked, which survives the
/// `exec` into the program it runs.
pub(super) fn block_in_child(command: &mut Command, signals: SigSet) {
    // SAFETY: the closure runs in the forked child before `exec`, where only
    // async-signal-safe calls are sound. `thread_block` is one `pthread_sigmask`
    // call on a set copied in, and the error conversion allocates nothing.
    unsafe {
        command.pre_exec(move || signals.thread_block().map_err(io::Error::from));
    }
}

/// Has `command`'s child hold `fd` as descriptor `target`, which survives the
/// `exec` into the program it runs. The parent's copy closes with `command`.
pub(crate) fn pass_in_child(command: &mut Command, fd: OwnedFd, target: u32) {
    let target = RawFd::try_from(target).unwrap_or(RawFd::MAX);
    // SAFETY: the closure runs in the forked child before `exec`, where only
    // async-signal-safe calls are sound. `dup2` and `fcntl` are, and neither
    // allocates. `dup2` leaves the copy open across `exec`; when `fd` already
    // is `target` it does nothing, so the close-on-exec flag is cleared by hand.
    unsafe {
        command.pre_exec(move || {
            let raw = fd.as_raw_fd();
            let moved = if raw == target {
                libc::fcntl(raw, libc::F_SETFD, 0)
            } else {
                libc::dup2(raw, target)
            };
            if moved < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
