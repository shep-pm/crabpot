//! The one Windows call crabpot's own code makes: which session a process is
//! in. srt-win's copy of it is private to `winsta.rs`.

#![allow(unsafe_code)]

use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

/// The session `pid` runs in, or `None` when the call fails.
pub(super) fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is a live `u32` the call writes through for its
    // duration, and `pid` is a plain value the call only reads.
    let found = unsafe { ProcessIdToSessionId(pid, &mut session) };
    (found != 0).then_some(session)
}
