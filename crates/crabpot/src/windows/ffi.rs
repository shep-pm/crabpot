//! The Windows calls crabpot's own code makes: which session a process is in,
//! and which of the groups the sandbox user will be in can read a file.
//! srt-win's copy of the first is private to `winsta.rs`.

#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE, WinAuthenticatedUserSid, WinBuiltinUsersSid,
    WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_EXECUTE, FILE_READ_DATA};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

/// The session `pid` runs in, or `None` when the call fails.
pub(super) fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is a live `u32` the call writes through for its
    // duration, and `pid` is a plain value the call only reads.
    let found = unsafe { ProcessIdToSessionId(pid, &mut session) };
    (found != 0).then_some(session)
}

/// Whether `path` lets Users, Authenticated Users or Everyone read and
/// execute it, by its DACL. The sandbox user is in the first, and its token
/// holds the other two. `None` when the DACL cannot be read.
pub(super) fn groups_can_read(path: &Path) -> Option<bool> {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call, the two owners
    // and the SACL are not asked for (null), and `dacl` and `descriptor` are
    // live pointers the call writes through. A DACL it returns points into
    // `descriptor`, which is freed below and not before.
    let found = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if found != ERROR_SUCCESS {
        return None;
    }
    // A file with no DACL grants everyone everything.
    let readable = dacl.is_null()
        || [WinBuiltinUsersSid, WinAuthenticatedUserSid, WinWorldSid]
            .into_iter()
            .any(|group| group_can_read(dacl, group));
    // SAFETY: `descriptor` was allocated by `GetNamedSecurityInfoW`, which
    // asks for `LocalFree`, and nothing points into it after this.
    unsafe { LocalFree(descriptor) };
    Some(readable)
}

/// Whether `dacl` grants the well-known group `group` read and execute.
fn group_can_read(dacl: *const ACL, group: WELL_KNOWN_SID_TYPE) -> bool {
    // Words, not bytes: a SID is read as 4-byte aligned.
    let mut sid = [0u32; SECURITY_MAX_SID_SIZE.div_ceil(4) as usize];
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` holds `size` bytes, which the call writes a SID into, and
    // a null domain SID is what a machine-wide group takes.
    let made = unsafe { CreateWellKnownSid(group, null_mut(), sid.as_mut_ptr().cast(), &mut size) };
    if made == 0 {
        return false;
    }
    // SAFETY: `TRUSTEE_W` is plain data, which all-zero bytes are a valid
    // value of, and the call fills it in.
    let mut trustee: TRUSTEE_W = unsafe { core::mem::zeroed() };
    // SAFETY: `trustee` is live, and `sid` stays in place and unchanged for as
    // long as `trustee` is read, which is to the end of this function.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid.as_mut_ptr().cast()) };
    let mut rights = 0u32;
    // SAFETY: `dacl` is the DACL the caller read, still alive, `trustee` was
    // built above, and `rights` is a live `u32` the call writes through.
    let computed = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) };
    computed == ERROR_SUCCESS
        && rights & (FILE_READ_DATA | FILE_EXECUTE) == (FILE_READ_DATA | FILE_EXECUTE)
}
