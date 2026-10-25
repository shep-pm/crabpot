//! The Windows calls crabpot's own code makes: which session a process is in,
//! and which of the groups the sandbox user will be in can read a file.
//! srt-win's copy of the first is private to `winsta.rs`.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertStringSidToSidW, GetEffectiveRightsFromAclW,
    GetNamedSecurityInfoW, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
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

/// Whether the sandbox user can read and execute `path` by its DACL: an ACE for
/// one of the well-known groups its token holds, or for one of `sandbox` (the
/// sandbox account and the group it is in, which is who a grant made for the
/// sandbox names). `None` when the DACL cannot be read, which proves nothing.
pub(super) fn sandbox_can_read(path: &Path, sandbox: &[&str]) -> Option<bool> {
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
            .any(|group| group_can_read(dacl, group))
        || sandbox.iter().any(|sid| sid_can_read(dacl, sid));
    // SAFETY: `descriptor` was allocated by `GetNamedSecurityInfoW`, which
    // asks for `LocalFree`, and nothing points into it after this.
    unsafe { LocalFree(descriptor) };
    Some(readable)
}

/// Whether `dacl` grants the well-known group `group` read and execute.
fn group_can_read(dacl: *const ACL, group: WELL_KNOWN_SID_TYPE) -> bool {
    group_rights(dacl, group).is_some_and(read_exec)
}

/// The mask `dacl` answers for the well-known group `group`: `None` when the
/// group has no SID on this machine, or the call gives no answer.
fn group_rights(dacl: *const ACL, group: WELL_KNOWN_SID_TYPE) -> Option<u32> {
    // Words, not bytes: a SID is read as 4-byte aligned.
    let mut sid = [0u32; SECURITY_MAX_SID_SIZE.div_ceil(4) as usize];
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` holds `size` bytes, which the call writes a SID into, and
    // a null domain SID is what a machine-wide group takes.
    let made = unsafe { CreateWellKnownSid(group, null_mut(), sid.as_mut_ptr().cast(), &mut size) };
    if made == 0 {
        return None;
    }
    trustee_rights(dacl, sid.as_mut_ptr().cast())
}

/// Whether `dacl` grants the account or group whose SID string is `sid` read and
/// execute. A grant made for the sandbox is made for its account or its group,
/// and neither is one of the well-known groups, so a runner in a folder granted
/// to the sandbox alone reads as unreadable without this.
fn sid_can_read(dacl: *const ACL, sid: &str) -> bool {
    sid_rights(dacl, sid).is_some_and(read_exec)
}

/// The mask `dacl` answers for the account or group whose SID string is `sid`:
/// `None` when `sid` is no SID, or the call gives no answer.
fn sid_rights(dacl: *const ACL, sid: &str) -> Option<u32> {
    let name: Vec<u16> = OsStr::new(sid).encode_wide().chain([0]).collect();
    let mut psid: PSID = null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call, and `psid` is a
    // live pointer the call writes an allocated SID into.
    let made = unsafe { ConvertStringSidToSidW(name.as_ptr(), &mut psid) };
    if made == 0 {
        return None;
    }
    let rights = trustee_rights(dacl, psid);
    // SAFETY: `psid` was allocated by `ConvertStringSidToSidW`, which asks for
    // `LocalFree`, and nothing reads it after this.
    unsafe { LocalFree(psid) };
    rights
}

/// The mask `dacl` answers for the account or group `psid` names, `None` where
/// the call gives no answer.
fn trustee_rights(dacl: *const ACL, psid: PSID) -> Option<u32> {
    // SAFETY: `TRUSTEE_W` is plain data, which all-zero bytes are a valid
    // value of, and the call fills it in.
    let mut trustee: TRUSTEE_W = unsafe { core::mem::zeroed() };
    // SAFETY: `trustee` is live, and `psid` stays valid for as long as
    // `trustee` is read, which is to the end of this function.
    unsafe { BuildTrusteeWithSidW(&mut trustee, psid) };
    let mut rights = 0u32;
    // SAFETY: `dacl` is the DACL the caller read, still alive, `trustee` was
    // built above, and `rights` is a live `u32` the call writes through.
    let computed = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) };
    (computed == ERROR_SUCCESS).then_some(rights)
}

/// Whether an access mask holds read and execute.
///
/// `GetEffectiveRightsFromAclW` reports the mask of the ACEs that answer for the
/// trustee and maps nothing back, and a Windows run of this module's tests shows
/// that an ACE written in the generic rights answers as no rights at all. srt-win's
/// own grants are safe: its `FILE_GENERIC_READ` and `FILE_GENERIC_EXECUTE` are
/// already the mapped combinations, which hold `FILE_READ_DATA` and
/// `FILE_EXECUTE`. A folder opened to crabpot by a tool that wrote generic rights
/// reads as unreadable here, and the profile half of `Runner::readable` is what
/// saves it.
fn read_exec(rights: u32) -> bool {
    rights & FILE_READ_DATA != 0 && rights & FILE_EXECUTE != 0
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
    use windows_sys::Win32::Security::{
        ACL_REVISION, AddAccessAllowedAceEx, AddAccessDeniedAceEx, InitializeAcl,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

    use super::*;

    /// An account-shaped SID that is none of the three groups the check asks.
    const LOCAL_SERVICE: &str = "S-1-5-19";
    /// The group a grant to "Everyone" names.
    const EVERYONE: &str = "S-1-1-0";
    /// Read and execute, as srt-win writes it.
    const READ_EXEC: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

    /// A DACL held in memory words, so no test asks about a file of the machine
    /// it runs on. Each entry is `(deny, mask, SID string)`.
    fn dacl(aces: &[(bool, u32, &str)]) -> Vec<u32> {
        // Words, because an ACL and an ACE are 4-byte aligned, and 1024 bytes
        // is more than these few ACEs need.
        let mut buf = vec![0u32; 256];
        let dacl: *mut ACL = buf.as_mut_ptr().cast();
        // SAFETY: `buf` is 4-byte aligned and holds the 1024 bytes the call is
        // told it may write, and `dacl` points into it for every call below.
        assert_ne!(unsafe { InitializeAcl(dacl, 1024, ACL_REVISION) }, 0);
        for (deny, mask, sid) in aces {
            let name: Vec<u16> = OsStr::new(sid).encode_wide().chain([0]).collect();
            let mut psid: PSID = null_mut();
            // SAFETY: `name` is NUL-terminated and outlives the call, and
            // `psid` is a live pointer the call writes an allocated SID into.
            let made = unsafe { ConvertStringSidToSidW(name.as_ptr(), &mut psid) };
            assert_ne!(made, 0, "{sid} is not a SID");
            // SAFETY: `dacl` is the ACL initialized above, still in scope and
            // big enough for one more ACE, and `psid` is a SID the call reads.
            let added = unsafe {
                if *deny {
                    AddAccessDeniedAceEx(dacl, ACL_REVISION, 0, *mask, psid)
                } else {
                    AddAccessAllowedAceEx(dacl, ACL_REVISION, 0, *mask, psid)
                }
            };
            assert_ne!(added, 0, "no ACE is added for {sid}");
            // SAFETY: `psid` was allocated by `ConvertStringSidToSidW`, which
            // asks for `LocalFree`, and the ACE copied the SID out of it.
            unsafe { LocalFree(psid) };
        }
        buf
    }

    /// A mask as Windows wrote it, or `nothing` where the call gave no answer.
    ///
    /// Each assertion names the mask it was answered, because the mask is what
    /// the call reports and a bare `false` says nothing about why.
    fn shown(mask: Option<u32>) -> String {
        mask.map_or("nothing".to_owned(), |m| format!("{m:#010x}"))
    }

    /// The sandbox account and the group a grant for the sandbox names are not
    /// one of the well-known groups, and a folder granted to the sandbox alone
    /// has to answer for it.
    #[test]
    fn a_grant_for_one_account_answers_for_that_account() {
        let buf = dacl(&[(false, READ_EXEC, LOCAL_SERVICE)]);
        let dacl = buf.as_ptr().cast::<ACL>();
        let account = sid_rights(dacl, LOCAL_SERVICE);

        assert!(
            sid_can_read(dacl, LOCAL_SERVICE),
            "{LOCAL_SERVICE} answered {}",
            shown(account)
        );
        for group in [WinBuiltinUsersSid, WinAuthenticatedUserSid, WinWorldSid] {
            let mask = group_rights(dacl, group);
            assert!(
                !group_can_read(dacl, group),
                "{group:?} answered {}",
                shown(mask)
            );
        }
    }

    /// An ACE for Everyone answers for every trustee the check asks, an account
    /// of its own included: Everyone is in every token, and a Windows run showed
    /// the call reading it as a member of the trustee it was given. An ACE for
    /// one account answers for that account and for no group, which is the other
    /// half of this, and is what the test above holds.
    #[test]
    fn a_grant_for_everyone_answers_for_every_trustee() {
        let buf = dacl(&[(false, READ_EXEC, EVERYONE)]);
        let dacl = buf.as_ptr().cast::<ACL>();
        let world = group_rights(dacl, WinWorldSid);
        let account = sid_rights(dacl, LOCAL_SERVICE);

        assert!(
            group_can_read(dacl, WinWorldSid),
            "WinWorldSid answered {}",
            shown(world)
        );
        assert!(
            sid_can_read(dacl, LOCAL_SERVICE),
            "{LOCAL_SERVICE} answered {}",
            shown(account)
        );
    }

    /// A deny for the account takes its rights back, which is what a protected
    /// path has to read as. The same run showed a deny ACE taking the rights
    /// back for a trustee it does not name as well, so the check reads a deny as
    /// an answer and never as noise, and a file carrying one for an account
    /// nobody is asking about reads as unreadable.
    #[test]
    fn a_deny_for_the_account_takes_its_rights_back() {
        let buf = dacl(&[
            (false, READ_EXEC, LOCAL_SERVICE),
            (true, READ_EXEC, LOCAL_SERVICE),
        ]);
        let dacl = buf.as_ptr().cast::<ACL>();
        let account = sid_rights(dacl, LOCAL_SERVICE);

        assert!(
            !sid_can_read(dacl, LOCAL_SERVICE),
            "{LOCAL_SERVICE} answered {}",
            shown(account)
        );
    }

    /// An ACE written in the generic rights answers as no rights at all, which
    /// is what `GetEffectiveRightsFromAclW` reports for a mask it does not map.
    /// A folder opened to crabpot in generic rights is therefore refused, and
    /// the profile half of `Runner::readable` is what saves it.
    #[test]
    fn generic_rights_answer_as_nothing() {
        let buf = dacl(&[(false, GENERIC_READ | GENERIC_EXECUTE, LOCAL_SERVICE)]);
        let dacl = buf.as_ptr().cast::<ACL>();
        let account = sid_rights(dacl, LOCAL_SERVICE);

        assert!(
            !sid_can_read(dacl, LOCAL_SERVICE),
            "{LOCAL_SERVICE} answered {}",
            shown(account)
        );
    }

    /// Reading a file is not running it.
    #[test]
    fn read_data_alone_is_not_read_and_execute() {
        let buf = dacl(&[(false, FILE_READ_DATA, LOCAL_SERVICE)]);
        let dacl = buf.as_ptr().cast::<ACL>();
        let account = sid_rights(dacl, LOCAL_SERVICE);

        assert!(
            !sid_can_read(dacl, LOCAL_SERVICE),
            "{LOCAL_SERVICE} answered {}",
            shown(account)
        );
    }

    /// A SID the machine does not know answers as no grant, and not as a
    /// failure of the check.
    #[test]
    fn a_string_that_is_not_a_sid_grants_nothing() {
        let buf = dacl(&[(false, READ_EXEC, EVERYONE)]);
        let dacl = buf.as_ptr().cast::<ACL>();

        assert!(!sid_can_read(dacl, "nonsense"));
        assert!(sid_can_read(dacl, EVERYONE));
    }
}
