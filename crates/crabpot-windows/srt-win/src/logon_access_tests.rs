use super::{
    dacl_lets_sandbox_read, group_can_read, group_rights, sandbox_can_read, sid_can_read,
    sid_rights, unreadable_runner,
};
use crate::sid::LocalPsid;
use std::path::Path;
use windows::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, ACL_REVISION, AddAccessAllowedAceEx, AddAccessDeniedAceEx, InitializeAcl,
    WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
};
use windows::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_READ_DATA, FILE_WRITE_DATA,
};

/// An account-shaped SID that is none of the three groups the check asks.
const LOCAL_SERVICE: &str = "S-1-5-19";
/// The group a grant to "Everyone" names.
const EVERYONE: &str = "S-1-1-0";
/// The group a grant to "Users" names.
const USERS: &str = "S-1-5-32-545";
/// A sandbox account and its group, as strings a grant for the sandbox names.
const SANDBOX_USER: &str = "S-1-5-21-1-2-3-1001";
const SANDBOX_GROUP: &str = "S-1-5-21-1-2-3-1002";
/// Read and execute, as srt-win writes it.
const READ_EXEC: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

/// A DACL held in memory words, so no test asks about a file of the machine
/// it runs on. Each entry is `(deny, mask, SID string)`.
fn dacl(aces: &[(bool, u32, &str)]) -> Vec<u32> {
    // Words, because an ACL and an ACE are 4-byte aligned, and 1024 bytes
    // is more than these few ACEs need.
    let mut buf = vec![0u32; 256];
    let acl: *mut ACL = buf.as_mut_ptr().cast();
    unsafe { InitializeAcl(acl, 1024, ACL_REVISION) }.unwrap();
    for (deny, mask, sid) in aces {
        let psid = LocalPsid::from_string(sid).unwrap();
        unsafe {
            if *deny {
                AddAccessDeniedAceEx(acl, ACL_REVISION, ACE_FLAGS(0), *mask, psid.as_psid())
            } else {
                AddAccessAllowedAceEx(acl, ACL_REVISION, ACE_FLAGS(0), *mask, psid.as_psid())
            }
        }
        .unwrap();
    }
    buf
}

/// A mask as Windows wrote it, or `nothing` where the call gave no answer.
/// Each assertion names the mask it was answered, because a bare `false`
/// says nothing about why.
fn shown(mask: Option<u32>) -> String {
    mask.map_or("nothing".to_owned(), |m| format!("{m:#010x}"))
}

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

/// Everyone is in every token, and a Windows run showed the call reading
/// the ACE as a grant to the trustee it was given.
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

/// `GetEffectiveRightsFromAclW` maps no generic right, so an ACE written
/// in them answers as no rights at all.
#[test]
fn generic_rights_answer_as_nothing() {
    let buf = dacl(&[(false, GENERIC_READ.0 | GENERIC_EXECUTE.0, LOCAL_SERVICE)]);
    let dacl = buf.as_ptr().cast::<ACL>();
    let account = sid_rights(dacl, LOCAL_SERVICE);

    assert!(
        !sid_can_read(dacl, LOCAL_SERVICE),
        "{LOCAL_SERVICE} answered {}",
        shown(account)
    );
}

#[test]
fn read_data_alone_is_not_read_and_execute() {
    let buf = dacl(&[(false, FILE_READ_DATA.0, LOCAL_SERVICE)]);
    let dacl = buf.as_ptr().cast::<ACL>();
    let account = sid_rights(dacl, LOCAL_SERVICE);

    assert!(
        !sid_can_read(dacl, LOCAL_SERVICE),
        "{LOCAL_SERVICE} answered {}",
        shown(account)
    );
}

#[test]
fn a_string_that_is_not_a_sid_grants_nothing() {
    let buf = dacl(&[(false, READ_EXEC, EVERYONE)]);
    let dacl = buf.as_ptr().cast::<ACL>();

    assert!(!sid_can_read(dacl, "nonsense"));
    assert!(sid_can_read(dacl, EVERYONE));
}

#[test]
fn a_deny_for_the_sandbox_beats_a_grant_to_everyone() {
    let buf = dacl(&[
        (true, READ_EXEC, SANDBOX_USER),
        (false, READ_EXEC, EVERYONE),
    ]);
    let dacl = buf.as_ptr().cast::<ACL>();

    assert!(!dacl_lets_sandbox_read(
        dacl,
        &[SANDBOX_USER, SANDBOX_GROUP]
    ));
}

#[test]
fn a_deny_for_the_sandbox_group_beats_a_grant_to_users() {
    let buf = dacl(&[(true, READ_EXEC, SANDBOX_GROUP), (false, READ_EXEC, USERS)]);
    let dacl = buf.as_ptr().cast::<ACL>();

    assert!(!dacl_lets_sandbox_read(
        dacl,
        &[SANDBOX_USER, SANDBOX_GROUP]
    ));
}

#[test]
fn a_deny_of_write_alone_leaves_a_grant_to_users_standing() {
    let buf = dacl(&[
        (true, FILE_WRITE_DATA.0, SANDBOX_USER),
        (false, READ_EXEC, USERS),
    ]);
    let dacl = buf.as_ptr().cast::<ACL>();

    assert!(dacl_lets_sandbox_read(dacl, &[SANDBOX_USER, SANDBOX_GROUP]));
}

#[test]
fn a_deny_for_another_account_leaves_a_grant_to_users_standing() {
    let buf = dacl(&[(true, READ_EXEC, LOCAL_SERVICE), (false, READ_EXEC, USERS)]);
    let dacl = buf.as_ptr().cast::<ACL>();

    assert!(dacl_lets_sandbox_read(dacl, &[SANDBOX_USER, SANDBOX_GROUP]));
}

/// A name with an unpaired surrogate is valid on NTFS and is not UTF-8.
#[test]
fn a_path_that_is_not_utf8_is_still_checked() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let name = OsString::from_wide(&[0x72, 0xD800, 0x2E, 0x65, 0x78, 0x65]);
    let dir = std::env::temp_dir().join(format!("srtwin-nonutf8-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, b"").unwrap();

    let answer = sandbox_can_read(&path, &[SANDBOX_USER]);
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(answer.is_some(), "{answer:?}");
}

#[test]
fn a_path_whose_dacl_cannot_be_read_answers_none() {
    let missing = Path::new(r"C:\no\such\folder\runner.exe");

    assert_eq!(sandbox_can_read(missing, &[LOCAL_SERVICE]), None);
}

#[test]
fn the_message_names_the_runner_and_not_seclogon() {
    let exe = r"C:\Users\someone\AppData\Local\Temp\unreadable-runner\crabpot.exe";
    let message = unreadable_runner(exe).to_string();

    assert!(message.contains(exe), "{message}");
    assert!(!message.to_lowercase().contains("seclogon"), "{message}");
    assert!(
        !message.to_lowercase().contains("secondary logon"),
        "{message}"
    );
}
