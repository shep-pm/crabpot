//! Native Windows fixtures for the runner's access check.

use std::{fs, path::PathBuf, process::Command};

use crate::{
    LoopbackMode, ProfileExclusions, ProfileState, SetupVersion, UserState, WindowsStatus,
};

#[derive(Debug)]
pub(crate) struct RunnerFile {
    pub(crate) exe: PathBuf,
}

// A real ACL exercises the linked check without exposing upstream's private helpers.
pub(crate) fn runner_file(test: &str, sid: &str) -> RunnerFile {
    let root = std::env::temp_dir().join(format!("crabpot-runner-{}-{test}", std::process::id()));
    fs::create_dir(&root).expect("a directory for this runner test");
    let file = RunnerFile {
        exe: root.join("runner.exe"),
    };
    fs::write(&file.exe, b"runner").expect("a runner file");
    let output = Command::new("icacls.exe")
        .arg(&file.exe)
        .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(RX)")])
        .output()
        .expect("icacls is available on Windows");
    assert!(output.status.success(), "icacls failed: {output:?}");
    file
}

impl Drop for RunnerFile {
    fn drop(&mut self) {
        let _ = Command::new("icacls.exe")
            .arg(&self.exe)
            .arg("/reset")
            .output();
        let _ = fs::remove_dir_all(self.exe.parent().expect("the runner's directory"));
    }
}

// Only these two identities should affect the runner's access check.
pub(crate) fn sandbox_status(account: Option<&str>, group: Option<&str>) -> WindowsStatus {
    WindowsStatus {
        user: UserState::Provisioned,
        sandbox_sid: account.map(str::to_owned),
        sandbox_group_sid: group.map(str::to_owned),
        real_user_sid: None,
        session_user_sid: None,
        setup_version: SetupVersion {
            installed: Some(3),
            expected: 3,
        },
        loopback: LoopbackMode::Closed,
        proxy_ports: None,
        profile: ProfileState::None,
        profile_exclusions: ProfileExclusions::default(),
        profile_read_env: Vec::new(),
        seclogon_runs: true,
        in_desktop_session: true,
        runner_readable: None,
    }
}
