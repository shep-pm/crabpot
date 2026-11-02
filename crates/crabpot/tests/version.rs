//! `crabpot --version` answers with the package version, as upstream's `srt` does.

use std::process::Command;

#[test]
fn the_version_flags_print_the_package_version() {
    for flag in ["-V", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_crabpot"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
}
