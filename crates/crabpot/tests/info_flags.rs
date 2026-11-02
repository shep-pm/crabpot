//! `crabpot --version` and `--help` answer, as upstream's `srt` does.

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

#[test]
fn the_help_flags_print_the_usage() {
    for flag in ["-h", "--help"] {
        let output = Command::new(env!("CARGO_BIN_EXE_crabpot"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("--settings"),
            "{flag}"
        );
    }
}
