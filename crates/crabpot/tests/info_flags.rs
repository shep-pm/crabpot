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

#[test]
fn the_flags_answer_before_a_missing_settings_file_is_read() {
    for flag in ["-V", "--version", "-h", "--help"] {
        let output = Command::new(env!("CARGO_BIN_EXE_crabpot"))
            .args(["-s", "no-such-settings.json", flag])
            .output()
            .unwrap();
        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert!(!output.stdout.is_empty(), "{flag}");
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn a_windows_subcommand_answers_help() {
    for name in ["windows-install", "windows-uninstall"] {
        let output = Command::new(env!("CARGO_BIN_EXE_crabpot"))
            .args([name, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {:?}", output.status);
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("--settings"),
            "{name}"
        );
    }
}
