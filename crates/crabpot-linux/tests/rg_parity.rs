//! The walk lists what `rg` lists, on the fixture tree.
//!
//! Needs `rg`. Where it is missing the test is skipped, except under CI, where
//! it must be there.

use std::{path::PathBuf, process::Command, time::Duration};

use crabpot_core::dangerous::{DANGEROUS_DIRECTORIES, DANGEROUS_FILES};
use crabpot_linux::mandatory::scan;

mod support;

use support::Tree;

/// The arguments upstream's `linuxGetMandatoryDenyPaths` gives `rg`.
fn rg_args(max_depth: usize, allow_git_config: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "--files",
        "--hidden",
        "--no-ignore",
        "--no-config",
        "--line-buffered",
        "--max-depth",
    ]
    .map(str::to_owned)
    .into();
    args.push((max_depth + 1).to_string());
    for name in DANGEROUS_FILES {
        args.extend(["--iglob".to_owned(), name.to_owned()]);
    }
    for name in DANGEROUS_DIRECTORIES {
        args.extend(["--iglob".to_owned(), format!("**/{name}/**")]);
    }
    args.extend(["--iglob", "**/.git/hooks/**", "--iglob", "**/.git/HEAD"].map(str::to_owned));
    if !allow_git_config {
        args.extend(["--iglob", "**/.git/config"].map(str::to_owned));
    }
    args.extend(["-g", "!**/node_modules/**"].map(str::to_owned));
    args
}

#[test]
fn the_walker_lists_what_rg_lists_on_the_fixtures() {
    let tree = Tree::fixture("rg-parity");
    for max_depth in 0..=7 {
        for allow_git_config in [false, true] {
            // Globs are anchored where `rg` runs, which for upstream is the
            // target.
            let output = match Command::new("rg")
                .current_dir(tree.root())
                .args(rg_args(max_depth, allow_git_config))
                .arg(tree.root())
                .output()
            {
                Ok(output) => output,
                Err(error) if std::env::var_os("CI").is_none() => {
                    eprintln!("skipped: no rg to compare with ({error})");
                    return;
                }
                Err(error) => panic!("CI has rg: {error}"),
            };
            // 1 is "nothing listed".
            assert!(
                matches!(output.status.code(), Some(0 | 1)),
                "rg: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut by_rg: Vec<PathBuf> = String::from_utf8(output.stdout)
                .expect("UTF-8 names")
                .lines()
                .map(|line| {
                    PathBuf::from(line)
                        .strip_prefix(tree.root())
                        .expect("beneath the root")
                        .to_owned()
                })
                .collect();
            by_rg.sort();

            let by_walk = scan(
                tree.root(),
                max_depth,
                allow_git_config,
                Duration::from_secs(60),
            )
            .expect("within a minute")
            .listed;
            assert_eq!(
                by_walk, by_rg,
                "depth {max_depth}, allow_git_config {allow_git_config}"
            );
        }
    }
}
