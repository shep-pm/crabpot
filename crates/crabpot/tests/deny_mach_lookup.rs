//! `network.denyMachLookup` keeps a command from the keychain while its network
//! still works (ADR-0011). Upstream has no such key, so the differential
//! harness cannot cover it.
//!
//! The cases run on macOS CI, or anywhere `CRABPOT_KEYCHAIN_TEST=1`. They store
//! an item in a keychain of their own and put it on the user's search list
//! until they end, so the login keychain is never read or written.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crabpot::{Config, Sandbox};

const SECURITYD: &str = "com.apple.securityd.xpc";
const SECURITY_SERVER: &str = "com.apple.SecurityServer";

const ACCOUNT: &str = "crabpot-account";
const SERVICE: &str = "crabpot-service";
const GENERIC_SECRET: &str = "crabpot-generic-secret";
const GIT_HOST: &str = "crabpot-keychain-test.invalid";
const GIT_SECRET: &str = "crabpot-git-secret";
const KEYCHAIN_PASSWORD: &str = "crabpot";

/// Whether this run may use a keychain: on CI, or when asked for.
fn enabled() -> bool {
    let on = std::env::var_os("CI").is_some()
        || std::env::var("CRABPOT_KEYCHAIN_TEST").is_ok_and(|set| set == "1");
    if !on {
        eprintln!("skipped: set CRABPOT_KEYCHAIN_TEST=1 to use a temporary keychain");
    }
    on
}

/// A scratch folder named for the test, empty at the start.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("crabpot-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn security(args: &[&str]) -> Output {
    let output = Command::new("security").args(args).output().unwrap();
    assert!(output.status.success(), "security {args:?}: {output:?}");
    output
}

/// A keychain made for one test: on the user's search list, so a program that
/// takes no keychain argument finds its items, and removed with its folder.
struct TempKeychain {
    dir: PathBuf,
    path: PathBuf,
    searched: Vec<String>,
}

impl TempKeychain {
    fn new(test: &str) -> Self {
        let dir = scratch(test);
        let path = dir.join("crabpot.keychain-db");
        let path_text = path.to_str().unwrap().to_owned();
        security(&["create-keychain", "-p", KEYCHAIN_PASSWORD, &path_text]);
        // No lock timeout, so the keychain stays open for the test.
        security(&["set-keychain-settings", &path_text]);
        security(&["unlock-keychain", "-p", KEYCHAIN_PASSWORD, &path_text]);

        let listed = security(&["list-keychains", "-d", "user"]);
        let searched: Vec<String> = String::from_utf8(listed.stdout)
            .unwrap()
            .lines()
            .map(|line| line.trim().trim_matches('"').to_owned())
            .filter(|line| !line.is_empty())
            .collect();
        let keychain = Self {
            dir,
            path,
            searched,
        };
        keychain.search(&[&[path_text.clone()], &keychain.searched[..]].concat());

        // `-A` lets any program read the items, so no prompt stands in for the
        // sandbox's refusal.
        security(&[
            "add-generic-password",
            "-A",
            "-a",
            ACCOUNT,
            "-s",
            SERVICE,
            "-w",
            GENERIC_SECRET,
            &path_text,
        ]);
        // The item `git credential-osxkeychain` reads for an https host.
        security(&[
            "add-internet-password",
            "-A",
            "-a",
            ACCOUNT,
            "-s",
            GIT_HOST,
            "-r",
            "htps",
            "-w",
            GIT_SECRET,
            &path_text,
        ]);
        keychain
    }

    fn search(&self, keychains: &[String]) {
        let mut args = vec!["list-keychains", "-d", "user", "-s"];
        args.extend(keychains.iter().map(String::as_str));
        security(&args);
    }

    /// `security find-generic-password`, printing the item's password.
    fn find_generic(&self) -> Command {
        let mut command = Command::new("security");
        command
            .args(["find-generic-password", "-s", SERVICE, "-w"])
            .arg(&self.path);
        command
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        self.search(&self.searched);
        let _ = Command::new("security")
            .arg("delete-keychain")
            .arg(&self.path)
            .output();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// `git credential-osxkeychain get` for the host the keychain holds a password for.
fn credential_get() -> Command {
    let mut command = Command::new("git");
    command.args(["credential-osxkeychain", "get"]);
    command
}

fn run(command: &mut Command, stdin: &str) -> Output {
    use std::io::Write;

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// A settings file that denies `deny`, reaches `domains` and lets Go verify a
/// certificate.
fn settings(deny: &[&str], domains: &[&str]) -> String {
    let list = |names: &[&str]| {
        names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        r#"{{
            "enableWeakerNetworkIsolation": true,
            "network": {{
                "allowedDomains": [{}], "deniedDomains": [],
                "denyMachLookup": [{}]
            }},
            "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
        }}"#,
        list(domains),
        list(deny)
    )
}

fn sandboxed(deny: &[&str], domains: &[&str]) -> Sandbox {
    let settings = settings(deny, domains);
    Sandbox::start(&Config::from_json(&settings).unwrap_or_else(|e| panic!("{settings}: {e}")))
        .unwrap()
}

fn wrapped(sandbox: &Sandbox, command: &Command) -> Command {
    sandbox.command(command).unwrap()
}

#[test]
fn the_stored_item_is_refused_to_security_and_git_credential_osxkeychain() {
    if !enabled() {
        return;
    }
    let keychain = TempKeychain::new("keychain");
    let git_request = format!("protocol=https\nhost={GIT_HOST}\n\n");
    let git_password = format!("password={GIT_SECRET}");

    // The fixture holds the items, and a sandbox that denies nothing reads them.
    for sandbox in [None, Some(sandboxed(&[], &[]))] {
        let mut find = keychain.find_generic();
        let mut get = credential_get();
        if let Some(sandbox) = &sandbox {
            find = wrapped(sandbox, &find);
            get = wrapped(sandbox, &get);
        }
        let found = run(&mut find, "");
        assert_eq!(
            String::from_utf8_lossy(&found.stdout).trim(),
            GENERIC_SECRET,
            "{found:?}"
        );
        let got = run(&mut get, &git_request);
        assert!(
            String::from_utf8_lossy(&got.stdout).contains(&git_password),
            "{got:?}"
        );
    }

    let sandbox = sandboxed(&[SECURITYD, SECURITY_SERVER], &[]);
    let found = run(&mut wrapped(&sandbox, &keychain.find_generic()), "");
    assert!(!found.status.success(), "{found:?}");
    assert!(
        !String::from_utf8_lossy(&found.stdout).contains(GENERIC_SECRET),
        "{found:?}"
    );
    let got = run(&mut wrapped(&sandbox, &credential_get()), &git_request);
    assert!(
        !String::from_utf8_lossy(&got.stdout).contains(&git_password),
        "{got:?}"
    );
}

/// A Go program that fetches the URL it is given and prints the status.
const GO_FETCH: &str = r#"package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	response, err := http.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(response.StatusCode)
}
"#;

/// Builds [`GO_FETCH`] into `dir`, outside any sandbox, since the build cache
/// is not writable inside one.
fn build_go_fetch(dir: &Path) -> PathBuf {
    let source = dir.join("fetch.go");
    let binary = dir.join("fetch");
    fs::write(&source, GO_FETCH).unwrap();
    let built = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("go is on the PATH");
    assert!(built.status.success(), "{built:?}");
    binary
}

#[test]
fn curl_go_tls_and_git_ls_remote_still_work() {
    if !enabled() {
        return;
    }
    let dir = scratch("network");
    let fetch = build_go_fetch(&dir);
    let sandbox = sandboxed(&[SECURITYD, SECURITY_SERVER], &["github.com"]);

    let mut curl = Command::new("curl");
    curl.args(["--silent", "--show-error", "--output", "/dev/null"])
        .args(["--write-out", "%{http_code}", "https://github.com/"]);
    let mut go = Command::new(&fetch);
    go.arg("https://github.com/");
    let mut ls_remote = Command::new("git");
    ls_remote.args([
        "ls-remote",
        "https://github.com/anthropics/sandbox-runtime.git",
        "HEAD",
    ]);

    for (name, command, expected) in [
        ("curl", curl, "200"),
        ("go", go, "200"),
        ("git ls-remote", ls_remote, "\tHEAD"),
    ] {
        let output = run(&mut wrapped(&sandbox, &command), "");
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(expected),
            "{name}: {output:?}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}
