//! The Windows half of crabpot: upstream's `srt-win` source, taken in under
//! crabpot's name (ADR-0005).
//!
//! `srt-win/` is upstream's `vendor/srt-win-src`, copied byte for byte at the
//! baseline commit so a later sync is a copy and not a merge. `PATCHES.md`
//! lists every change from upstream, and it is a short list.
//!
//! Upstream's files write `crate::acl` and its siblings about 235 times, and
//! `cli.rs` does `use crate as srt_win`, so the crate root names every upstream
//! module. That is what lets the copied source compile unchanged with `crate`
//! meaning `crabpot_windows`: no path inside a copied file is edited to say so.
//! The names are `pub(crate)` re-exports (ADR-0015): upstream's internal API
//! stays off crates.io, and what this crate publishes is
//! [`env`](mod@env), [`fs_access`], `sandbox_can_read`, `run_from_args` and
//! `SRT_WIN_DISPATCH_ARG1`, which is exactly what the facade reaches. The last
//! three are Windows-only, so they are named in code spans here rather than
//! linked: this page builds on every host.
//!
//! Upstream's two integration tests are included here as test modules rather
//! than built as separate test crates, because an integration test cannot name
//! a `pub(crate)` module. The `extern crate self` below is what makes each
//! file's `use crabpot_windows as srt_win;` line resolve inside the crate, so
//! both files stay byte for byte as upstream wrote them.
//!
//! Off Windows the copied library is empty, the way upstream's own crate is: it
//! is `#![cfg(windows)]`. [`env`](mod@env) and [`fs_access`] are crabpot's own
//! and compile on every host, so a macOS or Linux host builds them and their
//! tests alone, and the copied source is compiled by the cross-target
//! clippy and `check` gates with the C compiler and archiver stubbed
//! (`.github/stubs/`), which is the only gate that reads the clap-derive CLI
//! structs off a Windows host.
//!
//! The facade depends on this crate on every host, and ADR-0015 publishes it:
//! crates.io refuses a `crabpot` release without it. The crate is Apache-2.0,
//! because what it holds is upstream's Apache-2.0 source.

pub mod env;
pub mod fs_access;

// The two upstream test files alias this crate as `srt_win` through its own
// name, and inside the crate that name only resolves through this declaration.
#[cfg(test)]
extern crate self as crabpot_windows;

// Upstream's own crate is a library, so every module in it is `pub` and its
// items are reachable from outside. Here they are crate-private (ADR-0015), and
// everything upstream exports that crabpot does not call then reads as dead
// code. The copied source is never edited to prune it (ADR-0005), so the lint
// is off for that module alone and not for crabpot's own files in this crate.
#[cfg(windows)]
#[allow(dead_code)]
#[path = "../srt-win/src/lib.rs"]
mod srt_win;

// The facade shares srt-win's runner preflight check.
#[cfg(windows)]
pub use srt_win::logon::sandbox_can_read;

// What the facade links: upstream's multicall entry point and its sentinel.
#[cfg(windows)]
pub use srt_win::{SRT_WIN_DISPATCH_ARG1, run_from_args};

// Upstream's module list, re-exported so `crate::…` inside the copied source
// resolves. It is `pub(crate)` and not `pub`: upstream's primitives are not
// crabpot's API, and a published crate's public surface is permanent
// (ADR-0015).
#[cfg(windows)]
pub(crate) use srt_win::{
    acl, ambient, cert_store, cli, dpapi, install, job, launch, logon, path_id, persist, probe,
    profile, profile_plan, reg, runner, sam, self_protect, sid, state_db, token, user, util, wfp,
    winsta,
};

// Upstream's two access-check tests, kept where upstream keeps them and byte
// for byte as it wrote them. A test crate outside the library cannot reach a
// `pub(crate)` module, so each one is compiled as a module of the library
// under `cfg(test)`, where its `use crabpot_windows as srt_win;` alias
// resolves through the `extern crate self` above. On Windows,
// `cargo test -p crabpot-windows` runs them as unit tests.
#[cfg(all(test, windows))]
#[path = "../srt-win/tests/persistent_grant_access_check.rs"]
mod persistent_grant_access_check;

#[cfg(all(test, windows))]
#[path = "../srt-win/tests/sd_access_check_matrix.rs"]
mod sd_access_check_matrix;

#[cfg(test)]
mod tests {
    /// The patch list has to name the fixture the `cert_store` patch points at.
    /// A sync from upstream that drops the fixture copy fails here instead of
    /// failing the Windows build.
    #[test]
    fn the_patches_list_names_the_cert_store_fixture() {
        let patches = include_str!("../PATCHES.md");
        assert!(
            patches.contains("cert_store.rs"),
            "PATCHES.md does not mention the cert_store patch at all"
        );
        assert!(
            patches.contains("srt-win/tests/data/ca.crt"),
            "PATCHES.md does not name the fixture copy the cert_store patch points at"
        );
    }

    /// The fixture the patched `include_bytes!` reads is where the patch says.
    #[test]
    fn the_fixture_copy_exists_where_the_patch_points() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/srt-win/tests/data/ca.crt");
        let pem = std::fs::read(path)
            .unwrap_or_else(|e| panic!("{path} is where PATCHES.md points the fixture: {e}"));
        assert!(
            pem.starts_with(b"-----BEGIN CERTIFICATE"),
            "{path} is not the PEM fixture the patch expects"
        );
    }

    /// The two upstream tests are wired into the library here, and the patch
    /// list has to say so. Putting them back as `[[test]]` entries builds an
    /// empty test crate off Windows and fails on it, since an integration test
    /// cannot name a `pub(crate)` module, so the guard has to be here
    /// (ADR-0015).
    #[test]
    fn the_patches_list_says_where_the_two_upstream_tests_run() {
        let patches = include_str!("../PATCHES.md");
        let manifest = include_str!("../Cargo.toml");
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
        let lib = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        for (file, module) in [
            (
                "srt-win/tests/persistent_grant_access_check.rs",
                "mod persistent_grant_access_check;",
            ),
            (
                "srt-win/tests/sd_access_check_matrix.rs",
                "mod sd_access_check_matrix;",
            ),
        ] {
            assert!(
                patches.contains(file),
                "PATCHES.md does not name {file} at all"
            );
            assert!(lib.contains(module), "src/lib.rs no longer has {module}");
        }
        assert!(
            !manifest.contains("[[test]]"),
            "Cargo.toml declares a test target again: these two cannot build as test crates, because their modules are private to the library"
        );
        assert!(
            patches.contains("unit test"),
            "PATCHES.md does not say the two upstream tests run as unit tests of the library"
        );
    }
}
