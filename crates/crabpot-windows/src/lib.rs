//! The Windows half of crabpot: upstream's `srt-win` source, taken in under
//! crabpot's name (ADR-0005).
//!
//! `srt-win/` is upstream's `vendor/srt-win-src`, copied byte for byte at the
//! baseline commit so a later sync is a copy and not a merge. `PATCHES.md`
//! lists every change from upstream, and it is a short list.
//!
//! Upstream's files write `crate::acl` and its siblings about 235 times, and
//! `cli.rs` does `use crate as srt_win`, so the crate root re-exports every
//! upstream module. That is what lets the copied source compile unchanged with
//! `crate` meaning `crabpot_windows`: no path inside a copied file is edited to
//! say so.
//!
//! Off Windows the copied library is empty, the way upstream's own crate is: it
//! is `#![cfg(windows)]`. [`fs_access`] is crabpot's own and compiles on every
//! host, so a macOS or Linux host builds it and its tests alone, and the copied
//! source is compiled by the cross-target
//! clippy and `check` gates with the C compiler and archiver stubbed
//! (`.github/stubs/`), which is the only gate that reads the clap-derive CLI
//! structs off a Windows host.
//!
//! The crate is not a dependency of the facade yet, and ADR-0005 keeps it
//! unpublished: what crabpot ships is its own name, never upstream's.

pub mod fs_access;

#[cfg(windows)]
#[path = "../srt-win/src/lib.rs"]
mod srt_win;

// Upstream's module list, re-exported so `crate::…` inside the copied source
// resolves, and so a caller reaches the primitives at the crate root. The two
// items upstream re-exports from `cli` come through `srt_win`'s own re-export,
// which is what keeps that line used.
#[cfg(windows)]
pub use srt_win::{
    SRT_WIN_DISPATCH_ARG1, acl, ambient, cert_store, cli, dpapi, install, job, launch, logon,
    path_id, persist, probe, profile, profile_plan, reg, run_from_args, runner, sam, self_protect,
    sid, state_db, token, user, util, wfp, winsta,
};

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
}
