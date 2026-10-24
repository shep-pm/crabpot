//! The Linux half of crabpot: the bwrap argv, the mandatory-deny walker, the
//! seccomp filters and the bwrap dependency checks.
//!
//! The crate is the landing place for the Linux slices of the Linux map, and
//! holds only the ones that have landed: [`argv`], [`deps`], [`fs`],
//! [`helper`], [`mandatory`], [`net`], `seccomp` and [`wrap`]. It builds on every platform so a
//! Linux slice fails on the macOS runner too, as `crabpot-macos` does in
//! reverse; Linux-only code sits behind
//! `cfg(target_os = "linux")`. The facade depends on it as a target-specific
//! dependency under `cfg(target_os = "linux")`, the way it gates
//! `crabpot-macos` to macOS (ADR-0012).
//!
//! What lives here, or will, per ADR-0014:
//!
//! - The bwrap words for a config: [`wrap::words`], over the filesystem
//!   [`fs::Plan`].
//! - The bwrap argv, rendered under upstream's size limits ([`argv`]).
//! - The mandatory-deny walker, matching upstream's `rg` list with `std::fs`
//!   ([`mandatory`]).
//! - The two seccomp filters, built per architecture: `seccomp`, on Linux
//!   only.
//! - The bwrap dependency checks, run before a sandbox starts: [`deps`].
//! - The Linux path entries mapped onto bwrap binds: `denyRead`, `allowRead`,
//!   `allowWrite` and `denyWrite` have landed, the first as a tmpfs over a
//!   directory and `/dev/null` over a file, the second as a bind of each
//!   allowed path back over what hid it, writable where a write grant covers
//!   it, the third as a bind of each writable path, and the last as a
//!   read-only bind over each denied path, last, with the directories above it
//!   pinned so it cannot be moved away.
//! - The helper crabpot's own binary becomes when bwrap re-enters it
//!   (ADR-0010): [`helper`]. Reading the `--crabpot-helper` argument is the
//!   facade's.
//! - The way out of the network namespace: the proxy's Unix socket is bound
//!   into the sandbox, the helper's relay forwards TCP ports 3128 and 1080 to
//!   it, and the command's proxy variables name those ports ([`net`]).

/// The bwrap argv is unix's: its words are `exec` arguments, and the args file
/// is a descriptor. `argv` sits behind `cfg(unix)`, and the args file it opens
/// behind `cfg(target_os = "linux")`.
#[cfg(unix)]
pub mod argv;
pub mod deps;
pub mod env;
pub mod fs;
#[cfg(unix)]
pub mod helper;
#[cfg(unix)]
pub mod mandatory;
pub mod net;
#[cfg(target_os = "linux")]
pub mod seccomp;
pub mod wrap;

/// The fixture tree the test modules build their cases on, which is
/// `tests/support` and needs `symlink`, so it sits with the unix tests.
#[cfg(all(test, unix))]
#[path = "../tests/support/mod.rs"]
mod support;
