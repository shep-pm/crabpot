//! The Linux half of crabpot: the bwrap argv, the mandatory-deny walker, the
//! seccomp filters and the bwrap dependency checks.
//!
//! The crate is the landing place for the Linux slices of the Linux map, and
//! is empty until they land in it. It builds on every platform so a Linux
//! slice fails on the macOS runner too, as `crabpot-macos` does in reverse;
//! Linux-only code sits behind `cfg(target_os = "linux")`. The facade will
//! depend on it as a target-specific dependency under `cfg(target_os =
//! "linux")`, the way it gates `crabpot-macos` to macOS (ADR-0012).
//!
//! What will live here, per ADR-0014:
//!
//! - The bwrap argv, rendered under upstream's size limits.
//! - The mandatory-deny walker, matching upstream's `rg` list with `std::fs`.
//! - The two seccomp filters, built per architecture.
//! - The bwrap dependency checks, run before a sandbox starts.
//! - The Linux path entries: `denyRead`, `allowRead`, `allowWrite` and
//!   `denyWrite` mapped onto bwrap binds.
//!
//! The helper crabpot's own binary re-enters inside bwrap (ADR-0010) is the
//! facade's `cli` half, not this crate.
