//! The jobs crabpot's own binary does when bwrap re-enters it (ADR-0014, ADR-0010).
//!
//! bwrap runs the binary as the first process of the sandbox, in place of
//! upstream's `apply-seccomp`. Each stage of the helper is a file in the folder
//! of this module's name, so slices that add one do not touch another. The
//! facade reads the `--crabpot-helper` argument and hands the stage its
//! arguments.
//!
//! Only [`exec`] exists so far: it runs the command and does nothing else.

mod exec;

pub use exec::{ExecError, exec};
