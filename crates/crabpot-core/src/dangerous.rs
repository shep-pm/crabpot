//! The names upstream protects from writes wherever the working directory is
//! open, which `src/sandbox/sandbox-utils.ts` lists as `DANGEROUS_FILES` and
//! `getDangerousDirectories`.
//!
//! Public so the platform crates reach them (ADR-0012). A command that can
//! write one of these runs code outside the sandbox the next time it is read.

/// Files that run or configure a program outside the sandbox.
pub const DANGEROUS_FILES: [&str; 9] = [
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
];

/// Directories whose contents do the same. `.git` is not one: a command must
/// write it to use git, so only `.git/hooks` and `.git/config` are denied.
pub const DANGEROUS_DIRECTORIES: [&str; 4] =
    [".vscode", ".idea", ".claude/commands", ".claude/agents"];
