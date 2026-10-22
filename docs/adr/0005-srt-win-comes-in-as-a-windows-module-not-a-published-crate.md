# srt-win comes in as a Windows module, not a published crate

Upstream's Windows backend is TypeScript orchestration over `srt-win`, a Rust crate of about 30,000 lines with 313 unsafe sites. Upstream made it a library (commit `feea0bf`) so a program can link it into its own multicall binary: `run_from_args` takes over when `argv[1]` is `--srt-win`, and every elevated or sandbox-user hop re-spawns the same exe with that sentinel. Upstream does not publish it (`publish = false`), and crates.io refuses git dependencies, so crabpot cannot depend on it.

crabpot takes its source into the crabpot crate as a `#[cfg(windows)]` module, keeps upstream's licence and notice, and routes `--srt-win` in its own binary as upstream designed. Only the TypeScript orchestration around it is rewritten. Nothing is published under upstream's crate name, which Apache-2.0's trademark clause would not allow anyway. Upstream's later changes to it come in through following. The module is exempt from rust-house-style IR-22 (unsafe in one module per crate), and `docs/rust-house-style-addendum.md` gets that exemption when the module lands.

## Considered options

- **Rewrite it.** Rejected: 30,000 lines of Windows security code that upstream already maintains.
- **Publish it as a crate of its own.** Rejected because it would put upstream's internal API on crates.io under crabpot's name.
- **A git dependency on upstream.** Rejected because crabpot could no longer be published.
