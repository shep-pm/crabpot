# crabpot

Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime. MIT OR Apache-2.0.

A Rust port of anthropics/sandbox-runtime (`srt`). It sandboxes a process's filesystem and network access with the OS's own primitives (`sandbox-exec` on macOS, bubblewrap on Linux, and on Windows a restricted-token launch through `srt-win` behind a WFP egress fence) plus a filtering proxy. A local clone of upstream lives at `../sandbox-runtime`, and that clone is the reference for behaviour.

## Commands

- `cargo test --locked` is the test shape.
- CI's gates, all required: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features --locked`, and `cargo +1.88 check --all-targets --all-features --locked` for the MSRV.
- One cargo command at a time: they share the target-dir lock.
- `crates/crabpot-windows` is empty off Windows, so its code is gated from both sides. Off Windows, by the cross-target gates after `rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc`: `CC_x86_64_pc_windows_msvc=.github/stubs/stubcc AR_x86_64_pc_windows_msvc=.github/stubs/stubar cargo clippy --locked --all-features --target x86_64-pc-windows-msvc -p crabpot -p crabpot-core -p crabpot-windows -p crabpot-harness --all-targets -- -D warnings`, and the same pair of variables for `aarch64-pc-windows-msvc`. `rusqlite`'s `bundled` feature needs the stubs, and nothing links in `check` or `clippy`. The package list is what builds for a Windows target: `crabpot-macos` and `crabpot-linux` keep unix-only test targets. The `msrv` job runs the same check with `cargo +1.88 check` for `x86_64-pc-windows-msvc`.
- On Windows, `cargo test --locked -p crabpot-windows`, which CI runs on `windows-latest` and `windows-11-arm`. A cold build is about 80 s, incremental about 10 s.
- On Windows, the harness runs upstream's `srt-win` path after `npm ci` in `harness/` and a one-time `node harness/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js windows-install`, then `cargo test --locked -p crabpot-harness`. CI does that as the `windows-harness` job.
- `rust-toolchain.toml` floats on stable, like CI. When CI's clippy flags something a local run did not, `rustup update stable` first.

## Where things live

The repository is a workspace (ADR-0012). Each published crate carries symlinks to the root `NOTICE`, `LICENSE-MIT` and `LICENSE-APACHE`, which `cargo package` follows. `crates/crabpot-windows` is the exception: it is Apache-2.0 alone (ADR-0015) and carries `LICENSE-APACHE` and `NOTICE` only.

- `crates/crabpot`: the facade and the only crate users depend on. Depends on `crabpot-core`, on `crabpot-macos` for `cfg(target_os = "macos")`, on `crabpot-linux` for `cfg(target_os = "linux")`, and on `crabpot-windows` on every host.
- `crates/crabpot/src/windows/`: Windows support, built and unit-tested on every host behind the injected `Srt` runner. `Sandbox::start` follows upstream's `initialize` (`start.rs`: profile status, one `acl grant --persistent` call from a `Plan`, `wfp verify` once per process and loopback mode, the proxy in the installed port range), `Sandbox::command` wraps into `<current_exe> --srt-win exec` (`command.rs`), and `Drop` runs `acl revoke` then `acl restore`. A `Plan` is built from the `sections!` list in `plan.rs`: a new setting adds one file under `plan/` and one name to that list. `tests/windows_sandbox.rs` is the end-to-end check, run by CI on a Windows runner.
- `crates/crabpot-core`: what is the same on every platform. Depends on no other crabpot crate.
- `crates/crabpot-macos`: the seatbelt profile, the child's environment and the `sandbox-exec` argv. Depends on `crabpot-core`, and compiles on every platform.
- `crates/crabpot-linux`: the bwrap argv, the mandatory-deny walker, the seccomp filters and the dependency checks. Compiles on every platform, holds each Linux slice as it lands behind `cfg(target_os = "linux")` and the unix-only `argv` behind `cfg(unix)`. Published, and released with the rest of the workspace.
- `crates/crabpot-windows`: upstream's `srt-win` source, copied byte for byte into `srt-win/` (ADR-0005), plus crabpot's own `src/lib.rs`, which pulls it in with `#[path]` and re-exports upstream's 25 modules as `pub(crate)` so `crate::…` inside the copied source resolves while the crate's public surface stays `env`, `fs_access`, `run_from_args` and `SRT_WIN_DISPATCH_ARG1` (ADR-0015). Compiles on every platform and is empty off Windows; the copied library is `#![cfg(windows)]`. `crates/crabpot-windows/PATCHES.md` lists every change from upstream, and a sync re-copies the tree and re-applies that list. The crate has its own `[lints]` table, not the workspace's, which is where the IR-22 exemption lives. ADR-0015 publishes it under `license = "Apache-2.0"` alone, with no `LICENSE-MIT` symlink, and the Windows release slice (#165) flips `publish` and `release`. Upstream's two access-check tests are included from `src/lib.rs` as `#[cfg(all(test, windows))]` modules and have no test target in the manifest, because an integration test cannot name a `pub(crate)` module. The facade depends on it on every host, for the environment and filesystem-access rules its Windows tests run off Windows, and routes `--srt-win` to it on Windows.
- `harness/`: `crabpot-harness`, `publish = false`, excluded from release in `release-plz.toml`.
- `[workspace.dependencies]` gives `crabpot-windows` a `path` and no `version`. release-plz rewrites a dependency requirement only for a crate it releases, and `release-plz.toml` keeps it at `release = false`, so a pinned requirement there is a copy of the version that nothing maintains: it goes stale on a bump and the release PR cannot resolve the workspace (#195). The Windows release slice adds its version back when it publishes that crate.
- `NOTICE` carries upstream's Apache-2.0 attribution. It ships with the crate, so keep it accurate.

## Style

- Invoke the `rust-house-style` skill before writing or reviewing Rust. The rules are shep-pm/rust-house-style, IR-1..IR-48. This repo's exceptions go in `docs/rust-house-style-addendum.md`, which wins where the two disagree.
- `unsafe_code` is `deny` in Cargo.toml, not `forbid`: the OS sandboxes are reached through FFI. Unsafe lives in one module per crate per OS behind `#[allow(unsafe_code)]`, with a `// SAFETY:` comment on every block (IR-22, IR-23).
- shep's vocabulary: a `sheep` is one managed process, the plural is `flock`, dogs are plugin processes, and the daemon is only ever "the shepherd".
- Committed text says "the maintainer", never a name, and uses repo-relative paths.

## Commits and pull requests

- Conventional subjects: `type(scope): summary`, with types `feat` `fix` `perf` `refactor` `docs` `test` `ci` `chore` `style`, and `!` on the commit that breaks something. `.githooks/commit-msg` checks locally (run `git config core.hooksPath .githooks` once per clone) and `.github/workflows/commits.yml` checks every pull request.
- Pull request titles are conventional too. `merge_commit_title` is set to the PR title, so a merge commit's subject is the title.
- Merge with a merge commit, never a squash. Release pull requests are the exception, and their workflow squashes them itself.
- One commit per item. Bodies carry the full reasoning.
- release-plz writes CHANGELOG.md from commit subjects, so never hand-write an entry. A merged release pull request publishes to crates.io on its own.

## Agent skills

### Issue tracker

GitHub Issues on `shep-pm/crabpot`, via `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles, label string equal to role name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the root and ADRs in `docs/adr/`, both created when a term or decision is first settled. See `docs/agents/domain.md`.
