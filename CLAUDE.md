# crabpot

Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime. MIT OR Apache-2.0.

A Rust port of anthropics/sandbox-runtime (`srt`). It sandboxes a process's filesystem and network access with the OS's own primitives (`sandbox-exec` on macOS, bubblewrap on Linux) plus a filtering proxy. A local clone of upstream lives at `../sandbox-runtime`, and that clone is the reference for behaviour.

## Commands

- `cargo test --locked` is the test shape.
- CI's gates, all required: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features --locked`, and `cargo +1.88 check --all-targets --all-features --locked` for the MSRV.
- One cargo command at a time: they share the target-dir lock.
- `rust-toolchain.toml` floats on stable, like CI. When CI's clippy flags something a local run did not, `rustup update stable` first.

## Where things live

The repository is a workspace (ADR-0012). Each published crate carries symlinks to the root `NOTICE`, `LICENSE-MIT` and `LICENSE-APACHE`, which `cargo package` follows.

- `crates/crabpot`: the facade and the only crate users depend on. Depends on `crabpot-core`, and on `crabpot-macos` for `cfg(target_os = "macos")`.
- `crates/crabpot-core`: what is the same on every platform. Depends on no other crabpot crate.
- `crates/crabpot-macos`: the seatbelt profile, the child's environment and the `sandbox-exec` argv. Depends on `crabpot-core`, and compiles on every platform.
- `crates/crabpot-linux`: the bwrap argv, the mandatory-deny walker, the seccomp filters and the dependency checks. Compiles on every platform, is empty until the Linux slices land in it, and the facade does not depend on it yet. `publish = false` in its `Cargo.toml` and unreleased in `release-plz.toml` until the Linux release slice flips both.
- `harness/`: `crabpot-harness`, `publish = false`, excluded from release in `release-plz.toml`.
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
