# Patches to upstream's source

`crates/crabpot-windows/srt-win/` is upstream's `vendor/srt-win-src` from
anthropics/sandbox-runtime at commit
`aceba124fd725f4a43d7016ed3f5651d61f83115` (the baseline, ADR-0001), copied
byte for byte. Everything below is the whole distance between the two trees.

A sync from upstream re-copies the tree, then re-applies this list in order.
`crates/crabpot-windows/src/lib.rs` is crabpot's own file and is not in the
copy: a sync never touches it.

## `srt-win/src/cert_store.rs`

The `include_bytes!` in the `tests` module (upstream line 292) reads
`../../../test/fixtures/tls-terminate/ca.crt`, which reaches out of the crate
into upstream's TypeScript test fixtures. crabpot carries no `test/` tree, so
the fixture is copied to `srt-win/tests/data/ca.crt` and the macro now reads
`../tests/data/ca.crt`.

Reason: the crate has to build from its own directory. The fixture is upstream's
own `srt-test-ca`, byte for byte from `test/fixtures/tls-terminate/ca.crt`.

## `srt-win/tests/persistent_grant_access_check.rs` and `srt-win/tests/sd_access_check_matrix.rs`

One line added after each file's `#![cfg(windows)]`:

```rust
use crabpot_windows as srt_win;
```

Reason: the library here is `crabpot_windows`, not `srt_win`, because ADR-0005
keeps upstream's crate name out of crabpot's published surface. The tests name
`srt_win::acl` and friends, and the alias is one line each instead of a rewrite
of every path in them.

## Not copied

- `Cargo.lock`: the workspace has one.
- `Cargo.toml`: crabpot writes its own manifest. It carries upstream's
  dependencies, upstream's `windows` feature list and upstream's `test-hooks`
  feature under `[target.'cfg(windows)'.dependencies]`, and its own `[lints]`
  table (ADR-0005's exemption from rust-house-style IR-22 and IR-23, recorded in
  `docs/rust-house-style-addendum.md`) so no copied file needs a lint attribute.
  Upstream's `[profile.release]` is dropped: cargo ignores a profile in a
  workspace member.

## Copied but not built

- `srt-win/src/main.rs`: crabpot declares no `[[bin]]`. ADR-0005 routes
  `--srt-win` inside crabpot's own binary, so the shim stays in the tree
  uncompiled until a slice wants it.
- `srt-win/ci/*.ps1`: upstream's Windows smoke scripts. #145 wires the Windows
  CI leg that runs them.
- `srt-win/.gitignore`, `srt-win/rustfmt.toml`: kept so the copy is a copy.
