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

Where they run: ADR-0015 makes upstream's modules private to this crate, and a
test crate built outside the library cannot name a private module. So
`src/lib.rs` includes each file with `#[path]` as a `#[cfg(all(test, windows))]`
module, and `Cargo.toml` carries no `[[test]]` entry for either. On Windows,
`cargo test --locked -p crabpot-windows` runs both as unit tests of the library,
which is the command CI's `windows` job runs, and the `extern crate self as
crabpot_windows` in `src/lib.rs` is what makes the alias line resolve inside it.
Nothing else in the two files changed.

## `srt-win/src/acl.rs` and `srt-win/src/cli.rs`: a metadata grant

The first change to upstream's behaviour (ADR-0016). A read deny is one
inheritable `FILE_ALL` deny ACE, so the folders between it and a grant beneath
it cannot be stat'd, which upstream's macOS profile avoids with
`file-read-metadata` on every directory.

- `acl.rs`: `GrantMask::Metadata`, `FILE_READ_ATTRIBUTES | SYNCHRONIZE`
  (`0x0010_0080`), written with `NO_INHERIT` where the other grants are `OICI`
  (`GrantMask::flags`). `SbAce::as_str` and `SbAce::parse` call it
  `"metadata"`, and `SbAce::max` ranks it below `ReadOnly`. `SbAceSet::aces`
  writes a metadata allow ahead of the same set's read deny, so a folder the
  session also read-denies (a recorded profile path under the deny) can still be
  stat'd. Unit tests pin the bits, the flags, the round trip, the rank and that
  order.
- `cli.rs`: `AclGrantInput` gains a `metadata` list, applied per session for the
  sandbox user SID as `read` is, and left out of `check_session_grants`, since
  it reads no content.

Reason: kelpie denies the home folder and grants paths beneath `~\.shep`, and
claude refuses a file whose path has a component it cannot examine.

## `srt-win/src/winsta.rs`: no session folder grant from session 0

From session 0 (ssh, a "run whether logged on or not" task) every launch failed
before the runner started: `grant_sandbox_on_session_bno` opened
`\Sessions\0\BaseNamedObjects`, which does not exist, and got
`NTSTATUS 0xC0000034`.

- `grant_sandbox_on_session_bno` returns `Ok(())` without opening anything when
  the broker runs in session 0.
- `broker_session` wraps `ProcessIdToSessionId` and is read once.
  `open_session_bno` takes the path as an argument instead of reading the
  session itself.
- `session_bno_path` is pure: `None` for session 0,
  `\Sessions\<ts>\BaseNamedObjects` otherwise. Two unit tests pin it.
- The module doc's "Session BNO" paragraph says so.

Reason: session 0's named objects live in the global `\BaseNamedObjects`. That
folder is shared by every service and only SYSTEM and Administrators can write
its DACL, so it must not be granted. It needs no grant: its DACL already gives
Everyone `QUERY | TRAVERSE | CREATE_OBJECT | CREATE_SUBDIRECTORY` (`0x2000F`),
and the lockdown token keeps Everyone enabled, so msys2's per-DLL subdirectory
can be made there. This patch goes upstream with #166.

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
