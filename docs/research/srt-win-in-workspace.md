# Does srt-win's source build inside crabpot's workspace as it is?

Answers shep-pm/crabpot#130. Upstream is read at `aceba124`, where srt-win lives in `vendor/srt-win-src` (29,280 lines in `src/`).

## It builds, cross-target, from macOS

`cargo clippy --locked --target <arch>-pc-windows-msvc --all-targets -- -D warnings`, run in upstream's tree with `CC` and `AR` pointed at stubs:

| Target | Toolchain | Result | Time, warm |
|---|---|---|---|
| `x86_64-pc-windows-msvc` | stable | clean | 2 s |
| `aarch64-pc-windows-msvc` | stable | clean | 2 s |
| `x86_64-pc-windows-msvc` | 1.88 (`cargo check`) | clean | 2 s |

- The stubs only create the file named by `-o`, `-Fo`, `-out:` or `/OUT:`. MSVC's `lib.exe` style `-out:` is what `cc` passes for an msvc target.
- Without stubs, `libsqlite3-sys`'s build script fails for want of `cl.exe`, as upstream's `Cargo.toml` comment says.
- `rustup target add` is needed per toolchain, so 1.88 needs its own.
- cc-rs also reads per-target `CC_<target>` and `AR_<target>` ([docs](https://docs.rs/cc/latest/cc/)), which keeps the stubs off the host build.

## Dependencies

From crates.io, at the versions `Cargo.lock` pins. None is yanked.

| Crate | Licence | rust-version |
|---|---|---|
| anyhow 1.0.102 | MIT OR Apache-2.0 | 1.68 |
| clap 4.6.1 | MIT OR Apache-2.0 | 1.85 |
| serde 1.0.228 | MIT OR Apache-2.0 | 1.56 |
| serde_json 1.0.150 | MIT OR Apache-2.0 | 1.71 |
| windows 0.62.2, windows-core 0.62.2 | MIT OR Apache-2.0 | 1.82 |
| rusqlite 0.32.1 | MIT | none, but builds at 1.88 above |
| libsqlite3-sys 0.30.1 | MIT, bundled SQLite 3.46.0 is public domain | none, but builds at 1.88 above |
| cc 1.2.62 | MIT OR Apache-2.0 | 1.63 |

- All fit `MIT OR Apache-2.0`.
- The SQLite amalgamation ships inside `libsqlite3-sys` (a 5.1 MB `.crate`), not in the crate that depends on it, so it doesn't count toward crates.io's 10 MB limit.
- A Windows user's build compiles SQLite with `cl.exe`, which a Rust msvc toolchain already needs for linking.

## What crabpot's gates make of it

Under the workspace lints (`missing_docs`, `missing_debug_implementations`, `unsafe_code` deny, `clippy::undocumented_unsafe_blocks` deny), x86_64:

| Lint | Hits |
|---|---|
| `unsafe_code` | 308 |
| `undocumented_unsafe_blocks` | 298 |
| `missing_docs` | 186 |
| `missing_debug_implementations` | 11 |

- ADR-0005 already exempts the crate from IR-22. These numbers say the exemption has to cover the workspace lints too: either the crate keeps its own `[lints]` table, or 600 edits to upstream's code make every later sync a merge.
- 9 files are over IR-48's 1,000 lines, the largest `cli.rs` at 3,985. They would go in `.github/rust-file-size-baseline.txt`.

## One path reaches outside the crate

- `src/cert_store.rs:292`: `include_bytes!("../../../test/fixtures/tls-terminate/ca.crt")`, in a test.
- From a copy anywhere else, `--all-targets` fails with "couldn't read". The fixture has to come along, and that one line changes. It's the first local patch crabpot would carry.

## How upstream ships it

- `vendor/srt-win/build.ts` (28 lines) runs `cargo build --release` and copies `srt-win.exe` into the npm package.
- crabpot links the library and routes `--srt-win` through its own binary (ADR-0005), so it needs none of that.
