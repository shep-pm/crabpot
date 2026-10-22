# A workspace of crates, split by platform

crabpot is a Cargo workspace under `crates/`. `crabpot` is the facade: `Sandbox`, `run_from_args`, the re-exported config and error types, and the CLI binary behind the `cli` feature, so ADR-0009 holds and kelpie still depends on `crabpot` alone. `crabpot-core` holds what is the same on every platform: the config schema, globs, path entries and the proxies. `crabpot-macos` builds the seatbelt profile, the child's environment and the `sandbox-exec` argv. It compiles and is tested on every platform, and only `crabpot` gates it to macOS, so profile bugs fail on both CI runners. `crabpot-linux` and `crabpot-windows` are added by the maps that need them, never published empty. `harness/` is a member with `publish = false`.

The reason is boundaries the compiler enforces. `crabpot-core` cannot reach platform code, a platform crate is a target-specific dependency that other platforms never compile, and srt-win's unsafe code is confined to `crabpot-windows` (ADR-0005). kelpie grew as a single binary crate and its modules ran together, and a crate boundary is what stops that here.

Every crate `crabpot` depends on has to be published, since crates.io refuses path-only dependencies. So `crabpot-core`'s types are a public contract too, release-plz releases the workspace, and the repository's crates.io token has to cover `crabpot-*` as well as `crabpot`.

## Considered options

- **One crate with platform modules.** Rejected because nothing but convention keeps the modules apart, and srt-win's 313 unsafe sites would need their exemption from IR-22 inside the crate every user links.
- **Publish `crabpot-linux` and `crabpot-windows` now, empty.** Rejected because a crates.io release is permanent, and nothing would be in them before their maps.
