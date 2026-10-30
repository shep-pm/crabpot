# crabpot-windows is published, with upstream's modules private to it

The facade depends on `crabpot-windows` on every host, for its environment and filesystem-access rules and for `run_from_args` and `SRT_WIN_DISPATCH_ARG1`, and ADR-0012 makes every crate `crabpot` depends on a published one: crates.io refuses a path-only dependency. So no `crabpot` release, on Linux or anywhere else, goes out while `crabpot-windows` is unpublished.

ADR-0005 rejected publishing srt-win as a crate of its own because that would put upstream's internal API on crates.io under crabpot's name. The objection is to the API, not to the crate. `crates/crabpot-windows/src/lib.rs` re-exports upstream's 25 modules as `pub(crate)`: they are there so `crate::acl` and its siblings inside the copied source resolve, and nothing outside the crate can name them. What the crate publishes is `env`, `fs_access`, `sandbox_can_read`, `run_from_args` and `SRT_WIN_DISPATCH_ARG1`, which is exactly what the facade already reaches, and a published crate's public surface is permanent, so keeping the rest private is what keeps ADR-0005's ruling intact.

`sandbox_can_read` exposes srt-win's runner access check so the facade's preflight uses the same check as the launch.

The crate is Apache-2.0 alone, not the workspace's `MIT OR Apache-2.0`, because nearly all of it is upstream's Apache-2.0 source: `license = "Apache-2.0"` in its manifest, no `LICENSE-MIT` alongside it, and `NOTICE` still carrying upstream's attribution. crabpot's own two modules in the crate are Apache-2.0 as well, which the workspace's dual licence already permits.

Two consequences follow from the modules being crate-private. Upstream's two access-check tests alias this crate as `srt_win` and name `srt_win::acl` and friends, and a test crate built outside the library cannot name a private module, so `src/lib.rs` includes each file with `#[path]` as a `#[cfg(all(test, windows))]` module instead of the manifest carrying test targets for them: on Windows `cargo test -p crabpot-windows` runs them as unit tests of the library. And everything in upstream's modules that crabpot does not call now reads as dead code, so `dead_code` is off for the `srt_win` module alone, since ADR-0005 never edits the copied source to prune it.

`publish` in the manifest and `release` in `release-plz.toml` stay false in this change: the Windows release slice (#165) flips them, and ADR-0012's rule against publishing a platform crate before it holds that platform's sandbox is what #165 satisfies.

## Considered options

- **Keep the crate unpublished and move `env` and `fs_access` to `crabpot-core`.** Rejected: both are Windows rules (`%USERPROFILE%` expansion, 8.3 names and junctions, the stdin shape `acl grant` reads), and `crabpot-core` is what is the same on every platform.
- **Publish with upstream's modules public.** Rejected: 25 modules of upstream's internal API, permanent on crates.io under crabpot's name, which is ADR-0005's objection verbatim.
- **Publish it under upstream's own crate name.** Rejected for the reason ADR-0005 gives, and Apache-2.0's trademark clause would not allow it either.
