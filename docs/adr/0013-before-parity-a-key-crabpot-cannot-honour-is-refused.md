# Before parity, a key crabpot cannot honour is refused

Upstream drops a settings key it does not know, silently: none of its config objects is strict. crabpot does the same for a key upstream does not know either. But before parity crabpot lacks keys that upstream applies, such as `credentials`, `network.tlsTerminate` and `network.parentProxy`, and dropping one of those would run the command without a rule its caller asked for. So a config that sets a key upstream knows and crabpot does not yet implement is refused, with `ConfigError::Unsupported` naming the key and exit status 1 from the CLI. Each refusal goes away when its key is built, and none is left at parity. A key counts as set only when its value asks for something, such as a non-empty list, `true` or an object, so the empty lists upstream's schema requires still load.

A key upstream accepts but ignores on a platform is accepted and ignored there too, since upstream applies nothing for it. On macOS that is every Linux-only key: `bwrapPath`, `socatPath`, `seccomp`, `mandatoryDenySearchDepth`, `enableWeakerNestedSandbox`, `allowNestedUserNamespaces` and `ripgrep`. On Linux the keys that are macOS-only stay accepted and ignored, which are `allowUnixSockets`, `allowLocalBinding`, `enableWeakerNetworkIsolation` and `allowMachLookup`, since a host such as kelpie writes them on every platform. The Linux list differs, because upstream applies the Linux-only keys there and each changes what the sandbox does:

| Linux key | Upstream | On Linux |
|---|---|---|
| `bwrapPath`, `seccomp` | picks the bwrap binary, the filter and the helper | refused when set |
| `mandatoryDenySearchDepth` | sets how deep the deny walk looks | refused when set |
| `enableWeakerNestedSandbox`, `allowNestedUserNamespaces` | weaken the isolation | refused when set |
| `socatPath`, `ripgrep` | name a helper tool | accepted and ignored, since ADR-0014 removes the tool |

Ignoring the first five would fail open: a caller who weakens the sandbox to run in a container, or who points it at its own filter, would get the default one without being told. The list is `LINUX_PATHS` in `crates/crabpot-core/src/config/unsupported.rs`, behind `cfg(target_os = "linux")`. `network.allowAllUnixSockets` stays refused on every platform, since it lifts a rule on Linux as it does on macOS.

The differential harness cannot compare these, since upstream accepts them, so they are listed as crabpot-only cases. Every other refusal follows upstream's settings-file load: the same conditions and exit status, in crabpot's own words, refused when a `Config` is deserialized, whether through the CLI or the library.

## Considered options

- **Drop them, as upstream drops unknown keys.** Rejected because a sandbox that ignores a rule it was given fails open, and the caller has no way to tell.
- **Warn and run.** Rejected for the same reason: a warning on stderr is easy to miss in a host such as kelpie that runs commands unattended.
