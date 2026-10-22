# Before parity, a key crabpot cannot honour is refused

Upstream drops a settings key it does not know, silently: none of its config objects is strict. crabpot does the same for a key upstream does not know either. But before parity crabpot lacks keys that upstream applies, such as `credentials`, `network.tlsTerminate` and `network.parentProxy`, and dropping one of those would run the command without a rule its caller asked for. So a config that sets a key upstream knows and crabpot does not yet implement is refused, with `ConfigError::Unsupported` naming the key and exit status 1 from the CLI. Each refusal goes away when its key is built, and none is left at parity.

The differential harness cannot compare these, since upstream accepts them, so they are listed as crabpot-only cases. Every other refusal follows upstream's settings-file load: the same conditions and exit status, in crabpot's own words, refused when a `Config` is deserialized, whether through the CLI or the library.

## Considered options

- **Drop them, as upstream drops unknown keys.** Rejected because a sandbox that ignores a rule it was given fails open, and the caller has no way to tell.
- **Warn and run.** Rejected for the same reason: a warning on stderr is easy to miss in a host such as kelpie that runs commands unattended.
