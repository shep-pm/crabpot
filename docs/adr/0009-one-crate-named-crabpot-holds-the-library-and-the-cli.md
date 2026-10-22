# One crate named crabpot holds the library and the CLI

The library and the CLI are both `crabpot`, in one crate. The binary sits behind a `cli` feature that is on by default, so `cargo install crabpot` gives the CLI, and a host that only links the library (kelpie) sets `default-features = false` to leave out its dependencies. The CLI takes upstream's arguments unchanged (`-s`/`--settings`, `-c`, `--control-fd`, `-d`, `proxy`) and reads `~/.srt-settings.json` by default, so a user who switches changes only the binary's name and keeps their settings. The binary is not named `srt`: that name is upstream's, and both could be installed at once.

## Considered options

- **Two crates, `crabpot` and `crabpot-cli`.** Rejected because it means two names to publish and release, and `cargo install crabpot` would not give the CLI. Splitting later stays easy. Merging two published crates would not be.
- **A binary named `srt`.** Rejected for the clash on `PATH` and because the name is upstream's.
