# crabpot

[![crates.io](https://img.shields.io/crates/v/crabpot.svg)](https://crates.io/crates/crabpot)
[![License](https://img.shields.io/crates/l/crabpot.svg)](https://github.com/shep-pm/crabpot#license)

Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime.

crabpot enforces filesystem and network restrictions on any process at the OS level, without a container. It is a port of [anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) to Rust, with no Node runtime.

Nothing is implemented yet. The crate on crates.io is a placeholder until the first real release.

## Windows setup

The Windows sandbox needs a one-time install: the sandbox user, the WFP network filters and the read access the user needs. It is the same install as upstream's `srt windows-install` (same user, same WFP sublayer, same setup version), so an install by either tool satisfies the other.

```
crabpot windows-install [--allow-loopback] [--proxy-port-range LOW-HIGH]
                        [--sandbox-user NAME] [--sublayer-guid GUID] [--force]
crabpot windows-uninstall [--keep-user] [--sublayer-guid GUID]
```

- `windows-install` asks for elevation itself, with one UAC prompt, and does the work in the elevated process.
- Before it asks, it checks that the sandbox user can read the crabpot executable, which the sandbox runs as its runner. A binary the user cannot read is refused with a message naming it. Keep crabpot under your profile or in a folder every user can read.
- `--allow-loopback` opens every loopback port to the sandbox user, not only the proxy's. Every listener on localhost becomes reachable from the sandbox, including a forwarder that carries traffic off the machine. A session must use the loopback mode the install used, so changing it means running the install again with `--force`.
- `--proxy-port-range` sets the loopback ports left open for the proxy (default `60080-60089`).
- `windows-uninstall` removes the user, its credential and the filters. `--keep-user` keeps the user. It then removes any WFP filters left under the sublayer.
- Both commands are for Windows and refuse on any other platform.

## License

MIT OR Apache-2.0, at your option.

crabpot is derived from anthropics/sandbox-runtime, which is Apache-2.0. See [NOTICE](NOTICE).
