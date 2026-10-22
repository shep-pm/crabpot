# crabpot

[![crates.io](https://img.shields.io/crates/v/crabpot.svg)](https://crates.io/crates/crabpot)
[![License](https://img.shields.io/crates/l/crabpot.svg)](https://github.com/shep-pm/crabpot#license)

Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime.

crabpot enforces filesystem and network restrictions on any process at the OS level, without a container. It is a port of [anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) to Rust, with no Node runtime.

Nothing is implemented yet. The crate on crates.io is a placeholder until the first real release.

## License

MIT OR Apache-2.0, at your option.

crabpot is derived from anthropics/sandbox-runtime, which is Apache-2.0. See [NOTICE](NOTICE).
