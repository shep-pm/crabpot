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
                        [--profile-exclude PATH] [--skip-profile-grant]
crabpot windows-uninstall [--keep-user] [--sublayer-guid GUID]
```

- `windows-install` asks for elevation itself, with one UAC prompt, and does the work in the elevated process.
- After the install it makes the profile read grant, as upstream's install does: the sandbox user can then read your profile, except what srt-win keeps out on its own (`~\.ssh`, `~\.aws` and the other key dot-directories, Windows' own per-user secret stores, browser profiles and password managers, your registry hives) and anything `--profile-exclude` names. What it opens includes package-manager configuration that can hold feed tokens (`.npmrc`, `pip.ini`, `NuGet.Config`, `Maven settings.xml`, `gradle.properties`, `.gitconfig`). The grant runs as you and needs no elevation. Its first pass touches every file it grants, which takes minutes on a large profile, and a new top-level item of the profile stays unreadable until it runs again. `crabpot --srt-win profile forget` removes the grant.
- `--profile-exclude PATH` keeps one more path unreadable. Repeatable, and it reaches `srt-win profile grant` as `--exclude`: an exclusion once recorded stays in force.
- `--skip-profile-grant` makes no grant. A crabpot under your profile, which is where `cargo install` puts one, then stays unreadable to the sandbox user.
- The install also makes no grant when it ran as a service account (LocalSystem, LocalService, NetworkService), when the owner of the session it ran in could not be read, or when that session belongs to another account, where granting would open the installing account's profile instead of the one the sessions in it read. Each prints the account it turned on.
- The install ends by checking that the sandbox user can read the crabpot executable, which it runs as the runner. The grant is what makes a binary under your profile readable, and a binary in a folder every user can read, such as one under Program Files, needs no grant at all. When the install made no grant, an unreadable runner is a notice naming `crabpot --srt-win profile grant` and the install still exits 0, since skipping the grant is what you asked for.
- `Sandbox::start` refuses an unreadable runner by name (`StartError::RunnerUnreadable`) before it grants anything, so the binary is named instead of seclogon answering `CreateProcessWithLogonW: Access is denied`. It reads the executable's own access list for the sandbox account, the group it is in, and Users, Authenticated Users and Everyone, so a folder granted to the sandbox alone counts. Sitting under your profile is not enough on its own: the grant writes one entry per path it reaches, so what it excludes, what it leaves ungranted (your temporary directory) and any top-level item made after it ran are all refused.
- `--allow-loopback` opens every loopback port to the sandbox user, not only the proxy's. Every listener on localhost becomes reachable from the sandbox, including a forwarder that carries traffic off the machine. A session must use the loopback mode the install used, so changing it means running the install again with `--force`.
- `--proxy-port-range` sets the loopback ports left open for the proxy (default `60080-60089`). Each sandbox takes two of them, so the default range holds five sandboxes at once, and a session that finds every port of its range taken refuses with `StartError::ProxyRangeFull`, which names the range and the flag.
- `windows-uninstall` removes the user, its credential and the filters, and with them the profile read grant (`--keep-user` keeps the user and the grant). It then removes any WFP filters left under the sublayer.
- Both commands are for Windows and refuse on any other platform.

## License

MIT OR Apache-2.0, at your option.

crabpot is derived from anthropics/sandbox-runtime, which is Apache-2.0. See [NOTICE](NOTICE).
