<p align="center">
  <img src="https://raw.githubusercontent.com/shep-pm/crabpot/main/assets/crabpot-logo.png" alt="A crab sitting in a crab pot" width="220">
</p>

<h1 align="center">crabpot</h1>

<p align="center">Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime.</p>

<p align="center">
  <a href="https://crates.io/crates/crabpot"><img src="https://img.shields.io/crates/v/crabpot.svg" alt="crates.io"></a>
  <a href="https://docs.rs/crabpot"><img src="https://img.shields.io/docsrs/crabpot" alt="docs.rs"></a>
  <a href="https://github.com/shep-pm/crabpot/actions/workflows/test.yml"><img src="https://github.com/shep-pm/crabpot/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-blue" alt="MSRV 1.88">
  <a href="https://github.com/shep-pm/crabpot#license"><img src="https://img.shields.io/crates/l/crabpot.svg" alt="License"></a>
</p>

crabpot restricts what a process can read, write and reach on the network, using the OS's own sandbox and no container. It is a port of [anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) to Rust, with no Node runtime, and reads the same settings file.

| Platform | How it confines a process |
|---|---|
| macOS | `sandbox-exec` with a generated profile |
| Linux | bubblewrap and seccomp (`bwrap` must be on `PATH`) |
| Windows | a separate sandbox user behind a WFP firewall fence, after a [one-time install](#windows-setup) |

On every platform, network traffic goes through a filtering proxy that only lets the allowed domains through.

## Install

```sh
cargo install crabpot   # the command
cargo add crabpot       # the library
```

## Use it

Write a settings file, upstream's format:

```json
{
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": ["."],
    "denyWrite": [".env"]
  }
}
```

crabpot adds two optional network keys for services. Both take lists of strings,
and an empty list asks for nothing on every platform:

- `network.publish`, for example `["127.0.0.1:8001", "0.0.0.0:3600", "[::1]:8002"]`,
  lets the command bind and accept connections on those ports on macOS. The
  command chooses its bind address as it would unsandboxed. Seatbelt grants each
  port on every local address, so the address in the entry does not restrict the
  sandbox rule. `allowLocalBinding: true` already covers these ports. Linux and
  Windows refuse a nonempty list until publication is supported there.
- `network.allowTcp`, for example `["10.0.0.5:3306", "db.example.com:5432"]`,
  names hosts and ports the command may dial directly on Linux. crabpot resolves
  each host once at startup and refuses the sandbox if a name does not resolve.
  A relay listens on those addresses and ports inside the sandbox and opens
  authenticated `CONNECT` tunnels through the proxy. `deniedDomains` still wins.
  Name resolution inside the sandbox is unchanged: dial the address, or a name
  the command already resolves. Windows refuses nonempty lists. On macOS,
  Seatbelt cannot restrict the grant to the requested host: `*:<port>` would
  admit every host on that port, so macOS refuses nonempty lists too.

`publish` requires IP literals. `allowTcp` accepts DNS names or IP literals.
IPv6 literals use brackets, as in `[::1]:8001`. Both require a port from 1 to
65535 and reject duplicates, with an error naming the entry.
IPv4 literals use four decimal octets without leading zeros. `allowTcp` retains
numeric IPv6 scopes, as in `[fe80::1%2]:22`.

Then run a command under it. With no `-s`, crabpot reads `~/.srt-settings.json`, as upstream does.

```sh
crabpot -s settings.json -- git pull
crabpot -s settings.json -c 'npm install && npm test'
```

`-d` prints debug output. Or use the library:

```rust
use std::path::Path;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // On Linux and Windows the sandbox runs this binary again as a helper.
    crabpot::run_from_args();

    let config = crabpot::Config::from_file(Path::new("settings.json"))?;
    let sandbox = crabpot::Sandbox::start(&config)?;
    let status = sandbox
        .command(Command::new("curl").arg("https://example.com"))?
        .status()?;
    println!("{status}");
    Ok(())
}
```

`Sandbox::start` refuses with a typed `StartError` that names what is missing. The sandbox's grants and proxy last until it drops.

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
- `Sandbox::start` refuses an unreadable runner by name (`StartError::RunnerUnreadable`) before it grants anything, so the binary is named instead of seclogon answering `CreateProcessWithLogonW: Access is denied`. It reads the executable's own access list for the sandbox account, the group it is in, and Users, Authenticated Users and Everyone, so a folder granted to the sandbox alone counts. Sitting under your profile is not enough on its own: the grant puts an inheritable entry on each folder it reaches, so what it excludes, what it leaves ungranted (your temporary directory) and any top-level item made after it ran are all refused. So is a binary moved in from another folder, which is what `cargo install` does: it keeps its old access list, a new grant writes nothing for it, and `icacls <path to the binary> /reset` re-applies the folder's inherited entries. A host can read that same check before it starts anything: `crabpot::windows_status()` reports it as `WindowsStatus::runner_readable`, `None` when the machine could not make the check.
- `--allow-loopback` opens every loopback port to the sandbox user, not only the proxy's. Every listener on localhost becomes reachable from the sandbox, including a forwarder that carries traffic off the machine. A session must use the loopback mode the install used, so changing it means running the install again with `--force`.
- `--proxy-port-range` sets the loopback ports left open for the proxy (default `60080-60089`). Each sandbox takes two of them, so the default range holds five sandboxes at once, and a session that finds every port of its range taken refuses with `StartError::ProxyRangeFull`, which names the range and the flag.
- `windows-uninstall` removes the user, its credential and the filters, and with them the profile read grant (`--keep-user` keeps the user and the grant). It then removes any WFP filters left under the sublayer.
- Both commands are for Windows and refuse on any other platform.

## License

MIT OR Apache-2.0, at your option.

crabpot is derived from anthropics/sandbox-runtime, which is Apache-2.0. See [NOTICE](NOTICE).
