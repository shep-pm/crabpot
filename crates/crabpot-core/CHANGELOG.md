# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-10-31

### Added

- Allow resolved TCP destinations on their ports
- Relay direct TCP grants through CONNECT


## [0.7.0] - 2026-10-31


## [0.6.0] - 2026-10-31


## [0.5.12] - 2026-10-31

### Added

- Parse published socket addresses
- Validate direct TCP destinations
- Refuse unsupported TCP and publish grants

### Fixed

- Reject invalid and duplicate published ports
- Validate numeric TCP hosts and preserve IPv6 scopes


### Fixes

- Reject malformed numeric `allowTcp` hosts instead of treating them as DNS names ([#290])
- Preserve numeric IPv6 scopes in `allowTcp` destinations and duplicate checks ([#290])

### Additions

- Parse `network.publish` and `network.allowTcp`, refusing grants unsupported on the current platform ([#290])

## [0.5.11] - 2026-10-31


## [0.5.10] - 2026-10-30


## [0.5.9] - 2026-10-30

### Fixed

- Make and grant the TMPDIR the sandbox sets
- Refuse a temp link spelled with a trailing slash
- Grant the chosen temp folder as a name, not a pattern
- Refuse a relative TMPDIR and accept another user's default folder
- Grant a temp folder beneath a link by its real path
- Refuse a dotted TMPDIR and settle the review's smaller points


## [0.5.8] - 2026-10-30


## [0.5.7] - 2026-10-30


## [0.5.6] - 2026-10-30


## [0.5.5] - 2026-10-30


## [0.5.4] - 2026-10-29


## [0.5.3] - 2026-10-29


## [0.5.2] - 2026-10-29


## [0.5.1] - 2026-10-28


## [0.5.0] - 2026-10-28


## [0.4.0] - 2026-10-28

### Added

- Honour git.safeDirectories on every platform


## [0.3.2] - 2026-10-28


## [0.3.1] - 2026-10-28


## [0.3.0] - 2026-10-28


## [0.2.1] - 2026-10-25

### Added

- Dial a mitmProxy named pipe on Windows as upstream does


## [0.2.0] - 2026-10-24

### Added

- Read the windows group and ignore the keys upstream ignores on Windows


## [0.1.7] - 2026-10-24

### Added

- Refuse the Linux-only keys that change enforcement on Linux


## [0.1.6] - 2026-10-24

### Added

- Give the command SANDBOX_RUNTIME and TMPDIR


## [0.1.5] - 2026-10-23

### Fixed

- Keep a deny in /proc to its spelling alone


## [0.1.4] - 2026-10-23

### Added

- Connect mitmProxy.socketPath over AF_UNIX on Windows

### Fixed

- Use a short socket path in the Windows connect tests


## [0.1.3] - 2026-10-23

### Added

- Build the proxies on Windows and bind them inside srt-win's port range


## [0.1.2] - 2026-10-23

### Changed

- Move the dangerous file and directory lists to crabpot-core


## [0.1.1] - 2026-10-23

### Added

- Serve the mux on a Unix socket too


## [0.1.0] - 2026-10-23

### Added

- Split the repository into crabpot, crabpot-core, crabpot-macos and harness
- Turn a glob into the regex upstream does
- Resolve filesystem path entries as upstream does
- Read upstream's settings schema and refuse the keys crabpot cannot honour
- An HTTP proxy that tunnels to the hosts allowedDomains covers
- Honour network.allowedDomains instead of refusing it
- Honour network.deniedDomains, which beats allowedDomains
- Send mitmProxy domains through a Unix socket tunnel

### Fixed

- Refuse a refused key of the wrong type instead of reading it as not asking
- Forward one plain request and stop the proxy without waiting on a lookup
- Bind and dial socket paths past sun_path as upstream does
- Create sockets close-on-exec atomically, and lay out BSD headers
- Set SO_NOSIGPIPE on the sockets made for macOS
