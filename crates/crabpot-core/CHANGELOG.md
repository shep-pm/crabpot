# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

