# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-10-31


## [0.8.0] - 2026-10-31

### Added

- Relay direct TCP grants through CONNECT

### Fixed

- Keep proxy ports free for TCP grants and refuse scoped IPv6 grants
- Harden the TCP relay and its CONNECT handshake


## [0.7.0] - 2026-10-31

### Fixed

- Exit 125 when the sandbox refuses to start **(BREAKING)**
- Observe report completion before the pid
- Require the helper to acknowledge startup


## [0.6.0] - 2026-10-31

### Added

- Add addresses to loopback in a helper network namespace **(BREAKING)**

### Changed

- Group Linux command wrapping with its tests

### Fixed

- Limit platform imports after splitting Linux wrapping
- Clarify loopback failures and skip unavailable bwrap


## [0.5.12] - 2026-10-31


## [0.5.11] - 2026-10-31

### Fixed

- Signal the helper bwrap reports instead of walking /proc from bwrap
- Read bwrap's whole report and bound the launcher signal tests
- Collapse the nested if in the report reader
- Retry an interrupted report read and read the launcher's stderr on a thread


## [0.5.10] - 2026-10-30

### Fixed

- Forward host shutdown signals to the command
- Hold signals from bwrap until the helper forwards them


## [0.5.9] - 2026-10-30


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

