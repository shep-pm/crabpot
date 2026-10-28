# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-10-28


## [0.4.0] - 2026-10-28

### Added

- Honour git.safeDirectories on every platform


## [0.3.2] - 2026-10-28


## [0.3.1] - 2026-10-28


## [0.3.0] - 2026-10-28


## [0.2.1] - 2026-10-25


## [0.2.0] - 2026-10-24


## [0.1.7] - 2026-10-24


## [0.1.6] - 2026-10-24

### Added

- Give the command SANDBOX_RUNTIME and TMPDIR


## [0.1.5] - 2026-10-23


## [0.1.4] - 2026-10-23


## [0.1.3] - 2026-10-23


## [0.1.2] - 2026-10-23

### Changed

- Move the dangerous file and directory lists to crabpot-core


## [0.1.1] - 2026-10-23


## [0.1.0] - 2026-10-23

### Added

- Split the repository into crabpot, crabpot-core, crabpot-macos and harness
- Run a command under sandbox-exec with the default settings
- Allow writes to the default roots and to allowWrite
- Take denyWrite paths back from allowWrite
- Admit the SOCKS port and point SOCKS-only clients at it
- Serve HTTP and SOCKS on one loopback port, as upstream's mux does **(BREAKING)**

### Fixed

- Set the nc -X 5 GIT_SSH_COMMAND only without an HTTP proxy
- Keep git's shell from expanding the ssh proxy script
- Reopen create and unlink for the write roots the read denies pin
- Keep a read-denied name inside a write root from being renamed
- Keep a read-denied glob inside a write root from being renamed

