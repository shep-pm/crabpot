# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

