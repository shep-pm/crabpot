# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-31

### Added

- Add addresses to loopback in a helper network namespace **(BREAKING)**

### Changed

- Group Linux command wrapping with its tests

### Fixed

- Limit platform imports after splitting Linux wrapping
- Clarify loopback failures and skip unavailable bwrap


## [0.5.12] - 2026-10-31

### Fixed

- Validate numeric TCP hosts and preserve IPv6 scopes


## [0.5.11] - 2026-10-31

### Fixed

- Signal the helper bwrap reports instead of walking /proc from bwrap
- Read bwrap's whole report and bound the launcher signal tests
- Retry an interrupted report read and read the launcher's stderr on a thread


## [0.5.10] - 2026-10-30

### Fixed

- Forward host shutdown signals to the command
- Forward Linux signals past bwrap monitors
- Retain shutdown signals during helper startup
- Hold signals from bwrap until the helper forwards them


## [0.5.9] - 2026-10-30

### Fixed

- Make and grant the TMPDIR the sandbox sets
- Refuse a relative TMPDIR and accept another user's default folder
- Refuse a dotted TMPDIR and settle the review's smaller points


## [0.5.8] - 2026-10-30


## [0.5.7] - 2026-10-30

### Changed

- Share srt-win runner access check


## [0.5.6] - 2026-10-30


## [0.5.5] - 2026-10-30


## [0.5.4] - 2026-10-29

### Added

- Let a host read the runner check ahead of a start


## [0.5.3] - 2026-10-29

### Fixed

- Name icacls /reset for an unreadable runner moved in from another folder
- Name icacls /reset in the notice after an install that made no grant


## [0.5.2] - 2026-10-29

### Added

- Let a host read the variables that point a tool at the real user's config


## [0.5.1] - 2026-10-28

### Added

- Let a host ask which paths meet the profile exclusions


## [0.5.0] - 2026-10-28

### Fixed

- Let the folders between a read deny and a grant beneath it be stat'd
- Give the metadata sandbox test a complete config, and let the patched srt-win files grow


## [0.4.0] - 2026-10-28

### Added

- Honour git.safeDirectories on every platform


## [0.3.2] - 2026-10-28

### Fixed

- Keep the wrapper's environment on the command it runs
- Keep the carried environment within the srt-win command line


## [0.3.1] - 2026-10-28

### Fixed

- Run an executable without the cmd.exe hop so its arguments stay as given
- Keep cmd.exe on the quoted line and pick a program as cmd.exe would
- Try only .exe on a name with no extension, as std does


## [0.3.0] - 2026-10-28

### Added

- Carry what a failed srt-win call printed in StartError **(BREAKING)**


## [0.2.1] - 2026-10-25


## [0.1.2] - 2026-10-23


## [0.1.1] - 2026-10-23


## [0.1.0] - 2026-10-23

### Added

- Split the repository into crabpot, crabpot-core, crabpot-macos and harness
- Run a command under sandbox-exec with the default settings
- Refuse a settings file as upstream refuses it
- Give the sandboxed command the env that needs no proxy
- Admit the SOCKS port and point SOCKS-only clients at it
- Refuse a name that resolves to an address it may not reach
- Refuse a Mach service a command may look up with network.denyMachLookup

### Fixed

- Refuse settings the stub cannot honour, and a named file that is missing
- Leave a command's own JAVA_TOOL_OPTIONS to the command
- Gate the proxy import to the platform that uses it
- Set the nc -X 5 GIT_SSH_COMMAND only without an HTTP proxy
- Bind and dial socket paths past sun_path as upstream does

