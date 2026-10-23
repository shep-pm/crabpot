# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

