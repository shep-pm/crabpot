# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.10] - 2026-10-30


## [0.5.9] - 2026-10-30


## [0.5.8] - 2026-10-30

### Changed

- Move the runner access tests out of logon.rs

### Fixed

- Honour a deny for the sandbox user in the runner check
- Read the DACL in order and count every deny that blocks a read
- Count a grant ahead of a deny from the ordered walk


## [0.5.7] - 2026-10-30

### Changed

- Share srt-win runner access check


## [0.5.6] - 2026-10-30

### Fixed

- Name a runner the sandbox user cannot read
- Say read and execute in the unreadable-runner error


## [0.5.5] - 2026-10-30

### Fixed

- Skip the session folder grant from session 0


## [0.5.4] - 2026-10-29


## [0.5.3] - 2026-10-29


## [0.5.2] - 2026-10-29


## [0.5.1] - 2026-10-28


## [0.5.0] - 2026-10-28

### Fixed

- Let the folders between a read deny and a grant beneath it be stat'd
- Put the metadata allow ahead of a read deny on the same folder


## [0.4.0] - 2026-10-28

### Added

- Honour git.safeDirectories on every platform


## [0.3.2] - 2026-10-28


## [0.3.1] - 2026-10-28


## [0.3.0] - 2026-10-28


## [0.2.1] - 2026-10-25

