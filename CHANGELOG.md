# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For versions that have a major of 0, a convention is followed so that
the minor number is incremented when backward-incompatible changes are
made, while the third number is incremented for backward compatible
changes. For example, versions `0.2.x` are not compatible with `0.1.x`.

## [Unreleased]

## [0.3.1] - 2025-02-23

### Changed

* Go was updated to 1.24.0.

## [0.3.0] - 2024-05-21

### Added

* There is now a devcontainer definition based on the official Go image, Alpine
  version. This can be used locally to make fully static builds of handyproxy,
  as the C library in Alpine is musl.
* There is now a makefile in the project root which takes care of passing
  appropriate flags to `go build` in order to get static builds. In addition,
  it supports targets to run tests and create release builds, which don't have
  any symbols and thus are smaller.

### Changed

* Go was updated to 1.22.0.
* Minor code tweaks to take advantage of Go 1.22.
* The `hostname` package is now internal.
* The CI pipeline now builds stripped executables via the devcontainer.

## [0.2.1] - 2023-11-19

### Added

* Add hostname sniffing for TLS and HTTP connections.
* The `debug` build tag can be used to create a debug version that depends
* neither on Linux nor on REDIRECT rules; instead it just uses a configurable
* IP and port as the traffic target. Useful for tests and debug.

### Changed

* Bump Go to 1.20.

## [0.2.0] - 2021-08-23

### Added

* It is now possible to specify a connection timeout used when
  connecting to the proxy.

### Fixed

* When data forwarding stops in a given direction, the write end of the
  connection is closed to notify the end-of-file condition to the other
  side. This is important for clients that `shutdown` their connections
  rather than just `close`ing them and expect to be able to read the
  rest of the data from the server.
* Fix types used in syscall invocations, to better follow the standards.

### Changed

* If no dial timeout is specified, a finite default (currently 3
  minutes) is used. In previous versions, dialling would wait forever,
  unless the OS enforced its own built-in timeout. This makes the CLI
  behaviour non-backward compatible and is why this is not `v0.1.1`.

## [0.1.0] - 2021-07-30

### Added

* Working program and docs

<!-- vi: set tw=72 et sw=2 fo=tcroqan autoindent: -->
