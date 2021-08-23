# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For versions that have a major of 0, a convention is followed so that
the minor number is incremented when backward-incompatible changes are
made, while the third number is incremented for backward compatible
changes. For example, versions `0.2.x` are not compatible with `0.1.x`.

## [Unreleased]

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
