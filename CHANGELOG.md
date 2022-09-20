# Changelog

All notable changes to python-linstor will be documented in this file starting from version 1.13.0,
for older version see github releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added autoplace-options to resource-group spawn method
- Added SED support for physical-storage create
- Added EBS support

### Changed

- linstor-common: update
- Compatible to API Version 1.15.0

## [1.14.0] - 2022-07-06

### Added

- Added methods for schedule backup
- SOS-Report: Added filters
- Added backup delete `keep-snaps` option

### Changed

- Compatible to API Version 1.14.0

## [1.13.1] - 2022-05-12

### Changed

- linstor-common update
- Documentation updates
- Compatible to API Version 1.13.0

### Fixes

- Fixed loading remotes with ETCD backend
- Autosnapshot: fix property not working on RG or controller

## [1.13.0] - 2022-05-22

### Added

- Added ZFS clone option for clone resource-definition
- Resource class: allow setting resource group
- Added resource sync status method
- Added backup snapshot name
- Added backup DB method

### Changed

- Compatible to API Version 1.13.0
