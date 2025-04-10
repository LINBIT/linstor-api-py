# Changelog

All notable changes to python-linstor will be documented in this file starting from version 1.13.0,
for older version see github releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add TLS certificate options to "curl" debug output

### Fixed

- Correctly pass parameters in error_report_delete

## [1.25.2] - 2025-04-08

### Changed

- remove replication_state and done_percentage, but added instead replication_states

## [1.25.1] - 2025-04-02

### Fixed

- Correctly encode all rest url path calls

## [1.25.0] - 2025-03-19

### Added

- responses: replication_state and done_percentage to volume

## [1.24.0] - 2024-12-17

### Added

- Added options dst_rsc_grp and force_rsc_grp to BackupShip, BackupRestore and BackupSchedule
- resource_definition_clone: add layer_list parameter
- resource_definition_clone: add resource_group parameter
- Added responses ResourdeDfnLayerData object and some mor layer_stack props

## [1.23.1] - 2024-09-25

### Changed
- updated linstor-common properties

## [1.23.0] - 2024-07-11

### Added

- Autoplacer: Add --x-replicas-on-different option
- Resource delete: Add keep_tiebreaker parameter

## [1.22.0] - 2024-04-02

### Changed
- LinstorApi is now parsing .conf files in /etc/linstor/linstor-client.d and merging with other client conf

### Fixed
- resource-group list throwing error in curl mode
- volume-group list throwing error in curl mode

## [1.21.1] - 2024-02-22

### Changed

- Updated linstor-common reference

## [1.21.0] - 2024-01-22

### Added

- Add optional peer_slots parameter to resource_group_{create,modify,spawn}
- Allow storpool rename map on snap restore an schedule enable

### Fixed

- resource.py exception if a resource reply is an apicallrc

## [1.20.1] - 2023-10-25

### Added

- Add set_log_level for controller and node

## [1.20.0] - 2023-10-11

### Added

- Add EffectiveProps structure

### Changed

- Updated linstor-common code

## [1.19.0] - 2023-07-19

### Added

- Added backup queue list methods 

## [1.18.0] - 2023-04-17

### Added

- Added snapshot_create_multi method to create snapshots of multiple resources

### Changed

- SizeCalc now supports sector units

### Fixed

- RscDfn create doesn't ignore peerslot

## [1.17.0] - 2023-03-14

### Added

- Added resource_group_query_size_info() method

## [1.16.0] - 2022-12-13

### Added

- Add node-connection methods

## [1.15.1] - 2022-10-18

### Added

- SnapVlm: Add response object for state

### Fixed

- Fixed sos_report_create and sos_report_download since parameter concatenation


## [1.15.0] - 2022-09-20

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
