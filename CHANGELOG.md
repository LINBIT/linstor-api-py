# Changelog

All notable changes to python-linstor will be documented in this file starting from version 1.13.0,
for older version see github releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `resource_dfn_truncate()` to delete all resources of a resource definition ("truncate")
  without touching the resource definition or its snapshots, with an optional `delete_empty`
  parameter that additionally deletes the resource definition when it has no snapshots
- `delete_empty_resource_definition` parameter to `snapshot_delete()` that additionally deletes
  the resource definition when it has neither resources nor snapshots left after the deletion
- resource_make_available: new `auto_manage_dual_primary` parameter preparing a resource for a live
  migration (REST 1.29.0)
- New method resource_unmake_available reverting a make-available on the migration source node
  (REST 1.29.0)

## [1.28.2] - 2026-06-26

### Fixed

- AuthToken timestamp parsing (created_at, deleted_at, expires_at) no longer requires
  datetime.fromisoformat() (unavailable on Python 3.6) and now handles nanosecond and
  other arbitrary-precision fractions as well as 'Z'/numeric timezone offsets

## [1.28.1] - 2026-06-03

### Changed

- Auth token is no longer sent over plaintext HTTP connections. The HTTP->HTTPS redirect is now
  resolved once in connect() and the token is only attached once the connection is known to be
  secure (HTTPS), or when allow_insecure is set.

### Fixed

- Config.set_value() no longer errors if the config file directory doesn't exist

## [1.28.0] - 2026-05-28

### Added

- Added controller_exportdb
- Added platform property to responses.py
- Added support for linstor-controller token authentication and also checking for token file in /var/lib/linstor.d
- Added LUKSVolumeData.corrupted_key property
- Added drbd_client to
  - class "ResourceData"
  - method "resource_create"
  - method "resource_modify"
  - method "resource_toggle_disk"
  - class "DrbdResource" (exposed via "flags")

### Changed

- Removed py2 support
- Updated build system to use python build module

### Fixed

- Fixed Combined+SSL nodes getting controller port (3371) instead of satellite port (3367) in node_create()
- Fixed netinterface_modify() resetting encryption type when only port is changed
- Fixed incorrect Volume.layer_data, .drbd_data, .luks_data and .storage_data property methods

## [1.27.1] - 2025-12-10

### Added

- Added api method to check the controller's current encryption state (locked/unlocked/unset)

## [1.27.0] - 2025-11-11

### Added

- Added missing resource_dfn_clone() arguments to Resource.clone()
- Added optional parameter snapshot to backup_abort
- Added optional parameter force_full to backup_ship
- Added optional parameter src_snap to backup_ship
- Added optional parameter target to node_evacuate
- Added optional parameter do_not_target to node_evacuate

### Changed

- Fixed handling of clone api error status codes

## [1.26.1] - 2025-08-26

### Added

- Added optional dst_rsc_name to backup_schedule_enable

## [1.26.0] - 2025-08-18

### Added

- snapshot_dfn_modify() and properties to responses.SnapshotDefinition
- Add tcp_ports to DrbdResource
- snapshot_rollback(..., zfs_rollback_strategy=None)
- resource_dfn_clone() can now set and delete properties

### Fixed

- Error out if reading controller version fails

### Removed

- Removed deprecated EXOS methods
- Removed deprecated snapshot shipping methods. Use backup shipping instead

## [1.25.3] - 2025-04-10

### Added

- Add TLS certificate options to "curl" debug output

### Fixed

- Correctly pass parameters in error_report_delete
- resource_dfn_clone: Fix exception if curl option was set

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
