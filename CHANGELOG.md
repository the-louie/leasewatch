# Changelog

All notable changes to leasewatch are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.1.0 (unreleased)

### Added

- **Connector instances:** `LW_CONNECTORS` lists named instances, each configured with `LW_CONNECTOR__<NAME>__<KEY>` (`TYPE` required, `TIMEOUT` per instance, `<KEY>_FILE` for secrets such as Docker secrets). Several firewalls, switches or controllers can run side by side. A wrong setting stops the start with a message that names the instance and the key.
- Each instance collects in its own thread with its own timeout. A failing or slow instance greys only its own status dot and keeps its last values; a failed first probe is retried with a backoff up to 10 minutes. The poll fails only when every sighting-producing instance failed.
- **Per-instance status:** one status dot per instance in the page (the switch's `NAME`, "Wi-Fi" for the controller) and `GET /api/status` with a `connectors` list (`name`, `label`, `type`, `ok`, `error`, `ts`, `ms`, `count`, `strategy`, `enabled`).
- **SNMP profiles** for the switch lookup: `standard`, `comware`, `cisco_ios`, `routeros`, `jetstream`, `zynos`, `edgeswitch`, detected from sysObjectID/sysDescr or set with `PROFILE`; your own JSON profile with `PROFILE_FILE` (it may extend a built-in one); `MIN_MACS` for the uplink threshold. Legacy variables: `SNMP_PROFILE`, `SNMP_PROFILE_FILE`, `SNMP_MIN_MACS`.
- **Cisco IOS:** the forwarding table is read per VLAN through SNMPv3 `vlan-<N>` contexts, with a fallback to Q-BRIDGE (logged once per instance) when the contexts are unavailable.
- Commands `python -m leasewatch snmp-profiles` (list the built-in profiles) and `python -m leasewatch snmp-detect <instance>` (sysObjectID, sysDescr, chosen profile and the first rows of each walk).
- **Seen by** on the device page: one line per instance that listed the device, with when it last did and whether it was on the wire.
- **Several switches:** an edge port beats an uplink port, then the newest observation, then the order in `LW_CONNECTORS`. The instance that placed a device is stored as `loc_source` (also a CSV column).

### Changed

- Without `LW_CONNECTORS` the existing `FW1_*`, `SNMP_*` and `UNIFI_*` variables work unchanged; they describe the instances `fw1`, `switch` and `unifi`.
- The database gets a `schema_version` and is migrated automatically at the first start (a `seen` table and the `loc_source` column). The migration is one-way: back up `DATA_DIR` before the upgrade if you may go back to 1.0.
- SNMP errors never contain the switch address; an error from a per-VLAN walk names the VLAN.
- The startup line names each instance and its type, without URLs.

### Deprecated

- The `switch` and `unifi` objects in the API `meta` block. Use `meta.connectors`; the old objects go away in 1.2.

## 1.0.0

First release; see the git tag `v1.0.0`.
