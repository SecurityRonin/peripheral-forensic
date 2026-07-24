# 1. Reader/analyzer split and Pattern A crate naming

Date: 2026-07-24
Status: Accepted

## Context

External-device connection forensics has two separable concerns: **decoding**
the raw evidence sources (Windows `setupapi.dev.log`, `SYSTEM`/`SOFTWARE`/
`NTUSER.DAT` hive keys, Linux kernel logs) into a normalized record, and
**judging** those records for anomalies (DMA-capable devices, mass storage,
HID/BadUSB, OS-generated serials). A single crate would force a consumer that
only wants the decoded `DeviceConnection` stream — e.g. `issen` correlation, or
another fleet tool — to also compile the `forensicnomicon` reporting dependency
and the grading logic.

The fleet Crate-structure standard (ronin-issen `CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates, for a single-format repo, exactly
two crates: `<x>-core` (the reader) and `<x>-forensic` (the analyzer), in one
workspace named `<x>-forensic`.

## Decision

Ship a two-member Cargo workspace (`Cargo.toml` `members = ["core", "forensic"]`):

- **`core/` → `peripheral-core`** — the reader. Parses every source into a
  uniform `DeviceConnection` stream. Emits no findings. Depends only on
  `winreg-core` (hive access) and, for `setupapi`/`linux_syslog`, nothing.
- **`forensic/` → `peripheral-forensic`** — the analyzer. Consumes
  `peripheral_core::DeviceConnection` and emits graded
  `forensicnomicon::report::Finding`s via the `Observation` trait.

Naming follows Pattern A (single-format repo): the bare `peripheral-core` /
`peripheral-forensic` names were free on crates.io, so no `[lib] name`
override or collision-driven rename was needed; the import path is
`peripheral_core`. The analyzer is deliberately **not** renamed to a suite form —
Pattern A reserves `<x>-forensic` for exactly this one-reader/one-analyzer shape.

## Consequences

A downstream tool links `peripheral-core` alone for the decoded stream without
pulling `forensicnomicon`. The two crates version independently
(`peripheral-core` at 0.8.1 has iterated well ahead of `peripheral-forensic` at
0.2.0, reflecting that most work has been new reader sources). The split matches
`ntfs-core`/`ntfs-forensic` and the rest of the fleet, so the repo reads
consistently. The workspace root owns edition, MSRV, license, authors, and the
lint posture so both members inherit one policy.
