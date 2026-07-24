# 2. Dependency direction and prefer-our-own crates

Date: 2026-07-24
Status: Accepted

## Context

The reader needs to walk Windows registry hives (`SYSTEM`,
`SOFTWARE`, `NTUSER.DAT`) to reach the `Enum\` device keys, `MountedDevices`,
`VolumeInfoCache`, `MountPoints2`, and `EMDMgmt`. The analyzer needs a shared
reporting vocabulary so its findings aggregate uniformly with the rest of the
fleet inside `issen`. Both are places where a third-party crate (a general hive
parser, a bespoke finding type) could have been reached for.

The fleet constitution binds two rules here: **prefer our own
(SecurityRonin/`h4x0r`) crates** over third-party equivalents, and the layer
dependency direction — a PARSER/analyzer depends **down** onto the KNOWLEDGE
leaf `forensicnomicon`, never sideways or up.

## Decision

- `peripheral-core` reads hives through the fleet hive parser **`winreg-core`**
  (`core/Cargo.toml`: `winreg-core = "0.2"`), not a third-party registry crate.
  `setupapi` and `linux_syslog` parsing stay dependency-free text handling (no
  regex engine, no date library).
- `peripheral-forensic` depends on **`peripheral-core`** (the reader) and
  **`forensicnomicon`** (`forensic/Cargo.toml`: `forensicnomicon = "1"`), and on
  nothing below the reader. It emits `forensicnomicon::report::Finding` via the
  `Observation` trait rather than defining a bespoke `XxxAnalysis` type.
- The `peripheral-core` dependency is declared as both a registry version and a
  workspace `path` (`{ version = "0.8", path = "../core" }`) so in-workspace
  builds use the local crate while published consumers resolve the registry
  version.

## Consequences

External-device findings render uniformly alongside disk, memory, and log
artifacts because they share the `forensicnomicon::report` model. Using
`winreg-core` means hive-format fixes and hardening accrue fleet-wide instead of
being re-derived here. The reader stays medium-agnostic on its non-hive paths:
`setupapi`/`linux_syslog` take `&str`, and the registry modules take an
already-opened `Hive`, so the caller owns the hive-open bootstrap (which must
fail loudly on its own) and the reader functions stay total over a valid hive.
