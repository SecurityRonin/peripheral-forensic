# peripheral-forensic

[![peripheral-forensic](https://img.shields.io/crates/v/peripheral-forensic.svg?label=peripheral-forensic)](https://crates.io/crates/peripheral-forensic)
[![peripheral-core](https://img.shields.io/crates/v/peripheral-core.svg?label=peripheral-core)](https://crates.io/crates/peripheral-core)
[![Docs.rs](https://img.shields.io/docsrs/peripheral-forensic)](https://docs.rs/peripheral-forensic)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/peripheral-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/peripheral-forensic/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

**Point it at a Windows `setupapi.dev.log`, get back severity-graded external-device anomalies — DMA-capable devices, mass storage, BadUSB-shaped HID, and OS-synthesized serials as `forensicnomicon::report::Finding`s.**

```toml
[dependencies]
peripheral-forensic = "0.1"   # pulls in peripheral-core
```

```rust
use peripheral_core::setupapi::parse_setupapi;
use peripheral_forensic::{audit, source};

let devices = parse_setupapi(&log, "setupapi.dev.log");

for anomaly in audit(&devices) {
    let finding = anomaly.to_finding(source("evidence-host"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
}
```

`audit(&devices)` grades a connection stream; `audit_findings(&devices, scope)` does the parse-to-`Finding` conversion in one call. A malformed log degrades line-by-line upstream in `peripheral-core`, never a panic.

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `PERIPHERAL-DMA-CAPABLE-DEVICE` | High | Threat | A FireWire / Thunderbolt / PCIe / ExpressCard device connected — consistent with a direct-memory-access attack surface (MITRE T1200) |
| `PERIPHERAL-MASS-STORAGE-CONNECTED` | Medium | Threat | Removable mass storage connected — consistent with data staging/exfiltration or autorun payload delivery (MITRE T1052.001 / T1091) |
| `PERIPHERAL-HID-DEVICE` | Medium | Threat | A human-interface device connected — consistent with keystroke-injection hardware such as BadUSB (MITRE T1200) |
| `PERIPHERAL-OS-GENERATED-SERIAL` | Low | Integrity | The device exposed no real iSerial (Windows synthesized one) — consistent with weaker device attribution |

## The threat-class map

The bus classification (from the device instance id's enumerator) drives which lens fires:

| Class | Buses | Lens |
|---|---|---|
| **DMA-capable** | FireWire, Thunderbolt, PCIe, ExpressCard | bus-mastering direct-memory-access (T1200) |
| **Mass storage** (NOT DMA) | USB mass storage, eSATA, SD/MMC, SCSI/SAS, NVMe | exfiltration / autorun (T1052.001 / T1091) |
| **HID / wireless** | USB-HID, Bluetooth | keystroke-injection / BadUSB (T1200) |

`audit(&devices)` returns the typed [`DeviceAnomaly`] stream; each anomaly emits a graded `report::Finding` via `to_finding(source)`. `source(scope)` stamps the analyzer provenance. MITRE techniques are narrated as *consistent with*, never as a verdict.

## The two-crate split

This crate is the **analyzer**; the **reader** is [`peripheral-core`](https://crates.io/crates/peripheral-core) (`setupapi.dev.log` / `setupapi.log` → bus-classified `DeviceConnection` with authoritative-vs-inferred timestamp tagging and the iSerial kept distinct from the volume serial). The split mirrors `ntfs-core`/`ntfs-forensic`. Together they feed [`issen`](https://github.com/SecurityRonin/issen) for cross-artifact correlation.

## v0.2 roadmap: registry `Enum\` + EVTX

The richest source — the registry `SYSTEM\CurrentControlSet\Enum\` keys, `MountedDevices`, the undocumented `0066` / `0067` Last-Arrival / Last-Removal device-property `FILETIME`s, and EVTX device events — requires the (unpublished) `winreg-core` and `winevt-forensic` crates and is deferred to v0.2. v0.1 is scoped to the self-contained `setupapi.dev.log` source and the complete data model.

## Trust, but verify

Built for untrusted logs from potentially compromised systems: `#![forbid(unsafe_code)]`; panic-free on crafted input (the workspace denies `clippy::unwrap_used` / `expect_used` in production code, parsing is lenient and bounds-checked); fuzzed with two `cargo-fuzz` targets (`setupapi` parse plus the full parse→audit pipeline) and exercised end-to-end against spec-exact `setupapi.dev.log` / `setupapi.log` fixtures, with planted traces re-surfaced.

---

[Privacy Policy](https://securityronin.github.io/peripheral-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/peripheral-forensic/terms/) · © 2026 Security Ronin Ltd
