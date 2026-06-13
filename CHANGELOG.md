# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned — v0.2 (registry `Enum\` + EVTX enrichment)

- Windows registry `SYSTEM\CurrentControlSet\Enum\` (USBSTOR/USB) source — real
  iSerials, `ParentIdPrefix`, friendly names; `MountedDevices` for volume-serial
  / drive-letter / disk-signature correlation join keys; the undocumented
  `0066` / `0067` Last-Arrival / Last-Removal device-property `FILETIME`s
  (populating the `Inferred` `last_arrival` / `last_removal` stamps).
- EVTX device-connection events.
- Both require the (unpublished) `winreg-core` and `winevt-forensic` fleet
  crates and are therefore out of scope for v0.1.

## [peripheral-core 0.1.0 / peripheral-forensic 0.1.0] — 2026-06-13

### Added — `peripheral-core` (reader)

- From-scratch `setupapi.dev.log` (Vista+) and `setupapi.log` (XP) parser —
  no regex engine, no date library, pure Rust. Real-world `>>>` / `<<<` section
  markers are stripped; both header grammars are handled; non-matching lines are
  skipped, never panicked on.
- `DeviceConnection` model with the three forensic cautions baked into the type:
  the USB `device_serial` (iSerial) is a distinct field from `volume_serial`;
  `serial_is_os_generated` flags an instance-id serial whose 2nd character is `&`
  (Windows-synthesized, weaker attribution); every timestamp is a
  `Stamp { value, confidence }` tagged `Authoritative` vs `Inferred`.
- `Bus` enum + `from_enumerator` classifier (`USBSTOR`/`USB`→Usb, `1394`→FireWire,
  `SCSI`→ScsiSas, `PCI`→Pcie, `SD`→SdMmc, `WpdBusEnumRoot`→Mtp, …) with the
  `is_dma_capable` (FireWire / Thunderbolt / PCIe / ExpressCard) and
  `is_mass_storage` (USB / eSATA / SD-MMC / SCSI-SAS / NVMe) threat-class lenses.
- VID/PID and iSerial extraction from the device instance id; authoritative
  `first_install` from the section-header timestamp.

### Added — `peripheral-forensic` (analyzer)

- `PERIPHERAL-DMA-CAPABLE-DEVICE` (High / Threat) — FireWire / Thunderbolt /
  PCIe / ExpressCard device; MITRE T1200.
- `PERIPHERAL-MASS-STORAGE-CONNECTED` (Medium / Threat) — removable mass storage;
  MITRE T1052.001 / T1091.
- `PERIPHERAL-HID-DEVICE` (Medium / Threat) — a HID device (possible BadUSB);
  MITRE T1200.
- `PERIPHERAL-OS-GENERATED-SERIAL` (Low / Integrity) — device exposed no real
  iSerial; weaker attribution.
- `audit` (typed `DeviceAnomaly` stream) and `audit_findings` (graded
  `forensicnomicon::report::Finding`s in one call). Each anomaly emits a graded
  `Finding` via the `Observation` trait; `source(scope)` stamps the analyzer
  provenance. Notes are hedged observations, never verdicts.

### Security

- `#![forbid(unsafe_code)]` across both crates; the workspace denies
  `clippy::unwrap_used` / `expect_used` in production code; the parser is
  panic-free and bounds-checked on adversarial input.
- Two `cargo-fuzz` targets (`setupapi`, `forensic`) with PR smoke-fuzzing and a
  scheduled weekly run.

### Testing

- Production-line coverage with `cargo-llvm-cov` (genuinely-unreachable defensive
  guards annotated `// cov:unreachable`).
- Analyzer exercised end-to-end against spec-exact `setupapi.dev.log` /
  `setupapi.log` fixtures matching the Microsoft SetupAPI text-log grammar, with
  planted DMA / mass-storage / HID / OS-generated-serial traces re-surfaced.

[Unreleased]: https://github.com/SecurityRonin/peripheral-forensic/compare/v0.1.0...HEAD
[peripheral-core 0.1.0 / peripheral-forensic 0.1.0]: https://github.com/SecurityRonin/peripheral-forensic/releases/tag/v0.1.0
