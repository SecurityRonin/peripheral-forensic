# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [peripheral-core 0.3.0] — 2026-07-11

### Added — `peripheral-core` (reader)

- `MountedDevices` drive-letter join: `parse_registry` now decodes the SYSTEM
  `MountedDevices` key and sets `DeviceConnection.drive_letter` for device-path
  entries under `\DosDevices\X:` (the UTF-16LE `\??\<CLASS>#<Ven&Prod>#<instance>#{guid}`
  form that names a device instance directly). MBR records and volume-GUID names
  carry no drive letter and are skipped; the decoders are panic-free and total.
  Validated Tier-1 on the real Szechuan hive (regipy oracle: `D:` → the CD-ROM
  device instance).

## [peripheral-core 0.2.0 / peripheral-forensic 0.2.0] — 2026-07-11

### Added — `peripheral-core` (reader)

- Windows registry `SYSTEM\CurrentControlSet\Enum\{USBSTOR,SCSI,USB}` device
  source (`registry` module, over `winreg-core`) — real device iSerials,
  friendly names, and the device-property `FILETIME`s under
  `Properties\{83da6326-…}\`: `0064` install, `0065` first-install, and the
  undocumented `0066` / `0067` Last-Arrival / Last-Removal stamps that populate
  the `Inferred` `last_arrival` / `last_removal` fields. Decoder validated
  Tier-1 against `regipy` on the real DFIRMadness Szechuan SYSTEM hive.
- Linux kernel-log (`syslog` / `dmesg`) USB source (`linux_syslog` module) —
  parses `usb … idVendor=…, idProduct=…` connection blocks into
  `DeviceConnection`s. Validated against a real UAC-collected `installer/syslog`.

### Fixed — `peripheral-core`

- `setupapi` `civil_to_epoch` no longer panics on a malformed log line carrying
  an out-of-range year; the year is bounded to `1..=9999` before the day/second
  multiplications (fuzz-found integer overflow, regression-tested and seeded in
  the fuzz corpus).

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
