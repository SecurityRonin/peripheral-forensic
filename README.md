# peripheral-forensic

[![peripheral-core](https://img.shields.io/crates/v/peripheral-core.svg?label=peripheral-core)](https://crates.io/crates/peripheral-core)
[![peripheral-forensic](https://img.shields.io/crates/v/peripheral-forensic.svg?label=peripheral-forensic)](https://crates.io/crates/peripheral-forensic)
[![Docs.rs](https://img.shields.io/docsrs/peripheral-forensic)](https://docs.rs/peripheral-forensic)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/peripheral-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/peripheral-forensic/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

**Point it at a Windows `setupapi.dev.log` and get back severity-graded external-device anomalies — the DMA-capable Thunderbolt/FireWire/PCIe attack surfaces, the removable mass storage, the BadUSB-shaped HID devices, and the OS-synthesized serials that weaken attribution — as `forensicnomicon::report::Finding`s.**

Two crates, one workspace:

- **[`peripheral-core`](https://crates.io/crates/peripheral-core)** — the reader: parses `setupapi.dev.log` (Vista+) and `setupapi.log` (XP) device-installation logs into a uniform [`DeviceConnection`] stream — bus-classified, VID/PID/iSerial extracted, and every timestamp tagged authoritative-vs-inferred. Pure Rust, no `unsafe`, no regex engine, no date library.
- **[`peripheral-forensic`](https://crates.io/crates/peripheral-forensic)** — the analyzer: turns the connection stream into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, so external-device evidence aggregates uniformly with the rest of the forensic fleet.

## Audit a setupapi log in 30 seconds

```toml
[dependencies]
peripheral-forensic = "0.1"   # pulls in peripheral-core
```

```rust
use peripheral_core::setupapi::parse_setupapi;
use peripheral_forensic::{audit, source};

let log = std::fs::read_to_string(r"C:\Windows\INF\setupapi.dev.log")?;
let devices = parse_setupapi(&log, "setupapi.dev.log");

for anomaly in audit(&devices) {
    let finding = anomaly.to_finding(source("evidence-host"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] PERIPHERAL-DMA-CAPABLE-DEVICE — a Thunderbolt device … consistent with a direct-memory-access attack surface (MITRE T1200)
}
# Ok::<(), std::io::Error>(())
```

`audit(&devices)` returns the typed [`DeviceAnomaly`] stream; `audit_findings(&devices, scope)` does the parse-to-`Finding` conversion in one call. A malformed or garbled log degrades line-by-line, never a panic.

## The `DeviceConnection` model

One record per device-install section header. The forensic cautions are baked into the **type**, not just the docs:

- **`device_serial` is the USB iSerial — a distinct field from `volume_serial`.** A filesystem volume serial and a device's hardware serial are different things; keeping them separate fields means the two can never be conflated in correlation.
- **`serial_is_os_generated: bool`** — `true` when the instance-id serial's 2nd character is `&` (e.g. `7&1c2c4f0a&0`). Windows synthesized the serial because the device exposed no real iSerial, so attribution back to a specific physical device is weaker. The OS-generated value is *not* reported as a real `device_serial`.
- **Every timestamp is a `Stamp { value, confidence }`.** `first_install` from the setupapi section header is `Authoritative`; the registry-derived `last_arrival` / `last_removal` (the undocumented `0066` / `0067` device properties) are `Inferred` — and arrive only in v0.2.
- **Correlation join keys** (`parent_id_prefix`, `volume_guid`, `drive_letter`, `volume_serial`, `disk_signature`) and a **threat lens** (`dma_capable`, `mitre`) round out the record.

## Bus classification and the threat lenses

The enumerator (the leading token of a device instance id) classifies the [`Bus`], which drives two threat lenses:

| Class | Buses | Lens | MITRE |
|---|---|---|---|
| **DMA-capable** | FireWire, Thunderbolt, PCIe, ExpressCard | Bus-mastering direct-memory-access attack surface | T1200 |
| **Mass storage** (NOT DMA) | USB mass storage, eSATA, SD/MMC, SCSI/SAS, NVMe | Data staging/exfiltration, autorun payload | T1052.001 / T1091 |
| **HID / wireless** | USB-HID, Bluetooth | Keystroke-injection (BadUSB) | T1200 |

eSATA is a SATA/storage transport and is **explicitly not** DMA-capable. (Caveat: SD-Express tunnels PCIe and *can* be DMA-capable; v0.1 treats bare `SD` as the legacy non-DMA SD/MMC bus — distinguishing SD-Express needs the device-capability bits the v0.2 registry source carries.)

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `PERIPHERAL-DMA-CAPABLE-DEVICE` | High | Threat | A FireWire / Thunderbolt / PCIe / ExpressCard device connected — consistent with a direct-memory-access attack surface (MITRE T1200) |
| `PERIPHERAL-MASS-STORAGE-CONNECTED` | Medium | Threat | Removable mass storage connected — consistent with data staging/exfiltration or autorun payload delivery (MITRE T1052.001 / T1091) |
| `PERIPHERAL-HID-DEVICE` | Medium | Threat | A human-interface device connected — consistent with keystroke-injection hardware such as BadUSB (MITRE T1200) |
| `PERIPHERAL-OS-GENERATED-SERIAL` | Low | Integrity | The device exposed no real iSerial (Windows synthesized one) — consistent with weaker device attribution |

## What's parsed (setupapi format coverage)

`parse_setupapi(text, file)` handles both header grammars, with the real-world `>>>  ` / `<<<  ` section markers stripped:

- **Vista+** — description first, timestamp last: `[Device Install (Hardware initiated) - USB\VID_0781&PID_5583\<serial> 2023/04/15 14:23:11.456]`
- **XP** — timestamp first: `[2005/05/12 12:34:56 632.5] Device Install - USB\VID_...`

VID/PID, enumerator, and iSerial are extracted from the device instance id; the section-header time becomes the authoritative `first_install`. Lines that match neither grammar are skipped — never a panic.

## v0.2 roadmap: registry `Enum\` + EVTX

The richest source — the Windows registry `SYSTEM\CurrentControlSet\Enum\` keys (USBSTOR/USB serials, `ParentIdPrefix`), `MountedDevices` (volume serial / drive-letter / disk-signature correlation), the undocumented `0066` / `0067` Last-Arrival / Last-Removal device-property `FILETIME`s, and the EVTX device-connection events — requires the (unpublished) `winreg-core` and `winevt-forensic` fleet crates. They are deferred to **v0.2**; v0.1 is scoped to the fully self-contained `setupapi.dev.log` source and the complete data model.

## Trust, but verify

Built for untrusted logs acquired from potentially compromised systems:

- **`#![forbid(unsafe_code)]`** across both crates — no FFI, no C bindings. It reads a log authored on Windows from any OS.
- **Panic-free on malicious input** — parsing is lenient (lossy UTF-8) and bounds-checked; the workspace denies `clippy::unwrap_used` / `expect_used` in production code. A truncated or garbled log degrades line-by-line, never a crash.
- **Fuzzed** — two `cargo-fuzz` targets (`setupapi` parse, `forensic` full parse→audit pipeline); a `fuzz.yml` CI workflow builds and smoke-runs each.
- **Validated against spec-exact fixtures** — the analyzer is exercised end-to-end against `setupapi.dev.log` / `setupapi.log` fixtures matching the Microsoft SetupAPI text-log grammar, with planted DMA / mass-storage / HID / OS-generated-serial traces re-surfaced (see `forensic/tests/real_data.rs`).

```bash
cargo test
cargo +nightly fuzz run forensic   # requires nightly + cargo-fuzz
```

## Where this fits

`peripheral-forensic` is one analyzer in the SecurityRonin forensic fleet. The reader/analyzer split mirrors `ntfs-core`/`ntfs-forensic`; findings are emitted in the shared `forensicnomicon::report` vocabulary so [`issen`](https://github.com/SecurityRonin/issen) can correlate external-device evidence with disk, memory, and log artifacts.

---

[Privacy Policy](https://securityronin.github.io/peripheral-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/peripheral-forensic/terms/) · © 2026 Security Ronin Ltd
