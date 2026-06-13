# peripheral-forensic

An external-device (peripheral) connection reader and a graded anomaly auditor —
parse a Windows `setupapi.dev.log` from a log authored on **any** OS, then surface
the DMA-capable attack surfaces, removable mass storage, BadUSB-shaped HID
devices, and OS-synthesized serials that an attacker hoped you would scroll past.

Two crates, one workspace:

- **[`peripheral-core`](https://crates.io/crates/peripheral-core)** — the reader:
  parses `setupapi.dev.log` (Vista+) and `setupapi.log` (XP) into a uniform
  `DeviceConnection` stream — bus-classified, VID/PID/iSerial extracted, every
  timestamp tagged authoritative-vs-inferred, and the USB iSerial kept distinct
  from any volume serial. No `unsafe`, no regex engine, no date library.
- **[`peripheral-forensic`](https://crates.io/crates/peripheral-forensic)** — the
  analyzer: turns the connection stream into severity-graded
  [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s
  so external-device evidence aggregates uniformly with the rest of the fleet.

## Audit a setupapi log

```rust
use peripheral_core::setupapi::parse_setupapi;
use peripheral_forensic::{audit, source};

let devices = parse_setupapi(&log, "setupapi.dev.log");

for anomaly in audit(&devices) {
    let finding = anomaly.to_finding(source("evidence-host"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] PERIPHERAL-DMA-CAPABLE-DEVICE — a Thunderbolt device … consistent with a direct-memory-access attack surface (MITRE T1200)
}
```

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `PERIPHERAL-DMA-CAPABLE-DEVICE` | High | Threat | A FireWire / Thunderbolt / PCIe / ExpressCard device connected — consistent with a direct-memory-access attack surface (MITRE T1200) |
| `PERIPHERAL-MASS-STORAGE-CONNECTED` | Medium | Threat | Removable mass storage connected — consistent with data staging/exfiltration or autorun payload delivery (MITRE T1052.001 / T1091) |
| `PERIPHERAL-HID-DEVICE` | Medium | Threat | A human-interface device connected — consistent with keystroke-injection hardware such as BadUSB (MITRE T1200) |
| `PERIPHERAL-OS-GENERATED-SERIAL` | Low | Integrity | The device exposed no real iSerial (Windows synthesized one) — consistent with weaker device attribution |

## The threat-class map

| Class | Buses | MITRE |
|---|---|---|
| **DMA-capable** | FireWire, Thunderbolt, PCIe, ExpressCard | T1200 |
| **Mass storage** (NOT DMA) | USB mass storage, eSATA, SD/MMC, SCSI/SAS, NVMe | T1052.001 / T1091 |
| **HID / wireless** | USB-HID, Bluetooth | T1200 |

eSATA is a storage transport and is explicitly not DMA-capable.

## v0.2 roadmap: registry `Enum\` + EVTX

The richest source — the registry `SYSTEM\CurrentControlSet\Enum\` keys,
`MountedDevices`, the undocumented `0066` / `0067` Last-Arrival / Last-Removal
device-property `FILETIME`s, and EVTX device events — requires the (unpublished)
`winreg-core` and `winevt-forensic` fleet crates and is deferred to v0.2. v0.1 is
scoped to the fully self-contained `setupapi.dev.log` source.

## Trust but verify

`peripheral-core` is panic-free on untrusted input (lenient lossy-UTF-8 parsing,
no `unwrap` in production), fuzzed, and validated against spec-exact
`setupapi.dev.log` / `setupapi.log` fixtures matching the Microsoft text-log
grammar (Doer-Checker). A setupapi log is attacker-controllable evidence; the
reader treats it as such.

---

[Privacy Policy](https://securityronin.github.io/peripheral-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/peripheral-forensic/terms/) · © 2026 Security Ronin Ltd
