# peripheral-core

[![peripheral-core](https://img.shields.io/crates/v/peripheral-core.svg?label=peripheral-core)](https://crates.io/crates/peripheral-core)
[![peripheral-forensic](https://img.shields.io/crates/v/peripheral-forensic.svg?label=peripheral-forensic)](https://crates.io/crates/peripheral-forensic)
[![Docs.rs](https://img.shields.io/docsrs/peripheral-core)](https://docs.rs/peripheral-core)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/peripheral-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/peripheral-forensic/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

**An external-device connection reader — parses Windows `setupapi.dev.log` device-installation logs into a uniform, bus-classified `DeviceConnection` stream with authoritative-vs-inferred timestamp tagging. No `unsafe`, no regex engine, no date library — reads a log authored on Windows from any OS.**

```toml
[dependencies]
peripheral-core = "0.1"
```

```rust
use peripheral_core::{setupapi::parse_setupapi, Bus, Confidence};

let log = "[Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\AABBCCDD 2023/04/15 14:23:11.456]";
let devices = parse_setupapi(log, "setupapi.dev.log");

assert_eq!(devices[0].bus, Bus::Usb);
assert_eq!(devices[0].vid, Some(0x0781));
assert_eq!(devices[0].device_serial.as_deref(), Some("AABBCCDD"));
// The section-header install time is the authoritative first-seen timestamp.
assert_eq!(devices[0].first_install.unwrap().confidence, Confidence::Authoritative);
```

## What it parses

`parse_setupapi(text, file)` extracts one `DeviceConnection` per device-install section header, in both grammars (with the real-world `>>>` / `<<<` section markers stripped):

- **Vista+** (`setupapi.dev.log`) — description first, timestamp last inside the brackets.
- **XP** (`setupapi.log`) — timestamp first inside the brackets, device path after.

VID/PID, the enumerator (which classifies the [`Bus`]), and the iSerial are pulled from the device instance id; out-of-range or malformed timestamps drop to `None`, never a panic.

## The `DeviceConnection` model

The three known forensic cautions are baked into the **type**:

- **`device_serial`** is the **USB iSerial** — a distinct field from **`volume_serial`** (a filesystem volume serial), so the two can never be conflated.
- **`serial_is_os_generated`** is `true` when the instance-id serial's 2nd character is `&` (Windows synthesized it — the device had no real iSerial), and the synthesized value is then *not* reported as a real `device_serial`.
- Each timestamp is a **`Stamp { value, confidence }`** — `first_install` (from the section header) is `Authoritative`; the registry-derived `last_arrival` / `last_removal` are `Inferred` (and v0.2).

[`Bus::is_dma_capable`] and [`Bus::is_mass_storage`] expose the threat-class lenses the analyzer grades on.

## Trust, but verify

`#![forbid(unsafe_code)]`; panic-free on crafted input (the workspace denies `clippy::unwrap_used` / `expect_used` in production code; parsing is lenient lossy-UTF-8 and bounds-checked); fuzzed with `cargo-fuzz` (`setupapi`); the reader is exercised against spec-exact `setupapi.dev.log` / `setupapi.log` fixtures matching the Microsoft text-log grammar.

## Forensic analysis

Severity-graded anomaly auditing (DMA-capable / mass-storage / HID / OS-generated-serial findings) lives in the sibling **[`peripheral-forensic`](https://crates.io/crates/peripheral-forensic)** crate, built on this one — the reader/analyzer split mirrors `ntfs-core`/`ntfs-forensic`.

---

[Privacy Policy](https://securityronin.github.io/peripheral-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/peripheral-forensic/terms/) · © 2026 Security Ronin Ltd
