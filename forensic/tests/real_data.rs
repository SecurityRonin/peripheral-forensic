#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end validation against spec-exact `setupapi.dev.log` fixtures (the
//! Doer-Checker front door). The fixtures match the Microsoft SetupAPI text-log
//! grammar; provenance and the way to capture a real log are in
//! `tests/data/README.md`.

use peripheral_core::{setupapi::parse_setupapi, Bus, Confidence};
use peripheral_forensic::{audit, audit_findings, DeviceAnomaly};

const DEV_LOG: &str = include_str!("../../tests/data/setupapi.dev.log");
const XP_LOG: &str = include_str!("../../tests/data/setupapi_xp.log");

#[test]
fn vista_log_parses_devices_with_authoritative_first_install() {
    let devices = parse_setupapi(DEV_LOG, "setupapi.dev.log");
    assert!(
        devices.len() >= 5,
        "expected the 5 device-install headers, got {}",
        devices.len()
    );
    // Every install timestamp from a section header is authoritative.
    for d in &devices {
        if let Some(s) = d.first_install {
            assert_eq!(s.confidence, Confidence::Authoritative);
        }
    }
    // The SanDisk USB mass-storage device with a real iSerial.
    let sandisk = devices
        .iter()
        .find(|d| d.vid == Some(0x0781) && d.pid == Some(0x5583))
        .expect("SanDisk USB device present");
    assert_eq!(sandisk.bus, Bus::Usb);
    assert_eq!(
        sandisk.device_serial.as_deref(),
        Some("4C530001234567890123")
    );
    assert!(!sandisk.serial_is_os_generated);
    // device_serial (iSerial) is kept distinct from any volume serial.
    assert_eq!(sandisk.volume_serial, None);
}

#[test]
fn vista_log_audit_surfaces_dma_storage_hid_and_os_serial() {
    let devices = parse_setupapi(DEV_LOG, "setupapi.dev.log");
    let anomalies = audit(&devices);
    let codes: Vec<&str> = anomalies.iter().map(DeviceAnomaly::code).collect();

    // 1394 FireWire camera → DMA-capable (T1200).
    assert!(
        codes.contains(&"PERIPHERAL-DMA-CAPABLE-DEVICE"),
        "FireWire DMA device not surfaced; got {codes:?}"
    );
    // USB/USBSTOR mass storage → exfil/autorun.
    assert!(
        codes.contains(&"PERIPHERAL-MASS-STORAGE-CONNECTED"),
        "mass storage not surfaced; got {codes:?}"
    );
    // HID\... mouse → BadUSB lens.
    assert!(
        codes.contains(&"PERIPHERAL-HID-DEVICE"),
        "HID device not surfaced; got {codes:?}"
    );
    // The HID and PCI devices carry OS-generated (2nd-char-&) serials.
    assert!(
        codes.contains(&"PERIPHERAL-OS-GENERATED-SERIAL"),
        "OS-generated serial not surfaced; got {codes:?}"
    );

    // Findings are hedged observations.
    let findings = audit_findings(&devices, "evidence-host");
    assert!(!findings.is_empty());
    for f in &findings {
        assert!(
            f.note.to_ascii_lowercase().contains("consistent with"),
            "finding must hedge: {}",
            f.note
        );
    }
}

#[test]
fn xp_log_parses_both_grammars() {
    let devices = parse_setupapi(XP_LOG, "setupapi.log");
    assert!(
        devices.len() >= 2,
        "expected 2 XP device-install lines, got {}",
        devices.len()
    );
    let samsung = devices
        .iter()
        .find(|d| d.vid == Some(0x04E8) && d.pid == Some(0x6860))
        .expect("XP-format Samsung USB device present");
    assert_eq!(samsung.device_serial.as_deref(), Some("0123456789ABCDEF"));
    assert_eq!(samsung.bus, Bus::Usb);
}
