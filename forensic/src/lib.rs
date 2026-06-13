//! `peripheral-forensic` — graded anomaly auditor over external-device
//! connections.
//!
//! Consumes [`peripheral_core::DeviceConnection`] records and emits
//! [`forensicnomicon::report::Finding`]s. Every anomaly is an **observation**
//! ("consistent with …"); the examiner draws the conclusions. MITRE techniques
//! are narrated as consistency, never as a verdict.

#![forbid(unsafe_code)]
// RED commit: is_hid is wired up by the GREEN `audit`.
#![allow(dead_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source};
use peripheral_core::{Bus, DeviceConnection};

/// A graded external-device anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAnomaly {
    /// A bus-mastering DMA-capable device (FireWire / Thunderbolt / PCIe /
    /// ExpressCard) was connected — a direct-memory-access attack surface.
    /// MITRE T1200.
    DmaCapableDevice {
        /// The device instance id.
        instance_id: String,
        /// The DMA-capable bus.
        bus: Bus,
    },
    /// Removable mass storage was connected — an exfiltration / autorun-payload
    /// surface. MITRE T1052.001 / T1091.
    MassStorageConnected {
        /// The device instance id.
        instance_id: String,
    },
    /// A Human Interface Device was connected — possible keystroke-injection
    /// (BadUSB). MITRE T1200.
    HidDevice {
        /// The device instance id.
        instance_id: String,
    },
    /// The device's serial was synthesized by Windows (no real iSerial), so
    /// attribution back to a specific physical device is weaker.
    OsGeneratedSerial {
        /// The device instance id.
        instance_id: String,
    },
}

impl DeviceAnomaly {
    /// The stable, published anomaly code (scheme-prefixed SCREAMING-KEBAB).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DmaCapableDevice { .. } => "PERIPHERAL-DMA-CAPABLE-DEVICE",
            Self::MassStorageConnected { .. } => "PERIPHERAL-MASS-STORAGE-CONNECTED",
            Self::HidDevice { .. } => "PERIPHERAL-HID-DEVICE",
            Self::OsGeneratedSerial { .. } => "PERIPHERAL-OS-GENERATED-SERIAL",
        }
    }
}

impl Observation for DeviceAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            Self::DmaCapableDevice { .. } => Severity::High,
            Self::MassStorageConnected { .. } | Self::HidDevice { .. } => Severity::Medium,
            Self::OsGeneratedSerial { .. } => Severity::Low,
        })
    }

    fn code(&self) -> &'static str {
        DeviceAnomaly::code(self)
    }

    fn category(&self) -> Category {
        match self {
            Self::DmaCapableDevice { .. }
            | Self::MassStorageConnected { .. }
            | Self::HidDevice { .. } => Category::Threat,
            Self::OsGeneratedSerial { .. } => Category::Integrity,
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            Self::DmaCapableDevice { .. } | Self::HidDevice { .. } => &["T1200"],
            Self::MassStorageConnected { .. } => &["T1052.001", "T1091"],
            Self::OsGeneratedSerial { .. } => &[],
        }
    }

    fn note(&self) -> String {
        match self {
            Self::DmaCapableDevice { instance_id, bus } => format!(
                "a {bus:?} device ({instance_id:?}) connected; the bus is bus-mastering \
                 DMA-capable, consistent with a direct-memory-access attack surface \
                 (MITRE T1200)"
            ),
            Self::MassStorageConnected { instance_id } => format!(
                "removable mass storage ({instance_id:?}) connected; consistent with data \
                 staging/exfiltration or autorun payload delivery (MITRE T1052.001 / T1091)"
            ),
            Self::HidDevice { instance_id } => format!(
                "a human-interface device ({instance_id:?}) connected; consistent with \
                 keystroke-injection hardware such as BadUSB (MITRE T1200)"
            ),
            Self::OsGeneratedSerial { instance_id } => format!(
                "the device ({instance_id:?}) exposed no real iSerial — Windows synthesized \
                 the instance-id serial; consistent with weaker device attribution"
            ),
        }
    }
}

/// Audit a slice of [`DeviceConnection`]s into a typed [`DeviceAnomaly`] stream.
#[must_use]
pub fn audit(_devices: &[DeviceConnection]) -> Vec<DeviceAnomaly> {
    // RED stub — the real DMA / mass-storage / HID / OS-serial detection lands
    // in the GREEN commit.
    Vec::new()
}

/// Convenience: audit and convert directly to graded [`Finding`]s.
#[must_use]
pub fn audit_findings(devices: &[DeviceConnection], scope: impl Into<String>) -> Vec<Finding> {
    let src = source(scope);
    audit(devices)
        .iter()
        .map(|a| a.to_finding(src.clone()))
        .collect()
}

/// Whether a connection is a Human Interface Device — a Bluetooth transport, or
/// a USB device whose instance id names the HID class.
fn is_hid(d: &DeviceConnection) -> bool {
    if d.bus == Bus::Bluetooth {
        return true;
    }
    let id = d.device_instance_id.to_ascii_uppercase();
    id.starts_with("HID\\") || id.contains("\\HID") || id.contains("&HID")
}

/// The [`Source`] stamp for findings this analyzer emits.
#[must_use]
pub fn source(scope: impl Into<String>) -> Source {
    Source {
        analyzer: "peripheral-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::{MitreRef, Provenance};

    fn conn(instance_id: &str, bus: Bus, dma: bool, os_serial: bool) -> DeviceConnection {
        DeviceConnection {
            bus,
            device_class_guid: None,
            vid: None,
            pid: None,
            device_serial: None,
            serial_is_os_generated: os_serial,
            friendly_name: None,
            device_instance_id: instance_id.to_string(),
            first_install: None,
            last_install: None,
            last_arrival: None,
            last_removal: None,
            parent_id_prefix: None,
            volume_guid: None,
            drive_letter: None,
            volume_serial: None,
            disk_signature: None,
            dma_capable: dma,
            mitre: vec![MitreRef("T1200")],
            source: Provenance {
                file: "f".into(),
                line: 1,
            },
        }
    }

    fn codes(a: &[DeviceAnomaly]) -> Vec<&str> {
        a.iter().map(DeviceAnomaly::code).collect()
    }

    #[test]
    fn dma_device_is_flagged_high_threat() {
        let a = audit(&[conn("1394\\X\\0", Bus::FireWire, true, false)]);
        assert!(codes(&a).contains(&"PERIPHERAL-DMA-CAPABLE-DEVICE"));
        let dma = a
            .iter()
            .find(|x| x.code() == "PERIPHERAL-DMA-CAPABLE-DEVICE")
            .unwrap();
        assert_eq!(dma.severity(), Some(Severity::High));
        assert_eq!(dma.category(), Category::Threat);
        assert!(dma.mitre().contains(&"T1200"));
    }

    #[test]
    fn mass_storage_is_flagged_medium_threat() {
        let a = audit(&[conn("USBSTOR\\Disk\\X", Bus::Usb, false, false)]);
        assert!(codes(&a).contains(&"PERIPHERAL-MASS-STORAGE-CONNECTED"));
        let ms = a
            .iter()
            .find(|x| x.code() == "PERIPHERAL-MASS-STORAGE-CONNECTED")
            .unwrap();
        assert_eq!(ms.severity(), Some(Severity::Medium));
        assert!(ms.mitre().contains(&"T1052.001"));
        assert!(ms.mitre().contains(&"T1091"));
    }

    #[test]
    fn hid_device_is_flagged() {
        // Bluetooth transport.
        assert!(
            codes(&audit(&[conn("BTHENUM\\X", Bus::Bluetooth, false, false)]))
                .contains(&"PERIPHERAL-HID-DEVICE")
        );
        // USB HID class in the instance id.
        assert!(codes(&audit(&[conn(
            "HID\\VID_046D&PID_C52B\\X",
            Bus::Usb,
            false,
            false
        )]))
        .contains(&"PERIPHERAL-HID-DEVICE"));
    }

    #[test]
    fn os_generated_serial_is_flagged_low_integrity() {
        let a = audit(&[conn("USBSTOR\\Disk\\7&abc&0", Bus::Usb, false, true)]);
        assert!(codes(&a).contains(&"PERIPHERAL-OS-GENERATED-SERIAL"));
        let os = a
            .iter()
            .find(|x| x.code() == "PERIPHERAL-OS-GENERATED-SERIAL")
            .unwrap();
        assert_eq!(os.severity(), Some(Severity::Low));
        assert_eq!(os.category(), Category::Integrity);
        assert!(os.mitre().is_empty());
    }

    #[test]
    fn benign_non_storage_non_dma_device_fires_nothing() {
        // A keyboard-less PCI... actually PCI is DMA; use an MTP phone (no flags).
        let a = audit(&[conn("WpdBusEnumRoot\\X", Bus::Mtp, false, false)]);
        assert!(a.is_empty(), "got {:?}", codes(&a));
    }

    #[test]
    fn findings_are_hedged_observations_never_verdicts() {
        // Exercise every anomaly kind's note arm: DMA bus + mass-storage +
        // OS-generated serial on one USB device, plus a Bluetooth HID device.
        let f = audit_findings(
            &[
                conn("1394\\X\\0", Bus::FireWire, true, false),
                conn("USBSTOR\\Disk\\7&abc&0", Bus::Usb, false, true),
                conn("BTHENUM\\X", Bus::Bluetooth, false, false),
            ],
            "host",
        );
        assert_eq!(
            f.len(),
            4,
            "DMA + (mass-storage + os-serial) + hid = 4 findings"
        );
        for finding in &f {
            let note = finding.note.to_ascii_lowercase();
            assert!(note.contains("consistent with"), "must hedge: {note}");
            for forbidden in ["proves", "confirms", "definitely"] {
                assert!(
                    !note.contains(forbidden),
                    "must not assert a verdict: {note}"
                );
            }
        }
    }

    #[test]
    fn source_stamps_analyzer_and_version() {
        let s = source("partition 1");
        assert_eq!(s.analyzer, "peripheral-forensic");
        assert_eq!(s.scope, "partition 1");
        assert!(s.version.is_some());
    }
}
