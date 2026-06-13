//! `peripheral-core` — external-device (peripheral) connection forensic reader.
//!
//! Parses Windows `setupapi.dev.log` device-installation logs into a uniform
//! [`DeviceConnection`] stream: bus-classified, with each timestamp tagged
//! authoritative-vs-inferred and the USB iSerial kept distinct from any volume
//! serial. The input is attacker-controllable evidence — parsing is lenient
//! (lossy UTF-8), bounds-checked, and never panics. No `unsafe`.
//!
//! Findings (DMA-capable device, mass-storage, HID/BadUSB, OS-generated serial)
//! live in the sibling `peripheral-forensic` crate; this crate only decodes.
//!
//! ## v0.2 enrichment (not in this release)
//!
//! The richest source — the Windows registry `SYSTEM\CurrentControlSet\Enum\`
//! keys (USBSTOR/USB), `MountedDevices`, and the device-property `0066`/`0067`
//! Last-Arrival/Last-Removal `FILETIME`s — plus EVTX device events require the
//! (unpublished) `winreg-core` and `winevt-forensic` crates. They are deferred
//! to v0.2; v0.1 is scoped to the self-contained `setupapi.dev.log` source.

#![forbid(unsafe_code)]

pub mod setupapi;

/// The physical/logical bus a peripheral attached through.
///
/// The variant drives the DMA-capability and storage-class threat lenses
/// downstream (see [`DeviceConnection::dma_capable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bus {
    /// USB (host-controller mediated; not directly DMA-capable as mass storage).
    Usb,
    /// Media Transfer Protocol (phones/cameras) — surfaced via `WpdBusEnumRoot`.
    Mtp,
    /// IEEE 1394 FireWire — bus-mastering DMA.
    FireWire,
    /// Thunderbolt — PCIe tunnelled, bus-mastering DMA.
    Thunderbolt,
    /// PCI Express — bus-mastering DMA.
    Pcie,
    /// External SATA — SATA/storage transport, explicitly NOT DMA.
    Esata,
    /// SD/MMC card.
    SdMmc,
    /// Bluetooth (typically HID/wireless).
    Bluetooth,
    /// ExpressCard — PCIe-backed, bus-mastering DMA.
    ExpressCard,
    /// SCSI / SAS storage transport.
    ScsiSas,
    /// NVMe storage.
    Nvme,
    /// Bus could not be determined from the enumerator.
    Unknown,
}

impl Bus {
    /// Classify a bus from a setupapi/instance-id **enumerator** prefix — the
    /// leading token of a device instance id (`USBSTOR`, `USB`, `1394`, `PCI`,
    /// `SCSI`, `SD`, `WpdBusEnumRoot`, …), matched case-insensitively.
    ///
    /// Returns [`Bus::Unknown`] for an unrecognized or empty enumerator; the
    /// caller never gets a panic.
    #[must_use]
    pub fn from_enumerator(_enumerator: &str) -> Self {
        // RED stub — real classifier lands in GREEN.
        Self::Unknown
    }

    /// Whether this bus can perform **bus-mastering DMA**, the property that
    /// makes a device a direct-memory-access attack surface (MITRE T1200).
    ///
    /// DMA-capable: FireWire, Thunderbolt, PCIe, ExpressCard. Storage-class
    /// transports (USB mass storage, eSATA, SD/MMC, SCSI/SAS, NVMe) and
    /// HID/wireless transports (USB-HID, Bluetooth) are NOT DMA in this model.
    ///
    /// Caveat: SD-Express tunnels PCIe and *can* be DMA-capable; this v0.1
    /// classifier treats bare `SD` as the legacy non-DMA SD/MMC bus, the common
    /// case. Distinguishing SD-Express needs the device-capability bits that the
    /// registry/EVTX v0.2 source carries.
    #[must_use]
    pub fn is_dma_capable(self) -> bool {
        false // RED stub
    }

    /// Whether this bus is a removable mass-storage transport (the
    /// data-exfiltration / autorun lens, MITRE T1052.001 / T1091).
    #[must_use]
    pub fn is_mass_storage(self) -> bool {
        false // RED stub
    }
}

/// How much trust a timestamp carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    /// Directly recorded by the source as the stated event
    /// (e.g. the setupapi section-header install time → first-seen).
    Authoritative,
    /// Derived/undocumented — the value's meaning is inferred, not stated by the
    /// source (e.g. the registry `0066`/`0067` Last-Arrival/Last-Removal
    /// device-property `FILETIME`s, which are undocumented).
    Inferred,
}

/// A timestamp tagged with its evidentiary confidence.
///
/// Pairing the value with its [`Confidence`] in the type makes the
/// authoritative-vs-inferred distinction impossible to drop on the floor: a
/// consumer cannot read `value` without also seeing how trustworthy it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp {
    /// Unix epoch seconds.
    pub value: i64,
    /// How the value should be trusted.
    pub confidence: Confidence,
}

impl Stamp {
    /// An authoritative (source-stated) timestamp.
    #[must_use]
    pub fn authoritative(value: i64) -> Self {
        Self {
            value,
            confidence: Confidence::Authoritative,
        }
    }

    /// An inferred (derived/undocumented) timestamp.
    #[must_use]
    pub fn inferred(value: i64) -> Self {
        Self {
            value,
            confidence: Confidence::Inferred,
        }
    }
}

/// A MITRE ATT&CK technique a connection is *consistent with* — never a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MitreRef(pub &'static str);

/// One external-device connection, normalized across sources.
///
/// The forensic cautions are baked into the type, not just the docs:
/// - [`device_serial`](Self::device_serial) is the **USB iSerial** and is a
///   distinct field from [`volume_serial`](Self::volume_serial) (a filesystem
///   volume serial), so the two can never be conflated.
/// - [`serial_is_os_generated`](Self::serial_is_os_generated) records that the
///   device had no real iSerial (Windows synthesized one), weakening attribution.
/// - Each timestamp is a [`Stamp`] carrying its authoritative-vs-inferred
///   [`Confidence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConnection {
    // ── Identity ────────────────────────────────────────────────────────────
    /// The classified bus.
    pub bus: Bus,
    /// Device setup-class GUID, when known.
    pub device_class_guid: Option<String>,
    /// USB vendor id (`VID_xxxx`).
    pub vid: Option<u16>,
    /// USB product id (`PID_xxxx`).
    pub pid: Option<u16>,
    /// The **USB iSerial** — the device-unique serial reported by the device.
    /// DISTINCT from any [`volume_serial`](Self::volume_serial).
    pub device_serial: Option<String>,
    /// `true` when the instance-id serial was synthesized by Windows (the
    /// serial's 2nd character is `&`) — the device exposed no real iSerial, so
    /// attribution is weaker.
    pub serial_is_os_generated: bool,
    /// Human-readable friendly name, when present.
    pub friendly_name: Option<String>,
    /// The full device instance id (e.g.
    /// `USB\VID_0781&PID_5583\1234567890AB`) — the primary key.
    pub device_instance_id: String,

    // ── Timestamps (each tagged authoritative-vs-inferred) ───────────────────
    /// First-seen / first-install — authoritative when from the setupapi
    /// section header.
    pub first_install: Option<Stamp>,
    /// Last install/driver event.
    pub last_install: Option<Stamp>,
    /// Last arrival (connect). INFERRED — derived from the undocumented registry
    /// `0066` device property (v0.2).
    pub last_arrival: Option<Stamp>,
    /// Last removal (disconnect). INFERRED — derived from the undocumented
    /// registry `0067` device property (v0.2).
    pub last_removal: Option<Stamp>,

    // ── Correlation join keys (volume_serial kept DISTINCT from device_serial) ─
    /// `ParentIdPrefix` — joins the storage device to its volume.
    pub parent_id_prefix: Option<String>,
    /// Volume GUID (`\\?\Volume{...}`).
    pub volume_guid: Option<String>,
    /// Mounted drive letter.
    pub drive_letter: Option<char>,
    /// Filesystem **volume** serial (NTFS/FAT) — DISTINCT from the device's
    /// USB [`device_serial`](Self::device_serial).
    pub volume_serial: Option<u32>,
    /// MBR disk signature.
    pub disk_signature: Option<u32>,

    // ── Threat lens ──────────────────────────────────────────────────────────
    /// Whether the bus is bus-mastering DMA-capable (see [`Bus::is_dma_capable`]).
    pub dma_capable: bool,
    /// MITRE ATT&CK techniques this connection is *consistent with*.
    pub mitre: Vec<MitreRef>,

    // ── Provenance ───────────────────────────────────────────────────────────
    /// Where this record came from (source file + 1-based line).
    pub source: Provenance,
}

/// Where a [`DeviceConnection`] was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The source file (e.g. `setupapi.dev.log`).
    pub file: String,
    /// 1-based line number of the section header the record came from.
    pub line: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_enumerators_classify_as_usb() {
        assert_eq!(Bus::from_enumerator("USBSTOR"), Bus::Usb);
        assert_eq!(Bus::from_enumerator("USB"), Bus::Usb);
        assert_eq!(Bus::from_enumerator("usbstor"), Bus::Usb); // case-insensitive
    }

    #[test]
    fn bus_specific_enumerators_classify() {
        assert_eq!(Bus::from_enumerator("1394"), Bus::FireWire);
        assert_eq!(Bus::from_enumerator("SCSI"), Bus::ScsiSas);
        assert_eq!(Bus::from_enumerator("PCI"), Bus::Pcie);
        assert_eq!(Bus::from_enumerator("SD"), Bus::SdMmc);
        assert_eq!(Bus::from_enumerator("WpdBusEnumRoot"), Bus::Mtp);
        assert_eq!(Bus::from_enumerator("THUNDERBOLT"), Bus::Thunderbolt);
        assert_eq!(Bus::from_enumerator("ESATA"), Bus::Esata);
        assert_eq!(Bus::from_enumerator("EXPRESSCARD"), Bus::ExpressCard);
        assert_eq!(Bus::from_enumerator("BTHENUM"), Bus::Bluetooth);
        assert_eq!(Bus::from_enumerator("NVME"), Bus::Nvme);
    }

    #[test]
    fn unknown_enumerator_is_unknown_never_panics() {
        assert_eq!(Bus::from_enumerator("HID"), Bus::Unknown);
        assert_eq!(Bus::from_enumerator(""), Bus::Unknown);
        assert_eq!(Bus::from_enumerator("   "), Bus::Unknown);
    }

    #[test]
    fn dma_capable_is_exactly_firewire_thunderbolt_pcie_expresscard() {
        for b in [Bus::FireWire, Bus::Thunderbolt, Bus::Pcie, Bus::ExpressCard] {
            assert!(b.is_dma_capable(), "{b:?} must be DMA-capable");
        }
        // Storage-only transports are explicitly NOT DMA (eSATA is SATA/storage).
        for b in [Bus::Usb, Bus::Esata, Bus::SdMmc, Bus::ScsiSas, Bus::Nvme] {
            assert!(!b.is_dma_capable(), "{b:?} must NOT be DMA-capable");
        }
        // HID/wireless transports are not DMA either.
        for b in [Bus::Bluetooth, Bus::Mtp, Bus::Unknown] {
            assert!(!b.is_dma_capable(), "{b:?} must NOT be DMA-capable");
        }
    }

    #[test]
    fn mass_storage_classes() {
        for b in [Bus::Usb, Bus::Esata, Bus::SdMmc, Bus::ScsiSas, Bus::Nvme] {
            assert!(b.is_mass_storage(), "{b:?} should be mass storage");
        }
        for b in [Bus::FireWire, Bus::Thunderbolt, Bus::Bluetooth, Bus::Mtp] {
            assert!(!b.is_mass_storage(), "{b:?} should not be mass storage");
        }
    }

    #[test]
    fn stamp_carries_confidence() {
        assert_eq!(
            Stamp::authoritative(10).confidence,
            Confidence::Authoritative
        );
        assert_eq!(Stamp::inferred(10).confidence, Confidence::Inferred);
    }
}
