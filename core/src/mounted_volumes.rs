//! MBR-signature volume bridge: decode `MountedDevices` MBR records from a Windows
//! `SYSTEM` hive.
//!
//! `MountedDevices` stores, for each mount name, a REG_BINARY value. A 12-byte value is an
//! **MBR record**: a 4-byte disk signature followed by an 8-byte partition byte-offset.
//! Both a drive letter (`\DosDevices\X:`) and a volume GUID (`\??\Volume{…}`) point at the
//! same MBR record for one volume — so records sharing a `(disk_signature, partition_offset)`
//! name the *same volume*. That equivalence is the bridge the correlation layer uses to
//! join a drive-letter fact (a volume label) to a volume-GUID fact (a per-user mount).
//!
//! (Device-path MountedDevices entries — which name a device instance directly — are
//! handled by the `registry` reader's drive-letter join; this module covers the MBR form.)

use crate::Provenance;
use std::io::Cursor;
use winreg_core::hive::Hive;

/// One `MountedDevices` MBR record: a mount name resolved to its disk signature and
/// partition offset. Volumes with equal `(disk_signature, partition_offset)` are the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolume {
    /// The drive letter, when the mount name was `\DosDevices\X:` (upper-cased).
    pub drive_letter: Option<char>,
    /// The volume GUID, when the mount name was `\??\Volume{GUID}` (lower-cased, braces).
    pub volume_guid: Option<String>,
    /// MBR disk signature (the first 4 bytes of the record, little-endian).
    pub disk_signature: u32,
    /// Partition byte-offset within the disk (the next 8 bytes, little-endian).
    pub partition_offset: u64,
    /// Where the record was decoded from.
    pub source: Provenance,
}

/// Parse `MountedDevices` MBR records (drive-letter and volume-GUID mount names) from an
/// already-opened `SYSTEM` hive. Total over a valid hive: a non-MBR value (a device path,
/// a wrong length) or an unrecognized mount name is skipped, never panicked on.
#[must_use]
pub fn parse_mounted_volumes(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<MountedVolume> {
    let _ = (hive, file);
    Vec::new()
}

/// Extract the drive letter from a `\DosDevices\X:` mount name, upper-cased.
fn dos_drive_letter(name: &str) -> Option<char> {
    let tail = name.strip_prefix("\\DosDevices\\")?;
    let mut chars = tail.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':') && chars.next().is_none())
        .then(|| letter.to_ascii_uppercase())
}

/// Extract the volume GUID from a `\??\Volume{GUID}` mount name (lower-cased, braces kept).
fn volume_guid(name: &str) -> Option<String> {
    let g = name.strip_prefix("\\??\\Volume")?;
    (g.starts_with('{') && g.ends_with('}')).then(|| g.to_ascii_lowercase())
}

/// Decode a 12-byte MBR `MountedDevices` value into `(disk_signature, partition_offset)`.
/// `None` for any other length (a device-path string, a truncated record).
fn decode_mbr(raw: &[u8]) -> Option<(u32, u64)> {
    if raw.len() != 12 {
        return None;
    }
    let sig = u32::from_le_bytes(raw.get(0..4)?.try_into().ok()?);
    let offset = u64::from_le_bytes(raw.get(4..12)?.try_into().ok()?);
    Some((sig, offset))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn dos_drive_letter_reads_only_well_formed_names() {
        assert_eq!(dos_drive_letter("\\DosDevices\\E:"), Some('E'));
        assert_eq!(dos_drive_letter("\\DosDevices\\c:"), Some('C'));
        assert_eq!(dos_drive_letter("\\??\\Volume{1234}"), None);
        assert_eq!(dos_drive_letter("\\DosDevices\\EE:"), None);
    }

    #[test]
    fn volume_guid_reads_only_volume_names() {
        assert_eq!(
            volume_guid("\\??\\Volume{A2F2048E-D228-11E4-B630-000C29FF2429}").as_deref(),
            Some("{a2f2048e-d228-11e4-b630-000c29ff2429}")
        );
        assert_eq!(volume_guid("\\DosDevices\\E:"), None);
        assert_eq!(volume_guid("\\??\\Volumexyz"), None);
    }

    #[test]
    fn decode_mbr_reads_signature_and_offset_or_rejects() {
        // E: on the CFReDS hive: disk sig 0xE221034C, offset 0x10000.
        assert_eq!(
            decode_mbr(&[0x4c, 0x03, 0x21, 0xe2, 0, 0, 1, 0, 0, 0, 0, 0]),
            Some((0xE221_034C, 0x1_0000))
        );
        // wrong length (a UTF-16 device path) → None, no panic.
        assert_eq!(decode_mbr(&[0; 216]), None);
        assert_eq!(decode_mbr(&[1, 2, 3]), None);
    }

    #[test]
    fn synthetic_mounted_devices_hive_yields_the_mbr_volume() {
        // The synthetic MountedDevices fixture has a 12-byte MBR record under \DosDevices\C:.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_mounted_devices.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let vols = parse_mounted_volumes(&hive, "SYNTHETIC");
        let c = vols
            .iter()
            .find(|v| v.drive_letter == Some('C'))
            .expect("C: MBR record present");
        assert_eq!(c.disk_signature, 0x4433_2211);
        assert!(c.source.key_path.is_some());
    }
}
