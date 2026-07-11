//! Per-user volume mounts: decode `MountPoints2` from a Windows `NTUSER.DAT` hive.
//!
//! `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{GUID}` records
//! every volume the user mounted, keyed by the volume GUID. The subkey's last-written time
//! is the last time that user mounted the volume. This is per-user attribution — *which
//! user* connected a device — that no machine-wide source provides; the volume GUID joins
//! (via the `MountedDevices` MBR bridge) to a drive letter and its cached volume label.

use crate::Provenance;
use std::io::Cursor;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// The `MountPoints2` path in an `NTUSER.DAT` (user) hive.
const MP2_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";

/// One per-user volume mount: the volume GUID and the last time the user mounted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMount {
    /// The mounted volume's GUID (lower-cased, braces kept).
    pub volume_guid: String,
    /// Last-mounted time (the subkey's last-written `FILETIME`), epoch seconds UTC;
    /// `None` when the hive recorded no timestamp.
    pub last_mounted: Option<i64>,
    /// Where the record was decoded from.
    pub source: Provenance,
}

/// Parse per-user `MountPoints2` volume mounts from an already-opened `NTUSER.DAT` hive.
/// Total over a valid hive: a non-`{GUID}` mount name (a UNC/`##server#share` entry) is
/// skipped, never panicked on. `file` is recorded as each record's [`Provenance`] file.
#[must_use]
pub fn parse_mountpoints2(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<UserMount> {
    let Ok(Some(mp2)) = hive.open_key(MP2_PATH) else {
        return Vec::new();
    };
    let Ok(subkeys) = mp2.subkeys() else {
        return Vec::new(); // cov:unreachable: subkeys() only errors on hive corruption
    };
    let mut out = Vec::new();
    for sub in subkeys {
        let name = sub.name();
        if !(name.starts_with('{') && name.ends_with('}')) {
            continue;
        }
        out.push(UserMount {
            volume_guid: name.to_ascii_lowercase(),
            last_mounted: last_written_epoch(&sub),
            source: Provenance {
                file: file.to_string(),
                line: 0,
                key_path: Some(format!("{MP2_PATH}\\{name}")),
            },
        });
    }
    out
}

/// A key's last-written time as epoch seconds UTC; `None` when the hive recorded none.
fn last_written_epoch(key: &Key<'_>) -> Option<i64> {
    Some(key.last_written()?.as_second())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_mountpoints2_decodes_guid_mounts_only() {
        // Synthetic NTUSER hive: one volume-GUID mount (key last-write epoch 1427230953)
        // and a `##server#share` UNC entry that must be skipped.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_mountpoints2.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let mounts = parse_mountpoints2(&hive, "NTUSER.DAT");
        assert_eq!(mounts.len(), 1);
        assert_eq!(
            mounts[0].volume_guid,
            "{a2f2048e-d228-11e4-b630-000c29ff2429}"
        );
        assert_eq!(mounts[0].last_mounted, Some(1_427_230_953));
        assert!(mounts[0].source.key_path.is_some());
    }

    #[test]
    fn a_hive_without_mountpoints2_yields_nothing() {
        // The synthetic USBSTOR SYSTEM hive has no MountPoints2 key → empty, no panic.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_usb_system.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        assert!(parse_mountpoints2(&hive, "NTUSER.DAT").is_empty());
    }
}
