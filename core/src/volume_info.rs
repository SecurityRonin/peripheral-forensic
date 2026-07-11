//! Volume-label source: decode `VolumeInfoCache` from a Windows `SOFTWARE` hive.
//!
//! `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\<X:>` caches, per mounted volume,
//! the drive letter it was seen at and its volume label. For a removable device this is
//! the human-readable name the user gave the stick ("Authorized USB", "IAMAN"), which
//! corroborates the device that mounted that drive letter. This reader emits those
//! `(drive_letter, volume_label)` facts; the correlation layer joins them to a device via
//! the drive letter (`MountedDevices`).

use crate::Provenance;
use std::io::Cursor;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// The Windows Search `VolumeInfoCache` path (a `SOFTWARE`-hive key).
const CACHE_PATH: &str = "Microsoft\\Windows Search\\VolumeInfoCache";

/// A cached volume label keyed by the drive letter it was mounted at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeLabel {
    /// The drive letter the volume was mounted as (upper-cased, e.g. `E`).
    pub drive_letter: char,
    /// The volume label (never empty — unlabelled volumes are omitted).
    pub volume_label: String,
    /// Where the record was decoded from.
    pub source: Provenance,
}

/// Parse `VolumeInfoCache` volume labels from an already-opened `SOFTWARE` hive.
///
/// Total over a valid hive: a subkey that is not a `X:` drive letter, or that carries no
/// non-empty string `VolumeLabel`, is skipped rather than panicked on. `file` is recorded
/// as each record's [`Provenance`] file (the hive name, e.g. `SOFTWARE`).
#[must_use]
pub fn parse_volume_info_cache(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<VolumeLabel> {
    return Vec::new(); // RED stub
    #[allow(unreachable_code)]
    let Ok(Some(cache)) = hive.open_key(CACHE_PATH) else {
        return Vec::new();
    };
    let Ok(subkeys) = cache.subkeys() else {
        return Vec::new(); // cov:unreachable: subkeys() only errors on hive corruption
    };
    let mut out = Vec::new();
    for sub in subkeys {
        let name = sub.name();
        let Some(letter) = drive_letter(&name) else {
            continue;
        };
        let Some(label) = string_value(&sub, "VolumeLabel") else {
            continue;
        };
        out.push(VolumeLabel {
            drive_letter: letter,
            volume_label: label,
            source: Provenance {
                file: file.to_string(),
                line: 0,
                key_path: Some(format!("{CACHE_PATH}\\{name}")),
            },
        });
    }
    out
}

/// Extract the drive letter from an `X:` subkey name, upper-cased; `None` for any other
/// name (a non-letter, a multi-character prefix).
fn drive_letter(name: &str) -> Option<char> {
    let mut chars = name.chars();
    let letter = chars.next()?;
    if letter.is_ascii_alphabetic() && chars.next() == Some(':') && chars.next().is_none() {
        Some(letter.to_ascii_uppercase())
    } else {
        None
    }
}

/// Read a non-empty string value; `None` if absent, non-string, or empty.
fn string_value(key: &Key<'_>, name: &str) -> Option<String> {
    key.value(name)
        .ok()
        .flatten()
        .and_then(|v| v.as_string().ok())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_volume_info_cache_decodes_labelled_drives_only() {
        // Synthetic SOFTWARE hive: E: labelled "TESTLABEL", C: unlabelled (DWORD 0),
        // ZZ: a bogus non-drive-letter name. Only E: yields a record.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_volume_info_cache.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let labels = parse_volume_info_cache(&hive, "SOFTWARE");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].drive_letter, 'E');
        assert_eq!(labels[0].volume_label, "TESTLABEL");
        assert!(labels[0].source.key_path.is_some());
    }

    #[test]
    fn drive_letter_accepts_only_well_formed_names() {
        assert_eq!(drive_letter("E:"), Some('E'));
        assert_eq!(drive_letter("c:"), Some('C'));
        assert_eq!(drive_letter("ZZ:"), None);
        assert_eq!(drive_letter("E"), None);
        assert_eq!(drive_letter("1:"), None);
        assert_eq!(drive_letter(""), None);
    }

    #[test]
    fn a_hive_without_the_cache_yields_nothing() {
        // The synthetic USBSTOR SYSTEM hive has no VolumeInfoCache → empty, no panic.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_usb_system.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        assert!(parse_volume_info_cache(&hive, "SYSTEM").is_empty());
    }
}
