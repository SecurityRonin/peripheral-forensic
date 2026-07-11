//! Volume label + serial history: decode `EMDMgmt` from a Windows `SOFTWARE` hive.
//!
//! `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` is the ReadyBoost device cache.
//! Windows evaluated every volume it saw for ReadyBoost and left one subkey per volume,
//! named `<device-prefix>__<VolumeLabel>_<VolumeSerialNumber>` (the serial in decimal).
//! It is a durable record of a removable volume's **label and 4-byte volume serial** — the
//! same serial a Shell Link's `DriveSerialNumber` stores — so it ties a `.lnk` file-access
//! to a named volume even after the device is gone. This reader emits those `(label,
//! volume_serial)` facts.

use crate::Provenance;
use std::io::Cursor;
use winreg_core::hive::Hive;

/// The `EMDMgmt` (ReadyBoost) cache path in a `SOFTWARE` hive.
const EMD_PATH: &str = "Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt";

/// One cached volume: its label and 4-byte volume serial number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmdVolume {
    /// The volume label (may be empty — an unlabelled volume still has a serial).
    pub volume_label: String,
    /// The 4-byte volume serial number (`BS_VolID` / the `vol`-displayed serial).
    pub volume_serial: u32,
    /// Where the record was decoded from.
    pub source: Provenance,
}

/// Parse `EMDMgmt` volume records from an already-opened `SOFTWARE` hive. Total over a
/// valid hive: a subkey whose name has no trailing `_<decimal>` serial is skipped, never
/// panicked on. `file` is recorded as each record's [`Provenance`] file.
#[must_use]
pub fn parse_emdmgmt(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<EmdVolume> {
    let Ok(Some(emd)) = hive.open_key(EMD_PATH) else {
        return Vec::new();
    };
    let Ok(subkeys) = emd.subkeys() else {
        return Vec::new(); // cov:unreachable: subkeys() only errors on hive corruption
    };
    let mut out = Vec::new();
    for sub in subkeys {
        let name = sub.name();
        let Some((label, serial)) = parse_emd_name(&name) else {
            continue;
        };
        out.push(EmdVolume {
            volume_label: label,
            volume_serial: serial,
            source: Provenance {
                file: file.to_string(),
                line: 0,
                key_path: Some(format!("{EMD_PATH}\\{name}")),
            },
        });
    }
    out
}

/// Decode an `EMDMgmt` subkey name `<prefix>__<label>_<serial>` into `(label, serial)`.
///
/// The volume serial is the trailing `_<decimal>` group; the label is the text after the
/// **last** `__` (double underscore) in the remainder, which cleanly separates the varying
/// device prefix from a label that may itself contain single underscores (e.g. `IAMAN $_@`)
/// or be empty. `None` when there is no trailing decimal serial.
fn parse_emd_name(name: &str) -> Option<(String, u32)> {
    let (rest, serial_str) = name.rsplit_once('_')?;
    let serial: u32 = serial_str.parse().ok()?;
    let label = match rest.rfind("__") {
        Some(i) => &rest[i + 2..],
        None => rest,
    };
    Some((label.to_string(), serial))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_emd_name_splits_prefix_label_and_serial() {
        // Real CFReDS EMDMgmt key names (answer-key labels).
        assert_eq!(
            parse_emd_name("JOJ___Authorized USB_1551191358"),
            Some(("Authorized USB".to_string(), 1_551_191_358))
        );
        assert_eq!(
            parse_emd_name("TO_B__IAMAN $_@_2657770370"),
            Some(("IAMAN $_@".to_string(), 2_657_770_370))
        );
        // An unlabelled volume → empty label, serial intact.
        assert_eq!(
            parse_emd_name("ED_Q___3389815368"),
            Some((String::new(), 3_389_815_368))
        );
        // A label containing internal double underscores keeps everything after the last.
        assert_eq!(
            parse_emd_name("PFX__My__Disk_42"),
            Some(("Disk".to_string(), 42))
        );
        // A name with a serial but no `__` boundary → the whole remainder is the label.
        assert_eq!(parse_emd_name("Label_42"), Some(("Label".to_string(), 42)));
        // No trailing decimal serial → None, no panic.
        assert_eq!(parse_emd_name("NoSerialHere"), None);
        assert_eq!(parse_emd_name("Prefix__Label_notanumber"), None);
    }

    #[test]
    fn synthetic_emdmgmt_hive_decodes_the_volume() {
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_emdmgmt.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let vols = parse_emdmgmt(&hive, "SOFTWARE");
        let v = vols
            .iter()
            .find(|v| v.volume_label == "TESTUSB")
            .expect("labelled volume present");
        assert_eq!(v.volume_serial, 1_234_567_890);
        assert!(v.source.key_path.is_some());
    }

    #[test]
    fn a_hive_without_emdmgmt_yields_nothing() {
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_usb_system.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        assert!(parse_emdmgmt(&hive, "SYSTEM").is_empty());
    }
}
