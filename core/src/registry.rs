//! Registry device source: decode USB / SCSI / USBSTOR device instances from a Windows
//! `SYSTEM` hive into [`DeviceConnection`] records, complementing the `setupapi` source.
//!
//! Device instances live under `ControlSet00X\Enum\{USBSTOR,SCSI,USB}\<Ven&Prod>\<instance>`.
//! Per-device timestamps live in the undocumented device-property subtree
//! `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<PROP>` whose default value is a
//! `FILETIME`: `0064` install, `0065` first-install (both documented → authoritative),
//! `0066` last-arrival/connect, `0067` last-removal/disconnect (undocumented → inferred).

use crate::DeviceConnection;
use std::io::Cursor;
use winreg_core::hive::Hive;

/// Parse USB / SCSI / USBSTOR device instances from an already-opened `SYSTEM` hive.
///
/// The caller opens the hive (a bootstrap step that must fail loudly on its own); this
/// function walks it and is total over a valid hive — a malformed subkey is skipped, not
/// panicked on. `file` is recorded as the [`Provenance`](crate::Provenance) file (the
/// hive name, e.g. `SYSTEM`); each record also carries its full key path.
#[must_use]
pub fn parse_registry(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<DeviceConnection> {
    let _ = (hive, file);
    unimplemented!("GREEN step")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Bus, Confidence};
    use std::path::Path;

    // Env-gated real-artifact test (fleet test-data standard): the DFIR Madness
    // "Szechuan Sauce" SYSTEM hive. Skips cleanly when the hive is not present.
    fn open_system_hive() -> Option<Hive<Cursor<Vec<u8>>>> {
        let p = std::env::var("PERIPHERAL_TEST_SYSTEM_HIVE").ok()?;
        Hive::from_path(Path::new(&p)).ok()
    }

    #[test]
    fn vmware_scsi_disk_matches_regipy_ground_truth() {
        let Some(hive) = open_system_hive() else {
            eprintln!("SKIP: set PERIPHERAL_TEST_SYSTEM_HIVE to the Szechuan SYSTEM hive");
            return;
        };
        let conns = parse_registry(&hive, "SYSTEM");

        let disk = conns
            .iter()
            .find(|c| {
                c.device_instance_id
                    .contains("Disk&Ven_VMware_&Prod_VMware_Virtual_S")
            })
            .expect("VMware virtual disk instance present in the Szechuan SYSTEM hive");

        assert_eq!(disk.bus, Bus::ScsiSas);
        // regipy oracle: 0064 first-install = 2020-09-17 15:51:34 UTC.
        assert_eq!(
            disk.first_install.as_ref().map(|s| s.value),
            Some(1_600_357_894)
        );
        // regipy oracle: 0066 last-arrival = 2020-09-19 01:22:38 UTC (inferred).
        assert_eq!(
            disk.last_arrival.as_ref().map(|s| s.value),
            Some(1_600_478_558)
        );
        assert_eq!(
            disk.last_arrival.as_ref().map(|s| s.confidence),
            Some(Confidence::Inferred)
        );
        assert!(
            disk.source.key_path.is_some(),
            "registry record carries its key path"
        );
    }
}
