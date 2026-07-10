//! Tier-1 real-artifact validation of the registry device decoder against the DFIR
//! Madness "Szechuan Sauce" SYSTEM hive, cross-checked with the independent **regipy**
//! oracle. Env-gated (skips cleanly when the hive is absent) and kept out of `src/` so
//! its skip does not affect `--lib` line coverage.
//!
//! Enable by pointing `PERIPHERAL_TEST_SYSTEM_HIVE` at the extracted SYSTEM hive.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use peripheral_core::registry::parse_registry;
use peripheral_core::{Bus, Confidence};
use std::path::Path;
use winreg_core::hive::Hive;

#[test]
fn vmware_scsi_disk_matches_regipy_ground_truth() {
    let Ok(path) = std::env::var("PERIPHERAL_TEST_SYSTEM_HIVE") else {
        eprintln!("SKIP: set PERIPHERAL_TEST_SYSTEM_HIVE to the Szechuan SYSTEM hive");
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid SYSTEM hive");
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
    assert!(disk.source.key_path.is_some());
}

#[test]
fn mounted_devices_joins_drive_letter_d_to_the_cdrom_device() {
    // regipy oracle on \MountedDevices: \DosDevices\D: → the device path
    // \??\SCSI#CdRom&Ven_NECVMWar&Prod_VMware_SATA_CD01#5&12368b4a&0&010000#{…},
    // so the CD-ROM device instance mounts as drive D:.
    let Ok(path) = std::env::var("PERIPHERAL_TEST_SYSTEM_HIVE") else {
        eprintln!("SKIP: set PERIPHERAL_TEST_SYSTEM_HIVE to the Szechuan SYSTEM hive");
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid SYSTEM hive");
    let conns = parse_registry(&hive, "SYSTEM");

    let cdrom = conns
        .iter()
        .find(|c| c.device_instance_id.ends_with("5&12368b4a&0&010000"))
        .expect("CD-ROM device instance present in the Szechuan SYSTEM hive");
    assert_eq!(cdrom.drive_letter, Some('D'));
}
