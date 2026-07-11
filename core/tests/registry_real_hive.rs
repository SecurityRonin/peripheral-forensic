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

#[test]
fn win7_usbstor_device_property_filetimes_are_decoded() {
    // Tier-1 on the NIST CFReDS "Data Leakage Case" SYSTEM hive (Windows 7), whose
    // device-property FILETIMEs use the older layout: 8-hex property names
    // (`00000064`) with the FILETIME in the `Data` value of a nested `00000000` leaf,
    // NOT the modern `0064`-default-value layout. Ground truth = the NIST answer key:
    // SanDisk Cruzer Fit RM#1 (serial 4C530012450531101593) first connected
    // 2015-03-23 18:31:11 UTC; RM#2 (4C530012550531106501) 2015-03-24 13:58:33 UTC.
    let Ok(path) = std::env::var("PERIPHERAL_TEST_WIN7_SYSTEM") else {
        eprintln!("SKIP: set PERIPHERAL_TEST_WIN7_SYSTEM to the CFReDS Data-Leakage SYSTEM hive");
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid Win7 SYSTEM hive");
    let conns = parse_registry(&hive, "SYSTEM");

    let by_serial = |serial: &str| {
        conns
            .iter()
            .find(|c| {
                c.device_instance_id.starts_with("USBSTOR") && c.device_instance_id.contains(serial)
            })
            .unwrap_or_else(|| panic!("USBSTOR device {serial} present in the CFReDS hive"))
    };

    let rm1 = by_serial("4C530012450531101593");
    assert_eq!(
        rm1.first_install.as_ref().map(|s| s.value),
        Some(1_427_135_471),
        "RM#1 first-install = 2015-03-23 18:31:11 UTC (NIST answer key)"
    );
    let rm2 = by_serial("4C530012550531106501");
    assert_eq!(
        rm2.first_install.as_ref().map(|s| s.value),
        Some(1_427_205_513),
        "RM#2 first-install = 2015-03-24 13:58:33 UTC (NIST answer key)"
    );
}
