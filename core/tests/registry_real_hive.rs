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
    // MTP negative control: this hive has no WUDFWpdMtp device (all its USB endpoints are
    // mass storage / HID / hubs), so nothing must be misclassified as Bus::Mtp — the
    // real-data guard on the MTP detection rule.
    assert!(
        conns.iter().all(|c| c.bus != Bus::Mtp),
        "no device in the CFReDS hive is MTP; the rule must not false-positive"
    );
}

#[test]
fn cfreds_volume_info_cache_recovers_the_usb_volume_label() {
    // Tier-1 on the NIST CFReDS Data-Leakage SOFTWARE hive (Windows 7). Ground truth =
    // the NIST answer key: the SanDisk RM#2 stick's volume label is "IAMAN $_@", cached
    // in VolumeInfoCache against drive E:.
    let Ok(path) = std::env::var("PERIPHERAL_TEST_WIN7_SOFTWARE") else {
        eprintln!(
            "SKIP: set PERIPHERAL_TEST_WIN7_SOFTWARE to the CFReDS Data-Leakage SOFTWARE hive"
        );
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid Win7 SOFTWARE hive");
    let labels = peripheral_core::volume_info::parse_volume_info_cache(&hive, "SOFTWARE");
    let e = labels
        .iter()
        .find(|l| l.drive_letter == 'E')
        .expect("drive E: present in VolumeInfoCache");
    assert_eq!(
        e.volume_label, "IAMAN $_@",
        "the NIST answer-key USB volume label"
    );
}

#[test]
fn cfreds_mounted_devices_mbr_bridges_drive_letter_to_volume_guid() {
    // Tier-1 on the NIST CFReDS Data-Leakage SYSTEM hive (Windows 7). MountedDevices maps
    // both \DosDevices\E: and \??\Volume{a2f2048e-…} to the SAME 12-byte MBR record
    // (disk signature 0xE221034C, offset 0x10000), so they are the same volume — the
    // bridge that ties drive E: ("IAMAN $_@") to the volume GUID the informant mounted.
    let Ok(path) = std::env::var("PERIPHERAL_TEST_WIN7_SYSTEM") else {
        eprintln!("SKIP: set PERIPHERAL_TEST_WIN7_SYSTEM to the CFReDS Data-Leakage SYSTEM hive");
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid Win7 SYSTEM hive");
    let vols = peripheral_core::mounted_volumes::parse_mounted_volumes(&hive, "SYSTEM");

    let e = vols
        .iter()
        .find(|v| v.drive_letter == Some('E'))
        .expect("drive E: MBR record present");
    assert_eq!(e.disk_signature, 0xE221_034C);
    assert_eq!(e.partition_offset, 0x1_0000);

    // The volume GUID sharing that MBR record is the same volume.
    let guid = vols
        .iter()
        .find(|v| {
            v.volume_guid.is_some()
                && v.disk_signature == e.disk_signature
                && v.partition_offset == e.partition_offset
        })
        .expect("a Volume{GUID} shares E:'s MBR record");
    assert_eq!(
        guid.volume_guid.as_deref(),
        Some("{a2f2048e-d228-11e4-b630-000c29ff2429}")
    );
}

#[test]
fn cfreds_mountpoints2_records_the_informants_usb_volume_mount() {
    // Tier-1 on the NIST CFReDS Data-Leakage informant NTUSER.DAT (Windows 7). The user
    // mounted volume {a2f2048e-…} — which the MBR bridge ties to drive E: ("IAMAN $_@") —
    // the per-user half of the USB-exfil attribution. Its key last-write is the mount time.
    let Ok(path) = std::env::var("PERIPHERAL_TEST_WIN7_NTUSER") else {
        eprintln!("SKIP: set PERIPHERAL_TEST_WIN7_NTUSER to the CFReDS informant NTUSER.DAT");
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid Win7 NTUSER.DAT");
    let mounts = peripheral_core::mountpoints2::parse_mountpoints2(&hive, "NTUSER.DAT");
    let m = mounts
        .iter()
        .find(|m| m.volume_guid == "{a2f2048e-d228-11e4-b630-000c29ff2429}")
        .expect("the informant mounted volume {a2f2048e-…}");
    // Last-mounted 2015-03-24 21:02:33 UTC (the subkey last-write).
    assert_eq!(m.last_mounted, Some(1_427_230_953));
}

#[test]
fn cfreds_emdmgmt_recovers_the_usb_volume_labels_and_serials() {
    // Tier-1 on the NIST CFReDS Data-Leakage SOFTWARE hive (Windows 7). EMDMgmt caches the
    // two SanDisk sticks' labels + 4-byte volume serials (the NIST answer-key labels).
    let Ok(path) = std::env::var("PERIPHERAL_TEST_WIN7_SOFTWARE") else {
        eprintln!(
            "SKIP: set PERIPHERAL_TEST_WIN7_SOFTWARE to the CFReDS Data-Leakage SOFTWARE hive"
        );
        return;
    };
    let hive = Hive::from_path(Path::new(&path)).expect("valid Win7 SOFTWARE hive");
    let vols = peripheral_core::emdmgmt::parse_emdmgmt(&hive, "SOFTWARE");
    let auth = vols
        .iter()
        .find(|v| v.volume_label == "Authorized USB")
        .expect("RM#1 'Authorized USB' present in EMDMgmt");
    assert_eq!(auth.volume_serial, 1_551_191_358);
    let iaman = vols
        .iter()
        .find(|v| v.volume_label == "IAMAN $_@")
        .expect("RM#2 'IAMAN $_@' present in EMDMgmt");
    assert_eq!(iaman.volume_serial, 2_657_770_370);
}
