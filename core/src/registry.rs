//! Registry device source: decode USB / SCSI / USBSTOR device instances from a Windows
//! `SYSTEM` hive into [`DeviceConnection`] records, complementing the `setupapi` source.
//!
//! Device instances live under `ControlSet00X\Enum\{USBSTOR,SCSI,USB}\<Ven&Prod>\<instance>`.
//! Per-device timestamps live in the undocumented device-property subtree
//! `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<PROP>` whose default value is a
//! `FILETIME`: `0064` install, `0065` first-install (both documented → authoritative),
//! `0066` last-arrival/connect, `0067` last-removal/disconnect (undocumented → inferred).

use crate::{Bus, DeviceConnection, Provenance, Stamp};
use std::io::Cursor;
use winreg_core::hive::Hive;
use winreg_core::key::{filetime_to_datetime, Key};

/// The undocumented device-property subtree holding the install/arrival/removal
/// `FILETIME`s (`0064`/`0065`/`0066`/`0067`).
const TS_GUID: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";

/// The device enumerator classes that carry USB / removable mass-storage history,
/// paired with the bus each implies. `SCSI` is included because virtual and UASP/USB-3
/// disks enumerate there rather than under `USBSTOR`.
const ENUM_CLASSES: [(&str, Bus); 3] = [
    ("USBSTOR", Bus::Usb),
    ("USB", Bus::Usb),
    ("SCSI", Bus::ScsiSas),
];

/// Both control sets are walked; the same device may appear in each.
const CONTROL_SETS: [&str; 2] = ["ControlSet001", "ControlSet002"];

/// Parse USB / SCSI / USBSTOR device instances from an already-opened `SYSTEM` hive.
///
/// The caller opens the hive (a bootstrap step that must fail loudly on its own); this
/// function walks it and is total over a valid hive — a malformed subkey is skipped, not
/// panicked on. `file` is recorded as the [`Provenance`](crate::Provenance) file (the
/// hive name, e.g. `SYSTEM`); each record also carries its full key path.
#[must_use]
pub fn parse_registry(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<DeviceConnection> {
    let mut out = Vec::new();
    for cs in CONTROL_SETS {
        for (class, bus) in ENUM_CLASSES {
            let base = format!("{cs}\\Enum\\{class}");
            let Ok(Some(class_key)) = hive.open_key(&base) else {
                continue;
            };
            let Ok(vendors) = class_key.subkeys() else {
                continue;
            };
            for vendor in vendors {
                let ven_name = vendor.name();
                let Ok(instances) = vendor.subkeys() else {
                    continue;
                };
                for inst in instances {
                    let inst_name = inst.name();
                    let key_path = format!("{base}\\{ven_name}\\{inst_name}");
                    out.push(build_connection(
                        &inst, class, bus, &ven_name, &inst_name, file, key_path,
                    ));
                }
            }
        }
    }
    out
}

/// Build one [`DeviceConnection`] from a decoded device-instance key.
fn build_connection(
    inst: &Key<'_>,
    class: &str,
    bus: Bus,
    ven_name: &str,
    inst_name: &str,
    file: &str,
    key_path: String,
) -> DeviceConnection {
    let (vid, pid) = parse_vid_pid(ven_name);
    // Windows synthesizes an instance id whose 2nd character is `&` when the device
    // exposed no real iSerial — attribution is then weaker.
    let serial_is_os_generated = inst_name.as_bytes().get(1) == Some(&b'&');

    let ts = inst
        .subkey("Properties")
        .ok()
        .flatten()
        .and_then(|p| p.subkey(TS_GUID).ok().flatten());
    let filetime = |prop: &str| ts.as_ref().and_then(|k| read_filetime(k, prop));
    // 0064/0065 are documented install dates (authoritative); 0066/0067 are the
    // undocumented last-arrival/removal properties (inferred).
    let first_install = filetime("0064")
        .or_else(|| filetime("0065"))
        .map(Stamp::authoritative);
    let last_arrival = filetime("0066").map(Stamp::inferred);
    let last_removal = filetime("0067").map(Stamp::inferred);

    DeviceConnection {
        bus,
        device_class_guid: None,
        vid,
        pid,
        device_serial: (!inst_name.is_empty()).then(|| inst_name.to_string()),
        serial_is_os_generated,
        friendly_name: value_string(inst, "FriendlyName"),
        device_instance_id: format!("{class}\\{ven_name}\\{inst_name}"),
        first_install,
        last_install: None,
        last_arrival,
        last_removal,
        parent_id_prefix: value_string(inst, "ParentIdPrefix"),
        volume_guid: None,
        drive_letter: None,
        volume_serial: None,
        disk_signature: None,
        dma_capable: bus.is_dma_capable(),
        mitre: Vec::new(),
        source: Provenance {
            file: file.to_string(),
            line: 0,
            key_path: Some(key_path),
        },
    }
}

/// Read a key's named string value, `None` if absent, unreadable, or empty.
fn value_string(key: &Key<'_>, name: &str) -> Option<String> {
    key.value(name)
        .ok()
        .flatten()
        .and_then(|v| v.as_string().ok())
        .filter(|s| !s.is_empty())
}

/// Read the `FILETIME` in the default value of `guid_key\<prop>` as Unix epoch seconds.
fn read_filetime(guid_key: &Key<'_>, prop: &str) -> Option<i64> {
    let prop_key = guid_key.subkey(prop).ok().flatten()?;
    let raw = prop_key.value("").ok().flatten()?.raw_data().ok()?;
    let bytes: [u8; 8] = raw.get(..8)?.try_into().ok()?;
    let ts = filetime_to_datetime(u64::from_le_bytes(bytes))?;
    Some(ts.as_second())
}

/// Extract `(vid, pid)` from a `VID_xxxx&PID_xxxx` enumerator key name (USB only).
fn parse_vid_pid(name: &str) -> (Option<u16>, Option<u16>) {
    let hex4 = |tag: &str| {
        name.split('&').find_map(|seg| {
            let h = seg.strip_prefix(tag)?;
            u16::from_str_radix(h.get(..4)?, 16).ok()
        })
    };
    (hex4("VID_"), hex4("PID_"))
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
