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
/// panicked on. `file` is recorded as the [`Provenance`] file (the
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
                continue; // cov:unreachable: subkeys() only errors on hive corruption; a valid hive yields Ok
            };
            for vendor in vendors {
                let ven_name = vendor.name();
                let Ok(instances) = vendor.subkeys() else {
                    continue; // cov:unreachable: subkeys() only errors on hive corruption; a valid hive yields Ok
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
    apply_mounted_devices(hive, &mut out);
    out
}

/// Enrich connections with drive letters decoded from the `MountedDevices` key.
///
/// `MountedDevices` maps a mount name — `\DosDevices\X:` (a drive letter) or
/// `\??\Volume{guid}` (a volume, no letter) — to a REG_BINARY value that is either a
/// 12-byte MBR record (disk signature + partition offset) or a UTF-16LE device path
/// `\??\<CLASS>#<Ven&Prod>#<instance>#{guid}`. The device-path form names a device
/// instance directly, so a `\DosDevices\X:` entry pointing at a device path gives a
/// drive-letter ↔ device join. MBR records and volume-GUID names carry no drive letter;
/// the MBR disk-signature join needs the device-side signature from the
/// Partition/Diagnostic log (a separate source) and is not attempted here.
fn apply_mounted_devices(hive: &Hive<Cursor<Vec<u8>>>, conns: &mut [DeviceConnection]) {
    let Ok(Some(md)) = hive.open_key("MountedDevices") else {
        return;
    };
    let Ok(values) = md.values() else {
        return; // cov:unreachable: values() only errors on hive corruption; a valid hive yields Ok
    };
    for value in values {
        let Some(letter) = dos_drive_letter(&value.name()) else {
            continue;
        };
        let Ok(raw) = value.raw_data() else {
            continue; // cov:unreachable: raw_data() only errors on hive corruption
        };
        let Some(instance) = device_path_instance(&raw) else {
            continue;
        };
        let suffix = format!("\\{instance}");
        for conn in conns.iter_mut() {
            if conn.device_instance_id == instance || conn.device_instance_id.ends_with(&suffix) {
                conn.drive_letter = Some(letter);
            }
        }
    }
}

/// Extract the drive letter from a `\DosDevices\X:` mount name, upper-cased. Any other
/// name (a volume GUID, a malformed name) yields `None`.
fn dos_drive_letter(name: &str) -> Option<char> {
    let tail = name.strip_prefix("\\DosDevices\\")?;
    let mut chars = tail.chars();
    let letter = chars.next()?;
    if letter.is_ascii_alphabetic() && chars.next() == Some(':') && chars.next().is_none() {
        Some(letter.to_ascii_uppercase())
    } else {
        None
    }
}

/// Decode a `MountedDevices` REG_BINARY value as a UTF-16LE device path and return the
/// device instance component (`\??\<CLASS>#<Ven&Prod>#<instance>#{guid}` → `<instance>`).
/// Returns `None` for a 12-byte MBR record, a non-device-path string, or malformed bytes.
fn device_path_instance(raw: &[u8]) -> Option<String> {
    if raw.len() < 8 || raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded = String::from_utf16(&units).ok()?;
    let path = decoded.strip_prefix("\\??\\")?;
    let mut parts: Vec<&str> = path.split('#').collect();
    // Drop the trailing `{GUID}` interface-class component when present.
    if parts
        .last()
        .is_some_and(|p| p.starts_with('{') && p.ends_with('}'))
    {
        parts.pop();
    }
    let instance = *parts.last()?;
    if instance.is_empty() || parts.len() < 2 {
        return None;
    }
    Some(instance.to_string())
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
    let filetime = |prop: u32| ts.as_ref().and_then(|k| read_filetime(k, prop));
    // 0x64/0x65 are documented install dates (authoritative); 0x66/0x67 are the
    // undocumented last-arrival/removal properties (inferred).
    let first_install = filetime(0x64)
        .or_else(|| filetime(0x65))
        .map(Stamp::authoritative);
    let last_arrival = filetime(0x66).map(Stamp::inferred);
    let last_removal = filetime(0x67).map(Stamp::inferred);

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

/// Read the device-property `FILETIME` numbered `prop` (e.g. `0x64`) as Unix epoch
/// seconds, handling both Windows device-property-store layouts:
///
/// - **Windows 8+/Server 2012+:** the property subkey is named with 4 hex digits
///   (`0064`) and the `FILETIME` is its default (unnamed) value.
/// - **Windows 7:** the subkey is named with 8 hex digits (`00000064`) and the
///   `FILETIME` is the `Data` value of a nested `00000000` leaf key.
///
/// The property is matched by its numeric value so any zero-padding resolves, and both
/// value locations are tried. Verified Tier-1 against the Szechuan (Server 2012 R2) and
/// NIST CFReDS Data-Leakage (Windows 7) hives.
fn read_filetime(guid_key: &Key<'_>, prop: u32) -> Option<i64> {
    let prop_key = find_prop_subkey(guid_key, prop)?;
    let raw = prop_key
        .value("")
        .ok()
        .flatten()
        .and_then(|v| v.raw_data().ok())
        .or_else(|| {
            // Win7 nested layout: `<prop>\00000000` with the FILETIME in `Data`.
            let leaf = find_prop_subkey(&prop_key, 0)?;
            leaf.value("Data")
                .ok()
                .flatten()
                .and_then(|v| v.raw_data().ok())
        })?;
    let bytes: [u8; 8] = raw.get(..8)?.try_into().ok()?;
    let ts = filetime_to_datetime(u64::from_le_bytes(bytes))?;
    Some(ts.as_second())
}

/// Find a device-property subkey by its numeric hex value, tolerating any zero-padding
/// (`0064` and `00000064` both match `0x64`).
fn find_prop_subkey<'a>(key: &Key<'a>, num: u32) -> Option<Key<'a>> {
    key.subkeys()
        .ok()?
        .into_iter()
        .find(|k| u32::from_str_radix(&k.name(), 16).ok() == Some(num))
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
    use crate::Bus;

    // The real-artifact validation against the Szechuan SYSTEM hive + regipy oracle
    // lives in `core/tests/registry_real_hive.rs` (an integration test, env-gated), so
    // it is excluded from `--lib` line coverage while still proving correctness on real
    // data. The tests here exercise the walker deterministically from a synthetic hive.

    /// Deterministic coverage fixture (Tier-3): a `winreg-testutil`-built SYSTEM hive
    /// with three device instances covering every branch. Decoder *correctness* is
    /// validated at Tier-1 by `vmware_scsi_disk_matches_regipy_ground_truth` against the
    /// real hive + regipy oracle; this test exercises the walker deterministically in CI.
    #[test]
    fn synthetic_hive_exercises_every_branch() {
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_usb_system.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid synthetic REGF");
        let conns = parse_registry(&hive, "SYNTHETIC");
        let by = |needle: &str| {
            conns
                .iter()
                .find(|c| c.device_instance_id.contains(needle))
                .expect("device present")
        };

        // SCSI: 0064 first-install, 0066 last-arrival, FriendlyName, OS-generated serial.
        let scsi = by("Disk&Ven_Test&Prod_Disk");
        assert_eq!(scsi.bus, Bus::ScsiSas);
        assert_eq!(scsi.friendly_name.as_deref(), Some("Test Virtual Disk"));
        assert_eq!(
            scsi.first_install.as_ref().map(|s| s.value),
            Some(1_600_357_894)
        );
        assert_eq!(
            scsi.last_arrival.as_ref().map(|s| s.value),
            Some(1_600_478_558)
        );
        assert_eq!(scsi.last_removal, None);
        assert!(scsi.serial_is_os_generated);
        assert!(scsi.source.key_path.is_some());

        // USBSTOR: first-install via the 0065 fallback, 0067 last-removal, no FriendlyName.
        let usbstor = by("Disk&Ven_Gen&Prod_Flash");
        assert_eq!(usbstor.bus, Bus::Usb);
        assert_eq!(
            usbstor.first_install.as_ref().map(|s| s.value),
            Some(1_500_000_000)
        );
        assert_eq!(
            usbstor.last_removal.as_ref().map(|s| s.value),
            Some(1_500_009_999)
        );
        assert_eq!(usbstor.friendly_name, None);

        // USB: VID/PID extraction, a real (not OS-generated) iSerial.
        let usb = by("VID_0781&PID_5583");
        assert_eq!(usb.bus, Bus::Usb);
        assert_eq!(usb.vid, Some(0x0781));
        assert_eq!(usb.pid, Some(0x5583));
        assert_eq!(usb.device_serial.as_deref(), Some("0123456789AB"));
        assert!(!usb.serial_is_os_generated);
    }

    #[test]
    fn parse_vid_pid_handles_absent_and_malformed() {
        assert_eq!(
            parse_vid_pid("VID_0781&PID_5583"),
            (Some(0x0781), Some(0x5583))
        );
        assert_eq!(parse_vid_pid("Disk&Ven_Gen&Prod_Flash"), (None, None));
        // present prefix but too short / non-hex → None, never a panic.
        assert_eq!(parse_vid_pid("VID_07&PID_ZZZZ"), (None, None));
    }

    /// UTF-16LE encode a device path the way `MountedDevices` stores it (REG_BINARY).
    fn u16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn dos_drive_letter_extracts_only_well_formed_names() {
        assert_eq!(dos_drive_letter("\\DosDevices\\E:"), Some('E'));
        assert_eq!(dos_drive_letter("\\DosDevices\\c:"), Some('C')); // upper-cased
                                                                     // a volume-GUID mount name carries no drive letter.
        assert_eq!(dos_drive_letter("\\??\\Volume{1234}"), None);
        // malformed DosDevices names never panic, never yield a letter.
        assert_eq!(dos_drive_letter("\\DosDevices\\"), None);
        assert_eq!(dos_drive_letter("\\DosDevices\\EE:"), None);
        assert_eq!(dos_drive_letter("\\DosDevices\\1:"), None);
    }

    #[test]
    fn device_path_instance_extracts_the_instance_or_rejects() {
        let dev =
            "\\??\\SCSI#Disk&Ven_Test&Prod_X#5&join123&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
        assert_eq!(
            device_path_instance(&u16le(dev)).as_deref(),
            Some("5&join123&0")
        );
        // a device path without a trailing {GUID} component still yields the instance.
        assert_eq!(
            device_path_instance(&u16le("\\??\\USBSTOR#Disk&Ven#INST42")).as_deref(),
            Some("INST42")
        );
        // a 12-byte MBR record (disk signature + offset) is not a device path.
        assert_eq!(
            device_path_instance(&[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
        // too short / odd length / not a \??\ path / single component → None, no panic.
        assert_eq!(device_path_instance(&[0, 0]), None);
        assert_eq!(device_path_instance(&[1, 2, 3]), None);
        assert_eq!(device_path_instance(&u16le("C:\\not-a-device-path")), None);
        assert_eq!(device_path_instance(&u16le("\\??\\onlyonepart")), None);
        // a lone UTF-16 surrogate must be rejected, not panic.
        assert_eq!(
            device_path_instance(&[0x00, 0xD8, 0x00, 0xD8, 0x00, 0x00, 0x00, 0x00]),
            None
        );
    }

    #[test]
    fn mounted_devices_join_sets_drive_letter_on_the_matching_device() {
        // Synthetic SYSTEM hive: one SCSI instance + a MountedDevices key mapping
        // \DosDevices\E: → that instance's device path, plus an MBR record and a
        // volume-GUID path that must NOT produce a drive letter.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_mounted_devices.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let conns = parse_registry(&hive, "SYNTHETIC");
        let dev = conns
            .iter()
            .find(|c| c.device_instance_id.ends_with("5&join123&0"))
            .expect("device present");
        assert_eq!(dev.drive_letter, Some('E'));
    }

    #[test]
    fn win7_nested_property_layout_filetime_is_decoded() {
        // Synthetic Windows-7-layout hive: the install FILETIME lives at
        // Properties\{GUID}\00000064\00000000 in a `Data` value (8-hex property name +
        // nested leaf), not the modern 0064-default-value layout. Deterministic CI cover
        // for the Win7 branch of `read_filetime`; the same decode is validated Tier-1 on
        // the real NIST CFReDS hive in `tests/registry_real_hive.rs`.
        const HIVE: &[u8] = include_bytes!("../../tests/data/synthetic_win7_props.hive");
        let hive = Hive::from_bytes(HIVE.to_vec()).expect("valid REGF");
        let conns = parse_registry(&hive, "SYNTHETIC");
        let dev = conns
            .iter()
            .find(|c| c.device_instance_id.ends_with("7&win7serial&0"))
            .expect("Win7 device present");
        assert_eq!(
            dev.first_install.as_ref().map(|s| s.value),
            Some(1_427_135_471),
            "install FILETIME decoded from the nested 00000064\\00000000\\Data leaf"
        );
    }
}
