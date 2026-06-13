//! Parser for Windows `setupapi.dev.log` (Vista+) and `setupapi.log` (XP)
//! device-installation logs.
//!
//! Forensic value: a device-install section header records the exact moment a
//! device's driver was installed — a first-connect timestamp that survives even
//! after the registry `Enum\` keys are wiped. This module extracts the
//! enumerator, VID/PID, iSerial, and install time into a [`DeviceConnection`].
//!
//! Two header grammars are handled (citation: Microsoft Learn, *SetupAPI Text
//! Logs* / *Format of a Text Log Section Header*):
//!
//! - **Vista+** — description first, timestamp last inside the brackets:
//!   `[Device Install (Hardware initiated) - USB\VID_0781&PID_5583\<serial> 2023/04/15 14:23:11.456]`
//! - **XP** — timestamp first inside the brackets:
//!   `[2005/05/12 12:34:56 1234.5678] Device Install - USB\...`
//!
//! Lines that match neither grammar are skipped; the parser never panics.

// RED commit: the helpers below are wired up by the GREEN `parse_setupapi`.
#![allow(dead_code)]

use crate::{Bus, DeviceConnection, MitreRef, Provenance, Stamp};

/// `MITRE` techniques narrated as *consistent with*, attached to a connection
/// by [`DeviceConnection`] construction so downstream analyzers inherit them.
const MITRE_DMA: MitreRef = MitreRef("T1200");
const MITRE_EXFIL_USB: MitreRef = MitreRef("T1052.001");

/// Parse a `setupapi.dev.log` / `setupapi.log` text body into one
/// [`DeviceConnection`] per device-install section header.
///
/// `file` is the source filename recorded in each record's [`Provenance`].
/// Non-matching lines are skipped; the function never panics on any input.
#[must_use]
pub fn parse_setupapi(_text: &str, _file: &str) -> Vec<DeviceConnection> {
    // RED stub — the real parser (header grammars, VID/PID/serial extraction,
    // bus classification, timestamp tagging) lands in the GREEN commit.
    Vec::new()
}

/// Extract `(device_instance_id, epoch_seconds)` from a `[ … ]` section header,
/// trying the Vista+ grammar then the XP grammar. Returns `None` for a line that
/// is not a recognizable device-install header.
fn parse_header(line: &str) -> Option<(String, Option<i64>)> {
    let inner = line.strip_prefix('[')?;
    let close = inner.find(']')?;
    let body = &inner[..close];

    // Vista+: `<description with INSTANCE\PATH> YYYY/MM/DD HH:MM:SS[.mmm]`
    if let Some((desc, ts)) = split_trailing_timestamp(body) {
        let instance = extract_instance_id(desc);
        // Only keep device-install headers that actually carry a device path.
        if let Some(instance) = instance {
            return Some((instance, ts));
        }
    }

    // XP: `YYYY/MM/DD HH:MM:SS <pid.tid>` then `] Device Install - <path>`.
    if let Some((ts, _rest)) = split_leading_timestamp(body) {
        // The device path follows the closing bracket.
        let after = &inner[close + 1..];
        let instance = extract_instance_id(after)?;
        return Some((instance, ts));
    }

    None
}

/// Split a Vista+ header body into `(description, Option<epoch>)` by finding a
/// trailing `YYYY/MM/DD HH:MM:SS[.mmm]` token. Returns `None` if no trailing
/// timestamp is present.
fn split_trailing_timestamp(body: &str) -> Option<(&str, Option<i64>)> {
    // The timestamp is the last `date time` pair: split off the last two
    // whitespace-separated tokens and test them.
    let body = body.trim_end();
    let mut it = body.rsplitn(3, char::is_whitespace);
    let time = it.next()?;
    let date = it.next()?;
    let head = it.next()?;
    let ts_str = format!("{date} {time}");
    let epoch = parse_timestamp(&ts_str)?;
    Some((head, Some(epoch)))
}

/// Split an XP header body that *begins* with a timestamp into
/// `(Option<epoch>, rest)`. Returns `None` if the body does not start with a
/// `YYYY/MM/DD HH:MM:SS` pair.
fn split_leading_timestamp(body: &str) -> Option<(Option<i64>, &str)> {
    let mut it = body.splitn(3, char::is_whitespace);
    let date = it.next()?;
    let time = it.next()?;
    let rest = it.next().unwrap_or("");
    let ts_str = format!("{date} {time}");
    let epoch = parse_timestamp(&ts_str)?;
    Some((Some(epoch), rest))
}

/// Find a device instance id — a `ENUM\…` token containing at least one
/// backslash — inside a free-text description. Returns `None` if the text holds
/// no instance-id-shaped token.
fn extract_instance_id(text: &str) -> Option<String> {
    // The instance id is the longest whitespace-delimited token that contains a
    // backslash and whose first segment is an alphanumeric enumerator.
    text.split_whitespace()
        .filter(|tok| tok.contains('\\'))
        .filter(|tok| {
            tok.split('\\')
                .next()
                .is_some_and(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric()))
        })
        .max_by_key(|tok| tok.len())
        .map(str::to_string)
}

/// Parse a `YYYY/MM/DD HH:MM:SS[.mmm]` timestamp (treated as UTC) into Unix
/// epoch seconds, with no external date library. Returns `None` on any
/// malformed component — the parser then skips the timestamp, never panics.
fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once(' ')?;
    let mut dparts = date.split('/');
    let year: i64 = dparts.next()?.parse().ok()?;
    let month: i64 = dparts.next()?.parse().ok()?;
    let day: i64 = dparts.next()?.parse().ok()?;
    if dparts.next().is_some() {
        return None;
    }
    // Drop fractional seconds.
    let time = rest.split('.').next()?;
    let mut tparts = time.split(':');
    let hour: i64 = tparts.next()?.parse().ok()?;
    let min: i64 = tparts.next()?.parse().ok()?;
    let sec: i64 = tparts.next()?.parse().ok()?;
    if tparts.next().is_some() {
        return None;
    }
    civil_to_epoch(year, month, day, hour, min, sec)
}

/// Convert a civil UTC date-time to Unix epoch seconds (Howard Hinnant's
/// `days_from_civil` algorithm). Returns `None` for an out-of-range field.
fn civil_to_epoch(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

/// Build a [`DeviceConnection`] from a device instance id and its install time.
/// Returns `None` if the instance id has no enumerator segment.
fn build_connection(
    instance_id: &str,
    install_epoch: Option<i64>,
    file: &str,
    line: usize,
) -> Option<DeviceConnection> {
    let mut segs = instance_id.split('\\');
    let enumerator = segs.next()?;
    if enumerator.is_empty() {
        return None; // cov:unreachable: callers pass instance ids whose enumerator is non-empty alphanumeric
    }
    let device_id = segs.next().unwrap_or("");
    let serial_seg = segs.next();

    let bus = Bus::from_enumerator(enumerator);
    let (vid, pid) = parse_vid_pid(device_id);
    let serial_is_os_generated = serial_seg.is_some_and(is_os_generated_serial);
    let device_serial = serial_seg
        .filter(|_| !serial_is_os_generated)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let dma_capable = bus.is_dma_capable();
    let mut mitre = Vec::new();
    if dma_capable {
        mitre.push(MITRE_DMA);
    }
    if bus.is_mass_storage() {
        mitre.push(MITRE_EXFIL_USB);
    }

    Some(DeviceConnection {
        bus,
        device_class_guid: None,
        vid,
        pid,
        device_serial,
        serial_is_os_generated,
        friendly_name: None,
        device_instance_id: instance_id.to_string(),
        first_install: install_epoch.map(Stamp::authoritative),
        last_install: install_epoch.map(Stamp::authoritative),
        last_arrival: None,
        last_removal: None,
        parent_id_prefix: None,
        volume_guid: None,
        drive_letter: None,
        volume_serial: None,
        disk_signature: None,
        dma_capable,
        mitre,
        source: Provenance {
            file: file.to_string(),
            line,
        },
    })
}

/// Extract `(vid, pid)` from a `VID_xxxx&PID_xxxx[&…]` device-id segment. Either
/// or both may be `None` for a non-USB device id.
fn parse_vid_pid(device_id: &str) -> (Option<u16>, Option<u16>) {
    let mut vid = None;
    let mut pid = None;
    for part in device_id.split('&') {
        if let Some(hex) = part.strip_prefix("VID_") {
            vid = u16::from_str_radix(hex_prefix(hex), 16).ok();
        } else if let Some(hex) = part.strip_prefix("PID_") {
            pid = u16::from_str_radix(hex_prefix(hex), 16).ok();
        }
    }
    (vid, pid)
}

/// The leading hex run of `s` (stops at the first non-hex character).
fn hex_prefix(s: &str) -> &str {
    let end = s.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(s.len());
    &s[..end]
}

/// The instance-id serial is OS-generated when its **second character** is `&`
/// (the bus had no device-unique serial, so Windows synthesized one, e.g.
/// `7&1c2c4f0a&0`). Citation: Microsoft Learn, *Instance IDs* — a bus-supplied
/// instance id encodes either a device serial or location information.
fn is_os_generated_serial(serial: &str) -> bool {
    serial.chars().nth(1) == Some('&')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    const VISTA_USB: &str = "[Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\1234567890AB 2023/04/15 14:23:11.456]";

    #[test]
    fn parses_vista_usb_header() {
        let conns = parse_setupapi(VISTA_USB, "setupapi.dev.log");
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.bus, Bus::Usb);
        assert_eq!(c.vid, Some(0x0781));
        assert_eq!(c.pid, Some(0x5583));
        assert_eq!(c.device_serial.as_deref(), Some("1234567890AB"));
        assert!(!c.serial_is_os_generated);
        assert_eq!(c.device_instance_id, "USB\\VID_0781&PID_5583\\1234567890AB");
        assert_eq!(c.source.file, "setupapi.dev.log");
        assert_eq!(c.source.line, 1);
    }

    #[test]
    fn section_marker_prefix_is_stripped() {
        // Real setupapi.dev.log headers are prefixed by a `>>>  ` marker.
        let line =
            ">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\AB 2023/04/15 14:23:11.456]";
        let conns = parse_setupapi(line, "f");
        assert_eq!(conns.len(), 1, "the `>>>` section marker must be stripped");
        assert_eq!(conns[0].vid, Some(0x0781));
    }

    #[test]
    fn install_time_is_authoritative() {
        let c = &parse_setupapi(VISTA_USB, "f")[0];
        let s = c.first_install.expect("first_install present");
        assert_eq!(s.confidence, Confidence::Authoritative);
        // 2023/04/15 14:23:11 UTC = 1681568591
        assert_eq!(s.value, 1_681_568_591);
        assert_eq!(c.last_arrival, None); // inferred-only fields stay empty in v0.1
        assert_eq!(c.last_removal, None);
    }

    #[test]
    fn parses_xp_header() {
        let xp =
            "[2005/05/12 12:34:56 1234.5678] Device Install - USB\\VID_04E8&PID_6860\\0123456789";
        let conns = parse_setupapi(xp, "setupapi.log");
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.vid, Some(0x04E8));
        assert_eq!(c.pid, Some(0x6860));
        assert_eq!(c.device_serial.as_deref(), Some("0123456789"));
        // 2005/05/12 12:34:56 UTC = 1115901296
        assert_eq!(c.first_install.map(|s| s.value), Some(1_115_901_296));
    }

    #[test]
    fn os_generated_serial_is_flagged_and_not_kept_as_device_serial() {
        // Second character `&` => Windows synthesized the serial.
        let line = "[Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Generic&Prod_Flash\\7&1c2c4f0a&0 2024/01/02 03:04:05.000]";
        let c = &parse_setupapi(line, "f")[0];
        assert!(
            c.serial_is_os_generated,
            "2nd-char-& serial must be flagged"
        );
        assert_eq!(
            c.device_serial, None,
            "OS-generated serial must not be reported as a real iSerial"
        );
    }

    #[test]
    fn dma_bus_attaches_t1200_and_dma_flag() {
        let line = "[Device Install (Hardware initiated) - 1394\\SONY&CAMERA\\0123 2024/01/02 03:04:05.000]";
        let c = &parse_setupapi(line, "f")[0];
        assert_eq!(c.bus, Bus::FireWire);
        assert!(c.dma_capable);
        assert!(c.mitre.contains(&MitreRef("T1200")));
    }

    #[test]
    fn mass_storage_attaches_exfil_mitre() {
        let c = &parse_setupapi(VISTA_USB, "f")[0];
        assert!(c.mitre.contains(&MitreRef("T1052.001")));
    }

    #[test]
    fn volume_serial_is_distinct_field_from_device_serial() {
        // v0.1 setupapi source never populates volume_serial; the type keeps it
        // separate from the USB device_serial so the two can't be conflated.
        let c = &parse_setupapi(VISTA_USB, "f")[0];
        assert!(c.device_serial.is_some());
        assert_eq!(c.volume_serial, None);
    }

    #[test]
    fn parse_timestamp_rejects_malformed_components() {
        // Well-formed reference.
        assert_eq!(
            parse_timestamp("2023/04/15 14:23:11.456"),
            Some(1_681_568_591)
        );
        // Extra date component (4th `/` segment).
        assert_eq!(parse_timestamp("2024/01/02/03 04:05:06"), None);
        // Extra time component (4th `:` segment).
        assert_eq!(parse_timestamp("2024/01/02 04:05:06:07"), None);
        // Valid date, out-of-range hour → civil range check.
        assert_eq!(parse_timestamp("2024/01/02 25:00:00"), None);
        assert_eq!(parse_timestamp("2024/01/02 00:60:00"), None); // bad minute
        assert_eq!(parse_timestamp("2024/01/02 00:00:61"), None); // bad second
                                                                  // A header whose trailing token is an unparseable timestamp matches no
                                                                  // grammar → the line is skipped entirely (no connection, no panic).
        let bad = "[Device Install - USB\\VID_0781&PID_5583\\X 2024/01/02 25:00:00]";
        assert!(parse_setupapi(bad, "f").is_empty());
    }

    #[test]
    fn non_matching_lines_are_skipped_never_panic() {
        let junk = ">>>  [Setup online Device Install (Hardware initiated)]\n\
                    not a header at all\n\
                    [no closing bracket\n\
                    \n\
                    [Some Note Without A Path 2024/01/02 03:04:05.000]";
        // None of these carry a device instance path → zero connections, no panic.
        assert!(parse_setupapi(junk, "f").is_empty());
    }

    #[test]
    fn garbled_and_empty_input_never_panics() {
        assert!(parse_setupapi("", "f").is_empty());
        assert!(parse_setupapi("\u{feff}\0\\\\\\[[[]]]", "f").is_empty());
        // A header with a bad date is skipped, not panicked on.
        assert!(parse_setupapi("[USB\\VID_0781&PID_5583\\X 9999/99/99 99:99:99]", "f").is_empty());
    }

    #[test]
    fn missing_serial_segment_yields_none_serial() {
        let line = "[Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234 2024/01/02 03:04:05.000]";
        let c = &parse_setupapi(line, "f")[0];
        assert_eq!(c.bus, Bus::Pcie);
        assert_eq!(c.device_serial, None);
        assert!(!c.serial_is_os_generated);
        assert!(c.dma_capable); // PCI is DMA-capable
    }
}
